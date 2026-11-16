import { parseJsonB64url, randomBytes } from "./crypto.ts";
import { importHmacKey, signJwt, verifyJwt, type Claims } from "./jwt.ts";
import { checkPassword, hashPassword } from "./password.ts";

/**
 * Each flaw can be switched on by itself. Everything that is not switched on
 * runs in its fixed form, so one lesson never leaks into another.
 */
export const VULNS = ["bola", "jwt-none", "mass-assign", "bruteforce", "bfla", "race"] as const;
export type Vuln = (typeof VULNS)[number];

/** Lab control header: which flaws are on for this request. Not part of the API itself. */
export const VULN_HEADER = "x-range-vulns";

export type L = { es: string; en: string };

export interface Req {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string;
}

export interface Res {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** What the server saw and decided, plus the data it holds, at that moment. */
export interface RangeEvent {
  level: "info" | "ok" | "block" | "breach";
  msg: L;
  at: number;
  snapshot: Snapshot;
}

export interface Snapshot {
  users: { id: number; username: string; role: string }[];
  wallets: Record<number, number>;
  logins: Record<string, { failures: number; lockedSeconds: number }>;
  couponCredits: number;
}

export type Emit = (e: RangeEvent) => void;

type Role = "user" | "admin";

interface User {
  id: number;
  username: string;
  name: string;
  email: string;
  phone: string;
  role: Role;
  passwordHash: string;
}

interface Order {
  id: number;
  userId: number;
  item: string;
  total: number;
  address: string;
  card: string;
}

/** Demo accounts. All data is fictional. */
export const ACCOUNTS = {
  admin: { id: 1, password: "" }, // random per run, never guessable
  lucia: { id: 2, password: "lucia-demo-2026" },
  mateo: { id: 3, password: "medellin2026" },
} as const;

export const COUPON = { code: "BIENVENIDA", amount: 20_000 } as const;
export const LOCKOUT = { maxFailures: 5, seconds: 60 } as const;

export interface RangeOptions {
  /** Time the vulnerable coupon flow waits between its check and its write. */
  raceWindowMs?: number;
  now?: () => number;
  /** Lower only in tests; the default follows OWASP guidance. */
  pbkdf2Iterations?: number;
}

type Say = (level: RangeEvent["level"], es: string, en: string) => void;

export function createRange(opts: RangeOptions = {}) {
  const raceWindowMs = opts.raceWindowMs ?? 40;
  const now = opts.now ?? (() => Date.now());
  const keyPromise = importHmacKey(randomBytes(32));

  let users: User[] = [];
  let orders: Order[] = [];
  let wallets = new Map<number, number>();
  let redeemed = new Set<number>();
  let couponCredits = 0;
  let failures = new Map<string, { count: number; lockedUntil: number }>();
  let dummyHash = "";

  async function seed(): Promise<void> {
    const it = opts.pbkdf2Iterations;
    const [a, l, m, d] = await Promise.all([
      hashPassword(crypto.randomUUID(), it),
      hashPassword(ACCOUNTS.lucia.password, it),
      hashPassword(ACCOUNTS.mateo.password, it),
      hashPassword(crypto.randomUUID(), it),
    ]);
    users = [
      { id: 1, username: "admin", name: "Admin", email: "admin@range.test", phone: "+57 300 000 0001", role: "admin", passwordHash: a },
      { id: 2, username: "lucia", name: "Lucía Restrepo", email: "lucia@range.test", phone: "+57 300 000 0002", role: "user", passwordHash: l },
      { id: 3, username: "mateo", name: "Mateo Gómez", email: "mateo@range.test", phone: "+57 300 000 0003", role: "user", passwordHash: m },
    ];
    orders = [
      { id: 1001, userId: 2, item: "Audífonos inalámbricos", total: 189_900, address: "Cl. 10 #40-20, Medellín", card: "•••• 0042" },
      { id: 1002, userId: 2, item: "Teclado mecánico", total: 329_000, address: "Cl. 10 #40-20, Medellín", card: "•••• 0042" },
      { id: 1003, userId: 3, item: "Portátil 14\"", total: 3_499_000, address: "Cra. 43A #1-50, apto 1204, Medellín", card: "•••• 4417" },
    ];
    wallets = new Map([[1, 0], [2, 0], [3, 0]]);
    redeemed = new Set();
    couponCredits = 0;
    failures = new Map();
    dummyHash = d;
  }

  let ready = seed();

  function snapshot(): Snapshot {
    const logins: Snapshot["logins"] = {};
    for (const [u, r] of failures) logins[u] = { failures: r.count, lockedSeconds: Math.max(0, Math.ceil((r.lockedUntil - now()) / 1000)) };
    return {
      users: users.map((u) => ({ id: u.id, username: u.username, role: String(u.role) })),
      wallets: Object.fromEntries(wallets),
      logins,
      couponCredits,
    };
  }

  async function handle(req: Req, emit?: Emit): Promise<Res> {
    await ready;
    const say: Say = (level, es, en) => emit?.({ level, msg: { es, en }, at: now(), snapshot: snapshot() });
    try {
      return await route(req, say);
    } catch {
      say("block", "Error interno: 500", "Internal error: 500");
      return json(500, { error: "internal error" });
    }
  }

  async function route(req: Req, say: Say): Promise<Res> {
    const headers = lower(req.headers);
    const vulns = parseVulns(headers[VULN_HEADER]);
    const method = req.method.toUpperCase();
    const path = req.path.split("?")[0]!.replace(/\/+$/, "") || "/";

    if (method === "POST" && path === "/api/_reset") {
      ready = seed();
      await ready;
      say("info", "Datos reiniciados", "Data reset");
      return json(200, { reset: true });
    }
    if (method === "POST" && path === "/api/login") return login(req.body, vulns, say);

    const user = await authenticate(headers.authorization, vulns, say);
    if (!user) return json(401, { error: "authentication required" });
    const who = `${user.username} (id ${user.id})`;

    if (path === "/api/users/me") {
      if (method === "GET") {
        if (vulns.has("mass-assign")) {
          say("breach", `Perfil de ${user.username} enviado completo, con el hash de su contraseña`, `${user.username}'s full profile sent, password hash included`);
          return json(200, { ...user });
        }
        say("ok", `Perfil de ${user.username} enviado sin datos sensibles`, `${user.username}'s profile sent without sensitive fields`);
        return json(200, publicUser(user));
      }
      if (method === "PATCH") return updateMe(user, req.body, vulns, say);
    }
    if (method === "GET" && path === "/api/orders") {
      const mine = orders.filter((o) => o.userId === user.id);
      say("ok", `${mine.length} pedidos de ${user.username}, filtrados por dueño`, `${mine.length} orders for ${user.username}, filtered by owner`);
      return json(200, mine);
    }
    const orderMatch = /^\/api\/orders\/(\d+)$/.exec(path);
    if (method === "GET" && orderMatch) {
      const order = orders.find((o) => o.id === Number(orderMatch[1]));
      if (!order) {
        say("info", `Pedido ${orderMatch[1]} no existe: 404`, `Order ${orderMatch[1]} does not exist: 404`);
        return json(404, { error: "order not found" });
      }
      const owner = users.find((u) => u.id === order.userId)?.username ?? `id ${order.userId}`;
      if (order.userId !== user.id) {
        if (!vulns.has("bola")) {
          // Fixed: an order that is not yours looks exactly like one that does not exist.
          say("block", `Pedido ${order.id} es de ${owner}, no de ${user.username}: 404`, `Order ${order.id} belongs to ${owner}, not ${user.username}: 404`);
          return json(404, { error: "order not found" });
        }
        say("breach", `Pedido ${order.id} es de ${owner} y se le entregó a ${user.username} sin revisar el dueño`, `Order ${order.id} belongs to ${owner} and was handed to ${user.username} without an owner check`);
      } else {
        say("ok", `Pedido ${order.id} entregado a su dueño`, `Order ${order.id} sent to its owner`);
      }
      return json(200, order);
    }
    if (path === "/api/admin/users" && method === "GET") {
      if (!isAdmin(user, vulns, say)) return json(403, { error: "admin role required" });
      say(user.role === "admin" ? "ok" : "breach", `Lista de ${users.length} usuarios entregada a ${who}`, `List of ${users.length} users sent to ${who}`);
      return json(200, users.map(publicUser));
    }
    const delMatch = /^\/api\/admin\/users\/(\d+)$/.exec(path);
    if (method === "DELETE" && delMatch) {
      if (!isAdmin(user, vulns, say)) return json(403, { error: "admin role required" });
      const id = Number(delMatch[1]);
      const target = users.find((u) => u.id === id);
      if (!target) return json(404, { error: "user not found" });
      users = users.filter((u) => u.id !== id);
      orders = orders.filter((o) => o.userId !== id);
      say(user.role === "admin" ? "ok" : "breach", `Cuenta de ${target.username} eliminada por ${user.username}`, `${target.username}'s account deleted by ${user.username}`);
      return { status: 204, headers: {}, body: "" };
    }
    if (method === "GET" && path === "/api/wallet") {
      const balance = wallets.get(user.id) ?? 0;
      say("info", `Saldo de ${user.username}: $${balance.toLocaleString("es-CO")}`, `${user.username}'s balance: $${balance.toLocaleString("es-CO")}`);
      return json(200, { balance, currency: "COP" });
    }
    if (method === "POST" && path === "/api/coupons/redeem") return redeem(user, req.body, vulns, say);

    return json(404, { error: "route not found" });
  }

  async function login(body: string | undefined, vulns: Set<Vuln>, say: Say): Promise<Res> {
    const input = parseBody(body);
    if (!input || typeof input.username !== "string" || typeof input.password !== "string") {
      return json(400, { error: "username and password are required" });
    }
    const username = input.username.toLowerCase();
    const record = failures.get(username);

    if (!vulns.has("bruteforce") && record && record.lockedUntil > now()) {
      const retry = Math.ceil((record.lockedUntil - now()) / 1000);
      say("block", `Cuenta ${username} bloqueada: 429 sin revisar la contraseña`, `Account ${username} locked: 429 without checking the password`);
      return json(429, { error: "too many attempts, try again later", retryAfter: retry }, { "retry-after": String(retry) });
    }

    const user = users.find((u) => u.username === username);
    // Fixed: unknown users still cost one hash, so timing does not reveal who exists.
    const ok = user ? await checkPassword(input.password, user.passwordHash) : (await checkPassword(input.password, dummyHash), false);

    if (!user || !ok) {
      const next = { count: (record?.count ?? 0) + 1, lockedUntil: 0 };
      if (vulns.has("bruteforce")) {
        // VULNERABLE: unlimited attempts, and the message tells users apart.
        failures.set(username, next);
        say("info", `Contraseña incorrecta para ${username} (fallo ${next.count}, sin límite)`, `Wrong password for ${username} (failure ${next.count}, no limit)`);
        return json(401, { error: user ? "wrong password" : "user does not exist" });
      }
      if (next.count >= LOCKOUT.maxFailures) next.lockedUntil = now() + LOCKOUT.seconds * 1000;
      failures.set(username, next);
      if (next.lockedUntil) say("block", `${username}: ${next.count} fallos, cuenta bloqueada ${LOCKOUT.seconds} s`, `${username}: ${next.count} failures, account locked for ${LOCKOUT.seconds} s`);
      else say("info", `Contraseña incorrecta para ${username} (fallo ${next.count} de ${LOCKOUT.maxFailures})`, `Wrong password for ${username} (failure ${next.count} of ${LOCKOUT.maxFailures})`);
      return json(401, { error: "invalid credentials" });
    }

    const prior = record?.count ?? 0;
    failures.delete(username);
    if (prior >= LOCKOUT.maxFailures) {
      say("breach", `Login de ${username} tras ${prior} intentos fallidos seguidos`, `${username} signed in after ${prior} failed attempts in a row`);
    } else {
      say("ok", `Login correcto: ${username}`, `Signed in: ${username}`);
    }
    const iat = Math.floor(now() / 1000);
    const token = await signJwt({ sub: user.id, role: user.role, iat, exp: iat + 15 * 60 }, await keyPromise);
    return json(200, { token, tokenType: "Bearer", expiresIn: 900 });
  }

  async function authenticate(header: string | undefined, vulns: Set<Vuln>, say: Say): Promise<User | null> {
    if (!header || !/^Bearer\s+/i.test(header)) {
      say("block", "Sin token: 401", "No token: 401");
      return null;
    }
    const token = header.replace(/^Bearer\s+/i, "").trim();
    let alg = "";
    try {
      alg = String((parseJsonB64url(token.split(".")[0] ?? "") as { alg?: unknown }).alg);
    } catch {
      /* malformed header: verifyJwt rejects it */
    }
    const claims: Claims | null = await verifyJwt(token, await keyPromise, { trustAlgNone: vulns.has("jwt-none"), nowMs: now() });
    if (!claims) {
      if (alg.toLowerCase() === "none") say("block", "Token con alg «none»: rechazado, solo se acepta HS256", "Token with alg \"none\": rejected, only HS256 is accepted");
      else say("block", "Token con firma inválida o vencido: 401", "Token with a bad signature or expired: 401");
      return null;
    }
    const user = users.find((u) => u.id === Number(claims.sub)) ?? null;
    if (alg.toLowerCase() === "none" && user) {
      say("breach", `Token sin firma aceptado: el servidor cree que eres ${user.username} (${user.role})`, `Unsigned token accepted: the server believes you are ${user.username} (${user.role})`);
    }
    return user;
  }

  function isAdmin(user: User, vulns: Set<Vuln>, say: Say): boolean {
    if (user.role === "admin") return true;
    if (vulns.has("bfla")) {
      // VULNERABLE (bfla): any signed-in user reaches admin functions.
      say("breach", `Sin revisar el rol: ${user.username} (user) entra a una función de admin`, `No role check: ${user.username} (user) reaches an admin function`);
      return true;
    }
    say("block", `${user.username} no es admin: 403`, `${user.username} is not an admin: 403`);
    return false;
  }

  function updateMe(user: User, body: string | undefined, vulns: Set<Vuln>, say: Say): Res {
    const input = parseBody(body);
    if (!input) return json(400, { error: "JSON object expected" });
    const allowed = ["name", "email"];
    const extra = Object.keys(input).filter((k) => !allowed.includes(k));

    if (vulns.has("mass-assign")) {
      // VULNERABLE: copies whatever the client sends onto the stored user.
      // (Even the lab keeps id and prototype keys out, so the demo itself stays stable.)
      for (const [k, v] of Object.entries(input)) {
        if (k === "id" || k === "__proto__" || k === "constructor" || k === "prototype") continue;
        (user as unknown as Record<string, unknown>)[k] = v;
      }
      if (extra.length) {
        say("breach", `Campos copiados sin filtro: ${extra.join(", ")}. ${user.username} ahora tiene rol ${user.role}`, `Fields copied unfiltered: ${extra.join(", ")}. ${user.username} now has role ${user.role}`);
      } else {
        say("ok", `Perfil de ${user.username} actualizado`, `${user.username}'s profile updated`);
      }
      return json(200, { ...user });
    }

    // Fixed: an allowlist of fields a user may change about themselves.
    if (extra.length) {
      say("block", `Campo no permitido: ${extra.join(", ")} → 400, nada cambió`, `Field not allowed: ${extra.join(", ")} → 400, nothing changed`);
      return json(400, { error: "field not allowed", fields: extra });
    }
    for (const k of allowed) {
      const v = input[k];
      if (v === undefined) continue;
      if (typeof v !== "string" || v.length < 1 || v.length > 120) return json(400, { error: `invalid ${k}` });
      (user as unknown as Record<string, string>)[k] = v;
    }
    say("ok", `Perfil de ${user.username} actualizado (solo nombre y correo)`, `${user.username}'s profile updated (name and email only)`);
    return json(200, publicUser(user));
  }

  async function redeem(user: User, body: string | undefined, vulns: Set<Vuln>, say: Say): Promise<Res> {
    const input = parseBody(body);
    if (!input || input.code !== COUPON.code) return json(404, { error: "coupon not found" });

    if (vulns.has("race")) {
      // VULNERABLE: check, wait for "the database", then write. Parallel requests all pass the check.
      if (redeemed.has(user.id)) {
        say("block", "Cupón ya usado: 409", "Coupon already used: 409");
        return json(409, { error: "coupon already used" });
      }
      say("info", `Revisado: ${user.username} no ha usado el cupón. Esperando la base de datos…`, `Checked: ${user.username} has not used the coupon. Waiting for the database…`);
      await new Promise((r) => setTimeout(r, raceWindowMs));
      redeemed.add(user.id);
      wallets.set(user.id, (wallets.get(user.id) ?? 0) + COUPON.amount);
      couponCredits++;
      if (couponCredits > 1) say("breach", `Cupón acreditado otra vez (vez ${couponCredits})`, `Coupon credited again (time ${couponCredits})`);
      else say("ok", "Cupón acreditado", "Coupon credited");
      return json(200, { credited: COUPON.amount, balance: wallets.get(user.id) });
    }

    // Fixed: check and write happen in one step with no await between them,
    // the in-memory equivalent of a conditional UPDATE or a unique constraint.
    if (redeemed.has(user.id)) {
      say("block", "Cupón ya usado: 409", "Coupon already used: 409");
      return json(409, { error: "coupon already used" });
    }
    redeemed.add(user.id);
    wallets.set(user.id, (wallets.get(user.id) ?? 0) + COUPON.amount);
    couponCredits++;
    say("ok", "Cupón acreditado y marcado como usado en el mismo paso", "Coupon credited and marked as used in the same step");
    return json(200, { credited: COUPON.amount, balance: wallets.get(user.id) });
  }

  return {
    handle,
    reset: () => {
      ready = seed();
      return ready;
    },
  };
}

export type Range = ReturnType<typeof createRange>;

function publicUser(u: User) {
  return { id: u.id, username: u.username, name: u.name, email: u.email, role: u.role };
}

function json(status: number, value: unknown, extra: Record<string, string> = {}): Res {
  return { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra }, body: JSON.stringify(value) };
}

function lower(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

function parseVulns(value: string | undefined): Set<Vuln> {
  const out = new Set<Vuln>();
  for (const part of (value ?? "").split(",")) {
    const v = part.trim() as Vuln;
    if ((VULNS as readonly string[]).includes(v)) out.add(v);
  }
  return out;
}

function parseBody(body: string | undefined): Record<string, unknown> | null {
  if (!body) return null;
  try {
    const v: unknown = JSON.parse(body);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
