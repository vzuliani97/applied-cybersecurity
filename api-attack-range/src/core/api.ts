import { randomBytes } from "./crypto.ts";
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

export function createRange(opts: RangeOptions = {}) {
  const raceWindowMs = opts.raceWindowMs ?? 40;
  const now = opts.now ?? (() => Date.now());
  const keyPromise = importHmacKey(randomBytes(32));

  let users: User[] = [];
  let orders: Order[] = [];
  let wallets = new Map<number, number>();
  let redeemed = new Set<number>();
  let failures = new Map<string, { count: number; lockedUntil: number }>();
  let dummyHash = "";

  async function seed(): Promise<void> {
    const it = opts.pbkdf2Iterations;
    const adminPassword = crypto.randomUUID();
    const [a, l, m, d] = await Promise.all([
      hashPassword(adminPassword, it),
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
    failures = new Map();
    dummyHash = d;
  }

  let ready = seed();

  async function handle(req: Req): Promise<Res> {
    await ready;
    try {
      return await route(req);
    } catch {
      return json(500, { error: "internal error" });
    }
  }

  async function route(req: Req): Promise<Res> {
    const headers = lower(req.headers);
    const vulns = parseVulns(headers[VULN_HEADER]);
    const method = req.method.toUpperCase();
    const path = req.path.split("?")[0]!.replace(/\/+$/, "") || "/";

    if (method === "POST" && path === "/api/_reset") {
      ready = seed();
      await ready;
      return json(200, { reset: true });
    }
    if (method === "POST" && path === "/api/login") return login(req.body, vulns);

    const user = await authenticate(headers.authorization, vulns);
    if (!user) return json(401, { error: "authentication required" });

    if (path === "/api/users/me") {
      if (method === "GET") return json(200, vulns.has("mass-assign") ? { ...user } : publicUser(user));
      if (method === "PATCH") return updateMe(user, req.body, vulns);
    }
    if (method === "GET" && path === "/api/orders") {
      return json(200, orders.filter((o) => o.userId === user.id));
    }
    const orderMatch = /^\/api\/orders\/(\d+)$/.exec(path);
    if (method === "GET" && orderMatch) {
      const order = orders.find((o) => o.id === Number(orderMatch[1]));
      // Fixed: an order that is not yours looks exactly like one that does not exist.
      if (!order || (!vulns.has("bola") && order.userId !== user.id)) return json(404, { error: "order not found" });
      return json(200, order);
    }
    if (path === "/api/admin/users" && method === "GET") {
      if (!isAdmin(user, vulns)) return json(403, { error: "admin role required" });
      return json(200, users.map(publicUser));
    }
    const delMatch = /^\/api\/admin\/users\/(\d+)$/.exec(path);
    if (method === "DELETE" && delMatch) {
      if (!isAdmin(user, vulns)) return json(403, { error: "admin role required" });
      const id = Number(delMatch[1]);
      if (!users.some((u) => u.id === id)) return json(404, { error: "user not found" });
      users = users.filter((u) => u.id !== id);
      orders = orders.filter((o) => o.userId !== id);
      return { status: 204, headers: {}, body: "" };
    }
    if (method === "GET" && path === "/api/wallet") {
      return json(200, { balance: wallets.get(user.id) ?? 0, currency: "COP" });
    }
    if (method === "POST" && path === "/api/coupons/redeem") return redeem(user, req.body, vulns);

    return json(404, { error: "route not found" });
  }

  async function login(body: string | undefined, vulns: Set<Vuln>): Promise<Res> {
    const input = parseBody(body);
    if (!input || typeof input.username !== "string" || typeof input.password !== "string") {
      return json(400, { error: "username and password are required" });
    }
    const username = input.username.toLowerCase();
    const record = failures.get(username);

    if (!vulns.has("bruteforce") && record && record.lockedUntil > now()) {
      const retry = Math.ceil((record.lockedUntil - now()) / 1000);
      return json(429, { error: "too many attempts, try again later", retryAfter: retry }, { "retry-after": String(retry) });
    }

    const user = users.find((u) => u.username === username);
    // Fixed: unknown users still cost one hash, so timing does not reveal who exists.
    const ok = user ? await checkPassword(input.password, user.passwordHash) : (await checkPassword(input.password, dummyHash), false);

    if (!user || !ok) {
      if (vulns.has("bruteforce")) {
        // VULNERABLE: unlimited attempts, and the message tells users apart.
        return json(401, { error: user ? "wrong password" : "user does not exist" });
      }
      const next = { count: (record?.count ?? 0) + 1, lockedUntil: 0 };
      if (next.count >= LOCKOUT.maxFailures) next.lockedUntil = now() + LOCKOUT.seconds * 1000;
      failures.set(username, next);
      return json(401, { error: "invalid credentials" });
    }

    failures.delete(username);
    const iat = Math.floor(now() / 1000);
    const token = await signJwt({ sub: user.id, role: user.role, iat, exp: iat + 15 * 60 }, await keyPromise);
    return json(200, { token, tokenType: "Bearer", expiresIn: 900 });
  }

  async function authenticate(header: string | undefined, vulns: Set<Vuln>): Promise<User | null> {
    if (!header || !/^Bearer\s+/i.test(header)) return null;
    const claims: Claims | null = await verifyJwt(header.replace(/^Bearer\s+/i, "").trim(), await keyPromise, {
      trustAlgNone: vulns.has("jwt-none"),
      nowMs: now(),
    });
    if (!claims) return null;
    return users.find((u) => u.id === Number(claims.sub)) ?? null;
  }

  function isAdmin(user: User, vulns: Set<Vuln>): boolean {
    // VULNERABLE (bfla): any signed-in user reaches admin functions.
    return vulns.has("bfla") || user.role === "admin";
  }

  function updateMe(user: User, body: string | undefined, vulns: Set<Vuln>): Res {
    const input = parseBody(body);
    if (!input) return json(400, { error: "JSON object expected" });

    if (vulns.has("mass-assign")) {
      // VULNERABLE: copies whatever the client sends onto the stored user.
      // (Even the lab keeps id and prototype keys out, so the demo itself stays stable.)
      for (const [k, v] of Object.entries(input)) {
        if (k === "id" || k === "__proto__" || k === "constructor" || k === "prototype") continue;
        (user as unknown as Record<string, unknown>)[k] = v;
      }
      return json(200, { ...user });
    }

    // Fixed: an allowlist of fields a user may change about themselves.
    const allowed = ["name", "email"];
    const extra = Object.keys(input).filter((k) => !allowed.includes(k));
    if (extra.length) return json(400, { error: "field not allowed", fields: extra });
    for (const k of allowed) {
      const v = input[k];
      if (v === undefined) continue;
      if (typeof v !== "string" || v.length < 1 || v.length > 120) return json(400, { error: `invalid ${k}` });
      (user as unknown as Record<string, string>)[k] = v;
    }
    return json(200, publicUser(user));
  }

  async function redeem(user: User, body: string | undefined, vulns: Set<Vuln>): Promise<Res> {
    const input = parseBody(body);
    if (!input || input.code !== COUPON.code) return json(404, { error: "coupon not found" });

    if (vulns.has("race")) {
      // VULNERABLE: check, wait for "the database", then write. Parallel requests all pass the check.
      if (redeemed.has(user.id)) return json(409, { error: "coupon already used" });
      await new Promise((r) => setTimeout(r, raceWindowMs));
      redeemed.add(user.id);
      wallets.set(user.id, (wallets.get(user.id) ?? 0) + COUPON.amount);
      return json(200, { credited: COUPON.amount, balance: wallets.get(user.id) });
    }

    // Fixed: check and write happen in one step with no await between them,
    // the in-memory equivalent of a conditional UPDATE or a unique constraint.
    if (redeemed.has(user.id)) return json(409, { error: "coupon already used" });
    redeemed.add(user.id);
    wallets.set(user.id, (wallets.get(user.id) ?? 0) + COUPON.amount);
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
