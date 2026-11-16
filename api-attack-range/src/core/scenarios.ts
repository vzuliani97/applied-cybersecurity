import { ACCOUNTS, COUPON, LOCKOUT, type Req, type Res, type Vuln } from "./api.ts";
import { jsonB64url } from "./crypto.ts";

export type L = { es: string; en: string };

export interface RunCtx {
  /** Sends a request. `key` marks the exchange that decides the outcome. */
  send(req: Req, opts?: { key?: boolean }): Promise<Res>;
  progress?(done: number, total: number): void;
}

export interface Outcome {
  breached: boolean;
  headline: L;
  detail: L;
}

export interface Scenario {
  id: string;
  vuln: Vuln;
  owasp: string;
  title: L;
  tagline: L;
  story: L;
  fix: L;
  code: { vulnerable: string; fixed: string };
  run(ctx: RunCtx): Promise<Outcome>;
}

const JSON_HDR = { "Content-Type": "application/json" };

async function login(ctx: RunCtx, username: keyof typeof ACCOUNTS, password: string): Promise<string> {
  const res = await ctx.send({ method: "POST", path: "/api/login", headers: JSON_HDR, body: JSON.stringify({ username, password }) });
  if (res.status !== 200) throw new Error(`login failed (${res.status})`);
  return (JSON.parse(res.body) as { token: string }).token;
}

const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });
const read = (res: Res): Record<string, unknown> => {
  try {
    return JSON.parse(res.body) as Record<string, unknown>;
  } catch {
    return {};
  }
};
const cop = (n: number) => "$" + n.toLocaleString("es-CO");

export const SCENARIOS: Scenario[] = [
  {
    id: "bola",
    vuln: "bola",
    owasp: "API1:2023",
    title: { es: "Pedidos ajenos", en: "Someone else's orders" },
    tagline: { es: "Autorización rota a nivel de objeto (BOLA)", en: "Broken object level authorization (BOLA)" },
    story: {
      es: "Entras como Lucía y ves tus pedidos 1001 y 1002. ¿Qué pasa si pides el 1003, que es de Mateo?",
      en: "You sign in as Lucía and see your orders 1001 and 1002. What happens if you ask for 1003, which belongs to Mateo?",
    },
    fix: {
      es: "La consulta filtra por el dueño. Si el pedido no es tuyo, la respuesta es la misma que si no existiera (404), así ni siquiera confirma que existe.",
      en: "The lookup filters by owner. If the order is not yours, you get the same answer as if it did not exist (404), so it does not even confirm it exists.",
    },
    code: {
      vulnerable: `const order = orders.find((o) => o.id === id);\nif (!order) return json(404, { error: "order not found" });\nreturn json(200, order);`,
      fixed: `const order = orders.find((o) => o.id === id);\nif (!order || order.userId !== user.id)\n  return json(404, { error: "order not found" });\nreturn json(200, order);`,
    },
    async run(ctx) {
      const token = await login(ctx, "lucia", ACCOUNTS.lucia.password);
      await ctx.send({ method: "GET", path: "/api/orders", headers: bearer(token) });
      const res = await ctx.send({ method: "GET", path: "/api/orders/1003", headers: bearer(token) }, { key: true });
      const body = read(res);
      if (res.status === 200 && body.userId === ACCOUNTS.mateo.id) {
        return {
          breached: true,
          headline: { es: "Brecha: leíste el pedido de Mateo", en: "Breach: you read Mateo's order" },
          detail: {
            es: `Con la sesión de Lucía obtuviste la dirección de Mateo (${String(body.address)}) y su tarjeta. Bastó cambiar un número en la URL.`,
            en: `With Lucía's session you got Mateo's address (${String(body.address)}) and card. Changing one number in the URL was enough.`,
          },
        };
      }
      return {
        breached: false,
        headline: { es: "Bloqueado: 404, como si el pedido no existiera", en: "Blocked: 404, as if the order did not exist" },
        detail: {
          es: "La API no distingue entre «no es tuyo» y «no existe», así que tampoco puedes enumerar pedidos ajenos.",
          en: "The API does not tell \"not yours\" apart from \"does not exist\", so you cannot enumerate other people's orders either.",
        },
      };
    },
  },
  {
    id: "jwt-none",
    vuln: "jwt-none",
    owasp: "API2:2023",
    title: { es: "Token sin firma", en: "Unsigned token" },
    tagline: { es: "Autenticación rota: JWT con alg «none»", en: "Broken authentication: JWT with alg \"none\"" },
    story: {
      es: "No tienes cuenta. Armas a mano un JWT que dice «soy el usuario 1, admin» y en el encabezado pones alg: none, o sea, sin firma.",
      en: "You have no account. You hand-craft a JWT that says \"I am user 1, admin\" and set alg: none in its header, meaning no signature.",
    },
    fix: {
      es: "El servidor decide el algoritmo, no el token: solo acepta HS256, verifica la firma con la llave secreta y rechaza tokens vencidos.",
      en: "The server picks the algorithm, not the token: it only accepts HS256, checks the signature with the secret key and rejects expired tokens.",
    },
    code: {
      vulnerable: `if (header.alg.toLowerCase() === "none")\n  return claims; // se cree lo que diga el token`,
      fixed: `if (header.alg !== "HS256") return null;\nconst ok = await crypto.subtle.verify("HMAC", key, sig, data);\nif (!ok || claims.exp * 1000 <= now) return null;\nreturn claims;`,
    },
    async run(ctx) {
      const forged = `${jsonB64url({ alg: "none", typ: "JWT" })}.${jsonB64url({ sub: 1, role: "admin" })}.`;
      const res = await ctx.send({ method: "GET", path: "/api/admin/users", headers: bearer(forged) }, { key: true });
      if (res.status === 200) {
        const list = JSON.parse(res.body) as unknown[];
        return {
          breached: true,
          headline: { es: "Brecha: entraste como admin sin contraseña", en: "Breach: you got in as admin with no password" },
          detail: {
            es: `El servidor aceptó un token sin firma y te entregó la lista de ${list.length} usuarios del panel de administración.`,
            en: `The server accepted an unsigned token and handed you the admin list of ${list.length} users.`,
          },
        };
      }
      return {
        breached: false,
        headline: { es: "Bloqueado: 401, token rechazado", en: "Blocked: 401, token rejected" },
        detail: {
          es: "Sin una firma HS256 válida, el token no vale nada, diga lo que diga adentro.",
          en: "Without a valid HS256 signature the token is worthless, whatever it says inside.",
        },
      };
    },
  },
  {
    id: "mass-assign",
    vuln: "mass-assign",
    owasp: "API3:2023",
    title: { es: "Ascenso por formulario", en: "Promotion by form" },
    tagline: { es: "Asignación masiva de propiedades", en: "Mass assignment of properties" },
    story: {
      es: "El perfil permite cambiar tu nombre. Lucía manda su nombre nuevo y, de paso, un campo que el formulario no tiene: \"role\": \"admin\".",
      en: "The profile lets you change your name. Lucía sends her new name and, while at it, a field the form does not have: \"role\": \"admin\".",
    },
    fix: {
      es: "Una lista blanca de campos que un usuario puede cambiar de sí mismo (nombre y correo). Cualquier otro campo se rechaza con 400, y la respuesta nunca incluye el hash de la contraseña.",
      en: "An allowlist of fields users may change about themselves (name and email). Any other field is rejected with 400, and the response never includes the password hash.",
    },
    code: {
      vulnerable: `for (const [k, v] of Object.entries(input))\n  user[k] = v; // copia todo lo que manda el cliente\nreturn json(200, user);`,
      fixed: `const allowed = ["name", "email"];\nconst extra = Object.keys(input).filter((k) => !allowed.includes(k));\nif (extra.length) return json(400, { error: "field not allowed", fields: extra });\n// ...copia solo name y email\nreturn json(200, publicUser(user));`,
    },
    async run(ctx) {
      const token = await login(ctx, "lucia", ACCOUNTS.lucia.password);
      await ctx.send(
        { method: "PATCH", path: "/api/users/me", headers: { ...bearer(token), ...JSON_HDR }, body: JSON.stringify({ name: "Lucía R.", role: "admin" }) },
        { key: true },
      );
      const me = read(await ctx.send({ method: "GET", path: "/api/users/me", headers: bearer(token) }));
      if (me.role === "admin") {
        const leaked = typeof me.passwordHash === "string";
        return {
          breached: true,
          headline: { es: "Brecha: Lucía ahora es admin", en: "Breach: Lucía is now an admin" },
          detail: {
            es: "La API copió el campo role tal cual." + (leaked ? " Además, la respuesta expone el hash de su contraseña." : ""),
            en: "The API copied the role field as is." + (leaked ? " The response also exposes her password hash." : ""),
          },
        };
      }
      return {
        breached: false,
        headline: { es: "Bloqueado: 400, campo no permitido", en: "Blocked: 400, field not allowed" },
        detail: {
          es: "La API solo acepta nombre y correo; Lucía sigue siendo usuaria normal y su hash no sale en ninguna respuesta.",
          en: "The API only accepts name and email; Lucía stays a regular user and her hash never appears in any response.",
        },
      };
    },
  },
  {
    id: "bruteforce",
    vuln: "bruteforce",
    owasp: "API4:2023",
    title: { es: "Fuerza bruta", en: "Brute force" },
    tagline: { es: "Consumo de recursos sin límite en el login", en: "Unrestricted resource consumption on login" },
    story: {
      es: "Pruebas contra la cuenta de Mateo una lista de 25 contraseñas comunes, una tras otra, sin que nadie te frene.",
      en: "You try a list of 25 common passwords against Mateo's account, one after another, with nothing to stop you.",
    },
    fix: {
      es: `Tras ${LOCKOUT.maxFailures} intentos fallidos la cuenta se bloquea ${LOCKOUT.seconds} s y la API responde 429, aunque después llegue la contraseña correcta. El mensaje de error es el mismo exista o no el usuario.`,
      en: `After ${LOCKOUT.maxFailures} failed attempts the account locks for ${LOCKOUT.seconds} s and the API answers 429, even if the right password arrives later. The error message is the same whether or not the user exists.`,
    },
    code: {
      vulnerable: `if (!ok) return json(401, {\n  error: user ? "wrong password" : "user does not exist",\n});`,
      fixed: `if (record && record.lockedUntil > now())\n  return json(429, { error: "too many attempts" }, { "retry-after": "60" });\nif (!ok) {\n  record.count++;\n  if (record.count >= 5) record.lockedUntil = now() + 60_000;\n  return json(401, { error: "invalid credentials" });\n}`,
    },
    async run(ctx) {
      const total = WORDLIST.length;
      let lockedAt = 0;
      for (let i = 0; i < total; i++) {
        const isLast = WORDLIST[i] === ACCOUNTS.mateo.password;
        const res = await ctx.send(
          { method: "POST", path: "/api/login", headers: JSON_HDR, body: JSON.stringify({ username: "mateo", password: WORDLIST[i] }) },
          { key: isLast },
        );
        ctx.progress?.(i + 1, total);
        if (res.status === 429 && !lockedAt) lockedAt = i + 1;
        if (res.status === 200) {
          return {
            breached: true,
            headline: { es: `Brecha: contraseña de Mateo encontrada en el intento ${i + 1}`, en: `Breach: Mateo's password found on attempt ${i + 1}` },
            detail: {
              es: `Era «${WORDLIST[i]}». Nadie limitó los intentos y el token de Mateo quedó en tus manos.`,
              en: `It was "${WORDLIST[i]}". Nothing limited the attempts, and Mateo's token is now yours.`,
            },
          };
        }
      }
      return {
        breached: false,
        headline: { es: `Bloqueado: cuenta congelada desde el intento ${lockedAt}`, en: `Blocked: account frozen from attempt ${lockedAt}` },
        detail: {
          es: "La contraseña correcta llegó en el intento 20, pero ya la API respondía 429 a todo.",
          en: "The right password arrived on attempt 20, but by then the API answered 429 to everything.",
        },
      };
    },
  },
  {
    id: "bfla",
    vuln: "bfla",
    owasp: "API5:2023",
    title: { es: "Botón de admin escondido", en: "Hidden admin button" },
    tagline: { es: "Autorización rota a nivel de función (BFLA)", en: "Broken function level authorization (BFLA)" },
    story: {
      es: "La interfaz de Lucía no tiene botón para borrar usuarios. Pero la ruta DELETE /api/admin/users/:id existe, y la llamas directo.",
      en: "Lucía's interface has no button to delete users. But the route DELETE /api/admin/users/:id exists, and you call it directly.",
    },
    fix: {
      es: "Cada función de administración verifica el rol en el servidor. Esconder el botón en la interfaz no es un control de seguridad.",
      en: "Every admin function checks the role on the server. Hiding the button in the interface is not a security control.",
    },
    code: {
      vulnerable: `// cualquier usuario autenticado llega aquí\nusers = users.filter((u) => u.id !== id);\nreturn { status: 204 };`,
      fixed: `if (user.role !== "admin")\n  return json(403, { error: "admin role required" });\nusers = users.filter((u) => u.id !== id);\nreturn { status: 204 };`,
    },
    async run(ctx) {
      const token = await login(ctx, "lucia", ACCOUNTS.lucia.password);
      const res = await ctx.send({ method: "DELETE", path: "/api/admin/users/3", headers: bearer(token) }, { key: true });
      if (res.status === 204) {
        return {
          breached: true,
          headline: { es: "Brecha: Lucía borró la cuenta de Mateo", en: "Breach: Lucía deleted Mateo's account" },
          detail: {
            es: "Una usuaria normal ejecutó una función de administrador. La cuenta de Mateo y sus pedidos desaparecieron.",
            en: "A regular user ran an admin function. Mateo's account and his orders are gone.",
          },
        };
      }
      return {
        breached: false,
        headline: { es: "Bloqueado: 403, se requiere rol admin", en: "Blocked: 403, admin role required" },
        detail: { es: "El servidor revisa el rol en cada función, con o sin botón en la interfaz.", en: "The server checks the role on every function, button or no button." },
      };
    },
  },
  {
    id: "race",
    vuln: "race",
    owasp: "API6:2023",
    title: { es: "Cupón infinito", en: "Infinite coupon" },
    tagline: { es: "Flujo de negocio sensible: condición de carrera", en: "Sensitive business flow: race condition" },
    story: {
      es: `El cupón ${COUPON.code} da ${cop(COUPON.amount)} y es de un solo uso. Lucía lo canjea 20 veces al mismo tiempo.`,
      en: `Coupon ${COUPON.code} is worth ${cop(COUPON.amount)} and is single-use. Lucía redeems it 20 times at once.`,
    },
    fix: {
      es: "La verificación y el registro del canje ocurren en un solo paso, sin pausa entre ellos. En una base de datos es un UPDATE condicional o una restricción única, igual que en el saldo de NekoBet.",
      en: "Checking and recording the redemption happen in one step, with no gap between them. In a database that is a conditional UPDATE or a unique constraint, like the balance in NekoBet.",
    },
    code: {
      vulnerable: `if (redeemed.has(user.id)) return json(409, ...);\nawait db.write(); // ventana: otras peticiones pasan el if\nredeemed.add(user.id);\nbalance += 20_000;`,
      fixed: `if (redeemed.has(user.id)) return json(409, ...);\nredeemed.add(user.id); // mismo paso, sin await en medio\nbalance += 20_000;\n// SQL: UPDATE ... WHERE NOT redeemed RETURNING ...`,
    },
    async run(ctx) {
      const token = await login(ctx, "lucia", ACCOUNTS.lucia.password);
      const before = Number(read(await ctx.send({ method: "GET", path: "/api/wallet", headers: bearer(token) })).balance ?? 0);
      const n = 20;
      let done = 0;
      await Promise.all(
        Array.from({ length: n }, () =>
          ctx
            .send({ method: "POST", path: "/api/coupons/redeem", headers: { ...bearer(token), ...JSON_HDR }, body: JSON.stringify({ code: COUPON.code }) })
            .then(() => ctx.progress?.(++done, n)),
        ),
      );
      const after = Number(read(await ctx.send({ method: "GET", path: "/api/wallet", headers: bearer(token) }, { key: true })).balance ?? 0);
      const times = Math.round((after - before) / COUPON.amount);
      if (times > 1) {
        return {
          breached: true,
          headline: { es: `Brecha: el cupón se aplicó ${times} veces`, en: `Breach: the coupon was applied ${times} times` },
          detail: {
            es: `Un cupón de un solo uso dejó ${cop(after - before)} en el saldo de Lucía.`,
            en: `A single-use coupon put ${cop(after - before)} in Lucía's balance.`,
          },
        };
      }
      return {
        breached: false,
        headline: { es: "Bloqueado: se aplicó una sola vez", en: "Blocked: applied exactly once" },
        detail: {
          es: `De 20 peticiones simultáneas, una acreditó ${cop(COUPON.amount)} y las otras 19 recibieron 409.`,
          en: `Out of 20 simultaneous requests, one credited ${cop(COUPON.amount)} and the other 19 got 409.`,
        },
      };
    },
  },
];

/** 25 common passwords; Mateo's is number 20. */
export const WORDLIST = [
  "123456", "password", "12345678", "qwerty", "admin", "colombia", "medellin", "mateo", "mateo123", "iloveyou",
  "nacional", "medellin123", "abc123", "111111", "Medellin2026", "letmein", "sunshine", "medellin2025", "welcome", "medellin2026",
  "dragon", "football", "monkey", "000000", "password1",
];
