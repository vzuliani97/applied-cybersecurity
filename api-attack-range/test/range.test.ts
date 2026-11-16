import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ACCOUNTS, VULN_HEADER, createRange, type RangeEvent, type Req, type Res, type Vuln } from "../src/core/api.ts";
import { SCENARIOS } from "../src/core/scenarios.ts";

// Low iteration count keeps the suite fast; the hashing code path is the same.
const fresh = () => createRange({ pbkdf2Iterations: 1_000, raceWindowMs: 15 });

function ctxFor(range: ReturnType<typeof fresh>, vulns: Vuln[]) {
  const log: { req: Req; res: Res }[] = [];
  const events: RangeEvent[] = [];
  return {
    log,
    events,
    send: async (req: Req) => {
      const res = await range.handle({ ...req, headers: { ...req.headers, [VULN_HEADER]: vulns.join(",") } }, (e) => events.push(e));
      log.push({ req, res });
      return res;
    },
  };
}

describe("every scenario breaches when its flaw is on and is blocked when it is off", () => {
  for (const s of SCENARIOS) {
    it(`${s.owasp} ${s.id}: vulnerable`, async () => {
      const out = await s.run(ctxFor(fresh(), [s.vuln]));
      assert.equal(out.breached, true, out.headline.en);
    });
    it(`${s.owasp} ${s.id}: fixed`, async () => {
      const out = await s.run(ctxFor(fresh(), []));
      assert.equal(out.breached, false, out.headline.en);
    });
  }
});

describe("the server narrates what it decides", () => {
  for (const s of SCENARIOS) {
    it(`${s.id}: reports a breach when vulnerable and a block when fixed`, async () => {
      const v = ctxFor(fresh(), [s.vuln]);
      await s.run(v);
      assert.ok(v.events.some((e) => e.level === "breach"), "no breach event");
      const f = ctxFor(fresh(), []);
      await s.run(f);
      assert.ok(!f.events.some((e) => e.level === "breach"), "breach event while fixed");
      assert.ok(f.events.some((e) => e.level === "block"), "no block event");
    });
  }

  it("shows the role change and the deleted account in the data snapshot", async () => {
    const r = fresh();
    const m = ctxFor(r, ["mass-assign"]);
    await SCENARIOS.find((x) => x.id === "mass-assign")!.run(m);
    assert.equal(m.events.at(-1)!.snapshot.users.find((u) => u.username === "lucia")!.role, "admin");
    const d = ctxFor(fresh(), ["bfla"]);
    await SCENARIOS.find((x) => x.id === "bfla")!.run(d);
    assert.ok(!d.events.at(-1)!.snapshot.users.some((u) => u.username === "mateo"));
  });
});

describe("one flaw never opens another", () => {
  for (const s of SCENARIOS) {
    it(`${s.id} stays blocked with every other flaw on`, async () => {
      const others = SCENARIOS.map((x) => x.vuln).filter((v) => v !== s.vuln);
      const out = await s.run(ctxFor(fresh(), others));
      assert.equal(out.breached, false, out.headline.en);
    });
  }
});

describe("fixed API still works for legitimate use", () => {
  const login = async (r: ReturnType<typeof fresh>, username: string, password: string) =>
    r.handle({ method: "POST", path: "/api/login", headers: {}, body: JSON.stringify({ username, password }) });

  it("lets Lucía read her own order and update her name", async () => {
    const r = fresh();
    const token = (JSON.parse((await login(r, "lucia", ACCOUNTS.lucia.password)).body) as { token: string }).token;
    const auth = { authorization: `Bearer ${token}` };
    assert.equal((await r.handle({ method: "GET", path: "/api/orders/1001", headers: auth })).status, 200);
    const upd = await r.handle({ method: "PATCH", path: "/api/users/me", headers: auth, body: JSON.stringify({ name: "Lucía R." }) });
    assert.equal(upd.status, 200);
    assert.equal((JSON.parse(upd.body) as { name: string }).name, "Lucía R.");
    assert.ok(!upd.body.includes("passwordHash"));
  });

  it("redeems the coupon once and answers 409 after", async () => {
    const r = fresh();
    const token = (JSON.parse((await login(r, "lucia", ACCOUNTS.lucia.password)).body) as { token: string }).token;
    const req = { method: "POST", path: "/api/coupons/redeem", headers: { authorization: `Bearer ${token}` }, body: '{"code":"BIENVENIDA"}' };
    assert.equal((await r.handle(req)).status, 200);
    assert.equal((await r.handle(req)).status, 409);
  });

  it("gives the same error for an unknown user and a wrong password", async () => {
    const r = fresh();
    const a = await login(r, "nobody", "x");
    const b = await login(r, "mateo", "x");
    assert.equal(a.status, 401);
    assert.equal(a.body, b.body);
  });

  it("unlocks the account once the lockout expires", async () => {
    let t = 1_000_000;
    const r = createRange({ pbkdf2Iterations: 1_000, now: () => t });
    for (let i = 0; i < 5; i++) await login(r, "mateo", "wrong");
    assert.equal((await login(r, "mateo", ACCOUNTS.mateo.password)).status, 429);
    t += 61_000;
    assert.equal((await login(r, "mateo", ACCOUNTS.mateo.password)).status, 200);
  });

  it("rejects a validly signed token after it expires", async () => {
    let t = 1_000_000_000;
    const r = createRange({ pbkdf2Iterations: 1_000, now: () => t });
    const token = (JSON.parse((await login(r, "lucia", ACCOUNTS.lucia.password)).body) as { token: string }).token;
    const me = () => r.handle({ method: "GET", path: "/api/users/me", headers: { authorization: `Bearer ${token}` } });
    assert.equal((await me()).status, 200);
    t += 16 * 60 * 1000;
    assert.equal((await me()).status, 401);
  });

  it("rejects a token whose signature was tampered with", async () => {
    const r = fresh();
    const token = (JSON.parse((await login(r, "lucia", ACCOUNTS.lucia.password)).body) as { token: string }).token;
    const [h, , s] = token.split(".");
    const forgedClaims = Buffer.from(JSON.stringify({ sub: 1, role: "admin", exp: 9_999_999_999 })).toString("base64url");
    const res = await r.handle({ method: "GET", path: "/api/admin/users", headers: { authorization: `Bearer ${h}.${forgedClaims}.${s}` } });
    assert.equal(res.status, 401);
  });

  it("ignores unknown lab switches", async () => {
    const r = fresh();
    const res = await r.handle({ method: "GET", path: "/api/admin/users", headers: { [VULN_HEADER]: "everything,sqli" } });
    assert.equal(res.status, 401);
  });
});
