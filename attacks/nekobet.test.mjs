// NekoBet: authentication, tenant isolation between stores, and the HMAC-signed partner and casino APIs.
import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import {
  decodeJwt,
  envOf,
  literal,
  login,
  PLACEHOLDER_JWT_SECRET,
  request,
  signedHeaders,
  signJwt,
  sql,
  tamperJwt,
  targets,
  uniqueKey,
  unsignedJwt,
} from './lib.mjs';

const { api, dir } = targets.nekobet;
const env = envOf(dir);
const root = api.replace(/\/api$/, ''); // signed paths start with /api
const PARTNER_KEY = 'pk_demo_tienda_centro';
const CASINO_SECRET = env.CASINO_PROVIDER_SECRET ?? 'demo-casino-provider-secret-change-me';
const db = (statement) => sql(dir, 'paypoint', 'paypoint', statement);

/** A user created for the test with the demo password, the way a client provisions test accounts. */
function provisionCashier(email, posId) {
  db(`INSERT INTO users (email, password_hash, role, pos_id)
      SELECT ${literal(email)}, password_hash, 'CASHIER', ${literal(posId)} FROM users WHERE email = 'cajero@paypoint.local'
      ON CONFLICT (email) DO UPDATE SET pos_id = EXCLUDED.pos_id`);
}

function partnerCall(method, path, { body, idempotencyKey, sendIdempotencyKey, timestamp, apiKey = PARTNER_KEY, sendRaw } = {}) {
  const raw = body ? JSON.stringify(body) : '';
  const headers = signedHeaders({ secret: env.DEMO_PARTNER_SECRET, method, path, raw, apiKey, idempotencyKey, timestamp });
  if (sendIdempotencyKey) headers['Idempotency-Key'] = sendIdempotencyKey;
  return request(root, method, path, { headers, raw: body ? (sendRaw ?? raw) : undefined });
}

const sale = (destination = '3001112233') => ({ productId: 1, amount: 1000, destination });

describe('NekoBet', () => {
  let admin;
  let cashierA;
  let cashierB;
  let posA;
  let posB;

  before(async () => {
    admin = await login(api, 'admin@paypoint.local', env.DEMO_PASSWORD);
    cashierA = await login(api, 'cajero@paypoint.local', env.DEMO_PASSWORD);
    posA = cashierA.user.posId;

    // Tenant B: a second store with its own cashier.
    const stores = await request(api, 'GET', '/pos', { token: admin.accessToken });
    posB =
      stores.json.find((pos) => pos.name === 'Escudo tienda B')?.id ??
      (await request(api, 'POST', '/pos', { token: admin.accessToken, body: { name: 'Escudo tienda B' } })).json.id;
    await request(api, 'POST', `/pos/${posB}/credits`, { token: admin.accessToken, body: { amount: 50_000, note: 'Escudo' } });
    provisionCashier('cajero.b@escudo.test', posB);
    cashierB = await login(api, 'cajero.b@escudo.test', env.DEMO_PASSWORD);
  });

  describe('authentication', () => {
    it('refuses every private route without a token', async () => {
      for (const path of ['/auth/me', '/pos', '/pos/me', '/sales', '/betting/bets', '/casino/games']) {
        assert.equal((await request(api, 'GET', path)).status, 401, path);
      }
    });

    it('refuses a token with "alg: none"', async () => {
      const token = unsignedJwt({ ...decodeJwt(cashierA.accessToken).payload, role: 'ADMIN' });
      assert.equal((await request(api, 'GET', '/pos', { token })).status, 401);
    });

    it('refuses a real token whose role was changed after signing', async () => {
      const token = tamperJwt(cashierA.accessToken, { role: 'ADMIN' });
      assert.equal((await request(api, 'GET', '/pos', { token })).status, 401);
    });

    it('refuses an admin token signed with the placeholder secret of .env.example (ESC-01)', async () => {
      const token = signJwt({ sub: '00000000-0000-4000-8000-000000000000', email: 'x@x.co', role: 'ADMIN', posId: null }, PLACEHOLDER_JWT_SECRET);
      assert.equal((await request(api, 'GET', '/pos', { token })).status, 401);
    });

    it('locks an email after 5 failed logins, even for the right password', async () => {
      const email = `${uniqueKey('lock')}@escudo.test`;
      provisionCashier(email, posB);
      for (let i = 0; i < 5; i += 1) {
        const wrong = await request(api, 'POST', '/auth/login', { body: { email, password: 'wrong-password' } });
        assert.equal(wrong.status, 401);
      }
      const right = await request(api, 'POST', '/auth/login', { body: { email, password: env.DEMO_PASSWORD } });
      assert.equal(right.status, 429);
      assert.equal(right.json.error.code, 'TOO_MANY_ATTEMPTS');
    });
  });

  describe('authorization between roles and stores', () => {
    it('keeps a cashier out of admin routes, including crediting its own store', async () => {
      const token = cashierA.accessToken;
      assert.equal((await request(api, 'GET', '/pos', { token })).status, 403);
      assert.equal((await request(api, 'POST', `/pos/${posA}/credits`, { token, body: { amount: 1_000_000 } })).status, 403);
      assert.equal((await request(api, 'GET', `/pos/${posB}/movements`, { token })).status, 403);
    });

    it("does not show one store's sale to another store's cashier (IDOR)", async () => {
      const created = await request(api, 'POST', '/sales', {
        token: cashierA.accessToken,
        body: sale(),
        headers: { 'Idempotency-Key': uniqueKey() },
      });
      assert.equal(created.status, 201);
      const id = created.json.data.id;

      const direct = await request(api, 'GET', `/sales/${id}`, { token: cashierB.accessToken });
      const filtered = await request(api, 'GET', `/sales?posId=${posA}`, { token: cashierB.accessToken });
      assert.equal(direct.status, 404);
      assert.equal(filtered.status, 200);
      assert.ok(filtered.json.every((row) => row.posId === posB), 'the posId filter is ignored for cashiers');
    });

    it('does not let a cashier sell on behalf of another store by naming it in the body', async () => {
      const response = await request(api, 'POST', '/sales', {
        token: cashierB.accessToken,
        body: { ...sale(), posId: posA },
        headers: { 'Idempotency-Key': uniqueKey() },
      });
      assert.equal(response.status, 400);
    });

    it("does not show another store's sale to a partner", async () => {
      const created = await request(api, 'POST', '/sales', {
        token: cashierB.accessToken,
        body: sale(),
        headers: { 'Idempotency-Key': uniqueKey() },
      });
      const path = `/api/partner/v1/sales/${created.json.data.id}`;
      assert.equal((await partnerCall('GET', path)).status, 404);
    });
  });

  describe('signed partner API', () => {
    const balance = async () => (await partnerCall('GET', '/api/partner/v1/balance')).json.balance;

    it('answers a correctly signed call (control)', async () => {
      const response = await partnerCall('GET', '/api/partner/v1/balance');
      assert.equal(response.status, 200);
      assert.equal(response.json.posId, posA);
    });

    it('refuses a body changed after signing', async () => {
      const response = await partnerCall('POST', '/api/partner/v1/sales', {
        body: sale(),
        idempotencyKey: uniqueKey(),
        sendRaw: JSON.stringify({ ...sale(), amount: 90_000 }),
      });
      assert.equal(response.status, 401);
      assert.equal(response.json.error.code, 'INVALID_SIGNATURE');
    });

    it('refuses timestamps outside the 5-minute window, in the past or the future', async () => {
      const now = Math.floor(Date.now() / 1000);
      for (const timestamp of [now - 301, now + 301]) {
        const response = await partnerCall('GET', '/api/partner/v1/balance', { timestamp });
        assert.equal(response.json.error.code, 'STALE_TIMESTAMP');
      }
    });

    it('answers an unknown key exactly like a bad signature', async () => {
      const response = await partnerCall('GET', '/api/partner/v1/balance', { apiKey: 'pk_does_not_exist' });
      assert.equal(response.status, 401);
      assert.equal(response.json.error.code, 'INVALID_SIGNATURE');
    });

    it('does not charge a captured sale twice when it is replayed under a new Idempotency-Key (ESC-02)', async () => {
      const before = await balance();
      const idempotencyKey = uniqueKey();
      const original = await partnerCall('POST', '/api/partner/v1/sales', { body: sale(), idempotencyKey });
      const replayNewKey = await partnerCall('POST', '/api/partner/v1/sales', { body: sale(), idempotencyKey, sendIdempotencyKey: uniqueKey() });
      const replaySameKey = await partnerCall('POST', '/api/partner/v1/sales', { body: sale(), idempotencyKey });

      assert.equal(original.status, 201);
      assert.equal(replayNewKey.status, 401, 'a replay under a new key created another sale');
      assert.equal(replaySameKey.status, 200);
      assert.equal(replaySameKey.json.data.id, original.json.data.id);
      assert.equal(await balance(), before - 1000);
    });
  });

  describe('casino wallet callbacks', () => {
    it('applies a replayed debit once', async () => {
      const path = '/api/casino/wallet/debit';
      const raw = JSON.stringify({ posId: posB, providerTxId: uniqueKey('tx'), roundId: uniqueKey('round'), gameCode: 'escudo-slot', amount: 700 });
      const call = () => request(root, 'POST', path, { raw, headers: signedHeaders({ secret: CASINO_SECRET, method: 'POST', path, raw }) });

      const first = await call();
      const replay = await call();
      assert.equal(first.json.status, 'APPLIED');
      assert.equal(replay.json.status, 'ALREADY_APPLIED');
      assert.equal(replay.json.balance, first.json.balance);
    });

    it('refuses a callback signed with another secret', async () => {
      const path = '/api/casino/wallet/credit';
      const raw = JSON.stringify({ posId: posB, providerTxId: uniqueKey('tx'), roundId: uniqueKey('round'), gameCode: 'escudo-slot', amount: 1_000_000 });
      const response = await request(root, 'POST', path, { raw, headers: signedHeaders({ secret: 'not-the-provider-secret', method: 'POST', path, raw }) });
      assert.equal(response.status, 401);
    });
  });
});
