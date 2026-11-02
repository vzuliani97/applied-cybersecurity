// Yamesi: authentication, the seller/admin boundary, data a seller should not get, and photo uploads.
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  decodeJwt,
  envOf,
  jpegHasGps,
  jpegWithGps,
  literal,
  login,
  PLACEHOLDER_JWT_SECRET,
  request,
  signJwt,
  sql,
  tamperJwt,
  targets,
  uniqueKey,
  unsignedJwt,
} from './lib.mjs';

const { api, dir } = targets.yamesi;
const env = envOf(dir);
const db = (statement) => sql(dir, 'yamesi', 'yamesi', statement);

function provisionSeller(email) {
  db(`INSERT INTO users (email, name, password_hash, role)
      SELECT ${literal(email)}, 'Escudo', password_hash, 'SELLER' FROM users WHERE email = 'vendedor@yamesi.local'
      ON CONFLICT (email) DO NOTHING`);
}

const download = async (url) => {
  const response = await fetch(url);
  return { bytes: Buffer.from(await response.arrayBuffer()), headers: response.headers };
};

describe('Yamesi', () => {
  let admin;
  let seller;

  before(async () => {
    admin = (await login(api, 'admin@yamesi.local', env.DEMO_PASSWORD)).accessToken;
    seller = (await login(api, 'vendedor@yamesi.local', env.DEMO_PASSWORD)).accessToken;
  });

  describe('authentication', () => {
    it('refuses every private route without a token', async () => {
      for (const path of ['/auth/me', '/pieces', '/lots', '/invoices', '/expenses', '/closings/today', '/reports/margins', '/audit']) {
        assert.equal((await request(api, 'GET', path)).status, 401, path);
      }
    });

    it('refuses a token with "alg: none"', async () => {
      const token = unsignedJwt({ ...decodeJwt(seller).payload, role: 'ADMIN' });
      assert.equal((await request(api, 'GET', '/reports/margins', { token })).status, 401);
    });

    it('refuses a real token whose role was changed after signing', async () => {
      const token = tamperJwt(seller, { role: 'ADMIN' });
      assert.equal((await request(api, 'GET', '/reports/margins', { token })).status, 401);
    });

    it('refuses an admin token signed with the placeholder secret of .env.example (ESC-01)', async () => {
      const token = signJwt({ sub: '00000000-0000-4000-8000-000000000000', email: 'x@x.co', name: 'X', role: 'ADMIN' }, PLACEHOLDER_JWT_SECRET);
      assert.equal((await request(api, 'GET', '/reports/margins', { token })).status, 401);
    });

    it('locks an email after 5 failed logins, even for the right password', async () => {
      const email = `${uniqueKey('lock')}@escudo.test`;
      provisionSeller(email);
      for (let i = 0; i < 5; i += 1) {
        const wrong = await request(api, 'POST', '/auth/login', { body: { email, password: 'wrong-password' } });
        assert.equal(wrong.status, 401);
      }
      const right = await request(api, 'POST', '/auth/login', { body: { email, password: env.DEMO_PASSWORD } });
      assert.equal(right.status, 429);
    });
  });

  describe('seller and admin boundary', () => {
    it('keeps a seller out of every admin action', async () => {
      const piece = (await request(api, 'GET', '/pieces?status=IN_STOCK', { token: seller })).json[0];
      const attempts = [
        ['GET', '/reports/margins'],
        ['GET', '/reports/gold-inventory'],
        ['GET', '/audit'],
        ['POST', '/lots', { karat: 18, supplier: 'X', grams: 1, costPerGram: 1, purchasedOn: '2026-11-02' }],
        ['PATCH', `/pieces/${piece.id}`, { price: 1 }],
        ['POST', '/closings', { countedCash: 0 }],
        ['POST', '/assistant/ask', { question: '¿Cuánto vendimos hoy?' }],
      ];
      for (const [method, path, body] of attempts) {
        assert.equal((await request(api, method, path, { token: seller, body })).status, 403, `${method} ${path}`);
      }
    });

    it('does not send a seller the costs behind the admin-only margin (ESC-05)', async () => {
      const pieces = await request(api, 'GET', '/pieces', { token: seller });
      const lots = await request(api, 'GET', '/lots', { token: seller });
      assert.ok(pieces.json.length > 0 && lots.json.length > 0);
      assert.ok(pieces.json.every((piece) => !('laborCost' in piece)), 'pieces carry laborCost');
      assert.ok(lots.json.every((lot) => !('costPerGram' in lot)), 'lots carry costPerGram');
    });

    it('still sends the costs to an admin', async () => {
      const lots = await request(api, 'GET', '/lots', { token: admin });
      assert.equal(typeof lots.json[0].costPerGram, 'number');
    });
  });

  describe('photo upload', () => {
    let piece;
    let original;

    const upload = (bytes, filename, type) => {
      const form = new FormData();
      form.append('image', new Blob([bytes], { type }), filename);
      return request(api, 'PUT', `/pieces/${piece.id}/photo`, { token: admin, raw: form });
    };
    const currentPhoto = async () => (await request(api, 'GET', `/pieces/${piece.id}`, { token: admin })).json.imageUrl;

    before(async () => {
      piece = (await request(api, 'GET', '/pieces?status=IN_STOCK', { token: admin })).json.find((p) => p.imageUrl);
      original = (await download(piece.imageUrl)).bytes;
    });

    after(async () => {
      // Put the catalog photo back.
      await upload(original, 'original.jpg', 'image/jpeg');
    });

    it('refuses files that only claim to be images, and keeps the current photo', async () => {
      const before = await currentPhoto();
      const fakes = [
        [Buffer.from('<?php system($_GET["c"]); ?> padding'), 'shell.jpg', 'image/jpeg'],
        [Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), 'logo.svg', 'image/svg+xml'],
        [Buffer.from('%PDF-1.7 not an image at all'), 'doc.png', 'image/png'],
      ];
      for (const [bytes, filename, type] of fakes) {
        const response = await upload(bytes, filename, type);
        assert.equal(response.status, 400, filename);
        assert.equal(response.json.error.code, 'INVALID_IMAGE');
      }
      assert.equal(new URL(await currentPhoto()).pathname, new URL(before).pathname);
    });

    it('refuses a file that starts like a JPEG and carries HTML (ESC-06)', async () => {
      const polyglot = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.from('<html><script>alert(document.domain)</script></html>')]);
      const response = await upload(polyglot, 'photo.html', 'text/html');
      assert.equal(response.status, 400);
    });

    it('refuses a file over 2 MiB', async () => {
      const big = Buffer.concat([original.subarray(0, 3), Buffer.alloc(2 * 1024 * 1024)]);
      assert.equal((await upload(big, 'big.jpg', 'image/jpeg')).status, 413);
    });

    it('stores a phone photo without its GPS coordinates (ESC-04)', async () => {
      const fromPhone = jpegWithGps(original);
      assert.ok(jpegHasGps(fromPhone));

      const response = await upload(fromPhone, 'IMG_0001.jpg', 'image/jpeg');
      assert.equal(response.status, 200);
      const stored = await download(response.json.imageUrl);
      assert.equal(stored.headers.get('content-type'), 'image/jpeg');
      assert.equal(jpegHasGps(stored.bytes), false, 'the stored photo still carries GPS');
    });
  });
});
