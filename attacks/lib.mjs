// Helpers shared by the attack suites: targets, HTTP, JWT forging, HMAC signing and test fixtures.
// Node's standard library only, so the suite runs anywhere Node 24 runs.
import { execFileSync } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const here = import.meta.dirname;

export const targets = {
  nekobet: {
    api: process.env.NEKOBET_API ?? 'http://localhost:8081/api',
    dir: resolve(process.env.NEKOBET_DIR ?? `${here}/../../nekobet`),
  },
  yamesi: {
    api: process.env.YAMESI_API ?? 'http://localhost:8083/api',
    dir: resolve(process.env.YAMESI_DIR ?? `${here}/../../yamesi`),
  },
};

/** Values from a target's .env file: the credentials a client hands over for a gray-box test. */
export function envOf(dir) {
  const values = {};
  for (const line of readFileSync(`${dir}/.env`, 'utf8').split('\n')) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (match) values[match[1]] = match[2];
  }
  return values;
}

/** The JWT secret published in both repositories' .env.example. */
export const PLACEHOLDER_JWT_SECRET = 'replace-with-output-of-openssl-rand-hex-32';

export async function request(base, method, path, { token, body, headers = {}, raw } = {}) {
  const init = { method, headers: { ...headers } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (raw !== undefined) {
    init.body = raw;
  } else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }
  const response = await fetch(base + path, init);
  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: response.status, headers: response.headers, json, text };
}

export async function login(base, email, password) {
  const response = await request(base, 'POST', '/auth/login', { body: { email, password } });
  if (response.status !== 200) throw new Error(`login ${email}: ${response.status} ${response.text}`);
  return response.json;
}

export function uniqueKey(prefix = 'escudo') {
  return `${prefix}-${randomBytes(8).toString('hex')}`;
}

// --- JWT -------------------------------------------------------------------------------------

const b64url = (data) => Buffer.from(data).toString('base64url');

export function decodeJwt(token) {
  const [header, payload] = token.split('.');
  return { header: JSON.parse(Buffer.from(header, 'base64url')), payload: JSON.parse(Buffer.from(payload, 'base64url')) };
}

/** A token signed with HS256 and the given secret. */
export function signJwt(payload, secret) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ iat: now, exp: now + 600, ...payload }));
  const signature = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${signature}`;
}

/** The classic "alg: none" token: no signature at all. */
export function unsignedJwt(payload) {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.`;
}

/** Changes claims in a real token but keeps its original signature. */
export function tamperJwt(token, changes) {
  const [head, , signature] = token.split('.');
  const payload = { ...decodeJwt(token).payload, ...changes };
  return `${head}.${b64url(JSON.stringify(payload))}.${signature}`;
}

// --- HMAC requests (NekoBet partner API and casino wallet) -----------------------------------

/**
 * Builds the headers of a signed call. The string to sign is
 *   <unix seconds>\n<METHOD>\n<path with query>\n<sha256 hex of the raw body>\n<Idempotency-Key or empty>
 * (the last line was added by the fix for ESC-02).
 */
export function signedHeaders({ secret, method, path, raw = '', apiKey, idempotencyKey, timestamp }) {
  const ts = String(timestamp ?? Math.floor(Date.now() / 1000));
  const bodyHash = createHash('sha256').update(raw).digest('hex');
  const stringToSign = [ts, method, path, bodyHash, idempotencyKey ?? ''].join('\n');
  const headers = {
    'X-Timestamp': ts,
    'X-Signature': createHmac('sha256', secret).update(stringToSign).digest('hex'),
  };
  if (apiKey) headers['X-Api-Key'] = apiKey;
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  if (raw) headers['Content-Type'] = 'application/json';
  return headers;
}

// --- Fixtures --------------------------------------------------------------------------------

/** Runs SQL in a target's PostgreSQL container and returns the output rows. */
export function sql(dir, user, database, statement) {
  return execFileSync(
    'docker',
    ['compose', '--project-directory', dir, 'exec', '-T', 'postgres', 'psql', '-U', user, '-d', database, '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', statement],
    { encoding: 'utf8' },
  ).trim();
}

/** A literal for SQL built from values the suite itself generates (never from responses). */
export const literal = (value) => `'${String(value).replaceAll("'", "''")}'`;

/**
 * A JPEG that carries EXIF with GPS coordinates, the way a phone photo does: the real image data
 * comes from `base` and an APP1 segment is inserted after the SOI marker.
 * IFD0 has Orientation (6 = rotate 90°) and a pointer to a GPS IFD with latitude 6°15'N.
 */
export function jpegWithGps(base) {
  const tiff = Buffer.alloc(78);
  tiff.write('MM', 0, 'latin1'); // big endian
  tiff.writeUInt16BE(42, 2);
  tiff.writeUInt32BE(8, 4); // IFD0 offset
  // IFD0: 2 entries.
  tiff.writeUInt16BE(2, 8);
  tiff.writeUInt16BE(0x0112, 10); // Orientation, SHORT, 1, value 6
  tiff.writeUInt16BE(3, 12);
  tiff.writeUInt32BE(1, 14);
  tiff.writeUInt16BE(6, 18);
  tiff.writeUInt16BE(0x8825, 22); // GPSInfo, LONG, 1, offset 38
  tiff.writeUInt16BE(4, 24);
  tiff.writeUInt32BE(1, 26);
  tiff.writeUInt32BE(38, 30);
  tiff.writeUInt32BE(0, 34); // no next IFD
  // GPS IFD at 38: 2 entries.
  tiff.writeUInt16BE(2, 38);
  tiff.writeUInt16BE(0x0001, 40); // GPSLatitudeRef, ASCII, 2, "N"
  tiff.writeUInt16BE(2, 42);
  tiff.writeUInt32BE(2, 44);
  tiff.write('N\0', 48, 'latin1');
  tiff.writeUInt16BE(0x0002, 52); // GPSLatitude, RATIONAL, 3, offset 70
  tiff.writeUInt16BE(5, 54);
  tiff.writeUInt32BE(3, 56);
  tiff.writeUInt32BE(70, 60);
  tiff.writeUInt32BE(0, 64); // no next IFD
  // Only the degrees fit in the remaining bytes; that is enough to be a GPS tag.
  const rationals = Buffer.alloc(24);
  rationals.writeUInt32BE(6, 0);
  rationals.writeUInt32BE(1, 4);
  rationals.writeUInt32BE(15, 8);
  rationals.writeUInt32BE(1, 12);
  rationals.writeUInt32BE(0, 16);
  rationals.writeUInt32BE(1, 20);
  const exif = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff.subarray(0, 70), rationals]);
  const app1 = Buffer.alloc(4);
  app1.writeUInt16BE(0xffe1, 0);
  app1.writeUInt16BE(exif.length + 2, 2);
  return Buffer.concat([base.subarray(0, 2), app1, exif, base.subarray(2)]);
}

/** True if a JPEG still has an EXIF segment with a GPS pointer (tag 0x8825). */
export function jpegHasGps(buffer) {
  let offset = 2;
  while (offset + 4 <= buffer.length && buffer[offset] === 0xff) {
    const marker = buffer[offset + 1];
    if (marker === 0xda) break; // start of scan: no more metadata segments
    const length = buffer.readUInt16BE(offset + 2);
    const segment = buffer.subarray(offset + 4, offset + 2 + length);
    if (marker === 0xe1 && segment.subarray(0, 6).toString('latin1') === 'Exif\0\0') {
      const tiff = segment.subarray(6);
      const big = tiff.toString('latin1', 0, 2) === 'MM';
      const u16 = (at) => (big ? tiff.readUInt16BE(at) : tiff.readUInt16LE(at));
      const u32 = (at) => (big ? tiff.readUInt32BE(at) : tiff.readUInt32LE(at));
      const ifd = u32(4);
      for (let i = 0; i < u16(ifd); i += 1) {
        if (u16(ifd + 2 + i * 12) === 0x8825) return true;
      }
    }
    offset += 2 + length;
  }
  return false;
}
