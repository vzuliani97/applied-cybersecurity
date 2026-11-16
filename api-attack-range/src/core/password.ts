import { b64url, fromB64url, randomBytes, timingSafeEqual, utf8 } from "./crypto.ts";

// OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256 with 600,000 iterations.
export const PBKDF2_ITERATIONS = 600_000;

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256);
  return new Uint8Array(bits);
}

export async function hashPassword(password: string, iterations = PBKDF2_ITERATIONS): Promise<string> {
  const salt = randomBytes(16);
  const hash = await derive(password, salt, iterations);
  return `pbkdf2-sha256$${iterations}$${b64url(salt)}$${b64url(hash)}`;
}

export async function checkPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iter, salt, hash] = stored.split("$");
  if (scheme !== "pbkdf2-sha256" || !iter || !salt || !hash) return false;
  const got = await derive(password, fromB64url(salt), Number(iter));
  return timingSafeEqual(got, fromB64url(hash));
}
