// Small helpers on top of Web Crypto, which exists both in Node 22+ and in a
// service worker, so the same API code runs on a server and in the browser.

const te = new TextEncoder();
const td = new TextDecoder();

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function jsonB64url(value: unknown): string {
  return b64url(te.encode(JSON.stringify(value)));
}

export function parseJsonB64url(part: string): unknown {
  return JSON.parse(td.decode(fromB64url(part)));
}

export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return te.encode(text);
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Compares two byte arrays without stopping at the first difference. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
