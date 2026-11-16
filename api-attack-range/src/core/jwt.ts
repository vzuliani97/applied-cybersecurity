import { b64url, fromB64url, jsonB64url, parseJsonB64url, utf8 } from "./crypto.ts";

export interface Claims {
  sub: number;
  role: string;
  iat?: number;
  exp?: number;
}

export function importHmacKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function signJwt(claims: Claims, key: CryptoKey): Promise<string> {
  const head = jsonB64url({ alg: "HS256", typ: "JWT" });
  const body = jsonB64url(claims);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(`${head}.${body}`)));
  return `${head}.${body}.${b64url(sig)}`;
}

/**
 * Returns the claims if the token is acceptable, or null.
 * With `trustAlgNone` the verifier believes the token's own header when it says
 * it is unsigned: the classic "alg: none" flaw (OWASP API2:2023).
 */
export async function verifyJwt(
  token: string,
  key: CryptoKey,
  opts: { trustAlgNone: boolean; nowMs: number },
): Promise<Claims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header: { alg?: unknown };
  let claims: Claims;
  try {
    header = parseJsonB64url(parts[0]!) as { alg?: unknown };
    claims = parseJsonB64url(parts[1]!) as Claims;
  } catch {
    return null;
  }
  if (typeof claims !== "object" || claims === null) return null;

  if (opts.trustAlgNone && String(header.alg).toLowerCase() === "none") {
    return claims; // VULNERABLE: no signature, no expiry check
  }

  // Fixed: the server decides the algorithm, never the token.
  if (header.alg !== "HS256") return null;
  let sig: Uint8Array<ArrayBuffer>;
  try {
    sig = fromB64url(parts[2]!);
  } catch {
    return null;
  }
  const ok = await crypto.subtle.verify("HMAC", key, sig, utf8(`${parts[0]}.${parts[1]}`));
  if (!ok) return null;
  if (typeof claims.exp !== "number" || claims.exp * 1000 <= opts.nowMs) return null;
  return claims;
}
