// Request signing in the shape of AWS Signature Version 4, simplified for the
// lab: the signature is an HMAC-SHA256 over the method, path, query and date,
// keyed with the secret access key. Real SigV4 derives a scoped signing key
// and canonicalises headers too; the point here is the same one AWS makes:
// whoever holds the secret can sign, so stolen credentials work from anywhere.
import { utf8 } from "./crypto.ts";

export interface Credentials {
  AccessKeyId: string;
  SecretAccessKey: string;
  Token: string;
}

export const ALGO = "AWS4-HMAC-SHA256";

const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export function stringToSign(method: string, path: string, query: string, amzDate: string): string {
  return [ALGO, amzDate, method.toUpperCase(), path, query].join("\n");
}

export async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8("AWS4" + secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, utf8(data)));
}

export function amzDate(d = new Date()): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

/** Headers an AWS SDK would add to a request signed with these credentials. */
export async function signedHeaders(creds: Credentials, method: string, path: string, query = ""): Promise<Record<string, string>> {
  const date = amzDate();
  const sig = await hmacHex(creds.SecretAccessKey, stringToSign(method, path, query, date));
  return {
    Authorization: `${ALGO} Credential=${creds.AccessKeyId}/${date.slice(0, 8)}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=${sig}`,
    "x-amz-date": date,
    "x-amz-security-token": creds.Token,
  };
}

export function parseAuthorization(h: string | undefined): { keyId: string; signature: string } | null {
  const m = /^AWS4-HMAC-SHA256 Credential=([A-Z0-9]+)\/[^,]+,\s*SignedHeaders=[^,]+,\s*Signature=([0-9a-f]{64})$/.exec(h ?? "");
  return m ? { keyId: m[1]!, signature: m[2]! } : null;
}
