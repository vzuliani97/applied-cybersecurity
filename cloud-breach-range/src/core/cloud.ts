// A tiny, simulated slice of AWS: one web app on an EC2 instance, the
// instance metadata service (IMDS), an IAM role, three S3 buckets, CloudTrail
// and GuardDuty with an automatic response. It is enough to replay the attack
// chain behind several real cloud breaches: SSRF in the app -> credentials
// from IMDS -> an over-privileged role -> data out of S3.
//
// Each defence is a switch. A switch that is off leaves that layer in the
// misconfigured state; everything else behaves the same.
import { randomBytes } from "./crypto.ts";
import { evaluate, type Context, type Decision, type Policy } from "./iam.ts";
import { hmacHex, parseAuthorization, stringToSign } from "./sign.ts";

export const CONTROLS = ["ssrf-allowlist", "imdsv2", "least-privilege", "vpce-only", "detect-respond"] as const;
export type Control = (typeof CONTROLS)[number];

/** Lab header: which defences are switched on for this request. Not part of any AWS API. */
export const CONTROL_HEADER = "x-range-controls";

export type L = { es: string; en: string };

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

export const ACCOUNT = "111122223333";
export const INSTANCE_ID = "i-0a1b2c3d4e5f60718";
export const ROLE = "shop-web-role";
export const VPCE = "vpce-0f2e4d6c8a1b3c5d7";
export const IMDS_HOST = "169.254.169.254";
/** Documentation address (TEST-NET-3): where the attacker's laptop appears to be. */
export const ATTACKER_IP = "203.0.113.66";
export const DATA_BUCKET = "acme-customer-exports";
export const DATA_KEY = "customers-2026-10.csv";
export const PREVIEW_ALLOWLIST = ["example.com", "cdn.acme-shop.example"];

export type Layer = "app" | "imds" | "iam" | "s3" | "trail" | "guardduty";

export interface TrailEntry {
  at: string;
  eventName: string;
  sourceIp: string;
  errorCode?: string;
}
export interface Finding {
  type: string;
  severity: "High";
  detail: L;
}
export interface Snapshot {
  credentialsLeaked: string | null;
  revoked: boolean;
  trail: TrailEntry[];
  findings: Finding[];
  exfiltrated: string[];
}
export interface CloudEvent {
  level: "info" | "ok" | "block" | "breach";
  layer: Layer;
  msg: L;
  at: number;
  snapshot: Snapshot;
}
/** What layers emit; the world adds the time and a snapshot. */
export type Emit = (e: Omit<CloudEvent, "at" | "snapshot">) => void;

// ---------- the misconfigured and the fixed policies ----------

/** The classic mistake: the web server's role can do anything in S3. */
export const ROLE_POLICY_BROAD: Policy = {
  name: "shop-web-role-policy",
  Statement: [{ Sid: "S3FullAccess", Effect: "Allow", Action: "s3:*", Resource: "*" }],
};

/** What the app actually needs: read its own images and styles. */
export const ROLE_POLICY_LEAST: Policy = {
  name: "shop-web-role-policy",
  Statement: [{ Sid: "ReadShopAssets", Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::acme-shop-assets/*" }],
};

/** Customer data can only be reached through the VPC endpoint, never from the internet. */
export const DATA_BUCKET_POLICY: Policy = {
  name: `${DATA_BUCKET}-bucket-policy`,
  Statement: [
    {
      Sid: "DenyOutsideVpcEndpoint",
      Effect: "Deny",
      Action: "s3:*",
      Resource: [`arn:aws:s3:::${DATA_BUCKET}`, `arn:aws:s3:::${DATA_BUCKET}/*`],
      Condition: { StringNotEquals: { "aws:SourceVpce": VPCE } },
    },
  ],
};

/** What AWS's "Revoke active sessions" button attaches to a role. */
export function revokePolicy(before: string): Policy {
  return {
    name: "AWSRevokeOlderSessions",
    Statement: [{ Sid: "RevokeOlderSessions", Effect: "Deny", Action: "*", Resource: "*", Condition: { DateLessThan: { "aws:TokenIssueTime": before } } }],
  };
}

// ---------- fictional data ----------

const CUSTOMERS_CSV = `customer_id,name,email,city,orders,lifetime_value_cop
10021,Ana Restrepo,ana.restrepo@example.com,Medellín,14,3240000
10022,Julián Ortiz,julian.ortiz@example.com,Bogotá,3,410000
10023,Camila Duarte,camila.duarte@example.com,Cali,22,6875000
10024,Santiago Mejía,santiago.mejia@example.com,Envigado,7,1190000
10025,Valentina Rojas,valentina.rojas@example.com,Barranquilla,11,2560000
10026,Mateo Gallego,mateo.gallego@example.com,Pereira,5,780000
`;

const BUCKETS: Record<string, Record<string, string>> = {
  "acme-shop-assets": { "img/logo.svg": "<svg xmlns='http://www.w3.org/2000/svg'/>", "css/site.css": "body{margin:0}" },
  [DATA_BUCKET]: { [DATA_KEY]: CUSTOMERS_CSV },
  "acme-terraform-state": { "prod/terraform.tfstate": '{"version":4,"resources":["..."]}' },
};

export const CUSTOMER_RECORDS = CUSTOMERS_CSV.trim().split("\n").length - 1;

// ---------- helpers ----------

const xml = (status: number, body: string, extra: Record<string, string> = {}): Res => ({
  status,
  headers: { "content-type": "application/xml", ...extra },
  body: `<?xml version="1.0" encoding="UTF-8"?>\n${body}`,
});
const s3Error = (status: number, code: string, message: string) => xml(status, `<Error><Code>${code}</Code><Message>${message}</Message></Error>`);
const json = (status: number, value: unknown): Res => ({ status, headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
const text = (status: number, body: string): Res => ({ status, headers: { "content-type": "text/plain" }, body });

function randomId(prefix: string, n: number): string {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return prefix + [...randomBytes(n)].map((b) => abc[b % abc.length]).join("");
}
function randomSecret(n: number): string {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  return [...randomBytes(n)].map((b) => abc[b % abc.length]).join("");
}

export function parseControls(h: string | undefined): Set<Control> {
  return new Set((h ?? "").split(",").map((s) => s.trim()).filter((s): s is Control => (CONTROLS as readonly string[]).includes(s)));
}

interface Session {
  keyId: string;
  secret: string;
  token: string;
  issued: string;
}

// ---------- the world ----------

export function createCloud() {
  let session: Session | null = null;
  let leaked: string | null = null;
  let revokedBefore: string | null = null;
  let trail: TrailEntry[] = [];
  let findings: Finding[] = [];
  let exfiltrated: string[] = [];

  function reset(): void {
    session = null;
    leaked = null;
    revokedBefore = null;
    trail = [];
    findings = [];
    exfiltrated = [];
  }

  const snapshot = (): Snapshot => ({
    credentialsLeaked: leaked,
    revoked: revokedBefore !== null,
    trail: trail.map((t) => ({ ...t })),
    findings: findings.map((f) => ({ ...f })),
    exfiltrated: [...exfiltrated],
  });

  function instanceSession(): Session {
    session ??= { keyId: randomId("ASIA", 16), secret: randomSecret(40), token: "IQoJb3JpZ2luX2VjE" + randomSecret(120), issued: new Date().toISOString() };
    return session;
  }

  // ----- IMDS, as reached from inside the instance -----
  function imds(path: string, headers: Record<string, string>, on: Set<Control>, emit: Emit): Res {
    const hasToken = Object.keys(headers).some((k) => k.toLowerCase() === "x-aws-ec2-metadata-token");
    if (on.has("imdsv2") && !hasToken) {
      emit({ level: "block", layer: "imds", msg: { es: "IMDS: petición sin token de sesión. Con IMDSv2 obligatorio responde 401: primero hay que pedir un token con PUT, y la función de vista previa solo hace GET.", en: "IMDS: request without a session token. With IMDSv2 required it answers 401: a token must first be requested with PUT, and the preview feature only sends GET." } });
      return text(401, "");
    }
    const base = "/latest/meta-data/";
    if (path === base) {
      emit({ level: "info", layer: "imds", msg: { es: "IMDS (v1) responde sin pedir token: lista de metadatos de la instancia.", en: "IMDS (v1) answers without asking for a token: the instance metadata listing." } });
      return text(200, ["ami-id", "hostname", "instance-id", "local-ipv4", "iam/", "placement/", "security-groups"].join("\n"));
    }
    if (path === base + "iam/security-credentials/") {
      emit({ level: "info", layer: "imds", msg: { es: `IMDS revela el nombre del rol de la instancia: ${ROLE}.`, en: `IMDS reveals the instance role name: ${ROLE}.` } });
      return text(200, ROLE);
    }
    if (path === base + "iam/security-credentials/" + ROLE) {
      const s = instanceSession();
      leaked = s.keyId;
      emit({ level: "breach", layer: "imds", msg: { es: `IMDS entrega credenciales temporales del rol (${s.keyId}). Ya salieron del servidor dentro de la respuesta de la app.`, en: `IMDS hands out temporary role credentials (${s.keyId}). They have now left the server inside the app's response.` } });
      const exp = new Date(Date.now() + 6 * 3600_000).toISOString().replace(/\.\d{3}/, "");
      return json(200, { Code: "Success", LastUpdated: s.issued.replace(/\.\d{3}/, ""), Type: "AWS-HMAC", AccessKeyId: s.keyId, SecretAccessKey: s.secret, Token: s.token, Expiration: exp });
    }
    if (path === base + "instance-id") return text(200, INSTANCE_ID);
    return text(404, "Not Found");
  }

  // ----- the vulnerable feature: link preview -----
  function preview(rawUrl: string | null, on: Set<Control>, emit: Emit): Res {
    if (!rawUrl) return json(400, { error: "url is required" });
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      return json(400, { error: "invalid url" });
    }
    if (on.has("ssrf-allowlist")) {
      const ok = url.protocol === "https:" && PREVIEW_ALLOWLIST.includes(url.hostname);
      if (!ok) {
        emit({ level: "block", layer: "app", msg: { es: `App: ${url.hostname} no está en la lista de dominios permitidos para vista previa (solo https y ${PREVIEW_ALLOWLIST.join(", ")}). 400.`, en: `App: ${url.hostname} is not on the preview allowlist (https only, ${PREVIEW_ALLOWLIST.join(", ")}). 400.` } });
        return json(400, { error: "url not allowed" });
      }
    }
    if (url.hostname === IMDS_HOST) {
      emit({ level: "info", layer: "app", msg: { es: `App: el servidor hace GET a ${url.href} desde dentro de AWS, en nombre del visitante.`, en: `App: the server sends GET ${url.href} from inside AWS, on the visitor's behalf.` } });
      const r = imds(url.pathname, {}, on, emit);
      return json(200, { url: url.href, status: r.status, body: r.body });
    }
    if (url.hostname === "example.com") {
      emit({ level: "ok", layer: "app", msg: { es: "App: vista previa normal de example.com.", en: "App: an ordinary preview of example.com." } });
      return json(200, { url: url.href, status: 200, title: "Example Domain", body: "<title>Example Domain</title>" });
    }
    emit({ level: "info", layer: "app", msg: { es: `App: no se pudo alcanzar ${url.hostname}.`, en: `App: could not reach ${url.hostname}.` } });
    return json(502, { error: "upstream unreachable" });
  }

  // ----- S3, as reached from the internet with signed requests -----
  async function s3(req: Req, path: string, query: string, on: Set<Control>, emit: Emit): Promise<Res> {
    const auth = parseAuthorization(req.headers.authorization ?? req.headers.Authorization);
    const s = session;
    if (!auth) return s3Error(403, "AccessDenied", "Anonymous access is not allowed");
    if (!s || auth.keyId !== s.keyId) return s3Error(403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.");
    const token = req.headers["x-amz-security-token"];
    const date = req.headers["x-amz-date"] ?? "";
    const expected = await hmacHex(s.secret, stringToSign(req.method, path, query, date));
    if (token !== s.token || expected !== auth.signature) return s3Error(403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.");

    const parts = path.replace(/^\/aws\/s3\/?/, "").split("/");
    const bucket = parts[0] ?? "";
    const key = parts.slice(1).join("/");
    let action: string, resource: string, eventName: string, dataEvent: boolean;
    if (!bucket) [action, resource, eventName, dataEvent] = ["s3:ListAllMyBuckets", "*", "ListBuckets", false];
    else if (!key) [action, resource, eventName, dataEvent] = ["s3:ListBucket", `arn:aws:s3:::${bucket}`, "ListObjects", true];
    else [action, resource, eventName, dataEvent] = ["s3:GetObject", `arn:aws:s3:::${bucket}/${key}`, "GetObject", true];

    const identity = [on.has("least-privilege") ? ROLE_POLICY_LEAST : ROLE_POLICY_BROAD];
    if (revokedBefore) identity.push(revokePolicy(revokedBefore));
    const resourcePolicy = on.has("vpce-only") && bucket === DATA_BUCKET ? DATA_BUCKET_POLICY : null;
    // The request arrives from the attacker's own machine: no VPC endpoint, an internet IP.
    const ctx: Context = { "aws:SourceIp": ATTACKER_IP, "aws:TokenIssueTime": s.issued };
    const d: Decision = evaluate(identity, resourcePolicy, action, resource, ctx);

    // CloudTrail: management events are recorded by default; S3 data events only when configured.
    if (!dataEvent || on.has("detect-respond")) {
      trail.push({ at: new Date().toISOString().slice(11, 19), eventName, sourceIp: ATTACKER_IP, errorCode: d.allowed ? undefined : "AccessDenied" });
    }

    const verdict = d.allowed
      ? { es: `IAM: ${action} permitido por ${d.by}.`, en: `IAM: ${action} allowed by ${d.by}.` }
      : d.reason === "explicit-deny"
        ? { es: `IAM: ${action} denegado explícitamente por ${d.by}.`, en: `IAM: ${action} explicitly denied by ${d.by}.` }
        : { es: `IAM: ${action} sobre ${resource} no está permitido por ninguna política (denegación implícita).`, en: `IAM: no policy allows ${action} on ${resource} (implicit deny).` };
    emit({ level: d.allowed ? (dataEvent && key ? "breach" : "info") : "block", layer: "iam", msg: verdict });
    if (!dataEvent || on.has("detect-respond")) {
      emit({ level: "info", layer: "trail", msg: { es: `CloudTrail registra ${eventName} desde ${ATTACKER_IP}${d.allowed ? "" : " (AccessDenied)"}.`, en: `CloudTrail records ${eventName} from ${ATTACKER_IP}${d.allowed ? "" : " (AccessDenied)"}.` } });
    } else if (d.allowed) {
      emit({ level: "info", layer: "trail", msg: { es: `CloudTrail no registra ${eventName}: los eventos de datos de S3 no están activados. Nadie sabrá que pasó.`, en: `CloudTrail does not record ${eventName}: S3 data events are not enabled. Nobody will know it happened.` } });
    }

    // GuardDuty notices instance credentials used from outside AWS, whether or not the call worked.
    if (on.has("detect-respond") && !revokedBefore) {
      findings.push({
        type: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        severity: "High",
        detail: { es: `Credenciales de ${INSTANCE_ID} usadas desde ${ATTACKER_IP}, fuera de AWS.`, en: `Credentials of ${INSTANCE_ID} used from ${ATTACKER_IP}, outside AWS.` },
      });
      emit({ level: "ok", layer: "guardduty", msg: { es: "GuardDuty: hallazgo de severidad alta, credenciales de la instancia usadas fuera de AWS.", en: "GuardDuty: high-severity finding, instance credentials used outside AWS." } });
      revokedBefore = new Date(Date.now() + 1).toISOString();
      emit({ level: "ok", layer: "guardduty", msg: { es: "Respuesta automática (EventBridge + Lambda): se revocan las sesiones del rol emitidas antes de ahora. Las credenciales robadas dejan de servir.", en: "Automatic response (EventBridge + Lambda): role sessions issued before now are revoked. The stolen credentials stop working." } });
    }

    if (!d.allowed) return s3Error(403, "AccessDenied", "Access Denied");
    const objects = BUCKETS[bucket];
    if (bucket && !objects) return s3Error(404, "NoSuchBucket", "The specified bucket does not exist");
    if (!bucket) {
      const names = Object.keys(BUCKETS).map((b) => `<Bucket><Name>${b}</Name></Bucket>`).join("");
      return xml(200, `<ListAllMyBucketsResult><Buckets>${names}</Buckets></ListAllMyBucketsResult>`);
    }
    if (!key) {
      const items = Object.entries(objects!).map(([k, v]) => `<Contents><Key>${k}</Key><Size>${v.length}</Size></Contents>`).join("");
      return xml(200, `<ListBucketResult><Name>${bucket}</Name><KeyCount>${Object.keys(objects!).length}</KeyCount>${items}</ListBucketResult>`);
    }
    const body = objects![key];
    if (body === undefined) return s3Error(404, "NoSuchKey", "The specified key does not exist.");
    exfiltrated.push(`${bucket}/${key}`);
    emit({ level: "breach", layer: "s3", msg: { es: `S3 entrega ${bucket}/${key} a una máquina fuera de AWS.`, en: `S3 hands ${bucket}/${key} to a machine outside AWS.` } });
    return { status: 200, headers: { "content-type": key.endsWith(".csv") ? "text/csv" : "application/octet-stream" }, body };
  }

  async function handle(req: Req, emit: (e: CloudEvent) => void = () => {}): Promise<Res> {
    const on = parseControls(req.headers[CONTROL_HEADER]);
    const e: Emit = (ev) => emit({ ...ev, at: 0, snapshot: snapshot() });
    const q = req.path.indexOf("?");
    const path = q >= 0 ? req.path.slice(0, q) : req.path;
    const query = q >= 0 ? req.path.slice(q + 1) : "";
    if (req.method === "POST" && path === "/_reset") {
      reset();
      return { status: 204, headers: {}, body: "" };
    }
    if (req.method === "GET" && path === "/shop/api/preview") return preview(new URLSearchParams(query).get("url"), on, e);
    if (req.method === "GET" && path.startsWith("/aws/s3")) return s3(req, path, query, on, e);
    return json(404, { error: "not found" });
  }

  /** Simulated time passing is not needed: every run starts from a reset. */
  return { handle, reset, snapshot };
}

export type Cloud = ReturnType<typeof createCloud>;
