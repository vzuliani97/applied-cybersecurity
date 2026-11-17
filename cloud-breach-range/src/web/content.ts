// Words and code shown on the page, kept apart from the logic.
import type { Control, L } from "../core/cloud.ts";
import type { Stage } from "../core/chain.ts";

export const UI = {
  back: { es: "← valterzuliani.com", en: "← valterzuliani.com" },
  title: { es: "Brecha en la nube", en: "Cloud breach range" },
  lede: {
    es: "Un SSRF, un servicio de metadatos sin token y un rol con permisos de más: la cadena detrás de brechas reales en AWS. Enciende defensas, ataca y mira dónde se rompe.",
    en: "One SSRF, a metadata service without tokens and a role with too many permissions: the chain behind real AWS breaches. Switch on defences, attack, and see where it breaks.",
  },
  where: {
    es: "Todo corre en tu navegador: un service worker hace de tienda, de servicio de metadatos y de S3. Las credenciales se generan en cada intento y los datos son ficticios.",
    en: "Everything runs in your browser: a service worker plays the shop, the metadata service and S3. Credentials are generated on every run and the data is fictional.",
  },
  whereFallback: {
    es: "Tu navegador no permite service workers aquí, así que la nube simulada corre dentro de la página.",
    en: "Your browser does not allow service workers here, so the simulated cloud runs inside the page.",
  },
  devtools: { es: "Abre la pestaña Red de las herramientas de desarrollador: cada petición es real.", en: "Open the Network tab in developer tools: every request is real." },
  chain: { es: "La cadena", en: "The chain" },
  defences: { es: "Defensas", en: "Defences" },
  allOff: { es: "Todo apagado (como se desplegó)", en: "All off (as deployed)" },
  allOn: { es: "Todo encendido", en: "All on" },
  launch: { es: "Lanzar ataque", en: "Launch attack" },
  running: { es: "Atacando…", en: "Attacking…" },
  slow: { es: "Cámara lenta", en: "Slow motion" },
  attacker: { es: "Terminal del atacante", en: "Attacker's terminal" },
  cloud: { es: "Lo que ve AWS", en: "What AWS sees" },
  waiting: { es: "Esperando el primer comando…", en: "Waiting for the first command…" },
  leaked: { es: "Credenciales filtradas", en: "Credentials leaked" },
  trail: { es: "Eventos en CloudTrail", en: "CloudTrail events" },
  findings: { es: "Hallazgos de GuardDuty", en: "GuardDuty findings" },
  exfil: { es: "Archivos robados", en: "Files stolen" },
  none: { es: "ninguno", en: "none" },
  revoked: { es: "sesiones revocadas", en: "sessions revoked" },
  breached: { es: "Brecha", en: "Breach" },
  held: { es: "Contenido", en: "Contained" },
  detected: { es: "Detectado", en: "Detected" },
  unseen: { es: "Nadie lo vio", en: "Nobody saw it" },
  requests: { es: "peticiones", en: "requests" },
  request: { es: "Petición", en: "Request" },
  response: { es: "Respuesta", en: "Response" },
  hint: { es: "Empieza con todo apagado. Luego enciende una sola defensa y vuelve a atacar.", en: "Start with everything off. Then switch on a single defence and attack again." },
  error: { es: "Algo falló al lanzar el ataque:", en: "Something failed while launching the attack:" },
  fixes: { es: "Cada defensa, en Terraform", en: "Each defence, in Terraform" },
  fixesLede: {
    es: "Los dos stacks completos están en el repositorio. Checkov los escanea en cada push: el corregido debe pasar los 9 controles de la cadena y el vulnerable debe fallarlos.",
    en: "Both full stacks are in the repository. Checkov scans them on every push: the fixed one must pass the 9 chain checks and the vulnerable one must fail them.",
  },
  before: { es: "Como se desplegó", en: "As deployed" },
  after: { es: "Corregido", en: "Fixed" },
  source: { es: "Código y Terraform en GitHub", en: "Code and Terraform on GitHub" },
  credit: {
    es: "Basado en el patrón de la brecha de Capital One en 2019 y en laboratorios como flaws.cloud y CloudGoat. Código propio; nada toca una cuenta real de AWS.",
    en: "Modelled on the pattern of the 2019 Capital One breach and labs such as flaws.cloud and CloudGoat. Original code; nothing touches a real AWS account.",
  },
  timing: {
    es: "En AWS real, GuardDuty tarda minutos en emitir un hallazgo; aquí es inmediato para que se vea la respuesta.",
    en: "In real AWS, GuardDuty takes minutes to raise a finding; here it is instant so you can see the response.",
  },
} satisfies Record<string, L>;

export const STAGE_TEXT: Record<Stage, { name: L; sub: L }> = {
  app: { name: { es: "Vista previa de enlaces", en: "Link preview" }, sub: { es: "la app en EC2", en: "the app on EC2" } },
  imds: { name: { es: "Metadatos (IMDS)", en: "Metadata (IMDS)" }, sub: { es: "169.254.169.254", en: "169.254.169.254" } },
  creds: { name: { es: "Credenciales del rol", en: "Role credentials" }, sub: { es: "en manos del atacante", en: "in the attacker's hands" } },
  s3: { name: { es: "API de S3", en: "S3 API" }, sub: { es: "desde internet", en: "from the internet" } },
  data: { name: { es: "Datos de clientes", en: "Customer data" }, sub: { es: "customers.csv", en: "customers.csv" } },
};

export interface ControlText {
  name: L;
  layer: L;
  what: L;
  guards: Stage;
  vulnerable: string;
  fixed: string;
}

export const CONTROL_TEXT: Record<Control, ControlText> = {
  "ssrf-allowlist": {
    name: { es: "Lista de dominios permitidos", en: "URL allowlist" },
    layer: { es: "Aplicación", en: "Application" },
    what: { es: "La vista previa solo pide https a dominios de una lista, nunca a direcciones internas.", en: "The preview only fetches https from listed domains, never internal addresses." },
    guards: "app",
    vulnerable: `// Fetch whatever the visitor asks for, from inside AWS.
app.get("/api/preview", async (req, res) => {
  const page = await fetch(req.query.url);
  res.json({ status: page.status, body: await page.text() });
});`,
    fixed: `const ALLOWED = new Set(["example.com", "cdn.acme-shop.example"]);

app.get("/api/preview", async (req, res) => {
  const url = new URL(req.query.url);
  if (url.protocol !== "https:" || !ALLOWED.has(url.hostname))
    return res.status(400).json({ error: "url not allowed" });
  // ...and resolve the name, rejecting private and link-local IPs
  const page = await fetch(url, { redirect: "error" });
  res.json({ title: extractTitle(await page.text()) });
});`,
  },
  imdsv2: {
    name: { es: "IMDSv2 obligatorio", en: "IMDSv2 required" },
    layer: { es: "EC2", en: "EC2" },
    what: { es: "El servicio de metadatos exige un token que se pide con PUT. Un SSRF de solo GET no puede conseguirlo.", en: "The metadata service demands a token requested with PUT. A GET-only SSRF cannot get one." },
    guards: "imds",
    vulnerable: `resource "aws_instance" "shop_web" {
  # ...
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"   # IMDSv1 still answers
  }
}`,
    fixed: `resource "aws_instance" "shop_web" {
  # ...
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
  }
}`,
  },
  "least-privilege": {
    name: { es: "Rol de mínimo privilegio", en: "Least-privilege role" },
    layer: { es: "IAM", en: "IAM" },
    what: { es: "El rol del servidor solo puede leer sus propias imágenes. Aunque roben sus llaves, no abren nada más.", en: "The server's role can only read its own images. Even stolen, its keys open nothing else." },
    guards: "s3",
    vulnerable: `resource "aws_iam_role_policy" "shop_web" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}`,
    fixed: `resource "aws_iam_role_policy" "shop_web" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "\${aws_s3_bucket.assets.arn}/*"
    }]
  })
}`,
  },
  "vpce-only": {
    name: { es: "Solo por VPC endpoint", en: "VPC endpoint only" },
    layer: { es: "Política del bucket", en: "Bucket policy" },
    what: { es: "El bucket de clientes rechaza toda petición que no llegue por el VPC endpoint, incluso con llaves válidas.", en: "The customer bucket refuses any request that does not arrive through the VPC endpoint, even with valid keys." },
    guards: "data",
    vulnerable: `resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-exports"
}
# no bucket policy: valid keys work from anywhere`,
    fixed: `resource "aws_s3_bucket_policy" "customer_exports" {
  policy = jsonencode({
    Statement = [{
      Sid       = "DenyOutsideVpcEndpoint"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [bucket_arn, "\${bucket_arn}/*"]
      Condition = { StringNotEquals = {
        "aws:SourceVpce" = aws_vpc_endpoint.s3.id } }
    }]
  })
}`,
  },
  "detect-respond": {
    name: { es: "Detección y respuesta", en: "Detect and respond" },
    layer: { es: "GuardDuty + CloudTrail", en: "GuardDuty + CloudTrail" },
    what: { es: "CloudTrail registra cada lectura de S3; GuardDuty detecta las llaves usadas fuera de AWS y una Lambda revoca las sesiones.", en: "CloudTrail records every S3 read; GuardDuty spots the keys used outside AWS and a Lambda revokes the sessions." },
    guards: "s3",
    vulnerable: `resource "aws_cloudtrail" "main" {
  name           = "acme-trail"
  s3_bucket_name = "acme-cloudtrail-logs"
  # management events only: downloads are invisible
}
# no GuardDuty, no response`,
    fixed: `resource "aws_guardduty_detector" "main" { enable = true }

resource "aws_cloudwatch_event_rule" "exfil" {
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = { type = [
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"] }
  })
}
# target: Lambda that attaches AWSRevokeOlderSessions
# (deny if aws:TokenIssueTime < now)`,
  },
};
