import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ATTACKER_IP, CONTROL_HEADER, CONTROLS, DATA_BUCKET, DATA_BUCKET_POLICY, DATA_KEY, ROLE_POLICY_BROAD, ROLE_POLICY_LEAST, VPCE,
  createCloud, revokePolicy, type CloudEvent, type Control, type Req,
} from "../src/core/cloud.ts";
import { runChain, type Send } from "../src/core/chain.ts";
import { evaluate, wildcard } from "../src/core/iam.ts";
import { signedHeaders } from "../src/core/sign.ts";

function harness(controls: Control[]) {
  const cloud = createCloud();
  const events: CloudEvent[] = [];
  const log: { req: Req; status: number; cmd: string }[] = [];
  const send: Send = async (req, step) => {
    const res = await cloud.handle({ ...req, headers: { ...req.headers, [CONTROL_HEADER]: controls.join(",") } }, (e) => events.push(e));
    log.push({ req, status: res.status, cmd: step.cmd });
    return res;
  };
  return { cloud, events, log, send, on: new Set(controls) };
}

async function run(controls: Control[]) {
  const h = harness(controls);
  const outcome = await runChain(h.send, h.on);
  return { ...h, outcome, snap: h.cloud.snapshot() };
}

// ---------- the evaluator ----------

test("IAM wildcards match like AWS", () => {
  assert.ok(wildcard("s3:*", "s3:GetObject", true));
  assert.ok(wildcard("S3:get*", "s3:GetObject", true));
  assert.ok(wildcard("arn:aws:s3:::acme-shop-assets/*", "arn:aws:s3:::acme-shop-assets/img/logo.svg"));
  assert.ok(!wildcard("arn:aws:s3:::acme-shop-assets/*", "arn:aws:s3:::acme-customer-exports/x.csv"));
  assert.ok(wildcard("arn:aws:s3:::acme-?hop-assets", "arn:aws:s3:::acme-shop-assets"));
});

test("an explicit deny beats any allow", () => {
  const d = evaluate([ROLE_POLICY_BROAD], DATA_BUCKET_POLICY, "s3:GetObject", `arn:aws:s3:::${DATA_BUCKET}/${DATA_KEY}`, { "aws:SourceIp": ATTACKER_IP });
  assert.equal(d.allowed, false);
  assert.equal(d.reason, "explicit-deny");
  assert.match(d.by!, /DenyOutsideVpcEndpoint/);
});

test("the VPC endpoint condition lets the same request through from inside", () => {
  const d = evaluate([ROLE_POLICY_BROAD], DATA_BUCKET_POLICY, "s3:GetObject", `arn:aws:s3:::${DATA_BUCKET}/${DATA_KEY}`, { "aws:SourceVpce": VPCE });
  assert.equal(d.allowed, true);
});

test("least privilege leaves customer data implicitly denied", () => {
  const d = evaluate([ROLE_POLICY_LEAST], null, "s3:GetObject", `arn:aws:s3:::${DATA_BUCKET}/${DATA_KEY}`, {});
  assert.deepEqual(d, { allowed: false, reason: "implicit-deny" });
  assert.equal(evaluate([ROLE_POLICY_LEAST], null, "s3:GetObject", "arn:aws:s3:::acme-shop-assets/img/logo.svg", {}).allowed, true);
  assert.equal(evaluate([ROLE_POLICY_LEAST], null, "s3:ListAllMyBuckets", "*", {}).allowed, false);
});

test("session revocation denies tokens issued before it, not after", () => {
  const p = revokePolicy("2026-11-16T12:00:00.000Z");
  assert.equal(evaluate([ROLE_POLICY_BROAD, p], null, "s3:GetObject", "arn:aws:s3:::b/k", { "aws:TokenIssueTime": "2026-11-16T11:59:00.000Z" }).allowed, false);
  assert.equal(evaluate([ROLE_POLICY_BROAD, p], null, "s3:GetObject", "arn:aws:s3:::b/k", { "aws:TokenIssueTime": "2026-11-16T12:01:00.000Z" }).allowed, true);
});

// ---------- the chain ----------

test("with every control off, the chain ends in a breach nobody logged", async () => {
  const { outcome, snap, log } = await run([]);
  assert.equal(outcome.breached, true);
  assert.equal(outcome.reached, 5);
  assert.deepEqual(snap.exfiltrated, [`${DATA_BUCKET}/${DATA_KEY}`]);
  assert.ok(snap.credentialsLeaked?.startsWith("ASIA"));
  // Only the management event (ListBuckets) reaches CloudTrail; the download leaves no trace.
  assert.deepEqual(snap.trail.map((t) => t.eventName), ["ListBuckets"]);
  assert.equal(snap.findings.length, 0);
  assert.deepEqual(log.map((l) => l.status), [200, 200, 200, 200, 200, 200, 200]);
});

test("the SSRF allowlist stops it at the first link", async () => {
  const { outcome, snap, log } = await run(["ssrf-allowlist"]);
  assert.equal(outcome.breached, false);
  assert.equal(outcome.reached, 0);
  assert.deepEqual(outcome.stoppedBy, ["ssrf-allowlist"]);
  assert.equal(snap.credentialsLeaked, null);
  assert.equal(log.at(-1)!.status, 400);
});

test("IMDSv2 stops it even though the SSRF is still there", async () => {
  const { outcome, snap, events } = await run(["imdsv2"]);
  assert.equal(outcome.breached, false);
  assert.deepEqual(outcome.stoppedBy, ["imdsv2"]);
  assert.equal(snap.credentialsLeaked, null);
  assert.ok(events.some((e) => e.layer === "imds" && e.level === "block"));
});

test("least privilege: credentials leak, data does not", async () => {
  const { outcome, snap, log } = await run(["least-privilege"]);
  assert.equal(outcome.breached, false);
  assert.ok(snap.credentialsLeaked);
  assert.deepEqual(outcome.stoppedBy, ["least-privilege"]);
  assert.deepEqual(log.slice(-3).map((l) => l.status), [403, 403, 403]);
});

test("the VPC endpoint bucket policy blocks the stolen keys from the internet", async () => {
  const { outcome, snap, log } = await run(["vpce-only"]);
  assert.equal(outcome.breached, false);
  assert.deepEqual(outcome.stoppedBy, ["vpce-only"]);
  assert.equal(outcome.reached, 4);
  assert.equal(snap.exfiltrated.length, 0);
  // Listing all buckets still works: the role is broad, only the data bucket is fenced.
  assert.deepEqual(log.slice(-3).map((l) => l.status), [200, 403, 403]);
});

test("detection and response: GuardDuty fires on first use and revocation stops the rest", async () => {
  const { outcome, snap, log } = await run(["detect-respond"]);
  assert.equal(outcome.breached, false);
  assert.equal(outcome.detected, true);
  assert.equal(snap.revoked, true);
  assert.equal(snap.findings.length, 1);
  assert.match(snap.findings[0]!.type, /InstanceCredentialExfiltration\.OutsideAWS/);
  // The first call got through before the response landed; the next two did not.
  assert.deepEqual(log.slice(-3).map((l) => l.status), [200, 403, 403]);
  // With data events on, the denied attempts are on record too.
  assert.deepEqual(snap.trail.map((t) => [t.eventName, t.errorCode ?? "ok"]), [["ListBuckets", "ok"], ["ListObjects", "AccessDenied"], ["GetObject", "AccessDenied"]]);
});

test("layers after the leak each block on their own and together", async () => {
  const { outcome } = await run(["least-privilege", "vpce-only", "detect-respond"]);
  assert.equal(outcome.breached, false);
  assert.deepEqual(outcome.stoppedBy, ["least-privilege", "vpce-only", "detect-respond"]);
});

test("every single control on its own prevents the breach", async () => {
  for (const c of CONTROLS) {
    const { outcome } = await run([c]);
    assert.equal(outcome.breached, false, c);
  }
});

// ---------- the S3 front door ----------

test("S3 rejects anonymous, unknown and tampered requests", async () => {
  const cloud = createCloud();
  const get = (headers: Record<string, string>) => cloud.handle({ method: "GET", path: "/aws/s3/", headers });
  assert.match((await get({})).body, /AccessDenied/);
  const fake = await signedHeaders({ AccessKeyId: "ASIAFAKEFAKEFAKEFAKE", SecretAccessKey: "x", Token: "y" }, "GET", "/aws/s3/");
  assert.match((await get(fake)).body, /InvalidAccessKeyId/);

  // Get real credentials through the vulnerable preview, then tamper with the signature.
  const r = await cloud.handle({ method: "GET", path: "/shop/api/preview?url=" + encodeURIComponent("http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-web-role"), headers: {} });
  const creds = JSON.parse(JSON.parse(r.body).body);
  const good = await signedHeaders(creds, "GET", "/aws/s3/");
  assert.equal((await get(good)).status, 200);
  const bad = { ...good, Authorization: good.Authorization!.replace(/Signature=.{4}/, "Signature=0000") };
  assert.match((await get(bad)).body, /SignatureDoesNotMatch/);
  // A signature for one path does not work for another.
  const other = await cloud.handle({ method: "GET", path: `/aws/s3/${DATA_BUCKET}`, headers: good });
  assert.match(other.body, /SignatureDoesNotMatch/);
});

test("the allowlist rejects http, other hosts and lookalikes", async () => {
  const cloud = createCloud();
  const p = (u: string) => cloud.handle({ method: "GET", path: "/shop/api/preview?url=" + encodeURIComponent(u), headers: { [CONTROL_HEADER]: "ssrf-allowlist" } });
  assert.equal((await p("https://example.com/")).status, 200);
  for (const u of ["http://example.com/", "https://169.254.169.254/", "https://example.com.evil.test/", "https://evil.test/?example.com", "file:///etc/passwd"]) {
    assert.equal((await p(u)).status, 400, u);
  }
});

test("a reset gives a fresh world with new credentials", async () => {
  const h = harness([]);
  await runChain(h.send, h.on);
  const first = h.cloud.snapshot().credentialsLeaked;
  await h.cloud.handle({ method: "POST", path: "/_reset", headers: {} });
  assert.equal(h.cloud.snapshot().credentialsLeaked, null);
  await runChain(h.send, h.on);
  assert.notEqual(h.cloud.snapshot().credentialsLeaked, first);
});
