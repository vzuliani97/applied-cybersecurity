# Identity and access review

Applies ICTCYS604 *Implement best practices for identity management* to NekoBet, Yamesi and the OpsCircuit
cluster. Every identity that can act on these systems is listed below, people and machines alike. For each one:
how it proves who it is, what it may do, and where its secret lives. Reviewed against the code on 2026-11-02.

## Identities

| Identity | Proves itself with | May do | Secret lives in | Lifetime and rotation |
|---|---|---|---|---|
| Admin, cashier (NekoBet); admin, seller (Yamesi) | Email and password (bcrypt, cost 10), then a JWT signed with HS256 | What the role in the token allows; a cashier only acts on its own store, taken from the token, never from the request | Password hash in PostgreSQL; JWT key in the API environment | Token valid 1 h (NekoBet) or 8 h (Yamesi); no revocation; rotating the JWT key logs everyone out |
| Partner integrator (NekoBet B2B API) | API key id and an HMAC-SHA256 signature over timestamp, method, path, body hash and idempotency key; source address on an allowlist | Sell and read on its one store | HMAC secret in plain text in the `partners` table | 5-minute window per request; the demo partner's secret follows `DEMO_PARTNER_SECRET` on restart |
| Casino game provider (NekoBet wallet callbacks) | HMAC-SHA256 signature with one shared secret | Debit, credit or roll back **any** store's balance (the store id comes in the signed body) | `CASINO_PROVIDER_SECRET` in the API environment | Refused in production mode if it is the published default |
| Yamesi API, as a storage client | S3 access key and secret (RustFS locally); an IAM role on AWS, since the keys are optional | Read and write the photo and receipt bucket; hand out presigned URLs | API environment | Presigned URLs expire after 300 s |
| Prometheus, in the cluster | Kubernetes ServiceAccount | Read pods, cluster-wide, through a read-only ClusterRole | Token mounted by Kubernetes | Managed by Kubernetes |
| Alertmanager, calling n8n | Bearer token on the webhook | Open incidents in the incident workflow; a wrong token gets 403 and nothing is stored | Secret of the incident lab | Static |
| CI jobs | GitHub's per-run `GITHUB_TOKEN` | Read the repository; only the publish job may write packages | Issued by GitHub per run | Expires with the run |
| Image signer (NekoBet publish job) | GitHub OIDC token exchanged for a short-lived Sigstore certificate (cosign keyless) | Sign the images it built; each signature is recorded in the public Rekor log | No stored key | Certificate lives minutes |
| Cluster admission (Kyverno) | Verifies the signer instead of being one: issuer `token.actions.githubusercontent.com`, subject NekoBet's `ci.yml` on `main` | Admit only images signed by that workflow, pinned to the verified digest | Policy in git | Changes go through review |
| Lab operators (Grafana, Argo CD) | Grafana admin password generated at setup; Argo CD's initial admin secret; Grafana anonymous viewer | Administer the lab tools | Kubernetes Secrets | Local lab only, on loopback |

## What holds up

- Passwords are hashed with bcrypt. An unknown email costs the same bcrypt comparison as a wrong password and
  gets the same error, so the login does not reveal which accounts exist.
- The JWT algorithm is pinned to HS256, so `alg: none` and changed claims are refused. Placeholder keys are
  refused at startup.
- Roles are enforced on the server for every route. A user's store comes from the token, never from the request.
- Partner requests are signed over everything that changes their meaning, compared in constant time, limited to
  5 minutes and to known addresses.
- CI holds no long-lived cloud or registry credentials, and image signing needs no stored key.
- No secret is committed: Gitleaks scans the full history of every repository.

## Gaps and recommendations

| # | Gap | Risk | Recommendation |
|---|---|---|---|
| 1 | Tokens cannot be revoked, and the API trusts the role inside the token without looking the user up | [R-03](RISK_REGISTER.md) | A token version per user, checked on each request, or short access tokens with refresh |
| 2 | No MFA; lockout counters live in memory per replica | [R-04](RISK_REGISTER.md) | MFA (TOTP) for administrators; a shared counter in PostgreSQL or Redis |
| 3 | Partner HMAC secrets are stored in plain text; one provider secret can credit every store | [R-01](RISK_REGISTER.md) | Encrypt secrets at rest with KMS (HMAC needs the secret itself, so hashing is not an option); bind each provider credential to the stores it serves |
| 4 | Logins, failed logins and lockouts are not recorded. Yamesi's audit trail covers business writes (invoices, pieces, lots, expenses, closings), not authentication | Detection | Log authentication events, without passwords, and alert on lockout bursts |
| 5 | Storage uses access keys locally | [R-01](RISK_REGISTER.md) | On AWS, an IAM role for the instance or pod, which the configuration already allows by leaving the keys unset |
