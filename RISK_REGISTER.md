# Risk register

Applies ICTCYS608 *Perform cyber security risk assessments* to NekoBet, Yamesi and the OpsCircuit cluster, as
they are documented to run (local stacks with synthetic data, production settings described in each README).

**Scales.** Likelihood (L) and impact (I) go from 1 to 5. Rating = L × I: 1–4 Low, 5–9 Medium, 10–16 High,
20–25 Critical. They are judgments for these systems, not measured frequencies. *Inherent* is the risk as it was
found; *residual* is the risk with today's controls. Last review: 2026-11-02.

| ID | Risk | Inherent (L×I) | Controls in place | Residual (L×I) | Treatment |
|---|---|---|---|---|---|
| R-01 | A signing secret (JWT, partner HMAC, casino provider) is published or guessed, so anyone can sign an admin token or move money | 4×5 = 20 Critical ([ESC-01](findings/ESC-01-placeholder-jwt-secret.md), [ESC-08](findings/ESC-08-demo-hmac-secrets-outside-demo.md)) | Placeholder and demo secrets are refused in production mode; `make .env` generates random ones; demos listen on loopback only | 2×5 = 10 **High** | **Reduce, open.** Secrets still live in plain `.env` files, and partner HMAC secrets in plain text in the database. Production would keep them in a secrets manager encrypted with KMS and rotate them per partner. Not built. |
| R-02 | A captured partner request is replayed and charged again | 3×4 = 12 High ([ESC-02](findings/ESC-02-hmac-replay-new-idempotency-key.md)) | The signature covers the idempotency key; 5-minute window; IP allowlist | 1×2 = 2 Low | **Accept.** A GET replayed within 5 minutes returns data the attacker already saw. |
| R-03 | A token outlives the user's access (user removed, role changed) | 3×3 = 9 Medium | Tokens expire after 1 hour (NekoBet) or 8 hours, one shift (Yamesi) | 3×3 = 9 **Medium** | **Accept for the demo.** Production: a token version per user checked on each request, or short tokens with refresh. |
| R-04 | Passwords are guessed | 3×4 = 12 High ([ESC-11](findings/ESC-11-no-login-throttling.md)) | bcrypt (cost 10); 5 failures per email and address lock it for 15 minutes | 2×4 = 8 **Medium** | **Reduce later.** Counters live in memory per API replica, many addresses bypass them, and there is no MFA. Next: a shared counter and MFA for administrators. |
| R-05 | An employee reads confidential business data (costs, margins) | 4×2 = 8 Medium ([ESC-05](findings/ESC-05-sellers-receive-costs.md)) | Costs go to administrators only | 1×2 = 2 Low | **Accept.** The store owner decides who sees costs. |
| R-06 | A photo reveals where it was taken | 4×3 = 12 High ([ESC-04](findings/ESC-04-uploaded-photos-keep-gps.md), [ESC-10](findings/ESC-10-gps-in-published-photo.md)) | Metadata stripped on upload; CI check on committed images; history rewritten | 1×3 = 3 Low | **Accept.** Bytes appended after a valid JPEG are still stored ([ESC-06](findings/ESC-06-jpeg-prefixed-html-accepted.md)). |
| R-07 | An image or dependency ships a known vulnerability | 4×4 = 16 High ([ESC-07](findings/ESC-07-vulnerable-base-images.md)) | Trivy gate on fixable critical and high CVEs; npm audit; Dependabot; CodeQL | 2×3 = 6 **Medium** | **Accept and monitor.** CVEs with no fix yet pass the gate until a fix exists. |
| R-08 | A demo is reachable from the local network | 3×3 = 9 Medium ([ESC-03](findings/ESC-03-kind-ports-on-all-interfaces.md), [ESC-09](findings/ESC-09-compose-ports-on-all-interfaces.md)) | Loopback-only ports, checked by `make validate` and the network attacks | 1×3 = 3 Low | **Accept.** |
| R-09 | A compromised CI action or image reaches the cluster | 2×5 = 10 High | Actions pinned by SHA, scanner images by digest, read-only tokens by default; images signed with cosign and only signed images admitted by Kyverno | 1×5 = 5 **Medium** | **Accept.** The apps' CI runs this repository's attacks from `main`: my own repository, with a read-only token. |
| R-10 | A prompt steers Yamesi's AI assistant | 3×2 = 6 Medium | No SQL; five read-only tools that return aggregates; validated arguments; 4-step cap; every answer lists its data | 2×2 = 4 Low | **Accept.** It can still produce a misleading summary of the aggregates. |
| R-11 | A sale stays PENDING when the top-up provider times out | 3×3 = 9 Medium | The provider is called outside the transaction; a refund can happen only once | 3×3 = 9 **Medium** | **Reduce, open.** There is no reconciliation job yet; a PENDING sale needs manual follow-up. |
| R-12 | Default access to lab tools (published demo password, Grafana anonymous viewer, Argo CD initial admin secret) | 3×2 = 6 Medium | Loopback-only; Grafana admin password generated at setup | 1×2 = 2 Low | **Accept** for a local lab. |

**Summary.** Residual: 1 High (R-01), 5 Medium (R-03, R-04, R-07, R-09, R-11), 6 Low. The High one is the
next thing to fix in a real deployment.
