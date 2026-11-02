# Methodology

## Scope and rules of engagement

| Target | Version tested | What it is |
|---|---|---|
| [NekoBet](https://github.com/vzuliani97/nekobet) | `6b0483b` | Point-of-sale platform: sportsbook, casino wallet, top-ups, HMAC partner API |
| [Yamesi](https://github.com/vzuliani97/yamesi) | `15f0bf8` | Jewelry store accounting: catalog with photos, invoices, day closing |
| [OpsCircuit](https://github.com/vzuliani97/opscircuit) | `7f8bd14` | The local Kubernetes cluster (kind) that runs NekoBet |

- I wrote all three. Testing ran on my own machine against local stacks with synthetic data. No third-party
  system was touched.
- Gray-box: the source code was available, and so were the demo accounts and the partner key, as a client
  would hand them over. Extra accounts (a second store and its cashier, throwaway users for the lockout tests)
  were created directly in the test databases, because neither app has a user-admin screen.
- Window: 2026-11-01, a review of the published repositories plus automated scans (ESC-07 to ESC-12, fixed
  the same day); 2026-11-02, manual testing (ESC-01 to ESC-06).

## Threat model

| Asset | Who could want it | Entry points |
|---|---|---|
| Store balances and the ledger (NekoBet) | A partner or someone who captured its traffic, a cashier, the game provider | Partner API, casino wallet callbacks, cashier portal |
| Admin role (both) | Anyone on the internet, a cashier or seller | Login, JWT handling, configuration defaults |
| One store's data (NekoBet) | Another store's cashier or partner | Every endpoint that takes an id |
| Costs and margins (Yamesi) | A seller | Catalog and lots endpoints |
| Location of the owner or workshop (Yamesi) | Anyone who sees the catalog | Photo uploads, published images |
| The demos themselves | Someone on the same network | Published ports |

## What was tested

Test categories follow the OWASP Web Security Testing Guide v4.2. Findings map to CWE and to the OWASP Top 10
(2021) or the OWASP API Security Top 10 (2023).

| Area | Tests | Result |
|---|---|---|
| Configuration (WSTG-CONF) | Default and published secrets, network exposure, headers, image CVEs | ESC-01, 03, 07, 08, 09, 12 |
| Information leakage (WSTG-INFO-02) | Server banner, image metadata | ESC-04, 10, 12 |
| Authentication (WSTG-ATHN-03) | No token, `alg: none`, a changed role claim, a forged token, lockout | ESC-01, 11; the rest held |
| Authorization (WSTG-ATHZ-03, -04) | Cashier and seller against admin routes; one store against another's sales (IDOR); `posId` injected in a body | ESC-05; the rest held |
| Business logic (WSTG-BUSL-03, -05) | HMAC body tampering, stale and future timestamps, replay with a new or the same idempotency key, casino callback replay | ESC-02; the rest held |
| File upload (WSTG-BUSL-08, -09) | Text, SVG and PDF disguised as images, a JPEG-prefixed HTML file, an oversize file, a phone photo with GPS | ESC-04, 06; the rest held |
| Injection | Code review of every SQL statement | Held: values always go as parameters; the only dynamic SQL is constant fragments and column names from a fixed map |

## Tools

| Tool | Use |
|---|---|
| Node.js 24 scripts in [`attacks/`](attacks/) | Every manual test, written as a repeatable test with no dependencies |
| Trivy 0.69.3 (pinned by digest) | Image vulnerabilities |
| OWASP ZAP 2.17.0 baseline (pinned by digest) | Passive scan of the running stacks |
| curl, Docker, `psql` | Probes and test accounts |
| Headless Chrome via the DevTools protocol | Checking that the CSP breaks nothing and blocks an unlisted origin |

## Severity

CVSS 3.1 base scores, computed from the vector shown in each finding. Findings that come from a scanner
(ESC-07, ESC-12) keep the scanner's rating, because they group many issues.

## Not covered

- Denial of service and load.
- An active ZAP scan or a manual XSS review of the React frontends. React escapes output and the CSP blocks
  inline scripts, but neither was attacked directly.
- Prompt injection against Yamesi's local AI assistant. Its limits are documented in the Yamesi README.
- TLS. The stacks run on plain HTTP on localhost; a deployment terminates TLS at the load balancer.
- The AWS infrastructure in OpsCircuit's Terraform, which is validated but not deployed.
- Third-party dependencies beyond what Trivy reports.
