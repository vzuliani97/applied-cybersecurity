# Applied Cyber Security

[![Attack suite](https://github.com/vzuliani97/applied-cybersecurity/actions/workflows/ci.yml/badge.svg)](https://github.com/vzuliani97/applied-cybersecurity/actions/workflows/ci.yml)

Three units of my Advanced Diploma of Information Technology (Cyber Security), ICT60220, applied to the systems I
built: [NekoBet](https://github.com/vzuliani97/nekobet), [Yamesi](https://github.com/vzuliani97/yamesi) and the
[OpsCircuit](https://github.com/vzuliani97/opscircuit) cluster that runs NekoBet. Formerly *Escudo*; the finding
IDs keep its `ESC` prefix.

| Diploma unit | Applied here | Result |
|---|---|---|
| ICTCYS603 Undertake penetration testing for organisations | A gray-box penetration test: [findings](#findings), [methodology](METHODOLOGY.md) and [the attacks as tests](attacks/) | 12 findings, all fixed; 38 attacks run in both apps' CI |
| ICTCYS608 Perform cyber security risk assessments | [Risk register](RISK_REGISTER.md) | 12 risks rated before and after controls; 1 High, 5 Medium and 6 Low remain, each with a treatment |
| ICTCYS604 Implement best practices for identity management | [Identity and access review](IDENTITY_REVIEW.md) | 10 identities, people and machines, with what holds up and 5 recommendations |

**Scope and limits.** The targets are three portfolio systems I wrote. They run locally with synthetic data:
no production system, no third-party target, and no TLS (the stacks serve plain HTTP on localhost). The
testing is gray-box, with the source code available. It covers the categories in
[METHODOLOGY.md](METHODOLOGY.md); denial of service, an active scan, manual XSS testing and the undeployed AWS
infrastructure are out of scope.

## Findings

Nine findings carry a CVSS 3.1 base score computed from the vector in each file. Two come from scanners and keep
the scanner's own severity (Trivy for CVEs, OWASP ZAP for headers), which is not a CVSS score of these apps. One
is informational and not scored.

| ID | Finding | Target | Severity | Rated with | Fixed |
|---|---|---|---|---|---|
| [ESC-01](findings/ESC-01-placeholder-jwt-secret.md) | The JWT secret published in `.env.example` was accepted, so anyone could sign an admin token | NekoBet, Yamesi | Critical | CVSS 3.1: 9.1 (first published as 7.4; see the finding) | 2026-11-02 |
| [ESC-02](findings/ESC-02-hmac-replay-new-idempotency-key.md) | A captured partner sale replayed under a new Idempotency-Key was charged again | NekoBet | Medium | CVSS 3.1: 5.9 | 2026-11-02 |
| [ESC-03](findings/ESC-03-kind-ports-on-all-interfaces.md) | The cluster published the app, Grafana and Prometheus to the local network | OpsCircuit | Medium | CVSS 3.1: 5.4 | 2026-11-02 |
| [ESC-04](findings/ESC-04-uploaded-photos-keep-gps.md) | Uploaded photos kept their EXIF metadata, GPS included | Yamesi | Medium | CVSS 3.1: 4.3 | 2026-11-02 |
| [ESC-05](findings/ESC-05-sellers-receive-costs.md) | Sellers received the costs behind the admin-only margin report | Yamesi | Medium | CVSS 3.1: 4.3 | 2026-11-02 |
| [ESC-06](findings/ESC-06-jpeg-prefixed-html-accepted.md) | A file that only started like a JPEG was accepted as a photo | Yamesi | Informational | Not scored | 2026-11-02 |
| [ESC-07](findings/ESC-07-vulnerable-base-images.md) | Runtime images shipped with 64 fixable critical and high CVEs | NekoBet, Yamesi | High | Trivy's rating of the CVEs | 2026-11-01 |
| [ESC-08](findings/ESC-08-demo-hmac-secrets-outside-demo.md) | The published demo signing secrets were accepted in production mode | NekoBet | High | CVSS 3.1: 8.2 (first published as 6.5; see the finding) | 2026-11-01, completed 2026-11-02 |
| [ESC-09](findings/ESC-09-compose-ports-on-all-interfaces.md) | The Docker Compose demos listened on every network interface | NekoBet, Yamesi | Medium | CVSS 3.1: 5.4 | 2026-11-01 |
| [ESC-10](findings/ESC-10-gps-in-published-photo.md) | A catalog photo in the public repository carried exact GPS coordinates | Yamesi | Medium | CVSS 3.1: 5.3 | 2026-11-01 |
| [ESC-11](findings/ESC-11-no-login-throttling.md) | Logins could be guessed without limit | NekoBet, Yamesi | Medium | CVSS 3.1: 4.8 | 2026-11-01 |
| [ESC-12](findings/ESC-12-missing-security-headers.md) | Missing security headers, and nginx announced its version | NekoBet, Yamesi | Medium | OWASP ZAP's risk rating | 2026-11-01 |

Scored with CVSS 3.1: 1 Critical, 1 High and 7 Medium. Scanner-rated: 1 High and 1 Medium. Informational: 1.

## What held up

| Attack | Result |
|---|---|
| Any private route without a token | 401 on every route tried in both apps |
| A token with `alg: none`, or a real token with its role changed to admin | 401: the algorithm is pinned to HS256 and the signature covers the claims |
| A cashier on admin routes, including crediting its own store | 403 |
| A cashier reading another store's sale by id, or filtering by the other store's id | 404, and the filter is ignored for cashiers |
| A cashier naming another store's `posId` in a sale body | 400: the body schema is strict and the store comes from the token |
| A partner reading another store's sale | 404 |
| A seller on any admin action (margins, audit, lots, catalog edits, closing, assistant) | 403 |
| A partner request with its body changed, a timestamp 301 s old or 301 s ahead, or an unknown key | 401; an unknown key gets the same answer as a bad signature |
| A casino wallet debit replayed with the same transaction id | Applied once |
| PHP, SVG and PDF files disguised as photos; a 2 MiB + 1 byte upload | 400 and 413, and the current photo is untouched |
| SQL injection | Every statement takes its values as parameters (code review) |

## Regression suite

[`attacks/`](attacks/) holds the attacks of this assessment as Node.js tests with no dependencies: 38 tests
in three files (NekoBet, Yamesi, network exposure). They run in three places:

- **In NekoBet's and Yamesi's CI,** on every push and pull request, against the stack that CI has just built.
  A change that reopens a finding fails before merge.
- **In this repository's [CI](.github/workflows/ci.yml),** on every push here and every Monday, against the
  latest `main` of both apps.
- **Locally:** `make attack`, with NekoBet on :8081 and Yamesi on :8083 from sibling checkouts
  (`make .env && make up` in each).

### Coverage

| Finding | Regression test |
|---|---|
| ESC-01 | Attack suite: each API refuses to start with the placeholder, and a token signed with it gets 401. App unit tests on the configuration. |
| ESC-02 | Attack suite: a replay under a new key gets 401; a replay under its own key returns the original sale; the balance moves once. App unit and e2e tests. |
| ESC-03 | Network attack test (ports 8082, 3030, 9090, while the cluster runs). OpsCircuit `make validate`. |
| ESC-04 | Attack suite: the photo served from the bucket has no GPS. Yamesi unit (6) and e2e tests. |
| ESC-05 | Attack suite: a seller gets no costs, an admin does. Yamesi e2e test. |
| ESC-06 | Attack suite: the JPEG-prefixed HTML file gets 400. Yamesi unit test. |
| ESC-07 | App CI only: the Trivy gate. |
| ESC-08 | Attack suite: the API refuses to start in production mode with the published casino secret. NekoBet unit test. |
| ESC-09 | Network attack test (ports 8081, 8083, 9002). |
| ESC-10 | App CI only: the image-metadata check over committed images. |
| ESC-11 | Attack suite: a fresh account gets 401 five times, then 429 for the right password. App e2e tests. |
| ESC-12 | App CI only: the ZAP baseline gate. |

Of the 38 tests, 17 guard the findings above and 18 attack the controls in "What held up". The other 3 are
baselines: a correctly signed partner call, an admin who still sees costs, and a network address to test from.

### Results

- **2026-11-02, first run (35 tests), against the vulnerable versions:** 25 passed and 10 failed.
  - Six failures were findings: the three cluster ports of ESC-03, plus ESC-04, ESC-05 and ESC-06.
  - Four failed only because the old API did not know ESC-02's new signature format. The replay itself was
    demonstrated separately; see the finding.
  - ESC-01 did not show, because that run's stack used a random secret.
- **2026-11-02, after the fixes:** 35 of 35 passed.
- **2026-11-02, after an independent review (38 tests):** three startup tests were added. Against the build
  before the second fix, the ESC-08 test failed, because the API started in production mode with the
  published casino secret. After the fix, 38 of 38 passed.

The tests inside each app cover the same fixes at the unit and e2e level: NekoBet went from 54 to 60 tests,
Yamesi from 54 to 64.

## Accepted and open risks

Every risk that is accepted or still open, including the ones below, is rated and tracked in the
[risk register](RISK_REGISTER.md).

- **Stateless tokens.** The API trusts the role inside a valid JWT and does not look the user up, which is
  why ESC-01 worked even for a user that does not exist. A disabled user or a changed role keeps working until
  the token expires: 1 hour in NekoBet, 8 hours (one shift) in Yamesi. A production version would use short
  access tokens with refresh, or a token version per user checked on each request.
- **Partner GETs can be replayed within 5 minutes.** They return data the attacker already captured. Every
  request that changes state is protected by ESC-02's fix.
- **The demo password is published on purpose.** The demo users exist only when demo data is loaded, the
  README tells reviewers how to log in, and since ESC-03 and ESC-09 every demo stack listens on loopback
  only. Signing secrets, unlike the password, are refused in production mode (ESC-01, ESC-08).
- **Lockout counters live in memory,** one per API replica. Several replicas need a shared store.
- **The live odds stream is public** by design: the browser's EventSource cannot send a token, and the
  stream carries no store or customer data.
- **ESC-06's residual risk:** a well-formed JPEG with bytes appended after its image data is still accepted.
  Those bytes are served as `image/jpeg`.

## Layout

```text
METHODOLOGY.md   scope, threat model, coverage, tools, severity, limits
findings/        one file per finding: evidence, impact, fix, regression tests
attacks/         the attacks as tests (node:test), plus lib.mjs with JWT, HMAC, EXIF and startup helpers
```
