# Escudo

[![Attack suite](https://github.com/vzuliani97/escudo/actions/workflows/ci.yml/badge.svg)](https://github.com/vzuliani97/escudo/actions/workflows/ci.yml)

A security assessment of my own applications: [NekoBet](https://github.com/vzuliani97/nekobet),
[Yamesi](https://github.com/vzuliani97/yamesi), and the [OpsCircuit](https://github.com/vzuliani97/opscircuit)
cluster that runs NekoBet. It found 12 issues, and all of them are fixed. Each fix has a regression test,
and the attacks run again in CI against the latest code of both apps.

Scope, threat model, tools and what was not covered: [METHODOLOGY.md](METHODOLOGY.md).

## Findings

| ID | Finding | Target | Severity | Fixed |
|---|---|---|---|---|
| [ESC-01](findings/ESC-01-placeholder-jwt-secret.md) | The JWT secret published in `.env.example` was accepted, so anyone could sign an admin token | NekoBet, Yamesi | High 7.4 | 2026-11-02 |
| [ESC-02](findings/ESC-02-hmac-replay-new-idempotency-key.md) | A captured partner sale replayed under a new Idempotency-Key was charged again | NekoBet | Medium 5.9 | 2026-11-02 |
| [ESC-03](findings/ESC-03-kind-ports-on-all-interfaces.md) | The cluster published the app, Grafana and Prometheus to the local network | OpsCircuit | Medium 5.4 | 2026-11-02 |
| [ESC-04](findings/ESC-04-uploaded-photos-keep-gps.md) | Uploaded photos kept their EXIF metadata, GPS included | Yamesi | Medium 4.3 | 2026-11-02 |
| [ESC-05](findings/ESC-05-sellers-receive-costs.md) | Sellers received the costs behind the admin-only margin report | Yamesi | Medium 4.3 | 2026-11-02 |
| [ESC-06](findings/ESC-06-jpeg-prefixed-html-accepted.md) | A file that only started like a JPEG was accepted as a photo | Yamesi | Informational | 2026-11-02 |
| [ESC-07](findings/ESC-07-vulnerable-base-images.md) | Runtime images shipped with 64 fixable critical and high CVEs | NekoBet, Yamesi | High (Trivy) | 2026-11-01 |
| [ESC-08](findings/ESC-08-demo-hmac-secrets-outside-demo.md) | The published demo HMAC secrets would have been used outside demo mode | NekoBet | Medium 6.5 | 2026-11-01 |
| [ESC-09](findings/ESC-09-compose-ports-on-all-interfaces.md) | The Docker Compose demos listened on every network interface | NekoBet, Yamesi | Medium 5.4 | 2026-11-01 |
| [ESC-10](findings/ESC-10-gps-in-published-photo.md) | A catalog photo in the public repository carried exact GPS coordinates | Yamesi | Medium 5.3 | 2026-11-01 |
| [ESC-11](findings/ESC-11-no-login-throttling.md) | Logins could be guessed without limit | NekoBet, Yamesi | Medium 4.8 | 2026-11-01 |
| [ESC-12](findings/ESC-12-missing-security-headers.md) | Missing security headers, and nginx announced its version | NekoBet, Yamesi | Medium (ZAP) | 2026-11-01 |

Severities are CVSS 3.1 base scores; the vector is in each finding.

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

[`attacks/`](attacks/) holds every attack from this assessment as a Node.js test with no dependencies.
There are 35 tests in three files: NekoBet, Yamesi, and network exposure.

```bash
# NekoBet on :8081 and Yamesi on :8083, from sibling checkouts (make .env && make up in each)
make attack
```

Results on 2026-11-02:

- **Against the vulnerable versions:** 25 passed and 10 failed.
  - 6 failures were findings: the three cluster ports of ESC-03, plus ESC-04, ESC-05 and ESC-06.
  - 4 failures happened because the old API did not know ESC-02's new signature format. The replay itself was demonstrated separately; see the finding.
  - ESC-01 did not show locally, because the local stack used a random secret. CI, which copied the placeholder, is where it would have shown.
- **After the fixes:** 35 of 35 passed.

[CI](.github/workflows/ci.yml) checks out the latest `main` of NekoBet and Yamesi, starts both with
random secrets, and runs the suite on every push and every Monday. A change in either app that reopens a
finding fails the run.

The tests inside each app cover the same fixes at the unit and e2e level: NekoBet went from 54 to 59 tests,
Yamesi from 54 to 64.

## Observations and accepted risks

- **Stateless tokens.** The API trusts the role inside a valid JWT and does not look the user up, which is
  why ESC-01 worked even for a user that does not exist. A disabled user or a changed role keeps working until
  the token expires: 1 hour in NekoBet, 8 hours (one shift) in Yamesi. A production version would use short
  access tokens with refresh, or a token version per user checked on each request.
- **Partner GETs can be replayed within 5 minutes.** They return data the attacker already captured. Every
  request that changes state is protected by ESC-02's fix.
- **Lockout counters live in memory,** one per API replica. Several replicas need a shared store.
- **The live odds stream is public** by design: the browser's EventSource cannot send a token, and the
  stream carries no store or customer data.
- **ESC-06's residual risk:** a well-formed JPEG with bytes appended after its image data is still accepted.
  Those bytes are served as `image/jpeg`.

## Layout

```text
METHODOLOGY.md   scope, threat model, coverage, tools, severity, limits
findings/        one file per finding: evidence, impact, fix, regression tests
attacks/         the attacks as tests (node:test), plus lib.mjs with JWT, HMAC and EXIF helpers
```
