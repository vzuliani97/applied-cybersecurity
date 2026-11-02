# ESC-12: Missing security headers, and nginx announced its version

| | |
|---|---|
| Severity | **Medium** (scanner rating: OWASP ZAP rates a missing CSP as Medium, the rest Low) |
| Weakness | CWE-693 Protection Mechanism Failure; CWE-200 for the version banner |
| Affected | NekoBet and Yamesi frontends (`frontend/nginx.conf`) |
| Status | Fixed 2026-11-01: nekobet `986f5b4`, yamesi `0559246`; CI gate in nekobet `6b0483b`, yamesi `15f0bf8` |

## Description and evidence

An OWASP ZAP 2.17.0 baseline scan of the running stacks raised 8 warnings:

| ZAP rule | Result |
|---|---|
| 10038 Content Security Policy header not set | Fixed |
| 10020 Missing anti-clickjacking header | Fixed |
| 10021 X-Content-Type-Options header missing | Fixed |
| 10063 Permissions Policy header not set | Fixed |
| 10036 Server leaks version information via the `Server` header | Fixed |
| 10049 Storable and cacheable content | Accepted: only public static files; hashed build assets are cached for a year on purpose, `index.html` is no-cache |
| 10109 Modern web application | Accepted: informational, it only tells ZAP the site is a single-page app |
| 90004 Cross-Origin-Embedder-Policy missing | Accepted: the apps do not need cross-origin isolation, COOP and CORP are set, and `COEP: require-corp` can break the browser's PDF viewer |

## Fix

A strict CSP (`default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`,
plus the photo bucket's origin in Yamesi's `img-src`), `nosniff`, `X-Frame-Options: DENY`, Referrer-Policy,
Permissions-Policy, COOP/CORP, and `server_tokens off`. The headers live in one snippet included by each
`location`, because nginx drops inherited `add_header` directives as soon as a location defines its own.

Both apps were then checked in a real browser with the CSP enforced: no violations on any screen, every
photo loads, the invoice PDF opens, and an image from an origin outside the list is blocked.

## Regression tests

CI runs the ZAP baseline against the running stack and fails on any warning not marked IGNORE, with its
reason, in `.zap/rules.tsv`.
