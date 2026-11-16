# API attack range

Live demo: **https://valterzuliani.com/range/**

Part of [Applied Cyber Security](../README.md): the assessment there tested my own systems; this lab turns the same
API attacks into something anyone can run, flaw by flaw.

An attack range for the OWASP API Security Top 10 (2023). Each flaw has a switch: attack it while it is **vulnerable**, flip it to **fixed**, attack again and watch the request bounce. The page shows every raw request and response, plus the lines of code that make the difference.

| OWASP | Attack | What the fix does |
|---|---|---|
| API1 BOLA | Read another user's order by changing the id | Filters by owner; foreign and missing orders both return 404 |
| API2 Broken authentication | Forge a JWT with `alg: none` and become admin | Server pins HS256, verifies the signature and expiry |
| API3 Mass assignment | Send `"role": "admin"` in a profile update | Field allowlist, 400 on anything else, hash never serialized |
| API4 Unrestricted resource consumption | Brute-force a password from a 25-word list | 5 failures lock the account for 60 s (429); same error for unknown users |
| API5 BFLA | Call an admin-only DELETE as a normal user | Role checked on the server for every admin function |
| API6 Sensitive business flow | Redeem a single-use coupon 20 times in parallel | Check and write happen as one step (no gap for a race) |

## How the live demo stays safe

There is no vulnerable server on the internet. A **service worker** answers every request to `./api/*` inside the visitor's own browser, with fictional data that resets on each run. Requests are real `fetch` calls, so they show up in the browser's Network tab. If service workers are unavailable, the same API runs inside the page.

The switches are a lab control header (`x-range-vulns`), not part of the API. Anything not switched on runs in its fixed form, and the tests check that one flaw never opens another.

## Run it

Requires Node 22.18 or later (TypeScript runs directly through Node's type stripping).

```sh
cd api-attack-range
npm install
npm test          # 25 tests: every attack in both modes, cross-flaw isolation, legitimate use
npm run build     # bundles the page and the service worker into dist/
npm start         # same API as a real HTTP server on 127.0.0.1:8787, for curl / Burp / Postman
```

```sh
curl -s localhost:8787/api/login -H 'content-type: application/json' \
  -d '{"username":"lucia","password":"lucia-demo-2026"}'
curl -s localhost:8787/api/orders/1003 -H "authorization: Bearer $TOKEN" -H 'x-range-vulns: bola'
```

`npm start` binds to localhost only. Do not expose it.

## Layout

```
src/core/api.ts         the API: routes, each flaw and its fix side by side
src/core/jwt.ts         HS256 with Web Crypto, plus the alg:none flaw
src/core/password.ts    PBKDF2-SHA256, 600,000 iterations (OWASP guidance)
src/core/scenarios.ts   the six attacks, shared by the page and the tests
src/sw.ts               service worker that serves the API in the browser
src/server.ts           the same API on node:http
src/web/                the attack page
test/range.test.ts      node:test suite
```

## Credits

Inspired by [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI) and the [PortSwigger Web Security Academy](https://portswigger.net/web-security). No code was copied from them.

---

**Español:** campo de tiro del OWASP API Security Top 10. Cada falla tiene un interruptor vulnerable/corregido; todo corre en el navegador del visitante mediante un service worker, con datos ficticios. Demo en https://valterzuliani.com/range/.
