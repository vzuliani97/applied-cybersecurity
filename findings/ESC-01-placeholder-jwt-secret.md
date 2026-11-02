# ESC-01: The JWT secret published in .env.example was accepted, so anyone could sign an admin token

| | |
|---|---|
| Severity | **High**, CVSS 3.1 7.4 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`) |
| Weakness | CWE-1188 Initialization of a Resource with an Insecure Default; OWASP A05:2021 Security Misconfiguration |
| Affected | NekoBet `6b0483b`, Yamesi `15f0bf8` (`backend/src/config.ts`, `.env.example`, `Makefile`, CI) |
| Status | Fixed: nekobet `1b7353c`, yamesi `f606dad` |

## Description

Both quick starts said `cp .env.example .env  # then change the values`. The example file contains
`JWT_SECRET=replace-with-output-of-openssl-rand-hex-32`, which is 41 characters long, so it passed the
only check (`min(32)`). CI did exactly that copy, so every CI run signed tokens with a public key.
Whoever runs a copy without editing `.env` hands out the key to their admin role.

The API trusts the role inside a valid token and does not look the user up, so a forged token does not even
need an existing account.

## Evidence (2026-11-02, NekoBet)

```text
$ JWT_SECRET=replace-with-output-of-openssl-rand-hex-32 docker compose up -d --wait backend
# HS256 token, role ADMIN, sub = a user id that does not exist, signed with the placeholder
forged ADMIN token, GET /pos -> 200 [{"id":"53e1…","name":"Tienda Centro","balance":98000,"active":true,…}]

# same token against the stack started with a random secret
forged ADMIN token, GET /pos -> 401 {"error":{"code":"UNAUTHORIZED","message":"Invalid or expired token"}}
```

Yamesi had the same configuration: the same placeholder in `.env.example`, the same `min(32)` check, and the
same `cp` in CI. The exploit was run against NekoBet only.

## Impact

Full administrator access: list and credit stores (NekoBet), read margins, audit trail and invoices, and edit
the catalog (Yamesi). The precondition is a deployment that kept the example value, hence `AC:H`.

## Fix

- The configuration refuses any secret that starts with `replace-with`, at startup and in every environment
  (`JWT_SECRET` in both apps, plus `S3_SECRET_KEY` in Yamesi).
- `make .env` creates `.env` from the example with a fresh `openssl rand -hex 32` for each placeholder.
  `make up`, `make test` and the other targets depend on it, and CI runs it instead of `cp`.

```text
$ docker compose run --rm --no-deps -e JWT_SECRET=replace-with-output-of-openssl-rand-hex-32 backend
Invalid configuration: JWT_SECRET: replace the .env.example placeholder: openssl rand -hex 32, or delete .env and run make .env   (exit 1)
```

## Regression tests

- NekoBet `backend/test/unit/config.spec.ts` and Yamesi `backend/test/unit/config.spec.ts`: the placeholder is refused.
- [`attacks/nekobet.test.mjs`](../attacks/nekobet.test.mjs) and [`attacks/yamesi.test.mjs`](../attacks/yamesi.test.mjs):
  an admin token signed with the placeholder gets 401 from the running stack.
