# ESC-01: The JWT secret published in .env.example was accepted, so anyone could sign an admin token

| | |
|---|---|
| Severity | **Critical**, CVSS 3.1 9.1 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`); first published as 7.4 with `AC:H`, see Scoring |
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
the catalog (Yamesi).

## Scoring

The first version of this report scored 7.4, with `AC:H`. The reasoning was that the attack only works where a
deployment kept the example value, which the attacker does not control. An independent review questioned that,
and the CVSS 3.1 documents side with the review:

- The [User Guide](https://www.first.org/cvss/v3.1/user-guide), section 2.3.3 "Assume Vulnerable
  Configurations", says a flaw that depends on a configuration is scored "assuming it is in that configuration",
  unless the configuration is unreasonable, one that deliberately puts the target in a vulnerable state.
- CVSS 3.1 removed "the presence of certain system configuration settings" from the conditions that make
  attack complexity high, which v3.0 had listed.

Copying `.env.example` was this project's documented quick start and exactly what its own CI did, so the
configuration is reasonable. With it in place, the attack is one HMAC computation: `AC:L`, base score **9.1**.
The 7.4 figure described the risk to a deployment that followed the README's advice to change the values. That
is an environmental consideration, and the CVSS Environmental metrics, not the base score, are where it belongs.

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
