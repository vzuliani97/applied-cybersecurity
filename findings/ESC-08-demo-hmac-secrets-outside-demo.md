# ESC-08: The published demo signing secrets were accepted in production mode

| | |
|---|---|
| Severity | **High**, CVSS 3.1 8.2 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`); first published as 6.5 with `AC:H`, see Scoring |
| Weakness | CWE-1188 Initialization of a Resource with an Insecure Default |
| Affected | NekoBet before `341f758` fully; before `69954b4` when demo data was loaded (`backend/src/config.ts`) |
| Status | Partly fixed 2026-11-01 (nekobet `341f758`); completed 2026-11-02 (nekobet `69954b4`, opscircuit `4ab9481`) |

## Description

`CASINO_PROVIDER_SECRET` and `DEMO_PARTNER_SECRET` default to values written in the public repository. Those
defaults let the demo start with no setup. The casino guard uses its secret whether or not demo data is loaded.

The first fix (2026-11-01) refused the defaults in production mode, but only when no demo data was loaded. An
independent review asked about that exception, and it turned out to be the common case: Docker Compose and the
OpsCircuit cluster both run the API with `NODE_ENV=production` and `SEED_DEMO_DATA=true`, and neither set
`CASINO_PROVIDER_SECRET`. Both stacks therefore accepted wallet callbacks signed with the published secret.

## Evidence (2026-11-02)

```text
# build before the second fix, started like Compose does, with the published casino secret
refuses to start in production with the published casino provider secret, even with demo data (ESC-08)
  ✖ the API started with a published signing secret
```

## Impact

Anyone who could reach the API and had read the repository could sign casino wallet callbacks, crediting any
store's balance, or sign partner calls. Since ESC-03 and ESC-09 the demo stacks listen on loopback only, which
limited who could reach them, but not the flaw itself.

## Scoring

The first version of this report scored 6.5 with `AC:H`, because the attack needs a deployment that did not set
its own secrets. For the reason explained in [ESC-01](ESC-01-placeholder-jwt-secret.md#scoring), CVSS 3.1
scores the vulnerable configuration as present when it is a reasonable one, and here it was the default of both
demo stacks. With `AC:L` the base score is **8.2**.

## Fix

- In production mode the configuration refuses the `demo-` defaults of both signing secrets, with or without
  demo data. Tests and local development keep them.
- `.env.example` has placeholders for both, so `make .env` generates random values, and Compose passes them to
  the API. The OpsCircuit cluster's secrets file gets a random `CASINO_PROVIDER_SECRET` too. An older file has
  the key appended instead of being regenerated.
- The demo partner's stored secret now follows `DEMO_PARTNER_SECRET` on every start, so rotating it in `.env`
  takes effect on restart.

## Regression tests

- NekoBet `backend/test/unit/config.spec.ts`: production mode refuses the defaults, with and without demo data,
  and accepts real secrets; other modes keep the defaults.
- [`attacks/nekobet.test.mjs`](../attacks/nekobet.test.mjs): the API refuses to start in production mode with
  the published casino secret.
