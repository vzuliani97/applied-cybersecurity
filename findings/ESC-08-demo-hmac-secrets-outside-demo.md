# ESC-08: The published demo HMAC secrets would have been used outside demo mode

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 6.5 (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N`) |
| Weakness | CWE-1188 Initialization of a Resource with an Insecure Default |
| Affected | NekoBet before `341f758` (`backend/src/config.ts`) |
| Status | Fixed 2026-11-01: nekobet `341f758` |

## Description

`CASINO_PROVIDER_SECRET` and `DEMO_PARTNER_SECRET` default to values written in the public repository. Those
defaults make the demo start with no setup. Nothing stopped a production deployment from starting with them
too. The casino guard uses its secret whether or not demo data is loaded.

## Impact

Anyone who read the repository could sign casino wallet callbacks, crediting any store's balance, or sign
partner calls. The precondition is a deployment that did not set its own secrets, hence `AC:H`.

## Fix

With `NODE_ENV=production` and no demo data, the configuration refuses to start if either secret still has
its `demo-` default.

## Regression tests

NekoBet `backend/test/unit/config.spec.ts` (added 2026-11-02): production without demo data and with the
defaults fails to load; with demo data it loads.
