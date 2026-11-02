# ESC-11: Logins could be guessed without limit

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 4.8 (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`) |
| Weakness | CWE-307 Improper Restriction of Excessive Authentication Attempts; OWASP A07:2021 |
| Affected | NekoBet before `343ecb6`, Yamesi before `e8501fa` (`POST /api/auth/login`) |
| Status | Fixed 2026-11-01: nekobet `343ecb6`, yamesi `e8501fa` |

## Description

Passwords are hashed with bcrypt, which slows each guess down but does not cap the number of guesses. An
online attack against one account could run indefinitely. Success depends on the password being weak,
hence `AC:H`.

## Fix

After 5 failed logins for one email from one address within 15 minutes, that pair gets 429 until the window
ends, even with the right password. An unknown email is counted the same way, so the lock does not reveal
which accounts exist. The counter lives in memory and is bounded at 10,000 keys. With several API replicas
each one counts on its own, and a shared store would be needed (documented in the code).

## Regression tests

- `backend/test/e2e/auth.e2e-spec.ts` in both apps.
- [`attacks/nekobet.test.mjs`](../attacks/nekobet.test.mjs) and [`attacks/yamesi.test.mjs`](../attacks/yamesi.test.mjs):
  a fresh test account gets 401 five times and then 429 for the right password.
