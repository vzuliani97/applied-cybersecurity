# ESC-02: A captured partner sale could be replayed under a new Idempotency-Key and was charged again

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 5.9 (`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N`) |
| Weakness | CWE-294 Authentication Bypass by Capture-replay; OWASP API2:2023 Broken Authentication |
| Affected | NekoBet `6b0483b` (`backend/src/partner/signature.ts` and the two guards that use it) |
| Status | Fixed: nekobet `1b7353c` |

## Description

Partner calls carry `X-Timestamp` and an HMAC-SHA256 signature of `timestamp \n METHOD \n path \n sha256(body)`.
The timestamp limits a replay to 5 minutes, and the design notes said a replay inside that window "is absorbed
by idempotency". It was not: the `Idempotency-Key` header was outside the signature. Someone who captured
one signed sale (a proxy log, a debugging dump, a TLS-terminating middlebox) could send it again with any new
key within 5 minutes, and the API treated it as a new sale.

## Evidence (2026-11-02)

```text
balance before: 100000
original request -> 201 7bfd43f8-… CONFIRMED
replay, same signature, new Idempotency-Key -> 201 e81add77-… CONFIRMED replayed: false
balance after: 98000
```

Two top-ups for one authorized request. The replay must also come from an address on the partner's IP
allowlist, which together with the capture is why the attack complexity is high.

## Impact

Duplicate financial transactions on the partner's store: each replay debits the prepaid balance and sends
another top-up to the carrier.

## Fix

The idempotency key is now the fifth line of the signed string (empty when there is none):

```text
<unix seconds>\n<METHOD>\n<path with query>\n<sha256 hex of the body>\n<Idempotency-Key>
```

A replay with a new key fails the signature check (401). A replay with its own key returns the original sale
(200, `replayed: true`), so nothing is charged twice and the server keeps no extra state. The casino wallet
callbacks use the same function. The example client (`scripts/partner-client.mjs`), the README and the
design walkthrough were updated.

## Regression tests

- NekoBet `backend/test/unit/signature.spec.ts`: the signature changes when the key changes.
- NekoBet `backend/test/e2e/partner.e2e-spec.ts`: a replay under a new key gets 401 and the balance moves once.
- [`attacks/nekobet.test.mjs`](../attacks/nekobet.test.mjs): the same attack against the running stack, plus a
  replay with the original key that must return the original sale.
