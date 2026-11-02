# ESC-05: Sellers received the costs behind the admin-only margin report

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 4.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`) |
| Weakness | CWE-213 Exposure of Sensitive Information Due to Incompatible Policies; OWASP API3:2023 Broken Object Property Level Authorization |
| Affected | Yamesi `15f0bf8` (`GET /api/pieces`, `GET /api/pieces/:id`, `GET /api/lots`) |
| Status | Fixed: yamesi `f606dad` |

## Description

The margin report (`GET /api/reports/margins`) is restricted to administrators, and a seller gets 403. The
inputs of that margin were not restricted. Every piece carried its `laborCost` and every gold lot its
`costPerGram`, the purchase price. The inventory page even showed the cost column to sellers.

## Evidence (2026-11-02, seller token)

```text
GET /pieces          -> 200  fields include laborCost (laborCost=48000)
GET /lots            -> 200  {"code":"L-00002","supplier":"…","costPerGram":335000,…}
GET /reports/margins -> 403
```

## Impact

A seller can compute the cost and margin of every piece (gold grams × lot cost per gram + labor) and the
store's purchase prices per supplier, which the role model meant to keep with the administrator.

## Fix

The pieces and lots endpoints omit `laborCost` and `costPerGram` unless the caller is an administrator. The
inventory page shows the cost column to administrators only. Whether sellers should see costs is a business
decision; the API now enforces the one the reports already implied, and changing it is a one-line change.

## Regression tests

- Yamesi `backend/test/e2e/inventory.e2e-spec.ts`: a seller gets lots and pieces without costs; an admin still gets them.
- [`attacks/yamesi.test.mjs`](../attacks/yamesi.test.mjs): the same against the running stack.
