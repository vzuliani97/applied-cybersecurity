# ESC-09: The Docker Compose demos listened on every network interface

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 5.4 (`AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) |
| Weakness | CWE-1327 Binding to an Unrestricted IP Address |
| Affected | NekoBet before `341f758`, Yamesi before `4468f57` (`docker-compose.yml`) |
| Status | Fixed 2026-11-01: nekobet `341f758`, yamesi `4468f57` |

## Description

`ports: "8081:8080"` publishes on `0.0.0.0`. The web apps (8081, 8083) and Yamesi's object storage (9002)
were reachable from the local network, with demo passwords that are documented in the README.

## Fix

Every published port is bound to loopback (`"127.0.0.1:8081:8080"`). The same class of issue was found again
in the kind cluster on day 2, see [ESC-03](ESC-03-kind-ports-on-all-interfaces.md).

## Regression tests

[`attacks/network.test.mjs`](../attacks/network.test.mjs) connects to 8081, 8083 and 9002 on every
non-loopback address of the machine and expects them closed. It runs in this repository's CI against both
stacks.
