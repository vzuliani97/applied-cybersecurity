# ESC-03: The OpsCircuit cluster published the app, Grafana and Prometheus to the local network

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 5.4 (`AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) |
| Weakness | CWE-1327 Binding to an Unrestricted IP Address; OWASP A05:2021 Security Misconfiguration |
| Affected | OpsCircuit `7f8bd14` (`kind/cluster.yaml`) |
| Status | Fixed: opscircuit `9ba5585` |

## Description

The day-1 fix for the Compose demos ([ESC-09](ESC-09-compose-ports-on-all-interfaces.md)) did not cover
OpsCircuit, which runs NekoBet on a local kind cluster. kind's `extraPortMappings` listen on `0.0.0.0` unless
`listenAddress` is set, so the three NodePorts were reachable from any device on the same network.

## Evidence (2026-11-02, from the machine's own LAN address)

```text
$ curl -s -o /dev/null -w '%{http_code}' http://<LAN address>:8082/   -> 200   NekoBet web
$ curl ... http://<LAN address>:3030/                                 -> 200   Grafana, anonymous Viewer
$ curl ... http://<LAN address>:9090/                                 -> 302   Prometheus, no authentication
```

The NekoBet ports of the Compose stack (8081) and Yamesi's (8083, 9002) were closed on the same address.

## Impact

Anyone on the same Wi-Fi (a coworking space, a café) could open the NekoBet portal. The cluster's demo
password is set in the public Makefile, so that means logging in as the demo admin. They could also browse
the dashboards and query every metric and scrape target in Prometheus, which has no authentication.

## Fix

Each mapping now has `listenAddress: 127.0.0.1`, and `make validate` fails if a `hostPort` lacks it. kind
reads port mappings only when it creates the cluster, so the fix was verified on a recreated cluster.

## Regression tests

- OpsCircuit `make validate` (runs in CI): every `hostPort` in `kind/cluster.yaml` listens on loopback.
- [`attacks/network.test.mjs`](../attacks/network.test.mjs): ports 8082, 3030 and 9090 are closed on every
  non-loopback address of the machine while the cluster runs.
