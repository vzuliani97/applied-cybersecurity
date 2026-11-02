# ESC-07: Runtime images shipped with fixable critical and high CVEs

| | |
|---|---|
| Severity | **High** (scanner rating: Trivy reported critical and high CVEs; exploitability was not assessed one by one) |
| Weakness | CWE-1104 Use of Unmaintained Third Party Components; OWASP A06:2021 Vulnerable and Outdated Components |
| Affected | NekoBet and Yamesi frontend images (nginx 1.27 base); Yamesi backend image (npm bundled in `node:24-alpine`) |
| Status | Fixed 2026-11-01: nekobet `986f5b4`, yamesi `0559246`; CI gate in nekobet `6b0483b`, yamesi `15f0bf8` |

## Description and evidence

A Trivy scan of the four production images found 58 fixable critical and high CVEs in the nginx 1.27 base
of the frontends, and 6 high ones in the Yamesi backend. The backend ones were not in the app's
dependencies: they came from npm, which the Node base image bundles and the runtime never uses.

## Fix

- Frontends: `nginxinc/nginx-unprivileged:1.30.6-alpine` plus `apk upgrade` at build time.
- Backends: npm, npx, corepack and yarn are deleted from the runtime stage, which only needs `node`.

After the fix, Trivy reports 0 fixable critical or high findings in all four images.

## Regression tests

CI builds the images and fails if Trivy (pinned by digest) finds any fixable critical or high CVE
(`--exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed`). Unfixed CVEs do not block, because no upgrade
exists yet to apply.
