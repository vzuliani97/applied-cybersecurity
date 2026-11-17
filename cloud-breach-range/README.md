# Cloud breach range

Live demo: **https://valterzuliani.com/cloud/**

Part of [Applied Cyber Security](../README.md). The [API attack range](../api-attack-range/) covers flaws inside one API; this lab covers what happens when an app flaw meets a misconfigured cloud account.

It replays a well-known AWS attack chain, the pattern behind the 2019 Capital One breach:

1. **SSRF.** The shop has a link preview that fetches any URL from its server.
2. **Instance metadata.** The attacker points it at `169.254.169.254`. IMDSv1 answers a plain GET with the instance role's temporary credentials.
3. **Stolen credentials.** The keys come back inside the preview response and leave AWS.
4. **Over-privileged role.** From their own laptop, the attacker signs S3 requests with those keys. The role has `s3:*` on `*`.
5. **Data out.** `customers-2026-10.csv` downloads. CloudTrail only keeps management events, so the download is not even logged.

Five defences can be switched on, alone or together. Each one breaks the chain by itself, at a different link:

| Defence | Layer | Where it breaks the chain |
|---|---|---|
| URL allowlist | Application | The preview refuses `169.254.169.254`: no SSRF |
| IMDSv2 required | EC2 | IMDS answers 401: a token needs a PUT with a custom header, which a GET-only SSRF cannot send |
| Least-privilege role | IAM | The keys leak but only open `acme-shop-assets/*`; S3 answers AccessDenied (implicit deny) |
| VPC endpoint only | Bucket policy | `Deny s3:*` unless `aws:SourceVpce` matches; requests from the internet carry no endpoint, so valid keys still fail (explicit deny) |
| Detect and respond | CloudTrail, GuardDuty, EventBridge, Lambda | The first outside call raises `InstanceCredentialExfiltration.OutsideAWS`; a Lambda attaches `AWSRevokeOlderSessions`, and the next calls fail |

While the attack runs, the page shows both sides live: the attacker's terminal (`curl`, `aws s3 ls`, `aws s3 cp`) and what AWS sees (IMDS answers, each IAM decision with the statement that decided it, CloudTrail entries, GuardDuty findings). Every raw request and response is kept afterwards.

## How it stays safe and still feels real

Nothing touches a real AWS account. A **service worker** plays the shop, IMDS and S3 inside the visitor's browser. The parts that matter are implemented rather than faked:

- **IAM evaluation** follows AWS's order for a same-account request: explicit deny, then allow from the identity or resource policy, then implicit deny. It supports wildcards and the `StringEquals`, `StringNotEquals` and `DateLessThan` conditions, including the rule that a negated operator matches when the key is missing, which is what makes the VPC endpoint policy work ([src/core/iam.ts](src/core/iam.ts)).
- **Credentials** are random on every run (`ASIA…` key id, secret, session token), and S3 checks an HMAC-SHA256 signature over method, path, query and date with Web Crypto. It is a simplified SigV4: no derived signing key or canonical headers. Tampering with the signature, or reusing it for another path, fails with `SignatureDoesNotMatch` ([src/core/sign.ts](src/core/sign.ts)).
- **Session revocation** is the same inline policy the IAM console's "Revoke active sessions" button attaches: deny everything when `aws:TokenIssueTime` is older than now.

One shortcut is deliberate: in real AWS, GuardDuty takes minutes to raise a finding. Here it is instant so the response is visible, and the page says so.

## The infrastructure, as code

[`terraform/vulnerable`](terraform/vulnerable/main.tf) is the shop as deployed. [`terraform/fixed`](terraform/fixed/main.tf) adds every control, plus the [Lambda that revokes sessions](terraform/fixed/revoke/handler.py). Neither is meant to be applied as is; they are for reading, validating and scanning.

CI runs `terraform validate` on both and uses Checkov as a gate on the 9 checks that map to this chain (IMDSv1, IAM wildcards and exfiltration, public access blocks, CloudTrail coverage and encryption), 14 results across the resources. The fixed stack must pass all of them, and the vulnerable stack must fail them, so the scanner is shown to catch exactly what the lab exploits.

## Run it

Requires Node 22.18 or later.

```sh
cd cloud-breach-range
npm install
npm test          # 16 tests: the IAM evaluator, each defence alone, all together, S3 signature checks, the allowlist
npm run build     # bundles the page and the service worker into dist/
```

Inspired by [flaws.cloud](http://flaws.cloud) and Rhino Security Labs' [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat). Original code. The customer data is fictional.
