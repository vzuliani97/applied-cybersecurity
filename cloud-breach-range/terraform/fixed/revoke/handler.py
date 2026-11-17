"""Revoke every session of the web server's role issued before now.

It attaches the same inline policy as the "Revoke active sessions" button in
the IAM console: deny everything to tokens whose aws:TokenIssueTime is older
than this moment. The instance gets fresh credentials from IMDS on its next
refresh; the copies an attacker took stop working.
"""

import json
import os
from datetime import datetime, timezone

import boto3

iam = boto3.client("iam")


def handler(event, _context):
    role = os.environ["ROLE_NAME"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}},
            }
        ],
    }
    iam.put_role_policy(RoleName=role, PolicyName="AWSRevokeOlderSessions", PolicyDocument=json.dumps(policy))
    finding = event.get("detail", {}).get("type", "unknown")
    print(json.dumps({"revoked_role": role, "before": now, "finding": finding}))
    return {"revoked": role, "before": now}
