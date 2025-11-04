#!/usr/bin/env python3

"""
CloudSentinel — IAM Collector (read-only)

Purpose:
  Read IAM metadata from an AWS account (users, roles, managed and inline policies,
  and trust policies) and write a JSON snapshot for offline analysis and graphing.

Safety:
  - Read-only (list/get/describe) APIs only.
  - No sts:AssumeRole calls.
  - Demo mode available to run without AWS credentials.
"""


from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    import boto3
    from botocore.config import Config as BotoConfig 
    from botocore.exceptions import ClientError

except Exception:
    print("[!] Missing dependency: boto3 is required. Install it with: pip install boto3", file=sys.stderr)
    raise


def iso_utc_now() -> str:
                """Return current UTC time in ISO 8601 format with a 'Z' suffix."""
                return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def read_json(path: str | Path) -> Any:
    """Load and return JSON data from a file."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def write_json(data: Dict[str, Any], path:Path) -> None:
            """Write dictionary data to a JSON file, creating parent directories if needed."""
            path.parent.mkdir(parents=True, exist_ok = True)
            path.write_text(json.dumps(data, indent=2, sort_keys=True))
            print(f"[+] Wrote JSON to {path}")


def load_json(path: Path) -> Dict[str, Any]:
         """Load and parse a JSON file into a Python dictionary."""
         text = path.read_text()
         return json.loads(text)

def get_paginator(client, op_name: str):

        try:
                return client.get_paginator(op_name)
        except Exception:
                return None


class CloudSentinelCollector:
        
        def __init__(self, profile: Optional[str] = None):
                """Initialize AWS session and IAM clients."""

                session = boto3.Session(profile_name=profile) if profile else boto3.Session()
                cfg = BotoConfig(retries={"max_attempts":10, "mode": "standard"})
                self.iam = session.client("iam", config=cfg)
                self.sts = session.client("sts", config=cfg)
                self.snapshot: Dict[str, Any] = {
                        "collected_at": iso_utc_now(),
                        "iam": {},
                }
                self.snapshot["account_id"] = self.sts.get_caller_identity().get("Account")


                def collect(self) -> Dict[str, Any]:
                        """Run all IAM data collectors and return the full snapshot."""
                        self._collect_users()
                        self._collect_roles()
                        return self.snapshot

                def _collect_users(self) -> None:
                               
                            """Enumerate all IAM users and store them in the snapshot."""
                            print("[*] Collecting IAM users...")
                            paginator = get_paginator(self.iam, "list_users")
                            users: List[Any] = []

                            if paginator:
                                    for page in paginator.paginate:
                                            users.extend(page.get("Users", []))
                            else:
                                    try:
                                            users.extend(self.iam.list_users().get("Users", []))

                                    except ClientError as e:
                                            print(f"[!] list_users() failed: {e}")
                            
                            self.snapshot["iam"]["users"] = users
                            print(f"[+] Found {len(users)} IAM users.")

                def _collect_roles(self) -> None:
                            """Enumerate IAM roles, collect trust documents, attached and inline policies."""
                            print("[*] Collecting IAM roles...")
                            paginator = get_paginator(self.iam, "list_roles")
                            roles: List[Any] = []

                            if paginator:
                                    for page in paginator.paginate():
                                            roles.extend(page.get("Roles", []))
                            else:
                                    try:
                                            roles.extend(self.iam.list_roles().get("Roles", []))
                                    
                                    except ClientError as e:
                                            print(f"[!] list_roles() failed: {e}")

                            self.snapshot["iam"]["roles"] = roles
                            print(f"[+] Found {len(roles)} IAM roles.")
 
                            for role in roles:
                                    role_name = role.get("RoleName")
                                    try:
                                            resp = self.iam.get_role(RoleName=role_name)
                                            trust = resp.get("Role", {}).get("AssumeRolePolicyDocument")
                                            role["AssumeRolePolicyDocument"] = trust
                                            role["AttachedPolicies"] = []
                                            role["InlinePolicies"] = {}

                                            p = get_paginator(self.iam, "list_attached_role_policies")

                                            if p:
                                                    for page in p.paginate(RoleName=role_name):
                                                            role["AttachedPolicies"].extend(page.get("AttachedPolicies", []))

                                            else:
                                                    try:
                                                        resp2 = self.iam.list_attached_role_policies(RoleName=role_name)
                                                        role["AttachedPolicies"].extend(resp2.get("AttachedPolicies", []))

                                                    except ClientError as e:
                                                            print(f"[!] list_attached_policies({role_name}) failed:{e}")

                                            for ap in role["AttachedPolicies"]:
                                                    policy_arn = ap.get("PolicyArn")
                                                    try:
                                                            policy_meta = self.iam.get_policy(PolicyArn=policy_arn)
                                                            version_id = policy_meta.get("Policy", {}).get("DefaultVersionId")
                                                            if not version_id:
                                                                    continue
                                                            
                                                            policy_ver = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                                                            ap["PolicyDocument"] = policy_ver.get("PolicyVersion", {}).get("Document", {})

                                                    except ClientError as e:
                                                            print(f"[!] Failed to fetch policy document {policy_arn} for role {role_name}: {e}")

                                            in_p = get_paginator(self.iam, "list_role_policies")          

                                            if in_p:
                                                for page in in_p.paginate(RoleName=role_name):
                                                        for pname in page.get("PolicyNames", []):
                                                            try:
                                                                rp = self.iam.get_role_policy(RoleName=role_name, PolicyName=pname)
                                                                role["InlinePolicies"][pname] = rp.get("PolicyDocument", {})
                                                            except ClientError as e:
                                                                    print(f"[!] get_role_policy({role_name}, {pname}) failed: {e}")

                                            else:
                                                    try:
                                                            resp_inline = self.iam.list_role_policies(RoleName=role_name)
                                                            for pname in resp_inline.get("PolicyNames",[]):
                                                                    try:
                                                                            rp = self.iam.get_role_policy(RoleName=role_name, PolicyName=pname)
                                                                            role["InlinePolicies"][pname] = rp.get("PolicyDocument", {})
                                                                    except ClientError as e:
                                                                            print(f"[!] get_role_policy({role_name}, {pname}) failed: {e}")
                                                    except ClientError as e:
                                                        print(f"[!] list_role_policies({role_name}) failed: {e}")
                                    except ClientError as e:
                                            print(f"[!] get_role({role_name}) failed: {e}")


                                                                                                                      
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
            description="CloudSentinel IAM collector (read-only). Use --demo for offline runs."
    )

    parser.add_argument("--profile", help="AWS profile name to use (for live scan).", default=None)
    parser.add_argument("--demo", help="Path to demo/sample JSON to load instead of calling AWS.", default=None)
    parser.add_argument("--out", help="Where to write iam_snapshot.json", required=True)

    args = parser.parse_args()

    # Load JSON AWS data and write it back out

    if args.demo:
             print("[*] Loading demo dataset...")

















                                            


                        





