#!/usr/bin/env python3
"""
CloudSentinel — analyze.py (built function-by-function)

We will add one small function per step with clear docstrings and keep it
simple for a demo-friendly, readable analyzer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

# Step 1 — JSON loader
# ---------------------
# Purpose: read the snapshot file created by collect_iam.py and return it as a dict.
# Design: minimal, raise on common errors so callers fail fast with clear messages.

def load_json(path: str) -> Dict[str, Any]:
    """Load and parse a JSON file from disk.

    Args:
        path: Filesystem path to the JSON snapshot (e.g., "data/iam_snapshot.json").

    Returns:
        A Python dict representing the JSON content.

    Raises:
        FileNotFoundError: If the path does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    return json.loads(Path(path).read_text(encoding="utf-8"))

# Step 2 — ensure_list
# ---------------------
# Purpose: make sure that any field we handle (like Action, Resource, Principal)
# can be safely iterated as a list.
# Example:
#   ensure_list('s3:*')       -> ['s3:*']
#   ensure_list(['s3:*'])     -> ['s3:*']
#   ensure_list(None)         -> []
# This keeps later logic simple and avoids if/else clutter.

def ensure_list(x: Any) -> list[Any]:
    """Return x as a list.

    Args:
        x: Any object that might be a list, string, or None.

    Returns:
        Always a list. If x is None, returns an empty list.
    """
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# Step 3 — iter_statements
# -------------------------
# Purpose: AWS policy documents contain a key called 'Statement' that can be
# either a single dictionary or a list of dictionaries. This helper yields each
# statement safely as a dictionary so our rule functions can just loop over it.
# Example input:
#   {"Statement": {"Action": "s3:*", "Effect": "Allow"}}
#   {"Statement": [{...}, {...}]}
# Example use:
#   for stmt in iter_statements(policy):
#       print(stmt['Action'])

def iter_statements(policy_doc: Dict[str, Any]):
    """Yield every statement in a policy document.

    Args:
        policy_doc: A dictionary representing an IAM policy document.

    Yields:
        Each statement (dict) in the document, even if there is only one.
    """
    if not isinstance(policy_doc, dict):
        return []
    stmts = policy_doc.get("Statement")
    return ensure_list(stmts)


# Step 4 — resource_is_star
# --------------------------
# Purpose: detect whether a policy statement applies to all resources.
# IAM policies may use "Resource": "*" or a list like ["*", ...].
# This function returns True if either case is found.

def resource_is_star(stmt: Dict[str, Any]) -> bool:
    """Return True if a statement's Resource allows everything ('*').

    Args:
        stmt: A single policy statement.

    Returns:
        True if Resource is '*' or includes '*', otherwise False.
    """
    res = stmt.get("Resource")
    if res == "*":
        return True
    if isinstance(res, list) and any(r == "*" for r in res):
        return True
    return False

# Step 5 — has_action
# --------------------
# Purpose: check whether a given policy statement includes one of the actions
# we're looking for. For example, does it allow 'iam:PassRole' or 's3:DeleteBucket'?
# The 'Action' field can be a string or a list of strings, so we reuse ensure_list.

def has_action(stmt: Dict[str, Any], actions: list[str]) -> bool:
    """Return True if any of the specified actions appear in the statement.

    Args:
        stmt: A single policy statement.
        actions: A list of action names to search for (e.g., ["iam:PassRole"]).

    Returns:
        True if at least one action matches exactly.
    """
    stmt_actions = ensure_list(stmt.get("Action"))
    want = set(actions)
    return any(isinstance(a, str) and a in want for a in stmt_actions)

# Step 6 — has_wildcard_action
# -----------------------------
# Purpose: detect actions like 's3:*', 'iam:*'. You pass service prefixes
# (e.g., ["iam", "s3"]) and we check if any action equals '<prefix>:*'.

def has_wildcard_action(stmt: Dict[str, Any], prefixes: list[str]) -> bool:
    actions = ensure_list(stmt.get("Action"))
    prefs = [p + ":" for p in prefixes]
    for a in actions:
        if isinstance(a, str) and a.endswith(":*") and any(a.startswith(p) for p in prefs):
            return True
    return False


# Step 7 — r1_passrole_star
# -------------------------
# Purpose: HIGH severity if a policy grants iam:PassRole on Resource "*".
# Checks both inline policies and managed policies (when the collector included
# the managed policy's PolicyDocument in the snapshot).

def r1_passrole_star(role: Dict[str, Any]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []

    # Inline policies
    for pname, pdoc in (role.get("InlinePolicies") or {}).items():
        for stmt in iter_statements(pdoc):
            if has_action(stmt, ["iam:PassRole"]) and resource_is_star(stmt):
                findings.append({
                    "rule": "R1",
                    "severity": "HIGH",
                    "title": "iam:PassRole allowed on all resources (*)",
                    "role": role.get("RoleName"),
                    "policy_type": "inline",
                    "policy_name": pname,
                    "statement": stmt,
                })

    # Managed policies (attached)
    for ap in (role.get("AttachedPolicies") or []):
        pdoc = ap.get("PolicyDocument")
        if not pdoc:
            continue
        for stmt in iter_statements(pdoc):
            if has_action(stmt, ["iam:PassRole"]) and resource_is_star(stmt):
                findings.append({
                    "rule": "R1",
                    "severity": "HIGH",
                    "title": "iam:PassRole allowed on all resources (*)",
                    "role": role.get("RoleName"),
                    "policy_type": "managed",
                    "policy_arn": ap.get("PolicyArn"),
                    "policy_name": ap.get("PolicyName"),
                    "statement": stmt,
                })

    return findings


# Step 8 — r2_admin_star
# ----------------------
# Purpose: MEDIUM/HIGH severity if a statement grants '<service>:*' on '*'.
# If the wildcard action is in 'iam' or 'sts', bump severity to HIGH.

def r2_admin_star(role: Dict[str, Any]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    prefixes = ["iam", "sts", "ec2", "s3", "lambda"]

    def sev_for_action(action: str) -> str:
        return "HIGH" if action.startswith("iam:") or action.startswith("sts:") else "MEDIUM"

    # Inline
    for pname, pdoc in (role.get("InlinePolicies") or {}).items():
        for stmt in iter_statements(pdoc):
            if has_wildcard_action(stmt, prefixes) and resource_is_star(stmt):
                # Derive worst-case severity from the actions in this statement
                sev = "MEDIUM"
                for act in ensure_list(stmt.get("Action")):
                    if isinstance(act, str) and act.endswith(":*"):
                        sev = max(sev, sev_for_action(act), key=["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index)
                findings.append({
                    "rule": "R2",
                    "severity": sev,
                    "title": "Admin-style wildcard action on *",
                    "role": role.get("RoleName"),
                    "policy_type": "inline",
                    "policy_name": pname,
                    "statement": stmt,
                })

    # Managed
    for ap in (role.get("AttachedPolicies") or []):
        pdoc = ap.get("PolicyDocument")
        if not pdoc:
            continue
        for stmt in iter_statements(pdoc):
            if has_wildcard_action(stmt, prefixes) and resource_is_star(stmt):
                sev = "MEDIUM"
                for act in ensure_list(stmt.get("Action")):
                    if isinstance(act, str) and act.endswith(":*"):
                        sev = max(sev, sev_for_action(act), key=["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index)
                findings.append({
                    "rule": "R2",
                    "severity": sev,
                    "title": "Admin-style wildcard action on *",
                    "role": role.get("RoleName"),
                    "policy_type": "managed",
                    "policy_arn": ap.get("PolicyArn"),
                    "policy_name": ap.get("PolicyName"),
                    "statement": stmt,
                })

    return findings


# Step 9 — r3_trust_broad
# -----------------------
# Purpose: flag broad/unsafe trust principals in assume role policies.
#  • HIGH if Principal == "*"
#  • MEDIUM if Principal is an account root (":root") without any Condition

def r3_trust_broad(role: Dict[str, Any]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    trust = (role.get("AssumeRolePolicyDocument") or {})
    for stmt in iter_statements(trust):
        principal = (stmt.get("Principal") or {}).get("AWS")
        cond = stmt.get("Condition")
        for p in ensure_list(principal):
            if p == "*":
                findings.append({
                    "rule": "R3",
                    "severity": "HIGH",
                    "title": "Trust allows any AWS principal (*)",
                    "role": role.get("RoleName"),
                    "statement": stmt,
                })
            elif isinstance(p, str) and p.endswith(":root") and not cond:
                findings.append({
                    "rule": "R3",
                    "severity": "MEDIUM",
                    "title": "Trust allows entire account root without conditions",
                    "role": role.get("RoleName"),
                    "statement": stmt,
                })
    return findings


# Step 10 — analyze (runner)
# --------------------------
# Purpose: iterate roles and run all rules, collecting findings.

def analyze(snapshot: Dict[str, Any]) -> list[Dict[str, Any]]:
    roles = (snapshot.get("iam") or {}).get("roles") or []
    all_findings: list[Dict[str, Any]] = []
    rules = [r1_passrole_star, r2_admin_star, r3_trust_broad]
    for role in roles:
        for rule in rules:
            try:
                all_findings.extend(rule(role))
            except Exception as e:
                all_findings.append({
                    "rule": "ENGINE",
                    "severity": "LOW",
                    "title": f"Rule crashed on role {role.get('RoleName')}",
                    "error": str(e),
                })
    return all_findings


# Step 11 — render_text
# ----------------------
# Purpose: human-friendly console output for the demo.

def render_text(findings: list[Dict[str, Any]]) -> str:
    if not findings:
        return "No findings."
    lines: list[str] = []
    for f in findings:
        lines.append(f"[{f['severity']}] {f['rule']} — {f['title']}")
        if role := f.get("role"):
            lines.append(f"  role: {role}")
        if f.get("policy_type"):
            lines.append(f"  policy: {f.get('policy_type')} {f.get('policy_name') or f.get('policy_arn')}")
        lines.append("")
    return "".join(lines)


# Step 12 — main
# ---------------
# Purpose: tiny CLI for your demo. Keep flags minimal.

def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="CloudSentinel analyze (simple demo)")
    ap.add_argument("--in", dest="inp", required=True, help="Path to iam_snapshot.json")
    ap.add_argument("--out", dest="out", help="Write findings to this file (optional)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    args = ap.parse_args(argv)

    snapshot = load_json(args.inp)
    findings = analyze(snapshot)

    if args.format == "json":
        out = json.dumps(findings, indent=2)
    else:
        out = render_text(findings)

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"[+] Wrote findings to {args.out}")
    else:
        print(out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())























