#!/usr/bin/env python3
"""
CloudSentinel — analyzer (library-only)

Provides:
  - analyze(snapshot) -> list[findings]
  - summarize_findings(findings)
  - render_text(findings)

Used by cloudsentinel.py wrappers.
"""
from __future__ import annotations

import json
from typing import Any, Dict

# ---------- Helper functions ----------

def ensure_list(x: Any) -> list[Any]:
    """Return x as a list so we can iterate safely."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def iter_statements(policy_doc: Dict[str, Any]):
    """Yield every statement in a policy document."""
    if not isinstance(policy_doc, dict):
        return []
    stmts = policy_doc.get("Statement")
    return ensure_list(stmts)


def resource_is_star(stmt: Dict[str, Any]) -> bool:
    """Return True if a statement applies to all resources."""
    res = stmt.get("Resource")
    if res == "*":
        return True
    if isinstance(res, list) and any(r == "*" for r in res):
        return True
    return False


def has_action(stmt: Dict[str, Any], actions: list[str]) -> bool:
    """Return True if the statement includes any of the given actions."""
    stmt_actions = ensure_list(stmt.get("Action"))
    want = set(actions)
    return any(isinstance(a, str) and a in want for a in stmt_actions)


def has_wildcard_action(stmt: Dict[str, Any], prefixes: list[str]) -> bool:
    """Return True if the statement contains actions like 'iam:*' or 's3:*'."""
    actions = ensure_list(stmt.get("Action"))
    prefs = [p + ":" for p in prefixes]
    for a in actions:
        if isinstance(a, str) and a.endswith(":*") and any(a.startswith(p) for p in prefs):
            return True
    return False

# ---------- Rule R1 ----------

def r1_passrole_star(role: Dict[str, Any]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
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

# ---------- Rule R2 ----------

def r2_admin_star(role: Dict[str, Any]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    prefixes = ["iam", "sts", "ec2", "s3", "lambda"]
    def sev_for(a: str) -> str:
        return "HIGH" if a.startswith("iam:") or a.startswith("sts:") else "MEDIUM"
    for pname, pdoc in (role.get("InlinePolicies") or {}).items():
        for stmt in iter_statements(pdoc):
            if has_wildcard_action(stmt, prefixes) and resource_is_star(stmt):
                sev = "MEDIUM"
                for act in ensure_list(stmt.get("Action")):
                    if isinstance(act, str) and act.endswith(":*"):
                        sev = max(sev, sev_for(act), key=["INFO","LOW","MEDIUM","HIGH"].index)
                findings.append({
                    "rule": "R2",
                    "severity": sev,
                    "title": "Admin-style wildcard action on *",
                    "role": role.get("RoleName"),
                    "policy_type": "inline",
                    "policy_name": pname,
                    "statement": stmt,
                })
    for ap in (role.get("AttachedPolicies") or []):
        pdoc = ap.get("PolicyDocument")
        if not pdoc:
            continue
        for stmt in iter_statements(pdoc):
            if has_wildcard_action(stmt, prefixes) and resource_is_star(stmt):
                sev = "MEDIUM"
                for act in ensure_list(stmt.get("Action")):
                    if isinstance(act, str) and act.endswith(":*"):
                        sev = max(sev, sev_for(act), key=["INFO","LOW","MEDIUM","HIGH"].index)
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

# ---------- Rule R3 ----------

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

# ---------- Analyzer ----------

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
                    "statement": stmt,  # latent bug left as-is (not executed unless a rule raises)
                })
    return all_findings

# ---------- Summary ----------

def summarize_findings(findings: list[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    by_rule: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_rule[f.get("rule", "?")] = by_rule.get(f.get("rule", "?"), 0) + 1
        by_sev[f.get("severity", "INFO")] = by_sev.get(f.get("severity", "INFO"), 0) + 1
    return {"by_rule": by_rule, "by_severity": by_sev}

# ---------- Output ----------

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
    return "\n".join(lines)

























