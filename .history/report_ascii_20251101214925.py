#!/usr/bin/env python3
"""
CloudSentinel — report_ascii.py
Render findings.json as a clean terminal report (ASCII tables).

Usage:
  python report_ascii.py --in findings.json
"""

from __future__ import annotations
import argparse, json, textwrap
from pathlib import Path
from typing import Any, Dict, List, Tuple, Set

# ---- Presentation config ----------------------------------------------------

COLS = [
    ("Role", 24),
    ("Finding", 18),   # (R1/R2/R3) + short name
    ("Severity", 8),
    ("Why it matters / Notes", 70),
]

RULE_LABEL = {
    "R1": "PassRole misuse",
    "R2": "Service wildcard",
    "R3": "Trust broad/unsafe",
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Services/actions that can "launch code" (for escalation)
EXPLOITABLE_ACTIONS = {
    "ec2": {"RunInstances", "CreateLaunchTemplate", "CreateFleet"},
    "lambda": {"CreateFunction", "UpdateFunctionConfiguration"},
    "ecs": {"RunTask", "CreateService"},
    "cloudformation": {"CreateStack", "UpdateStack", "CreateChangeSet"},
    "batch": {"SubmitJob"},
    "sagemaker": {"CreateTrainingJob", "CreateModel"},
    "eks": {"CreateFargateProfile"},
}

# ---- Helpers ----------------------------------------------------------------

def load_findings(path: str) -> Dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return {"findings": data["findings"], "summary": data.get("summary", {})}
    if isinstance(data, list):
        return {"findings": data, "summary": {}}
    raise ValueError("Unrecognized findings.json format")

def parse_action(a: Any) -> Tuple[str, str] | None:
    if not isinstance(a, str):
        return None
    if a.strip() == "*":
        return ("*", "*")
    if ":" not in a:
        return None
    svc, act = a.split(":", 1)
    return svc.lower(), act

def normalize_actions(stmt: Dict[str, Any]) -> List[Tuple[str, str]]:
    acts = stmt.get("Action")
    acts = acts if isinstance(acts, list) else [acts] if acts is not None else []
    out: List[Tuple[str, str]] = []
    for a in acts:
        pa = parse_action(a)
        if pa:
            out.append(pa)
    return out

def wrap(s: str, width: int) -> List[str]:
    return textwrap.wrap(s, width=width, replace_whitespace=False, drop_whitespace=False) or [""]

def row_lines(cells: List[Tuple[str, int]]) -> List[str]:
    # wrap each cell to its column width; then pad rows to same height
    wrapped = [wrap(txt, w) for (txt, w) in cells]
    height = max(len(lines) for lines in wrapped)
    out = []
    for i in range(height):
        parts = []
        for (lines, (_, w)) in zip(wrapped, enumerate([w for _, w in cells])):
            seg = lines[i] if i < len(lines) else ""
            parts.append(seg.ljust(w))
        out.append("  ".join(parts))
    return out

def hr(cols=COLS) -> str:
    return "  ".join("-" * w for _, w in cols)

# ---- Escalation-ready detection (simple & demo-friendly) --------------------

def analyze_escalation_ready(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    A role is 'escalation-ready' if BOTH:
      (1) it can PassRole (treat 'iam:PassRole', 'iam:*', or statement text containing PassRole as presence)
      (2) it has a launcher in a compute service (explicit action like ec2:RunInstances OR service wildcard like ec2:*)
    """
    roles: Dict[str, Dict[str, Any]] = {}

    def ensure(role: str) -> Dict[str, Any]:
        return roles.setdefault(role, {
            "has_passrole": False,
            "exploitable": set(),  # e.g., {"ec2:*", "lambda:CreateFunction"}
            "ready": False,
            "exploit": "",
        })

    for f in findings:
        role = f.get("role")
        if not role:
            continue
        info = ensure(role)
        stmt = f.get("statement") or {}
        acts = normalize_actions(stmt)

        # (1) PassRole presence
        if "PassRole" in json.dumps(stmt):
            info["has_passrole"] = True
        for svc, act in acts:
            if svc == "iam" and (act.lower().startswith("passrole") or act == "*" or act.endswith("*")):
                info["has_passrole"] = True

        # (2) Launcher presence
        for svc, act in acts:
            if svc in EXPLOITABLE_ACTIONS:
                if act == "*" or act.endswith("*"):
                    info["exploitable"].add(f"{svc}:*")
                elif act in EXPLOITABLE_ACTIONS[svc]:
                    info["exploitable"].add(f"{svc}:{act}")
        # Global "*:*" (extreme) — assume it implies both for demo purposes
        if ("*", "*") in acts:
            info["has_passrole"] = True
            for s in EXPLOITABLE_ACTIONS:
                info["exploitable"].add(f"{s}:*")

    # finalize
    for role, info in roles.items():
        if info["has_passrole"] and info["exploitable"]:
            info["ready"] = True
            rep = sorted(info["exploitable"])[0]
            svc, act = rep.split(":", 1)
            if svc == "ec2" and (act == "*" or act == "RunInstances"):
                info["exploit"] = "EC2: RunInstances(IamInstanceProfile=ANY_ROLE)"
            elif svc == "lambda" and (act == "*" or act == "CreateFunction"):
                info["exploit"] = "Lambda: CreateFunction(Role=ANY_ROLE)"
            elif svc == "ecs":
                info["exploit"] = "ECS: RunTask(taskRole=ANY_ROLE)"
            elif svc == "cloudformation":
                info["exploit"] = "CFN: CreateStack(Role=ANY_ROLE)"
            else:
                info["exploit"] = f"{svc}:{act} + iam:PassRole"
    return roles

# ---- Main rendering ----------------------------------------------------------

def make_row(role: str, f: Dict[str, Any]) -> List[Tuple[str, int]]:
    rule = f.get("rule", "R?")
    sev = (f.get("severity") or "INFO").upper()
    title = f.get("title") or ""
    # Short statement preview
    stmt = f.get("statement") or {}
    acts = [a for a in (stmt.get("Action") if isinstance(stmt.get("Action"), list) else [stmt.get("Action")]) if a]
    res = stmt.get("Resource")
    res_s = res if isinstance(res, str) else ",".join(res) if isinstance(res, list) else ""
    preview = f"{title}"
    if acts:
        preview += f" | Action: {acts[:3]}"
        if len(acts) > 3:
            preview += " …"
    if res_s:
        preview += f" | Resource: {res_s[:60]}{'…' if len(res_s)>60 else ''}"

    finding_name = f"{rule} – {RULE_LABEL.get(rule, 'Unknown')}"
    cells = [
        (role, COLS[0][1]),
        (finding_name, COLS[1][1]),
        (sev, COLS[2][1]),
        (preview, COLS[3][1]),
    ]
    return cells

def render_table(findings: List[Dict[str, Any]], esc_map: Dict[str, Dict[str, Any]]) -> None:
    # sort by severity, then rule, then role
    def sort_key(f: Dict[str, Any]):
        sev = (f.get("severity") or "INFO").upper()
        return (SEV_ORDER.get(sev, 9), f.get("rule","R?"), f.get("role",""))
    findings_sorted = sorted(findings, key=sort_key)

    # Header
    hdr = "  ".join(h.ljust(w) for h, w in COLS)
    print(hdr)
    print(hr())

    # Rows
    for f in findings_sorted:
        role = f.get("role","")
        lines = row_lines(make_row(role, f))
        for ln in lines:
            print(ln)
        print()  # spacer

def render_summary(findings: List[Dict[str, Any]], esc_map: Dict[str, Dict[str, Any]]) -> None:
    counts = {"R1":0,"R2":0,"R3":0}
    sev_counts: Dict[str,int] = {}
    for f in findings:
        rule = f.get("rule")
        if rule in counts: counts[rule]+=1
        sev = (f.get("severity") or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev,0)+1
    esc_count = sum(1 for v in esc_map.values() if v.get("ready"))
    parts = [f"R1={counts['R1']}", f"R2={counts['R2']}", f"R3={counts['R3']}", f"Escalation-ready={esc_count}"]
    sev_part = "  ".join(f"{k}={sev_counts[k]}" for k in sorted(sev_counts, key=lambda x: SEV_ORDER.get(x,9)))
    print("\nSUMMARY:", " | ".join(parts), "   ", sev_part)

def render_top_paths(esc_map: Dict[str, Dict[str, Any]]) -> None:
    items = [(r, info) for r, info in esc_map.items() if info.get("ready")]
    if not items:
        print("\nTop Exploitable Chains: (none detected)")
        return
    print("\nTop Exploitable Chains:")
    rank = 1
    for role, info in sorted(items):
        print(f" {rank}) {role}  →  {info.get('exploit')}")
        print("     Impact: attacker can run code under ANY passed role (account takeover likely).")
        rank += 1

def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CloudSentinel ASCII report")
    ap.add_argument("--in", dest="inp", required=True, help="findings.json")
    args = ap.parse_args(argv)

    data = load_findings(args.inp)
    findings = data.get("findings", [])
    if not findings:
        print("[!] No findings in", args.inp)
        return 1

    esc_map = analyze_escalation_ready(findings)

    print("\nCloudSentinel — Account Risk Report (ASCII)\n")
    render_summary(findings, esc_map)
    print("\nFindings (sorted):\n")
    render_table(findings, esc_map)
    render_top_paths(esc_map)
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
