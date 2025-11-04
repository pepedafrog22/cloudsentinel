#!/usr/bin/env python3
"""
CloudSentinel — graph.py (robust readable layout + escalation-ready detection)

Usage:
  python graph.py --in findings.json --out graph.html

This version:
- Scans all findings/statements for iam:PassRole and service actions (not limited by rule)
- Treats svc:* (e.g., ec2:*) and actions ending with '*' as exploitable for demo purposes
- Computes escalation-ready count once (no double-counting)
- Prints helpful debug info if escalation-ready remains zero
"""
from __future__ import annotations
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set
import networkx as nx
from pyvis.network import Network

# Styling
SEV_COLOR = {
    "CRITICAL": "#8B0000",
    "HIGH": "#FF4136",
    "MEDIUM": "#FF851B",
    "LOW": "#FFDC00",
    "INFO": "#2ECC40",
}
SEV_SIZE = {"CRITICAL": 34, "HIGH": 30, "MEDIUM": 24, "LOW": 20, "INFO": 18}

EDGE_COLOR = {"R1": "#FF4136", "R2": "#FF851B", "R3": "#B10DC9"}

TYPE_COLOR = {"principal": "#B10DC9", "service": "#FF851B", "any_role": "#888888", "summary": "#f0f0f0"}

# Map of services to example launcher actions we treat as exploitable
EXPLOITABLE_ACTIONS = {
    "ec2": {"RunInstances", "CreateLaunchTemplate", "CreateFleet"},
    "lambda": {"CreateFunction", "UpdateFunctionConfiguration"},
    "ecs": {"RunTask", "CreateService"},
    "cloudformation": {"CreateStack", "UpdateStack", "CreateChangeSet"},
    "batch": {"SubmitJob"},
    "sagemaker": {"CreateTrainingJob", "CreateModel"},
    "eks": {"CreateFargateProfile"},
}

def parse_action(action: str) -> Tuple[str, str] | None:
    """Return (service_lowercase, action) or None."""
    if not isinstance(action, str):
        return None
    if action == "*" or action.strip() == "*":
        return ("*", "*")
    if ":" not in action:
        return None
    svc, act = action.split(":", 1)
    return svc.lower(), act

def load_findings(path: str) -> Dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return {"findings": data["findings"], "summary": data.get("summary", {})}
    if isinstance(data, list):
        return {"findings": data, "summary": {}}
    raise ValueError("Unrecognized findings.json format")

def _node_id(kind: str, name: str) -> str:
    return f"{kind}::{name}"

def _ensure_node(net: Network, G: nx.DiGraph, node_id: str, *, label: str, title: str, color: str, size: int, level: int, physics: bool = False):
    if node_id not in G:
        G.add_node(node_id)
        net.add_node(node_id, label=label, title=title, color=color, size=size, level=level, physics=physics)

def analyze_escalation_ready(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Robust detection: look across all policy statements in findings for:
      - iam:PassRole (on any Resource or on '*')
      - exploitable actions (explicit or wildcard svc:*)
    Returns per-role dict with keys:
      - has_passrole_star (bool)
      - exploitable_actions (set of svc:action or svc:*)
      - escalation_ready (bool)
      - exploit_string (human readable)
    """
    roles: Dict[str, Dict[str, Any]] = {}

    # helper to ensure role present
    def _ensure(role_name: str):
        return roles.setdefault(role_name, {
            "has_passrole_star": False,
            "exploitable_actions": set(),
            "escalation_ready": False,
            "exploit_string": "",
        })

    for f in findings:
        role = f.get("role")
        # If there's no role associated with the finding, skip (some finders include non-role items)
        if not role:
            continue
        r = _ensure(role)

        # extract statement(s) from the finding, if present
        stmt = f.get("statement") or {}
        # 'Action' may be list or single string or even "*"
        actions = stmt.get("Action")
        if actions is None:
            # sometimes statement nested differently; check for PolicyDocument style
            # but keep simple: if missing, continue
            actions = []
        # normalize list
        if isinstance(actions, list):
            actions_list = actions
        else:
            actions_list = [actions]

        # check for iam:PassRole and for exploitable actions
        for a in actions_list:
            if not isinstance(a, str):
                continue
            parsed = parse_action(a)
            if parsed is None:
                continue
            svc, act = parsed  # svc lowercased
            # catch global wildcard Action: "*"
            if svc == "*" and act == "*":
                # global wildcard implies everything — treat as exploitable for all known services
                for s in EXPLOITABLE_ACTIONS.keys():
                    r["exploitable_actions"].add(f"{s}:*")
                # also mark passrole if iam:PassRole is implied by '*'
                r["has_passrole_star"] = True
                continue

            # If this is iam:PassRole (explicit)
            if svc == "iam" and (act.lower() == "passrole" or act.lower() == "passrole*"):
                # We want to know if PassRole applies to '*' resource; sometimes the finding's Resource shows "*"
                # For demo simplicity we treat presence of iam:PassRole in statement as PassRole capability.
                r["has_passrole_star"] = True

            # If the action is a wildcard for a service (e.g., ec2:*)
            if act == "*" or act.endswith("*"):
                # if the service is one we consider exploitable, treat wildcard as exploitable
                if svc in EXPLOITABLE_ACTIONS:
                    r["exploitable_actions"].add(f"{svc}:*")
                # also if svc == "iam" and act == "*" we mark passrole as present (conservative)
                if svc == "iam":
                    r["has_passrole_star"] = True
                continue

            # If explicit actionable launcher present and service in map
            if svc in EXPLOITABLE_ACTIONS and act in EXPLOITABLE_ACTIONS[svc]:
                r["exploitable_actions"].add(f"{svc}:{act}")

        # Additional safety: sometimes a finding's title or statement contains iam:PassRole but not in Action array
        # check statement for presence of "PassRole" substring (conservative)
        stmt_text = json.dumps(stmt)
        if "PassRole" in stmt_text or "iam:PassRole" in stmt_text:
            r["has_passrole_star"] = True

    # finalize escalation flags and build exploit strings
    for role_name, info in roles.items():
        if info["has_passrole_star"] and info["exploitable_actions"]:
            info["escalation_ready"] = True
            # choose representative exploit action
            rep = sorted(info["exploitable_actions"])[0]
            svc, act = rep.split(":", 1)
            if act == "*":
                if svc == "ec2":
                    info["exploit_string"] = "RunInstances(IamInstanceProfile=ANY_ROLE)"
                elif svc == "lambda":
                    info["exploit_string"] = "CreateFunction(Role=ANY_ROLE)"
                elif svc == "cloudformation":
                    info["exploit_string"] = "CreateStack(CloudFormation creates resources using role=ANY_ROLE)"
                elif svc == "ecs":
                    info["exploit_string"] = "RunTask(taskRole=ANY_ROLE)"
                else:
                    info["exploit_string"] = f"{svc}:* (wildcard launcher likely available)"
            else:
                # specific action
                if svc == "ec2" and act == "RunInstances":
                    info["exploit_string"] = "RunInstances(IamInstanceProfile=ANY_ROLE)"
                elif svc == "lambda" and act == "CreateFunction":
                    info["exploit_string"] = "CreateFunction(Role=ANY_ROLE)"
                else:
                    info["exploit_string"] = f"{svc}:{act} (requires iam:PassRole)"
        else:
            info["escalation_ready"] = False

    return roles

def build_graph_from_findings(findings: List[Dict[str, Any]]) -> Tuple[nx.DiGraph, Network, Dict[str, Any]]:
    escalation_info = analyze_escalation_ready(findings)

    G = nx.DiGraph()
    net = Network(height="760px", width="100%", directed=True)

    # pyvis options (valid JSON)
    net.set_options("""{
      "layout": { "hierarchical": { "enabled": true, "levelSeparation": 200, "nodeSpacing": 200, "direction": "LR", "sortMethod": "directed" } },
      "physics": { "enabled": false },
      "edges": { "arrows": { "to": { "enabled": true } }, "smooth": { "type": "cubicBezier" } }
    }""")

    # wildcard target node
    any_role_id = _node_id("anyrole", "*")
    _ensure_node(net, G, any_role_id, label="* (any role)", title="Wildcard role target (PassRole on *)", color=TYPE_COLOR["any_role"], size=22, level=2)

    counts = {"R1": 0, "R2": 0, "R3": 0}
    sev_counts: Dict[str, int] = {}
    seen_edges: Set[Tuple[str, str, str]] = set()

    for f in findings:
        rule = f.get("rule")
        if rule in counts:
            counts[rule] += 1
        sev = (f.get("severity") or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        role_name = f.get("role")
        if not role_name:
            continue
        role_id = _node_id("role", role_name)
        esc = escalation_info.get(role_name, {})
        is_esc = bool(esc.get("escalation_ready"))

        hover = [f"Role: {role_name}", f"Severity: {sev}", f"Rule: {rule}", f"{f.get('title','')}"]
        if f.get("policy_type"):
            hover.append(f"Policy: {f.get('policy_type')} {f.get('policy_name') or f.get('policy_arn','')}")
        stmt = f.get("statement")
        if stmt:
            hover.append("Statement: " + json.dumps(stmt, separators=(",", ":")))
        if is_esc:
            hover.append(f"Escalation-ready: {esc.get('exploit_string')}")
            wilds = sorted(list(esc.get("exploitable_actions", [])))
            if wilds:
                hover.append("Exploit candidates: " + ", ".join(wilds))

        _ensure_node(net, G, role_id, label=role_name + (" ⚠️" if is_esc else ""), title="\n".join(hover), color=SEV_COLOR.get(sev, "#888888"), size=SEV_SIZE.get(sev, 20), level=1)

        # edges by rule
        if rule == "R1":
            edge_key = (role_id, any_role_id, "R1")
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                net.add_edge(role_id, any_role_id, label="PassRole (*)", color=EDGE_COLOR["R1"], width=2)

        if rule == "R2":
            stmt = f.get("statement") or {}
            actions = stmt.get("Action") or []
            acts = actions if isinstance(actions, list) else [actions]
            services = set()
            for a in acts:
                p = parse_action(a) if isinstance(a, str) else None
                if p:
                    svc, act = p
                    services.add(svc)
            if not services:
                svc_id = _node_id("service", "*")
                _ensure_node(net, G, svc_id, label="* (service)", title="Wildcard service target", color=TYPE_COLOR["service"], size=20, level=2)
                edge_key = (role_id, svc_id, "R2")
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    width = 3 if is_esc else 2
                    net.add_edge(role_id, svc_id, label="svc:* on *", color=EDGE_COLOR["R2"], width=width)
            else:
                for svc in sorted(services):
                    svc_id = _node_id("service", svc)
                    _ensure_node(net, G, svc_id, label=f"{svc}:*", title=f"{svc}:* on *", color=TYPE_COLOR["service"], size=20, level=2)
                    edge_key = (role_id, svc_id, "R2")
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        width = 3 if is_esc else 2
                        net.add_edge(role_id, svc_id, label=f"{svc}:* on *", color=EDGE_COLOR["R2"], width=width)

        if rule == "R3":
            stmt = f.get("statement") or {}
            principal = (stmt.get("Principal") or {}).get("AWS")
            principals = principal if isinstance(principal, list) else [principal]
            for p in principals:
                if not p:
                    continue
                pname = str(p)
                pid = _node_id("principal", pname)
                _ensure_node(net, G, pid, label=pname, title=f"Principal: {pname}\nTrusts role", color=TYPE_COLOR["principal"], size=18, level=0)
                edge_key = (pid, role_id, "R3")
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    net.add_edge(pid, role_id, label="trusts", color=EDGE_COLOR["R3"], width=2)

    # compute escalation-ready count once from escalation_info
    esc_count = sum(1 for info in escalation_info.values() if info.get("escalation_ready"))
    counts["escalation_ready"] = esc_count

    # build summary line
    summary_parts = [f"R1={counts.get('R1',0)}", f"R2={counts.get('R2',0)}", f"R3={counts.get('R3',0)}", f"Escalation-ready={counts.get('escalation_ready',0)}"]
    sev_parts = [f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda x: x[0])]
    summary_line = " | ".join(summary_parts) + "   " + "  ".join(sev_parts)

    # legend + summary node
    legend_label = ("Legend\\nR1 PassRole on *  (red)\\nR2 svc:* on *     (orange)\\nR3 Trusts         (purple)\\n\\n" f"Summary: {summary_line}")
    net.add_node("legend", label=legend_label, shape="box", color=TYPE_COLOR["summary"], font={"face":"monospace"}, x=-900, y=-500, fixed=True, physics=False, level=3)
    net.add_node("top_summary", label=f"Summary: {summary_line}", shape="box", color="#ffffff", font={"face":"monospace"}, x=-900, y=-620, fixed=True, physics=False, level=4)

    meta = {"counts": counts, "sev_counts": sev_counts, "summary_line": summary_line, "escalation_info": escalation_info}
    return G, net, meta

def render_and_save(net: Network, out_path: str):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(p), notebook=False)
    print(f"[+] Wrote interactive graph to {p}")

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloudSentinel graph generator (robust + escalation-ready)")
    parser.add_argument("--in", dest="inp", required=True, help="Path to findings.json")
    parser.add_argument("--out", dest="out", required=True, help="Path to write graph HTML (e.g., graph.html)")
    args = parser.parse_args(argv)

    data = load_findings(args.inp)
    findings = data.get("findings", [])
    if not findings:
        print("[!] No findings found in", args.inp)
        return 1

    _, net, meta = build_graph_from_findings(findings)
    render_and_save(net, args.out)

    # print summary and debug if zero
    print("[*] Summary:", meta.get("summary_line"))
    esc = meta.get("escalation_info", {})
    if esc:
        any_esc = False
        for role, info in esc.items():
            if info.get("escalation_ready"):
                print(f" - Escalation-ready: {role} -> {info.get('exploit_string')}")
                any_esc = True
        if not any_esc:
            # helpful debug: show roles with passrole and roles with exploitable_actions separately
            print("[!] No escalation-ready roles detected. Debug info:")
            for role, info in esc.items():
                if info.get("has_passrole_star") or info.get("exploitable_actions"):
                    print(f"  Role: {role}")
                    print(f"    has_passrole_star: {info.get('has_passrole_star')}")
                    print(f"    exploitable_actions: {sorted(info.get('exploitable_actions', []))}")
            print("Hint: escalation-ready requires BOTH has_passrole_star=True AND exploitable_actions non-empty.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

