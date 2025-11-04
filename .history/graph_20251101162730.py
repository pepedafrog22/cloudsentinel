#!/usr/bin/env python3
"""
CloudSentinel — graph.py (readable layout + escalation-ready detection)

Usage:
  python graph.py --in findings.json --out graph.html

Outputs an interactive HTML graph showing:
- principals (left), roles (center), service/targets (right)
- R1 (PassRole) edges in red, R2 (svc:* on *) in orange, R3 (trust) in purple
- Escalation-ready roles flagged with a ⚠️ and an exploit string in the tooltip
- Top-line summary box with counts
"""
from __future__ import annotations
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set
import networkx as nx
from pyvis.network import Network

# Node/edge styling
SEV_COLOR = {
    "CRITICAL": "#8B0000",
    "HIGH": "#FF4136",
    "MEDIUM": "#FF851B",
    "LOW": "#FFDC00",
    "INFO": "#2ECC40",
}
SEV_SIZE = {"CRITICAL": 34, "HIGH": 30, "MEDIUM": 24, "LOW": 20, "INFO": 18}

EDGE_COLOR = {
    "R1": "#FF4136",  # red (PassRole)
    "R2": "#FF851B",  # orange (service wildcard)
    "R3": "#B10DC9",  # purple (trust)
}

TYPE_COLOR = {
    "principal": "#B10DC9",
    "service": "#FF851B",
    "any_role": "#888888",
    "summary": "#f0f0f0",
}

# Services + specific actions we consider "exploitable" when combined with PassRole
# These map service -> list of actions that, when present, allow attaching roles to runtime resources.
EXPLOITABLE_ACTIONS = {
    "ec2": {"RunInstances", "CreateLaunchTemplate", "CreateFleet"},
    "lambda": {"CreateFunction", "UpdateFunctionConfiguration"},
    "ecs": {"RunTask", "CreateService"},
    "cloudformation": {"CreateStack", "UpdateStack", "CreateChangeSet"},
    "batch": {"SubmitJob"},
    "sagemaker": {"CreateTrainingJob", "CreateModel"},
    "eks": {"CreateFargateProfile"},  # example
    # Add more services/actions if you want
}

# helper: normalize action like "ec2:RunInstances" -> ("ec2", "RunInstances")
def parse_action(action: str) -> Tuple[str, str] | None:
    if not isinstance(action, str):
        return None
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

def _ensure_node(
    net: Network, G: nx.DiGraph, node_id: str, *, label: str, title: str,
    color: str, size: int, level: int, physics: bool = False
):
    if node_id not in G:
        G.add_node(node_id)
        net.add_node(
            node_id,
            label=label,
            title=title,
            color=color,
            size=size,
            level=level,
            physics=physics,
        )

def analyze_escalation_ready(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    For each role in findings, detect:
      - has_passrole_star: True if role has R1 (PassRole on *)
      - exploitable_actions: list of (svc:Action) that match our EXPLOITABLE_ACTIONS
      - escalation_ready: True if has_passrole_star AND exploitable_actions not empty
      - exploit_string: short precomputed exploit phrase, if escalation_ready

    NEW: treat service wildcards like 'ec2:*' as exploitable for demo purposes.
    """
    roles: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        role = f.get("role")
        if not role:
            continue
        r = roles.setdefault(role, {
            "has_passrole_star": False,
            "exploitable_actions": set(),  # set of "svc:Action" or "svc:*"
            "escalation_ready": False,
            "exploit_string": "",
        })
        rule = f.get("rule")
        if rule == "R1":
            r["has_passrole_star"] = True
        if rule == "R2":
            stmt = f.get("statement") or {}
            acts = stmt.get("Action") or []
            acts = acts if isinstance(acts, list) else [acts]
            for a in acts:
                if not isinstance(a, str):
                    continue
                parsed = parse_action(a)
                if not parsed:
                    # If action is a wildcard without colon (rare), ignore
                    continue
                svc, act = parsed  # svc is lowercased by parse_action
                # If the action is a wildcard for the service (e.g., 'ec2:*'), treat as exploitable
                if act == "*" and svc in EXPLOITABLE_ACTIONS:
                    # add a generic wildcard marker for this service
                    r["exploitable_actions"].add(f"{svc}:*")
                # Otherwise, if the action matches one of our known exploitable actions, add it
                elif svc in EXPLOITABLE_ACTIONS and act in EXPLOITABLE_ACTIONS[svc]:
                    r["exploitable_actions"].add(f"{svc}:{act}")

    # finalize escalation flag and create short exploit string
    for role, info in roles.items():
        if info["has_passrole_star"] and info["exploitable_actions"]:
            info["escalation_ready"] = True
            # pick a representative exploitable action to create a concise exploit string
            svc_act = sorted(info["exploitable_actions"])[0]
            svc, act = svc_act.split(":", 1)
            if act == "*":
                # wildcard service: show a generic exploit using the most-likely launcher
                # pick a canonical launcher for that service for the string
                if svc == "ec2":
                    info["exploit_string"] = "RunInstances(IamInstanceProfile=ANY_ROLE)"
                elif svc == "lambda":
                    info["exploit_string"] = "CreateFunction(Role=ANY_ROLE)"
                elif svc == "cloudformation":
                    info["exploit_string"] = "CreateStack(CloudFormation creates resources using role=ANY_ROLE)"
                elif svc == "ecs":
                    info["exploit_string"] = "RunTask(taskRole=ANY_ROLE)"
                else:
                    info["exploit_string"] = f"{svc}:* (wildcard - likely includes launcher actions)"
            else:
                # specific action
                if svc == "ec2" and act == "RunInstances":
                    info["exploit_string"] = f"RunInstances(IamInstanceProfile=ANY_ROLE)"
                elif svc == "lambda" and act == "CreateFunction":
                    info["exploit_string"] = f"CreateFunction(Role=ANY_ROLE)"
                elif svc == "cloudformation" and act in ("CreateStack", "CreateChangeSet", "UpdateStack"):
                    info["exploit_string"] = f"CreateStack(CloudFormation creates resources using role=ANY_ROLE)"
                elif svc == "ecs" and act == "RunTask":
                    info["exploit_string"] = f"RunTask(taskRole=ANY_ROLE)"
                else:
                    info["exploit_string"] = f"{svc}:{act} (requires iam:PassRole)"
        else:
            info["escalation_ready"] = False
    return roles


def build_graph_from_findings(findings: List[Dict[str, Any]]) -> Tuple[nx.DiGraph, Network, Dict[str, Any]]:
    """
    Build graph and also return a summary dict:
      {counts: {...}, escalation_info: {...}}
    """
    # compute escalation info first
    escalation_info = analyze_escalation_ready(findings)

    G = nx.DiGraph()
    net = Network(height="760px", width="100%", directed=True)

    # hierarchical left-to-right layout: provide valid JSON options to pyvis
    net.set_options("""{
      "layout": {
        "hierarchical": {
          "enabled": true,
          "levelSeparation": 200,
          "nodeSpacing": 200,
          "direction": "LR",
          "sortMethod": "directed"
        }
      },
      "physics": { "enabled": false },
      "edges": {
        "arrows": { "to": { "enabled": true, "scaleFactor": 1 } },
        "smooth": { "type": "cubicBezier" }
      }
    }""")

    # Pre-create wildcard nodes
    any_role_id = _node_id("anyrole", "*")
    _ensure_node(
        net, G, any_role_id,
        label="* (any role)",
        title="Wildcard role target (PassRole on *)",
        color=TYPE_COLOR["any_role"],
        size=22, level=2
    )

    # track counts for summary
    counts = {"R1": 0, "R2": 0, "R3": 0, "escalation_ready": 0}
    sev_counts: Dict[str, int] = {}

    # avoid duplicate edges
    seen_edges: Set[Tuple[str, str, str]] = set()

    # Build nodes/edges
    for f in findings:
        rule = f.get("rule")
        if rule in counts:
            counts[rule] += 1
        sev = (f.get("severity") or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        role_name = f.get("role")
        role_id = None
        if role_name:
            role_id = _node_id("role", role_name)
            # escalation decoration if applicable
            esc = escalation_info.get(role_name, {})
            is_esc = esc.get("escalation_ready", False)
            esc_mark = " ⚠️" if is_esc else ""
            # tooltip
            hover_lines = [f"Role: {role_name}", f"Severity: {sev}", f"Rule: {rule}", f"{f.get('title','')}"]
            if f.get("policy_type"):
                hover_lines.append(f"Policy: {f.get('policy_type')} {f.get('policy_name') or f.get('policy_arn','')}")
            stmt = f.get("statement")
            if stmt:
                hover_lines.append("Statement: " + json.dumps(stmt, separators=(",", ":")))
            if is_esc:
                hover_lines.append(f"Escalation-ready: {esc.get('exploit_string')}")
            title = "\n".join(hover_lines)
            # add or update node (size/color by severity)
            _ensure_node(
                net, G, role_id,
                label=role_name + esc_mark,
                title=title,
                color=SEV_COLOR.get(sev, "#888888"),
                size=SEV_SIZE.get(sev, 20),
                level=1
            )
            # count escalation-ready roles for summary (do once)
            if is_esc:
                counts["escalation_ready"] = counts.get("escalation_ready", 0) + 1

        # Edges per rule, with dedupe
        if rule == "R1" and role_id:
            edge_key = (role_id, any_role_id, "R1")
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                net.add_edge(role_id, any_role_id, label="PassRole (*)", color=EDGE_COLOR["R1"], width=2)

        elif rule == "R2" and role_id:
            stmt = f.get("statement") or {}
            acts = stmt.get("Action") or []
            acts = acts if isinstance(acts, list) else [acts]
            # gather services present
            services = set()
            for a in acts:
                parsed = parse_action(a)
                if parsed:
                    svc, act = parsed
                    services.add(svc)
            # if no parseable services, use generic service node
            if not services:
                svc_id = _node_id("service", "*")
                _ensure_node(
                    net, G, svc_id, label="* (service)", title="Wildcard service target",
                    color=TYPE_COLOR["service"], size=20, level=2
                )
                edge_key = (role_id, svc_id, "R2")
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    # If role is escalation-ready, slightly thicker/bolder
                    width = 3 if escalation_info.get(role_name, {}).get("escalation_ready") else 2
                    net.add_edge(role_id, svc_id, label="svc:* on *", color=EDGE_COLOR["R2"], width=width)
            else:
                for svc in sorted(services):
                    svc_id = _node_id("service", svc)
                    _ensure_node(
                        net, G, svc_id, label=f"{svc}:*", title=f"{svc}:* on *",
                        color=TYPE_COLOR["service"], size=20, level=2
                    )
                    edge_key = (role_id, svc_id, "R2")
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        width = 3 if escalation_info.get(role_name, {}).get("escalation_ready") else 2
                        net.add_edge(role_id, svc_id, label=f"{svc}:* on *", color=EDGE_COLOR["R2"], width=width)

        elif rule == "R3" and role_id:
            stmt = f.get("statement") or {}
            principal = (stmt.get("Principal") or {}).get("AWS")
            principals = principal if isinstance(principal, list) else [principal]
            for p in principals:
                if not p:
                    continue
                pname = str(p)
                pid = _node_id("principal", pname)
                _ensure_node(
                    net, G, pid,
                    label=pname, title=f"Principal: {pname}\nTrusts role",
                    color=TYPE_COLOR["principal"], size=18, level=0
                )
                edge_key = (pid, role_id, "R3")
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    net.add_edge(pid, role_id, label="trusts", color=EDGE_COLOR["R3"], width=2)

    # Build one-line summary string
    summary_parts = [
        f"R1={counts.get('R1',0)}",
        f"R2={counts.get('R2',0)}",
        f"R3={counts.get('R3',0)}",
        f"Escalation-ready={counts.get('escalation_ready',0)}",
    ]
    sev_parts = [f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda x: x[0])]
    summary_line = " | ".join(summary_parts) + "   " + "  ".join(sev_parts)

    # Legend / summary node (fixed in bottom-right)
    legend_label = (
        "Legend\\n"
        "R1 PassRole on *  (red)\\n"
        "R2 svc:* on *     (orange)\\n"
        "R3 Trusts         (purple)\\n\\n"
        f"Summary: {summary_line}"
    )
    net.add_node(
        "legend",
        label=legend_label,
        shape="box",
        color=TYPE_COLOR["summary"],
        font={"face": "monospace"},
        x=-900, y=-500, fixed=True, physics=False, level=3
    )

    # Also add a small top summary node (non-physics, fixed)
    net.add_node(
        "top_summary",
        label=f"Summary: {summary_line}",
        shape="box",
        color="#ffffff",
        font={"face": "monospace"},
        x=-900, y=-620, fixed=True, physics=False, level=4
    )

    return G, net, {"counts": counts, "sev_counts": sev_counts, "summary_line": summary_line, "escalation_info": escalation_info}

def render_and_save(net: Network, out_path: str):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(p), notebook=False)
    print(f"[+] Wrote interactive graph to {p}")

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloudSentinel graph generator (readable + escalation-ready)")
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

    # Print the summary to stdout so you can show it in terminal too
    print("[*] Summary:", meta.get("summary_line"))
    esc = meta.get("escalation_info", {})
    if esc:
        # print any escalation-ready roles and their exploit strings
        for role, info in esc.items():
            if info.get("escalation_ready"):
                print(f" - Escalation-ready: {role} -> {info.get('exploit_string')}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
