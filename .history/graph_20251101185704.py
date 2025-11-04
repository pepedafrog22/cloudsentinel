#!/usr/bin/env python3
"""
CloudSentinel — graph.py (clean lanes + simple legend)

- Principals (purple ♦)  → left lane
- Roles (red ●)          → middle lane
- Services (orange ▭)    → right lane
- Any role (gray ▭)      → far-right

Edges:
- R1  PassRole(*)  = red
- R2  svc:*        = orange
- R3  trust        = purple

Escalation-ready roles show a ⚠️ and a thick red border.
"""

from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import networkx as nx
from pyvis.network import Network

# Colors & sizes
CLR_ROLE = "#FF4136"       # red
CLR_SVC = "#FF851B"        # orange
CLR_PRINC = "#B10DC9"      # purple
CLR_ANYROLE = "#808080"    # gray
CLR_SUMMARY = "#f5f5f5"

EDG_R1 = CLR_ROLE
EDG_R2 = CLR_SVC
EDG_R3 = CLR_PRINC

SIZE_ROLE = 28
SIZE_PRINC = 20
SIZE_SVC = 20
SIZE_ANY = 20

# Services we consider "compute launchers"
EXPLOITABLE_ACTIONS = {
    "ec2": {"RunInstances", "CreateLaunchTemplate", "CreateFleet"},
    "lambda": {"CreateFunction", "UpdateFunctionConfiguration"},
    "ecs": {"RunTask", "CreateService"},
    "cloudformation": {"CreateStack", "UpdateStack", "CreateChangeSet"},
    "batch": {"SubmitJob"},
    "sagemaker": {"CreateTrainingJob", "CreateModel"},
    "eks": {"CreateFargateProfile"},
}

def parse_action(a: str) -> Tuple[str, str] | None:
    if not isinstance(a, str):
        return None
    if a.strip() == "*":
        return ("*", "*")
    if ":" not in a:
        return None
    svc, act = a.split(":", 1)
    return svc.lower(), act

def load_findings(path: str) -> Dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return {"findings": data["findings"], "summary": data.get("summary", {})}
    if isinstance(data, list):
        return {"findings": data, "summary": {}}
    raise ValueError("Unrecognized findings.json format")

def analyze_escalation_ready(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Escalation-ready if a role has BOTH:
      - iam:PassRole (treat '*' or iam:* as including it)
      - a compute launcher (explicit like ec2:RunInstances OR service wildcard like ec2:*)
    """
    roles: Dict[str, Dict[str, Any]] = {}
    def ensure(role: str):
        return roles.setdefault(role, {
            "has_passrole": False,
            "exploitable": set(),   # {"ec2:*", "lambda:CreateFunction", ...}
            "ready": False,
            "exploit": "",
        })

    for f in findings:
        role = f.get("role")
        if not role: 
            continue
        r = ensure(role)
        stmt = f.get("statement") or {}
        acts = stmt.get("Action")
        acts = acts if isinstance(acts, list) else [acts] if acts is not None else []

        for a in acts:
            if not isinstance(a, str):
                continue
            svc_act = parse_action(a)
            if not svc_act:
                continue
            svc, act = svc_act

            # Global wildcard: assume exploitable + passrole present
            if svc == "*" and act == "*":
                for s in EXPLOITABLE_ACTIONS:
                    r["exploitable"].add(f"{s}:*")
                r["has_passrole"] = True
                continue

            # PassRole presence
            if svc == "iam":
                if act.lower().startswith("passrole") or act == "*" or act.endswith("*"):
                    r["has_passrole"] = True

            # Exploitable presence
            if svc in EXPLOITABLE_ACTIONS:
                if act == "*" or act.endswith("*"):
                    r["exploitable"].add(f"{svc}:*")
                elif act in EXPLOITABLE_ACTIONS[svc]:
                    r["exploitable"].add(f"{svc}:{act}")

        # Safety: if the raw JSON contains "PassRole" text anywhere in the statement
        if "PassRole" in json.dumps(stmt):
            r["has_passrole"] = True

    # finalize
    for role, info in roles.items():
        if info["has_passrole"] and info["exploitable"]:
            info["ready"] = True
            rep = sorted(info["exploitable"])[0]
            svc, act = rep.split(":", 1)
            if act == "*":
                info["exploit"] = {
                    "ec2": "RunInstances(IamInstanceProfile=ANY_ROLE)",
                    "lambda": "CreateFunction(Role=ANY_ROLE)",
                    "ecs": "RunTask(taskRole=ANY_ROLE)",
                    "cloudformation": "CreateStack(Role=ANY_ROLE)",
                }.get(svc, f"{svc}:* (likely includes launcher)")
            else:
                if svc == "ec2" and act == "RunInstances":
                    info["exploit"] = "RunInstances(IamInstanceProfile=ANY_ROLE)"
                elif svc == "lambda" and act == "CreateFunction":
                    info["exploit"] = "CreateFunction(Role=ANY_ROLE)"
                else:
                    info["exploit"] = f"{svc}:{act} (requires iam:PassRole)"
    return roles

def _node_id(kind: str, name: str) -> str:
    return f"{kind}::{name}"

def _add_node(
    net: Network, G: nx.DiGraph, node_id: str, *, label: str, title: str,
    color: str, size: int, level: int, shape: str, border_width: int = 1,
    fixed: bool = False, x: int | None = None, y: int | None = None,
):
    if node_id in G:
        return
    G.add_node(node_id)
    kwargs = dict(label=label, title=title, color=color, size=size, level=level, shape=shape, borderWidth=border_width)
    if fixed:
        kwargs["fixed"] = True
        kwargs["physics"] = False
        if x is not None and y is not None:
            kwargs["x"] = x
            kwargs["y"] = y
    net.add_node(node_id, **kwargs)

def build_graph(findings: List[Dict[str, Any]]) -> Tuple[Network, Dict[str, Any]]:
    # Analyze escalation
    esc = analyze_escalation_ready(findings)

    # Build network (strict left→right)
    net = Network(height="760px", width="100%", directed=True)
    net.set_options("""{
      "layout": { "hierarchical": { "enabled": true, "direction": "LR", "levelSeparation": 220, "nodeSpacing": 200 } },
      "physics": { "enabled": false },
      "edges": { "arrows": { "to": { "enabled": true } }, "smooth": { "type": "cubicBezier" } }
    }""")

    G = nx.DiGraph()
    seen_edges: Set[Tuple[str, str, str]] = set()

    # Lane headers (fixed labels)
    _add_node(net, G, "hdr::principals", label="Principals", title="", color=CLR_SUMMARY, size=14, level=0, shape="box", fixed=True, x=-900, y=-620)
    _add_node(net, G, "hdr::roles",      label="Roles",      title="", color=CLR_SUMMARY, size=14, level=1, shape="box", fixed=True, x=-300, y=-620)
    _add_node(net, G, "hdr::services",   label="Services",   title="", color=CLR_SUMMARY, size=14, level=2, shape="box", fixed=True, x= 300, y=-620)

    # Wildcard "any role" node on far-right
    any_role_id = _node_id("anyrole", "*")
    _add_node(net, G, any_role_id,
              label="* (any role)", title="Wildcard role target for PassRole(*)",
              color=CLR_ANYROLE, size=SIZE_ANY, level=3, shape="box")

    counts = {"R1": 0, "R2": 0, "R3": 0}
    sev_counts: Dict[str, int] = {}

    for f in findings:
        rule = f.get("rule")
        if rule in counts:
            counts[rule] += 1
        sev = (f.get("severity") or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        role_name = f.get("role")
        if not role_name:
            continue

        # Role node
        role_id = _node_id("role", role_name)
        is_ready = esc.get(role_name, {}).get("ready", False)
        badge = " ⚠️" if is_ready else ""
        border = 4 if is_ready else 1
        tooltip_lines = [f"Role: {role_name}", f"Rule: {rule}", f"{f.get('title','')}"]
        stmt = f.get("statement")
        if stmt:
            tooltip_lines.append("Statement: " + json.dumps(stmt, separators=(",", ":")))
        if is_ready:
            tooltip_lines.append("Escalation-ready: " + esc[role_name].get("exploit", ""))
        _add_node(net, G, role_id,
                  label=role_name + badge, title="\n".join(tooltip_lines),
                  color=CLR_ROLE, size=SIZE_ROLE, level=1, shape="dot", border_width=border)

        # R1: PassRole(*) → role → any_role
        if rule == "R1":
            ek = (role_id, any_role_id, "R1")
            if ek not in seen_edges:
                seen_edges.add(ek)
                net.add_edge(role_id, any_role_id, label="PassRole(*)", color=EDG_R1, width=2)

        # R2: svc:* on * → role → service node(s)
        if rule == "R2":
            stmt = f.get("statement") or {}
            acts = stmt.get("Action") or []
            acts = acts if isinstance(acts, list) else [acts]
            services = set()
            for a in acts:
                pa = parse_action(a) if isinstance(a, str) else None
                if pa:
                    services.add(pa[0])
            if not services:
                services = {"*"}
            for svc in sorted(services):
                svc_id = _node_id("svc", svc)
                svc_label = f"{svc}:*" if svc != "*" else "* (service)"
                svc_title = f"{svc_label} on *"
                _add_node(net, G, svc_id,
                          label=svc_label, title=svc_title,
                          color=CLR_SVC, size=SIZE_SVC, level=2, shape="box")
                ek = (role_id, svc_id, "R2")
                if ek not in seen_edges:
                    seen_edges.add(ek)
                    width = 3 if is_ready else 2
                    net.add_edge(role_id, svc_id, label="svc:*", color=EDG_R2, width=width)

        # R3: trust → principal → role
        if rule == "R3":
            stmt = f.get("statement") or {}
            principal = (stmt.get("Principal") or {}).get("AWS")
            principals = principal if isinstance(principal, list) else [principal]
            for p in principals:
                if not p:
                    continue
                pname = str(p)
                pid = _node_id("principal", pname)
                _add_node(net, G, pid,
                          label=pname, title=f"Principal: {pname}\nTrusts role",
                          color=CLR_PRINC, size=SIZE_PRINC, level=0, shape="diamond")
                ek = (pid, role_id, "R3")
                if ek not in seen_edges:
                    seen_edges.add(ek)
                    net.add_edge(pid, role_id, label="trust", color=EDG_R3, width=2)

    # Escalation-ready count once
    esc_count = sum(1 for i in esc.values() if i.get("ready"))
    counts["escalation_ready"] = esc_count

    # Legend + summary
    summary = f"R1={counts['R1']} | R2={counts['R2']} | R3={counts['R3']} | Escalation-ready={counts['escalation_ready']}"
    legend = (
        "Legend\n"
        "Red  edge = PassRole(*)\n"
        "Orange edge = svc:* (full service control)\n"
        "Purple edge = trust (can assume role)\n\n"
        "Nodes:\n"
        "♦ Principal (left)   ● Role (middle)   ▭ Service (right)   ▭ Any role (far-right)\n\n"
        f"{summary}"
    )
    net.add_node("legend", label=legend, shape="box", color=CLR_SUMMARY,
                 font={"face":"monospace"}, fixed=True, physics=False, x=-900, y=-520, level=3)

    return net, {"counts": counts, "summary": summary}

def render(net: Network, out_path: str):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(p), notebook=False)
    print(f"[+] Wrote {p}")

def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CloudSentinel graph (clean lanes)")
    ap.add_argument("--in", dest="inp", required=True, help="findings.json")
    ap.add_argument("--out", dest="out", required=True, help="graph.html")
    args = ap.parse_args(argv)

    data = load_findings(args.inp)
    findings = data.get("findings", [])
    if not findings:
        print("[!] No findings in", args.inp)
        return 1

    net, meta = build_graph(findings)
    render(net, args.out)
    print("[*]", meta["summary"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


