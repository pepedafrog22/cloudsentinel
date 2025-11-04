#!/usr/bin/env python3
"""
CloudSentinel — graph.py (readable layout)
Renders findings.json into a left→right graph with clear edge labels & colors.

Usage:
  python graph.py --in findings.json --out graph.html
"""

from __future__ import annotations
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set
import networkx as nx
from pyvis.network import Network

# Severity colors (node color) and size mapping
SEV_COLOR = {
    "CRITICAL": "#8B0000",
    "HIGH": "#FF4136",
    "MEDIUM": "#FF851B",
    "LOW": "#FFDC00",
    "INFO": "#2ECC40",
}
SEV_SIZE = {"CRITICAL": 32, "HIGH": 28, "MEDIUM": 24, "LOW": 20, "INFO": 18}

# Edge colors by rule
EDGE_COLOR = {
    "R1": "#FF4136",  # red (PassRole)
    "R2": "#FF851B",  # orange (service wildcard)
    "R3": "#B10DC9",  # purple (trust)
}

# Node colors for non-severity types
TYPE_COLOR = {
    "principal": "#B10DC9",
    "service": "#FF851B",
    "any_role": "#888888",
}

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
    color: str, size: int, level: int
):
    if node_id not in G:
        G.add_node(node_id)
        net.add_node(
            node_id,
            label=label,
            title=title,
            color=color,
            size=size,
            level=level,   # used by hierarchical layout
        )

def build_graph_from_findings(findings: List[Dict[str, Any]]) -> Tuple[nx.DiGraph, Network]:
    G = nx.DiGraph()
    net = Network(height="750px", width="100%", directed=True)

    # ✅ set_options wants valid JSON (NOT "var options = ...")
    net.set_options("""{
      "layout": {
        "hierarchical": {
          "enabled": true,
          "levelSeparation": 220,
          "nodeSpacing": 220,
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

    # Special target node for "any role"
    any_role_id = _node_id("anyrole", "*")
    _ensure_node(
        net, G, any_role_id,
        label="* (any role)",
        title="Wildcard role target (PassRole on *)",
        color=TYPE_COLOR["any_role"],
        size=22, level=2
    )

    # Track edges to avoid duplicates
    seen_edges: Set[Tuple[str, str, str]] = set()

    for f in findings:
        rule = f.get("rule")
        sev = (f.get("severity") or "INFO").upper()
        title = f.get("title") or ""
        sev_color = SEV_COLOR.get(sev, "#888888")
        sev_size = SEV_SIZE.get(sev, 18)

        # Role node (center column / level 1)
        role_name = f.get("role")
        role_id = None
        if role_name:
            role_id = _node_id("role", role_name)
            hover = [f"Role: {role_name}", f"Rule: {rule}", f"Severity: {sev}", title]
            pol = f.get("policy_type")
            if pol:
                hover.append(f"Policy: {pol} {f.get('policy_name') or f.get('policy_arn','')}")
            stmt = f.get("statement")
            if stmt:
                hover.append("Statement: " + json.dumps(stmt, separators=(",", ":")))
            _ensure_node(
                net, G, role_id,
                label=role_name, title="\n".join(hover),
                color=sev_color, size=sev_size, level=1
            )

        # R1: role -> any_role
        if rule == "R1" and role_id:
            lbl = "PassRole (*)"
            edge_key = (role_id, any_role_id, "R1")
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                net.add_edge(role_id, any_role_id, label=lbl, color=EDGE_COLOR["R1"], width=2)

        # R2: role -> service nodes (e.g., s3:*)
        elif rule == "R2" and role_id:
            stmt = f.get("statement") or {}
            acts = stmt.get("Action") or []
            acts = acts if isinstance(acts, list) else [acts]
            services = sorted({a.split(":")[0] for a in acts if isinstance(a, str) and a.endswith(":*") and ":" in a})
            if not services:
                svc_id = _node_id("service", "*")
                _ensure_node(
                    net, G, svc_id,
                    label="* (service)", title="Wildcard service target",
                    color=TYPE_COLOR["service"], size=20, level=2
                )
                edge_key = (role_id, svc_id, "R2")
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    net.add_edge(role_id, svc_id, label="svc:* on *", color=EDGE_COLOR["R2"], width=2)
            else:
                for svc in services:
                    svc_id = _node_id("service", svc)
                    _ensure_node(
                        net, G, svc_id,
                        label=f"{svc}:*", title=f"{svc}:* on *",
                        color=TYPE_COLOR["service"], size=20, level=2
                    )
                    edge_key = (role_id, svc_id, "R2")
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        net.add_edge(role_id, svc_id, label=f"{svc}:* on *", color=EDGE_COLOR["R2"], width=2)

        # R3: principal -> role (trust)
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

    # Legend box
    net.add_node(
        "legend",
        label="Legend\nR1 PassRole on *  (red)\nR2 svc:* on *     (orange)\nR3 Trusts          (purple)",
        shape="box",
        color="#f0f0f0",
        font={"face": "monospace"},
        x=-900, y=-500, fixed=True, physics=False, level=3
    )

    return G, net

def render_and_save(net: Network, out_path: str):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(p), notebook=False)
    print(f"[+] Wrote interactive graph to {p}")

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloudSentinel graph generator (readable)")
    parser.add_argument("--in", dest="inp", required=True, help="Path to findings.json")
    parser.add_argument("--out", dest="out", required=True, help="Path to write graph HTML (e.g., graph.html)")
    args = parser.parse_args(argv)

    data = load_findings(args.inp)
    findings = data.get("findings", [])
    if not findings:
        print("[!] No findings found in", args.inp)
        return 1

    _, net = build_graph_from_findings(findings)
    render_and_save(net, args.out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())



