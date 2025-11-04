#!/usr/bin/env python3
"""
CloudSentinel — graph.py (demo)
Reads findings.json produced by analyze.py and renders an interactive HTML attack-path graph.

Usage:
  python graph.py --in findings.json --out graph.html
"""

from __future__ import annotations
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
import networkx as nx
from pyvis.network import Network

# color mapping for severities
SEV_COLORS = {
    "CRITICAL": "#8B0000",
    "HIGH": "#FF4136",
    "MEDIUM": "#FF851B",
    "LOW": "#FFDC00",
    "INFO": "#2ECC40",
}

# node styles for entity types
TYPE_COLORS = {
    "role": "#0074D9",
    "principal": "#B10DC9",
    "service": "#FF851B",
    "any_role": "#AAAAAA",
}

def load_findings(path: str) -> Dict[str, Any]:
    """Load findings JSON which may contain {'findings': [...], 'summary': {...}} or just an array."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return {"findings": data["findings"], "summary": data.get("summary", {})}
    if isinstance(data, list):
        return {"findings": data, "summary": {}}
    raise ValueError("Unrecognized findings.json format")

def _node_id(entity_type: str, name: str) -> str:
    return f"{entity_type}::{name}"

def _ensure_node(net: Network, G: nx.DiGraph, node_id: str, label: str, title: str, color: str, size: int = 20):
    if node_id not in G:
        G.add_node(node_id, label=label, title=title, color=color, size=size)
        net.add_node(node_id, label=label, title=title, color=color, size=size)

def build_graph_from_findings(findings: List[Dict[str, Any]]) -> Tuple[nx.DiGraph, Network]:
    G = nx.DiGraph()
    net = Network(height="750px", width="100%", directed=True)
    net.barnes_hut()
    net.toggle_physics(True)

    # special node for "any role / wildcard role target"
    any_role_id = _node_id("anyrole", "*")
    _ensure_node(net, G, any_role_id, label="* (any role)", title="Wildcard role target (PassRole on *)",
                 color=TYPE_COLORS["any_role"], size=24)

    for f in findings:
        rule = f.get("rule")
        sev = f.get("severity", "INFO")
        severity_color = SEV_COLORS.get(sev.upper(), "#888888")

        role_name = f.get("role")
        role_id = None
        if role_name:
            role_id = _node_id("role", role_name)
            title = f"Role: {role_name}\nRule: {rule}\nSeverity: {sev}\n{f.get('title')}"
            extra = []
            if f.get("policy_type"):
                extra.append(f"Policy: {f.get('policy_type')} {f.get('policy_name') or f.get('policy_arn','')}")
            if f.get("statement"):
                extra.append("Statement: " + json.dumps(f.get("statement"), indent=None))
            if extra:
                title += "\n" + "\n".join(extra)
            _ensure_node(net, G, role_id, label=role_name, title=title, color=severity_color, size=26)

        if rule == "R1":
            if role_id:
                G.add_edge(role_id, any_role_id, title=f"R1: {f.get('title')}")
                net.add_edge(role_id, any_role_id, title=f"R1: {f.get('title')}")
        elif rule == "R2":
            stmt = f.get("statement") or {}
            actions = stmt.get("Action") or []
            actions = actions if isinstance(actions, list) else [actions]
            services = set()
            for a in actions:
                if isinstance(a, str) and ":" in a and a.endswith(":*"):
                    services.add(a.split(":")[0])
            if not services:
                svc_id = _node_id("service", "*")
                _ensure_node(net, G, svc_id, label="* (service)", title="Wildcard service target", color=TYPE_COLORS["service"])
                if role_id:
                    G.add_edge(role_id, svc_id, title=f"R2: {f.get('title')}")
                    net.add_edge(role_id, svc_id, title=f"R2: {f.get('title')}")
            else:
                for svc in services:
                    svc_id = _node_id("service", svc)
                    _ensure_node(net, G, svc_id, label=f"{svc}:*", title=f"{svc}:* on *", color=TYPE_COLORS["service"])
                    if role_id:
                        G.add_edge(role_id, svc_id, title=f"R2: {svc}:* on *")
                        net.add_edge(role_id, svc_id, title=f"R2: {svc}:* on *")
        elif rule == "R3":
            stmt = f.get("statement") or {}
            principal = (stmt.get("Principal") or {}).get("AWS")
            principals = principal if isinstance(principal, list) else [principal]
            for p in principals:
                if p is None:
                    continue
                pname = str(p)
                princ_id = _node_id("principal", pname)
                ptitle = f"Principal: {pname}\nRule: R3\nSeverity: {sev}\n{f.get('title')}"
                _ensure_node(net, G, princ_id, label=pname, title=ptitle, color=TYPE_COLORS["principal"], size=20)
                if role_id:
                    G.add_edge(princ_id, role_id, title=f"R3: {f.get('title')}")
                    net.add_edge(princ_id, role_id, title=f"R3: {f.get('title')}")

    return G, net

def render_and_save(net: Network, out_path: str):
    """Save the PyVis graph to an HTML file (interactive) without notebook mode."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(p), notebook=False)
    print(f"[+] Wrote interactive graph to {p}")

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloudSentinel graph generator (demo)")
    parser.add_argument("--in", dest="inp", required=True, help="Path to findings.json")
    parser.add_argument("--out", dest="out", required=True, help="Path to write graph HTML (e.g., graph.html)")
    args = parser.parse_args(argv)

    data = load_findings(args.inp)
    findings = data.get("findings", [])
    if not findings:
        print("[!] No findings found in", args.inp)
        return 1

    G, net = build_graph_from_findings(findings)

    # Optional: seed layout for more stable initial view
    try:
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        for nid, (x, y) in pos.items():
            net.set_coords(nid, x * 1000, y * 1000)
    except Exception:
        pass

    render_and_save(net, args.out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

