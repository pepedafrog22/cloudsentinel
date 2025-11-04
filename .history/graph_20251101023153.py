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
    "CRITICAL": "#8B0000",  # very dark red
    "HIGH": "#FF4136",      # red
    "MEDIUM": "#FF851B",    # orange
    "LOW": "#FFDC00",       # yellow
    "INFO": "#2ECC40",      # green
}

# node styles for entity types
TYPE_COLORS = {
    "role": "#0074D9",
    "principal": "#B10DC9",
    "service": "#FF851B",
    "any_role": "#AAAAAA",
}


def load_findings(path: str) -> Dict[str, Any]:
    """Load findings JSON which may contain {"findings": [...], "summary": {...}} or just an array."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        return {"findings": data["findings"], "summary": data.get("summary", {})}
    # assume file is raw list
    if isinstance(data, list):
        return {"findings": data, "summary": {}}
    raise ValueError("Unrecognized findings.json format")


def _node_id(entity_type: str, name: str) -> str:
    """Create a stable node id string; include type so nodes are unique across types."""
    return f"{entity_type}::{name}"


def _ensure_node(net: Network, G: nx.DiGraph, node_id: str, label: str, title: str, color: str, size: int = 20):
    """Add node to graph (NetworkX + PyVis) if not present."""
    if node_id not in G:
        G.add_node(node_id, label=label, title=title, color=color, size=size)
        net.add_node(node_id, label=label, title=title, color=color, size=size)


def build_graph_from_findings(findings: List[Dict[str, Any]]) -> Tuple[nx.DiGraph, Network]:
    """
    Build a directed graph and PyVis network from analyzer findings.

    Nodes:
      - roles: role::<rolename>
      - principals: principal::<arn-or-*>
      - services / any-role placeholders: service::<name> or anyrole::ANY

    Edges reflect:
      - R1: role -> ANY_ROLE (PassRole on *)
      - R2: role -> service (e.g., s3:* on *)
      - R3: principal -> role (trust relationship)
    """
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

        # If role is present, ensure role node
        role_name = f.get("role")
        role_id = None
        if role_name:
            role_id = _node_id("role", role_name)
            title = f"Role: {role_name}\nRule: {rule}\nSeverity: {sev}\n{f.get('title')}"
            # include more detail in hover if available
            extra = []
            if f.get("policy_type"):
                extra.append(f"Policy: {f.get('policy_type')} {f.get('policy_name') or f.get('policy_arn','')}")
            if f.get("statement"):
                extra.append("Statement: " + json.dumps(f.get("statement"), indent=None))
            if extra:
                title += "\n" + "\n".join(extra)
            _ensure_node(net, G, role_id, label=role_name, title=title, color=severity_color, size=26)

        # R1: PassRole on *  -> draw role -> any_role
        if rule == "R1":
            if role_id:
                G.add_edge(role_id, any_role_id, title=f"R1: {f.get('title')}")
                net.add_edge(role_id, any_role_id, title=f"R1: {f.get('title')}")

        # R2: Admin-style wildcard -> map to service nodes
        elif rule == "R2":
            # try to infer service from statement actions (e.g., 's3:*', 'iam:*')
            stmt = f.get("statement") or {}
            actions = stmt.get("Action") or []
            actions = actions if isinstance(actions, list) else [actions]
            services = set()
            for a in actions:
                if isinstance(a, str) and ":" in a and a.endswith(":*"):
                    svc = a.split(":")[0]
                    services.add(svc)
            # if no specific service found, fallback to "*" node
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

        # R3: trust broad -> Principal -> role edges
        elif rule == "R3":
            stmt = f.get("statement") or {}
            principal = (stmt.get("Principal") or {}).get("AWS")
            principals = principal if isinstance(principal, list) else [principal]
            for p in principals:
                if p is None:
                    continue
                # normalize '*'
                pname = str(p)
                princ_id = _node_id("principal", pname)
                ptitle = f"Principal: {pname}\nRule: R3\nSeverity: {sev}\n{f.get('title')}"
                _ensure_node(net, G, princ_id, label=pname, title=ptitle, color=TYPE_COLORS["principal"], size=20)
                if role_id:
                    # principal -> role (principal can assume role)
                    G.add_edge(princ_id, role_id, title=f"R3: {f.get('title')}")
                    net.add_edge(princ_id, role_id, title=f"R3: {f.get('title')}")

    return G, net


def render_and_save(net: Network, out_path: str):
    """Save the PyVis graph to an HTML file (interactive)."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    net.show(str(p))


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
    # Use NetworkX layout for initial positions (optional)
    try:
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        # push positions into PyVis nodes for stability
        for nid, (x, y) in pos.items():
            net.set_coords(nid, x * 1000, y * 1000)
    except Exception:
        # layout optional; ignore if layout fails
        pass

    def render_and_save(net: Network, out_path: str):
        """Save the PyVis graph to an HTML file (interactive) without notebook mode."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Write HTML directly and don't try to use notebook rendering
    net.write_html(str(p), notebook=False)  # <-- key change


if __name__ == "__main__":
    raise SystemExit(main())
