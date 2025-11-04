#!/usr/bin/env python3
"""
CloudSentinel — unified runner (imports the 3 modules and pipes data in-memory)

Usage examples
--------------
# Full live run (uses boto3 + --profile) → prints ASCII report
python run_pipeline.py pipeline --profile defender-readonly \
  --snapshot-out data/iam_snapshot.json --findings-out out/findings.json

# Full demo run (use canned snapshot) → prints ASCII report
python run_pipeline.py pipeline --demo demo/sample_account.json

# Start from an existing snapshot file → analyze + report only
python run_pipeline.py pipeline --in-snapshot data/iam_snapshot.json

# Start from existing findings → just render the ASCII report
python run_pipeline.py pipeline --in-findings out/findings.json

# Also expose pass-through wrappers so you can call the original tools via this CLI:
python run_pipeline.py collect --profile defender-readonly --out data/iam_snapshot.json
python run_pipeline.py analyze --in data/iam_snapshot.json --out out/findings.json --format json
python run_pipeline.py report --in out/findings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# --- Import project modules ---------------------------------------------------
# Assumes these files are in the same directory or on PYTHONPATH:
#   collect_iam.py, analyzer.py, report_ascii.py
import collect_iam as collect_mod        # your collector file
import analyzer as analyzer_mod          # your analyzer file
import report_ascii as report_mod        # your ASCII reporter


# ---------------------------- helpers ----------------------------------------

def _read_json(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))

def _write_json(data: Dict[str, Any], path: Optional[str | Path]) -> None:
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Wrote JSON to {p}")

# ---------------------------- pipeline core ----------------------------------

def collect_snapshot(profile: Optional[str]=None,
                     demo_path: Optional[str]=None) -> Dict[str, Any]:
    """
    Returns the IAM snapshot dict (never writes unless the caller asks).
    """
    if demo_path:
        print("[*] Pipeline: loading demo snapshot…")
        data = collect_mod.read_json(demo_path)
        data.setdefault("collected_at", collect_mod.iso_utc_now())
        data.setdefault("iam", {})
        return data

    print("[*] Pipeline: starting live IAM collection (read-only)…")
    collector = collect_mod.CloudSentinelCollector(profile=profile)
    return collector.collect()


def analyze_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns {"findings": [...], "summary": {...}}
    (compatible with report_ascii.load_findings() expectations)
    """
    findings = analyzer_mod.analyze(snapshot)
    summary = analyzer_mod.summarize_findings(findings)
    return {"findings": findings, "summary": summary}


def render_ascii_from_findings(findings_blob: Dict[str, Any]) -> None:
    """
    Prints the same ASCII report as report_ascii.py would produce.
    """
    findings = findings_blob.get("findings", [])
    if not findings:
        print("[!] No findings to report.")
        return

    esc_map = report_mod.analyze_escalation_ready(findings)

    print("\nCloudSentinel — Account Risk Report (ASCII)\n")
    report_mod.render_summary(findings, esc_map)
    print("\nFindings (sorted):\n")
    report_mod.render_table(findings, esc_map)
    report_mod.render_top_paths(esc_map)
    print()


# ---------------------------- CLI commands -----------------------------------

def cmd_pipeline(args: argparse.Namespace) -> int:
    # 1) Source a snapshot (either collect live, load demo, or read an existing file)
    if args.in_findings:
        # Skip to reporting
        findings_blob = _read_json(args.in_findings)
        if isinstance(findings_blob, list):
            findings_blob = {"findings": findings_blob, "summary": {}}
        render_ascii_from_findings(findings_blob)
        return 0

    if args.in_snapshot:
        snapshot = _read_json(args.in_snapshot)
    else:
        snapshot = collect_snapshot(profile=args.profile, demo_path=args.demo)

    # optionally save the snapshot
    _write_json(snapshot, args.snapshot_out)

    # 2) Analyze
    analyzed = analyze_snapshot(snapshot)

    # optionally save the findings as JSON (always JSON)
    _write_json(analyzed, args.findings_out)

    # 3) Report (ASCII to stdout)
    render_ascii_from_findings(analyzed)
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    # Passthrough wrapper to behave like collect_iam.py but via this CLI
    if args.demo:
        data = collect_mod.read_json(args.demo)
        data.setdefault("collected_at", collect_mod.iso_utc_now())
        data.setdefault("iam", {})
        collect_mod.write_json(data, args.out)
        print(f"[+] Wrote demo snapshot to {args.out}")
        return 0

    collector = collect_mod.CloudSentinelCollector(profile=args.profile)
    snapshot = collector.collect()
    collect_mod.write_json(snapshot, args.out)
    print(f"[+] Wrote IAM snapshot to {args.out}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    # Passthrough wrapper mirroring analyzer.py’s interface
    snapshot = _read_json(args.inp)
    findings = analyzer_mod.analyze(snapshot)
    summary = analyzer_mod.summarize_findings(findings)

    if args.format == "json":
        out_text = json.dumps({"findings": findings, "summary": summary}, indent=2)
    else:
        out_text = analyzer_mod.render_text(findings) + "\nSummary: " + str(summary)

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out_text, encoding="utf-8")
        print(f"[+] Wrote findings to {args.out}")
    else:
        print(out_text)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    # Passthrough wrapper mirroring report_ascii.py’s interface
    data = report_mod.load_findings(args.inp)  # accepts list or {"findings": ...}
    findings = data.get("findings", [])
    if not findings:
        print("[!] No findings in", args.inp)
        return 1
    esc_map = report_mod.analyze_escalation_ready(findings)

    print("\nCloudSentinel — Account Risk Report (ASCII)\n")
    report_mod.render_summary(findings, esc_map)
    print("\nFindings (sorted):\n")
    report_mod.render_table(findings, esc_map)
    report_mod.render_top_paths(esc_map)
    print()
    return 0


# ---------------------------- main -------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_pipeline.py",
        description="CloudSentinel unified runner (imports collect_iam/analyzer/report_ascii)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # pipeline
    sp = sub.add_parser("pipeline", help="Run end-to-end or from any stage, then print ASCII report")
    sp.add_argument("--profile", help="AWS profile (live collection)", default=None)
    sp.add_argument("--demo", help="Demo snapshot JSON path (skip live)", default=None)
    sp.add_argument("--in-snapshot", help="Existing iam_snapshot.json to analyze", default=None)
    sp.add_argument("--in-findings", help="Existing findings.json to render", default=None)
    sp.add_argument("--snapshot-out", help="Optional path to save the snapshot JSON", default=None)
    sp.add_argument("--findings-out", help="Optional path to save the findings JSON", default=None)
    sp.set_defaults(func=cmd_pipeline)

    # collect passthrough
    sc = sub.add_parser("collect", help="Run collector like collect_iam.py")
    sc.add_argument("--profile", help="AWS profile name (live)", default=None)
    sc.add_argument("--demo", help="Demo snapshot JSON path", default=None)
    sc.add_argument("--out", required=True, help="Where to write iam_snapshot.json")
    sc.set_defaults(func=cmd_collect)

    # analyze passthrough
    sa = sub.add_parser("analyze", help="Run analyzer like analyzer.py")
    sa.add_argument("--in", dest="inp", required=True, help="Path to iam_snapshot.json")
    sa.add_argument("--out", help="Write findings to file (optional)")
    sa.add_argument("--format", choices=["text", "json"], default="text")
    sa.set_defaults(func=cmd_analyze)

    # report passthrough
    sr = sub.add_parser("report", help="Run reporter like report_ascii.py")
    sr.add_argument("--in", dest="inp", required=True, help="Path to findings.json")
    sr.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        return 130
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
