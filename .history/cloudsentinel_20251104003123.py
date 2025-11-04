#!/usr/bin/env python3



"""
CloudSentinel — single-entry CLI (no graph, clean demo mode)

Pipeline:
  1) collect_iam.py   -> IAM snapshot (JSON)
  2) analyzer.py      -> findings (JSON)
  3) report_ascii.py  -> terminal report (captured & saved to --out)

Defaults:
  - Writes ONLY the final report (text) to --out.
  - Intermediate files go to a temp dir and are removed automatically.

Options:
  --save-snapshot PATH   Also save iam_snapshot.json here
  --save-findings PATH   Also save findings.json here
  --use-snapshot PATH    Skip collection; use existing snapshot
  --use-findings PATH    Skip collection & analysis; use existing findings (implies snapshot is not needed)
  --demo PATH            Use a demo snapshot source (offline safe)
  --profile NAME         Use an AWS profile for live collection

Examples:
  # Demo mode, only final report:
  python cloudsentinel_cli.py --demo data/iam_snapshot.json --out out/report.txt

  # Live profile, keep intermediates:
  python cloudsentinel_cli.py --profile defender-readonly \
      --save-snapshot out/iam_snapshot.json \
      --save-findings out/findings.json \
      --out out/report.txt

  # Reuse existing artifacts:
  python cloudsentinel_cli.py --use-findings out/findings.json --out out/report.txt
"""

from __future__ import annotations
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

def _find_script(name: str) -> Path:
    p = HERE / name
    if not p.exists():
        p = Path(name)
    if not p.exists():
        raise FileNotFoundError(f"Could not find script {name}. Expected at {HERE / name}")
    return p.resolve()

def _run(cmd: list[str], capture: bool = False) -> tuple[int, str]:
    if capture:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return proc.returncode, proc.stdout
    proc = subprocess.run(cmd)
    return proc.returncode, ""

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CloudSentinel one-command runner (no graph)")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--demo", help="Path to demo snapshot JSON to load (offline safe).")
    src.add_argument("--profile", help="AWS profile name for live collection.")

    ap.add_argument("--out", required=True, help="Path to write the final ASCII report (e.g., out/report.txt).")

    # Optional artifacts
    ap.add_argument("--save-snapshot", help="Also save iam_snapshot.json to this path.")
    ap.add_argument("--save-findings", help="Also save findings.json to this path.")

    # Short-circuit inputs (skip steps)
    ap.add_argument("--use-snapshot", help="Skip collection; use this existing iam_snapshot.json.")
    ap.add_argument("--use-findings", help="Skip collection & analysis; use this existing findings.json.")

    args = ap.parse_args(argv)

    # Validate source selection if not short-circuiting
    if not args.use_snapshot and not args.use_findings and not args.demo and not args.profile:
        ap.error("Provide one of --demo / --profile, or use --use-snapshot / --use-findings to skip steps.")

    py = sys.executable
    collect = _find_script("collect_iam.py")
    analyze = _find_script("analyzer.py")
    report = _find_script("report_ascii.py")

    tmpdir = Path(tempfile.mkdtemp(prefix="cloudsentinel_"))
    snapshot_path = Path(args.save_snapshot) if args.save_snapshot else tmpdir / "iam_snapshot.json"
    findings_path = Path(args.save_findings) if args.save_findings else tmpdir / "findings.json"
    report_path = Path(args.out).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Determine input for analysis/reporting
        if args.use_findings:
            findings_path = Path(args.use_findings).resolve()
            if not findings_path.exists():
                raise FileNotFoundError(f"--use-findings file not found: {findings_path}")
            print(f"[*] Using existing findings: {findings_path}")
        else:
            # Snapshot source
            if args.use_snapshot:
                snapshot_path = Path(args.use_snapshot).resolve()
                if not snapshot_path.exists():
                    raise FileNotFoundError(f"--use-snapshot file not found: {snapshot_path}")
                print(f"[*] Using existing snapshot: {snapshot_path}")
            else:
                # Collect fresh snapshot
                print("[*] Collecting IAM snapshot...")
                if args.demo:
                    rc, _ = _run([py, str(collect), "--demo", args.demo, "--out", str(snapshot_path)])
                else:
                    rc, _ = _run([py, str(collect), "--profile", args.profile, "--out", str(snapshot_path)])
                if rc != 0:
                    print("[!] Collection failed.")
                    return rc
                if args.save_snapshot:
                    print(f"[+] Snapshot saved: {snapshot_path}")
                else:
                    print("[+] Snapshot collected (temp).")

            # Analyze snapshot -> findings
            print("[*] Analyzing snapshot...")
            rc, _ = _run([py, str(analyze), "--in", str(snapshot_path), "--out", str(findings_path)])
            if rc != 0:
                print("[!] Analysis failed.")
                return rc
            if args.save_findings:
                print(f"[+] Findings saved: {findings_path}")
            else:
                print("[+] Findings generated (temp).")

        # Render final ASCII report (capture output to file)
        print("[*] Rendering final ASCII report...")
        rc, out_text = _run([py, str(report), "--in", str(findings_path)], capture=True)
        if rc != 0:
            print("[!] Report rendering failed.")
            report_path.write_text(out_text or "", encoding="utf-8")
            return rc

        # Tee to console and save
        print(out_text, end="")
        report_path.write_text(out_text, encoding="utf-8")
        print(f"\n[+] Wrote final report to {report_path}")
        return 0
    finally:
        # Clean temp dir if user did not request to save intermediates or supply their own
        should_keep = any([
            args.save_snapshot, args.save_findings, args.use_snapshot, args.use_findings
        ])
        if not should_keep:
            try:
                if tmpdir.exists():
                    shutil.rmtree(tmpdir)
            except Exception:
                pass

if __name__ == "__main__":
    raise SystemExit(main())