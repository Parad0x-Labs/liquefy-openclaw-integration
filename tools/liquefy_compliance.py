#!/usr/bin/env python3
"""
liquefy_compliance.py
=====================
Generate compliance-grade HTML reports from Liquefy audit chains and vault metadata.

Designed for CTOs, compliance officers, and auditors who need human-readable proof
that agent operations are tracked, verified, and tamper-free.

Modes:
    report    — generate HTML compliance report from audit chain + vault
    verify    — verify chain integrity and output pass/fail summary
    timeline  — generate chronological event timeline

Usage:
    python tools/liquefy_compliance.py report --vault ./vault --output report.html
    python tools/liquefy_compliance.py report --vault ./vault --output report.html --org acme --title "Q1 Audit"
    python tools/liquefy_compliance.py verify --vault ./vault --json
    python tools/liquefy_compliance.py timeline --vault ./vault --output timeline.html
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)


def _load_audit_chain(vault_dir: Path) -> List[Dict]:
    """Load audit chain entries from vault or default audit dir."""
    entries: List[Dict] = []
    candidates = [
        vault_dir / "audit" / "chain.jsonl",
        vault_dir / "chain.jsonl",
        vault_dir / ".liquefy" / "audit" / "default" / "chain.jsonl",
        Path.home() / ".liquefy" / "audit" / "default" / "chain.jsonl",
    ]
    for p in candidates:
        if p.exists():
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            break
    return entries


def _load_vault_manifests(vault_dir: Path) -> List[Dict]:
    """Load .null vault manifests."""
    manifests = []
    for mf in vault_dir.rglob("*.manifest.json"):
        try:
            manifests.append(json.loads(mf.read_text("utf-8")))
        except Exception:
            pass
    for mf in vault_dir.rglob("OPENCLAW_LIQUEFY_REPORT.md"):
        manifests.append({"_type": "report_md", "path": str(mf)})
    return manifests


def _verify_chain(entries: List[Dict]) -> Tuple[bool, List[Dict]]:
    """Verify hash chain integrity. Returns (ok, issues)."""
    issues = []
    if not entries:
        return True, []

    prev_hash = "0" * 64
    for i, entry in enumerate(entries):
        entry_prev = entry.get("prev_hash", "")
        if entry_prev != prev_hash:
            issues.append({
                "seq": entry.get("seq", i),
                "issue": "prev_hash mismatch",
                "expected": prev_hash[:16] + "...",
                "got": entry_prev[:16] + "...",
            })

        verify_entry = {k: v for k, v in entry.items() if k != "_hash"}
        canonical = json.dumps(verify_entry, sort_keys=True, separators=(",", ":"))
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        stored = entry.get("_hash", "")

        if computed != stored:
            issues.append({
                "seq": entry.get("seq", i),
                "issue": "hash mismatch (possible tampering)",
            })

        prev_hash = stored

    return len(issues) == 0, issues


def _event_stats(entries: List[Dict]) -> Dict[str, Any]:
    """Compute statistics from audit chain."""
    events = Counter()
    first_ts = None
    last_ts = None

    for e in entries:
        events[e.get("event", "unknown")] += 1
        ts = e.get("ts")
        if ts:
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

    return {
        "total_entries": len(entries),
        "event_types": dict(events),
        "first_event": first_ts,
        "last_event": last_ts,
        "unique_events": len(events),
    }


CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0a0a0f; color: #e0e0e0; line-height: 1.6; padding: 40px; }
.container { max-width: 900px; margin: 0 auto; }
.header { border-bottom: 2px solid #1a1a2e; padding-bottom: 30px; margin-bottom: 40px; }
.header h1 { font-size: 28px; font-weight: 900; text-transform: uppercase;
             letter-spacing: 2px; color: #fff; }
.header .subtitle { font-size: 13px; color: #888; font-family: monospace;
                     margin-top: 8px; letter-spacing: 1px; text-transform: uppercase; }
.badge { display: inline-block; padding: 4px 12px; border-radius: 4px;
         font-size: 11px; font-weight: 700; text-transform: uppercase;
         letter-spacing: 1px; margin-right: 8px; }
.badge-pass { background: #0d3320; color: #4ade80; border: 1px solid #166534; }
.badge-fail { background: #3b1019; color: #f87171; border: 1px solid #991b1b; }
.badge-info { background: #1a1a2e; color: #818cf8; border: 1px solid #3730a3; }
.section { margin-bottom: 40px; }
.section h2 { font-size: 16px; text-transform: uppercase; letter-spacing: 2px;
              color: #a78bfa; margin-bottom: 16px; padding-bottom: 8px;
              border-bottom: 1px solid #1a1a2e; }
.card { background: #111118; border: 1px solid #1a1a2e; border-radius: 12px;
        padding: 24px; margin-bottom: 16px; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
             gap: 16px; }
.stat { text-align: center; padding: 20px; background: #0d0d14; border-radius: 8px;
        border: 1px solid #1a1a2e; }
.stat .value { font-size: 32px; font-weight: 900; color: #fff; font-style: italic; }
.stat .label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px;
               color: #666; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 10px 12px; background: #0d0d14; color: #888;
     font-size: 10px; text-transform: uppercase; letter-spacing: 1px;
     border-bottom: 1px solid #1a1a2e; }
td { padding: 10px 12px; border-bottom: 1px solid #0d0d14; }
tr:hover td { background: #111118; }
.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; }
.timestamp { color: #666; font-size: 11px; font-family: monospace; }
.footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #1a1a2e;
          text-align: center; color: #444; font-size: 11px; font-family: monospace;
          text-transform: uppercase; letter-spacing: 2px; }
.chain-ok { color: #4ade80; }
.chain-fail { color: #f87171; }
"""


def _generate_html_report(
    entries: List[Dict],
    chain_ok: bool,
    chain_issues: List[Dict],
    stats: Dict,
    org: str,
    title: str,
    vault_dir: str,
) -> str:
    """Generate a full compliance HTML report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    chain_status = "CHAIN INTACT" if chain_ok else "CHAIN BROKEN"
    chain_class = "chain-ok" if chain_ok else "chain-fail"

    event_rows = ""
    for event_type, count in sorted(stats["event_types"].items(), key=lambda x: -x[1]):
        event_rows += f"<tr><td class='mono'>{html.escape(event_type)}</td><td>{count}</td></tr>\n"

    recent_rows = ""
    for e in entries[-25:]:
        ts = e.get("ts", "")[:19]
        evt = html.escape(e.get("event", ""))
        seq = e.get("seq", "")
        h = e.get("_hash", "")[:12] + "..."
        recent_rows += f"<tr><td class='timestamp'>{ts}</td><td>{seq}</td><td class='mono'>{evt}</td><td class='mono'>{h}</td></tr>\n"

    issue_section = ""
    if chain_issues:
        issue_rows = ""
        for iss in chain_issues:
            issue_rows += f"<tr><td>{iss.get('seq','')}</td><td class='mono'>{html.escape(iss.get('issue',''))}</td></tr>\n"
        issue_section = f"""
        <div class="section">
            <h2>Chain Issues</h2>
            <div class="card">
                <table>
                    <tr><th>Sequence</th><th>Issue</th></tr>
                    {issue_rows}
                </table>
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — Liquefy Compliance Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>{html.escape(title)}</h1>
    <div class="subtitle">Liquefy Compliance Report // {html.escape(org)} // Generated {now}</div>
    <div style="margin-top: 16px;">
        <span class="badge {'badge-pass' if chain_ok else 'badge-fail'}">{chain_status}</span>
        <span class="badge badge-info">{stats['total_entries']} Events</span>
        <span class="badge badge-info">{stats['unique_events']} Types</span>
    </div>
</div>

<div class="section">
    <h2>Integrity Verification</h2>
    <div class="card">
        <p style="font-size: 15px;">
            Audit chain hash verification:
            <strong class="{chain_class}" style="font-size: 18px;">{chain_status}</strong>
        </p>
        <p style="margin-top: 8px; color: #888; font-size: 13px;">
            {'Every entry in the SHA-256 hash chain has been verified. No tampering detected.' if chain_ok
             else f'{len(chain_issues)} integrity issue(s) detected. Review the issues section below.'}
        </p>
        <p style="margin-top: 8px; color: #666; font-size: 12px; font-family: monospace;">
            Vault: {html.escape(vault_dir)}
        </p>
    </div>
</div>

<div class="section">
    <h2>Summary</h2>
    <div class="stat-grid">
        <div class="stat">
            <div class="value">{stats['total_entries']}</div>
            <div class="label">Total Events</div>
        </div>
        <div class="stat">
            <div class="value">{stats['unique_events']}</div>
            <div class="label">Event Types</div>
        </div>
        <div class="stat">
            <div class="value">{'✓' if chain_ok else '✗'}</div>
            <div class="label">Chain Status</div>
        </div>
    </div>
    <div class="card" style="margin-top: 16px;">
        <table>
            <tr><td style="color:#888;">First Event</td><td class="mono">{stats.get('first_event','N/A')}</td></tr>
            <tr><td style="color:#888;">Last Event</td><td class="mono">{stats.get('last_event','N/A')}</td></tr>
            <tr><td style="color:#888;">Organization</td><td>{html.escape(org)}</td></tr>
            <tr><td style="color:#888;">Report Generated</td><td class="mono">{now}</td></tr>
        </table>
    </div>
</div>

<div class="section">
    <h2>Event Breakdown</h2>
    <div class="card">
        <table>
            <tr><th>Event Type</th><th>Count</th></tr>
            {event_rows}
        </table>
    </div>
</div>

{issue_section}

<div class="section">
    <h2>Recent Activity (Last 25 Events)</h2>
    <div class="card" style="overflow-x:auto;">
        <table>
            <tr><th>Timestamp</th><th>Seq</th><th>Event</th><th>Hash</th></tr>
            {recent_rows}
        </table>
    </div>
</div>

<div class="footer">
    Liquefy Compliance Report &copy; {datetime.now().year} Parad0x Labs — Tamper-Proof Audit Chain
</div>

</div>
</body>
</html>"""


def cmd_report(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    if not vault_dir.exists():
        print(json.dumps({"ok": False, "error": f"Vault not found: {vault_dir}"}))
        return 1

    entries = _load_audit_chain(vault_dir)
    chain_ok, issues = _verify_chain(entries)
    stats = _event_stats(entries)

    org = args.org or os.environ.get("LIQUEFY_ORG", "default")
    title = args.title or "Agent Compliance Audit"

    report_html = _generate_html_report(entries, chain_ok, issues, stats, org, title, str(vault_dir))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_html, encoding="utf-8")

    result = {
        "ok": True,
        "output": str(output),
        "format": "html",
        "chain_intact": chain_ok,
        "total_entries": stats["total_entries"],
        "issues": len(issues),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if chain_ok else "FAIL"
        print(f"  Compliance report generated: {output}")
        print(f"  Chain integrity: {status}")
        print(f"  Events: {stats['total_entries']}")
        if issues:
            print(f"  Issues: {len(issues)}")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    entries = _load_audit_chain(vault_dir)
    chain_ok, issues = _verify_chain(entries)
    stats = _event_stats(entries)

    result = {
        "ok": chain_ok,
        "chain_intact": chain_ok,
        "entries_verified": len(entries),
        "issues": issues,
        "stats": stats,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS — chain intact" if chain_ok else "FAIL — tampering detected"
        print(f"  Chain verification: {status}")
        print(f"  Entries verified: {len(entries)}")
        for iss in issues:
            print(f"  Issue at seq {iss.get('seq')}: {iss.get('issue')}")

    return 0 if chain_ok else 1


def cmd_timeline(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    entries = _load_audit_chain(vault_dir)
    org = args.org or "default"

    rows = ""
    for e in entries:
        ts = e.get("ts", "")[:19]
        evt = html.escape(e.get("event", ""))
        details = {k: v for k, v in e.items() if k not in ("ts", "event", "seq", "prev_hash", "_hash")}
        detail_str = html.escape(json.dumps(details, separators=(",", ":")))[:120]
        rows += f"<tr><td class='timestamp'>{ts}</td><td class='mono'>{evt}</td><td style='color:#666;font-size:11px;'>{detail_str}</td></tr>\n"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Timeline — {html.escape(org)}</title>
<style>{CSS}</style></head>
<body><div class="container">
<div class="header"><h1>Event Timeline</h1>
<div class="subtitle">{html.escape(org)} // {now}</div></div>
<div class="section"><div class="card" style="overflow-x:auto;">
<table><tr><th>Timestamp</th><th>Event</th><th>Details</th></tr>
{rows}
</table></div></div>
<div class="footer">Liquefy Timeline &copy; {datetime.now().year} Parad0x Labs</div>
</div></body></html>"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_html, encoding="utf-8")

    if args.json:
        print(json.dumps({"ok": True, "output": str(output), "events": len(entries)}))
    else:
        print(f"  Timeline generated: {output} ({len(entries)} events)")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-compliance",
        description="Generate compliance reports from Liquefy audit chains.",
    )
    sub = parser.add_subparsers(dest="command")

    p_report = sub.add_parser("report", help="Generate HTML compliance report")
    p_report.add_argument("--vault", required=True, help="Path to vault directory")
    p_report.add_argument("--output", default="COMPLIANCE_REPORT.html", help="Output file path")
    p_report.add_argument("--org", help="Organization name")
    p_report.add_argument("--title", help="Report title")
    p_report.add_argument("--json", action="store_true", help="JSON output")

    p_verify = sub.add_parser("verify", help="Verify audit chain integrity")
    p_verify.add_argument("--vault", required=True, help="Path to vault directory")
    p_verify.add_argument("--json", action="store_true", help="JSON output")

    p_timeline = sub.add_parser("timeline", help="Generate event timeline")
    p_timeline.add_argument("--vault", required=True, help="Path to vault directory")
    p_timeline.add_argument("--output", default="TIMELINE.html", help="Output file path")
    p_timeline.add_argument("--org", help="Organization name")
    p_timeline.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args()

    if args.command == "report":
        return cmd_report(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "timeline":
        return cmd_timeline(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
