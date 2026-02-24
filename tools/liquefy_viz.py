#!/usr/bin/env python3
"""
liquefy_viz.py
==============
Vault Visualizer — terminal timeline + token/cost heatmap + per-engine
breakdown + leak highlights.  Optional tiny single-page web UI.

Commands:
    timeline   — chronological vault activity with compression stats
    heatmap    — per-file token/cost/ratio breakdown
    engines    — engine usage breakdown across vaults
    leaks      — highlight risky/quarantined files
    web        — launch a tiny local web UI (single-binary, no deps)

Usage:
    python tools/liquefy_viz.py timeline ./vault
    python tools/liquefy_viz.py heatmap  ./vault
    python tools/liquefy_viz.py engines  ./vault
    python tools/liquefy_viz.py leaks    ./vault
    python tools/liquefy_viz.py web      ./vault --port 8377
"""
from __future__ import annotations

import argparse
import html
import http.server
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
CLI_SCHEMA_VERSION = "liquefy.viz.cli.v1"

# ANSI helpers
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"

BAR_CHARS = " ▏▎▍▌▋▊▉█"

COST_PER_GB_S3 = 0.023  # USD/GB/month S3 Standard
TOKEN_APPROX_BYTES = 4   # ~4 bytes per token (GPT-family average)


def _load_vault_index(vault_dir: Path) -> Optional[Dict]:
    index_path = vault_dir / "tracevault_index.json"
    if not index_path.exists():
        return None
    try:
        return json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_all_vaults(root: Path) -> List[Tuple[Path, Dict]]:
    vaults = []
    if (root / "tracevault_index.json").exists():
        idx = _load_vault_index(root)
        if idx:
            vaults.append((root, idx))
    else:
        for sub in sorted(root.iterdir()):
            if sub.is_dir():
                idx = _load_vault_index(sub)
                if idx:
                    vaults.append((sub, idx))
    return vaults


def _format_bytes(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.0f} KB"
    return f"{n} B"


def _bar(ratio: float, width: int = 20) -> str:
    filled = min(ratio, 1.0) * width
    full_blocks = int(filled)
    remainder = filled - full_blocks
    idx = int(remainder * (len(BAR_CHARS) - 1))
    bar = BAR_CHARS[-1] * full_blocks
    if full_blocks < width:
        bar += BAR_CHARS[idx]
        bar += BAR_CHARS[0] * (width - full_blocks - 1)
    return bar


def _severity_color(severity: str) -> str:
    return {"critical": RED, "high": YELLOW, "medium": CYAN, "low": DIM}.get(severity, "")


# ── Timeline ──


def cmd_timeline(root: Path, **_: Any) -> int:
    vaults = _load_all_vaults(root)
    if not vaults:
        print(f"No vaults found in {root}")
        return 1

    print(f"\n{BOLD}{'═' * 78}{RESET}")
    print(f"{BOLD}  LIQUEFY VAULT TIMELINE{RESET}")
    print(f"{BOLD}{'═' * 78}{RESET}\n")

    total_raw = 0
    total_comp = 0

    for vault_path, index in vaults:
        meta = index.get("metadata", {})
        ts = meta.get("packed_at", meta.get("ts", "unknown"))
        org = meta.get("org", "?")
        profile = meta.get("profile", "?")

        receipts = index.get("receipts", [])
        vault_raw = sum(r.get("original_bytes", 0) for r in receipts)
        vault_comp = sum(r.get("compressed_bytes", 0) for r in receipts)
        total_raw += vault_raw
        total_comp += vault_comp

        ratio = vault_raw / max(1, vault_comp)
        savings_pct = (1 - vault_comp / max(1, vault_raw)) * 100

        color = GREEN if ratio >= 3.0 else (YELLOW if ratio >= 1.5 else RED)
        print(f"  {CYAN}{ts}{RESET}  {BOLD}{vault_path.name}{RESET}")
        print(f"    org={org}  profile={profile}  files={len(receipts)}")
        print(f"    {_format_bytes(vault_raw)} → {_format_bytes(vault_comp)}  "
              f"{color}{ratio:.1f}x{RESET} ({savings_pct:.0f}% saved)")
        print(f"    {DIM}{_bar(savings_pct / 100, 40)}{RESET}")
        print()

    overall_ratio = total_raw / max(1, total_comp)
    print(f"{BOLD}  TOTALS: {_format_bytes(total_raw)} → {_format_bytes(total_comp)}  "
          f"{overall_ratio:.1f}x{RESET}")
    monthly_savings = (total_raw - total_comp) / (1 << 30) * COST_PER_GB_S3
    print(f"  {DIM}Est. storage savings: ${monthly_savings:.2f}/month (S3 Standard){RESET}\n")
    return 0


# ── Heatmap ──


def cmd_heatmap(root: Path, **_: Any) -> int:
    vaults = _load_all_vaults(root)
    if not vaults:
        print(f"No vaults found in {root}")
        return 1

    all_files: List[Dict] = []
    for vault_path, index in vaults:
        for r in index.get("receipts", []):
            all_files.append({
                "vault": vault_path.name,
                "file": r.get("run_relpath", Path(r.get("output_path", "?")).name),
                "raw": r.get("original_bytes", 0),
                "comp": r.get("compressed_bytes", 0),
                "engine": r.get("engine_id", "?"),
            })

    if not all_files:
        print("No files in vaults")
        return 1

    all_files.sort(key=lambda f: f["raw"], reverse=True)

    print(f"\n{BOLD}{'═' * 90}{RESET}")
    print(f"{BOLD}  LIQUEFY HEATMAP — Token Cost & Compression Breakdown{RESET}")
    print(f"{BOLD}{'═' * 90}{RESET}\n")

    print(f"  {'File':<35} {'Raw':>10} {'Comp':>10} {'Ratio':>7} {'~Tokens':>10} {'~Cost':>8}  {'Heat':>20}")
    print(f"  {'─' * 35} {'─' * 10} {'─' * 10} {'─' * 7} {'─' * 10} {'─' * 8}  {'─' * 20}")

    max_raw = max(f["raw"] for f in all_files) if all_files else 1

    for f in all_files[:50]:
        ratio = f["raw"] / max(1, f["comp"])
        tokens = f["raw"] // TOKEN_APPROX_BYTES
        cost_usd = f["raw"] / (1 << 30) * COST_PER_GB_S3

        heat_ratio = f["raw"] / max_raw
        color = RED if ratio < 2.0 else (YELLOW if ratio < 4.0 else GREEN)

        name = f["file"]
        if len(name) > 33:
            name = name[:30] + "..."

        print(f"  {name:<35} {_format_bytes(f['raw']):>10} {_format_bytes(f['comp']):>10} "
              f"{color}{ratio:>6.1f}x{RESET} {tokens:>10,} ${cost_usd:>7.4f}  "
              f"{color}{_bar(heat_ratio, 20)}{RESET}")

    print()
    return 0


# ── Engine Breakdown ──


def cmd_engines(root: Path, **_: Any) -> int:
    vaults = _load_all_vaults(root)
    if not vaults:
        print(f"No vaults found in {root}")
        return 1

    engine_stats: Dict[str, Dict[str, int]] = {}
    for _, index in vaults:
        for r in index.get("receipts", []):
            eid = r.get("engine_id", "unknown")
            if eid not in engine_stats:
                engine_stats[eid] = {"files": 0, "raw": 0, "comp": 0}
            engine_stats[eid]["files"] += 1
            engine_stats[eid]["raw"] += r.get("original_bytes", 0)
            engine_stats[eid]["comp"] += r.get("compressed_bytes", 0)

    print(f"\n{BOLD}{'═' * 78}{RESET}")
    print(f"{BOLD}  LIQUEFY ENGINE BREAKDOWN{RESET}")
    print(f"{BOLD}{'═' * 78}{RESET}\n")

    print(f"  {'Engine':<30} {'Files':>6} {'Raw':>12} {'Compressed':>12} {'Ratio':>8}")
    print(f"  {'─' * 30} {'─' * 6} {'─' * 12} {'─' * 12} {'─' * 8}")

    for eid in sorted(engine_stats, key=lambda e: engine_stats[e]["raw"], reverse=True):
        s = engine_stats[eid]
        ratio = s["raw"] / max(1, s["comp"])
        color = GREEN if ratio >= 3.0 else (YELLOW if ratio >= 1.5 else RED)
        print(f"  {eid:<30} {s['files']:>6} {_format_bytes(s['raw']):>12} "
              f"{_format_bytes(s['comp']):>12} {color}{ratio:>7.1f}x{RESET}")

    total_raw = sum(s["raw"] for s in engine_stats.values())
    total_comp = sum(s["comp"] for s in engine_stats.values())
    total_files = sum(s["files"] for s in engine_stats.values())
    overall = total_raw / max(1, total_comp)
    print(f"  {'─' * 70}")
    print(f"  {'TOTAL':<30} {total_files:>6} {_format_bytes(total_raw):>12} "
          f"{_format_bytes(total_comp):>12} {BOLD}{overall:>7.1f}x{RESET}")
    print()
    return 0


# ── Leak Highlights ──


def cmd_leaks(root: Path, **_: Any) -> int:
    vaults = _load_all_vaults(root)
    if not vaults:
        print(f"No vaults found in {root}")
        return 1

    print(f"\n{BOLD}{'═' * 78}{RESET}")
    print(f"{BOLD}  LIQUEFY LEAK HIGHLIGHTS{RESET}")
    print(f"{BOLD}{'═' * 78}{RESET}\n")

    total_risky = 0
    total_denied = 0

    for vault_path, index in vaults:
        meta = index.get("metadata", {})
        denied = meta.get("denied_files", [])
        risky = meta.get("risky_included", [])
        policy = meta.get("policy", {})

        if not denied and not risky:
            continue

        print(f"  {BOLD}{vault_path.name}{RESET}  policy={policy.get('mode', '?')}")

        for d in denied:
            total_denied += 1
            cat = d.get("category", "?")
            reason = d.get("reason", "?")
            path = d.get("path", d.get("rel_path", "?"))
            print(f"    {RED}DENIED{RESET}  {cat:<25} {path}")

        for r in risky:
            total_risky += 1
            cat = r.get("category", "?")
            path = r.get("path", r.get("rel_path", "?"))
            print(f"    {YELLOW}RISKY{RESET}   {cat:<25} {path}")

        print()

    if total_denied == 0 and total_risky == 0:
        print(f"  {GREEN}No leaks or risky files found across all vaults.{RESET}\n")
    else:
        print(f"  {BOLD}Summary: {total_denied} denied, {total_risky} risky included{RESET}\n")

    return 0


# ── Web UI ──


def _generate_web_html(root: Path) -> str:
    vaults = _load_all_vaults(root)

    vault_data = []
    for vault_path, index in vaults:
        meta = index.get("metadata", {})
        receipts = index.get("receipts", [])
        vault_raw = sum(r.get("original_bytes", 0) for r in receipts)
        vault_comp = sum(r.get("compressed_bytes", 0) for r in receipts)
        vault_data.append({
            "name": vault_path.name,
            "ts": meta.get("packed_at", "?"),
            "org": meta.get("org", "?"),
            "profile": meta.get("profile", "?"),
            "files": len(receipts),
            "raw_bytes": vault_raw,
            "comp_bytes": vault_comp,
            "ratio": round(vault_raw / max(1, vault_comp), 2),
            "receipts": [
                {
                    "file": r.get("run_relpath", "?"),
                    "raw": r.get("original_bytes", 0),
                    "comp": r.get("compressed_bytes", 0),
                    "engine": r.get("engine_id", "?"),
                }
                for r in receipts
            ],
            "denied": meta.get("denied_files", []),
        })

    data_json = json.dumps(vault_data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Liquefy Vault Visualizer</title>
<style>
:root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
         --accent: #58a6ff; --green: #3fb950; --yellow: #d29922; --red: #f85149; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, 'Segoe UI', Roboto, monospace; background: var(--bg); color: var(--text); padding: 24px; }}
h1 {{ color: var(--accent); margin-bottom: 8px; font-size: 1.5rem; }}
.subtitle {{ color: #8b949e; margin-bottom: 24px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.card h2 {{ font-size: 1rem; color: var(--accent); margin-bottom: 8px; }}
.stat {{ display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid var(--border); }}
.stat:last-child {{ border-bottom: none; }}
.label {{ color: #8b949e; }}
.value {{ font-weight: bold; }}
.ratio-good {{ color: var(--green); }}
.ratio-ok {{ color: var(--yellow); }}
.ratio-bad {{ color: var(--red); }}
.bar {{ height: 8px; border-radius: 4px; background: var(--border); overflow: hidden; margin-top: 8px; }}
.bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.85rem; }}
th, td {{ padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ color: #8b949e; font-weight: 500; }}
.denied {{ color: var(--red); font-weight: bold; }}
.tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
.tag-engine {{ background: #1f2937; color: var(--accent); }}
</style>
</head>
<body>
<h1>Liquefy Vault Visualizer</h1>
<p class="subtitle">Root: {html.escape(str(root))} &mdash; {len(vault_data)} vaults</p>
<div class="grid" id="grid"></div>
<script>
const data = {data_json};
const grid = document.getElementById('grid');
const fmt = (n) => {{
  if (n >= 1<<30) return (n/(1<<30)).toFixed(2)+' GB';
  if (n >= 1<<20) return (n/(1<<20)).toFixed(1)+' MB';
  if (n >= 1<<10) return (n/(1<<10)).toFixed(0)+' KB';
  return n+' B';
}};
const rc = (r) => r >= 3 ? 'ratio-good' : r >= 1.5 ? 'ratio-ok' : 'ratio-bad';
data.forEach(v => {{
  const savings = v.raw_bytes > 0 ? ((1 - v.comp_bytes/v.raw_bytes)*100).toFixed(1) : 0;
  let rows = v.receipts.slice(0, 20).map(r => {{
    const ratio = r.raw > 0 ? (r.raw / Math.max(1, r.comp)).toFixed(1) : '0.0';
    return `<tr><td>${{r.file}}</td><td>${{fmt(r.raw)}}</td><td>${{fmt(r.comp)}}</td><td class="${{rc(parseFloat(ratio))}}">${{ratio}}x</td><td><span class="tag tag-engine">${{r.engine}}</span></td></tr>`;
  }}).join('');
  let denied = v.denied.map(d => `<tr><td class="denied">DENIED</td><td colspan="4">${{d.category||d.reason||'?'}}</td></tr>`).join('');
  grid.innerHTML += `<div class="card">
    <h2>${{v.name}}</h2>
    <div class="stat"><span class="label">Time</span><span class="value">${{v.ts}}</span></div>
    <div class="stat"><span class="label">Files</span><span class="value">${{v.files}}</span></div>
    <div class="stat"><span class="label">Raw</span><span class="value">${{fmt(v.raw_bytes)}}</span></div>
    <div class="stat"><span class="label">Compressed</span><span class="value">${{fmt(v.comp_bytes)}}</span></div>
    <div class="stat"><span class="label">Ratio</span><span class="value ${{rc(v.ratio)}}">${{v.ratio}}x (${{savings}}% saved)</span></div>
    <div class="bar"><div class="bar-fill" style="width:${{Math.min(savings,100)}}%;background:${{v.ratio>=3?'var(--green)':v.ratio>=1.5?'var(--yellow)':'var(--red)'}}"></div></div>
    <table><tr><th>File</th><th>Raw</th><th>Comp</th><th>Ratio</th><th>Engine</th></tr>${{rows}}${{denied}}</table>
  </div>`;
}});
</script>
</body></html>"""


def cmd_web(root: Path, port: int = 8377, **_: Any) -> int:
    page_html = _generate_web_html(root)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page_html.encode())

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    print(f"\n  Liquefy Viz running at http://127.0.0.1:{port}")
    print(f"  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    return 0


# ── CLI ──


COMMANDS = {
    "timeline": cmd_timeline,
    "heatmap": cmd_heatmap,
    "engines": cmd_engines,
    "leaks": cmd_leaks,
    "web": cmd_web,
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="liquefy-viz", description="Liquefy Vault Visualizer")
    sub = ap.add_subparsers(dest="command")

    for name in ("timeline", "heatmap", "engines", "leaks"):
        p = sub.add_parser(name)
        p.add_argument("root", help="Vault root directory")
        p.add_argument("--json", action="store_true")

    p_web = sub.add_parser("web", help="Launch tiny web UI")
    p_web.add_argument("root", help="Vault root directory")
    p_web.add_argument("--port", type=int, default=8377)

    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help()
        return 1

    root = Path(args.root).expanduser().resolve()
    handler = COMMANDS.get(args.command)
    if not handler:
        return 1

    kwargs: Dict[str, Any] = {}
    if args.command == "web":
        kwargs["port"] = args.port
    return handler(root, **kwargs)


if __name__ == "__main__":
    raise SystemExit(main())
