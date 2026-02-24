#!/usr/bin/env python3
"""
liquefy_obsidian.py
===================
Obsidian Sync + Memory Bridge.

Pushes vault summaries, searchable indexes, and daily agent recaps into
an Obsidian vault as dataview-ready markdown notes with YAML frontmatter.

Commands:
    sync       — full sync: vault summaries + file index + daily recap
    recap      — push only today's recap note
    index      — push searchable vault index
    link       — print Obsidian vault URI for a specific vault

Usage:
    python tools/liquefy_obsidian.py sync  --vault-root ./vault --obsidian ~/Obsidian/Agent
    python tools/liquefy_obsidian.py recap --vault-root ./vault --obsidian ~/Obsidian/Agent
    python tools/liquefy_obsidian.py index --vault-root ./vault --obsidian ~/Obsidian/Agent
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
CLI_SCHEMA_VERSION = "liquefy.obsidian.cli.v1"

DEFAULT_OBSIDIAN_SUBDIR = "Liquefy"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _format_bytes(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.0f} KB"
    return f"{n} B"


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


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _vault_summary_note(vault_path: Path, index: Dict) -> str:
    """Generate a dataview-ready Obsidian note for a single vault."""
    meta = index.get("metadata", {})
    receipts = index.get("receipts", [])
    raw_total = sum(r.get("original_bytes", 0) for r in receipts)
    comp_total = sum(r.get("compressed_bytes", 0) for r in receipts)
    ratio = raw_total / max(1, comp_total)
    savings_pct = (1 - comp_total / max(1, raw_total)) * 100 if raw_total > 0 else 0

    engines_used = set()
    for r in receipts:
        eid = r.get("engine_id")
        if eid:
            engines_used.add(eid)

    denied = meta.get("denied_files", [])

    lines = [
        "---",
        f"type: liquefy-vault",
        f"vault_name: \"{vault_path.name}\"",
        f"packed_at: \"{meta.get('packed_at', '?')}\"",
        f"org: \"{meta.get('org', '?')}\"",
        f"profile: \"{meta.get('profile', '?')}\"",
        f"files: {len(receipts)}",
        f"raw_bytes: {raw_total}",
        f"compressed_bytes: {comp_total}",
        f"ratio: {ratio:.2f}",
        f"savings_pct: {savings_pct:.1f}",
        "engines: [{}]".format(", ".join('"{}"'.format(e) for e in sorted(engines_used))),
        f"leaks_blocked: {len(denied)}",
        f"tags: [liquefy, vault, compression]",
        "---",
        "",
        f"# {vault_path.name}",
        "",
        f"**Packed**: {meta.get('packed_at', '?')}  ",
        f"**Org**: {meta.get('org', '?')} | **Profile**: {meta.get('profile', '?')}  ",
        f"**Files**: {len(receipts)} | **Raw**: {_format_bytes(raw_total)} → **Compressed**: {_format_bytes(comp_total)}  ",
        f"**Ratio**: {ratio:.1f}x ({savings_pct:.0f}% saved)  ",
        "",
        "## Files",
        "",
        "| File | Raw | Compressed | Ratio | Engine |",
        "|------|-----|-----------|-------|--------|",
    ]

    for r in receipts:
        rpath = r.get("run_relpath", "?")
        rb = r.get("original_bytes", 0)
        cb = r.get("compressed_bytes", 0)
        er = rb / max(1, cb)
        eid = r.get("engine_id", "?")
        lines.append(f"| `{rpath}` | {_format_bytes(rb)} | {_format_bytes(cb)} | {er:.1f}x | {eid} |")

    if denied:
        lines.extend(["", "## Blocked / Denied Files", ""])
        for d in denied:
            lines.append(f"- **{d.get('category', '?')}**: `{d.get('path', d.get('rel_path', '?'))}`")

    lines.append("")
    return "\n".join(lines)


def _daily_recap_note(vaults: List[Tuple[Path, Dict]], date: str) -> str:
    """Generate a daily recap note for Obsidian."""
    total_raw = 0
    total_comp = 0
    total_files = 0
    total_denied = 0
    engines: Dict[str, int] = {}

    for _, index in vaults:
        meta = index.get("metadata", {})
        packed_at = meta.get("packed_at", "")
        if date not in packed_at:
            continue
        receipts = index.get("receipts", [])
        for r in receipts:
            total_raw += r.get("original_bytes", 0)
            total_comp += r.get("compressed_bytes", 0)
            total_files += 1
            eid = r.get("engine_id", "?")
            engines[eid] = engines.get(eid, 0) + 1
        total_denied += len(meta.get("denied_files", []))

    ratio = total_raw / max(1, total_comp)
    savings_pct = (1 - total_comp / max(1, total_raw)) * 100 if total_raw > 0 else 0

    lines = [
        "---",
        f"type: liquefy-recap",
        f"date: \"{date}\"",
        f"files_archived: {total_files}",
        f"raw_bytes: {total_raw}",
        f"compressed_bytes: {total_comp}",
        f"ratio: {ratio:.2f}",
        f"leaks_blocked: {total_denied}",
        f"tags: [liquefy, recap, daily]",
        "---",
        "",
        f"# Liquefy Daily Recap — {date}",
        "",
        f"Your agents produced **{_format_bytes(total_raw)}** raw → **{_format_bytes(total_comp)}** in vaults.  ",
        f"**{total_denied}** leaks blocked. **{total_files}** files archived.  ",
        f"Overall ratio: **{ratio:.1f}x** ({savings_pct:.0f}% savings).  ",
        "",
        "## Engine Usage",
        "",
        "| Engine | Files |",
        "|--------|-------|",
    ]

    for eid, count in sorted(engines.items(), key=lambda x: -x[1]):
        lines.append(f"| {eid} | {count} |")

    lines.extend(["", "---", f"*Generated by Liquefy Obsidian Bridge at {_utc_now()}*", ""])
    return "\n".join(lines)


def _searchable_index_note(vaults: List[Tuple[Path, Dict]]) -> str:
    """Generate a master searchable index for dataview queries."""
    lines = [
        "---",
        f"type: liquefy-index",
        f"generated_at: \"{_utc_now()}\"",
        f"vault_count: {len(vaults)}",
        f"tags: [liquefy, index, dataview]",
        "---",
        "",
        "# Liquefy Vault Index",
        "",
        "Use with Obsidian Dataview:",
        "```dataview",
        "TABLE vault_name, ratio, savings_pct, files, packed_at",
        "FROM #liquefy AND #vault",
        "SORT packed_at DESC",
        "```",
        "",
        "## All Vaults",
        "",
        "| Vault | Files | Raw | Compressed | Ratio | Date |",
        "|-------|-------|-----|-----------|-------|------|",
    ]

    for vault_path, index in vaults:
        meta = index.get("metadata", {})
        receipts = index.get("receipts", [])
        raw = sum(r.get("original_bytes", 0) for r in receipts)
        comp = sum(r.get("compressed_bytes", 0) for r in receipts)
        ratio = raw / max(1, comp)
        ts = meta.get("packed_at", "?")
        lines.append(f"| [[{vault_path.name}]] | {len(receipts)} | {_format_bytes(raw)} | {_format_bytes(comp)} | {ratio:.1f}x | {ts} |")

    lines.extend(["", f"*Last updated: {_utc_now()}*", ""])
    return "\n".join(lines)


def cmd_sync(vault_root: Path, obsidian_dir: Path, **_: Any) -> int:
    vaults = _load_all_vaults(vault_root)
    liquefy_dir = obsidian_dir / DEFAULT_OBSIDIAN_SUBDIR
    vaults_dir = liquefy_dir / "Vaults"
    _ensure_dir(vaults_dir)

    written = 0

    for vault_path, index in vaults:
        note = _vault_summary_note(vault_path, index)
        note_path = vaults_dir / f"{vault_path.name}.md"
        note_path.write_text(note, encoding="utf-8")
        written += 1

    index_note = _searchable_index_note(vaults)
    (liquefy_dir / "Vault Index.md").write_text(index_note, encoding="utf-8")
    written += 1

    recap_note = _daily_recap_note(vaults, _today())
    recaps_dir = liquefy_dir / "Recaps"
    _ensure_dir(recaps_dir)
    (recaps_dir / f"Recap {_today()}.md").write_text(recap_note, encoding="utf-8")
    written += 1

    print(f"Synced {written} notes to {liquefy_dir}")
    return 0


def cmd_recap(vault_root: Path, obsidian_dir: Path, **_: Any) -> int:
    vaults = _load_all_vaults(vault_root)
    liquefy_dir = obsidian_dir / DEFAULT_OBSIDIAN_SUBDIR
    recaps_dir = liquefy_dir / "Recaps"
    _ensure_dir(recaps_dir)

    note = _daily_recap_note(vaults, _today())
    path = recaps_dir / f"Recap {_today()}.md"
    path.write_text(note, encoding="utf-8")
    print(f"Recap written to {path}")
    return 0


def cmd_index(vault_root: Path, obsidian_dir: Path, **_: Any) -> int:
    vaults = _load_all_vaults(vault_root)
    liquefy_dir = obsidian_dir / DEFAULT_OBSIDIAN_SUBDIR
    _ensure_dir(liquefy_dir)

    note = _searchable_index_note(vaults)
    path = liquefy_dir / "Vault Index.md"
    path.write_text(note, encoding="utf-8")
    print(f"Index written to {path}")
    return 0


def cmd_link(vault_root: Path, vault_name: str, **_: Any) -> int:
    print(f"obsidian://open?vault=Agent&file=Liquefy/Vaults/{vault_name}")
    return 0


COMMANDS = {
    "sync": cmd_sync,
    "recap": cmd_recap,
    "index": cmd_index,
}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="liquefy-obsidian", description="Liquefy Obsidian Sync + Memory Bridge")
    sub = ap.add_subparsers(dest="command")

    for name in ("sync", "recap", "index"):
        p = sub.add_parser(name)
        p.add_argument("--vault-root", required=True, help="Liquefy vault root directory")
        p.add_argument("--obsidian", required=True, help="Obsidian vault root directory")

    p_link = sub.add_parser("link")
    p_link.add_argument("--vault-root", required=True)
    p_link.add_argument("--name", required=True, help="Vault name to generate link for")

    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help()
        return 1

    if args.command == "link":
        return cmd_link(Path(args.vault_root), args.name)

    vault_root = Path(args.vault_root).expanduser().resolve()
    obsidian_dir = Path(args.obsidian).expanduser().resolve()
    handler = COMMANDS[args.command]
    return handler(vault_root, obsidian_dir)


if __name__ == "__main__":
    raise SystemExit(main())
