#!/usr/bin/env python3
"""
tracevault_search.py
====================
Search TraceVault archives without restoring the full dataset to disk.

Usage:
    python tools/tracevault_search.py ./vault/run_001 --query "HTTP/1.1"
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Reuse robust local decode logic from restore tool.
from tracevault_restore import local_decode_receipt


def _iter_searchable_units(index: Dict) -> Iterable[Tuple[str, List[Dict], bool]]:
    # Normal files: one receipt per logical file.
    for receipt in index.get("receipts", []):
        rel = receipt.get("run_relpath")
        if not rel:
            out = receipt.get("output_path", "")
            rel = Path(out).name if out else "unknown"
        yield rel, [receipt], False

    # Chunked files: decode/search each chunk in order without building full file.
    for group in index.get("bigfile_groups", []):
        rel = group.get("run_relpath") or "unknown"
        parts = sorted(group.get("parts", []), key=lambda p: int(p.get("chunk_index", 0)))
        if parts:
            yield rel, parts, True


def _decode_receipt_payload(receipt: Dict) -> Optional[bytes]:
    output_path = receipt.get("output_path")
    if not output_path:
        return None
    archive_path = Path(output_path)
    if not archive_path.exists():
        return None
    return local_decode_receipt(archive_path, receipt)


def _line_matches(
    line: str,
    query: str,
    *,
    regex: Optional[re.Pattern],
    ignore_case: bool,
) -> bool:
    if regex is not None:
        return bool(regex.search(line))
    if ignore_case:
        return query.lower() in line.lower()
    return query in line


def search_vault(
    vault_dir: Path,
    query: str,
    *,
    limit: int,
    ignore_case: bool,
    regex_mode: bool,
    quiet: bool,
    json_mode: bool,
) -> int:
    index_path = vault_dir / "tracevault_index.json"
    if not index_path.exists():
        print(f"Missing index: {index_path}", file=sys.stderr)
        return 2

    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to parse index: {exc}", file=sys.stderr)
        return 2

    regex = None
    if regex_mode:
        flags = re.IGNORECASE if ignore_case else 0
        try:
            regex = re.compile(query, flags)
        except re.error as exc:
            print(f"Invalid regex: {exc}", file=sys.stderr)
            return 2

    matches: List[Dict] = []
    files_scanned = 0

    for rel, parts, _is_chunked in _iter_searchable_units(index):
        files_scanned += 1
        line_no = 0
        matched_in_file = 0

        for receipt in parts:
            payload = _decode_receipt_payload(receipt)
            if payload is None:
                continue

            text = payload.decode("utf-8", errors="replace")
            for line in text.splitlines():
                line_no += 1
                if not _line_matches(line, query, regex=regex, ignore_case=ignore_case):
                    continue

                matched_in_file += 1
                if len(matches) < limit:
                    matches.append({
                        "file": rel,
                        "line": line_no,
                        "text": line,
                    })
                if len(matches) >= limit:
                    break
            if len(matches) >= limit:
                break
        if len(matches) >= limit:
            break
        if matched_in_file and not quiet and not json_mode:
            print(f"[MATCH] {rel}: {matched_in_file} hit(s)")

    result = {
        "ok": True,
        "query": query,
        "limit": limit,
        "files_scanned": files_scanned,
        "matches": matches,
        "match_count": len(matches),
    }

    if json_mode:
        print(json.dumps(result, ensure_ascii=True))
    elif not quiet:
        for m in matches:
            print(f"{m['file']}:{m['line']}: {m['text']}")
        print(f"\n[RESULT] {len(matches)} match(es) across {files_scanned} file(s)")

    return 0 if len(matches) > 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Search TraceVault archives without full restore.")
    parser.add_argument("vault_dir", help="Path to vault directory containing tracevault_index.json")
    parser.add_argument("--query", required=True, help="Search token or regex pattern")
    parser.add_argument("--limit", type=int, default=20, help="Maximum matches to output")
    parser.add_argument("--ignore-case", action="store_true", help="Case-insensitive search")
    parser.add_argument("--regex", action="store_true", help="Treat query as regex")
    parser.add_argument("--quiet", action="store_true", help="Suppress human-readable match output")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    args = parser.parse_args()

    code = search_vault(
        vault_dir=Path(args.vault_dir).resolve(),
        query=args.query,
        limit=max(1, args.limit),
        ignore_case=args.ignore_case,
        regex_mode=args.regex,
        quiet=args.quiet,
        json_mode=args.json,
    )
    raise SystemExit(code)


if __name__ == "__main__":
    main()
