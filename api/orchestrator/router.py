#!/usr/bin/env python3
"""
Liquefy Router -- Manifest-Driven File Routing
==============================================
Matches incoming files to the best engine using:
  1. File extension matching (case-insensitive)
  2. MIME type matching (with wildcard support: image/*)
  3. Content sniffing for ambiguous extensions (.log, .txt)
Deterministic tie-breaking by engine ID.
"""

import re
import mimetypes
from pathlib import Path
from typing import Optional, List, Tuple
from orchestrator.contracts import EngineManifest

SNIFF_BYTES = 16384  # Read first 16 KB for content sniffing


def _mime_matches(pattern: str, actual: str) -> bool:
    """Check if a MIME pattern matches an actual type. Supports wildcards like image/*."""
    if not actual:
        return False
    if pattern.endswith("/*"):
        return actual.startswith(pattern[:-1])  # "image/" prefix
    return pattern == actual


def _sniff_score(manifest: EngineManifest, head: str) -> int:
    """Score a manifest's sniff rules against file content. Higher = better match."""
    sniff = manifest.sniff
    if sniff is None:
        return 0

    score = 0

    # contains_all: every string must be present (strong signal)
    if sniff.contains_all:
        if all(s in head for s in sniff.contains_all):
            score += 100
        else:
            return -1  # Hard disqualify if contains_all fails

    # contains_any: at least one string present
    if sniff.contains_any:
        hits = sum(1 for s in sniff.contains_any if s in head)
        if hits > 0:
            score += 10 * hits

    # regex_any: at least one pattern matches
    if sniff.regex_any:
        for pattern in sniff.regex_any:
            try:
                if re.search(pattern, head, re.MULTILINE):
                    score += 50
                    break
            except re.error:
                pass

    return score


def select_engine(
    registry: List[Tuple[EngineManifest, Path]],
    filepath: str,
) -> Optional[EngineManifest]:
    """
    Selects the best engine for a given file.
    Registry is pre-sorted by priority DESC.

    When multiple engines match the same extension, content sniffing
    disambiguates (e.g. Apache vs K8s vs Syslog for .log files).
    """
    ext = Path(filepath).suffix.lower()
    mime, _ = mimetypes.guess_type(filepath)
    mime = (mime or "").lower()

    # Collect matches separately to avoid MIME overreach when extension is explicit.
    ext_matches: List[EngineManifest] = []
    mime_matches: List[EngineManifest] = []

    for manifest, _path in registry:
        caps = manifest.capabilities

        # Check extension match
        if ext and ext in [e.lower() for e in caps.extensions]:
            ext_matches.append(manifest)

        # Check MIME match
        for pat in caps.mimetypes:
            if _mime_matches(pat.lower(), mime):
                mime_matches.append(manifest)
                break

    # Prefer extension matches when extension is known.
    matches = ext_matches if ext_matches else mime_matches

    if not matches:
        return None

    # If only one match, return it directly
    if len(matches) == 1:
        return matches[0]

    # Multiple matches: sniff content to disambiguate
    has_sniff = any(m.sniff is not None for m in matches)
    if has_sniff:
        try:
            with open(filepath, "rb") as f:
                raw = f.read(SNIFF_BYTES)
            head = raw.decode("utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            head = ""

        scored = []
        disqualified_ids = set()
        for m in matches:
            s = _sniff_score(m, head)
            if s < 0:  # -1 means disqualified
                disqualified_ids.add(m.id)
                continue
            scored.append((s, m))

        if scored:
            # Require positive sniff evidence before selecting sniff-driven engines.
            positive = [(s, m) for s, m in scored if s > 0]
            if positive:
                positive.sort(key=lambda t: (-t[0], -t[1].priority, t[1].id))
                return positive[0][1]

            # No positive evidence: prefer generic (non-sniff) engines if available.
            non_sniff = [m for m in matches if m.sniff is None and m.id not in disqualified_ids]
            if non_sniff:
                non_sniff.sort(key=lambda m: (-m.priority, m.id))
                return non_sniff[0]

            # If all candidates are sniff-based and none matched positively,
            # keep deterministic priority fallback among non-disqualified engines.
            remaining = [m for m in matches if m.id not in disqualified_ids]
            if remaining:
                remaining.sort(key=lambda m: (-m.priority, m.id))
                return remaining[0]

    # Fallback: highest priority, alphabetical tie-break
    matches.sort(key=lambda m: (-m.priority, m.id))
    return matches[0]
