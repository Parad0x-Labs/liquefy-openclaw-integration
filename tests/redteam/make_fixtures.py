#!/usr/bin/env python3
"""Generate hostile test fixtures for red-team suite."""
from pathlib import Path
import os, json, shutil

root = Path(os.environ.get("RT_ROOT", "tests/redteam/tmp")).resolve()
if root.exists():
    shutil.rmtree(root)
root.mkdir(parents=True, exist_ok=True)

src = root / "src"
(src / "base").mkdir(parents=True)
(src / "dupes_a").mkdir()
(src / "dupes_b").mkdir()
(src / "secrets").mkdir()
(src / "benign").mkdir()

(src / "base" / "notes.txt").write_text("agent run ok\nstep=1\nstep=2\n")
(src / "base" / "trace.jsonl").write_text(
    '{"tool":"grep","ok":true}\n{"tool":"curl","ok":false,"error":"timeout"}\n'
)

dup = b"A" * 4096 + b"same-payload" + b"B" * 4096
(src / "dupes_a" / "same.bin").write_bytes(dup)
(src / "dupes_b" / "same.bin").write_bytes(dup)

near = bytearray(dup)
near[-1] ^= 1
(src / "dupes_b" / "one_bit_off.bin").write_bytes(bytes(near))

(src / "secrets" / "leaked.env").write_text(
    "OPENAI_API_KEY=sk-test-abcdef1234567890abcdef12\n"
    "AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n"
)
(src / "secrets" / "jwt.txt").write_text(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
)

for i in range(50):
    (src / "benign" / f"doc_{i}.txt").write_text(
        f"document {i}\nhash={i:064x}\nuuid=123e4567-e89b-12d3-a456-426614174000\n"
    )

manifest = {"root": str(root), "src": str(src)}
(root / "fixture_manifest.json").write_text(json.dumps(manifest, indent=2))
print(f"Fixtures created at {root}")
