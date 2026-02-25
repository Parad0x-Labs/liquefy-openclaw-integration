#!/usr/bin/env python3
"""
DNA x402 Payment Bridge for Liquefy

Exports DNA payment audit logs and receipts into a Liquefy-ready directory
structure that can be packed into a .null vault.

Usage:
    python dna_bridge.py export --server http://localhost:8080 --out ./vault-staging/dna
    python dna_bridge.py status --server http://localhost:8080
    python dna_bridge.py archive --server http://localhost:8080 --out ./vault/dna-payments

Environment:
    DNA_SERVER      DNA x402 server URL (default: http://localhost:8080)
    DNA_ADMIN_TOKEN Admin token for authenticated endpoints
    LIQUEFY_ROOT    Path to Liquefy repo root (for auto-pack)
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DNA_SERVER = os.getenv("DNA_SERVER", "http://localhost:8080")
ADMIN_TOKEN = os.getenv("DNA_ADMIN_TOKEN", "")

SEVERITY_MAP = {
    "QUOTE_ISSUED": "info",
    "COMMIT_CREATED": "info",
    "PAYMENT_VERIFIED": "info",
    "PAYMENT_REJECTED": "error",
    "RECEIPT_ISSUED": "info",
    "RECEIPT_ANCHORED": "info",
    "NETTING_FLUSH": "info",
    "WEBHOOK_SENT": "info",
    "WEBHOOK_FAILED": "warn",
    "RATE_LIMITED": "warn",
    "SHOP_REGISTERED": "info",
    "SERVER_STARTED": "info",
}

DOMAIN_MAP = {
    "QUOTE_ISSUED": "payment",
    "COMMIT_CREATED": "payment",
    "PAYMENT_VERIFIED": "payment",
    "PAYMENT_REJECTED": "payment",
    "RECEIPT_ISSUED": "receipt",
    "RECEIPT_ANCHORED": "receipt",
    "NETTING_FLUSH": "payment",
    "SHOP_REGISTERED": "market",
}


def fetch_json(url: str) -> Any:
    headers = {}
    if ADMIN_TOKEN:
        headers["x-admin-token"] = ADMIN_TOKEN
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def fetch_text(url: str) -> str:
    headers = {}
    if ADMIN_TOKEN:
        headers["x-admin-token"] = ADMIN_TOKEN
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def audit_to_telemetry(entry: dict) -> dict:
    kind = entry.get("kind", "unknown")
    tags = [f"kind:{kind}"]
    if entry.get("settlement"):
        tags.append(f"settlement:{entry['settlement']}")
    if entry.get("shopId"):
        tags.append(f"shop:{entry['shopId']}")

    return {
        "_schema": "liquefy.dna.telemetry.v1",
        "_source": "dna-x402",
        "ts": entry.get("ts", ""),
        "event_type": kind,
        "trace_id": entry.get("traceId"),
        "severity": SEVERITY_MAP.get(kind, "info"),
        "domain": DOMAIN_MAP.get(kind, "system"),
        "tags": tags,
        "fields": {k: v for k, v in entry.items() if k not in ("ts", "kind")},
    }


def cmd_status(args):
    server = args.server or DNA_SERVER
    try:
        health = fetch_json(f"{server}/health")
        summary = fetch_json(f"{server}/admin/audit/summary")
        result = {
            "schema_version": "liquefy.dna.bridge.v1",
            "command": "status",
            "ok": True,
            "server": server,
            "health": health,
            "audit_summary": summary,
        }
    except Exception as e:
        result = {
            "schema_version": "liquefy.dna.bridge.v1",
            "command": "status",
            "ok": False,
            "server": server,
            "error": str(e),
        }
    print(json.dumps(result, indent=2))
    return result["ok"]


def cmd_export(args):
    server = args.server or DNA_SERVER
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    proofs_dir = out_dir / "proofs"
    proofs_dir.mkdir(exist_ok=True)

    # Fetch audit logs
    raw = fetch_text(f"{server}/admin/audit/export")
    lines = [l for l in raw.strip().split("\n") if l.strip()]

    event_count = 0
    receipt_ids = set()

    with open(out_dir / "telemetry.jsonl", "w") as f:
        for line in lines:
            try:
                entry = json.loads(line)
                if entry.get("ts") and entry.get("kind"):
                    record = audit_to_telemetry(entry)
                    f.write(json.dumps(record) + "\n")
                    event_count += 1
                    if entry.get("receiptId"):
                        receipt_ids.add(entry["receiptId"])
            except json.JSONDecodeError:
                continue

    # Fetch full receipts
    receipt_count = 0
    with open(out_dir / "receipts.jsonl", "w") as f:
        for rid in receipt_ids:
            try:
                receipt = fetch_json(f"{server}/receipt/{rid}")
                if receipt.get("payload", {}).get("receiptId"):
                    f.write(json.dumps(receipt) + "\n")
                    with open(proofs_dir / f"{rid}.json", "w") as pf:
                        json.dump(receipt, pf, indent=2)
                    receipt_count += 1
            except Exception:
                continue

    # Write manifest
    manifest = {
        "_schema": "liquefy.dna.run.v1",
        "_source": "dna-x402",
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "total_payments": receipt_count,
        "total_receipts": receipt_count,
        "proof_artifact_count": receipt_count,
    }
    with open(out_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    result = {
        "schema_version": "liquefy.dna.bridge.v1",
        "command": "export",
        "ok": True,
        "out_dir": str(out_dir),
        "audit_events": event_count,
        "receipts": receipt_count,
        "proof_artifacts": receipt_count,
        "next_step": f"python tools/tracevault_pack.py {out_dir} --org dna --out ./vault/dna-payments --json",
    }
    print(json.dumps(result, indent=2))
    return True


def cmd_archive(args):
    if not cmd_export(args):
        return False

    liquefy_root = os.getenv("LIQUEFY_ROOT", str(Path(__file__).parent.parent.parent))
    pack_script = Path(liquefy_root) / "tools" / "tracevault_pack.py"

    if not pack_script.exists():
        print(json.dumps({
            "schema_version": "liquefy.dna.bridge.v1",
            "command": "archive",
            "ok": False,
            "error": f"Liquefy pack script not found at {pack_script}. Set LIQUEFY_ROOT.",
        }, indent=2))
        return False

    vault_out = args.vault_out or "./vault/dna-payments"
    cmd = [
        sys.executable, str(pack_script),
        args.out,
        "--org", "dna",
        "--out", vault_out,
        "--json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(json.dumps({
            "schema_version": "liquefy.dna.bridge.v1",
            "command": "archive",
            "ok": True,
            "vault": vault_out,
            "pack_output": json.loads(result.stdout) if result.stdout.strip() else {},
        }, indent=2))
        return True
    else:
        print(json.dumps({
            "schema_version": "liquefy.dna.bridge.v1",
            "command": "archive",
            "ok": False,
            "error": result.stderr[:500],
        }, indent=2))
        return False


def main():
    parser = argparse.ArgumentParser(description="DNA x402 Payment Bridge for Liquefy")
    parser.add_argument("--server", default=DNA_SERVER, help="DNA server URL")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Check DNA server status")

    p_export = sub.add_parser("export", help="Export DNA data to Liquefy-ready dir")
    p_export.add_argument("--out", default="./vault-staging/dna-export", help="Output directory")

    p_archive = sub.add_parser("archive", help="Export + pack into .null vault")
    p_archive.add_argument("--out", default="./vault-staging/dna-export", help="Staging directory")
    p_archive.add_argument("--vault-out", default="./vault/dna-payments", help="Final vault output")

    args = parser.parse_args()

    if args.command == "status":
        sys.exit(0 if cmd_status(args) else 1)
    elif args.command == "export":
        sys.exit(0 if cmd_export(args) else 1)
    elif args.command == "archive":
        sys.exit(0 if cmd_archive(args) else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
