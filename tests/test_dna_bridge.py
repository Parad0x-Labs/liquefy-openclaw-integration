"""tests/test_dna_bridge.py — DNA payment bridge guard-event coverage."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


PLUGIN_PATH = Path(__file__).resolve().parent.parent / "plugins" / "dna-payment" / "dna_bridge.py"
SPEC = importlib.util.spec_from_file_location("dna_bridge", PLUGIN_PATH)
dna_bridge = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(dna_bridge)


def test_audit_to_telemetry_maps_guard_receipt_invalid():
    record = dna_bridge.audit_to_telemetry({
        "ts": "2026-03-11T11:00:00Z",
        "kind": "GUARD_RECEIPT_INVALID",
        "traceId": "trace-guard",
        "shopId": "seller-alpha",
        "receiptId": "receipt-123",
        "mint": "USDC",
        "errorCode": "SIG_MISMATCH",
    })

    assert record["event_type"] == "GUARD_RECEIPT_INVALID"
    assert record["severity"] == "error"
    assert record["domain"] == "receipt"
    assert "shop:seller-alpha" in record["tags"]
    assert "mint:USDC" in record["tags"]
    assert "error:SIG_MISMATCH" in record["tags"]


def test_cmd_export_writes_guard_events_into_telemetry(tmp_path, monkeypatch):
    receipt = {
        "payload": {
          "receiptId": "receipt-123",
          "quoteId": "quote-123",
          "commitId": "commit-123",
        },
        "signature": "sig",
    }

    audit_lines = "\n".join([
        json.dumps({
            "ts": "2026-03-11T11:00:00Z",
            "kind": "GUARD_VALIDATION_FAILED",
            "shopId": "seller-alpha",
            "receiptId": "receipt-123",
        }),
        json.dumps({
            "ts": "2026-03-11T11:01:00Z",
            "kind": "PAYMENT_VERIFIED",
            "shopId": "seller-alpha",
        }),
    ])

    monkeypatch.setattr(dna_bridge, "fetch_text", lambda _url: audit_lines)
    monkeypatch.setattr(dna_bridge, "fetch_json", lambda _url: receipt)

    ok = dna_bridge.cmd_export(SimpleNamespace(
        server="https://dna.test",
        out=str(tmp_path),
    ))

    assert ok is True
    telemetry_lines = (tmp_path / "telemetry.jsonl").read_text(encoding="utf-8").strip().splitlines()
    receipts_lines = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))

    assert len(telemetry_lines) == 2
    assert json.loads(telemetry_lines[0])["event_type"] == "GUARD_VALIDATION_FAILED"
    assert len(receipts_lines) == 1
    assert manifest["proof_artifact_count"] == 1
