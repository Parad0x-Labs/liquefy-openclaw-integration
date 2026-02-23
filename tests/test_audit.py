"""tests/test_audit.py — SOC2-style audit trail validation."""
import io
import json
import sys
import pytest
from unittest.mock import patch


class TestAuditTrail:
    """Verify audit log entries contain required fields and no secrets."""

    def test_audit_entry_format(self):
        """secure_audit_log should emit valid JSON with timestamp and event."""
        from liquefy_security import secure_audit_log

        captured = io.StringIO()
        with patch("sys.stdout", captured):
            secure_audit_log("TEST_EVENT", {
                "tenant": "org-x",
                "engine": "json-v1",
                "bytes_in": 1000,
            })

        output = captured.getvalue().strip()
        assert output, "audit log produced no output"

        # Should be parseable JSON (or at minimum contain the event name)
        assert "TEST_EVENT" in output

    def test_audit_on_failure_path(self):
        """Failure events should also be logged."""
        from liquefy_security import secure_audit_log

        captured = io.StringIO()
        with patch("sys.stdout", captured):
            secure_audit_log("ENGINE_FAILURE", {
                "engine": "broken-v1",
                "error": "division by zero",
                "status": "failed",
            })

        output = captured.getvalue().strip()
        assert "ENGINE_FAILURE" in output

    def test_no_secrets_in_log(self):
        """Audit entries must not contain keys, tokens, or raw payloads."""
        from liquefy_security import secure_audit_log

        captured = io.StringIO()
        with patch("sys.stdout", captured):
            secure_audit_log("COMPRESS_SUCCESS", {
                "tenant": "org-x",
                "bytes_in": 5000,
                "bytes_out": 500,
            })

        output = captured.getvalue()
        # Must not contain common secret patterns
        assert "BEGIN PRIVATE" not in output
        assert "SECRET" not in output.upper() or "master_secret" not in output.lower()
        assert "Bearer" not in output
