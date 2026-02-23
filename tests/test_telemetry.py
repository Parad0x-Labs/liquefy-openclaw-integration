"""tests/test_telemetry.py — Observability metrics validation."""
import pytest


class TestTelemetry:
    """Verify telemetry counters update correctly and do not leak secrets."""

    def test_track_op_updates_counters(self, vision_instance):
        """After tracking an op, counters should reflect it."""
        vision_instance.track_op(
            engine_id="json-v1",
            tenant_id="test-org",
            bytes_in=10000,
            bytes_out=500,
            duration_ms=12.5,
            success=True,
        )

        stats = vision_instance.get_stats()
        assert stats["kpis"]["total_ops"] >= 1
        assert stats["kpis"]["compression_ratio"] > 1.0

    def test_engine_usage_tracked(self, vision_instance):
        """Engine usage map should contain the engine we just used."""
        vision_instance.track_op(
            engine_id="apache-v1",
            tenant_id="test-org",
            bytes_in=5000,
            bytes_out=250,
            duration_ms=8.0,
        )

        stats = vision_instance.get_stats()
        assert "apache-v1" in stats["usage"]["engines"]

    def test_tenant_usage_tracked(self, vision_instance):
        """Tenant usage map should show per-tenant byte counts."""
        vision_instance.track_op(
            engine_id="k8s-v1",
            tenant_id="acme-corp",
            bytes_in=20000,
            bytes_out=1000,
            duration_ms=15.0,
        )

        stats = vision_instance.get_stats()
        assert "acme-corp" in stats["usage"]["tenants"]
        assert stats["usage"]["tenants"]["acme-corp"]["bytes_in"] >= 20000

    def test_error_rate_tracked(self, vision_instance):
        """Failed ops should increment the error counter."""
        vision_instance.track_op(
            engine_id="broken-v1",
            tenant_id="test-org",
            bytes_in=1000,
            bytes_out=0,
            duration_ms=1.0,
            success=False,
        )

        stats = vision_instance.get_stats()
        assert stats["kpis"]["error_rate"] > 0

    def test_no_secrets_in_stats(self, vision_instance):
        """Telemetry output must not contain keys, tokens, or raw data."""
        vision_instance.track_op(
            engine_id="json-v1",
            tenant_id="secret-org",
            bytes_in=100,
            bytes_out=50,
            duration_ms=5.0,
        )

        import json
        stats_json = json.dumps(vision_instance.get_stats())
        assert "master_secret" not in stats_json
        assert "Bearer" not in stats_json
        assert "password" not in stats_json.lower()

    def test_savings_calculation(self, vision_instance):
        """Data savings in GB should be non-negative."""
        vision_instance.track_op(
            engine_id="json-v1",
            tenant_id="test-org",
            bytes_in=1024 * 1024 * 100,  # 100 MB
            bytes_out=1024 * 1024,        # 1 MB
            duration_ms=500.0,
        )

        stats = vision_instance.get_stats()
        assert stats["kpis"]["data_reduced_gb"] > 0
