#!/usr/bin/env python3
"""Safety tests for VPC Flow ratio-mode candidate selection."""
from pathlib import Path

import pytest

from orchestrator.engine_map import get_engine_instance


REPO_ROOT = Path(__file__).resolve().parent.parent
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


@pytest.fixture
def vpc_raw():
    return (REPO_ROOT / "tests" / "fixtures" / "golden_inputs" / "vpcflow_canonical_256.log").read_bytes()


@pytest.fixture
def vpc_custom_raw():
    return (REPO_ROOT / "tests" / "fixtures" / "vpcflow" / "vpcflow_custom_order_64.log").read_bytes()


def test_ratio_mode_choose_smaller_when_columnar_attempted(monkeypatch, vpc_raw):
    monkeypatch.setenv("LIQUEFY_PROFILE", "ratio")
    engine = get_engine_instance("liquefy-vpcflow-v1")
    assert engine is not None

    # Force the candidate path to run so we can assert the choose-smaller rule.
    monkeypatch.setattr(engine, "_sample_prefers_columnar", lambda raw: True)

    raw_comp = engine.cctx.compress(vpc_raw)
    col_comp = engine._compress_legacy_columnar(vpc_raw)
    assert col_comp is not None

    final = engine.compress(vpc_raw)
    expected = col_comp if len(col_comp) < len(raw_comp) else raw_comp
    assert len(final) == len(expected)
    assert final == expected
    assert engine.decompress(final) == vpc_raw


def test_ratio_mode_precheck_can_skip_columnar_work(monkeypatch, vpc_raw):
    monkeypatch.setenv("LIQUEFY_PROFILE", "ratio")
    engine = get_engine_instance("liquefy-vpcflow-v1")
    assert engine is not None

    monkeypatch.setattr(engine, "_sample_prefers_columnar", lambda raw: False)

    def _boom(_raw):
        raise AssertionError("columnar path should not be called when precheck rejects")

    monkeypatch.setattr(engine, "_compress_legacy_columnar", _boom)
    final = engine.compress(vpc_raw)
    assert final.startswith(ZSTD_MAGIC)
    assert engine.decompress(final) == vpc_raw


def test_ratio_mode_choose_smaller_on_custom_order_fixture(monkeypatch, vpc_custom_raw):
    monkeypatch.setenv("LIQUEFY_DETERMINISTIC", "1")
    monkeypatch.setenv("LIQUEFY_PROFILE", "ratio")
    engine = get_engine_instance("liquefy-vpcflow-v1")
    assert engine is not None

    # Force candidate evaluation on custom-order data; final result must still obey min(raw, columnar).
    monkeypatch.setattr(engine, "_sample_prefers_columnar", lambda raw: True)

    raw_comp = engine.cctx.compress(vpc_custom_raw)
    col_comp = engine._compress_legacy_columnar(vpc_custom_raw)
    assert col_comp is not None

    final = engine.compress(vpc_custom_raw)
    expected = col_comp if len(col_comp) < len(raw_comp) else raw_comp
    assert final == expected
    assert len(final) == len(expected)
    assert engine.decompress(final) == vpc_custom_raw
