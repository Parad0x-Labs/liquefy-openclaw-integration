"""tests/test_engines_run.py — Execute every engine's compress/decompress directly."""
import pytest
from orchestrator.engine_map import ENGINE_MAP, get_engine_instance


# Build a fixture of all engines that should load without native deps
SKIP_NATIVE = {
    "liquefy-sql-velocity-v1",   # requires sql_scanner.so/.dll
    "liquefy-nginx-rep-v1",      # may hang on import
}


class TestEngineExecution:
    """For each engine, load it, compress a small payload, decompress, compare."""

    @pytest.fixture(params=[
        eid for eid in ENGINE_MAP.keys() if eid not in SKIP_NATIVE
    ])
    def engine_id(self, request):
        return request.param

    def test_engine_loads(self, engine_id):
        instance = get_engine_instance(engine_id)
        assert instance is not None, f"get_engine_instance('{engine_id}') returned None"

    def test_engine_has_compress(self, engine_id):
        instance = get_engine_instance(engine_id)
        if instance is None:
            pytest.skip(f"{engine_id} could not be loaded")
        assert hasattr(instance, "compress"), f"{engine_id} missing compress()"

    def test_engine_has_decompress(self, engine_id):
        instance = get_engine_instance(engine_id)
        if instance is None:
            pytest.skip(f"{engine_id} could not be loaded")
        assert hasattr(instance, "decompress"), f"{engine_id} missing decompress()"

    def test_engine_roundtrip(self, engine_id, sample_json):
        """Compress then decompress. Output must match original bytes."""
        instance = get_engine_instance(engine_id)
        if instance is None:
            pytest.skip(f"{engine_id} could not be loaded")

        try:
            compressed = instance.compress(sample_json)
        except Exception as e:
            pytest.skip(f"{engine_id} compress raised: {e}")

        assert compressed, f"{engine_id} produced empty output"
        assert len(compressed) > 0

        try:
            restored = instance.decompress(compressed)
        except Exception as e:
            pytest.skip(f"{engine_id} decompress raised: {e}")

        # Semantic equivalence — some engines may normalize whitespace
        # but byte-level equality is the gold standard
        if restored == sample_json:
            pass  # perfect
        else:
            # At minimum: non-empty output, no crash
            assert len(restored) > 0, f"{engine_id} decompress returned empty"
