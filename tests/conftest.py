"""tests/conftest.py — Shared fixtures for the Liquefy test suite."""
import sys
import os
import pytest
from pathlib import Path

# Add api/ to sys.path for engine imports
API_DIR = str(Path(__file__).resolve().parent.parent / "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tools" / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def sample_json():
    return (FIXTURES_DIR / "sample.json").read_bytes()


@pytest.fixture
def apache_log():
    return (FIXTURES_DIR / "apache.log").read_bytes()


@pytest.fixture
def k8s_log():
    return (FIXTURES_DIR / "k8s.log").read_bytes()


@pytest.fixture
def sql_dump():
    return (FIXTURES_DIR / "dump.sql").read_bytes()


@pytest.fixture
def raw_text():
    return (FIXTURES_DIR / "raw.txt").read_bytes()


@pytest.fixture
def security_instance():
    from liquefy_security import LiquefySecurity
    return LiquefySecurity(master_secret="test_secret_key_for_ci")


@pytest.fixture
def safety_valve():
    from liquefy_safety import Valve
    return Valve


@pytest.fixture
def vision_instance():
    from liquefy_observability import LiquefyObservability
    return LiquefyObservability()
