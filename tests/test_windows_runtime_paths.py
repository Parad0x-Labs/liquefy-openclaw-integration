from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from skills.liquefy_archive import trigger as archive_trigger
from tools import liquefy_archiver


def test_archiver_runtime_defaults_use_platform_temp_dir():
    expected = Path(tempfile.gettempdir())
    assert liquefy_archiver._default_runtime_file("liquefy_archiver.pid").parent == expected
    assert archive_trigger._default_runtime_file("liquefy_archiver.pid").parent == expected


def test_archiver_runtime_defaults_are_not_posix_tmp_on_windows():
    if os.name != "nt":
        pytest.skip("Windows-specific path assertion")
    assert not str(liquefy_archiver.PID_FILE).startswith("/tmp/")
    assert not str(archive_trigger.PID_FILE).startswith("/tmp/")
