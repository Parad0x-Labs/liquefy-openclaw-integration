"""Tests for liquefy_config_guard.py — config snapshot/restore/diff."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_config_guard import (
    cmd_save,
    cmd_restore,
    cmd_diff,
    cmd_status,
    _file_sha256,
    _is_config_file,
    _collect_files,
    _load_manifest,
    GUARD_DIR,
    SCHEMA,
)


@pytest.fixture
def project_dir(tmp_path):
    """Create a mock project directory with config files."""
    d = tmp_path / "my-agent"
    d.mkdir()
    (d / "config.yaml").write_text("model: gpt-4\ntemp: 0.7\n")
    (d / "config.json").write_text('{"api_url": "https://api.example.com"}')
    (d / ".env").write_text("API_KEY=test123\nDEBUG=true\n")
    (d / "requirements.txt").write_text("langchain==0.1.0\nopenai==1.0\n")
    (d / "Makefile").write_text("run:\n\tpython main.py\n")

    skills = d / "skills"
    skills.mkdir()
    (skills / "custom_skill.py").write_text("def run(): return 'custom'\n")
    (skills / "prompts.yaml").write_text("system: You are a helpful agent\n")

    (d / "main.py").write_text("print('hello')\n")

    (d / "node_modules").mkdir()
    (d / "node_modules" / "junk.json").write_text("{}")

    return d


class _Args:
    """Mock argparse namespace."""
    def __init__(self, **kwargs):
        self.json = False
        self.dir = ""
        self.include = None
        self.label = None
        self.force = False
        self.dry_run = False
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestIsConfigFile:
    def test_yaml(self):
        assert _is_config_file(Path("config.yaml"))

    def test_json(self):
        assert _is_config_file(Path("settings.json"))

    def test_env(self):
        assert _is_config_file(Path(".env"))

    def test_makefile(self):
        assert _is_config_file(Path("Makefile"))

    def test_python(self):
        assert _is_config_file(Path("script.py"))

    def test_binary(self):
        assert not _is_config_file(Path("image.png"))

    def test_compiled(self):
        assert not _is_config_file(Path("output.o"))


class TestCollectFiles:
    def test_collects_configs(self, project_dir):
        files = _collect_files(project_dir)
        names = {f.name for f in files}
        assert "config.yaml" in names
        assert "config.json" in names
        assert ".env" in names
        assert "requirements.txt" in names
        assert "Makefile" in names

    def test_skips_node_modules(self, project_dir):
        files = _collect_files(project_dir)
        for f in files:
            rel = str(f.relative_to(project_dir))
            assert not rel.startswith("node_modules")

    def test_includes_nested(self, project_dir):
        files = _collect_files(project_dir)
        names = {f.name for f in files}
        assert "custom_skill.py" in names
        assert "prompts.yaml" in names

    def test_pattern_filter(self, project_dir):
        files = _collect_files(project_dir, patterns=["*.yaml"])
        names = {f.name for f in files}
        assert "config.yaml" in names
        assert "prompts.yaml" in names
        assert "config.json" not in names


class TestSaveAndRestore:
    def test_save_creates_snapshot(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        ret = cmd_save(args)
        assert ret == 0
        assert (project_dir / GUARD_DIR / "manifest.json").exists()
        assert (project_dir / GUARD_DIR / "snapshot" / "config.yaml").exists()

    def test_save_manifest_schema(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        manifest = _load_manifest(project_dir)
        assert manifest["schema"] == SCHEMA
        assert manifest["file_count"] > 0
        assert manifest["total_bytes"] > 0

    def test_save_with_label(self, project_dir):
        args = _Args(dir=str(project_dir), json=True, label="pre-v2.0")
        cmd_save(args)
        manifest = _load_manifest(project_dir)
        assert manifest["label"] == "pre-v2.0"

    def test_restore_after_overwrite(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)

        original = (project_dir / "config.yaml").read_text()
        (project_dir / "config.yaml").write_text("model: gpt-5\ntemp: 0.1\n")

        ret = cmd_restore(args)
        assert ret == 0
        assert (project_dir / "config.yaml").read_text() == original

    def test_restore_after_deletion(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)

        original = (project_dir / ".env").read_text()
        (project_dir / ".env").unlink()

        ret = cmd_restore(args)
        assert ret == 0
        assert (project_dir / ".env").exists()
        assert (project_dir / ".env").read_text() == original

    def test_restore_skips_unchanged(self, project_dir, capsys):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        capsys.readouterr()  # clear save output
        ret = cmd_restore(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["skipped"] > 0
        assert output["restored"] == 0

    def test_restore_dry_run(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)

        (project_dir / "config.yaml").write_text("OVERWRITTEN")

        args_dry = _Args(dir=str(project_dir), json=True, dry_run=True)
        ret = cmd_restore(args_dry)
        assert ret == 0
        assert (project_dir / "config.yaml").read_text() == "OVERWRITTEN"

    def test_restore_creates_backup_on_conflict(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)

        (project_dir / "config.yaml").write_text("CONFLICTING CHANGE")

        ret = cmd_restore(args)
        assert ret == 0
        assert (project_dir / "config.yaml.update-backup").exists()
        assert (project_dir / "config.yaml.update-backup").read_text() == "CONFLICTING CHANGE"

    def test_restore_no_snapshot(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        args = _Args(dir=str(empty), json=True)
        ret = cmd_restore(args)
        assert ret == 1


class TestDiff:
    def test_diff_no_changes(self, project_dir, capsys):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        capsys.readouterr()
        ret = cmd_diff(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["changed"] == 0
        assert output["deleted"] == 0

    def test_diff_detects_modification(self, project_dir, capsys):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        capsys.readouterr()

        (project_dir / "config.yaml").write_text("model: gpt-5\n")

        ret = cmd_diff(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["changed"] == 1
        assert any(f["file"] == "config.yaml" for f in output["changed_files"])

    def test_diff_detects_deletion(self, project_dir, capsys):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        capsys.readouterr()

        (project_dir / ".env").unlink()

        ret = cmd_diff(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["deleted"] == 1
        assert ".env" in output["deleted_files"]

    def test_diff_no_snapshot(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        args = _Args(dir=str(empty), json=True)
        ret = cmd_diff(args)
        assert ret == 1


class TestStatus:
    def test_status_all_unchanged(self, project_dir, capsys):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        capsys.readouterr()
        ret = cmd_status(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["modified"] == 0
        assert output["deleted"] == 0
        assert output["unchanged"] > 0

    def test_status_shows_modified(self, project_dir, capsys):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        capsys.readouterr()

        (project_dir / "config.yaml").write_text("CHANGED")
        (project_dir / ".env").unlink()

        ret = cmd_status(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["modified"] == 1
        assert output["deleted"] == 1
        assert output["files"]["config.yaml"] == "modified"
        assert output["files"][".env"] == "deleted"


class TestEdgeCases:
    def test_save_empty_dir(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        args = _Args(dir=str(empty), json=True)
        ret = cmd_save(args)
        assert ret == 1

    def test_save_nonexistent_dir(self, tmp_path):
        args = _Args(dir=str(tmp_path / "nope"), json=True)
        ret = cmd_save(args)
        assert ret == 1

    def test_double_save_overwrites(self, project_dir):
        args = _Args(dir=str(project_dir), json=True)
        cmd_save(args)
        m1 = _load_manifest(project_dir)

        (project_dir / "config.yaml").write_text("UPDATED")
        cmd_save(args)
        m2 = _load_manifest(project_dir)

        assert m1["files"]["config.yaml"]["sha256"] != m2["files"]["config.yaml"]["sha256"]

    def test_file_sha256_deterministic(self, project_dir):
        f = project_dir / "config.yaml"
        h1 = _file_sha256(f)
        h2 = _file_sha256(f)
        assert h1 == h2
        assert len(h1) == 64
