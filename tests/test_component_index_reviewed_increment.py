"""Independent current-worktree admission controls for the reviewed increment.

The positive runs the directly imported current builder/exporter without source
writes. Negative cases use a newly created private Git fixture with real files,
real index and real untracked enumeration; no capture/admission result is mocked.
Fixture-only commits and origin labels have no network or public repository effect.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from scripts import build_component_index as component_builder

ROOT = Path(component_builder.__file__).resolve().parents[1]
REVIEWED = (
    "src/verifier/domains/contracts/subject_security.py",
    "src/verifier/runtime/polish_requirements.py",
    "src/verifier/standard/CURRENT_SUBJECT_SECURITY.md",
    "src/verifier/standard/POLISH_REQUIREMENTS.md",
)
UNEXPECTED = "src/verifier/unreviewed_fifth_source.py"
FIXED = ("pyproject.toml", "LICENSE", "NOTICE", "README.md")


def _builder():
    assert Path(component_builder.__file__).resolve() == (
        ROOT / "scripts/build_component_index.py").resolve()
    return component_builder


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, timeout=15).stdout


@pytest.fixture(autouse=True)
def isolated_import_search_path(monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "dont_write_bytecode", True)


@pytest.fixture
def real_source_fixture(tmp_path: Path):
    root = tmp_path / "private-source-fixture"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "core.autocrlf", "false")
    # A fixture repository identity label; no fetch, push or remote contact.
    _git(root, "config", "remote.origin.url", "https://github.com/TimeLordRaps/verifier.git")
    hooks = root / "empty-hooks"
    hooks.mkdir()
    _git(root, "config", "core.hooksPath", str(hooks))
    for name in FIXED:
        (root / name).write_bytes((ROOT / name).read_bytes())
    _git(root, "add", "--", *FIXED)
    _git(root, "-c", "user.name=Private Test Fixture",
         "-c", "user.email=fixture" + "@" + "example.invalid",
         "-c", "commit.gpgSign=false", "commit", "--no-gpg-sign", "-m", "Private admission fixture")
    for name in REVIEWED:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    return root


def test_default_real_builder_retains_all_four_reviewed_source_bytes(tmp_path: Path):
    module = _builder()
    output = tmp_path / "components"
    module.build(output, source_ref="WORKTREE")
    from verifier.interoperability.component_index import load_component_index
    from verifier.interoperability.storage import load_component_package
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)
    artifacts = {item.path: item.content for item in package.artifacts}
    archive_bytes = artifacts.get("source-archive/exact-public-source.zip")
    if archive_bytes is None:
        for name in REVIEWED:
            assert artifacts[name] == (ROOT / name).read_bytes()
    else:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            inventory = json.loads(archive.read("source-inventory.json"))
            records = {row["path"]: row for row in inventory["files"]}
            assert set(REVIEWED) <= records.keys()
            for name in REVIEWED:
                expected = (ROOT / name).read_bytes()
                actual = artifacts[name] if records[name]["location"] == "DIRECT" else archive.read(name)
                assert actual == expected
                assert records[name]["sha256"] == hashlib.sha256(expected).hexdigest()
                assert records[name]["size_bytes"] == len(expected)
    assert set(REVIEWED) <= set(module.REVIEWED_CANDIDATE_SOURCE_PATHS)
    assert UNEXPECTED not in module.REVIEWED_CANDIDATE_SOURCE_PATHS
    assert json.loads((output / "deployment-coordinate.json").read_bytes())["source_ref"] == "WORKTREE"


def test_real_capture_accepts_exact_reviewed_untracked_selection(real_source_fixture: Path):
    exporter = _builder()._reference_exporter()
    captured, head, dirty = exporter._capture_snapshot(real_source_fixture, REVIEWED)
    assert set(captured) == set(FIXED) | set(REVIEWED)
    assert head == _git(real_source_fixture, "rev-parse", "HEAD").decode().strip()
    assert dirty is True
    for name, raw in captured.items():
        assert raw == (real_source_fixture / name).read_bytes()


def test_real_capture_refuses_an_omitted_reviewed_file(real_source_fixture: Path):
    exporter = _builder()._reference_exporter()
    with pytest.raises(ValueError, match="untracked public source files require explicit"):
        exporter._capture_snapshot(real_source_fixture, REVIEWED[:-1])


def test_real_capture_refuses_a_real_unexpected_fifth_file(real_source_fixture: Path):
    exporter = _builder()._reference_exporter()
    extra = real_source_fixture / UNEXPECTED
    extra.write_text("# Inert independently introduced negative fixture.\n", encoding="utf-8")
    assert UNEXPECTED.encode() in _git(real_source_fixture, "ls-files", "--others", "--exclude-standard", "-z")
    with pytest.raises(ValueError, match="untracked public source files require explicit"):
        exporter._capture_snapshot(real_source_fixture, REVIEWED)
    assert extra.is_file()


def test_real_default_builder_refuses_fifth_file_before_output(real_source_fixture: Path, tmp_path: Path, monkeypatch):
    module = _builder()
    exporter = module._reference_exporter()
    extra = real_source_fixture / UNEXPECTED
    extra.write_text("# Real private untracked file, never executed.\n", encoding="utf-8")
    monkeypatch.setattr(module, "ROOT", real_source_fixture)
    monkeypatch.setattr(module, "SOURCE", real_source_fixture / "src")
    # Use the actual loaded exporter; _git, _capture_snapshot and build_package
    # are unchanged. Only the source coordinate and loader location differ.
    monkeypatch.setattr(module, "_reference_exporter", lambda: exporter)
    assert set(module._reviewed_untracked_candidate_sources()) == set(REVIEWED)
    output = tmp_path / "refused-components"
    with pytest.raises(ValueError, match="untracked public source files require explicit"):
        module.build(output, source_ref="WORKTREE")
    assert not output.exists()
    assert extra.is_file()
