"""Test-first contract for an exact, non-discovering materialized-member adapter."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from scripts import exact_materialized_member, exact_source_scope


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
READER_PATH = SCRIPTS / "exact_source_scope.py"
ADAPTER_PATH = SCRIPTS / "exact_materialized_member.py"
FROZEN_READER_SHA256 = "0304ca0eaf2f0dda052b205cf724fb22e7be959b1e1190c58c68733c06e6659b"
FROZEN_READER_TEST_SHA256 = "01ca1cd358f6cc9d8ec6600efa042623fd9d64719d0764d09c456da3915858ac"
SOURCE_COORDINATE = "ab" * 32


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def modules(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, ModuleType]:
    assert _sha256(READER_PATH) == FROZEN_READER_SHA256
    assert _sha256(ROOT / "tests/test_exact_source_scope.py") == FROZEN_READER_TEST_SHA256
    reader = exact_source_scope
    assert ADAPTER_PATH.is_file(), (
        "EXACT_MATERIALIZED_MEMBER_ADAPTER_MISSING: preserve this pre-edit RED "
        "before adding scripts/exact_materialized_member.py"
    )
    adapter = exact_materialized_member

    def synthetic_unanchored_opener(root: Path, parts: tuple[str, ...]) -> int:
        """Explicit test capability; it confers no production/platform credit."""

        target = root.joinpath(*parts)
        flags = adapter.os.O_RDONLY | getattr(adapter.os, "O_BINARY", 0)
        return adapter.os.open(target, flags)

    monkeypatch.setattr(adapter, "_open_anchored_member", synthetic_unanchored_opener)
    return reader, adapter


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def _manifest(path: str, payload: bytes) -> bytes:
    return _canonical(
        {
            "schema_version": "verifier-selected-source-scope-1",
            "candidate_status": "CANDIDATE",
            "completeness": "UNKNOWN",
            "release_admissible": False,
            "source_coordinate": SOURCE_COORDINATE,
            "members": [
                {
                    "path": path,
                    "role": "SOURCE",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            ],
        }
    )


def _load_scope(reader: ModuleType, callback: Any, path: str, payload: bytes) -> Any:
    raw = _manifest(path, payload)
    return reader.load_selected_source_scope(
        manifest_bytes=raw,
        expected_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        expected_source_coordinate=SOURCE_COORDINATE,
        read_member=callback,
        max_member_bytes=1024,
        max_total_bytes=2048,
    )


def _adapter_error(adapter: ModuleType, code: str, action: Any) -> None:
    with pytest.raises(adapter.MaterializedMemberError) as captured:
        action()
    assert captured.value.code == code


def test_exact_validated_member_is_the_only_opened_path(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader, adapter = modules
    root = tmp_path / "root"
    admitted = root / "allowed" / "a.txt"
    unlisted = root / "unlisted" / "secret.txt"
    admitted.parent.mkdir(parents=True)
    unlisted.parent.mkdir(parents=True)
    admitted.write_bytes(b"admitted\n")
    unlisted.write_bytes(b"must not be opened\n")
    actual_open = adapter.os.open
    opened: list[Path] = []

    def observed_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        opened.append(Path(path))
        return actual_open(path, flags, *args, **kwargs)

    def forbidden_discovery(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("materialized adapter attempted discovery")

    with monkeypatch.context() as isolated:
        isolated.setattr(adapter.os, "open", observed_open)
        isolated.setattr(adapter.os, "walk", forbidden_discovery)
        isolated.setattr(adapter.os, "scandir", forbidden_discovery)
        isolated.setattr(subprocess, "run", forbidden_discovery)
        isolated.setattr(subprocess, "check_output", forbidden_discovery)
        isolated.setattr(Path, "glob", forbidden_discovery)
        isolated.setattr(Path, "rglob", forbidden_discovery)
        isolated.setattr(Path, "iterdir", forbidden_discovery)
        callback = adapter.exact_materialized_member_reader(root, max_member_bytes=1024)
        scope = _load_scope(reader, callback, "allowed/a.txt", b"admitted\n")

    assert opened == [admitted]
    assert unlisted not in opened
    assert scope.member_paths == ("allowed/a.txt",)
    assert scope.completeness == "UNKNOWN"
    assert scope.release_admissible is False


@pytest.mark.parametrize(
    "path",
    ("bad-\ud800.txt", "cafe\u0301.txt"),
    ids=("unpaired-surrogate", "non-nfc"),
)
def test_nonportable_unicode_member_path_is_refused_before_filesystem_io(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("nonportable member path reached filesystem inspection")

    monkeypatch.setattr(adapter, "_inspect_parent_chain", forbidden)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "MEMBER_PATH_INVALID", lambda: callback(path))


@pytest.mark.parametrize("position", ("ROOT", "PARENT"))
def test_root_or_parent_reparse_is_rejected_before_open(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    position: str,
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    target = root / "parent" / "a.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x")
    selected = root if position == "ROOT" else target.parent
    actual_lstat = adapter.os.lstat
    opened: list[Any] = []

    def marked_lstat(path: Any) -> Any:
        observed = actual_lstat(path)
        if Path(path) != selected:
            return observed
        values = {name: getattr(observed, name) for name in dir(observed) if name.startswith("st_")}
        values["st_file_attributes"] = values.get("st_file_attributes", 0) | 0x400
        return SimpleNamespace(**values)

    monkeypatch.setattr(adapter.os, "lstat", marked_lstat)
    monkeypatch.setattr(adapter.os, "open", lambda *args, **kwargs: opened.append(args) or -1)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "PATH_COMPONENT_LINK", lambda: callback("parent/a.txt"))
    assert opened == []


@pytest.mark.parametrize("kind", ("LINK", "REPARSE"))
def test_leaf_link_or_reparse_is_rejected(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    target = root / "a.txt"
    target.write_bytes(b"x")
    actual_lstat = adapter.os.lstat

    def marked_lstat(path: Any) -> Any:
        observed = actual_lstat(path)
        if Path(path) != target:
            return observed
        values = {name: getattr(observed, name) for name in dir(observed) if name.startswith("st_")}
        if kind == "LINK":
            values["st_mode"] = stat.S_IFLNK | 0o777
        else:
            values["st_file_attributes"] = values.get("st_file_attributes", 0) | 0x400
        return SimpleNamespace(**values)

    monkeypatch.setattr(adapter.os, "lstat", marked_lstat)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "TARGET_LINK", lambda: callback("a.txt"))


def test_file_substitution_between_lstat_and_open_is_rejected(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    target = root / "a.txt"
    replacement = root / "replacement.txt"
    target.write_bytes(b"first")
    replacement.write_bytes(b"other")
    actual_open = adapter.os.open
    replaced = False

    def replacing_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal replaced
        if not replaced and Path(path) == target:
            os.replace(replacement, target)
            replaced = True
        return actual_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(adapter.os, "open", replacing_open)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "MEMBER_IDENTITY_CHANGED", lambda: callback("a.txt"))
    assert replaced


def test_directory_target_is_rejected(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    (root / "directory").mkdir(parents=True)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "TARGET_NOT_REGULAR", lambda: callback("directory"))


def test_adapter_size_limit_rejects_before_open(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"12345")
    opened: list[Any] = []
    monkeypatch.setattr(adapter.os, "open", lambda *args, **kwargs: opened.append(args) or -1)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=4)
    _adapter_error(adapter, "MEMBER_SIZE_LIMIT", lambda: callback("a.txt"))
    assert opened == []


def test_truncated_read_is_rejected(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"12345")
    monkeypatch.setattr(adapter.os, "read", lambda descriptor, size: b"")
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "MEMBER_TRUNCATED_READ", lambda: callback("a.txt"))


def test_changed_bytes_reach_reader_digest_rejection(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"original")
    actual_read = adapter.os.read
    changed = False

    def changing_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        raw = actual_read(descriptor, size)
        if raw and not changed:
            changed = True
            return bytes([raw[0] ^ 1]) + raw[1:]
        return raw

    monkeypatch.setattr(adapter.os, "read", changing_read)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    with pytest.raises(reader.ScopeInputError) as captured:
        _load_scope(reader, callback, "a.txt", b"original")
    assert captured.value.code == "MEMBER_DIGEST_MISMATCH"
    assert changed


def test_metadata_change_during_read_is_rejected_for_the_right_reason(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"stable")
    actual_fstat = adapter.os.fstat
    calls = 0

    def changed_fstat(descriptor: int) -> Any:
        nonlocal calls
        calls += 1
        observed = actual_fstat(descriptor)
        if calls == 1:
            return observed
        values = {name: getattr(observed, name) for name in dir(observed) if name.startswith("st_")}
        values["st_mtime_ns"] = values.get("st_mtime_ns", 0) + 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(adapter.os, "fstat", changed_fstat)
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "MEMBER_CHANGED_DURING_READ", lambda: callback("a.txt"))


def test_missing_target_is_rejected(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=16)
    _adapter_error(adapter, "MEMBER_MISSING", lambda: callback("missing.txt"))

