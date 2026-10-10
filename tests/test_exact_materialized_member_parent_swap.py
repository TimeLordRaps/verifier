"""Regression for parent substitution before an unanchored member open."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _metadata(*, mode: int, device: int, inode: int, size: int = 0) -> Any:
    return SimpleNamespace(
        st_mode=mode,
        st_dev=device,
        st_ino=inode,
        st_size=size,
        st_mtime_ns=10,
        st_ctime_ns=20,
        st_file_attributes=0,
    )


def test_parent_substitution_is_refused_before_open_or_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _load("exact_source_scope", SCRIPTS / "exact_source_scope.py")
    adapter = _load(
        "exact_materialized_member_parent_swap_candidate",
        SCRIPTS / "exact_materialized_member.py",
    )
    root = tmp_path / "root"
    parent = root / "parent"
    target = parent / "a.txt"
    safe_root = _metadata(mode=stat.S_IFDIR | 0o755, device=1, inode=10)
    safe_parent = _metadata(mode=stat.S_IFDIR | 0o755, device=1, inode=11)
    outside_file = _metadata(
        mode=stat.S_IFREG | 0o644,
        device=2,
        inode=99,
        size=len(b"outside"),
    )
    parent_was_checked = False
    parent_was_substituted = False
    opened: list[Path] = []
    reads: list[tuple[int, int]] = []
    closed: list[int] = []

    def substituted_lstat(path: Any) -> Any:
        nonlocal parent_was_checked, parent_was_substituted
        observed = Path(path)
        if observed == root:
            return safe_root
        if observed == parent:
            parent_was_checked = True
            return safe_parent
        if observed == target:
            assert parent_was_checked
            parent_was_substituted = True
            return outside_file
        raise AssertionError(f"unexpected lstat target: {observed}")

    def sentinel_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        assert parent_was_substituted
        opened.append(Path(path))
        return 91

    def sentinel_read(descriptor: int, size: int) -> bytes:
        reads.append((descriptor, size))
        return b"outside" if len(reads) == 1 else b""

    monkeypatch.setattr(adapter.os, "lstat", substituted_lstat)
    monkeypatch.setattr(adapter.os, "open", sentinel_open)
    monkeypatch.setattr(adapter.os, "fstat", lambda descriptor: outside_file)
    monkeypatch.setattr(adapter.os, "read", sentinel_read)
    monkeypatch.setattr(adapter.os, "close", lambda descriptor: closed.append(descriptor))

    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=32)
    try:
        observed = callback("parent/a.txt")
    except adapter.MaterializedMemberError as error:
        assert error.code == "ANCHORED_OPEN_UNAVAILABLE"
    else:
        pytest.fail(
            "PARENT_SUBSTITUTION_READ_ACCEPTED: "
            f"opened={opened!r}, reads={reads!r}, content={observed.content!r}"
        )

    assert parent_was_checked
    assert parent_was_substituted
    assert opened == []
    assert reads == []
    assert closed == []
