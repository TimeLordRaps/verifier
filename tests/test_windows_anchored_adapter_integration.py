"""Integration contract for the accepted Windows anchored opener and reader."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import ModuleType
from typing import Any

import pytest
from scripts import exact_materialized_member, exact_source_scope


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SOURCE_COORDINATE = "cd" * 32


@pytest.fixture(scope="module")
def modules() -> tuple[ModuleType, ModuleType]:
    reader = exact_source_scope
    adapter = exact_materialized_member
    assert hasattr(adapter, "exact_windows_anchored_member_reader"), (
        "WINDOWS_ANCHORED_ADAPTER_INTEGRATION_MISSING: retain this RED before "
        "adding a trusted-root-handle reader"
    )
    return reader, adapter


def _open_root(root: Path) -> tuple[Any, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.CreateFileW(
        str(root),
        0x00000080 | 0x00000020 | 0x00100000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    assert handle not in (None, ctypes.c_void_p(-1).value)
    return kernel32, int(handle)


def _manifest(path: str, payload: bytes) -> bytes:
    document = {
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
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


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


def test_trusted_root_reader_never_uses_path_open_or_discovery(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, adapter = modules
    root = tmp_path / "root"
    admitted = root / "allowed" / "a.txt"
    unlisted = root / "unlisted" / "secret.txt"
    admitted.parent.mkdir(parents=True)
    unlisted.parent.mkdir(parents=True)
    admitted.write_bytes(b"anchored-admitted")
    unlisted.write_bytes(b"must-not-read")
    kernel32, root_handle = _open_root(root)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("anchored adapter attempted pathname or discovery access")

    try:
        monkeypatch.setattr(adapter.os, "open", forbidden)
        monkeypatch.setattr(adapter.os, "lstat", forbidden)
        monkeypatch.setattr(adapter.os, "walk", forbidden)
        monkeypatch.setattr(adapter.os, "scandir", forbidden)
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(subprocess, "check_output", forbidden)
        monkeypatch.setattr(Path, "glob", forbidden)
        monkeypatch.setattr(Path, "rglob", forbidden)
        monkeypatch.setattr(Path, "iterdir", forbidden)
        callback = adapter.exact_windows_anchored_member_reader(
            root_handle, max_member_bytes=1024
        )
        scope = _load_scope(reader, callback, "allowed/a.txt", b"anchored-admitted")
        assert scope.member_paths == ("allowed/a.txt",)
        assert scope.completeness == "UNKNOWN"
        assert scope.release_admissible is False
    finally:
        assert kernel32.CloseHandle(ctypes.c_void_p(root_handle))


def test_reader_digest_binding_rejects_changed_bytes(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path
) -> None:
    reader, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"changed!")
    kernel32, root_handle = _open_root(root)
    try:
        callback = adapter.exact_windows_anchored_member_reader(
            root_handle, max_member_bytes=1024
        )
        with pytest.raises(reader.ScopeInputError) as captured:
            _load_scope(reader, callback, "a.txt", b"expected")
        assert captured.value.code == "MEMBER_DIGEST_MISMATCH"
    finally:
        assert kernel32.CloseHandle(ctypes.c_void_p(root_handle))


def test_size_bound_rejects_before_content_read(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"12345")
    kernel32, root_handle = _open_root(root)
    reads: list[Any] = []
    try:
        monkeypatch.setattr(
            adapter.os, "read", lambda *args: reads.append(args) or b""
        )
        callback = adapter.exact_windows_anchored_member_reader(
            root_handle, max_member_bytes=4
        )
        with pytest.raises(adapter.MaterializedMemberError) as captured:
            callback("a.txt")
        assert captured.value.code == "MEMBER_SIZE_LIMIT"
        assert reads == []
    finally:
        assert kernel32.CloseHandle(ctypes.c_void_p(root_handle))


def test_read_cancellation_closes_descriptor_before_first_read(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"cancelled")
    kernel32, root_handle = _open_root(root)
    reads: list[Any] = []
    closed: list[int] = []
    calls = 0
    actual_close = adapter.os.close

    def cancellation() -> bool:
        nonlocal calls
        calls += 1
        return calls >= 5

    try:
        monkeypatch.setattr(
            adapter.os, "read", lambda *args: reads.append(args) or b""
        )
        monkeypatch.setattr(
            adapter.os,
            "close",
            lambda descriptor: closed.append(descriptor) or actual_close(descriptor),
        )
        callback = adapter.exact_windows_anchored_member_reader(
            root_handle,
            max_member_bytes=32,
            cancel_requested=cancellation,
        )
        with pytest.raises(adapter.MaterializedMemberError) as captured:
            callback("a.txt")
        assert captured.value.code == "ANCHORED_READ_CANCELLED"
        assert reads == []
        assert len(closed) == 1
    finally:
        assert kernel32.CloseHandle(ctypes.c_void_p(root_handle))


def test_descriptor_close_failure_is_explicitly_accounted(
    modules: tuple[ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"close")
    kernel32, root_handle = _open_root(root)
    close_attempts: list[int] = []
    actual_close = adapter.os.close

    def failed_close(descriptor: int) -> None:
        close_attempts.append(descriptor)
        raise OSError("synthetic descriptor close failure")

    try:
        monkeypatch.setattr(adapter.os, "close", failed_close)
        callback = adapter.exact_windows_anchored_member_reader(
            root_handle, max_member_bytes=32
        )
        with pytest.raises(adapter.MaterializedMemberError) as captured:
            callback("a.txt")
        assert captured.value.code == "MEMBER_CLOSE_FAILED"
        assert captured.value.unclosed_handles == tuple(close_attempts)
    finally:
        monkeypatch.setattr(adapter.os, "close", actual_close)
        for descriptor in close_attempts:
            actual_close(descriptor)
        assert kernel32.CloseHandle(ctypes.c_void_p(root_handle))


def test_borrowed_root_handle_supports_multiple_exact_reads(
    modules: tuple[ModuleType, ModuleType], tmp_path: Path
) -> None:
    _, adapter = modules
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"repeat")
    kernel32, root_handle = _open_root(root)
    try:
        callback = adapter.exact_windows_anchored_member_reader(
            root_handle, max_member_bytes=32
        )
        assert callback("a.txt").content == b"repeat"
        assert callback("a.txt").content == b"repeat"
    finally:
        assert kernel32.CloseHandle(ctypes.c_void_p(root_handle))
