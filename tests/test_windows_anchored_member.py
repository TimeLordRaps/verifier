"""Test-first contract for Windows handle-relative member opening."""

from __future__ import annotations

import ctypes
import importlib.util
import os
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Callable

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "windows_anchored_member.py"
ADAPTER_PATH = ROOT / "scripts" / "exact_materialized_member.py"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def opener() -> ModuleType:
    assert MODULE_PATH.is_file(), (
        "WINDOWS_ANCHORED_OPENER_MISSING: retain this pre-edit RED before "
        "adding scripts/windows_anchored_member.py"
    )
    return _load("windows_anchored_member_candidate", MODULE_PATH)


class FakeBackend:
    def __init__(self, module: ModuleType) -> None:
        self.module = module
        self.operations: list[tuple[Any, ...]] = []
        self.closed: list[int] = []
        self.close_attempts: list[int] = []
        self.close_failures: set[int] = set()
        self.infos: dict[int, Any] = {}
        self.relative_results: list[int | BaseException] = []
        self.duplicate_result: int | BaseException = 101
        self.convert_result: int | BaseException = 77

    def duplicate_handle(self, handle: int) -> int:
        self.operations.append(("duplicate", handle))
        if isinstance(self.duplicate_result, BaseException):
            raise self.duplicate_result
        return self.duplicate_result

    def inspect_handle(self, handle: int) -> Any:
        self.operations.append(("inspect", handle))
        result = self.infos[handle]
        if isinstance(result, BaseException):
            raise result
        return result

    def open_relative(self, parent: int, component: str, *, directory: bool) -> int:
        self.operations.append(("open_relative", parent, component, directory))
        result = self.relative_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def handle_to_fd(self, handle: int) -> int:
        self.operations.append(("handle_to_fd", handle))
        if isinstance(self.convert_result, BaseException):
            raise self.convert_result
        return self.convert_result

    def close_handle(self, handle: int) -> None:
        self.operations.append(("close", handle))
        self.close_attempts.append(handle)
        if handle in self.close_failures:
            raise OSError("synthetic close failure")
        self.closed.append(handle)


def _info(opener: ModuleType, *, directory: bool, reparse: bool = False) -> Any:
    return opener.HandleInfo(is_disk=True, is_directory=directory, is_reparse=reparse)


def _error(opener: ModuleType, code: str, action: Callable[[], Any]) -> None:
    with pytest.raises(opener.AnchoredOpenError) as captured:
        action()
    assert captured.value.code == code


def test_components_are_opened_relative_to_held_parent_handles(opener: ModuleType) -> None:
    backend = FakeBackend(opener)
    backend.infos = {
        101: _info(opener, directory=True),
        201: _info(opener, directory=True),
        301: _info(opener, directory=False),
    }
    backend.relative_results = [201, 301]

    descriptor = opener.open_anchored_member(
        100, ("parent", "a.txt"), _backend=backend
    )

    assert descriptor == 77
    assert ("open_relative", 101, "parent", True) in backend.operations
    assert ("open_relative", 201, "a.txt", False) in backend.operations
    assert backend.closed == [101, 201]
    assert ("close", 301) not in backend.operations


def test_parent_namespace_replacement_cannot_change_held_handle(opener: ModuleType) -> None:
    backend = FakeBackend(opener)
    backend.infos = {
        101: _info(opener, directory=True),
        222: _info(opener, directory=True),
        333: _info(opener, directory=False),
    }
    backend.relative_results = [222, 333]
    namespace_replaced = False

    def cancellation_probe() -> bool:
        nonlocal namespace_replaced
        if ("open_relative", 101, "parent", True) in backend.operations:
            namespace_replaced = True
        return False

    opener.open_anchored_member(
        100,
        ("parent", "a.txt"),
        cancel_requested=cancellation_probe,
        _backend=backend,
    )

    assert namespace_replaced
    assert ("open_relative", 222, "a.txt", False) in backend.operations


@pytest.mark.parametrize("position", ("ROOT", "PARENT", "LEAF"))
def test_reparse_handle_is_rejected_before_traversal_or_transfer(
    opener: ModuleType, position: str
) -> None:
    backend = FakeBackend(opener)
    backend.infos[101] = _info(opener, directory=True, reparse=position == "ROOT")
    if position != "ROOT":
        backend.relative_results.append(201)
        backend.infos[201] = _info(
            opener, directory=position != "LEAF", reparse=position in {"PARENT", "LEAF"}
        )
        parts = ("parent", "a.txt") if position == "PARENT" else ("a.txt",)
    else:
        parts = ("a.txt",)

    _error(
        opener,
        "ANCHORED_REPARSE_REFUSED",
        lambda: opener.open_anchored_member(100, parts, _backend=backend),
    )

    if position == "ROOT":
        assert not any(operation[0] == "open_relative" for operation in backend.operations)
    if position == "PARENT":
        assert len([item for item in backend.operations if item[0] == "open_relative"]) == 1
    assert not any(operation[0] == "handle_to_fd" for operation in backend.operations)


def test_cancellation_before_duplicate_has_no_native_effect(opener: ModuleType) -> None:
    backend = FakeBackend(opener)
    _error(
        opener,
        "ANCHORED_OPEN_CANCELLED",
        lambda: opener.open_anchored_member(
            100, ("a.txt",), cancel_requested=lambda: True, _backend=backend
        ),
    )
    assert backend.operations == []


def test_cancellation_after_child_open_closes_all_owned_handles(opener: ModuleType) -> None:
    backend = FakeBackend(opener)
    backend.infos[101] = _info(opener, directory=True)
    backend.relative_results = [201]
    states = iter((False, False, True))
    _error(
        opener,
        "ANCHORED_OPEN_CANCELLED",
        lambda: opener.open_anchored_member(
            100, ("a.txt",), cancel_requested=lambda: next(states), _backend=backend
        ),
    )
    assert backend.closed == [201, 101]
    assert not any(operation[0] == "inspect" and operation[1] == 201 for operation in backend.operations)


@pytest.mark.parametrize("failure", ("OPEN", "INSPECT", "CONVERT"))
def test_failure_paths_close_each_owned_handle_once(opener: ModuleType, failure: str) -> None:
    backend = FakeBackend(opener)
    backend.infos[101] = _info(opener, directory=True)
    native_failure = OSError("synthetic native failure")
    if failure == "OPEN":
        backend.relative_results = [native_failure]
        expected = [101]
    else:
        backend.relative_results = [201]
        backend.infos[201] = (
            native_failure if failure == "INSPECT" else _info(opener, directory=False)
        )
        backend.convert_result = native_failure if failure == "CONVERT" else 77
        expected = [201, 101] if failure == "INSPECT" else [101, 201]

    _error(
        opener,
        f"ANCHORED_{failure}_FAILED",
        lambda: opener.open_anchored_member(100, ("a.txt",), _backend=backend),
    )
    assert backend.closed == expected
    assert len(backend.closed) == len(set(backend.closed))


@pytest.mark.parametrize(
    "parts",
    (
        (),
        ("",),
        (".",),
        ("..",),
        ("a/b",),
        ("a\\b",),
        ("C:",),
        ("nul\x00x",),
        ("cafe\u0301.txt",),
    ),
)
def test_malformed_components_fail_before_native_operations(
    opener: ModuleType, parts: tuple[str, ...]
) -> None:
    backend = FakeBackend(opener)
    _error(
        opener,
        "ANCHORED_COMPONENT_INVALID",
        lambda: opener.open_anchored_member(100, parts, _backend=backend),
    )
    assert backend.operations == []


@pytest.mark.parametrize("component", ("a" * 256, "\ud800"))
def test_unrepresentable_or_overlong_component_fails_before_native_operations(
    opener: ModuleType, component: str
) -> None:
    backend = FakeBackend(opener)
    _error(
        opener,
        "ANCHORED_COMPONENT_INVALID",
        lambda: opener.open_anchored_member(100, (component,), _backend=backend),
    )
    assert backend.operations == []


def test_non_bmp_component_uses_exact_utf16_byte_length(opener: ModuleType) -> None:
    captured: dict[str, int] = {}

    class FakeNtDll:
        def NtCreateFile(self, *arguments: Any) -> int:
            result = ctypes.cast(arguments[0], ctypes.POINTER(ctypes.c_void_p))
            attributes = ctypes.cast(
                arguments[2], ctypes.POINTER(opener._OBJECT_ATTRIBUTES)
            ).contents
            captured["length"] = int(attributes.ObjectName.contents.Length)
            captured["maximum_length"] = int(
                attributes.ObjectName.contents.MaximumLength
            )
            result.contents.value = 123
            return 0

        def RtlNtStatusToDosError(self, status: int) -> int:
            return 0

    backend = opener._WindowsNativeBackend.__new__(opener._WindowsNativeBackend)
    backend._ntdll = FakeNtDll()
    result = backend.open_relative(99, "\U0001f600", directory=False)
    assert result == 123
    assert captured == {"length": 4, "maximum_length": 6}


def test_failed_close_is_reported_and_other_owned_handle_is_cleaned(
    opener: ModuleType,
) -> None:
    backend = FakeBackend(opener)
    backend.infos = {
        101: _info(opener, directory=True),
        201: _info(opener, directory=False),
    }
    backend.relative_results = [201]
    backend.close_failures = {101}

    with pytest.raises(opener.AnchoredOpenError) as captured:
        opener.open_anchored_member(100, ("a.txt",), _backend=backend)

    assert captured.value.code == "ANCHORED_CLOSE_FAILED"
    assert captured.value.unclosed_handles == (101,)
    assert backend.close_attempts == [101, 201]
    assert backend.closed == [201]


@pytest.mark.skipif(os.name != "nt", reason="Windows-only native synthetic control")
def test_actual_native_backend_preserves_spaces_and_windows_case_behavior(
    opener: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    target = root / "Parent With Spaces" / "Case File.TXT"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"anchored-synthetic")
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
    try:
        descriptor = opener.open_anchored_member(
            int(handle), ("parent with spaces", "case file.txt")
        )
        try:
            assert os.read(descriptor, 64) == b"anchored-synthetic"
            assert os.read(descriptor, 1) == b""
        finally:
            os.close(descriptor)
    finally:
        assert kernel32.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows-only native synthetic control")
def test_actual_parent_replacement_does_not_redirect_held_directory(
    opener: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    parent = root / "parent"
    held_parent = root / "held-parent"
    target = parent / "a.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"held-original")
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
    root_handle = kernel32.CreateFileW(
        str(root),
        0x00000080 | 0x00000020 | 0x00100000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    assert root_handle not in (None, ctypes.c_void_p(-1).value)
    native = opener._WindowsNativeBackend()

    class ReplacingBackend:
        def duplicate_handle(self, handle: int) -> int:
            return native.duplicate_handle(handle)

        def inspect_handle(self, handle: int) -> Any:
            return native.inspect_handle(handle)

        def open_relative(self, parent_handle: int, component: str, *, directory: bool) -> int:
            result = native.open_relative(parent_handle, component, directory=directory)
            if directory and component == "parent":
                parent.rename(held_parent)
                parent.mkdir()
                (parent / "a.txt").write_bytes(b"replacement")
            return result

        def handle_to_fd(self, handle: int) -> int:
            return native.handle_to_fd(handle)

        def close_handle(self, handle: int) -> None:
            native.close_handle(handle)

    try:
        descriptor = opener.open_anchored_member(
            int(root_handle), ("parent", "a.txt"), _backend=ReplacingBackend()
        )
        try:
            assert os.read(descriptor, 64) == b"held-original"
        finally:
            os.close(descriptor)
        assert (parent / "a.txt").read_bytes() == b"replacement"
        assert (held_parent / "a.txt").read_bytes() == b"held-original"
    finally:
        assert kernel32.CloseHandle(root_handle)


def test_pinned_windows_x64_abi_layout(opener: ModuleType) -> None:
    assert ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(ctypes.c_ulong) == 4
    assert ctypes.sizeof(ctypes.c_ushort) == 2
    assert ctypes.sizeof(ctypes.c_wchar) == 2
    assert ctypes.sizeof(opener._UNICODE_STRING) == 16
    assert ctypes.sizeof(opener._OBJECT_ATTRIBUTES) == 48
    assert ctypes.sizeof(opener._IO_STATUS_BLOCK) == 16
    assert ctypes.sizeof(opener._FILE_ATTRIBUTE_TAG_INFO) == 8


def test_existing_production_adapter_remains_fail_closed(opener: ModuleType) -> None:
    source = ADAPTER_PATH.read_text(encoding="utf-8")
    assert "def _open_anchored_member" in source
    assert "ANCHORED_OPEN_UNAVAILABLE" in source
    assert "os.open(" not in source
