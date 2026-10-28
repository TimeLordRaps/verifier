"""Test-first contract for an operating system (OS) admitted-root boundary.

The binding module is intentionally absent in this candidate.  The first
independent run must record the RED diagnostic ADMITTED_ROOT_BINDING_MISSING
before scripts/admitted_root_binding.py is added.  Admission is an explicit
external input: these tests never derive authority from the bytes they check.
Only synthetic temporary trees are used; no real application member is named.
"""

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
from scripts import admitted_root_binding, exact_materialized_member, exact_source_scope


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
BINDING = SCRIPTS / "admitted_root_binding.py"
SCHEMA = "verifier-selected-source-scope-1"
SOURCE_COORDINATE = "ab" * 32
GENERATION = 7

FILE_READ_ATTRIBUTES = 0x00000080
FILE_TRAVERSE = 0x00000020
SYNCHRONIZE = 0x00100000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", ctypes.c_uint32 * 2),
        ("ftLastAccessTime", ctypes.c_uint32 * 2),
        ("ftLastWriteTime", ctypes.c_uint32 * 2),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


@pytest.fixture(scope="module")
def modules() -> tuple[ModuleType, ModuleType, ModuleType]:
    reader = exact_source_scope
    adapter = exact_materialized_member
    assert BINDING.is_file(), (
        "ADMITTED_ROOT_BINDING_MISSING: preserve this pre-edit RED before adding "
        "scripts/admitted_root_binding.py"
    )
    binding = admitted_root_binding
    return reader, adapter, binding


def _kernel32() -> Any:
    if os.name != "nt":
        pytest.skip("OS_CAPABILITY_GUARD: this test requires native Windows root handles")
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
    kernel32.GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = ctypes.c_int
    return kernel32


def _open_root(root: Path) -> tuple[Any, int]:
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        str(root),
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
        FILE_SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    assert handle not in (None, ctypes.c_void_p(-1).value)
    return kernel32, int(handle)


def _identity(kernel32: Any, handle: int) -> tuple[int, int]:
    """Independent test oracle: volume serial and 64-bit file index of a handle."""

    information = _ByHandleFileInformation()
    assert kernel32.GetFileInformationByHandle(
        ctypes.c_void_p(handle), ctypes.byref(information)
    )
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    return int(information.dwVolumeSerialNumber), file_index


def _close(kernel32: Any, handle: int) -> None:
    assert kernel32.CloseHandle(ctypes.c_void_p(handle))


def _write_tree(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, payload in files.items():
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return root


def _member(path: str, payload: bytes, role: str = "SOURCE") -> dict[str, Any]:
    return {
        "path": path,
        "role": role,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def _manifest(*members: dict[str, Any], source_coordinate: str = SOURCE_COORDINATE) -> bytes:
    document = {
        "schema_version": SCHEMA,
        "candidate_status": "CANDIDATE",
        "completeness": "UNKNOWN",
        "release_admissible": False,
        "source_coordinate": source_coordinate,
        "members": list(members),
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def _materialization_coordinate(source_coordinate: str, members: list[dict[str, Any]]) -> str:
    """Specification oracle: digest of the canonical member table plus source coordinate."""

    table = sorted(members, key=lambda member: member["path"])
    canonical = json.dumps(
        {"members": table, "source_coordinate": source_coordinate},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _admission(
    binding: ModuleType,
    identity: tuple[int, int],
    members: list[dict[str, Any]],
    raw: bytes,
    *,
    source_coordinate: str = SOURCE_COORDINATE,
    **overrides: Any,
) -> Any:
    fields: dict[str, Any] = {
        "admission_id": "admission-1",
        "generation": GENERATION,
        "root_volume_serial": identity[0],
        "root_file_index": identity[1],
        "source_coordinate": source_coordinate,
        "materialization_coordinate": _materialization_coordinate(source_coordinate, members),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
    }
    fields.update(overrides)
    return binding.RootAdmission(**fields)


def _bind(
    binding: ModuleType,
    admission: Any,
    root_handle: Any,
    raw: bytes,
    *,
    current_generation: Any = GENERATION,
    consumed: set[str] | None = None,
    cancel_requested: Any = None,
) -> Any:
    return binding.bind_admitted_root(
        admission=admission,
        trusted_root_handle=root_handle,
        manifest_bytes=raw,
        current_generation=current_generation,
        consumed_admission_ids=set() if consumed is None else consumed,
        max_member_bytes=1024,
        max_total_bytes=2048,
        cancel_requested=cancel_requested,
    )


def _spy_reads(monkeypatch: pytest.MonkeyPatch, adapter: ModuleType) -> list[Any]:
    reads: list[Any] = []
    monkeypatch.setattr(adapter.os, "read", lambda *args: reads.append(args) or b"")
    return reads


def _forbid_pathname_and_discovery(
    monkeypatch: pytest.MonkeyPatch, adapter: ModuleType
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("admitted binding attempted pathname or discovery access")

    for owner, name in (
        (adapter.os, "open"),
        (adapter.os, "lstat"),
        (adapter.os, "walk"),
        (adapter.os, "scandir"),
        (subprocess, "run"),
        (subprocess, "check_output"),
        (Path, "glob"),
        (Path, "rglob"),
        (Path, "iterdir"),
    ):
        monkeypatch.setattr(owner, name, forbidden)


def test_admitted_root_loads_only_declared_members(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter, binding = modules
    payload = b"admitted-source"
    members = [_member("allowed/a.txt", payload)]
    raw = _manifest(*members)
    root = _write_tree(
        tmp_path / "root",
        {"allowed/a.txt": payload, "unlisted/secret.txt": b"must-not-read"},
    )
    kernel32, handle = _open_root(root)
    try:
        admission = _admission(binding, _identity(kernel32, handle), members, raw)
        _forbid_pathname_and_discovery(monkeypatch, adapter)
        bound = _bind(binding, admission, handle, raw)
        scope = bound.load_scope()
        assert scope.member_paths == ("allowed/a.txt",)
        assert scope.source_coordinate == SOURCE_COORDINATE
        assert scope.completeness == "UNKNOWN"
        assert scope.release_admissible is False
    finally:
        _close(kernel32, handle)


def test_binding_borrows_root_handle_and_leaves_ownership_with_caller(
    modules: tuple[ModuleType, ModuleType, ModuleType], tmp_path: Path
) -> None:
    _, _, binding = modules
    payload = b"borrowed"
    members = [_member("a.txt", payload)]
    raw = _manifest(*members)
    root = _write_tree(tmp_path / "root", {"a.txt": payload})
    kernel32, handle = _open_root(root)
    admission = _admission(binding, _identity(kernel32, handle), members, raw)
    bound = _bind(binding, admission, handle, raw)
    bound.load_scope()
    assert bound.read_member("a.txt").content == payload
    # The caller still owns the handle: this single close must succeed.
    _close(kernel32, handle)


def test_wrong_root_handle_is_refused_and_admission_is_not_consumed(
    modules: tuple[ModuleType, ModuleType, ModuleType], tmp_path: Path
) -> None:
    reader, _, binding = modules
    payload = b"admitted"
    members = [_member("a.txt", payload)]
    raw = _manifest(*members)
    admitted_root = _write_tree(tmp_path / "admitted", {"a.txt": payload})
    other_root = _write_tree(tmp_path / "other", {"a.txt": payload})
    admitted_kernel, admitted_handle = _open_root(admitted_root)
    other_kernel, other_handle = _open_root(other_root)
    consumed: set[str] = set()
    try:
        admission = _admission(
            binding, _identity(admitted_kernel, admitted_handle), members, raw
        )
        with pytest.raises(reader.ScopeInputError) as captured:
            _bind(binding, admission, other_handle, raw, consumed=consumed)
        assert captured.value.code == "ROOT_IDENTITY_MISMATCH"
        assert consumed == set()
        # The failed attempt did not spend the admission: the true root still binds.
        _bind(binding, admission, admitted_handle, raw, consumed=consumed)
        assert consumed == {"admission-1"}
    finally:
        _close(other_kernel, other_handle)
        _close(admitted_kernel, admitted_handle)


def test_stale_admission_is_refused_before_any_root_use(
    modules: tuple[ModuleType, ModuleType, ModuleType],
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(binding, (1, 2), members, raw, generation=GENERATION - 1)
    # Handle 1 is synthetic: staleness must be refused before any native call.
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, 1, raw, current_generation=GENERATION)
    assert captured.value.code == "ADMISSION_STALE"


def test_reused_admission_is_refused_after_successful_binding(
    modules: tuple[ModuleType, ModuleType, ModuleType], tmp_path: Path
) -> None:
    reader, _, binding = modules
    payload = b"once"
    members = [_member("a.txt", payload)]
    raw = _manifest(*members)
    root = _write_tree(tmp_path / "root", {"a.txt": payload})
    kernel32, handle = _open_root(root)
    consumed: set[str] = set()
    try:
        admission = _admission(binding, _identity(kernel32, handle), members, raw)
        _bind(binding, admission, handle, raw, consumed=consumed)
        assert consumed == {"admission-1"}
        with pytest.raises(reader.ScopeInputError) as captured:
            _bind(binding, admission, handle, raw, consumed=consumed)
        assert captured.value.code == "ADMISSION_REUSED"
    finally:
        _close(kernel32, handle)


def test_missing_generation_or_ledger_fails_closed(
    modules: tuple[ModuleType, ModuleType, ModuleType],
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(binding, (1, 2), members, raw)
    with pytest.raises(reader.ScopeInputError) as generation_error:
        binding.bind_admitted_root(
            admission=admission,
            trusted_root_handle=1,
            manifest_bytes=raw,
            current_generation=None,
            consumed_admission_ids=set(),
            max_member_bytes=1024,
            max_total_bytes=2048,
        )
    assert generation_error.value.code == "ADMISSION_GENERATION_MISSING"
    with pytest.raises(reader.ScopeInputError) as ledger_error:
        binding.bind_admitted_root(
            admission=admission,
            trusted_root_handle=1,
            manifest_bytes=raw,
            current_generation=GENERATION,
            consumed_admission_ids=None,
            max_member_bytes=1024,
            max_total_bytes=2048,
        )
    assert ledger_error.value.code == "ADMISSION_LEDGER_MISSING"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("admission_id", ""),
        ("generation", -1),
        ("generation", True),
        ("root_volume_serial", -1),
        ("root_file_index", True),
        ("source_coordinate", "AB" * 32),
        ("materialization_coordinate", "ab" * 31),
        ("manifest_sha256", "zz" * 32),
    ),
)
def test_malformed_admission_fields_are_refused(
    modules: tuple[ModuleType, ModuleType, ModuleType], field: str, value: Any
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(binding, (1, 2), members, raw, **{field: value})
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, 1, raw)
    assert captured.value.code == "ADMISSION_FIELD_INVALID"


def test_admission_must_be_an_explicit_admission_record(
    modules: tuple[ModuleType, ModuleType, ModuleType],
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    # A bare mapping is not an admission and must never be accepted as authority.
    declaration = {"admission_id": "admission-1", "generation": GENERATION}
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, declaration, 1, raw)
    assert captured.value.code == "ADMISSION_TYPE_INVALID"


def test_substituted_source_coordinate_is_refused(
    modules: tuple[ModuleType, ModuleType, ModuleType],
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(
        binding, (1, 2), members, raw, source_coordinate="cd" * 32
    )
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, 1, raw)
    assert captured.value.code == "SOURCE_COORDINATE_MISMATCH"


def test_substituted_materialization_coordinate_is_refused(
    modules: tuple[ModuleType, ModuleType, ModuleType],
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(
        binding, (1, 2), members, raw, materialization_coordinate="00" * 32
    )
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, 1, raw)
    assert captured.value.code == "MATERIALIZATION_COORDINATE_MISMATCH"


def test_substituted_manifest_bytes_are_refused(
    modules: tuple[ModuleType, ModuleType, ModuleType],
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(binding, (1, 2), members, raw, manifest_sha256="00" * 32)
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, 1, raw)
    assert captured.value.code == "MANIFEST_DIGEST_MISMATCH"


@pytest.mark.parametrize("second_path", ("a.txt", "A.txt"))
def test_duplicate_member_declaration_is_refused_before_any_io(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    second_path: str,
) -> None:
    reader, adapter, binding = modules
    payload = b"dup"
    members = [_member("a.txt", payload), _member(second_path, payload)]
    raw = _manifest(*members)
    admission = _admission(binding, (1, 2), members, raw)
    reads = _spy_reads(monkeypatch, adapter)
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, 1, raw)
    assert captured.value.code == "MEMBER_PATH_COLLISION"
    assert reads == []


@pytest.mark.parametrize(
    "requested",
    ("unlisted/secret.txt", "allowed/../unlisted/secret.txt", "Allowed/A.txt"),
)
def test_unlisted_member_request_is_refused_before_any_io(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requested: str,
) -> None:
    reader, adapter, binding = modules
    payload = b"allowed"
    members = [_member("allowed/a.txt", payload)]
    raw = _manifest(*members)
    root = _write_tree(
        tmp_path / "root",
        {"allowed/a.txt": payload, "unlisted/secret.txt": b"must-not-read"},
    )
    kernel32, handle = _open_root(root)
    try:
        admission = _admission(binding, _identity(kernel32, handle), members, raw)
        bound = _bind(binding, admission, handle, raw)
        reads = _spy_reads(monkeypatch, adapter)
        with pytest.raises(reader.ScopeInputError) as captured:
            bound.read_member(requested)
        assert captured.value.code == "UNLISTED_MEMBER_REQUEST"
        assert reads == []
    finally:
        _close(kernel32, handle)


def test_member_bytes_must_match_the_requested_declaration(
    modules: tuple[ModuleType, ModuleType, ModuleType], tmp_path: Path
) -> None:
    reader, _, binding = modules
    declared_a = b"alpha-declared"
    declared_b = b"bravo-declared"
    members = [_member("a.txt", declared_a), _member("b.txt", declared_b)]
    raw = _manifest(*members)
    # a.txt is substituted with the bytes that b.txt legitimately declares.
    root = _write_tree(tmp_path / "root", {"a.txt": declared_b, "b.txt": declared_b})
    kernel32, handle = _open_root(root)
    try:
        admission = _admission(binding, _identity(kernel32, handle), members, raw)
        bound = _bind(binding, admission, handle, raw)
        with pytest.raises(reader.ScopeInputError) as captured:
            bound.read_member("a.txt")
        assert captured.value.code == "MEMBER_DIGEST_MISMATCH"
        assert bound.read_member("b.txt").content == declared_b
        with pytest.raises(reader.ScopeInputError) as scope_captured:
            bound.load_scope()
        assert scope_captured.value.code == "MEMBER_DIGEST_MISMATCH"
    finally:
        _close(kernel32, handle)


@pytest.mark.parametrize("handle", (0, -1, True, "1", None))
def test_root_handle_must_be_a_positive_integer(
    modules: tuple[ModuleType, ModuleType, ModuleType], handle: Any
) -> None:
    reader, _, binding = modules
    members = [_member("a.txt", b"x")]
    raw = _manifest(*members)
    admission = _admission(binding, (1, 2), members, raw)
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, handle, raw)
    assert captured.value.code == "ROOT_HANDLE_INVALID"


def test_cancellation_propagates_unchanged_and_reads_nothing(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter, binding = modules
    payload = b"cancel-me"
    members = [_member("a.txt", payload)]
    raw = _manifest(*members)
    root = _write_tree(tmp_path / "root", {"a.txt": payload})
    kernel32, handle = _open_root(root)
    cancelled = [False]
    try:
        admission = _admission(binding, _identity(kernel32, handle), members, raw)
        bound = _bind(
            binding,
            admission,
            handle,
            raw,
            cancel_requested=lambda: cancelled[0],
        )
        reads = _spy_reads(monkeypatch, adapter)
        cancelled[0] = True
        with pytest.raises(adapter.MaterializedMemberError) as captured:
            bound.read_member("a.txt")
        # The accepted opener checks the predicate before opening, so the
        # propagated code is the open-phase cancellation, not a read-phase one.
        assert captured.value.code == "ANCHORED_OPEN_CANCELLED"
        assert reads == []
    finally:
        _close(kernel32, handle)


def test_descriptor_close_failure_keeps_unclosed_handles_visible(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter, binding = modules
    payload = b"close-me"
    members = [_member("a.txt", payload)]
    raw = _manifest(*members)
    root = _write_tree(tmp_path / "root", {"a.txt": payload})
    kernel32, handle = _open_root(root)
    close_attempts: list[int] = []
    actual_close = adapter.os.close

    def failed_close(descriptor: int) -> None:
        close_attempts.append(descriptor)
        raise OSError("synthetic descriptor close failure")

    try:
        admission = _admission(binding, _identity(kernel32, handle), members, raw)
        bound = _bind(binding, admission, handle, raw)
        monkeypatch.setattr(adapter.os, "close", failed_close)
        with pytest.raises(adapter.MaterializedMemberError) as captured:
            bound.read_member("a.txt")
        assert captured.value.code == "MEMBER_CLOSE_FAILED"
        assert len(close_attempts) == 1
        assert captured.value.unclosed_handles == tuple(close_attempts)
    finally:
        monkeypatch.setattr(adapter.os, "close", actual_close)
        for descriptor in close_attempts:
            actual_close(descriptor)
        _close(kernel32, handle)


def test_legacy_pathname_route_remains_fail_closed(tmp_path: Path) -> None:
    # Characterization guard for the accepted adapter; it does not depend on the
    # binding module, so it is expected GREEN independently of the RED above.
    adapter = exact_materialized_member
    root = _write_tree(tmp_path / "root", {"a.txt": b"legacy"})
    callback = adapter.exact_materialized_member_reader(root, max_member_bytes=32)
    with pytest.raises(adapter.MaterializedMemberError) as captured:
        callback("a.txt")
    assert captured.value.code == "ANCHORED_OPEN_UNAVAILABLE"


# Independent REJECT fc5dd0bbc67017a1a7ccaaecc7985d59bba99a57200dde6f2caee080f8705908
# observed the following four gaps.  These tests are intentionally synthetic:
# they exercise the admitted-root boundary without claiming live OS handle-value
# reuse, a realizable non-disk directory object, or actual memory exhaustion.
_SYNTHETIC_HANDLE = 111
_SYNTHETIC_HELD_HANDLE = 222
_IDENTITY_A = (1, 11)
_IDENTITY_B = (1, 22)
_ADVERSARIAL_PAYLOAD = b"same-declared-bytes"


def _adversarial_declaration(binding: ModuleType) -> tuple[Any, bytes]:
    members = [_member("a.txt", _ADVERSARIAL_PAYLOAD)]
    raw = _manifest(*members)
    return _admission(binding, _IDENTITY_A, members, raw), raw


def _install_identity_model(
    monkeypatch: pytest.MonkeyPatch,
    reader: ModuleType,
    binding: ModuleType,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "current_identity": _IDENTITY_A,
        "identity_calls": [],
        "reader_handles": [],
    }

    def identity(handle: int) -> tuple[int, int]:
        state["identity_calls"].append(handle)
        return state["current_identity"]

    def factory(handle: int, **kwargs: Any) -> Any:
        state["reader_handles"].append(handle)

        def read_member(path: str) -> Any:
            assert path == "a.txt"
            return reader.MemberObservation(kind="REGULAR", content=_ADVERSARIAL_PAYLOAD)

        return read_member

    monkeypatch.setattr(binding, "_borrowed_root_identity", identity)
    monkeypatch.setattr(binding, "exact_windows_anchored_member_reader", factory)
    # These are the intended narrow repair seams.  ``raising=False`` lets this
    # test record the current pre-repair RED before the seams exist.
    monkeypatch.setattr(
        binding,
        "_duplicate_root_handle",
        lambda handle: _SYNTHETIC_HELD_HANDLE,
        raising=False,
    )
    monkeypatch.setattr(
        binding,
        "_close_duplicated_root_handle",
        lambda handle: None,
        raising=False,
    )
    return state


def test_substituted_numeric_root_handle_is_refused_at_read(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, _, binding = modules
    state = _install_identity_model(monkeypatch, reader, binding)
    admission, raw = _adversarial_declaration(binding)
    bound = _bind(binding, admission, _SYNTHETIC_HANDLE, raw)
    # Models caller close plus reuse of the same numeric value for identity B.
    state["current_identity"] = _IDENTITY_B
    with pytest.raises(reader.ScopeInputError) as captured:
        bound.read_member("a.txt")
    assert captured.value.code == "ROOT_IDENTITY_MISMATCH"


def test_each_read_uses_a_held_duplicate_not_the_borrowed_numeric_value(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, _, binding = modules
    identity_calls: list[int] = []
    reader_handles: list[int] = []
    closed: list[int] = []

    def identity(handle: int) -> tuple[int, int]:
        identity_calls.append(handle)
        if handle == _SYNTHETIC_HANDLE and len(identity_calls) == 1:
            return _IDENTITY_A
        if handle == _SYNTHETIC_HELD_HANDLE:
            return _IDENTITY_A
        return _IDENTITY_B

    def factory(handle: int, **kwargs: Any) -> Any:
        reader_handles.append(handle)
        return lambda path: reader.MemberObservation(
            kind="REGULAR", content=_ADVERSARIAL_PAYLOAD
        )

    monkeypatch.setattr(binding, "_borrowed_root_identity", identity)
    monkeypatch.setattr(binding, "exact_windows_anchored_member_reader", factory)
    monkeypatch.setattr(
        binding,
        "_duplicate_root_handle",
        lambda handle: _SYNTHETIC_HELD_HANDLE,
        raising=False,
    )
    monkeypatch.setattr(
        binding,
        "_close_duplicated_root_handle",
        lambda handle: closed.append(handle),
        raising=False,
    )
    admission, raw = _adversarial_declaration(binding)
    bound = _bind(binding, admission, _SYNTHETIC_HANDLE, raw)
    assert bound.read_member("a.txt").content == _ADVERSARIAL_PAYLOAD
    assert identity_calls == [_SYNTHETIC_HANDLE, _SYNTHETIC_HELD_HANDLE]
    assert reader_handles == [_SYNTHETIC_HELD_HANDLE]
    assert closed == [_SYNTHETIC_HELD_HANDLE]


class _FunctionDouble:
    def __init__(self, action: Any) -> None:
        self.action = action

    def __call__(self, *args: Any) -> Any:
        return self.action(*args)


@pytest.mark.skipif(os.name != "nt", reason="OS_CAPABILITY_GUARD: Windows handle identity is unavailable")
def test_mocked_non_disk_directory_is_refused_before_admission_commit(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, _, binding = modules
    calls = {"get_info": 0, "get_file_type": 0}

    def get_info(handle: Any, pointer: Any) -> int:
        calls["get_info"] += 1
        information = ctypes.cast(
            pointer, ctypes.POINTER(binding._ByHandleFileInformation)
        ).contents
        information.dwFileAttributes = binding.FILE_ATTRIBUTE_DIRECTORY
        information.dwVolumeSerialNumber = _IDENTITY_A[0]
        information.nFileIndexHigh = 0
        information.nFileIndexLow = _IDENTITY_A[1]
        return 1

    def get_file_type(handle: Any) -> int:
        calls["get_file_type"] += 1
        return 2  # FILE_TYPE_CHAR, explicitly not FILE_TYPE_DISK.

    class KernelDouble:
        GetFileInformationByHandle = _FunctionDouble(get_info)
        GetFileType = _FunctionDouble(get_file_type)

    monkeypatch.setattr(binding.ctypes, "WinDLL", lambda *args, **kwargs: KernelDouble())
    monkeypatch.setattr(
        binding,
        "exact_windows_anchored_member_reader",
        lambda *args, **kwargs: lambda relative: reader.MemberObservation(
            kind="REGULAR", content=_ADVERSARIAL_PAYLOAD
        ),
    )
    admission, raw = _adversarial_declaration(binding)
    ledger: set[str] = set()
    with pytest.raises(reader.ScopeInputError) as captured:
        _bind(binding, admission, _SYNTHETIC_HANDLE, raw, consumed=ledger)
    assert captured.value.code == "ROOT_NOT_DISK"
    assert calls == {"get_info": 0, "get_file_type": 1}
    assert ledger == set()


@pytest.mark.parametrize("code", ("ANCHORED_READ_CANCELLED", "MEMBER_CLOSE_FAILED"))
def test_load_scope_preserves_adapter_error_and_cleanup_metadata(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    code: str,
) -> None:
    _, adapter, binding = modules
    failure = adapter.MaterializedMemberError(
        code, "injected read failure", unclosed_handles=(707,)
    )
    monkeypatch.setattr(binding, "_borrowed_root_identity", lambda handle: _IDENTITY_A)
    monkeypatch.setattr(
        binding,
        "_duplicate_root_handle",
        lambda handle: _SYNTHETIC_HELD_HANDLE,
        raising=False,
    )
    monkeypatch.setattr(
        binding,
        "_close_duplicated_root_handle",
        lambda handle: None,
        raising=False,
    )

    def factory(*args: Any, **kwargs: Any) -> Any:
        def read_member(relative: str) -> Any:
            raise failure

        return read_member

    monkeypatch.setattr(binding, "exact_windows_anchored_member_reader", factory)
    admission, raw = _adversarial_declaration(binding)
    bound = _bind(binding, admission, _SYNTHETIC_HANDLE, raw)
    with pytest.raises(adapter.MaterializedMemberError) as captured:
        bound.load_scope()
    assert captured.value is failure
    assert captured.value.code == code
    assert captured.value.unclosed_handles == (707,)


def test_constructor_failure_does_not_consume_admission(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, binding = modules
    monkeypatch.setattr(binding, "_borrowed_root_identity", lambda handle: _IDENTITY_A)
    monkeypatch.setattr(
        binding,
        "exact_windows_anchored_member_reader",
        lambda *args, **kwargs: lambda relative: None,
    )
    ledger: set[str] = set()
    admission, raw = _adversarial_declaration(binding)

    def unavailable_constructor(**kwargs: Any) -> Any:
        raise MemoryError("injected constructor allocation failure")

    monkeypatch.setattr(binding, "AdmittedRootBinding", unavailable_constructor)
    with pytest.raises(MemoryError, match="injected constructor allocation failure"):
        _bind(binding, admission, _SYNTHETIC_HANDLE, raw, consumed=ledger)
    assert ledger == set()


def test_held_root_duplicate_closes_once_when_inner_read_raises(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter, binding = modules
    failure = adapter.MaterializedMemberError("ANCHORED_READ_CANCELLED", "injected")
    closed: list[int] = []
    monkeypatch.setattr(binding, "_borrowed_root_identity", lambda handle: _IDENTITY_A)
    monkeypatch.setattr(
        binding, "_duplicate_root_handle", lambda handle: _SYNTHETIC_HELD_HANDLE
    )
    monkeypatch.setattr(
        binding, "_close_duplicated_root_handle", lambda handle: closed.append(handle)
    )

    def factory(*args: Any, **kwargs: Any) -> Any:
        def read_member(relative: str) -> Any:
            raise failure

        return read_member

    monkeypatch.setattr(binding, "exact_windows_anchored_member_reader", factory)
    admission, raw = _adversarial_declaration(binding)
    bound = _bind(binding, admission, _SYNTHETIC_HANDLE, raw)
    with pytest.raises(adapter.MaterializedMemberError) as captured:
        bound.read_member("a.txt")
    assert captured.value is failure
    assert closed == [_SYNTHETIC_HELD_HANDLE]


def test_held_root_close_failure_is_visible_through_load_scope(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, adapter, binding = modules
    close_failure = adapter.MaterializedMemberError(
        "ROOT_HANDLE_CLOSE_FAILED",
        "injected",
        unclosed_handles=(_SYNTHETIC_HELD_HANDLE,),
    )
    monkeypatch.setattr(binding, "_borrowed_root_identity", lambda handle: _IDENTITY_A)
    monkeypatch.setattr(
        binding, "_duplicate_root_handle", lambda handle: _SYNTHETIC_HELD_HANDLE
    )

    def failed_close(handle: int) -> None:
        raise close_failure

    monkeypatch.setattr(binding, "_close_duplicated_root_handle", failed_close)
    monkeypatch.setattr(
        binding,
        "exact_windows_anchored_member_reader",
        lambda *args, **kwargs: lambda relative: reader.MemberObservation(
            kind="REGULAR", content=_ADVERSARIAL_PAYLOAD
        ),
    )
    admission, raw = _adversarial_declaration(binding)
    bound = _bind(binding, admission, _SYNTHETIC_HANDLE, raw)
    with pytest.raises(adapter.MaterializedMemberError) as captured:
        bound.load_scope()
    assert captured.value is close_failure
    assert captured.value.code == "ROOT_HANDLE_CLOSE_FAILED"
    assert captured.value.unclosed_handles == (_SYNTHETIC_HELD_HANDLE,)


def test_held_root_close_failure_augments_existing_adapter_error(
    modules: tuple[ModuleType, ModuleType, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, adapter, binding = modules
    read_failure = adapter.MaterializedMemberError(
        "MEMBER_CLOSE_FAILED", "injected read cleanup", unclosed_handles=(707,)
    )
    close_failure = adapter.MaterializedMemberError(
        "ROOT_HANDLE_CLOSE_FAILED",
        "injected root cleanup",
        unclosed_handles=(_SYNTHETIC_HELD_HANDLE,),
    )
    monkeypatch.setattr(binding, "_borrowed_root_identity", lambda handle: _IDENTITY_A)
    monkeypatch.setattr(
        binding, "_duplicate_root_handle", lambda handle: _SYNTHETIC_HELD_HANDLE
    )

    def failed_close(handle: int) -> None:
        raise close_failure

    monkeypatch.setattr(binding, "_close_duplicated_root_handle", failed_close)

    def factory(*args: Any, **kwargs: Any) -> Any:
        def read_member(relative: str) -> Any:
            raise read_failure

        return read_member

    monkeypatch.setattr(binding, "exact_windows_anchored_member_reader", factory)
    admission, raw = _adversarial_declaration(binding)
    bound = _bind(binding, admission, _SYNTHETIC_HANDLE, raw)
    with pytest.raises(adapter.MaterializedMemberError) as captured:
        bound.read_member("a.txt")
    assert captured.value is read_failure
    assert captured.value.unclosed_handles == (707, _SYNTHETIC_HELD_HANDLE)
