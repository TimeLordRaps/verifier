"""Bind an externally admitted trusted root to exact declared members.

Admission is an explicit input from an external authority.  This module never
derives authority from manifest bytes, file contents, or a hash.  It checks that
a caller-owned, already-open root handle has the admitted volume serial and file
index, that the manifest and its materialization coordinate match the admission,
and that each member read returns exactly the bytes declared for that path.

The caller's root handle is borrowed and never closed.  Each member read creates,
validates, and closes a short-lived duplicate so later reuse of the caller's
numeric handle cannot redirect the read.  The accepted parser, reader and
Windows-anchored adapter are reused unchanged.  There is no pathname, glob, walk,
or discovery route.  The consumed-admission set is caller-owned and
process-scoped; it is not a durable replay defense.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
import re
from typing import Any, Callable, NoReturn

if __package__:
    from .exact_materialized_member import (
        MaterializedMemberError,
        exact_windows_anchored_member_reader,
    )
    from .exact_source_scope import (
        MemberObservation,
        ScopeInputError,
        _parse_manifest,
        load_selected_source_scope,
    )
else:  # Preserve direct execution beside the accepted sibling scripts.
    from exact_materialized_member import (
        MaterializedMemberError,
        exact_windows_anchored_member_reader,
    )
    from exact_source_scope import (
        MemberObservation,
        ScopeInputError,
        _parse_manifest,
        load_selected_source_scope,
    )


FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_TYPE_DISK = 0x00000001
DUPLICATE_SAME_ACCESS = 0x00000002
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
SHA256 = re.compile(r"[0-9a-f]{64}")


class AdmittedRootError(ScopeInputError):
    """A fail-closed admitted-root binding error with a stable code."""

    __slots__ = ()


@dataclass(frozen=True)
class RootAdmission:
    """Explicit external authority for one root identity and one manifest."""

    admission_id: str
    generation: int
    root_volume_serial: int
    root_file_index: int
    source_coordinate: str
    materialization_coordinate: str
    manifest_sha256: str


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


def _reject(code: str, message: str) -> NoReturn:
    raise AdmittedRootError(code, message)


def _is_bounded_int(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _is_sha256(value: Any) -> bool:
    return type(value) is str and SHA256.fullmatch(value) is not None


def _validate_root_handle(handle: Any) -> None:
    if type(handle) is not int or handle <= 0:
        _reject("ROOT_HANDLE_INVALID", "trusted root handle must be a positive integer")


def _validate_admission(admission: Any) -> None:
    if not isinstance(admission, RootAdmission):
        _reject("ADMISSION_TYPE_INVALID", "admission must be an explicit RootAdmission record")
    if (
        type(admission.admission_id) is not str
        or not admission.admission_id
        or not _is_bounded_int(admission.generation, UINT64_MAX)
        or not _is_bounded_int(admission.root_volume_serial, UINT32_MAX)
        or not _is_bounded_int(admission.root_file_index, UINT64_MAX)
        or not _is_sha256(admission.source_coordinate)
        or not _is_sha256(admission.materialization_coordinate)
        or not _is_sha256(admission.manifest_sha256)
    ):
        _reject("ADMISSION_FIELD_INVALID", "admission fields are not exact")


def _borrowed_root_identity(handle: int) -> tuple[int, int]:
    """Return (volume serial, 64-bit file index) of a borrowed directory handle.

    Uses GetFileInformationByHandle on the caller's handle; nothing is opened,
    duplicated, or closed here.
    """

    if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
        _reject("ROOT_IDENTITY_UNAVAILABLE", "Windows handle identity is unavailable")
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError as error:
        raise AdmittedRootError(
            "ROOT_IDENTITY_UNAVAILABLE", "kernel32 is unavailable"
        ) from error
    kernel32.GetFileType.argtypes = [ctypes.c_void_p]
    kernel32.GetFileType.restype = ctypes.c_ulong
    if int(kernel32.GetFileType(ctypes.c_void_p(handle))) != FILE_TYPE_DISK:
        _reject("ROOT_NOT_DISK", "trusted root handle is not a disk object")
    kernel32.GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = ctypes.c_int
    information = _ByHandleFileInformation()
    if not kernel32.GetFileInformationByHandle(
        ctypes.c_void_p(handle), ctypes.byref(information)
    ):
        _reject(
            "ROOT_IDENTITY_UNAVAILABLE",
            f"root handle inspection failed (WinError {ctypes.get_last_error()})",
        )
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        _reject("ROOT_REPARSE_REFUSED", "trusted root handle is a reparse point")
    if not (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY):
        _reject("ROOT_NOT_DIRECTORY", "trusted root handle is not a directory")
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    return int(information.dwVolumeSerialNumber), file_index


def _duplicate_root_handle(handle: int) -> int:
    """Hold the current object behind a borrowed numeric handle for one read."""

    if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
        _reject("ROOT_DUPLICATE_UNAVAILABLE", "Windows handle duplication is unavailable")
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError as error:
        raise AdmittedRootError(
            "ROOT_DUPLICATE_UNAVAILABLE", "kernel32 is unavailable"
        ) from error
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.DuplicateHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    kernel32.DuplicateHandle.restype = ctypes.c_int
    process = kernel32.GetCurrentProcess()
    duplicate = ctypes.c_void_p()
    if not kernel32.DuplicateHandle(
        process,
        ctypes.c_void_p(handle),
        process,
        ctypes.byref(duplicate),
        0,
        False,
        DUPLICATE_SAME_ACCESS,
    ):
        _reject(
            "ROOT_HANDLE_DUPLICATE_FAILED",
            f"trusted root handle duplication failed (WinError {ctypes.get_last_error()})",
        )
    if duplicate.value is None:
        _reject("ROOT_HANDLE_DUPLICATE_FAILED", "root duplication returned a null handle")
    return int(duplicate.value)


def _close_duplicated_root_handle(handle: int) -> None:
    """Close exactly one per-read root duplicate and expose cleanup failure."""

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        closed = bool(kernel32.CloseHandle(ctypes.c_void_p(handle)))
    except (AttributeError, OSError) as error:
        raise MaterializedMemberError(
            "ROOT_HANDLE_CLOSE_FAILED",
            "duplicated root handle could not be closed",
            unclosed_handles=(handle,),
        ) from error
    if not closed:
        raise MaterializedMemberError(
            "ROOT_HANDLE_CLOSE_FAILED",
            f"duplicated root handle close failed (WinError {ctypes.get_last_error()})",
            unclosed_handles=(handle,),
        )


def _materialization_coordinate(
    source_coordinate: str, members: tuple[dict[str, Any], ...]
) -> str:
    """Consistency digest over the canonical member table and source coordinate.

    This is derived from the parsed manifest; it is not an authority input.
    """

    table = [
        {
            "path": member["path"],
            "role": member["role"],
            "sha256": member["sha256"],
            "size_bytes": member["size_bytes"],
        }
        for member in sorted(members, key=lambda member: member["path"])
    ]
    canonical = json.dumps(
        {"members": table, "source_coordinate": source_coordinate},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _check_observation(declared: dict[str, Any], observation: Any) -> None:
    """Bind the returned bytes to the requested member's own declaration."""

    if not isinstance(observation, MemberObservation):
        _reject("MEMBER_OBSERVATION_INVALID", "callback returned an invalid observation")
    if observation.kind != "REGULAR":
        _reject("MEMBER_NOT_REGULAR", "admitted member is not a regular file")
    if type(observation.content) is not bytes:
        _reject("MEMBER_CONTENT_INVALID", "admitted member content must be exact bytes")
    if len(observation.content) != declared["size_bytes"]:
        _reject("MEMBER_SIZE_MISMATCH", "observed member size differs from its declaration")
    if hashlib.sha256(observation.content).hexdigest() != declared["sha256"]:
        _reject("MEMBER_DIGEST_MISMATCH", "observed member bytes differ from its declaration")


class AdmittedRootBinding:
    """A read view over one admitted root; the root handle stays caller-owned."""

    __slots__ = (
        "_admission",
        "_manifest_bytes",
        "_members",
        "_declared",
        "_trusted_root_handle",
        "_root_identity",
        "_cancel_requested",
        "_max_member_bytes",
        "_max_total_bytes",
    )

    def __init__(
        self,
        *,
        admission: RootAdmission,
        manifest_bytes: bytes,
        members: tuple[dict[str, Any], ...],
        trusted_root_handle: int,
        root_identity: tuple[int, int],
        cancel_requested: Callable[[], bool] | None,
        max_member_bytes: int,
        max_total_bytes: int,
    ) -> None:
        self._admission = admission
        self._manifest_bytes = manifest_bytes
        self._members = members
        self._declared = {member["path"]: member for member in members}
        self._trusted_root_handle = trusted_root_handle
        self._root_identity = root_identity
        self._cancel_requested = cancel_requested
        self._max_member_bytes = max_member_bytes
        self._max_total_bytes = max_total_bytes

    @property
    def admitted_paths(self) -> tuple[str, ...]:
        return tuple(member["path"] for member in self._members)

    def read_member(self, relative: str) -> MemberObservation:
        declared = self._declared.get(relative) if type(relative) is str else None
        if declared is None:
            _reject("UNLISTED_MEMBER_REQUEST", "member was not named by the admitted declaration")
        # Duplicate first, then validate the held object.  If the caller closed
        # and the numeric value was reused, the duplicate either fails or its
        # identity differs.  Once duplicated, later changes to the caller's
        # numeric handle cannot redirect this read.
        held_root = _duplicate_root_handle(self._trusted_root_handle)
        active_error: BaseException | None = None
        try:
            if _borrowed_root_identity(held_root) != self._root_identity:
                _reject(
                    "ROOT_IDENTITY_MISMATCH",
                    "trusted root handle changed after admission",
                )
            read = exact_windows_anchored_member_reader(
                held_root,
                max_member_bytes=self._max_member_bytes,
                cancel_requested=self._cancel_requested,
            )
            observation = read(relative)
            _check_observation(declared, observation)
            return observation
        except BaseException as error:
            active_error = error
            raise
        finally:
            try:
                _close_duplicated_root_handle(held_root)
            except MaterializedMemberError as close_error:
                if active_error is None:
                    raise
                if isinstance(active_error, MaterializedMemberError):
                    active_error.unclosed_handles = tuple(
                        dict.fromkeys(
                            (*active_error.unclosed_handles, *close_error.unclosed_handles)
                        )
                    )
                else:
                    raise close_error from active_error

    def load_scope(self):
        try:
            return load_selected_source_scope(
                manifest_bytes=self._manifest_bytes,
                expected_manifest_sha256=self._admission.manifest_sha256,
                expected_source_coordinate=self._admission.source_coordinate,
                read_member=self.read_member,
                max_member_bytes=self._max_member_bytes,
                max_total_bytes=self._max_total_bytes,
            )
        except ScopeInputError as error:
            # The accepted generic reader wraps non-ScopeInputError callbacks.
            # This binding's public contract keeps adapter cancellation and
            # cleanup metadata exact, so unwrap only that known boundary.
            cause = error.__cause__
            if error.code == "MEMBER_READ_FAILED" and isinstance(
                cause, MaterializedMemberError
            ):
                raise cause
            raise


def bind_admitted_root(
    *,
    admission: RootAdmission,
    trusted_root_handle: int,
    manifest_bytes: bytes,
    current_generation: int | None,
    consumed_admission_ids: set[str] | None,
    max_member_bytes: int,
    max_total_bytes: int,
    cancel_requested: Callable[[], bool] | None = None,
) -> AdmittedRootBinding:
    """Admit a borrowed root for exact members; spends the admission on success.

    Failed attempts leave the caller-owned ledger unchanged.
    """

    _validate_root_handle(trusted_root_handle)
    _validate_admission(admission)
    if current_generation is None:
        _reject("ADMISSION_GENERATION_MISSING", "current generation must be supplied by the caller")
    if not _is_bounded_int(current_generation, UINT64_MAX):
        _reject("ADMISSION_FIELD_INVALID", "current generation must be a nonnegative integer")
    if not isinstance(consumed_admission_ids, set):
        _reject("ADMISSION_LEDGER_MISSING", "a caller-owned consumed-admission set is required")
    if admission.generation != current_generation:
        _reject("ADMISSION_STALE", "admission generation differs from the current generation")
    if admission.admission_id in consumed_admission_ids:
        _reject("ADMISSION_REUSED", "admission was already consumed")

    # The accepted parser performs the digest, source coordinate, size and
    # case-fold collision checks before any member I/O.
    source_coordinate, members = _parse_manifest(
        manifest_bytes,
        expected_manifest_sha256=admission.manifest_sha256,
        expected_source_coordinate=admission.source_coordinate,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
    )
    if _materialization_coordinate(source_coordinate, members) != admission.materialization_coordinate:
        _reject(
            "MATERIALIZATION_COORDINATE_MISMATCH",
            "materialization differs from the admitted coordinate",
        )
    root_identity = _borrowed_root_identity(trusted_root_handle)
    if root_identity != (
        admission.root_volume_serial,
        admission.root_file_index,
    ):
        _reject("ROOT_IDENTITY_MISMATCH", "trusted root handle differs from the admitted root")

    binding = AdmittedRootBinding(
        admission=admission,
        manifest_bytes=manifest_bytes,
        members=members,
        trusted_root_handle=trusted_root_handle,
        root_identity=root_identity,
        cancel_requested=cancel_requested,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
    )
    consumed_admission_ids.add(admission.admission_id)
    return binding


__all__ = [
    "AdmittedRootBinding",
    "AdmittedRootError",
    "RootAdmission",
    "bind_admitted_root",
]
