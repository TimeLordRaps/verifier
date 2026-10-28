"""Exact-path filesystem adapter for the selected-source callback contract.

This module never discovers members.  It receives one already validated relative
path, checks only that path and its exact parent chain, and returns exact bytes.
Paths must be Unicode scalar text in Unicode Normalization Form C (NFC); the
adapter rejects noncanonical text rather than normalizing or rewriting it.
Reading additionally requires a reviewed anchored-open capability.  No such
capability is currently implemented here, so the production path fails closed
before opening a file instead of falling back to pathname-based ``os.open``.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
from typing import Callable
import unicodedata

if __package__:
    from .exact_source_scope import MemberObservation
else:  # Preserve the documented direct-script import surface.
    from exact_source_scope import MemberObservation


WINDOWS_REPARSE_POINT = 0x400
READ_CHUNK_BYTES = 64 * 1024


class MaterializedMemberError(OSError):
    """A fail-closed exact-path adapter error with a stable code."""

    __slots__ = ("code", "unclosed_handles")

    def __init__(
        self, code: str, message: str, *, unclosed_handles: tuple[int, ...] = ()
    ) -> None:
        super().__init__(message)
        self.code = code
        self.unclosed_handles = unclosed_handles


def _reject(code: str, message: str) -> None:
    raise MaterializedMemberError(code, message)


def _canonical_parts(value: str) -> tuple[str, ...]:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        _reject("MEMBER_PATH_INVALID", "member path is not canonical relative text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise MaterializedMemberError(
            "MEMBER_PATH_INVALID", "member path is not Unicode scalar text"
        ) from error
    if unicodedata.normalize("NFC", value) != value:
        _reject("MEMBER_PATH_INVALID", "member path is not NFC-normalized text")
    if value.startswith("/") or ":" in value:
        _reject("MEMBER_PATH_INVALID", "member path is absolute or drive-qualified")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        _reject("MEMBER_PATH_INVALID", "member path is noncanonical or traversing")
    return path.parts


def _is_link_or_reparse(metadata: object) -> bool:
    mode = getattr(metadata, "st_mode", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(mode) or bool(attributes & WINDOWS_REPARSE_POINT)


def _identity(metadata: object) -> tuple[int, int]:
    return (int(getattr(metadata, "st_dev", -1)), int(getattr(metadata, "st_ino", -1)))


def _snapshot(metadata: object) -> tuple[int, int, int, int, int]:
    return (
        *_identity(metadata),
        int(getattr(metadata, "st_size", -1)),
        int(getattr(metadata, "st_mtime_ns", -1)),
        int(getattr(metadata, "st_ctime_ns", -1)),
    )


def _open_anchored_member(root: Path, parts: tuple[str, ...]) -> int:
    """Open a member without re-resolving unpinned parent pathnames.

    A portable Python implementation is deliberately not supplied.  In
    particular, a final-component ``O_NOFOLLOW`` flag would not anchor the
    parent chain, and the current Windows runtime supplies no ``O_NOFOLLOW`` at
    all.  Tests may replace this private boundary with an explicit synthetic
    opener; production callers receive a fail-closed refusal.
    """

    _reject(
        "ANCHORED_OPEN_UNAVAILABLE",
        "no reviewed anchored no-follow member-open capability is available",
    )


def _lstat(path: Path, *, missing_code: str) -> object:
    try:
        return os.lstat(path)
    except FileNotFoundError as error:
        raise MaterializedMemberError(missing_code, "selected path is unavailable") from error
    except OSError as error:
        raise MaterializedMemberError("MEMBER_INSPECTION_FAILED", "exact path inspection failed") from error


def _inspect_parent_chain(root: Path, parts: tuple[str, ...]) -> None:
    current = root
    parents = (root, *(root.joinpath(*parts[:index]) for index in range(1, len(parts))))
    for current in parents:
        metadata = _lstat(current, missing_code="MEMBER_MISSING")
        if _is_link_or_reparse(metadata):
            _reject("PATH_COMPONENT_LINK", "root or parent component is a link or reparse point")
        if not stat.S_ISDIR(getattr(metadata, "st_mode", 0)):
            _reject("PATH_COMPONENT_NOT_DIRECTORY", "root or parent component is not a directory")


def exact_materialized_member_reader(
    root: Path,
    *,
    max_member_bytes: int,
) -> Callable[[str], MemberObservation]:
    """Return a callback that reads only an explicitly supplied member path."""

    if type(max_member_bytes) is not int or isinstance(max_member_bytes, bool) or max_member_bytes < 0:
        _reject("BYTE_BOUND_INVALID", "member byte bound must be a nonnegative integer")
    root_path = Path(os.path.abspath(os.fspath(root)))

    def read_member(relative: str) -> MemberObservation:
        parts = _canonical_parts(relative)
        _inspect_parent_chain(root_path, parts)
        target = root_path.joinpath(*parts)
        before_path = _lstat(target, missing_code="MEMBER_MISSING")
        if _is_link_or_reparse(before_path):
            _reject("TARGET_LINK", "selected target is a link or reparse point")
        if not stat.S_ISREG(getattr(before_path, "st_mode", 0)):
            _reject("TARGET_NOT_REGULAR", "selected target is not a regular file")
        if int(getattr(before_path, "st_size", -1)) > max_member_bytes:
            _reject("MEMBER_SIZE_LIMIT", "selected target exceeds its byte bound")

        try:
            descriptor = _open_anchored_member(root_path, parts)
        except MaterializedMemberError:
            raise
        except FileNotFoundError as error:
            raise MaterializedMemberError("MEMBER_MISSING", "selected target vanished") from error
        except OSError as error:
            raise MaterializedMemberError("MEMBER_OPEN_FAILED", "exact target open failed") from error

        try:
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(before_path):
                _reject("MEMBER_IDENTITY_CHANGED", "target identity changed before open")
            if not stat.S_ISREG(getattr(opened, "st_mode", 0)):
                _reject("TARGET_NOT_REGULAR", "opened target is not a regular file")
            opened_size = int(getattr(opened, "st_size", -1))
            if opened_size > max_member_bytes:
                _reject("MEMBER_SIZE_LIMIT", "opened target exceeds its byte bound")

            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = max_member_bytes - total
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_member_bytes:
                    _reject("MEMBER_SIZE_LIMIT", "streamed target exceeds its byte bound")
                chunks.append(chunk)
            if total != opened_size:
                _reject("MEMBER_TRUNCATED_READ", "streamed byte count differs from opened size")

            after_handle = os.fstat(descriptor)
            if _snapshot(after_handle) != _snapshot(opened):
                _reject("MEMBER_CHANGED_DURING_READ", "opened target metadata changed during read")
            after_path = _lstat(target, missing_code="MEMBER_CHANGED_DURING_READ")
            if _is_link_or_reparse(after_path):
                _reject("MEMBER_CHANGED_DURING_READ", "target became a link during read")
            if _snapshot(after_path) != _snapshot(before_path):
                _reject("MEMBER_CHANGED_DURING_READ", "target path changed during read")
            return MemberObservation(kind="REGULAR", content=b"".join(chunks))
        finally:
            os.close(descriptor)

    return read_member


def _read_cancelled(cancel_requested: Callable[[], bool] | None) -> None:
    if cancel_requested is None:
        return
    try:
        result = cancel_requested()
    except Exception as error:
        raise MaterializedMemberError(
            "ANCHORED_CANCEL_CHECK_FAILED", "read cancellation predicate failed"
        ) from error
    if type(result) is not bool:
        _reject("ANCHORED_CANCEL_CHECK_FAILED", "read cancellation predicate did not return bool")
    if result:
        _reject("ANCHORED_READ_CANCELLED", "anchored member read was cancelled")


def exact_windows_anchored_member_reader(
    trusted_root_handle: int,
    *,
    max_member_bytes: int,
    cancel_requested: Callable[[], bool] | None = None,
) -> Callable[[str], MemberObservation]:
    """Read exact members relative to a caller-supplied trusted Windows handle.

    This is a separate capability entry point.  The pathname-based production
    entry point remains fail-closed and this function never calls ``lstat`` or
    ``os.open``.
    """

    if type(max_member_bytes) is not int or isinstance(max_member_bytes, bool) or max_member_bytes < 0:
        _reject("BYTE_BOUND_INVALID", "member byte bound must be a nonnegative integer")

    def read_member(relative: str) -> MemberObservation:
        parts = _canonical_parts(relative)
        try:
            if __package__:
                from .windows_anchored_member import AnchoredOpenError, open_anchored_member
            else:
                from windows_anchored_member import AnchoredOpenError, open_anchored_member
        except (ImportError, AttributeError) as error:
            raise MaterializedMemberError(
                "ANCHORED_OPEN_UNAVAILABLE", "Windows anchored opener is unavailable"
            ) from error
        try:
            descriptor = open_anchored_member(
                trusted_root_handle,
                parts,
                cancel_requested=cancel_requested,
            )
        except AnchoredOpenError as error:
            raise MaterializedMemberError(
                error.code,
                str(error),
                unclosed_handles=error.unclosed_handles,
            ) from error

        active_error: BaseException | None = None
        try:
            _read_cancelled(cancel_requested)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(getattr(opened, "st_mode", 0)):
                _reject("TARGET_NOT_REGULAR", "anchored target is not a regular file")
            opened_size = int(getattr(opened, "st_size", -1))
            if opened_size > max_member_bytes:
                _reject("MEMBER_SIZE_LIMIT", "anchored target exceeds its byte bound")

            chunks: list[bytes] = []
            total = 0
            while True:
                _read_cancelled(cancel_requested)
                remaining = max_member_bytes - total
                chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_member_bytes:
                    _reject("MEMBER_SIZE_LIMIT", "anchored stream exceeds its byte bound")
                chunks.append(chunk)
            if total != opened_size:
                _reject("MEMBER_TRUNCATED_READ", "anchored byte count differs from opened size")

            after_handle = os.fstat(descriptor)
            if _snapshot(after_handle) != _snapshot(opened):
                _reject("MEMBER_CHANGED_DURING_READ", "anchored target metadata changed during read")
            return MemberObservation(kind="REGULAR", content=b"".join(chunks))
        except BaseException as error:
            active_error = error
            raise
        finally:
            try:
                os.close(descriptor)
            except Exception as close_error:
                if isinstance(active_error, MaterializedMemberError):
                    active_error.unclosed_handles = tuple(
                        dict.fromkeys((*active_error.unclosed_handles, descriptor))
                    )
                else:
                    failure = MaterializedMemberError(
                        "MEMBER_CLOSE_FAILED",
                        "anchored descriptor close failed",
                        unclosed_handles=(descriptor,),
                    )
                    if active_error is not None:
                        failure.add_note(f"read path also raised: {active_error!r}")
                    raise failure from close_error

    return read_member


__all__ = [
    "MaterializedMemberError",
    "exact_materialized_member_reader",
    "exact_windows_anchored_member_reader",
]
