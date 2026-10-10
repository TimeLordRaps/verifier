"""Windows handle-relative opener for one already selected member.

The caller supplies a trusted directory handle.  This module never derives the
root from a path and has no pathname fallback.
Every component must be Unicode scalar text in Unicode Normalization Form C
(NFC); invalid or noncanonical text is refused before a native operation.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import sys
from typing import Callable, Protocol
import unicodedata


FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_TYPE_DISK = 0x0001
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9

FILE_READ_DATA = 0x00000001
FILE_TRAVERSE = 0x00000020
FILE_READ_ATTRIBUTES = 0x00000080
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_OPEN = 0x00000001
FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000
OBJ_CASE_INSENSITIVE = 0x00000040
DUPLICATE_SAME_ACCESS = 0x00000002


class AnchoredOpenError(OSError):
    """A stable fail-closed error from anchored member opening."""

    __slots__ = ("code", "unclosed_handles")

    def __init__(
        self, code: str, message: str, *, unclosed_handles: tuple[int, ...] = ()
    ) -> None:
        super().__init__(message)
        self.code = code
        self.unclosed_handles = unclosed_handles


@dataclass(frozen=True)
class HandleInfo:
    is_disk: bool
    is_directory: bool
    is_reparse: bool


class _Backend(Protocol):
    def duplicate_handle(self, handle: int) -> int: ...

    def inspect_handle(self, handle: int) -> HandleInfo: ...

    def open_relative(self, parent: int, component: str, *, directory: bool) -> int: ...

    def handle_to_fd(self, handle: int) -> int: ...

    def close_handle(self, handle: int) -> None: ...


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.POINTER(ctypes.c_wchar)),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", ctypes.c_ulong),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IO_STATUS_VALUE(ctypes.Union):
    _fields_ = [("Status", ctypes.c_long), ("Pointer", ctypes.c_void_p)]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("value", _IO_STATUS_VALUE), ("Information", ctypes.c_size_t)]


class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", ctypes.c_ulong), ("ReparseTag", ctypes.c_ulong)]


class _WindowsNativeBackend:
    def __init__(self) -> None:
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            raise AnchoredOpenError(
                "ANCHORED_OPEN_UNAVAILABLE", "Windows native interfaces are unavailable"
            )
        try:
            import msvcrt

            self._msvcrt = msvcrt
            self._ntdll = ctypes.WinDLL("ntdll")
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._configure_signatures()
        except (AttributeError, ImportError, OSError) as error:
            raise AnchoredOpenError(
                "ANCHORED_OPEN_UNAVAILABLE", "required Windows interfaces are unavailable"
            ) from error

    def _configure_signatures(self) -> None:
        self._ntdll.NtCreateFile.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.POINTER(_OBJECT_ATTRIBUTES),
            ctypes.POINTER(_IO_STATUS_BLOCK),
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        self._ntdll.NtCreateFile.restype = ctypes.c_long
        self._ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_long]
        self._ntdll.RtlNtStatusToDosError.restype = ctypes.c_ulong
        self._kernel32.GetCurrentProcess.argtypes = []
        self._kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        self._kernel32.DuplicateHandle.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_ulong,
        ]
        self._kernel32.DuplicateHandle.restype = ctypes.c_int
        self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel32.CloseHandle.restype = ctypes.c_int
        self._kernel32.GetFileInformationByHandleEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        self._kernel32.GetFileInformationByHandleEx.restype = ctypes.c_int
        self._kernel32.GetFileType.argtypes = [ctypes.c_void_p]
        self._kernel32.GetFileType.restype = ctypes.c_ulong

    @staticmethod
    def _last_error(message: str) -> OSError:
        number = ctypes.get_last_error()
        return OSError(number, f"{message} (WinError {number})")

    def duplicate_handle(self, handle: int) -> int:
        process = self._kernel32.GetCurrentProcess()
        duplicate = ctypes.c_void_p()
        if not self._kernel32.DuplicateHandle(
            process,
            ctypes.c_void_p(handle),
            process,
            ctypes.byref(duplicate),
            0,
            False,
            DUPLICATE_SAME_ACCESS,
        ):
            raise self._last_error("DuplicateHandle failed")
        if duplicate.value is None:
            raise OSError("DuplicateHandle returned a null handle")
        return int(duplicate.value)

    def inspect_handle(self, handle: int) -> HandleInfo:
        file_type = int(self._kernel32.GetFileType(ctypes.c_void_p(handle)))
        if file_type != FILE_TYPE_DISK:
            raise OSError(f"handle is not a disk object (type {file_type})")
        details = _FILE_ATTRIBUTE_TAG_INFO()
        if not self._kernel32.GetFileInformationByHandleEx(
            ctypes.c_void_p(handle),
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(details),
            ctypes.sizeof(details),
        ):
            raise self._last_error("GetFileInformationByHandleEx failed")
        attributes = int(details.FileAttributes)
        return HandleInfo(
            is_disk=True,
            is_directory=bool(attributes & FILE_ATTRIBUTE_DIRECTORY),
            is_reparse=bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT),
        )

    def open_relative(self, parent: int, component: str, *, directory: bool) -> int:
        encoded = component.encode("utf-16-le", "strict")
        buffer = ctypes.create_string_buffer(encoded + b"\x00\x00")
        name = _UNICODE_STRING(
            Length=len(encoded),
            MaximumLength=len(encoded) + 2,
            Buffer=ctypes.cast(buffer, ctypes.POINTER(ctypes.c_wchar)),
        )
        attributes = _OBJECT_ATTRIBUTES(
            Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
            RootDirectory=ctypes.c_void_p(parent),
            ObjectName=ctypes.pointer(name),
            Attributes=OBJ_CASE_INSENSITIVE,
            SecurityDescriptor=None,
            SecurityQualityOfService=None,
        )
        result = ctypes.c_void_p()
        io_status = _IO_STATUS_BLOCK()
        desired_access = FILE_READ_ATTRIBUTES | SYNCHRONIZE
        options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        if directory:
            desired_access |= FILE_TRAVERSE
            options |= FILE_DIRECTORY_FILE
        else:
            desired_access |= FILE_READ_DATA
            options |= FILE_NON_DIRECTORY_FILE
        status = int(
            self._ntdll.NtCreateFile(
                ctypes.byref(result),
                desired_access,
                ctypes.byref(attributes),
                ctypes.byref(io_status),
                None,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                options,
                None,
                0,
            )
        )
        if status < 0 or result.value is None:
            win_error = int(self._ntdll.RtlNtStatusToDosError(status))
            raise OSError(win_error, f"NtCreateFile failed (NTSTATUS 0x{status & 0xFFFFFFFF:08x})")
        return int(result.value)

    def handle_to_fd(self, handle: int) -> int:
        return int(self._msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY))

    def close_handle(self, handle: int) -> None:
        if not self._kernel32.CloseHandle(ctypes.c_void_p(handle)):
            raise self._last_error("CloseHandle failed")


def _reject(code: str, message: str) -> None:
    raise AnchoredOpenError(code, message)


def _validate_inputs(root_handle: int, parts: tuple[str, ...]) -> None:
    if type(root_handle) is not int or isinstance(root_handle, bool) or root_handle <= 0:
        _reject("ANCHORED_ROOT_HANDLE_INVALID", "trusted root handle must be a positive integer")
    if type(parts) is not tuple or not parts:
        _reject("ANCHORED_COMPONENT_INVALID", "member components must be a nonempty tuple")
    for component in parts:
        if type(component) is not str or not component:
            _reject("ANCHORED_COMPONENT_INVALID", "member component is not canonical")
        try:
            encoded = component.encode("utf-16-le", "strict")
        except UnicodeEncodeError as error:
            raise AnchoredOpenError(
                "ANCHORED_COMPONENT_INVALID", "member component is not valid UTF-16"
            ) from error
        if (
            component in {".", ".."}
            or unicodedata.normalize("NFC", component) != component
            or any(character in component for character in ("/", "\\", ":", "\x00"))
            or len(encoded) // 2 > 255
        ):
            _reject("ANCHORED_COMPONENT_INVALID", "member component is not canonical")


def _is_cancelled(cancel_requested: Callable[[], bool]) -> bool:
    try:
        result = cancel_requested()
    except Exception as error:
        raise AnchoredOpenError(
            "ANCHORED_CANCEL_CHECK_FAILED", "cancellation predicate failed"
        ) from error
    if type(result) is not bool:
        _reject("ANCHORED_CANCEL_CHECK_FAILED", "cancellation predicate did not return bool")
    return result


def _call(code: str, message: str, action: Callable[[], object]) -> object:
    try:
        return action()
    except AnchoredOpenError:
        raise
    except Exception as error:
        raise AnchoredOpenError(code, message) from error


def open_anchored_member(
    trusted_root_handle: int,
    parts: tuple[str, ...],
    *,
    cancel_requested: Callable[[], bool] | None = None,
    _backend: _Backend | None = None,
) -> int:
    """Return an owned descriptor for a no-follow, handle-relative member."""

    _validate_inputs(trusted_root_handle, parts)
    cancellation = cancel_requested if cancel_requested is not None else (lambda: False)
    if _is_cancelled(cancellation):
        _reject("ANCHORED_OPEN_CANCELLED", "member open was cancelled before duplication")
    backend = _backend if _backend is not None else _WindowsNativeBackend()
    owned: list[int] = []
    try:
        current = int(
            _call(
                "ANCHORED_DUPLICATE_FAILED",
                "trusted root handle duplication failed",
                lambda: backend.duplicate_handle(trusted_root_handle),
            )
        )
        owned.append(current)
        root_info = _call(
            "ANCHORED_INSPECT_FAILED",
            "trusted root handle inspection failed",
            lambda: backend.inspect_handle(current),
        )
        if root_info.is_reparse:
            _reject("ANCHORED_REPARSE_REFUSED", "trusted root handle is a reparse point")
        if not root_info.is_disk or not root_info.is_directory:
            _reject("ANCHORED_ROOT_NOT_DIRECTORY", "trusted root handle is not a disk directory")

        for index, component in enumerate(parts):
            directory = index < len(parts) - 1
            if _is_cancelled(cancellation):
                _reject("ANCHORED_OPEN_CANCELLED", "member open was cancelled before traversal")
            child = int(
                _call(
                    "ANCHORED_OPEN_FAILED",
                    "relative component open failed",
                    lambda: backend.open_relative(current, component, directory=directory),
                )
            )
            owned.append(child)
            if _is_cancelled(cancellation):
                _reject("ANCHORED_OPEN_CANCELLED", "member open was cancelled after traversal")
            child_info = _call(
                "ANCHORED_INSPECT_FAILED",
                "relative component inspection failed",
                lambda: backend.inspect_handle(child),
            )
            if child_info.is_reparse:
                _reject("ANCHORED_REPARSE_REFUSED", "relative component is a reparse point")
            if not child_info.is_disk:
                _reject("ANCHORED_NOT_DISK", "relative component is not a disk object")
            if directory and not child_info.is_directory:
                _reject("ANCHORED_PARENT_NOT_DIRECTORY", "relative parent is not a directory")
            if not directory and child_info.is_directory:
                _reject("ANCHORED_LEAF_NOT_FILE", "relative leaf is a directory")

            owned.remove(current)
            try:
                backend.close_handle(current)
            except Exception as error:
                raise AnchoredOpenError(
                    "ANCHORED_CLOSE_FAILED",
                    "previous parent handle close failed",
                    unclosed_handles=(current,),
                ) from error
            current = child

        if _is_cancelled(cancellation):
            _reject("ANCHORED_OPEN_CANCELLED", "member open was cancelled before transfer")
        descriptor = int(
            _call(
                "ANCHORED_CONVERT_FAILED",
                "final handle transfer failed",
                lambda: backend.handle_to_fd(current),
            )
        )
        owned.remove(current)
        return descriptor
    finally:
        cleanup_error: Exception | None = None
        cleanup_failed: list[int] = []
        active_error = sys.exc_info()[1]
        for handle in reversed(owned):
            try:
                backend.close_handle(handle)
            except Exception as error:
                cleanup_failed.append(handle)
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_failed:
            if isinstance(active_error, AnchoredOpenError):
                active_error.unclosed_handles = tuple(
                    dict.fromkeys((*active_error.unclosed_handles, *cleanup_failed))
                )
            elif active_error is None:
                raise AnchoredOpenError(
                    "ANCHORED_CLOSE_FAILED",
                    "owned handle cleanup failed",
                    unclosed_handles=tuple(cleanup_failed),
                ) from cleanup_error


__all__ = ["AnchoredOpenError", "HandleInfo", "open_anchored_member"]
