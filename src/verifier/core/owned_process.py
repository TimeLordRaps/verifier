# Terminology: signal kill (SIGKILL).
"""Bounded, stdlib-only ownership for one subprocess tree.

The primitive owns an entire process tree, not merely the direct child.  On
Windows the child is created suspended and assigned to a kill-on-close Job
Object before any user code runs.  On POSIX the child leads a new process
group.  Every return or exceptional exit terminates the owned tree and reports
whether emptiness was positively confirmed.

This is a process-lifetime and stream-retention boundary.  It does not provide
filesystem, network, syscall, or hostile-host isolation.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from typing import Any, Callable, Mapping, Optional, Sequence


CLEANUP_CONFIRMED = "CONFIRMED"
CLEANUP_NOT_CONFIRMED = "NOT_CONFIRMED"
CLEANUP_UNKNOWN = "UNKNOWN"

STATUS_EXITED = "EXITED"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_OUTPUT_CAP = "OUTPUT_CAP"

_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_DEFAULT_CLEANUP_SECONDS = 5.0
_DEFAULT_POLL_SECONDS = 0.01


@dataclass(frozen=True)
class OwnedProcessResult:
    """One bounded observation; only EXITED+CONFIRMED can attest completion."""

    status: str
    cleanup: str
    returncode: Optional[int]
    stdout: bytes
    stderr: bytes
    stdout_overflowed: bool
    stderr_overflowed: bool

    @property
    def streams_complete(self) -> bool:
        return (
            self.status == STATUS_EXITED
            and not self.stdout_overflowed
            and not self.stderr_overflowed
        )


class OwnedProcessAbort(BaseException):
    """Carries cleanup evidence while preserving an exceptional control flow.

    Callers must record ``result`` and then re-raise ``cause``.  In particular,
    KeyboardInterrupt and SystemExit are never converted into timeout.
    """

    def __init__(self, cause: BaseException, result: OwnedProcessResult) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.result = result


def _windows_job_api() -> tuple[Any, Any, Any]:
    from ctypes import wintypes

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("per_process_user_time_limit", ctypes.c_longlong),
            ("per_job_user_time_limit", ctypes.c_longlong),
            ("limit_flags", wintypes.DWORD),
            ("minimum_working_set_size", ctypes.c_size_t),
            ("maximum_working_set_size", ctypes.c_size_t),
            ("active_process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority_class", wintypes.DWORD),
            ("scheduling_class", wintypes.DWORD),
        ]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimit),
            ("io_counters", ctypes.c_ulonglong * 6),
            ("process_memory_limit", ctypes.c_size_t),
            ("job_memory_limit", ctypes.c_size_t),
            ("peak_process_memory_used", ctypes.c_size_t),
            ("peak_job_memory_used", ctypes.c_size_t),
        ]

    class Accounting(ctypes.Structure):
        _fields_ = [
            ("times", ctypes.c_longlong * 4),
            ("page_faults", wintypes.DWORD),
            ("total_processes", wintypes.DWORD),
            ("active_processes", wintypes.DWORD),
            ("terminated_processes", wintypes.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
        "SetInformationJobObject": (
            [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
            wintypes.BOOL,
        ),
        "QueryInformationJobObject": (
            [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p],
            wintypes.BOOL,
        ),
        "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        "ResumeThread": ([wintypes.HANDLE], wintypes.DWORD),
        "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
    }
    for name, (argtypes, restype) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = argtypes, restype
    return kernel, ExtendedLimit, Accounting


class WindowsOwnedTree:
    """A child assigned to one kill-on-close Job Object before it runs."""

    def __init__(self, cleanup_seconds: float) -> None:
        self._cleanup_seconds = cleanup_seconds
        self._process: Optional[int] = None
        self._thread: Optional[int] = None
        self._job: Optional[int] = None
        self._kernel, extended_type, self._accounting_type = _windows_job_api()
        self._job = self._kernel.CreateJobObjectW(None, None)
        if not self._job:
            raise OSError("owned Job Object creation unavailable")
        limits = extended_type()
        limits.basic.limit_flags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self._kernel.SetInformationJobObject(
            self._job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self.close()
            raise OSError("owned Job Object kill-on-close limit unavailable")

    def launch(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        stdin: Any,
        stdout: Any,
        stderr: Any,
    ) -> None:
        import _winapi
        import msvcrt

        inherited = [
            msvcrt.get_osfhandle(stdin.fileno()),
            msvcrt.get_osfhandle(stdout.fileno()),
            msvcrt.get_osfhandle(stderr.fileno()),
        ]
        previous = [os.get_handle_inheritable(handle) for handle in inherited]
        try:
            for handle in inherited:
                os.set_handle_inheritable(handle, True)
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = subprocess.STARTF_USESTDHANDLES
            startup.hStdInput, startup.hStdOutput, startup.hStdError = inherited
            startup.lpAttributeList = {"handle_list": inherited}
            process, thread, _process_id, _thread_id = _winapi.CreateProcess(
                None,
                subprocess.list2cmdline(list(argv)),
                None,
                None,
                True,
                _CREATE_SUSPENDED,
                dict(environment),
                str(cwd),
                startup,
            )
        finally:
            for handle, was_inheritable in zip(inherited, previous):
                os.set_handle_inheritable(handle, was_inheritable)
        self._process, self._thread = process, thread
        if not self._kernel.AssignProcessToJobObject(self._job, process):
            _winapi.TerminateProcess(process, 1)
            _winapi.WaitForSingleObject(process, int(self._cleanup_seconds * 1000))
            raise OSError("suspended child could not join owned Job Object")
        if self._kernel.ResumeThread(thread) != 1:
            self.terminate_owned()
            raise OSError("owned child primary thread was not resumed exactly once")
        self._kernel.CloseHandle(thread)
        self._thread = None

    def direct_child_exited(self) -> bool:
        import _winapi

        return (
            self._process is not None
            and _winapi.WaitForSingleObject(self._process, 0) == 0
        )

    def returncode(self) -> Optional[int]:
        import _winapi

        if self._process is None or not self.direct_child_exited():
            return None
        return int(_winapi.GetExitCodeProcess(self._process))

    def terminate_owned(self) -> bool:
        import _winapi

        if self._job is None or not self._kernel.TerminateJobObject(self._job, 1):
            return False
        if self._process is None:
            return True
        return (
            _winapi.WaitForSingleObject(
                self._process, int(self._cleanup_seconds * 1000)
            )
            == 0
        )

    def owned_members_remain(self) -> Optional[bool]:
        if self._job is None:
            return False
        accounting = self._accounting_type()
        if not self._kernel.QueryInformationJobObject(
            self._job,
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        ):
            return None
        return accounting.active_processes > 0

    def close(self) -> None:
        import _winapi

        if self._thread is not None:
            self._kernel.CloseHandle(self._thread)
            self._thread = None
        if self._process is not None:
            _winapi.CloseHandle(self._process)
            self._process = None
        if self._job is not None:
            self._kernel.CloseHandle(self._job)
            self._job = None


class PosixOwnedTree:
    """A child leading a new session and process group."""

    def __init__(self, cleanup_seconds: float) -> None:
        self._cleanup_seconds = cleanup_seconds
        self._popen: Optional[subprocess.Popen[bytes]] = None

    def launch(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        stdin: Any,
        stdout: Any,
        stderr: Any,
    ) -> None:
        self._popen = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            env=dict(environment),
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            start_new_session=True,
        )

    def direct_child_exited(self) -> bool:
        if self._popen is None:
            return False
        if self._popen.returncode is not None:
            return True
        waitid = getattr(os, "waitid", None)
        if waitid is None:
            return self._popen.poll() is not None
        return (
            waitid(
                os.P_PID,
                self._popen.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
            is not None
        )

    def returncode(self) -> Optional[int]:
        return None if self._popen is None else self._popen.returncode

    def terminate_owned(self) -> bool:
        if self._popen is None:
            return True
        try:
            os.killpg(self._popen.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            return False
        try:
            self._popen.wait(timeout=self._cleanup_seconds)
        except subprocess.TimeoutExpired:
            return False
        return True

    def owned_members_remain(self) -> Optional[bool]:
        if self._popen is None:
            return False
        try:
            os.killpg(self._popen.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return None
        return True

    def close(self) -> None:
        # Second guard for exceptional paths: a caller closing the owner may not
        # leave a still-running group merely because observation failed.
        if self._popen is not None and self._popen.poll() is None:
            try:
                os.killpg(self._popen.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self._popen.wait(timeout=self._cleanup_seconds)
            except subprocess.TimeoutExpired:
                pass


def _poll_pause() -> None:
    time.sleep(_DEFAULT_POLL_SECONDS)


def _file_size(path: Path) -> int:
    return path.stat().st_size


def _read_prefix(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def _await_child_end(
    tree: Any,
    out_path: Path,
    err_path: Path,
    deadline: float,
    stdout_limit: int,
    stderr_limit: int,
    poll_callback: Callable[[], None] = _poll_pause,
) -> str:
    while True:
        if tree.direct_child_exited():
            return STATUS_EXITED
        if time.monotonic() >= deadline:
            return STATUS_TIMEOUT
        if _file_size(out_path) > stdout_limit or _file_size(err_path) > stderr_limit:
            return STATUS_OUTPUT_CAP
        poll_callback()


def _confirm_empty(tree: Any, cleanup_seconds: float, poll_seconds: float) -> str:
    deadline = time.monotonic() + cleanup_seconds
    while True:
        remaining = tree.owned_members_remain()
        if remaining is False:
            return CLEANUP_CONFIRMED
        if time.monotonic() >= deadline:
            return CLEANUP_NOT_CONFIRMED if remaining is True else CLEANUP_UNKNOWN
        time.sleep(poll_seconds)


def _terminate(
    tree: Any,
    cleanup_seconds: float,
    poll_seconds: float,
    confirm_empty: Callable[[Any], str] | None = None,
) -> str:
    if not tree.terminate_owned():
        return CLEANUP_UNKNOWN
    if confirm_empty is not None:
        return confirm_empty(tree)
    return _confirm_empty(tree, cleanup_seconds, poll_seconds)


def run_owned_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    stdin: bytes,
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    cleanup_seconds: float = _DEFAULT_CLEANUP_SECONDS,
    poll_seconds: float = _DEFAULT_POLL_SECONDS,
    tree_factory: Callable[[float], Any] | None = None,
    poll_callback: Callable[[], None] | None = None,
    confirm_empty: Callable[[Any], str] | None = None,
    wait_for_end: Callable[[Any, Path, Path, float, int, int, Callable[[], None]], str] | None = None,
) -> OwnedProcessResult:
    """Run one argv in an owned tree and retain bounded stream prefixes.

    ``stdout`` and ``stderr`` contain at most their respective limits.  Separate
    overflow flags prevent a retained prefix from being mistaken for a complete
    stream.  The environment and stdin are explicit; no ambient stdin is
    inherited and no shell is involved.
    """

    checked_argv = tuple(argv)
    if (
        not checked_argv
        or any(type(value) is not str or "\x00" in value for value in checked_argv)
        or type(stdin) is not bytes
        or type(timeout_seconds) not in {int, float}
        or timeout_seconds <= 0
        or type(stdout_limit) is not int
        or stdout_limit < 0
        or type(stderr_limit) is not int
        or stderr_limit < 0
        or type(cleanup_seconds) not in {int, float}
        or cleanup_seconds <= 0
        or type(poll_seconds) not in {int, float}
        or poll_seconds <= 0
    ):
        raise ValueError("OWNED_PROCESS_ARGUMENT_INVALID")
    checked_cwd = Path(cwd).resolve(strict=True)
    checked_environment = dict(environment)
    if any(type(key) is not str or type(value) is not str for key, value in checked_environment.items()):
        raise ValueError("OWNED_PROCESS_ENVIRONMENT_INVALID")
    if tree_factory is None:
        tree_factory = WindowsOwnedTree if os.name == "nt" else PosixOwnedTree
    if poll_callback is None:
        poll_callback = _poll_pause
    tree = tree_factory(float(cleanup_seconds))
    with tempfile.TemporaryDirectory(
        prefix="vstd-owned-process-", ignore_cleanup_errors=True
    ) as folder:
        folder_path = Path(folder)
        in_path = folder_path / "stdin.bin"
        out_path = folder_path / "stdout.bin"
        err_path = folder_path / "stderr.bin"
        in_path.write_bytes(stdin)
        out_path.write_bytes(b"")
        err_path.write_bytes(b"")
        ended: str | None = None
        try:
            with (
                in_path.open("rb") as in_stream,
                out_path.open("wb") as out_stream,
                err_path.open("wb") as err_stream,
            ):
                tree.launch(
                    checked_argv,
                    checked_cwd,
                    checked_environment,
                    in_stream,
                    out_stream,
                    err_stream,
                )
                deadline = time.monotonic() + float(timeout_seconds)
                ended = (
                    _await_child_end(
                        tree,
                        out_path,
                        err_path,
                        deadline,
                        stdout_limit,
                        stderr_limit,
                        poll_callback,
                    )
                    if wait_for_end is None
                    else wait_for_end(
                        tree,
                        out_path,
                        err_path,
                        deadline,
                        stdout_limit,
                        stderr_limit,
                        poll_callback,
                    )
                )
        except BaseException as exc:
            cleanup = CLEANUP_UNKNOWN
            try:
                cleanup = _terminate(
                    tree,
                    float(cleanup_seconds),
                    float(poll_seconds),
                    confirm_empty,
                )
            except BaseException:
                # The original interruption/internal fault remains primary.
                # close() is still the Windows kill-on-close/POSIX second guard.
                pass
            finally:
                try:
                    tree.close()
                except BaseException:
                    cleanup = CLEANUP_UNKNOWN
            stdout_overflowed = _file_size(out_path) > stdout_limit
            stderr_overflowed = _file_size(err_path) > stderr_limit
            result = OwnedProcessResult(
                status="ABORTED",
                cleanup=cleanup,
                returncode=None,
                stdout=_read_prefix(out_path, stdout_limit),
                stderr=_read_prefix(err_path, stderr_limit),
                stdout_overflowed=stdout_overflowed,
                stderr_overflowed=stderr_overflowed,
            )
            raise OwnedProcessAbort(exc, result) from exc

        try:
            cleanup = _terminate(
                tree,
                float(cleanup_seconds),
                float(poll_seconds),
                confirm_empty,
            )
            returncode = tree.returncode()
        except BaseException as exc:
            try:
                tree.close()
            except BaseException:
                pass
            result = OwnedProcessResult(
                status="ABORTED",
                cleanup=CLEANUP_UNKNOWN,
                returncode=None,
                stdout=_read_prefix(out_path, stdout_limit),
                stderr=_read_prefix(err_path, stderr_limit),
                stdout_overflowed=_file_size(out_path) > stdout_limit,
                stderr_overflowed=_file_size(err_path) > stderr_limit,
            )
            raise OwnedProcessAbort(exc, result) from exc
        try:
            tree.close()
        except BaseException:
            cleanup = CLEANUP_UNKNOWN
        stdout_overflowed = _file_size(out_path) > stdout_limit
        stderr_overflowed = _file_size(err_path) > stderr_limit
        status = (
            STATUS_OUTPUT_CAP
            if ended == STATUS_OUTPUT_CAP
            or (ended == STATUS_EXITED and (stdout_overflowed or stderr_overflowed))
            else ended
        )
        assert status is not None
        return OwnedProcessResult(
            status=status,
            cleanup=cleanup,
            returncode=returncode if status == STATUS_EXITED else None,
            stdout=_read_prefix(out_path, stdout_limit),
            stderr=_read_prefix(err_path, stderr_limit),
            stdout_overflowed=stdout_overflowed,
            stderr_overflowed=stderr_overflowed,
        )
