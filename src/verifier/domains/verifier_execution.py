"""Bound one checker-owned native proof replay with Windows Job Object limits.

Verifier Standard (VSTD); application programming interface (API); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); operating system
(OS). The memory limit rejects allocations above the configured job-wide committed
byte cap; it is not a resident or system-wide memory bound. Post-run peak counters
are not an admission oracle: they can exceed the limit even when an over-limit
allocation is denied.
Wall time counts seconds from immediately before primary-thread resume through
observed process completion. Watchdog scheduling and termination are not hard
real-time guarantees. ``max_loop_iterations`` retains its wire spelling but
counts charged input bytes, structure nodes and conservative native proof work,
not every Python or OS loop. Imports are covered by process memory/time bounds.

Only fixed, isolated native proof replay is admitted; submitted commands and code
are never executed. This is not a general sandbox or verifier-soundness proof.
Windows CPython is the only implemented process capability. Trusted local source,
interpreter and OS integrity are assumptions; source hashes are not authenticity.
The Microsoft contracts are JobObjectExtendedLimitInformation (class 9), job-wide
committed-memory and kill-on-close flags, and documented ResumeThread semantics:
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
"""
from __future__ import annotations

import hashlib
from importlib import resources
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from .common import Budget, Refuted, Unavailable, digest, inspect_structure, integer, need, number, obj, same


MECHANISM = "windows-job-native-kernel-1"
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_WALL_SECONDS = 60.0


def _supported_platform() -> bool:
    return os.name == "nt" and sys.implementation.name == "cpython"


def _checker_digest() -> str:
    sources = {}
    for package, names in (
        ("verifier.domains", ("verifier_execution", "verifier", "common")),
        ("verifier.core", ("certificate", "receipt", "kernel", "grounding", "depth")),
    ):
        for name in names:
            sources[package + "." + name] = hashlib.sha256(
                resources.files(package).joinpath(name + ".py").read_bytes()).hexdigest()
    return digest({"sources": sources, "runtime": [sys.implementation.name, *sys.version_info[:3]]})


class _WindowsJob:
    """Owned job handle with exact limit query and bounded termination checking."""

    def __init__(self, memory_bytes: int) -> None:
        import ctypes
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", w.DWORD), ("minimum_working_set", ctypes.c_size_t),
                        ("maximum_working_set", ctypes.c_size_t), ("active_limit", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

        class Accounting(ctypes.Structure):
            _fields_ = [("times", ctypes.c_longlong * 4), ("page_faults", w.DWORD),
                        ("total", w.DWORD), ("active", w.DWORD), ("terminated", w.DWORD)]

        self.ctypes, self.extended_type, self.accounting_type = ctypes, Extended, Accounting
        self.kernel = kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "QueryInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "ResumeThread": ([w.HANDLE], w.DWORD),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(kernel, name)
            function.argtypes, function.restype = args, result
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("native job creation unavailable")
        limits = Extended()
        limits.basic.flags = 0x00000200 | 0x00002000  # Job memory; kill on last job-handle close.
        limits.job_memory = memory_bytes
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise OSError("native job memory limit unavailable")
        self.memory_bytes = memory_bytes

    def assign(self, process_handle: int) -> None:
        if not self.kernel.AssignProcessToJobObject(self.handle, process_handle):
            raise OSError("suspended native child could not join owned job")

    def verify_limits(self) -> dict[str, int]:
        limits = self.extended_type()
        if not self.kernel.QueryInformationJobObject(self.handle, 9, self.ctypes.byref(limits),
                                                     self.ctypes.sizeof(limits), None):
            raise OSError("native job limit query unavailable")
        if limits.basic.flags != 0x2200 or limits.job_memory != self.memory_bytes:
            raise OSError("native job applied limits differ from required limits")
        if limits.peak_job > self.memory_bytes:
            raise OSError("native job memory peak exceeded the required cap")
        return {"job_committed_memory_bytes": int(limits.job_memory), "job_limit_flags": int(limits.basic.flags)}

    def resume(self, thread_handle: int) -> None:
        if self.kernel.ResumeThread(thread_handle) != 1:
            raise OSError("native primary thread was not resumed from exactly one suspension")

    def stop(self) -> None:
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise OSError("owned native job termination unavailable")
        deadline = time.monotonic() + 5.0
        while True:
            accounting = self.accounting_type()
            if not self.kernel.QueryInformationJobObject(self.handle, 1, self.ctypes.byref(accounting),
                                                         self.ctypes.sizeof(accounting), None):
                raise OSError("owned native job termination could not be observed")
            if accounting.active == 0:
                return
            if time.monotonic() >= deadline:
                raise OSError("owned native job termination deadline exceeded")
            time.sleep(0.01)

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _run_windows(argv: list[str], payload: bytes, memory_bytes: int, wall_seconds: float) -> dict[str, Any]:
    """Private process primitive; the public caller supplies only the fixed worker.

    Tests may exercise the same enforcement with test-authored programs. The
    retained primary thread permits documented resume after assignment and query.
    Only the three explicitly listed standard-stream handles are inherited.
    """
    import _winapi
    import msvcrt

    job = _WindowsJob(memory_bytes)
    process_handle = thread_handle = None
    assigned = False
    result: dict[str, Any] = {"timed_out": False, "output_exhausted": False, "owned_job_empty": False}
    try:
        with tempfile.TemporaryDirectory(prefix="vstd-native-replay-") as folder:
            root = Path(folder)
            with (root / "input").open("w+b") as incoming, (root / "output").open("w+b") as outgoing, (root / "error").open("w+b") as errors:
                incoming.write(payload)
                incoming.flush()
                incoming.seek(0)
                handles = [msvcrt.get_osfhandle(stream.fileno()) for stream in (incoming, outgoing, errors)]
                startup = subprocess.STARTUPINFO()
                startup.dwFlags = subprocess.STARTF_USESTDHANDLES
                startup.hStdInput, startup.hStdOutput, startup.hStdError = handles
                startup.lpAttributeList = {"handle_list": handles}
                environment = {key: value for key, value in os.environ.items()
                               if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
                try:
                    for handle in handles:
                        os.set_handle_inheritable(handle, True)
                    process_handle, thread_handle, _, _ = _winapi.CreateProcess(
                        argv[0], subprocess.list2cmdline(argv), None, None, True,
                        0x00000004 | 0x08000000, environment, folder, startup)
                finally:
                    for handle in handles:
                        os.set_handle_inheritable(handle, False)
                try:
                    job.assign(process_handle)
                    assigned = True
                    result["applied_limits"] = job.verify_limits()
                    result["limits_verified_before_resume"] = True
                    deadline = time.monotonic() + wall_seconds
                    job.resume(thread_handle)
                    while True:
                        # Conservative completion acceptance: a late observation
                        # never becomes a pass, even if the process exited earlier.
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            result["timed_out"] = True
                            break
                        if sum(os.fstat(stream.fileno()).st_size for stream in (outgoing, errors)) > MAX_OUTPUT_BYTES:
                            result["output_exhausted"] = True
                            break
                        if _winapi.WaitForSingleObject(process_handle, 0) == 0:
                            break
                        time.sleep(min(0.01, remaining))
                finally:
                    if assigned:
                        job.stop()
                        result["owned_job_empty"] = True
                    elif _winapi.WaitForSingleObject(process_handle, 0) != 0:
                        _winapi.TerminateProcess(process_handle, 1)
                    if _winapi.WaitForSingleObject(process_handle, 5000) != 0:
                        raise OSError("owned native child termination could not be observed")
                result["exit_code"] = _winapi.GetExitCodeProcess(process_handle)
                outgoing.seek(0)
                errors.seek(0)
                result["stdout"] = outgoing.read(MAX_OUTPUT_BYTES + 1)
                result["stderr"] = errors.read(MAX_OUTPUT_BYTES + 1)
                if len(result["stdout"]) + len(result["stderr"]) > MAX_OUTPUT_BYTES:
                    result["output_exhausted"] = True
    finally:
        # Closing the job is a second termination guard after any error. Retained
        # handles close only after termination was attempted on our exact child.
        try:
            job.close()
            if process_handle is not None:
                if not assigned and _winapi.WaitForSingleObject(process_handle, 0) != 0:
                    _winapi.TerminateProcess(process_handle, 1)
                if _winapi.WaitForSingleObject(process_handle, 5000) != 0:
                    raise OSError("owned suspended child termination could not be observed")
        finally:
            for handle in (thread_handle, process_handle):
                if handle is not None:
                    _winapi.CloseHandle(handle)
    return result


def _payload(artifact: dict, inputs: dict, budget: Budget) -> dict:
    result = {"artifact": {name: need(artifact, name) for name in (
        "toolchain_digest", "proposition_classes", "refutation_boundaries", "soundness_claims_digest")},
        "inputs": {"soundness_claims": need(inputs, "soundness_claims")}, "checker_digest": _checker_digest()}
    inspect_structure(result, budget)
    pending: list[Any] = [result]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            budget.tick(len(item))
        elif isinstance(item, dict):
            pending.extend(item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return result


def evaluate_resources(artifact: dict, inputs: dict, budget: Budget) -> dict:
    """Observe one admitted native replay; do not accept measurements as evidence."""
    selection = obj(need(inputs, "resource_execution"), {"mechanism"})
    if selection["mechanism"] != MECHANISM:
        raise Unavailable("unsupported native resource enforcement mechanism")
    ceilings = obj(need(artifact, "ceilings"), {"max_memory_bytes", "max_wall_seconds", "max_loop_iterations"})
    memory = integer(ceilings["max_memory_bytes"], minimum=1)
    wall = number(ceilings["max_wall_seconds"])
    work = integer(ceilings["max_loop_iterations"], minimum=1)
    if wall <= 0:
        raise Refuted("time ceiling must be positive")
    if wall > MAX_WALL_SECONDS:
        raise Unavailable("native execution wall ceiling exceeds supported 60 seconds")
    if not _supported_platform():
        raise Unavailable("Windows CPython Job Object resource enforcement is unavailable")
    packet = _payload(artifact, inputs, budget)
    raw = canonical_bytes(packet)
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise Unavailable("native execution input byte bound exhausted")
    # Reserve the complete child's work allowance before creating a process;
    # parent policy can never be bypassed by splitting work into a subprocess.
    budget.tick(len(raw) + work)
    request_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    loader = ("import sys;sys.path.insert(0,sys.argv[1]);"
              "from verifier.domains.verifier_execution import _worker;"
              "_worker(sys.argv[2],int(sys.argv[3]),int(sys.argv[4]))")
    argv = [sys.executable, "-I", "-S", "-B", "-u", "-c", loader,
            str(Path(__file__).resolve().parents[2]), request_digest, str(work), str(budget.max_items)]
    try:
        process = _run_windows(argv, raw, memory, wall)
    except OSError as exc:
        raise Unavailable("native execution enforcement unavailable: " + str(exc)) from exc
    if process["timed_out"]:
        raise Unavailable("native execution wall ceiling exhausted; owned job terminated")
    if process["output_exhausted"] or not process["owned_job_empty"]:
        raise Unavailable("native execution output or cleanup bound not established")
    if process["exit_code"] != 0 or process["stderr"]:
        raise Unavailable("native child could not finish under the admitted process bounds")
    try:
        answer = obj(strict_json_loads(process["stdout"].decode("utf-8")))
    except (ValueError, UnicodeError) as exc:
        raise Unavailable("native child returned no valid bounded result") from exc
    same(answer.get("request_digest"), request_digest, "native child input binding differs")
    same(packet["checker_digest"], _checker_digest(), "native checker changed during execution")
    if answer.get("status") == "UNKNOWN":
        raise Unavailable("native work unavailable: " + str(answer.get("detail", "unknown")))
    if answer.get("status") == "FAIL":
        raise Refuted("native proof execution refuted: " + str(answer.get("detail", "invalid")))
    obj(answer, {"status", "request_digest", "checker_digest", "native_work_used", "proof_results"})
    same(answer["status"], "PASS", "unexpected native execution result")
    same(answer["checker_digest"], packet["checker_digest"], "native checker source binding differs")
    used = integer(answer["native_work_used"], minimum=1, maximum=work)
    proofs = answer["proof_results"]
    if not isinstance(proofs, list) or not proofs:
        raise Refuted("native execution retained no proof result")
    return {"mechanism": MECHANISM, "request_digest": request_digest,
            "checker_digest": packet["checker_digest"], "toolchain_digest": artifact["toolchain_digest"],
            "proof_output_digest": digest(proofs), "proof_instances_checked": len(proofs),
            "native_work_used": used, "native_work_limit": work,
            "applied_limits": {**process["applied_limits"], "max_wall_seconds": wall},
            "limits_verified_before_resume": True, "owned_job_empty": True,
            "scope": "one checker-owned native proof replay; committed bytes and observed completion",
            "work_units": "charged input bytes, structure nodes and conservative native proof work; not interpreter or OS loops",
            "hard_real_time_termination": "NOT_ESTABLISHED", "arbitrary_verifier_execution": "NOT_ESTABLISHED"}


def _worker(expected_digest: str, work_limit: int, max_items: int) -> None:
    """Fixed child entry point. Charge bytes before parsing or native replay."""
    budget = Budget(work_limit, max_items)
    answer: dict[str, Any] = {"request_digest": expected_digest}
    try:
        raw = sys.stdin.buffer.read(min(MAX_PAYLOAD_BYTES, work_limit) + 1)
        budget.tick(len(raw))
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise Unavailable("native input byte bound exhausted")
        same("sha256:" + hashlib.sha256(raw).hexdigest(), expected_digest, "native payload digest mismatch")
        packet = obj(strict_json_loads(raw.decode("utf-8")), {"artifact", "inputs", "checker_digest"})
        if canonical_bytes(packet) != raw:
            raise Refuted("native payload is not canonical")
        inspect_structure(packet, budget)
        same(packet["checker_digest"], _checker_digest(), "native worker source changed before replay")
        from .verifier import evaluate
        checked = evaluate("soundness", obj(packet["artifact"]), obj(packet["inputs"]), budget)
        same(packet["checker_digest"], _checker_digest(), "native worker source changed during replay")
        answer.update(status="PASS", checker_digest=packet["checker_digest"],
                      native_work_used=budget.used, proof_results=checked["proof_results"])
    except (Unavailable, MemoryError) as exc:
        answer.update(status="UNKNOWN", detail=str(exc) or "native process memory exhausted")
    except (ValueError, TypeError, KeyError, IndexError, ArithmeticError, RecursionError) as exc:
        answer.update(status="FAIL", detail=str(exc))
    sys.stdout.buffer.write(canonical_bytes(answer))
    sys.stdout.buffer.flush()
