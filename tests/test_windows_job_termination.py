"""Owned Windows process termination is observed through retained handles.

Verifier Standard (VSTD); application programming interface (API); operating
system (OS); identifier (ID). Time bounds use seconds; process counts are
dimensionless. All actual processes below are test-authored and job-owned.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import os
import sys
from types import SimpleNamespace

import pytest

from verifier.domains import verifier_execution as execution


class Accounting(ctypes.Structure):
    _fields_ = [("total", w.DWORD), ("active", w.DWORD)]


class Kernel:
    """Independent process-signal oracle despite an empty accounting snapshot."""

    def __init__(
        self, *, total: int = 2, active: int = 0, completes: bool = True
    ) -> None:
        self.total = total
        self.active = active
        self.completes = completes
        self.terminated = False
        self.waits: dict[int, int] = {}
        self.signaled: set[int] = set()

    def TerminateJobObject(self, handle: int, exit_code: int) -> int:
        assert handle == 1 and exit_code == 1
        self.terminated = True
        return 1

    def QueryInformationJobObject(self, handle: int, kind: int,
                                  pointer: object, size: int, returned: object) -> int:
        assert handle == 1 and kind == 1
        pointer._obj.total = self.total
        pointer._obj.active = self.active
        return 1

    def WaitForSingleObject(self, handle: int, milliseconds: int) -> int:
        assert handle in {101, 102} and milliseconds >= 0
        self.waits[handle] = self.waits.get(handle, 0) + 1
        if self.completes and self.waits[handle] >= 2:
            self.signaled.add(handle)
        return 0 if handle in self.signaled else 258


def selected_job(kernel: Kernel, monkeypatch: pytest.MonkeyPatch) -> object:
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes = ctypes
    job.accounting_type = Accounting
    job.kernel = kernel
    job.handle = 1
    job._process_handles = {11: 101, 12: 102}
    # This unit fixture has an independently complete retained membership set.
    job._observe_processes = lambda: None
    ticks = iter(range(100))
    monkeypatch.setattr(execution, "time", SimpleNamespace(
        monotonic=lambda: float(next(ticks)), sleep=lambda seconds: None))
    return job


def test_zero_active_count_waits_for_retained_process_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = Kernel()
    job = selected_job(kernel, monkeypatch)
    job.stop()
    assert kernel.terminated
    assert kernel.signaled == {101, 102}, "accounting zero was mistaken for process exit"


def test_unsignaled_owned_process_cannot_be_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = Kernel(completes=False)
    job = selected_job(kernel, monkeypatch)
    with pytest.raises(OSError, match="termination"):
        job.stop()
    assert kernel.terminated and not kernel.signaled


def test_unobserved_historical_identity_does_not_hide_an_empty_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Kernel(total=3)
    job = selected_job(kernel, monkeypatch)
    job.stop()
    assert kernel.terminated and kernel.signaled == {101, 102}


def test_lifetime_accounting_regression_prevents_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Kernel(total=1)
    job = selected_job(kernel, monkeypatch)
    with pytest.raises(OSError, match="accounting regressed"):
        job.stop()
    assert kernel.terminated


def test_active_accounting_member_prevents_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Kernel(active=1)
    job = selected_job(kernel, monkeypatch)
    with pytest.raises(OSError, match="deadline"):
        job.stop()
    assert kernel.terminated


def test_membership_observation_failure_still_attempts_owned_termination(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = Kernel()
    job = selected_job(kernel, monkeypatch)
    def unavailable() -> None:
        raise OSError("selected process membership observation unavailable")
    job._observe_processes = unavailable
    with pytest.raises(OSError, match="membership"):
        job.stop()
    assert kernel.terminated


@pytest.mark.parametrize("failure", ["open", "query", "outside"])
def test_unestablished_member_never_enters_retained_inventory(failure: str) -> None:
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job._process_handles = ctypes, 1, {}
    closed: list[int] = []
    def member(handle: int, owner: int, result: object) -> int:
        assert handle == 909 and owner == 1
        result._obj.value = failure != "outside"
        return 0 if failure == "query" else 1
    job.kernel = SimpleNamespace(
        OpenProcess=lambda access, inherit, pid: 0 if failure == "open" else 909,
        IsProcessInJob=member, CloseHandle=closed.append)
    with pytest.raises(OSError):
        job._retain_process(7)
    assert job._process_handles == {}
    assert closed == ([] if failure == "open" else [909])


def test_retention_bound_prevents_opening_another_handle() -> None:
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job._process_handles = {pid: pid + 1000 for pid in range(1, 129)}
    def forbidden(*args: object) -> int:
        pytest.fail("handle opened beyond the 128-handle observation bound")
    job.kernel = SimpleNamespace(OpenProcess=forbidden)
    with pytest.raises(OSError, match="bound"):
        job._retain_process(129)
    assert len(job._process_handles) == 128


def test_only_signaled_nonmembers_are_retired() -> None:
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job._process_handles = {11: 101, 12: 102, 13: 103}
    job._retired_process_count = 7
    closed: list[int] = []
    signals = {101: 0, 102: 258, 103: 0xFFFFFFFF}
    def close(handle: int) -> int:
        closed.append(handle)
        return 1
    job.kernel = SimpleNamespace(
        WaitForSingleObject=lambda handle, timeout: signals[handle],
        CloseHandle=close,
    )
    with pytest.raises(OSError, match="retirement signal"):
        job._retire_signaled_processes(set())
    assert job._process_handles == {12: 102, 13: 103}
    assert job._retired_process_count == 8
    assert closed == [101]


def test_failed_retirement_handle_close_is_not_counted() -> None:
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job._process_handles = {11: 101}
    job._retired_process_count = 7
    job.kernel = SimpleNamespace(
        WaitForSingleObject=lambda handle, timeout: 0,
        CloseHandle=lambda handle: 0,
    )
    with pytest.raises(OSError, match="handle close"):
        job._retire_signaled_processes(set())
    assert job._process_handles == {11: 101}
    assert job._retired_process_count == 7


def test_retired_members_remain_in_lifetime_accounting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Kernel(total=2)
    job = selected_job(kernel, monkeypatch)
    job._process_handles = {12: 102}
    job._retired_process_count = 1
    job.stop()
    assert kernel.terminated and kernel.signaled == {102}


def test_incomplete_process_list_never_becomes_a_membership_observation() -> None:
    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 128)]
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job.process_ids_type = ctypes, 1, ProcessList
    queries: list[tuple[int, int]] = []
    def partial(handle: int, kind: int, result: object, size: int, returned: object) -> int:
        result._obj.assigned, result._obj.included = 129, 128
        queries.append((129, 128))
        return 1
    def forbidden(pid: int) -> None:
        pytest.fail("partial process membership was admitted")
    job.kernel = SimpleNamespace(QueryInformationJobObject=partial)
    job._retain_process = forbidden
    with pytest.raises(OSError, match="incomplete"):
        job._observe_processes()
    assert queries == [(129, 128)]


def test_transient_incomplete_membership_retries_before_inventory_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 128)]
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job.process_ids_type = ctypes, 1, ProcessList
    snapshots = iter(((2, 1), (1, 1)))
    events: list[object] = []
    def query(handle: int, kind: int, result: object, size: int, returned: object) -> int:
        assigned, included = next(snapshots)
        result._obj.assigned, result._obj.included = assigned, included
        result._obj.ids[0] = 77
        events.append(("query", assigned, included))
        return 1
    job.kernel = SimpleNamespace(QueryInformationJobObject=query)
    job._retire_signaled_processes = lambda active: events.append(
        ("retire", tuple(sorted(active))))
    job._retain_process = lambda process_id: events.append(("retain", process_id))
    monkeypatch.setattr(execution, "time", SimpleNamespace(
        monotonic=lambda: 0.0, sleep=lambda seconds: None))
    job._observe_processes()
    assert events == [
        ("query", 2, 1),
        ("query", 1, 1),
        ("retire", (77,)),
        ("retain", 77),
    ]


def test_persistent_incomplete_membership_refuses_without_inventory_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 128)]
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job.process_ids_type = ctypes, 1, ProcessList
    queries: list[tuple[int, int]] = []
    def query(handle: int, kind: int, result: object, size: int, returned: object) -> int:
        result._obj.assigned, result._obj.included = 2, 1
        result._obj.ids[0] = 77
        queries.append((2, 1))
        return 1
    def forbidden(*args: object) -> None:
        pytest.fail("incomplete process membership mutated the retained inventory")
    job.kernel = SimpleNamespace(QueryInformationJobObject=query)
    job._retire_signaled_processes = forbidden
    job._retain_process = forbidden
    monkeypatch.setattr(execution, "time", SimpleNamespace(
        monotonic=lambda: 0.0, sleep=lambda seconds: None))
    with pytest.raises(OSError, match="incomplete"):
        job._observe_processes()
    assert queries == [(2, 1)] * 4


def test_incomplete_membership_deadline_refuses_without_inventory_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 128)]
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job.process_ids_type = ctypes, 1, ProcessList
    queries: list[tuple[int, int]] = []
    def query(handle: int, kind: int, result: object, size: int, returned: object) -> int:
        result._obj.assigned, result._obj.included = 2, 1
        queries.append((2, 1))
        return 1
    def forbidden(*args: object) -> None:
        pytest.fail("expired process membership mutated the retained inventory")
    job.kernel = SimpleNamespace(QueryInformationJobObject=query)
    job._retire_signaled_processes = forbidden
    job._retain_process = forbidden
    ticks = iter((0.0, 0.051))
    monkeypatch.setattr(execution, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda seconds: None))
    with pytest.raises(OSError, match="incomplete"):
        job._observe_processes()
    assert queries == [(2, 1)]


def test_membership_query_failure_is_not_retried() -> None:
    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 128)]
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job.process_ids_type = ctypes, 1, ProcessList
    queries: list[int] = []
    def unavailable(*args: object) -> int:
        queries.append(1)
        return 0
    def forbidden(*args: object) -> None:
        pytest.fail("failed process membership query mutated the retained inventory")
    job.kernel = SimpleNamespace(QueryInformationJobObject=unavailable)
    job._retire_signaled_processes = forbidden
    job._retain_process = forbidden
    with pytest.raises(OSError, match="query unavailable"):
        job._observe_processes()
    assert queries == [1]


def test_duplicate_complete_membership_is_not_retried() -> None:
    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 128)]
    job = execution._WindowsJob.__new__(execution._WindowsJob)
    job.ctypes, job.handle, job.process_ids_type = ctypes, 1, ProcessList
    queries: list[int] = []
    def duplicate(handle: int, kind: int, result: object, size: int, returned: object) -> int:
        result._obj.assigned, result._obj.included = 2, 2
        result._obj.ids[0], result._obj.ids[1] = 77, 77
        queries.append(1)
        return 1
    def forbidden(*args: object) -> None:
        pytest.fail("duplicate process membership mutated the retained inventory")
    job.kernel = SimpleNamespace(QueryInformationJobObject=duplicate)
    job._retire_signaled_processes = forbidden
    job._retain_process = forbidden
    with pytest.raises(OSError, match="incomplete"):
        job._observe_processes()
    assert queries == [1]


def test_failed_process_signal_query_cannot_confirm_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = Kernel()
    kernel.WaitForSingleObject = lambda handle, timeout: 0xFFFFFFFF
    job = selected_job(kernel, monkeypatch)
    with pytest.raises(OSError, match="signal"):
        job.stop()
    assert kernel.terminated


@pytest.mark.skipif(os.name != "nt", reason="OS_CAPABILITY_GUARD: retained Windows process handles require Windows")
def test_real_descendant_handles_are_signaled_before_stop_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    import _winapi

    class ProcessList(ctypes.Structure):
        _fields_ = [("assigned", w.DWORD), ("included", w.DWORD),
                    ("ids", ctypes.c_size_t * 16)]

    stop = execution._WindowsJob.stop
    observations: list[tuple[int, int]] = []
    def retained_stop(job: object) -> None:
        snapshot = ProcessList()
        assert job.kernel.QueryInformationJobObject(
            job.handle, 3, ctypes.byref(snapshot), ctypes.sizeof(snapshot), None)
        assert snapshot.assigned == snapshot.included <= 16
        member = job.kernel.IsProcessInJob
        member.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]
        member.restype = w.BOOL
        handles: list[tuple[int, int]] = []
        try:
            for pid in list(snapshot.ids)[:snapshot.included]:
                handle = _winapi.OpenProcess(0x00101000, False, pid)
                handles.append((pid, handle))
                included = w.BOOL()
                assert member(handle, job.handle, ctypes.byref(included)) and included.value
            stop(job)
            observations.extend((pid, _winapi.WaitForSingleObject(handle, 0))
                                for pid, handle in handles)
        finally:
            # Even a counterexample must confirm its owned fixture's cleanup.
            for _, handle in handles:
                try:
                    assert _winapi.WaitForSingleObject(handle, 5000) == 0
                finally:
                    _winapi.CloseHandle(handle)

    monkeypatch.setattr(execution._WindowsJob, "stop", retained_stop)
    program = ("import subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(30)']); "
        "print(p.pid,flush=True); time.sleep(30)")
    result = execution._run_windows([sys.executable, "-I", "-S", "-B", "-u", "-c", program],
                                    b"", 128 * 1024 * 1024, 1.0)
    child = int(result["stdout"].strip())
    assert result["timed_out"] is True and result["owned_job_empty"] is True
    assert result["lifetime_process_identity_census"] == "NOT_ESTABLISHED"
    assert child in {pid for pid, _ in observations}
    assert observations and all(signal == 0 for _, signal in observations)


@pytest.mark.skipif(
    os.name != "nt",
    reason="OS_CAPABILITY_GUARD: short-lived Windows descendants require Windows",
)
def test_real_short_lived_descendants_preserve_bounded_cleanup_scope() -> None:
    program = "\n".join(
        (
            "import os",
            "import subprocess",
            "command = [os.path.join(os.environ['SYSTEMROOT'], 'System32', "
            "'cmd.exe'), '/d', '/c', 'exit', '0']",
            "for _ in range(300):",
            "    subprocess.run(command, check=True)",
            "print('done', flush=True)",
        )
    )
    result = execution._run_windows(
        [sys.executable, "-I", "-S", "-B", "-u", "-c", program],
        b"",
        256 * 1024 * 1024,
        60.0,
    )
    assert result["exit_code"] == 0
    assert result["owned_job_empty"] is True
    assert result["lifetime_process_identity_census"] == "NOT_ESTABLISHED"
    assert result["stdout"] == b"done\r\n"
