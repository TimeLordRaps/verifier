"""Owned process-tree boundary for package execution workers.

These tests launch real worker/grandchild trees.  A direct worker exit is not
accepted unless its owned tree is positively empty; timeout and cancellation
must stop the nested process before the private filesystem is removed.
"""

from __future__ import annotations

import os
from pathlib import Path
import time
from types import SimpleNamespace
import uuid

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.core import owned_process
from verifier.runtime import package_execution as execution
from verifier.runtime import package_execution_observation as observation


_DIGEST = "sha256:" + "a" * 64


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000 | 0x1000, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_until_dead(pid: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_alive(pid)


@pytest.fixture
def package_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Install one test-authored runtime worker and a minimal source-bound snapshot."""

    from verifier.runtime import local_ledger_worker

    runtime = Path(execution.__file__).resolve().parent
    worker_name = f"_owned_tree_fixture_{uuid.uuid4().hex}.py"
    worker_path = runtime / worker_name
    heartbeat = tmp_path / "heartbeat.txt"
    child_pid = tmp_path / "grandchild.pid"
    private_path = tmp_path / "private-path.txt"
    mode_path = tmp_path / "mode.txt"
    mode_path.write_text("normal", encoding="utf-8")
    grandchild = (
        "import os,time\n"
        "from pathlib import Path\n"
        f"p=Path({str(heartbeat)!r})\n"
        "while True:\n"
        " p.write_text(p.read_text(encoding='utf-8')+'x' if p.exists() else 'x', encoding='utf-8')\n"
        " time.sleep(0.05)\n"
    )
    worker_path.write_text(
        "import json, os, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "request=json.loads(sys.stdin.buffer.read().decode('utf-8'))\n"
        f"Path({str(private_path)!r}).write_text(os.environ['TEMP'], encoding='utf-8')\n"
        f"mode=Path({str(mode_path)!r}).read_text(encoding='utf-8')\n"
        "if mode != 'normal':\n"
        f" child=subprocess.Popen([sys.executable, '-B', '-c', {grandchild!r}])\n"
        f" Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        " time.sleep(60)\n"
        "else:\n"
        " report={'schema_version':'fixture-observation-1','request':request,'source_pins':{},'observations':{'normal':True}}\n"
        " sys.stdout.write(json.dumps(report, sort_keys=True, separators=(',', ':'))+'\\n')\n",
        encoding="utf-8",
    )
    module = SimpleNamespace(
        ADAPTER="owned-tree-fixture-1",
        IMPLEMENTATION="runtime/package_execution.py",
        WORKER=worker_name,
        REQUEST_SCHEMA="fixture-request-1",
        OBSERVATION_SCHEMA="fixture-observation-1",
    )
    item = NamespaceObject.create("owned-tree-fixture", "OBJECT", {}, {})
    selection = {
        "object_id": item.object_id,
        "mechanism": module.ADAPTER,
        "reason": "Test-owned source-bound package worker.",
        "evidence": [{"path": module.IMPLEMENTATION, "sha256": _DIGEST}],
    }
    snapshot = SimpleNamespace(
        rows={item.object_id: {"surfaces": ["file:" + module.IMPLEMENTATION]}},
        root=Path(__file__).resolve().parents[1],
        collection_digest="sha256:" + "b" * 64,
        read=lambda ref: b"",
        execution_transports={},
    )
    private_parent = tmp_path / "private-parent"
    private_parent.mkdir()
    monkeypatch.setattr(execution, "mechanisms", lambda: {module.ADAPTER: module})
    monkeypatch.setattr(local_ledger_worker, "source_pins", lambda: {})
    monkeypatch.setattr(execution, "_temporary_parent_candidates", lambda root: (private_parent,))
    try:
        yield SimpleNamespace(
            snapshot=snapshot,
            item=item,
            selection=selection,
            mode=mode_path,
            heartbeat=heartbeat,
            child_pid=child_pid,
            private_path=private_path,
            module=module,
        )
    finally:
        worker_path.unlink(missing_ok=True)


def _assert_private_temp_removed(fixture: SimpleNamespace) -> None:
    private = Path(fixture.private_path.read_text(encoding="utf-8"))
    assert not private.exists()


def test_normal_package_worker_is_accepted_only_after_owned_tree_is_empty(
    package_worker: SimpleNamespace,
) -> None:
    report = execution.execute_bound(
        package_worker.snapshot, package_worker.item, package_worker.selection
    )

    assert report["observations"] == {"normal": True}
    trace = next(iter(package_worker.snapshot.execution_transports.values()))
    assert trace["outcome"] == "ACCEPTED"
    assert trace["returncode"] == 0
    assert trace["streams_complete"] is True
    observation.verify_accepted(
        trace,
        report,
        selection=package_worker.selection,
        item=package_worker.item,
        collection_digest=package_worker.snapshot.collection_digest,
        module=package_worker.module,
    )
    _assert_private_temp_removed(package_worker)


@pytest.mark.parametrize(
    ("result", "code", "outcome"),
    [
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_OUTPUT_CAP,
                owned_process.CLEANUP_CONFIRMED,
                None,
                b"x",
                b"",
                True,
                False,
            ),
            "PACKAGE_EXECUTION_OUTPUT_CAPACITY",
            "OUTPUT_CAP_EXCEEDED",
        ),
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_EXITED,
                owned_process.CLEANUP_NOT_CONFIRMED,
                0,
                b"",
                b"",
                False,
                False,
            ),
            "PACKAGE_EXECUTION_CLEANUP_NOT_CONFIRMED",
            "CLEANUP_NOT_CONFIRMED",
        ),
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_EXITED,
                owned_process.CLEANUP_UNKNOWN,
                0,
                b"",
                b"",
                False,
                False,
            ),
            "PACKAGE_EXECUTION_CLEANUP_UNKNOWN",
            "CLEANUP_UNKNOWN",
        ),
        (
            owned_process.OwnedProcessResult(
                owned_process.STATUS_EXITED,
                owned_process.CLEANUP_CONFIRMED,
                None,
                b"",
                b"",
                False,
                False,
            ),
            "PACKAGE_EXECUTION_EXIT_STATUS_UNKNOWN",
            "EXIT_STATUS_UNKNOWN",
        ),
    ],
    ids=["output-cap", "cleanup-not-confirmed", "cleanup-unknown", "exit-unknown"],
)
def test_uncertain_package_endings_have_stable_non_pass_codes_without_retry(
    package_worker: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    result: owned_process.OwnedProcessResult,
    code: str,
    outcome: str,
) -> None:
    calls = {"count": 0}

    def finish_once(*args, **kwargs):
        calls["count"] += 1
        return result

    monkeypatch.setattr(owned_process, "run_owned_process", finish_once)
    with pytest.raises(OSError, match=code):
        execution.execute_bound(
            package_worker.snapshot, package_worker.item, package_worker.selection
        )

    assert calls == {"count": 1}
    trace = next(iter(package_worker.snapshot.execution_transports.values()))
    assert trace["outcome"] == outcome
    assert trace["returncode"] is None
    assert trace["streams_complete"] is False


def test_timeout_kills_nested_package_grandchild_and_cleans_private_temp(
    package_worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_worker.mode.write_text("timeout", encoding="utf-8")
    monkeypatch.setattr(execution, "_WORKER_TIMEOUT_SECONDS", 1)

    with pytest.raises(OSError, match="PACKAGE_EXECUTION_WORKER_TIMEOUT"):
        execution.execute_bound(
            package_worker.snapshot, package_worker.item, package_worker.selection
        )

    pid = int(package_worker.child_pid.read_text(encoding="utf-8"))
    assert _wait_until_dead(pid), "owned package grandchild survived timeout"
    before = package_worker.heartbeat.stat().st_size
    time.sleep(0.3)
    assert package_worker.heartbeat.stat().st_size == before
    trace = next(iter(package_worker.snapshot.execution_transports.values()))
    assert trace["outcome"] == "TIMEOUT"
    assert trace["returncode"] is None
    assert trace["streams_complete"] is False
    _assert_private_temp_removed(package_worker)


def test_keyboard_interrupt_cleans_package_tree_without_becoming_timeout(
    package_worker: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_worker.mode.write_text("cancel", encoding="utf-8")
    original_pause = owned_process._poll_pause

    def interrupt_after_heartbeat() -> None:
        if package_worker.heartbeat.exists() and package_worker.child_pid.exists():
            raise KeyboardInterrupt
        original_pause()

    monkeypatch.setattr(owned_process, "_poll_pause", interrupt_after_heartbeat)
    with pytest.raises(KeyboardInterrupt):
        execution.execute_bound(
            package_worker.snapshot, package_worker.item, package_worker.selection
        )

    pid = int(package_worker.child_pid.read_text(encoding="utf-8"))
    assert _wait_until_dead(pid), "owned package grandchild survived cancellation"
    trace = next(iter(package_worker.snapshot.execution_transports.values()))
    assert trace["outcome"] == "CANCELLED"
    assert trace["outcome"] != "TIMEOUT"
    assert trace["exception_type"] == "KeyboardInterrupt"
    assert trace["returncode"] is None
    assert trace["streams_complete"] is False
    _assert_private_temp_removed(package_worker)
