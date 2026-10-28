"""Owned process-tree boundary for trusted-local generic runs.

Verifier Standard (VSTD); operating system (OS); process identifier (PID).
Time bounds are seconds. Every process below is a test-authored fixture spawned
by this test or by the run under test; an unrelated sentinel process is started
by the test to prove that only owned descendants are terminated.

Output-cap and cleanup uncertainty are typed, non-PASS receipts: no exit status
is attested for them, and completion is always denied.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from verifier.core import run as run_module
from verifier.core.run import capture_run
from verifier.core.run_support import RunOutcome

# Generous wall bound: the manifest timeout is 2 s; the margin absorbs slow
# Windows process teardown without accepting a 20 s hang as a pass.
WALL_BOUND_SECONDS = 15.0
GRANDCHILD_SLEEP_SECONDS = 45
WINDOWS_STILL_ACTIVE_WAIT = 258


def _manifest(tmp_path: Path, script: str, *, timeout_seconds: int = 2) -> dict:
    (tmp_path / "fixture.py").write_text(script, encoding="utf-8")
    return {
        "claim": {
            "id": "RUN-OWNED-TREE",
            "title": "Owned process tree",
            "statement": "Fixture process tree is bounded by the runner.",
            "scope": "unit test",
            "limitations": ["fixture only"],
            "falsification_condition": "a descendant outlives the bounded run",
        },
        "command": [sys.executable, "-B", "fixture.py"],
        "cwd": ".",
        "inputs": [],
        "outputs": [],
        "determinism_declared": "NONDETERMINISTIC",
        "timeout_seconds": timeout_seconds,
    }


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
        synchronize, query_limited = 0x00100000, 0x1000
        handle = kernel.OpenProcess(synchronize | query_limited, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == WINDOWS_STILL_ACTIVE_WAIT
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


GRANDCHILD_HOLDS_STDOUT = """
import subprocess, sys, time
from pathlib import Path
grand = subprocess.Popen([sys.executable, "-B", "-c",
    "import time; time.sleep({sleep})"])
Path("grandchild.pid").write_text(str(grand.pid), encoding="utf-8")
print("parent started", flush=True)
time.sleep(60)
""".format(sleep=GRANDCHILD_SLEEP_SECONDS)

DELAYED_MARKER = """
import subprocess, sys, time
from pathlib import Path
grand = subprocess.Popen([sys.executable, "-B", "-c",
    "import time; from pathlib import Path; time.sleep(4); "
    "Path('late-marker.txt').write_text('late', encoding='utf-8')"])
Path("grandchild.pid").write_text(str(grand.pid), encoding="utf-8")
time.sleep(60)
"""

STDOUT_FLOOD = """
import sys, time
chunk = b"x" * 65536
for _ in range(1024):
    sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
time.sleep(60)
"""

STDERR_FLOOD = """
import sys, time
chunk = b"e" * 65536
for _ in range(1024):
    sys.stderr.buffer.write(chunk)
    sys.stderr.buffer.flush()
time.sleep(60)
"""

SHORT_CHILD = """
import sys
sys.stdout.write("short-ok")
sys.stderr.write("short-warning")
"""

SLEEP_CHILD = "import time; time.sleep(60)"


def _observation(receipt) -> dict:
    return receipt.assessment_context["refutation_surface"]["parent_process_observation"]


def _assert_typed_non_pass(receipt, outcome: RunOutcome) -> dict:
    """A typed non-PASS receipt names its outcome, denies completion, and attests no exit status."""

    observed = _observation(receipt)
    assert receipt.execution.outcome == outcome.value
    assert receipt.claims.execution_completed is False
    assert receipt.execution.exit_code is None
    assert observed["result"]["outcome"] == outcome.value
    assert observed["result"]["returncode"] is None
    return observed


def _grandchild_pid(tmp_path: Path) -> int:
    return int((tmp_path / "grandchild.pid").read_text(encoding="utf-8"))


class _ScriptedTree:
    """Deterministic owned-tree stand-in; capture_run's classification is the code under test."""

    def __init__(self, plan: dict) -> None:
        self._plan = plan

    def launch(self, argv, cwd, stdout, stderr) -> None:
        if "raise_on_launch" in self._plan:
            raise self._plan["raise_on_launch"]
        stdout.write(self._plan.get("stdout", b""))
        stderr.write(self._plan.get("stderr", b""))
        stdout.flush()
        stderr.flush()

    def direct_child_exited(self) -> bool:
        return self._plan.get("exited", True)

    def returncode(self):
        return self._plan.get("returncode", 0)

    def terminate_owned(self) -> bool:
        self._plan.setdefault("events", []).append("terminate")
        return self._plan.get("terminate_ok", True)

    def owned_members_remain(self):
        return self._plan.get("remaining", False)

    def close(self) -> None:
        return None


@pytest.fixture
def scripted_tree(monkeypatch: pytest.MonkeyPatch):
    def install(**plan) -> dict:
        monkeypatch.setattr(run_module, "_WindowsOwnedTree", lambda: _ScriptedTree(plan))
        monkeypatch.setattr(run_module, "_PosixOwnedTree", lambda: _ScriptedTree(plan))
        monkeypatch.setattr(run_module, "_TREE_CLEANUP_SECONDS", 0.05)
        return plan

    return install


@pytest.fixture
def small_cap(monkeypatch: pytest.MonkeyPatch) -> int:
    limit = 1024 * 1024
    monkeypatch.setattr(run_module, "_OUTPUT_CAPTURE_LIMIT_BYTES", limit, raising=False)
    return limit


@pytest.fixture
def unrelated_sentinel():
    """A process this test did not create through the runner; it must survive."""

    sentinel = subprocess.Popen([sys.executable, "-B", "-c", SLEEP_CHILD])
    try:
        yield sentinel
    finally:
        sentinel.kill()
        sentinel.wait(timeout=10)


def test_grandchild_holding_stdout_cannot_extend_timeout(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, GRANDCHILD_HOLDS_STDOUT, timeout_seconds=2)

    started = time.monotonic()
    receipt = capture_run(manifest, manifest_dir=tmp_path)
    wall = time.monotonic() - started

    assert wall < WALL_BOUND_SECONDS, f"timeout=2 returned after {wall:.1f}s"
    assert receipt.execution.outcome == RunOutcome.TIMEOUT.value
    assert _observation(receipt)["result"]["outcome"] == "TIMEOUT"
    assert _observation(receipt)["result"]["owned_tree_cleanup"] == "CONFIRMED"
    assert _wait_until_dead(_grandchild_pid(tmp_path)), "owned grandchild survived"


def test_grandchild_cannot_write_delayed_marker_after_timeout(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DELAYED_MARKER, timeout_seconds=2)

    receipt = capture_run(manifest, manifest_dir=tmp_path)
    assert receipt.execution.outcome == RunOutcome.TIMEOUT.value
    assert _wait_until_dead(_grandchild_pid(tmp_path))
    time.sleep(5)

    assert not (tmp_path / "late-marker.txt").exists()


def test_stdout_flood_is_typed_output_cap_not_pass(
    tmp_path: Path, small_cap: int
) -> None:
    manifest = _manifest(tmp_path, STDOUT_FLOOD, timeout_seconds=10)

    started = time.monotonic()
    receipt = capture_run(manifest, manifest_dir=tmp_path)
    assert time.monotonic() - started < WALL_BOUND_SECONDS

    observed = _assert_typed_non_pass(receipt, RunOutcome.OUTPUT_CAP_EXCEEDED)
    result = observed["result"]
    assert result["process_started"] == "YES"
    assert result["streams_complete"] == "NO"
    assert result["owned_tree_cleanup"] == "CONFIRMED"
    # Truncated-output accounting: byte_count is the captured prefix, never the stream size.
    assert result["stdout"]["byte_count"] == small_cap
    assert result["stdout"]["retention_truncated"] is True
    assert result["stdout"]["completeness"] == "PARTIAL"
    assert result["stdout"]["sha256"] == "sha256:" + receipt.execution.stdout_sha256


def test_stderr_flood_is_typed_output_cap_not_pass(
    tmp_path: Path, small_cap: int
) -> None:
    manifest = _manifest(tmp_path, STDERR_FLOOD, timeout_seconds=10)

    started = time.monotonic()
    receipt = capture_run(manifest, manifest_dir=tmp_path)
    assert time.monotonic() - started < WALL_BOUND_SECONDS

    observed = _assert_typed_non_pass(receipt, RunOutcome.OUTPUT_CAP_EXCEEDED)
    result = observed["result"]
    assert result["stderr"]["byte_count"] == small_cap
    assert result["stderr"]["completeness"] == "PARTIAL"
    assert result["stderr"]["sha256"] == "sha256:" + receipt.execution.stderr_sha256
    assert result["stdout"]["completeness"] == "PARTIAL"


def test_timeout_and_flood_budgets_both_yield_a_typed_non_pass(
    tmp_path: Path, small_cap: int
) -> None:
    manifest = _manifest(tmp_path, STDOUT_FLOOD, timeout_seconds=1)

    started = time.monotonic()
    receipt = capture_run(manifest, manifest_dir=tmp_path)

    assert time.monotonic() - started < WALL_BOUND_SECONDS
    assert receipt.execution.outcome in {
        RunOutcome.TIMEOUT.value,
        RunOutcome.OUTPUT_CAP_EXCEEDED.value,
    }
    assert receipt.claims.execution_completed is False
    assert receipt.execution.exit_code is None


def test_normal_short_child_keeps_existing_completed_semantics(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, SHORT_CHILD, timeout_seconds=30)

    receipt = capture_run(manifest, manifest_dir=tmp_path)

    assert receipt.execution.outcome == RunOutcome.COMPLETED.value
    assert receipt.execution.exit_code == 0
    assert receipt.execution.stdout_snippet == "short-ok"
    assert receipt.execution.stderr_snippet == "short-warning"
    assert _observation(receipt)["result"]["outcome"] == "SUCCESS"
    assert _observation(receipt)["result"]["streams_complete"] == "YES"
    assert _observation(receipt)["result"]["owned_tree_cleanup"] == "CONFIRMED"


@pytest.mark.parametrize("cleanup", ["NOT_CONFIRMED", "UNKNOWN"])
def test_clean_exit_with_real_uncertain_cleanup_is_typed_and_withholds_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup: str
) -> None:
    manifest = _manifest(tmp_path, SHORT_CHILD, timeout_seconds=30)
    monkeypatch.setattr(
        run_module, "_confirm_owned_tree_empty", lambda *_a, **_k: cleanup, raising=False
    )

    receipt = capture_run(manifest, manifest_dir=tmp_path)

    observed = _assert_typed_non_pass(receipt, RunOutcome.CLEANUP_NOT_ESTABLISHED)
    assert observed["result"]["owned_tree_cleanup"] == cleanup
    assert observed["result"]["streams_complete"] == "UNKNOWN"
    # Captured bytes are retained as a prefix only; they are not presented as a complete run.
    assert observed["result"]["stdout"]["completeness"] == "PARTIAL"
    assert base64.b64decode(observed["result"]["stdout"]["retained_base64"]) == b"short-ok"


def test_timeout_with_uncertain_cleanup_stays_timeout_and_carries_cleanup_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path, GRANDCHILD_HOLDS_STDOUT, timeout_seconds=2)
    monkeypatch.setattr(
        run_module, "_confirm_owned_tree_empty", lambda *_a, **_k: "UNKNOWN", raising=False
    )

    receipt = capture_run(manifest, manifest_dir=tmp_path)

    observed = _assert_typed_non_pass(receipt, RunOutcome.TIMEOUT)
    assert observed["result"]["owned_tree_cleanup"] == "UNKNOWN"
    assert _wait_until_dead(_grandchild_pid(tmp_path)), "termination still attempted"


def test_clean_exit_through_scripted_tree_is_the_only_completed_path(
    tmp_path: Path, scripted_tree
) -> None:
    scripted_tree(exited=True, returncode=0, stdout=b"ok", remaining=False)

    receipt = capture_run(_manifest(tmp_path, SHORT_CHILD), manifest_dir=tmp_path)

    assert receipt.execution.outcome == RunOutcome.COMPLETED.value
    assert _observation(receipt)["result"]["owned_tree_cleanup"] == "CONFIRMED"


@pytest.mark.parametrize(
    ("remaining", "cleanup"),
    [(True, "NOT_CONFIRMED"), (None, "UNKNOWN")],
    ids=["members-observed-after-deadline", "member-count-unreadable"],
)
def test_exit_zero_with_uncertain_cleanup_is_never_completed_or_attested(
    tmp_path: Path, scripted_tree, remaining, cleanup: str
) -> None:
    scripted_tree(exited=True, returncode=0, stdout=b"ok", stderr=b"warn", remaining=remaining)

    receipt = capture_run(_manifest(tmp_path, SHORT_CHILD), manifest_dir=tmp_path)

    observed = _assert_typed_non_pass(receipt, RunOutcome.CLEANUP_NOT_ESTABLISHED)
    assert observed["result"]["owned_tree_cleanup"] == cleanup
    assert observed["result"]["streams_complete"] == "UNKNOWN"


def test_exit_without_observed_return_code_is_typed_exit_status_unknown(
    tmp_path: Path, scripted_tree
) -> None:
    scripted_tree(exited=True, returncode=None, remaining=False)

    receipt = capture_run(_manifest(tmp_path, SHORT_CHILD), manifest_dir=tmp_path)

    observed = _assert_typed_non_pass(receipt, RunOutcome.EXIT_STATUS_UNKNOWN)
    assert observed["result"]["owned_tree_cleanup"] == "CONFIRMED"
    assert observed["result"]["streams_complete"] == "YES"


@pytest.mark.parametrize(
    "exited", [True, False], ids=["exited-with-overflow", "running-at-overflow"]
)
def test_output_overflow_is_typed_whether_or_not_the_child_had_exited(
    tmp_path: Path, scripted_tree, small_cap: int, exited: bool
) -> None:
    scripted_tree(exited=exited, returncode=0, stdout=b"x" * (small_cap + 1), remaining=False)

    receipt = capture_run(
        _manifest(tmp_path, SHORT_CHILD, timeout_seconds=30), manifest_dir=tmp_path
    )

    observed = _assert_typed_non_pass(receipt, RunOutcome.OUTPUT_CAP_EXCEEDED)
    stdout = observed["result"]["stdout"]
    assert stdout["byte_count"] == small_cap
    assert stdout["retention_truncated"] is True
    assert stdout["completeness"] == "PARTIAL"


def test_deadline_is_observed_before_output_cap_and_exit_before_both(
    tmp_path: Path, small_cap: int
) -> None:
    out_path = tmp_path / "stdout.bin"
    err_path = tmp_path / "stderr.bin"
    out_path.write_bytes(b"x" * (small_cap + 1))
    err_path.write_bytes(b"")
    past = time.monotonic() - 1
    future = time.monotonic() + 60

    assert run_module._await_child_end(_ScriptedTree({"exited": False}), out_path, err_path, past) == "TIMEOUT"
    assert run_module._await_child_end(_ScriptedTree({"exited": False}), out_path, err_path, future) == "OUTPUT_CAP"
    assert run_module._await_child_end(_ScriptedTree({"exited": True}), out_path, err_path, past) == "EXITED"


def test_timeout_takes_precedence_when_deadline_is_observed_with_overflow(
    tmp_path: Path, scripted_tree, small_cap: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted_tree(exited=False, stdout=b"x" * (small_cap + 1), remaining=False)
    monkeypatch.setattr(run_module, "_await_child_end", lambda *_args: "TIMEOUT")

    receipt = capture_run(
        _manifest(tmp_path, SLEEP_CHILD, timeout_seconds=1), manifest_dir=tmp_path
    )

    observed = _assert_typed_non_pass(receipt, RunOutcome.TIMEOUT)
    result = observed["result"]
    assert result["owned_tree_cleanup"] == "CONFIRMED"
    assert result["streams_complete"] == "NO"
    assert result["stdout"]["byte_count"] == small_cap
    assert result["stdout"]["completeness"] == "PARTIAL"


def test_keyboard_interrupt_terminates_owned_tree_and_is_not_converted(
    tmp_path: Path, scripted_tree
) -> None:
    plan = scripted_tree(raise_on_launch=KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        capture_run(_manifest(tmp_path, SHORT_CHILD), manifest_dir=tmp_path)

    assert plan["events"] == ["terminate"]


def test_cancellation_is_not_recorded_as_timeout_and_still_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path, GRANDCHILD_HOLDS_STDOUT, timeout_seconds=30)
    calls = {"count": 0}

    def interrupt_after_grandchild_started(*_args, **_kwargs) -> None:
        calls["count"] += 1
        pid_file = tmp_path / "grandchild.pid"
        if pid_file.exists() and pid_file.read_text(encoding="utf-8").strip():
            raise KeyboardInterrupt

    monkeypatch.setattr(
        run_module, "_poll_pause", interrupt_after_grandchild_started, raising=False
    )

    with pytest.raises(KeyboardInterrupt):
        capture_run(manifest, manifest_dir=tmp_path)
    assert calls["count"] >= 1
    assert _wait_until_dead(_grandchild_pid(tmp_path))


def test_only_owned_descendants_are_terminated(
    tmp_path: Path, unrelated_sentinel: subprocess.Popen
) -> None:
    manifest = _manifest(tmp_path, GRANDCHILD_HOLDS_STDOUT, timeout_seconds=2)

    capture_run(manifest, manifest_dir=tmp_path)

    assert unrelated_sentinel.poll() is None, "an unowned process was terminated"
    assert _wait_until_dead(_grandchild_pid(tmp_path))
