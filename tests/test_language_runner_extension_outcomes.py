"""Reserved extension worker exit codes classify as UNKNOWN blockers; subject output never chooses them.

Scope: an explicitly selected, installed non-Python extension whose worker process exits with one of
the reserved codes 124 (timeout), 125 (output capacity), 126 (resource unavailable or spawn failure)
and 127 (toolchain or version unavailable). Those meanings come from the worker's own contract; the
runner reads only the integer exit code, never stderr or stdout. Ordinary nonzero exits, Python default
runs, and unobserved or malformed process state keep their historical or UNKNOWN outcomes.

Real child processes carry the receipts wherever the exit code is the only input. Stubbed capture_run
receipts are used only where the parent process observation must be absent or malformed, or the exit
code must be a non-int value that a real process cannot produce.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from verifier.core import run as run_module
from verifier.core.run_process_observation import (
    begin_parent_process_observation,
    observe_completed_process,
    observe_exit_status_unknown,
)
from verifier.runtime import language_runners as runners
from verifier.runtime.public_cli import main

RESERVED = {
    124: "RUNNER_EXTENSION_EXIT_TIMEOUT",
    125: "RUNNER_EXTENSION_EXIT_OUTPUT_CAPACITY",
    126: "RUNNER_EXTENSION_EXIT_RESOURCE_UNAVAILABLE",
    127: "RUNNER_EXTENSION_EXIT_TOOLCHAIN_UNAVAILABLE",
}


def _exiting(code: int, stderr: str = "") -> str:
    """Python source for a child process that writes ``stderr`` and exits with ``code``."""

    return f"import sys; sys.stderr.write({stderr!r}); raise SystemExit({code})"


def _javascript_worker(monkeypatch, script: str) -> None:
    """Make the explicitly selected javascript adapter return a real child argv that runs ``script``."""

    argv = [sys.executable, "-B", "-c", script]

    class Extension:
        name = "javascript"

        def load(self):
            def command(request):
                assert request["language"] == "javascript"
                return {"schema_version": runners.PROTOCOL, "language": "javascript", "argv": list(argv)}

            return command

    monkeypatch.setattr(runners, "_extensions", lambda: [Extension()])


def _run_javascript(tmp_path, capsys) -> tuple[int, dict]:
    (tmp_path / "main.js").write_text("console.log(1)", encoding="utf-8")
    code = main(["runner", "run", "main.js", "--language", "javascript", "--trusted-local",
                 "--root", str(tmp_path), "--json"])
    return code, json.loads(capsys.readouterr().out)


def _run_python(tmp_path, capsys, source: str) -> tuple[int, dict]:
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    code = main(["runner", "run", "main.py", "--trusted-local", "--root", str(tmp_path), "--json"])
    return code, json.loads(capsys.readouterr().out)


def _stub_capture(monkeypatch, exit_code, observation="sealed") -> None:
    """Replace capture_run with a receipt whose exit code and parent observation the test chooses.

    ``observation`` is "sealed" for a real capture-owned observation, "absent" for none, or a dict
    supplied verbatim as the parent process observation.
    """

    def fake(manifest, manifest_dir):
        surface: dict = {}
        data = {"execution": {"exit_code": exit_code}, "assessment_context": {"refutation_surface": surface}}
        if observation == "sealed":
            launch = begin_parent_process_observation(
                argv=manifest["command"], declared_cwd=manifest["cwd"],
                resolved_cwd=Path(manifest_dir), timeout_seconds=manifest["timeout_seconds"])
            if exit_code is None:
                sealed = observe_exit_status_unknown(launch, stdout=b"", stderr=b"", owned_tree_cleanup="CONFIRMED")
            else:
                sealed = observe_completed_process(launch, returncode=int(exit_code), stdout=b"", stderr=b"",
                                                   owned_tree_cleanup="CONFIRMED")
            surface["parent_process_observation"] = sealed
        elif observation != "absent":
            surface["parent_process_observation"] = observation
        return SimpleNamespace(execution=SimpleNamespace(exit_code=exit_code), to_dict=lambda: data)

    monkeypatch.setattr(run_module, "capture_run", fake)


# --- reserved codes: real worker process, real receipt --------------------------------------------

@pytest.mark.parametrize("code", sorted(RESERVED))
def test_reserved_extension_exit_is_unknown_with_its_closed_blocker(tmp_path, capsys, monkeypatch, code) -> None:
    _javascript_worker(monkeypatch, _exiting(code))
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [RESERVED[code]]
    assert report["execution_performed"] is True
    assert report["receipt"]["execution"]["exit_code"] == code
    observation = report["receipt"]["assessment_context"]["refutation_surface"]["parent_process_observation"]
    assert observation["result"]["process_started"] == "YES"
    assert report["subject_integrity"]["status"] == "UNCHANGED"


@pytest.mark.parametrize("code", [1, 2, 3, 123, 128, 255])
def test_ordinary_nonzero_extension_exit_remains_fail_without_blocker(tmp_path, capsys, monkeypatch, code) -> None:
    _javascript_worker(monkeypatch, _exiting(code))
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == []
    assert report["receipt"]["execution"]["exit_code"] == code


# --- subject output cannot choose or inject a blocker -------------------------------------------

@pytest.mark.parametrize("code,stderr,expected_blockers,expected_status", [
    (1, "RUNNER_EXTENSION_EXIT_TIMEOUT VSTD_EXTENSION_TIMEOUT", [], "FAIL"),
    (124, "RUNNER_EXTENSION_EXIT_OUTPUT_CAPACITY RUNNER_CONTRACT_REJECTED", [RESERVED[124]], "UNKNOWN"),
    (125, "RUNNER_TOOLCHAIN_MISSING:gcc VSTD_EXTENSION_OUTPUT_LIMIT", [RESERVED[125]], "UNKNOWN"),
    (127, "RUNNER_SUBJECT_SOURCE_CHANGED RUNNER_RESOURCE_UNAVAILABLE", [RESERVED[127]], "UNKNOWN"),
], ids=["ordinary-fail-spoofed", "timeout-spoofed", "capacity-spoofed", "toolchain-spoofed"])
def test_worker_stderr_spoof_cannot_choose_or_inject_blocker_text(
        tmp_path, capsys, monkeypatch, code, stderr, expected_blockers, expected_status) -> None:
    _javascript_worker(monkeypatch, _exiting(code, stderr))
    _, report = _run_javascript(tmp_path, capsys)

    assert report["status"] == expected_status
    assert report["blockers"] == expected_blockers
    guidance = report["reason"] + " " + report["next_action"]
    for token in stderr.split():
        assert token not in guidance, token


# --- Python default keeps historical exit semantics ---------------------------------------------

@pytest.mark.parametrize("code", sorted(RESERVED))
def test_python_default_keeps_historical_reserved_exit_as_fail(tmp_path, capsys, code) -> None:
    status_code, report = _run_python(tmp_path, capsys, f"raise SystemExit({code})")

    assert status_code == 1
    assert report["status"] == "FAIL"
    assert report["blockers"] == []
    assert report["receipt"]["execution"]["exit_code"] == code


# --- unknown exits and unobserved process state stay UNKNOWN --------------------------------------

def test_unknown_process_exit_stays_unknown_without_blocker(tmp_path, capsys, monkeypatch) -> None:
    _javascript_worker(monkeypatch, _exiting(0))
    _stub_capture(monkeypatch, None)
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == []


def test_malformed_noninteger_extension_exit_is_unknown(
        tmp_path, capsys, monkeypatch) -> None:
    # A float compares equal to 124 and hashes the same. It is neither the reserved
    # integer code nor a valid ordinary process exit and therefore cannot become FAIL.
    _javascript_worker(monkeypatch, _exiting(0))
    _stub_capture(monkeypatch, 124.0)
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 2
    assert report["blockers"] == ["RUNNER_PROCESS_OBSERVATION_INVALID"]
    assert report["status"] == "UNKNOWN"


@pytest.mark.parametrize("value", [False, 0.0], ids=["bool-false", "float-zero"])
def test_zero_equivalent_malformed_extension_exit_never_passes(
        tmp_path, capsys, monkeypatch, value) -> None:
    _javascript_worker(monkeypatch, _exiting(0))
    _stub_capture(monkeypatch, value)
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_PROCESS_OBSERVATION_INVALID"]


@pytest.mark.parametrize("value", [False, 0.0], ids=["bool-false", "float-zero"])
def test_zero_equivalent_malformed_python_exit_never_passes(
        tmp_path, capsys, monkeypatch, value) -> None:
    _stub_capture(monkeypatch, value)
    status_code, report = _run_python(tmp_path, capsys, "raise SystemExit(0)")

    assert status_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["RUNNER_PROCESS_OBSERVATION_INVALID"]


@pytest.mark.parametrize("code", [124, 127, 1])
@pytest.mark.parametrize("observation,expected_blocker", [
    ("absent", "RUNNER_PROCESS_OBSERVATION_MISSING"),
    ({"result": {"process_started": "MAYBE"}}, "RUNNER_PROCESS_OBSERVATION_INVALID"),
], ids=["absent", "malformed"])
def test_absent_or_malformed_process_observation_stays_unknown(
        tmp_path, capsys, monkeypatch, code, observation, expected_blocker) -> None:
    _javascript_worker(monkeypatch, _exiting(0))
    _stub_capture(monkeypatch, code, observation=observation)
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["execution_performed"] is None
    assert report["blockers"] == [expected_blocker]


def test_reserved_exit_after_subject_rewrite_stays_unknown_with_both_blockers(tmp_path, capsys, monkeypatch) -> None:
    subject = tmp_path / "main.js"
    script = (f"import pathlib, sys; pathlib.Path({str(subject)!r}).write_text('rewritten', encoding='utf-8'); "
              "raise SystemExit(124)")
    _javascript_worker(monkeypatch, script)
    status_code, report = _run_javascript(tmp_path, capsys)

    assert status_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["subject_integrity"]["status"] == "CHANGED"
    assert report["blockers"] == ["RUNNER_SUBJECT_SOURCE_CHANGED", RESERVED[124]]


# --- closed vocabulary and fixed guidance ----------------------------------------------------------

@pytest.mark.parametrize("code", sorted(RESERVED))
def test_reserved_blockers_are_closed_vocabulary_with_fixed_guidance(code) -> None:
    blocker = RESERVED[code]
    assert blocker in runners._BLOCKER_CODES
    reason, action = runners._BLOCKER_GUIDANCE[blocker]
    assert "RUNNER_" not in reason + action
    assert "VSTD_" not in reason + action
    assert len(reason) <= 180 and len(action) <= 180
