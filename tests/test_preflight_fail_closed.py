"""Terminology: GNU Privacy Guard (GPG).

Local preflight gates must fail closed when their own evidence cannot establish a pass.
A gate that succeeds because its input was unreadable, empty or absent reports a missing
observation as a verified result. An unreadable commit range, a log with no parsable
signature rows, an empty log for a range whose commit count is not zero, a missing
presentation checker, and a skip audit over a failed or empty test run each have to stop a
push instead of clearing it."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import preflight

GOOD_ROW = "\x00".join(["a" * 40, "G", "Author", "Subject"])
UNSIGNED_ROW = "\x00".join(["b" * 40, "N", "Author", "Subject"])
RANGE = "a..b"


def _git_returns(monkeypatch: pytest.MonkeyPatch, *, log: tuple[int, str, str] = (0, "", ""),
                 count: tuple[int, str, str] = (0, "0", "")) -> None:
    """Stub the command boundary: one answer for 'git log', one for 'git rev-list'."""
    def fake(command: list[str], **kwargs: Any) -> tuple[int, str, str]:
        assert command[0] == "git", command
        if command[1] == "log":
            return log
        if command[1] == "rev-list":
            return count
        pytest.fail(f"unexpected git command: {command}")
    monkeypatch.setattr(preflight, "_run_command", fake)


def _commands_return(monkeypatch: pytest.MonkeyPatch, code: int, stdout: str = "", stderr: str = "") -> None:
    monkeypatch.setattr(preflight, "_run_command", lambda command, **kwargs: (code, stdout, stderr))


def _run_main(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> int:
    monkeypatch.setattr(sys, "argv", ["preflight.py", *arguments])
    return preflight.main()


def test_unreadable_commit_range_is_not_a_signature_pass(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _git_returns(monkeypatch, log=(128, "", "fatal: bad revision 'nowhere..HEAD'"))
    assert preflight.check_git_signatures("nowhere..HEAD") is False
    assert "[SIGNATURE GATE] PASS" not in capsys.readouterr().out


def test_unreadable_commit_range_does_not_exit_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    _git_returns(monkeypatch, log=(128, "", "fatal: bad revision"))
    assert _run_main(monkeypatch, "--signatures-only", "--range", RANGE) == 1


@pytest.mark.parametrize("log", [
    "a line that has no field separators",
    "a\x00b\x00c",
    "a\x00b\x00c\x00d\x00e",
])
def test_log_without_a_parsable_signature_row_is_not_a_signature_pass(
        log: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _git_returns(monkeypatch, log=(0, log, ""))
    assert preflight.check_git_signatures(RANGE) is False
    assert _run_main(monkeypatch, "--signatures-only", "--range", RANGE) == 1
    assert "[SIGNATURE GATE] PASS" not in capsys.readouterr().out


def test_one_unparsable_row_beside_good_rows_is_not_a_signature_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _git_returns(monkeypatch, log=(0, GOOD_ROW + "\nnot a signature row", ""))
    assert preflight.check_git_signatures(RANGE) is False


@pytest.mark.parametrize("count", [(0, "2", ""), (0, "", ""), (128, "", "fatal: bad revision")])
def test_empty_log_for_a_range_that_is_not_known_empty_is_not_a_signature_pass(
        count: tuple[int, str, str], monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    _git_returns(monkeypatch, log=(0, "", ""), count=count)
    assert preflight.check_git_signatures(RANGE) is False
    assert _run_main(monkeypatch, "--signatures-only", "--range", RANGE) == 1
    assert "[SIGNATURE GATE] PASS" not in capsys.readouterr().out


def test_signature_gate_keeps_its_pass_fail_and_empty_outcomes(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _git_returns(monkeypatch, log=(0, GOOD_ROW, ""))
    assert preflight.check_git_signatures(RANGE) is True
    assert _run_main(monkeypatch, "--signatures-only", "--range", RANGE) == 0
    _git_returns(monkeypatch, log=(0, GOOD_ROW + "\n" + UNSIGNED_ROW, ""))
    assert preflight.check_git_signatures(RANGE) is False
    _git_returns(monkeypatch, log=(0, "", ""), count=(0, "0", ""))
    assert preflight.check_git_signatures(RANGE) is True


def test_missing_presentation_checker_is_not_a_pass(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert not (tmp_path / "scripts" / "check_presentation.py").exists()
    assert preflight.check_presentation_gate() is False
    assert "[PRESENTATION GATE] PASS" not in capsys.readouterr().out


def test_missing_presentation_checker_does_not_exit_zero(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    for name in ("check_git_signatures", "check_readme_version", "check_docs_versions",
                 "check_stdlib_smoke", "check_schema_inventory", "check_pr_description"):
        monkeypatch.setattr(preflight, name, lambda *args, **kwargs: True)
    assert _run_main(monkeypatch) == 1


@pytest.mark.parametrize("code,stdout,stderr", [
    (1, "3 failed, 2 passed in 1.0s", ""),
    (1, "", ""),
    (2, "", "INTERNALERROR> interrupted"),
    (5, "no tests ran in 0.01s", ""),
])
def test_skip_audit_over_a_failed_run_is_not_a_pass(
        code: int, stdout: str, stderr: str,
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _commands_return(monkeypatch, code, stdout, stderr)
    assert preflight.check_test_skips() is False
    assert _run_main(monkeypatch, "--audit-skips") == 1
    assert "[SKIP AUDIT] PASS" not in capsys.readouterr().out


@pytest.mark.parametrize("output", ["", "   \n", "\n\n"])
def test_skip_audit_over_an_empty_run_is_not_a_pass(
        output: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    assert preflight.check_test_skips(output) is False
    _commands_return(monkeypatch, 0, "", "")
    assert preflight.check_test_skips() is False
    assert _run_main(monkeypatch, "--audit-skips") == 1
    assert "[SKIP AUDIT] PASS" not in capsys.readouterr().out


def test_skip_audit_keeps_its_pass_outcome_over_a_clean_run(monkeypatch: pytest.MonkeyPatch) -> None:
    _commands_return(monkeypatch, 0, "================ 12 passed in 1.0s ================", "")
    assert preflight.check_test_skips() is True
    assert _run_main(monkeypatch, "--audit-skips") == 0
