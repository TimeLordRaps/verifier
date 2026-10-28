"""Local preflight must preserve unavailable evidence and authority bounds.

Terminology: JavaScript Object Notation (JSON); pull request (PR).
"""
from __future__ import annotations
import json
import subprocess
import sys
from typing import Any
import pytest
from test_preflight import preflight

@pytest.mark.parametrize("code,output,expected",[
    (0,json.dumps({"status":"PASS","findings":[]}),True),
    (1,json.dumps({"status":"FAIL","findings":["mismatch"]}),False),
    (0,json.dumps({"status":"FAIL","findings":["mismatch"]}),False),
    (0,"[PR DESCRIPTION] UNKNOWN: description unavailable",None),
    (0,"[PR DESCRIPTION] PASS: no pull request is attached to this branch.",None),
    (0,"",None),
    (0,"[]",None),
    (0,json.dumps({"status":"PASS","findings":["mismatch"]}),False),
    (0,json.dumps({"status":"PASS"}),None),
    (0,json.dumps({"status":"PASS","findings":[1]}),None),
])
def test_description_outcome_requires_explicit_parseable_evidence(
        code: int, output: str, expected: bool | None,
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    commands: list[list[str]] = []
    def run(command: list[str], **kwargs: Any) -> tuple[int, str, str]:
        commands.append(command);return code,output,""
    monkeypatch.setattr(preflight,"_run_command",run)
    assert preflight.check_pr_description() is expected
    assert len(commands)==1 and "--json" in commands[0]
    text=capsys.readouterr().out
    if expected is None:
        assert "[PR DESCRIPTION GATE] UNKNOWN" in text
        assert "[PR DESCRIPTION GATE] PASS" not in text

def local_checks(monkeypatch: pytest.MonkeyPatch, description: bool | None) -> None:
    monkeypatch.setattr(sys,"argv",["preflight.py"])
    for name in ("check_git_signatures","check_readme_version","check_docs_versions","check_stdlib_smoke","check_presentation_gate","check_schema_inventory"):
        monkeypatch.setattr(preflight,name,lambda *a,**kw:True)
    monkeypatch.setattr(preflight,"check_pr_description",lambda:description)

@pytest.mark.parametrize("error",[OSError("unavailable"),subprocess.TimeoutExpired(["checker"],1)])
def test_unavailable_description_process_preserves_unknown(
        error: BaseException, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    def run(*args: Any, **kwargs: Any) -> tuple[int, str, str]:
        raise error
    monkeypatch.setattr(preflight,"_run_command",run)
    assert preflight.check_pr_description() is None
    assert "[PR DESCRIPTION GATE] UNKNOWN" in capsys.readouterr().out

@pytest.mark.parametrize("description,expected",[(True,0),(False,1),(None,2)])
def test_main_retains_three_outcomes_without_claiming_push_authority(
        description: bool | None, expected: int, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    local_checks(monkeypatch,description)
    assert preflight.main()==expected
    text=capsys.readouterr().out
    assert "Safe to push" not in text
    if description is None:
        assert "UNKNOWN" in text and "ALL CHECKS PASSED" not in text
    if description is True:
        assert "LOCAL CHECKS PASSED" in text and "authorization" in text

def test_known_local_failure_is_not_hidden_by_unknown_description(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    local_checks(monkeypatch,None)
    monkeypatch.setattr(preflight,"check_readme_version",lambda:False)
    assert preflight.main()==1
    assert "FAILED" in capsys.readouterr().out

@pytest.mark.parametrize("full_result,expected",[(True,2),(False,1)])
def test_full_suite_still_runs_with_unknown_description(
        full_result: bool, expected: int, monkeypatch: pytest.MonkeyPatch) -> None:
    local_checks(monkeypatch,None);monkeypatch.setattr(sys,"argv",["preflight.py","--full"])
    calls: list[bool] = []
    def full() -> bool:
        calls.append(True)
        return full_result
    monkeypatch.setattr(preflight,"check_full_test_suite",full)
    assert preflight.main()==expected and calls==[True]
