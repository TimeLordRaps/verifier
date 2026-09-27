"""Local command-line interface (CLI) pipeline counterexamples; no domain proof."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from verifier.runtime.gate_pipeline import (
    check_pipeline, init_pipeline, plan_pipeline, run_pipeline,
)


def manifest(tmp_path: Path, commands: list[list[str]]) -> Path:
    (tmp_path / "input.txt").write_text("retained input", encoding="utf-8")
    value = {"schema_version": "verifier-gate-pipeline-1", "root": ".",
             "inputs": ["input.txt"], "overall_timeout_seconds": 10,
             "max_output_bytes": 4096,
             "steps": [{"id": f"check{i}", "argv": command,
                        "needs": [] if i == 0 else [f"check{i-1}"],
                        "timeout_seconds": 2} for i, command in enumerate(commands)]}
    path = tmp_path / "pipeline.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_plan_does_not_execute_and_run_binds_inputs(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "print('observed')"]])
    assert plan_pipeline(path)["status"] == "PASS"
    receipt = tmp_path / "receipt.json"
    result = run_pipeline(path, receipt)
    assert result["status"] == "PASS"
    assert result["steps"][0]["stdout"] == "observed" + os.linesep
    assert check_pipeline(receipt)["status"] == "PASS"
    (tmp_path / "input.txt").write_text("changed", encoding="utf-8")
    assert check_pipeline(receipt)["status"] == "FAIL"


def test_failure_blocks_dependent_command(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "raise SystemExit(7)"],
                              [sys.executable, "-c", "raise RuntimeError('must not run')"]])
    result = run_pipeline(path, tmp_path / "receipt.json")
    assert result["status"] == "FAIL"
    assert [step["status"] for step in result["steps"]] == ["FAIL", "BLOCKED"]


def test_timeout_is_retained(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "import time; time.sleep(10)"]])
    value = json.loads(path.read_text())
    value["steps"][0]["timeout_seconds"] = 0.2
    path.write_text(json.dumps(value))
    result = run_pipeline(path, tmp_path / "receipt.json")
    assert result["status"] == "FAIL"
    assert result["steps"][0]["status"] == "TIMEOUT"


@pytest.mark.parametrize("mutation", ["cycle", "unknown", "duplicate", "empty", "escape", "badargv", "duplicatekey"])
def test_invalid_manifests_do_not_execute(tmp_path: Path, mutation: str) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "open('unexpected','w').write('bad')"]])
    value = json.loads(path.read_text())
    if mutation == "cycle": value["steps"][0]["needs"] = ["check0"]
    elif mutation == "unknown": value["surprise"] = True
    elif mutation == "duplicate": value["steps"].append(value["steps"][0])
    elif mutation == "empty": value["inputs"] = []
    elif mutation == "escape": value["inputs"] = ["../outside"]
    elif mutation == "badargv": value["steps"][0]["argv"] = "echo injected"
    if mutation == "duplicatekey": path.write_text('{"root":".","root":"."}')
    else: path.write_text(json.dumps(value))
    with pytest.raises(ValueError): plan_pipeline(path)
    assert not (tmp_path / "unexpected").exists()


def test_plan_is_read_only_and_reorders_dependencies(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "open('unexpected','w').write('bad')"], [sys.executable, "-c", "pass"]])
    value = json.loads(path.read_text()); value["steps"].reverse(); path.write_text(json.dumps(value))
    assert plan_pipeline(path)["order"] == ["check0", "check1"]
    assert not (tmp_path / "unexpected").exists()


def test_changed_input_during_run_cannot_pass(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "open('input.txt','w').write('different')"]])
    receipt = run_pipeline(path, tmp_path / "receipt.json")
    assert receipt["steps"][0]["status"] == "PASS"
    assert receipt["status"] == "FAIL"
    assert receipt["inputs_unchanged"] is False


def test_output_limit_is_a_failure(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "print('x'*100000)"]])
    receipt = run_pipeline(path, tmp_path / "receipt.json")
    assert receipt["steps"][0]["status"] == "OUTPUT_LIMIT"
    assert len(receipt["steps"][0]["stdout"].encode()) <= 4096
    assert receipt["status"] == "FAIL"


def test_receipt_output_does_not_digest_itself(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "pass"]])
    value = json.loads(path.read_text()); value["inputs"] = ["."]; path.write_text(json.dumps(value))
    output = tmp_path / "receipt.json"
    result = run_pipeline(path, output)
    assert result["status"] == "PASS"
    assert "receipt.json" not in [item["path"] for item in result["inputs"]]
    assert check_pipeline(output)["status"] == "PASS"


def test_tampered_receipt_and_changed_manifest_rejected(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "pass"]]); output = tmp_path / "receipt.json"
    run_pipeline(path, output); original = output.read_bytes()
    value = json.loads(original); value["status"] = "FAIL"; output.write_text(json.dumps(value))
    assert check_pipeline(output)["status"] == "FAIL"
    output.write_bytes(original); path.write_bytes(path.read_bytes() + b" ")
    assert check_pipeline(output)["status"] == "FAIL"


def test_init_is_exclusive_and_project_checks_plan(tmp_path: Path) -> None:
    path = tmp_path / "starter.json"
    assert init_pipeline(path)["status"] == "PASS"
    assert plan_pipeline(path)["status"] == "PASS"
    with pytest.raises(FileExistsError): init_pipeline(path)


@pytest.mark.parametrize("parent_sleeps", [False, True])
def test_selected_inherited_child_cannot_write_after_cleanup(tmp_path: Path, parent_sleeps: bool) -> None:
    child = "import time;open('started','w').write('yes');time.sleep(1.5);open('escaped','w').write('bad')"
    code = ("import subprocess,sys,time,pathlib; subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);"
            "deadline=time.monotonic()+2\nwhile not pathlib.Path('started').exists() and time.monotonic()<deadline: time.sleep(.01)\n")
    if parent_sleeps: code += "time.sleep(10)\n"
    path = manifest(tmp_path, [[sys.executable, "-c", code]])
    value = json.loads(path.read_text()); value["steps"][0]["timeout_seconds"] = .8; path.write_text(json.dumps(value))
    receipt = run_pipeline(path, tmp_path / "receipt.json")
    assert (tmp_path / "started").read_text() == "yes"
    assert receipt["steps"][0]["cleanup"] == ("OWNED_TREE_TERMINATED" if os.name == "nt" else "OWNED_GROUP_SIGNALLED")
    assert receipt["steps"][0]["status"] == ("TIMEOUT" if parent_sleeps else "PASS")
    time.sleep(1.7)
    assert not (tmp_path / "escaped").exists()


def test_overall_deadline_blocks_remaining_independent_step(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "import time;time.sleep(10)"], [sys.executable, "-c", "pass"]])
    value = json.loads(path.read_text()); value["overall_timeout_seconds"] = .2; value["steps"][1]["needs"] = []; path.write_text(json.dumps(value))
    receipt = run_pipeline(path, tmp_path / "receipt.json")
    assert [item["status"] for item in receipt["steps"]] == ["TIMEOUT", "BLOCKED"]


def test_public_cli_round_trip_separates_progress_and_json(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.json"
    output = tmp_path / "receipt.json"
    commands = [["init", str(path)], ["plan", str(path)],
                ["run", str(path), "--output", str(output)], ["check", str(output)]]
    for command in commands:
        result = subprocess.run([sys.executable, "-m", "verifier", "gate", *command, "--json"],
                                capture_output=True, text=True, timeout=10, check=False)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["status"] == "PASS"
        if command[0] == "run": assert "paths_0: START" in result.stderr


def test_receipt_relocation_requires_explicit_manifest_authority(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "pass"]])
    (tmp_path / "results").mkdir()
    output = tmp_path / "results" / "receipt.json"
    run_pipeline(path, output)
    assert check_pipeline(output)["status"] == "FAIL"
    assert check_pipeline(output, manifest_path=path)["status"] == "PASS"


def test_rehashed_false_success_is_structurally_refused(tmp_path: Path) -> None:
    from verifier.runtime.gate_pipeline import _canonical, _digest
    path = manifest(tmp_path, [[sys.executable, "-c", "raise SystemExit(2)"]]); output = tmp_path / "receipt.json"
    value = run_pipeline(path, output)
    value["status"] = "PASS"
    value.pop("receipt_digest")
    value["receipt_digest"] = _digest(_canonical(value))
    output.write_text(json.dumps(value))
    assert check_pipeline(output)["status"] == "FAIL"


def test_failing_run_retains_separate_receipt_integrity(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "raise SystemExit(2)"]]); output = tmp_path / "receipt.json"
    run_pipeline(path, output)
    assert check_pipeline(output)["integrity_status"] == "PASS"
    assert check_pipeline(output)["run_status"] == "FAIL"


def test_check_cli_cannot_approve_intact_failed_run(tmp_path: Path) -> None:
    path = manifest(tmp_path, [[sys.executable, "-c", "raise SystemExit(2)"]]); output = tmp_path / "receipt.json"
    run_pipeline(path, output)
    result = subprocess.run([sys.executable, "-m", "verifier", "gate", "check", str(output), "--json"],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode != 0
    value = json.loads(result.stdout)
    assert value["integrity_status"] == "PASS"
    assert value["status"] == value["run_status"] == "FAIL"


def test_rehashed_overbound_output_cannot_pass_consistency(tmp_path: Path) -> None:
    from verifier.runtime.gate_pipeline import _canonical, _digest
    path = manifest(tmp_path, [[sys.executable, "-c", "pass"]]); output = tmp_path / "receipt.json"
    value = run_pipeline(path, output)
    value["steps"][0]["stdout"] = "x" * 4097
    value.pop("receipt_digest"); value["receipt_digest"] = _digest(_canonical(value))
    output.write_text(json.dumps(value))
    assert check_pipeline(output)["status"] == "FAIL"
