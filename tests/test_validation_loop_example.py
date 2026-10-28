"""Verifier Standard (VSTD) bounded validation-loop example regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.core.geometry_io import load_verification_geometry
from test_selected_validation_example import DEMO, ROOT, load_demo


def test_two_file_loop_replans_and_keeps_unrelated_holes() -> None:
    demo = load_demo()
    record = demo.build_loop_demo()
    assert record["stop_reason"] == "TARGETS_EXHAUSTED"
    assert record["attempted_steps"] == 2
    assert record["reserved_evidence_bytes"] == 8192
    assert not record["unattempted_targets"]
    first, second = (step["execution"] for step in record["steps"])
    assert first["request"]["geometry"] == record["request"]["geometry"]
    assert second["request"]["geometry"] == first["updated_geometry"]
    assert first["request"]["plan"]["plan_id"] != second["request"]["plan"]["plan_id"]
    assert all(step["execution"]["evaluation"]["outcome"] == "PASS" for step in record["steps"])
    judgments = {item["coordinate_id"]: item["status"] for item in record["final_geometry"]["judgments"]}
    assert judgments[demo.SELECTED] == judgments[demo.PANTRY] == "VERIFIED"
    assert judgments[demo.UNSELECTED] == "INDETERMINATE"
    assert not record["final_analysis"]["ordinary_closed"]
    assert not record["final_analysis"]["self_closed"]
    assert record["final_plan"]["geometry_digest"] == load_verification_geometry(record["final_geometry"]).canonical_digest()


@pytest.mark.parametrize("options,reason", [
    ({"max_steps": 1}, "STEP_BUDGET_EXHAUSTED"),
    ({"max_reserved_evidence_bytes": 4096}, "EVIDENCE_BUDGET_EXHAUSTED"),
    ({"first_payload": b"changed first file"}, "FAILED"),
])
def test_loop_example_preserves_unattempted_second_target(options: dict, reason: str) -> None:
    demo = load_demo()
    record = demo.build_loop_demo(**options)
    assert record["stop_reason"] == reason
    assert record["attempted_steps"] == 1
    assert record["reserved_evidence_bytes"] == 4096
    assert len(record["unattempted_targets"]) == 1
    assert next(item["status"] for item in record["final_geometry"]["judgments"]
                if item["coordinate_id"] == demo.PANTRY) == "INDETERMINATE"


def test_later_failure_preserves_earlier_bounded_result() -> None:
    demo = load_demo()
    record = demo.build_loop_demo(second_payload=b"changed pantry notes")
    assert record["stop_reason"] == "FAILED"
    assert [step["execution"]["evaluation"]["outcome"] for step in record["steps"]] == ["PASS", "FAIL"]
    judgments = {item["coordinate_id"]: item["status"] for item in record["final_geometry"]["judgments"]}
    assert judgments[demo.SELECTED] == "VERIFIED"
    assert judgments[demo.PANTRY] == "FALSIFIED"
    assert judgments[demo.UNSELECTED] == "INDETERMINATE"


@pytest.mark.parametrize("package_mode", [False, True])
def test_documented_loop_command_replays_without_writing_files(tmp_path: Path, package_mode: bool) -> None:
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}
    arguments = [sys.executable, "-u", str(DEMO), "--loop"]
    if package_mode:
        arguments.append("--package")
    result = subprocess.run(arguments, cwd=tmp_path, env=environment, text=True,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["stop_reason"] == "TARGETS_EXHAUSTED"
    assert record["attempted_steps"] == 2
    for step in record["steps"]:
        assert step["execution"]["request"]["plan"]["binding_scope"] == ("STORED_PACKAGE" if package_mode else "REGISTRY_ONLY")
    assert list(tmp_path.iterdir()) == []
