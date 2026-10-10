"""Executable Verifier Standard (VSTD) selected-validation instructional checks."""

from __future__ import annotations

import importlib.util
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest

from verifier.interoperability.storage import load_component_package, save_component_package


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "selected_validation" / "demo.py"


def load_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("selected_validation_demo", DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_retained_example_executes_one_coordinate_without_hiding_holes() -> None:
    demo = load_demo()
    record = demo.build_demo()
    assert record["evaluation"]["outcome"] == "PASS"
    judgments = {item["coordinate_id"]: item for item in record["updated_geometry"]["judgments"]}
    assert judgments[demo.SELECTED]["status"] == "VERIFIED"
    assert judgments[demo.UNSELECTED]["status"] == "INDETERMINATE"
    original = record["request"]["geometry"]
    assert original["judgments"][0]["status"] == "INDETERMINATE"
    assert judgments[demo.SELECTED]["assumptions"] == original["judgments"][0]["assumptions"]
    assert judgments[demo.SELECTED]["limitations"] == original["judgments"][0]["limitations"]
    assert not record["updated_analysis"]["ordinary_closed"]
    assert not record["updated_analysis"]["self_closed"]
    assert record["updated_geometry"]["mechanisms"] == original["mechanisms"]
    assert record["updated_analysis"]["holes"]


def test_changed_bytes_fail_against_the_same_pinned_expectation() -> None:
    demo = load_demo()
    record = demo.build_demo(b"apples\nbread\ntea\nextra item\n")
    assert record["evaluation"]["outcome"] == "FAIL"
    assert record["request"]["proposition"]["expected"] == demo.EXPECTED_DIGEST
    assert record["updated_geometry"]["judgments"][0]["status"] == "FALSIFIED"


def test_example_acquisition_is_bounded() -> None:
    with pytest.raises(ValueError, match="acquisition limit"):
        load_demo().build_demo(b"x" * 4097)


def test_documented_command_runs_from_an_unrelated_directory(tmp_path: Path) -> None:
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}
    result = subprocess.run([sys.executable, "-u", str(DEMO)], cwd=tmp_path,
                            env=environment, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["evaluation"]["outcome"] == "PASS"


def test_stored_package_round_trip_preserves_execution_plan_binding(tmp_path: Path) -> None:
    demo = load_demo()
    package = demo.build_package()
    assert package.license == "Apache-2.0"
    assert next(item.content for item in package.artifacts if item.path == "LICENSE") == (ROOT / "LICENSE").read_bytes()
    package = replace(package, registry=replace(package.registry, registry_version="example:loaded-catalog:2"))
    destination = tmp_path / "builtin.json"
    save_component_package(package, destination)
    loaded = load_component_package(destination, expected_digest=package.canonical_digest())
    record = demo.build_demo(package=loaded)
    assert record["schema_version"] == "verifier-selected-digest-execution-2"
    assert record["request"]["package"] == loaded.to_dict()
    assert record["request"]["registry"]["registry_version"] == "example:loaded-catalog:2"
    assert record["request"]["plan"]["binding_scope"] == "STORED_PACKAGE"
    assert record["request"]["plan"]["package_digest"] == loaded.canonical_digest()
    assert record["evaluation"]["outcome"] == "PASS"
    assert not record["updated_analysis"]["ordinary_closed"]
    assert not record["updated_analysis"]["self_closed"]


def test_documented_package_command_retains_source_without_extraction(tmp_path: Path) -> None:
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}
    result = subprocess.run([sys.executable, "-u", str(DEMO), "--package"], cwd=tmp_path,
                            env=environment, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["schema_version"] == "verifier-selected-digest-execution-2"
    assert record["evaluation"]["outcome"] == "PASS"
    assert list(tmp_path.iterdir()) == []
