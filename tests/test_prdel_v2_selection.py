"""Refutation tests for the exact native-v2 PRDEL source selection."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

from scripts import check_prdel_v2_selection as CHECKER


OVERLAY_ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = Path(os.environ.get("PRDEL_V2_TARGET_ROOT", OVERLAY_ROOT))
RETAINED_FIXTURE_COMMIT = "36790ab3ff14978ec286debc705778de32bcc6ca"
PROFILE = OVERLAY_ROOT / "src/verifier/profiles/prdel-native-v2-selection-1.json"
CHECKER_PATH = OVERLAY_ROOT / "scripts/check_prdel_v2_selection.py"

assert Path(CHECKER.__file__).resolve() == CHECKER_PATH


def _profile() -> dict[str, object]:
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def _write_profile(root: Path, value: dict[str, object]) -> Path:
    path = root / "src/verifier/profiles/prdel-native-v2-selection-1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def _retained_bytes(relative: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(OVERLAY_ROOT), "show", f"{RETAINED_FIXTURE_COMMIT}:{relative}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result.stdout


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    target = tmp_path / "target"
    selection = tmp_path / "selection"
    value = json.loads(
        _retained_bytes("src/verifier/profiles/prdel-native-v2-selection-1.json")
    )
    for row in value["inventory"]:
        destination_root = target if row["origin"] == "target" else selection
        destination = destination_root / row["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_retained_bytes(row["path"]))
    profile_path = _write_profile(selection, value)
    return target, selection, profile_path, value


def _codes(report: dict[str, object]) -> set[str]:
    return {finding["code"] for finding in report["findings"]}


def test_exact_selection_matches_sealed_target(tmp_path: Path) -> None:
    target, selection, profile_path, _ = _fixture(tmp_path)
    report = CHECKER.check_selection(target, profile_path, selection_root=selection)
    assert report == {
        "schema_version": "verifier-prdel-native-v2-selection-report-1",
        "status": "PASS",
        "checked_files": 17,
        "findings": [],
    }


def test_current_checkout_cannot_borrow_retained_selection() -> None:
    report = CHECKER.check_selection(OVERLAY_ROOT, PROFILE, selection_root=OVERLAY_ROOT)
    assert report["status"] == "FAIL"
    assert {"SELECTED_BYTES", "SELECTED_SHA256"} <= _codes(report)


def test_old_manifest_v2_selection_is_not_native_v2_selection() -> None:
    old = TARGET_ROOT / "src/verifier/profiles/prdel-manifest-2-selection.json"
    report = CHECKER.check_selection(TARGET_ROOT, old, selection_root=OVERLAY_ROOT)
    assert report["status"] == "FAIL"
    assert "PROFILE_SCHEMA" in _codes(report)


def test_mutated_selected_bytes_fail(tmp_path: Path) -> None:
    target, selection, profile_path, _ = _fixture(tmp_path)
    selected = target / "src/verifier/runtime/prdel.py"
    selected.write_bytes(selected.read_bytes() + b"\n")
    report = CHECKER.check_selection(target, profile_path, selection_root=selection)
    assert report["status"] == "FAIL"
    assert {"SELECTED_BYTES", "SELECTED_SHA256"} <= _codes(report)


def test_stale_declared_hash_fails(tmp_path: Path) -> None:
    target, selection, _, value = _fixture(tmp_path)
    stale = copy.deepcopy(value)
    stale["inventory"][1]["sha256"] = "0" * 64
    profile_path = _write_profile(selection, stale)
    report = CHECKER.check_selection(target, profile_path, selection_root=selection)
    assert report["status"] == "FAIL"
    assert "SELECTED_SHA256" in _codes(report)


def test_omitted_selected_path_fails(tmp_path: Path) -> None:
    target, selection, _, value = _fixture(tmp_path)
    omitted = copy.deepcopy(value)
    omitted["inventory"] = omitted["inventory"][:-1]
    profile_path = _write_profile(selection, omitted)
    report = CHECKER.check_selection(target, profile_path, selection_root=selection)
    assert report["status"] == "FAIL"
    assert "INVENTORY_PATH_SET" in _codes(report)


def test_extra_selected_path_fails(tmp_path: Path) -> None:
    target, selection, _, value = _fixture(tmp_path)
    extra = copy.deepcopy(value)
    row = copy.deepcopy(extra["inventory"][0])
    row["path"] = "src/verifier/runtime/undeclared_prdel_v2.py"
    extra["inventory"].append(row)
    extra["inventory"].sort(key=lambda item: item["path"])
    profile_path = _write_profile(selection, extra)
    report = CHECKER.check_selection(target, profile_path, selection_root=selection)
    assert report["status"] == "FAIL"
    assert "INVENTORY_PATH_SET" in _codes(report)


def test_legacy_selection_is_exact_and_release_claims_remain_absent() -> None:
    value = _profile()
    legacy = TARGET_ROOT / value["legacy_compatibility"]["path"]
    assert legacy.stat().st_size == 3992
    assert hashlib.sha256(legacy.read_bytes()).hexdigest() == CHECKER.LEGACY_SELECTION_SHA256
    assert value["candidate_status"] == "DEVELOPMENT_CANDIDATE"
    assert value["semantic_completeness"] == "UNKNOWN"
    assert value["release_authorized"] is False
    assert value["release_dependencies"] == [
        "PACKAGED_SCHEMA_INVENTORY_OWNER_ADMISSION_REQUIRED",
        "FULL_APPLICABLE_TEST_AND_RELEASE_EVIDENCE_REQUIRED",
        "HUMAN_ACCEPTANCE_AND_RELEASE_AUTHORITY_REQUIRED",
    ]
