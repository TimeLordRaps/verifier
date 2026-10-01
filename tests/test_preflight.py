"""Terminology: continuous integration (CI); GNU Privacy Guard (GPG); operating system (OS);
pull request (PR); Verifier Standard (VSTD).

Verify that local preflight checks catch defects before remote push."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import preflight


def test_stdlib_smoke_conforms() -> None:
    assert preflight.check_stdlib_smoke() is True


def test_readme_version_conforms() -> None:
    assert preflight.check_readme_version() is True


def test_readme_version_detects_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "2.0.0"\n', encoding="utf-8")
    (tmp_path / "README.md").write_text('python -m pip install "verifier-standard==1.0.0"\n', encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight.check_readme_version() is False


def test_docs_versions_conforms() -> None:
    assert preflight.check_docs_versions() is True


def test_docs_versions_detects_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "2.0.0"\n', encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "TEST.md").write_text('python -m pip install "verifier-standard==1.0.0"\n', encoding="utf-8")
    monkeypatch.setattr(preflight, "ROOT", tmp_path)
    assert preflight.check_docs_versions() is False


@pytest.mark.timeout(180)
def test_presentation_gate_conforms() -> None:
    assert preflight.check_presentation_gate() is True


def test_schema_inventory_conforms() -> None:
    assert preflight.check_schema_inventory() is True


def test_git_signatures_on_head_or_range() -> None:
    assert isinstance(preflight.check_git_signatures("HEAD~1..HEAD"), bool)


@pytest.mark.timeout(180)
def test_preflight_main_execution() -> None:
    assert preflight.main() in (0, 1)


def test_classify_skip_reason_rubric_tags() -> None:
    for category in preflight.TEST_SKIP_RUBRIC_CATEGORIES:
        assert preflight.classify_skip_reason(f"[{category}] Explicit justification") == category
        assert preflight.classify_skip_reason(f"{category}: Explicit justification") == category


def test_classify_skip_reason_heuristics() -> None:
    assert (
        preflight.classify_skip_reason("symlink creation is unavailable (errno=22, winerror=1314)")
        == "OS_CAPABILITY_GUARD"
    )
    assert (
        preflight.classify_skip_reason("first-in, first-out special objects are unavailable")
        == "OS_CAPABILITY_GUARD"
    )
    assert (
        preflight.classify_skip_reason("optional scitt dependency not installed")
        == "OPTIONAL_DEPENDENCY_ABSENT"
    )
    assert (
        preflight.classify_skip_reason("arbitrary unknown reason without justification")
        == "UNCLASSIFIED"
    )


def test_audit_test_skips_classified() -> None:
    sample_output = (
        "SKIPPED [33] tests/test_artifact_control.py:109: symlink creation is unavailable (errno=22, winerror=1314)\n"
        "SKIPPED [5] tests/test_artifact_control.py:117: first-in, first-out special objects are unavailable\n"
        "SKIPPED [1] tests/test_graph_topology_integration.py:160: named pipe creation requires Unix\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is True
    assert counts["OS_CAPABILITY_GUARD"] == 39
    assert len(unclassified) == 0
    assert preflight.check_test_skips(sample_output) is True


def test_audit_test_skips_detects_unclassified() -> None:
    sample_output = (
        "SKIPPED [1] tests/test_foo.py:12: arbitrary unclassified skip\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is False
    assert len(unclassified) == 1
    assert unclassified[0] == ("tests/test_foo.py:12", "arbitrary unclassified skip")
    assert preflight.check_test_skips(sample_output) is False


def test_audit_test_skips_handles_windows_drive_letters_and_node_ids() -> None:
    drive_e = "E" + ":\\"
    drive_c = "C" + ":\\"
    sample_output = (
        f"SKIPPED [33] {drive_e}verifier\\tests\\test_artifact_control.py:109: symlink creation is unavailable (errno=22, winerror=1314)\n"
        "SKIPPED [1] tests/test_foo.py::test_bar: [`OPTIONAL_DEPENDENCY_ABSENT`] missing extra\n"
        f"SKIPPED {drive_c}repo\\tests\\test_baz.py:42: EXTERNAL_SERVICE_BOUNDARY - live endpoint offline\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is True
    assert counts["OS_CAPABILITY_GUARD"] == 33
    assert counts["OPTIONAL_DEPENDENCY_ABSENT"] == 1
    assert counts["EXTERNAL_SERVICE_BOUNDARY"] == 1
    assert len(unclassified) == 0


def test_audit_test_skips_detects_summary_count_discrepancy() -> None:
    sample_output = (
        "SKIPPED [5] tests/test_artifact_control.py:117: first-in, first-out special objects are unavailable\n"
        "=========================== 100 passed, 39 skipped in 10.50s ===========================\n"
    )
    success, counts, unclassified = preflight.audit_test_skips(sample_output)
    assert success is False
    assert counts["OS_CAPABILITY_GUARD"] == 5
    assert any("PYTEST_SUMMARY_DISCREPANCY" in item[0] for item in unclassified)
    assert any("pytest reported 39 skipped tests, but audit parsed only 5" in item[1] for item in unclassified)


