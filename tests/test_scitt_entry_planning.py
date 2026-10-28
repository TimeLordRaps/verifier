"""Supply Chain Integrity, Transparency, and Trust (SCITT) planning integration.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); command-line interface (CLI). Synthetic package outputs test
nonexecuting composition only, not native evidence or qualification.
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import replace
from types import ModuleType
from typing import Any

import pytest

from verifier.core.geometry import CoordinateStatus
from verifier.core.geometry_io import load_verification_geometry
from verifier.core.receipt import strict_json_loads
from verifier.interoperability.control_surface import CandidateStatus, analyze_verification_surface, plan_validation
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision, ExecutionReadinessStatus, PostExecutionReassessmentContract,
    SuppliedAuthorizationDecision, assess_execution_readiness,
)
from verifier.interoperability.storage import StoredComponentPackage, load_component_package
from verifier.runtime.public_cli import main

from test_scitt_catalog_entry import entry, files
from test_scitt_native_runner import runner
from test_scitt_package_comparison import change_artifact, change_json, comparison, native_output, specimen


ROOT = Path(__file__).resolve().parents[1]
GEOMETRY = ROOT / "examples/scitt_native_interop/planning_geometry.json"


def test_public_planning_geometry_is_strict_and_explicitly_indeterminate() -> None:
    geometry = load_verification_geometry(GEOMETRY)
    assert len(geometry.coordinates) == len(geometry.judgments) == 3
    assert all(item.status is CoordinateStatus.INDETERMINATE for item in geometry.judgments)
    assert {item.mechanism_id for item in geometry.mechanisms} == {
        "scitt-cose:statement-signature", "scitt-cose:receipt-inclusion",
    }
    assert all(not item.evidence_ids for item in geometry.judgments)
    assert all(not item.post_verified for item in geometry.mechanisms)


def admitted(entry: ModuleType, package: StoredComponentPackage, tmp_path: Path) -> tuple[Path, Path, dict[str, Any], StoredComponentPackage]:
    package_path, sidecar, _ = files(tmp_path, package)
    entry_path = tmp_path / "entry.json"
    created = entry.create_entry(entry_path, package_path, sidecar)
    inspected = entry.inspect_entry(entry_path, expected_entry_digest=created["entry_digest"])
    loaded = load_component_package(package_path, expected_digest=inspected["comparison"]["package_digest"])
    return entry_path, package_path, inspected, loaded


def test_descriptive_public_file_coordinates_match_retained_fixture_bytes() -> None:
    geometry = load_verification_geometry(GEOMETRY)
    for locus in geometry.loci:
        relative, expected = locus.address.split("#sha256=")
        assert comparison.sha((ROOT / relative).read_bytes()) == expected
    for facet_id, filename in (("facet:statement-signature", "issuer_public.pem"), ("facet:receipt-inclusion", "log_public.pem")):
        relative = "examples/scitt_interop/generated/" + filename
        description = next(item.description for item in geometry.facets if item.facet_id == facet_id)
        assert relative in description
        assert comparison.sha((ROOT / relative).read_bytes()) in description
    # These assertions establish descriptive fixture identity only, not native
    # input validation or a correspondence from recorded flags to judgments.
    payload = next(item for item in geometry.judgments if item.coordinate_id == "coordinate:payload-computational-truth")
    assert payload.mechanism_ids == ()


@pytest.mark.parametrize("recorded", ["matched", "unknown", "conflicted"])
def test_inspected_entry_catalog_detection_planning_readiness_stays_nonexecuting(
    entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, recorded: str,
) -> None:
    monkeypatch.setattr(runner, "capture_comparison", lambda *a, **k: pytest.fail("planning invoked native capture"))
    monkeypatch.setattr(runner, "_run_process", lambda *a, **k: pytest.fail("planning invoked native process"))
    if recorded == "unknown":
        specimen = change_json(specimen, "observations.json", lambda value: value["observations"][0].update(stop_reason="TIMEOUT"))
    elif recorded == "conflicted":
        raw = comparison.canonical(native_output("python", "statement", False, "0" * 64))
        specimen = change_artifact(specimen, "outputs/positive-statement-python.stdout", raw)
        specimen = change_json(specimen, "observations.json", lambda value: value["observations"][0].update(exit_code=1, stdout_sha256=comparison.sha(raw)))
    _, _, inspected, package = admitted(entry, specimen, tmp_path)
    assert inspected["comparison"]["agreement"] == {"matched": "MATCHED", "unknown": "NOT_ESTABLISHED", "conflicted": "CONFLICTED"}[recorded]
    geometry = load_verification_geometry(GEOMETRY)
    original = comparison.canonical(geometry.to_dict())
    analysis = analyze_verification_surface(geometry)
    plan = plan_validation(analysis, package.registry, package=package)
    assert not analysis.validity_errors
    assert not analysis.ordinary_closed and not analysis.self_closed
    assert plan.binding_scope == "STORED_PACKAGE"
    assert plan.package_digest == inspected["comparison"]["package_digest"] == package.canonical_digest()
    assert plan.registry_digest == package.registry.canonical_digest()
    assert plan.geometry_digest == geometry.canonical_digest()
    assert not ({"entry_digest", "sidecar_digest", "reconstruction_sources"} & set(plan.to_dict()))
    coordinate_holes = {hole.source_id: hole for hole in analysis.holes if hole.source_kind == "COORDINATE"}
    for coordinate, mechanism in (("coordinate:statement-signature", "scitt-cose:statement-signature"), ("coordinate:receipt-inclusion", "scitt-cose:receipt-inclusion")):
        candidates = [item for item in plan.candidates if item.hole_id == coordinate_holes[coordinate].hole_id]
        assert len(candidates) == 2
        assert {item.component_id for item in candidates} == set(comparison.COMPONENTS.values())
        assert all(item.mechanism_id == mechanism and item.status is CandidateStatus.BLOCKED for item in candidates)
        assert all("component availability is NOT_CHECKED" in item.blockers for item in candidates)
        assert all(any(text.startswith("PACKAGE_DEPENDENCY:" + package.canonical_digest() + ":") for text in item.execution_prerequisites) for item in candidates)
    truth = [item for item in plan.candidates if item.hole_id == coordinate_holes["coordinate:payload-computational-truth"].hole_id]
    assert len(truth) == 1 and truth[0].status is CandidateStatus.UNMATCHED
    assert truth[0].component_id is None and truth[0].mechanism_id is None
    # NOT_REQUIRED describes this modeled context's empty authority list only;
    # it is not permission for native execution. No candidate is selected.
    readiness = assess_execution_readiness(
        analysis, plan, package.registry, (),
        SuppliedAuthorizationDecision(AuthorizationDecision.NOT_REQUIRED, ()),
        PostExecutionReassessmentContract(analysis.geometry_id, analysis.geometry_digest, ()),
        package=package,
    )
    assert readiness.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("no selected candidate for holes" in text for text in readiness.findings)
    assert not readiness.execution_performed and not readiness.authorization_granted_by_module
    assert plan.plan_only and not plan.execution_performed
    assert comparison.canonical(geometry.to_dict()) == original
    assert analyze_verification_surface(geometry).to_dict() == analysis.to_dict()


def test_public_planning_command_uses_inspected_canonical_package_coordinate(
    entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(runner, "_run_process", lambda *a, **k: pytest.fail("public planning executed native code"))
    _, package_path, inspected, package = admitted(entry, specimen, tmp_path)
    before = GEOMETRY.read_bytes()
    expected = inspected["comparison"]["package_digest"]
    assert main(["surface", "analyze", str(GEOMETRY), "--plan", "--package", str(package_path), "--expected-package-sha256", expected, "--json"]) == 0
    report = strict_json_loads(capsys.readouterr().out)
    analysis = analyze_verification_surface(load_verification_geometry(GEOMETRY))
    assert report["analysis"] == analysis.to_dict()
    assert report["plan"] == plan_validation(analysis, package.registry, package=package).to_dict()
    assert report["catalog"]["source"] == "STORED_COMPONENT_PACKAGE"
    assert report["catalog"]["package_digest"] == expected
    assert report["catalog"]["component_count"] == 2
    assert GEOMETRY.read_bytes() == before


def test_changed_package_cannot_reuse_inspected_coordinate(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path) -> None:
    _, package_path, inspected, _ = admitted(entry, specimen, tmp_path)
    package_path.write_bytes(replace(specimen, description="Changed whole-package declaration").canonical_json_bytes())
    with pytest.raises(ValueError, match="expected digest"):
        load_component_package(package_path, expected_digest=inspected["comparison"]["package_digest"])


def test_entry_raw_binding_and_existing_canonical_planning_binding_stay_distinct(
    entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    entry_path, package_path, inspected, package = admitted(entry, specimen, tmp_path)
    package_path.write_bytes(package_path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="artifact bytes differ"):
        entry.inspect_entry(entry_path, expected_entry_digest=inspected["entry_digest"])
    expected = inspected["comparison"]["package_digest"]
    assert load_component_package(package_path, expected_digest=expected).canonical_digest() == expected
    # Planning deliberately binds canonical package content, not the entry/raw
    # transport or sidecar. It does not implicitly rerun entry inspection.
    assert main(["surface", "analyze", str(GEOMETRY), "--plan", "--package", str(package_path), "--expected-package-sha256", expected, "--json"]) == 0
    result = strict_json_loads(capsys.readouterr().out)
    assert result["plan"]["package_digest"] == package.canonical_digest()
    assert result["plan"]["execution_performed"] is False
