"""Verifier Standard (VSTD) finite authority discovery never executes a checker.

JavaScript Object Notation (JSON) encodes exact modeled inputs; counts are
dimensionless and source identity covers only the retained bytes.
"""

from __future__ import annotations

from importlib import import_module
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.catalog import ComponentKind, ComponentLifecycle, InteractionMode
from verifier.interoperability.component_index import load_component_index
from verifier.interoperability.control_surface import (
    CandidateStatus, ControlSurfaceContext, analyze_verification_surface, plan_validation,
)
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision, CandidateExecutionDeclaration, ExecutionReadinessStatus,
    PostExecutionReassessmentContract, SuppliedAuthorizationDecision,
    assess_execution_readiness,
)
from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.interoperability.storage import load_component_package


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "component:artifact-network-authority-composition-assessor"


def test_authority_composition_descriptor_preserves_exact_scope() -> None:
    component = reference_component_registry().get(COMPONENT)
    assert component.kind is ComponentKind.CHECKER
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.implementation_ref == "verifier.interoperability.authority_composition:assess_authority_composition"
    assert component.accepted_schema_ids == ("VSTD-FINITE-AUTHORITY-COMPOSITION-0.1",)
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.interaction_modes == (InteractionMode.OFFLINE_REPLAY,)
    mechanism = import_module("verifier.interoperability.authority_composition")
    assert callable(mechanism.assess_authority_composition)
    assert f"EXACT_RULE_PROFILE:{mechanism.authority_composition_profile_digest()}" in component.execution_prerequisites
    for boundary in ("self-derivation", "completeness", "runtime", "six-axis"):
        assert boundary in component.claim_boundary


def test_authority_composition_package_detection_planning_and_readiness_are_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.build_component_index import build

    mechanism = import_module("verifier.interoperability.authority_composition")

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("planning must not run finite authority checking")

    monkeypatch.setattr(mechanism, "assess_authority_composition", forbidden)
    output = tmp_path / "components"
    build(output, source_ref="WORKTREE")
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)
    assert entry.validate_package(package) == package.canonical_digest()
    component = package.registry.get(COMPONENT)
    binding = next(item for item in package.implementations if item.component_id == COMPONENT)
    required = {
        "src/verifier/interoperability/authority_composition.py",
        "src/verifier/specifications/FINITE_AUTHORITY_COMPOSITION.md",
    }
    assert required <= set(binding.artifact_paths)
    artifacts = {item.path: item for item in package.artifacts}
    for path in required:
        assert artifacts[path].content == (ROOT / path).read_bytes()
    query = dict(schema_id="VSTD-2", interaction_mode=InteractionMode.OFFLINE_REPLAY,
                 mechanism_id=component.mechanism_ids[0], relation_id=component.supported_relations[0])
    found = index.search_exact(**query)
    assert found["match_count"] == 1
    assert found["matches"][0]["component"]["component_id"] == COMPONENT
    assert found["native_qualification"] == "NOT_ESTABLISHED"
    assert found["execution_performed"] is False
    assert index.search_exact(**{**query, "schema_id": component.accepted_schema_ids[0]})["match_count"] == 0
    source = (ROOT / "examples/verification_geometry_residual/geometry.json").read_text(encoding="utf-8")
    modeled = json.loads(source.replace("mechanism:fixture-test", component.mechanism_ids[0]))
    for judgment in modeled["judgments"]:
        if judgment["coordinate_id"] == "coordinate:render-functional":
            judgment["status"] = "INDETERMINATE"
            judgment["evidence_ids"] = []
    geometry = load_verification_geometry(modeled)
    before = geometry.to_dict()
    analysis = analyze_verification_surface(geometry, ControlSurfaceContext(
        interaction_mode=InteractionMode.OFFLINE_REPLAY, authority_requirements=("LOCAL_REVIEW",),
    ))
    plan = plan_validation(analysis, package.registry, package=package)
    candidate = next(item for item in plan.candidates if item.component_id == COMPONENT and item.status is CandidateStatus.CANDIDATE)
    assert plan.package_digest == package.canonical_digest()
    assert plan.execution_performed is False
    declaration = CandidateExecutionDeclaration(candidate.candidate_id, candidate.hole_id, COMPONENT, (), (), ())
    readiness = assess_execution_readiness(
        analysis, plan, package.registry, (declaration,),
        SuppliedAuthorizationDecision(AuthorizationDecision.UNKNOWN, ("LOCAL_REVIEW",), reason="No authorization supplied."),
        PostExecutionReassessmentContract(analysis.geometry_id, analysis.geometry_digest, ()), package=package,
    )
    assert readiness.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert readiness.execution_performed is False
    assert readiness.authorization_granted_by_module is False
    assert geometry.to_dict() == before
