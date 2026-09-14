"""Verifier Standard (VSTD) mechanism discovery remains inert and fail-closed.

JavaScript Object Notation (JSON) carries only a modeled planning surface.  The
stored package binds exact source bytes, but discovery, planning, and readiness
do not import through an entrypoint, execute a mechanism, grant authorization,
or close the supplied geometry.
"""

from __future__ import annotations

from importlib import import_module
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.catalog import ComponentLifecycle, InteractionMode
from verifier.interoperability.component_index import load_component_index
from verifier.interoperability.control_surface import (
    CandidateStatus,
    ControlSurfaceContext,
    analyze_verification_surface,
    plan_validation,
)
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision,
    CandidateExecutionDeclaration,
    ExecutionReadinessStatus,
    PostExecutionReassessmentContract,
    SuppliedAuthorizationDecision,
    assess_execution_readiness,
)
from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.interoperability.storage import load_component_package


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATHS = (
    "src/verifier/interoperability/bounded_completeness.py",
    "src/verifier/interoperability/deriver_self_status.py",
    "src/verifier/interoperability/global_cycle_assessment.py",
    "src/verifier/interoperability/relation_boundary.py",
    "src/verifier/interoperability/runtime_authority_correspondence.py",
    "src/verifier/interoperability/source_grounding.py",
)
COMPONENTS = (
    (
        "component:artifact-network-source-grounding-assessor",
        "verifier.interoperability.source_grounding:qualify_source_grounding",
        "relation:assesses-source-grounding",
        "mechanism:source-grounding-assessment",
    ),
    (
        "component:artifact-network-source-grounding-receipt-rechecker",
        "verifier.interoperability.source_grounding:recheck_source_grounding_receipt",
        "relation:rechecks-source-grounding-receipt",
        "mechanism:source-grounding-receipt-recheck",
    ),
    (
        "component:artifact-network-relation-boundary-assessor",
        "verifier.interoperability.relation_boundary:qualify_relation_boundary",
        "relation:assesses-relation-boundary",
        "mechanism:relation-boundary-assessment",
    ),
    (
        "component:artifact-network-relation-boundary-receipt-rechecker",
        "verifier.interoperability.relation_boundary:recheck_relation_boundary_receipt",
        "relation:rechecks-relation-boundary-receipt",
        "mechanism:relation-boundary-receipt-recheck",
    ),
    (
        "component:artifact-network-deriver-session-recorder",
        "verifier.interoperability.deriver_self_status:record_deriver_session",
        "relation:records-deriver-session",
        "mechanism:bounded-deriver-session-recording",
    ),
    (
        "component:artifact-network-deriver-self-status-rechecker",
        "verifier.interoperability.deriver_self_status:recheck_deriver_self_status",
        "relation:rechecks-deriver-session-receipt",
        "mechanism:deriver-self-status-recheck",
    ),
    (
        "component:artifact-network-global-cycle-assessor",
        "verifier.interoperability.global_cycle_assessment:assess_global_cycles",
        "relation:assesses-global-cycles",
        "mechanism:grounded-global-cycle-assessment",
    ),
    (
        "component:artifact-network-global-cycle-receipt-rechecker",
        "verifier.interoperability.global_cycle_assessment:recheck_global_cycle_receipt",
        "relation:rechecks-global-cycle-receipt",
        "mechanism:global-cycle-receipt-recheck",
    ),
    (
        "component:artifact-network-bounded-completeness-assessor",
        "verifier.interoperability.bounded_completeness:assess_bounded_completeness",
        "relation:assesses-bounded-completeness",
        "mechanism:bounded-completeness-assessment",
    ),
    (
        "component:artifact-network-bounded-completeness-receipt-rechecker",
        "verifier.interoperability.bounded_completeness:recheck_bounded_completeness_receipt",
        "relation:rechecks-bounded-completeness-receipt",
        "mechanism:bounded-completeness-receipt-recheck",
    ),
    (
        "component:artifact-network-runtime-authority-correspondence-assessor",
        "verifier.interoperability.runtime_authority_correspondence:build_runtime_authority_correspondence_receipt",
        "relation:assesses-runtime-authority-correspondence",
        "mechanism:runtime-authority-correspondence-assessment",
    ),
    (
        "component:artifact-network-runtime-authority-correspondence-receipt-rechecker",
        "verifier.interoperability.runtime_authority_correspondence:recheck_runtime_authority_correspondence_receipt",
        "relation:rechecks-runtime-authority-correspondence-receipt",
        "mechanism:runtime-authority-correspondence-receipt-recheck",
    ),
)


@pytest.mark.parametrize(
    "component_id,implementation_ref,relation_id,mechanism_id", COMPONENTS
)
def test_mechanism_descriptor_and_exact_match_are_role_bound(
    component_id: str,
    implementation_ref: str,
    relation_id: str,
    mechanism_id: str,
) -> None:
    registry = reference_component_registry()
    component = registry.get(component_id)

    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.implementation_ref == implementation_ref
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.supported_relations == (relation_id,)
    assert component.mechanism_ids == (mechanism_id,)
    assert component.optional_dependencies == ()
    assert len(component.verifier_family_ids) == 1
    assert "does not" in component.claim_boundary.lower()

    query = {
        "schema_id": "VSTD-2",
        "interaction_mode": component.interaction_modes[0],
        "mechanism_id": mechanism_id,
        "relation_id": relation_id,
    }
    assert registry.match_exact(**query) == (component,)
    assert registry.match_exact(
        **{**query, "mechanism_id": mechanism_id + "-near-miss"}
    ) == ()
    assert registry.match_exact(
        **{**query, "relation_id": relation_id + "-near-miss"}
    ) == ()
    assert registry.match_exact(**{**query, "schema_id": "VSTD-2-near-miss"}) == ()
    wrong_mode = next(mode for mode in InteractionMode if mode not in component.interaction_modes)
    assert registry.match_exact(**{**query, "interaction_mode": wrong_mode}) == ()

    module_name, attribute_name = implementation_ref.split(":", 1)
    assert getattr(import_module(module_name), attribute_name) is not None


def test_stored_package_detection_plan_and_readiness_never_execute_mechanisms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.build_component_index import build

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(
            "package export, detection, planning, and readiness must not execute mechanisms"
        )

    for _component_id, implementation_ref, _relation_id, _mechanism_id in COMPONENTS:
        module_name, attribute_name = implementation_ref.split(":", 1)
        monkeypatch.setattr(import_module(module_name), attribute_name, forbidden)

    output = tmp_path / "components"
    build(output, source_ref="WORKTREE")
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(
        output / entry.package_path, expected_digest=entry.package_sha256
    )
    assert entry.validate_package(package) == package.canonical_digest()
    assert len(package.registry.components) == 43
    assert len(
        {
            family
            for component in package.registry.components
            for family in component.verifier_family_ids
        }
    ) == 19

    artifacts = {item.path: item for item in package.artifacts}
    for path in MODULE_PATHS:
        assert artifacts[path].content == (ROOT / path).read_bytes()

    source = (ROOT / "examples/verification_geometry_residual/geometry.json").read_text(
        encoding="utf-8"
    )
    for component_id, _implementation_ref, relation_id, mechanism_id in COMPONENTS:
        component = package.registry.get(component_id)
        binding = next(
            item for item in package.implementations if item.component_id == component_id
        )
        module_path = (
            "src/" + component.implementation_ref.split(":", 1)[0].replace(".", "/") + ".py"
        )
        assert module_path in binding.artifact_paths
        assert artifacts[module_path].content == (ROOT / module_path).read_bytes()

        query = {
            "schema_id": "VSTD-2",
            "interaction_mode": component.interaction_modes[0],
            "mechanism_id": mechanism_id,
            "relation_id": relation_id,
        }
        found = index.search_exact(**query)
        assert found["match_count"] == 1
        assert found["matches"][0]["component"]["component_id"] == component_id
        assert found["matches"][0]["package_sha256"] == package.canonical_digest()
        assert found["matches"][0]["registry_sha256"] == package.registry.canonical_digest()
        assert found["package_availability"] == "NOT_CHECKED"
        assert found["native_qualification"] == "NOT_ESTABLISHED"
        assert found["execution_performed"] is False
        assert index.search_exact(
            **{**query, "mechanism_id": mechanism_id + "-near-miss"}
        )["match_count"] == 0
        assert index.search_exact(
            **{**query, "relation_id": relation_id + "-near-miss"}
        )["match_count"] == 0

        modeled = json.loads(source.replace("mechanism:fixture-test", mechanism_id))
        for judgment in modeled["judgments"]:
            if judgment["coordinate_id"] == "coordinate:render-functional":
                judgment["status"] = "INDETERMINATE"
                judgment["evidence_ids"] = []
        geometry = load_verification_geometry(modeled)
        before = geometry.to_dict()
        analysis = analyze_verification_surface(
            geometry,
            ControlSurfaceContext(
                interaction_mode=component.interaction_modes[0],
                authority_requirements=("LOCAL_REVIEW",),
            ),
        )
        plan = plan_validation(analysis, package.registry, package=package)
        candidate = next(
            item
            for item in plan.candidates
            if item.component_id == component_id
            and item.status is CandidateStatus.CANDIDATE
        )
        assert plan.binding_scope == "STORED_PACKAGE"
        assert plan.package_digest == package.canonical_digest()
        assert plan.registry_digest == package.registry.canonical_digest()
        assert plan.execution_performed is False
        declaration = CandidateExecutionDeclaration(
            candidate.candidate_id,
            candidate.hole_id,
            component_id,
            (),
            (),
            (),
        )
        readiness = assess_execution_readiness(
            analysis,
            plan,
            package.registry,
            (declaration,),
            SuppliedAuthorizationDecision(
                AuthorizationDecision.UNKNOWN,
                ("LOCAL_REVIEW",),
                reason="No authorization evidence supplied.",
            ),
            PostExecutionReassessmentContract(
                analysis.geometry_id, analysis.geometry_digest, ()
            ),
            package=package,
        )
        assert readiness.status is ExecutionReadinessStatus.NOT_ESTABLISHED
        assert readiness.execution_performed is False
        assert readiness.authorization_granted_by_module is False
        assert any("missing native input bindings" in item for item in readiness.findings)
        assert any("no planned output/evidence mapping" in item for item in readiness.findings)
        assert not analysis.ordinary_closed
        assert not analysis.self_closed
        assert geometry.to_dict() == before
