"""Verifier Standard (VSTD) composition-qualification catalog integration.

JavaScript Object Notation (JSON) encodes bounded fixture records. Secure Hash
Algorithm 256-bit (SHA-256) digests bind retained bytes, not execution, source
correctness, custody, or an atomic filesystem snapshot.
"""

from __future__ import annotations

from importlib import import_module
import json
from pathlib import Path
from typing import Any

import pytest

from test_authority_composition import _fixture
from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.authority_composition import (
    authority_composition_profile_digest,
)
from verifier.interoperability.catalog import (
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
)
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
from verifier.interoperability.network import canonical_bytes, digest_bytes
from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.interoperability.storage import load_component_package


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "component:artifact-network-finite-composition-qualifier"
RAW_COMPONENT = "component:artifact-network-authority-composition-assessor"
RELATION = "relation:qualifies-selected-finite-silo-composition"
MECHANISM = "mechanism:artifact-network-finite-composition-qualification"
NATIVE_INPUTS = tuple(sorted((
    "local path to verifier-finite-authority-composition-1 canonical bytes",
    "ordered local (ContentAddressedStore root, silo-commit path) member pairs",
    "local composite ContentAddressedStore root",
    "local composite silo-commit path",
)))
NATIVE_OUTPUT = (
    "unversioned composition qualification report retaining legacy and finite assessments"
)


def _resolve(reference: str) -> object:
    module_name, separator, attribute = reference.partition(":")
    assert separator and module_name and attribute
    return getattr(import_module(module_name), attribute)


def _native_inputs(tmp_path: Path) -> tuple[
    Path,
    tuple[tuple[Path, Path], ...],
    Path,
    Path,
]:
    declaration, _evidence, pairs = _fixture(tmp_path)
    declaration["profile_digest"] = authority_composition_profile_digest()
    commit_paths: list[Path] = []
    for index, (commit, _store) in enumerate(pairs):
        path = tmp_path / f"catalog-commit-{index}.json"
        path.write_bytes(canonical_bytes(commit.to_dict()))
        commit_paths.append(path)
    declaration_path = tmp_path / "catalog-finite-composition.json"
    declaration_path.write_bytes(canonical_bytes(declaration))
    members = tuple(
        (store.root, path)
        for (_commit, store), path in zip(pairs[:-1], commit_paths[:-1])
    )
    return declaration_path, members, pairs[-1][1].root, commit_paths[-1]


def test_qualifier_descriptor_matches_the_native_callable_and_real_result(
    tmp_path: Path,
) -> None:
    registry = reference_component_registry()
    component = registry.get(COMPONENT)

    assert component.kind is ComponentKind.CHECKER
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.implementation_ref == (
        "verifier.interoperability.composition_qualification:qualify_silo_composition"
    )
    assert component.accepted_schema_ids == (
        "verifier-finite-authority-composition-1",
        "verifier-silo-commit-1",
    )
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.native_inputs == NATIVE_INPUTS
    assert component.native_outputs == (NATIVE_OUTPUT,)
    assert component.emitted_schema_ids == ()
    assert component.native_result_vocabulary == (
        "FINITE_COMPOSITION_QUALIFIED",
        "NOT_QUALIFIED",
    )
    assert component.supported_relations == (RELATION,)
    assert component.mechanism_ids == (MECHANISM,)
    assert component.interaction_modes == (InteractionMode.OFFLINE_REPLAY,)
    assert (
        f"EXACT_RULE_PROFILE:{authority_composition_profile_digest()}"
        in component.execution_prerequisites
    )
    assert "EXACT_SELECTED_LOCAL_SILO_INPUTS" in component.execution_prerequisites
    assert "standalone serialized call schema" in component.transformation_loss
    assert "portable replay receipt" in component.claim_boundary
    assert "six-axis silo-status upgrade" in component.claim_boundary

    qualifier = _resolve(component.implementation_ref)
    assert callable(qualifier)
    result = qualifier(*_native_inputs(tmp_path))
    assert result["qualification"] == "FINITE_COMPOSITION_QUALIFIED"
    assert result["selection_binding"] == "BOUND"
    assert result["legacy_assessment"]["result"] == "ADMISSIBLE"
    assert result["finite_assessment"]["coordinate_binding"] == "BOUND"
    assert result["finite_assessment"]["transition_correspondence"] == "MATCHED"
    assert result["finite_assessment"]["agency_preservation"] == "PRESERVED"
    assert "FULL_SILO_ASSESSMENT_NOT_PERFORMED" in result["finite_assessment"][
        "residual_obligations"
    ]


def test_raw_and_combined_composition_discovery_are_disjoint() -> None:
    registry = reference_component_registry()
    qualifier = registry.get(COMPONENT)
    raw = registry.get(RAW_COMPONENT)
    qualifier_query = {
        "schema_id": "VSTD-2",
        "interaction_mode": InteractionMode.OFFLINE_REPLAY,
        "relation_id": RELATION,
        "mechanism_id": MECHANISM,
    }
    raw_query = {
        "schema_id": "VSTD-2",
        "interaction_mode": InteractionMode.OFFLINE_REPLAY,
        "relation_id": raw.supported_relations[0],
        "mechanism_id": raw.mechanism_ids[0],
    }

    assert registry.match_exact(**qualifier_query) == (qualifier,)
    assert registry.match_exact(**raw_query) == (raw,)
    assert registry.match_exact(
        **{**qualifier_query, "mechanism_id": raw.mechanism_ids[0]}
    ) == ()
    assert registry.match_exact(
        **{**raw_query, "mechanism_id": qualifier.mechanism_ids[0]}
    ) == ()
    for changed in (
        {"schema_id": qualifier.accepted_schema_ids[0]},
        {"interaction_mode": InteractionMode.LIVE_READ_ONLY},
        {"relation_id": RELATION + "-other"},
        {"mechanism_id": MECHANISM + "-other"},
    ):
        assert registry.match_exact(**{**qualifier_query, **changed}) == ()


def test_qualifier_package_detection_planning_and_readiness_remain_nonexecuting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.build_component_index import build
    from verifier.interoperability import composition_qualification

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("catalog integration must not execute qualification")

    monkeypatch.setattr(composition_qualification, "qualify_silo_composition", forbidden)
    output = tmp_path / "components"
    build(output, source_ref="WORKTREE")
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(
        output / entry.package_path,
        expected_digest=entry.package_sha256,
    )
    assert entry.validate_package(package) == package.canonical_digest()
    component = package.registry.get(COMPONENT)
    binding = next(
        item for item in package.implementations if item.component_id == COMPONENT
    )
    required = {
        "src/verifier/interoperability/composition_qualification.py",
        "src/verifier/interoperability/authority_composition.py",
        "src/verifier/interoperability/network.py",
        "src/verifier/standard/FINITE_AUTHORITY_COMPOSITION.md",
    }
    assert required <= set(binding.artifact_paths)
    artifacts = {item.path: item for item in package.artifacts}
    for path in required:
        assert artifacts[path].content == (ROOT / path).read_bytes()

    query = {
        "schema_id": "VSTD-2",
        "interaction_mode": InteractionMode.OFFLINE_REPLAY,
        "mechanism_id": MECHANISM,
        "relation_id": RELATION,
    }
    found = index.search_exact(**query)
    assert found["match_count"] == 1
    assert found["matches"][0]["component"]["component_id"] == COMPONENT
    assert found["matches"][0]["package_sha256"] == package.canonical_digest()
    assert found["matches"][0]["registry_sha256"] == package.registry.canonical_digest()
    assert found["package_availability"] == "NOT_CHECKED"
    assert found["native_qualification"] == "NOT_ESTABLISHED"
    assert found["execution_performed"] is False
    raw = package.registry.get(RAW_COMPONENT)
    raw_found = index.search_exact(
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.OFFLINE_REPLAY,
        mechanism_id=raw.mechanism_ids[0],
        relation_id=raw.supported_relations[0],
    )
    assert raw_found["match_count"] == 1
    assert raw_found["matches"][0]["component"]["component_id"] == RAW_COMPONENT

    source = (ROOT / "examples/verification_geometry_residual/geometry.json").read_text(
        encoding="utf-8"
    )
    modeled = json.loads(source.replace("mechanism:fixture-test", MECHANISM))
    for judgment in modeled["judgments"]:
        if judgment["coordinate_id"] == "coordinate:render-functional":
            judgment["status"] = "INDETERMINATE"
            judgment["evidence_ids"] = []
    geometry = load_verification_geometry(modeled)
    before = geometry.to_dict()
    analysis = analyze_verification_surface(
        geometry,
        ControlSurfaceContext(
            interaction_mode=InteractionMode.OFFLINE_REPLAY,
            authority_requirements=("LOCAL_REVIEW",),
        ),
    )
    plan = plan_validation(analysis, package.registry, package=package)
    candidate = next(
        item
        for item in plan.candidates
        if item.component_id == COMPONENT and item.status is CandidateStatus.CANDIDATE
    )
    assert plan.package_digest == package.canonical_digest()
    assert plan.execution_performed is False
    assert component.native_inputs == NATIVE_INPUTS
    assert f"EXACT_RULE_PROFILE:{authority_composition_profile_digest()}" in (
        candidate.execution_prerequisites
    )
    assert "EXACT_SELECTED_LOCAL_SILO_INPUTS" in candidate.execution_prerequisites
    declaration = CandidateExecutionDeclaration(
        candidate.candidate_id,
        candidate.hole_id,
        COMPONENT,
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
            analysis.geometry_id,
            analysis.geometry_digest,
            (),
        ),
        package=package,
    )
    assert readiness.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert readiness.execution_performed is False
    assert readiness.authorization_granted_by_module is False
    assert any("missing native input bindings" in item for item in readiness.findings)
    assert any("no planned output/evidence mapping" in item for item in readiness.findings)
    assert any(
        "EXACT_RULE_PROFILE:" in item and "missing prerequisite resolutions" in item
        for item in readiness.findings
    )
    assert any(
        "EXACT_SELECTED_LOCAL_SILO_INPUTS" in item
        and "missing prerequisite resolutions" in item
        for item in readiness.findings
    )
    assert geometry.to_dict() == before
