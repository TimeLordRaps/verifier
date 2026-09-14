"""Verifier Standard (VSTD) transfer discovery is not execution or support.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256). The fixture's finite-set members are dimensionless strings.
"""

from __future__ import annotations

import base64
import importlib.resources
import json
from importlib import import_module
from pathlib import Path

import pytest

from verifier.interoperability.catalog import ComponentLifecycle, InteractionMode
from verifier.interoperability.network import canonical_bytes, digest_bytes
from verifier.interoperability.proposition_transfer import (
    ASSESSMENT_SCHEMA, RECEIPT_SCHEMA, TRANSFER_SCHEMA,
    assess_transfer, recheck_transfer_receipt, rule_profile_bytes,
)
from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.component_index import load_component_index
from verifier.interoperability.control_surface import (
    CandidateStatus, ControlSurfaceContext, analyze_verification_surface, plan_validation,
)
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision, CandidateExecutionDeclaration, ExecutionReadinessStatus,
    PostExecutionReassessmentContract, SuppliedAuthorizationDecision, assess_execution_readiness,
)
from verifier.interoperability.storage import load_component_package


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = "src/verifier/profiles/proposition-transfer-rule-0.1.json"
PROFILE_DIGEST = "sha256:0d26f06addc32e61e0ba68a466b4721db6a8ad2a46021c96f226da7d91b410bd"
COMPONENTS = (
    ("assessor", "assess_transfer", (TRANSFER_SCHEMA,)),
    ("rechecker", "recheck_transfer_receipt", tuple(sorted((TRANSFER_SCHEMA, RECEIPT_SCHEMA)))),
)


def _component_id(role: str) -> str:
    return f"component:artifact-network-proposition-transfer-{role}"


def _fixture(case_id: str = "two_source_union") -> tuple[bytes, bytes, dict[str, bytes]]:
    from scripts.build_proposition_transfer_fixture import TARGET

    corpus = json.loads(TARGET.read_text(encoding="utf-8"))
    case = next(value for value in corpus["cases"] if value["case_id"] == case_id)
    return (
        case["declaration_canonical_json"].encode("utf-8"),
        case["receipt_canonical_json"].encode("utf-8"),
        {item["digest"]: base64.urlsafe_b64decode(item["bytes_base64url"] + "=" * (-len(item["bytes_base64url"]) % 4))
         for item in case["objects"]},
    )


def test_compiled_profile_has_an_exact_inert_packaged_mirror() -> None:
    artifact = importlib.resources.files("verifier").joinpath("profiles/proposition-transfer-rule-0.1.json")
    assert artifact.read_bytes() == rule_profile_bytes()
    assert digest_bytes(artifact.read_bytes()) == PROFILE_DIGEST
    assert '"profiles/*.json"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


@pytest.mark.parametrize("role,function_name,accepted", COMPONENTS)
def test_transfer_descriptors_name_exact_native_contracts_and_profile(
    role: str, function_name: str, accepted: tuple[str, ...],
) -> None:
    component = reference_component_registry().get(_component_id(role))
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.implementation_ref == f"verifier.interoperability.proposition_transfer:{function_name}"
    assert component.accepted_schema_ids == accepted
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.emitted_schema_ids == (ASSESSMENT_SCHEMA,)
    assert component.optional_dependencies == ()
    assert PROFILE_DIGEST in component.native_versions
    assert PROFILE_PATH in component.transformation_loss
    assert f"EXACT_RULE_PROFILE:{PROFILE_DIGEST}" in component.execution_prerequisites
    assert "mechanism match does not establish rule-profile compatibility" in component.claim_boundary
    assert "six" in component.claim_boundary
    assert "execution" in component.claim_boundary

    declaration, receipt, evidence = _fixture()
    module_name, attribute = component.implementation_ref.split(":")
    function = getattr(import_module(module_name), attribute)
    actual = function(declaration, evidence) if role == "assessor" else function(declaration, receipt, evidence)
    assert actual["schema_version"] == ASSESSMENT_SCHEMA
    assert actual["conclusion_support"] == "SUPPORTED"
    assert actual["authority_admissibility"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("role,function_name,accepted", COMPONENTS)
def test_exact_transfer_planning_match_does_not_validate_the_rule_profile(
    role: str, function_name: str, accepted: tuple[str, ...],
) -> None:
    registry = reference_component_registry()
    component = registry.get(_component_id(role))
    query = dict(schema_id="VSTD-2", interaction_mode=InteractionMode.OFFLINE_REPLAY,
                 mechanism_id=component.mechanism_ids[0], relation_id=component.supported_relations[0])
    assert registry.match_exact(**query) == (component,)
    assert registry.match_exact(**{**query, "mechanism_id": component.mechanism_ids[0] + "-other"}) == ()
    assert registry.match_exact(**{**query, "schema_id": TRANSFER_SCHEMA}) == ()
    assert registry.match_exact(**{**query, "interaction_mode": InteractionMode.LIVE_MUTATING}) == ()

    declaration, _, evidence = _fixture()
    substituted = json.loads(declaration)
    substituted["rule_profile_digest"] = "sha256:" + "0" * 64
    result = assess_transfer(canonical_bytes(substituted), evidence)
    assert result["conclusion"]["predicate_result"] == "PASS"
    assert result["artifact_relation"] == "UNKNOWN"
    assert result["conclusion_support"] == "NOT_ESTABLISHED"
    assert "UNSUPPORTED_RULE" in result["reason_codes"]


@pytest.mark.parametrize("role,function_name,accepted", COMPONENTS)
def test_transfer_package_index_detection_plan_and_missing_evidence_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    role: str, function_name: str, accepted: tuple[str, ...],
) -> None:
    from scripts.build_component_index import build
    from verifier.interoperability import proposition_transfer

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("discovery, package loading, planning and readiness must not execute transfer checking")

    monkeypatch.setattr(proposition_transfer, "assess_transfer", forbidden)
    monkeypatch.setattr(proposition_transfer, "recheck_transfer_receipt", forbidden)
    output = tmp_path / "components"
    build(output, source_ref="WORKTREE")
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)
    assert entry.validate_package(package) == package.canonical_digest()
    component = package.registry.get(_component_id(role))
    artifacts = {item.path: item for item in package.artifacts}
    assert artifacts[PROFILE_PATH].content == rule_profile_bytes()
    assert digest_bytes(artifacts[PROFILE_PATH].content) == PROFILE_DIGEST
    binding = next(value for value in package.implementations if value.component_id == component.component_id)
    assert PROFILE_PATH in binding.artifact_paths
    assert "src/verifier/interoperability/proposition_transfer.py" in binding.artifact_paths

    found = index.search_exact(schema_id="VSTD-2", interaction_mode=InteractionMode.OFFLINE_REPLAY,
                               mechanism_id=component.mechanism_ids[0], relation_id=component.supported_relations[0])
    assert found["match_count"] == 1
    assert found["matches"][0]["component"]["component_id"] == component.component_id
    assert found["matches"][0]["package_sha256"] == package.canonical_digest()
    assert found["matches"][0]["registry_sha256"] == package.registry.canonical_digest()
    assert found["package_availability"] == "NOT_CHECKED"
    assert found["native_qualification"] == "NOT_ESTABLISHED"
    assert found["execution_performed"] is False

    source = (ROOT / "examples/verification_geometry_residual/geometry.json").read_text(encoding="utf-8")
    modeled = json.loads(source.replace("mechanism:fixture-test", component.mechanism_ids[0]))
    # This is a modeled missing-evidence hole, not a cast of the specimen's
    # carried VERIFIED judgments into native transfer evidence.
    for judgment in modeled["judgments"]:
        if judgment["coordinate_id"] == "coordinate:render-functional":
            judgment["status"] = "INDETERMINATE"
            judgment["evidence_ids"] = []
    geometry = load_verification_geometry(modeled)
    before = geometry.to_dict()
    analysis = analyze_verification_surface(geometry, ControlSurfaceContext(
        interaction_mode=InteractionMode.OFFLINE_REPLAY, authority_requirements=("LOCAL_REVIEW",),
    ))
    assert not analysis.validity_errors
    plan = plan_validation(analysis, package.registry, package=package)
    selected = [value for value in plan.candidates
                if value.component_id == component.component_id and value.status is CandidateStatus.CANDIDATE]
    assert selected
    assert plan.binding_scope == "STORED_PACKAGE"
    assert plan.package_digest == package.canonical_digest()
    assert plan.registry_digest == package.registry.canonical_digest()
    assert plan.execution_performed is False
    candidate = selected[0]
    assert f"EXACT_RULE_PROFILE:{PROFILE_DIGEST}" in candidate.execution_prerequisites
    assert "EVIDENCE_BYTES" in candidate.execution_prerequisites
    assert any(value.startswith("PACKAGE_DEPENDENCY:") for value in candidate.execution_prerequisites)
    declaration = CandidateExecutionDeclaration(candidate.candidate_id, candidate.hole_id, component.component_id, (), (), ())
    readiness = assess_execution_readiness(
        analysis, plan, package.registry, (declaration,),
        SuppliedAuthorizationDecision(AuthorizationDecision.UNKNOWN, ("LOCAL_REVIEW",), reason="No authorization evidence supplied."),
        PostExecutionReassessmentContract(analysis.geometry_id, analysis.geometry_digest, ()),
        package=package,
    )
    assert readiness.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert readiness.execution_performed is False
    assert readiness.authorization_granted_by_module is False
    assert any("missing native input bindings" in finding for finding in readiness.findings)
    assert any("no planned output/evidence mapping" in finding for finding in readiness.findings)
    assert any("EXACT_RULE_PROFILE:" in finding and "EVIDENCE_BYTES" in finding for finding in readiness.findings)
    assert not analysis.ordinary_closed and not analysis.self_closed
    assert geometry.to_dict() == before


def test_native_negative_transfer_preserves_true_target_and_input_evidence() -> None:
    declaration, receipt, evidence = _fixture("true_target_failed_upper_bound")
    before = dict(evidence)
    result = recheck_transfer_receipt(declaration, receipt, evidence)
    assert result["conclusion"]["predicate_result"] == "PASS"
    assert result["upper_bound_preservation"] == "FAIL"
    assert result["conclusion_support"] == "NOT_ESTABLISHED"
    assert result["authority_admissibility"] == "NOT_ESTABLISHED"
    assert evidence == before
