"""Verifier Standard (VSTD) formation discovery is not execution or closure.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256). Formation profile counts are dimensionless and record sizes are bytes.
"""

from __future__ import annotations

from importlib import import_module
import importlib.resources
from dataclasses import replace
from inspect import signature
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.interoperability.catalog import ComponentKind, ComponentLifecycle, InteractionMode
from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismOutcome, VerificationSession
from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.component_index import ComponentIndexError, load_component_index
from verifier.interoperability.control_surface import (
    CandidateStatus, ControlSurfaceContext, analyze_verification_surface, plan_validation,
)
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision, CandidateExecutionDeclaration, ExecutionReadinessStatus,
    NativeInputBinding, PostExecutionReassessmentContract, PrerequisiteResolution,
    SuppliedAuthorizationDecision, assess_execution_readiness,
)
from verifier.interoperability.network import canonical_bytes, digest_bytes
from verifier.interoperability.storage import load_component_package


ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIGEST = "sha256:271760d604e1ade55cba4974c658b92263bd3ee8ae343677dd91d0e713fb677f"
PROFILE_PATH = "src/verifier/profiles/typed-formation-0.1.json"
SUBJECT_SCHEMA = "VSTD-TYPED-FORMATION-0.1"
CERTIFICATE_SCHEMA = "VSTD-TYPED-FORMATION-CERTIFICATE-0.1"
COMPONENTS = (
    ("producer", "formation_producer:produce_formation_certificate", ComponentKind.PROVER,
     InteractionMode.STATIC, (SUBJECT_SCHEMA,), (CERTIFICATE_SCHEMA,)),
    ("checker", "formation_checker:check_formation", ComponentKind.CHECKER,
     InteractionMode.OFFLINE_REPLAY, tuple(sorted((SUBJECT_SCHEMA, CERTIFICATE_SCHEMA))), ()),
    ("receipt-rechecker", "formation_receipt:recheck_formation_receipt", ComponentKind.CHECKER,
     InteractionMode.OFFLINE_REPLAY, ("VSTD-SILO-COMMIT-0.1", "VSTD-SILO-FORMATION-RECEIPT-0.1", "VSTD-SILO-FORMATION-SELECTION-0.1"), ()),
    ("session-mechanism", "formation_mechanism:FormationPathCertificateMechanism.evaluate", ComponentKind.ADAPTER,
     InteractionMode.OFFLINE_REPLAY, (), ()),
)


def _component_id(role: str) -> str:
    return f"component:artifact-network-typed-formation-{role}"


def _resolve(reference: str) -> Any:
    module_name, attribute_path = reference.split(":")
    value = import_module(module_name)
    for attribute in attribute_path.split("."):
        value = getattr(value, attribute)
    return value


def _native_pair() -> tuple[bytes, bytes]:
    subject = canonical_bytes({
        "schema_version": SUBJECT_SCHEMA, "profile_digest": PROFILE_DIGEST,
        "context": {"ground_artifact_digest": "sha256:" + "a" * 64,
                    "authority_axiom_agency_digest": "sha256:" + "b" * 64},
        "nodes": [{"tag": "ATOM", "payload_digest": "sha256:" + "c" * 64},
                  {"tag": "APPLY", "argument": 0},
                  {"tag": "APPLY_STEP", "source": 0, "target": 1}], "root": 2,
    })
    certificate = canonical_bytes({
        "schema_version": CERTIFICATE_SCHEMA, "profile_digest": PROFILE_DIGEST,
        "subject_digest": digest_bytes(subject), "root": 2,
        "steps": [{"node": 0, "rule": "ATOM", "premises": []},
                  {"node": 1, "rule": "APPLY", "premises": [0]},
                  {"node": 2, "rule": "APPLY_STEP", "premises": [0, 1]}],
    })
    return subject, certificate


@pytest.mark.parametrize("role,reference,kind,mode,accepted,emitted", COMPONENTS)
def test_formation_catalog_names_exact_native_roles_and_profile(
    role: str, reference: str, kind: ComponentKind, mode: InteractionMode,
    accepted: tuple[str, ...], emitted: tuple[str, ...],
) -> None:
    component = reference_component_registry().get(_component_id(role))
    assert component.implementation_ref == f"verifier.interoperability.{reference}"
    assert callable(_resolve(component.implementation_ref))
    assert component.kind is kind
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.verifier_family_ids == ("artifact-network",)
    assert component.interaction_modes == (mode,)
    assert component.accepted_schema_ids == accepted
    assert component.emitted_schema_ids == emitted
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.optional_dependencies == ()
    assert PROFILE_DIGEST in component.native_versions
    assert f"EXACT_RULE_PROFILE:{PROFILE_DIGEST}" in component.execution_prerequisites
    assert PROFILE_PATH in component.transformation_loss
    for boundary in ("self-derivation", "completeness", "agency", "execution"):
        assert boundary in component.claim_boundary
    if role == "session-mechanism":
        assert "EXPLICIT_MECHANISM_INSTANCE" in component.execution_prerequisites
        assert "unbound instance method" in component.freshness_behavior
        assert "FormationPathCertificateMechanism()" in component.freshness_behavior


def test_formation_profile_and_packaged_contract_are_exact_inert_resources() -> None:
    wire = import_module("verifier.interoperability.formation_wire")
    artifact = importlib.resources.files("verifier").joinpath("profiles/typed-formation-0.1.json")
    assert artifact.read_bytes() == wire.profile_bytes()
    assert digest_bytes(artifact.read_bytes()) == PROFILE_DIGEST
    for source, packaged in (
        ("standard/TYPED_FORMATION.md", "specifications/TYPED_FORMATION.md"),
        ("standard/schemas/vstd-typed-formation-0.1.schema.json", "schemas/vstd-typed-formation-0.1.schema.json"),
    ):
        assert (ROOT / source).read_bytes() == importlib.resources.files("verifier").joinpath(packaged).read_bytes()


def test_formation_catalog_entrypoints_execute_only_explicitly_and_retain_residuals() -> None:
    registry = reference_component_registry()
    producer = _resolve(registry.get(_component_id("producer")).implementation_ref)
    checker = _resolve(registry.get(_component_id("checker")).implementation_ref)
    adapter = registry.get(_component_id("session-mechanism"))
    assert tuple(signature(producer).parameters) == ("subject_bytes",)
    assert tuple(signature(checker).parameters) == ("subject_bytes", "certificate_bytes")
    assert tuple(signature(_resolve(adapter.implementation_ref)).parameters) == ("self", "binding", "evidence")
    subject, certificate = _native_pair()
    assert producer(subject) == certificate
    checked = checker(subject, certificate)
    assert checked["status"] == "CHECKED"
    assert checked["observation"]["type"] == "PATH"
    assert len(checked["observation"]["path_steps"]) == 1

    mechanism = _resolve(adapter.implementation_ref.rsplit(".", 1)[0])()
    assert adapter.mechanism_ids == (mechanism.mechanism_id,)
    store = EvidenceStore()
    refs = (store.add(subject), store.add(certificate))
    context = json.loads(subject)["context"]
    parameters = dict(context, profile_digest=PROFILE_DIGEST)
    binding = BoundProposition(
        subject_id=refs[0], predicate=mechanism.mechanism_id, expected="CHECKED",
        mechanism_id=mechanism.mechanism_id, mechanism_digest=mechanism.mechanism_digest,
        evidence_refs=refs, trust_roots=tuple(parameters.values()), bounds=EvidenceBounds(2, len(subject) + len(certificate)),
        parameters=parameters,
    )
    session = VerificationSession(store)
    assert session.evaluate(binding).outcome is MechanismOutcome.UNKNOWN
    session.register(mechanism)
    evaluated = session.evaluate(binding)
    assert evaluated.outcome is MechanismOutcome.PASS
    assert evaluated.observations["formation_report"] == checked
    wire = import_module("verifier.interoperability.formation_wire")
    assert checked["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)
    assert {"COMPLETENESS_NOT_ESTABLISHED", "AGENCY_NOT_CHECKED", "SELF_STATUS_NOT_ESTABLISHED"} <= set(checked["residual_obligations"])
    assert registry.canonical_digest() == reference_component_registry().canonical_digest()


@pytest.mark.parametrize("role,reference,kind,mode,accepted,emitted", COMPONENTS)
def test_formation_package_index_detection_plan_and_readiness_remain_nonexecuting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    role: str, reference: str, kind: ComponentKind, mode: InteractionMode,
    accepted: tuple[str, ...], emitted: tuple[str, ...],
) -> None:
    from scripts.build_component_index import build

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("catalog pipeline must not execute or instantiate formation code")

    monkeypatch.setattr(import_module("verifier.interoperability.formation_producer"), "produce_formation_certificate", forbidden)
    monkeypatch.setattr(import_module("verifier.interoperability.formation_checker"), "check_formation", forbidden)
    monkeypatch.setattr(import_module("verifier.interoperability.formation_mechanism"), "FormationPathCertificateMechanism", forbidden)
    monkeypatch.setattr(import_module("verifier.interoperability.formation_receipt"), "recheck_formation_receipt", forbidden)
    output = tmp_path / "components"
    build(output, source_ref="WORKTREE")
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)
    assert entry.validate_package(package) == package.canonical_digest()
    component = package.registry.get(_component_id(role))
    assert component == reference_component_registry().get(component.component_id)
    artifacts = {artifact.path: artifact for artifact in package.artifacts}
    required = {PROFILE_PATH, "src/verifier/specifications/TYPED_FORMATION.md",
                "src/verifier/schemas/vstd-typed-formation-0.1.schema.json",
                "src/verifier/interoperability/" + reference.split(":")[0] + ".py"}
    if role == "receipt-rechecker":
        required.update({"src/verifier/specifications/FORMATION_RECEIPT.md",
                         "src/verifier/schemas/vstd-silo-formation-receipt-0.1.schema.json"})
    implementation = next(item for item in package.implementations if item.component_id == component.component_id)
    assert required <= set(implementation.artifact_paths)
    for path in required:
        assert artifacts[path].content == (ROOT / path).read_bytes()
    assert digest_bytes(artifacts[PROFILE_PATH].content) == PROFILE_DIGEST

    query = dict(schema_id="VSTD-2", interaction_mode=mode,
                 mechanism_id=component.mechanism_ids[0], relation_id=component.supported_relations[0])
    found = index.search_exact(**query)
    assert found["match_count"] == 1
    assert found["matches"][0]["component"]["component_id"] == component.component_id
    assert found["matches"][0]["package_sha256"] == package.canonical_digest()
    assert found["matches"][0]["registry_sha256"] == package.registry.canonical_digest()
    assert found["package_availability"] == "NOT_CHECKED"
    assert found["native_qualification"] == "NOT_ESTABLISHED"
    assert found["execution_performed"] is False
    for changed in ({"schema_id": SUBJECT_SCHEMA}, {"mechanism_id": "mechanism:unrelated"},
                    {"relation_id": "relation:establishes-self-derivation"}, {"interaction_mode": InteractionMode.LIVE_MUTATING}):
        assert index.search_exact(**{**query, **changed})["match_count"] == 0

    source = (ROOT / "examples/verification_geometry_residual/geometry.json").read_text(encoding="utf-8")
    modeled = json.loads(source.replace("mechanism:fixture-test", component.mechanism_ids[0]))
    for judgment in modeled["judgments"]:
        if judgment["coordinate_id"] == "coordinate:render-functional":
            judgment["status"] = "INDETERMINATE"
            judgment["evidence_ids"] = []
    geometry = load_verification_geometry(modeled)
    before = geometry.to_dict()
    analysis = analyze_verification_surface(geometry, ControlSurfaceContext(
        interaction_mode=mode, authority_requirements=("LOCAL_REVIEW",),
    ))
    assert not analysis.validity_errors
    plan = plan_validation(analysis, package.registry, package=package)
    candidate = next(item for item in plan.candidates
                     if item.component_id == component.component_id and item.status is CandidateStatus.CANDIDATE)
    assert plan.binding_scope == "STORED_PACKAGE"
    assert plan.package_digest == package.canonical_digest()
    assert plan.registry_digest == package.registry.canonical_digest()
    assert plan.execution_performed is False
    assert f"EXACT_RULE_PROFILE:{PROFILE_DIGEST}" in candidate.execution_prerequisites
    assert "EVIDENCE_BYTES" in candidate.execution_prerequisites
    assert any(item.startswith("PACKAGE_DEPENDENCY:") for item in candidate.execution_prerequisites)
    declaration = CandidateExecutionDeclaration(candidate.candidate_id, candidate.hole_id, component.component_id, (), (), ())
    authorization = SuppliedAuthorizationDecision(AuthorizationDecision.UNKNOWN, ("LOCAL_REVIEW",), reason="No authorization evidence supplied.")
    reassessment = PostExecutionReassessmentContract(analysis.geometry_id, analysis.geometry_digest, ())

    def readiness(declared: CandidateExecutionDeclaration, **kwargs: Any) -> Any:
        return assess_execution_readiness(analysis, plan, package.registry, (declared,), authorization,
                                          reassessment, **kwargs)

    missing = readiness(declaration, package=package)
    assert missing.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("missing native input bindings" in item for item in missing.findings)
    assert any("EXACT_RULE_PROFILE:" in item and "EVIDENCE_BYTES" in item for item in missing.findings)
    assert readiness(declaration).status is ExecutionReadinessStatus.NOT_ESTABLISHED
    wrong_schema = NativeInputBinding(
        "input:formation", candidate.candidate_id, candidate.hole_id, component.component_id,
        component.native_inputs[0], "d" * 64, SUBJECT_SCHEMA if not accepted else "VSTD-2", "application/json",
    )
    assert readiness(replace(declaration, native_inputs=(wrong_schema,)), package=package).status is ExecutionReadinessStatus.INVALID
    invented_profile = PrerequisiteResolution(candidate.candidate_id, "EXACT_RULE_PROFILE:sha256:" + "0" * 64, True, "d" * 64)
    assert readiness(replace(declaration, prerequisite_resolutions=(invented_profile,)), package=package).status is ExecutionReadinessStatus.INVALID
    changed_package = replace(package, artifacts=tuple(
        replace(artifact, content=artifact.content + b" ") if artifact.path == PROFILE_PATH else artifact
        for artifact in package.artifacts
    ))
    with pytest.raises(ComponentIndexError):
        entry.validate_package(changed_package)
    assert readiness(declaration, package=changed_package).status is ExecutionReadinessStatus.INVALID
    assert missing.execution_performed is False
    assert missing.authorization_granted_by_module is False
    assert not analysis.ordinary_closed and not analysis.self_closed
    assert geometry.to_dict() == before


@pytest.mark.parametrize("change,expected", [("profile", "UNKNOWN"), ("certificate", "INVALID"), ("swapped_roles", "UNKNOWN")])
def test_formation_planning_match_cannot_promote_unsupported_or_invalid_native_evidence(change: str, expected: str) -> None:
    registry = reference_component_registry()
    component = registry.get(_component_id("checker"))
    assert registry.match_exact(schema_id="VSTD-2", interaction_mode=InteractionMode.OFFLINE_REPLAY,
                                mechanism_id=component.mechanism_ids[0]) == (component,)
    subject, certificate = _native_pair()
    if change == "profile":
        record = json.loads(subject)
        record["profile_digest"] = "sha256:" + "0" * 64
        subject = canonical_bytes(record)
    elif change == "certificate":
        record = json.loads(certificate)
        record["steps"][-1]["premises"] = [1, 0]
        certificate = canonical_bytes(record)
    else:
        # Both schemas are component-wide catalog capabilities, not proof of
        # per-input-role compatibility. The native checker must still dispatch
        # subject and certificate roles exactly and refuse the reversed pair.
        subject, certificate = certificate, subject
    report = _resolve(component.implementation_ref)(subject, certificate)
    assert report["status"] == expected
    assert report["observation"] is None
    assert "COMPLETENESS_NOT_ESTABLISHED" in report["residual_obligations"]
    assert "AGENCY_NOT_CHECKED" in report["residual_obligations"]
