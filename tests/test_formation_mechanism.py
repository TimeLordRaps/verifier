"""Experimental Verifier Standard (VSTD) native formation binding checks.

Passing finite syntax does not establish source grounding, self-derivation,
completeness, historical execution or authority axiom agency.
"""

from __future__ import annotations

import importlib
import ast
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.evidence import (
    BoundProposition,
    EvidenceBounds,
    EvidenceStore,
    MechanismOutcome,
    VerificationSession,
)
from verifier.interoperability import formation_wire as wire


GROUND = "sha256:" + "a" * 64
AGENCY = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64
PREDICATE = "vstd.typed_formation.checked.0.1"


def _fixture() -> tuple[Any, EvidenceStore, VerificationSession, BoundProposition, tuple[bytes, bytes]]:
    module = importlib.import_module("verifier.interoperability.formation_mechanism")
    mechanism = module.FormationPathCertificateMechanism()
    subject = wire.canonical_bytes({
        "schema_version": wire.SUBJECT_SCHEMA,
        "profile_digest": wire.profile_digest(),
        "context": {"ground_artifact_digest": GROUND, "authority_axiom_agency_digest": AGENCY},
        "nodes": [{"tag": "ATOM", "payload_digest": OTHER}], "root": 0,
    })
    certificate = wire.canonical_bytes({
        "schema_version": wire.CERTIFICATE_SCHEMA,
        "subject_digest": wire.digest_bytes(subject), "profile_digest": wire.profile_digest(),
        "steps": [{"node": 0, "rule": "ATOM", "premises": []}], "root": 0,
    })
    evidence = EvidenceStore()
    refs = (evidence.add(subject), evidence.add(certificate))
    session = VerificationSession(evidence)
    session.register(mechanism)
    binding = BoundProposition(
        subject_id=refs[0], predicate=PREDICATE, expected="CHECKED",
        mechanism_id=mechanism.mechanism_id, mechanism_digest=mechanism.mechanism_digest,
        evidence_refs=refs, trust_roots=tuple(sorted((wire.profile_digest(), GROUND, AGENCY))),
        bounds=EvidenceBounds(2, 2 * wire.MAX_RECORD_BYTES),
        parameters={"profile_digest": wire.profile_digest(), "ground_artifact_digest": GROUND,
                    "authority_axiom_agency_digest": AGENCY},
    )
    return mechanism, evidence, session, binding, (subject, certificate)


def test_formation_session_rechecks_exact_certificate_without_promoting_residuals() -> None:
    _mechanism, _evidence, session, binding, payloads = _fixture()
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.PASS, result
    assert result.binding_digest == binding.digest()
    assert result.observed_evidence_bytes == sum(map(len, payloads))
    report = result.observations["formation_report"]
    checker = importlib.import_module("verifier.interoperability.formation_checker")
    assert report == checker.check_formation(*payloads)
    assert report["status"] == "CHECKED"
    assert report["subject_digest"] == binding.subject_id
    assert report["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)
    assert result.observations["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)
    assert "AGENCY_NOT_CHECKED" in report["residual_obligations"]


def _rebind_payloads(
    store: EvidenceStore, binding: BoundProposition, payloads: tuple[bytes, bytes],
) -> BoundProposition:
    refs = tuple(store.add(payload) for payload in payloads)
    return replace(binding, subject_id=refs[0], evidence_refs=refs)


def test_formation_session_changed_target_is_a_bounded_binding_failure() -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    result = session.evaluate(replace(binding, subject_id=OTHER))
    assert result.outcome is MechanismOutcome.FAIL
    assert result.observations["status"] == "INVALID"
    assert result.details == "FORMATION_SUBJECT_BINDING_INVALID"


@pytest.mark.parametrize("field", ["ground_artifact_digest", "authority_axiom_agency_digest"])
def test_formation_session_context_parameters_do_not_establish_context(field: str) -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    parameters = dict(binding.parameters, **{field: OTHER})
    result = session.evaluate(replace(binding, parameters=parameters, trust_roots=tuple(parameters.values())))
    assert result.outcome is MechanismOutcome.FAIL
    assert result.details == "FORMATION_CONTEXT_BINDING_INVALID"
    # A known binding failure is returned before syntax inference, not upgraded.
    assert result.observations["formation_report"] is None
    assert result.observations["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


@pytest.mark.parametrize("change", ["target", "ground_context", "agency_context", "certificate_profile"])
def test_formation_session_old_certificate_does_not_cover_changed_bytes(change: str) -> None:
    _mechanism, store, session, binding, payloads = _fixture()
    subject, certificate = (json.loads(payload) for payload in payloads)
    parameters = dict(binding.parameters)
    if change == "target":
        subject["nodes"][0]["payload_digest"] = GROUND
    elif change == "certificate_profile":
        certificate["profile_digest"] = OTHER
    else:
        field = "ground_artifact_digest" if change == "ground_context" else "authority_axiom_agency_digest"
        subject["context"][field] = OTHER
        parameters[field] = OTHER
    binding = _rebind_payloads(store, binding, (wire.canonical_bytes(subject), wire.canonical_bytes(certificate)))
    binding = replace(binding, parameters=parameters, trust_roots=tuple(parameters.values()))
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.FAIL
    assert result.observations["formation_report"]["reason_codes"] == ["FORMATION_CERTIFICATE_BINDING_INVALID"]


@pytest.mark.parametrize("location", ["parameters", "subject"])
def test_formation_session_unsupported_profile_is_unknown(location: str) -> None:
    _mechanism, store, session, binding, payloads = _fixture()
    if location == "parameters":
        parameters = dict(binding.parameters, profile_digest=OTHER)
        binding = replace(binding, parameters=parameters, trust_roots=tuple(parameters.values()))
    else:
        subject = json.loads(payloads[0])
        subject["profile_digest"] = OTHER
        binding = _rebind_payloads(store, binding, (wire.canonical_bytes(subject), payloads[1]))
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.UNKNOWN
    assert result.observations["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


def test_formation_session_missing_evidence_and_implementation_mismatch_are_unknown() -> None:
    mechanism, _store, session, binding, _payloads = _fixture()
    missing_session = VerificationSession(EvidenceStore())
    missing_session.register(mechanism)
    assert missing_session.evaluate(binding).outcome is MechanismOutcome.UNKNOWN
    assert session.evaluate(replace(binding, mechanism_digest=OTHER)).outcome is MechanismOutcome.UNKNOWN
    assert VerificationSession(EvidenceStore()).evaluate(binding).outcome is MechanismOutcome.UNKNOWN


@pytest.mark.parametrize("index", [0, 1])
def test_formation_direct_evaluation_rehashes_substituted_bytes(index: int) -> None:
    mechanism, _store, _session, binding, payloads = _fixture()
    altered = list(payloads)
    altered[index] += b" "
    result = mechanism.evaluate(binding, altered)
    assert result.outcome is MechanismOutcome.FAIL
    assert result.details == "FORMATION_EVIDENCE_BINDING_INVALID"
    assert result.observations["formation_report"] is None


def test_formation_session_rechecks_tampered_evidence_store() -> None:
    _mechanism, store, session, binding, _payloads = _fixture()
    store._payloads[binding.evidence_refs[1]] = b"forged"
    assert session.evaluate(binding).outcome is MechanismOutcome.UNKNOWN


def test_formation_session_forged_verdict_is_not_a_certificate() -> None:
    _mechanism, store, session, binding, payloads = _fixture()
    certificate = json.loads(payloads[1])
    certificate["status"] = "CHECKED"
    binding = _rebind_payloads(store, binding, (payloads[0], wire.canonical_bytes(certificate)))
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.FAIL
    assert result.observations["formation_report"]["status"] == "INVALID"


@pytest.mark.parametrize("field,value", [
    ("expected", True), ("expected", "PASS"), ("expected", {"status": "CHECKED"}),
    ("predicate", "self_derivable"), ("parameters", {}),
    ("parameters", {"profile_digest": wire.profile_digest(), "ground_artifact_digest": GROUND,
                    "authority_axiom_agency_digest": AGENCY, "claimed_status": "CHECKED"}),
    ("trust_roots", ("declared-authority",)),
])
def test_formation_session_unsupported_binding_shape_is_unknown(field: str, value: Any) -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    result = session.evaluate(replace(binding, **{field: value}))
    assert result.outcome is MechanismOutcome.UNKNOWN
    assert result.observations["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


@pytest.mark.parametrize("bounds", [EvidenceBounds(2, 0), EvidenceBounds(2, 1),
    EvidenceBounds(True, 1000), EvidenceBounds(2, True), EvidenceBounds(2, 1.0),
    EvidenceBounds(3, 1000), EvidenceBounds(2, 2 * wire.MAX_RECORD_BYTES + 1)])
def test_formation_exact_integer_budget_is_enforced_directly_and_in_session(bounds: EvidenceBounds) -> None:
    mechanism, _store, session, binding, payloads = _fixture()
    binding = replace(binding, bounds=bounds)
    assert mechanism.evaluate(binding, payloads).outcome is MechanismOutcome.UNKNOWN
    assert session.evaluate(binding).outcome is MechanismOutcome.UNKNOWN


@pytest.mark.parametrize("index", [0, 1])
def test_formation_per_record_byte_budget_is_unknown(index: int) -> None:
    mechanism, store, session, binding, payloads = _fixture()
    oversized = list(payloads)
    oversized[index] = b" " * (wire.MAX_RECORD_BYTES + 1)
    binding = _rebind_payloads(store, binding, tuple(oversized))
    assert mechanism.evaluate(binding, oversized).outcome is MechanismOutcome.UNKNOWN
    assert session.evaluate(binding).outcome is MechanismOutcome.UNKNOWN


def test_formation_direct_ref_order_types_and_missing_inputs_are_not_accepted() -> None:
    mechanism, _store, _session, binding, payloads = _fixture()
    assert mechanism.evaluate(binding, payloads[:1]).outcome is MechanismOutcome.UNKNOWN
    assert mechanism.evaluate(binding, (bytearray(payloads[0]), payloads[1])).outcome is MechanismOutcome.FAIL
    reversed_binding = replace(binding, evidence_refs=tuple(reversed(binding.evidence_refs)))
    assert mechanism.evaluate(reversed_binding, tuple(reversed(payloads))).outcome is MechanismOutcome.FAIL
    assert mechanism.evaluate(replace(binding, mechanism_digest=OTHER), payloads).outcome is MechanismOutcome.UNKNOWN


@pytest.mark.parametrize("field", ["parameters", "trust_roots", "evidence_refs", "subject_id"])
def test_formation_direct_malformed_binding_is_unknown_before_execution(field: str) -> None:
    mechanism, _store, _session, binding, payloads = _fixture()
    values = {
        "parameters": dict(binding.parameters, ground_artifact_digest=GROUND.upper()),
        "trust_roots": tuple(reversed(binding.trust_roots)),
        "evidence_refs": (binding.evidence_refs[0], binding.evidence_refs[1].removeprefix("sha256:")),
        "subject_id": "not-a-digest",
    }
    # Deliberately bypass the core constructor's normalization to exercise this
    # direct-call boundary; ordinary callers should not mutate frozen bindings.
    object.__setattr__(binding, field, values[field])
    result = mechanism.evaluate(binding, payloads)
    assert result.outcome is MechanismOutcome.UNKNOWN
    assert result.observations["formation_report"] is None


def test_formation_unexpected_checker_exception_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    mechanism, _store, session, binding, payloads = _fixture()
    module = importlib.import_module("verifier.interoperability.formation_mechanism")

    def broken(*args: Any) -> Any:
        raise RuntimeError("test-only broken checker")

    monkeypatch.setattr(module, "check_formation", broken)
    for result in (mechanism.evaluate(binding, payloads), session.evaluate(binding)):
        assert result.outcome is MechanismOutcome.UNKNOWN
        assert result.details == "FORMATION_EXECUTION_UNKNOWN"
        assert result.observations["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


def test_formation_session_never_binds_pass_to_caller_mutation_during_check(monkeypatch: pytest.MonkeyPatch) -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    module = importlib.import_module("verifier.interoperability.formation_mechanism")
    real_checker = module.check_formation
    original_digest = binding.digest()

    def mutate_after_real_check(subject: bytes, certificate: bytes) -> dict[str, Any]:
        report = real_checker(subject, certificate)
        assert report["status"] == "CHECKED"
        # Simulate an independently held caller reference changing while a real
        # checker runs. The checked snapshot must not inherit this later claim.
        binding.parameters["ground_artifact_digest"] = OTHER
        return report

    monkeypatch.setattr(module, "check_formation", mutate_after_real_check)
    result = session.evaluate(binding)
    assert binding.parameters["ground_artifact_digest"] == OTHER
    assert binding.digest() != original_digest
    assert result.outcome is MechanismOutcome.UNKNOWN or result.binding_digest == original_digest, (
        "A passing check must bind the evaluated declaration, not its caller's later mutation", result,
    )


def test_formation_direct_parameters_are_copied_before_semantic_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    mechanism, _store, _session, binding, payloads = _fixture()
    module = importlib.import_module("verifier.interoperability.formation_mechanism")
    real_is_digest = module._is_digest

    def mutate_during_validation(value: Any) -> bool:
        result = real_is_digest(value)
        if value == wire.profile_digest():
            binding.parameters["ground_artifact_digest"] = "not-a-digest"
        return result

    monkeypatch.setattr(module, "_is_digest", mutate_during_validation)
    result = mechanism.evaluate(binding, payloads)
    assert binding.parameters["ground_artifact_digest"] == "not-a-digest"
    assert result.outcome is MechanismOutcome.PASS, result
    assert result.observations["formation_report"]["status"] == "CHECKED"


def test_formation_checker_exhaustion_keeps_pure_report_and_residuals(monkeypatch: pytest.MonkeyPatch) -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    checker = importlib.import_module("verifier.interoperability.formation_checker")
    # Explicit test-only budget reduction; not production source identity evidence.
    monkeypatch.setattr(checker, "MAX_DEPTH", 0)
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.UNKNOWN
    assert result.observations["formation_report"]["reason_codes"] == ["FORMATION_LIMIT_EXCEEDED"]
    assert result.observations["formation_report"]["residual_obligations"] == list(wire.RESIDUAL_OBLIGATIONS)


def test_formation_known_context_failure_precedes_later_inference_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    checker = importlib.import_module("verifier.interoperability.formation_checker")
    monkeypatch.setattr(checker, "MAX_DEPTH", 0)
    parameters = dict(binding.parameters, ground_artifact_digest=OTHER)
    binding = replace(binding, parameters=parameters, trust_roots=tuple(parameters.values()))
    result = session.evaluate(binding)
    assert result.outcome is MechanismOutcome.FAIL
    assert result.details == "FORMATION_CONTEXT_BINDING_INVALID"
    assert result.observations["formation_report"] is None


def test_formation_mechanism_has_exact_selected_source_identity() -> None:
    mechanism, _store, _session, _binding, _payloads = _fixture()
    module = importlib.import_module("verifier.interoperability.formation_mechanism")
    root = Path(module.__file__).parent
    inventory = {"schema_version": "VSTD-TYPED-FORMATION-SOURCE-IDENTITY-0.1",
        "profile_digest": wire.profile_digest(), "sources": [
            {"path": name, "digest": wire.digest_bytes((root / name).read_bytes())}
            for name in ("formation_mechanism.py", "formation_checker.py", "formation_wire.py", "network.py")
        ]}
    assert mechanism.mechanism_digest == wire.digest_bytes(wire.canonical_bytes(inventory))
    assert "formation_producer.py" not in str(inventory)


def test_formation_adapter_imports_no_producer_and_reads_no_evidence_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    _mechanism, _store, session, binding, _payloads = _fixture()
    module = importlib.import_module("verifier.interoperability.formation_mechanism")
    syntax = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            assert all("producer" not in alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert "producer" not in (node.module or "")
            assert all("producer" not in alias.name for alias in node.names)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("evaluation attempted file access")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    assert session.evaluate(binding).outcome is MechanismOutcome.PASS
