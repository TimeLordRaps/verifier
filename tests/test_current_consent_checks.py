"""Current consent certificates with independently signed selected-holder evidence.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Generated signing
keys are ephemeral test fixtures. Times are integer Unix seconds.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import importlib
import json
from typing import Any

import pytest

from verifier.consent import public, stages
from verifier.consent.engine import ConsentContext
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import composition_digest
from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
from test_current_typed_facets import KINDS, collection
# test_public_consent skips this whole module where the signing backend is absent (see its module-level guard).
from test_public_consent import sign


def contract() -> Any:
    return importlib.import_module("verifier.domains.contracts.consent_checks")


def inputs(kind: str = "OBJECT", stage: int = 1, *, holders: int = 2,
           missing: str | None = None, revoked: str | None = None,
           verdict: str = "FAIL", **limits: int) -> tuple[Any, dict, dict, bytes]:
    candidate = contract()
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    objects = collection()
    subject = next(obj for obj in objects if obj.object_id == kind.lower())
    context = ConsentContext(subject.object_id, subject.digest.removeprefix("sha256:"),
        "inspect", "operator", "reader", "review", 100)
    selected, retained, historical = [], {}, {}
    for index in range(holders):
        holder = "holder-" + str(index)
        private = {name: crypto.Ed25519PrivateKey.generate() for name in ("root", "status")}
        keys = [{"key_id": name, "actor_id": holder if name == "root" else "registry-" + holder,
            "public_key": key.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()} for name, key in private.items()]
        policy = public.public_consent_policy(policy_id="policy-" + holder, grantor_id=holder,
            keys=keys, root_key_ids=["root"], revocation_key_ids=["status"],
            artifact_bindings=[[subject.object_id, context.artifact_digest]],
            max_revocation_age_seconds=30)
        grant = {"schema_version": "verifier-consent-public-grant-1", "grant_id": "grant-" + holder,
            "issuer_id": holder, "actor_id": "operator", "object_name": subject.object_id,
            "artifact_digest": context.artifact_digest, "operations": ["inspect"],
            "observer_ids": ["reader"], "purposes": ["review"], "not_before": 90,
            "not_after": 110, "effect": "ALLOW", "allow_delegation": False, "parent_digest": None}
        status = {"schema_version": "verifier-consent-public-revocations-1",
            "issuer_id": "registry-" + holder, "policy_id": "policy-" + holder,
            "as_of": 95, "next_update": 105,
            "revoked_grant_ids": ["grant-" + holder] if revoked == holder else []}
        selected.append({"holder_id": holder, "public_policy": policy})
        row = {"grants": [sign(grant, "root", private)],
            "revocation": sign(status, "status", private), "receipt": None}
        if stage == 5:
            row["receipt"] = stages.evaluate_consent_stages(context, tuple(row["grants"]),
                policy=policy, revocation=row["revocation"], evaluation_time=100,
                computational_verdict=verdict)
            historical[holder] = "sha256:" + canonical_digest(row["receipt"])
        if holder != missing:
            retained[holder] = row
    policy = candidate.consent_checks_policy(trust_roots=["test:selected-authority"],
        required_holders=selected)
    evidence = canonical_bytes({"schema_version": candidate.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in sorted(objects, key=lambda obj: obj.object_id)],
        "holders": retained})
    request = candidate.consent_checks_request(object_kind=kind, stage=stage,
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects), evidence_ref="sha256:" + canonical_digest(json.loads(evidence)),
        action={"operation": "inspect", "actor_id": "operator", "observer_id": "reader",
            "purpose": "review", "timestamp": 100}, evaluation_time=100,
        computational_verdict=verdict, historical_receipts=historical, policy=policy,
        limits=limits or None)
    return candidate, request, policy, evidence


def replay(candidate: Any, request: dict, policy: dict, evidence: bytes | None) -> dict:
    encoded = candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    return replay_current_object_certificate(encoded, semantic_version=request["semantic_version"],
        objective=request["coordinate"], represented_kind=request["object_kind"],
        expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("stage", range(1, 7))
def test_each_kind_and_stage_replays_two_independently_selected_holders(kind: str, stage: int) -> None:
    candidate, request, policy, evidence = inputs(kind, stage)
    encoded = candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    assert encoded == candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    report = replay(candidate, request, policy, evidence)
    assert report["schema_version"] == "verifier-current-object-route-replay-2"
    assert report["replay_status"] == "REPRODUCED" and report["computational_status"] == "PASS"
    native = report["native_result"]
    assert native["selected_computational_verdict"] == "FAIL"
    assert native["admission_status"] == "PASS"
    assert native["enforcement"] == native["holder_set_completeness"] == "NOT_ESTABLISHED"
    assert set(native["holder_results"]) == {"holder-0", "holder-1"}


@pytest.mark.parametrize("stage", [1, 2, 3, 4, 5])
def test_one_holder_cannot_supply_missing_second_holder(stage: int) -> None:
    report = replay(*inputs(stage=stage, missing="holder-1"))
    assert report["computational_status"] == "UNKNOWN"
    assert report["native_result"]["admission_status"] == "UNKNOWN"


@pytest.mark.parametrize("stage,expected", [(1,"PASS"),(2,"PASS"),(3,"FAIL"),(4,"FAIL"),(5,"PASS"),(6,"PASS")])
def test_reproduction_and_scope_do_not_mask_revoked_admission(stage: int, expected: str) -> None:
    report = replay(*inputs(stage=stage, revoked="holder-1"))
    assert report["computational_status"] == expected
    assert report["native_result"]["admission_status"] == "FAIL"


@pytest.mark.parametrize("field", ["object_digest", "collection_digest", "subject_id"])
def test_selected_full_record_and_collection_are_bound(field: str) -> None:
    candidate, request, policy, evidence = inputs()
    request[field] = "other" if field == "subject_id" else "sha256:" + "0" * 64
    assert replay(candidate, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("limit", ["max_objects", "max_operations", "max_composition_operations",
    "max_evidence_bytes", "max_payload_bytes", "max_reference_bytes", "max_holder_evaluations"])
def test_external_resource_limits_preserve_unknown(limit: str) -> None:
    assert replay(*inputs(**{limit: 1}))["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("stage", range(1, 7))
def test_missing_retained_evidence_never_passes(stage: int) -> None:
    candidate, request, policy, _ = inputs(stage=stage)
    assert replay(candidate, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("stage", range(1, 7))
def test_replay_missing_backend_is_unavailable_not_reproduced(monkeypatch: Any, stage: int) -> None:
    candidate, request, policy, evidence = inputs(stage=stage)
    encoded = candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    def absent(*args: Any) -> None:
        raise public._Unknown("public signature backend unavailable")
    monkeypatch.setattr(public, "_verify_signature", absent)
    report = replay_current_object_certificate(encoded, semantic_version=request["semantic_version"],
        objective=request["coordinate"], represented_kind=request["object_kind"], expected_request=request, policy=policy)
    assert report["replay_status"] == "UNAVAILABLE"
    assert report["computational_status"] == "UNKNOWN"


def test_rehashed_false_result_rejects() -> None:
    candidate, request, policy, evidence = inputs(stage=3, revoked="holder-1")
    value = json.loads(candidate.build_consent_checks_certificate(request, evidence, policy=policy))
    value["result"]["status"] = "PASS"
    value["digest"] = "sha256:" + canonical_digest({key: item for key, item in value.items() if key != "digest"})
    with pytest.raises(ValueError):
        candidate.recheck_consent_checks_certificate(canonical_bytes(value), expected_request=request, policy=policy)


def test_external_policy_and_selection_mutation_are_rejected() -> None:
    candidate, request, policy, evidence = inputs()
    encoded = candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    altered = deepcopy(policy)
    altered["required_holders"] = altered["required_holders"][:1]
    with pytest.raises(ValueError):
        candidate.recheck_consent_checks_certificate(encoded, expected_request=request, policy=altered)


def test_computational_verdict_does_not_grant_consent() -> None:
    report = replay(*inputs(stage=6, revoked="holder-1", verdict="PASS"))
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["admission_status"] == "FAIL"
    assert report["native_result"]["selected_computational_verdict"] == "PASS"


def test_polish_reports_unavailable_replay_without_reproduction_claim(monkeypatch: Any) -> None:
    from verifier.runtime.polish import _objective
    candidate, request, policy, evidence = inputs()
    encoded = candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    identifier = "sha256:" + canonical_digest(json.loads(encoded))
    selected = {"semantic_version": request["semantic_version"], "coordinate": request["coordinate"],
        "certificate_digest": identifier, "request": request, "policy": policy}
    subject = next(obj for obj in collection() if obj.object_id == request["subject_id"])
    def absent(*args: Any) -> None:
        raise public._Unknown("public signature backend unavailable")
    monkeypatch.setattr(public, "_verify_signature", absent)
    result = _objective(selected, subject, {identifier: encoded}, request["collection_digest"])
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "NATIVE_REPLAY_UNAVAILABLE"
    assert result["replay_observation"] == "RETAINED_CERTIFICATE_REPLAY_UNAVAILABLE"


def test_consent_certificate_cannot_have_evidence_redacted() -> None:
    from verifier.privacy import DisclosureSurface, DisclosureBound, ObserverParty, EmissionContext, EmissionEvaluator, EmissionRefusalError
    candidate, request, policy, evidence = inputs()
    value = json.loads(candidate.build_consent_checks_certificate(request, evidence, policy=policy))
    fields = tuple(key for key in value if key != "evidence")
    surface = DisclosureSurface("OBJECT", fields, ("evidence",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("stage,revoked,expected", [(1,None,0),(3,"holder-1",1),(3,None,2)])
def test_public_command_reports_selected_result(tmp_path: Any, capsys: Any, stage: int, revoked: str | None, expected: int) -> None:
    from verifier.runtime.public_cli import main
    candidate, request, policy, evidence = inputs(stage=stage, revoked=revoked)
    if expected == 2:
        request["evaluation_time"] = None
    encoded = candidate.build_consent_checks_certificate(request, evidence, policy=policy)
    for name, data in (("certificate", encoded), ("request", canonical_bytes(request)), ("policy", canonical_bytes(policy))):
        (tmp_path / name).write_bytes(data)
    result = main(["current-object", "check", str(tmp_path / "certificate"), "--semantic-version", request["semantic_version"],
        "--objective", request["coordinate"], "--represented-kind", request["object_kind"],
        "--request", str(tmp_path / "request"), "--policy", str(tmp_path / "policy"), "--json"])
    assert result == expected
    assert json.loads(capsys.readouterr().out)["computational_status"] == ("PASS", "FAIL", "UNKNOWN")[expected]
