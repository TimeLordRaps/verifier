"""Verifier Standard (VSTD) grounded certification boundary tests.

Fixture mechanisms exercise orchestration, not real-world profile conformance.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import ClaimBinding, ClaimCoordinate, ResourceBounds, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.kernel import reference_descriptor
from verifier.core.profile_obligations import OBLIGATIONS, obligation_catalog
from verifier.core.grounded_certification import (
    CertificationError, CertificationPolicy, CertificationRequest,
    MechanismAdmission, assess_grounded_certification,
    build_grounded_certificate, recheck_grounded_certificate,
    evidence_root,
)


class FixtureMechanism:
    """Test-only executable arithmetic oracle; never a production profile adapter."""
    mechanism_id = "test.arithmetic-obligations"
    mechanism_digest = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def __init__(self):
        self.calls = []

    def evaluate(self, binding, evidence):
        self.calls.append(binding.predicate)
        value = json.loads(evidence[0])
        if value["predicate"] != binding.predicate:
            return MechanismDecision(MechanismOutcome.FAIL, "wrong predicate")
        actual = value["left"] + value["right"] == value["sum"]
        return MechanismDecision(
            MechanismOutcome.PASS if actual else MechanismOutcome.FAIL,
            "fixture arithmetic executed",
        )


def fixture_request(target=5):
    store = EvidenceStore()
    mechanism = FixtureMechanism()
    session = VerificationSession(store)
    session.register(mechanism)
    selected = [o for o in OBLIGATIONS if o.profile <= target]
    policy = CertificationPolicy({
        o.id: MechanismAdmission(mechanism.mechanism_id, mechanism.mechanism_digest,
                                 ("test:arithmetic-only",)) for o in selected
    })
    refs = {o.id: store.add(json.dumps({"predicate": o.predicate,
            "left": o.profile, "right": o.index, "sum": o.profile + o.index},
            sort_keys=True).encode()) for o in selected}
    binding = ClaimBinding(
        "test-only orchestration fixture", ClaimCoordinate("fixture:subject", "test"),
        policy.digest(), evidence_root(tuple(refs.values())), reference_descriptor(),
        ResourceBounds(10000, 10000, 1000000),
    )
    obligations = {o.id: BoundProposition(
        "fixture:claim", o.predicate, True, mechanism.mechanism_id,
        mechanism.mechanism_digest, (refs[o.id],), ("test:arithmetic-only",),
        EvidenceBounds(1, 10000), {"claim_binding_digest": binding.digest()},
    ) for o in selected}
    return CertificationRequest("fixture:claim", binding, target, obligations), policy, session, mechanism


def test_every_profile_has_contiguous_obligations_and_existing_rungs_are_preserved():
    from verifier.core.depth import RUNGS
    assert {o.profile for o in OBLIGATIONS} == {1, 2, 3, 4, 5}
    for profile in range(1, 6):
        rows = [o for o in OBLIGATIONS if o.profile == profile]
        assert [o.id for o in rows] == [f"{profile}.{i}" for i in range(1, len(rows)+1)]
    assert [(o.id, o.name) for o in OBLIGATIONS if o.profile == 4] == [(r.id, r.name) for r in RUNGS]
    assert obligation_catalog()["schema_version"] == "VSTD-OBLIGATIONS-1"


@pytest.mark.parametrize("target", range(1, 6))
def test_all_profiles_require_mechanism_execution_and_portable_replay(target):
    request, policy, session, mechanism = fixture_request(target)
    certificate = build_grounded_certificate(request, policy=policy, session=session)
    assert len(mechanism.calls) == len(request.obligations)
    assert certificate["result"]["certified_profile_depth"] == target
    replay = recheck_grounded_certificate(certificate, policy=policy, mechanisms=[FixtureMechanism()], expected_request_digest=canonical_digest(request.to_dict()))
    assert replay == certificate["result"]


@pytest.mark.parametrize("profile", range(1, 6))
def test_missing_obligation_never_becomes_false_or_cumulative_success(profile):
    request, policy, session, _ = fixture_request()
    obligations = dict(request.obligations)
    obligations.pop(f"{profile}.1")
    request = replace(request, obligations=obligations)
    request = rebind(request, policy)
    result = assess_grounded_certification(request, policy=policy, session=session)
    assert result["obligations"][f"{profile}.1"]["outcome"] == "UNKNOWN"
    assert result["certified_profile_depth"] == profile - 1
    assert result["status"] == "UNKNOWN"


def rebind(request, policy):
    refs = tuple(r for b in request.obligations.values() for r in b.evidence_refs)
    binding = replace(request.binding, evidence_root=evidence_root(refs), policy_root=policy.digest())
    return replace(request, binding=binding, obligations={
        key: replace(value, parameters={"claim_binding_digest": binding.digest()})
        for key, value in request.obligations.items()
    })


@pytest.mark.parametrize("mutation", ["subject", "predicate", "expected", "commitment", "mechanism", "roots"])
def test_neighboring_binding_or_unapproved_mechanism_does_not_earn_an_obligation(mutation):
    request, policy, session, mechanism = fixture_request(1)
    item = request.obligations["1.1"]
    changes = {
        "subject": {"subject_id": "neighbor"},
        "predicate": {"predicate": "bytes.sha256"},
        "expected": {"expected": 1},
        "commitment": {"parameters": {"claim_binding_digest": "0"*64}},
        "mechanism": {"mechanism_digest": "0"*64},
        "roots": {"trust_roots": ("unapproved",)},
    }
    request = replace(request, obligations={**request.obligations, "1.1": replace(item, **changes[mutation])})
    result = assess_grounded_certification(request, policy=policy, session=session)
    assert result["certified_profile_depth"] == 0
    assert result["obligations"]["1.1"]["outcome"] == "UNKNOWN"
    assert item.predicate not in mechanism.calls


def test_refutation_remains_fail_even_when_another_obligation_is_unknown():
    request, policy, session, _ = fixture_request(1)
    item = request.obligations["1.1"]
    ref = session.evidence.add(json.dumps({"predicate": item.predicate,
        "left": 1, "right": 1, "sum": 3}).encode())
    obligations = {**request.obligations, "1.1": replace(item, evidence_refs=(ref,))}
    obligations.pop("1.2")
    request = rebind(replace(request, obligations=obligations), policy)
    cert = build_grounded_certificate(request, policy=policy, session=session)
    assert cert["result"]["status"] == "FAIL"
    assert cert["result"]["obligations"]["1.2"]["outcome"] == "UNKNOWN"
    assert recheck_grounded_certificate(cert, policy=policy, mechanisms=[FixtureMechanism()], expected_request_digest=canonical_digest(request.to_dict())) == cert["result"]


@pytest.mark.parametrize("field", ["result", "payload", "catalog", "target", "policy"])
def test_rechecker_rejects_substitution_even_after_outer_digest_is_recomputed(field):
    from verifier.core.certificate import canonical_digest
    request, policy, session, _ = fixture_request(1)
    cert = build_grounded_certificate(request, policy=policy, session=session)
    if field == "result": cert["result"]["certified_profile_depth"] = 5
    if field == "payload": cert["evidence_payloads"][next(iter(cert["evidence_payloads"]))] = "e30="
    if field == "catalog": cert["catalog_digest"] = "0"*64
    if field == "target": cert["request"]["target_profile"] = 2
    if field == "policy": cert["policy_digest"] = "0"*64
    cert["digest"] = canonical_digest({k:v for k,v in cert.items() if k != "digest"})
    with pytest.raises(CertificationError):
        recheck_grounded_certificate(cert, policy=policy, mechanisms=[FixtureMechanism()], expected_request_digest=canonical_digest(request.to_dict()))


def test_global_evidence_budget_stops_before_any_mechanism_executes():
    request, policy, session, mechanism = fixture_request(1)
    policy = replace(policy, max_evidence_bytes=1)
    request = rebind(request, policy)
    result = assess_grounded_certification(request, policy=policy, session=session)
    assert result["status"] == "UNKNOWN"
    assert not mechanism.calls


def test_foreign_policy_cannot_be_selected_by_the_certificate():
    request, policy, session, _ = fixture_request(1)
    cert = build_grounded_certificate(request, policy=policy, session=session)
    with pytest.raises(CertificationError, match="policy"):
        recheck_grounded_certificate(cert, policy=replace(policy, max_evidence_bytes=123), mechanisms=[FixtureMechanism()], expected_request_digest=canonical_digest(request.to_dict()))


@pytest.mark.parametrize("bad", [True, "1", 0, 6, 1.5])
def test_invalid_profile_coordinates_are_rejected(bad):
    request, policy, session, _ = fixture_request(1)
    with pytest.raises(CertificationError):
        assess_grounded_certification(replace(request, target_profile=bad), policy=policy, session=session)


def test_serialized_pass_and_unknown_fields_are_not_admission_inputs():
    request, _, _, _ = fixture_request(1)
    payload = request.to_dict()
    payload["obligations"]["1.1"]["outcome"] = "PASS"
    with pytest.raises(CertificationError):
        CertificationRequest.from_dict(payload)


def test_published_schemas_match_requests_policies_and_all_verdicts():
    from jsonschema import Draft202012Validator
    root = Path(__file__).resolve().parents[1] / "standard" / "schemas"
    validators = {kind: Draft202012Validator(json.loads((root/f"vstd-grounded-{kind}-1.schema.json").read_text()))
                  for kind in ("request", "policy", "certification")}
    for validator in validators.values():
        validator.check_schema(validator.schema)
    for target in range(1, 6):
        request, policy, session, _ = fixture_request(target)
        validators["request"].validate(request.to_dict())
        validators["policy"].validate(policy.to_dict())
        validators["certification"].validate(build_grounded_certificate(request, policy=policy, session=session))
        unknown = rebind(replace(request, obligations={}), policy)
        validators["certification"].validate(build_grounded_certificate(unknown, policy=policy, session=session))
    request, policy, session, _ = fixture_request(1)
    prop = request.obligations["1.1"]
    bad = session.evidence.add(json.dumps({"predicate":prop.predicate,"left":0,"right":0,"sum":1}).encode())
    request = rebind(replace(request, obligations={**request.obligations,"1.1":replace(prop,evidence_refs=(bad,))}),policy)
    cert = build_grounded_certificate(request, policy=policy, session=session)
    assert cert["result"]["status"] == "FAIL"
    validators["certification"].validate(cert)


def test_missing_payload_replays_unknown_without_a_false_receipt_of_availability():
    request, policy, session, _ = fixture_request(1)
    missing = request.obligations["1.1"].evidence_refs[0]
    # Simulate unavailable evidence, preserving the exact requested address.
    empty = EvidenceStore()
    for p in request.obligations.values():
        for ref in p.evidence_refs:
            if ref != missing:
                empty.add(session.evidence.resolve(ref))
    limited = VerificationSession(empty)
    limited.register(FixtureMechanism())
    cert = build_grounded_certificate(request, policy=policy, session=limited)
    assert missing not in cert["evidence_payloads"]
    assert cert["result"]["obligations"]["1.1"]["outcome"] == "UNKNOWN"
    assert recheck_grounded_certificate(cert, policy=policy, mechanisms=[FixtureMechanism()],
        expected_request_digest=canonical_digest(request.to_dict())) == cert["result"]


def test_unregistered_or_crashing_mechanism_is_unknown_and_never_pass():
    request, policy, session, _ = fixture_request(1)
    empty = VerificationSession(session.evidence)
    assert assess_grounded_certification(request,policy=policy,session=empty)["status"] == "UNKNOWN"
    class Crashing(FixtureMechanism):
        def evaluate(self, binding, evidence):
            raise RuntimeError("fixture crash")
    empty.register(Crashing())
    result = assess_grounded_certification(request,policy=policy,session=empty)
    assert result["status"] == "UNKNOWN"
    assert "fixture crash" in result["obligations"]["1.1"]["reason"]


def test_unknown_outcome_type_and_mutating_mechanism_do_not_earn_certification():
    request, policy, session, _ = fixture_request(1)
    class Bad(FixtureMechanism):
        def evaluate(self, binding, evidence):
            return MechanismDecision("PASS", "invalid enum")
    session.register(Bad())
    assert assess_grounded_certification(request,policy=policy,session=session)["status"] == "UNKNOWN"
    class Mutating(FixtureMechanism):
        def evaluate(self, binding, evidence):
            binding.parameters["claim_binding_digest"] = "changed"
            return MechanismDecision(MechanismOutcome.PASS,"mutated input")
    session.register(Mutating())
    before = canonical_digest(request.to_dict())
    assert assess_grounded_certification(request,policy=policy,session=session)["status"] == "UNKNOWN"
    assert canonical_digest(request.to_dict()) == before


def test_byte_item_and_certificate_limits_are_enforced():
    request, policy, session, mechanism = fixture_request(1)
    for field in ("max_evidence_items", "max_evidence_bytes"):
        small = replace(policy, **{field:0})
        bounded = rebind(request, small)
        with pytest.raises(CertificationError, match="bound"):
            build_grounded_certificate(bounded,policy=small,session=session)
    assert mechanism.calls == []
    small = replace(policy,max_certificate_bytes=10)
    with pytest.raises(CertificationError, match="bound"):
        build_grounded_certificate(rebind(request,small),policy=small,session=session)


def test_missing_independence_dimension_blocks_profile_five_with_lower_evidence_intact():
    request, policy, session, _ = fixture_request(5)
    obligations = dict(request.obligations)
    obligations.pop("5.8")
    request = rebind(replace(request,obligations=obligations),policy)
    result = assess_grounded_certification(request,policy=policy,session=session)
    assert result["certified_profile_depth"] == 4
    assert result["obligations"]["5.10"]["outcome"] == "PASS"
    assert result["obligations"]["5.10"]["established"] is False
    assert "5.8" in result["obligations"]["5.10"]["blocked_by"]


def test_normative_catalogue_and_runtime_rows_agree():
    text = (Path(__file__).resolve().parents[1]/"standard/GROUNDED_CERTIFICATION.md").read_text(encoding="utf-8")
    for o in OBLIGATIONS:
        row = f"| {o.id} | {o.name} | {o.requirement} | {', '.join(o.depends_on) or 'none'} | {o.source} |"
        assert row in text


def test_builtin_digest_checker_cannot_launder_a_profile_obligation():
    from verifier.core.evidence import BytesDigestMechanism
    request, policy, session, _ = fixture_request(1)
    mechanism = BytesDigestMechanism()
    session.register(mechanism)
    policy = replace(policy,admissions={k:MechanismAdmission(mechanism.mechanism_id,
        mechanism.mechanism_digest,("test:arithmetic-only",)) for k in request.obligations})
    request = replace(request,obligations={k:replace(v,mechanism_id=mechanism.mechanism_id,
        mechanism_digest=mechanism.mechanism_digest) for k,v in request.obligations.items()})
    request = rebind(request,policy)
    result = assess_grounded_certification(request,policy=policy,session=session)
    assert result["status"] == "UNKNOWN"
    assert result["certified_profile_depth"] == 0


def test_externally_expected_request_and_checker_coordinate_are_required():
    request,policy,session,_ = fixture_request(1)
    cert = build_grounded_certificate(request,policy=policy,session=session)
    with pytest.raises(CertificationError,match="expected request"):
        recheck_grounded_certificate(cert,policy=policy,mechanisms=[FixtureMechanism()],
                                    expected_request_digest="0"*64)
    cert["checker_digest"] = "0"*64
    cert["digest"] = canonical_digest({k:v for k,v in cert.items() if k != "digest"})
    with pytest.raises(CertificationError,match="checker"):
        recheck_grounded_certificate(cert,policy=policy,mechanisms=[FixtureMechanism()],
                                    expected_request_digest=canonical_digest(request.to_dict()))


def test_one_byte_change_to_evidence_or_policy_changes_claim_commitment():
    request,policy,session,_ = fixture_request(1)
    prop = request.obligations["1.1"]
    changed = session.evidence.add(session.evidence.resolve(prop.evidence_refs[0])+b" ")
    swapped = replace(request,obligations={**request.obligations,"1.1":replace(prop,evidence_refs=(changed,))})
    with pytest.raises(CertificationError,match="evidence root"):
        assess_grounded_certification(swapped,policy=policy,session=session)
    with pytest.raises(CertificationError,match="policy"):
        assess_grounded_certification(request,policy=replace(policy,max_evidence_items=100),session=session)


def test_edited_catalogue_or_unknown_coordinate_is_rejected_before_execution():
    request,policy,session,mechanism = fixture_request(1)
    stale = replace(policy,catalog="0"*64)
    with pytest.raises(CertificationError,match="catalogue"):
        assess_grounded_certification(rebind(request,stale),policy=stale,session=session)
    bad = replace(request,obligations={**request.obligations,"1.99":request.obligations["1.1"]})
    with pytest.raises(CertificationError,match="unknown"):
        assess_grounded_certification(bad,policy=policy,session=session)
    assert not mechanism.calls


@pytest.mark.parametrize("block", ["bounds", "proposition_bounds", "target"])
def test_booleans_cannot_impersonate_integer_counts(block):
    request,_,_,_ = fixture_request(1)
    value = request.to_dict()
    if block == "bounds":value["binding"]["bounds"]["memory_bound"] = True
    if block == "proposition_bounds":value["obligations"]["1.1"]["bounds"]["max_evidence_items"] = True
    if block == "target":value["target_profile"] = True
    with pytest.raises(CertificationError):CertificationRequest.from_dict(value)
