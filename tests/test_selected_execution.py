"""Adversarial selected byte-digest execution for Verifier Standard (VSTD).

These bounded tests make no broad correctness claims.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from verifier.core.evidence import BytesDigestMechanism, EvidenceBounds, EvidenceStore
from verifier.core.geometry import (
    Coordinate, CoordinateJudgment, CoordinateStatus, Facet, Grain, Horizon,
    HorizonKind, Locus, LocusKind, Stratum, Subject, VerificationGeometry,
    VerificationMechanism, VerificationSurface,
)
from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.catalog import (
    ComponentAvailability, ComponentKind, ComponentLifecycle,
    InteroperabilityComponentDescriptor, InteroperabilityComponentRegistry,
)
from verifier.interoperability.control_surface import analyze_verification_surface, plan_validation
from verifier.interoperability.selected_execution import (
    DIGEST_FACET_DESCRIPTION, DigestHostPolicy, SelectedExecutionError,
    execute_selected_validation, prepare_digest_validation, replay_selected_validation,
)


PAYLOAD = b"hello"
# Fixed independently of the evidence delivered to execution.
EXPECTED = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def specimen() -> tuple[VerificationGeometry, InteroperabilityComponentRegistry]:
    geometry = VerificationGeometry(
        "geometry:bytes", "subject:bytes", [Subject("subject:bytes", "Supplied bytes", "1")],
        [Locus("locus:bytes", "subject:bytes", "Input", LocusKind.FILE, Grain.FILE, Stratum.SOURCE, "input.txt")],
        [Facet("bytes.sha256", "Byte digest equality", DIGEST_FACET_DESCRIPTION), Facet("meaning", "Meaning", "Not checked")],
        [Coordinate("digest", "locus:bytes", "bytes.sha256"), Coordinate("meaning", "locus:bytes", "meaning")],
        VerificationSurface("surface:bytes", "subject:bytes", ("digest", "meaning")),
        mechanisms=[VerificationMechanism("vstd.bytes.sha256", "Byte digest", "1")],
        judgments=[CoordinateJudgment("digest", CoordinateStatus.INDETERMINATE, ("vstd.bytes.sha256",), ("old-observation",), ("host expectation is appropriate",), ("digest only",)), CoordinateJudgment("meaning", CoordinateStatus.UNSUPPORTED)],
        horizons=[Horizon("horizon:meaning", HorizonKind.EVIDENCE, "Meaning has no checker", coordinate_id="meaning")],
    )
    registry = InteroperabilityComponentRegistry("selected-test-1", (
        InteroperabilityComponentDescriptor(
            "builtin-digest", "Builtin byte digest", ComponentKind.CHECKER,
            ComponentLifecycle.EXPERIMENTAL, "verifier.core.evidence:BytesDigestMechanism", (),
            mechanism_ids=("vstd.bytes.sha256",), planning_surface_schema_ids=("VSTD-2",),
            trust_roots=("host-pinned-expectation",), availability=ComponentAvailability.AVAILABLE,
        ),
    ))
    return geometry, registry


def request_for(*, payload: bytes = PAYLOAD, bounds: EvidenceBounds | None = None) -> tuple[dict, EvidenceStore, VerificationGeometry]:
    geometry, registry = specimen()
    store = EvidenceStore()
    reference = store.add(payload)
    request = prepare_digest_validation(geometry, registry, plan_validation(analyze_verification_surface(geometry), registry), coordinate_id="digest", expected_digest=EXPECTED, evidence_ref=reference, bounds=bounds or EvidenceBounds(1, 100))
    return request, store, geometry


def policy_for(request: dict, *, available: bool = True) -> DigestHostPolicy:
    return DigestHostPolicy((request,), mechanism=BytesDigestMechanism() if available else None)


def test_executes_and_replays_exact_coordinate_preserving_full_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, geometry = request_for()
    original = deepcopy(geometry.to_dict())
    calls = []
    real = BytesDigestMechanism.evaluate
    def observe(self, binding, evidence):
        calls.append(binding.digest())
        return real(self, binding, evidence)
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", observe)
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert len(calls) == 1
    assert record["evaluation"]["outcome"] == "PASS"
    updated = load_verification_geometry(record["updated_geometry"])
    assert updated.judgments[0].status is CoordinateStatus.VERIFIED
    assert updated.judgments[0].assumptions == geometry.judgments[0].assumptions
    assert updated.judgments[0].limitations == geometry.judgments[0].limitations
    assert updated.judgments[0].evidence_ids[:-1] == geometry.judgments[0].evidence_ids
    assert updated.judgments[1] == geometry.judgments[1]
    assert updated.horizons == geometry.horizons
    assert updated.mechanisms == geometry.mechanisms
    assert not updated.mechanisms[0].post_verified
    assert not record["updated_analysis"]["ordinary_closed"]
    assert not record["updated_analysis"]["self_closed"]
    old_holes = {item["hole_id"] for item in record["original_analysis"]["holes"] if item["source_id"] != "digest"}
    assert old_holes <= {item["hole_id"] for item in record["updated_analysis"]["holes"]}
    assert geometry.to_dict() == original
    assert replay_selected_validation(record, policy=policy_for(request)) == record
    assert len(calls) == 2


@pytest.mark.parametrize("authority", [None, {}, {"AUTHORIZED": True}, "AUTHORIZED", "sha256:" + "a" * 64, DigestHostPolicy()])
def test_serialized_or_absent_authority_never_executes(authority: object, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for()
    def forbidden(*args):
        pytest.fail("unauthorized mechanism invocation")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises(SelectedExecutionError, match="authorization denied"):
        execute_selected_validation(request, store, policy=authority)


def test_mutated_bytes_with_old_reference_are_not_passed() -> None:
    request, store, _ = request_for()
    store._payloads[EXPECTED] = b"changed"
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "UNKNOWN"
    assert record["updated_geometry"]["judgments"][0]["status"] == "INDETERMINATE"
    assert replay_selected_validation(record, policy=policy_for(request)) == record


def test_mutated_bytes_with_fresh_reference_falsify_fixed_expectation() -> None:
    request, store, _ = request_for(payload=b"changed")
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "FAIL"
    assert record["updated_geometry"]["judgments"][0]["status"] == "FALSIFIED"
    assert replay_selected_validation(record, policy=policy_for(request)) == record


@pytest.mark.parametrize("field,value", [("subject_id", "other"), ("predicate", "reactor.stable"), ("expected", 42), ("expected", True), ("expected", EXPECTED.upper()), ("mechanism_id", "custom"), ("mechanism_digest", 123), ("evidence_refs", EXPECTED), ("trust_roots", [1]), ("parameters", {"coordinate_id": "digest", "locus_id": "locus:bytes", "address": "elsewhere"})])
def test_proposition_substitutions_refused_before_execution(field: str, value: object, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for()
    policy = policy_for(request)
    request["proposition"][field] = value
    def forbidden(*args):
        pytest.fail("malformed request invoked mechanism")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises((SelectedExecutionError, ValueError, TypeError)):
        execute_selected_validation(request, store, policy=policy)


@pytest.mark.parametrize("change", ["coordinate", "candidate", "geometry", "registry", "plan", "expectation", "reference", "mapping"])
def test_stale_or_mutated_request_never_reuses_host_approval(change: str) -> None:
    request, store, _ = request_for()
    policy = policy_for(request)
    if change == "coordinate":
        request["coordinate_id"] = "meaning"
    elif change == "candidate":
        request["candidate_id"] = "forged"
    elif change == "geometry":
        request["geometry"]["subjects"][0]["version"] = "2"
    elif change == "registry":
        request["registry"]["registry_version"] = "2"
    elif change == "plan":
        request["plan"]["plan_id"] = "forged"
    elif change == "expectation":
        request["proposition"]["expected"] = "sha256:" + "0" * 64
    elif change == "reference":
        request["proposition"]["evidence_refs"] = [store.add(b"other")]
    else:
        request["proposition"]["parameters"]["coordinate_id"] = "meaning"
    with pytest.raises((SelectedExecutionError, ValueError)):
        execute_selected_validation(request, store, policy=policy)


@pytest.mark.parametrize("limit", [True, 1.5, "1", -1])
def test_strict_bound_types_rejected(limit: object) -> None:
    request, store, _ = request_for()
    request["proposition"]["bounds"]["max_evidence_items"] = limit
    with pytest.raises(SelectedExecutionError):
        execute_selected_validation(request, store)


@pytest.mark.parametrize("bounds", [EvidenceBounds(0, 100), EvidenceBounds(1, 4)])
def test_bounds_prevent_mechanism_execution(bounds: EvidenceBounds, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for(bounds=bounds)
    def forbidden(*args):
        pytest.fail("out-of-bounds execution")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "UNKNOWN"
    assert record["updated_geometry"]["judgments"][0]["status"] == "INDETERMINATE"
    assert replay_selected_validation(record, policy=policy_for(request)) == record


def test_missing_evidence_or_mechanism_remains_unknown() -> None:
    request, store, _ = request_for()
    for evidence, policy in [(EvidenceStore(), policy_for(request)), (store, policy_for(request, available=False))]:
        record = execute_selected_validation(request, evidence, policy=policy)
        assert record["evaluation"]["outcome"] == "UNKNOWN"
        assert replay_selected_validation(record, policy=policy) == record


def test_substituted_mechanism_instances_rejected() -> None:
    request, _, _ = request_for()
    class Substitute(BytesDigestMechanism):
        pass
    with pytest.raises(SelectedExecutionError):
        DigestHostPolicy((request,), mechanism=Substitute())
    changed = BytesDigestMechanism()
    changed.mechanism_digest = "sha256:" + "0" * 64
    with pytest.raises(SelectedExecutionError):
        DigestHostPolicy((request,), mechanism=changed)


@pytest.mark.parametrize("part", ["evaluation", "updated_geometry", "updated_analysis", "original_analysis", "evidence_id"])
def test_replay_refuses_tampered_derived_results(part: str) -> None:
    request, store, _ = request_for()
    record = execute_selected_validation(request, store, policy=policy_for(request))
    if part == "evaluation":
        record[part]["outcome"] = "FAIL"
    elif part == "updated_geometry":
        record[part]["judgments"][1]["status"] = "VERIFIED"
    elif part == "evidence_id":
        record[part] = "forged"
    else:
        record[part]["self_closed"] = True
    with pytest.raises(SelectedExecutionError, match="reproduce"):
        replay_selected_validation(record, policy=policy_for(request))


def test_replay_needs_separate_host_authority_but_policy_is_reusable() -> None:
    request, store, _ = request_for()
    policy = policy_for(request)
    record = execute_selected_validation(request, store, policy=policy)
    with pytest.raises(SelectedExecutionError, match="authorization denied"):
        replay_selected_validation(record)
    assert replay_selected_validation(record, policy=policy) == record


@pytest.mark.parametrize("invalid_at_entry", [True, False])
def test_replay_binds_entry_snapshot_despite_caller_mutation_during_evaluation(
    invalid_at_entry: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typing import Sequence
    from verifier.core.evidence import BoundProposition, MechanismDecision

    request, store, _ = request_for()
    policy = policy_for(request)
    correct = execute_selected_validation(request, store, policy=policy)
    supplied = deepcopy(correct)
    if invalid_at_entry:
        supplied["updated_analysis"]["self_closed"] = True
    real = BytesDigestMechanism.evaluate
    calls = []

    def mutate_caller_record(
        mechanism: BytesDigestMechanism, binding: BoundProposition, evidence: Sequence[bytes],
    ) -> MechanismDecision:
        calls.append(True)
        supplied["updated_analysis"]["self_closed"] = not invalid_at_entry
        return real(mechanism, binding, evidence)

    monkeypatch.setattr(BytesDigestMechanism, "evaluate", mutate_caller_record)
    if invalid_at_entry:
        with pytest.raises(SelectedExecutionError, match="reproduce"):
            replay_selected_validation(supplied, policy=policy)
        assert supplied == correct
    else:
        assert replay_selected_validation(supplied, policy=policy) == correct
        assert supplied != correct
    assert calls == [True]


@pytest.mark.parametrize("status", [CoordinateStatus.UNSUPPORTED, CoordinateStatus.FALSIFIED, CoordinateStatus.STALE, CoordinateStatus.PRE_VERIFIED])
def test_non_indeterminate_target_is_not_silently_replaced(status: CoordinateStatus) -> None:
    geometry, registry = specimen()
    geometry.judgments[0] = replace(geometry.judgments[0], status=status)
    with pytest.raises(SelectedExecutionError):
        prepare_digest_validation(geometry, registry, plan_validation(analyze_verification_surface(geometry), registry), coordinate_id="digest", expected_digest=EXPECTED, evidence_ref=EXPECTED, bounds=EvidenceBounds(1, 100))


@pytest.mark.parametrize("field,value", [("facet_id", "reactor.stable"), ("label", "Reactor stable"), ("description", "All computations are correct")])
def test_unrelated_facets_rejected_even_with_fresh_plan(field: str, value: str) -> None:
    geometry, registry = specimen()
    geometry.facets[0] = replace(geometry.facets[0], **{field: value})
    if field == "facet_id":
        geometry.coordinates[0] = replace(geometry.coordinates[0], facet_id=value)
    with pytest.raises(SelectedExecutionError, match="arbitrary facet"):
        prepare_digest_validation(geometry, registry, plan_validation(analyze_verification_surface(geometry), registry), coordinate_id="digest", expected_digest=EXPECTED, evidence_ref=EXPECTED, bounds=EvidenceBounds(1, 100))


def test_unknown_mechanism_digest_does_not_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for()
    request["proposition"]["mechanism_digest"] = "sha256:" + "0" * 64
    def forbidden(*args):
        pytest.fail("substituted mechanism coordinate executed")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "UNKNOWN"
    assert record["updated_geometry"]["judgments"][0]["status"] == "INDETERMINATE"


def test_freshly_recomputed_plan_still_requires_new_host_approval() -> None:
    request, store, _ = request_for()
    old_policy = policy_for(request)
    geometry = load_verification_geometry(request["geometry"])
    registry = InteroperabilityComponentRegistry.from_dict(request["registry"])
    geometry.subjects[0] = replace(geometry.subjects[0], version="2")
    changed = prepare_digest_validation(geometry, registry, plan_validation(analyze_verification_surface(geometry), registry), coordinate_id="digest", expected_digest=EXPECTED, evidence_ref=EXPECTED, bounds=EvidenceBounds(1, 100))
    with pytest.raises(SelectedExecutionError, match="authorization denied"):
        execute_selected_validation(changed, store, policy=old_policy)


def test_malformed_mapping_cannot_be_approved_even_with_recomputed_plan() -> None:
    request, _, _ = request_for()
    request["proposition"]["parameters"]["address"] = "another-file.txt"
    with pytest.raises(SelectedExecutionError, match="exact subject"):
        policy_for(request)


def test_output_mutation_does_not_change_input_or_host_approval() -> None:
    request, store, geometry = request_for()
    policy = policy_for(request)
    original_request = deepcopy(request)
    original_geometry = deepcopy(geometry.to_dict())
    original_approvals = policy.approved_requests
    record = execute_selected_validation(request, store, policy=policy)
    record["request"]["geometry"]["horizons"].clear()
    record["updated_geometry"]["judgments"].clear()
    assert request == original_request
    assert geometry.to_dict() == original_geometry
    assert policy.approved_requests == original_approvals
    assert execute_selected_validation(request, store, policy=policy)["evaluation"]["outcome"] == "PASS"


def test_evaluation_and_retention_use_same_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for()
    real = BytesDigestMechanism.evaluate
    def mutate_caller_store(self, binding, evidence):
        store._payloads.clear()
        return real(self, binding, evidence)
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", mutate_caller_store)
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "PASS"
    assert record["evidence"][EXPECTED]
    assert replay_selected_validation(record, policy=policy_for(request)) == record


def test_planning_and_readiness_remain_nonexecuting(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.interoperability.execution_readiness import (
        AuthorizationDecision, PostExecutionReassessmentContract,
        SuppliedAuthorizationDecision, assess_execution_readiness,
    )

    geometry, registry = specimen()
    def forbidden(*args):
        pytest.fail("planner or readiness invoked mechanism")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    analysis = analyze_verification_surface(geometry)
    plan = plan_validation(analysis, registry)
    assert plan.plan_only and not plan.execution_performed
    # Missing execution declarations remain a readiness failure, never a run.
    result = assess_execution_readiness(analysis, plan, registry, (),
        SuppliedAuthorizationDecision(AuthorizationDecision.DENIED, ()),
        PostExecutionReassessmentContract(geometry.geometry_id, geometry.canonical_digest(), ()))
    assert not result.execution_performed


def test_mechanism_exception_remains_unknown_and_replays(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for()
    def crash(*args):
        raise RuntimeError("bounded simulated mechanism failure")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", crash)
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "UNKNOWN"
    assert record["updated_geometry"]["judgments"][0]["status"] == "INDETERMINATE"
    assert replay_selected_validation(record, policy=policy_for(request)) == record


def test_serialized_pass_cannot_replace_native_failure() -> None:
    request, store, _ = request_for(payload=b"changed")
    record = execute_selected_validation(request, store, policy=policy_for(request))
    assert record["evaluation"]["outcome"] == "FAIL"
    record["evaluation"]["outcome"] = "PASS"
    record["updated_geometry"]["judgments"][0]["status"] = "VERIFIED"
    with pytest.raises(SelectedExecutionError, match="reproduce"):
        replay_selected_validation(record, policy=policy_for(request))


def test_direct_module_does_not_expand_either_facade() -> None:
    import verifier
    import verifier.interoperability as facade

    for name in ("prepare_digest_validation", "DigestHostPolicy", "execute_selected_validation", "replay_selected_validation"):
        assert name not in verifier.__all__
        assert not hasattr(verifier, name)
        assert name not in facade.__all__
        assert not hasattr(facade, name)
