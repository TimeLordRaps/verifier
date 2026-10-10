"""Bounded digest validation loops for Verifier Standard (VSTD)."""

from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
import base64

import pytest

from verifier.core.evidence import BytesDigestMechanism, EvidenceStore
from verifier.core.geometry import Coordinate
from verifier.interoperability.validation_loop import (
    DigestLoopBounds, DigestLoopError, DigestLoopPolicy, DigestValidationTarget,
    execute_digest_validation_loop, prepare_digest_validation_loop,
    replay_digest_validation_loop,
)
from test_selected_execution import EXPECTED, PAYLOAD, specimen


def loop_specimen():
    geometry, registry = specimen()
    geometry.loci.append(replace(geometry.loci[0], locus_id="locus:second", address="second.txt"))
    geometry.coordinates.append(Coordinate("second-digest", "locus:second", "bytes.sha256"))
    geometry.judgments.append(replace(geometry.judgments[0], coordinate_id="second-digest"))
    geometry.surface = replace(geometry.surface, coordinate_ids=(*geometry.surface.coordinate_ids, "second-digest"))
    targets = (DigestValidationTarget("digest", EXPECTED, EXPECTED, 10), DigestValidationTarget("second-digest", EXPECTED, EXPECTED, 10))
    request = prepare_digest_validation_loop(geometry, registry, targets, bounds=DigestLoopBounds(2, 20))
    store = EvidenceStore()
    store.add(PAYLOAD)
    return request, store, geometry


def test_two_steps_replan_full_geometry_and_replay_without_claiming_closure() -> None:
    request, store, original = loop_specimen()
    policy = DigestLoopPolicy((request,), mechanism=BytesDigestMechanism())
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert record["stop_reason"] == "TARGETS_EXHAUSTED"
    assert record["attempted_steps"] == 2
    assert record["reserved_evidence_bytes"] == 20
    assert record["unattempted_targets"] == []
    first, second = [item["execution"] for item in record["steps"]]
    assert second["request"]["geometry"] == first["updated_geometry"]
    assert second["request"]["plan"]["plan_id"] != first["request"]["plan"]["plan_id"]
    assert record["final_plan"]["geometry_digest"] == record["final_analysis"]["geometry_digest"]
    assert not record["final_analysis"]["ordinary_closed"]
    assert not record["final_analysis"]["self_closed"]
    assert record["final_geometry"]["horizons"] == original.to_dict()["horizons"]
    assert replay_digest_validation_loop(record, policy=policy) == record


def approved(request: dict) -> DigestLoopPolicy:
    return DigestLoopPolicy((request,), mechanism=BytesDigestMechanism())


@pytest.mark.parametrize("outcome", ["FAILED", "UNKNOWN"])
def test_first_nonpass_stops_and_replans_without_erasing_later_targets(outcome: str) -> None:
    request, store, _ = loop_specimen()
    if outcome == "FAILED":
        request["targets"][0]["expected_digest"] = "sha256:" + "0" * 64
    else:
        store = EvidenceStore()
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert record["stop_reason"] == outcome
    assert record["attempted_steps"] == 1
    assert record["reserved_evidence_bytes"] == 10
    assert record["unattempted_targets"] == request["targets"][1:]
    assert record["final_geometry"]["judgments"][2]["status"] == "INDETERMINATE"
    assert record["final_plan"]["geometry_digest"] == record["final_analysis"]["geometry_digest"]
    assert record["final_plan"]["plan_id"] != record["steps"][0]["execution"]["request"]["plan"]["plan_id"]
    assert replay_digest_validation_loop(record, policy=policy) == record


@pytest.mark.parametrize("max_steps,reservation,reason", [(0, 0, "STEP_BUDGET_EXHAUSTED"), (0, 20, "STEP_BUDGET_EXHAUSTED"), (2, 0, "EVIDENCE_BUDGET_EXHAUSTED")])
def test_zero_budget_stops_before_any_evidence_lookup(max_steps: int, reservation: int, reason: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, original = loop_specimen()
    request["bounds"] = {"max_steps": max_steps, "max_reserved_evidence_bytes": reservation}
    policy = approved(request)
    def forbidden(*args, **kwargs):
        pytest.fail("budget stop performed evidence lookup or mechanism execution")
    monkeypatch.setattr(EvidenceStore, "resolve", forbidden)
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert record["stop_reason"] == reason
    assert record["attempted_steps"] == record["reserved_evidence_bytes"] == 0
    assert record["final_geometry"] == original.to_dict()
    assert record["unattempted_targets"] == request["targets"]
    assert replay_digest_validation_loop(record, policy=policy) == record


def test_reservations_charge_declared_caps_not_observed_lengths() -> None:
    request, store, _ = loop_specimen()
    request["bounds"]["max_reserved_evidence_bytes"] = 15
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert record["stop_reason"] == "EVIDENCE_BUDGET_EXHAUSTED"
    assert record["attempted_steps"] == 1
    assert record["reserved_evidence_bytes"] == 10
    assert record["steps"][0]["execution"]["evaluation"]["observed_evidence_bytes"] == 5
    assert replay_digest_validation_loop(record, policy=policy) == record


def test_step_budget_applies_before_second_reservation() -> None:
    request, store, _ = loop_specimen()
    request["bounds"] = {"max_steps": 1, "max_reserved_evidence_bytes": 10}
    record = execute_digest_validation_loop(request, store, policy=approved(request))
    assert record["stop_reason"] == "STEP_BUDGET_EXHAUSTED"
    assert record["reserved_evidence_bytes"] == 10


@pytest.mark.parametrize("unavailable", ["missing", "corrupt", "oversized"])
def test_unadmitted_input_is_replayable_unknown_without_retaining_bytes(unavailable: str) -> None:
    request, store, _ = loop_specimen()
    if unavailable == "missing":
        store = EvidenceStore()
    elif unavailable == "corrupt":
        store._payloads[EXPECTED] = b"corrupt"
    else:
        request["targets"][0]["max_evidence_bytes"] = 4
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    first = record["steps"][0]["execution"]
    assert first["evidence"] == {}
    assert first["evaluation"]["outcome"] == "UNKNOWN"
    assert first["evaluation"]["observed_evidence_bytes"] == 0
    assert "unavailable" in first["evaluation"]["details"]
    assert record["stop_reason"] == "UNKNOWN"
    assert replay_digest_validation_loop(record, policy=policy) == record


def test_empty_bytes_are_admitted_under_zero_byte_cap() -> None:
    request, _, _ = loop_specimen()
    empty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    for target in request["targets"]:
        target.update(expected_digest=empty, evidence_ref=empty, max_evidence_bytes=0)
    request["bounds"]["max_reserved_evidence_bytes"] = 0
    store = EvidenceStore()
    store.add(b"")
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert record["stop_reason"] == "TARGETS_EXHAUSTED"
    assert record["attempted_steps"] == 2
    assert record["reserved_evidence_bytes"] == 0
    assert all(item["execution"]["evidence"] == {empty: ""} for item in record["steps"])
    assert replay_digest_validation_loop(record, policy=policy) == record


def test_same_reference_preserves_distinct_per_step_admission_snapshots(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = loop_specimen()
    policy = approved(request)
    real = BytesDigestMechanism.evaluate
    def remove_caller_evidence_after_first_step(self, binding, evidence):
        store._payloads.clear()
        return real(self, binding, evidence)
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", remove_caller_evidence_after_first_step)
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert record["attempted_steps"] == 2
    assert record["reserved_evidence_bytes"] == 20
    assert [item["execution"]["evaluation"]["outcome"] for item in record["steps"]] == ["PASS", "UNKNOWN"]
    assert record["steps"][1]["execution"]["evidence"] == {}
    assert replay_digest_validation_loop(record, policy=policy) == record


@pytest.mark.parametrize("value", [True, "1", -1, 1.5])
def test_budget_and_target_integer_coercions_are_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        DigestLoopBounds(value, 20)
    with pytest.raises(ValueError):
        DigestLoopBounds(2, value)
    with pytest.raises(ValueError):
        DigestValidationTarget("digest", EXPECTED, EXPECTED, value)


@pytest.mark.parametrize("change", ["empty", "duplicate", "many", "bad_coordinate", "absent_coordinate", "bad_digest", "bad_bound"])
def test_invalid_target_contracts_are_rejected(change: str) -> None:
    request, _, _ = loop_specimen()
    if change == "empty":
        request["targets"] = []
    elif change == "duplicate":
        request["targets"][1] = deepcopy(request["targets"][0])
    elif change == "many":
        request["targets"] = request["targets"] * 129
    elif change == "bad_coordinate":
        request["targets"][0]["coordinate_id"] = "meaning"
    elif change == "absent_coordinate":
        request["targets"][0]["coordinate_id"] = "absent"
    elif change == "bad_digest":
        request["targets"][0]["expected_digest"] = "0" * 64
    else:
        request["bounds"]["max_steps"] = 257
    with pytest.raises(ValueError):
        approved(request)


@pytest.mark.parametrize("authority", [None, "AUTHORIZED", {"AUTHORIZED": True}, DigestLoopPolicy()])
def test_missing_or_forged_loop_authority_cannot_lookup_evidence(authority: object, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = loop_specimen()
    def forbidden(*args, **kwargs):
        pytest.fail("denied loop performed lookup or mechanism execution")
    monkeypatch.setattr(EvidenceStore, "resolve", forbidden)
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises(DigestLoopError, match="authorization denied"):
        execute_digest_validation_loop(request, store, policy=authority)


@pytest.mark.parametrize("change", ["order", "expectation", "budget", "mechanism", "geometry"])
def test_postapproval_mutations_do_not_reuse_loop_authority(change: str) -> None:
    request, store, _ = loop_specimen()
    policy = approved(request)
    if change == "order":
        request["targets"].reverse()
    elif change == "expectation":
        request["targets"][0]["expected_digest"] = "sha256:" + "0" * 64
    elif change == "budget":
        request["bounds"]["max_steps"] = 1
    elif change == "mechanism":
        request["mechanism_digest"] = "sha256:" + "0" * 64
    else:
        request["geometry"]["subjects"][0]["version"] = "2"
    with pytest.raises(ValueError):
        execute_digest_validation_loop(request, store, policy=policy)


def test_mechanism_change_after_loop_approval_rejects_before_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = loop_specimen()
    policy = approved(request)
    monkeypatch.setattr(BytesDigestMechanism, "mechanism_digest", "sha256:" + "0" * 64)
    def forbidden(*args, **kwargs):
        pytest.fail("changed mechanism coordinate reached evidence")
    monkeypatch.setattr(EvidenceStore, "resolve", forbidden)
    with pytest.raises(DigestLoopError, match="mechanism coordinate"):
        execute_digest_validation_loop(request, store, policy=policy)


@pytest.mark.parametrize("part", ["reorder", "omit", "extra", "child_request", "outcome", "reason", "reservation", "attempts", "unattempted", "geometry", "analysis", "plan"])
def test_replay_rejects_tampered_chain_and_summaries(part: str) -> None:
    request, store, _ = loop_specimen()
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    if part == "reorder":
        record["steps"].reverse()
    elif part == "omit":
        record["steps"].pop()
    elif part == "extra":
        record["steps"].append(deepcopy(record["steps"][0]))
    elif part == "child_request":
        record["steps"][0]["execution"]["request"]["coordinate_id"] = "meaning"
    elif part == "outcome":
        record["steps"][0]["execution"]["evaluation"]["outcome"] = "FAIL"
    elif part == "reason":
        record["stop_reason"] = "FAILED"
    elif part == "reservation":
        record["reserved_evidence_bytes"] = 10
    elif part == "attempts":
        record["attempted_steps"] = True
    elif part == "unattempted":
        record["unattempted_targets"] = request["targets"]
    elif part == "geometry":
        record["final_geometry"]["horizons"] = []
    elif part == "analysis":
        record["final_analysis"]["self_closed"] = True
    else:
        record["final_plan"]["candidates"] = []
    with pytest.raises(ValueError):
        replay_digest_validation_loop(record, policy=policy)


@pytest.mark.parametrize("tamper", ["extra_ref", "wrong_ref", "oversized", "substituted", "padding"])
def test_replay_rejects_bad_retained_evidence_before_mechanism_invocation(tamper: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = loop_specimen()
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    evidence = record["steps"][0]["execution"]["evidence"]
    if tamper == "extra_ref":
        evidence["sha256:" + "0" * 64] = ""
    elif tamper == "wrong_ref":
        evidence["sha256:" + "0" * 64] = evidence.pop(EXPECTED)
    elif tamper == "oversized":
        evidence[EXPECTED] = base64.b64encode(b"x" * 11).decode("ascii")
    elif tamper == "substituted":
        evidence[EXPECTED] = base64.b64encode(b"other").decode("ascii")
    else:
        evidence[EXPECTED] = "aGVsbG9="
    def forbidden(*args, **kwargs):
        pytest.fail("bad retained evidence reached mechanism")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises(ValueError):
        replay_digest_validation_loop(record, policy=policy)


def test_optional_package_is_carried_and_revalidated_in_every_step() -> None:
    from verifier.core.geometry_io import load_verification_geometry
    from test_selected_package_execution import package_specimen

    request, store, _ = loop_specimen()
    package = package_specimen()
    request = prepare_digest_validation_loop(load_verification_geometry(request["geometry"]), package.registry,
        tuple(DigestValidationTarget(**item) for item in request["targets"]),
        bounds=DigestLoopBounds(2, 20), package=package)
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    assert all(item["execution"]["request"]["package"] == package.to_dict() for item in record["steps"])
    assert record["final_plan"]["package_digest"] == package.canonical_digest()
    assert replay_digest_validation_loop(record, policy=policy) == record
    request["package"]["license"] = "changed declaration"
    with pytest.raises(DigestLoopError, match="authorization denied"):
        execute_digest_validation_loop(request, store, policy=policy)


def test_replay_requires_external_loop_approval_and_does_not_change_original() -> None:
    request, store, geometry = loop_specimen()
    original = deepcopy(geometry.to_dict())
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    with pytest.raises(DigestLoopError, match="authorization denied"):
        replay_digest_validation_loop(record)
    assert replay_digest_validation_loop(record, policy=policy) == record
    record["request"]["geometry"]["horizons"].clear()
    record["final_geometry"]["judgments"].clear()
    assert geometry.to_dict() == original
    assert request["geometry"] == original


@pytest.mark.parametrize("initially_invalid", [False, True])
def test_replay_compares_entry_snapshot_despite_caller_record_mutation(initially_invalid: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = loop_specimen()
    policy = approved(request)
    record = execute_digest_validation_loop(request, store, policy=policy)
    if initially_invalid:
        record["stop_reason"] = "FAILED"
    entry = deepcopy(record)
    real = BytesDigestMechanism.evaluate
    def mutate_callers_record(self, binding, evidence):
        record["stop_reason"] = "TARGETS_EXHAUSTED" if initially_invalid else "FAILED"
        return real(self, binding, evidence)
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", mutate_callers_record)
    if initially_invalid:
        with pytest.raises(DigestLoopError, match="reproduce"):
            replay_digest_validation_loop(record, policy=policy)
        assert record["stop_reason"] == "TARGETS_EXHAUSTED"
        return
    reproduced = replay_digest_validation_loop(record, policy=policy)
    assert reproduced == entry
    assert record["stop_reason"] == "FAILED"
    assert reproduced["stop_reason"] == "TARGETS_EXHAUSTED"
