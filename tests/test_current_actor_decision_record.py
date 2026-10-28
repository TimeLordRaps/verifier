"""Independent finite ACTOR-3.3 decision-record retention counterexamples.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions and counts are dimensionless. The oracle
below is plain set inclusion over decision tuples, computed independently of
the mechanism under test.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import actor_decision_record as record_module


ROW = ("Past decisions remain the actor's own after revocation, rotation or "
       "dissolution. Ending an actor's capacity to decide never ends its record "
       "of having decided.")
PREFIXED_HUMAN = "actor" + ":" + "mallory"
_ABSENT = object()


def content(number: int) -> str:
    return "sha256:" + format(number, "064x")


def collection() -> list[NamespaceObject]:
    humans = [NamespaceObject.create(name, "HUMAN", {"fixture": name})
              for name in ("alice", "bob")]

    def actor(object_id: str, human: str) -> NamespaceObject:
        return NamespaceObject.create(object_id, "ACTOR", {"fixture": object_id},
                                      {"representation": [human], "root_human": [human]})

    return [*humans, actor("p-alice", "alice"), actor("p-bob", "bob"),
            NamespaceObject.create(PREFIXED_HUMAN, "HUMAN", {"fixture": "label-only"})]


def earlier() -> dict:
    return {"head_position": 10, "decisions": [
        {"decision_id": "x1", "position": 2, "actor": "p-alice", "content_digest": content(1)},
        {"decision_id": "x2", "position": 5, "actor": "p-bob", "content_digest": content(2)},
        {"decision_id": "x3", "position": 8, "actor": "p-alice", "content_digest": content(3)},
    ]}


def window() -> list[dict]:
    return [
        {"position": 11, "event": "delegation", "delegation_id": "d1", "delegator": "p-alice",
         "delegate": "p-bob", "subset": ["approve"], "interval": [11, 30]},
        {"position": 12, "event": "revocation", "delegation_id": "d1"},
        {"position": 13, "event": "rotation", "actor": "p-alice",
         "prior_key": content(41), "key": content(42)},
        {"position": 15, "event": "dissolution", "actor": "p-alice"},
    ]


def later() -> dict:
    return {"head_position": 20, "decisions": [
        *earlier()["decisions"],
        {"decision_id": "x4", "position": 14, "actor": "p-bob", "content_digest": content(4)},
    ]}


def oracle(before: dict, after: dict) -> str:
    """Every earlier decision tuple is also a later decision tuple."""
    fields = ("decision_id", "position", "actor", "content_digest")
    old = {tuple(row[f] for f in fields) for row in before["decisions"]}
    new = {tuple(row[f] for f in fields) for row in after["decisions"]}
    return "PASS" if old <= new else "FAIL"


def case(*, earlier_value: dict | None = None, events_value: list | None = None,
         later_value: dict | None = None, inputs: object = _ABSENT,
         subject: str = "p-alice", **limits: int) -> tuple[dict, dict, bytes]:
    objects = collection()
    selected_earlier = earlier() if earlier_value is None else earlier_value
    selected_events = window() if events_value is None else events_value
    selected_later = later() if later_value is None else later_value
    retained = ({"earlier": selected_earlier, "events": selected_events,
                 "later": selected_later} if inputs is _ABSENT else inputs)
    value = {"schema_version": record_module.EVIDENCE_VERSION,
             "objects": [item.to_dict() for item in objects], "inputs": retained}
    if inputs == "omit":
        del value["inputs"]
    evidence = canonical_bytes(value)
    policy = record_module.actor_decision_record_policy(
        trust_roots=["externally-selected-decision-records"])
    record = next(item for item in objects if item.object_id == subject)
    request = record_module.actor_decision_record_request(
        subject_id=subject, object_digest=record.digest,
        collection_digest=composition_digest(objects),
        earlier_digest=digest(selected_earlier), events_digest=digest(selected_events),
        later_digest=digest(selected_later), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits or None)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None) -> dict:
    cert = record_module.build_actor_decision_record_certificate(request, evidence, policy=policy)
    result = record_module.recheck_actor_decision_record_certificate(
        cert, expected_request=request, policy=policy)
    assert result["coordinate"] == "ACTOR-3.3"
    assert result["object_kind"] == "ACTOR"
    for field in ("object_profile_conformance", "whole_actor_statics_tier", "personhood",
                  "real_world_completeness", "record_authenticity", "authority", "consent"):
        assert result[field] == "NOT_ESTABLISHED", field
    assert result["decision_record_retention"] == (
        "PASS" if result["status"] == "PASS" else "NOT_ESTABLISHED")
    return result


def test_past_decisions_remain_their_actors_own_after_ending_events() -> None:
    assert oracle(earlier(), later()) == "PASS"
    request, policy, evidence = case()
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    observed = result["evaluation"]["observations"]["retention"]
    assert observed["earlier_decisions"] == 3
    assert observed["subject_earlier_decisions"] == 2
    assert observed["event_counts"] == {
        "delegation": 1, "revocation": 1, "rotation": 1, "dissolution": 1}


def test_pass_rechecks_from_decoded_certificate_bytes() -> None:
    request, policy, evidence = case()
    cert = record_module.build_actor_decision_record_certificate(request, evidence, policy=policy)
    decoded = json.loads(cert.decode("utf-8"))
    assert canonical_bytes(decoded) == cert
    again = record_module.recheck_actor_decision_record_certificate(
        canonical_bytes(decoded), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert again["status"] == "PASS"


def _dropped_after_revocation(after: dict) -> None:
    del after["decisions"][0]


def _moved_by_later_delegation(after: dict) -> None:
    after["decisions"][0]["actor"] = "p-bob"


def _redated(after: dict) -> None:
    after["decisions"][2]["position"] = 9


def _rewritten_after_rotation(after: dict) -> None:
    after["decisions"][2]["content_digest"] = content(99)


def _other_actor_decision_dropped(after: dict) -> None:
    del after["decisions"][1]


@pytest.mark.parametrize(("change", "reason"), [
    (_dropped_after_revocation, "absent from the later record"),
    (_moved_by_later_delegation, "accountability moved"),
    (_redated, "re-dated"),
    (_rewritten_after_rotation, "content commitment changed"),
    (_other_actor_decision_dropped, "absent from the later record"),
], ids=lambda value: getattr(value, "__name__", "reason"))
def test_semantically_distinct_mutants_refute(change, reason: str) -> None:
    after = later()
    change(after)
    assert oracle(earlier(), after) == "FAIL"
    request, policy, evidence = case(later_value=after)
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["details"]


def test_kind_comes_from_typed_record_not_label_prefix() -> None:
    kinds = {item.object_id: item.kind.value for item in collection()}
    assert kinds[PREFIXED_HUMAN] == "HUMAN"
    before = earlier()
    before["decisions"][1]["actor"] = PREFIXED_HUMAN
    after = later()
    after["decisions"][1]["actor"] = PREFIXED_HUMAN
    assert oracle(before, after) == "PASS"  # the tuples alone would pass
    request, policy, evidence = case(earlier_value=before, later_value=after)
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "typed ACTOR record" in result["evaluation"]["details"]
    events = window()
    events[3]["actor"] = PREFIXED_HUMAN
    request, policy, evidence = case(events_value=events)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_events_must_lie_between_the_records_in_order() -> None:
    events = window()
    events[0]["position"] = 10
    request, policy, evidence = case(events_value=events)
    assert replay(request, policy, evidence)["status"] == "FAIL"
    events = window()
    events[1]["position"], events[2]["position"] = 13, 12
    request, policy, evidence = case(events_value=events)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_absent_row_premise_or_subject_decision_remains_unknown() -> None:
    # Only a delegation between the records: no revocation, rotation or dissolution.
    request, policy, evidence = case(events_value=window()[:1])
    result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert "revocation, rotation or dissolution" in result["evaluation"]["details"]
    # The selected actor took no earlier decision.
    before = {"head_position": 10, "decisions": [earlier()["decisions"][1]]}
    after = {"head_position": 20, "decisions": [earlier()["decisions"][1]]}
    request, policy, evidence = case(earlier_value=before, later_value=after)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"
    # An event kind this row does not name is outside its scope.
    events = window()
    events.append({"position": 16, "event": "membership", "actor": "p-bob",
                   "collective": "board", "change": "enter"})
    request, policy, evidence = case(events_value=events)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("inputs", ["omit", None, {"earlier": earlier(), "events": window()}],
                         ids=["no-inputs-field", "null-inputs", "later-absent"])
def test_missing_retained_inputs_remain_unknown(inputs: object) -> None:
    request, policy, evidence = case(inputs=inputs)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_absent_evidence_and_exhausted_budget_remain_unknown() -> None:
    request, policy, evidence = case()
    assert replay(request, policy, None)["status"] == "UNKNOWN"
    request, policy, evidence = case(max_operations=5)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"
    request, policy, evidence = case(max_decisions=2)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("offset", [0, 57, -3, -90])
def test_one_flipped_certificate_bit_is_rejected(offset: int) -> None:
    request, policy, evidence = case()
    cert = bytearray(record_module.build_actor_decision_record_certificate(
        request, evidence, policy=policy))
    cert[offset] ^= 0x01
    with pytest.raises(record_module.ActorDecisionRecordError):
        record_module.recheck_actor_decision_record_certificate(
            bytes(cert), expected_request=request, policy=policy)


def test_substituted_subject_request_and_policy_are_refused() -> None:
    request, policy, evidence = case()
    cert = record_module.build_actor_decision_record_certificate(request, evidence, policy=policy)
    other_subject, _, _ = case(subject="p-bob")
    for wrong in (other_subject, {**request, "later_digest": digest({"other": 1})}):
        with pytest.raises(record_module.ActorDecisionRecordError):
            record_module.recheck_actor_decision_record_certificate(
                cert, expected_request=wrong, policy=policy)
    other_policy = record_module.actor_decision_record_policy(trust_roots=["another-selection"])
    with pytest.raises(record_module.ActorDecisionRecordError):
        record_module.recheck_actor_decision_record_certificate(
            cert, expected_request=request, policy=other_policy)
    bob = next(item for item in collection() if item.object_id == "p-bob")
    mismatched = record_module.actor_decision_record_request(
        subject_id="p-alice", object_digest=bob.digest,
        collection_digest=request["collection_digest"],
        earlier_digest=request["earlier_digest"], events_digest=request["events_digest"],
        later_digest=request["later_digest"], evidence_ref=request["evidence_ref"],
        policy=policy)
    assert replay(mismatched, policy, evidence)["status"] == "FAIL"


def test_public_route_and_inventory_register_only_decision_record_retention() -> None:
    from verifier.domains.contracts.current_object_routes import (
        current_object_route_catalog, replay_current_object_certificate)
    from verifier.domains.inventory import get_slot

    request, policy, evidence = case()
    cert = record_module.build_actor_decision_record_certificate(request, evidence, policy=policy)
    report = replay_current_object_certificate(
        cert, semantic_version=record_module.SEMANTIC_VERSION, objective="ACTOR-3.3",
        represented_kind="ACTOR", expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    route = next(row for row in current_object_route_catalog() if row["objective"] == "ACTOR-3.3")
    assert route["represented_kind_rule"] == "ACTOR"
    slot = get_slot("ACTOR", 3).to_dict()
    assert slot["status"] == "REPLAYABLE"
    assert slot["coordinate"] == "ACTOR-3.3"
    assert slot["mechanized_route"]["checking_mechanism"] == (
        "verifier.domains.contracts.actor_decision_record."
        "recheck_actor_decision_record_certificate")
    assert {item["coordinate"] for item in slot["registered_objectives"]} == {"ACTOR-3.3"}


def test_specification_quotes_the_obligation_row_verbatim() -> None:
    root = Path(record_module.__file__).parents[2] / "standard"
    obligations = (root / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    row = next(line for line in obligations.splitlines() if line.startswith("| ACTOR-3.3 |"))
    assert "| " + ROW + " |" in row
    spec = " ".join((root / "CURRENT_ACTOR_DECISION_RECORD.md").read_text(encoding="utf-8").split())
    assert ROW in spec
    assert record_module.registration()["obligation_row"] == ROW


@pytest.mark.parametrize("relative", [
    "domains/contracts/actor_decision_record.py", "standard/CURRENT_ACTOR_DECISION_RECORD.md",
])
def test_decision_record_dependency_change_invalidates_polish_digest(
    relative: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged ACTOR decision record dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert polish.mechanism_digest() != before
