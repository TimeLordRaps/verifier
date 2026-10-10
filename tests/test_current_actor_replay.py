"""Independent finite ACTOR-2.7 accountability replay counterexamples.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions, event counts and operation counts are
dimensionless. The expected current state below is derived by hand from the
declared events, independently of the mechanism under test.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import actor_replay


ROW = ("Replaying the declared events from the first reproduces the current "
       "delegation, key and membership state.")
# Labels whose prefix disagrees with the typed record kind, built at runtime.
PREFIXED_HUMAN = "actor" + ":" + "mallory"
PREFIXED_ACTOR = "human" + ":" + "dana"
_ABSENT = object()


def key(number: int) -> str:
    return "sha256:" + format(number, "064x")


def collection() -> list[NamespaceObject]:
    humans = [NamespaceObject.create(name, "HUMAN", {"fixture": name})
              for name in ("alice", "bob", "carol", "dana")]

    def actor(object_id: str, human: str) -> NamespaceObject:
        return NamespaceObject.create(object_id, "ACTOR", {"fixture": object_id},
                                      {"representation": [human], "root_human": [human]})

    return [
        *humans,
        actor("p-alice", "alice"), actor("p-bob", "bob"), actor("p-carol", "carol"),
        actor(PREFIXED_ACTOR, "dana"), actor("p-alice-2", "alice"),
        NamespaceObject.create("treasurer", "ROLE", {"fixture": "treasurer"}),
        NamespaceObject.create("board", "COLLECTIVE", {"fixture": "board"},
                               {"roles": ["treasurer"]}),
        NamespaceObject.create(PREFIXED_HUMAN, "HUMAN", {"fixture": "label-only"}),
    ]


def base() -> dict:
    return {
        "keys": {"p-alice": [key(1)], "p-bob": [key(2)], PREFIXED_ACTOR: [key(3)]},
        "decision_classes": {"p-alice": ["approve", "pay", "sign"], "p-bob": ["pay"],
                             PREFIXED_ACTOR: ["sign"]},
    }


def events() -> list[dict]:
    return [
        {"position": 1, "event": "delegation", "delegation_id": "d1",
         "delegator": "p-alice", "delegate": "p-bob", "subset": ["approve", "pay"],
         "interval": [1, 100]},
        {"position": 2, "event": "delegation", "delegation_id": "d2",
         "delegator": "p-alice", "delegate": PREFIXED_ACTOR, "subset": ["sign"],
         "interval": [2, 50]},
        {"position": 3, "event": "rotation", "actor": "p-alice",
         "prior_key": key(1), "key": key(4)},
        {"position": 4, "event": "membership", "actor": "p-bob",
         "collective": "board", "change": "enter"},
        {"position": 5, "event": "revocation", "delegation_id": "d2"},
        {"position": 7, "event": "succession_end", "succession_id": "s1", "actor": "p-bob"},
        {"position": 7, "event": "succession_begin", "succession_id": "s1",
         "actor": "p-carol", "keys": [key(5)], "decision_classes": ["pay"]},
        {"position": 9, "event": "dissolution", "actor": PREFIXED_ACTOR},
        {"position": 10, "event": "membership", "actor": "p-carol",
         "collective": "board", "change": "enter"},
        {"position": 11, "event": "membership", "actor": "p-bob",
         "collective": "board", "change": "leave"},
    ]


def expected_state() -> dict:
    """Hand-derived oracle: d2 revoked, p-alice rotated, p-bob left the board."""
    return {
        "delegations": [{"delegation_id": "d1", "delegator": "p-alice", "delegate": "p-bob",
                         "subset": ["approve", "pay"], "interval": [1, 100]}],
        "keys": {"p-alice": [key(4)], "p-bob": [key(2)], PREFIXED_ACTOR: [key(3)],
                 "p-carol": [key(5)]},
        "memberships": [{"actor": "p-carol", "collective": "board"}],
    }


def case(*, base_value: dict | None = None, events_value: list | None = None,
         state_value: dict | None = None, inputs: object = _ABSENT,
         subject: str = "p-alice", **limits: int) -> tuple[dict, dict, bytes]:
    objects = collection()
    selected_base = base() if base_value is None else base_value
    selected_events = events() if events_value is None else events_value
    selected_state = expected_state() if state_value is None else state_value
    retained = ({"base": selected_base, "events": selected_events, "state": selected_state}
                if inputs is _ABSENT else inputs)
    value = {"schema_version": actor_replay.EVIDENCE_VERSION,
             "objects": [item.to_dict() for item in objects], "inputs": retained}
    if inputs == "omit":
        del value["inputs"]
    evidence = canonical_bytes(value)
    policy = actor_replay.actor_replay_policy(trust_roots=["externally-selected-actor-events"])
    record = next(item for item in objects if item.object_id == subject)
    request = actor_replay.actor_replay_request(
        subject_id=subject, object_digest=record.digest,
        collection_digest=composition_digest(objects),
        base_digest=digest(selected_base), events_digest=digest(selected_events),
        state_digest=digest(selected_state), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits or None)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None) -> dict:
    cert = actor_replay.build_actor_replay_certificate(request, evidence, policy=policy)
    result = actor_replay.recheck_actor_replay_certificate(
        cert, expected_request=request, policy=policy)
    assert result["coordinate"] == "ACTOR-2.7"
    assert result["object_kind"] == "ACTOR"
    for field in ("object_profile_conformance", "whole_actor_dynamics_tier", "personhood",
                  "real_world_completeness", "record_authenticity", "authority", "consent"):
        assert result[field] == "NOT_ESTABLISHED", field
    assert result["accountability_replay"] == (
        "PASS" if result["status"] == "PASS" else "NOT_ESTABLISHED")
    return result


def test_declared_events_replay_to_the_retained_current_state() -> None:
    request, policy, evidence = case()
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    observed = result["evaluation"]["observations"]["replay"]
    assert observed["state_digest"] == digest(expected_state())
    assert observed["event_counts"] == {
        "delegation": 2, "revocation": 1, "rotation": 1, "membership": 3,
        "dissolution": 1, "succession_end": 1, "succession_begin": 1}


def test_pass_rechecks_from_decoded_certificate_bytes() -> None:
    request, policy, evidence = case()
    cert = actor_replay.build_actor_replay_certificate(request, evidence, policy=policy)
    decoded = json.loads(cert.decode("utf-8"))
    assert canonical_bytes(decoded) == cert
    again = actor_replay.recheck_actor_replay_certificate(
        canonical_bytes(decoded), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert again["status"] == "PASS"


def _mutated(change) -> tuple[list, dict]:
    selected_events, selected_state = events(), expected_state()
    change(selected_events, selected_state)
    return selected_events, selected_state


def _superset(ev: list, st: dict) -> None:
    ev[0]["subset"] = ["approve", "pay", "refund"]
    st["delegations"][0]["subset"] = ["approve", "pay", "refund"]


def _revoke_never_declared(ev: list, st: dict) -> None:
    ev.insert(5, {"position": 6, "event": "revocation", "delegation_id": "d9"})


def _revoke_twice(ev: list, st: dict) -> None:
    ev.insert(5, {"position": 6, "event": "revocation", "delegation_id": "d2"})


def _rotation_mints_new_actor(ev: list, st: dict) -> None:
    ev[2]["actor"] = "p-alice-2"
    st["keys"]["p-alice"] = [key(1)]
    st["keys"]["p-alice-2"] = [key(4)]


def _rotation_prior_key_not_held(ev: list, st: dict) -> None:
    ev[2]["prior_key"] = key(9)


def _succession_unpaired(ev: list, st: dict) -> None:
    del ev[6]
    del ev[7]
    del st["keys"]["p-carol"]
    st["memberships"] = []


def _succession_split_positions(ev: list, st: dict) -> None:
    ev[6]["position"] = 8


def _state_differs(ev: list, st: dict) -> None:
    st["memberships"].insert(0, {"actor": "p-bob", "collective": "board"})


def _out_of_order(ev: list, st: dict) -> None:
    ev[2]["position"], ev[3]["position"] = 4, 3


def _prefixed_human_delegate(ev: list, st: dict) -> None:
    ev[1]["delegate"] = PREFIXED_HUMAN


def _absent_delegate(ev: list, st: dict) -> None:
    ev[1]["delegate"] = "p-zed"


def _delegation_after_dissolution(ev: list, st: dict) -> None:
    ev.append({"position": 12, "event": "delegation", "delegation_id": "d3",
               "delegator": PREFIXED_ACTOR, "delegate": "p-alice", "subset": ["sign"],
               "interval": [12, 20]})
    st["delegations"].append({"delegation_id": "d3", "delegator": PREFIXED_ACTOR,
                              "delegate": "p-alice", "subset": ["sign"],
                              "interval": [12, 20]})


def _membership_label_not_collective(ev: list, st: dict) -> None:
    ev[3]["collective"] = "treasurer"


@pytest.mark.parametrize(("change", "reason"), [
    (_superset, "exceeds the delegator's declared decision classes"),
    (_revoke_never_declared, "no live delegation"),
    (_revoke_twice, "no live delegation"),
    (_rotation_mints_new_actor, "never mints a new actor"),
    (_rotation_prior_key_not_held, "prior key is not held"),
    (_succession_unpaired, "paired"),
    (_succession_split_positions, "paired"),
    (_state_differs, "differs from the replay"),
    (_out_of_order, "strictly increase"),
    (_prefixed_human_delegate, "typed ACTOR record"),
    (_absent_delegate, "typed ACTOR record"),
    (_delegation_after_dissolution, "capacity to decide has ended"),
    (_membership_label_not_collective, "typed COLLECTIVE record"),
], ids=lambda value: getattr(value, "__name__", "reason"))
def test_semantically_distinct_mutants_refute(change, reason: str) -> None:
    selected_events, selected_state = _mutated(change)
    request, policy, evidence = case(events_value=selected_events, state_value=selected_state)
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["details"]


def test_kind_comes_from_typed_record_not_label_prefix() -> None:
    # The human-looking label is a typed ACTOR record and passes in the positive case;
    # the actor-looking label is a typed HUMAN record and refutes.
    kinds = {item.object_id: item.kind.value for item in collection()}
    assert kinds[PREFIXED_ACTOR] == "ACTOR" and kinds[PREFIXED_HUMAN] == "HUMAN"
    request, policy, evidence = case()
    assert replay(request, policy, evidence)["status"] == "PASS"
    selected_events, selected_state = _mutated(_prefixed_human_delegate)
    request, policy, evidence = case(events_value=selected_events, state_value=selected_state)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_redelegating_conveyed_authority_is_outside_scope() -> None:
    selected_events = events()
    selected_events.insert(5, {"position": 6, "event": "delegation", "delegation_id": "d3",
                               "delegator": "p-bob", "delegate": PREFIXED_ACTOR,
                               "subset": ["approve"], "interval": [6, 8]})
    request, policy, evidence = case(events_value=selected_events)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_subject_absent_from_base_declaration_refutes() -> None:
    request, policy, evidence = case(subject="p-carol")
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "absent from the base declaration" in result["evaluation"]["details"]


@pytest.mark.parametrize("inputs", ["omit", None, {"base": base(), "events": events()}],
                         ids=["no-inputs-field", "null-inputs", "state-absent"])
def test_missing_retained_inputs_remain_unknown(inputs: object) -> None:
    request, policy, evidence = case(inputs=inputs)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_absent_evidence_and_exhausted_budget_remain_unknown() -> None:
    request, policy, evidence = case()
    assert replay(request, policy, None)["status"] == "UNKNOWN"
    request, policy, evidence = case(max_operations=5)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"
    request, policy, evidence = case(max_events=2)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("offset", [0, 57, -3, -90])
def test_one_flipped_certificate_bit_is_rejected(offset: int) -> None:
    request, policy, evidence = case()
    cert = bytearray(actor_replay.build_actor_replay_certificate(request, evidence, policy=policy))
    cert[offset] ^= 0x01
    with pytest.raises(actor_replay.ActorReplayError):
        actor_replay.recheck_actor_replay_certificate(
            bytes(cert), expected_request=request, policy=policy)


def test_substituted_subject_request_and_policy_are_refused() -> None:
    request, policy, evidence = case()
    cert = actor_replay.build_actor_replay_certificate(request, evidence, policy=policy)
    other_subject, _, _ = case(subject="p-bob")
    for wrong in (other_subject, {**request, "state_digest": digest({"other": 1})}):
        with pytest.raises(actor_replay.ActorReplayError):
            actor_replay.recheck_actor_replay_certificate(
                cert, expected_request=wrong, policy=policy)
    other_policy = actor_replay.actor_replay_policy(trust_roots=["another-selection"])
    with pytest.raises(actor_replay.ActorReplayError):
        actor_replay.recheck_actor_replay_certificate(
            cert, expected_request=request, policy=other_policy)
    with pytest.raises(actor_replay.ActorReplayError):
        actor_replay.actor_replay_policy(trust_roots=["b", "a"])
    forged = {**policy, "mechanism_digest": "sha256:" + "0" * 64}
    with pytest.raises(actor_replay.ActorReplayError):
        actor_replay.recheck_actor_replay_certificate(
            cert, expected_request=request, policy=forged)
    # A request naming the subject with another record's digest evaluates to FAIL.
    bob = next(item for item in collection() if item.object_id == "p-bob")
    mismatched = actor_replay.actor_replay_request(
        subject_id="p-alice", object_digest=bob.digest,
        collection_digest=request["collection_digest"], base_digest=request["base_digest"],
        events_digest=request["events_digest"], state_digest=request["state_digest"],
        evidence_ref=request["evidence_ref"], policy=policy)
    assert replay(mismatched, policy, evidence)["status"] == "FAIL"


def test_public_route_and_inventory_register_only_accountability_replay() -> None:
    from verifier.domains.contracts.current_object_routes import (
        CurrentObjectRouteRefusal, current_object_route_catalog,
        replay_current_object_certificate, select_current_object_route)
    from verifier.domains.inventory import get_slot

    request, policy, evidence = case()
    cert = actor_replay.build_actor_replay_certificate(request, evidence, policy=policy)
    report = replay_current_object_certificate(
        cert, semantic_version=actor_replay.SEMANTIC_VERSION, objective="ACTOR-2.7",
        represented_kind="ACTOR", expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    route = next(row for row in current_object_route_catalog() if row["objective"] == "ACTOR-2.7")
    assert route["represented_kind_rule"] == "ACTOR"
    assert route["certificate_schema_version"] == actor_replay.CERTIFICATE_VERSION
    slot = get_slot("ACTOR", 2).to_dict()
    assert slot["status"] == "REPLAYABLE"
    assert slot["coordinate"] == "ACTOR-2.7"
    assert slot["mechanized_route"]["checking_mechanism"] == (
        "verifier.domains.contracts.actor_replay.recheck_actor_replay_certificate")
    assert {item["coordinate"] for item in slot["registered_objectives"]} == {"ACTOR-2.7"}
    assert slot["objective_inventory_closure"] == "NOT_ESTABLISHED"
    # The delegation row stays the known-unknown route fixture.
    with pytest.raises(CurrentObjectRouteRefusal):
        select_current_object_route(semantic_version=actor_replay.SEMANTIC_VERSION,
                                    objective="ACTOR-2.1", represented_kind="ACTOR")


def test_specification_quotes_the_obligation_row_verbatim() -> None:
    root = Path(actor_replay.__file__).parents[2] / "standard"
    obligations = (root / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    row = next(line for line in obligations.splitlines() if line.startswith("| ACTOR-2.7 |"))
    assert "| " + ROW + " |" in row
    assert ROW in (root / "CURRENT_ACTOR_REPLAY.md").read_text(encoding="utf-8")
    registration = actor_replay.registration()
    assert registration["obligation_row"] == ROW
    assert registration["proposition"] != ROW


@pytest.mark.parametrize("relative", [
    "domains/contracts/actor_replay.py", "standard/CURRENT_ACTOR_REPLAY.md",
])
def test_actor_replay_dependency_change_invalidates_polish_digest(
    relative: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged ACTOR replay dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert polish.mechanism_digest() != before


def test_actor_replay_certificate_cannot_emit_redacted_replay_evidence() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import (
        DisclosureBound, DisclosureSurface, EmissionContext, ObserverParty)

    request, policy, evidence = case()
    value = json.loads(actor_replay.build_actor_replay_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("ACTOR",
        tuple(field for field in value if field != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",))
                   for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"),
                              "2026-10-01T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


def test_selected_inputs_are_not_mutated_by_replay() -> None:
    selected_events = events()
    snapshot = copy.deepcopy(selected_events)
    request, policy, evidence = case(events_value=selected_events)
    replay(request, policy, evidence)
    assert selected_events == snapshot
