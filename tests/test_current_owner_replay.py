"""Selected OWNER ordered replay: declared events reproduce the current holding.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions and term bounds are dimensionless
integers in the declared order; counts are dimensionless. The expected
holdings below are written by hand and recomputed by an independent oracle in
this file, never by the checker under test.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import owner_replay
from verifier.domains.inventory import get_slot


ROOT = Path(__file__).resolve().parents[1]
ROW = ("Replaying the declared events from the origin in the declared order "
       "reproduces the current holding.")
HOLDERS = ("alice", "bob", "carol")
NON_EXPIRING = {"start": 0, "non_expiring": True}


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def instrument(name: str) -> tuple[str, str]:
    data = ("instrument:" + name).encode("utf-8")
    return (base64.b64encode(data).decode("ascii"),
            "sha256:" + hashlib.sha256(data).hexdigest())


ORIGIN_B64, ORIGIN_D = instrument("origin")
TRANSFER_B64, TRANSFER_D = instrument("transfer")
DELEGATION_B64, DELEGATION_D = instrument("delegation")
REVOCATION_B64, REVOCATION_D = instrument("revocation")
EXTRA_B64, EXTRA_D = instrument("extra")


def grant(holder: str, limb: str, kind: str, term: dict) -> dict:
    return {"object": "artifact", "holder": holder + "-actor", "limb": limb,
            "kind": kind, "term": dict(term)}


def base_inputs() -> dict:
    return {
        "instruments": sorted([ORIGIN_B64, TRANSFER_B64, DELEGATION_B64,
                               REVOCATION_B64, EXTRA_B64]),
        "origin": {"position": 0, "instrument_digest": ORIGIN_D, "grants": [
            grant("alice", "use", "right", NON_EXPIRING),
            grant("alice", "sublicense", "right", {"start": 0, "end": 10}),
            grant("alice", "preview", "right", {"start": 0, "end": 3}),
            grant("alice", "maintain", "discharge_duty", NON_EXPIRING),
            grant("alice", "report", "answering_duty", NON_EXPIRING),
        ]},
        "events": [
            {"position": 1, "event": "transfer", "instrument_digest": TRANSFER_D,
             "object": "artifact", "from": "alice-actor", "to": "bob-actor",
             "limbs": ["maintain", "use"]},
            {"position": 2, "event": "delegation", "instrument_digest": DELEGATION_D,
             "object": "artifact", "from": "bob-actor", "to": "carol-actor",
             "limbs": ["use"]},
            {"position": 3, "event": "revocation", "instrument_digest": REVOCATION_D,
             "object": "artifact", "holder": "alice-actor", "limbs": ["sublicense"]},
        ],
        "evaluation_position": 5,
        # Written by hand: preview lapsed by the clock at 3, sublicense was
        # revoked at 3, bob kept use when delegating it to carol.
        "current_holding": [
            grant("alice", "report", "answering_duty", NON_EXPIRING),
            grant("bob", "maintain", "discharge_duty", NON_EXPIRING),
            grant("bob", "use", "right", NON_EXPIRING),
            grant("carol", "use", "right", NON_EXPIRING),
        ],
    }


def records(inputs: dict) -> tuple[NamespaceObject, list[NamespaceObject]]:
    humans = [NamespaceObject.create(name, "HUMAN", {"fixture": name}) for name in HOLDERS]
    actors = [NamespaceObject.create(name + "-actor", "ACTOR", {"fixture": name + "-actor"},
                                     {"representation": [name], "root_human": [name]})
              for name in HOLDERS]
    artifact = NamespaceObject.create("artifact", "DATA", {"fixture": "artifact"})
    subject = NamespaceObject.create("holding", "OWNER", {
        "scope": "retained-ordered-holding-replay", "inputs_digest": digest(inputs)},
        {"actor": [actor.object_id for actor in actors], "object": ["artifact"]})
    return subject, [*humans, *actors, artifact, subject]


def selected(inputs: dict | None = None, *, limits: dict | None = None,
             include_evidence: bool = True):
    inputs = base_inputs() if inputs is None else inputs
    subject, objects = records(inputs)
    evidence = canonical_bytes({
        "schema_version": owner_replay.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects], "inputs": inputs})
    policy = owner_replay.owner_replay_policy(trust_roots=["owner-root"])
    request = owner_replay.owner_replay_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        inputs_digest=digest(inputs),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, (evidence if include_evidence else None)


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = owner_replay.build_owner_replay_certificate(
        request, evidence, policy=policy)
    result = owner_replay.recheck_owner_replay_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle(inputs: dict):
    """Independent replay over plain dictionaries; returns (verdict, rows)."""
    actors = {name + "-actor" for name in HOLDERS}
    bound = {"sha256:" + hashlib.sha256(base64.b64decode(row)).hexdigest()
             for row in inputs["instruments"]}

    def alive(term: dict, position: int) -> bool:
        return term["start"] <= position and (term.get("non_expiring") is True
                                              or position < term["end"])

    def ended(term: dict, position: int) -> bool:
        return "end" in term and term["end"] <= position

    if inputs["origin"]["instrument_digest"] not in bound:
        return "FAIL", None
    table = {}
    for row in inputs["origin"]["grants"]:
        if row["holder"] not in actors:
            return "FAIL", None
        table[(row["object"], row["holder"], row["limb"])] = (row["kind"], row["term"])
    last = inputs["origin"]["position"]
    for event in inputs["events"]:
        if event["event"] == "lapse" or event["position"] <= last:
            return "FAIL", None
        if event["instrument_digest"] not in bound:
            return "FAIL", None
        last = position = event["position"]
        if event["event"] == "revocation":
            if event["holder"] not in actors:
                return "FAIL", None
            for limb in event["limbs"]:
                key = (event["object"], event["holder"], limb)
                if key not in table or not alive(table[key][1], position):
                    return "FAIL", None
                del table[key]
            continue
        if event["from"] == event["to"] or {event["from"], event["to"]} - actors:
            return "FAIL", None
        for limb in event["limbs"]:
            source = (event["object"], event["from"], limb)
            if source not in table or not alive(table[source][1], position):
                return "FAIL", None
        for limb in event["limbs"]:
            target = (event["object"], event["to"], limb)
            if target in table and not ended(table[target][1], position):
                return "UNKNOWN", None
        for limb in event["limbs"]:
            source = (event["object"], event["from"], limb)
            table[(event["object"], event["to"], limb)] = table[source]
            if event["event"] == "transfer":
                del table[source]
    if inputs["evaluation_position"] < last:
        return "FAIL", None
    rows = [{"object": key[0], "holder": key[1], "limb": key[2], "kind": kind,
             "term": term} for key, (kind, term) in sorted(table.items())
            if alive(term, inputs["evaluation_position"])]
    retained = sorted(inputs["current_holding"],
                      key=lambda row: (row["object"], row["holder"], row["limb"]))
    return ("PASS" if retained == rows else "FAIL"), rows


def test_grounded_row_is_quoted_verbatim_from_the_owner_dynamics_table():
    spec = (ROOT / "src" / "verifier" / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(
        encoding="utf-8")
    assert "| OWNER-2.6 | Ordered replay | " + ROW + " |" in spec
    current = (ROOT / "src" / "verifier" / "standard" / "CURRENT_OWNER_REPLAY.md").read_text(
        encoding="utf-8")
    assert ROW in current
    assert owner_replay.COORDINATE == "OWNER-2.6"
    registration = owner_replay.registration()
    assert registration["subject_kind"] == "OWNER"
    joined = " ".join(registration["exclusions"])
    for excluded in ("legal title", "liens", "authority", "consent", "personhood"):
        assert excluded in joined


def test_hand_written_holding_matches_the_independent_oracle():
    inputs = base_inputs()
    verdict, rows = oracle(inputs)
    assert verdict == "PASS"
    assert rows == inputs["current_holding"]


def test_declared_events_replay_to_the_retained_current_holding():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["ordered_replay"] == "PASS"
    for field in ("legal_title", "liens", "authority", "consent", "personhood",
                  "holder_actor_certificate", "instrument_issuing_authority",
                  "whole_owner_dynamics_tier", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED", field
    assert certificate == owner_replay.build_owner_replay_certificate(
        request, evidence, policy=policy)
    decoded = json.loads(certificate)
    retained = base64.b64decode(decoded["evidence_payloads"][request["evidence_ref"]])
    assert retained == evidence
    assert owner_replay.recheck_owner_replay_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))["status"] == "PASS"


def _transfer_unheld(inputs):
    inputs["events"][0]["limbs"] = ["maintain", "publish", "use"]


def _transfer_from_nonholder(inputs):
    inputs["events"][0]["from"] = "carol-actor"
    inputs["events"][0]["to"] = "bob-actor"


def _delegation_strips_delegator(inputs):
    inputs["current_holding"] = [row for row in inputs["current_holding"]
                                 if not (row["holder"] == "bob-actor" and row["limb"] == "use")]


def _delegation_exceeds_delegator(inputs):
    inputs["events"][1]["limbs"] = ["report", "use"]


def _revocation_removes_unnamed_limb(inputs):
    inputs["current_holding"] = [row for row in inputs["current_holding"]
                                 if row["limb"] != "report"]


def _revocation_names_unheld_limb(inputs):
    inputs["events"][2]["limbs"] = ["sublicense", "use"]


def _lapse_declared_as_event(inputs):
    inputs["events"].append({"position": 4, "event": "lapse",
        "instrument_digest": EXTRA_D, "object": "artifact",
        "holder": "alice-actor", "limbs": ["preview"]})


def _lapsed_limb_revoked(inputs):
    inputs["events"].append({"position": 4, "event": "revocation",
        "instrument_digest": EXTRA_D, "object": "artifact",
        "holder": "alice-actor", "limbs": ["preview"]})


def _lapsed_limb_transferred(inputs):
    inputs["events"].append({"position": 4, "event": "transfer",
        "instrument_digest": EXTRA_D, "object": "artifact",
        "from": "alice-actor", "to": "bob-actor", "limbs": ["preview"]})


def _lapsed_limb_retained_as_current(inputs):
    inputs["current_holding"] = sorted(
        [*inputs["current_holding"],
         grant("alice", "preview", "right", {"start": 0, "end": 3})],
        key=lambda row: (row["object"], row["holder"], row["limb"]))


def _retained_term_differs(inputs):
    inputs["current_holding"][3]["term"] = {"start": 0, "end": 9}


def _out_of_order_position(inputs):
    inputs["events"][1]["position"], inputs["events"][2]["position"] = 3, 2


def _repeated_position(inputs):
    inputs["events"][1]["position"] = 1


def _label_prefix_holder(inputs):
    label = "human:" + "person:carol"
    inputs["events"][1]["to"] = label
    inputs["current_holding"][3]["holder"] = label


def _human_record_as_holder(inputs):
    inputs["events"][1]["to"] = "carol"
    inputs["current_holding"][3]["holder"] = "carol"


def _unbound_event_instrument(inputs):
    inputs["events"][1]["instrument_digest"] = "sha256:" + hashlib.sha256(
        b"instrument:never-retained").hexdigest()


def _unbound_origin_instrument(inputs):
    inputs["instruments"].remove(ORIGIN_B64)


def _evaluation_before_last_event(inputs):
    inputs["evaluation_position"] = 2


MUTANTS = {
    "transfer-of-unheld-limb": _transfer_unheld,
    "transfer-from-nonholder": _transfer_from_nonholder,
    "delegation-strips-delegator": _delegation_strips_delegator,
    "delegation-exceeds-delegator": _delegation_exceeds_delegator,
    "revocation-removes-unnamed-limb": _revocation_removes_unnamed_limb,
    "revocation-names-unheld-limb": _revocation_names_unheld_limb,
    "lapse-declared-as-event": _lapse_declared_as_event,
    "lapsed-limb-revoked": _lapsed_limb_revoked,
    "lapsed-limb-transferred": _lapsed_limb_transferred,
    "lapsed-limb-retained-as-current": _lapsed_limb_retained_as_current,
    "retained-term-differs": _retained_term_differs,
    "out-of-order-position": _out_of_order_position,
    "repeated-position": _repeated_position,
    "label-prefix-holder": _label_prefix_holder,
    "human-record-as-holder": _human_record_as_holder,
    "unbound-event-instrument": _unbound_event_instrument,
    "unbound-origin-instrument": _unbound_origin_instrument,
    "evaluation-before-last-event": _evaluation_before_last_event,
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutant_replays_fail(name):
    inputs = base_inputs()
    MUTANTS[name](inputs)
    if name not in ("label-prefix-holder", "human-record-as-holder"):
        assert oracle(inputs)[0] == "FAIL", name
    request, policy, evidence = selected(inputs)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL", (name, result["evaluation"]["details"])
    assert result["ordered_replay"] == "NOT_ESTABLISHED"


def test_label_holder_is_refused_even_when_a_matching_human_record_exists():
    inputs = base_inputs()
    _label_prefix_holder(inputs)
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "ACTOR record" in result["evaluation"]["details"]


@pytest.mark.parametrize(("encoded", "reason"), [
    ("!!!!", "invalid base64"),
    ("QR==", "noncanonical base64"),
])
def test_malformed_retained_instrument_bytes_fail(encoded, reason):
    inputs = base_inputs()
    inputs["instruments"] = sorted([*inputs["instruments"], encoded])
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["details"]


def test_conveyance_into_an_already_held_limb_stays_unknown():
    inputs = base_inputs()
    inputs["events"].append({"position": 4, "event": "delegation",
        "instrument_digest": EXTRA_D, "object": "artifact",
        "from": "bob-actor", "to": "carol-actor", "limbs": ["use"]})
    assert oracle(inputs)[0] == "UNKNOWN"
    request, policy, evidence = selected(inputs)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("limits", [{"max_events": 2}, {"max_grants": 4},
                                    {"max_instruments": 4}, {"max_operations": 40}])
def test_exhausted_budget_stays_unknown(limits):
    request, policy, evidence = selected(limits=limits)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["ordered_replay"] == "NOT_ESTABLISHED"


def test_missing_evidence_stays_unknown():
    request, policy, _ = selected(include_evidence=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("offset", [0, 17, 211, -40, -2])
def test_one_bit_flip_in_certificate_is_refused(offset):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    flipped = bytearray(certificate)
    flipped[offset] ^= 0x01
    with pytest.raises(owner_replay.OwnerReplayError):
        owner_replay.recheck_owner_replay_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_or_verdict_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    other = deepcopy(request)
    other["subject_id"] = "artifact"
    with pytest.raises(owner_replay.OwnerReplayError):
        owner_replay.recheck_owner_replay_certificate(
            certificate, expected_request=other, policy=policy)
    roots = deepcopy(policy)
    roots["trust_roots"] = ["other-root"]
    with pytest.raises(owner_replay.OwnerReplayError):
        owner_replay.recheck_owner_replay_certificate(
            certificate, expected_request=request, policy=roots)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(owner_replay.OwnerReplayError):
        owner_replay.recheck_owner_replay_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong_subject = deepcopy(request)
    wrong_subject["subject_id"] = "artifact"
    wrong_subject["object_digest"] = NamespaceObject.create(
        "artifact", "DATA", {"fixture": "artifact"}).digest
    assert replay(wrong_subject, policy, evidence)[1]["status"] == "FAIL"
    with pytest.raises(owner_replay.OwnerReplayError):
        owner_replay.build_owner_replay_certificate(
            request, evidence + b" ", policy=policy)
    with pytest.raises(owner_replay.OwnerReplayError):
        owner_replay.owner_replay_request(
            subject_id="holding", object_digest=request["object_digest"],
            collection_digest=request["collection_digest"],
            inputs_digest=request["inputs_digest"],
            evidence_ref=request["evidence_ref"], policy=policy,
            limits={"max_unknown": 1})


def test_inputs_substituted_under_the_same_subject_fail():
    request, policy, evidence = selected()
    value = json.loads(evidence)
    value["inputs"]["evaluation_position"] = 6
    changed = canonical_bytes(value)
    swapped = deepcopy(request)
    swapped["evidence_ref"] = digest(value)
    assert replay(swapped, policy, changed)[1]["status"] == "FAIL"


def test_public_route_and_inventory_select_ordered_replay():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=owner_replay.SEMANTIC_VERSION,
        objective=owner_replay.COORDINATE, represented_kind="OWNER",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["legal_title"] == "NOT_ESTABLISHED"
    slot = get_slot("OWNER", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "OWNER-2.6"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.owner_replay.recheck_owner_replay_certificate")


def test_retained_replay_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("OWNER", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def _generated(seed: int) -> dict:
    chooser = random.Random(seed)
    actors = [name + "-actor" for name in HOLDERS]
    limbs = ["a", "b", "c", "d"]
    grants = []
    for holder in actors:
        for limb in limbs:
            if chooser.random() < 0.4:
                start = chooser.randrange(0, 3)
                term = ({"start": start, "non_expiring": True} if chooser.random() < 0.5
                        else {"start": start, "end": start + chooser.randrange(1, 12)})
                grants.append({"object": "artifact", "holder": holder, "limb": limb,
                               "kind": chooser.choice(["answering_duty", "discharge_duty", "right"]),
                               "term": term})
    events, position = [], 0
    digests = [TRANSFER_D, DELEGATION_D, REVOCATION_D]
    instruments = sorted([ORIGIN_B64, TRANSFER_B64, DELEGATION_B64, REVOCATION_B64])

    def candidate(at: int) -> dict:
        kind = chooser.choice(["transfer", "delegation", "revocation"])
        named = sorted(chooser.sample(limbs, chooser.randrange(1, 3)))
        if kind == "revocation":
            return {"position": at, "event": kind,
                    "instrument_digest": chooser.choice(digests), "object": "artifact",
                    "holder": chooser.choice(actors), "limbs": named}
        source, target = chooser.sample(actors, 2)
        return {"position": at, "event": kind,
                "instrument_digest": chooser.choice(digests), "object": "artifact",
                "from": source, "to": target, "limbs": named}

    for _ in range(chooser.randrange(1, 6)):
        position += chooser.randrange(1, 4)
        # Most steps keep drawing until the oracle accepts the prefix, so the
        # corpus reaches valid replays as well as refuted ones; the verdict is
        # still the oracle's, never the checker's.
        attempts = 24 if chooser.random() < 0.75 else 1
        for _attempt in range(attempts):
            event = candidate(position)
            trial = {"instruments": instruments,
                     "origin": {"position": 0, "instrument_digest": ORIGIN_D, "grants": grants},
                     "events": [*events, event], "evaluation_position": position,
                     "current_holding": []}
            if attempts == 1 or oracle(trial)[1] is not None:
                break
        events.append(event)
    inputs = {"instruments": instruments,
              "origin": {"position": 0, "instrument_digest": ORIGIN_D, "grants": grants},
              "events": events, "evaluation_position": position + chooser.randrange(0, 4),
              "current_holding": []}
    verdict, rows = oracle(inputs)
    if verdict == "PASS" or rows is not None:
        inputs["current_holding"] = rows
    return inputs


@pytest.mark.parametrize("seed", range(40))
def test_differential_replay_agrees_with_the_independent_oracle(seed):
    inputs = _generated(seed)
    expected = oracle(inputs)[0]
    request, policy, evidence = selected(inputs)
    assert replay(request, policy, evidence)[1]["status"] == expected
    if expected == "PASS" and inputs["current_holding"]:
        dropped = deepcopy(inputs)
        dropped["current_holding"] = dropped["current_holding"][1:]
        request, policy, evidence = selected(dropped)
        assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_differential_corpus_reaches_every_verdict():
    verdicts = {oracle(_generated(seed))[0] for seed in range(40)}
    assert verdicts == {"PASS", "FAIL", "UNKNOWN"}


@pytest.mark.parametrize("relative", [
    "domains/contracts/owner_replay.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_OWNER_REPLAY.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(owner_replay.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        owner_replay.recheck_owner_replay_certificate(
            certificate, expected_request=request, policy=policy)
