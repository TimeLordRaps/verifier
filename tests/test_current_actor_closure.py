"""Independent finite ACTOR-4.6 closure-result counterexamples.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions and counts are dimensionless. The oracle
below recomputes the expected verdict with plain sets and ranges, independently
of the mechanism under test.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import actor_closure


ROW = ("The inventory, the attributions and their independence are reported "
       "together; a closure missing any of the three is incomplete rather than passing.")
PREFIXED_HUMAN = "actor" + ":" + "mallory"
COMPONENTS = ("inventory", "attributions", "independence")
_ABSENT = object()


def collection() -> list[NamespaceObject]:
    humans = [NamespaceObject.create(name, "HUMAN", {"fixture": name})
              for name in ("alice", "bob", "carol")]

    def actor(object_id: str, human: str) -> NamespaceObject:
        return NamespaceObject.create(object_id, "ACTOR", {"fixture": object_id},
                                      {"representation": [human], "root_human": [human]})

    return [*humans, actor("p-alice", "alice"), actor("p-bob", "bob"),
            actor("p-carol", "carol"),
            NamespaceObject.create(PREFIXED_HUMAN, "HUMAN", {"fixture": "label-only"})]


ACTOR_IDS = {item.object_id for item in collection() if item.kind.value == "ACTOR"}


def inventory() -> dict:
    return {"interval": [0, 4], "decision_classes": ["approve", "pay"], "decisions": [
        {"decision_id": "q0", "position": 0, "decision_class": "approve"},
        {"decision_id": "q1", "position": 1, "decision_class": "pay"},
        {"decision_id": "q2", "position": 2, "decision_class": "log"},
        {"decision_id": "q3", "position": 3, "decision_class": "pay"},
        {"decision_id": "q4", "position": 4, "decision_class": "approve"},
    ]}


def attributions() -> list[dict]:
    return [
        {"decision_id": "q0", "actor": "p-alice", "evidence": ["r1"]},
        {"decision_id": "q1", "actor": "p-bob", "evidence": ["r2"]},
        {"decision_id": "q3", "actor": "p-alice", "evidence": ["r1", "r3"]},
        {"decision_id": "q4", "actor": "p-bob", "evidence": ["r2"]},
    ]


def independence() -> dict:
    return {"records": [
        {"record_id": "r1", "controllers": ["p-alice", "p-carol"]},
        {"record_id": "r2", "controllers": ["p-carol"]},
        {"record_id": "r3", "controllers": ["p-bob"]},
        {"record_id": "r4", "controllers": ["p-bob"]},
    ]}


def oracle(inv: dict | None, attrs: list | None, ind: dict | None) -> str:
    fails = False
    unknown = inv is None or attrs is None or ind is None
    if inv is not None:
        start, end = inv["interval"]
        if [row["position"] for row in inv["decisions"]] != list(range(start, end + 1)):
            fails = True
    if attrs is not None:
        ids = [row["decision_id"] for row in attrs]
        if len(ids) != len(set(ids)) or any(row["actor"] not in ACTOR_IDS for row in attrs):
            fails = True
        if inv is not None:
            every = {row["decision_id"] for row in inv["decisions"]}
            declared = {row["decision_id"] for row in inv["decisions"]
                        if row["decision_class"] in inv["decision_classes"]}
            if not declared <= set(ids) or not set(ids) <= every:
                fails = True
        if ind is not None:
            control = {row["record_id"]: row["controllers"] for row in ind["records"]}
            for row in attrs:
                cited = [control.get(name) for name in row["evidence"]]
                own = [held == [row["actor"]] for held in cited]
                if not cited or None in cited:
                    unknown = True
                elif all(own):
                    fails = True
                elif any(own):
                    unknown = True
    return "FAIL" if fails else "UNKNOWN" if unknown else "PASS"


def case(*, inv: object = _ABSENT, attrs: object = _ABSENT, ind: object = _ABSENT,
         drop: tuple[str, ...] = (), inputs: object = _ABSENT,
         subject: str = "p-alice", **limits: int) -> tuple[dict, dict, bytes, dict]:
    objects = collection()
    selected = {
        "inventory": inventory() if inv is _ABSENT else inv,
        "attributions": attributions() if attrs is _ABSENT else attrs,
        "independence": independence() if ind is _ABSENT else ind,
    }
    retained = ({name: value for name, value in selected.items() if name not in drop}
                if inputs is _ABSENT else inputs)
    value = {"schema_version": actor_closure.EVIDENCE_VERSION,
             "objects": [item.to_dict() for item in objects], "inputs": retained}
    if inputs == "omit":
        del value["inputs"]
    evidence = canonical_bytes(value)
    policy = actor_closure.actor_closure_policy(trust_roots=["externally-selected-closure"])
    record = next(item for item in objects if item.object_id == subject)
    request = actor_closure.actor_closure_request(
        subject_id=subject, object_digest=record.digest,
        collection_digest=composition_digest(objects),
        inventory_digest=digest(selected["inventory"]),
        attributions_digest=digest(selected["attributions"]),
        independence_digest=digest(selected["independence"]),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits or None)
    return request, policy, evidence, selected


def replay(request: dict, policy: dict, evidence: bytes | None) -> dict:
    cert = actor_closure.build_actor_closure_certificate(request, evidence, policy=policy)
    result = actor_closure.recheck_actor_closure_certificate(
        cert, expected_request=request, policy=policy)
    assert result["coordinate"] == "ACTOR-4.6"
    assert result["object_kind"] == "ACTOR"
    for field in ("object_profile_conformance", "whole_actor_closure_tier", "personhood",
                  "real_world_completeness", "record_authenticity", "authority", "consent"):
        assert result[field] == "NOT_ESTABLISHED", field
    assert result["closure_result"] == (
        "PASS" if result["status"] == "PASS" else "NOT_ESTABLISHED")
    return result


def components(result: dict) -> dict:
    return {name: row["status"] for name, row in
            result["evaluation"]["observations"]["closure"]["components"].items()}


def test_inventory_attributions_and_independence_pass_reported_together() -> None:
    assert oracle(inventory(), attributions(), independence()) == "PASS"
    request, policy, evidence, _ = case()
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert components(result) == {name: "PASS" for name in COMPONENTS}
    observed = result["evaluation"]["observations"]["closure"]
    assert observed["decisions"] == 5 and observed["declared_class_decisions"] == 4


def test_pass_rechecks_from_decoded_certificate_bytes() -> None:
    request, policy, evidence, _ = case()
    cert = actor_closure.build_actor_closure_certificate(request, evidence, policy=policy)
    decoded = json.loads(cert.decode("utf-8"))
    assert canonical_bytes(decoded) == cert
    again = actor_closure.recheck_actor_closure_certificate(
        canonical_bytes(decoded), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert again["status"] == "PASS"


def _gap(inv: dict, attrs: list, ind: dict) -> str:
    inv["decisions"][3]["position"] = 5
    inv["interval"] = [0, 5]
    return "inventory"


def _outside_interval(inv: dict, attrs: list, ind: dict) -> str:
    inv["interval"] = [0, 3]
    return "inventory"


def _not_an_actor(inv: dict, attrs: list, ind: dict) -> str:
    attrs[1]["actor"] = PREFIXED_HUMAN
    return "attributions"


def _absent_actor(inv: dict, attrs: list, ind: dict) -> str:
    attrs[1]["actor"] = "p-zed"
    return "attributions"


def _unattributed(inv: dict, attrs: list, ind: dict) -> str:
    del attrs[3]
    return "attributions"


def _attribution_outside_inventory(inv: dict, attrs: list, ind: dict) -> str:
    attrs.append({"decision_id": "q9", "actor": "p-bob", "evidence": ["r2"]})
    return "attributions"


def _doubly_attributed(inv: dict, attrs: list, ind: dict) -> str:
    attrs.insert(2, {"decision_id": "q1", "actor": "p-carol", "evidence": ["r1"]})
    return "attributions"


def _self_witnessed(inv: dict, attrs: list, ind: dict) -> str:
    attrs[3]["evidence"] = ["r4"]
    return "independence"


@pytest.mark.parametrize("change", [
    _gap, _outside_interval,                       # ACTOR-4.1 inventory
    _not_an_actor, _absent_actor,                   # ACTOR-4.2 exactly one typed actor
    _unattributed, _attribution_outside_inventory,  # ACTOR-4.3 none unattributed
    _doubly_attributed,                             # ACTOR-4.4 none doubly attributed
    _self_witnessed,                                # ACTOR-4.5 independent attribution
], ids=lambda value: value.__name__)
def test_each_prerequisite_violation_refutes_separately(change) -> None:
    inv, attrs, ind = inventory(), attributions(), independence()
    failing = change(inv, attrs, ind)
    assert oracle(inv, attrs, ind) == "FAIL"
    request, policy, evidence, _ = case(inv=inv, attrs=attrs, ind=ind)
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert components(result)[failing] == "FAIL"
    assert [name for name, status in components(result).items() if status == "FAIL"] == [failing]


@pytest.mark.parametrize("missing", COMPONENTS)
@pytest.mark.parametrize("how", ["null", "key-absent"])
def test_a_closure_missing_any_component_is_incomplete_not_passing(missing: str, how: str) -> None:
    selected = {"inventory": inventory(), "attributions": attributions(),
                "independence": independence()}
    selected[missing] = None
    assert oracle(selected["inventory"], selected["attributions"],
                  selected["independence"]) == "UNKNOWN"
    if how == "null":
        request, policy, evidence, _ = case(**{
            {"inventory": "inv", "attributions": "attrs", "independence": "ind"}[missing]: None})
    else:
        request, policy, evidence, _ = case(drop=(missing,))
    result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert components(result)[missing] == "ABSENT"


def test_refuted_component_dominates_a_missing_one() -> None:
    inv, attrs = inventory(), attributions()
    _doubly_attributed(inv, attrs, {})
    assert oracle(inv, attrs, None) == "FAIL"
    request, policy, evidence, _ = case(inv=inv, attrs=attrs, ind=None)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_mixed_self_and_independent_citation_remains_unknown() -> None:
    inv, attrs, ind = inventory(), attributions(), independence()
    attrs[3]["evidence"] = ["r2", "r4"]
    assert oracle(inv, attrs, ind) == "UNKNOWN"
    request, policy, evidence, _ = case(inv=inv, attrs=attrs, ind=ind)
    result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert components(result)["independence"] == "UNKNOWN"


def test_kind_comes_from_typed_record_not_label_prefix() -> None:
    kinds = {item.object_id: item.kind.value for item in collection()}
    assert kinds[PREFIXED_HUMAN] == "HUMAN"
    ind = independence()
    ind["records"][1]["controllers"] = [PREFIXED_HUMAN]
    request, policy, evidence, _ = case(ind=ind)
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "typed ACTOR record" in result["evaluation"]["details"]


@pytest.mark.parametrize("inputs", ["omit", None], ids=["no-inputs-field", "null-inputs"])
def test_missing_retained_inputs_remain_unknown(inputs: object) -> None:
    request, policy, evidence, _ = case(inputs=inputs)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_absent_evidence_and_exhausted_budget_remain_unknown() -> None:
    request, policy, evidence, _ = case()
    assert replay(request, policy, None)["status"] == "UNKNOWN"
    request, policy, evidence, _ = case(max_operations=5)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"
    request, policy, evidence, _ = case(max_decisions=2)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("offset", [0, 57, -3, -90])
def test_one_flipped_certificate_bit_is_rejected(offset: int) -> None:
    request, policy, evidence, _ = case()
    cert = bytearray(actor_closure.build_actor_closure_certificate(request, evidence, policy=policy))
    cert[offset] ^= 0x01
    with pytest.raises(actor_closure.ActorClosureError):
        actor_closure.recheck_actor_closure_certificate(
            bytes(cert), expected_request=request, policy=policy)


def test_substituted_subject_request_and_policy_are_refused() -> None:
    request, policy, evidence, _ = case()
    cert = actor_closure.build_actor_closure_certificate(request, evidence, policy=policy)
    other_subject, _, _, _ = case(subject="p-bob")
    for wrong in (other_subject, {**request, "attributions_digest": digest({"other": 1})}):
        with pytest.raises(actor_closure.ActorClosureError):
            actor_closure.recheck_actor_closure_certificate(
                cert, expected_request=wrong, policy=policy)
    other_policy = actor_closure.actor_closure_policy(trust_roots=["another-selection"])
    with pytest.raises(actor_closure.ActorClosureError):
        actor_closure.recheck_actor_closure_certificate(
            cert, expected_request=request, policy=other_policy)
    # A retained component that differs from the external selection refutes.
    request, policy, evidence, _ = case()
    swapped = {**request, "independence_digest": digest({"records": []})}
    swapped = actor_closure.actor_closure_request(
        **{key: swapped[key] for key in (
            "subject_id", "object_digest", "collection_digest", "inventory_digest",
            "attributions_digest", "independence_digest", "evidence_ref")}, policy=policy)
    assert replay(swapped, policy, evidence)["status"] == "FAIL"


def test_public_route_and_inventory_register_only_closure_result() -> None:
    from verifier.domains.contracts.current_object_routes import (
        current_object_route_catalog, replay_current_object_certificate)
    from verifier.domains.inventory import get_slot

    request, policy, evidence, _ = case()
    cert = actor_closure.build_actor_closure_certificate(request, evidence, policy=policy)
    report = replay_current_object_certificate(
        cert, semantic_version=actor_closure.SEMANTIC_VERSION, objective="ACTOR-4.6",
        represented_kind="ACTOR", expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    route = next(row for row in current_object_route_catalog() if row["objective"] == "ACTOR-4.6")
    assert route["represented_kind_rule"] == "ACTOR"
    slot = get_slot("ACTOR", 4).to_dict()
    assert slot["status"] == "REPLAYABLE"
    assert slot["coordinate"] == "ACTOR-4.6"
    assert slot["mechanized_route"]["checking_mechanism"] == (
        "verifier.domains.contracts.actor_closure.recheck_actor_closure_certificate")
    assert {item["coordinate"] for item in slot["registered_objectives"]} == {"ACTOR-4.6"}


def test_specification_quotes_the_obligation_row_verbatim() -> None:
    root = Path(actor_closure.__file__).parents[2] / "standard"
    obligations = (root / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    row = next(line for line in obligations.splitlines() if line.startswith("| ACTOR-4.6 |"))
    assert "| " + ROW + " |" in row
    spec = " ".join((root / "CURRENT_ACTOR_CLOSURE.md").read_text(encoding="utf-8").split())
    assert ROW in spec
    assert actor_closure.registration()["obligation_row"] == ROW


@pytest.mark.parametrize("relative", [
    "domains/contracts/actor_closure.py", "standard/CURRENT_ACTOR_CLOSURE.md",
])
def test_closure_dependency_change_invalidates_polish_digest(
    relative: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged ACTOR closure dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert polish.mechanism_digest() != before
