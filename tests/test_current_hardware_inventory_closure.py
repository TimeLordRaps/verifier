"""Current HARDWARE-4.1 retained inventory closure under independent records.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Members, entries, identity keys and producers are
exact strings; counts are dimensionless.

The governing row (DOMAIN_OBLIGATIONS.md, HARDWARE-4.1) reads: "Complete
coverage, nonaliasing physical identities and resource isolation require
independent bounded evidence; a retained inventory alone leaves closure
UNKNOWN."

The oracle decides each fixture with plain sets and loops, independently of
the mechanism under test. Nothing here claims physical coverage, isolation,
identity or producer independence beyond distinct retained labels.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import hardware_inventory_closure as closure
from verifier.domains.inventory import get_slot


MEMBERS = ["rack-1/slot-1", "rack-1/slot-2", "rack-1/slot-3"]
AUTHOR = "inventory-bot"


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def record(evidence_id: str, producer: str, identity_key: str, covers: list[str]) -> dict:
    return {"evidence_id": evidence_id, "producer": producer,
            "identity_key": identity_key, "covers": list(covers)}


def base_inventory() -> dict:
    return {"author": AUTHOR, "entries": [
        {"entry_id": "entry-1", "identity_key": "SERIAL-A",
         "covers": ["rack-1/slot-1"],
         "evidence": [record("ev-1", "bmc-scan", "SERIAL-A", ["rack-1/slot-1"])]},
        {"entry_id": "entry-2", "identity_key": "SERIAL-B",
         "covers": ["rack-1/slot-2", "rack-1/slot-3"],
         "evidence": [
             record("ev-2", AUTHOR, "SERIAL-B", ["rack-1/slot-2", "rack-1/slot-3"]),
             record("ev-3", "site-audit", "SERIAL-B", ["rack-1/slot-2", "rack-1/slot-3"]),
         ]},
    ]}


def oracle(members: list[str], inventory: dict, selected_members: list[str] | None = None) -> str:
    """FAIL only for what no further independent record could repair."""
    if selected_members is not None and selected_members != members:
        return "FAIL"
    if not members:
        return "UNKNOWN"
    entries = inventory["entries"]
    if len({entry["entry_id"] for entry in entries}) != len(entries):
        return "FAIL"
    evidence_ids = [row["evidence_id"] for entry in entries for row in entry["evidence"]]
    if len(set(evidence_ids)) != len(evidence_ids):
        return "FAIL"
    keys = [entry["identity_key"] for entry in entries]
    if len(set(keys)) != len(keys):
        return "FAIL"
    covered: set[str] = set()
    for entry in entries:
        if not set(entry["covers"]) <= set(members):
            return "FAIL"
        covered |= set(entry["covers"])
        for row in entry["evidence"]:
            if row["identity_key"] != entry["identity_key"] or row["covers"] != entry["covers"]:
                return "FAIL"
    if covered != set(members):
        return "FAIL"
    independent = all(any(row["producer"] != inventory["author"] for row in entry["evidence"])
                      for entry in entries)
    return "PASS" if independent else "UNKNOWN"


def selected(members: list[str] | None = None, inventory: dict | None = None, *,
             selected_members: list[str] | None = None, include_inputs: bool = True,
             limits: dict | None = None, subject_id: str = "hardware-a"):
    members = list(MEMBERS) if members is None else members
    inventory = base_inventory() if inventory is None else inventory
    selected_members = members if selected_members is None else selected_members
    payload = {"scope": closure.SUBJECT_SCOPE, "inventory_digest": digest(inventory)}
    subject = NamespaceObject.create("hardware-a", "HARDWARE", payload)
    sibling = NamespaceObject.create("hardware-b", "HARDWARE", payload)
    objects = [subject, sibling]
    evidence = {"schema_version": closure.EVIDENCE_VERSION,
                "objects": [item.to_dict() for item in objects],
                "inputs": {"members": members, "inventory": inventory}
                if include_inputs else None}
    by_id = {item.object_id: item for item in objects}
    policy = closure.hardware_inventory_closure_policy(trust_roots=["selected-scope"])
    request = closure.hardware_inventory_closure_request(
        subject_id=subject_id, object_digest=by_id[subject_id].digest,
        collection_digest=composition_digest(objects),
        members_digest=digest(selected_members), evidence_ref=digest(evidence),
        policy=policy, limits=limits)
    return request, policy, canonical_bytes(evidence)


def replay(request: dict, policy: dict, evidence: bytes):
    certificate = closure.build_hardware_inventory_closure_certificate(
        request, evidence, policy=policy)
    result = closure.recheck_hardware_inventory_closure_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def verdict(members=None, inventory=None, **kwargs) -> dict:
    return replay(*selected(members, inventory, **kwargs))[1]


SCOPE_FIELD = "independent_inventory_record_closure"
EXCLUDED = ("complete_physical_coverage", "resource_isolation",
            "physical_identity_authenticity", "producer_independence_authenticity",
            "evidence_authenticity", "legacy_hardware_closure",
            "hardware_closure_tier_conformance", "object_profile_conformance",
            "privacy", "consent", "governance", "security")


def test_inventory_selects_inventory_closure_for_hardware_closure_slot():
    slot = get_slot("HARDWARE", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == closure.COORDINATE == "HARDWARE-4.1"
    assert slot.mechanized_route["artifact_coordinate"] == "HARDWARE-4.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.hardware_inventory_closure."
        "recheck_hardware_inventory_closure_certificate")
    assert slot.mechanized_route["resulting_evidence"] == closure.CERTIFICATE_VERSION


def test_nonaliasing_covered_independent_inventory_passes_and_rechecks():
    assert oracle(MEMBERS, base_inventory()) == "PASS"
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", result["evaluation"]
    assert result[SCOPE_FIELD] == "PASS"
    for field in EXCLUDED:
        assert result[field] == "NOT_ESTABLISHED", field
    assert json.loads(certificate.decode("utf-8"))["result"] == result
    again = closure.recheck_hardware_inventory_closure_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert again == result
    assert certificate == closure.build_hardware_inventory_closure_certificate(
        request, evidence, policy=policy)


def _strip(keep) -> dict:
    inventory = base_inventory()
    for entry in inventory["entries"]:
        entry["evidence"] = [row for row in entry["evidence"] if keep(entry, row)]
    return inventory


def _author_only() -> dict:
    """Every entry keeps consistent records, and every record is the author's own."""
    inventory = base_inventory()
    for entry in inventory["entries"]:
        entry["evidence"] = [record("by-author-" + entry["entry_id"], AUTHOR,
                                    entry["identity_key"], entry["covers"])]
    return inventory


DECLARATION_ONLY = {
    "no_evidence_records": _strip(lambda entry, row: False),
    "only_author_produced_records": _author_only(),
    "one_entry_without_independent_record": _strip(
        lambda entry, row: entry["entry_id"] != "entry-1"),
}


@pytest.mark.parametrize("name", sorted(DECLARATION_ONLY))
def test_retained_inventory_alone_leaves_closure_unknown(name):
    inventory = DECLARATION_ONLY[name]
    assert oracle(MEMBERS, inventory) == "UNKNOWN"
    result = verdict(inventory=inventory)
    assert result["status"] == "UNKNOWN", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"
    for field in EXCLUDED:
        assert result[field] == "NOT_ESTABLISHED", field


def test_absent_inputs_and_empty_selected_scope_remain_unknown():
    assert verdict(include_inputs=False)["status"] == "UNKNOWN"
    empty = {"author": AUTHOR, "entries": []}
    assert oracle([], empty) == "UNKNOWN"
    assert verdict([], empty)["status"] == "UNKNOWN"


def _edit(change) -> dict:
    inventory = base_inventory()
    change(inventory["entries"])
    return inventory


def _alias(entries):
    entries[1]["identity_key"] = "SERIAL-A"
    for row in entries[1]["evidence"]:
        row["identity_key"] = "SERIAL-A"


def _uncover(entries):
    entries[1]["covers"] = ["rack-1/slot-2"]
    for row in entries[1]["evidence"]:
        row["covers"] = ["rack-1/slot-2"]


def _outside(entries):
    entries[0]["covers"] = ["rack-1/slot-1", "rack-2/slot-1"]
    for row in entries[0]["evidence"]:
        row["covers"] = ["rack-1/slot-1", "rack-2/slot-1"]


def _contradict_identity(entries):
    entries[1]["evidence"][1]["identity_key"] = "SERIAL-C"


def _contradict_coverage(entries):
    entries[1]["evidence"][1]["covers"] = ["rack-1/slot-2"]


def _duplicate_entry(entries):
    entries[1]["entry_id"] = "entry-1"


def _duplicate_evidence(entries):
    entries[1]["evidence"][1]["evidence_id"] = "ev-1"


def _alias_without_evidence(entries):
    _alias(entries)
    for entry in entries:
        entry["evidence"] = []


MUTANTS = {
    "two_entries_alias_one_identity_key": _edit(_alias),
    "selected_member_uncovered": _edit(_uncover),
    "entry_covers_member_outside_selected_scope": _edit(_outside),
    "independent_record_contradicts_identity": _edit(_contradict_identity),
    "independent_record_contradicts_coverage": _edit(_contradict_coverage),
    "duplicate_entry_identifier": _edit(_duplicate_entry),
    "duplicate_evidence_identifier": _edit(_duplicate_evidence),
    "self_declared_alias_without_any_evidence": _edit(_alias_without_evidence),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutants_fail_with_consistent_commitments(name):
    inventory = MUTANTS[name]
    assert oracle(MEMBERS, inventory) == "FAIL"
    result = verdict(inventory=inventory)
    assert result["status"] == "FAIL", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"


def test_scope_is_externally_selected_not_chosen_by_the_inventory():
    narrowed = ["rack-1/slot-1", "rack-1/slot-2"]
    assert oracle(MEMBERS, base_inventory(), selected_members=narrowed) == "FAIL"
    assert verdict(selected_members=narrowed)["status"] == "FAIL"
    widened = MEMBERS + ["rack-1/slot-4"]
    assert oracle(widened, base_inventory()) == "FAIL"
    assert verdict(widened)["status"] == "FAIL"


@pytest.mark.parametrize("limits", [
    {"max_members": 2}, {"max_entries": 1}, {"max_evidence_records": 2},
    {"max_operations": 8},
])
def test_exhausted_budget_remains_unknown(limits):
    result = verdict(limits=limits)
    assert result["status"] == "UNKNOWN", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("fraction", [0.0, 0.25, 0.5, 0.75, 0.999])
def test_one_flipped_certificate_bit_is_rejected(fraction):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    tampered = bytearray(certificate)
    tampered[int(len(tampered) * fraction)] ^= 0x01
    with pytest.raises(closure.HardwareInventoryClosureError):
        closure.recheck_hardware_inventory_closure_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_wrong_subject_scope_policy_or_evidence_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    for other in (selected(subject_id="hardware-b")[0],
                  selected(selected_members=MEMBERS[:2])[0]):
        with pytest.raises(closure.HardwareInventoryClosureError):
            closure.recheck_hardware_inventory_closure_certificate(
                certificate, expected_request=other, policy=policy)
    other_policy = closure.hardware_inventory_closure_policy(trust_roots=["other-root"])
    with pytest.raises(closure.HardwareInventoryClosureError):
        closure.recheck_hardware_inventory_closure_certificate(
            certificate, expected_request=request, policy=other_policy)
    with pytest.raises(closure.HardwareInventoryClosureError):
        closure.build_hardware_inventory_closure_certificate(
            request, evidence + b" ", policy=policy)
    substituted = deepcopy(request)
    substituted["members_digest"] = "sha256:" + "0" * 64
    with pytest.raises(closure.HardwareInventoryClosureError):
        closure.recheck_hardware_inventory_closure_certificate(
            certificate, expected_request=substituted, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(closure.HardwareInventoryClosureError):
        closure.recheck_hardware_inventory_closure_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_public_route_replays_pass_and_refuses_other_kind():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=closure.SEMANTIC_VERSION,
        objective=closure.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["resource_isolation"] == "NOT_ESTABLISHED"
    assert report["native_result"]["complete_physical_coverage"] == "NOT_ESTABLISHED"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=closure.SEMANTIC_VERSION,
            objective=closure.COORDINATE, represented_kind="MODEL",
            expected_request=request, policy=policy)


def test_retained_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("HARDWARE", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/hardware_inventory_closure.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_HARDWARE_INVENTORY_CLOSURE.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(closure.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        closure.recheck_hardware_inventory_closure_certificate(
            certificate, expected_request=request, policy=policy)
