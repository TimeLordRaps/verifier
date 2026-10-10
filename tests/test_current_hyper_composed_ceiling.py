"""Selected HYPER-3.1 composed ceiling: the weakest operand bound governs.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Tiers, depths and counts are dimensionless;
extents are bytes and instants are microseconds. The expected ceiling is an
independently computed minimum over string-parsed child tiers.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import hyper_composed_ceiling as ceiling
from verifier.domains.contracts import space_layout, time_order, typed_facets
from verifier.domains.inventory import get_slot


GOOD_PARTS = [{"id": "left", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
              {"id": "right", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8}]
GOOD_SAMPLES = [{"id": "a", "at_us": 2}, {"id": "b", "at_us": 7}]
LATE_SAMPLES = [{"id": "a", "at_us": 2}, {"id": "b", "at_us": 12}]


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def space_record(object_id: str = "space-a", **extra):
    return NamespaceObject.create(object_id, "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 32, "partitions_digest": digest(GOOD_PARTS), **extra})


def time_record(object_id: str = "time-b", samples=GOOD_SAMPLES):
    return NamespaceObject.create(object_id, "TIME", {
        "scope": "retained-declared-clock-order", "clock": "test:clock",
        "unit": "microsecond", "span_start_us": 0, "span_end_us": 10,
        "samples_digest": digest(samples)})


def facets_child(record) -> dict:
    kind = record.kind.value
    evidence = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION,
                                "objects": [record.to_dict()]})
    policy = typed_facets.typed_facets_policy(trust_roots=["facets-root"])
    request = typed_facets.typed_facets_request(
        object_kind=kind, subject_id=record.object_id, object_digest=record.digest,
        collection_digest=composition_digest([record]), evidence_ref=raw(evidence),
        policy=policy)
    return {"coordinate": typed_facets.coordinate(kind), "request": request, "policy": policy,
            "certificate": typed_facets.build_typed_facets_certificate(
                request, evidence, policy=policy)}


def space_child(record) -> dict:
    evidence = canonical_bytes({"schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [record.to_dict()], "inputs": {"partitions": GOOD_PARTS}})
    policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    request = space_layout.space_layout_request(
        subject_id=record.object_id, object_digest=record.digest,
        collection_digest=composition_digest([record]),
        evidence_ref=raw(evidence), policy=policy)
    return {"coordinate": space_layout.COORDINATE, "request": request, "policy": policy,
            "certificate": space_layout.build_space_layout_certificate(
                request, evidence, policy=policy)}


def time_child(record, samples=GOOD_SAMPLES, *, retained: bool = True) -> dict:
    evidence = canonical_bytes({"schema_version": time_order.EVIDENCE_VERSION,
        "objects": [record.to_dict()],
        "inputs": {"samples": samples} if retained else None})
    policy = time_order.time_order_policy(trust_roots=["clock-root"])
    request = time_order.time_order_request(
        subject_id=record.object_id, object_digest=record.digest,
        collection_digest=composition_digest([record]),
        evidence_ref=raw(evidence), policy=policy)
    return {"coordinate": time_order.COORDINATE, "request": request, "policy": policy,
            "certificate": time_order.build_time_order_certificate(
                request, evidence, policy=policy)}


def hyper(declared=1, operands=None, **extra):
    payload = {"label": "place-and-clock", **extra}
    if declared is not None:
        payload["declared_depth"] = declared
    return NamespaceObject.create("h", "HYPER", payload,
                                  operands or {"clock": ["time-b"], "place": ["space-a"]})


def scenario(declared=1, *, operands=None, clock_samples=GOOD_SAMPLES,
             clock_retained=True, space_facets=True):
    """space-a selects tiers 1 and 3 (prefix 1); time-b selects tiers 1 and 2 (prefix 2)."""
    place, moment = space_record(), time_record(samples=clock_samples)
    children = [("space-a", space_child(place)),
                ("time-b", facets_child(moment)),
                ("time-b", time_child(moment, clock_samples, retained=clock_retained))]
    if space_facets:
        children.insert(0, ("space-a", facets_child(place)))
    root = hyper(declared, operands)
    return [root, place, moment], root, children


def tier_of(coordinate: str) -> int:
    return int(coordinate.split("-", 1)[1].split(".", 1)[0])


def oracle_ceiling(root, children) -> int:
    """Independent minimum: count up from tier one while a PASS child exists."""
    operands = {target for targets in root.to_dict()["operands"].values() for target in targets}
    prefixes = []
    for operand in sorted(operands):
        passed = {tier_of(child["coordinate"]) for target, child in children
                  if target == operand
                  and json.loads(child["certificate"])["result"]["status"] == "PASS"}
        depth = 0
        while depth + 1 in passed:
            depth += 1
        prefixes.append(depth)
    return min(prefixes)


def compose(records, root, children, *, limits=None):
    ordered = sorted(children, key=lambda row: (row[0], tier_of(row[1]["coordinate"])))
    selections = [{"target": target, "coordinate": child["coordinate"],
                   "request_digest": digest(child["request"]),
                   "policy_digest": digest(child["policy"]),
                   "certificate_digest": raw(child["certificate"])}
                  for target, child in ordered]
    evidence = canonical_bytes({"schema_version": ceiling.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(records, key=lambda x: x.object_id)],
        "children": [{"target": target, "coordinate": child["coordinate"],
                      "request": child["request"], "policy": child["policy"],
                      "certificate": base64.b64encode(child["certificate"]).decode("ascii")}
                     for target, child in ordered]})
    policy = ceiling.hyper_composed_ceiling_policy(trust_roots=["hyper-root"])
    request = ceiling.hyper_composed_ceiling_request(
        subject_id=root.object_id, object_digest=root.digest,
        collection_digest=composition_digest(records), child_selections=selections,
        evidence_ref=raw(evidence), policy=policy, limits=limits)
    return request, policy, evidence


def run(request, policy, evidence):
    certificate = ceiling.build_hyper_composed_ceiling_certificate(
        request, evidence, policy=policy)
    result = ceiling.recheck_hyper_composed_ceiling_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def observed(result) -> dict:
    return result["evaluation"]["observations"]


def test_inventory_selects_composed_ceiling_for_hyper_statics():
    slot = get_slot("HYPER", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "HYPER-3.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.hyper_composed_ceiling."
        "recheck_hyper_composed_ceiling_certificate")


def test_declaration_at_weakest_operand_passes_from_decoded_bytes():
    records, root, children = scenario(1)
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    decoded = json.loads(certificate.decode("utf-8"))
    assert canonical_bytes(decoded) == certificate
    result = ceiling.recheck_hyper_composed_ceiling_certificate(
        canonical_bytes(decoded), expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["coordinate"] == "HYPER-3.1" and result["object_kind"] == "HYPER"
    assert result["composed_ceiling_bound"] == "PASS"
    assert observed(result)["composed_ceiling"] == oracle_ceiling(root, children) == 1
    assert observed(result)["operand_prefixes"] == {"space-a": 1, "time-b": 2}
    for field in ("hyper_statics_tier", "substrate_recurrence", "decider_exteriority",
                  "manufacture_impossibility", "level_independence",
                  "object_profile_depth", "object_profile_conformance",
                  "authority", "privacy", "consent", "governance", "security"):
        assert result[field] == "NOT_ESTABLISHED", field


@pytest.mark.parametrize("declared", [2, 3, 9])
def test_declared_ceiling_above_weakest_operand_cannot_raise_the_result(declared):
    records, root, children = scenario(declared)
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "FAIL"
    assert result["composed_ceiling_bound"] == "NOT_ESTABLISHED"
    assert observed(result)["composed_ceiling"] == oracle_ceiling(root, children) == 1
    assert observed(result)["declared_depth"] == declared


def test_declaration_below_the_ceiling_does_not_lower_it():
    records, root, children = scenario(0)
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "PASS"
    assert observed(result)["composed_ceiling"] == oracle_ceiling(root, children) == 1


def test_tier_after_a_gap_is_not_counted():
    records, root, children = scenario(1, space_facets=False)
    assert oracle_ceiling(root, children) == 0
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "FAIL"
    assert observed(result)["operand_prefixes"]["space-a"] == 0
    records, root, children = scenario(0, space_facets=False)
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "PASS" and observed(result)["composed_ceiling"] == 0


@pytest.mark.parametrize("operands", [
    {"place": ["space-a"], "clock": ["time-b"]},
    {"first": ["time-b"], "second": ["space-a"]},
    {"both": ["time-b", "space-a"]},
    {"again": ["space-a"], "both": ["space-a", "time-b"]},
])
def test_operand_roles_and_order_do_not_change_the_ceiling(operands):
    for declared, expected in ((1, "PASS"), (2, "FAIL")):
        records, root, children = scenario(declared, operands=operands)
        result = run(*compose(records, root, children))[1]
        assert result["status"] == expected
        assert observed(result)["composed_ceiling"] == oracle_ceiling(root, children) == 1


def test_selected_child_fail_makes_the_parent_fail():
    records, root, children = scenario(1, clock_samples=LATE_SAMPLES)
    assert json.loads(children[-1][1]["certificate"])["result"]["status"] == "FAIL"
    assert run(*compose(records, root, children))[1]["status"] == "FAIL"


def test_selected_child_unknown_makes_the_parent_unknown():
    records, root, children = scenario(1, clock_retained=False)
    assert json.loads(children[-1][1]["certificate"])["result"]["status"] == "UNKNOWN"
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "UNKNOWN"
    assert result["composed_ceiling_bound"] == "NOT_ESTABLISHED"


def test_wrong_subject_child_fails():
    records, root, children = scenario(1)
    children[0] = ("space-a", facets_child(space_record("space-z")))
    assert run(*compose(records, root, children))[1]["status"] == "FAIL"


def test_stale_operand_digest_fails():
    records, root, children = scenario(1)
    records = [root, space_record(note="edited after selection"), records[2]]
    assert run(*compose(records, root, children))[1]["status"] == "FAIL"


def test_selection_naming_a_non_operand_fails():
    records, root, children = scenario(1)
    outsider = space_record("space-x")
    records.append(outsider)
    children.append(("space-x", facets_child(outsider)))
    assert run(*compose(records, root, children))[1]["status"] == "FAIL"


@pytest.mark.parametrize("declared", ["1", -1, 1.0, True])
def test_malformed_declaration_fails(declared):
    records, root, children = scenario(declared)
    assert run(*compose(records, root, children))[1]["status"] == "FAIL"


def test_absent_declaration_is_unknown():
    records, root, children = scenario(None)
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "UNKNOWN"


def test_budget_exhaustion_is_unknown():
    records, root, children = scenario(1)
    result = run(*compose(records, root, children, limits={"max_operations": 8}))[1]
    assert result["status"] == "UNKNOWN"


@pytest.mark.parametrize("position", [0.1, 0.5, 0.9])
def test_one_bit_flip_in_certificate_is_rejected(position):
    records, root, children = scenario(1)
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    flipped = bytearray(certificate)
    flipped[int(len(flipped) * position)] ^= 0x01
    with pytest.raises(ceiling.HyperComposedCeilingError):
        ceiling.recheck_hyper_composed_ceiling_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_or_policy_is_refused():
    records, root, children = scenario(1)
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    other_subject = deepcopy(request)
    other_subject["object_digest"] = hyper(2).digest
    with pytest.raises(ceiling.HyperComposedCeilingError):
        ceiling.recheck_hyper_composed_ceiling_certificate(
            certificate, expected_request=other_subject, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(ceiling.HyperComposedCeilingError):
        ceiling.recheck_hyper_composed_ceiling_certificate(
            certificate, expected_request=request, policy=other_policy)
    unsorted = deepcopy(request)
    unsorted["child_selections"] = list(reversed(unsorted["child_selections"]))
    with pytest.raises(ceiling.HyperComposedCeilingError):
        ceiling.recheck_hyper_composed_ceiling_certificate(
            certificate, expected_request=unsorted, policy=policy)


def test_public_route_dispatch_reaches_pass():
    records, root, children = scenario(1)
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=ceiling.SEMANTIC_VERSION,
        objective=ceiling.COORDINATE, represented_kind="HYPER",
        expected_request=request, policy=policy)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["composed_ceiling_bound"] == "PASS"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=ceiling.SEMANTIC_VERSION,
            objective=ceiling.COORDINATE, represented_kind="TIME",
            expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/hyper_composed_ceiling.py",
    "domains/contracts/hyper_unknown_absorption.py",
    "standard/CURRENT_HYPER_COMPOSED_CEILING.md",
    "standard/LADDER.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    records, root, children = scenario(1)
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    target = Path(ceiling.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        ceiling.recheck_hyper_composed_ceiling_certificate(
            certificate, expected_request=request, policy=policy)
