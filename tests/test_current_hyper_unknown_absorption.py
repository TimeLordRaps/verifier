"""Selected HYPER-2.3 UNKNOWN absorption over replayed direct-operand verdicts.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Extents are bytes, instants are microseconds and
counts are dimensionless. Every expected composed verdict is computed by a
separate precedence table, not by the checker's own fold.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import hyper_unknown_absorption as absorption
from verifier.domains.contracts import space_layout, time_order
from verifier.domains.inventory import get_slot


GOOD_PARTS = [{"id": "left", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
              {"id": "right", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8}]
OVERLAP_PARTS = [{"id": "a", "start_byte": 0, "end_byte": 24, "alignment_bytes": 8},
                 {"id": "b", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8}]
GOOD_SAMPLES = [{"id": "a", "at_us": 2}, {"id": "b", "at_us": 7}]
LATE_SAMPLES = [{"id": "a", "at_us": 2}, {"id": "b", "at_us": 12}]
STATUSES = ("PASS", "FAIL", "UNKNOWN")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def space_record(object_id: str = "space-a", parts=GOOD_PARTS, **extra):
    return NamespaceObject.create(object_id, "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 32, "partitions_digest": digest(parts), **extra})


def time_record(object_id: str = "time-b", samples=GOOD_SAMPLES):
    return NamespaceObject.create(object_id, "TIME", {
        "scope": "retained-declared-clock-order", "clock": "test:clock",
        "unit": "microsecond", "span_start_us": 0, "span_end_us": 10,
        "samples_digest": digest(samples)})


def space_child(record, parts, *, retained: bool = True) -> dict:
    evidence = canonical_bytes({"schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [record.to_dict()], "inputs": {"partitions": parts}})
    policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    request = space_layout.space_layout_request(
        subject_id=record.object_id, object_digest=record.digest,
        collection_digest=composition_digest([record]),
        evidence_ref=raw(evidence), policy=policy)
    certificate = space_layout.build_space_layout_certificate(
        request, evidence if retained else None, policy=policy)
    return {"coordinate": space_layout.COORDINATE, "request": request,
            "policy": policy, "certificate": certificate}


def time_child(record, samples, *, retained: bool = True) -> dict:
    evidence = canonical_bytes({"schema_version": time_order.EVIDENCE_VERSION,
        "objects": [record.to_dict()],
        "inputs": {"samples": samples} if retained else None})
    policy = time_order.time_order_policy(trust_roots=["clock-root"])
    request = time_order.time_order_request(
        subject_id=record.object_id, object_digest=record.digest,
        collection_digest=composition_digest([record]),
        evidence_ref=raw(evidence), policy=policy)
    certificate = time_order.build_time_order_certificate(request, evidence, policy=policy)
    return {"coordinate": time_order.COORDINATE, "request": request,
            "policy": policy, "certificate": certificate}


def hyper(operands=None, payload=None):
    return NamespaceObject.create("h", "HYPER", payload or {"label": "place-and-clock"},
        operands or {"clock": ["time-b"], "place": ["space-a"]})


def scenario(space: str = "PASS", clock: str = "PASS"):
    parts = OVERLAP_PARTS if space == "FAIL" else GOOD_PARTS
    samples = LATE_SAMPLES if clock == "FAIL" else GOOD_SAMPLES
    place, moment = space_record(parts=parts), time_record(samples=samples)
    children = {"space-a": space_child(place, parts, retained=space != "UNKNOWN"),
                "time-b": time_child(moment, samples, retained=clock != "UNKNOWN")}
    root = hyper()
    return [root, place, moment], root, children


def compose(records, root, children: dict, *, limits=None):
    ordered = sorted(children.items())
    selections = [{"target": target, "coordinate": child["coordinate"],
                   "request_digest": digest(child["request"]),
                   "policy_digest": digest(child["policy"]),
                   "certificate_digest": raw(child["certificate"])}
                  for target, child in ordered]
    evidence = canonical_bytes({"schema_version": absorption.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(records, key=lambda x: x.object_id)],
        "children": [{"target": target, "coordinate": child["coordinate"],
                      "request": child["request"], "policy": child["policy"],
                      "certificate": base64.b64encode(child["certificate"]).decode("ascii")}
                     for target, child in ordered]})
    policy = absorption.hyper_unknown_absorption_policy(trust_roots=["hyper-root"])
    request = absorption.hyper_unknown_absorption_request(
        subject_id=root.object_id, object_digest=root.digest,
        collection_digest=composition_digest(records), child_selections=selections,
        evidence_ref=raw(evidence), policy=policy, limits=limits)
    return request, policy, evidence


def run(request, policy, evidence):
    certificate = absorption.build_hyper_unknown_absorption_certificate(
        request, evidence, policy=policy)
    result = absorption.recheck_hyper_unknown_absorption_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle(statuses) -> str:
    """Independent fold: the highest-precedence verdict under the row's rule."""
    precedence = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}
    return max(statuses, key=precedence.__getitem__) if statuses else "UNKNOWN"


def child_status(child: dict) -> str:
    return json.loads(child["certificate"])["result"]["status"]


def test_inventory_selects_unknown_absorption_for_hyper_dynamics():
    slot = get_slot("HYPER", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "HYPER-2.3"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.hyper_unknown_absorption."
        "recheck_hyper_unknown_absorption_certificate")


def test_all_passing_operands_compose_pass_from_decoded_bytes():
    records, root, children = scenario()
    request, policy, evidence = compose(records, root, children)
    certificate, _ = run(request, policy, evidence)
    decoded = json.loads(certificate.decode("utf-8"))
    assert canonical_bytes(decoded) == certificate
    result = absorption.recheck_hyper_unknown_absorption_certificate(
        canonical_bytes(decoded), expected_request=request, policy=policy)
    assert result["status"] == "PASS" == oracle([child_status(c) for c in children.values()])
    assert result["coordinate"] == "HYPER-2.3" and result["object_kind"] == "HYPER"
    assert result["operand_verdict_composition"] == "PASS"
    for field in ("hyper_dynamics_tier", "strength_total_order",
                  "strength_non_increase", "recomposition", "associativity",
                  "depth_propagation", "object_profile_conformance",
                  "authority", "privacy", "consent", "governance", "security"):
        assert result[field] == "NOT_ESTABLISHED", field
    observed = result["evaluation"]["observations"]["operand_statuses"]
    assert observed == {"space-a": "PASS", "time-b": "PASS"}


@pytest.mark.parametrize("space,clock", list(itertools.product(STATUSES, repeat=2)))
def test_composed_verdict_matches_independent_fold(space, clock):
    records, root, children = scenario(space, clock)
    assert [child_status(children[k]) for k in ("space-a", "time-b")] == [space, clock]
    request, policy, evidence = compose(records, root, children)
    result = run(request, policy, evidence)[1]
    assert result["status"] == oracle([space, clock])
    assert result["evaluation"]["observations"]["operand_statuses"] == {
        "space-a": space, "time-b": clock}
    if result["status"] != "PASS":
        assert result["operand_verdict_composition"] == "NOT_ESTABLISHED"


def test_one_unknown_operand_absorbs_a_failing_operand():
    records, root, children = scenario("FAIL", "UNKNOWN")
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "UNKNOWN"
    assert "UNKNOWN" in result["evaluation"]["details"]


def test_unselected_operand_is_unknown_not_pass():
    records, root, children = scenario()
    del children["time-b"]
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "UNKNOWN" == oracle(["PASS", "UNKNOWN"])
    assert result["evaluation"]["observations"]["operand_statuses"]["time-b"] == "UNKNOWN"
    result = run(*compose(records, root, {}))[1]
    assert result["status"] == "UNKNOWN"


def test_wrong_subject_child_fails_before_replay():
    records, root, children = scenario()
    stranger = space_record("space-z")
    children["space-a"] = space_child(stranger, GOOD_PARTS)
    assert child_status(children["space-a"]) == "PASS"
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "FAIL"
    assert result["evaluation"]["observations"] == {}


def test_stale_operand_digest_fails():
    records, root, children = scenario()
    changed = space_record(note="edited after the child was selected")
    records = [root, changed, records[2]]
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "FAIL"


def test_selection_naming_a_non_operand_fails():
    records, root, children = scenario()
    outsider = space_record("space-x")
    records.append(outsider)
    children["space-x"] = space_child(outsider, GOOD_PARTS)
    assert child_status(children["space-x"]) == "PASS"
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "FAIL"


def test_rehashed_child_verdict_fails():
    records, root, children = scenario("FAIL", "PASS")
    forged = json.loads(children["space-a"]["certificate"])
    forged["result"]["status"] = "PASS"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    children["space-a"]["certificate"] = canonical_bytes(forged)
    result = run(*compose(records, root, children))[1]
    assert result["status"] == "FAIL"
    assert "does not replay" in result["evaluation"]["details"]


def test_unrelated_unselected_record_does_not_change_the_verdict():
    records, root, children = scenario()
    records.append(space_record("space-unrelated"))
    assert run(*compose(records, root, children))[1]["status"] == "PASS"


def test_budget_exhaustion_is_unknown():
    records, root, children = scenario()
    result = run(*compose(records, root, children, limits={"max_operations": 8}))[1]
    assert result["status"] == "UNKNOWN"
    assert result["operand_verdict_composition"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("position", [0.1, 0.5, 0.9])
def test_one_bit_flip_in_certificate_is_rejected(position):
    records, root, children = scenario()
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    flipped = bytearray(certificate)
    flipped[int(len(flipped) * position)] ^= 0x01
    with pytest.raises(absorption.HyperUnknownAbsorptionError):
        absorption.recheck_hyper_unknown_absorption_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_or_policy_is_refused():
    records, root, children = scenario()
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    other_subject = deepcopy(request)
    other_subject["subject_id"] = "space-a"
    with pytest.raises(absorption.HyperUnknownAbsorptionError):
        absorption.recheck_hyper_unknown_absorption_certificate(
            certificate, expected_request=other_subject, policy=policy)
    other_selection = deepcopy(request)
    other_selection["child_selections"] = other_selection["child_selections"][:1]
    with pytest.raises(absorption.HyperUnknownAbsorptionError):
        absorption.recheck_hyper_unknown_absorption_certificate(
            certificate, expected_request=other_selection, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(absorption.HyperUnknownAbsorptionError):
        absorption.recheck_hyper_unknown_absorption_certificate(
            certificate, expected_request=request, policy=other_policy)


def test_public_route_dispatch_reaches_pass():
    records, root, children = scenario()
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=absorption.SEMANTIC_VERSION,
        objective=absorption.COORDINATE, represented_kind="HYPER",
        expected_request=request, policy=policy)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["operand_verdict_composition"] == "PASS"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=absorption.SEMANTIC_VERSION,
            objective=absorption.COORDINATE, represented_kind="SPACE",
            expected_request=request, policy=policy)


def test_retained_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    records, root, children = scenario()
    certificate = run(*compose(records, root, children))[0]
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("HYPER", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/hyper_unknown_absorption.py",
    "domains/contracts/current_object_routes.py",
    "standard/CURRENT_HYPER_UNKNOWN_ABSORPTION.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    records, root, children = scenario()
    request, policy, evidence = compose(records, root, children)
    certificate = run(request, policy, evidence)[0]
    target = Path(absorption.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        absorption.recheck_hyper_unknown_absorption_certificate(
            certificate, expected_request=request, policy=policy)
