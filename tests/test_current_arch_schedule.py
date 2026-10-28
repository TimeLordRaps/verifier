"""Current ARCH-2.1: retained execution order over a replayed ARCH-3.1 graph.

Verifier Standard (VSTD); computational model architecture (ARCH); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Tensor
dimensions and schedule positions are dimensionless. The oracle below simulates
execution by readiness, independently of the checker's position comparison.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from itertools import islice, permutations
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import arch_shapes, arch_schedule
from verifier.domains.inventory import get_slot


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def graph() -> dict:
    return {"nodes": [
        {"name": "x", "op": "INPUT", "inputs": [], "shape": [2, 3]},
        {"name": "w", "op": "INPUT", "inputs": [], "shape": [3, 4]},
        {"name": "product", "op": "MATMUL", "inputs": ["x", "w"], "shape": [2, 4]},
        {"name": "bias", "op": "INPUT", "inputs": [], "shape": [2, 4]},
        {"name": "sum", "op": "ADD", "inputs": ["product", "bias"], "shape": [2, 4]},
        {"name": "out", "op": "RELU", "inputs": ["sum"], "shape": [2, 4]},
    ], "outputs": ["out"]}


# A valid schedule that differs from the retained node order.
VALID = ["bias", "w", "x", "product", "sum", "out"]


def executes(schedule: list, retained: dict) -> bool:
    """Independent oracle: run each entry only when every input already ran."""
    rows = {row["name"]: row for row in retained["nodes"]}
    ran: list = []
    for name in schedule:
        if name not in rows or name in ran:
            return False
        if not all(source in ran for source in rows[name]["inputs"]):
            return False
        ran.append(name)
    return sorted(ran) == sorted(rows)


def child(retained: dict | None = None, *, include_graph: bool = True):
    retained = deepcopy(graph() if retained is None else retained)
    subject = NamespaceObject.create("arch-root", "ARCH", {
        "scope": "retained-static-tensor-graph", "graph_digest": digest(retained)})
    evidence = canonical_bytes({
        "schema_version": arch_shapes.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"graph": retained} if include_graph else None})
    policy = arch_shapes.arch_shapes_policy(trust_roots=["test:child-graph"])
    request = arch_shapes.arch_shapes_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    certificate = arch_shapes.build_arch_shapes_certificate(
        request, evidence, policy=policy)
    return subject, request, policy, certificate


def selected(schedule: list | None = None, *, retained: dict | None = None,
             include_graph: bool = True, include_bundle: bool = True,
             built=None, **limits: int):
    schedule = list(VALID if schedule is None else schedule)
    subject, child_request, child_policy, child_certificate = (
        built or child(retained, include_graph=include_graph))
    evidence = canonical_bytes({
        "schema_version": arch_schedule.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "schedule": schedule}) if include_bundle else None
    policy = arch_schedule.arch_schedule_policy(trust_roots=["test:schedule"])
    request = arch_schedule.arch_schedule_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),
        child_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        schedule_digest=digest(schedule),
        evidence_ref=digest(json.loads(evidence)) if evidence is not None
        else "sha256:" + "0" * 64,
        policy=policy, limits=limits or None)
    return request, policy, evidence, child_certificate


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = arch_schedule.build_arch_schedule_certificate(
        request, evidence, policy=policy)
    result = arch_schedule.recheck_arch_schedule_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_inventory_selects_this_dynamics_objective():
    slot = get_slot("ARCH", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "ARCH-2.1"
    assert slot.mechanized_route["artifact_coordinate"] == "ARCH-2.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.arch_schedule.recheck_arch_schedule_certificate")


def test_reordered_valid_schedule_passes_and_rechecks_from_bytes():
    assert VALID != [row["name"] for row in graph()["nodes"]]
    assert executes(VALID, graph())
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["execution_order"] == "PASS"
    for field in ("whole_arch_dynamics", "object_profile_conformance",
                  "layer_fusion", "dynamic_routing", "graph_compilation",
                  "runtime_execution", "numerical_equivalence"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    assert decoded["result"] == result
    assert certificate == arch_schedule.build_arch_schedule_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("label,schedule", [
    ("omitted-node", ["bias", "w", "x", "product", "out"]),
    ("repeated-node", ["bias", "w", "x", "product", "sum", "sum", "out"]),
    ("producer-after-consumer", ["bias", "w", "product", "x", "sum", "out"]),
    ("fused-name-outside-graph", ["bias", "w", "x", "product", "sum_relu", "out"]),
    ("reverse-order", list(reversed(VALID))),
])
def test_schedule_counterexamples_fail(label, schedule):
    assert not executes(schedule, graph()), label
    request, policy, evidence, child_certificate = selected(schedule)
    assert json.loads(child_certificate)["result"]["status"] == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL", label


def test_checker_agrees_with_independent_oracle_on_sampled_orders():
    names = [row["name"] for row in graph()["nodes"]]
    built = child()
    seen = {True: 0, False: 0}
    for order in islice(permutations(names), 0, 720, 29):
        request, policy, evidence, _ = selected(list(order), built=built)
        expected = "PASS" if executes(list(order), graph()) else "FAIL"
        assert replay(request, policy, evidence)[1]["status"] == expected, order
        seen[expected == "PASS"] += 1
    assert seen[True] and seen[False]


def test_child_unknown_or_failure_controls_parent():
    request, policy, evidence, child_certificate = selected(include_graph=False)
    assert json.loads(child_certificate)["result"]["status"] == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    broken = graph()
    broken["nodes"][2]["shape"] = [2, 5]
    request, policy, evidence, child_certificate = selected(retained=broken)
    assert json.loads(child_certificate)["result"]["status"] == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    request, policy, _, _ = selected(include_bundle=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_rehashed_forged_child_pass_cannot_be_selected():
    broken = graph()
    broken["nodes"][2]["shape"] = [2, 5]
    request, policy, evidence, child_certificate = selected(retained=broken)
    forged_child = json.loads(child_certificate)
    assert forged_child["result"]["status"] == "FAIL"
    forged_child["result"]["status"] = "PASS"
    forged_child["result"]["evaluation"]["outcome"] = "PASS"
    forged_child.pop("digest")
    forged_child["digest"] = digest(forged_child)
    forged_bytes = canonical_bytes(forged_child)
    bundle = json.loads(evidence)
    bundle["child_certificate"] = base64.b64encode(forged_bytes).decode("ascii")
    altered = deepcopy(request)
    altered["child_certificate_digest"] = "sha256:" + hashlib.sha256(forged_bytes).hexdigest()
    altered["evidence_ref"] = digest(bundle)
    assert replay(altered, policy, canonical_bytes(bundle))[1]["status"] == "FAIL"


@pytest.mark.parametrize("label,encoded,reason", [
    ("invalid-base64", "!!!!", "child certificate is invalid base64"),
    # "QR==" decodes to b"A" but only "QQ==" re-encodes it: nonzero padding bits.
    ("noncanonical-base64", "QR==", "child certificate is noncanonical base64"),
])
def test_child_certificate_encoding_counterexamples_fail(label, encoded, reason):
    if label == "noncanonical-base64":
        assert base64.b64decode(encoded, validate=True) == b"A"
        assert base64.b64encode(b"A").decode("ascii") != encoded
    request, policy, evidence, _ = selected()
    bundle = json.loads(evidence)
    bundle["child_certificate"] = encoded
    altered = deepcopy(request)
    altered["evidence_ref"] = digest(bundle)
    result = replay(altered, policy, canonical_bytes(bundle))[1]
    assert result["status"] == "FAIL", label
    assert result["evaluation"]["details"] == reason, label


@pytest.mark.parametrize("limits", [{"max_operations": 40}, {"max_items": 3}])
def test_exhausted_budget_is_unknown(limits):
    request, policy, evidence, _ = selected(**limits)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_operation_budget_one_short_of_measured_use_is_unknown():
    request, policy, evidence, _ = selected()
    used = replay(request, policy, evidence)[1]["evaluation"]["observations"]["operations"]
    request, policy, evidence, _ = selected(max_operations=used)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    request, policy, evidence, _ = selected(max_operations=used - 1)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_single_bit_certificate_tamper_is_rejected():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    for offset in (len(certificate) // 3, len(certificate) // 2, len(certificate) - 5):
        tampered = bytearray(certificate)
        tampered[offset] ^= 0x01
        with pytest.raises(arch_schedule.ArchScheduleError):
            arch_schedule.recheck_arch_schedule_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_or_policy_is_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    other = deepcopy(request)
    other["subject_id"] = "arch-other"
    with pytest.raises(arch_schedule.ArchScheduleError):
        arch_schedule.recheck_arch_schedule_certificate(
            certificate, expected_request=other, policy=policy)
    swapped = deepcopy(request)
    swapped["schedule_digest"] = digest(list(reversed(VALID)))
    with pytest.raises(arch_schedule.ArchScheduleError):
        arch_schedule.recheck_arch_schedule_certificate(
            certificate, expected_request=swapped, policy=policy)
    roots = deepcopy(policy)
    roots["trust_roots"] = ["test:other-root"]
    with pytest.raises(arch_schedule.ArchScheduleError):
        arch_schedule.recheck_arch_schedule_certificate(
            certificate, expected_request=request, policy=roots)
    # A parent selecting a different subject than its child cannot pass.
    wrong = deepcopy(request)
    wrong["subject_id"] = "arch-other"
    assert replay(wrong, policy, evidence)[1]["status"] == "FAIL"
    # A schedule commitment that differs from the retained schedule cannot pass.
    stale = deepcopy(request)
    stale["schedule_digest"] = digest(list(reversed(VALID)))
    assert replay(stale, policy, evidence)[1]["status"] == "FAIL"


def test_public_route_replays_selected_schedule():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=arch_schedule.SEMANTIC_VERSION,
        objective=arch_schedule.COORDINATE, represented_kind="ARCH",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["runtime_execution"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", [
    "domains/contracts/arch_schedule.py",
    "domains/contracts/arch_shapes.py",
    "standard/CURRENT_ARCH_SCHEDULE.md",
    "standard/CURRENT_ARCH_SHAPES.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(arch_schedule.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        arch_schedule.recheck_arch_schedule_certificate(
            certificate, expected_request=request, policy=policy)
