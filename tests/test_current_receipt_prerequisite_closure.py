"""Selected RECEIPT-4.1 declared prerequisite-cone closure, not real dependency.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte limits measure exact bytes; counts and
operation budgets are dimensionless. The cone oracle below uses fixed-point
reachability and brute-force search over member orderings, simpler methods
than the traversal and Kahn topological sort under test.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.checker import IndependentAuditor
from verifier.core.namespace import NamespaceObject
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import ClaimSpec, EvidencePayload, VstdReceipt
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import receipt_prerequisite_closure as closure
from verifier.domains.contracts import receipt_statics
from verifier.domains.inventory import get_slot


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def receipt_bytes(receipt_id: str) -> bytes:
    reasons = ({"reason_id": "r1", "proposition": "x1 holds",
                "evidence_kind": "OBSERVED", "parent_reason_ids": []},)
    receipt = VstdReceipt(
        schema_version="VSTD-1", receipt_kind="claim_mechanics", receipt_id=receipt_id,
        claim=ClaimSpec(id="claim-" + receipt_id, title="unit", statement="x1",
                        status="draft", scope="one clause", limitations=(),
                        falsification_condition="unsatisfiable",
                        last_verified="2026-10-01"),
        evidence=EvidencePayload(domain="sat", input_text_or_formula="x1", n_vars=1,
                                 clauses=((1,),), atomic_reasons=reasons,
                                 assumptions=(), source_artifacts={}),
        target_result={"satisfiable": True},
        independent_audit=IndependentAuditor.audit_claim_derivation(
            claim_id="claim-" + receipt_id, n_vars=1, clauses=((1,),),
            atomic_reasons=reasons),
        provenance=ProvenanceRecord(
            target_name="fixture", portable_repository_id="fixture-repository",
            local_repository_path="fixture/repository",
            git=GitProvenance("d" * 40, "main", False),
            runtime=RuntimeEnvironment("3.12", "CPython", "test", "test", "test", "masked"),
            captured_at_utc="2026-10-01T00:00:00+00:00", command_executed="fixture"),
        reproducibility={"level": "CONTENT_IDENTICAL"})
    return canonical(receipt.to_dict())


def child(subject: str, prerequisites=(), *, data: bytes | None = None,
          limits: dict | None = None):
    """One separately selected RECEIPT-3.1 child: request, policy, certificate."""
    data = receipt_bytes("VFY-" + subject) if data is None else data
    record = NamespaceObject.create(subject, "RECEIPT", {
        "receipt_kind": "claim_mechanics", "receipt_schema_version": "VSTD-1",
        "receipt_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "prerequisites": sorted(prerequisites)})
    evidence = canonical_bytes({
        "schema_version": receipt_statics.EVIDENCE_VERSION,
        "receipt_object": record.to_dict(),
        "receipt_base64": base64.b64encode(data).decode("ascii")})
    policy = receipt_statics.receipt_statics_policy(trust_roots=["statics-root"])
    request = receipt_statics.receipt_statics_request(
        subject_id=subject, object_digest=record.digest,
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    certificate = receipt_statics.build_receipt_statics_certificate(
        request, evidence, policy=policy)
    return request, policy, certificate


def selected(children: dict, *, root: str = "receipt-a", limits: dict | None = None):
    """Parent selection over a mapping subject -> (request, policy, certificate)."""
    ordered = sorted(children.items())
    evidence = canonical_bytes({
        "schema_version": closure.EVIDENCE_VERSION,
        "children": [{"child_request": request, "child_policy": policy,
                      "child_certificate": base64.b64encode(certificate).decode("ascii")}
                     for _, (request, policy, certificate) in ordered]})
    policy = closure.receipt_prerequisite_closure_policy(trust_roots=["closure-root"])
    root_digest = (children[root][0]["object_digest"] if root in children
                   else "sha256:" + "e" * 64)
    request = closure.receipt_prerequisite_closure_request(
        subject_id=root, object_digest=root_digest,
        children=[{"subject_id": subject,
                   "request_digest": "sha256:" + canonical_digest(request),
                   "policy_digest": "sha256:" + canonical_digest(policy),
                   "certificate_digest": "sha256:" + hashlib.sha256(certificate).hexdigest()}
                  for subject, (request, policy, certificate) in ordered],
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = closure.build_receipt_prerequisite_closure_certificate(
        request, evidence, policy=policy)
    result = closure.recheck_receipt_prerequisite_closure_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle_closed(graph: dict, root: str) -> bool:
    """Fixed-point reachability plus brute-force topological order existence."""
    if root not in graph:
        return False
    reached = {root}
    while True:
        grown = reached | {p for node in reached for p in graph.get(node, ())}
        if grown == reached:
            break
        reached = grown
    if reached != set(graph):
        return False
    for order in itertools.permutations(sorted(graph)):
        position = {node: index for index, node in enumerate(order)}
        if all(position[p] < position[node] for node in graph for p in graph[node]):
            return True
    return False


def graph_children(graph: dict) -> dict:
    return {subject: child(subject, prerequisites)
            for subject, prerequisites in graph.items()}


DIAMOND = {"receipt-a": ["receipt-b", "receipt-c"], "receipt-b": ["receipt-d"],
           "receipt-c": ["receipt-d"], "receipt-d": []}


def test_inventory_selects_the_receipt_prerequisite_closure_recheck():
    slot = get_slot("RECEIPT", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "RECEIPT-4.1"
    assert slot.mechanized_route["artifact_coordinate"] == "RECEIPT-4.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.receipt_prerequisite_closure."
        "recheck_receipt_prerequisite_closure_certificate")


def test_closed_acyclic_cone_passes_and_rechecks_from_decoded_bytes():
    assert oracle_closed(DIAMOND, "receipt-a")
    request, policy, evidence = selected(graph_children(DIAMOND))
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", result["evaluation"]["details"]
    assert result["declared_prerequisite_cone_closure"] == "PASS"
    for field in ("claim_truth", "actual_dependency", "transformation_closure",
                  "proof_bound_completeness", "audit_validation_replay",
                  "external_referent_bytes", "hash_chain_continuity",
                  "issuer_authenticity", "whole_receipt_closure",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    assert base64.b64decode(decoded["evidence_payloads"][request["evidence_ref"]]) == evidence
    assert closure.recheck_receipt_prerequisite_closure_certificate(
        bytes(certificate), expected_request=json.loads(json.dumps(request)),
        policy=json.loads(json.dumps(policy)))["status"] == "PASS"


@pytest.mark.parametrize("graph,reason", [
    ({"receipt-a": ["receipt-b"], "receipt-b": ["receipt-a"]}, "cycle"),
    ({"receipt-a": ["receipt-a"]}, "cycle"),
    ({"receipt-a": ["receipt-b"]}, "not a retained child"),
    ({"receipt-a": [], "receipt-c": []}, "outside the declared prerequisite cone"),
    ({"receipt-b": [], "receipt-c": ["receipt-b"]}, "root"),
], ids=["two-cycle", "self-reference", "missing-prerequisite", "unrelated-child",
        "root-absent"])
def test_refuting_cone_mutants_fail_and_agree_with_the_oracle(graph, reason):
    children = {subject: child(subject, prerequisites)
                for subject, prerequisites in graph.items()}
    assert not oracle_closed({s: p for s, p in graph.items()}, "receipt-a")
    request, policy, evidence = selected(children)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL", result["evaluation"]["details"]
    assert reason in result["evaluation"]["details"]
    assert result["declared_prerequisite_cone_closure"] == "NOT_ESTABLISHED"


def test_substituted_child_certificate_fails():
    children = graph_children(DIAMOND)
    request, policy, evidence = selected(children)
    request_b, policy_b, _ = children["receipt-b"]
    swapped = dict(children)
    swapped["receipt-b"] = (request_b, policy_b, children["receipt-c"][2])
    _, _, evidence = selected(swapped)
    retargeted = deepcopy(request)
    retargeted["evidence_ref"] = "sha256:" + hashlib.sha256(evidence).hexdigest()
    result = replay(retargeted, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "child certificate" in result["evaluation"]["details"]


def test_failing_child_makes_parent_fail():
    stale = json.loads(receipt_bytes("VFY-receipt-b"))
    stale["target_result"]["satisfiable"] = False
    children = graph_children({"receipt-a": ["receipt-b"]})
    children["receipt-b"] = child("receipt-b", data=canonical(stale))
    assert receipt_statics.recheck_receipt_statics_certificate(
        children["receipt-b"][2], expected_request=children["receipt-b"][0],
        policy=children["receipt-b"][1])["status"] == "FAIL"
    result = replay(*selected(children))[1]
    assert result["status"] == "FAIL"
    assert "did not pass" in result["evaluation"]["details"]


def test_unknown_child_makes_parent_unknown():
    children = graph_children({"receipt-a": ["receipt-b"]})
    children["receipt-b"] = child("receipt-b", limits={"max_operations": 8})
    assert receipt_statics.recheck_receipt_statics_certificate(
        children["receipt-b"][2], expected_request=children["receipt-b"][0],
        policy=children["receipt-b"][1])["status"] == "UNKNOWN"
    result = replay(*selected(children))[1]
    assert result["status"] == "UNKNOWN"
    assert result["declared_prerequisite_cone_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("limits", [{"max_operations": 8}, {"max_children": 3},
                                    {"max_evidence_bytes": 64}],
                         ids=["operations", "children", "evidence-bytes"])
def test_exhausted_budget_is_unknown(limits):
    request, policy, evidence = selected(graph_children(DIAMOND), limits=limits)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_missing_evidence_is_unknown():
    request, policy, _ = selected(graph_children(DIAMOND))
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_one_bit_certificate_tamper_raises():
    request, policy, evidence = selected(graph_children(DIAMOND))
    certificate, _ = replay(request, policy, evidence)
    index = certificate.index(b'"status":"PASS"') + len(b'"status":"')
    tampered = bytearray(certificate)
    tampered[index] ^= 0x01
    with pytest.raises(closure.ReceiptPrerequisiteClosureError):
        closure.recheck_receipt_prerequisite_closure_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_wrong_subject_and_substituted_request_or_policy_are_refused():
    children = graph_children(DIAMOND)
    request, policy, evidence = selected(children)
    certificate, _ = replay(request, policy, evidence)
    other_root, _, _ = selected(children, root="receipt-b")
    with pytest.raises(closure.ReceiptPrerequisiteClosureError):
        closure.recheck_receipt_prerequisite_closure_certificate(
            certificate, expected_request=other_root, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(closure.ReceiptPrerequisiteClosureError):
        closure.recheck_receipt_prerequisite_closure_certificate(
            certificate, expected_request=request, policy=other_policy)
    wrong_root = deepcopy(request)
    wrong_root["object_digest"] = children["receipt-b"][0]["object_digest"]
    assert replay(wrong_root, policy, evidence)[1]["status"] == "FAIL"
    unsorted = list(reversed(request["children"]))
    with pytest.raises(closure.ReceiptPrerequisiteClosureError):
        closure.receipt_prerequisite_closure_request(
            subject_id="receipt-a", object_digest=request["object_digest"],
            children=unsorted, evidence_ref=request["evidence_ref"], policy=policy)


def test_public_route_reaches_pass():
    request, policy, evidence = selected(graph_children(DIAMOND))
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=closure.SEMANTIC_VERSION,
        objective=closure.COORDINATE, represented_kind="RECEIPT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["actual_dependency"] == "NOT_ESTABLISHED"


def test_retained_closure_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected(graph_children(DIAMOND))
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("RECEIPT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/receipt_prerequisite_closure.py",
    "standard/CURRENT_RECEIPT_PREREQUISITE_CLOSURE.md",
    "domains/contracts/receipt_statics.py",
    "standard/CURRENT_RECEIPT_STATICS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected(graph_children({"receipt-a": []}))
    certificate, _ = replay(request, policy, evidence)
    target = Path(closure.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        closure.recheck_receipt_prerequisite_closure_certificate(
            certificate, expected_request=request, policy=policy)
