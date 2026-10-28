"""VERIFIER-4.1 declared finite claim-class coverage and counterexample boundaries.

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Member, node and
boundary counts are dimensionless; extents are bytes. The class is enumerated
from a retained DAG profile; completeness beyond it is never established.
"""
from __future__ import annotations

import base64
from collections import deque
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import space_closure, space_layout
from verifier.domains.contracts import verifier_coverage_closure as vcc
from verifier.domains.contracts.certificate_dag import (
    BUNDLE, POLICY, PROFILE, artifact_files_digest)
from verifier.domains.inventory import get_slot

ZERO = "sha256:" + "0" * 64
SV = space_layout.SEMANTIC_VERSION
PASSING = [
    {"id": "right", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8},
    {"id": "left", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
]
GAP = [
    {"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8},
    {"id": "b", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8},
]
OVERLAP = [
    {"id": "a", "start_byte": 0, "end_byte": 24, "alignment_bytes": 8},
    {"id": "b", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8},
]
EXCLUDED = ("completeness_beyond_declared_class", "declared_class_authority",
            "class_wide_soundness", "checker_correctness",
            "whole_verifier_closure", "object_profile_conformance")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def space(identity: str, partitions: list) -> NamespaceObject:
    return NamespaceObject.create(identity, "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 32, "partitions_digest": digest(partitions)})


def layout(item: NamespaceObject, partitions: list, *, retained: bool = True):
    evidence = canonical_bytes({"schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [item.to_dict()], "inputs": {"partitions": partitions}})
    policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    request = space_layout.space_layout_request(
        subject_id=item.object_id, object_digest=item.digest,
        collection_digest=composition_digest([item]),
        evidence_ref=raw_digest(evidence), policy=policy)
    return request, policy, space_layout.build_space_layout_certificate(
        request, evidence if retained else None, policy=policy)


def closure(item: NamespaceObject, child: tuple):
    child_request, child_policy, child_certificate = child
    evidence = canonical_bytes({"schema_version": space_closure.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": b64(child_certificate)})
    policy = space_closure.space_closure_policy(trust_roots=["closure-root"])
    request = space_closure.space_closure_request(
        subject_id=item.object_id, object_digest=item.digest,
        collection_digest=composition_digest([item]),
        child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),
        child_certificate_digest=raw_digest(child_certificate),
        evidence_ref=raw_digest(evidence), policy=policy)
    return request, policy, space_closure.build_space_closure_certificate(
        request, evidence, policy=policy)


def obligation(claim_id: str, objective: str, dependencies: list | None = None) -> dict:
    route = next(r for r in routes.current_object_route_catalog() if r["objective"] == objective)
    return {"claim_id": claim_id, "semantic_version": route["semantic_version"],
            "objective": objective, "proposition_digest": route["proposition_digest"],
            "scope": route["scope"], "assumptions": [], "dependencies": dependencies or []}


def local(claim_id: str) -> dict:
    return {"claim_id": claim_id, "operand_role": None, "object_kind": "SPACE",
            "profile_digest": None}


def node(item: NamespaceObject, claim_id: str, triple: tuple, files: dict) -> dict:
    request, policy, raw = triple
    identity = item.object_id + ":" + claim_id
    path = identity.replace(":", "-") + ".json"
    files[path] = raw
    return {"node_id": identity, "object_id": item.object_id, "claim_id": claim_id,
            "certificate_path": path, "certificate_digest": raw_digest(raw),
            "request": request, "checker_policy": policy, "contract_version": "1",
            "artifact_bindings": [{"path": path, "digest": raw_digest(raw)}],
            "facet_bindings": {"payload_digest": raw_digest(item.payload_bytes),
                "operands_digest": raw_digest(canonical_bytes(item.to_dict()["operands"]))}}


def boundary(case_id: str, objective: str, triple: tuple, expected: str):
    request, policy, raw = triple
    declared = {"case_id": case_id, "semantic_version": SV, "objective": objective,
                "represented_kind": "SPACE", "request_digest": digest(request),
                "policy_digest": digest(policy), "certificate_digest": raw_digest(raw),
                "expected": expected}
    return declared, {"request": request, "policy": policy, "certificate": b64(raw)}


def default_boundaries() -> list:
    gap = space("space-gap", GAP)
    overlap = space("space-overlap", OVERLAP)
    return [boundary("gap-closure", "SPACE-4.1", closure(gap, layout(gap, GAP)), "FAIL"),
            boundary("overlap-layout", "SPACE-3.1", layout(overlap, OVERLAP), "FAIL")]


def verifier_object(claim_class: list) -> NamespaceObject:
    objectives = sorted({(row["semantic_version"], row["objective"]) for row in claim_class})
    return NamespaceObject.create("verifier-coverage", "VERIFIER", {
        "checker_kind": "CURRENT_OBJECT_ROUTES",
        "objectives": [list(pair) for pair in objectives]})


def fixture(*, parts: list = PASSING, retained: bool = True, cyclic: bool = False,
            only_layout: bool = False, drop_layout_file: bool = False,
            boundaries: list | None = None, declare=None, subject=None,
            limits: dict | None = None):
    item = space("space-root", parts)
    files: dict[str, bytes] = {}
    member_layout = layout(item, parts, retained=retained)
    a = node(item, "layout", member_layout, files)
    claims = [obligation("layout", "SPACE-3.1", [local("closure")] if cyclic else [])]
    nodes, edges = [a], []
    if not only_layout:
        b = node(item, "closure", closure(item, member_layout), files)
        claims.append(obligation("closure", "SPACE-4.1", [local("layout")]))
        nodes.append(b)
        edges.append({"node_id": b["node_id"], "prerequisite_id": a["node_id"], "operand_role": None})
        if cyclic:
            edges.append({"node_id": a["node_id"], "prerequisite_id": b["node_id"], "operand_role": None})
    if drop_layout_file:
        files.pop(a["certificate_path"])
    profile = {"schema_version": PROFILE, "profile_id": "test-only-space",
               "profile_version": "test-1", "object_kind": "SPACE", "obligations": claims}
    pin = raw_digest(canonical_bytes(profile))
    bundle = {"schema_version": BUNDLE, "profiles": [profile], "objects": [item.to_dict()],
              "nodes": nodes, "edges": edges}
    dag_policy = {"schema_version": POLICY, "approved_profiles": [pin],
        "required_objects": [{"object_id": item.object_id, "object_kind": "SPACE",
                              "record_digest": item.digest, "profile_digest": pin}],
        "required_roots": [nodes[-1]["node_id"]], "nodes": deepcopy(nodes),
        "artifact_files_digest": artifact_files_digest(files)}
    claim_class = sorted(({"object_id": item.object_id, "claim_id": c["claim_id"],
        "semantic_version": c["semantic_version"], "objective": c["objective"],
        "proposition_digest": c["proposition_digest"]} for c in claims),
        key=lambda row: (row["object_id"], row["claim_id"]))
    declared_class = declare(claim_class) if declare else claim_class
    cases = default_boundaries() if boundaries is None else boundaries
    expected_subject = verifier_object(declared_class)
    carried_subject = subject or expected_subject
    bundle_bytes, policy_bytes = canonical_bytes(bundle), canonical_bytes(dag_policy)
    policy = vcc.verifier_coverage_closure_policy(trust_roots=["coverage-root"])
    request = vcc.verifier_coverage_closure_request(
        subject_id=expected_subject.object_id, object_digest=expected_subject.digest,
        collection_digest=composition_digest([expected_subject]),
        claim_class=declared_class, boundary_cases=[declared for declared, _ in cases],
        dag_bundle_digest=raw_digest(bundle_bytes), dag_policy_digest=raw_digest(policy_bytes),
        artifact_files_digest=artifact_files_digest(files), evidence_ref=ZERO,
        policy=policy, limits=limits)
    evidence = canonical_bytes({"schema_version": vcc.EVIDENCE_VERSION,
        "verifier_object": carried_subject.to_dict(),
        "dag_bundle": b64(bundle_bytes), "dag_policy": b64(policy_bytes),
        "artifact_files": {path: b64(raw) for path, raw in files.items()},
        "boundary_evidence": {declared["case_id"]: entry for declared, entry in cases}})
    request = dict(request, evidence_ref=raw_digest(evidence))
    return request, policy, evidence, {"nodes": nodes, "edges": edges, "files": files, "cases": cases}


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = vcc.build_verifier_coverage_closure_certificate(request, evidence, policy=policy)
    result = vcc.recheck_verifier_coverage_closure_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def direct(objective: str, request: dict, policy: dict, raw: bytes) -> str:
    """Independent oracle: one registered-route replay outside the DAG and parent."""
    return routes.replay_current_object_certificate(
        raw, semantic_version=SV, objective=objective, represented_kind="SPACE",
        expected_request=deepcopy(request), policy=deepcopy(policy))["computational_status"]


def node_status(parts: dict, index: int) -> str:
    item = parts["nodes"][index]
    objective = {"layout": "SPACE-3.1", "closure": "SPACE-4.1"}[item["claim_id"]]
    return direct(objective, item["request"], item["checker_policy"],
                  parts["files"][item["certificate_path"]])


def test_inventory_selects_the_coverage_closure_recheck():
    slot = get_slot("VERIFIER", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "VERIFIER-4.1"
    assert slot.mechanized_route["artifact_coordinate"] == "VERIFIER-4.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.verifier_coverage_closure."
        "recheck_verifier_coverage_closure_certificate")


def test_covered_class_with_boundaries_passes_and_rechecks_from_decoded_bytes():
    request, policy, evidence, parts = fixture()
    assert [node_status(parts, index) for index in range(2)] == ["PASS", "PASS"]
    for declared, entry in parts["cases"]:
        assert direct(declared["objective"], entry["request"], entry["policy"],
                      base64.b64decode(entry["certificate"])) == declared["expected"]
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["declared_class_coverage_closure"] == "PASS"
    for field in EXCLUDED:
        assert result[field] == "NOT_ESTABLISHED", field
    again = vcc.recheck_verifier_coverage_closure_certificate(
        canonical_bytes(json.loads(certificate.decode("utf-8"))),
        expected_request=request, policy=policy)
    assert again == result
    observed = result["evaluation"]["observations"]
    assert observed["members"] == 2 and observed["boundary_cases"] == 2
    assert sorted(row["observed"] for row in observed["boundary"]) == ["FAIL", "FAIL"]


def test_one_member_with_one_boundary_case_is_two_decisions_and_passes():
    overlap = space("space-overlap", OVERLAP)
    cases = [boundary("overlap-layout", "SPACE-3.1", layout(overlap, OVERLAP), "FAIL")]
    request, policy, evidence, _ = fixture(only_layout=True, boundaries=cases)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"


def test_member_whose_decision_is_refuted_is_a_counterexample():
    request, policy, evidence, parts = fixture(parts=GAP)
    assert [node_status(parts, index) for index in range(2)] == ["PASS", "FAIL"]
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "MEMBER_FAILS:space-root:closure" in result["evaluation"]["details"]


def test_cyclic_member_dependencies_are_a_counterexample():
    request, policy, evidence, parts = fixture(cyclic=True)
    pending = {n["node_id"]: set() for n in parts["nodes"]}
    for edge in parts["edges"]:
        pending[edge["node_id"]].add(edge["prerequisite_id"])
    ready = deque(nid for nid, deps in pending.items() if not deps)
    ordered = 0
    while ready:
        current = ready.popleft()
        ordered += 1
        for nid, deps in pending.items():
            if current in deps:
                deps.discard(current)
                if not deps:
                    ready.append(nid)
    assert ordered < len(pending)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "DEPENDENCY_CONTRACT_REJECTED" in result["evaluation"]["details"]


def test_boundary_case_accepted_by_its_checker_is_a_counterexample():
    accepted = space("space-accepted", PASSING)
    cases = [boundary("accepted-layout", "SPACE-3.1", layout(accepted, PASSING), "FAIL"),
             default_boundaries()[0]]
    declared, entry = cases[0]
    assert direct("SPACE-3.1", entry["request"], entry["policy"],
                  base64.b64decode(entry["certificate"])) == "PASS"
    request, policy, evidence, _ = fixture(boundaries=cases)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "BOUNDARY_PASS:accepted-layout" in result["evaluation"]["details"]


def test_declared_class_that_omits_an_enumerated_member_is_a_counterexample():
    request, policy, evidence, parts = fixture(
        declare=lambda rows: [row for row in rows if row["claim_id"] == "layout"],
        boundaries=[default_boundaries()[1]])
    assert len(parts["nodes"]) == 2
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "DECLARED_CLASS_DIFFERS_FROM_ENUMERATED_CLASS" in result["evaluation"]["details"]


def test_rehashed_boundary_verdict_is_refused_by_its_registered_route():
    overlap = space("space-overlap", OVERLAP)
    request_b, policy_b, raw = layout(overlap, OVERLAP)
    value = json.loads(raw)
    value["result"]["status"] = "FAIL" if value["result"]["status"] != "FAIL" else "UNKNOWN"
    value.pop("digest")
    value["digest"] = digest(value)
    forged = canonical_bytes(value)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        direct("SPACE-3.1", request_b, policy_b, forged)
    cases = [boundary("forged-layout", "SPACE-3.1", (request_b, policy_b, forged), "UNKNOWN"),
             default_boundaries()[0]]
    request, policy, evidence, _ = fixture(boundaries=cases)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "BOUNDARY_REFUSED:forged-layout" in result["evaluation"]["details"]


def test_node_budget_exhaustion_is_unknown():
    request, policy, evidence, _ = fixture(limits={"max_nodes": 1})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["declared_class_coverage_closure"] == "NOT_ESTABLISHED"


def test_single_retained_decision_does_not_close_the_class():
    request, policy, evidence, _ = fixture(only_layout=True, boundaries=[])
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert "COUNTEREXAMPLE_BOUNDARY_MISSING" in result["evaluation"]["details"]
    request, policy, evidence, _ = fixture(boundaries=[])
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_missing_member_decision_and_undecided_boundary_remain_unknown():
    request, policy, evidence, _ = fixture(drop_layout_file=True)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    absent = space("space-absent", PASSING)
    cases = [boundary("absent-layout", "SPACE-3.1", layout(absent, PASSING, retained=False), "FAIL"),
             default_boundaries()[0]]
    declared, entry = cases[0]
    assert direct("SPACE-3.1", entry["request"], entry["policy"],
                  base64.b64decode(entry["certificate"])) == "UNKNOWN"
    request, policy, evidence, _ = fixture(boundaries=cases)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert "BOUNDARY_UNDECIDED:absent-layout" in result["evaluation"]["details"]
    request, policy, _, _ = fixture()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_member_unknown_makes_parent_unknown_and_member_fail_makes_parent_fail():
    request, policy, evidence, parts = fixture(retained=False)
    assert node_status(parts, 0) == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    request, policy, evidence, parts = fixture(parts=OVERLAP)
    assert node_status(parts, 0) == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_one_bit_flip_in_the_certificate_is_refused():
    request, policy, evidence, _ = fixture()
    certificate, _ = replay(request, policy, evidence)
    for position in (1, len(certificate) // 3, len(certificate) // 2, len(certificate) - 2):
        flipped = bytearray(certificate)
        flipped[position] ^= 1
        with pytest.raises(vcc.VerifierCoverageClosureError):
            vcc.recheck_verifier_coverage_closure_certificate(
                bytes(flipped), expected_request=request, policy=policy)


def test_wrong_subject_and_substituted_selection_are_refused():
    wrong = NamespaceObject.create("verifier-coverage", "VERIFIER", {
        "checker_kind": "CURRENT_OBJECT_ROUTES", "objectives": [[SV, "SPACE-3.1"]]})
    request, policy, evidence, _ = fixture(subject=wrong)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    request, policy, evidence, _ = fixture()
    certificate, _ = replay(request, policy, evidence)
    substituted = deepcopy(request)
    substituted["boundary_cases"][0]["expected"] = "UNKNOWN"
    with pytest.raises(vcc.VerifierCoverageClosureError):
        vcc.recheck_verifier_coverage_closure_certificate(
            certificate, expected_request=substituted, policy=policy)
    with pytest.raises(vcc.VerifierCoverageClosureError):
        vcc.recheck_verifier_coverage_closure_certificate(
            certificate, expected_request=request,
            policy=dict(policy, trust_roots=["other-root"]))


def _rebuild(request: dict, policy: dict, **changes) -> dict:
    fields = {key: request[key] for key in (
        "subject_id", "object_digest", "collection_digest", "claim_class",
        "boundary_cases", "dag_bundle_digest", "dag_policy_digest",
        "artifact_files_digest", "evidence_ref")}
    fields.update(changes)
    return vcc.verifier_coverage_closure_request(policy=policy, **fields)


@pytest.mark.parametrize("objective", ["VERIFIER-3.1", "VERIFIER-4.1"])
def test_own_objectives_are_not_admissible_members_or_boundaries(objective):
    request, policy, _, _ = fixture()
    member = dict(request["claim_class"][0], objective=objective)
    with pytest.raises(vcc.VerifierCoverageClosureError):
        _rebuild(request, policy, claim_class=sorted(
            [member, request["claim_class"][1]],
            key=lambda row: (row["object_id"], row["claim_id"])))
    case = dict(request["boundary_cases"][0], objective=objective,
                represented_kind="VERIFIER")
    with pytest.raises(vcc.VerifierCoverageClosureError):
        _rebuild(request, policy, boundary_cases=[case, request["boundary_cases"][1]])


def test_boundary_case_outside_the_declared_class_is_rejected():
    request, policy, _, _ = fixture(only_layout=True, boundaries=[default_boundaries()[1]])
    case = dict(default_boundaries()[0][0])
    with pytest.raises(vcc.VerifierCoverageClosureError):
        _rebuild(request, policy, boundary_cases=[case])


def test_public_route_dispatch_reaches_pass():
    request, policy, evidence, _ = fixture()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=vcc.SEMANTIC_VERSION,
        objective=vcc.COORDINATE, represented_kind="VERIFIER",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["completeness_beyond_declared_class"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", [
    "domains/contracts/verifier_coverage_closure.py",
    "domains/contracts/certificate_dag.py",
    "standard/CURRENT_VERIFIER_COVERAGE_CLOSURE.md",
    "standard/CERTIFICATE_DAG.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(vcc.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        vcc.recheck_verifier_coverage_closure_certificate(
            certificate, expected_request=request, policy=policy)


def test_an_unreachable_boundary_checker_leaves_the_class_undecided(monkeypatch):
    request, policy, evidence, _ = fixture()

    class Unreachable(OSError):
        pass

    def unreachable(*args, **kwargs):
        raise Unreachable("selected native checker unavailable")

    monkeypatch.setattr(routes, "CurrentObjectRouteUnavailable", Unreachable, raising=False)
    monkeypatch.setattr(routes, "replay_current_object_certificate", unreachable)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert "BOUNDARY_UNDECIDED:gap-closure" in result["evaluation"]["details"]
