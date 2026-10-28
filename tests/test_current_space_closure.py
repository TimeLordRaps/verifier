"""Selected finite SPACE byte-extent closure, not physical non-leakage.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Extents and offsets are bytes; counts are
dimensionless. The child layout and parent coverage are separately replayed.
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
from verifier.domains.contracts import space_layout, space_closure
from verifier.domains.inventory import get_slot


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(partitions: list[dict] | None = None, *, extent: int = 32,
             include_child: bool = True):
    partitions = partitions if partitions is not None else [
        {"id": "right", "start_byte": 16, "end_byte": 32,
         "alignment_bytes": 8},
        {"id": "left", "start_byte": 0, "end_byte": 16,
         "alignment_bytes": 16},
    ]
    subject = NamespaceObject.create("space-root", "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": extent, "partitions_digest": digest(partitions),
    })
    child_evidence = canonical_bytes({
        "schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": {"partitions": partitions},
    })
    child_policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    child_request = space_layout.space_layout_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(child_evidence)), policy=child_policy)
    child_certificate = space_layout.build_space_layout_certificate(
        child_request, child_evidence, policy=child_policy)
    evidence = canonical_bytes({
        "schema_version": space_closure.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(child_certificate).decode("ascii"),
    }) if include_child else None
    policy = space_closure.space_closure_policy(trust_roots=["closure-root"])
    request = space_closure.space_closure_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),
        child_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        evidence_ref=digest(json.loads(evidence)) if evidence is not None
        else "sha256:" + "0" * 64,
        policy=policy)
    return request, policy, evidence, child_certificate


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = space_closure.build_space_closure_certificate(
        request, evidence, policy=policy)
    result = space_closure.recheck_space_closure_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_full_declared_extent_passes_without_physical_promotion():
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["logical_extent_coverage"] == "PASS"
    assert result["host_allocation"] == "NOT_ESTABLISHED"
    assert result["physical_non_leakage"] == "NOT_ESTABLISHED"
    assert result["whole_space_closure"] == "NOT_ESTABLISHED"
    assert certificate == space_closure.build_space_closure_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("partitions", [
    [{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8},
     {"id": "b", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8}],
    [{"id": "a", "start_byte": 0, "end_byte": 16, "alignment_bytes": 8}],
    [{"id": "a", "start_byte": 8, "end_byte": 32, "alignment_bytes": 8}],
])
def test_layout_pass_does_not_hide_a_gap(partitions):
    request, policy, evidence, child = selected(partitions)
    assert json.loads(child)["result"]["status"] == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_overlap_cannot_be_reinterpreted_as_coverage():
    rows = [{"id": "a", "start_byte": 0, "end_byte": 24,
             "alignment_bytes": 8},
            {"id": "b", "start_byte": 16, "end_byte": 32,
             "alignment_bytes": 8}]
    request, policy, evidence, child = selected(rows)
    assert json.loads(child)["result"]["status"] == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_missing_child_remains_unknown_and_rehashed_verdict_is_refused():
    request, policy, _, _ = selected(include_child=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        space_closure.recheck_space_closure_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    other = deepcopy(policy)
    other["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        space_closure.recheck_space_closure_certificate(
            certificate, expected_request=request, policy=other)


def test_public_route_and_inventory_select_only_this_closure_objective():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=space_closure.SEMANTIC_VERSION,
        objective=space_closure.COORDINATE, represented_kind="SPACE",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["physical_non_leakage"] == "NOT_ESTABLISHED"
    slot = get_slot("SPACE", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "SPACE-4.1"


def test_retained_closure_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("SPACE", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def test_rehashed_child_verdict_cannot_be_selected_as_coverage():
    request, policy, evidence, child = selected()
    altered_child = json.loads(child)
    altered_child["result"]["status"] = "FAIL"
    altered_child.pop("digest")
    altered_child["digest"] = digest(altered_child)
    altered_bytes = canonical_bytes(altered_child)
    altered_evidence = json.loads(evidence)
    altered_evidence["child_certificate"] = base64.b64encode(altered_bytes).decode("ascii")
    altered_evidence_bytes = canonical_bytes(altered_evidence)
    altered_request = deepcopy(request)
    altered_request["child_certificate_digest"] = (
        "sha256:" + hashlib.sha256(altered_bytes).hexdigest())
    altered_request["evidence_ref"] = digest(altered_evidence)
    assert replay(altered_request, policy, altered_evidence_bytes)[1]["status"] == "FAIL"


def test_partition_order_and_largest_safe_extent_do_not_change_coverage():
    largest = 2**53 - 1
    rows = [
        {"id": "tail", "start_byte": largest - 1,
         "end_byte": largest, "alignment_bytes": 1},
        {"id": "head", "start_byte": 0,
         "end_byte": largest - 1, "alignment_bytes": 1},
    ]
    for ordered in (rows, list(reversed(rows))):
        request, policy, evidence, _ = selected(ordered, extent=largest)
        assert replay(request, policy, evidence)[1]["status"] == "PASS"


def test_public_command_and_polish_keep_tier_boundary(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence, child = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", space_closure.SEMANTIC_VERSION,
        "--objective", space_closure.COORDINATE, "--represented-kind", "SPACE",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    child_ref = json.loads(child)["request"]["evidence_ref"]
    child_evidence = base64.b64decode(json.loads(child)["evidence_payloads"][child_ref])
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(child_evidence)["objects"],
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "space-root",
        "collection_digest": json.loads(child)["request"]["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "space-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected logical coverage only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][3]["objectives"] = [{
        "semantic_version": space_closure.SEMANTIC_VERSION,
        "coordinate": space_closure.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": digest(json.loads(certificate))}]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS", report["objectives"][0]
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


@pytest.mark.parametrize("relative", [
    "domains/contracts/space_closure.py",
    "domains/contracts/space_layout.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_SPACE_CLOSURE.md",
    "standard/CURRENT_SPACE_LAYOUT.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(space_closure.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        space_closure.recheck_space_closure_certificate(
            certificate, expected_request=request, policy=policy)
