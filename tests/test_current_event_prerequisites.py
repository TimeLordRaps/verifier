"""Current EVENT retained prerequisite cone and payload replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Sequence values and checker budgets are
dimensionless. A declared prerequisite is not physical causality.
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
from verifier.domains.contracts import event_prerequisites


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, events: list[tuple[str, object, list[str], object]] | None = None,
             retained_payloads: dict[str, object] | None = None,
             include_inputs: bool = True, **limits: int):
    events = events if events is not None else [
        ("parent", 1, [], {"value": "first"}),
        ("root", 2, ["parent"], {"value": "second"}),
    ]
    retained_payloads = retained_payloads if retained_payloads is not None else {
        name: payload for name, _, _, payload in events
    }
    fixed = [
        NamespaceObject.create("clock", "TIME", {}),
        NamespaceObject.create("place", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
    ]
    event_objects = [NamespaceObject.create(
        name, "EVENT", {"scope": "retained-declared-prerequisites",
            "sequence": sequence, "prerequisites": parents,
            "payload_digest": digest(payload)},
        {"time": ["clock"], "space": ["place"], "meaning": ["meaning"]},
    ) for name, sequence, parents, payload in events]
    objects = [*fixed, *event_objects]
    subject = next(obj for obj in event_objects if obj.object_id == "root")
    evidence = canonical_bytes({
        "schema_version": event_prerequisites.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": {"payloads": retained_payloads} if include_inputs else None,
    })
    policy = event_prerequisites.event_prerequisites_policy(
        trust_roots=["selected-event-cone"])
    request = event_prerequisites.event_prerequisites_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = event_prerequisites.build_event_prerequisites_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=event_prerequisites.SEMANTIC_VERSION,
        objective=event_prerequisites.COORDINATE, represented_kind="EVENT",
        expected_request=request, policy=policy)
    return certificate, result


def test_selected_prerequisite_cone_replays_without_occurrence_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    native = result["native_result"]
    assert native["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert native["occurrence_authenticity"] == "NOT_ESTABLISHED"
    assert native["physical_causality"] == "NOT_ESTABLISHED"
    assert native["operand_truth"] == "NOT_ESTABLISHED"
    assert certificate == event_prerequisites.build_event_prerequisites_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("events", [
    [("parent", 2, [], {"value": 1}), ("root", 2, ["parent"], {"value": 2})],
    [("parent", 3, [], {"value": 1}), ("root", 2, ["parent"], {"value": 2})],
    [("parent", 1, [], {"value": 1}), ("root", 2, ["missing"], {"value": 2})],
    [("parent", 1, [], {"value": 1}), ("root", 2, ["root"], {"value": 2})],
    [("parent", 1, [], {"value": 1}), ("root", 2, ["parent", "parent"], {"value": 2})],
    [("parent", True, [], {"value": 1}), ("root", 2, ["parent"], {"value": 2})],
    [("parent", 1.5, [], {"value": 1}), ("root", 2, ["parent"], {"value": 2})],
    [("parent", 1, [], {"value": 1}), ("root", 2**53, ["parent"], {"value": 2})],
])
def test_rehashed_false_prerequisite_claim_fails(events):
    request, policy, evidence = selected(events=events)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_rehashed_payload_substitution_and_unrelated_input_fail():
    request, policy, evidence = selected(retained_payloads={
        "parent": {"value": "changed"}, "root": {"value": "second"}})
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"
    request, policy, evidence = selected(retained_payloads={
        "parent": {"value": "first"}, "root": {"value": "second"},
        "extra": {"value": "not in cone"}})
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_declared_sequence_translation_preserves_prerequisite_relation():
    for shift in (0, 17, 1000000):
        request, policy, evidence = selected(events=[
            ("parent", 1 + shift, [], {"value": "first"}),
            ("root", 2 + shift, ["parent"], {"value": "second"}),
        ])
        assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"


def test_transitive_cone_is_checked_and_unrelated_event_stays_outside():
    events = [
        ("grand", 0, [], {"value": "oldest"}),
        ("parent", 1, ["grand"], {"value": "middle"}),
        ("root", 2, ["parent"], {"value": "newest"}),
        ("unrelated", 99, [], {"value": "outside cone"}),
    ]
    selected_payloads = {name: payload for name, _, _, payload in events
                         if name != "unrelated"}
    request, policy, evidence = selected(events=events,
                                         retained_payloads=selected_payloads)
    assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"
    selected_payloads.pop("grand")
    request, policy, evidence = selected(events=events,
                                         retained_payloads=selected_payloads)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_missing_reachable_payload_and_exhausted_limits_are_unknown():
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected()
    assert replay(request, policy, None)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected(retained_payloads={"root": {"value": "second"}})
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    for bound in ("max_objects", "max_operations", "max_composition_operations",
                  "max_items", "max_evidence_bytes", "max_payload_bytes",
                  "max_reference_bytes"):
        request, policy, evidence = selected(**{bound: 1})
        assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_explicit_null_payload_is_invalid_not_absent():
    request, policy, evidence = selected(retained_payloads={
        "parent": None, "root": {"value": "second"}})
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_external_request_policy_and_rehashed_result_substitution_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["subject_id"] = "other-event"
    with pytest.raises(ValueError):
        event_prerequisites.recheck_event_prerequisites_certificate(
            certificate, expected_request=changed, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        event_prerequisites.recheck_event_prerequisites_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        event_prerequisites.recheck_event_prerequisites_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_direct_builder_rejects_foreign_comparisons_and_owns_roots():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other):
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    request, policy, evidence = selected()
    policy["mechanism_id"] = HostileText(event_prerequisites.MECHANISM_ID)
    with pytest.raises(event_prerequisites.EventPrerequisitesError):
        event_prerequisites.build_event_prerequisites_certificate(
            request, evidence, policy=policy)
    request, policy, evidence = selected()
    policy[HostileText("extra")] = 1
    with pytest.raises(event_prerequisites.EventPrerequisitesError):
        event_prerequisites.build_event_prerequisites_certificate(
            request, evidence, policy=policy)
    roots = ["selected-event-cone"]
    policy = event_prerequisites.event_prerequisites_policy(trust_roots=roots)
    roots[0] = "changed"
    assert policy["trust_roots"] == ["selected-event-cone"]


@pytest.mark.parametrize("relative", [
    "domains/contracts/event_prerequisites.py", "domains/contracts/retained_selection.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py",
    "core/receipt.py", "standard/CURRENT_EVENT_PREREQUISITES.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = event_prerequisites.build_event_prerequisites_certificate(
        request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(event_prerequisites.__file__).parents[2] / relative

    def changed(path):
        data = original(path)
        return data + b"\nchanged event dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        event_prerequisites.recheck_event_prerequisites_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_command_and_polish_keep_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate = event_prerequisites.build_event_prerequisites_certificate(
        request, evidence, policy=policy)
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", event_prerequisites.SEMANTIC_VERSION,
        "--objective", event_prerequisites.COORDINATE, "--represented-kind", "EVENT",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected declared prerequisites only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][2]["objectives"] = [{
        "semantic_version": event_prerequisites.SEMANTIC_VERSION,
        "coordinate": event_prerequisites.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
