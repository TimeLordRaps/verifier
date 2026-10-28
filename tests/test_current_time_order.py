"""Current TIME retained ordering with bounded declared microseconds.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). A sample instant and span width use microseconds
on one declared clock; no physical clock or cross-clock equivalence is inferred.
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
from verifier.domains.contracts import time_order


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, samples: list[dict] | None = None, start: int = 0,
             end: int = 10, include_inputs: bool = True, **limits: int):
    samples = samples if samples is not None else [
        {"id": "a", "at_us": 2}, {"id": "b", "at_us": 7},
    ]
    artifact = {"scope": "retained-declared-clock-order", "clock": "test:clock",
                "unit": "microsecond", "span_start_us": start, "span_end_us": end,
                "samples_digest": digest(samples)}
    subject = NamespaceObject.create("time-root", "TIME", artifact)
    objects = [subject]
    evidence = canonical_bytes({
        "schema_version": time_order.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"samples": samples} if include_inputs else None,
    })
    policy = time_order.time_order_policy(trust_roots=["selected-retained-clock"])
    request = time_order.time_order_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = time_order.build_time_order_certificate(request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=time_order.SEMANTIC_VERSION,
        objective=time_order.COORDINATE, represented_kind="TIME",
        expected_request=request, policy=policy)
    return certificate, result


def test_selected_declared_clock_order_replays_without_physical_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    observed = result["native_result"]
    assert observed["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert observed["clock_authenticity"] == "NOT_ESTABLISHED"
    assert observed["cross_clock_synchronization"] == "NOT_ESTABLISHED"
    assert observed["causal_order"] == "NOT_ESTABLISHED"
    assert certificate == time_order.build_time_order_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("samples,start,end", [
    ([{"id": "a", "at_us": 7}, {"id": "b", "at_us": 2}], 0, 10),
    ([{"id": "a", "at_us": 10}], 0, 10),
    ([{"id": "a", "at_us": -1}], 0, 10),
    ([{"id": "a", "at_us": 2}, {"id": "a", "at_us": 7}], 0, 10),
    ([{"id": "a", "at_us": True}], 0, 10),
    ([{"id": "a", "at_us": 1.5}], 0, 10),
    ([{"id": "a", "at_us": 2}], 10, 10),
])
def test_rehashed_false_order_or_span_fails(samples, start, end):
    request, policy, evidence = selected(samples=samples, start=start, end=end)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_uniform_offset_preserves_declared_order_without_proving_clock_truth():
    for shift in (0, 13, 1000000):
        request, policy, evidence = selected(
            samples=[{"id": "a", "at_us": 2 + shift},
                     {"id": "b", "at_us": 7 + shift}],
            start=shift, end=10 + shift)
        _, result = replay(request, policy, evidence)
        assert result["computational_status"] == "PASS"
        assert result["native_result"]["clock_authenticity"] == "NOT_ESTABLISHED"


def test_missing_retained_samples_and_exhausted_limits_are_unknown():
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected()
    assert replay(request, policy, None)[1]["computational_status"] == "UNKNOWN"
    for bound in ("max_operations", "max_composition_operations", "max_items",
                  "max_evidence_bytes", "max_payload_bytes", "max_reference_bytes"):
        request, policy, evidence = selected(**{bound: 1})
        assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_external_selection_and_rehashed_certificate_substitution_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["subject_id"] = "other-time"
    with pytest.raises(ValueError):
        time_order.recheck_time_order_certificate(
            certificate, expected_request=changed, policy=policy)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        time_order.recheck_time_order_certificate(
            certificate, expected_request=request, policy=changed_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        time_order.recheck_time_order_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_direct_builder_rejects_foreign_comparison_before_callback():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other):
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    request, policy, evidence = selected()
    policy["schema_version"] = HostileText(time_order.POLICY_VERSION)
    with pytest.raises(time_order.TimeOrderError):
        time_order.build_time_order_certificate(request, evidence, policy=policy)
    request, policy, evidence = selected()
    request["coordinate"] = HostileText(time_order.COORDINATE)
    with pytest.raises(time_order.TimeOrderError):
        time_order.build_time_order_certificate(request, evidence, policy=policy)
    request, policy, evidence = selected()
    policy[HostileText("extra")] = 1
    with pytest.raises(time_order.TimeOrderError):
        time_order.build_time_order_certificate(request, evidence, policy=policy)


def test_policy_factory_owns_mutable_trust_root_list():
    roots = ["selected-retained-clock"]
    policy = time_order.time_order_policy(trust_roots=roots)
    roots[0] = "changed"
    assert policy["trust_roots"] == ["selected-retained-clock"]


@pytest.mark.parametrize("relative", [
    "domains/contracts/time_order.py", "domains/contracts/retained_selection.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py",
    "core/receipt.py", "standard/CURRENT_TIME_ORDER.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = time_order.build_time_order_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(time_order.__file__).parents[2] / relative
    def changed(path):
        data = original(path)
        return data + b"\nchanged time dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        time_order.recheck_time_order_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_command_and_polish_keep_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish
    request, policy, evidence = selected()
    certificate = time_order.build_time_order_certificate(request, evidence, policy=policy)
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", time_order.SEMANTIC_VERSION,
        "--objective", time_order.COORDINATE, "--represented-kind", "TIME",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "time-root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "time-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected declared ordering only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][1]["objectives"] = [{
        "semantic_version": time_order.SEMANTIC_VERSION,
        "coordinate": time_order.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
