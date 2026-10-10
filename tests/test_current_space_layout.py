"""Current SPACE retained logical byte layout and public replay boundaries.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Offsets, extents and alignment use bytes; counts
and operation budgets are dimensionless. Declared layout is not host isolation.
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
from verifier.domains.contracts import space_layout


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, partitions: list[dict] | None = None, extent: int = 1024,
             include_inputs: bool = True,
             extra_objects: list[NamespaceObject] | None = None, **limits: int):
    partitions = partitions if partitions is not None else [
        {"id": "first", "start_byte": 0, "end_byte": 128, "alignment_bytes": 64},
        {"id": "second", "start_byte": 256, "end_byte": 320, "alignment_bytes": 128},
    ]
    payload = {"scope": "retained-logical-byte-partitions", "unit": "byte",
               "extent_bytes": extent, "partitions_digest": digest(partitions)}
    subject = NamespaceObject.create("space-root", "SPACE", payload)
    objects = [subject, *(extra_objects or [])]
    evidence = canonical_bytes({
        "schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": {"partitions": partitions} if include_inputs else None,
    })
    policy = space_layout.space_layout_policy(trust_roots=["selected-layout"])
    request = space_layout.space_layout_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = space_layout.build_space_layout_certificate(request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=space_layout.SEMANTIC_VERSION,
        objective=space_layout.COORDINATE, represented_kind="SPACE",
        expected_request=request, policy=policy)
    return certificate, result


def test_selected_layout_replays_without_physical_or_isolation_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    observed = result["native_result"]
    assert observed["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert observed["host_allocation"] == "NOT_ESTABLISHED"
    assert observed["physical_containment"] == "NOT_ESTABLISHED"
    assert observed["isolation"] == "NOT_ESTABLISHED"
    assert certificate == space_layout.build_space_layout_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("partitions,extent", [
    ([{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8},
      {"id": "b", "start_byte": 7, "end_byte": 16, "alignment_bytes": 1}], 32),
    ([{"id": "b", "start_byte": 7, "end_byte": 16, "alignment_bytes": 1},
      {"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8}], 32),
    ([{"id": "a", "start_byte": 0, "end_byte": 33, "alignment_bytes": 1}], 32),
    ([{"id": "a", "start_byte": 9, "end_byte": 16, "alignment_bytes": 8}], 32),
    ([{"id": "a", "start_byte": 8, "end_byte": 8, "alignment_bytes": 8}], 32),
    ([{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 3}], 32),
    ([{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 0}], 32),
    ([{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8},
      {"id": "a", "start_byte": 16, "end_byte": 24, "alignment_bytes": 8}], 32),
    ([{"id": "a", "start_byte": True, "end_byte": 8, "alignment_bytes": 8}], 32),
    ([{"id": "a", "start_byte": 0.5, "end_byte": 8, "alignment_bytes": 8}], 32),
    ([{"id": "a", "start_byte": -1, "end_byte": 8, "alignment_bytes": 1}], 32),
    ([{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8}], 0),
    ([{"id": "a", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8}], 2**53),
])
def test_rehashed_contradictory_layout_fails(partitions, extent):
    request, policy, evidence = selected(partitions=partitions, extent=extent)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_partition_permutation_and_translation_preserve_nonoverlap():
    base = [
        {"id": "a", "start_byte": 0, "end_byte": 16, "alignment_bytes": 8},
        {"id": "b", "start_byte": 32, "end_byte": 40, "alignment_bytes": 16},
    ]
    for rows in (base, list(reversed(base))):
        for shift in (0, 64, 1024):
            moved = [{**p, "start_byte": p["start_byte"] + shift,
                      "end_byte": p["end_byte"] + shift} for p in rows]
            request, policy, evidence = selected(partitions=moved, extent=2048)
            assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"


def test_adjacent_intervals_and_largest_safe_extent_remain_valid():
    largest = 2**53 - 1
    partitions = [
        {"id": "tail", "start_byte": largest - 1,
         "end_byte": largest, "alignment_bytes": 1},
        {"id": "head", "start_byte": 0,
         "end_byte": largest - 1, "alignment_bytes": 1},
    ]
    request, policy, evidence = selected(partitions=partitions, extent=largest)
    assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"


def test_missing_retained_partitions_and_exhausted_limits_are_unknown():
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected()
    assert replay(request, policy, None)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected(partitions=[])
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected(
        extra_objects=[NamespaceObject.create("other", "OBJECT", {})], max_objects=1)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    for bound in ("max_operations", "max_composition_operations",
                  "max_items", "max_evidence_bytes", "max_payload_bytes",
                  "max_reference_bytes"):
        request, policy, evidence = selected(**{bound: 1})
        assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_external_selection_and_rehashed_certificate_substitution_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["subject_id"] = "other-space"
    with pytest.raises(ValueError):
        space_layout.recheck_space_layout_certificate(
            certificate, expected_request=changed, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        space_layout.recheck_space_layout_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        space_layout.recheck_space_layout_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_direct_builder_rejects_foreign_comparisons_and_owns_roots():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other):
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    request, policy, evidence = selected()
    policy["mechanism_id"] = HostileText(space_layout.MECHANISM_ID)
    with pytest.raises(space_layout.SpaceLayoutError):
        space_layout.build_space_layout_certificate(request, evidence, policy=policy)
    request, policy, evidence = selected()
    policy[HostileText("extra")] = 1
    with pytest.raises(space_layout.SpaceLayoutError):
        space_layout.build_space_layout_certificate(request, evidence, policy=policy)
    roots = ["selected-layout"]
    policy = space_layout.space_layout_policy(trust_roots=roots)
    roots[0] = "changed"
    assert policy["trust_roots"] == ["selected-layout"]


@pytest.mark.parametrize("relative", [
    "domains/contracts/space_layout.py", "domains/contracts/retained_selection.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py",
    "core/receipt.py", "standard/CURRENT_SPACE_LAYOUT.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = space_layout.build_space_layout_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(space_layout.__file__).parents[2] / relative

    def changed(path):
        data = original(path)
        return data + b"\nchanged space dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        space_layout.recheck_space_layout_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_command_and_polish_keep_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate = space_layout.build_space_layout_certificate(request, evidence, policy=policy)
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", space_layout.SEMANTIC_VERSION,
        "--objective", space_layout.COORDINATE, "--represented-kind", "SPACE",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "space-root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "space-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected logical layout only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][2]["objectives"] = [{
        "semantic_version": space_layout.SEMANTIC_VERSION,
        "coordinate": space_layout.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
