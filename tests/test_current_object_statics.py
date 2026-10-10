"""Selected finite OBJECT collection statics, not payload truth.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
Record sizes are bytes. Depths, counts and checking budgets are
dimensionless. The oracle below recomputes canonicality, addresses, payload
shape and the collection commitment with the standard library only.
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
from verifier.domains.contracts import object_statics
from verifier.domains.inventory import get_slot


BOUNDS = {"max_records": 8, "max_record_bytes": 4096, "max_payload_depth": 4,
          "max_payload_values": 64, "max_references": 4}


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def plain_canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def records() -> list[NamespaceObject]:
    return [
        NamespaceObject.create("doc-root", "OBJECT", {
            "title": "root",
            "body": {"lines": ["a", "b"], "meta": {"lang": "café"}}}),
        NamespaceObject.create("clock", "TIME", {"unit": "microsecond"}),
        NamespaceObject.create("region", "SPACE", {"unit": "byte", "extent_bytes": 64}),
        NamespaceObject.create("evt", "EVENT", {"label": "write"}, {
            "meaning": ["doc-root"], "space": ["region"], "time": ["clock"]}),
    ]


def row(raw: bytes) -> dict:
    return {"address": sha(raw), "bytes": base64.b64encode(raw).decode("ascii")}


def shape(value: object, depth: int = 0) -> tuple[int, int]:
    """Independent recursive oracle: (deepest nesting step, JSON value count)."""
    if isinstance(value, dict):
        children = list(value.values())
    elif isinstance(value, list):
        children = value
    else:
        return depth, 1
    deepest, count = depth, 1
    for child in children:
        child_depth, child_count = shape(child, depth + 1)
        deepest, count = max(deepest, child_depth), count + child_count
    return deepest, count


def oracle(rows: list[dict], bounds: dict, subject_id: str, object_digest: str,
           collection_digest: str) -> str:
    if len(rows) > bounds["max_records"]:
        return "FAIL"
    addresses, identifiers, parsed = set(), set(), []
    for item in rows:
        raw = base64.b64decode(item["bytes"])
        if len(raw) > bounds["max_record_bytes"] or sha(raw) != item["address"]:
            return "FAIL"
        if item["address"] in addresses:
            return "FAIL"
        addresses.add(item["address"])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "FAIL"
        duplicate = []

        def pairs(members, duplicate=duplicate):
            names = [name for name, _ in members]
            duplicate.extend(name for name in names if names.count(name) > 1)
            return dict(members)

        value = json.loads(text, object_pairs_hook=pairs)
        if duplicate or plain_canonical(value) != raw:
            return "FAIL"
        if value.get("kind") not in {"HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY",
                "OWNER", "HARDWARE", "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME",
                "EVENT", "ENV", "DATA", "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER",
                "MODEL", "HARNESS", "AGENT", "SIM", "BOT", "TOKEN"}:
            return "FAIL"
        if value["object_id"] in identifiers:
            return "FAIL"
        identifiers.add(value["object_id"])
        depth, count = shape(value["payload"])
        references = sum(len(targets) for targets in value["operands"].values())
        if (depth > bounds["max_payload_depth"] or count > bounds["max_payload_values"]
                or references > bounds["max_references"]):
            return "FAIL"
        parsed.append(value)
    collection = sha(plain_canonical({"schema_version": "verifier-object-composition-1",
        "objects": sorted(parsed, key=lambda value: value["object_id"])}))
    if collection != collection_digest:
        return "FAIL"
    subject = [value for value in parsed if value["object_id"] == subject_id]
    if (len(subject) != 1 or subject[0]["kind"] != "OBJECT"
            or sha(plain_canonical(subject[0])) != object_digest):
        return "FAIL"
    return "PASS"


def selected(rows: list[dict] | None = None, *, objects=None, bounds=None,
             subject: str = "doc-root", collection: str | None = None,
             include: bool = True, limits: dict | None = None):
    objects = objects if objects is not None else records()
    rows = rows if rows is not None else [row(plain_canonical(item.to_dict())) for item in objects]
    evidence = canonical_bytes({"schema_version": object_statics.EVIDENCE_VERSION,
                                "records": rows})
    subject_item = [item for item in objects if item.object_id == subject][0]
    policy = object_statics.object_statics_policy(trust_roots=["statics-root"])
    request = object_statics.object_statics_request(
        subject_id=subject, object_digest=subject_item.digest,
        collection_digest=collection or composition_digest(objects),
        structural_bounds=dict(bounds or BOUNDS),
        evidence_ref=sha(evidence) if include else "sha256:" + "0" * 64,
        policy=policy, limits=limits)
    return request, policy, (evidence if include else None), rows


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = object_statics.build_object_statics_certificate(
        request, evidence, policy=policy)
    result = object_statics.recheck_object_statics_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_canonical_unique_bounded_collection_passes_and_rechecks_from_bytes():
    request, policy, evidence, rows = selected()
    assert oracle(rows, BOUNDS, "doc-root", request["object_digest"],
                  request["collection_digest"]) == "PASS"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["canonical_collection_statics"] == "PASS"
    for field in ("typed_composition", "operand_resolution", "payload_truth",
                  "whole_object_statics", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    retained = base64.b64decode(decoded["evidence_payloads"][request["evidence_ref"]])
    assert retained == evidence
    assert object_statics.recheck_object_statics_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))["status"] == "PASS"


def test_declared_bounds_are_inclusive_and_each_is_refutable():
    objects = records()
    raws = [plain_canonical(item.to_dict()) for item in objects]
    measured = {
        "max_records": len(objects),
        "max_record_bytes": max(len(raw) for raw in raws),
        "max_payload_depth": max(shape(item.payload)[0] for item in objects),
        "max_payload_values": max(shape(item.payload)[1] for item in objects),
        "max_references": max(sum(len(targets) for _, targets in item.operands)
                              for item in objects),
    }
    request, policy, evidence, _ = selected(bounds=measured)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    for name in measured:
        tighter = {**measured, name: measured[name] - 1}
        request, policy, evidence, rows = selected(bounds=tighter)
        assert oracle(rows, tighter, "doc-root", request["object_digest"],
                      request["collection_digest"]) == "FAIL"
        result = replay(request, policy, evidence)[1]
        assert result["status"] == "FAIL", name
        assert "declared" in result["evaluation"]["details"], name
        assert result["canonical_collection_statics"] == "NOT_ESTABLISHED"


def _mutant(name: str):
    objects = records()
    raws = [plain_canonical(item.to_dict()) for item in objects]
    collection = None
    subject = "doc-root"
    if name == "formatting_whitespace":
        raws[0] = json.dumps(objects[0].to_dict(), sort_keys=True, indent=1).encode("ascii")
    elif name == "unescaped_non_ascii":
        raws[0] = json.dumps(objects[0].to_dict(), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
    elif name == "invalid_utf8":
        raws[1] = raws[1].replace(b"microsecond", b"microsecon\xff")
    elif name == "duplicate_member":
        raws[1] = raws[1].replace(b'"kind":"TIME",', b'"kind":"TIME","kind":"TIME",', 1)
    elif name == "inadmissible_kind":
        raws.append(plain_canonical({"kind": "VSTD", "object_id": "legacy",
                                     "operands": {}, "payload": {}}))
    rows = [row(raw) for raw in raws]
    if name == "address_not_digest":
        rows[1]["address"] = sha(b"some other record bytes")
    elif name == "duplicate_address":
        rows.append(dict(rows[1]))
    elif name == "duplicate_identifier":
        rows.append(row(plain_canonical(NamespaceObject.create(
            "clock", "TIME", {"unit": "nanosecond"}).to_dict())))
    elif name == "collection_differs":
        collection = composition_digest(objects[:3])
    elif name == "subject_not_object":
        subject = "clock"
    return objects, rows, collection, subject


MUTANTS = {
    "formatting_whitespace": "not canonical",
    "unescaped_non_ascii": "not canonical",
    "invalid_utf8": "UTF-8",
    "duplicate_member": "strict JSON",
    "inadmissible_kind": "admitted namespace record",
    "address_not_digest": "address differs",
    "duplicate_address": "address occurs twice",
    "duplicate_identifier": "identifier occurs twice",
    "collection_differs": "collection commitment differs",
    "subject_not_object": "OBJECT subject",
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutants_fail_for_their_own_reason(name):
    objects, rows, collection, subject = _mutant(name)
    request, policy, evidence, rows = selected(rows, objects=objects,
                                               collection=collection, subject=subject)
    assert oracle(rows, BOUNDS, subject, request["object_digest"],
                  request["collection_digest"]) == "FAIL"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert MUTANTS[name] in result["evaluation"]["details"], result["evaluation"]["details"]
    assert result["canonical_collection_statics"] == "NOT_ESTABLISHED"
    assert certificate == object_statics.build_object_statics_certificate(
        request, evidence, policy=policy)


def test_budget_exhaustion_and_missing_evidence_remain_unknown():
    request, policy, evidence, _ = selected(limits={"max_operations": 3})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["canonical_collection_statics"] == "NOT_ESTABLISHED"
    request, policy, _, _ = selected(include=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_one_bit_certificate_tamper_is_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    step = max(1, len(certificate) // 17)
    for position in range(0, len(certificate), step):
        tampered = bytearray(certificate)
        tampered[position] ^= 0x01
        with pytest.raises(object_statics.ObjectStaticsError):
            object_statics.recheck_object_statics_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_rehashed_verdict_are_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    other_bounds, _, _, _ = selected(bounds={**BOUNDS, "max_records": 7})
    for substituted in (other_bounds,
                        {**request, "subject_id": "evt"},
                        {**request, "object_kind": "DATA"},
                        {**request, "coordinate": "OBJECT-1.1"}):
        with pytest.raises(object_statics.ObjectStaticsError):
            object_statics.recheck_object_statics_certificate(
                certificate, expected_request=substituted, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(object_statics.ObjectStaticsError):
        object_statics.recheck_object_statics_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = sha(canonical_bytes(forged))
    with pytest.raises(object_statics.ObjectStaticsError):
        object_statics.recheck_object_statics_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    with pytest.raises(object_statics.ObjectStaticsError):
        selected(bounds={**BOUNDS, "max_payload_depth": 65})
    with pytest.raises(object_statics.ObjectStaticsError):
        selected(bounds={**BOUNDS, "max_unknown_thing": 1})
    with pytest.raises(object_statics.ObjectStaticsError):
        object_statics.build_object_statics_certificate(
            request, evidence + b" ", policy=policy)


def test_public_route_inventory_and_kind_selection():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=object_statics.SEMANTIC_VERSION,
        objective=object_statics.COORDINATE, represented_kind="OBJECT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["typed_composition"] == "NOT_ESTABLISHED"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=object_statics.SEMANTIC_VERSION,
            objective=object_statics.COORDINATE, represented_kind="DATA",
            expected_request=request, policy=policy)
    slot = get_slot("OBJECT", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == object_statics.COORDINATE == "OBJECT-3.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.object_statics.recheck_object_statics_certificate")


def test_retained_statics_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("OBJECT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def test_public_command_and_polish_keep_tier_boundary(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", object_statics.SEMANTIC_VERSION,
        "--objective", object_statics.COORDINATE, "--represented-kind", "OBJECT",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": [item.to_dict() for item in records()],
              "certificates": {sha(certificate): certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "doc-root", "collection_digest": request["collection_digest"],
        "bundle_digest": sha(canonical_bytes(bundle)),
        "requirements": [{"object_id": "doc-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected collection statics only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][2]["objectives"] = [{
        "semantic_version": object_statics.SEMANTIC_VERSION,
        "coordinate": object_statics.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": sha(certificate)}]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS", report["objectives"][0]
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["composition_status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


@pytest.mark.parametrize("relative", [
    "domains/contracts/object_statics.py",
    "domains/contracts/retained_selection.py",
    "core/namespace.py",
    "standard/CURRENT_OBJECT_STATICS.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(object_statics.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        object_statics.recheck_object_statics_certificate(
            certificate, expected_request=request, policy=policy)
