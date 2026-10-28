"""Selected finite version lineage of any admitted kind, not revision history.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Version numbers, counts and checking budgets are
dimensionless. The oracle sorts declared versions and recomputes every
predecessor and operand pin with the standard library only; the checker walks
predecessors from the selected head instead. The primary fixture is a
namespace-valid collection whose typed composition PASSes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, assess_composition, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import object_lineage
from verifier.domains.inventory import get_slot


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def plain_canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def version(object_id: str, number: int, predecessor: str | None, operands: dict,
            pins: dict, text: str, *, lineage: str = "run",
            kind: str = "RECEIPT") -> NamespaceObject:
    return NamespaceObject.create(object_id, kind, {
        "lineage": {"lineage_id": lineage, "version": number,
                    "predecessor": predecessor, "operand_digests": dict(pins)},
        "text": text}, operands)


def receipt_operands(*subjects: str) -> dict:
    return {"subject": list(subjects), "hardware": ["hw"]}


def base(*, dataset_rows: int = 3) -> dict[str, NamespaceObject]:
    # Three RECEIPT versions whose operands are real typed RECEIPT roles
    # (`subject` admits any kind, `hardware` admits HARDWARE) and one OBJECT
    # version with no operands: the collection is namespace-valid.
    hw = NamespaceObject.create("hw", "HARDWARE", {"model": "board"})
    dataset = NamespaceObject.create("dataset", "DATA", {"rows": dataset_rows})
    notes = NamespaceObject.create("notes", "OBJECT", {"text": "n"})
    v1 = version("run-v1", 1, None, receipt_operands("dataset"),
                 {"dataset": dataset.digest, "hw": hw.digest}, "first")
    v2 = version("run-v2", 2, v1.digest, receipt_operands("dataset", "notes"),
                 {"dataset": dataset.digest, "notes": notes.digest, "hw": hw.digest}, "second")
    v3 = version("run-v3", 3, v2.digest, receipt_operands("notes"),
                 {"notes": notes.digest, "hw": hw.digest}, "third")
    other = version("other-v1", 1, None, {}, {}, "unrelated lineage", lineage="other",
                    kind="OBJECT")
    return {item.object_id: item for item in (hw, dataset, notes, v1, v2, v3, other)}


HEAD, LINEAGE, HEAD_KIND = "run-v3", "run", "RECEIPT"


def oracle(rows: list[dict], head: str, lineage_id: str, object_kind: str,
           object_digest: str, collection_digest: str) -> str:
    by_id: dict[str, dict] = {}
    for value in rows:
        if value["object_id"] in by_id:
            return "FAIL"
        by_id[value["object_id"]] = value
    collection = sha(plain_canonical({"schema_version": "verifier-object-composition-1",
        "objects": sorted(rows, key=lambda value: value["object_id"])}))
    if collection != collection_digest or head not in by_id:
        return "FAIL"
    if sha(plain_canonical(by_id[head])) != object_digest:
        return "FAIL"
    members = [value for value in rows
               if isinstance(value["payload"].get("lineage"), dict)
               and value["payload"]["lineage"].get("lineage_id") == lineage_id]
    members.sort(key=lambda value: value["payload"]["lineage"]["version"])
    numbers = [value["payload"]["lineage"]["version"] for value in members]
    if not members or numbers != list(range(1, len(members) + 1)):
        return "FAIL"
    if members[-1]["object_id"] != head:
        return "FAIL"
    previous = None
    for value in members:
        lineage = value["payload"]["lineage"]
        if value["kind"] != object_kind:
            return "FAIL"
        expected = None if previous is None else sha(plain_canonical(previous))
        if lineage["predecessor"] != expected:
            return "FAIL"
        targets = [target for group in value["operands"].values() for target in group]
        if sorted(set(targets)) != sorted(lineage["operand_digests"]):
            return "FAIL"
        for target in targets:
            if (target not in by_id
                    or sha(plain_canonical(by_id[target])) != lineage["operand_digests"][target]):
                return "FAIL"
        previous = value
    return "PASS"


def selected(objects: list[NamespaceObject] | None = None, *, head: str = HEAD,
             lineage_id: str = LINEAGE, include: bool = True,
             limits: dict | None = None, collection: str | None = None,
             object_kind: str | None = None, object_digest: str | None = None):
    objects = objects if objects is not None else list(base().values())
    rows = [item.to_dict() for item in objects]
    evidence = canonical_bytes({"schema_version": object_lineage.EVIDENCE_VERSION,
                                "objects": rows})
    head_item = [item for item in objects if item.object_id == head][0]
    policy = object_lineage.object_lineage_policy(trust_roots=["lineage-root"])
    request = object_lineage.object_lineage_request(
        subject_id=head, object_kind=object_kind or head_item.kind.value,
        object_digest=object_digest or head_item.digest,
        collection_digest=collection or composition_digest(objects),
        lineage_id=lineage_id,
        evidence_ref=sha(evidence) if include else "sha256:" + "0" * 64,
        policy=policy, limits=limits)
    return request, policy, (evidence if include else None), rows


def check(rows: list[dict], request: dict) -> str:
    return oracle(rows, request["subject_id"], request["lineage_id"], request["object_kind"],
                  request["object_digest"], request["collection_digest"])


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = object_lineage.build_object_lineage_certificate(
        request, evidence, policy=policy)
    result = object_lineage.recheck_object_lineage_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_primary_fixture_is_namespace_valid_and_its_typed_composition_passes():
    objects = list(base().values())
    assessment = assess_composition(objects, expected_digest=composition_digest(objects))
    assert assessment.verdict.value == "PASS", assessment.reason


def test_consecutive_pinned_lineage_passes_and_rechecks_from_bytes():
    request, policy, evidence, rows = selected()
    assert request["object_kind"] == HEAD_KIND
    assert check(rows, request) == "PASS"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["object_kind"] == HEAD_KIND
    assert result["version_lineage_progression"] == "PASS"
    for field in ("typed_composition", "actual_revision_history", "payload_truth",
                  "whole_object_dynamics", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["versions"] == 3
    assert result["evaluation"]["observations"]["pinned_operands"] == 7
    assert object_lineage.recheck_object_lineage_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))["status"] == "PASS"


def test_single_version_lineage_of_another_kind_and_unrelated_records_pass():
    request, policy, evidence, rows = selected(head="other-v1", lineage_id="other")
    assert request["object_kind"] == "OBJECT"
    assert check(rows, request) == "PASS"
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "PASS" and result["object_kind"] == "OBJECT"


def _mutant(name: str) -> dict:
    items = base()
    options: dict = {}
    hw, dataset, notes, v1, v2 = (items["hw"], items["dataset"], items["notes"],
                                  items["run-v1"], items["run-v2"])
    v3_pins = {"notes": notes.digest, "hw": hw.digest}
    if name == "skipped_version":
        items.pop("run-v2")
        items["run-v3"] = version("run-v3", 3, v1.digest, receipt_operands("notes"),
                                  v3_pins, "third")
    elif name == "unretained_predecessor":
        items["run-v3"] = version("run-v3", 3, sha(b"elsewhere"), receipt_operands("notes"),
                                  v3_pins, "third")
    elif name == "stale_operand_pin":
        items["dataset"] = NamespaceObject.create("dataset", "DATA", {"rows": 4})
    elif name == "fork":
        items["run-v2b"] = version("run-v2b", 2, v1.digest, receipt_operands("notes"),
                                   v3_pins, "branch")
    elif name == "later_version":
        items["run-v4"] = version("run-v4", 4, items["run-v3"].digest,
                                  receipt_operands("notes"), v3_pins, "fourth")
    elif name == "dangling_operand":
        items["run-v3"] = version("run-v3", 3, v2.digest, receipt_operands("notes", "ghost"),
                                  {**v3_pins, "ghost": sha(b"ghost")}, "third")
    elif name == "unpinned_operand":
        items["run-v3"] = version("run-v3", 3, v2.digest,
                                  receipt_operands("dataset", "notes"), v3_pins, "third")
    elif name == "genesis_with_predecessor":
        new_v1 = version("run-v1", 1, sha(b"before"), receipt_operands("dataset"),
                         {"dataset": dataset.digest, "hw": hw.digest}, "first")
        new_v2 = version("run-v2", 2, new_v1.digest, receipt_operands("dataset", "notes"),
                         {"dataset": dataset.digest, "notes": notes.digest, "hw": hw.digest},
                         "second")
        items.update({"run-v1": new_v1, "run-v2": new_v2,
                      "run-v3": version("run-v3", 3, new_v2.digest, receipt_operands("notes"),
                                        v3_pins, "third")})
    elif name == "lineage_identifier_changes":
        new_v2 = version("run-v2", 2, v1.digest, receipt_operands("dataset", "notes"),
                         {"dataset": dataset.digest, "notes": notes.digest, "hw": hw.digest},
                         "second", lineage="run-renamed")
        items.update({"run-v2": new_v2,
                      "run-v3": version("run-v3", 3, new_v2.digest, receipt_operands("notes"),
                                        v3_pins, "third")})
    elif name == "wrong_lineage_selected":
        options["lineage_id"] = "other"
    elif name == "version_kind_differs":
        # The predecessor is an OBJECT record while the selected kind is RECEIPT.
        new_v2 = version("run-v2", 2, v1.digest, receipt_operands("dataset", "notes"),
                         {"dataset": dataset.digest, "notes": notes.digest, "hw": hw.digest},
                         "second", kind="OBJECT")
        items.update({"run-v2": new_v2,
                      "run-v3": version("run-v3", 3, new_v2.digest, receipt_operands("notes"),
                                        v3_pins, "third")})
    elif name == "selected_kind_differs":
        # The retained head is exactly the selected record, selected as OBJECT.
        options["object_kind"] = "OBJECT"
    elif name == "selected_identity_differs":
        # Same identifier and kind, different record at the head.
        options["object_digest"] = items["run-v3"].digest
        items["run-v3"] = version("run-v3", 3, v2.digest, receipt_operands("notes"),
                                  v3_pins, "third, revised")
    options["objects"] = list(items.values())
    return options


MUTANTS = {
    "skipped_version": "consecutive",
    "unretained_predecessor": "predecessor is not retained",
    "stale_operand_pin": "operand digest differs",
    "fork": "outside the selected chain",
    "later_version": "not the latest",
    "dangling_operand": "operand is not retained",
    "unpinned_operand": "operand pins differ",
    "genesis_with_predecessor": "first version has a predecessor",
    "lineage_identifier_changes": "lineage identifier",
    "wrong_lineage_selected": "lineage identifier",
    "version_kind_differs": "lineage version kind differs",
    "selected_kind_differs": "selected head kind differs",
    "selected_identity_differs": "selected head identity differs",
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutants_fail_for_their_own_reason(name):
    options = _mutant(name)
    request, policy, evidence, rows = selected(options.pop("objects"), **options)
    assert check(rows, request) == "FAIL"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert MUTANTS[name] in result["evaluation"]["details"], result["evaluation"]["details"]
    assert result["version_lineage_progression"] == "NOT_ESTABLISHED"
    assert certificate == object_lineage.build_object_lineage_certificate(
        request, evidence, policy=policy)


def test_substituted_collection_and_duplicate_identifier_fail():
    request, policy, evidence, _ = selected(
        collection=composition_digest(list(base().values())[:5]))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    objects = list(base().values())
    duplicate = NamespaceObject.create("notes", "OBJECT", {"text": "other"})
    rows = [item.to_dict() for item in objects] + [duplicate.to_dict()]
    evidence = canonical_bytes({"schema_version": object_lineage.EVIDENCE_VERSION,
                                "objects": rows})
    request = {**request, "collection_digest": composition_digest(objects),
               "evidence_ref": sha(evidence)}
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "identifier occurs twice" in result["evaluation"]["details"]


def test_budget_exhaustion_and_missing_evidence_remain_unknown():
    request, policy, evidence, _ = selected(limits={"max_operations": 3})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["version_lineage_progression"] == "NOT_ESTABLISHED"
    request, policy, _, _ = selected(include=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_one_bit_certificate_tamper_is_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    step = max(1, len(certificate) // 17)
    for position in range(0, len(certificate), step):
        tampered = bytearray(certificate)
        tampered[position] ^= 0x01
        with pytest.raises(object_lineage.ObjectLineageError):
            object_lineage.recheck_object_lineage_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_rehashed_verdict_are_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    previous_head, _, _, _ = selected(head="run-v2")
    for substituted in (previous_head,
                        {**request, "lineage_id": "other"},
                        {**request, "object_kind": "DATA"},
                        {**request, "object_kind": "OBJECT"},
                        {**request, "object_kind": "VSTD"},
                        {**request, "coordinate": "OBJECT-1.1"}):
        with pytest.raises(object_lineage.ObjectLineageError):
            object_lineage.recheck_object_lineage_certificate(
                certificate, expected_request=substituted, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(object_lineage.ObjectLineageError):
        object_lineage.recheck_object_lineage_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = sha(canonical_bytes(forged))
    with pytest.raises(object_lineage.ObjectLineageError):
        object_lineage.recheck_object_lineage_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    with pytest.raises(object_lineage.ObjectLineageError):
        selected(lineage_id=" ")
    with pytest.raises(object_lineage.ObjectLineageError):
        selected(object_kind="VSTD")
    with pytest.raises(object_lineage.ObjectLineageError):
        object_lineage.build_object_lineage_certificate(
            request, evidence + b" ", policy=policy)


def test_public_route_inventory_and_kind_selection():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=object_lineage.SEMANTIC_VERSION,
        objective=object_lineage.COORDINATE, represented_kind=HEAD_KIND,
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["object_kind"] == HEAD_KIND
    assert report["native_result"]["actual_revision_history"] == "NOT_ESTABLISHED"
    for other in ("OBJECT", "DATA", "VSTD"):
        with pytest.raises(routes.CurrentObjectRouteRefusal):
            routes.replay_current_object_certificate(
                certificate, semantic_version=object_lineage.SEMANTIC_VERSION,
                objective=object_lineage.COORDINATE, represented_kind=other,
                expected_request=request, policy=policy)
    row = {item["objective"]: item for item in routes.current_object_route_catalog()}[
        object_lineage.COORDINATE]
    assert row["represented_kind_rule"] == "externally_selected_admitted_kind"
    slot = get_slot("OBJECT", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == object_lineage.COORDINATE == "OBJECT-2.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.object_lineage.recheck_object_lineage_certificate")


def test_retained_lineage_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface(HEAD_KIND, fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def test_public_command_and_polish_on_a_namespace_valid_collection(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence, rows = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", object_lineage.SEMANTIC_VERSION,
        "--objective", object_lineage.COORDINATE, "--represented-kind", HEAD_KIND,
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": rows,
              "certificates": {sha(certificate): certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": HEAD, "collection_digest": request["collection_digest"],
        "bundle_digest": sha(canonical_bytes(bundle)),
        "requirements": [{"object_id": HEAD, "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected version lineage only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][1]["objectives"] = [{
        "semantic_version": object_lineage.SEMANTIC_VERSION,
        "coordinate": object_lineage.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": sha(certificate)}]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS", report["objectives"][0]
    assert report["composition_status"] == "PASS"
    # Overall polish never reports PASS: runtime/polish.py sets UNKNOWN when
    # nothing FAILs, because applicable-objective inventory closure stays open.
    assert report["status"] == "UNKNOWN" and report["polished"] is False


@pytest.mark.parametrize("relative", [
    "domains/contracts/object_lineage.py",
    "domains/contracts/retained_selection.py",
    "core/namespace.py",
    "standard/CURRENT_OBJECT_LINEAGE.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(object_lineage.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        object_lineage.recheck_object_lineage_certificate(
            certificate, expected_request=request, policy=policy)
