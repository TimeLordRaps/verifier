"""Selected finite reachable address closure of a root of any admitted kind.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts and checking budgets are dimensionless.
The oracle resolves references by recursive depth-first search with the
standard library only; the checker uses a bounded iterative walk instead.
The primary fixture is a namespace-valid collection whose typed composition
PASSes; a differential keeps the closure separate from typed composition.
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
from verifier.domains.contracts import object_address_closure as closure
from verifier.domains.inventory import get_slot


ROOT = "receipt"
ROOT_KIND = "RECEIPT"


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def plain_canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def base() -> dict[str, NamespaceObject]:
    # RECEIPT -> EVENT -> TIME/SPACE/OBJECT, with HARDWARE reached twice: every
    # role is a `_SLOTS` role with an admitted operand kind, so the collection
    # is namespace-valid and the closure is more than one level deep.
    items = (
        NamespaceObject.create(ROOT, "RECEIPT", {"status": "issued"},
                               {"subject": ["event"], "hardware": ["hw"]}),
        NamespaceObject.create("event", "EVENT", {"label": "run"},
                               {"time": ["t0"], "space": ["s0"], "meaning": ["note", "hw"]}),
        NamespaceObject.create("t0", "TIME", {"tick": 0}),
        NamespaceObject.create("s0", "SPACE", {"frame": "lab"}),
        NamespaceObject.create("hw", "HARDWARE", {"model": "board"}),
        NamespaceObject.create("note", "OBJECT", {"text": "note"}),
        NamespaceObject.create("other", "DATA", {"rows": 2}),
    )
    return {item.object_id: item for item in items}


class _Cycle(Exception):
    pass


def manifest(rows: list[dict], names: list[str], root: str = ROOT) -> str:
    by_id = {value["object_id"]: value for value in rows}
    return sha(plain_canonical({"schema_version": "verifier-object-address-closure-1",
        "root_id": root,
        "addresses": [{"object_id": name, "record_digest": sha(plain_canonical(by_id[name]))}
                      for name in sorted(names)]}))


def oracle(rows: list[dict], root: str, object_kind: str, object_digest: str,
           collection_digest: str, closure_digest: str) -> str:
    by_id: dict[str, dict] = {}
    for value in rows:
        if value["object_id"] in by_id:
            return "FAIL"
        by_id[value["object_id"]] = value
    collection = sha(plain_canonical({"schema_version": "verifier-object-composition-1",
        "objects": sorted(rows, key=lambda value: value["object_id"])}))
    if collection != collection_digest or root not in by_id:
        return "FAIL"
    if sha(plain_canonical(by_id[root])) != object_digest or by_id[root]["kind"] != object_kind:
        return "FAIL"
    state: dict[str, str] = {}

    def visit(name: str) -> None:
        if name not in by_id:
            raise LookupError(name)
        if state.get(name) == "active":
            raise _Cycle(name)
        if state.get(name) == "done":
            return
        state[name] = "active"
        for targets in by_id[name]["operands"].values():
            for target in targets:
                visit(target)
        state[name] = "done"

    try:
        visit(root)
    except (LookupError, _Cycle):
        return "FAIL"
    return "PASS" if manifest(rows, list(state), root) == closure_digest else "FAIL"


REACHED = [ROOT, "event", "t0", "s0", "hw", "note"]


def selected(rows: list[dict] | None = None, *, objects: list[NamespaceObject] | None = None,
             closure_digest: str | None = None, collection: str | None = None,
             include: bool = True, limits: dict | None = None, root: str = ROOT,
             object_kind: str | None = None, object_digest: str | None = None):
    objects = objects if objects is not None else list(base().values())
    rows = rows if rows is not None else [item.to_dict() for item in objects]
    evidence = canonical_bytes({"schema_version": closure.EVIDENCE_VERSION, "objects": rows})
    root_item = [item for item in objects if item.object_id == root][0]
    policy = closure.object_address_closure_policy(trust_roots=["closure-root"])
    base_rows = [item.to_dict() for item in base().values()]
    request = closure.object_address_closure_request(
        subject_id=root, object_kind=object_kind or root_item.kind.value,
        object_digest=object_digest or root_item.digest,
        collection_digest=collection or composition_digest(objects),
        closure_digest=closure_digest or manifest(base_rows, REACHED, root),
        evidence_ref=sha(evidence) if include else "sha256:" + "0" * 64,
        policy=policy, limits=limits)
    return request, policy, (evidence if include else None), rows


def check(rows: list[dict], request: dict) -> str:
    return oracle(rows, request["subject_id"], request["object_kind"], request["object_digest"],
                  request["collection_digest"], request["closure_digest"])


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = closure.build_object_address_closure_certificate(
        request, evidence, policy=policy)
    result = closure.recheck_object_address_closure_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_primary_fixture_is_namespace_valid_and_its_typed_composition_passes():
    objects = list(base().values())
    assessment = assess_composition(objects, expected_digest=composition_digest(objects))
    assert assessment.verdict.value == "PASS", assessment.reason


def test_complete_acyclic_reachable_closure_passes_and_rechecks_from_bytes():
    request, policy, evidence, rows = selected()
    assert request["object_kind"] == ROOT_KIND
    assert check(rows, request) == "PASS"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["object_kind"] == ROOT_KIND
    assert result["reachable_address_closure"] == "PASS"
    for field in ("typed_composition", "receipt_to_subject_closure", "payload_truth",
                  "whole_object_closure", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    observations = result["evaluation"]["observations"]
    assert observations["reached_records"] == len(REACHED)
    # Six references: two from the root (`hardware`, `subject`) and four from
    # the EVENT record (`meaning` x2, `space`, `time`); the second reference to
    # `hw` is checked but adds no reached record.
    assert observations["references"] == sum(
        len(targets) for item in base().values() if item.object_id in REACHED
        for _, targets in item.operands) == 6
    assert closure.recheck_object_address_closure_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))["status"] == "PASS"


@pytest.mark.parametrize("root, reached", [
    ("event", ["event", "t0", "s0", "hw", "note"]),
    ("note", ["note"]),
    ("hw", ["hw"]),
    ("other", ["other"]),
])
def test_any_admitted_kind_may_be_the_selected_root(root, reached):
    items = base()
    rows = [item.to_dict() for item in items.values()]
    request, policy, evidence, rows = selected(root=root,
        closure_digest=manifest(rows, reached, root))
    assert request["object_kind"] == items[root].kind.value
    assert check(rows, request) == "PASS"
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "PASS" and result["object_kind"] == items[root].kind.value
    assert result["evaluation"]["observations"]["reached_records"] == len(reached)


def test_closure_is_independent_of_typed_composition_and_unrelated_records():
    # Differential, not the primary PASS case: records outside the reachable
    # closure break typed composition (an operand-bearing OBJECT record and a
    # dangling reference), yet the selected closure is unaffected.
    objects = list(base().values()) + [
        NamespaceObject.create("legacy", "OBJECT", {"text": "l"}, {"parts": ["note"]}),
        NamespaceObject.create("stray", "OBJECT", {"text": "s"}, {"ref": ["nowhere"]}),
    ]
    assert assess_composition(objects, expected_digest=composition_digest(objects)
                              ).verdict.value == "FAIL"
    request, policy, evidence, rows = selected(objects=objects)
    assert check(rows, request) == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "PASS"


def test_closure_commitment_binds_referenced_contents_the_record_digest_omits():
    items = base()
    changed = dict(items)
    changed["t0"] = NamespaceObject.create("t0", "TIME", {"tick": 1})
    assert changed[ROOT].digest == items[ROOT].digest
    request, policy, evidence, rows = selected(objects=list(changed.values()))
    assert check(rows, request) == "FAIL"
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "closure commitment differs" in result["evaluation"]["details"]


def _mutant(name: str) -> dict:
    items = base()
    options: dict = {}
    if name == "dangling_reference":
        items["event"] = NamespaceObject.create("event", "EVENT", {"label": "run"},
            {"time": ["t0"], "space": ["s0"], "meaning": ["note", "hw", "missing"]})
    elif name == "reference_cycle":
        items["note"] = NamespaceObject.create("note", "OBJECT", {"text": "note"},
                                               {"back": [ROOT]})
    elif name == "overclaimed_closure":
        options["closure_digest"] = manifest([item.to_dict() for item in items.values()],
                                             REACHED + ["other"])
    elif name == "underclaimed_closure":
        options["closure_digest"] = manifest([item.to_dict() for item in items.values()],
                                             [value for value in REACHED if value != "note"])
    elif name == "inadmissible_kind":
        rows = [item.to_dict() for item in items.values()]
        rows[5] = {**rows[5], "kind": "VSTD"}
        options["rows"] = rows
    elif name == "duplicate_target":
        rows = [item.to_dict() for item in items.values()]
        rows[0] = deepcopy(rows[0])
        rows[0]["operands"]["subject"] = ["event", "event"]
        options["rows"] = rows
    elif name == "duplicate_identifier":
        rows = [item.to_dict() for item in items.values()]
        rows.append(NamespaceObject.create("note", "OBJECT", {"text": "twin"}).to_dict())
        options["rows"] = rows
    elif name == "collection_differs":
        options["collection"] = composition_digest(list(items.values())[:6])
    elif name == "selected_kind_differs":
        # The retained root is exactly the selected record, but the request
        # selects it as an EVENT: a kind the record does not carry.
        options["object_kind"] = "EVENT"
    elif name == "selected_identity_differs":
        # Same identifier and kind, different record: the request selects the
        # original receipt digest while the collection retains another record.
        options["object_digest"] = items[ROOT].digest
        items[ROOT] = NamespaceObject.create(ROOT, "RECEIPT", {"status": "revoked"},
                                             {"subject": ["event"], "hardware": ["hw"]})
    options["objects"] = list(items.values())
    return options


MUTANTS = {
    "dangling_reference": "dangling reference",
    "reference_cycle": "cycle",
    "overclaimed_closure": "closure commitment differs",
    "underclaimed_closure": "closure commitment differs",
    "inadmissible_kind": "admitted namespace record",
    "duplicate_target": "admitted namespace record",
    "duplicate_identifier": "identifier occurs twice",
    "collection_differs": "collection commitment differs",
    "selected_kind_differs": "selected root kind differs",
    "selected_identity_differs": "selected root identity differs",
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutants_fail_for_their_own_reason(name):
    options = _mutant(name)
    rows = options.pop("rows", None)
    request, policy, evidence, rows = selected(rows, **options)
    if name not in ("inadmissible_kind", "duplicate_target"):
        assert check(rows, request) == "FAIL"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert MUTANTS[name] in result["evaluation"]["details"], result["evaluation"]["details"]
    assert result["reachable_address_closure"] == "NOT_ESTABLISHED"
    assert certificate == closure.build_object_address_closure_certificate(
        request, evidence, policy=policy)


def test_budget_exhaustion_and_missing_evidence_remain_unknown():
    request, policy, evidence, _ = selected(limits={"max_operations": 3})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["reachable_address_closure"] == "NOT_ESTABLISHED"
    request, policy, _, _ = selected(include=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_one_bit_certificate_tamper_is_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    step = max(1, len(certificate) // 17)
    for position in range(0, len(certificate), step):
        tampered = bytearray(certificate)
        tampered[position] ^= 0x01
        with pytest.raises(closure.ObjectAddressClosureError):
            closure.recheck_object_address_closure_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_rehashed_verdict_are_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    for substituted in ({**request, "subject_id": "event"},
                        {**request, "closure_digest": sha(b"other closure")},
                        {**request, "object_kind": "EVENT"},
                        {**request, "object_kind": "OBJECT"},
                        {**request, "object_kind": "VSTD"},
                        {**request, "coordinate": "OBJECT-4.1"}):
        with pytest.raises(closure.ObjectAddressClosureError):
            closure.recheck_object_address_closure_certificate(
                certificate, expected_request=substituted, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(closure.ObjectAddressClosureError):
        closure.recheck_object_address_closure_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = sha(canonical_bytes(forged))
    with pytest.raises(closure.ObjectAddressClosureError):
        closure.recheck_object_address_closure_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    with pytest.raises(closure.ObjectAddressClosureError):
        selected(closure_digest="sha256:XYZ")
    with pytest.raises(closure.ObjectAddressClosureError):
        selected(object_kind="VSTD")
    with pytest.raises(closure.ObjectAddressClosureError):
        closure.build_object_address_closure_certificate(
            request, evidence + b" ", policy=policy)


def test_public_route_inventory_and_kind_selection():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=closure.SEMANTIC_VERSION,
        objective=closure.COORDINATE, represented_kind=ROOT_KIND,
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["object_kind"] == ROOT_KIND
    assert report["native_result"]["receipt_to_subject_closure"] == "NOT_ESTABLISHED"
    for other in ("OBJECT", "EVENT", "VSTD"):
        with pytest.raises(routes.CurrentObjectRouteRefusal):
            routes.replay_current_object_certificate(
                certificate, semantic_version=closure.SEMANTIC_VERSION,
                objective=closure.COORDINATE, represented_kind=other,
                expected_request=request, policy=policy)
    row = {item["objective"]: item for item in routes.current_object_route_catalog()}[
        closure.COORDINATE]
    assert row["represented_kind_rule"] == "externally_selected_admitted_kind"
    slot = get_slot("OBJECT", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == closure.COORDINATE == "OBJECT-4.2"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.object_address_closure."
        "recheck_object_address_closure_certificate")


def test_retained_closure_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface(ROOT_KIND, fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def _polish(rows: list[dict], request: dict, policy: dict, certificate: bytes,
            object_id: str = ROOT) -> dict:
    from verifier.runtime.polish import assess_polish

    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": rows,
              "certificates": {sha(certificate): certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": ROOT, "collection_digest": request["collection_digest"],
        "bundle_digest": sha(canonical_bytes(bundle)),
        "requirements": [{"object_id": object_id, "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected address closure only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][3]["objectives"] = [{
        "semantic_version": closure.SEMANTIC_VERSION,
        "coordinate": closure.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": sha(certificate)}]
    return assess_polish(canonical_bytes(bundle),
                         request_bytes=canonical_bytes(selected_request))


def test_public_command_and_polish_on_a_namespace_valid_collection(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence, rows = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", closure.SEMANTIC_VERSION,
        "--objective", closure.COORDINATE, "--represented-kind", ROOT_KIND,
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    report = _polish(rows, request, policy, certificate)
    assert report["objectives"][0]["status"] == "PASS", report["objectives"][0]
    assert report["composition_status"] == "PASS"
    # Overall polish never reports PASS: runtime/polish.py sets UNKNOWN when
    # nothing FAILs, because applicable-objective inventory closure stays open.
    assert report["status"] == "UNKNOWN" and report["polished"] is False


def test_polish_refuses_the_certificate_on_another_record():
    request, policy, evidence, rows = selected()
    certificate, _ = replay(request, policy, evidence)
    report = _polish(rows, request, policy, certificate, object_id="event")
    assert report["objectives"][0]["status"] == "FAIL", report["objectives"][0]
    assert report["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert report["composition_status"] == "PASS"
    assert report["status"] == "FAIL" and report["polished"] is False


@pytest.mark.parametrize("relative", [
    "domains/contracts/object_address_closure.py",
    "domains/contracts/retained_selection.py",
    "core/namespace.py",
    "standard/CURRENT_OBJECT_ADDRESS_CLOSURE.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(closure.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        closure.recheck_object_address_closure_certificate(
            certificate, expected_request=request, policy=policy)
