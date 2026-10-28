"""Independent fixtures for native declared structural facets across current kinds.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Simulation (SIM).
Fixtures follow NAMESPACE_OBJECTS.md rather than importing the checker's slot table.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import typed_facets as typed_facets_contract
from verifier.domains.contracts.current_object_routes import current_object_route_catalog, replay_current_object_certificate

KINDS = "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()
SEMANTIC = "verifier-current-object-obligations-1"


def coordinate(kind: str) -> str:
    return "OBJECT-1.2" if kind == "OBJECT" else kind + "-1.1"


def test_native_declared_facets_have_distinct_public_objectives() -> None:
    routes = {row["objective"]: row for row in current_object_route_catalog()}
    assert {coordinate(kind) for kind in KINDS} <= routes.keys()
    for kind in KINDS:
        assert routes[coordinate(kind)]["represented_kind_rule"] == kind
        assert routes[coordinate(kind)]["object_profile_conformance"] == "NOT_ESTABLISHED"


def collection() -> list[NamespaceObject]:
    make = NamespaceObject.create
    primitive = "HUMAN ROLE HARDWARE OBJECT SPACE TIME ENV DATA VERIFIER ARCH HARNESS TOKEN".split()
    objects = [make(kind.lower(), kind, {"fixture": kind}) for kind in primitive]
    operands = {
        "ACTOR": {"representation": ["human"], "root_human": ["human"]},
        "COLLECTIVE": {"roles": ["role"]},
        "IDENTITY": {"actor": ["actor"], "role": ["role"]},
        "OWNER": {"actor": ["actor"], "object": ["object"]},
        "RECEIPT": {"subject": ["object"], "hardware": ["hardware"]},
        "EVENT": {"time": ["time"], "space": ["space"], "meaning": ["object"]},
        "BENCH": {"verifier": ["verifier"], "data": ["data"]},
        "TRAIN": {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]},
        "MODEL": {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]},
        "AGENT": {"model": ["model"], "harness": ["harness"], "env": ["env"]},
        "SIM": {"data": ["data"], "verifier": ["verifier"], "objects": ["object"], "env": ["env"]},
        "BOT": {"agent": ["agent"], "sim": ["sim"], "env": ["env"]},
        "HYPER": {"model": ["model"], "identity": ["identity"]},
    }
    objects += [make(kind.lower(), kind, {"fixture": kind}, value) for kind, value in operands.items()]
    objects.append(make("graph", "GRAPH", {"element_kind": "ENV"}, {"members": ["env"]}))
    assert {obj.kind.value for obj in objects} == set(KINDS)
    return objects


def inputs(kind: str, objects: list[NamespaceObject] | None = None, **limits: int) -> tuple[Any, dict, dict, bytes]:
    contract = typed_facets_contract
    objects = collection() if objects is None else objects
    selected = next(obj for obj in objects if obj.object_id == kind.lower())
    evidence = canonical_bytes({"schema_version": contract.COLLECTION_VERSION,
        "objects": [obj.to_dict() for obj in sorted(objects, key=lambda obj: obj.object_id)]})
    policy = contract.typed_facets_policy(trust_roots=["externally-selected-test-records"])
    request = contract.typed_facets_request(object_kind=kind, subject_id=selected.object_id,
        object_digest=selected.digest, collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits or None)
    return contract, request, policy, evidence


def replay(contract: Any, request: dict, policy: dict, evidence: bytes | None) -> dict:
    cert = contract.build_typed_facets_certificate(request, evidence, policy=policy)
    return replay_current_object_certificate(cert, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind=request["object_kind"], expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
def test_native_typed_facets_replay_each_kind_without_profile_promotion(kind: str) -> None:
    contract, request, policy, evidence = inputs(kind)
    result = replay(contract, request, policy, evidence)
    assert result["computational_status"] == "PASS"
    native = result["native_result"]
    assert native["object_kind"] == kind and native["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert native["authority"] == "NOT_ESTABLISHED" and native["payload_semantics"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind", KINDS)
def test_native_facets_refute_a_selected_malformed_kind_contract(kind: str) -> None:
    objects = collection()
    selected = next(obj for obj in objects if obj.object_id == kind.lower())
    operands = {} if kind == "HYPER" else {**selected.to_dict()["operands"], "undeclared": ["object"]}
    broken = NamespaceObject.create(selected.object_id, kind, selected.payload, operands)
    objects = [broken if obj.object_id == selected.object_id else obj for obj in objects]
    contract, request, policy, evidence = inputs(kind, objects)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("case", ["missing", "object-budget", "operation-budget", "byte-budget"])
def test_native_facets_preserve_unknown_for_missing_support_and_bounds(case: str) -> None:
    limits = {"max_objects": 1} if case == "object-budget" else {"max_operations": 1} if case == "operation-budget" else {"max_evidence_bytes": 1} if case == "byte-budget" else {}
    contract, request, policy, evidence = inputs("MODEL", **limits)
    assert replay(contract, request, policy, None if case == "missing" else evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["kind", "subject", "record", "collection", "result"])
def test_native_facets_refuse_substituted_external_selection_or_carried_result(mutation: str) -> None:
    contract, request, policy, evidence = inputs("IDENTITY")
    cert = contract.build_typed_facets_certificate(request, evidence, policy=policy)
    if mutation == "result":
        value = json.loads(cert); value["result"]["authority"] = "PASS"
        value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
        cert = canonical_bytes(value)
    else:
        key, value = {"kind": ("object_kind", "ACTOR"), "subject": ("subject_id", "actor"),
            "record": ("object_digest", "sha256:" + "0" * 64), "collection": ("collection_digest", "sha256:" + "0" * 64)}[mutation]
        request[key] = value
    with pytest.raises(contract.TypedFacetsError):
        contract.recheck_typed_facets_certificate(cert, expected_request=request, policy=policy)


def test_typed_facets_canonical_evidence_cannot_be_redacted() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("IDENTITY")
    value = json.loads(contract.build_typed_facets_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("IDENTITY", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/typed_facets.py", "standard/CURRENT_TYPED_FACETS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_typed_facets_dependencies_invalidate_polish(relative: str, monkeypatch: Any) -> None:
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def substituted(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged typed-facet dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", substituted)
    assert polish.mechanism_digest() != before


def test_two_object_facet_objectives_are_preserved_in_slot_inventory() -> None:
    from verifier.domains.inventory import get_slot
    slot = get_slot("OBJECT", 1).to_dict()
    assert {row["coordinate"] for row in slot["registered_objectives"]} == {"OBJECT-1.1", "OBJECT-1.2"}
    assert slot["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind,role", [("IDENTITY", "actor"), ("RECEIPT", "hardware"), ("EVENT", "time"), ("BENCH", "data"), ("TRAIN", "arch"), ("MODEL", "env"), ("AGENT", "harness"), ("BOT", "sim")])
def test_kind_specific_wrong_operand_types_are_refuted(kind: str, role: str) -> None:
    objects = collection()
    selected = next(obj for obj in objects if obj.object_id == kind.lower())
    operands = selected.to_dict()["operands"]; operands[role] = ["object"]
    broken = NamespaceObject.create(selected.object_id, kind, selected.payload, operands)
    contract, request, policy, evidence = inputs(kind, [broken if obj == selected else obj for obj in objects])
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


def test_polish_binds_native_facets_to_exact_collection_without_promoting_closure() -> None:
    from verifier.runtime.polish import assess_polish
    contract, request, policy, evidence = inputs("IDENTITY")
    certificate = contract.build_typed_facets_certificate(request, evidence, policy=policy)
    certificate_ref = digest(json.loads(certificate))
    objects = collection()
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [obj.to_dict() for obj in objects], "certificates": {certificate_ref: certificate.decode()}}
    selected = {"schema_version": "verifier-polish-request-1", "root_id": "identity", "collection_digest": composition_digest(objects),
        "bundle_digest": digest(bundle), "requirements": [{"object_id": obj.object_id, "tier": tier,
          "applicability": "REQUIRED", "rationale": "Declared structural fixture only", "objectives": []} for obj in objects for tier in range(1, 10)]}
    row = next(row for row in selected["requirements"] if row["object_id"] == "identity" and row["tier"] == 1)
    row["objectives"] = [{"semantic_version": SEMANTIC, "coordinate": request["coordinate"], "request": request, "policy": policy, "certificate_digest": certificate_ref}]
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert result["objectives"][0]["status"] == "PASS"
    assert result["status"] == "UNKNOWN" and result["polished"] is False
    request["collection_digest"] = "sha256:" + "0" * 64
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert result["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"


def test_public_native_facets_command_replays_selected_certificate(tmp_path: Path, capsys: Any) -> None:
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs("MODEL")
    for label, value in (("request", canonical_bytes(request)), ("policy", canonical_bytes(policy)),
                         ("certificate", contract.build_typed_facets_certificate(request, evidence, policy=policy))):
        (tmp_path / (label + ".json")).write_bytes(value)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", "MODEL-1.1", "--represented-kind", "MODEL", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0 and json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("operands", [None, [], False, ""])
def test_native_facets_cannot_normalize_malformed_record_operands(operands: Any) -> None:
    contract, request, policy, evidence = inputs("HUMAN")
    value = json.loads(evidence)
    next(obj for obj in value["objects"] if obj["object_id"] == "human")["operands"] = operands
    request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, canonical_bytes(value))["computational_status"] == "FAIL"


def test_native_facets_plain_selection_refuses_hostile_key_comparison() -> None:
    contract, request, policy, evidence = inputs("IDENTITY")
    class Key(str):
        __hash__ = str.__hash__
        def __eq__(self, other: Any) -> bool:
            raise AssertionError("caller comparison executed")
    request[Key("schema_version")] = request.pop("schema_version")
    with pytest.raises(contract.TypedFacetsError):
        contract.build_typed_facets_certificate(request, evidence, policy=policy)


def test_native_facets_collection_order_changes_evidence_without_changing_composition() -> None:
    contract, request, policy, evidence = inputs("IDENTITY")
    value = json.loads(evidence); value["objects"].reverse()
    request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, canonical_bytes(value))["computational_status"] == "PASS"
