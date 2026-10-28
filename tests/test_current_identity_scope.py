"""Independent current Verifier Standard (VSTD) identity-scope acceptance cases."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import identity_scope
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
COORDINATE = "IDENTITY-3.1"


def specimen(kind: str = "HUMAN"):
    if kind != "HUMAN":
        from test_identity_occupancy_contract import specimen as represented
        return represented(kind)
    make = NamespaceObject.create
    declaration = {"schema_version": "verifier-namespace-identity-evidence-1",
        "identity_id": "identity", "actor_id": "actor", "role_id": "role",
        "collective_id": "collective", "representation_id": "human", "actor_kind": "HUMAN",
        "root_human_id": "human", "scope": "team:research", "evidence_ref": digest("unresolved-source")}
    objects = [make("human", "HUMAN", {}),
        make("role", "ROLE", {"admitted_scopes": ["team:research"]}),
        make("collective", "COLLECTIVE", {}, {"roles": ["role"]}),
        make("actor", "ACTOR", {}, {"representation": ["human"], "root_human": ["human"]}),
        make("identity", "IDENTITY", {"scope": "team:research", "binding_evidence_digest": digest(declaration)},
             {"actor": ["actor"], "role": ["role"]})]
    return objects, declaration


def inputs(kind: str = "HUMAN", *, objects=None, declaration=None, **limits):
    contract = identity_scope
    if objects is None:
        objects, declaration = specimen(kind)
    evidence = canonical_bytes({"schema_version": "verifier-current-identity-scope-evidence-1",
        "objects": [obj.to_dict() for obj in objects], "declaration": declaration})
    policy = contract.identity_scope_policy(trust_roots=["selected-declarations-only"])
    subject = next(obj for obj in objects if obj.object_id == "identity")
    request = contract.identity_scope_request(subject_id="identity", object_digest=subject.digest,
        collective_id="collective", declaration_digest=digest(declaration),
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_identity_scope_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=COORDINATE, represented_kind="IDENTITY", expected_request=request, policy=policy)


def test_identity_scope_is_a_distinct_registered_static_objective():
    route = routes.select_current_object_route(semantic_version=SEMANTIC,
        objective=COORDINATE, represented_kind="IDENTITY")
    assert route.fixed_kind == "IDENTITY"
    assert route.scope == "finite_declared_identity_role_scope_admission"
    assert route.module.CERTIFICATE_VERSION == "verifier-current-identity-scope-certificate-1"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version=SEMANTIC, objective=COORDINATE, represented_kind="ACTOR")


@pytest.mark.parametrize("bound", ["max_objects", "max_operations", "max_payload_bytes", "max_reference_bytes", "max_relation_steps"])
def test_native_identity_caller_selected_bounds_are_exercised(bound):
    from verifier.domains.contracts.identity_occupancy import assess_identity_occupancy
    objects, declaration = specimen()
    result = assess_identity_occupancy(objects, identity_id="identity", collective_id="collective",
        expected_digest=composition_digest(objects), expected_evidence_digest=digest(declaration),
        evidence=declaration, **{bound: 1})
    assert result["status"] == "UNKNOWN"
    assert "bound" in result["reason"]


@pytest.mark.parametrize("kind", ["HUMAN", "AGENT", "BOT"])
def test_native_identity_declarations_replay_without_authority_promotion(kind):
    contract, request, policy, evidence = inputs(kind)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS"
    result = report["native_result"]
    assert result["scope"] == "finite_declared_identity_role_scope_admission"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    facts = result["evaluation"]["observations"]["identity_assessment"]
    assert facts["actor_kind"] == kind
    for field in ("human_authenticity", "role_authority", "occupancy_liveness", "evidence_ref_resolution", "privacy", "consent", "governance"):
        assert facts[field] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("case", ["missing", "max_objects", "max_operations", "max_payload_bytes", "max_reference_bytes", "max_relation_steps", "max_evidence_bytes"])
def test_identity_missing_support_and_each_selected_bound_remain_unknown(case):
    contract, request, policy, evidence = inputs(**({case: 1} if case != "missing" else {}))
    assert replay(contract, request, policy, None if case == "missing" else evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("actor_id", "other"), ("role_id", "other"),
    ("collective_id", "other"), ("root_human_id", "other"), ("scope", "outside"),
    ("actor_kind", "BOT"), ("identity_id", "other"), ("representation_id", "other")])
def test_rebound_false_identity_declaration_is_refuted(field, value):
    objects, declaration = specimen()
    declaration[field] = value
    selected = objects[-1]
    objects[-1] = NamespaceObject.create("identity", "IDENTITY",
        {"scope": declaration["scope"], "binding_evidence_digest": digest(declaration)}, selected.to_dict()["operands"])
    contract, request, policy, evidence = inputs(objects=objects, declaration=declaration)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "collective_id", "declaration_digest", "evidence_ref", "policy_digest"])
def test_identity_external_selection_cannot_be_substituted(field):
    contract, request, policy, evidence = inputs()
    certificate = contract.build_identity_scope_certificate(request, evidence, policy=policy)
    request[field] = "other" if field.endswith("_id") else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_identity_scope_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["status", "authority", "object_profile_conformance"])
def test_rehashed_identity_result_cannot_upgrade_or_replace_native_evidence(field):
    contract, request, policy, evidence = inputs()
    value = json.loads(contract.build_identity_scope_certificate(request, evidence, policy=policy))
    value["result"][field] = "FAIL" if field == "status" else "PASS"
    value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_identity_scope_certificate(canonical_bytes(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("operands", [None, [], False, ""])
def test_identity_retained_records_cannot_normalize_malformed_operands(operands):
    contract, request, policy, evidence = inputs()
    value = json.loads(evidence); value["objects"][0]["operands"] = operands
    request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, canonical_bytes(value))["computational_status"] == "FAIL"


def test_identity_certificate_cannot_shed_retained_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs()
    value = json.loads(contract.build_identity_scope_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("IDENTITY", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/identity_scope.py", "domains/contracts/identity_occupancy.py", "standard/CURRENT_IDENTITY_SCOPE.md", "standard/IDENTITY_OCCUPANCY.md"])
def test_identity_dependencies_invalidate_polish(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        value = original(path)
        return value + b"\nchanged identity dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_identity_statics_inventory_names_the_actual_registered_proposition():
    from verifier.domains.inventory import get_slot
    row = get_slot("IDENTITY", 3).to_dict()
    assert row["mechanized"] and row["coordinate"] == COORDINATE
    assert [item["coordinate"] for item in row["registered_objectives"]] == [COORDINATE]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


def test_identity_public_command_replays_exact_selection(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs()
    for label, raw in (("request", canonical_bytes(request)), ("policy", canonical_bytes(policy)),
                       ("certificate", contract.build_identity_scope_certificate(request, evidence, policy=policy))):
        (tmp_path / (label + ".json")).write_bytes(raw)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", COORDINATE, "--represented-kind", "IDENTITY", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0 and json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("graph,budget,expected", [(False, 4, "UNKNOWN"), (False, 5, "PASS"),
    (True, 6, "UNKNOWN"), (True, 7, "PASS")])
def test_identity_relation_budget_has_exact_and_one_under_controls(graph, budget, expected):
    objects, declaration = specimen()
    if graph:
        make = NamespaceObject.create
        objects += [make("roles", "GRAPH", {"element_kind": "ROLE"}, {"members": ["role"]})]
        objects = [make(obj.object_id, obj.kind, obj.payload,
            {"actor": ["actor"], "role": ["roles"]} if obj.object_id == "identity" else {"roles": ["roles"]})
            if obj.object_id in ("identity", "collective") else obj for obj in objects]
    contract, request, policy, evidence = inputs(objects=objects, declaration=declaration, max_relation_steps=budget)
    assert replay(contract, request, policy, evidence)["computational_status"] == expected


def test_native_identity_recheck_uses_selected_relation_budget():
    from verifier.domains.contracts.identity_occupancy import assess_identity_occupancy, recheck_identity_occupancy
    objects, declaration = specimen()
    selected = dict(identity_id="identity", collective_id="collective", expected_digest=composition_digest(objects),
        expected_evidence_digest=digest(declaration), evidence=declaration)
    passed = assess_identity_occupancy(objects, **selected, max_relation_steps=5)
    assert passed["status"] == "PASS"
    with pytest.raises(ValueError):
        recheck_identity_occupancy(passed, objects, **selected, max_relation_steps=4)
    unknown = assess_identity_occupancy(objects, **selected, max_relation_steps=4)
    assert recheck_identity_occupancy(unknown, objects, **selected, max_relation_steps=4)["status"] == "UNKNOWN"


@pytest.mark.parametrize("value", [True, False, 0, -1, "5", 5.0])
def test_identity_relation_budget_requires_a_positive_plain_integer(value):
    from verifier.domains.contracts.identity_occupancy import assess_identity_occupancy
    objects, declaration = specimen()
    with pytest.raises(ValueError):
        assess_identity_occupancy(objects, identity_id="identity", collective_id="collective",
            expected_digest=composition_digest(objects), expected_evidence_digest=digest(declaration),
            evidence=declaration, max_relation_steps=value)


@pytest.mark.parametrize("relative", ["domains/contracts/identity_scope.py", "domains/contracts/identity_occupancy.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py", "domains/common.py",
    "standard/CURRENT_IDENTITY_SCOPE.md", "standard/IDENTITY_OCCUPANCY.md", "standard/NAMESPACE_OBJECTS.md"])
def test_identity_policy_refuses_changed_direct_dependency(relative, monkeypatch):
    contract, request, policy, evidence = inputs()
    certificate = contract.build_identity_scope_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_identity_scope_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("case", ["missing-declaration", "missing-scope", "unsupported-version"])
def test_selected_incomplete_identity_declarations_remain_unknown(case):
    objects, declaration = specimen()
    if case == "missing-scope":
        objects[1] = NamespaceObject.create("role", "ROLE", {})
    elif case == "unsupported-version":
        declaration["schema_version"] = "verifier-namespace-identity-evidence-future"
        objects[-1] = NamespaceObject.create("identity", "IDENTITY",
            {"scope": "team:research", "binding_evidence_digest": digest(declaration)},
            {"actor": ["actor"], "role": ["role"]})
    contract, request, policy, evidence = inputs(objects=objects, declaration=declaration)
    if case == "missing-declaration":
        value = json.loads(evidence); value["declaration"] = None
        evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


def test_identity_polish_replay_binds_exact_subject_and_collection():
    from verifier.runtime.polish import assess_polish
    contract, request, policy, evidence = inputs()
    certificate = contract.build_identity_scope_certificate(request, evidence, policy=policy)
    certificate_ref = digest(json.loads(certificate))
    objects, _ = specimen()
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [obj.to_dict() for obj in objects],
        "certificates": {certificate_ref: certificate.decode()}}
    selected = {"schema_version": "verifier-polish-request-1", "root_id": "identity",
        "collection_digest": composition_digest(objects), "bundle_digest": digest(bundle),
        "requirements": [{"object_id": obj.object_id, "tier": tier, "applicability": "REQUIRED",
            "rationale": "Selected finite declared relation only", "objectives": []} for obj in objects for tier in range(1, 10)]}
    row = next(row for row in selected["requirements"] if row["object_id"] == "identity" and row["tier"] == 3)
    row["objectives"] = [{"semantic_version": SEMANTIC, "coordinate": COORDINATE,
        "request": request, "policy": policy, "certificate_digest": certificate_ref}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    request["collection_digest"] = "sha256:" + "0" * 64
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert report["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"


def test_identity_single_byte_certificate_tamper_is_rejected():
    contract, request, policy, evidence = inputs()
    certificate = bytearray(contract.build_identity_scope_certificate(request, evidence, policy=policy))
    certificate[-3] ^= 1
    with pytest.raises(ValueError):
        contract.recheck_identity_scope_certificate(bytes(certificate), expected_request=request, policy=policy)


def test_larger_selected_native_collection_cannot_change_after_composition(monkeypatch):
    from verifier.domains.contracts import identity_occupancy as native
    objects, declaration = specimen()
    objects[1] = NamespaceObject.create("role", "ROLE", {"admitted_scopes": ["outside"]})
    objects.extend(NamespaceObject.create("extra-" + str(i), "OBJECT", {}) for i in range(4092))
    selected = composition_digest(objects)
    original = native.assess_composition
    def checked_then_mutated(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result.verdict.value == "PASS"
        objects[1] = NamespaceObject.create("role", "ROLE", {"admitted_scopes": ["team:research"]})
        return result
    monkeypatch.setattr(native, "assess_composition", checked_then_mutated)
    result = native.assess_identity_occupancy(objects, identity_id="identity", collective_id="collective",
        expected_digest=selected, expected_evidence_digest=digest(declaration), evidence=declaration,
        max_objects=4097)
    assert result["status"] == "FAIL"
    assert "outside" in result["reason"]
