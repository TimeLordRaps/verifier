"""Current dataset integrity and lineage (DATA) independently selected checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Counts are
dimensionless and byte commitments count canonical encoded bytes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import data
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
CHECKS = {"inventory": "DATA-1.2", "schema": "DATA-1.4", "lineage": "DATA-2.1",
          "splits": "DATA-4.1", "overlap": "DATA-4.4"}


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def commitment(rows: list) -> dict:
    leaves = [digest(row) for row in rows]
    tree = leaves[:]
    while len(tree) > 1:
        tree = [digest({"left": tree[i], "right": tree[min(i + 1, len(tree) - 1)]})
                for i in range(0, len(tree), 2)]
    return {"digest": digest(rows), "records": len(rows), "bytes": len(canonical_bytes(rows)),
            "record_digests": leaves, "merkle_root": tree[0] if tree else digest([])}


def specimen() -> tuple[dict, dict]:
    source = [{"id": "a", "text": "red apple"}, {"id": "b", "text": "blue moon"}]
    shards = {"source": source, "training": deepcopy(source[:1]), "testing": deepcopy(source[1:])}
    artifact = {"shards": {key: commitment(rows) for key, rows in shards.items()},
        "fields": {"id": "string", "text": "string"}, "source_shards": ["source"],
        "transforms": [{"inputs": ["source"], "output": output, "operation": "filter_eq",
                        "parameters": {"field": "id", "value": key}}
                       for output, key in (("training", "a"), ("testing", "b"))],
        "splits": {"train": ["training"], "test": ["testing"]},
        "final_shards": ["training", "testing"], "identity_field": "id",
        "overlap": {"train": "train", "evaluation": "test", "text_field": "text", "ngram": 1,
                    "max_overlap": 0.0}}
    return artifact, {"shards": shards}


def inputs(check: str, *, artifact=None, retained=None, **limits):
    contract = importlib.import_module("verifier.domains.contracts.data_checks")
    if artifact is None:
        artifact, retained = specimen()
    subject = NamespaceObject.create("dataset", "DATA", artifact)
    objects = [subject]
    evidence = canonical_bytes({"schema_version": "verifier-current-data-checks-evidence-1",
                               "objects": [obj.to_dict() for obj in objects], "inputs": retained})
    policy = contract.data_checks_policy(trust_roots=["selected-retained-data-only"])
    request = contract.data_checks_request(check=check, subject_id="dataset", object_digest=subject.digest,
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_data_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="DATA", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_data_route_is_explicitly_selected(check):
    route = routes.select_current_object_route(semantic_version=SEMANTIC,
        objective=CHECKS[check], represented_kind="DATA")
    assert route.fixed_kind == "DATA"
    assert route.scope == "finite_retained_data_" + check


@pytest.mark.parametrize("check", CHECKS)
def test_native_positive_controls_execute_every_selected_check(check):
    artifact, retained = specimen()
    assert data.evaluate(check, artifact, retained, Budget(10000)) == {"shards": 3, "records": 4}


@pytest.mark.parametrize("check", ["inventories", "", "SCHEMA", " schema", None, True, ["inventory"]])
def test_unsupported_native_selection_cannot_return_inventory_success(check):
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported dataset check"):
        data.evaluate(check, artifact, retained, Budget(10000))


def test_subclass_selection_cannot_choose_a_different_check():
    class Forged(str):
        def __eq__(self, other):
            return True
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported dataset check"):
        data.evaluate(Forged("inventories"), artifact, retained, Budget(10000))


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self, key):
            raise AssertionError("unsupported selector consumed evidence")
    budget = Budget(0)
    with pytest.raises(Unavailable, match="unsupported dataset check"):
        data.evaluate("inventories", {}, Unreadable(), budget)
    assert budget.used == 0


@pytest.mark.parametrize("check", CHECKS)
def test_current_data_positive_replay_is_bounded_and_deterministic(check):
    contract, request, policy, evidence = inputs(check)
    first = contract.build_data_checks_certificate(request, evidence, policy=policy)
    assert first == contract.build_data_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS"
    result = report["native_result"]
    assert result["object_profile_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["dataset"] == {"shards": 3, "records": 4}


@pytest.mark.parametrize("check", CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact, retained = specimen()
    if check == "inventory":
        artifact["shards"]["source"]["records"] = 3
    elif check == "schema":
        artifact["fields"]["id"] = "integer"
    elif check == "lineage":
        artifact["transforms"][0]["parameters"]["value"] = "b"
    elif check == "splits":
        artifact["splits"]["test"].append("training")
    else:
        retained["shards"]["testing"][0]["text"] = "red apple"
        artifact["shards"]["testing"] = commitment(retained["shards"]["testing"])
    contract, request, policy, evidence = inputs(check, artifact=artifact, retained=retained)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("bound", ["max_operations", "max_composition_operations", "max_evidence_bytes",
                                  "max_payload_bytes", "max_reference_bytes", "max_items"])
def test_selected_resource_exhaustion_remains_unknown(check, bound):
    contract, request, policy, evidence = inputs(check, **{bound: 1})
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", CHECKS)
def test_missing_retained_evidence_is_unknown(check):
    contract, request, policy, evidence = inputs(check)
    assert replay(contract, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest"])
def test_certificate_cannot_select_its_own_subject_or_evidence(field):
    contract, request, policy, evidence = inputs("schema")
    certificate = contract.build_data_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_data_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("inventory")
    certificate = json.loads(contract.build_data_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_data_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_data_record(bad):
    contract, request, policy, evidence = inputs("inventory")
    value = json.loads(evidence); value["objects"][0]["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_data_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_data_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "DATA", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_data_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("inventory")
    value = json.loads(contract.build_data_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("DATA", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/data_checks.py", "domains/data.py", "standard/CURRENT_DATA_CHECKS.md"])
def test_data_dependencies_invalidate_polish(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        value = original(path)
        return value + b"\nchanged dataset dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("check", CHECKS)
def test_data_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("DATA", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "data_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/data_checks.py", "domains/data.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_DATA_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_direct_dependency_invalidates_dataset_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("inventory")
    certificate = contract.build_data_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_data_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["missing-inputs", "missing-schema", "unsupported-schema", "unsupported-transform"])
def test_unavailable_dataset_support_is_unknown(case):
    artifact, retained = specimen()
    check = "lineage" if case == "unsupported-transform" else "schema"
    if case == "missing-schema":
        del artifact["fields"]
    elif case == "unsupported-schema":
        artifact["fields"]["text"] = "future-type"
    elif case == "unsupported-transform":
        artifact["transforms"][0]["operation"] = "future-transform"
    contract, request, policy, evidence = inputs(check, artifact=artifact, retained=retained)
    if case == "missing-inputs":
        value = json.loads(evidence); value["inputs"] = None
        evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


def test_same_spelling_under_legacy_semantics_cannot_select_current_data():
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version="legacy-domain", objective="DATA-1.2", represented_kind="DATA")


def test_wrong_check_cannot_reuse_another_proposition():
    contract, request, policy, evidence = inputs("inventory")
    request["check"] = "schema"
    with pytest.raises(ValueError, match="objective differs"):
        contract.build_data_checks_certificate(request, evidence, policy=policy)


def test_one_byte_tamper_is_rejected():
    contract, request, policy, evidence = inputs("inventory")
    certificate = bytearray(contract.build_data_checks_certificate(request, evidence, policy=policy))
    certificate[-3] ^= 1
    with pytest.raises(ValueError):
        contract.recheck_data_checks_certificate(bytes(certificate), expected_request=request, policy=policy)


def test_data_polish_replay_binds_subject_and_collection_without_issuing_polished_status():
    from verifier.runtime.polish import assess_polish
    contract, request, policy, evidence = inputs("inventory")
    certificate = contract.build_data_checks_certificate(request, evidence, policy=policy)
    objects = json.loads(evidence)["objects"]
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    selected = {"schema_version": "verifier-polish-request-1", "root_id": "dataset",
        "collection_digest": request["collection_digest"], "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "dataset", "tier": tier, "applicability": "REQUIRED",
                          "rationale": "Selected dataset proposition only", "objectives": []} for tier in range(1, 10)]}
    selected["requirements"][0]["objectives"] = [{"semantic_version": SEMANTIC, "coordinate": "DATA-1.2",
        "request": request, "policy": policy, "certificate_digest": digest(json.loads(certificate))}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    request["collection_digest"] = "sha256:" + "0" * 64
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected))
    assert report["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
