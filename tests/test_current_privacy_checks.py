"""Current full-record disclosure tests with independently selected bounds.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). These local checks
neither transmit records nor authenticate the declared observer.
"""
from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts.current_object_routes import current_object_route_catalog, replay_current_object_certificate
from test_current_typed_facets import KINDS, collection

SEMANTIC = "verifier-current-object-obligations-1"
FIELDS = ["kind", "object_id", "operands", "payload"]


def policy_inputs() -> dict:
    return {"trust_roots": ["test:independently-selected-disclosure"],
        "observer": {"actor_id": "reader", "role": "auditor", "purpose": "inspect", "credentials": ["declared-review"]},
        "disclosed_fields": FIELDS.copy(), "withheld_fields": [],
        "bounds": [{"bound_id": "admit:" + field, "field_name": field,
            "admitted_observers": ["reader"], "admitted_roles": [],
            "conditions": [["purpose", "inspect"], ["credential", "declared-review"]]} for field in FIELDS],
        "co_emitted_ids": [], "extra_join_rules": []}


def inputs(kind: str = "MODEL", *, objects: list[NamespaceObject] | None = None,
           selection: dict | None = None, **limits: int) -> tuple[Any, dict, dict, bytes]:
    contract = importlib.import_module("verifier.domains.contracts.privacy_checks")
    objects = collection() if objects is None else objects
    subject = next(item for item in objects if item.object_id == kind.lower())
    evidence = canonical_bytes({"schema_version": "verifier-current-privacy-checks-evidence-1",
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)]})
    policy = contract.privacy_checks_policy(**(policy_inputs() if selection is None else selection))
    request = contract.privacy_checks_request(object_kind=kind, subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), timestamp="2026-09-28T13:00:00Z",
        policy=policy, limits=limits or None)
    return contract, request, policy, evidence


def replay(contract: Any, request: dict, policy: dict, evidence: bytes | None) -> dict:
    certificate = contract.build_privacy_checks_certificate(request, evidence, policy=policy)
    return replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind=request["object_kind"],
        expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
def test_public_privacy_route_exists_for_each_kind(kind: str) -> None:
    routes = {row["objective"]: row for row in current_object_route_catalog()}
    assert routes.get(kind + "-6.7") is not None
    assert routes[kind + "-6.7"]["represented_kind_rule"] == kind


@pytest.mark.parametrize("kind", KINDS)
def test_full_selected_record_is_locally_admitted_for_each_kind(kind: str) -> None:
    contract, request, policy, evidence = inputs(kind)
    encoded = contract.build_privacy_checks_certificate(request, evidence, policy=policy)
    assert encoded == contract.build_privacy_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS"
    native = report["native_result"]
    assert native["authority"] == native["object_profile_conformance"] == "NOT_ESTABLISHED"
    observed = native["evaluation"]["observations"]
    assert observed["record_digest"] == request["object_digest"]
    assert observed["fields_checked"] == 4 and observed["emission"] == "NOT_PERFORMED"
    assert observed["observer_authentication"] == observed["general_composition_safety"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("case", ["missing-bound", "denied-party", "denied-role", "wrong-purpose", "missing-credential", "withheld-field", "unenumerated-field", "contradictory-conditions"])
def test_native_disclosure_refutes_incomplete_or_denied_full_record(case: str) -> None:
    selected = policy_inputs()
    if case == "missing-bound": selected["bounds"] = selected["bounds"][:-1]
    elif case == "denied-party": selected["observer"]["actor_id"] = "outsider"
    elif case == "denied-role":
        for bound in selected["bounds"]:
            bound["admitted_observers"] = []; bound["admitted_roles"] = ["owner"]
    elif case == "wrong-purpose": selected["observer"]["purpose"] = "sell"
    elif case == "missing-credential": selected["observer"]["credentials"] = []
    elif case == "withheld-field":
        selected["disclosed_fields"].remove("payload"); selected["withheld_fields"] = ["payload"]
    elif case == "unenumerated-field": selected["disclosed_fields"].remove("payload")
    else: selected["bounds"][0]["conditions"] += [["purpose", "sell"]]
    assert replay(*inputs(selection=selected))["computational_status"] == "FAIL"


@pytest.mark.parametrize("field", ["object_digest", "collection_digest", "subject_id"])
def test_changed_external_subject_is_refuted(field: str) -> None:
    contract, request, policy, evidence = inputs()
    request[field] = "different" if field == "subject_id" else "sha256:" + "0" * 64
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("limit", ["max_objects", "max_operations", "max_composition_operations", "max_evidence_bytes", "max_payload_bytes", "max_reference_bytes"])
def test_selected_resource_exhaustion_is_unknown(limit: str) -> None:
    assert replay(*inputs(**{limit: 1}))["computational_status"] == "UNKNOWN"


def test_missing_evidence_remains_unknown() -> None:
    contract, request, policy, _ = inputs()
    assert replay(contract, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("kind,other", [("ACTOR", "owner"), ("TOKEN", "actor"), ("DATA", "train"), ("MODEL", "sim"), ("BOT", "agent")])
def test_actual_typed_co_emission_is_refused_for_bundled_risky_pairs(kind: str, other: str) -> None:
    selected = policy_inputs(); selected["co_emitted_ids"] = [other]
    assert replay(*inputs(kind, selection=selected))["computational_status"] == "FAIL"


def test_explicit_additional_composition_rule_is_enforced() -> None:
    selected = policy_inputs(); selected["co_emitted_ids"] = ["env"]
    assert replay(*inputs(selection=selected))["computational_status"] == "PASS"
    selected["extra_join_rules"] = [["MODEL", "ENV", "selected extra correlation refusal"]]
    assert replay(*inputs(selection=selected))["computational_status"] == "FAIL"


@pytest.mark.parametrize("co_emitted", [["missing"], ["model"]])
def test_co_emitted_identifiers_must_name_distinct_actual_records(co_emitted: list[str]) -> None:
    selected = policy_inputs(); selected["co_emitted_ids"] = co_emitted
    assert replay(*inputs(selection=selected))["computational_status"] == "FAIL"


@pytest.mark.parametrize("change", ["status", "authority", "record_digest"])
def test_rehashed_forged_success_is_rejected(change: str) -> None:
    contract, request, policy, evidence = inputs()
    value = json.loads(contract.build_privacy_checks_certificate(request, evidence, policy=policy))
    if change == "record_digest": value["result"]["evaluation"]["observations"][change] = "sha256:" + "0" * 64
    else: value["result"][change] = "FAIL" if change == "status" else "PASS"
    value["digest"] = digest({k: v for k, v in value.items() if k != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_privacy_checks_certificate(canonical_bytes(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["observer", "bounds", "co_emitted_ids"])
def test_certificate_cannot_replace_current_external_disclosure_policy(field: str) -> None:
    contract, request, policy, evidence = inputs()
    certificate = contract.build_privacy_checks_certificate(request, evidence, policy=policy)
    selection = policy_inputs()
    if field == "observer": selection[field]["actor_id"] = "other"
    elif field == "bounds": selection[field][0]["conditions"] += [["purpose", "other"]]
    else: selection[field] = ["sim"]
    different = contract.privacy_checks_policy(**selection)
    with pytest.raises(ValueError):
        contract.recheck_privacy_checks_certificate(certificate, expected_request=request, policy=different)


def test_selection_is_snapshotted_without_invoking_custom_callbacks() -> None:
    selected = policy_inputs(); contract, request, policy, evidence = inputs(selection=selected)
    selected["observer"]["actor_id"] = "changed-after-selection"
    selected["bounds"][0]["conditions"].append(["purpose", "other"])
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    class Hostile(dict):
        def items(self): raise AssertionError("custom callback must not execute")
    selected["observer"] = Hostile(policy_inputs()["observer"])
    with pytest.raises(ValueError): contract.privacy_checks_policy(**selected)


@pytest.mark.parametrize("path", ["privacy/engine.py", "privacy/models.py", "privacy/composition.py", "privacy/independence.py", "privacy/adapters.py", "standard/CURRENT_PRIVACY_CHECKS.md"])
def test_selected_policy_binds_native_dependency_bytes(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    contract, request, policy, evidence = inputs()
    original = Path.read_bytes
    def changed(target: Path) -> bytes:
        data = original(target)
        return data + b"\n" if target.as_posix().endswith(path) else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError): contract.build_privacy_checks_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
def test_privacy_inventory_retains_actual_numbered_objective(kind: str) -> None:
    from verifier.domains.inventory import slot_inventory
    row = next(row for row in slot_inventory() if row["object_kind"] == kind and row["tier"] == 6)
    assert [item["coordinate"] for item in row["registered_objectives"]] == [kind + "-6.7"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


def test_privacy_certificate_canonical_evidence_cannot_be_redacted() -> None:
    from verifier.privacy import DisclosureSurface, DisclosureBound, ObserverParty, EmissionContext, EmissionEvaluator, EmissionRefusalError
    contract, request, policy, evidence = inputs()
    value = json.loads(contract.build_privacy_checks_certificate(request, evidence, policy=policy))
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("MODEL", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), request["timestamp"])
    with pytest.raises(EmissionRefusalError): EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("path", ["privacy/engine.py", "privacy/models.py", "privacy/composition.py", "privacy/independence.py", "privacy/adapters.py", "domains/contracts/privacy_checks.py", "standard/CURRENT_PRIVACY_CHECKS.md"])
def test_polish_binds_current_privacy_dependencies(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import polish
    before = polish.mechanism_digest(); original = Path.read_bytes
    def changed(target: Path) -> bytes:
        data = original(target)
        return data + b"\n" if target.as_posix().endswith(path) else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_exact_disclosure_work_limit_and_one_under() -> None:
    measured = replay(*inputs())["native_result"]["evaluation"]["observations"]["work_units"]
    assert measured > 1
    assert replay(*inputs(max_operations=measured))["computational_status"] == "PASS"
    assert replay(*inputs(max_operations=measured - 1))["computational_status"] == "UNKNOWN"


def test_actual_native_evaluator_receives_selected_record_and_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.privacy import engine
    original = engine.EmissionEvaluator.evaluate_emission; seen = []
    def observe(self, record, surface, bounds, context):
        seen.append((deepcopy(record), surface, bounds, context))
        return original(self, record, surface, bounds, context)
    monkeypatch.setattr(engine.EmissionEvaluator, "evaluate_emission", observe)
    assert replay(*inputs())["computational_status"] == "PASS"
    assert seen and all(row[0] == next(item for item in collection() if item.object_id == "model").to_dict() for row in seen)
    assert all(row[3].observer.actor_id == "reader" for row in seen)
    assert all(row[2][0].conditions == (("purpose", "inspect"), ("credential", "declared-review")) for row in seen)


def test_payload_labels_cannot_hide_selected_typed_join() -> None:
    objects = [NamespaceObject.create(item.object_id, item.kind,
        {"object_name": "SAFE", "domain": "OTHER"}, item.to_dict()["operands"]) if item.kind.value == "MODEL" else item for item in collection()]
    selected = policy_inputs(); selected["co_emitted_ids"] = ["sim"]
    assert replay(*inputs(objects=objects, selection=selected))["computational_status"] == "FAIL"


@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_payload_verdict_is_not_promoted_or_validated(status: str) -> None:
    objects = [NamespaceObject.create(item.object_id, item.kind,
        {"claim": "unverified retained claim", "verdict": status}, item.to_dict()["operands"]) if item.kind.value == "MODEL" else item for item in collection()]
    report = replay(*inputs(objects=objects))
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["evaluation"]["observations"]["underlying_certificate_validity"] == "NOT_ESTABLISHED"
    assert next(item for item in objects if item.object_id == "model").payload["verdict"] == status


@pytest.mark.parametrize("case", ["bool-limit", "duplicate-bound", "duplicate-co-id", "custom-list", "cyclic-policy", "overdeep-policy", "nonfinite-policy"])
def test_malformed_external_selection_refuses_before_native_work(case: str) -> None:
    contract = importlib.import_module("verifier.domains.contracts.privacy_checks")
    selected = policy_inputs()
    if case == "bool-limit":
        with pytest.raises(ValueError): inputs(max_operations=True)
        return
    if case == "duplicate-bound": selected["bounds"].append(deepcopy(selected["bounds"][0]))
    elif case == "duplicate-co-id": selected["co_emitted_ids"] = ["env", "env"]
    elif case == "custom-list":
        class Hostile(list):
            def __iter__(self): raise AssertionError("custom iterator must not execute")
        selected["bounds"] = Hostile(selected["bounds"])
    elif case == "cyclic-policy": selected["bounds"].append(selected)
    elif case == "overdeep-policy":
        nested = []
        for _ in range(70): nested = [nested]
        selected["observer"]["credentials"] = nested
    else: selected["observer"]["credentials"] = [float("nan")]
    with pytest.raises(ValueError): contract.privacy_checks_policy(**selected)


@pytest.mark.parametrize("kind", KINDS)
def test_public_privacy_command_does_not_echo_retained_payload(kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from verifier.runtime.public_cli import main
    marker = "private-payload-sentinel-current-disclosure"
    objects = [NamespaceObject.create(item.object_id, item.kind,
        {**item.payload, "private_test_marker": marker}, item.to_dict()["operands"]) if item.kind.value == kind else item for item in collection()]
    contract, request, policy, evidence = inputs(kind, objects=objects)
    certificate = contract.build_privacy_checks_certificate(request, evidence, policy=policy)
    for name, encoded in (("certificate", certificate), ("request", canonical_bytes(request)), ("policy", canonical_bytes(policy))):
        (tmp_path/(name + ".json")).write_bytes(encoded)
    code = main(["current-object", "check", str(tmp_path/"certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", request["coordinate"], "--represented-kind", kind, "--request", str(tmp_path/"request.json"),
        "--policy", str(tmp_path/"policy.json"), "--json"])
    output = capsys.readouterr()
    assert code == 0 and json.loads(output.out)["computational_status"] == "PASS"
    assert marker not in output.out + output.err


def test_polish_replays_privacy_without_upgrading_complete_admission() -> None:
    from verifier.runtime.polish import assess_polish
    contract, request, policy, evidence = inputs()
    certificate = contract.build_privacy_checks_certificate(request, evidence, policy=policy)
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": json.loads(evidence)["objects"],
        "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    raw = canonical_bytes(bundle)
    selected = {"schema_version": "verifier-polish-request-1", "root_id": "model", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle), "requirements": [{"object_id": "model", "tier": 6, "applicability": "REQUIRED",
        "rationale": "selected full-record disclosure", "objectives": [{"semantic_version": SEMANTIC, "coordinate": "MODEL-6.7",
        "request": request, "policy": policy, "certificate_digest": digest(json.loads(certificate))}]}]}
    result = assess_polish(raw, request_bytes=canonical_bytes(selected))
    assert result["status"] == "UNKNOWN" and not result["polished"]
    assert result["objectives"][0]["status"] == "PASS"
