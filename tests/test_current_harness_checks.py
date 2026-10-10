"""Agent harness (HARNESS) retained observation contracts.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Record indices and
counts are dimensionless. Tool payloads below are inert retained observations.
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
from verifier.domains import harness
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = 'verifier-current-object-obligations-1'
CHECKS = {'surface': 'HARNESS-1.6', 'messages': 'HARNESS-2.1', 'tools': 'HARNESS-2.2',
          'effects': 'HARNESS-2.3', 'transcript': 'HARNESS-4.1'}


def digest(value: Any) -> str:
    return 'sha256:' + hashlib.sha256(canonical_bytes(value)).hexdigest()


def root(records: list) -> str:
    leaves = [digest(row) for row in records]
    while len(leaves) > 1:
        leaves = [digest({'left': leaves[i], 'right': leaves[min(i+1, len(leaves)-1)]})
            for i in range(0, len(leaves), 2)]
    return leaves[0] if leaves else digest([])


def specimen() -> tuple[dict, dict]:
    declarations = {'sum': {'name': 'sum', 'inputs': ['a', 'b'], 'outputs': ['total']}}
    payloads = [('user', 'chat', {'text': 'Compute two sums.'}),
        ('agent', 'chat', {'text': 'Retaining the selected calls.'}),
        ('tool', 'tool_io', {'input': {'a': 2, 'b': 3}, 'output': {'total': 5}}),
        ('tool', 'tool_io', {'input': {'a': -1, 'b': 4}, 'output': {'total': 3}}),
        ('agent', 'chat', {'text': 'The retained answers are five and three.'})]
    records = [{'index': i, 'role': role, 'channel': channel, 'payload': payload,
        'payload_digest': digest(payload)} for i, (role, channel, payload) in enumerate(payloads)]
    invocations = [{'index': i, 'tool': 'sum', 'declaration_digest': digest(declarations['sum']),
        **deepcopy(records[i]['payload'])} for i in (2, 3)]
    effects = [{'index': 3, 'channel': 'retained-note', 'payload': {'value': 8}}]
    return ({'surface': {'chat': 'instrumented', 'tool_io': 'instrumented', 'hidden': 'declared-gap'},
        'tools': {name: digest(value) for name, value in declarations.items()},
        'effects': {'retained-note': 'instrumented', 'network': 'declared-gap'},
        'record_count': len(records), 'transcript_digest': digest(records), 'transcript_root': root(records),
        'invocations_digest': digest(invocations), 'effects_digest': digest(effects)},
        {'records': records, 'invocations': invocations, 'effects': effects, 'declarations': declarations})


@pytest.mark.parametrize('check', CHECKS)
def test_current_harness_route_is_explicitly_selected(check):
    route = routes.select_current_object_route(semantic_version=SEMANTIC, objective=CHECKS[check], represented_kind='HARNESS')
    assert route.fixed_kind == 'HARNESS' and route.scope == 'finite_retained_harness_' + check


@pytest.mark.parametrize('check', CHECKS)
def test_native_positive_controls_execute_selected_check(check):
    artifact, retained = specimen()
    assert harness.evaluate(check, artifact, retained, Budget(10000)) == {
        'instrumented_channels': ['chat', 'tool_io'], 'declared_gaps': ['hidden'],
        'records': 0 if check == 'surface' else 5, 'registered_tools': 1}


@pytest.mark.parametrize('check', ['transcripts', '', 'MESSAGES', ' messages', None, True, ['surface']])
def test_unsupported_native_selection_cannot_return_record_success(check):
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match='unsupported harness check'):
        harness.evaluate(check, artifact, retained, Budget(10000))


def test_subclass_selector_cannot_impersonate_surface():
    class Forged(str):
        def __eq__(self, other): return True
        def __ne__(self, other): return False
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match='unsupported harness check'):
        harness.evaluate(Forged('unregistered'), artifact, retained, Budget(10000))


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self, key): raise AssertionError('unsupported selector consumed evidence')
    budget = Budget(0)
    with pytest.raises(Unavailable, match='unsupported harness check'):
        harness.evaluate('unregistered', Unreadable(), Unreadable(), budget)
    assert budget.used == 0


@pytest.mark.parametrize('check', ['messages', 'tools', 'effects', 'transcript'])
@pytest.mark.parametrize('value', [True, 1.0])
def test_record_count_must_be_an_integer_not_equal_boolean_or_float(check, value):
    artifact, retained = specimen()
    retained['records'] = retained['records'][:1]
    retained['invocations'] = []; retained['effects'] = []
    artifact.update(record_count=value, transcript_digest=digest(retained['records']), transcript_root=root(retained['records']))
    with pytest.raises(Refuted, match='record count'):
        harness.evaluate(check, artifact, retained, Budget(10000))


@pytest.mark.parametrize('check', ['messages', 'tools', 'effects', 'transcript'])
@pytest.mark.parametrize('position,value', [(0, False), (0, 0.0), (1, True), (1, 1.0)])
def test_record_indices_cannot_pass_by_numeric_coercion(check, position, value):
    artifact, retained = specimen(); retained['records'][position]['index'] = value
    artifact.update(transcript_digest=digest(retained['records']), transcript_root=root(retained['records']))
    with pytest.raises(Refuted, match='indices'):
        harness.evaluate(check, artifact, retained, Budget(10000))


def inputs(check: str, *, artifact=None, retained=None, objects=None, **limits):
    contract = importlib.import_module("verifier.domains.contracts.harness_checks")
    if artifact is None: artifact, retained = specimen()
    artifact, retained = deepcopy(artifact), deepcopy(retained)
    if objects is None: objects = [NamespaceObject.create("harness", "HARNESS", artifact)]
    subject = next(item for item in objects if item.object_id == "harness")
    evidence = canonical_bytes({"schema_version": "verifier-current-harness-checks-evidence-1",
        "objects": [item.to_dict() for item in objects], "inputs": retained})
    policy = contract.harness_checks_policy(trust_roots=["selected-retained-harness-only"])
    request = contract.harness_checks_request(check=check, subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_harness_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="HARNESS", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_harness_positive_replay_is_bounded_and_deterministic(check):
    contract, request, policy, evidence = inputs(check)
    first = contract.build_harness_checks_certificate(request, evidence, policy=policy)
    assert first == contract.build_harness_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS", report
    result = report["native_result"]
    assert result["object_profile_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["harness"] == {
        "instrumented_channels": ["chat", "tool_io"], "declared_gaps": ["hidden"],
        "records": 0 if check == "surface" else 5, "registered_tools": 1}


@pytest.mark.parametrize("check", CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact, retained = specimen()
    if check == "surface": artifact["surface"]["chat"] = "unregistered"
    elif check == "messages": retained["records"][1]["index"] = 9
    elif check == "tools":
        retained["invocations"][0]["output"] = {"total": 99}
        artifact["invocations_digest"] = digest(retained["invocations"])
    elif check == "effects":
        retained["effects"][0]["channel"] = "network"
        artifact["effects_digest"] = digest(retained["effects"])
    else: artifact["transcript_root"] = "sha256:" + "0" * 64
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "FAIL"


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
    contract, request, policy, evidence = inputs("messages")
    certificate = contract.build_harness_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_harness_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("surface")
    certificate = json.loads(contract.build_harness_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_harness_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_harness_record(bad):
    contract, request, policy, evidence = inputs("surface")
    value = json.loads(evidence); value["objects"][0]["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_harness_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_harness_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "HARNESS", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_harness_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("surface")
    value = json.loads(contract.build_harness_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("HARNESS", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/harness_checks.py", "domains/harness.py", "standard/CURRENT_HARNESS_CHECKS.md"])
def test_harness_dependencies_invalidate_polish(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        value = original(path)
        return value + b"\nchanged benchmark dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("check", CHECKS)
def test_harness_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("HARNESS", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "harness_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/harness_checks.py", "domains/harness.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_HARNESS_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_direct_dependency_invalidates_harness_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("surface")
    certificate = contract.build_harness_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_harness_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"





@pytest.mark.parametrize("mutation", ["missing-invocation", "duplicate-invocation", "wrong-declaration-name",
    "missing-declaration", "extra-declaration", "changed-declaration", "changed-invocation-commitment"])
def test_tool_pairing_requires_complete_unique_bound_declarations(mutation):
    artifact, retained = specimen()
    if mutation == "missing-invocation": retained["invocations"].pop()
    elif mutation == "duplicate-invocation": retained["invocations"].append(deepcopy(retained["invocations"][0]))
    elif mutation == "wrong-declaration-name":
        retained["declarations"]["sum"]["name"] = "different"
        artifact["tools"]["sum"] = digest(retained["declarations"]["sum"])
        for invocation in retained["invocations"]: invocation["declaration_digest"] = artifact["tools"]["sum"]
    elif mutation == "missing-declaration": retained["declarations"].clear()
    elif mutation == "extra-declaration": retained["declarations"]["unused"] = {"name": "unused"}
    elif mutation == "changed-declaration": retained["declarations"]["sum"]["inputs"] = ["different"]
    artifact["invocations_digest"] = digest(retained["invocations"])
    if mutation == "changed-invocation-commitment": artifact["invocations_digest"] = "sha256:" + "0" * 64
    assert replay(*inputs("tools", artifact=artifact, retained=retained))["computational_status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["record-count", "index", "gap", "role", "payload"])
def test_retained_transcript_contradictions_cannot_hide_behind_new_hashes(mutation):
    artifact, retained = specimen()
    if mutation == "record-count": artifact["record_count"] = 5.0
    elif mutation == "index": retained["records"][0]["index"] = False
    elif mutation == "gap": retained["records"][1]["channel"] = "hidden"
    elif mutation == "role": retained["records"][1]["role"] = "observer"
    else: retained["records"][1]["payload"]["text"] = "substituted"
    artifact.update(transcript_digest=digest(retained["records"]), transcript_root=root(retained["records"]))
    assert replay(*inputs("transcript", artifact=artifact, retained=retained))["computational_status"] == "FAIL"


@pytest.mark.parametrize("check,field", [("messages", "records"), ("tools", "declarations"),
    ("tools", "invocations"), ("effects", "effects"), ("transcript", "records")])
def test_missing_selected_support_remains_unknown(check, field):
    artifact, retained = specimen(); retained.pop(field)
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", CHECKS)
def test_absent_native_inputs_are_unknown(check):
    artifact, _ = specimen()
    assert replay(*inputs(check, artifact=artifact, retained=None))["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", ["surface", "messages", "transcript"])
def test_unselected_invocation_and_effect_support_is_not_required(check):
    artifact, retained = specimen()
    retained = {} if check == "surface" else {"records": retained["records"]}
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "PASS"


def test_effects_cannot_change_without_rebinding_the_selected_inventory():
    artifact, retained = specimen(); retained["effects"][0]["payload"]["value"] = 9
    assert replay(*inputs("effects", artifact=artifact, retained=retained))["computational_status"] == "FAIL"


def test_actual_tool_behavior_is_outside_retained_pairing_claim():
    artifact, retained = specimen()
    retained["records"][2]["payload"]["output"] = {"total": 99}
    retained["records"][2]["payload_digest"] = digest(retained["records"][2]["payload"])
    retained["invocations"][0]["output"] = {"total": 99}
    artifact.update(invocations_digest=digest(retained["invocations"]), transcript_digest=digest(retained["records"]),
        transcript_root=root(retained["records"]))
    assert replay(*inputs("tools", artifact=artifact, retained=retained))["computational_status"] == "PASS"


def test_real_native_checker_runs_on_build_and_recheck(monkeypatch):
    checks = []; original = harness.evaluate
    def tracked(check, artifact, retained, budget):
        checks.append(check); return original(check, artifact, retained, budget)
    monkeypatch.setattr(harness, "evaluate", tracked)
    assert replay(*inputs("transcript"))["computational_status"] == "PASS"
    assert checks == ["transcript", "transcript"]


@pytest.mark.parametrize("check", CHECKS)
def test_current_harness_rejects_legacy_semantic_selection(check):
    with pytest.raises(ValueError):
        routes.select_current_object_route(semantic_version="verifier-domain-obligations-1",
            objective=CHECKS[check], represented_kind="HARNESS")
