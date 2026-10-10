"""Scoped TOKEN route, facet and certificate dependency integration.

command-line interface (CLI); JavaScript Object Notation (JSON).
Fixture rule/profile selection approves no production application or whole tier.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import token_checks, token_facets, facet_coverage as coverage
from verifier.domains.contracts import certificate_dag as dag, typed_facets
from verifier.domains.contracts.current_object_routes import replay_current_object_certificate, CurrentObjectRouteRefusal
from verifier.runtime.public_cli import main
from verifier.runtime.gates import DEFAULT_POLICY, run_gates
from verifier.runtime.polish_prepare import prepare_artifact
from verifier.runtime.clearance_publish import prepare_clearance_publication
from verifier.runtime.artifact_snapshot import digest
from test_current_token_checks import selected, holding
from current_token_dependency_fixture import node, facet, obligation

def specimen(check="tenure", outcome="PASS"):
    artifact, inputs = holding()
    if outcome == "FAIL":
        inputs["tokens"][2]["replay_id"] = inputs["tokens"][1]["replay_id"]
    request, policy, evidence = selected(check, artifact=artifact, inputs=inputs, absent=outcome == "UNKNOWN")
    certificate = token_checks.build_token_checks_certificate(request, evidence, policy=policy)
    return request, policy, evidence, certificate

@pytest.mark.parametrize("check", list(token_checks.CHECKS))
@pytest.mark.parametrize("outcome", ["PASS", "FAIL", "UNKNOWN"])
def test_central_token_routes_preserve_native_outcomes(check, outcome):
    request, policy, _, certificate = specimen(check, outcome)
    result = replay_current_object_certificate(certificate,
        semantic_version=token_checks.SEMANTIC_VERSION, objective=request["coordinate"],
        represented_kind="TOKEN", expected_request=request, policy=policy)
    assert result["computational_status"] == outcome
    assert result["native_result"]["authority"] == "NOT_ESTABLISHED"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"

@pytest.mark.parametrize("change", ["objective", "kind", "semantic", "request", "policy"])
def test_central_token_route_refuses_substituted_selection(change):
    request, policy, _, certificate = specimen()
    selection = dict(semantic_version=token_checks.SEMANTIC_VERSION, objective="TOKEN-2.1",
                     represented_kind="TOKEN", expected_request=request, policy=policy)
    if change == "objective": selection["objective"] = "TOKEN-4.1"
    elif change == "kind": selection["represented_kind"] = "MODEL"
    elif change == "semantic": selection["semantic_version"] = "verifier-domain-obligations-1"
    elif change == "request": request["object_digest"] = digest(b"other-object")
    else: policy["trust_roots"] = ["another-selector"]
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(certificate, **selection)

@pytest.mark.parametrize("check", list(token_checks.CHECKS))
def test_token_cli_replays_exact_external_selection(tmp_path, capsys, check):
    request, policy, _, certificate = specimen(check)
    for name, value in [("request", canonical_bytes(request)), ("policy", canonical_bytes(policy)),
                        ("certificate", certificate)]:
        (tmp_path / (name + ".json")).write_bytes(value)
    assert main(["current-object", "check", str(tmp_path/"certificate.json"),
        "--semantic-version", token_checks.SEMANTIC_VERSION, "--objective", request["coordinate"],
        "--represented-kind", "TOKEN", "--request", str(tmp_path/"request.json"),
        "--policy", str(tmp_path/"policy.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"

@pytest.mark.parametrize("check", list(token_checks.CHECKS))
@pytest.mark.parametrize("outcome", ["PASS", "FAIL", "UNKNOWN"])
def test_token_gates_and_preparation_preserve_scope(tmp_path, check, outcome):
    request, policy, _, certificate = specimen(check, outcome)
    target = tmp_path/"certificate.json"; target.write_bytes(certificate)
    identity = "current-object:" + token_checks.SEMANTIC_VERSION + ":" + request["coordinate"]
    host_policy = deepcopy(DEFAULT_POLICY)
    host_policy["selections"] = [{"gate_id": identity, "path": "artifact.json", "request": request,
        "policy": policy, "represented_kind": "TOKEN", "contract_version": "1"}]
    result = run_gates(target, polish_report_bytes=canonical_bytes(prepare_artifact(target)),
                       policy_bytes=canonical_bytes(host_policy))
    native = next(row for row in result["gates"] if row["gate_id"] == identity)
    assert native["status"] == outcome
    assert result["status"] == outcome
    assert "No complete nine-tier" in result["claim_boundary"]
    if outcome == "PASS":
        with pytest.raises(ValueError, match="dependency"):
            prepare_clearance_publication(target, canonical_bytes(result),
                                           expected_policy_bytes=canonical_bytes(host_policy))

def mapping_inputs(item):
    inventory = coverage.namespace_facet_inventory([item])
    mapping = token_facets.native_token_facet_mapping([item])
    spec = mapping["specification"]
    rules = coverage.installed_facet_derivation_rules()
    policy = {"schema_version": coverage.POLICY, "inventory_digest": digest(canonical_bytes(inventory)),
        "specification_digest": digest(canonical_bytes(spec)), "rule_set_digest": digest(canonical_bytes(rules)),
        "approved_rule_digests": [row["rule_digest"] for row in rules["rules"]]}
    return inventory, mapping, spec, policy

def derive(inventory, spec, policy):
    return coverage.derive_facet_obligations(canonical_bytes(inventory), canonical_bytes(spec),
        expected_policy_bytes=canonical_bytes(policy))

def subject():
    _, _, evidence, _ = specimen()
    return NamespaceObject.create(**json.loads(evidence)["objects"][0])

def test_token_partial_mapping_derives_three_predicates_without_invented_edges():
    item = subject(); inventory, mapping, spec, policy = mapping_inputs(item)
    result = derive(inventory, spec, policy)
    assert mapping["known_partial_semantic_projections"] == 10
    assert result["derivation_status"] == "PASS"
    assert {row["objective"] for row in result["obligations"]} == {
        "OBJECT-1.1", "TOKEN-1.1", "TOKEN-2.1", "TOKEN-3.1", "TOKEN-4.1"}
    assert len(spec["interactions"]) == 3 and result["edges"] == []
    assert result["status"] == "UNKNOWN"
    assert mapping["application_mapping_authority"] == "UNKNOWN"
    assert mapping["full_application_facet_denominator"] is None
    assert all(row["retained_contents_established"] == "NOT_ESTABLISHED" for row in mapping["semantic_facets"])

@pytest.mark.parametrize("change", ["scope", "unit", "origin", "missing-clock", "missing-commitment"])
def test_source_rule_guard_refuses_forced_unrelated_token_projection(change):
    item = subject(); payload = item.to_dict()["payload"]
    if change == "scope": payload["scope"] = "financial-balances"
    elif change == "unit": payload["clock_unit"] = "millisecond"
    elif change == "missing-clock": payload["artifact"].pop("clock")
    elif change == "missing-commitment": payload["artifact"].pop("tokens_digest")
    item = NamespaceObject.create(item.object_id, "TOKEN", payload)
    inventory, mapping, spec, policy = mapping_inputs(item)
    for row in spec["facets"]: row["properties"] = ["canonical_namespace_record"]
    target = next(f for f in inventory["facets"] if f["path"] == (
        ["payload", "artifact", "tokens_digest"] if change not in ("origin", "missing-commitment") else ["object_id"]))
    next(row for row in spec["facets"] if row["facet_id"] == target["facet_id"])["properties"].extend(token_facets.PROPERTY_CHECKS)
    spec["interactions"] = []
    policy["specification_digest"] = digest(canonical_bytes(spec))
    result = derive(inventory, spec, policy)
    assert not any(row["objective"] in token_checks.CHECKS.values() for row in result["obligations"])
    assert result["derivation_status"] == "UNKNOWN"
    assert any(row["code"] == "TOKEN_SCOPED_PROPERTY_BINDING_UNSUPPORTED" for row in result["diagnostics"])

def test_missing_epoch_anchor_blocks_only_tenure():
    item = subject(); payload = item.to_dict()["payload"]; payload["artifact"].pop("epochs_digest")
    item = NamespaceObject.create(item.object_id, "TOKEN", payload)
    inventory, mapping, spec, policy = mapping_inputs(item)
    result = derive(inventory, spec, policy)
    assert {row["objective"] for row in result["obligations"] if row["objective"] in token_checks.CHECKS.values()} == {"TOKEN-3.1", "TOKEN-4.1"}
    assert any(row["code"] == "TOKEN_PROPERTY_ANCHOR_MISSING" for row in mapping["diagnostics"])

def dependency_fixture():
    item = subject(); files = {}
    nodes = [facet(item, "representation", files)]
    checker_policy = typed_facets.typed_facets_policy(trust_roots=["test:token-selector"])
    evidence = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION, "objects": [item.to_dict()]})
    request = typed_facets.typed_facets_request(object_kind="TOKEN", subject_id=item.object_id,
        object_digest=item.digest, collection_digest=composition_digest([item]),
        evidence_ref=digest(evidence), policy=checker_policy)
    raw = typed_facets.build_typed_facets_certificate(request, evidence, policy=checker_policy)
    nodes.append(node(item, "composition", request, checker_policy, raw, files, version="1"))
    for check in token_checks.CHECKS:
        request, checker_policy, _, raw = specimen(check)
        nodes.append(node(item, check, request, checker_policy, raw, files, version="1"))
    profile = {"schema_version": dag.PROFILE, "profile_id": "test-only-token", "profile_version": "test-1",
        "object_kind": "TOKEN", "obligations": [
            obligation("representation", "OBJECT-1.1"), obligation("composition", "TOKEN-1.1"),
            *[obligation(check, coordinate) for check, coordinate in token_checks.CHECKS.items()]]}
    pin = digest(canonical_bytes(profile))
    bundle = {"schema_version": dag.BUNDLE, "profiles": [profile], "objects": [item.to_dict()], "nodes": nodes, "edges": []}
    policy = {"schema_version": dag.POLICY, "approved_profiles": [pin],
        "required_objects": [{"object_id": item.object_id, "object_kind": "TOKEN", "record_digest": item.digest, "profile_digest": pin}],
        "required_roots": [n["node_id"] for n in nodes], "nodes": deepcopy(nodes),
        "artifact_files_digest": dag.artifact_files_digest(files)}
    return item, bundle, policy, files

def test_token_native_dependency_replay_completes_only_selected_partial_obligations():
    item, bundle, dependency_policy, files = dependency_fixture()
    inventory, mapping, spec, policy = mapping_inputs(item)
    result = coverage.assess_facet_completeness(canonical_bytes(inventory), canonical_bytes(spec),
        expected_policy_bytes=canonical_bytes(policy), bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency_policy), artifact_files=files)
    assert len(result["obligations"]) == 5
    assert all(row["direct_status"] == row["completion_status"] == "PASS" for row in result["obligations"])
    assert result["status"] == "UNKNOWN" and result["qualification"] == "NOT_ESTABLISHED"

def test_missing_native_token_certificate_cannot_complete_its_facet_obligation():
    item, bundle, dependency_policy, files = dependency_fixture()
    dropped = bundle["nodes"].pop()
    dependency_policy["nodes"] = deepcopy(bundle["nodes"])
    dependency_policy["required_roots"].remove(dropped["node_id"])
    inventory, mapping, spec, policy = mapping_inputs(item)
    result = coverage.assess_facet_completeness(canonical_bytes(inventory), canonical_bytes(spec),
        expected_policy_bytes=canonical_bytes(policy), bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency_policy), artifact_files=files)
    assert any(row["completion_status"] == "UNKNOWN" for row in result["obligations"])
    assert any(row["code"] == "DERIVED_OBLIGATION_EVIDENCE_MISSING" for row in result["diagnostics"])
    assert result["status"] == "UNKNOWN"

def test_token_mapping_uses_the_single_packaged_normative_source():
    from importlib.resources import files
    root = Path(__file__).resolve().parents[1]
    packaged = files("verifier").joinpath("standard/CURRENT_TOKEN_FACET_MAPPING.md").read_bytes()
    assert packaged == (root/"src/verifier/standard/CURRENT_TOKEN_FACET_MAPPING.md").read_bytes()
    assert not (root/"standard/CURRENT_TOKEN_FACET_MAPPING.md").exists()


@pytest.mark.parametrize("relative", [
    "domains/contracts/token_facets.py",
    "standard/CURRENT_TOKEN_FACET_MAPPING.md"])
def test_token_facet_rule_rejects_a_changed_source_pin(relative, monkeypatch):
    item = subject(); inventory, mapping, spec, policy = mapping_inputs(item)
    target = Path(coverage.__file__).parents[2] / relative
    original = Path.read_bytes
    def changed(path):
        data = original(path)
        return data + b"changed-source" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    result = derive(inventory, spec, policy)
    assert result["status"] == "FAIL"
    assert result["diagnostics"][0]["code"] == "FACET_SPECIFICATION_OR_BINDING_REJECTED"


@pytest.mark.parametrize("check", list(token_checks.CHECKS))
def test_token_certificate_refuses_redaction_of_retained_evidence(check):
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    _, _, _, encoded = specimen(check)
    value = json.loads(encoded)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("TOKEN", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "local-check"), "2026-10-01T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)
