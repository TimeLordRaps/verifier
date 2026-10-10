"""Current SIM-4.2: selected cross-shard relations over retained finite rows."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import current_object_routes as routes
from test_current_sim_shard_coverage import selected as selected_shards
from verifier.runtime.polish import assess_polish


def commitment(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, relations: list | None = None, child: bytes | None | str = "default"):
    module = importlib.import_module("verifier.domains.contracts.sim_shard_relations")
    shard_module, shard_request, shard_policy, shard_evidence, _, _ = selected_shards()
    shard_certificate = shard_module.build_sim_shard_coverage_certificate(
        shard_request, shard_evidence, policy=shard_policy)
    assert shard_module.recheck_sim_shard_coverage_certificate(
        shard_certificate, expected_request=shard_request,
        policy=shard_policy)["status"] == "PASS"
    selected_relations = relations if relations is not None else [{
        "op": "eq", "args": [
            {"var": "right.r"},
            {"op": "add", "args": [{"var": "left.l"}, 2.0]},
        ]}]
    selected_child = shard_certificate if child == "default" else child
    evidence = canonical_bytes({
        "schema_version": module.EVIDENCE_VERSION,
        "shard_request": shard_request,
        "shard_policy": shard_policy,
        "shard_certificate": (base64.b64encode(selected_child).decode("ascii")
                              if selected_child is not None else None),
        "relations": selected_relations,
    })
    policy = module.sim_shard_relations_policy(trust_roots=["selected-shard-relations"])
    request = module.sim_shard_relations_request(
        subject_id=shard_request["subject_id"],
        object_digest=shard_request["object_digest"],
        collection_digest=shard_request["collection_digest"],
        shard_request_digest=commitment(shard_request),
        shard_policy_digest=commitment(shard_policy),
        shard_certificate_digest="sha256:" + hashlib.sha256(shard_certificate).hexdigest(),
        relations_digest=commitment(selected_relations),
        evidence_ref=commitment(json.loads(evidence)), policy=policy)
    return module, request, policy, evidence, shard_certificate


def replay(module, request, policy, evidence):
    certificate = module.build_sim_shard_relations_certificate(request, evidence, policy=policy)
    return certificate, module.recheck_sim_shard_relations_certificate(
        certificate, expected_request=request, policy=policy)


def test_two_shard_relation_replays_at_every_selected_time():
    module, request, policy, evidence, _ = selected()
    certificate, result = replay(module, request, policy, evidence)
    public = routes.replay_current_object_certificate(
        certificate, semantic_version=module.SEMANTIC_VERSION,
        objective=module.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["status"] == public["computational_status"] == "PASS"
    assert result["selected_cross_shard_relations"] == "PASS"
    assert result["all_cross_shard_relations"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["evaluations"] == 2
    assert result["sim_tier_4_conformance"] == "NOT_ESTABLISHED"
    assert certificate == module.build_sim_shard_relations_certificate(
        request, evidence, policy=policy)


def test_finite_cross_shard_relation_refuted_when_one_time_fails():
    relation = {"op": "le", "args": [
        {"op": "add", "args": [{"var": "right.r"}, {"var": "left.l"}]},
        3.0,
    ]}
    module, request, policy, evidence, _ = selected(relations=[relation])
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("relations", [
    [],
    [{"op": "eq", "args": [{"var": "left.l"}, {"var": "left.l"}]}],
    [{"op": "eq", "args": [2.0, 2.0]}],
    [{"op": "eq", "args": [{"var": "root.x"}, {"var": "left.l"}]}],
])
def test_empty_or_not_actually_cross_shard_relations_cannot_pass(relations):
    module, request, policy, evidence, _ = selected(relations=relations)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_absent_child_is_unknown_and_forged_child_is_not_trusted():
    module, request, policy, evidence, child = selected(child=None)
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"
    forged = json.loads(child)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = commitment(forged)
    forged_bytes = canonical_bytes(forged)
    changed = json.loads(evidence)
    changed["shard_certificate"] = base64.b64encode(forged_bytes).decode("ascii")
    request["shard_certificate_digest"] = "sha256:" + hashlib.sha256(forged_bytes).hexdigest()
    request["evidence_ref"] = commitment(changed)
    assert replay(module, request, policy, canonical_bytes(changed))[1]["status"] == "FAIL"


def test_rehashed_parent_verdict_and_changed_selection_are_refused():
    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    changed = deepcopy(request)
    changed["relations_digest"] = "sha256:" + "0" * 64
    with pytest.raises(module.SimShardRelationsError):
        module.recheck_sim_shard_relations_certificate(
            certificate, expected_request=changed, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = commitment(forged)
    with pytest.raises(module.SimShardRelationsError):
        module.recheck_sim_shard_relations_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


@pytest.mark.parametrize("relation", [
    {"op": "eq", "args": [{"var": "left.absent"}, {"var": "right.r"}]},
    {"op": "eq", "args": [
        {"op": "div", "args": [{"var": "left.l"}, 0.0]},
        {"var": "right.r"}]},
])
def test_missing_retained_variable_or_undefined_arithmetic_fails(relation):
    module, request, policy, evidence, _ = selected(relations=[relation])
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_parent_operation_exhaustion_is_unknown():
    module, request, policy, evidence, _ = selected()
    request["limits"]["max_operations"] = 1
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_actual_canonical_certificate_refuses_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        ObserverParty, EmissionContext, EmissionEvaluator, EmissionRefusalError)

    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    value = json.loads(certificate)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("SIM", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_shard_relations.py",
    "standard/CURRENT_SIM_SHARD_RELATIONS.md",
])
def test_checker_or_spec_substitution_invalidates_policy(monkeypatch, relative):
    module = importlib.import_module("verifier.domains.contracts.sim_shard_relations")
    before = module.mechanism_digest()
    target = (Path(module.__file__).resolve().parents[2] / relative).resolve()
    original = Path.read_bytes

    def changed(path):
        raw = original(path)
        return raw + b"\n# selected mechanism substitution\n" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert module.mechanism_digest() != before


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_shard_relations.py",
    "standard/CURRENT_SIM_SHARD_RELATIONS.md",
])
def test_checker_or_spec_substitution_invalidates_polish_mechanism(monkeypatch, relative):
    from verifier.runtime import polish

    before = polish.mechanism_digest()
    module = importlib.import_module("verifier.domains.contracts.sim_shard_relations")
    target = (Path(module.__file__).resolve().parents[2] / relative).resolve()
    original = Path.read_bytes

    def changed(path):
        raw = original(path)
        return raw + b"\n# selected mechanism substitution\n" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_polish_keeps_unknown_aggregate_despite_selected_pass():
    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    _, _, _, _, _, dynamics_evidence = selected_shards()
    objects = json.loads(dynamics_evidence)["objects"]
    certificate_digest = "sha256:" + hashlib.sha256(certificate).hexdigest()
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {certificate_digest: certificate.decode("utf-8")}}
    requirements = [{"object_id": item["object_id"], "tier": tier,
                     "applicability": "REQUIRED", "rationale": "selected finite scope",
                     "objectives": []}
                    for item in objects for tier in range(1, 10)]
    next(row for row in requirements if row["object_id"] == "sim" and row["tier"] == 4)["objectives"] = [{
        "semantic_version": module.SEMANTIC_VERSION, "coordinate": module.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": certificate_digest}]
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "sim", "collection_digest": request["collection_digest"],
        "bundle_digest": "sha256:" + hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
        "requirements": requirements}
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    assert report["objectives"][0]["status"] == "PASS"


def test_legacy_selector_and_wrong_kind_cannot_claim_current_relations():
    module, request, policy, evidence, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    for semantic, kind in (("legacy-sim-domain-1", "SIM"),
                           (module.SEMANTIC_VERSION, "BOT")):
        with pytest.raises(routes.CurrentObjectRouteRefusal):
            routes.replay_current_object_certificate(
                certificate, semantic_version=semantic, objective=module.COORDINATE,
                represented_kind=kind, expected_request=request, policy=policy)
