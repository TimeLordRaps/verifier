"""Current simulation (SIM) shard coverage of a selected finite trace.

Verifier Standard (VSTD) uses canonical JavaScript Object Notation (JSON) and
Secure Hash Algorithm 256-bit (SHA-256) commitments. Times share the selected
model's declared time unit; counts are dimensionless. This does not establish
physical execution, cross-shard relations or complete simulated-surface scope.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_dynamics
from verifier.domains.contracts import sim_shard_coverage as sim_shard_coverage_contract
from verifier.runtime.polish import assess_polish
from test_current_sim_dynamics import selected as selected_dynamics


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def shard_module():
    return sim_shard_coverage_contract


def selected(*, shard_ids: list[str] | None = None,
             shard_rows: dict | None = None, child: bytes | None | str = "default"):
    module = shard_module()
    child_request, child_policy, child_evidence = selected_dynamics()
    child_certificate = sim_dynamics.build_sim_dynamics_certificate(
        child_request, child_evidence, policy=child_policy)
    assert sim_dynamics.recheck_sim_dynamics_certificate(
        child_certificate, expected_request=child_request,
        policy=child_policy)["status"] == "PASS"
    ids = ["left", "right"] if shard_ids is None else shard_ids
    rows = ({"left": [{"time": 0.0, "state": {"l": 0.0}},
                      {"time": 1.0, "state": {"l": 1.0}}],
             "right": [{"time": 0.0, "state": {"r": 2.0}},
                       {"time": 1.0, "state": {"r": 3.0}}]}
            if shard_rows is None else shard_rows)
    retained_child = child_certificate if child == "default" else child
    evidence = canonical_bytes({"schema_version": module.EVIDENCE_VERSION,
        "dynamics_request": child_request, "dynamics_policy": child_policy,
        "dynamics_certificate": (base64.b64encode(retained_child).decode("ascii")
                                 if retained_child is not None else None),
        "shard_ids": ids, "shard_rows": rows})
    policy = module.sim_shard_coverage_policy(trust_roots=["selected-shard-fixture"])
    request = module.sim_shard_coverage_request(
        subject_id=child_request["subject_id"],
        object_digest=child_request["object_digest"],
        collection_digest=child_request["collection_digest"],
        dynamics_request_digest=digest(child_request),
        dynamics_policy_digest=digest(child_policy),
        dynamics_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        shard_ids_digest=digest(ids), shard_rows_digest=digest(rows),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    return module, request, policy, evidence, child_certificate, child_evidence


def replay(module, request, policy, evidence):
    certificate = module.build_sim_shard_coverage_certificate(
        request, evidence, policy=policy)
    return certificate, module.recheck_sim_shard_coverage_certificate(
        certificate, expected_request=request, policy=policy)


def test_selected_shards_cover_every_trajectory_time_without_tier_promotion():
    module, request, policy, evidence, _, _ = selected()
    certificate, native = replay(module, request, policy, evidence)
    public = routes.replay_current_object_certificate(
        certificate, semantic_version=module.SEMANTIC_VERSION,
        objective=module.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert native["status"] == public["computational_status"] == "PASS"
    assert native["evaluation"]["observations"]["shards"] == 2
    assert native["evaluation"]["observations"]["states"] == 2
    for field in ("cross_shard_relations", "shard_signatures",
                  "whole_surface_coverage", "sim_tier_4_conformance",
                  "historical_execution", "authority"):
        assert native[field] == "NOT_ESTABLISHED"
    assert certificate == module.build_sim_shard_coverage_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("ids,rows", [
    (["left", "right"], {"left": [{"time": 0.0, "state": {"l": 0.0}},
                                 {"time": 1.0, "state": {"l": 1.0}}]}),
    (["left", "right"], {"left": [{"time": 0.0, "state": {"l": 0.0}},
                                 {"time": 1.0, "state": {"l": 1.0}}],
                         "right": [{"time": 0.0, "state": {"r": 2.0}}]}),
    (["left", "left"], {"left": [{"time": 0.0, "state": {"l": 0.0}},
                                {"time": 1.0, "state": {"l": 1.0}}]}),
    (["left", "right"], {"left": [{"time": 0.0, "state": {"l": 0.0}},
                                 {"time": 1.0, "state": {"l": 1.0}}],
                         "right": [{"time": 0.0, "state": {"r": 2.0}},
                                   {"time": 0.5, "state": {"r": 3.0}}]}),
])
def test_missing_duplicate_short_or_misaligned_shard_refutes_coverage(ids, rows):
    module, request, policy, evidence, _, _ = selected(shard_ids=ids,
                                                       shard_rows=rows)
    assert replay(module, request, policy, evidence)[1]["status"] == "FAIL"


def test_absent_selected_child_remains_unknown():
    module, request, policy, evidence, _, _ = selected(child=None)
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_rehashed_child_verdict_cannot_supply_shard_pass():
    module, request, policy, evidence, child, _ = selected()
    forged = json.loads(child)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    forged_bytes = canonical_bytes(forged)
    changed = json.loads(evidence)
    changed["dynamics_certificate"] = base64.b64encode(forged_bytes).decode("ascii")
    request["dynamics_certificate_digest"] = "sha256:" + hashlib.sha256(forged_bytes).hexdigest()
    request["evidence_ref"] = digest(changed)
    assert replay(module, request, policy, canonical_bytes(changed))[1]["status"] == "FAIL"


def test_substituted_selection_and_rehashed_parent_verdict_are_refused():
    module, request, policy, evidence, _, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    changed = deepcopy(request)
    changed["object_digest"] = "sha256:" + "0" * 64
    with pytest.raises(module.SimShardCoverageError):
        module.recheck_sim_shard_coverage_certificate(
            certificate, expected_request=changed, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(module.SimShardCoverageError):
        module.recheck_sim_shard_coverage_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_polish_replays_selected_objective_without_claiming_whole_tier():
    module, request, policy, evidence, _, child_evidence = selected()
    certificate, _ = replay(module, request, policy, evidence)
    objects = json.loads(child_evidence)["objects"]
    certificate_digest = "sha256:" + hashlib.sha256(certificate).hexdigest()
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": objects,
              "certificates": {certificate_digest: certificate.decode("utf-8")}}
    requirements = [{"object_id": item["object_id"], "tier": tier,
                     "applicability": "REQUIRED", "rationale": "finite selected scope",
                     "objectives": []}
                    for item in objects for tier in range(1, 10)]
    next(row for row in requirements if row["object_id"] == "sim" and row["tier"] == 4)["objectives"] = [{
        "semantic_version": module.SEMANTIC_VERSION, "coordinate": module.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "sim", "collection_digest": request["collection_digest"],
        "bundle_digest": "sha256:" + hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
        "requirements": requirements}
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    assert report["objectives"][0]["status"] == "PASS"


def test_selected_operation_exhaustion_stays_unknown():
    module, request, policy, evidence, _, _ = selected()
    request["limits"]["max_operations"] = 1
    assert replay(module, request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_actual_retained_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        ObserverParty, EmissionContext, EmissionEvaluator, EmissionRefusalError)

    module, request, policy, evidence, _, _ = selected()
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
    "domains/contracts/sim_shard_coverage.py",
    "standard/CURRENT_SIM_SHARD_COVERAGE.md",
])
def test_selected_checker_or_spec_substitution_invalidates_policy(monkeypatch, relative):
    module = shard_module()
    before = module.mechanism_digest()
    target = (Path(module.__file__).resolve().parents[2] / relative).resolve()
    original = Path.read_bytes

    def changed(path):
        raw = original(path)
        return raw + b"\n# selected mechanism substitution\n" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert module.mechanism_digest() != before


def test_legacy_or_wrong_kind_route_cannot_claim_current_sim_shards():
    module, request, policy, evidence, _, _ = selected()
    certificate, _ = replay(module, request, policy, evidence)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version="legacy-sim-domain-1",
            objective=module.COORDINATE, represented_kind="SIM",
            expected_request=request, policy=policy)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=module.SEMANTIC_VERSION,
            objective=module.COORDINATE, represented_kind="BOT",
            expected_request=request, policy=policy)
