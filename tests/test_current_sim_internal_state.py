"""Independent finite examples for SIM-2.3's selected-channel enumeration core."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.inventory import MECHANIZED_12_POINT_BINDINGS
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import current_object_routes as routes, sim_dynamics, sim_internal_state
from verifier.domains.contracts.sim_internal_state import enumerate_hidden_changes
from verifier.runtime.public_cli import main

from test_current_sim_response import fixture as response_fixture


def _budget(operations: int = 100_000) -> Budget:
    return Budget(operations, 4096)


def test_simultaneous_visible_and_internal_changes_are_separated():
    states = [{"x": 0.0, "y": 0.0}, {"x": 1.0, "y": 2.0}]
    channels = {"display": {"var": "x"}}
    assert enumerate_hidden_changes(states, channels, _budget()) == [
        {"step": 0, "state_key": "y", "before": 0.0, "after": 2.0}]


def test_interacting_channel_exposes_both_changes_across_endpoint_hybrids():
    states = [{"x": 0.0, "y": 0.0}, {"x": 1.0, "y": 1.0}]
    channels = {"product": {"op": "mul", "args": [
        {"var": "x"}, {"var": "y"}]}}
    assert enumerate_hidden_changes(states, channels, _budget()) == []


def test_cancelled_channel_does_not_expose_a_changed_value():
    states = [{"x": 0.0}, {"x": 2.0}]
    channels = {"zero": {"op": "sub", "args": [
        {"var": "x"}, {"var": "x"}]}}
    assert enumerate_hidden_changes(states, channels, _budget()) == [
        {"step": 0, "state_key": "x", "before": 0.0, "after": 2.0}]


def test_empty_selected_channel_inventory_exposes_no_model_state_delta():
    assert enumerate_hidden_changes(
        [{"x": 0.0}, {"x": 1.0}], {}, _budget()) == [
            {"step": 0, "state_key": "x", "before": 0.0, "after": 1.0}]


def test_signed_zero_is_not_a_numeric_state_change():
    assert enumerate_hidden_changes(
        [{"x": 0.0}, {"x": -0.0}], {}, _budget()) == []


def test_channel_name_order_does_not_change_enumeration():
    states = [{"x": 0.0, "y": 0.0}, {"x": 1.0, "y": 2.0}]
    x = {"a": {"var": "x"}, "b": 4.0}
    y = {"b": 4.0, "a": {"var": "x"}}
    assert enumerate_hidden_changes(states, x, _budget()) == enumerate_hidden_changes(
        states, y, _budget())


def test_complete_state_inventory_refutes_unknown_channel_variable():
    with pytest.raises(Refuted, match="complete selected state"):
        enumerate_hidden_changes(
            [{"x": 0.0}, {"x": 1.0}], {"unknown": {"var": "z"}}, _budget())


def test_unchanged_trace_cannot_mask_invalid_selected_channel():
    with pytest.raises(Refuted, match="complete selected state"):
        enumerate_hidden_changes(
            [{"x": 0.0}, {"x": 0.0}], {"unknown": {"var": "z"}}, _budget())


def test_unchanged_trace_cannot_mask_unsupported_selected_channel():
    with pytest.raises(Unavailable, match="unsupported expression"):
        enumerate_hidden_changes(
            [{"x": 0.0}, {"x": 0.0}],
            {"unknown": {"op": "future", "args": [1.0, 2.0]}}, _budget())


def test_undefined_endpoint_hybrid_is_unknown_not_hidden_or_refuted():
    states = [{"x": 0.0, "y": 1.0}, {"x": 1.0, "y": 2.0}]
    channel = {"ratio": {"op": "div", "args": [
        1.0, {"op": "sub", "args": [{"var": "x"}, {"var": "y"}]}]}}
    with pytest.raises(Unavailable, match="undefined"):
        enumerate_hidden_changes(states, channel, _budget())


def test_nonfinite_endpoint_hybrid_is_unknown_not_refuted():
    states = [{"x": 1e100, "y": 0.0}, {"x": 0.0, "y": 1e100}]
    channel = {"product": {"op": "mul", "args": [
        {"var": "x"}, {"var": "y"}]}}
    with pytest.raises(Unavailable, match="undefined"):
        enumerate_hidden_changes(states, channel, _budget())


def test_undefined_retained_observation_is_refuted():
    channel = {"ratio": {"op": "div", "args": [1.0, {"var": "x"}]}}
    with pytest.raises(Refuted, match="retained state"):
        enumerate_hidden_changes(
            [{"x": 0.0}, {"x": 1.0}], channel, _budget())


def test_nonfinite_retained_observation_is_refuted():
    channel = {"product": {"op": "mul", "args": [
        {"var": "x"}, {"var": "y"}]}}
    with pytest.raises(Refuted, match="bounded finite real"):
        enumerate_hidden_changes(
            [{"x": 1e100, "y": 1e100}, {"x": 0.0, "y": 0.0}],
            channel, _budget())


def test_finite_operation_budget_exhaustion_is_unknown():
    with pytest.raises(Unavailable):
        enumerate_hidden_changes(
            [{"x": 0.0}, {"x": 1.0}], {"display": {"var": "x"}},
            _budget(1))


def test_endpoint_hypercube_limit_is_unknown_not_false_hiddenness():
    before = {f"s{i}": 0.0 for i in range(13)}
    after = {f"s{i}": 1.0 for i in range(13)}
    with pytest.raises(Unavailable, match="endpoint"):
        enumerate_hidden_changes([before, after], {"constant": 0.0}, _budget())


def test_ten_dimensional_additive_channel_completes_within_selected_budget():
    names = tuple(f"s{i}" for i in range(10))
    before = {name: 0.0 for name in names}
    after = {name: 1.0 for name in names}
    expression: object = {"var": names[0]}
    for name in names[1:]:
        expression = {"op": "add", "args": [expression, {"var": name}]}
    budget = _budget(100_000)
    assert enumerate_hidden_changes(
        [before, after], {"sum": expression}, budget) == []
    assert budget.used <= budget.limit


def test_insufficient_selected_state_item_bound_is_unknown():
    states = [{"x": 0.0, "y": 0.0, "z": 0.0},
              {"x": 1.0, "y": 1.0, "z": 1.0}]
    with pytest.raises(Unavailable, match="state item bound"):
        enumerate_hidden_changes(states, {"constant": 0.0}, Budget(100_000, 2))


def test_empty_state_inventory_is_refuted_independently_of_budget():
    with pytest.raises(Refuted, match="nonempty selected state"):
        enumerate_hidden_changes([{}, {}], {}, _budget())


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _selected(*, visible: bool = False):
    response_request, _, response_evidence, *_ = response_fixture(responsive=True)
    child = json.loads(response_evidence)["trajectory_certificate"]
    artifact = {"declared_complete": True,
                "channels": {"display": {"var": "x"} if visible else 0.0}}
    hidden = [] if visible else [
        {"step": 0, "state_key": "x", "before": 0.0, "after": 1.0}]
    evidence = {"schema_version": sim_internal_state.EVIDENCE_VERSION,
                "trajectory_certificate": child,
                "observation_artifact": artifact,
                "declared_hidden_changes": hidden}
    raw = canonical_bytes(evidence)
    policy = sim_internal_state.sim_internal_state_policy(
        trust_roots=["selected-internal-state-fixture"])
    request = sim_internal_state.sim_internal_state_request(
        subject_id=response_request["subject_id"],
        object_digest=response_request["object_digest"],
        collection_digest=response_request["collection_digest"],
        trajectory_request=response_request["trajectory_request"],
        trajectory_policy=response_request["trajectory_policy"],
        trajectory_certificate_digest=response_request["trajectory_certificate_digest"],
        observation_artifact_digest=_digest(artifact),
        hidden_changes_digest=_digest(hidden), evidence_ref=_digest(evidence),
        policy=policy)
    return request, policy, evidence, raw


def selected():
    request, policy, _, raw = _selected()
    return request, policy, raw


@pytest.mark.parametrize("visible", [False, True])
def test_exact_selected_child_and_channels_replay_internal_state(visible: bool):
    request, policy, _, raw = _selected(visible=visible)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, raw, policy=policy)
    result = sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["sim_tier_2_conformance"] == "NOT_ESTABLISHED"
    assert result["physical_observation_truth"] == "NOT_ESTABLISHED"
    assert result["channel_inventory_authority"] == "NOT_ESTABLISHED"


def test_selected_hidden_inventory_cannot_omit_observed_internal_change():
    request, policy, evidence, _ = _selected()
    evidence["declared_hidden_changes"] = []
    request["hidden_changes_digest"] = _digest([])
    request["evidence_ref"] = _digest(evidence)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    result = sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "FAIL"


def test_missing_channel_artifact_stays_unknown_not_empty_inventory():
    request, policy, evidence, _ = _selected()
    evidence["observation_artifact"] = None
    request["evidence_ref"] = _digest(evidence)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    result = sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"


def test_incomplete_selected_channel_declaration_stays_unknown():
    request, policy, evidence, _ = _selected()
    evidence["observation_artifact"]["declared_complete"] = False
    request["observation_artifact_digest"] = _digest(evidence["observation_artifact"])
    request["evidence_ref"] = _digest(evidence)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    assert sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "UNKNOWN"


@pytest.mark.parametrize("context", [
    "complete", "absent-child", "unknown-child", "absent-enumeration"])
@pytest.mark.parametrize("artifact", [
    {"declared_complete": 1, "channels": {"display": 0.0}},
    {"channels": {"display": 0.0}},
    {"declared_complete": True, "channels": {"display": 0.0}, "extra": 0},
    {"declared_complete": True, "channels": []},
])
def test_present_invalid_observation_artifact_precedes_unavailable_dependency(
        context: str, artifact: dict):
    request, policy, evidence, _ = _selected()
    evidence["observation_artifact"] = artifact
    request["observation_artifact_digest"] = _digest(artifact)
    if context == "absent-child":
        evidence["trajectory_certificate"] = None
    elif context == "unknown-child":
        unknown_child = sim_dynamics.build_sim_dynamics_certificate(
            request["trajectory_request"], None, policy=request["trajectory_policy"])
        assert json.loads(unknown_child)["result"]["status"] == "UNKNOWN"
        evidence["trajectory_certificate"] = base64.b64encode(unknown_child).decode("ascii")
        request["trajectory_certificate_digest"] = "sha256:" + hashlib.sha256(
            unknown_child).hexdigest()
    elif context == "absent-enumeration":
        evidence["declared_hidden_changes"] = None
    request["evidence_ref"] = _digest(evidence)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=sim_internal_state.SEMANTIC_VERSION,
        objective=sim_internal_state.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["computational_status"] == "FAIL"


def test_present_malformed_hidden_change_record_precedes_absent_child():
    request, policy, evidence, _ = _selected()
    evidence["trajectory_certificate"] = None
    evidence["declared_hidden_changes"] = [{"step": 0, "state_key": "x"}]
    request["hidden_changes_digest"] = _digest(evidence["declared_hidden_changes"])
    request["evidence_ref"] = _digest(evidence)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    assert sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_known_selected_artifact_contradiction_precedes_exhausted_budget():
    request, policy, evidence, _ = _selected()
    evidence["observation_artifact"]["channels"]["display"] = {"var": "x"}
    request["evidence_ref"] = _digest(evidence)
    request["limits"]["max_operations"] = 1
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    assert sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_refuted_child_precedes_missing_channels_and_parent_budget():
    request, policy, evidence, _ = _selected()
    child = json.loads(base64.b64decode(evidence["trajectory_certificate"]))
    child_evidence = json.loads(base64.b64decode(
        child["evidence_payloads"][request["trajectory_request"]["evidence_ref"]]))
    child_evidence["artifact"]["transition"]["x"] = 0.0
    request["trajectory_request"]["evidence_ref"] = _digest(child_evidence)
    child_bytes = sim_dynamics.build_sim_dynamics_certificate(
        request["trajectory_request"], canonical_bytes(child_evidence),
        policy=request["trajectory_policy"])
    assert json.loads(child_bytes)["result"]["status"] == "FAIL"
    evidence["trajectory_certificate"] = base64.b64encode(child_bytes).decode("ascii")
    evidence["observation_artifact"] = None
    request["trajectory_certificate_digest"] = "sha256:" + hashlib.sha256(child_bytes).hexdigest()
    request["evidence_ref"] = _digest(evidence)
    request["limits"]["max_operations"] = 1
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, canonical_bytes(evidence), policy=policy)
    assert sim_internal_state.recheck_sim_internal_state_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_selected_request_and_rehashed_result_substitution_are_refused():
    request, policy, evidence, raw = _selected()
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, raw, policy=policy)
    altered = deepcopy(request)
    altered["hidden_changes_digest"] = _digest([])
    with pytest.raises(ValueError):
        sim_internal_state.recheck_sim_internal_state_certificate(
            certificate, expected_request=altered, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = _digest(forged)
    with pytest.raises(ValueError):
        sim_internal_state.recheck_sim_internal_state_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def _five_state_selected(*, max_items: int, invalid_child: bool = False):
    names = tuple(f"s{i}" for i in range(5))
    before = {name: 0.0 for name in names}
    after = {name: 1.0 for name in names}
    trace = {"states": [before, after], "entropy": [1.0],
             "times": [0.0, 1.0]}
    program = {"transition": {name: {"op": "add", "args": [
        {"var": name}, {"var": "entropy"}]} for name in names},
        "initial_state": before, "trajectory_digest": _digest(trace["states"]),
        "entropy_digest": _digest(trace["entropy"]),
        "times_digest": _digest(trace["times"])}
    objects = [NamespaceObject.create("data", "DATA", {}),
               NamespaceObject.create("checker", "VERIFIER", {}),
               NamespaceObject.create("world", "OBJECT", {}),
               NamespaceObject.create("env", "ENV", {})]
    subject = NamespaceObject.create("sim", "SIM", {
        "scope": "selected-retained-trajectory-replay",
        "artifact_digest": _digest(program), "inputs_digest": _digest(trace)},
        {"data": ["data"], "verifier": ["checker"],
         "objects": ["world"], "env": ["env"]})
    objects.append(subject)
    child_evidence = {"schema_version": sim_dynamics.EVIDENCE_VERSION,
                      "objects": [obj.to_dict() for obj in objects],
                      "artifact": program, "inputs": trace}
    child_policy = sim_dynamics.sim_dynamics_policy(trust_roots=["five-state"])
    child_request = sim_dynamics.sim_dynamics_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        artifact_digest=_digest(program), inputs_digest=_digest(trace),
        expected_counts={"states": 2, "transitions": 1},
        evidence_ref=_digest(child_evidence), policy=child_policy)
    if invalid_child:
        child_evidence["inputs"]["states"][1]["s4"] = 2.0
        child_request["evidence_ref"] = _digest(child_evidence)
    child = sim_dynamics.build_sim_dynamics_certificate(
        child_request, canonical_bytes(child_evidence), policy=child_policy)
    assert json.loads(child)["result"]["status"] == (
        "FAIL" if invalid_child else "PASS")
    expression: object = {"var": names[0]}
    for name in names[1:]:
        expression = {"op": "add", "args": [expression, {"var": name}]}
    artifact = {"declared_complete": True, "channels": {"sum": expression}}
    evidence = {"schema_version": sim_internal_state.EVIDENCE_VERSION,
                "trajectory_certificate": base64.b64encode(child).decode("ascii"),
                "observation_artifact": artifact, "declared_hidden_changes": []}
    policy = sim_internal_state.sim_internal_state_policy(
        trust_roots=["five-state"])
    request = sim_internal_state.sim_internal_state_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        trajectory_request=child_request, trajectory_policy=child_policy,
        trajectory_certificate_digest="sha256:" + hashlib.sha256(child).hexdigest(),
        observation_artifact_digest=_digest(artifact),
        hidden_changes_digest=_digest([]), evidence_ref=_digest(evidence),
        policy=policy, limits={"max_items": max_items})
    return request, policy, canonical_bytes(evidence)


@pytest.mark.parametrize("max_items,invalid_child,expected", [
    (4, False, "UNKNOWN"), (8, False, "PASS"), (8, True, "FAIL")])
def test_public_five_state_bound_distinguishes_exhaustion_and_refutation(
        max_items: int, invalid_child: bool, expected: str):
    request, policy, evidence = _five_state_selected(
        max_items=max_items, invalid_child=invalid_child)
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=sim_internal_state.SEMANTIC_VERSION,
        objective=sim_internal_state.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["computational_status"] == expected
    if expected == "UNKNOWN":
        assert "state item bound" in result["native_result"]["evaluation"]["details"]


def test_public_route_replays_selected_internal_state_without_tier_promotion():
    request, policy, _, raw = _selected()
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, raw, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=sim_internal_state.SEMANTIC_VERSION,
        objective=sim_internal_state.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["sim_tier_2_conformance"] == "NOT_ESTABLISHED"


def test_public_cli_replays_selected_internal_state_from_immutable_files(tmp_path, capsys):
    request, policy, _, raw = _selected()
    certificate = sim_internal_state.build_sim_internal_state_certificate(
        request, raw, policy=policy)
    paths = [tmp_path / name for name in ("certificate.json", "request.json", "policy.json")]
    for path, data in zip(paths, (certificate, canonical_bytes(request), canonical_bytes(policy))):
        path.write_bytes(data)
    before = [path.read_bytes() for path in paths]
    exit_code = main([
        "current-object", "check", str(paths[0]),
        "--semantic-version", sim_internal_state.SEMANTIC_VERSION,
        "--objective", sim_internal_state.COORDINATE,
        "--represented-kind", "SIM", "--request", str(paths[1]),
        "--policy", str(paths[2]), "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert [path.read_bytes() for path in paths] == before


def test_internal_state_route_has_exact_public_inventory_binding():
    binding = MECHANIZED_12_POINT_BINDINGS["SIM-2.3"]
    assert binding["exact_claim"] == sim_internal_state.registration()["proposition"]
    assert binding["resulting_evidence"] == sim_internal_state.CERTIFICATE_VERSION
