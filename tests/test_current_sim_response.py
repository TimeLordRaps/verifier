"""Current simulation (SIM) action responsiveness is model-relative and selected."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import Budget
from verifier.domains import sim as legacy_sim
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_dynamics, sim_response


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def fixture(*, responsive: bool, steps: int = 1):
    initial = {"x": 0.0}
    entropy = [1.0 if responsive else 0.0] * steps
    inputs = {"states": [{"x": float(i if responsive else 0)} for i in range(steps + 1)],
              "entropy": entropy, "times": [float(i) for i in range(steps + 1)]}
    artifact = {"transition": {"x": {"op": "add", "args": [
        {"var": "x"}, {"var": "entropy"}]}},
        "initial_state": initial, "trajectory_digest": digest(inputs["states"]),
        "entropy_digest": digest(entropy), "times_digest": digest(inputs["times"])}
    objects = [NamespaceObject.create("data", "DATA", {}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("world", "OBJECT", {}),
        NamespaceObject.create("env", "ENV", {})]
    subject = NamespaceObject.create("sim", "SIM", {
        "scope": "selected-retained-trajectory-replay",
        "artifact_digest": digest(artifact), "inputs_digest": digest(inputs),
    }, {"data": ["data"], "verifier": ["checker"],
        "objects": ["world"], "env": ["env"]})
    objects.append(subject)
    child_evidence = canonical_bytes({"schema_version": sim_dynamics.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects], "artifact": artifact, "inputs": inputs})
    child_policy = sim_dynamics.sim_dynamics_policy(trust_roots=["selected-response-fixture"])
    child_request = sim_dynamics.sim_dynamics_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        artifact_digest=digest(artifact), inputs_digest=digest(inputs),
        expected_counts={"states": steps + 1, "transitions": steps},
        evidence_ref=digest(json.loads(child_evidence)), policy=child_policy)
    child_certificate = sim_dynamics.build_sim_dynamics_certificate(
        child_request, child_evidence, policy=child_policy)
    action_artifact = {"program": {"x": {"op": "add", "args": [
        {"var": "x"}, {"var": "action.push"}]} if responsive else {"var": "x"}},
        "baseline_action": {"push": 0.0},
        "action_bounds": {"push": {"minimum": 0.0, "maximum": 2.0}},
        "time_unit": "simulated_seconds"}
    action_inputs = {"actions": [{"push": 1.0} for _ in range(steps)]}
    evidence = canonical_bytes({"schema_version": sim_response.EVIDENCE_VERSION,
        "trajectory_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "action_artifact": action_artifact, "action_inputs": action_inputs})
    policy = sim_response.sim_response_policy(trust_roots=["selected-response-fixture"])
    request = sim_response.sim_response_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        trajectory_request=child_request, trajectory_policy=child_policy,
        trajectory_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        action_artifact_digest=digest(action_artifact),
        action_inputs_digest=digest(action_inputs),
        max_response_delay=1.0, time_unit="simulated_seconds",
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    return request, policy, evidence, artifact, inputs, action_artifact, action_inputs


def selected():
    request, policy, evidence, *_ = fixture(responsive=True)
    return request, policy, evidence


def test_action_change_without_state_response_is_not_promoted():
    request, policy, evidence, artifact, inputs, action_artifact, action_inputs = fixture(responsive=False)
    legacy_artifact = {**artifact, "observation": {"x": {"var": "x"}},
        "action_bounds": action_artifact["action_bounds"]}
    legacy_inputs = {**inputs, "observations": inputs["states"],
        "actions": action_inputs["actions"]}
    assert legacy_sim.evaluate("channels", legacy_artifact, legacy_inputs,
        Budget(10000), witness_keys={}) == {"states": 2, "transitions": 1}
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    result = sim_response.recheck_sim_response_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "FAIL"
    assert result["sim_tier_2_conformance"] == "NOT_ESTABLISHED"


def test_action_driven_next_state_passes_model_relative_check():
    request, policy, evidence, *_ = fixture(responsive=True)
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    result = sim_response.recheck_sim_response_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["sim_tier_2_conformance"] == "NOT_ESTABLISHED"


def test_every_selected_step_is_replayed_and_one_unresponsive_step_fails():
    request, policy, evidence, *_ = fixture(responsive=True, steps=3)
    assert replay(request, policy, evidence)["status"] == "PASS"
    value = json.loads(evidence)
    value["action_inputs"]["actions"][1]["push"] = 0.0
    selected, raw = reselection(request, canonical_bytes(value), inputs=True)
    assert replay(selected, policy, raw)["status"] == "FAIL"


def test_current_public_route_rechecks_selected_response():
    request, policy, evidence, *_ = fixture(responsive=True)
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=sim_response.SEMANTIC_VERSION,
        objective=sim_response.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["sim_tier_2_conformance"] == "NOT_ESTABLISHED"


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    return sim_response.recheck_sim_response_certificate(
        certificate, expected_request=request, policy=policy)


def reselection(request: dict, evidence: bytes, *, artifact: bool = False,
                inputs: bool = False) -> tuple[dict, bytes]:
    selected = deepcopy(request)
    value = json.loads(evidence)
    if artifact and value["action_artifact"] is not None:
        selected["action_artifact_digest"] = digest(value["action_artifact"])
    if inputs and value["action_inputs"] is not None:
        selected["action_inputs_digest"] = digest(value["action_inputs"])
    raw = canonical_bytes(value)
    selected["evidence_ref"] = digest(value)
    return selected, raw


def test_rehashed_action_with_no_effect_fails_even_when_child_passes():
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    value["action_inputs"]["actions"][0]["push"] = 0.0
    selected, raw = reselection(request, canonical_bytes(value), inputs=True)
    assert replay(selected, policy, raw)["status"] == "FAIL"


@pytest.mark.parametrize("selected_action", [0.0, 1.0])
def test_signed_zero_representation_does_not_establish_numeric_action_response(
        selected_action: float):
    request, policy, evidence, *_ = fixture(responsive=False)
    value = json.loads(evidence)
    value["action_artifact"]["program"]["x"] = (
        {"var": "action.push"} if selected_action == 0.0 else
        {"op": "mul", "args": [0.0, {"var": "action.push"}]})
    value["action_artifact"]["baseline_action"]["push"] = -0.0
    value["action_inputs"]["actions"][0]["push"] = selected_action
    selected, raw = reselection(request, canonical_bytes(value), artifact=True, inputs=True)
    assert replay(selected, policy, raw)["status"] == "FAIL"


def test_program_reference_outside_complete_selected_action_inventory_fails():
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    value["action_artifact"]["program"]["x"]["args"][1] = {"var": "action.absent"}
    selected, raw = reselection(request, canonical_bytes(value), artifact=True)
    assert replay(selected, policy, raw)["status"] == "FAIL"


def test_empty_action_array_cannot_hide_known_child_transition():
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    value["action_inputs"]["actions"] = []
    selected, raw = reselection(request, canonical_bytes(value), inputs=True)
    assert replay(selected, policy, raw)["status"] == "FAIL"


@pytest.mark.parametrize("change", ["wrong_state", "bounds", "unit", "missing"])
def test_rehashed_action_evidence_cannot_gain_unearned_response(change: str):
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    if change == "wrong_state":
        value["action_artifact"]["program"]["x"] = 0.0
    elif change == "bounds":
        value["action_artifact"]["action_bounds"]["push"]["maximum"] = 0.5
    elif change == "unit":
        value["action_artifact"]["time_unit"] = "model_steps"
    else:
        value["action_artifact"] = None
    selected, raw = reselection(request, canonical_bytes(value), artifact=True)
    assert replay(selected, policy, raw)["status"] == (
        "UNKNOWN" if change == "missing" else "FAIL")


def test_selected_simulated_time_bound_is_enforced():
    request, policy, evidence, *_ = fixture(responsive=True)
    request["max_response_delay"] = 0.5
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_missing_and_exhausted_response_evidence_stay_unknown():
    request, policy, evidence, *_ = fixture(responsive=True)
    assert replay(request, policy, None)["status"] == "UNKNOWN"
    request["limits"]["max_operations"] = 1
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_available_digest_contradiction_precedes_exhausted_interpreter_budget():
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    value["action_inputs"]["actions"][0]["push"] = 2.0
    request["evidence_ref"] = digest(value)
    request["limits"]["max_operations"] = 1
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def test_selected_child_unknown_cannot_be_promoted():
    request, policy, evidence, *_ = fixture(responsive=True)
    child = sim_dynamics.build_sim_dynamics_certificate(
        request["trajectory_request"], None, policy=request["trajectory_policy"])
    value = json.loads(evidence)
    value["trajectory_certificate"] = base64.b64encode(child).decode("ascii")
    request["trajectory_certificate_digest"] = "sha256:" + hashlib.sha256(child).hexdigest()
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "UNKNOWN"


def test_selected_child_fail_precedes_parent_execution_budget_unknown():
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    child = json.loads(base64.b64decode(value["trajectory_certificate"]))
    child_evidence = json.loads(base64.b64decode(
        child["evidence_payloads"][request["trajectory_request"]["evidence_ref"]]))
    child_evidence["artifact"]["transition"]["x"] = 0.0
    request["trajectory_request"]["evidence_ref"] = digest(child_evidence)
    child_bytes = sim_dynamics.build_sim_dynamics_certificate(
        request["trajectory_request"], canonical_bytes(child_evidence),
        policy=request["trajectory_policy"])
    assert json.loads(child_bytes)["result"]["status"] == "FAIL"
    value["trajectory_certificate"] = base64.b64encode(child_bytes).decode("ascii")
    request["trajectory_certificate_digest"] = "sha256:" + hashlib.sha256(child_bytes).hexdigest()
    request["evidence_ref"] = digest(value)
    request["limits"]["max_operations"] = 1
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


@pytest.mark.parametrize("child_state", ["FAIL", "FORGED"])
@pytest.mark.parametrize("omitted", [
    ("action_artifact",), ("action_inputs",),
    ("action_artifact", "action_inputs"),
])
def test_present_refuted_child_precedes_missing_action_evidence(child_state: str,
                                                               omitted: tuple[str, ...]):
    request, policy, evidence, *_ = fixture(responsive=True)
    value = json.loads(evidence)
    child = json.loads(base64.b64decode(value["trajectory_certificate"]))
    child_request = request["trajectory_request"]
    child_evidence = base64.b64decode(child["evidence_payloads"][child_request["evidence_ref"]])
    if child_state == "FAIL":
        child_request["expected_counts"]["states"] += 1
        child_request["expected_counts"]["transitions"] += 1
    child_bytes = sim_dynamics.build_sim_dynamics_certificate(
        child_request, child_evidence, policy=request["trajectory_policy"])
    if child_state == "FORGED":
        forged = json.loads(child_bytes)
        forged["result"]["status"] = "FAIL"
        forged.pop("digest")
        forged["digest"] = digest(forged)
        child_bytes = canonical_bytes(forged)
    value["trajectory_certificate"] = base64.b64encode(child_bytes).decode("ascii")
    request["trajectory_certificate_digest"] = "sha256:" + hashlib.sha256(child_bytes).hexdigest()
    for field in omitted:
        value[field] = None
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def test_child_and_external_selection_substitutions_are_refused():
    request, policy, evidence, *_ = fixture(responsive=True)
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    altered = deepcopy(request)
    altered["max_response_delay"] = 2.0
    with pytest.raises(ValueError):
        sim_response.recheck_sim_response_certificate(
            certificate, expected_request=altered, policy=policy)
    value = json.loads(evidence)
    value["trajectory_certificate"] = base64.b64encode(b"substituted child").decode("ascii")
    selected, raw = reselection(request, canonical_bytes(value))
    assert replay(selected, policy, raw)["status"] == "FAIL"
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        sim_response.recheck_sim_response_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_response.py", "domains/contracts/sim_dynamics.py",
    "domains/sim.py", "domains/common.py", "core/evidence.py",
    "standard/CURRENT_SIM_RESPONSE.md", "standard/CURRENT_SIM_DYNAMICS.md",
])
def test_changed_selected_dependency_invalidates_response_policy(relative: str, monkeypatch):
    request, policy, evidence, *_ = fixture(responsive=True)
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(sim_response.__file__).parents[2] / relative
    def changed(path):
        raw = original(path)
        return raw + b"\nchanged dependency\n" if path == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        sim_response.recheck_sim_response_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_command_and_polish_keep_whole_sim_unknown(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence, *_ = fixture(responsive=True)
    certificate = sim_response.build_sim_response_certificate(request, evidence, policy=policy)
    for name, raw in (("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(raw)
    assert main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", sim_response.SEMANTIC_VERSION,
        "--objective", sim_response.COORDINATE, "--represented-kind", "SIM",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"

    child = json.loads(base64.b64decode(json.loads(evidence)["trajectory_certificate"]))
    child_payload = child["evidence_payloads"][request["trajectory_request"]["evidence_ref"]]
    objects = json.loads(base64.b64decode(child_payload))["objects"]
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {certificate_digest: certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "sim", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle), "requirements": [{"object_id": "sim",
            "tier": tier, "applicability": "REQUIRED", "rationale": "Selected response only",
            "objectives": []} for tier in range(1, 10)]}
    polish_request["requirements"][1]["objectives"] = [{
        "semantic_version": sim_response.SEMANTIC_VERSION,
        "coordinate": sim_response.COORDINATE, "request": request,
        "policy": policy, "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polish_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
