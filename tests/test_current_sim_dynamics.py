"""Current simulation dynamics: selected finite native trajectory replay."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_dynamics


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, corrupt_transition: bool = False, omit: str | None = None,
             final_x: float = 1.0, final_time: float = 1.0,
             limits: dict[str, int] | None = None):
    inputs = {"states": [{"x": 0.0}, {"x": final_x}], "entropy": [1.0],
              "times": [0.0, final_time]}
    artifact = {"transition": {"x": {"op": "add", "args": [
        {"var": "x"}, {"var": "entropy"}]}},
        "initial_state": {"x": 0.0}, "trajectory_digest": digest(inputs["states"]),
        "entropy_digest": digest(inputs["entropy"]), "times_digest": digest(inputs["times"])}
    if corrupt_transition:
        artifact["transition"]["x"]["args"][1] = 2.0
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
    evidence = canonical_bytes({
        "schema_version": sim_dynamics.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "artifact": None if omit == "artifact" else artifact,
        "inputs": None if omit == "inputs" else inputs,
    })
    policy = sim_dynamics.sim_dynamics_policy(trust_roots=["selected-sim-fixture"])
    request = sim_dynamics.sim_dynamics_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        artifact_digest=digest(artifact), inputs_digest=digest(inputs),
        expected_counts={"states": 2, "transitions": 1},
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = sim_dynamics.build_sim_dynamics_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=sim_dynamics.SEMANTIC_VERSION,
        objective=sim_dynamics.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    return certificate, result


def test_selected_trajectory_reexecutes_without_tier_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["evaluation"]["observations"]["transitions"] == 1
    assert result["native_result"]["historical_execution"] == "NOT_ESTABLISHED"
    assert result["native_result"]["sim_tier_2_conformance"] == "NOT_ESTABLISHED"
    assert certificate == sim_dynamics.build_sim_dynamics_certificate(
        request, evidence, policy=policy)


def test_rehashed_false_transition_is_refuted():
    request, policy, evidence = selected(corrupt_transition=True)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    {"final_x": 2.0}, {"final_time": 0.0}, {"final_time": -1.0},
])
def test_rehashed_wrong_state_or_time_is_refuted(mutation: dict):
    request, policy, evidence = selected(**mutation)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


@pytest.mark.parametrize("missing", ["artifact", "inputs"])
def test_missing_selected_operand_stays_unknown(missing: str):
    request, policy, evidence = selected(omit=missing)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_substituted_request_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["subject_id"] = "other-sim"
    with pytest.raises(ValueError):
        sim_dynamics.recheck_sim_dynamics_certificate(
            certificate, expected_request=changed, policy=policy)


def test_wrong_selected_counts_refute_native_replay():
    request, policy, evidence = selected()
    request["expected_counts"] = {"states": 3, "transitions": 2}
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_known_artifact_contradiction_precedes_missing_inputs():
    request, policy, evidence = selected(omit="inputs")
    changed = json.loads(evidence)
    changed["artifact"]["transition"]["x"]["args"][1] = 9.0
    evidence = canonical_bytes(changed)
    request["evidence_ref"] = digest(changed)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


@pytest.mark.parametrize("bound", ["max_operations", "max_items", "max_composition_operations"])
def test_exhausted_selected_budget_stays_unknown(bound: str):
    request, policy, evidence = selected(limits={bound: 1})
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_rehashed_forged_result_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        sim_dynamics.recheck_sim_dynamics_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_dynamics.py", "domains/sim.py", "domains/common.py",
    "domains/contracts/retained_selection.py", "core/namespace.py",
    "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_SIM_DYNAMICS.md", "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = sim_dynamics.build_sim_dynamics_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(sim_dynamics.__file__).parents[2] / relative
    def changed(path):
        raw = original(path)
        return raw + b"\nchanged selected dependency\n" if path == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        sim_dynamics.recheck_sim_dynamics_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_command_and_polish_keep_unfilled_object_unknown(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish
    request, policy, evidence = selected()
    certificate = sim_dynamics.build_sim_dynamics_certificate(request, evidence, policy=policy)
    for name, raw in (("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(raw)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", sim_dynamics.SEMANTIC_VERSION,
        "--objective", sim_dynamics.COORDINATE, "--represented-kind", "SIM",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "sim", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle), "requirements": [{"object_id": "sim",
            "tier": tier, "applicability": "REQUIRED", "rationale": "Selected trace only",
            "objectives": []} for tier in range(1, 10)]}
    polish_request["requirements"][1]["objectives"] = [{
        "semantic_version": sim_dynamics.SEMANTIC_VERSION,
        "coordinate": sim_dynamics.COORDINATE, "request": request,
        "policy": policy, "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polish_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
