"""Refutable current SIM-2.4 per-step resource capture and public replay."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: SIM-2.4 resource records are Ed25519-signed and need the seal extra (cryptography); the platform-python-contracts workflow job installs it")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes, sim_dynamics, sim_resource


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def fixture():
    inputs = {"states": [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}],
              "entropy": [1.0, 1.0], "times": [0.0, 1.0, 2.0]}
    artifact = {"transition": {"x": {"op": "add", "args": [
        {"var": "x"}, {"var": "entropy"}]}}, "initial_state": {"x": 0.0},
        "trajectory_digest": digest(inputs["states"]),
        "entropy_digest": digest(inputs["entropy"]),
        "times_digest": digest(inputs["times"])}
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
    evidence = canonical_bytes({"schema_version": sim_dynamics.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "artifact": artifact, "inputs": inputs})
    child_policy = sim_dynamics.sim_dynamics_policy(trust_roots=["selected-capture-fixture"])
    child_request = sim_dynamics.sim_dynamics_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects), artifact_digest=digest(artifact),
        inputs_digest=digest(inputs), expected_counts={"states": 3, "transitions": 2},
        evidence_ref=digest(json.loads(evidence)), policy=child_policy)
    child = sim_dynamics.build_sim_dynamics_certificate(
        child_request, evidence, policy=child_policy)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    policy = sim_resource.sim_resource_policy(trust_roots=[public])
    captured = sim_resource.capture_sim_resource_evidence(
        child, child_request=child_request, child_policy=child_policy, signing_key=key)
    request = sim_resource.sim_resource_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects), trajectory_request=child_request,
        trajectory_policy=child_policy,
        trajectory_certificate_digest="sha256:" + hashlib.sha256(child).hexdigest(),
        evidence_ref=digest(json.loads(captured)), policy=policy)
    return request, policy, captured, child, key


def replay(request, policy, evidence):
    certificate = sim_resource.build_sim_resource_certificate(
        request, evidence, policy=policy)
    return sim_resource.recheck_sim_resource_certificate(
        certificate, expected_request=request, policy=policy)


def replay_route(request, policy, evidence):
    certificate = sim_resource.build_sim_resource_certificate(
        request, evidence, policy=policy)
    return current_object_routes.replay_current_object_certificate(
        certificate, semantic_version=sim_resource.SEMANTIC_VERSION,
        objective=sim_resource.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)


def resign(value, key):
    signed = {name: item for name, item in value.items() if name != "signature"}
    value["signature"] = base64.b64encode(key.sign(canonical_bytes(signed))).decode()
    return canonical_bytes(value)


def test_real_collector_records_each_selected_step_and_replays():
    request, policy, evidence, child, _ = fixture()
    result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert result["signed_record_status"] == "PASS"
    assert result["historical_device_use"] == "NOT_ESTABLISHED"
    assert result["sim_tier_2_conformance"] == "NOT_ESTABLISHED"
    rows = json.loads(evidence)["capture"]["steps"]
    assert len(rows) == 2
    assert [row["step"] for row in rows] == [0, 1]
    assert all(type(row["thread_cpu_ns"]) is int and row["thread_cpu_ns"] >= 0
               and type(row["traced_peak_bytes"]) is int
               and row["traced_peak_bytes"] >= 0 for row in rows)
    assert json.loads(evidence)["trajectory_certificate"] == base64.b64encode(child).decode()


def test_rehashed_self_reported_metric_without_collector_signature_fails():
    request, policy, evidence, _, _ = fixture()
    value = json.loads(evidence)
    value["capture"]["steps"][0]["thread_cpu_ns"] += 1
    changed = canonical_bytes(value)
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, changed)["status"] == "FAIL"


def test_signed_steps_cannot_be_rebound_to_another_selected_child():
    request, policy, evidence, _, _ = fixture()
    changed = deepcopy(request)
    changed["trajectory_certificate_digest"] = "sha256:" + "0" * 64
    assert replay(changed, policy, evidence)["status"] == "FAIL"


def test_missing_capture_or_child_is_unknown_but_intrinsic_forgery_fails():
    request, policy, evidence, _, key = fixture()
    value = json.loads(evidence)
    value["capture"] = None
    missing = resign(value, key)
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, missing)["status"] == "UNKNOWN"


def test_present_invalid_signature_precedes_missing_child():
    request, policy, evidence, _, _ = fixture()
    value = json.loads(evidence)
    value["trajectory_certificate"] = None
    value["signature"] = base64.b64encode(b"0" * 64).decode()
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def test_admitted_signer_can_fabricate_but_honesty_remains_unestablished():
    request, policy, evidence, _, key = fixture()
    value = json.loads(evidence)
    value["capture"]["steps"][0]["thread_cpu_ns"] += 10**6
    changed = resign(value, key)
    request["evidence_ref"] = digest(value)
    result = replay(request, policy, changed)
    assert result["status"] == "UNKNOWN"
    assert result["signed_record_status"] == "PASS"
    assert result["collector_honesty"] == "NOT_ESTABLISHED"


def test_budget_counter_cannot_replace_actual_measurement():
    request, policy, evidence, _, _ = fixture()
    value = json.loads(evidence)
    value["capture"]["steps"][0].pop("thread_cpu_ns")
    value["capture"]["steps"][0]["operations"] = 10
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


@pytest.mark.parametrize("timeout", [None, 0, -1, 31, float("inf"), True])
def test_collector_refuses_unbounded_or_invalid_timeout(timeout):
    request, _, _, child, key = fixture()
    with pytest.raises(sim_resource.SimResourceError):
        sim_resource.capture_sim_resource_evidence(
            child, child_request=request["trajectory_request"],
            child_policy=request["trajectory_policy"], signing_key=key,
            timeout_seconds=timeout)


def test_signed_record_is_registered_but_cannot_close_sim_resource():
    request, policy, evidence, _, _ = fixture()
    result = replay_route(request, policy, evidence)
    assert result["replay_status"] == "REPRODUCED"
    assert result["computational_status"] == "UNKNOWN"
    assert result["native_result"]["status"] == "UNKNOWN"
    assert result["native_result"]["signed_record_status"] == "PASS"
    assert result["native_result"]["actual_consumption_correspondence"] == "NOT_ESTABLISHED"
    rows = [row for row in current_object_routes.current_object_route_catalog()
            if row["semantic_version"] == sim_resource.SEMANTIC_VERSION
            and row["objective"] == sim_resource.COORDINATE]
    assert len(rows) == 1
    assert rows[0]["represented_kind_rule"] == "SIM"


def test_registered_route_preserves_signed_fail_and_unknown_mapping():
    request, policy, evidence, _, key = fixture()
    missing = json.loads(evidence)
    missing["capture"] = None
    missing_bytes = resign(missing, key)
    request["evidence_ref"] = digest(missing)
    unknown = replay_route(request, policy, missing_bytes)
    assert unknown["computational_status"] == "UNKNOWN"
    assert unknown["native_result"]["signed_record_status"] == "UNKNOWN"

    request, policy, evidence, _, key = fixture()
    contradicted = json.loads(evidence)
    contradicted["capture"]["steps"][0]["output_state_digest"] = "sha256:" + "0" * 64
    contradicted_bytes = resign(contradicted, key)
    request["evidence_ref"] = digest(contradicted)
    failed = replay_route(request, policy, contradicted_bytes)
    assert failed["computational_status"] == "FAIL"
    assert failed["native_result"]["signed_record_status"] == "FAIL"


def test_public_route_refuses_installed_callback_outer_pass_promotion(monkeypatch):
    request, policy, evidence, _, _ = fixture()
    original = current_object_routes._ROUTES[
        (sim_resource.SEMANTIC_VERSION, sim_resource.COORDINATE)]
    native = replay(request, policy, evidence)
    assert native["status"] == "UNKNOWN" and native["signed_record_status"] == "PASS"
    promoted = {**native, "status": "PASS"}
    monkeypatch.setitem(current_object_routes._ROUTES,
        (sim_resource.SEMANTIC_VERSION, sim_resource.COORDINATE),
        current_object_routes._Route(original.module, lambda *args, **kwargs: promoted,
                                     original.fixed_kind, original.scope))
    with pytest.raises(current_object_routes.CurrentObjectRouteRefusal):
        current_object_routes.replay_current_object_certificate(
            b"{}", semantic_version=sim_resource.SEMANTIC_VERSION,
            objective=sim_resource.COORDINATE, represented_kind="SIM",
            expected_request=request, policy=policy)


@pytest.mark.parametrize("changes", [
    {"signed_record_status": "REJECTED"},
    {"signed_record_status": "FAIL"},
    {"signed_record_status": "UNKNOWN", "status": "FAIL"},
    {"object_kind": "OBJECT"},
    {"scope": "other"},
    {"object_profile_conformance": "PASS"},
    {"sim_tier_2_conformance": "PASS"},
    {"historical_device_use": "PASS"},
    {"collector_honesty": "PASS"},
    {"actual_consumption_correspondence": "PASS"},
    {"physical_resource_truth": "PASS"},
    {"authority": "NOT_ESTABLISHED"},
])
def test_public_route_revalidates_sim_resource_result_boundary(monkeypatch, changes):
    request, policy, evidence, _, _ = fixture()
    original = current_object_routes._ROUTES[
        (sim_resource.SEMANTIC_VERSION, sim_resource.COORDINATE)]
    changed = {**replay(request, policy, evidence), **changes}
    monkeypatch.setitem(current_object_routes._ROUTES,
        (sim_resource.SEMANTIC_VERSION, sim_resource.COORDINATE),
        current_object_routes._Route(original.module, lambda *args, **kwargs: changed,
                                     original.fixed_kind, original.scope))
    with pytest.raises(current_object_routes.CurrentObjectRouteRefusal):
        current_object_routes.replay_current_object_certificate(
            b"{}", semantic_version=sim_resource.SEMANTIC_VERSION,
            objective=sim_resource.COORDINATE, represented_kind="SIM",
            expected_request=request, policy=policy)


@pytest.mark.parametrize("mutation", ["missing_step", "wrong_state", "wrong_method", "wrong_source"])
def test_even_authorized_signature_cannot_override_structural_contradiction(mutation):
    request, policy, evidence, _, key = fixture()
    value = json.loads(evidence)
    capture = value["capture"]
    if mutation == "missing_step":
        capture["steps"].pop()
    elif mutation == "wrong_state":
        capture["steps"][0]["output_state_digest"] = "sha256:" + "0" * 64
    elif mutation == "wrong_method":
        capture["method"] = "budget-ticks"
    else:
        capture["worker_source_digest"] = "sha256:" + "0" * 64
    changed = resign(value, key)
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, changed)["status"] == "FAIL"


def test_public_command_and_polish_preserve_unknown_signed_record(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish
    request, policy, evidence, _, _ = fixture()
    certificate = sim_resource.build_sim_resource_certificate(
        request, evidence, policy=policy)
    for name, raw in (("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(raw)
    exit_code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", sim_resource.SEMANTIC_VERSION,
        "--objective", sim_resource.COORDINATE, "--represented-kind", "SIM",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert exit_code == 2
    replayed = json.loads(capsys.readouterr().out)
    assert replayed["replay_status"] == "REPRODUCED"
    assert replayed["computational_status"] == "UNKNOWN"
    assert replayed["native_result"]["status"] == "UNKNOWN"
    certificate_digest = digest(json.loads(certificate))
    child_raw = base64.b64decode(json.loads(evidence)["trajectory_certificate"])
    child_evidence = json.loads(base64.b64decode(
        json.loads(child_raw)["evidence_payloads"][request["trajectory_request"]["evidence_ref"]]))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": child_evidence["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "sim", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle), "requirements": [{"object_id": "sim",
            "tier": tier, "applicability": "REQUIRED", "rationale": "Selected trace only",
            "objectives": []} for tier in range(1, 10)]}
    polish_request["requirements"][1]["objectives"] = [{
        "semantic_version": sim_resource.SEMANTIC_VERSION,
        "coordinate": sim_resource.COORDINATE, "request": request,
        "policy": policy, "certificate_digest": certificate_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polish_request))
    assert report["objectives"][0]["status"] == "UNKNOWN"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


def test_source_excluded_wheel_captures_and_replays(tmp_path):
    root = Path(__file__).resolve().parents[1]
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    built = subprocess.run([sys.executable, "-m", "pip", "wheel", ".",
        "--no-deps", "-w", str(wheels)],
        cwd=root, capture_output=True, text=True, timeout=90, check=False)
    assert built.returncode == 0, built.stdout + built.stderr
    wheel = next(wheels.glob("verifier_standard-*.whl"))
    target = tmp_path / "installed"
    target.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(target)
    request, policy, _, child, _ = fixture()
    code = """
import base64, hashlib, json, pathlib, sys
sys.path.insert(0, sys.argv[1])
import verifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import sim_resource
assert pathlib.Path(verifier.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())
data = json.loads(sys.stdin.buffer.read())
child = base64.b64decode(data['child'], validate=True)
request, policy = data['request'], data['policy']
key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
evidence = sim_resource.capture_sim_resource_evidence(child,
    child_request=request['trajectory_request'],
    child_policy=request['trajectory_policy'], signing_key=key)
request['evidence_ref'] = 'sha256:' + hashlib.sha256(evidence).hexdigest()
cert = sim_resource.build_sim_resource_certificate(request, evidence, policy=policy)
result = sim_resource.recheck_sim_resource_certificate(cert,
    expected_request=request, policy=policy)
print(json.dumps({'status': result['status'], 'signed': result['signed_record_status'],
                  'source': str(verifier.__file__)}))
"""
    payload = canonical_bytes({"child": base64.b64encode(child).decode(),
                               "request": request, "policy": policy})
    installed = subprocess.run([sys.executable, "-I", "-c", code, str(target)],
        cwd=tmp_path, input=payload, capture_output=True, timeout=45, check=False)
    assert installed.returncode == 0, installed.stderr.decode(errors="replace")
    assert json.loads(installed.stdout)["status"] == "UNKNOWN"
    assert json.loads(installed.stdout)["signed"] == "PASS"


def test_fresh_verifier_owned_replay_records_two_distinct_runs():
    request, _, _, child, _ = fixture()
    child_request, child_policy = request["trajectory_request"], request["trajectory_policy"]
    first = sim_resource.assess_fresh_sim_resource(child,
        child_request=child_request, child_policy=child_policy)
    second = sim_resource.assess_fresh_sim_resource(child,
        child_request=child_request, child_policy=child_policy)
    for report in (first, second):
        assert report["status"] == "PASS"
        assert report["scope"] == "this_new_bounded_replay_only"
        assert report["historical_metric_correspondence"] == "NOT_ESTABLISHED"
        assert report["selected_child_digest"] == "sha256:" + hashlib.sha256(child).hexdigest()
        assert len(report["capture"]["steps"]) == 2
    assert first["capture"]["run_id"] != second["capture"]["run_id"]


def test_fresh_replay_refuses_forged_worker_state_binding(monkeypatch):
    request, _, _, child, _ = fixture()
    real_run = subprocess.run

    def forged(*args, **kwargs):
        completed = real_run(*args, **kwargs)
        value = json.loads(completed.stdout)
        value["steps"][0]["output_state_digest"] = "sha256:" + "0" * 64
        return subprocess.CompletedProcess(completed.args, completed.returncode,
                                           canonical_bytes(value), completed.stderr)

    monkeypatch.setattr(sim_resource.subprocess, "run", forged)
    with pytest.raises(sim_resource.SimResourceError):
        sim_resource.assess_fresh_sim_resource(child,
            child_request=request["trajectory_request"],
            child_policy=request["trajectory_policy"])
