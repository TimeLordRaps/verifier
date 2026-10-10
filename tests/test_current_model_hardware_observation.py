"""Bound one selected MODEL resource bracket to actual local execution.

MODEL is the model reproducibility object. Verifier Standard (VSTD);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
MiB means 1,048,576 bytes. Memory caps count committed job bytes; wall caps
count seconds. This is not a minimum or cross-runtime hardware claim.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
import platform
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import model_hardware_observation as observation


# Keep import admission below the selected lower cap; the larger workload
# must exhaust within the admitted worker rather than during Python imports.
WIDTH = 512
ARCHITECTURE = canonical_bytes({
    "input_size": WIDTH,
    "layers": [{"outputs": WIDTH, "activation": "relu"},
               {"outputs": 1, "activation": "linear"}],
    "arithmetic": "python-binary64",
})
WEIGHTS = canonical_bytes([
    {"weight": [[0.125] * WIDTH for _ in range(WIDTH)],
     "bias": [0.0] * WIDTH},
    {"weight": [[1.0 / WIDTH] * WIDTH], "bias": [0.0]},
])


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def selected(*, lower_mib: int = 18, upper_mib: int = 40,
             declared_weights: bytes = WEIGHTS,
             retained_weights: bytes = WEIGHTS,
             expected_output: list[float] | None = None,
             inputs_present: bool = True,
             hardware_machine: str | None = None):
    subject = NamespaceObject.create("model-root", "MODEL", {
        "architecture_bytes_sha256": digest(ARCHITECTURE),
        "architecture_byte_length": len(ARCHITECTURE),
        "weights_bytes_sha256": digest(declared_weights),
        "weights_byte_length": len(declared_weights),
    }, {
        "arch": ["architecture"], "data": ["dataset"],
        "events": ["event"], "bench": ["benchmark"],
        "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        subject,
        NamespaceObject.create("architecture", "ARCH", {
            "artifact_bytes_sha256": digest(ARCHITECTURE),
        }),
        NamespaceObject.create("dataset", "DATA", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {
            "data": ["dataset"], "verifier": ["checker"],
        }),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("training", "TRAIN", {}, {
            "arch": ["architecture"], "data": ["dataset"],
            "bench": ["benchmark"], "events": ["event"],
        }),
        NamespaceObject.create("event", "EVENT", {}, {
            "time": ["time"], "space": ["space"],
            "meaning": ["meaning"],
        }),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {
            "process_backend": observation.BACKEND,
            "machine": platform.machine() if hardware_machine is None else hardware_machine,
        }),
    ]
    evidence = canonical_bytes({
        "schema_version": observation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {
            "architecture_b64": base64.b64encode(ARCHITECTURE).decode("ascii"),
            "weights_b64": base64.b64encode(retained_weights).decode("ascii"),
            "input": [1.0] * WIDTH,
            "expected_output": [64.0] if expected_output is None else expected_output,
        } if inputs_present else None,
    })
    policy = observation.model_hardware_policy(
        trust_roots=["selected-open-model-and-local-job"],
    )
    request = observation.model_hardware_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(evidence), policy=policy,
        lower_memory_bytes=lower_mib * 1024 * 1024,
        upper_memory_bytes=upper_mib * 1024 * 1024,
        wall_seconds=5,
        trials=2,
        max_native_operations=1000000,
    )
    return request, policy, evidence


def replay(request, policy, evidence):
    certificate = observation.build_model_hardware_certificate(
        request, evidence, policy=policy,
    )
    return certificate, observation.recheck_model_hardware_certificate(
        certificate, expected_request=request, policy=policy,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object mechanism only")
def test_real_bounded_execution_observes_one_selected_memory_bracket():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["model_3_1_prerequisite"] == "REPLAYED_LOCAL"
    assert result["minimum_required_memory"] == "NOT_ESTABLISHED"
    assert result["cross_runtime_hardware"] == "NOT_ESTABLISHED"
    assert certificate == observation.build_model_hardware_certificate(
        request, evidence, policy=policy,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object mechanism only")
def test_real_lower_cap_that_succeeds_refutes_selected_bracket():
    result = replay(*selected(lower_mib=40, upper_mib=48))[1]
    assert result["status"] == "FAIL"
    assert "lower cap did not exhaust" in result["evaluation"]["details"]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object mechanism only")
def test_real_output_disagreement_refutes_selected_run():
    assert replay(*selected(expected_output=[0.0]))[1]["status"] == "FAIL"


@pytest.mark.parametrize("observed_stdout, expected_status", [
    (b'{"status":"PASS","output":[0.512],"operations":1}', "PASS"),
    (b'{"status":"PASS","output":[0.5120000000000003],"operations":1}', "FAIL"),
], ids=["selected-output", "adverse-three-ulp-output"])
def test_original_nondyadic_fixture_strict_output_comparison(
        monkeypatch: pytest.MonkeyPatch, observed_stdout: bytes,
        expected_status: str) -> None:
    """Retain the original workload and reject its pinned adverse output.

    The child output, work count and job metadata are simulated. This test
    establishes neither native arithmetic nor a real resource bracket.
    """
    original_weights = canonical_bytes([
        {"weight": [[0.001] * WIDTH for _ in range(WIDTH)],
         "bias": [0.0] * WIDTH},
        {"weight": [[1.0 / WIDTH] * WIDTH], "bias": [0.0]},
    ])
    assert WIDTH == 512
    assert len(original_weights) == 1582131
    assert digest(original_weights) == (
        "sha256:6b046df4d3b00b043e2529e38765b2f01479a6e1cc45e22640697d7135614480"
    )
    assert digest(ARCHITECTURE) == (
        "sha256:bed6d8580ab402256cfde89679d4437420b2c389759e107b8ebcc73f23069b87"
    )
    request, policy, evidence = selected(
        declared_weights=original_weights, retained_weights=original_weights,
        expected_output=[0.512],
    )
    calls = []

    def observed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        packet = json.loads(args[1])
        assert canonical_bytes(packet["architecture"]) == ARCHITECTURE
        assert canonical_bytes(packet["weights"]) == original_weights
        assert digest(canonical_bytes(packet["input"])) == (
            "sha256:b692722cdbeb23bb20bb5e19efaafdab073edbb080c86fdccb426c322744896d"
        )
        cap = args[2]
        calls.append(cap)
        return {
            "applied_limits": {"job_committed_memory_bytes": cap,
                               "job_limit_flags": 0x2200},
            "limits_verified_before_resume": True, "owned_job_empty": True,
            "timed_out": False, "output_exhausted": False,
            "exit_code": 0, "stderr": b"",
            "stdout": (b'{"status":"RESOURCE_EXHAUSTED"}'
                       if cap == request["lower_memory_bytes"]
                       else observed_stdout),
        }

    monkeypatch.setattr(observation, "_supported_platform", lambda: True)
    monkeypatch.setattr(observation, "_run_windows", observed)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == expected_status
    assert result["minimum_required_memory"] == "NOT_ESTABLISHED"
    assert result["cross_runtime_hardware"] == "NOT_ESTABLISHED"
    if expected_status == "FAIL":
        assert result["evaluation"]["details"] == (
            "observed model output differs from selected output"
        )
    # Both build and recheck must reach the selected upper observation.
    repetitions = request["trials"] * 2 if expected_status == "PASS" else 2
    assert calls == [request["lower_memory_bytes"],
                     request["upper_memory_bytes"]] * repetitions


def test_missing_evidence_remains_unknown_without_dispatch(monkeypatch):
    request, policy, _ = selected()
    monkeypatch.setattr(observation, "_run_windows", lambda *a, **k: pytest.fail("dispatched"))
    certificate = observation.build_model_hardware_certificate(
        request, None, policy=policy,
    )
    assert observation.recheck_model_hardware_certificate(
        certificate, expected_request=request, policy=policy,
    )["status"] == "UNKNOWN"


def test_substituted_raw_weights_fail_before_dispatch(monkeypatch):
    request, policy, evidence = selected(retained_weights=WEIGHTS + b"changed")
    monkeypatch.setattr(observation, "_run_windows", lambda *a, **k: pytest.fail("dispatched"))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_unavailable_substrate_remains_unknown_without_dispatch(monkeypatch):
    request, policy, evidence = selected()
    monkeypatch.setattr(observation, "_supported_platform", lambda: False)
    monkeypatch.setattr(observation, "_run_windows", lambda *a, **k: pytest.fail("dispatched"))
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_ambiguous_child_failure_remains_unknown(monkeypatch):
    request, policy, evidence = selected()
    def failed(*args, **kwargs):
        cap = args[2]
        return {
            "applied_limits": {"job_committed_memory_bytes": cap, "job_limit_flags": 0x2200},
            "limits_verified_before_resume": True,
            "owned_job_empty": True,
            "timed_out": False, "output_exhausted": False,
            "exit_code": 1, "stdout": b"", "stderr": b"ambiguous",
        }
    monkeypatch.setattr(observation, "_run_windows", failed)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("change", [
    {"limits_verified_before_resume": False},
    {"owned_job_empty": False},
    {"output_exhausted": True},
    {"applied_limits": {"job_committed_memory_bytes": 1, "job_limit_flags": 0x2200}},
])
def test_unestablished_enforcement_never_passes(monkeypatch, change):
    request, policy, evidence = selected()
    calls = []
    def unverified(*args, **kwargs):
        calls.append(args[2])
        value = {
            "applied_limits": {
                "job_committed_memory_bytes": args[2],
                "job_limit_flags": 0x2200,
            },
            "limits_verified_before_resume": True,
            "owned_job_empty": True,
            "timed_out": False, "output_exhausted": False,
            "exit_code": 0,
            "stdout": b'{"status":"RESOURCE_EXHAUSTED"}',
            "stderr": b"",
        }
        value.update(change)
        return value
    monkeypatch.setattr(observation, "_run_windows", unverified)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    # Build and independent recheck each stop after the first invalid job.
    assert calls == [request["lower_memory_bytes"]] * 2


def test_selected_hardware_declaration_mismatch_fails_before_dispatch(monkeypatch):
    request, policy, evidence = selected(hardware_machine="different-machine")
    monkeypatch.setattr(observation, "_run_windows", lambda *a, **k: pytest.fail("dispatched"))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("change", [
    {"lower_memory_bytes": 0},
    {"lower_memory_bytes": 40 * 1024 * 1024},
    {"upper_memory_bytes": 65 * 1024 * 1024},
    {"trials": 4},
    {"wall_seconds": 0},
    {"max_native_operations": 2_000_000},
])
def test_unbounded_or_reversed_external_selection_is_refused(change):
    request, policy, evidence = selected()
    changed = deepcopy(request)
    changed.update(change)
    with pytest.raises(observation.ModelHardwareError):
        observation.build_model_hardware_certificate(
            changed, evidence, policy=policy,
        )


def test_changed_checker_source_invalidates_selected_policy(monkeypatch):
    request, policy, evidence = selected()
    certificate = observation.build_model_hardware_certificate(
        request, evidence, policy=policy,
    )
    monkeypatch.setattr(observation, "mechanism_digest", lambda: digest(b"changed checker"))
    with pytest.raises(observation.ModelHardwareError):
        observation.recheck_model_hardware_certificate(
            certificate, expected_request=request, policy=policy,
        )


def test_carried_result_substitution_is_rejected():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["result"]["minimum_required_memory"] = "ESTABLISHED"
    forged["digest"] = digest(canonical_bytes({
        key: value for key, value in forged.items() if key != "digest"
    }))
    with pytest.raises(observation.ModelHardwareError):
        observation.recheck_model_hardware_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object mechanism only")
def test_integrated_public_route_and_command(tmp_path, capsys):
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate = observation.build_model_hardware_certificate(
        request, evidence, policy=policy,
    )
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=observation.SEMANTIC_VERSION,
        objective=observation.COORDINATE, represented_kind="MODEL",
        expected_request=request, policy=policy,
    )
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["minimum_required_memory"] == "NOT_ESTABLISHED"
    for stem, raw in (
        ("certificate", certificate),
        ("request", canonical_bytes(request)),
        ("policy", canonical_bytes(policy)),
    ):
        (tmp_path / (stem + ".json")).write_bytes(raw)
    code = main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", observation.SEMANTIC_VERSION,
        "--objective", observation.COORDINATE, "--represented-kind", "MODEL",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_integrated_canonical_guard_refuses_raw_weight_redaction():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    request, policy, evidence = selected()
    certificate = json.loads(observation.build_model_hardware_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in certificate if key != "evidence_payloads")
    surface = DisclosureSurface("MODEL", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(
            certificate, surface, bounds, context,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object mechanism only")
@pytest.mark.parametrize("ambiguous_first", [True, False])
def test_changed_native_observation_is_rejected_without_status_promotion(
        monkeypatch: pytest.MonkeyPatch, ambiguous_first: bool) -> None:
    request, policy, evidence = selected()
    native_run = observation._run_windows
    ambiguous = ambiguous_first

    def observed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        if not ambiguous:
            return native_run(*args, **kwargs)
        cap = args[2]
        return {
            "applied_limits": {"job_committed_memory_bytes": cap,
                               "job_limit_flags": 0x2200},
            "limits_verified_before_resume": True, "owned_job_empty": True,
            "timed_out": False, "output_exhausted": False,
            "exit_code": 1, "stdout": b"", "stderr": b"import admission failed",
        }

    monkeypatch.setattr(observation, "_run_windows", observed)
    certificate = observation.build_model_hardware_certificate(
        request, evidence, policy=policy,
    )
    assert json.loads(certificate)["result"]["status"] == (
        "UNKNOWN" if ambiguous_first else "PASS"
    )
    ambiguous = not ambiguous_first
    with pytest.raises(observation.ModelHardwareError, match="does not reproduce exactly"):
        observation.recheck_model_hardware_certificate(
            certificate, expected_request=request, policy=policy,
        )
