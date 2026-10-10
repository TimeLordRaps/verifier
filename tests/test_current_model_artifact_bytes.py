"""Current exact retained model bytes, separate from training or execution.

Verifier Standard (VSTD); MODEL is the model reproducibility object.
Secure Hash Algorithm 256-bit (SHA-256) commitments cover raw bytes.
JavaScript Object Notation (JSON) carries canonical base64 evidence.
Lengths are bytes. No test asserts hash preimage or collision resistance.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import model_artifact_bytes as model_bytes


ARCHITECTURE = b"open-model-architecture\x00v1"
WEIGHTS = bytes(range(32)) + b"\x00weights"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def selected(*, architecture: bytes = ARCHITECTURE, weights: bytes = WEIGHTS,
             subject_architecture: bytes = ARCHITECTURE,
             subject_weights: bytes = WEIGHTS,
             arch_operand_architecture: bytes | None = None,
             include_inputs: bool = True, **limits: int):
    arch_operand_architecture = (subject_architecture if arch_operand_architecture is None
                                 else arch_operand_architecture)
    subject = NamespaceObject.create("model-root", "MODEL", {
        "architecture_bytes_sha256": digest(subject_architecture),
        "architecture_byte_length": len(subject_architecture),
        "weights_bytes_sha256": digest(subject_weights),
        "weights_byte_length": len(subject_weights),
        "format_note": "synthetic opaque bytes",
    }, {
        "arch": ["architecture"], "data": ["dataset"],
        "events": ["event"], "bench": ["benchmark"],
        "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        subject,
        NamespaceObject.create("architecture", "ARCH", {
            "artifact_bytes_sha256": digest(arch_operand_architecture),
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
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    evidence = canonical_bytes({
        "schema_version": model_bytes.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {
            "architecture_b64": base64.b64encode(architecture).decode("ascii"),
            "weights_b64": base64.b64encode(weights).decode("ascii"),
        } if include_inputs else None,
    })
    policy = model_bytes.model_artifact_bytes_policy(
        trust_roots=["externally-selected-retained-model"],
    )
    request = model_bytes.model_artifact_bytes_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(evidence),
        policy=policy,
        limits=limits,
    )
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes):
    certificate = model_bytes.build_model_artifact_bytes_certificate(
        request, evidence, policy=policy,
    )
    result = routes.replay_current_object_certificate(
        certificate,
        semantic_version=model_bytes.SEMANTIC_VERSION,
        objective=model_bytes.COORDINATE,
        represented_kind="MODEL",
        expected_request=request,
        policy=policy,
    )
    return certificate, result


def test_exact_raw_architecture_and_weights_replay_without_training_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["training_truth"] == "NOT_ESTABLISHED"
    assert result["native_result"]["format_validity"] == "NOT_ESTABLISHED"
    assert result["native_result"]["execution_truth"] == "NOT_ESTABLISHED"
    assert certificate == model_bytes.build_model_artifact_bytes_certificate(
        request, evidence, policy=policy,
    )


@pytest.mark.parametrize("kwargs", [
    {"architecture": b"changed-architecture"},
    {"weights": b"changed-weights"},
    {"architecture": b""},
    {"weights": b""},
])
def test_changed_or_empty_retained_artifacts_fail(kwargs):
    request, policy, evidence = selected(**kwargs)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_exact_alternative_artifacts_pass_when_externally_reselected():
    request, policy, evidence = selected(
        architecture=b"another-architecture", weights=b"another-weights",
        subject_architecture=b"another-architecture",
        subject_weights=b"another-weights",
    )
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"


def test_arch_operand_commitment_must_match_model_commitment():
    request, policy, evidence = selected(arch_operand_architecture=b"another-arch")
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_retained_evidence_byte_substitution_is_refused_before_certificate():
    request, policy, evidence = selected()
    changed = bytearray(evidence)
    position = changed.index(b"A")
    changed[position] = ord("B")
    with pytest.raises(model_bytes.ModelArtifactBytesError,
                       match="evidence differs"):
        model_bytes.build_model_artifact_bytes_certificate(
            request, bytes(changed), policy=policy,
        )


def test_model_statics_slot_registers_one_bounded_objective():
    from verifier.domains.inventory import get_slot

    slot = get_slot("MODEL", 3).to_dict()
    assert slot["coordinate"] == "MODEL-3.1"
    assert slot["mechanized"] is True
    assert slot["status"] == "REPLAYABLE"
    assert slot["objective_inventory_closure"] == "NOT_ESTABLISHED"


def test_missing_inputs_and_exhausted_checker_budget_stay_unknown():
    request, policy, evidence = selected(include_inputs=False)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected(max_operations=1)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected(max_artifact_bytes=1)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"


def test_noncanonical_or_malformed_base64_fails_without_bytes_cast():
    for malformed in ("YWJj=", " YWJj", "YWJj\n", "_", "🤖", None, True, 17, []):
        request, policy, evidence = selected()
        value = json.loads(evidence)
        value["inputs"]["weights_b64"] = malformed
        altered = canonical_bytes(value)
        request["evidence_ref"] = digest(altered)
        _, result = replay(request, policy, altered)
        assert result["computational_status"] == "FAIL", malformed


def test_external_selection_and_carried_result_substitution_are_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed_request = deepcopy(request)
    changed_request["subject_id"] = "different"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            certificate, semantic_version=model_bytes.SEMANTIC_VERSION,
            objective=model_bytes.COORDINATE, represented_kind="MODEL",
            expected_request=changed_request, policy=policy,
        )
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["different"]
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            certificate, semantic_version=model_bytes.SEMANTIC_VERSION,
            objective=model_bytes.COORDINATE, represented_kind="MODEL",
            expected_request=request, policy=changed_policy,
        )
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            canonical_bytes(forged), semantic_version=model_bytes.SEMANTIC_VERSION,
            objective=model_bytes.COORDINATE, represented_kind="MODEL",
            expected_request=request, policy=policy,
        )


def test_public_command_replays_exact_bytes(tmp_path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    for name, data in {
        "request": canonical_bytes(request),
        "policy": canonical_bytes(policy),
        "certificate": model_bytes.build_model_artifact_bytes_certificate(
            request, evidence, policy=policy,
        ),
    }.items():
        (tmp_path / (name + ".json")).write_bytes(data)
    exit_code = main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", model_bytes.SEMANTIC_VERSION,
        "--objective", model_bytes.COORDINATE,
        "--represented-kind", "MODEL",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ])
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_certificate_refuses_retained_weight_redaction():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    request, policy, evidence = selected()
    certificate = json.loads(model_bytes.build_model_artifact_bytes_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in certificate if key != "evidence_payloads")
    surface = DisclosureSurface("MODEL", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds,
                                              context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/model_artifact_bytes.py",
    "standard/CURRENT_MODEL_ARTIFACT_BYTES.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = model_bytes.build_model_artifact_bytes_certificate(
        request, evidence, policy=policy,
    )
    original = Path.read_bytes
    target = Path(model_bytes.__file__).parents[2] / relative

    def changed(path):
        data = original(path)
        return data + b"\nchanged source dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="policy differs"):
        model_bytes.recheck_model_artifact_bytes_certificate(
            certificate, expected_request=request, policy=policy,
        )
