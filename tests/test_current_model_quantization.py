"""Selected MODEL-3.3 quantization specification, without execution claims.

MODEL names the model reproducibility object; Verifier Standard (VSTD).
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Byte limits count octets. Integer scale ratios are dimensionless.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import model_quantization as quant


WEIGHTS = b"selected-open-quantized-weight-bytes\x00"
ARCHITECTURE = b"selected-open-architecture\x00"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def specification(**changes):
    value = {
        "schema_version": quant.SPECIFICATION_VERSION,
        "weight_artifact_sha256": digest(WEIGHTS),
        "scheme": "affine-per-tensor-v1",
        "configuration": {
            "storage_bits": 8,
            "signed": True,
            "scale_numerator": 1,
            "scale_denominator": 128,
            "zero_point": 0,
            "rounding": "ties-to-even",
            "saturation": "clamp",
        },
    }
    value.update(changes)
    return value


def selected(*, spec=None, retained=None, include_input=True,
             subject_spec=None, subject_raw=None, **limits):
    spec = specification() if spec is None else spec
    raw = canonical_bytes(spec)
    selected_raw = (subject_raw if subject_raw is not None else
                    raw if subject_spec is None else canonical_bytes(subject_spec))
    subject = NamespaceObject.create("model-root", "MODEL", {
        "architecture_bytes_sha256": digest(ARCHITECTURE),
        "architecture_byte_length": len(ARCHITECTURE),
        "weights_bytes_sha256": digest(WEIGHTS),
        "weights_byte_length": len(WEIGHTS),
        "quantization_spec_sha256": digest(selected_raw),
        "quantization_spec_byte_length": len(selected_raw),
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
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    evidence = canonical_bytes({
        "schema_version": quant.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {
            "quantization_spec_b64": base64.b64encode(
                raw if retained is None else retained
            ).decode("ascii"),
        } if include_input else None,
    })
    policy = quant.model_quantization_policy(trust_roots=["selected-open-model"])
    request = quant.model_quantization_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(evidence),
        policy=policy,
        limits=limits,
    )
    return request, policy, evidence


def replay(request, policy, evidence):
    certificate = quant.build_model_quantization_certificate(
        request, evidence, policy=policy,
    )
    return certificate, quant.recheck_model_quantization_certificate(
        certificate, expected_request=request, policy=policy,
    )


def test_selected_canonical_scheme_and_configuration_replay_exactly():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert certificate == quant.build_model_quantization_certificate(
        request, evidence, policy=policy,
    )
    assert result["status"] == "PASS"
    assert result["weight_bytes_conformance"] == "NOT_ESTABLISHED"
    assert result["quantized_execution"] == "NOT_ESTABLISHED"
    assert result["model_3_1_prerequisite"] == "NOT_ESTABLISHED"


def test_alternative_selected_configuration_replays_without_hardcoded_parameters():
    spec = specification()
    spec["configuration"]["storage_bits"] = 4
    spec["configuration"]["scale_denominator"] = 16
    _, result = replay(*selected(spec=spec))
    assert result["status"] == "PASS"


def test_unsigned_storage_range_is_exact_at_boundary():
    spec = specification()
    spec["configuration"].update(storage_bits=4, signed=False, zero_point=15)
    assert replay(*selected(spec=spec))[1]["status"] == "PASS"
    spec["configuration"]["zero_point"] = 16
    assert replay(*selected(spec=spec))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda s: s["configuration"].update(scale_denominator=0),
    lambda s: s["configuration"].update(scale_numerator=-1),
    lambda s: s["configuration"].update(zero_point=200),
    lambda s: s["configuration"].update(storage_bits=True),
    lambda s: s["configuration"].update(rounding="stochastic"),
    lambda s: s["configuration"].update(extra=1),
    lambda s: s["configuration"].update(
        scale_numerator=2, scale_denominator=256
    ),
])
def test_invalid_supported_scheme_configuration_fails(mutation):
    spec = specification()
    mutation(spec)
    _, result = replay(*selected(spec=spec))
    assert result["status"] == "FAIL"


def test_scheme_without_qualified_interpretation_is_unknown():
    _, result = replay(*selected(spec=specification(scheme="opaque-qpack-v9")))
    assert result["status"] == "UNKNOWN"


def test_unknown_specification_version_is_unknown_not_accepted():
    spec = specification(schema_version="future-quantization-v2")
    assert replay(*selected(spec=spec))[1]["status"] == "UNKNOWN"


def test_noncanonical_json_or_unexpected_field_fails():
    spec = specification()
    indented = json.dumps(spec, indent=2).encode("utf-8")
    assert replay(*selected(spec=spec, retained=indented,
                            subject_raw=indented))[1]["status"] == "FAIL"
    extra = specification(unqualified_extra=True)
    assert replay(*selected(spec=extra))[1]["status"] == "FAIL"


def test_selected_weight_artifact_mismatch_fails():
    spec = specification(weight_artifact_sha256=digest(b"other weights"))
    _, result = replay(*selected(spec=spec))
    assert result["status"] == "FAIL"


def test_retained_specification_substitution_fails():
    spec = specification()
    changed = deepcopy(spec)
    changed["configuration"]["scale_denominator"] = 64
    _, result = replay(*selected(spec=spec, retained=canonical_bytes(changed)))
    assert result["status"] == "FAIL"


def test_missing_input_and_exhausted_selected_bound_are_unknown():
    assert replay(*selected(include_input=False))[1]["status"] == "UNKNOWN"
    assert replay(*selected(max_spec_bytes=1))[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("replacement", ["%", "YQ", 9])
def test_malformed_or_noncanonical_base64_fails(replacement):
    request, policy, evidence = selected()
    value = json.loads(evidence)
    value["inputs"]["quantization_spec_b64"] = replacement
    changed = canonical_bytes(value)
    request["evidence_ref"] = digest(changed)
    _, result = replay(request, policy, changed)
    assert result["status"] == "FAIL"


def test_external_selection_and_carried_result_cannot_be_substituted():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = deepcopy(request)
    forged["subject_id"] = "other-model"
    with pytest.raises(quant.ModelQuantizationError):
        quant.recheck_model_quantization_certificate(
            certificate, expected_request=forged, policy=policy,
        )
    value = json.loads(certificate)
    value["result"]["status"] = "UNKNOWN"
    value["digest"] = digest(canonical_bytes({
        key: payload for key, payload in value.items() if key != "digest"
    }))
    with pytest.raises(quant.ModelQuantizationError):
        quant.recheck_model_quantization_certificate(
            canonical_bytes(value), expected_request=request, policy=policy,
        )


def test_selected_policy_invalidates_when_bound_checker_changes(monkeypatch):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    monkeypatch.setattr(quant, "mechanism_digest", lambda: digest(b"changed source"))
    with pytest.raises(quant.ModelQuantizationError):
        quant.recheck_model_quantization_certificate(
            certificate, expected_request=request, policy=policy,
        )


def test_retained_specification_does_not_include_raw_weight_bytes():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert base64.b64encode(WEIGHTS) not in certificate
    assert WEIGHTS not in certificate


def test_integrated_public_route_and_command(tmp_path, capsys):
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate = quant.build_model_quantization_certificate(
        request, evidence, policy=policy,
    )
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=quant.SEMANTIC_VERSION,
        objective=quant.COORDINATE, represented_kind="MODEL",
        expected_request=request, policy=policy,
    )
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["model_3_1_prerequisite"] == "NOT_ESTABLISHED"
    for stem, raw in (
        ("certificate", certificate),
        ("request", canonical_bytes(request)),
        ("policy", canonical_bytes(policy)),
    ):
        (tmp_path / (stem + ".json")).write_bytes(raw)
    code = main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", quant.SEMANTIC_VERSION,
        "--objective", quant.COORDINATE, "--represented-kind", "MODEL",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_integrated_canonical_guard_refuses_specification_redaction():
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    request, policy, evidence = selected()
    certificate = json.loads(quant.build_model_quantization_certificate(
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
