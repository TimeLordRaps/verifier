"""Selected MODEL quantization configuration as retained, bounded bytes.

MODEL is the model reproducibility namespace object. Verifier Standard (VSTD);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Lengths count bytes. The rational scale is dimensionless.
This checks a selected specification, not weight encoding or execution.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "MODEL-3.3"
SPECIFICATION_VERSION = "verifier-current-model-quantization-specification-1"
REQUEST_VERSION = "verifier-current-model-quantization-request-1"
POLICY_VERSION = "verifier-current-model-quantization-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-quantization-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-quantization-evidence-1"
MECHANISM_ID = "verifier.current-model.quantization-specification.1"
SCOPE = "finite_retained_model_quantization_specification"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_spec_bytes": 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_SPEC_FIELDS = {
    "schema_version", "weight_artifact_sha256", "scheme", "configuration",
}
_CONFIG_FIELDS = {
    "storage_bits", "signed", "scale_numerator", "scale_denominator",
    "zero_point", "rounding", "saturation",
}


class ModelQuantizationError(ValueError):
    """Malformed selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "MODEL",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact MODEL record occurs once in the "
            "selected finite typed collection, and its retained canonical "
            "quantization specification bytes match its SHA-256 and length "
            "commitments, name its selected weight artifact commitment, and "
            "satisfy the supported exact affine-per-tensor configuration."
        ),
        "prerequisites": [
            "independently selected MODEL record, finite collection, retained "
            "specification bytes, selected weight commitment, installed "
            "policy and finite limits"
        ],
        "exclusions": [
            "MODEL-3.1 raw-weight prerequisite and actual weight-byte conformance",
            "weight tensor parsing, quantizer execution, dequantized values or accuracy",
            "hardware requirements, training, format origin and provenance",
            "ownership, disclosure authority and private-weight confidentiality",
            "hash preimage or collision resistance as an observed property",
            "other MODEL statics objectives, whole tier or object profile",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ModelQuantizationDescriptor:
    """Native route metadata for one selected quantization specification."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "DOMAIN_OBLIGATIONS.md",
        "CURRENT_MODEL_QUANTIZATION.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ModelQuantizationError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def model_quantization_policy(*, trust_roots: list[str],
                              max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                              ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request", ModelQuantizationError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE),
        ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "MODEL"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise ModelQuantizationError("selected quantization objective differs")
    if (type(request["subject_id"]) is not str
            or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise ModelQuantizationError("bounded subject identifier required")
    for key in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(request[key], ModelQuantizationError)
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, ModelQuantizationError,
    )
    return request


def model_quantization_request(*, subject_id: str, object_digest: str,
                               collection_digest: str, evidence_ref: str,
                               policy: dict[str, Any],
                               limits: dict[str, int] | None = None
                               ) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ModelQuantizationError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "MODEL",
        "subject_id": subject_id,
        "object_digest": object_digest,
        "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _raw_spec(value: Any, max_bytes: int) -> bytes:
    if type(value) is not str:
        raise Refuted("quantization specification base64 must be text")
    if len(value) > (max_bytes + 2) // 3 * 4 + 4:
        raise Unavailable("quantization specification encoded bound exhausted")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("quantization specification base64 is malformed") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise Refuted("quantization specification base64 is noncanonical")
    if not raw:
        raise Refuted("quantization specification bytes are empty")
    if len(raw) > max_bytes:
        raise Unavailable("quantization specification byte bound exhausted")
    return raw


def _validate_spec(raw: bytes, weight_digest: str) -> dict[str, Any]:
    value = retained_selection.record(
        strict_json_loads(raw.decode("utf-8")), _SPEC_FIELDS,
        "quantization specification", ModelQuantizationError,
    )
    if canonical_bytes(value) != raw:
        raise Refuted("quantization specification is not canonical JSON")
    if value["schema_version"] != SPECIFICATION_VERSION:
        raise Unavailable("unqualified quantization specification version")
    commitment = retained_selection.commitment(
        value["weight_artifact_sha256"], ModelQuantizationError,
    )
    if commitment != weight_digest:
        raise Refuted("specification selects a different weight artifact")
    if type(value["scheme"]) is not str:
        raise Refuted("quantization scheme must be text")
    if value["scheme"] != "affine-per-tensor-v1":
        raise Unavailable("unqualified quantization scheme")
    config = retained_selection.record(
        value["configuration"], _CONFIG_FIELDS,
        "affine-per-tensor configuration", ModelQuantizationError,
    )
    bits, signed = config["storage_bits"], config["signed"]
    numerator, denominator = config["scale_numerator"], config["scale_denominator"]
    zero = config["zero_point"]
    if type(bits) is not int or not 2 <= bits <= 16 or type(signed) is not bool:
        raise Refuted("supported storage width and signedness required")
    if (type(numerator) is not int or type(denominator) is not int
            or not 1 <= numerator <= 2**31
            or not 1 <= denominator <= 2**31
            or math.gcd(numerator, denominator) != 1):
        raise Refuted("positive reduced finite rational scale required")
    low = -(1 << (bits - 1)) if signed else 0
    high = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
    if type(zero) is not int or not low <= zero <= high:
        raise Refuted("zero point exceeds selected storage range")
    if config["rounding"] != "ties-to-even" or config["saturation"] != "clamp":
        raise Refuted("unsupported affine arithmetic configuration")
    return value


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "inputs"}, "evidence",
            ModelQuantizationError,
        )
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = retained_selection.record(
                row, {"object_id", "kind", "payload", "operands"},
                "namespace record", ModelQuantizationError,
            )
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "MODEL"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained model subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(
                MechanismOutcome(composition.verdict.value), composition.reason,
            )
        payload = matches[0].payload
        if (type(payload) is not dict
                or not {"weights_bytes_sha256", "quantization_spec_sha256",
                        "quantization_spec_byte_length"} <= set(payload)):
            raise Refuted("model quantization commitments absent")
        weight_digest = retained_selection.commitment(
            payload["weights_bytes_sha256"], ModelQuantizationError,
        )
        selected_digest = retained_selection.commitment(
            payload["quantization_spec_sha256"], ModelQuantizationError,
        )
        selected_length = payload["quantization_spec_byte_length"]
        if type(selected_length) is not int or selected_length < 1:
            raise Refuted("selected specification length invalid")
        if selected_length > limits["max_spec_bytes"]:
            raise Unavailable("selected specification byte bound exhausted")
        if value["inputs"] is None:
            raise Unavailable("retained quantization specification absent")
        inputs = retained_selection.record(
            value["inputs"], {"quantization_spec_b64"},
            "quantization input", ModelQuantizationError,
        )
        raw = _raw_spec(inputs["quantization_spec_b64"], limits["max_spec_bytes"])
        if len(raw) != selected_length or "sha256:" + hashlib.sha256(raw).hexdigest() != selected_digest:
            raise Refuted("retained specification differs from selected commitment")
        spec = _validate_spec(raw, weight_digest)
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected quantization scheme and configuration reproduced",
            {"scheme": spec["scheme"], "specification_bytes": len(raw),
             "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ModelQuantizationMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != retained_selection.parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound model quantization proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained quantization evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelQuantizationError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=retained_selection.parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ModelQuantizationMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "MODEL",
        "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "statics_profile_conformance": "NOT_ESTABLISHED",
        "model_3_1_prerequisite": "NOT_ESTABLISHED",
        "weight_bytes_conformance": "NOT_ESTABLISHED",
        "quantized_execution": "NOT_ESTABLISHED",
        "training_truth": "NOT_ESTABLISHED",
        "public_disclosure_authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION,
        "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ModelQuantizationError("certificate byte bound exhausted")
    return encoded


def build_model_quantization_certificate(request: dict[str, Any],
                                         evidence_bytes: bytes | None, *,
                                         policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ModelQuantizationError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelQuantizationError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_model_quantization_certificate(certificate_bytes: bytes, *,
                                            expected_request: dict[str, Any],
                                            policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ModelQuantizationError("bounded immutable certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")), {
                "schema_version", "request", "policy_digest", "mechanism_digest",
                "proposition_digest", "evidence_refs", "evidence_payloads",
                "result", "digest",
            }, "certificate", ModelQuantizationError,
        )
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION):
            raise ModelQuantizationError("canonical certificate version differs")
        if value["request"] != selected:
            raise ModelQuantizationError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ModelQuantizationError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelQuantizationError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelQuantizationError):
            raise
        raise ModelQuantizationError("invalid retained quantization certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "SPECIFICATION_VERSION",
    "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "PROPOSITION_DIGEST",
    "ModelQuantizationDescriptor", "ModelQuantizationError",
    "registration", "model_quantization_policy", "model_quantization_request",
    "build_model_quantization_certificate", "recheck_model_quantization_certificate",
]
