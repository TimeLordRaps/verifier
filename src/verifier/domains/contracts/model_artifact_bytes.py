"""Versioned current MODEL retained architecture and weight byte certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Lengths and limits count bytes. Base64 is a
transport encoding, not encryption or proof of private-weight protection.
This mechanism checks selected raw byte commitments only; it does not parse
model formats, attest training, or establish live execution.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
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
COORDINATE = "MODEL-3.1"
REQUEST_VERSION = "verifier-current-model-artifact-bytes-request-1"
POLICY_VERSION = "verifier-current-model-artifact-bytes-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-artifact-bytes-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-artifact-bytes-evidence-1"
MECHANISM_ID = "verifier.current-model.retained-artifact-bytes.1"
SCOPE = "finite_retained_model_artifact_bytes"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_artifact_bytes": 2 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_SUBJECT_FIELDS = {
    "architecture_bytes_sha256", "architecture_byte_length",
    "weights_bytes_sha256", "weights_byte_length",
}


class ModelArtifactBytesError(ValueError):
    """Malformed external selection, policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "MODEL",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact MODEL namespace record occurs once "
            "in the selected finite typed collection, its one ARCH operand "
            "agrees on the architecture commitment, and the retained nonempty "
            "raw architecture and weight artifacts match its exact SHA-256 "
            "commitments and byte lengths."
        ),
        "prerequisites": [
            "independently selected MODEL record, finite collection, raw "
            "architecture and weight bytes, installed policy and finite limits"
        ],
        "exclusions": [
            "architecture or weight format validity and model semantics",
            "training, final checkpoint, execution or hardware authenticity",
            "artifact author, origin, ownership and public disclosure authority",
            "hash preimage or collision resistance as an observed property",
            "private-weight confidentiality, other MODEL statics objectives or whole tier",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ModelArtifactBytesDescriptor:
    """Native route metadata for exact retained model artifact bytes."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_MODEL_ARTIFACT_BYTES.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ModelArtifactBytesError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def model_artifact_bytes_policy(*, trust_roots: list[str],
                                max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
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
    }, "request", ModelArtifactBytesError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE),
        ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "MODEL"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise ModelArtifactBytesError("selected model byte objective differs")
    if (type(request["subject_id"]) is not str
            or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise ModelArtifactBytesError("bounded subject identifier required")
    for key in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(request[key], ModelArtifactBytesError)
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, ModelArtifactBytesError,
    )
    return request


def model_artifact_bytes_request(*, subject_id: str, object_digest: str,
                                 collection_digest: str, evidence_ref: str,
                                 policy: dict[str, Any],
                                 limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ModelArtifactBytesError("unsupported limit override")
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


def _raw_artifact(value: Any, *, name: str, max_bytes: int) -> bytes:
    if type(value) is not str:
        raise Refuted(name + " base64 encoding must be text")
    if len(value) > (max_bytes + 2) // 3 * 4 + 4:
        raise Unavailable(name + " encoded byte bound exhausted")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted(name + " base64 encoding is malformed") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise Refuted(name + " base64 encoding is noncanonical")
    if not raw:
        raise Refuted(name + " retained artifact is empty")
    if len(raw) > max_bytes:
        raise Unavailable(name + " byte bound exhausted")
    return raw


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "inputs"}, "evidence",
            ModelArtifactBytesError,
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
                "namespace record", ModelArtifactBytesError,
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
        if type(payload) is not dict or not _SUBJECT_FIELDS <= set(payload):
            raise Refuted("model byte commitments absent")
        arch_refs = dict(matches[0].operands).get("arch", ())
        if len(arch_refs) != 1:
            raise Refuted("one exact ARCH operand is required")
        arch_record = next((obj for obj in objects if obj.object_id == arch_refs[0]), None)
        if arch_record is None or arch_record.kind.value != "ARCH":
            raise Refuted("selected ARCH operand differs")
        arch_payload = arch_record.payload
        if (type(arch_payload) is not dict
                or arch_payload.get("artifact_bytes_sha256")
                != payload["architecture_bytes_sha256"]):
            raise Refuted("ARCH operand raw-byte commitment differs from MODEL")
        if value["inputs"] is None:
            raise Unavailable("retained architecture or weight bytes absent")
        inputs = retained_selection.record(
            value["inputs"], {"architecture_b64", "weights_b64"},
            "model artifact inputs", ModelArtifactBytesError,
        )
        for name in ("architecture", "weights"):
            committed_hash = retained_selection.commitment(
                payload[name + "_bytes_sha256"], ModelArtifactBytesError,
            )
            committed_length = payload[name + "_byte_length"]
            if type(committed_length) is not int or committed_length < 1:
                raise Refuted(name + " byte length is invalid")
            if committed_length > limits["max_artifact_bytes"]:
                raise Unavailable(name + " selected byte bound exhausted")
            raw = _raw_artifact(
                inputs[name + "_b64"], name=name,
                max_bytes=limits["max_artifact_bytes"],
            )
            if (len(raw) != committed_length
                    or "sha256:" + hashlib.sha256(raw).hexdigest() != committed_hash):
                raise Refuted(name + " retained bytes differ from selected commitment")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected retained model architecture and weight bytes reproduced",
            {"architecture_bytes": payload["architecture_byte_length"],
             "weights_bytes": payload["weights_byte_length"],
             "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ModelArtifactBytesMechanism:
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
                                     "bound model byte proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained model evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelArtifactBytesError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=retained_selection.parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ModelArtifactBytesMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "MODEL",
        "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "statics_profile_conformance": "NOT_ESTABLISHED",
        "format_validity": "NOT_ESTABLISHED",
        "training_truth": "NOT_ESTABLISHED",
        "execution_truth": "NOT_ESTABLISHED",
        "artifact_provenance": "NOT_ESTABLISHED",
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
        raise ModelArtifactBytesError("certificate byte bound exhausted")
    return encoded


def build_model_artifact_bytes_certificate(request: dict[str, Any],
                                           evidence_bytes: bytes | None,
                                           *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ModelArtifactBytesError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelArtifactBytesError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_model_artifact_bytes_certificate(certificate_bytes: bytes, *,
                                              expected_request: dict[str, Any],
                                              policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ModelArtifactBytesError("bounded immutable certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")), {
                "schema_version", "request", "policy_digest", "mechanism_digest",
                "proposition_digest", "evidence_refs", "evidence_payloads",
                "result", "digest",
            }, "certificate", ModelArtifactBytesError,
        )
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION):
            raise ModelArtifactBytesError("canonical certificate version differs")
        if value["request"] != selected:
            raise ModelArtifactBytesError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ModelArtifactBytesError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelArtifactBytesError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelArtifactBytesError):
            raise
        raise ModelArtifactBytesError("invalid retained model byte certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "ModelArtifactBytesDescriptor",
    "ModelArtifactBytesError", "registration", "model_artifact_bytes_policy",
    "model_artifact_bytes_request", "build_model_artifact_bytes_certificate",
    "recheck_model_artifact_bytes_certificate",
]
