"""Bind an exact MODEL training operand to a replayed MODEL data citation.

Verifier Standard (VSTD); MODEL is model reproducibility; TRAIN is a training
run specification; DATA is dataset integrity and lineage; JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless and limits count encoded bytes. This verifies an artifact
citation, not actual training execution or derivation of the model weights.
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
from verifier.domains.contracts import model_data_citation, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "MODEL-3.5"
REQUEST_VERSION = "verifier-current-model-train-request-1"
POLICY_VERSION = "verifier-current-model-train-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-train-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-train-evidence-1"
MECHANISM_ID = "verifier.current-model.retained-train-citation.1"
SCOPE = "finite_model_train_operand_and_replayed_data_citation"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 8 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_child_certificate_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 10 * 1024 * 1024
_MAX_CHILD_SELECTION_BYTES = 512 * 1024


class ModelTrainError(ValueError):
    """Malformed external selection, policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "MODEL",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact MODEL cites one exact typed TRAIN "
            "operand whose DATA operand equals the MODEL's exact DATA operand; "
            "that same MODEL-to-DATA citation is independently replayed under "
            "an exact selected MODEL-3.4 certificate."
        ),
        "prerequisites": [
            "selected MODEL, TRAIN and DATA records in one finite composition, "
            "retained MODEL-3.4 certificate, external child request and policy, "
            "canonical evidence and finite limits"
        ],
        "exclusions": [
            "actual training execution, checkpoint validity or complete history",
            "proof that retained training used the cited DATA records",
            "derivation of MODEL weights or artifact authenticity",
            "DATA origin, rights, consent, disclosure authority or whole statics tier",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ModelTrainDescriptor:
    """Native route metadata for the exact TRAIN citation."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, model_data_citation, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "CURRENT_MODEL_DATA_CITATION.md",
        "CURRENT_MODEL_TRAIN_CITATION.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ModelTrainError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def model_train_policy(*, trust_roots: list[str],
                       max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                       ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _child_selection(value: Any, model_data_policy: Any
                     ) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(value) is not dict or type(model_data_policy) is not dict:
        raise ModelTrainError("external MODEL-3.4 selection must be plain records")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(value, budget)
        common_module.inspect_structure(model_data_policy, budget)
        if (len(canonical_bytes(value)) + len(canonical_bytes(model_data_policy))
                > _MAX_CHILD_SELECTION_BYTES):
            raise ModelTrainError("external MODEL-3.4 selection byte bound exhausted")
        child_policy = model_data_citation._policy(model_data_policy)
        child_request = model_data_citation._request(value)
    except (ValueError, TypeError, KeyError, RecursionError,
            OverflowError, Unavailable) as exc:
        if isinstance(exc, ModelTrainError):
            raise
        raise ModelTrainError("invalid selected MODEL-3.4 prerequisite") from exc
    if (child_request["coordinate"] != "MODEL-3.4"
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise ModelTrainError("selected MODEL-3.4 prerequisite differs")
    return child_request, child_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "train_subject_id",
        "train_object_digest", "data_subject_id", "data_object_digest",
        "model_data_certificate_digest", "model_data_request", "model_data_policy",
    }, "request", ModelTrainError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE),
        ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "MODEL"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise ModelTrainError("selected MODEL training objective differs")
    for key in ("subject_id", "train_subject_id", "data_subject_id"):
        if (type(request[key]) is not str or not request[key].strip()
                or len(request[key]) > 256):
            raise ModelTrainError("bounded MODEL, TRAIN and DATA identifiers required")
    for key in (
        "object_digest", "collection_digest", "evidence_ref", "policy_digest",
        "train_object_digest", "data_object_digest", "model_data_certificate_digest",
    ):
        retained_selection.commitment(request[key], ModelTrainError)
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, ModelTrainError,
    )
    child_request, child_policy = _child_selection(
        request["model_data_request"], request["model_data_policy"],
    )
    if (child_request["subject_id"] != request["subject_id"]
            or child_request["object_digest"] != request["object_digest"]
            or child_request["collection_digest"] != request["collection_digest"]
            or child_request["data_subject_id"] != request["data_subject_id"]
            or child_request["data_object_digest"] != request["data_object_digest"]):
        raise ModelTrainError("selected MODEL-3.4 child object or collection differs")
    request["model_data_request"] = child_request
    request["model_data_policy"] = child_policy
    return request


def model_train_request(*, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str,
                        policy: dict[str, Any], train_subject_id: str,
                        train_object_digest: str, data_subject_id: str,
                        data_object_digest: str,
                        model_data_certificate_digest: str,
                        model_data_request: dict[str, Any],
                        model_data_policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ModelTrainError("unsupported limit override")
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
        "train_subject_id": train_subject_id,
        "train_object_digest": train_object_digest,
        "data_subject_id": data_subject_id,
        "data_object_digest": data_object_digest,
        "model_data_certificate_digest": model_data_certificate_digest,
        "model_data_request": model_data_request,
        "model_data_policy": model_data_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "train_subject_id": request["train_subject_id"],
        "train_object_digest": request["train_object_digest"],
        "data_subject_id": request["data_subject_id"],
        "data_object_digest": request["data_object_digest"],
        "model_data_certificate_digest": request["model_data_certificate_digest"],
        "model_data_selection_digest": "sha256:" + canonical_digest({
            "request": request["model_data_request"],
            "policy": request["model_data_policy"],
        }),
    }


def _child_certificate(value: Any, *, max_bytes: int) -> bytes:
    if type(value) is not str:
        raise Refuted("retained MODEL-3.4 certificate encoding must be text")
    if len(value) > (max_bytes + 2) // 3 * 4 + 4:
        raise Unavailable("retained MODEL-3.4 encoded bound exhausted")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("retained MODEL-3.4 certificate encoding malformed") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise Refuted("retained MODEL-3.4 certificate encoding noncanonical")
    if len(raw) > max_bytes:
        raise Unavailable("retained MODEL-3.4 certificate byte bound exhausted")
    if not raw:
        raise Unavailable("retained MODEL-3.4 certificate absent")
    return raw


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "inputs"}, "evidence", ModelTrainError,
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
                "namespace record", ModelTrainError,
            )
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        model_matches = [item for item in objects
                         if item.object_id == request["subject_id"]]
        if (len(model_matches) != 1 or model_matches[0].kind.value != "MODEL"
                or model_matches[0].digest != request["object_digest"]):
            raise Refuted("retained MODEL subject differs from external selection")
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
        model = model_matches[0]
        operands = dict(model.operands)
        if operands.get("train") != (request["train_subject_id"],):
            raise Refuted("MODEL train operand differs from selected TRAIN")
        if operands.get("data") != (request["data_subject_id"],):
            raise Refuted("MODEL data operand differs from selected DATA")
        train_matches = [item for item in objects
                         if item.object_id == request["train_subject_id"]]
        if (len(train_matches) != 1 or train_matches[0].kind.value != "TRAIN"
                or train_matches[0].digest != request["train_object_digest"]):
            raise Refuted("selected TRAIN record differs")
        if dict(train_matches[0].operands).get("data") != (request["data_subject_id"],):
            raise Refuted("TRAIN data operand differs from selected DATA")
        data_matches = [item for item in objects
                        if item.object_id == request["data_subject_id"]]
        if (len(data_matches) != 1 or data_matches[0].kind.value != "DATA"
                or data_matches[0].digest != request["data_object_digest"]):
            raise Refuted("selected DATA record differs")
        if value["inputs"] is None:
            raise Unavailable("retained MODEL-3.4 certificate absent")
        inputs = retained_selection.record(
            value["inputs"], {"model_data_certificate_b64"},
            "model TRAIN inputs", ModelTrainError,
        )
        child_bytes = _child_certificate(
            inputs["model_data_certificate_b64"],
            max_bytes=limits["max_child_certificate_bytes"],
        )
        if ("sha256:" + hashlib.sha256(child_bytes).hexdigest()
                != request["model_data_certificate_digest"]):
            raise Refuted("retained MODEL-3.4 certificate differs from selected bytes")
        try:
            child = model_data_citation.recheck_model_data_certificate(
                child_bytes, expected_request=request["model_data_request"],
                policy=request["model_data_policy"],
            )
        except model_data_citation.ModelDataError as exc:
            raise Refuted("selected MODEL-3.4 certificate did not reproduce") from exc
        outcome = child["status"]
        if outcome not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("selected MODEL-3.4 result is unsupported")
        if outcome != "PASS":
            return MechanismDecision(
                MechanismOutcome(outcome),
                "selected MODEL-3.4 retained data citation did not pass",
            )
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected MODEL TRAIN operand and retained MODEL-3.4 citation reproduced",
            {"train_subject_id": request["train_subject_id"],
             "train_object_digest": request["train_object_digest"],
             "data_subject_id": request["data_subject_id"],
             "data_object_digest": request["data_object_digest"],
             "model_data_certificate_digest": request["model_data_certificate_digest"],
             "model_3_4_prerequisite": "REPLAYED_LOCAL"},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ModelTrainMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound MODEL training proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained MODEL training evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelTrainError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ModelTrainMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "MODEL",
        "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "statics_profile_conformance": "NOT_ESTABLISHED",
        "model_data_prerequisite": (
            "REPLAYED_LOCAL" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"
        ),
        "train_checkpoint_inventory": "NOT_ESTABLISHED",
        "actual_training_execution": "NOT_ESTABLISHED",
        "model_weight_derivation": "NOT_ESTABLISHED",
        "data_origin_rights": "NOT_ESTABLISHED",
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
        raise ModelTrainError("certificate byte bound exhausted")
    return encoded


def build_model_train_certificate(request: dict[str, Any],
                                  evidence_bytes: bytes | None, *,
                                  policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ModelTrainError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelTrainError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_model_train_certificate(certificate_bytes: bytes, *,
                                    expected_request: dict[str, Any],
                                    policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ModelTrainError("bounded immutable certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")), {
                "schema_version", "request", "policy_digest", "mechanism_digest",
                "proposition_digest", "evidence_refs", "evidence_payloads",
                "result", "digest",
            }, "certificate", ModelTrainError,
        )
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION):
            raise ModelTrainError("canonical certificate version differs")
        if value["request"] != selected:
            raise ModelTrainError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise ModelTrainError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelTrainError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelTrainError):
            raise
        raise ModelTrainError("invalid retained MODEL training certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "ModelTrainDescriptor", "ModelTrainError",
    "registration", "mechanism_digest", "model_train_policy",
    "model_train_request", "build_model_train_certificate",
    "recheck_model_train_certificate",
]
