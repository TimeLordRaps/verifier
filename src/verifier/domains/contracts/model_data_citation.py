"""Bind one MODEL data operand to a replayed retained DATA inventory.

Verifier Standard (VSTD); MODEL is model reproducibility; DATA is dataset
integrity and lineage; JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Limits and certificate lengths count bytes.
This is an artifact citation, not evidence that a training run used the data.
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
from verifier.domains import data as data_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import data_checks, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "MODEL-3.4"
REQUEST_VERSION = "verifier-current-model-data-request-1"
POLICY_VERSION = "verifier-current-model-data-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-data-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-data-evidence-1"
MECHANISM_ID = "verifier.current-model.retained-data-citation.1"
SCOPE = "finite_model_data_operand_and_replayed_inventory"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_child_certificate_bytes": 2 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_CHILD_SELECTION_BYTES = 256 * 1024


class ModelDataError(ValueError):
    """Malformed external selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "MODEL",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact MODEL cites one exact typed DATA "
            "operand in a finite collection; the same DATA record's retained "
            "shard inventory is independently replayed under an exact selected "
            "DATA-1.2 certificate."
        ),
        "prerequisites": [
            "selected MODEL and DATA records, retained DATA-1.2 certificate, "
            "external child request and policy, canonical evidence and finite limits"
        ],
        "exclusions": [
            "actual use of these records during training or complete training history",
            "record origin, rights, consent, sampling quality or complete corpus",
            "real-world identity, authority or permission to disclose retained records",
            "MODEL provenance citation, artifact immutability or whole statics tier",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ModelDataDescriptor:
    """Native route metadata for one replayed DATA inventory citation."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, data_module, data_checks, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "CURRENT_DATA_CHECKS.md",
        "CURRENT_MODEL_DATA_CITATION.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ModelDataError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def model_data_policy(*, trust_roots: list[str],
                      max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                      ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _child_selection(value: Any, data_policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(value) is not dict or type(data_policy) is not dict:
        raise ModelDataError("external DATA selection must be plain records")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(value, budget)
        common_module.inspect_structure(data_policy, budget)
        if len(canonical_bytes(value)) + len(canonical_bytes(data_policy)) > _MAX_CHILD_SELECTION_BYTES:
            raise ModelDataError("external DATA selection byte bound exhausted")
        child_policy = data_checks._policy(data_policy)
        child_request = data_checks._request(value)
    except (ValueError, TypeError, KeyError, RecursionError,
            OverflowError, Unavailable) as exc:
        if isinstance(exc, ModelDataError):
            raise
        raise ModelDataError("invalid selected DATA-1.2 prerequisite") from exc
    if (child_request["check"] != "inventory"
            or child_request["coordinate"] != "DATA-1.2"
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise ModelDataError("selected DATA-1.2 prerequisite differs")
    return child_request, child_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "data_subject_id",
        "data_object_digest", "data_certificate_digest", "data_request", "data_policy",
    }, "request", ModelDataError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE),
        ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "MODEL"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise ModelDataError("selected model data objective differs")
    for key in ("subject_id", "data_subject_id"):
        if (type(request[key]) is not str or not request[key].strip()
                or len(request[key]) > 256):
            raise ModelDataError("bounded model and DATA identifiers required")
    for key in (
        "object_digest", "collection_digest", "evidence_ref", "policy_digest",
        "data_object_digest", "data_certificate_digest",
    ):
        retained_selection.commitment(request[key], ModelDataError)
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, ModelDataError,
    )
    child_request, child_policy = _child_selection(
        request["data_request"], request["data_policy"],
    )
    if (child_request["subject_id"] != request["data_subject_id"]
            or child_request["object_digest"] != request["data_object_digest"]):
        raise ModelDataError("selected DATA child subject differs")
    request["data_request"], request["data_policy"] = child_request, child_policy
    return request


def model_data_request(*, subject_id: str, object_digest: str,
                       collection_digest: str, evidence_ref: str,
                       policy: dict[str, Any], data_subject_id: str,
                       data_object_digest: str, data_certificate_digest: str,
                       data_request: dict[str, Any], data_policy: dict[str, Any],
                       limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ModelDataError("unsupported limit override")
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
        "data_subject_id": data_subject_id,
        "data_object_digest": data_object_digest,
        "data_certificate_digest": data_certificate_digest,
        "data_request": data_request,
        "data_policy": data_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "data_subject_id": request["data_subject_id"],
        "data_object_digest": request["data_object_digest"],
        "data_certificate_digest": request["data_certificate_digest"],
        "data_selection_digest": "sha256:" + canonical_digest({
            "request": request["data_request"], "policy": request["data_policy"],
        }),
    }


def _child_certificate(value: Any, *, max_bytes: int) -> bytes:
    if type(value) is not str:
        raise Refuted("retained DATA certificate encoding must be text")
    if len(value) > (max_bytes + 2) // 3 * 4 + 4:
        raise Unavailable("retained DATA certificate encoded bound exhausted")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("retained DATA certificate encoding malformed") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise Refuted("retained DATA certificate encoding noncanonical")
    if len(raw) > max_bytes:
        raise Unavailable("retained DATA certificate byte bound exhausted")
    if not raw:
        raise Unavailable("retained DATA certificate absent")
    return raw


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "inputs"}, "evidence", ModelDataError,
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
                "namespace record", ModelDataError,
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
        data_refs = dict(matches[0].operands).get("data", ())
        if data_refs != (request["data_subject_id"],):
            raise Refuted("MODEL data operand differs from selected DATA")
        data_matches = [obj for obj in objects
                        if obj.object_id == request["data_subject_id"]]
        if (len(data_matches) != 1 or data_matches[0].kind.value != "DATA"
                or data_matches[0].digest != request["data_object_digest"]):
            raise Refuted("selected DATA record differs")
        if value["inputs"] is None:
            raise Unavailable("retained DATA certificate absent")
        inputs = retained_selection.record(
            value["inputs"], {"data_certificate_b64"},
            "model data inputs", ModelDataError,
        )
        child_bytes = _child_certificate(
            inputs["data_certificate_b64"],
            max_bytes=limits["max_child_certificate_bytes"],
        )
        if "sha256:" + hashlib.sha256(child_bytes).hexdigest() != request["data_certificate_digest"]:
            raise Refuted("retained DATA certificate differs from selected bytes")
        try:
            child = data_checks.recheck_data_checks_certificate(
                child_bytes, expected_request=request["data_request"],
                policy=request["data_policy"],
            )
        except data_checks.DataChecksError as exc:
            raise Refuted("selected DATA-1.2 certificate did not reproduce") from exc
        outcome = child["status"]
        if outcome not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("selected DATA-1.2 result is unsupported")
        if outcome != "PASS":
            return MechanismDecision(
                MechanismOutcome(outcome),
                "selected DATA-1.2 retained inventory did not pass",
            )
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected MODEL DATA operand and retained inventory reproduced",
            {"data_subject_id": request["data_subject_id"],
             "data_object_digest": request["data_object_digest"],
             "data_certificate_digest": request["data_certificate_digest"],
             "data_1_2_prerequisite": "REPLAYED_LOCAL"},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ModelDataMechanism:
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
                                     "bound MODEL data proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained MODEL data evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelDataError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ModelDataMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "MODEL",
        "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "statics_profile_conformance": "NOT_ESTABLISHED",
        "data_inventory_prerequisite": (
            "REPLAYED_LOCAL" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"
        ),
        "actual_training_use": "NOT_ESTABLISHED",
        "data_origin_rights": "NOT_ESTABLISHED",
        "dataset_completeness": "NOT_ESTABLISHED",
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
        raise ModelDataError("certificate byte bound exhausted")
    return encoded


def build_model_data_certificate(request: dict[str, Any],
                                 evidence_bytes: bytes | None, *,
                                 policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ModelDataError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelDataError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_model_data_certificate(certificate_bytes: bytes, *,
                                   expected_request: dict[str, Any],
                                   policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ModelDataError("bounded immutable certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")), {
                "schema_version", "request", "policy_digest", "mechanism_digest",
                "proposition_digest", "evidence_refs", "evidence_payloads",
                "result", "digest",
            }, "certificate", ModelDataError,
        )
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION):
            raise ModelDataError("canonical certificate version differs")
        if value["request"] != selected:
            raise ModelDataError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise ModelDataError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelDataError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelDataError):
            raise
        raise ModelDataError("invalid retained MODEL data certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "ModelDataDescriptor", "ModelDataError",
    "registration", "mechanism_digest", "model_data_policy",
    "model_data_request", "build_model_data_certificate",
    "recheck_model_data_certificate",
]
