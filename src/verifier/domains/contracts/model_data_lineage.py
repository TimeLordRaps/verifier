"""Replay a selected MODEL, TRAIN, and two exact retained DATA views.

Verifier Standard (VSTD); MODEL is a model reproducibility object, TRAIN is a
training-run specification, and DATA is dataset integrity and lineage.
JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind bytes. Counts are dimensionless; size limits count bytes. This does not
establish historical training, actual data consumption, or weight derivation.
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
from verifier.domains.contracts import (
    model_data_citation, retained_selection, train_data_bridge,
)


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "MODEL-3.7"
REQUEST_VERSION = "verifier-current-model-data-lineage-request-1"
POLICY_VERSION = "verifier-current-model-data-lineage-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-data-lineage-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-data-lineage-evidence-1"
MECHANISM_ID = "verifier.current-model.retained-mediated-data-lineage.1"
SCOPE = "finite_model_train_two_data_view_retained_lineage"
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 12 * 1024 * 1024,
    "max_model_data_certificate_bytes": 3 * 1024 * 1024,
    "max_bridge_certificate_bytes": 5 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_CHILD_SELECTION_BYTES = 512 * 1024


class ModelDataLineageError(ValueError):
    """Malformed external selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "MODEL",
        "scope": SCOPE,
        "proposition": (
            "The selected MODEL names one exact TRAIN and DATA inventory; its "
            "TRAIN names a distinct exact batches DATA view. The retained "
            "MODEL-3.4 and TRAIN-1.5 certificates replay over identical "
            "collection records and the identical DATA-1.2 child selection "
            "and bytes, binding the TRAIN batches to the MODEL inventory."
        ),
        "prerequisites": [
            "externally selected MODEL-3.4 and TRAIN-1.5 requests, policies, "
            "canonical certificates, exact finite collection and bounds",
        ],
        "exclusions": [
            "actual historical execution or DATA consumption",
            "derivation of MODEL weights or complete training history",
            "DATA origin, rights, consent, disclosure authority, whole tier or polish",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ModelDataLineageDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, model_data_citation, train_data_bridge, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "CURRENT_MODEL_DATA_CITATION.md",
        "CURRENT_TRAIN_DATA_BRIDGE.md", "CURRENT_MODEL_DATA_LINEAGE.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ModelDataLineageError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def model_data_lineage_policy(*, trust_roots: list[str],
                              max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                              ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _child_selection(request: Any, policy: Any, *, model: bool
                     ) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(request) is not dict or type(policy) is not dict:
        raise ModelDataLineageError("selected child request and policy must be plain records")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(request, budget)
        common_module.inspect_structure(policy, budget)
        if len(canonical_bytes(request)) + len(canonical_bytes(policy)) > _MAX_CHILD_SELECTION_BYTES:
            raise ModelDataLineageError("selected child byte bound exhausted")
        if model:
            child_request = model_data_citation._request(request)
            child_policy = model_data_citation._policy(policy)
            expected = "MODEL-3.4"
        else:
            child_request = train_data_bridge._request(request)
            child_policy = train_data_bridge._policy(policy)
            expected = "TRAIN-1.5"
    except (ValueError, TypeError, KeyError, RecursionError,
            OverflowError, Unavailable) as exc:
        if isinstance(exc, ModelDataLineageError):
            raise
        raise ModelDataLineageError("invalid selected child prerequisite") from exc
    if (child_request["coordinate"] != expected
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise ModelDataLineageError("selected child coordinate or policy differs")
    return child_request, child_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "train_subject_id",
        "train_object_digest", "model_data_subject_id", "model_data_object_digest",
        "batch_view_subject_id", "batch_view_object_digest",
        "model_data_certificate_digest", "model_data_request", "model_data_policy",
        "bridge_certificate_digest", "bridge_request", "bridge_policy",
    }, "request", ModelDataLineageError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "MODEL"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise ModelDataLineageError("selected MODEL lineage objective differs")
    for key in ("subject_id", "train_subject_id", "model_data_subject_id",
                "batch_view_subject_id"):
        if type(request[key]) is not str or not request[key].strip() or len(request[key]) > 256:
            raise ModelDataLineageError("bounded selected identifiers required")
    for key in (
        "object_digest", "collection_digest", "evidence_ref", "policy_digest",
        "train_object_digest", "model_data_object_digest", "batch_view_object_digest",
        "model_data_certificate_digest", "bridge_certificate_digest",
    ):
        retained_selection.commitment(request[key], ModelDataLineageError)
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, ModelDataLineageError,
    )
    model_request, model_policy = _child_selection(
        request["model_data_request"], request["model_data_policy"], model=True,
    )
    bridge_request, bridge_policy = _child_selection(
        request["bridge_request"], request["bridge_policy"], model=False,
    )
    if (model_request["subject_id"] != request["subject_id"]
            or model_request["object_digest"] != request["object_digest"]
            or model_request["collection_digest"] != request["collection_digest"]
            or model_request["data_subject_id"] != request["model_data_subject_id"]
            or model_request["data_object_digest"] != request["model_data_object_digest"]
            or bridge_request["subject_id"] != request["train_subject_id"]
            or bridge_request["object_digest"] != request["train_object_digest"]
            or bridge_request["collection_digest"] != request["collection_digest"]
            or bridge_request["batch_view_id"] != request["batch_view_subject_id"]
            or bridge_request["batch_view_digest"] != request["batch_view_object_digest"]):
        raise ModelDataLineageError("selected children, subjects or collection differ")
    if (model_request["data_request"] != bridge_request["data_request"]
            or model_request["data_policy"] != bridge_request["data_policy"]
            or model_request["data_certificate_digest"] != bridge_request["data_certificate_digest"]):
        raise ModelDataLineageError("selected DATA-1.2 child differs between MODEL and TRAIN")
    if (bridge_request["train_request"]["subject_id"] != request["train_subject_id"]
            or bridge_request["train_request"]["object_digest"] != request["train_object_digest"]
            or bridge_request["train_request"]["collection_digest"] != request["collection_digest"]
            or request["model_data_subject_id"] == request["batch_view_subject_id"]):
        raise ModelDataLineageError("selected TRAIN or distinct DATA view differs")
    request["model_data_request"], request["model_data_policy"] = model_request, model_policy
    request["bridge_request"], request["bridge_policy"] = bridge_request, bridge_policy
    return request


def model_data_lineage_request(*, subject_id: str, object_digest: str,
                               collection_digest: str, evidence_ref: str,
                               train_subject_id: str, train_object_digest: str,
                               model_data_subject_id: str, model_data_object_digest: str,
                               batch_view_subject_id: str, batch_view_object_digest: str,
                               model_data_certificate_digest: str,
                               model_data_request: dict[str, Any],
                               model_data_policy: dict[str, Any],
                               bridge_certificate_digest: str,
                               bridge_request: dict[str, Any], bridge_policy: dict[str, Any],
                               policy: dict[str, Any], limits: dict[str, int] | None = None
                               ) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ModelDataLineageError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "MODEL", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
        "train_subject_id": train_subject_id, "train_object_digest": train_object_digest,
        "model_data_subject_id": model_data_subject_id,
        "model_data_object_digest": model_data_object_digest,
        "batch_view_subject_id": batch_view_subject_id,
        "batch_view_object_digest": batch_view_object_digest,
        "model_data_certificate_digest": model_data_certificate_digest,
        "model_data_request": model_data_request, "model_data_policy": model_data_policy,
        "bridge_certificate_digest": bridge_certificate_digest,
        "bridge_request": bridge_request, "bridge_policy": bridge_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "train_subject_id": request["train_subject_id"],
        "train_object_digest": request["train_object_digest"],
        "model_data_subject_id": request["model_data_subject_id"],
        "model_data_object_digest": request["model_data_object_digest"],
        "batch_view_subject_id": request["batch_view_subject_id"],
        "batch_view_object_digest": request["batch_view_object_digest"],
        "children_digest": "sha256:" + canonical_digest({
            "model_data_certificate_digest": request["model_data_certificate_digest"],
            "model_data_request": request["model_data_request"],
            "model_data_policy": request["model_data_policy"],
            "bridge_certificate_digest": request["bridge_certificate_digest"],
            "bridge_request": request["bridge_request"],
            "bridge_policy": request["bridge_policy"],
        }),
    }


def _child_bytes(encoded: Any, *, maximum: int) -> bytes:
    if type(encoded) is not str:
        raise Refuted("retained child encoding must be text")
    if not encoded:
        raise Unavailable("selected retained child certificate absent")
    if len(encoded) > (maximum + 2) // 3 * 4 + 4:
        raise Unavailable("selected retained child encoded bound exhausted")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("retained child certificate encoding malformed") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise Refuted("retained child certificate encoding noncanonical")
    if len(raw) > maximum:
        raise Unavailable("selected retained child certificate byte bound exhausted")
    return raw


def _child_evidence(certificate: bytes, expected_ref: str) -> dict[str, Any]:
    envelope = strict_json_loads(certificate.decode("utf-8"))
    payloads = envelope["evidence_payloads"]
    if type(payloads) is not dict or set(payloads) != {expected_ref}:
        raise Refuted("selected child retained evidence absent")
    store = EvidenceStore()
    store.import_base64(payloads)
    return strict_json_loads(store.resolve(expected_ref).decode("utf-8"))


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "model_data_certificate_b64", "bridge_certificate_b64"},
            "evidence", ModelDataLineageError,
        )
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained lineage evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        model_bytes = _child_bytes(
            value["model_data_certificate_b64"],
            maximum=limits["max_model_data_certificate_bytes"],
        )
        bridge_bytes = _child_bytes(
            value["bridge_certificate_b64"],
            maximum=limits["max_bridge_certificate_bytes"],
        )
        if ("sha256:" + hashlib.sha256(model_bytes).hexdigest()
                != request["model_data_certificate_digest"]
                or "sha256:" + hashlib.sha256(bridge_bytes).hexdigest()
                != request["bridge_certificate_digest"]):
            raise Refuted("retained child bytes differ from external selection")
        try:
            model_result = model_data_citation.recheck_model_data_certificate(
                model_bytes, expected_request=request["model_data_request"],
                policy=request["model_data_policy"],
            )
            bridge_result = train_data_bridge.recheck_train_data_bridge_certificate(
                bridge_bytes, expected_request=request["bridge_request"],
                policy=request["bridge_policy"],
            )
        except (model_data_citation.ModelDataError,
                train_data_bridge.TrainDataBridgeError) as exc:
            raise Refuted("selected child certificate did not reproduce") from exc
        for result, label in ((model_result, "MODEL-3.4"), (bridge_result, "TRAIN-1.5")):
            outcome = result["status"]
            if outcome not in ("PASS", "FAIL", "UNKNOWN"):
                raise Refuted("selected child result is unsupported")
            if outcome != "PASS":
                return MechanismDecision(
                    MechanismOutcome(outcome), f"selected {label} child did not pass",
                )
        model_evidence = _child_evidence(model_bytes, request["model_data_request"]["evidence_ref"])
        bridge_evidence = _child_evidence(bridge_bytes, request["bridge_request"]["evidence_ref"])
        train_bytes = _child_bytes(
            bridge_evidence["train_certificate_b64"],
            maximum=request["bridge_request"]["limits"]["max_train_certificate_bytes"],
        )
        train_evidence = _child_evidence(
            train_bytes, request["bridge_request"]["train_request"]["evidence_ref"],
        )
        common_module.inspect_structure(model_evidence, budget)
        common_module.inspect_structure(train_evidence, budget)
        model_rows, train_rows = model_evidence["objects"], train_evidence["objects"]
        if type(model_rows) is not list or type(train_rows) is not list:
            raise Refuted("retained collection records required")
        if len(model_rows) > limits["max_objects"] or len(train_rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        if canonical_bytes(model_rows) != canonical_bytes(train_rows):
            raise Refuted("retained MODEL and TRAIN collection bytes differ")
        objects: list[NamespaceObject] = []
        for row in model_rows:
            selected = retained_selection.record(
                row, {"object_id", "kind", "payload", "operands"},
                "namespace record", ModelDataLineageError,
            )
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
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
        selected_objects = {}
        for key, kind, identifier, digest in (
            ("model", "MODEL", request["subject_id"], request["object_digest"]),
            ("train", "TRAIN", request["train_subject_id"], request["train_object_digest"]),
            ("inventory", "DATA", request["model_data_subject_id"],
             request["model_data_object_digest"]),
            ("batches", "DATA", request["batch_view_subject_id"],
             request["batch_view_object_digest"]),
        ):
            matches = [item for item in objects if item.object_id == identifier]
            if (len(matches) != 1 or matches[0].kind.value != kind
                    or matches[0].digest != digest):
                raise Refuted("selected MODEL, TRAIN or DATA record differs")
            selected_objects[key] = matches[0]
        if (dict(selected_objects["model"].operands).get("train")
                != (request["train_subject_id"],)
                or dict(selected_objects["model"].operands).get("data")
                != (request["model_data_subject_id"],)
                or dict(selected_objects["train"].operands).get("data")
                != (request["batch_view_subject_id"],)):
            raise Refuted("selected MODEL or TRAIN DATA operand differs")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected MODEL and TRAIN replay over one collection and mediated DATA inventory",
            {"objects_checked": len(objects), "model_3_4_prerequisite": "REPLAYED_LOCAL",
             "train_1_5_prerequisite": "REPLAYED_LOCAL"},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _LineageMechanism:
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
            return MechanismDecision(MechanismOutcome.FAIL, "bound MODEL lineage proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained lineage bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelDataLineageError("request differs from selected lineage policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_LineageMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "MODEL", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "statics_profile_conformance": "NOT_ESTABLISHED",
        "actual_training_execution": "NOT_ESTABLISHED",
        "actual_data_consumption": "NOT_ESTABLISHED",
        "model_weight_derivation": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ModelDataLineageError("lineage certificate byte bound exhausted")
    return encoded


def build_model_data_lineage_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                         *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ModelDataLineageError("immutable bounded lineage evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelDataLineageError("lineage evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_model_data_lineage_certificate(certificate_bytes: bytes, *,
                                           expected_request: dict[str, Any],
                                           policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ModelDataLineageError("bounded immutable lineage certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate", ModelDataLineageError,
        )
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ModelDataLineageError("canonical lineage certificate version differs")
        if value["request"] != selected:
            raise ModelDataLineageError("lineage certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise ModelDataLineageError("retained lineage evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelDataLineageError("lineage certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelDataLineageError):
            raise
        raise ModelDataLineageError("invalid retained MODEL data-lineage certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "SCOPE", "ModelDataLineageDescriptor", "ModelDataLineageError", "registration",
    "mechanism_digest", "model_data_lineage_policy", "model_data_lineage_request",
    "build_model_data_lineage_certificate", "recheck_model_data_lineage_certificate",
]
