"""Retained TRAIN batch-view to DATA shard-view bridge.

Verifier Standard (VSTD); training run specification (TRAIN); dataset integrity
and lineage (DATA); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). Counts are dimensionless and limits count encoded bytes.
This checks selected retained representations, not historical consumption.
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
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import data_checks, retained_selection, train_checks


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "TRAIN-1.5"
REQUEST_VERSION = "verifier-current-train-data-bridge-request-1"
POLICY_VERSION = "verifier-current-train-data-bridge-policy-1"
CERTIFICATE_VERSION = "verifier-current-train-data-bridge-certificate-1"
EVIDENCE_VERSION = "verifier-current-train-data-bridge-evidence-1"
MECHANISM_ID = "verifier.current-train.retained-data-bridge.1"
SCOPE = "finite_retained_train_batch_to_data_shard_binding"
_CEILINGS = {
    "max_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 8 * 1024 * 1024,
    "max_train_certificate_bytes": 2 * 1024 * 1024,
    "max_data_certificate_bytes": 2 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 10 * 1024 * 1024
_MAX_SELECTION_BYTES = 512 * 1024


class TrainDataBridgeError(ValueError):
    """Malformed external selection or substituted bridge certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "TRAIN",
        "scope": SCOPE,
        "proposition": (
            "Every batch in the exact selected retained TRAIN-4.1 trace is byte-equal "
            "to one record in the selected shards of a separately replayed DATA-1.2 "
            "inventory, with no unmatched selected records or TRAIN batch entries."
        ),
        "prerequisites": [
            "externally selected exact TRAIN-4.1 and DATA-1.2 child requests, "
            "policies, canonical certificates, batch-view DATA record, shard names "
            "and finite limits"
        ],
        "exclusions": [
            "actual historical consumption, execution or observation",
            "unretained records, DATA origin, rights or consent",
            "MODEL weight derivation, whole TRAIN facets tier or polished issuance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class TrainDataBridgeDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, data_checks, train_checks, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_DATA_CHECKS.md",
                 "CURRENT_TRAIN_CHECKS.md", "CURRENT_TRAIN_DATA_BRIDGE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=TrainDataBridgeError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def train_data_bridge_policy(*, trust_roots: list[str],
                             max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                             ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _child_selection(request: Any, policy: Any, *, train: bool
                     ) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(request) is not dict or type(policy) is not dict:
        raise TrainDataBridgeError("selected child request and policy must be plain records")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(request, budget)
        common_module.inspect_structure(policy, budget)
        if len(canonical_bytes(request)) + len(canonical_bytes(policy)) > _MAX_SELECTION_BYTES:
            raise TrainDataBridgeError("selected child byte bound exhausted")
        if train:
            selected_request = train_checks._request(request)
            selected_policy = train_checks._policy(policy)
            expected = "lineage"
        else:
            selected_request = data_checks._request(request)
            selected_policy = data_checks._policy(policy)
            expected = "inventory"
    except (ValueError, TypeError, KeyError, RecursionError,
            OverflowError, Unavailable) as exc:
        if isinstance(exc, TrainDataBridgeError):
            raise
        raise TrainDataBridgeError("invalid selected child prerequisite") from exc
    if (selected_request["check"] != expected
            or selected_request["policy_digest"] != "sha256:" + canonical_digest(selected_policy)):
        raise TrainDataBridgeError("selected child check or policy differs")
    return selected_request, selected_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "batch_view_id",
        "batch_view_digest", "shard_ids", "train_certificate_digest",
        "train_request", "train_policy", "data_certificate_digest",
        "data_request", "data_policy",
    }, "request", TrainDataBridgeError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "TRAIN"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise TrainDataBridgeError("selected TRAIN data bridge differs")
    for key in ("subject_id", "batch_view_id"):
        if type(request[key]) is not str or not request[key].strip() or len(request[key]) > 256:
            raise TrainDataBridgeError("bounded subject and batch-view identifiers required")
    for key in (
        "object_digest", "collection_digest", "evidence_ref", "policy_digest",
        "batch_view_digest", "train_certificate_digest", "data_certificate_digest",
    ):
        retained_selection.commitment(request[key], TrainDataBridgeError)
    shards = request["shard_ids"]
    if (type(shards) is not list or not 1 <= len(shards) <= 16
            or any(type(key) is not str or not key.strip() or len(key) > 256 for key in shards)
            or shards != sorted(set(shards))):
        raise TrainDataBridgeError("bounded sorted unique selected shard identifiers required")
    request["shard_ids"] = list(shards)
    request["limits"] = retained_selection.limits(request["limits"], _CEILINGS, TrainDataBridgeError)
    train_request, train_policy = _child_selection(
        request["train_request"], request["train_policy"], train=True,
    )
    data_request, data_policy = _child_selection(
        request["data_request"], request["data_policy"], train=False,
    )
    if (request["subject_id"] != train_request["subject_id"]
            or request["object_digest"] != train_request["object_digest"]
            or request["collection_digest"] != train_request["collection_digest"]):
        raise TrainDataBridgeError("selected TRAIN child subject or collection differs")
    request["train_request"], request["train_policy"] = train_request, train_policy
    request["data_request"], request["data_policy"] = data_request, data_policy
    return request


def train_data_bridge_request(*, train_request: dict[str, Any], train_policy: dict[str, Any],
                              train_certificate_digest: str, data_request: dict[str, Any],
                              data_policy: dict[str, Any], data_certificate_digest: str,
                              batch_view_id: str, batch_view_digest: str,
                              shard_ids: list[str], evidence_ref: str,
                              policy: dict[str, Any], limits: dict[str, int] | None = None
                              ) -> dict[str, Any]:
    admitted = _policy(policy)
    selected_train, _ = _child_selection(train_request, train_policy, train=True)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise TrainDataBridgeError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "TRAIN", "subject_id": selected_train["subject_id"],
        "object_digest": selected_train["object_digest"],
        "collection_digest": selected_train["collection_digest"],
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
        "batch_view_id": batch_view_id, "batch_view_digest": batch_view_digest,
        "shard_ids": shard_ids,
        "train_certificate_digest": train_certificate_digest,
        "train_request": train_request, "train_policy": train_policy,
        "data_certificate_digest": data_certificate_digest,
        "data_request": data_request, "data_policy": data_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "batch_view_id": request["batch_view_id"],
        "batch_view_digest": request["batch_view_digest"],
        "shard_ids_digest": "sha256:" + canonical_digest(request["shard_ids"]),
        "children_digest": "sha256:" + canonical_digest({
            "train_certificate_digest": request["train_certificate_digest"],
            "train_request": request["train_request"],
            "train_policy": request["train_policy"],
            "data_certificate_digest": request["data_certificate_digest"],
            "data_request": request["data_request"],
            "data_policy": request["data_policy"],
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
    raw = store.resolve(expected_ref)
    return strict_json_loads(raw.decode("utf-8"))


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "train_certificate_b64", "data_certificate_b64"},
            "evidence", TrainDataBridgeError,
        )
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained bridge evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        train_bytes = _child_bytes(
            value["train_certificate_b64"], maximum=limits["max_train_certificate_bytes"],
        )
        data_bytes = _child_bytes(
            value["data_certificate_b64"], maximum=limits["max_data_certificate_bytes"],
        )
        if ("sha256:" + hashlib.sha256(train_bytes).hexdigest()
                != request["train_certificate_digest"]
                or "sha256:" + hashlib.sha256(data_bytes).hexdigest()
                != request["data_certificate_digest"]):
            raise Refuted("retained child bytes differ from external selection")
        try:
            train_result = train_checks.recheck_train_checks_certificate(
                train_bytes, expected_request=request["train_request"],
                policy=request["train_policy"],
            )
            data_result = data_checks.recheck_data_checks_certificate(
                data_bytes, expected_request=request["data_request"],
                policy=request["data_policy"],
            )
        except (train_checks.TrainChecksError, data_checks.DataChecksError) as exc:
            raise Refuted("selected child certificate did not reproduce") from exc
        for result, label in ((train_result, "TRAIN-4.1"), (data_result, "DATA-1.2")):
            outcome = result["status"]
            if outcome not in ("PASS", "FAIL", "UNKNOWN"):
                raise Refuted("selected child result is unsupported")
            if outcome != "PASS":
                return MechanismDecision(
                    MechanismOutcome(outcome), f"selected {label} child did not pass",
                )
        train_evidence = _child_evidence(train_bytes, request["train_request"]["evidence_ref"])
        data_evidence = _child_evidence(data_bytes, request["data_request"]["evidence_ref"])
        common_module.inspect_structure(train_evidence, budget)
        common_module.inspect_structure(data_evidence, budget)
        train_objects = train_evidence["objects"]
        views = [row for row in train_objects if row["object_id"] == request["batch_view_id"]]
        if len(views) != 1 or views[0]["kind"] != "DATA":
            raise Refuted("selected TRAIN batch-view DATA record differs")
        view = namespace_module.NamespaceObject.create(**views[0])
        if view.digest != request["batch_view_digest"]:
            raise Refuted("selected TRAIN batch-view digest differs")
        trains = [row for row in train_objects if row["object_id"] == request["subject_id"]]
        if len(trains) != 1 or trains[0]["kind"] != "TRAIN":
            raise Refuted("selected TRAIN subject absent")
        if trains[0]["operands"].get("data") != [request["batch_view_id"]]:
            raise Refuted("selected TRAIN data operand differs from batch view")
        batch_view = retained_selection.record(
            view.payload, {"batches"}, "TRAIN batch view", TrainDataBridgeError,
        )["batches"]
        batch_view = common_module.obj(batch_view)
        shards = common_module.obj(data_evidence["inputs"]["shards"])
        selected_rows: list[Any] = []
        for shard_id in request["shard_ids"]:
            if shard_id not in shards:
                raise Refuted("selected retained DATA shard absent")
            rows = common_module.seq(shards[shard_id], budget, nonempty=False)
            selected_rows.extend(rows)
        if not selected_rows:
            raise Unavailable("no selected retained batch records")
        if len(selected_rows) > limits["max_items"]:
            raise Unavailable("selected batch record bound exhausted")
        derived: dict[str, Any] = {}
        for row in selected_rows:
            budget.tick()
            key = common_module.digest(row)
            if key in derived:
                raise Refuted("duplicate selected retained batch record")
            derived[key] = row
        common_module.same(derived, batch_view, "TRAIN batch view differs from DATA shard records")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected TRAIN trace and DATA inventory replayed with exact retained batch relation",
            {"selected_shards": len(request["shard_ids"]),
             "selected_batches": len(selected_rows), "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _BridgeMechanism:
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
            return MechanismDecision(MechanismOutcome.FAIL, "bound bridge proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained bridge bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TrainDataBridgeError("request differs from selected bridge policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_BridgeMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "TRAIN", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
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
        raise TrainDataBridgeError("bridge certificate byte bound exhausted")
    return encoded


def build_train_data_bridge_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise TrainDataBridgeError("immutable bounded bridge evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TrainDataBridgeError("bridge evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_train_data_bridge_certificate(certificate_bytes: bytes, *,
                                          expected_request: dict[str, Any],
                                          policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise TrainDataBridgeError("bounded immutable bridge certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate", TrainDataBridgeError,
        )
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise TrainDataBridgeError("canonical bridge certificate version differs")
        if value["request"] != selected:
            raise TrainDataBridgeError("bridge certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise TrainDataBridgeError("retained bridge evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TrainDataBridgeError("bridge certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, TrainDataBridgeError):
            raise
        raise TrainDataBridgeError("invalid retained TRAIN/DATA bridge certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "SCOPE", "TrainDataBridgeDescriptor", "TrainDataBridgeError", "registration",
    "train_data_bridge_policy", "train_data_bridge_request",
    "build_train_data_bridge_certificate", "recheck_train_data_bridge_certificate",
]
