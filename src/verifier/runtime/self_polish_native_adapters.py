"""Explicit non-generic adapters for installed native replay specimens."""
from __future__ import annotations

import base64
import binascii
from copy import deepcopy
import hashlib
from typing import Any, Callable

from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import hyper_closure
from verifier.domains.contracts import object_grounding
from verifier.runtime import core_obligation_union


class NativeReplayAdapterError(ValueError):
    """A stored specimen cannot satisfy its declared adapter contract."""


SIM_INPUT_SCHEMA = "verifier-self-polish-native-object-grounding-input-1"


def _malformed_evidence_rebind(
        request: dict[str, Any], _evidence: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    selected = deepcopy(request)
    malformed = b"{}"
    malformed_digest = core_obligation_union.bytes_digest(malformed)
    if type(selected) is not dict:
        raise NativeReplayAdapterError(
            "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
        )
    if "evidence_ref" in selected:
        selected["evidence_ref"] = malformed_digest
    elif "evidence_digest" in selected:
        selected["evidence_digest"] = malformed_digest
    else:
        raise NativeReplayAdapterError(
            "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
        )
    return selected, malformed


def _decode_sim_object_grounding_input(
        replay_input: bytes,
        ) -> tuple[list[NamespaceObject], bytes, dict[str, Any]]:
    try:
        if type(replay_input) is not bytes:
            raise NativeReplayAdapterError("NATIVE_SIM_REPLAY_INPUT_INVALID")
        value = strict_json_loads(replay_input.decode("utf-8"))
        if (
            type(value) is not dict
            or set(value) != {
                "schema_version", "collection",
                "isolation_evidence_base64",
            }
            or value["schema_version"] != SIM_INPUT_SCHEMA
            or core_obligation_union.canonical_bytes(value) != replay_input
        ):
            raise NativeReplayAdapterError("NATIVE_SIM_REPLAY_INPUT_INVALID")
        collection = value["collection"]
        if (
            type(collection) is not dict
            or set(collection) != {"schema_version", "objects"}
            or collection["schema_version"]
                != object_grounding.COLLECTION_VERSION
            or type(collection["objects"]) is not list
        ):
            raise NativeReplayAdapterError(
                "NATIVE_SIM_REPLAY_COLLECTION_INVALID"
            )
        objects = []
        for row in collection["objects"]:
            if (
                type(row) is not dict
                or set(row) != {"object_id", "kind", "payload", "operands"}
            ):
                raise NativeReplayAdapterError(
                    "NATIVE_SIM_REPLAY_COLLECTION_INVALID"
                )
            item = NamespaceObject.create(
                row["object_id"], row["kind"], row["payload"],
                row["operands"],
            )
            if item.to_dict() != row:
                raise NativeReplayAdapterError(
                    "NATIVE_SIM_REPLAY_COLLECTION_INVALID"
                )
            objects.append(item)
        isolation = base64.b64decode(
            value["isolation_evidence_base64"], validate=True
        )
        return objects, isolation, value
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_SIM_REPLAY_INPUT_INVALID"
        ) from exc


def _sim_isolation_malformed_rebind(
        request: dict[str, Any], replay_input: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    _objects, _isolation, value = _decode_sim_object_grounding_input(
        replay_input
    )
    malformed = b"{}"
    selected = deepcopy(request)
    if type(selected) is not dict or "isolation_evidence_digest" not in selected:
        raise NativeReplayAdapterError(
            "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
        )
    selected["isolation_evidence_digest"] = (
        "sha256:" + hashlib.sha256(malformed).hexdigest()
    )
    malformed_input = deepcopy(value)
    malformed_input["isolation_evidence_base64"] = base64.b64encode(
        malformed
    ).decode("ascii")
    return selected, core_obligation_union.canonical_bytes(malformed_input)


def _governance_invalid_signature(
        request: dict[str, Any], evidence: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    try:
        value = strict_json_loads(evidence.decode("utf-8"))
        if (
            type(value) is not dict
            or type(value.get("decisions")) is not list
            or not value["decisions"]
            or type(value["decisions"][0]) is not dict
            or type(value["decisions"][0].get("signature")) is not str
        ):
            raise NativeReplayAdapterError(
                "NATIVE_GOVERNANCE_NEGATIVE_INPUT_INVALID"
            )
        value["decisions"][0]["signature"] = "00" * 64
        malformed = core_obligation_union.canonical_bytes(value)
        selected = deepcopy(request)
        if type(selected) is not dict or "evidence_ref" not in selected:
            raise NativeReplayAdapterError(
                "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
            )
        selected["evidence_ref"] = core_obligation_union.bytes_digest(
            malformed
        )
        return selected, malformed
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_GOVERNANCE_NEGATIVE_INPUT_INVALID"
        ) from exc


def _canonical_evidence_object(evidence: bytes) -> dict[str, Any]:
    try:
        if type(evidence) is not bytes:
            raise NativeReplayAdapterError("NATIVE_CASE_EVIDENCE_INVALID")
        value = strict_json_loads(evidence.decode("utf-8"))
        if (
            type(value) is not dict
            or core_obligation_union.canonical_bytes(value) != evidence
        ):
            raise NativeReplayAdapterError("NATIVE_CASE_EVIDENCE_INVALID")
        return value
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_CASE_EVIDENCE_INVALID"
        ) from exc


def _subject_security_valid_transplant(
        request: dict[str, Any], evidence: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    value = _canonical_evidence_object(evidence)
    try:
        if (
            type(value.get("subject")) is not dict
            or type(value["subject"].get("object_id")) is not str
        ):
            raise NativeReplayAdapterError("NATIVE_SUBJECT_EVIDENCE_INVALID")
        value["subject"]["object_id"] = "transplanted-subject"
        malformed = core_obligation_union.canonical_bytes(value)
        selected = deepcopy(request)
        if type(selected) is not dict or "evidence_ref" not in selected:
            raise NativeReplayAdapterError(
                "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
            )
        selected["evidence_ref"] = core_obligation_union.bytes_digest(
            malformed
        )
        return selected, malformed
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_SUBJECT_EVIDENCE_INVALID"
        ) from exc


def _receipt_chain_entry_substitution(
        request: dict[str, Any], evidence: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    value = _canonical_evidence_object(evidence)
    try:
        if (
            type(value.get("entries")) is not list
            or not value["entries"]
            or type(value["entries"][0]) is not dict
            or type(value["entries"][0].get("receipt_base64")) is not str
        ):
            raise NativeReplayAdapterError("NATIVE_RECEIPT_CHAIN_INPUT_INVALID")
        value["entries"][0]["receipt_base64"] = base64.b64encode(
            b"substituted-first"
        ).decode("ascii")
        malformed = core_obligation_union.canonical_bytes(value)
        selected = deepcopy(request)
        if type(selected) is not dict or "evidence_ref" not in selected:
            raise NativeReplayAdapterError(
                "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
            )
        selected["evidence_ref"] = core_obligation_union.bytes_digest(
            malformed
        )
        return selected, malformed
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_RECEIPT_CHAIN_INPUT_INVALID"
        ) from exc


def _receipt_attestation_signature_bit_flip(
        request: dict[str, Any], evidence: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    value = _canonical_evidence_object(evidence)
    try:
        if (
            type(value.get("attestation")) is not dict
            or type(value["attestation"].get("signature")) is not str
        ):
            raise NativeReplayAdapterError(
                "NATIVE_RECEIPT_ATTESTATION_INPUT_INVALID"
            )
        signature = bytearray.fromhex(value["attestation"]["signature"])
        if not signature:
            raise NativeReplayAdapterError(
                "NATIVE_RECEIPT_ATTESTATION_INPUT_INVALID"
            )
        signature[0] ^= 1
        value["attestation"]["signature"] = bytes(signature).hex()
        malformed = core_obligation_union.canonical_bytes(value)
        selected = deepcopy(request)
        if type(selected) is not dict or "evidence_ref" not in selected:
            raise NativeReplayAdapterError(
                "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
            )
        selected["evidence_ref"] = core_obligation_union.bytes_digest(
            malformed
        )
        return selected, malformed
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_RECEIPT_ATTESTATION_INPUT_INVALID"
        ) from exc


def _graph_edge_content_substitution(
        request: dict[str, Any], evidence: bytes,
        ) -> tuple[dict[str, Any], bytes]:
    value = _canonical_evidence_object(evidence)
    try:
        if (
            type(value.get("edge_contents")) is not list
            or not value["edge_contents"]
            or type(value["edge_contents"][0]) is not dict
            or type(value["edge_contents"][0].get("target_digest")) is not str
        ):
            raise NativeReplayAdapterError("NATIVE_GRAPH_LINEAGE_INPUT_INVALID")
        value["edge_contents"][0]["target_digest"] = "sha256:" + "0" * 64
        malformed = core_obligation_union.canonical_bytes(value)
        selected = deepcopy(request)
        if (
            type(selected) is not dict
            or "evidence_ref" not in selected
            or "edge_contents_digest" not in selected
        ):
            raise NativeReplayAdapterError(
                "NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE"
            )
        selected["evidence_ref"] = core_obligation_union.value_digest(value)
        selected["edge_contents_digest"] = (
            core_obligation_union.value_digest(value["edge_contents"])
        )
        return selected, malformed
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_GRAPH_LINEAGE_INPUT_INVALID"
        ) from exc


def _decode_hyper_object_collection(
        replay_input: bytes,
        ) -> tuple[list[NamespaceObject], dict[str, Any]]:
    try:
        if type(replay_input) is not bytes:
            raise NativeReplayAdapterError(
                "NATIVE_HYPER_REPLAY_INPUT_INVALID"
            )
        value = strict_json_loads(replay_input.decode("utf-8"))
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "objects"}
            or value["schema_version"] != hyper_closure.COLLECTION_VERSION
            or type(value["objects"]) is not list
            or core_obligation_union.canonical_bytes(value) != replay_input
        ):
            raise NativeReplayAdapterError(
                "NATIVE_HYPER_REPLAY_INPUT_INVALID"
            )
        objects = []
        for row in value["objects"]:
            if (
                type(row) is not dict
                or set(row) != {
                    "object_id", "kind", "payload", "operands",
                }
            ):
                raise NativeReplayAdapterError(
                    "NATIVE_HYPER_REPLAY_INPUT_INVALID"
                )
            item = NamespaceObject.create(
                row["object_id"], row["kind"], row["payload"],
                row["operands"],
            )
            if item.to_dict() != row:
                raise NativeReplayAdapterError(
                    "NATIVE_HYPER_REPLAY_INPUT_INVALID"
                )
            objects.append(item)
        return objects, value
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_HYPER_REPLAY_INPUT_INVALID"
        ) from exc


def _encode_hyper_object_collection(
        objects: list[NamespaceObject],
        ) -> bytes:
    return core_obligation_union.canonical_bytes({
        "schema_version": hyper_closure.COLLECTION_VERSION,
        "objects": [
            item.to_dict()
            for item in sorted(objects, key=lambda item: item.object_id)
        ],
    })


def _hyper_unrelated_object_collection(
        request: dict[str, Any], replay_input: bytes,
        policy: dict[str, Any] | None,
        ) -> tuple[dict[str, Any], bytes]:
    if policy is None:
        raise NativeReplayAdapterError("NATIVE_HYPER_POLICY_UNAVAILABLE")
    try:
        objects, _value = _decode_hyper_object_collection(replay_input)
        unrelated_id = "native-replay-unrelated"
        if any(item.object_id == unrelated_id for item in objects):
            raise NativeReplayAdapterError(
                "NATIVE_HYPER_NEGATIVE_INPUT_INVALID"
            )
        selected_objects = [
            *objects,
            NamespaceObject.create(unrelated_id, "TOKEN", {}),
        ]
        if type(request) is not dict:
            raise NativeReplayAdapterError(
                "NATIVE_HYPER_NEGATIVE_INPUT_INVALID"
            )
        selected = hyper_closure.hyper_closure_request(
            selected_objects,
            hyper_id=request["subject_id"],
            policy=policy,
            limits=request["limits"],
        )
        return selected, _encode_hyper_object_collection(selected_objects)
    except NativeReplayAdapterError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        raise NativeReplayAdapterError(
            "NATIVE_HYPER_NEGATIVE_INPUT_INVALID"
        ) from exc


def negative_case(
        adapter_id: str, request: dict[str, Any], evidence: bytes, *,
        policy: dict[str, Any] | None = None,
        ) -> tuple[dict[str, Any], bytes]:
    """Construct one bound native refutation through a named adapter."""

    if adapter_id == "MALFORMED_EVIDENCE_REBIND":
        return _malformed_evidence_rebind(request, evidence)
    if adapter_id == "SIM_ISOLATION_MALFORMED_REBIND":
        return _sim_isolation_malformed_rebind(request, evidence)
    if adapter_id == "GOVERNANCE_INVALID_SIGNATURE":
        return _governance_invalid_signature(request, evidence)
    if adapter_id == "SUBJECT_SECURITY_VALID_TRANSPLANT":
        return _subject_security_valid_transplant(request, evidence)
    if adapter_id == "RECEIPT_CHAIN_ENTRY_SUBSTITUTION":
        return _receipt_chain_entry_substitution(request, evidence)
    if adapter_id == "RECEIPT_ATTESTATION_SIGNATURE_BIT_FLIP":
        return _receipt_attestation_signature_bit_flip(request, evidence)
    if adapter_id == "GRAPH_EDGE_CONTENT_SUBSTITUTION":
        return _graph_edge_content_substitution(request, evidence)
    if adapter_id == "HYPER_UNRELATED_OBJECT_COLLECTION":
        return _hyper_unrelated_object_collection(
            request, evidence, policy
        )
    raise NativeReplayAdapterError("NATIVE_NEGATIVE_ADAPTER_UNAVAILABLE")


def unknown_case(
        adapter_id: str, request: dict[str, Any], replay_input: bytes, *,
        policy: dict[str, Any] | None = None,
        ) -> tuple[dict[str, Any], bytes]:
    """Construct one bound native unavailable case through a named adapter."""

    del policy
    if adapter_id == "ABSENT_EVIDENCE":
        return deepcopy(request), replay_input
    if adapter_id == "HYPER_CLOSURE_OPERATION_BUDGET":
        try:
            selected = deepcopy(request)
            if (
                type(selected) is not dict
                or type(selected.get("limits")) is not dict
            ):
                raise NativeReplayAdapterError(
                    "NATIVE_HYPER_UNKNOWN_INPUT_INVALID"
                )
            selected["limits"]["max_closure_operations"] = 1
            return selected, replay_input
        except NativeReplayAdapterError:
            raise
        except (ValueError, TypeError, KeyError, RecursionError,
                OverflowError) as exc:
            raise NativeReplayAdapterError(
                "NATIVE_HYPER_UNKNOWN_INPUT_INVALID"
            ) from exc
    raise NativeReplayAdapterError("NATIVE_UNKNOWN_ADAPTER_UNAVAILABLE")


def build_certificate(
        adapter_id: str,
        case_kind: str,
        builder: Callable[..., bytes],
        request: dict[str, Any],
        replay_input: bytes,
        policy: dict[str, Any],
        ) -> bytes:
    """Invoke one native builder through its explicit input-shape adapter."""

    if case_kind not in {
        "POSITIVE", "NEGATIVE", "ABSENT_EVIDENCE",
        "HYPER_CLOSURE_OPERATION_BUDGET",
    }:
        raise NativeReplayAdapterError("NATIVE_CASE_KIND_INVALID")
    if not callable(builder):
        raise NativeReplayAdapterError("NATIVE_CASE_BUILDER_UNAVAILABLE")
    if adapter_id == "BOUNDED_EVIDENCE_BYTES":
        evidence = None if case_kind == "ABSENT_EVIDENCE" else replay_input
        return builder(request, evidence, policy=policy)
    if adapter_id == "WINDOWS_MODEL_HARDWARE_OBSERVATION":
        # The contract itself performs the platform check before native
        # dispatch and emits UNKNOWN when Windows Job Objects are unavailable.
        evidence = None if case_kind == "ABSENT_EVIDENCE" else replay_input
        return builder(request, evidence, policy=policy)
    if adapter_id == "SIM_OBJECT_GROUNDING":
        objects, isolation, _value = _decode_sim_object_grounding_input(
            replay_input
        )
        if case_kind == "ABSENT_EVIDENCE":
            isolation = None
        return builder(request, objects, isolation, policy=policy)
    if adapter_id == "HYPER_OBJECT_COLLECTION":
        if case_kind == "ABSENT_EVIDENCE":
            raise NativeReplayAdapterError("NATIVE_CASE_KIND_INVALID")
        objects, _value = _decode_hyper_object_collection(replay_input)
        return builder(request, objects, policy=policy)
    raise NativeReplayAdapterError("NATIVE_BUILDER_ADAPTER_UNAVAILABLE")


__all__ = [
    "NativeReplayAdapterError", "SIM_INPUT_SCHEMA", "build_certificate",
    "negative_case", "unknown_case",
]
