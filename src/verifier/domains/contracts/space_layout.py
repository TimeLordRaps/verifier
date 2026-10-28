"""Versioned SPACE retained logical byte-partition layout certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Offsets, extents and alignment use bytes. Counts
and checker limits are dimensionless. Layout does not prove host allocation.
"""
from __future__ import annotations

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
COORDINATE = "SPACE-3.1"
REQUEST_VERSION = "verifier-current-space-layout-request-1"
POLICY_VERSION = "verifier-current-space-layout-policy-1"
CERTIFICATE_VERSION = "verifier-current-space-layout-certificate-1"
EVIDENCE_VERSION = "verifier-current-space-layout-evidence-1"
MECHANISM_ID = "verifier.current-space.retained-layout.1"
SCOPE = "finite_retained_logical_byte_partitions"
_MAX_SAFE_INTEGER = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class SpaceLayoutError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "SPACE",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact SPACE namespace record occurs in "
            "the selected finite typed collection, and its retained nonempty "
            "logical byte-partition sequence rehashes, uses unique identifiers "
            "and contains aligned, nonoverlapping half-open intervals within "
            "its declared finite byte extent."
        ),
        "prerequisites": [
            "independently selected exact SPACE record, full finite collection, "
            "retained partition bytes, installed policy and finite checker limits"
        ],
        "exclusions": [
            "actual memory, storage, network or hardware allocation",
            "physical containment, access control or isolation",
            "coverage of unallocated gaps or scheduling authority",
            "whole SPACE statics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SpaceLayoutDescriptor:
    """Native public route metadata for one logical layout proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SpaceLayoutError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, SpaceLayoutError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SPACE_LAYOUT.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=SpaceLayoutError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def space_layout_policy(*, trust_roots: list[str],
                      max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, SpaceLayoutError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "SPACE"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise SpaceLayoutError("selected logical layout objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise SpaceLayoutError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def space_layout_request(*, subject_id: str, object_digest: str,
                       collection_digest: str, evidence_ref: str,
                       policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise SpaceLayoutError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "SPACE", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise Refuted(label + " must be a nonnegative safe integer byte count")
    return value


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects", "inputs"}, "evidence")
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
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if len(matches) != 1 or matches[0].kind.value != "SPACE" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained space subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        if value["inputs"] is None:
            raise Unavailable("retained space partitions absent")
        retained = _record(value["inputs"], {"partitions"}, "space inputs")
        payload = _record(matches[0].payload, {
            "scope", "unit", "extent_bytes", "partitions_digest",
        }, "space payload")
        if payload["scope"] != "retained-logical-byte-partitions" or payload["unit"] != "byte":
            raise Refuted("space scope or unit differs")
        extent = _integer(payload["extent_bytes"], "space extent")
        if extent == 0:
            raise Refuted("declared byte extent must be nonempty")
        partitions = retained["partitions"]
        if type(partitions) is not list:
            raise Refuted("retained partitions must be a sequence")
        if not partitions:
            raise Unavailable("nonempty retained partition sequence required")
        if len(partitions) > limits["max_items"]:
            raise Unavailable("retained partition bound exhausted")
        if _hash(payload["partitions_digest"]) != "sha256:" + canonical_digest(partitions):
            raise Refuted("retained partition commitment differs")
        seen: set[str] = set()
        intervals: list[tuple[int, int]] = []
        for row in partitions:
            budget.tick()
            partition = _record(row, {
                "id", "start_byte", "end_byte", "alignment_bytes",
            }, "space partition")
            identifier = partition["id"]
            if type(identifier) is not str or not identifier.strip() or len(identifier) > 256 or identifier in seen:
                raise Refuted("partition identifier is absent, duplicate or unbounded")
            seen.add(identifier)
            start = _integer(partition["start_byte"], "partition start")
            end = _integer(partition["end_byte"], "partition end")
            alignment = _integer(partition["alignment_bytes"], "partition alignment")
            if alignment == 0 or alignment & (alignment - 1):
                raise Refuted("partition alignment must be a positive power of two")
            if start >= end or end > extent or start % alignment:
                raise Refuted("partition interval or alignment differs")
            intervals.append((start, end))
        budget.tick(len(intervals) * (len(intervals).bit_length() + 1))
        previous_end = 0
        for start, end in sorted(intervals):
            budget.tick()
            if start < previous_end:
                raise Refuted("declared byte partitions overlap")
            previous_end = end
        return MechanismDecision(
            MechanismOutcome.PASS, "selected retained space layout reproduced",
            {"partitions": len(partitions), "extent_bytes": extent,
             "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _SpaceLayoutMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound space proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained space evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SpaceLayoutError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_SpaceLayoutMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "SPACE", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "host_allocation": "NOT_ESTABLISHED",
        "physical_containment": "NOT_ESTABLISHED",
        "isolation": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
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
        raise SpaceLayoutError("certificate byte bound exhausted")
    return encoded


def build_space_layout_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                 *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise SpaceLayoutError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SpaceLayoutError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_space_layout_certificate(certificate_bytes: bytes, *,
                                   expected_request: dict[str, Any],
                                   policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SpaceLayoutError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise SpaceLayoutError("canonical certificate version differs")
        if value["request"] != selected:
            raise SpaceLayoutError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SpaceLayoutError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SpaceLayoutError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SpaceLayoutError):
            raise
        raise SpaceLayoutError("invalid retained space certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SpaceLayoutDescriptor",
    "SpaceLayoutError", "registration", "space_layout_policy",
    "space_layout_request", "build_space_layout_certificate",
    "recheck_space_layout_certificate",
]
