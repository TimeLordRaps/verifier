"""One bounded current generic object-facet and address certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless and byte limits count
canonical encoded or retained bytes. A PASS is generic representation only.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject, ObjectCoordinate, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "OBJECT-1.1"
ADDRESS_VERSION = "verifier-namespace-object-address-1"
REQUEST_VERSION = "verifier-current-object-facets-request-1"
POLICY_VERSION = "verifier-current-object-facets-policy-1"
CERTIFICATE_VERSION = "verifier-current-object-facets-certificate-1"
MECHANISM_ID = "verifier.current-object.generic-facets.1"
PROPOSITION = (
    "For the independently selected identifier, admitted kind, local record digest, "
    "facet commitments, and versioned object address, the retained bounded canonical "
    "namespace-record bytes reconstruct exactly one record whose identifier, kind, "
    "payload, and named operand map are explicit and losslessly recoverable; "
    "recomputation of the record and facet commitments yields the selected values, "
    "and the deterministic address identifies that exact record."
)
REGISTRATION = {
    "schema_version": "verifier-current-object-proposition-1",
    "semantic_version": SEMANTIC_VERSION,
    "coordinate": COORDINATE,
    "subject_kind": "OBJECT",
    "proposition": PROPOSITION,
    "scope": "generic_canonical_representation_and_address",
    "prerequisites": ["externally selected exact record and address commitments"],
    "exclusions": ["kind-specific facets", "operand resolution", "issued receipt",
                   "execution", "whole tier or object profile conformance"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(REGISTRATION)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_RECORD_BYTES = 4 * 1024 * 1024
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_LIMIT_CEILINGS = {
    "max_record_bytes": _MAX_RECORD_BYTES,
    "max_reference_bytes": 2 * 1024 * 1024,
    "max_operations": 10000,
    "max_evidence_bytes": _MAX_RECORD_BYTES,
}
DEFAULT_LIMITS = dict(_LIMIT_CEILINGS)


class ObjectFacetsError(ValueError):
    """Malformed selection, substituted policy, or unreplayable certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields):
        raise ObjectFacetsError(f"{label} fields differ")
    if any(type(key) is not str for key in value):
        raise ObjectFacetsError(f"{label} fields differ")
    captured = dict(value)
    if set(captured) != fields:
        raise ObjectFacetsError(f"{label} fields differ")
    return captured


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ObjectFacetsError(f"{label} requires canonical SHA-256 digest")
    return value


def _name(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ObjectFacetsError(f"{label} requires bounded nonempty text")
    return value


def _limits(value: Any) -> dict[str, int]:
    selected = _record(value, set(_LIMIT_CEILINGS), "limits")
    for key, ceiling in _LIMIT_CEILINGS.items():
        if type(selected[key]) is not int or not 1 <= selected[key] <= ceiling:
            raise ObjectFacetsError(f"{key} is outside checker bounds")
    return selected


def mechanism_digest() -> str:
    """Bind the installed candidate and all directly used checking contracts."""
    sources = {
        "object_facets.py": Path(__file__),
        "namespace.py": Path(namespace_module.__file__),
        "evidence.py": Path(evidence_module.__file__),
        "certificate.py": Path(certificate_module.__file__),
        "receipt.py": Path(receipt_module.__file__),
        "common.py": Path(common_module.__file__),
        "CURRENT_OBJECT_FACETS.md": Path(__file__).parents[2] / "standard" / "CURRENT_OBJECT_FACETS.md",
    }
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest()
                                         for name, path in sorted(sources.items())})


def object_facets_policy(*, trust_roots: Sequence[str],
                         max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Format a policy; construction does not authenticate external selection."""
    if type(trust_roots) not in (list, tuple) or not 1 <= len(trust_roots) <= 16:
        raise ObjectFacetsError("policy trust roots require a bounded plain sequence")
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": list(trust_roots),
        "max_certificate_bytes": max_certificate_bytes})


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
                               "trust_roots", "max_certificate_bytes"}, "policy")
    roots = selected["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        raise ObjectFacetsError("policy trust roots require a bounded plain list")
    selected["trust_roots"] = list(roots)
    if (any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise ObjectFacetsError("policy trust roots must be sorted unique labels")
    if (type(selected["schema_version"]) is not str or type(selected["mechanism_id"]) is not str
            or selected["schema_version"] != POLICY_VERSION
            or selected["mechanism_id"] != MECHANISM_ID):
        raise ObjectFacetsError("unsupported current object-facets policy")
    if _digest(selected["mechanism_digest"], "mechanism") != mechanism_digest():
        raise ObjectFacetsError("policy does not admit installed object-facets mechanism")
    size = selected["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ObjectFacetsError("certificate byte ceiling is invalid")
    return selected


def _address(*, object_id: str, object_kind: str, record_digest: str) -> dict[str, str]:
    return {"schema_version": ADDRESS_VERSION, "semantic_version": SEMANTIC_VERSION,
            "object_id": object_id, "object_kind": object_kind,
            "record_digest": record_digest}


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_id", "object_kind", "record_digest",
        "payload_digest", "operands_digest", "address_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    selected["limits"] = _limits(selected["limits"])
    if (type(selected["schema_version"]) is not str
            or type(selected["semantic_version"]) is not str
            or selected["schema_version"] != REQUEST_VERSION
            or selected["semantic_version"] != SEMANTIC_VERSION):
        raise ObjectFacetsError("unsupported current object-facets semantic version")
    if type(selected["coordinate"]) is not str:
        raise ObjectFacetsError("invalid current object-facets coordinate")
    try:
        coordinate = ObjectCoordinate.parse(selected["coordinate"])
    except (TypeError, ValueError) as exc:
        raise ObjectFacetsError("invalid current object-facets coordinate") from exc
    if str(coordinate) != COORDINATE:
        raise ObjectFacetsError("unregistered current object-facets coordinate")
    if _digest(selected["proposition_digest"], "proposition") != PROPOSITION_DIGEST:
        raise ObjectFacetsError("proposition differs from installed registration")
    _name(selected["object_id"], "selected object")
    if type(selected["object_kind"]) is not str or selected["object_kind"] not in {kind.value for kind in ObjectKind}:
        raise ObjectFacetsError("selected object kind is not admitted")
    for field in ("record_digest", "payload_digest", "operands_digest", "address_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field], field)
    if selected["evidence_ref"] != selected["record_digest"]:
        raise ObjectFacetsError("canonical record digest and evidence reference differ")
    expected_address = _address(object_id=selected["object_id"],
        object_kind=selected["object_kind"], record_digest=selected["record_digest"])
    if selected["address_digest"] != "sha256:" + canonical_digest(expected_address):
        raise ObjectFacetsError("selected object address commitment differs")
    return selected


def _capture_record(item: NamespaceObject, limits: Mapping[str, int]) -> tuple[NamespaceObject, bytes]:
    if type(item) is not NamespaceObject:
        raise ObjectFacetsError("candidate requires an exact namespace object")
    object_id, kind, payload, operands = item.object_id, item.kind, item.payload_bytes, item.operands
    if (type(object_id) is not str or not object_id.strip() or len(object_id) > 256
            or type(kind) is not ObjectKind or type(payload) is not bytes
            or type(operands) is not tuple or len(operands) > 4096):
        raise ObjectFacetsError("candidate fields must be bounded immutable built-ins")
    if len(payload) > limits["max_record_bytes"]:
        raise Unavailable("record payload bound exhausted before serialization")
    bindings: list[tuple[str, tuple[str, ...]]] = []
    operations = 1 + len(operands)
    if operations > limits["max_operations"]:
        raise Unavailable("record operation bound exhausted before serialization")
    for binding in operands:
        if type(binding) is not tuple or len(binding) != 2:
            raise ObjectFacetsError("candidate operand binding is malformed")
        role, targets = binding
        if (type(role) is not str or not role.strip() or len(role) > 256
                or type(targets) is not tuple or len(targets) > 4096
                or any(type(target) is not str or not target.strip() or len(target) > 256
                       for target in targets)):
            raise ObjectFacetsError("candidate operand fields must be bounded immutable built-ins")
        operations += len(targets)
        if operations > limits["max_operations"]:
            raise Unavailable("record operation bound exhausted before serialization")
        bindings.append((role, targets))
    identifier_bytes = len(canonical_bytes(object_id))
    reference_bytes = identifier_bytes
    operands_bytes = 2  # Braces around the named operand map.
    if reference_bytes > limits["max_reference_bytes"]:
        raise Unavailable("record reference bound exhausted before serialization")
    for role_index, (role, targets) in enumerate(bindings):
        role_bytes = len(canonical_bytes(role))
        reference_bytes += role_bytes
        operands_bytes += (1 if role_index else 0) + role_bytes + 3  # comma, colon and brackets
        if reference_bytes > limits["max_reference_bytes"]:
            raise Unavailable("record reference bound exhausted before serialization")
        for target_index, target in enumerate(targets):
            target_bytes = len(canonical_bytes(target))
            reference_bytes += target_bytes
            operands_bytes += (1 if target_index else 0) + target_bytes
            if reference_bytes > limits["max_reference_bytes"]:
                raise Unavailable("record reference bound exhausted before serialization")
    fixed_bytes = (len(b'{"kind":') + len(b',"object_id":')
                   + len(b',"operands":') + len(b',"payload":') + len(b'}'))
    predicted_bytes = (fixed_bytes + len(canonical_bytes(kind.value)) + identifier_bytes
                       + operands_bytes + len(payload))
    if predicted_bytes > limits["max_record_bytes"]:
        raise Unavailable("canonical record bound exhausted before serialization")
    try:
        captured = NamespaceObject(object_id, kind, payload, tuple(bindings))
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ObjectFacetsError("candidate namespace record is malformed") from exc
    encoded = canonical_bytes(captured.to_dict())
    if len(encoded) != predicted_bytes:
        raise ObjectFacetsError("canonical record length differs from checked snapshot")
    return captured, encoded


def object_facets_request(item: NamespaceObject, *, policy: dict[str, Any],
                          limits: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Format selectable intent; only external retention/selection admits it."""
    admitted = _policy(policy)
    selected_limits = _limits(DEFAULT_LIMITS if limits is None else limits)
    captured, encoded = _capture_record(item, selected_limits)
    record_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    address = _address(object_id=captured.object_id, object_kind=captured.kind.value,
                       record_digest=record_digest)
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_id": captured.object_id, "object_kind": captured.kind.value,
        "record_digest": record_digest,
        "payload_digest": "sha256:" + hashlib.sha256(captured.payload_bytes).hexdigest(),
        "operands_digest": "sha256:" + canonical_digest(captured.to_dict()["operands"]),
        "address_digest": "sha256:" + canonical_digest(address), "evidence_ref": record_digest,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": selected_limits})


def _retained_record_bounds(row: dict[str, Any], limits: Mapping[str, int]) -> None:
    """Charge selected finite work against parsed retained fields before reconstruction."""
    object_id = _name(row["object_id"], "retained object")
    kind = row["kind"]
    if type(kind) is not str or kind not in {member.value for member in ObjectKind}:
        raise Refuted("retained object kind is not admitted")
    if type(row["payload"]) is not dict:
        raise Refuted("retained object payload is malformed")
    operands = row["operands"]
    if type(operands) is not dict or len(operands) > 4096:
        raise Refuted("retained operand map is malformed")
    operations = 1 + len(operands)
    if operations > limits["max_operations"]:
        raise Unavailable("retained record operation bound exhausted")
    references = len(canonical_bytes(object_id))
    if references > limits["max_reference_bytes"]:
        raise Unavailable("retained record reference bound exhausted")
    for role, targets in operands.items():
        _name(role, "retained operand role")
        if type(targets) is not list or len(targets) > 4096:
            raise Refuted("retained operand targets are malformed")
        operations += len(targets)
        if operations > limits["max_operations"]:
            raise Unavailable("retained record operation bound exhausted")
        references += len(canonical_bytes(role))
        if references > limits["max_reference_bytes"]:
            raise Unavailable("retained record reference bound exhausted")
        for target in targets:
            _name(target, "retained operand target")
            references += len(canonical_bytes(target))
            if references > limits["max_reference_bytes"]:
                raise Unavailable("retained record reference bound exhausted")


def _parse_record(data: bytes, limits: Mapping[str, int]) -> NamespaceObject:
    if len(data) > limits["max_record_bytes"]:
        raise Unavailable("retained record byte bound exhausted")
    try:
        value = strict_json_loads(data.decode("utf-8"))
        row = _record(value, {"object_id", "kind", "payload", "operands"}, "retained record")
        _retained_record_bounds(row, limits)
        if canonical_bytes(row) != data:
            raise Refuted("retained record is not canonical")
        item = NamespaceObject.create(row["object_id"], row["kind"],
                                      row["payload"], row["operands"])
        if canonical_bytes(item.to_dict()) != data:
            raise Refuted("retained record does not reconstruct exactly")
        return item
    except (UnicodeError, TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        if isinstance(exc, (Refuted, Unavailable)):
            raise
        raise Refuted("retained record is malformed or unsupported") from exc


def _parameters(request: Mapping[str, Any]) -> dict[str, str]:
    return {"semantic_version": request["semantic_version"],
        "proposition_digest": request["proposition_digest"],
        "object_kind": request["object_kind"], "record_digest": request["record_digest"],
        "payload_digest": request["payload_digest"],
        "operands_digest": request["operands_digest"],
        "address_digest": request["address_digest"],
        "policy_digest": request["policy_digest"],
        "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _ObjectFacetsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request = request
        self.policy = policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        try:
            request = self.request
            if (binding.subject_id != request["object_id"] or binding.predicate != COORDINATE
                    or binding.expected is not True
                    or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])
                    or dict(binding.parameters) != _parameters(request)):
                raise Refuted("bound proposition differs from selected generic object objective")
            if len(evidence) != 1:
                raise Unavailable("one exact retained object record is required")
            item = _parse_record(evidence[0], request["limits"])
            if item.object_id != request["object_id"] or item.kind.value != request["object_kind"]:
                raise Refuted("retained object identity or kind differs")
            if item.digest != request["record_digest"]:
                raise Refuted("retained object record differs from selected digest")
            if "sha256:" + hashlib.sha256(item.payload_bytes).hexdigest() != request["payload_digest"]:
                raise Refuted("retained object payload facet differs")
            if "sha256:" + canonical_digest(item.to_dict()["operands"]) != request["operands_digest"]:
                raise Refuted("retained object operand facet differs")
            address = _address(object_id=item.object_id, object_kind=item.kind.value,
                               record_digest=item.digest)
            if "sha256:" + canonical_digest(address) != request["address_digest"]:
                raise Refuted("retained object address differs")
            return MechanismDecision(MechanismOutcome.PASS,
                "exact selected generic object facets and address reconstructed", {
                    "record_digest": item.digest, "address_digest": request["address_digest"],
                    "object_kind": item.kind.value})
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
        except (Refuted, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ObjectFacetsError("request does not bind independently supplied policy")
    proposition = BoundProposition(subject_id=request["object_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ObjectFacetsMechanism(request, policy))
    evaluation = session.evaluate(proposition)
    result = {"status": evaluation.outcome.value,
        "scope": "generic_canonical_representation_and_address",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_id": request["object_id"],
        "object_kind": request["object_kind"], "record_digest": request["record_digest"],
        "address_digest": request["address_digest"],
        "kind_specific_tier_1_conformance": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "issued_receipt": "NOT_ESTABLISHED", "execution": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ObjectFacetsError("certificate byte bound exhausted")
    return encoded


def build_object_facets_certificate(request: dict[str, Any], record_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    """Evaluate selected generic facets and retain all available exact evidence."""
    selected, admitted = _request(request), _policy(policy)
    if selected["policy_digest"] != "sha256:" + canonical_digest(admitted):
        raise ObjectFacetsError("request policy commitment differs")
    store = EvidenceStore()
    if record_bytes is not None:
        if type(record_bytes) is not bytes:
            raise ObjectFacetsError("retained record must be immutable bytes")
        if len(record_bytes) > selected["limits"]["max_record_bytes"]:
            raise Unavailable("retained record byte bound exhausted before parse")
        if store.add(record_bytes) != selected["evidence_ref"]:
            raise Refuted("supplied record bytes contradict expected evidence reference")
    return _build(selected, admitted, store)


def recheck_object_facets_certificate(certificate_bytes: bytes, *,
                                      expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the exact certificate against independently selected intent."""
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ObjectFacetsError("certificate is absent or exceeds selected byte bound")
    try:
        value = strict_json_loads(certificate_bytes.decode("utf-8"))
        if canonical_bytes(value) != certificate_bytes:
            raise ObjectFacetsError("certificate is noncanonical")
        envelope = _record(value, {"schema_version", "request", "policy_digest",
            "mechanism_digest", "proposition_digest", "evidence_refs",
            "evidence_payloads", "result", "digest"}, "certificate")
        if envelope["schema_version"] != CERTIFICATE_VERSION:
            raise ObjectFacetsError("unsupported current object-facets certificate version")
        if _digest(envelope["digest"], "certificate") != "sha256:" + canonical_digest({
                key: item for key, item in envelope.items() if key != "digest"}):
            raise ObjectFacetsError("certificate digest differs")
        if envelope["request"] != selected:
            raise ObjectFacetsError("certificate differs from externally selected request")
        if envelope["policy_digest"] != "sha256:" + canonical_digest(admitted):
            raise ObjectFacetsError("certificate differs from externally selected policy")
        if (envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST):
            raise ObjectFacetsError("certificate mechanism or proposition differs")
        if envelope["evidence_refs"] != [selected["evidence_ref"]]:
            raise ObjectFacetsError("certificate evidence reference differs")
        payloads = envelope["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise ObjectFacetsError("certificate embedded evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ObjectFacetsError("certificate result does not reproduce")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (UnicodeError, TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        if isinstance(exc, ObjectFacetsError):
            raise
        raise ObjectFacetsError(f"invalid current object-facets certificate: {exc}") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "PROPOSITION", "PROPOSITION_DIGEST",
           "object_facets_policy", "object_facets_request", "build_object_facets_certificate",
           "recheck_object_facets_certificate", "ObjectFacetsError"]
