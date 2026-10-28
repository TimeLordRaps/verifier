"""One versioned current-object simulation (SIM) grounding certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
All counts are dimensionless; byte ceilings count UTF-8 or retained bytes. A PASS is finite declared confinement only, never full
independence-tier conformance, physical containment, or external authority.
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
from verifier.core.namespace import NamespaceObject, ObjectCoordinate, ObjectKind, assess_composition, composition_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from . import sim_isolation as isolation_module


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-5.1"
REQUEST_VERSION = "verifier-current-object-request-1"
POLICY_VERSION = "verifier-current-object-policy-1"
CERTIFICATE_VERSION = "verifier-current-object-certificate-1"
COLLECTION_VERSION = "verifier-current-object-collection-1"
MECHANISM_ID = "verifier.current-object.sim-finite-confinement.1"
PROPOSITION = (
    "Within the externally selected finite SIM model, every reachable state has "
    "at least one retained outcome for every declared action, and every such "
    "outcome remains inside the declared simulation partition, acquires no "
    "capability, and has no outside write, external actuation, or external export effect."
)
REGISTRATION = {
    "schema_version": "verifier-current-object-proposition-1",
    "semantic_version": SEMANTIC_VERSION,
    "coordinate": COORDINATE,
    "subject_kind": "SIM",
    "proposition": PROPOSITION,
    "scope": "finite_declared_capability_effect_confinement",
    "prerequisites": ["exact finite typed composition", "selected SIM and isolation evidence commitments"],
    "exclusions": ["physical host containment", "external authority", "whole tier or profile conformance"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(REGISTRATION)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_COLLECTION_BYTES = 8 * 1024 * 1024
_MAX_ISOLATION_BYTES = 1024 * 1024
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_LIMIT_CEILINGS = {
    "max_objects": 4096,
    "max_collection_bytes": _MAX_COLLECTION_BYTES,
    "max_reference_bytes": 8 * 1024 * 1024,
    "max_composition_operations": 100000,
    "max_isolation_bytes": _MAX_ISOLATION_BYTES,
    "max_isolation_operations": 10000000,
    "max_isolation_items": 4096,
    "max_evidence_bytes": 16 * 1024 * 1024,
}
DEFAULT_LIMITS = {
    "max_objects": 4096,
    "max_collection_bytes": _MAX_COLLECTION_BYTES,
    "max_reference_bytes": 8 * 1024 * 1024,
    "max_composition_operations": 100000,
    "max_isolation_bytes": _MAX_ISOLATION_BYTES,
    "max_isolation_operations": 100000,
    "max_isolation_items": 4096,
    "max_evidence_bytes": 9 * 1024 * 1024,
}


class CurrentObjectGroundingError(ValueError):
    """Malformed, substituted, or unreplayable current-object certificate."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise CurrentObjectGroundingError(f"{label} requires canonical SHA-256 digest")
    return value


def _name(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise CurrentObjectGroundingError(f"{label} requires bounded nonempty text")
    return value


def _mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    # Bounded plain-dict capture precedes all callbacks, hashing and validation.
    # The snapshot has only string keys; nested known records snapshot separately.
    if type(value) is not dict or len(value) != len(fields):
        raise CurrentObjectGroundingError(f"{label} fields differ")
    if any(type(key) is not str for key in value):
        raise CurrentObjectGroundingError(f"{label} fields differ")
    captured = dict(value)
    if set(captured) != fields:
        raise CurrentObjectGroundingError(f"{label} fields differ")
    return captured


def _limits(value: Any) -> dict[str, int]:
    value = _mapping(value, set(_LIMIT_CEILINGS), "limits")
    for key, ceiling in _LIMIT_CEILINGS.items():
        if type(value[key]) is not int or not 1 <= value[key] <= ceiling:
            raise CurrentObjectGroundingError(f"{key} is outside checker bounds")
    return dict(value)


def mechanism_digest() -> str:
    """Pin the candidate and the exact built-in source/specification it executes."""
    sources = {
        "object_grounding.py": Path(__file__),
        "namespace.py": Path(namespace_module.__file__),
        "sim_isolation.py": Path(isolation_module.__file__),
        "evidence.py": Path(evidence_module.__file__),
        "certificate.py": Path(certificate_module.__file__),
        "receipt.py": Path(receipt_module.__file__),
        "common.py": Path(common_module.__file__),
        "CURRENT_OBJECT_GROUNDING.md": Path(__file__).parents[2] / "standard" / "CURRENT_OBJECT_GROUNDING.md",
    }
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(sources.items())
    })


def current_object_policy(*, trust_roots: Sequence[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Construct a policy descriptor; only an external selector can admit it."""
    if type(trust_roots) not in (list, tuple) or not 1 <= len(trust_roots) <= 16:
        raise CurrentObjectGroundingError("policy trust roots require a bounded plain sequence")
    roots = list(trust_roots)
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": roots,
        "max_certificate_bytes": max_certificate_bytes})


def _policy(value: Any) -> dict[str, Any]:
    value = _mapping(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes"}, "policy")
    roots = value["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        raise CurrentObjectGroundingError("policy trust roots must be bounded sorted unique labels")
    roots = list(roots)
    value["trust_roots"] = roots
    if (any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise CurrentObjectGroundingError("policy trust roots must be bounded sorted unique labels")
    if (type(value["schema_version"]) is not str or type(value["mechanism_id"]) is not str
            or value["schema_version"] != POLICY_VERSION or value["mechanism_id"] != MECHANISM_ID):
        raise CurrentObjectGroundingError("unsupported current-object policy")
    if _digest(value["mechanism_digest"], "mechanism") != mechanism_digest():
        raise CurrentObjectGroundingError("policy does not admit installed current-object mechanism")
    bound = value["max_certificate_bytes"]
    if type(bound) is not int or not 1 <= bound <= _MAX_CERTIFICATE_BYTES:
        raise CurrentObjectGroundingError("certificate byte ceiling is invalid")
    return value


def _request(value: Any) -> dict[str, Any]:
    value = _mapping(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "subject_id", "object_digest", "collection_digest",
        "isolation_evidence_digest", "policy_digest", "limits"}, "request")
    # Copy the nested plain limits before coordinate parsing and digest callbacks.
    value["limits"] = _limits(value["limits"])
    if (type(value["schema_version"]) is not str or type(value["semantic_version"]) is not str
            or value["schema_version"] != REQUEST_VERSION or value["semantic_version"] != SEMANTIC_VERSION):
        raise CurrentObjectGroundingError("unsupported current-object semantic version")
    if type(value["coordinate"]) is not str:
        raise CurrentObjectGroundingError("invalid current-object coordinate")
    try:
        coordinate = ObjectCoordinate.parse(value["coordinate"])
    except (TypeError, ValueError) as exc:
        raise CurrentObjectGroundingError("invalid current-object coordinate") from exc
    if str(coordinate) != COORDINATE:
        raise CurrentObjectGroundingError("unregistered current-object coordinate")
    if _digest(value["proposition_digest"], "proposition") != PROPOSITION_DIGEST:
        raise CurrentObjectGroundingError("proposition differs from installed registration")
    _name(value["subject_id"], "selected SIM")
    for field in ("object_digest", "collection_digest", "isolation_evidence_digest", "policy_digest"):
        _digest(value[field], field)
    return value


def _capture_objects(objects: Sequence[NamespaceObject], limits: Mapping[str, int]) -> tuple[tuple[NamespaceObject, ...], bytes]:
    if type(objects) not in (list, tuple):
        raise CurrentObjectGroundingError("collection must be a plain finite sequence")
    if len(objects) > limits["max_objects"]:
        raise Unavailable("collection object bound exhausted before serialization")
    # Capture exact built-in fields before any canonicalization callback. Frozen
    # dataclasses can still be altered with object.__setattr__, so retaining the
    # caller's NamespaceObject instances is not a stable evidence snapshot.
    records = []
    payload_bytes = 0
    operation_count = len(objects)
    for item in objects:
        if type(item) is not NamespaceObject:
            raise CurrentObjectGroundingError("collection must contain exact namespace objects")
        object_id, kind, payload, operands = item.object_id, item.kind, item.payload_bytes, item.operands
        if (type(object_id) is not str or not object_id.strip() or len(object_id) > 256
                or type(kind) is not ObjectKind
                or type(payload) is not bytes or type(operands) is not tuple
                or len(operands) > 4096):
            raise CurrentObjectGroundingError("collection object fields must be immutable built-ins")
        payload_bytes += len(payload)
        if payload_bytes > limits["max_collection_bytes"]:
            raise Unavailable("collection payload bound exhausted before serialization")
        bindings = []
        operation_count += len(operands)
        if operation_count > limits["max_composition_operations"]:
            raise Unavailable("collection operation bound exhausted before serialization")
        for binding in operands:
            if type(binding) is not tuple or len(binding) != 2:
                raise CurrentObjectGroundingError("collection operand binding is malformed")
            role, targets = binding
            if (type(role) is not str or not role.strip() or len(role) > 256
                    or type(targets) is not tuple or len(targets) > 4096):
                raise CurrentObjectGroundingError("collection operand fields must be immutable built-ins")
            if any(type(target) is not str or not target.strip() or len(target) > 256 for target in targets):
                raise CurrentObjectGroundingError("collection operand targets must be plain text")
            operation_count += len(targets)
            if operation_count > limits["max_composition_operations"]:
                raise Unavailable("collection operation bound exhausted before serialization")
            bindings.append((role, targets))
        records.append((object_id, kind, payload, tuple(bindings)))
    # This is the same canonical JSON string-byte measure used by the
    # composition checker. Escaping may make it larger than raw UTF-8.
    reference_bytes = 0
    for object_id, _, _, bindings in records:
        reference_bytes += len(canonical_bytes(object_id))
        if reference_bytes > limits["max_reference_bytes"]:
            raise Unavailable("collection reference bound exhausted before serialization")
        for role, targets in bindings:
            reference_bytes += len(canonical_bytes(role))
            if reference_bytes > limits["max_reference_bytes"]:
                raise Unavailable("collection reference bound exhausted before serialization")
            for target in targets:
                reference_bytes += len(canonical_bytes(target))
                if reference_bytes > limits["max_reference_bytes"]:
                    raise Unavailable("collection reference bound exhausted before serialization")
    captured = tuple(NamespaceObject(*record) for record in records)
    encoded = canonical_bytes({"schema_version": COLLECTION_VERSION,
        "objects": [item.to_dict() for item in sorted(captured, key=lambda item: item.object_id)]})
    if len(encoded) > limits["max_collection_bytes"]:
        raise Unavailable("collection serialized byte bound exhausted")
    return captured, encoded


def current_object_request(objects: Sequence[NamespaceObject], *, sim_id: str,
                           isolation_evidence_bytes: bytes, policy: dict[str, Any],
                           limits: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Build a selectable intent; creation itself does not authenticate it."""
    admitted = _policy(policy)
    selected_limits = _limits(DEFAULT_LIMITS if limits is None else limits)
    captured, _ = _capture_objects(objects, selected_limits)
    _name(sim_id, "selected SIM")
    selected = next((item for item in captured if item.object_id == sim_id and item.kind == ObjectKind.SIM), None)
    if selected is None:
        raise CurrentObjectGroundingError("selected SIM does not resolve")
    if type(isolation_evidence_bytes) is not bytes:
        raise CurrentObjectGroundingError("finite isolation evidence requires immutable bytes")
    if len(isolation_evidence_bytes) > selected_limits["max_isolation_bytes"]:
        raise Unavailable("finite isolation evidence byte bound exhausted")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "subject_id": sim_id, "object_digest": selected.digest,
        "collection_digest": composition_digest(captured),
        "isolation_evidence_digest": "sha256:" + hashlib.sha256(isolation_evidence_bytes).hexdigest(),
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": selected_limits})


def _parse_collection(data: bytes, limits: Mapping[str, int]) -> tuple[NamespaceObject, ...]:
    if len(data) > limits["max_collection_bytes"]:
        raise Unavailable("retained collection byte bound exhausted")
    value = strict_json_loads(data.decode("utf-8"))
    if (type(value) is not dict or len(value) != 2
            or set(value) != {"schema_version", "objects"}
            or value["schema_version"] != COLLECTION_VERSION):
        raise Refuted("unsupported or malformed collection evidence")
    rows = value["objects"]
    if type(rows) is not list or len(rows) > limits["max_objects"]:
        raise Unavailable("retained collection item bound exhausted")
    if canonical_bytes(value) != data:
        raise Refuted("collection evidence is not canonical")
    objects = []
    for row in rows:
        if (type(row) is not dict or len(row) != 4
                or set(row) != {"object_id", "kind", "payload", "operands"}):
            raise Refuted("namespace object record fields differ")
        item = NamespaceObject.create(row["object_id"], row["kind"], row["payload"], row["operands"])
        if canonical_bytes(item.to_dict()) != canonical_bytes(row):
            raise Refuted("namespace object record does not reconstruct exactly")
        objects.append(item)
    return tuple(objects)


class _SimConfinementMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request = request
        self.policy = policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        try:
            request, limits = self.request, self.request["limits"]
            if (binding.subject_id != request["subject_id"] or binding.predicate != COORDINATE
                    or binding.expected is not True or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])
                    or dict(binding.parameters) != _binding_parameters(request)):
                raise Refuted("bound proposition differs from selected current-object objective")
            if len(evidence) != 2:
                raise Unavailable("complete collection and isolation evidence required")
            objects = _parse_collection(evidence[0], limits)
            composition = assess_composition(objects, expected_digest=request["collection_digest"],
                max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
                max_payload_bytes=limits["max_collection_bytes"],
                max_reference_bytes=limits["max_reference_bytes"])
            if composition.verdict.value == "UNKNOWN":
                raise Unavailable(composition.reason)
            if composition.verdict.value != "PASS":
                raise Refuted(composition.reason)
            selected = next((item for item in objects if item.object_id == request["subject_id"]), None)
            if selected is None or selected.kind != ObjectKind.SIM:
                raise Refuted("selected SIM is absent or has another kind")
            if selected.digest != request["object_digest"]:
                raise Refuted("SIM object differs from externally selected digest")
            recorded = selected.payload.get("isolation_evidence_digest")
            if recorded is None:
                raise Unavailable("SIM object has no isolation evidence commitment")
            if recorded != request["isolation_evidence_digest"]:
                raise Refuted("SIM object binds different isolation evidence")
            if len(evidence[1]) > limits["max_isolation_bytes"]:
                raise Unavailable("finite isolation evidence byte bound exhausted")
            finite = strict_json_loads(evidence[1].decode("utf-8"))
            if canonical_bytes(finite) != evidence[1]:
                raise Refuted("finite isolation evidence is not canonical")
            selected_isolation = {
                "sim_id": request["subject_id"],
                "evidence_digest": request["isolation_evidence_digest"],
                "max_operations": limits["max_isolation_operations"],
                "max_items": limits["max_isolation_items"],
            }
            isolation = isolation_module.assess_sim_isolation(
                finite, expected_binding=selected_isolation)
            if (isolation["scope"] != "finite_declared_transition_model"
                    or isolation["sim_id"] != request["subject_id"]
                    or isolation["binding_digest"] != "sha256:" + canonical_digest(selected_isolation)
                    or isolation["evidence_digest"] != request["isolation_evidence_digest"]
                    or isolation["object_profile_conformance"] != "NOT_ESTABLISHED"
                    or isolation["physical_host_containment"] != "NOT_ESTABLISHED"
                    or isolation["authority"] != "NOT_ESTABLISHED"):
                raise Refuted("finite isolation result scope or binding differs")
            if (isolation["status"] == "PASS"
                    and isolation["observed_evidence_digest"] != request["isolation_evidence_digest"]):
                raise Refuted("passing finite isolation evidence commitment differs")
            outcome = MechanismOutcome(isolation["status"])
            return MechanismDecision(outcome, isolation["reason"], {
                "scope": "finite_declared_capability_effect_confinement",
                "composition_digest": composition.collection_digest,
                "sim_object_digest": selected.digest,
                "isolation_assessment_digest": isolation["assessment_digest"],
                "isolation_status": isolation["status"],
            })
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
        except (Refuted, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _binding_parameters(request: Mapping[str, Any]) -> dict[str, str]:
    return {"semantic_version": request["semantic_version"],
        "proposition_digest": request["proposition_digest"],
        "object_digest": request["object_digest"],
        "collection_digest": request["collection_digest"],
        "isolation_evidence_digest": request["isolation_evidence_digest"],
        "policy_digest": request["policy_digest"],
        "limits_digest": "sha256:" + canonical_digest(request["limits"])}


def _build_from_store(request: dict[str, Any], policy: dict[str, Any],
                      store: EvidenceStore, refs: tuple[str, str]) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise CurrentObjectGroundingError("request does not bind independently supplied policy")
    proposition = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=refs, trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(2, request["limits"]["max_evidence_bytes"]),
        parameters=_binding_parameters(request))
    session = VerificationSession(store)
    session.register(_SimConfinementMechanism(request, policy))
    evaluation = session.evaluate(proposition)
    result = {"status": evaluation.outcome.value,
        "scope": "finite_declared_capability_effect_confinement",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST,
        "subject_id": request["subject_id"], "object_digest": request["object_digest"],
        "collection_digest": request["collection_digest"],
        "isolation_evidence_digest": request["isolation_evidence_digest"],
        "physical_host_containment": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "sim_tier_5_conformance": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    available = [ref for ref in refs if ref in store]
    envelope: dict[str, Any] = {"schema_version": CERTIFICATE_VERSION,
        "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": list(refs),
        "evidence_payloads": store.export_base64(available), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise CurrentObjectGroundingError("certificate byte bound exhausted")
    return encoded


def build_current_object_certificate(request: dict[str, Any], objects: Sequence[NamespaceObject],
                                     isolation_evidence_bytes: bytes | None, *,
                                     policy: dict[str, Any]) -> bytes:
    """Execute one selected objective and retain exact offline replay inputs."""
    selected, admitted = _request(request), _policy(policy)
    if selected["policy_digest"] != "sha256:" + canonical_digest(admitted):
        raise CurrentObjectGroundingError("request policy commitment differs")
    _, collection_bytes = _capture_objects(objects, selected["limits"])
    store = EvidenceStore()
    collection_ref = store.add(collection_bytes)
    if isolation_evidence_bytes is None:
        isolation_ref = selected["isolation_evidence_digest"]
    else:
        if type(isolation_evidence_bytes) is not bytes:
            raise CurrentObjectGroundingError("isolation evidence must be immutable bytes")
        if len(isolation_evidence_bytes) > selected["limits"]["max_isolation_bytes"]:
            raise Unavailable("isolation evidence byte bound exhausted before parse")
        isolation_ref = store.add(isolation_evidence_bytes)
    return _build_from_store(selected, admitted, store, (collection_ref, isolation_ref))


def recheck_current_object_certificate(certificate_bytes: bytes, *,
                                       expected_request: dict[str, Any],
                                       policy: dict[str, Any]) -> dict[str, Any]:
    """Rerun retained bytes against external intent; reject a rehashed forgery."""
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise CurrentObjectGroundingError("certificate is absent or exceeds the selected byte bound")
    try:
        certificate = strict_json_loads(certificate_bytes.decode("utf-8"))
        if canonical_bytes(certificate) != certificate_bytes:
            raise CurrentObjectGroundingError("certificate is noncanonical")
        _mapping(certificate, {"schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if certificate["schema_version"] != CERTIFICATE_VERSION:
            raise CurrentObjectGroundingError("unsupported current-object certificate version")
        stated_digest = certificate["digest"]
        if _digest(stated_digest, "certificate") != "sha256:" + canonical_digest({
                key: value for key, value in certificate.items() if key != "digest"}):
            raise CurrentObjectGroundingError("certificate digest differs")
        if certificate["request"] != selected:
            raise CurrentObjectGroundingError("certificate differs from externally selected request")
        if certificate["policy_digest"] != "sha256:" + canonical_digest(admitted):
            raise CurrentObjectGroundingError("certificate differs from externally selected policy")
        if certificate["mechanism_digest"] != admitted["mechanism_digest"] or certificate["proposition_digest"] != PROPOSITION_DIGEST:
            raise CurrentObjectGroundingError("certificate mechanism or proposition differs")
        refs = certificate["evidence_refs"]
        if type(refs) is not list or len(refs) != 2 or any(type(ref) is not str for ref in refs):
            raise CurrentObjectGroundingError("certificate evidence references differ")
        refs = tuple(_digest(ref, "evidence reference") for ref in refs)
        if refs[0] == refs[1]:
            raise CurrentObjectGroundingError("two evidence roles cannot alias")
        payloads = certificate["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 2
                or set(payloads) - set(refs)
                or any(type(value) is not str for value in payloads.values())):
            raise CurrentObjectGroundingError("certificate embedded evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build_from_store(selected, admitted, store, refs)
        if rebuilt != certificate_bytes:
            raise CurrentObjectGroundingError("certificate result does not reproduce")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (UnicodeError, TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        if isinstance(exc, CurrentObjectGroundingError):
            raise
        raise CurrentObjectGroundingError(f"invalid current-object certificate: {exc}") from exc
