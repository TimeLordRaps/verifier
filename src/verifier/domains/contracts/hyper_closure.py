"""One current HYPER finite declared operand-closure certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
Counts and operation limits are dimensionless; byte limits count retained bytes.
The finite declaration check grants no authority or whole-tier conformance.
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
from verifier.core.namespace import (
    NamespaceObject, ObjectCoordinate, ObjectKind, assess_composition,
    composition_digest,
)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HYPER-4.1"
REQUEST_VERSION = "verifier-current-hyper-closure-request-1"
POLICY_VERSION = "verifier-current-hyper-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-hyper-closure-certificate-1"
COLLECTION_VERSION = "verifier-current-hyper-closure-collection-1"
CONE_VERSION = "verifier-current-hyper-closure-members-1"
MECHANISM_ID = "verifier.current-object.hyper-declared-operand-closure.1"
SCOPE = "finite_declared_hyper_operand_closure"
PROPOSITION = (
    "For the independently selected HYPER object and expected finite collection "
    "commitment, the retained canonical namespace records are exactly the transitive "
    "closure of its declared named operand references, including the HYPER root: "
    "each referenced object occurs once with its exact bytes and admitted kind, "
    "each declared edge resolves inside that collection, no composition dependency "
    "cycle occurs, no unrelated record is included, and the recomputed canonical "
    "closure-member commitment equals the externally selected expected commitment."
)
REGISTRATION = {
    "schema_version": "verifier-current-object-proposition-1",
    "semantic_version": SEMANTIC_VERSION,
    "coordinate": COORDINATE,
    "subject_kind": "HYPER",
    "proposition": PROPOSITION,
    "scope": SCOPE,
    "prerequisites": ["exact finite typed composition", "independently selected HYPER and closure commitments"],
    "exclusions": ["undeclared payload dependencies", "mathematical or physical completeness",
                   "privacy, consent, governance or authority", "whole tier or profile conformance"],
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest(REGISTRATION)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_COLLECTION_BYTES = 8 * 1024 * 1024
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_CEILINGS = {
    "max_objects": 4096,
    "max_collection_bytes": _MAX_COLLECTION_BYTES,
    "max_reference_bytes": 8 * 1024 * 1024,
    "max_composition_operations": 100000,
    "max_closure_operations": 100000,
    "max_evidence_bytes": _MAX_COLLECTION_BYTES,
}
DEFAULT_LIMITS = dict(_CEILINGS)
_REQUEST_FIELDS = {"schema_version", "semantic_version", "coordinate", "proposition_digest",
                   "subject_id", "object_digest", "collection_digest", "cone_digest",
                   "evidence_ref", "policy_digest", "limits"}
_POLICY_FIELDS = {"schema_version", "mechanism_id", "mechanism_digest",
                  "trust_roots", "max_certificate_bytes"}
_CERTIFICATE_FIELDS = {"schema_version", "request", "policy_digest", "mechanism_digest",
                       "proposition_digest", "evidence_ref", "evidence_payloads", "result", "digest"}


class CurrentHyperClosureError(ValueError):
    """Malformed or substituted current closure selection or certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    # Exact built-in shape and count precede key-set construction and callbacks.
    if type(value) is not dict or len(value) != len(fields):
        raise CurrentHyperClosureError(f"{label} fields differ")
    if any(type(key) is not str for key in value):
        raise CurrentHyperClosureError(f"{label} fields differ")
    captured = dict(value)
    if set(captured) != fields:
        raise CurrentHyperClosureError(f"{label} fields differ")
    return captured


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise CurrentHyperClosureError(f"{label} requires canonical SHA-256 digest")
    return value


def _name(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise CurrentHyperClosureError(f"{label} requires bounded nonblank text")
    return value


def _limits(value: Any) -> dict[str, int]:
    selected = _record(value, set(_CEILINGS), "limits")
    for name, ceiling in _CEILINGS.items():
        if type(selected[name]) is not int or not 1 <= selected[name] <= ceiling:
            raise CurrentHyperClosureError(f"{name} exceeds installed checker bounds")
    return selected


def mechanism_digest() -> str:
    """Commit installed checker, normative statement and executed dependencies."""
    paths = {
        "hyper_closure.py": Path(__file__),
        "CURRENT_HYPER_CLOSURE.md": Path(__file__).parents[2] / "standard" / "CURRENT_HYPER_CLOSURE.md",
        "namespace.py": Path(namespace_module.__file__),
        "evidence.py": Path(evidence_module.__file__),
        "certificate.py": Path(certificate_module.__file__),
        "receipt.py": Path(receipt_module.__file__),
        "common.py": Path(common_module.__file__),
    }
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def hyper_closure_policy(*, trust_roots: Sequence[str],
                         max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Construct a descriptor; only an external selector can admit it."""
    if type(trust_roots) not in (list, tuple) or not 1 <= len(trust_roots) <= 16:
        raise CurrentHyperClosureError("trust roots require a bounded plain sequence")
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), "trust_roots": list(trust_roots),
                    "max_certificate_bytes": max_certificate_bytes})


def _policy(value: Any) -> dict[str, Any]:
    selected = _record(value, _POLICY_FIELDS, "policy")
    roots = selected["trust_roots"]
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        raise CurrentHyperClosureError("trust roots require a bounded plain list")
    roots = list(roots)
    selected["trust_roots"] = roots
    if (any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise CurrentHyperClosureError("trust roots must be sorted unique nonblank labels")
    if type(selected["schema_version"]) is not str or type(selected["mechanism_id"]) is not str:
        raise CurrentHyperClosureError("policy identifiers must be plain text")
    if selected["schema_version"] != POLICY_VERSION or selected["mechanism_id"] != MECHANISM_ID:
        raise CurrentHyperClosureError("unsupported closure policy")
    if _digest(selected["mechanism_digest"], "mechanism") != mechanism_digest():
        raise CurrentHyperClosureError("policy does not admit installed closure mechanism")
    ceiling = selected["max_certificate_bytes"]
    if type(ceiling) is not int or not 1 <= ceiling <= _MAX_CERTIFICATE_BYTES:
        raise CurrentHyperClosureError("certificate byte limit invalid")
    return selected


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, _REQUEST_FIELDS, "request")
    # Nested limits must be copied before any digest or coordinate callback.
    selected["limits"] = _limits(selected["limits"])
    if type(selected["schema_version"]) is not str or type(selected["semantic_version"]) is not str:
        raise CurrentHyperClosureError("request versions must be plain text")
    if selected["schema_version"] != REQUEST_VERSION or selected["semantic_version"] != SEMANTIC_VERSION:
        raise CurrentHyperClosureError("unsupported current semantic namespace")
    if type(selected["coordinate"]) is not str:
        raise CurrentHyperClosureError("coordinate must be plain text")
    try:
        coordinate = ObjectCoordinate.parse(selected["coordinate"])
    except ValueError as exc:
        raise CurrentHyperClosureError("invalid current-object coordinate") from exc
    if str(coordinate) != COORDINATE:
        raise CurrentHyperClosureError("unregistered current-object coordinate")
    if _digest(selected["proposition_digest"], "proposition") != PROPOSITION_DIGEST:
        raise CurrentHyperClosureError("proposition differs from installed registration")
    _name(selected["subject_id"], "selected HYPER")
    for field in ("object_digest", "collection_digest", "cone_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field], field)
    return selected


def _capture_collection(objects: Sequence[NamespaceObject], limits: Mapping[str, int]) -> tuple[tuple[NamespaceObject, ...], bytes]:
    if type(objects) not in (list, tuple):
        raise CurrentHyperClosureError("collection must be an exact built-in list or tuple")
    if len(objects) > limits["max_objects"]:
        raise Unavailable("collection object count exhausted before serialization")
    captured = tuple(objects)
    raw_fields: list[tuple[str, ObjectKind, bytes, tuple[tuple[str, tuple[str, ...]], ...]]] = []
    payload_count = operations = 0
    # Read every field into immutable built-ins before invoking serialization,
    # hashing, or a possible instrumented callback. A caller replacing a field
    # afterward cannot change the accepted snapshot.
    for item in captured:
        if type(item) is not NamespaceObject:
            raise CurrentHyperClosureError("collection contains a noncanonical namespace record")
        object_id, kind, payload_bytes, operands = item.object_id, item.kind, item.payload_bytes, item.operands
        if (type(object_id) is not str or type(kind) is not ObjectKind
                or type(payload_bytes) is not bytes or type(operands) is not tuple):
            raise CurrentHyperClosureError("collection contains a noncanonical namespace record")
        payload_count += len(payload_bytes)
        operations += 1 + len(operands)
        if payload_count > limits["max_collection_bytes"] or operations > limits["max_composition_operations"]:
            raise Unavailable("collection input budget exhausted before serialization")
        for binding in operands:
            if (type(binding) is not tuple or len(binding) != 2 or type(binding[0]) is not str
                    or type(binding[1]) is not tuple):
                raise CurrentHyperClosureError("operand binding is not immutable")
            _role, targets = binding
            operations += len(targets)
            if operations > limits["max_composition_operations"]:
                raise Unavailable("collection reference operation budget exhausted")
            if any(type(target) is not str for target in targets):
                raise CurrentHyperClosureError("operand target is not plain text")
        raw_fields.append((object_id, kind, payload_bytes, operands))
    reference_bytes = 0
    for object_id, _kind, _payload, operands in raw_fields:
        reference_bytes += len(certificate_module.canonical_bytes(object_id))
        for role, targets in operands:
            reference_bytes += len(certificate_module.canonical_bytes(role))
            for target in targets:
                reference_bytes += len(certificate_module.canonical_bytes(target))
                if reference_bytes > limits["max_reference_bytes"]:
                    raise Unavailable("collection encoded reference byte budget exhausted before serialization")
        if reference_bytes > limits["max_reference_bytes"]:
            raise Unavailable("collection encoded reference byte budget exhausted before serialization")
    try:
        frozen = tuple(NamespaceObject(*fields) for fields in raw_fields)
        encoded = canonical_bytes({"schema_version": COLLECTION_VERSION,
                                   "objects": [item.to_dict() for item in sorted(frozen, key=lambda x: x.object_id)]})
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise CurrentHyperClosureError("collection cannot be captured canonically") from exc
    if len(encoded) > limits["max_collection_bytes"]:
        raise Unavailable("collection encoded byte budget exhausted")
    return _parse_collection(encoded, limits), encoded


def _parse_collection(data: bytes, limits: Mapping[str, int]) -> tuple[NamespaceObject, ...]:
    if len(data) > limits["max_collection_bytes"]:
        raise Unavailable("retained collection byte budget exhausted")
    value = strict_json_loads(data.decode("utf-8"))
    outer = _record(value, {"schema_version", "objects"}, "collection evidence")
    if outer["schema_version"] != COLLECTION_VERSION:
        raise Refuted("unsupported collection evidence version")
    rows = outer["objects"]
    if type(rows) is not list:
        raise Refuted("collection evidence requires object rows")
    if len(rows) > limits["max_objects"]:
        raise Unavailable("retained object count budget exhausted")
    objects = []
    for row in rows:
        record = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace row")
        item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
        if canonical_bytes(item.to_dict()) != canonical_bytes(record):
            raise Refuted("namespace row does not reconstruct exactly")
        objects.append(item)
    if canonical_bytes(value) != data:
        raise Refuted("collection evidence is not canonical")
    return tuple(objects)


def _cone(objects: Sequence[NamespaceObject], subject_id: str, max_operations: int) -> tuple[str, frozenset[str]]:
    by_id = {obj.object_id: obj for obj in objects}
    if len(by_id) != len(objects):
        raise Refuted("duplicate object identifier")
    root = by_id.get(subject_id)
    if root is None or root.kind is not ObjectKind.HYPER:
        raise Refuted("selected HYPER is absent or another kind")
    visited: set[str] = set()
    pending = [subject_id]
    used = 0
    while pending:
        used += 1
        if used > max_operations:
            raise Unavailable("operand-closure operation budget exhausted")
        name = pending.pop()
        if name in visited:
            continue
        item = by_id.get(name)
        if item is None:
            raise Refuted("operand target is absent from retained collection")
        visited.add(name)
        for _role, targets in item.operands:
            used += len(targets)
            if used > max_operations:
                raise Unavailable("operand-closure operation budget exhausted")
            pending.extend(targets)
    members = [{"object_id": name, "object_digest": by_id[name].digest} for name in sorted(visited)]
    commitment = "sha256:" + canonical_digest({"schema_version": CONE_VERSION,
                                              "subject_id": subject_id, "members": members})
    return commitment, frozenset(visited)


def hyper_closure_request(objects: Sequence[NamespaceObject], *, hyper_id: str,
                          policy: dict[str, Any], limits: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Construct selectable intent; this helper does not make selection independent."""
    admitted = _policy(policy)
    selected_limits = _limits(DEFAULT_LIMITS if limits is None else limits)
    _name(hyper_id, "selected HYPER")
    captured, encoded = _capture_collection(objects, selected_limits)
    root = next((item for item in captured if item.object_id == hyper_id), None)
    if root is None or root.kind is not ObjectKind.HYPER:
        raise CurrentHyperClosureError("selected HYPER does not resolve")
    cone_digest, _ = _cone(captured, hyper_id, selected_limits["max_closure_operations"])
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
                     "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
                     "subject_id": hyper_id, "object_digest": root.digest,
                     "collection_digest": composition_digest(captured), "cone_digest": cone_digest,
                     "evidence_ref": "sha256:" + hashlib.sha256(encoded).hexdigest(),
                     "policy_digest": "sha256:" + canonical_digest(admitted), "limits": selected_limits})


def _parameters(request: Mapping[str, Any]) -> dict[str, str]:
    return {"semantic_version": request["semantic_version"], "proposition_digest": request["proposition_digest"],
            "object_digest": request["object_digest"], "collection_digest": request["collection_digest"],
            "cone_digest": request["cone_digest"], "evidence_ref": request["evidence_ref"],
            "policy_digest": request["policy_digest"],
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _HyperClosureMechanism:
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
                    or dict(binding.parameters) != _parameters(request)):
                raise Refuted("bound proposition differs from selected closure objective")
            if len(evidence) != 1:
                raise Unavailable("complete collection evidence required")
            objects = _parse_collection(evidence[0], limits)
            composition = assess_composition(objects, expected_digest=request["collection_digest"],
                max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
                max_payload_bytes=limits["max_collection_bytes"],
                max_reference_bytes=limits["max_reference_bytes"])
            if composition.verdict.value == "UNKNOWN":
                raise Unavailable(composition.reason)
            if composition.verdict.value != "PASS":
                raise Refuted(composition.reason)
            root = next((item for item in objects if item.object_id == request["subject_id"]), None)
            if root is None or root.kind is not ObjectKind.HYPER or root.digest != request["object_digest"]:
                raise Refuted("selected HYPER identifier, kind or digest differs")
            observed_cone, visited = _cone(objects, request["subject_id"], limits["max_closure_operations"])
            if len(visited) != len(objects):
                raise Refuted("retained collection contains an unrelated object")
            if observed_cone != request["cone_digest"]:
                raise Refuted("operand-closure member commitment differs")
            return MechanismDecision(MechanismOutcome.PASS, "exact finite declared operand cone replayed", {
                "scope": SCOPE, "collection_digest": composition.collection_digest,
                "root_object_digest": root.digest, "cone_digest": observed_cone,
                "members_checked": len(visited),
            })
        except Unavailable as exc:
            return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
        except (Refuted, CurrentHyperClosureError, ValueError, TypeError, KeyError, UnicodeError,
                OverflowError, RecursionError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise CurrentHyperClosureError("request does not bind independently supplied policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_HyperClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "scope": SCOPE,
              "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
              "proposition_digest": PROPOSITION_DIGEST, "subject_id": request["subject_id"],
              "object_digest": request["object_digest"], "collection_digest": request["collection_digest"],
              "cone_digest": request["cone_digest"], "evidence_ref": request["evidence_ref"],
              "hyper_tier_4_conformance": "NOT_ESTABLISHED",
              "object_profile_conformance": "NOT_ESTABLISHED",
              "mathematical_closure": "NOT_ESTABLISHED", "physical_completeness": "NOT_ESTABLISHED",
              "privacy": "NOT_ESTABLISHED", "consent": "NOT_ESTABLISHED",
              "governance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
              "evaluation": evaluation.to_dict()}
    payloads = store.export_base64([request["evidence_ref"]] if request["evidence_ref"] in store else [])
    envelope: dict[str, Any] = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_ref": request["evidence_ref"],
        "evidence_payloads": payloads, "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise Unavailable("certificate byte budget exhausted")
    return encoded


def build_hyper_closure_certificate(request: dict[str, Any], objects: Sequence[NamespaceObject], *,
                                    policy: dict[str, Any]) -> bytes:
    """Check the selected proposition and retain exact offline replay input bytes."""
    selected, admitted = _request(request), _policy(policy)
    if selected["policy_digest"] != "sha256:" + canonical_digest(admitted):
        raise CurrentHyperClosureError("request policy commitment differs")
    _, encoded = _capture_collection(objects, selected["limits"])
    store = EvidenceStore()
    if store.add(encoded) != selected["evidence_ref"]:
        raise Refuted("supplied collection bytes contradict expected evidence reference")
    return _build(selected, admitted, store)


def recheck_hyper_closure_certificate(certificate_bytes: bytes, *,
                                      expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    """Rerun retained bytes under external selection and compare the whole result."""
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise CurrentHyperClosureError("certificate absent or over selected byte limit")
    try:
        certificate = strict_json_loads(certificate_bytes.decode("utf-8"))
        if canonical_bytes(certificate) != certificate_bytes:
            raise CurrentHyperClosureError("certificate is not canonical")
        envelope = _record(certificate, _CERTIFICATE_FIELDS, "certificate")
        if envelope["schema_version"] != CERTIFICATE_VERSION:
            raise CurrentHyperClosureError("unsupported current closure certificate")
        if _digest(envelope["digest"], "certificate") != "sha256:" + canonical_digest({
                key: value for key, value in envelope.items() if key != "digest"}):
            raise CurrentHyperClosureError("certificate digest differs")
        if envelope["request"] != selected or envelope["policy_digest"] != "sha256:" + canonical_digest(admitted):
            raise CurrentHyperClosureError("certificate differs from external request or policy")
        if (envelope["mechanism_digest"] != admitted["mechanism_digest"]
                or envelope["proposition_digest"] != PROPOSITION_DIGEST
                or envelope["evidence_ref"] != selected["evidence_ref"]):
            raise CurrentHyperClosureError("certificate mechanism, proposition or evidence differs")
        payloads = envelope["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1 or any(type(key) is not str for key in payloads)
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(value) is not str for value in payloads.values())):
            raise CurrentHyperClosureError("embedded evidence inventory differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise CurrentHyperClosureError("replayed closure certificate differs")
        return envelope["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError) as exc:
        if isinstance(exc, CurrentHyperClosureError):
            raise
        raise CurrentHyperClosureError("certificate cannot be replayed") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "PROPOSITION", "PROPOSITION_DIGEST",
           "CurrentHyperClosureError", "DEFAULT_LIMITS", "mechanism_digest",
           "hyper_closure_policy", "hyper_closure_request",
           "build_hyper_closure_certificate", "recheck_hyper_closure_certificate"]
