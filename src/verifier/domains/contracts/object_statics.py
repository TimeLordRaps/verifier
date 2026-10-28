"""Current OBJECT-3.1: canonical retained namespace-collection statics.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
Record sizes are bytes. Payload depth, value counts, reference counts and
checking budgets are dimensionless. PASS establishes no typed composition,
operand resolution or payload truth.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject, ObjectKind, composition_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "OBJECT-3.1"
REQUEST_VERSION = "verifier-current-object-statics-request-1"
POLICY_VERSION = "verifier-current-object-statics-policy-1"
CERTIFICATE_VERSION = "verifier-current-object-statics-certificate-1"
EVIDENCE_VERSION = "verifier-current-object-statics-evidence-1"
MECHANISM_ID = "verifier.current-object.canonical-collection-statics.1"
SCOPE = "selected_canonical_collection_statics"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
# Inclusive (minimum, maximum) for each declared structural bound. The maxima
# are the namespace record bounds; a declaration may only be tighter.
_BOUND_RANGES = {"max_records": (1, 4096),
                 "max_record_bytes": (1, 8 * 1024 * 1024),
                 "max_payload_depth": (0, 64),
                 "max_payload_values": (1, 10000),
                 "max_references": (0, 4096)}


class ObjectStaticsError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "OBJECT", "scope": SCOPE,
        "proposition": (
            "Every retained record of the selected finite collection is at "
            "most the declared byte bound, its SHA-256 digest equals its "
            "retained address, and addresses and identifiers are unique; its "
            "bytes are valid UTF-8, strict and canonical JSON that reconstruct "
            "exactly one admitted namespace record whose digest is that "
            "address; record count, payload depth, payload value count and "
            "operand reference count are within the declared inclusive bounds; "
            "the records recompute the selected collection commitment; and the "
            "selected subject is the OBJECT record with the selected digest."),
        "prerequisites": [
            "externally selected OBJECT subject, record digest, collection "
            "commitment and declared structural bounds; retained record bytes; "
            "finite checker limits"],
        "exclusions": [
            "typed composition or resolution of operand references",
            "payload meaning, truth, authorship or provenance",
            "revision history, address closure or receipt issuance",
            "whole OBJECT statics tier or object-profile conformance",
            "privacy, consent, governance, security or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ObjectStaticsDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ObjectStaticsError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, ObjectStaticsError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               namespace_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_OBJECT_STATICS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ObjectStaticsError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def object_statics_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _bounds(value: Any) -> dict[str, int]:
    selected = _record(value, set(_BOUND_RANGES), "structural bounds")
    for key, (low, high) in _BOUND_RANGES.items():
        if type(selected[key]) is not int or not low <= selected[key] <= high:
            raise ObjectStaticsError("declared structural bound is unsupported")
    return selected


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "structural_bounds",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "OBJECT")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise ObjectStaticsError("selected OBJECT statics objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise ObjectStaticsError("bounded OBJECT subject required")
    for field in ("object_digest", "collection_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["structural_bounds"] = _bounds(selected["structural_bounds"])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ObjectStaticsError)
    return selected


def object_statics_request(*, subject_id: str, object_digest: str,
        collection_digest: str, structural_bounds: dict[str, int],
        evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ObjectStaticsError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "OBJECT",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "structural_bounds": structural_bounds,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _shape(payload: Any, budget: common_module.Budget) -> tuple[int, int]:
    """Deepest nesting step below the payload root and its JSON value count."""
    pending = [(payload, 0)]
    deepest = count = 0
    while pending:
        part, depth = pending.pop()
        budget.tick()
        count += 1
        deepest = max(deepest, depth)
        if type(part) is dict:
            pending.extend((child, depth + 1) for child in part.values())
        elif type(part) is list:
            pending.extend((child, depth + 1) for child in part)
    return deepest, count


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits, bounds = request["limits"], request["structural_bounds"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "records"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained statics evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["records"]
        if type(rows) is not list:
            raise Refuted("retained records must be a list")
        if len(rows) > bounds["max_records"]:
            raise Refuted("declared record count bound exceeded")
        addresses: set[str] = set()
        identifiers: set[str] = set()
        objects: list[NamespaceObject] = []
        observed = {"max_record_bytes": 0, "max_payload_depth": 0,
                    "max_payload_values": 0, "max_references": 0}
        for row in rows:
            budget.tick()
            row = _record(row, {"address", "bytes"}, "retained record")
            address = retained_selection.commitment(row["address"], Refuted)
            raw = _decode_b64(row["bytes"], "retained record")
            if len(raw) > bounds["max_record_bytes"]:
                raise Refuted("declared record byte bound exceeded")
            budget.tick(len(raw) // 64 + 1)
            if "sha256:" + hashlib.sha256(raw).hexdigest() != address:
                raise Refuted("retained address differs from SHA-256 of retained bytes")
            if address in addresses:
                raise Refuted("retained record address occurs twice")
            addresses.add(address)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise Refuted("retained record is not valid UTF-8") from exc
            try:
                parsed = strict_json_loads(text)
            except (ValueError, RecursionError) as exc:
                raise Refuted("retained record is not strict JSON") from exc
            if canonical_bytes(parsed) != raw:
                raise Refuted("retained record bytes are not canonical JSON")
            try:
                fields = _record(parsed, {"object_id", "kind", "payload", "operands"},
                                 "namespace record")
                if type(fields["operands"]) is not dict:
                    raise ValueError("operand map required")
                item = NamespaceObject.create(fields["object_id"], fields["kind"],
                                              fields["payload"], fields["operands"])
                if canonical_bytes(item.to_dict()) != raw:
                    raise ValueError("record does not reconstruct exactly")
            except (ValueError, TypeError, RecursionError) as exc:
                raise Refuted("retained record is not an admitted namespace record") from exc
            if item.digest != address:
                raise Refuted("namespace record digest differs from its address")
            if item.object_id in identifiers:
                raise Refuted("retained record identifier occurs twice")
            identifiers.add(item.object_id)
            depth, count = _shape(parsed["payload"], budget)
            references = sum(len(targets) for _, targets in item.operands)
            if depth > bounds["max_payload_depth"]:
                raise Refuted("declared payload depth bound exceeded")
            if count > bounds["max_payload_values"]:
                raise Refuted("declared payload value bound exceeded")
            if references > bounds["max_references"]:
                raise Refuted("declared reference bound exceeded")
            for key, measured in (("max_record_bytes", len(raw)),
                                  ("max_payload_depth", depth),
                                  ("max_payload_values", count),
                                  ("max_references", references)):
                observed[key] = max(observed[key], measured)
            objects.append(item)
        budget.tick(len(objects))
        if composition_digest(objects) != request["collection_digest"]:
            raise Refuted("retained collection commitment differs")
        subject = [item for item in objects if item.object_id == request["subject_id"]]
        if (len(subject) != 1 or subject[0].kind != ObjectKind.OBJECT
                or subject[0].digest != request["object_digest"]):
            raise Refuted("selected OBJECT subject differs")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected collection is canonical, uniquely addressed and within declared bounds",
            {"records": len(objects), **observed, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ObjectStaticsMechanism:
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
                                     "bound OBJECT statics proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected record bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ObjectStaticsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ObjectStaticsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "OBJECT", "scope": SCOPE,
        "canonical_collection_statics": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "typed_composition": "NOT_ESTABLISHED",
        "operand_resolution": "NOT_ESTABLISHED",
        "payload_truth": "NOT_ESTABLISHED",
        "whole_object_statics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ObjectStaticsError("certificate byte bound exhausted")
    return encoded


def build_object_statics_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ObjectStaticsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ObjectStaticsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_object_statics_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ObjectStaticsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ObjectStaticsError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ObjectStaticsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ObjectStaticsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ObjectStaticsError):
            raise
        raise ObjectStaticsError("invalid retained OBJECT statics certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SCOPE",
           "ObjectStaticsDescriptor", "ObjectStaticsError", "registration",
           "object_statics_policy", "object_statics_request",
           "build_object_statics_certificate",
           "recheck_object_statics_certificate"]
