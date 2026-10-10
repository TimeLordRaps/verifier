"""Versioned EVENT retained declared prerequisite and payload certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Sequence numbers, counts and checker limits are
dimensionless; evidence and certificate limits are bytes. No occurrence truth.
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
COORDINATE = "EVENT-3.1"
REQUEST_VERSION = "verifier-current-event-prerequisites-request-1"
POLICY_VERSION = "verifier-current-event-prerequisites-policy-1"
CERTIFICATE_VERSION = "verifier-current-event-prerequisites-certificate-1"
EVIDENCE_VERSION = "verifier-current-event-prerequisites-evidence-1"
MECHANISM_ID = "verifier.current-event.retained-prerequisites.1"
SCOPE = "finite_retained_declared_prerequisites"
_MAX_SAFE_INTEGER = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class EventPrerequisitesError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "EVENT",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact EVENT namespace record occurs in "
            "the selected finite typed collection; every event in its finite "
            "declared prerequisite cone has retained payload bytes matching "
            "its digest, and each unique declared prerequisite is a retained "
            "EVENT with a strictly lower dimensionless sequence number."
        ),
        "prerequisites": [
            "independently selected exact EVENT record, full finite collection, "
            "retained cone payloads, installed policy and finite checker limits"
        ],
        "exclusions": [
            "actual historical occurrence, observer authenticity or physical causality",
            "truth of TIME, SPACE and meaning operands",
            "unrelated events, sequence gap absence or global event-log closure",
            "whole EVENT statics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class EventPrerequisitesDescriptor:
    """Native public route metadata for one declared event cone proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, EventPrerequisitesError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, EventPrerequisitesError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_EVENT_PREREQUISITES.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=EventPrerequisitesError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def event_prerequisites_policy(*, trust_roots: list[str],
                      max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, EventPrerequisitesError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "EVENT"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise EventPrerequisitesError("selected event objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise EventPrerequisitesError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def event_prerequisites_request(*, subject_id: str, object_digest: str,
                       collection_digest: str, evidence_ref: str,
                       policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise EventPrerequisitesError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "EVENT", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise Refuted(label + " must be a nonnegative safe integer sequence")
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
        if len(matches) != 1 or matches[0].kind.value != "EVENT" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained event subject differs from external selection")
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
            raise Unavailable("retained event payloads absent")
        retained = _record(value["inputs"], {"payloads"}, "event inputs")
        payloads = retained["payloads"]
        if type(payloads) is not dict or any(type(key) is not str for key in payloads):
            raise Refuted("retained event payload map requires plain identifiers")
        if len(payloads) > limits["max_items"]:
            raise Unavailable("retained payload bound exhausted")
        by_id = {obj.object_id: obj for obj in objects}
        pending = [request["subject_id"]]
        visited: set[str] = set()
        edges = 0
        while pending:
            budget.tick()
            identifier = pending.pop()
            if identifier in visited:
                continue
            if len(visited) >= limits["max_items"]:
                raise Unavailable("selected event cone bound exhausted")
            event = by_id.get(identifier)
            if event is None or event.kind.value != "EVENT":
                raise Refuted("declared prerequisite is not a retained EVENT")
            statement = _record(event.payload, {
                "scope", "sequence", "prerequisites", "payload_digest",
            }, "event payload")
            if statement["scope"] != "retained-declared-prerequisites":
                raise Refuted("event scope differs")
            sequence = _integer(statement["sequence"], "event sequence")
            parents = statement["prerequisites"]
            if type(parents) is not list:
                raise Refuted("declared prerequisites must be a list")
            if len(parents) > limits["max_items"]:
                raise Unavailable("prerequisite bound exhausted")
            budget.tick(len(parents))
            if len(set(parents)) != len(parents):
                raise Refuted("duplicate prerequisite")
            if identifier not in payloads:
                raise Unavailable("reachable event payload absent")
            content = payloads[identifier]
            if type(content) is not dict:
                raise Refuted("retained event payload must be a JSON object")
            if _hash(statement["payload_digest"]) != "sha256:" + canonical_digest(content):
                raise Refuted("retained event payload commitment differs")
            visited.add(identifier)
            for parent_id in parents:
                budget.tick()
                edges += 1
                if type(parent_id) is not str or not parent_id.strip() or len(parent_id) > 256:
                    raise Refuted("bounded prerequisite identifier required")
                parent = by_id.get(parent_id)
                if parent is None or parent.kind.value != "EVENT":
                    raise Refuted("declared prerequisite is not a retained EVENT")
                parent_statement = _record(parent.payload, {
                    "scope", "sequence", "prerequisites", "payload_digest",
                }, "prerequisite payload")
                if _integer(parent_statement["sequence"], "prerequisite sequence") >= sequence:
                    raise Refuted("declared prerequisite does not precede event")
                pending.append(parent_id)
        if set(payloads) != visited:
            raise Refuted("retained payload map differs from selected event cone")
        return MechanismDecision(
            MechanismOutcome.PASS, "selected retained event prerequisites reproduced",
            {"events": len(visited), "edges": edges, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _EventPrerequisitesMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound event proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained event evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise EventPrerequisitesError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_EventPrerequisitesMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "EVENT", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "occurrence_authenticity": "NOT_ESTABLISHED",
        "physical_causality": "NOT_ESTABLISHED",
        "operand_truth": "NOT_ESTABLISHED",
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
        raise EventPrerequisitesError("certificate byte bound exhausted")
    return encoded


def build_event_prerequisites_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                 *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise EventPrerequisitesError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise EventPrerequisitesError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_event_prerequisites_certificate(certificate_bytes: bytes, *,
                                   expected_request: dict[str, Any],
                                   policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise EventPrerequisitesError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise EventPrerequisitesError("canonical certificate version differs")
        if value["request"] != selected:
            raise EventPrerequisitesError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise EventPrerequisitesError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise EventPrerequisitesError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, EventPrerequisitesError):
            raise
        raise EventPrerequisitesError("invalid retained event certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "EventPrerequisitesDescriptor",
    "EventPrerequisitesError", "registration", "event_prerequisites_policy",
    "event_prerequisites_request", "build_event_prerequisites_certificate",
    "recheck_event_prerequisites_certificate",
]
