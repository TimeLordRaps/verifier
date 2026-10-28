"""Current EVENT-4.1: finite declared event-log closure over one selected head.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Sequence numbers, event counts and checker
budgets are dimensionless; evidence and certificate limits are bytes. The
parent replays one exact EVENT-3.1 child and adds no-orphan, no-gap and log
commitment clauses. This proves no historical occurrence or causality.
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
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import event_prerequisites, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "EVENT-4.1"
REQUEST_VERSION = "verifier-current-event-closure-request-1"
POLICY_VERSION = "verifier-current-event-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-event-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-event-closure-evidence-1"
LOG_VERSION = "verifier-current-event-closure-log-1"
MECHANISM_ID = "verifier.current-event.retained-log-closure.1"
SCOPE = "finite_declared_event_log_closure"
_MAX_SAFE_INTEGER = 2**53 - 1
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class EventClosureError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "EVENT", "scope": SCOPE,
        "proposition": (
            "The independently selected exact EVENT-3.1 child replays PASS; "
            "every EVENT record in its retained finite collection is the "
            "selected head or a transitive declared prerequisite of it; their "
            "dimensionless sequence numbers are exactly first_sequence through "
            "first_sequence plus the event count minus one, each once; and the "
            "recomputed ascending-sequence log commitment equals the selected "
            "log digest."),
        "prerequisites": [
            "exact separately selected EVENT-3.1 request, policy and retained "
            "certificate; child replay PASS; selected first sequence and log "
            "digest; finite checker limits"],
        "exclusions": [
            "actual historical occurrence, observer authenticity or physical causality",
            "completeness against events outside the selected collection",
            "logs with several heads or merged logs",
            "append-only behaviour or immutability over time",
            "truth of TIME, SPACE and meaning operands",
            "whole EVENT closure tier or object-profile conformance",
            "privacy, consent, governance and security admission"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class EventClosureDescriptor:
    """Native public route metadata for one declared event-log closure."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, EventClosureError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, EventClosureError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection,
               event_prerequisites)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_EVENT_PREREQUISITES.md",
                 "CURRENT_EVENT_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=EventClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def event_closure_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest",
        "child_request_digest", "child_policy_digest",
        "child_certificate_digest", "first_sequence", "log_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "EVENT")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise EventClosureError("selected EVENT closure objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise EventClosureError("bounded EVENT head identifier required")
    first = selected["first_sequence"]
    if type(first) is not int or not 0 <= first <= _MAX_SAFE_INTEGER:
        raise EventClosureError("first_sequence must be a nonnegative safe integer")
    for field in ("object_digest", "collection_digest",
                  "child_request_digest", "child_policy_digest",
                  "child_certificate_digest", "log_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, EventClosureError)
    return selected


def event_closure_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str,
        first_sequence: int, log_digest: str, evidence_ref: str,
        policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise EventClosureError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "EVENT",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "first_sequence": first_sequence, "log_digest": log_digest,
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


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "child_request", "child_policy",
                         "child_certificate"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained closure evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        child_request = value["child_request"]
        child_policy = value["child_policy"]
        if ("sha256:" + canonical_digest(child_request)
                != request["child_request_digest"]
                or "sha256:" + canonical_digest(child_policy)
                != request["child_policy_digest"]):
            raise Refuted("selected child request or policy differs")
        if (type(child_request) is not dict
                or child_request.get("subject_id") != request["subject_id"]
                or child_request.get("object_digest") != request["object_digest"]
                or child_request.get("collection_digest") != request["collection_digest"]
                or child_request.get("semantic_version") != event_prerequisites.SEMANTIC_VERSION
                or child_request.get("coordinate") != event_prerequisites.COORDINATE
                or child_request.get("object_kind") != "EVENT"):
            raise Refuted("child is not the selected EVENT-3.1 head")
        child_certificate = _decode_b64(value["child_certificate"], "child certificate")
        if len(child_certificate) > event_prerequisites._MAX_CERTIFICATE_BYTES:
            raise Unavailable("child certificate bound exhausted")
        if ("sha256:" + hashlib.sha256(child_certificate).hexdigest()
                != request["child_certificate_digest"]):
            raise Refuted("selected child certificate differs")
        try:
            child_result = event_prerequisites.recheck_event_prerequisites_certificate(
                child_certificate, expected_request=child_request,
                policy=child_policy)
        except event_prerequisites.EventPrerequisitesError as exc:
            raise Refuted("selected EVENT-3.1 child does not replay") from exc
        if child_result["status"] == "UNKNOWN":
            raise Unavailable("selected EVENT-3.1 child remains UNKNOWN")
        if child_result["status"] != "PASS":
            raise Refuted("selected EVENT-3.1 child did not pass")
        child = strict_json_loads(child_certificate.decode("utf-8"))
        child_data = _decode_b64(child["evidence_payloads"][child_request["evidence_ref"]],
                                 "child retained evidence")
        retained = strict_json_loads(child_data.decode("utf-8"))
        payloads = retained["inputs"]["payloads"]
        events = [row for row in retained["objects"] if row["kind"] == "EVENT"]
        if len(events) > limits["max_items"]:
            raise Unavailable("selected event log item bound exhausted")
        budget.tick(len(events) + len(payloads))
        identifiers = [row["object_id"] for row in events]
        if len(set(identifiers)) != len(identifiers):
            raise Refuted("retained collection repeats an EVENT identifier")
        # Clause 3: every retained EVENT is the head or in its declared cone.
        if set(identifiers) != set(payloads):
            raise Refuted("retained collection holds an EVENT outside the head's declared cone")
        # Clause 4: sequences are first_sequence onward, each exactly once.
        sequences = [row["payload"]["sequence"] for row in events]
        budget.tick(len(sequences) * (len(sequences).bit_length() + 1))
        first = request["first_sequence"]
        if sorted(sequences) != list(range(first, first + len(sequences))):
            raise Refuted("declared sequences have a gap or repeat from first_sequence")
        # Clause 5: recompute the ascending-sequence log commitment.
        rows = []
        for row in events:
            budget.tick()
            rows.append({"object_id": row["object_id"],
                         "object_digest": NamespaceObject.create(**row).digest,
                         "sequence": row["payload"]["sequence"]})
        log = sorted(rows, key=lambda row: row["sequence"])
        commitment = "sha256:" + canonical_digest({
            "schema_version": LOG_VERSION, "head_id": request["subject_id"],
            "first_sequence": request["first_sequence"], "events": log})
        if commitment != request["log_digest"]:
            raise Refuted("recomputed event log commitment differs from selected log digest")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected finite declared event log is closed and gapless",
            {"events": len(events), "first_sequence": first,
             "last_sequence": first + len(events) - 1,
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _EventClosureMechanism:
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
                                     "bound EVENT closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise EventClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_EventClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "EVENT", "scope": SCOPE,
        "declared_log_closure": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "occurrence_authenticity": "NOT_ESTABLISHED",
        "physical_causality": "NOT_ESTABLISHED",
        "completeness_outside_collection": "NOT_ESTABLISHED",
        "append_only": "NOT_ESTABLISHED",
        "operand_truth": "NOT_ESTABLISHED",
        "whole_event_closure": "NOT_ESTABLISHED",
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
        raise EventClosureError("certificate byte bound exhausted")
    return encoded


def build_event_closure_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise EventClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise EventClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_event_closure_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise EventClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise EventClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise EventClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise EventClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, EventClosureError):
            raise
        raise EventClosureError("invalid retained EVENT closure certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "LOG_VERSION", "PROPOSITION_DIGEST",
           "EventClosureDescriptor", "EventClosureError", "registration",
           "event_closure_policy", "event_closure_request",
           "build_event_closure_certificate", "recheck_event_closure_certificate"]
