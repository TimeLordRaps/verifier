"""Current EVENT-2.1: retained declared dispatch and acknowledgment log.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Log positions, counts and checker limits are
dimensionless; evidence and certificate limits are bytes. A retained
acknowledgment is a recorded log entry, not proof that a handler executed.
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
COORDINATE = "EVENT-2.1"
REQUEST_VERSION = "verifier-current-event-dispatch-request-1"
POLICY_VERSION = "verifier-current-event-dispatch-policy-1"
CERTIFICATE_VERSION = "verifier-current-event-dispatch-certificate-1"
EVIDENCE_VERSION = "verifier-current-event-dispatch-evidence-1"
MECHANISM_ID = "verifier.current-event.retained-dispatch-acknowledgment.1"
SCOPE = "finite_retained_declared_dispatch_and_acknowledgment"
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_OPERATIONS = {"emit": "topic", "dispatch": "handler", "ack": "handler"}


class EventDispatchError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "EVENT",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact EVENT namespace record occurs in the "
            "selected finite typed collection and commits to the retained "
            "finite handler declaration and ordered dispatch log; in that log "
            "each log-local event is emitted once, is dispatched exactly once "
            "to each declared handler whose subscribed topics contain its "
            "topic and to no other handler, every dispatch follows its "
            "emission and is acknowledged exactly once after the dispatch, "
            "and the retained final state equals the retained initial state "
            "updated by each acknowledged handler's declared writes in log "
            "order."
        ),
        "prerequisites": [
            "independently selected exact EVENT record and full finite "
            "collection, retained handler declaration and nonempty ordered "
            "log, installed policy and finite checker limits"
        ],
        "exclusions": [
            "actual emission, transport, delivery, handler execution or "
            "observer authenticity",
            "physical causality, wall-clock timing or truth of TIME, SPACE "
            "and meaning operands",
            "events, handlers or state outside the retained log and declaration",
            "whole EVENT dynamics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class EventDispatchDescriptor:
    """Native public route metadata for one declared dispatch proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, EventDispatchError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, EventDispatchError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_EVENT_DISPATCH.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=EventDispatchError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def event_dispatch_policy(*, trust_roots: list[str],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


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
            raise EventDispatchError("selected event dispatch objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise EventDispatchError("bounded subject identifier required")
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, EventDispatchError)
    return request


def event_dispatch_request(*, subject_id: str, object_digest: str,
                           collection_digest: str, evidence_ref: str,
                           policy: dict[str, Any],
                           limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise EventDispatchError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "EVENT", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _name(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise Refuted(label + " must be a bounded identifier")
    return value


def _state(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise Refuted(label + " must be a JSON object with plain keys")
    return dict(value)


def _handlers(value: Any, limits: dict[str, int],
              budget: common_module.Budget) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    if type(value) is not list:
        raise Refuted("declared handlers must be a sequence")
    if len(value) > limits["max_items"]:
        raise Unavailable("declared handler bound exhausted")
    handlers: dict[str, dict[str, Any]] = {}
    subscribers: dict[str, list[str]] = {}
    for row in value:
        budget.tick()
        handler = _record(row, {"id", "topics", "writes"}, "declared handler")
        identifier = _name(handler["id"], "handler identifier")
        if identifier in handlers:
            raise Refuted("handler identifier repeats")
        topics = handler["topics"]
        if type(topics) is not list or not topics:
            raise Refuted("handler subscription must be a nonempty topic sequence")
        budget.tick(len(topics))
        for topic in topics:
            _name(topic, "subscribed topic")
        if len(set(topics)) != len(topics):
            raise Refuted("handler subscription repeats a topic")
        handlers[identifier] = {"topics": set(topics),
                                "writes": _state(handler["writes"], "handler writes")}
        for topic in topics:
            subscribers.setdefault(topic, []).append(identifier)
    return handlers, subscribers


def _replay_log(inputs: dict[str, Any], limits: dict[str, int],
                budget: common_module.Budget) -> dict[str, int]:
    handlers, subscribers = _handlers(inputs["handlers"], limits, budget)
    state = _state(inputs["initial_state"], "retained initial state")
    final = _state(inputs["final_state"], "retained final state")
    log = inputs["log"]
    if type(log) is not list:
        raise Refuted("retained dispatch log must be a sequence")
    if len(log) > limits["max_items"]:
        raise Unavailable("retained log bound exhausted")
    if not log:
        raise Unavailable("nonempty retained dispatch log required")
    topic_of: dict[str, str] = {}
    pending: set[tuple[str, str]] = set()
    acknowledged: set[tuple[str, str]] = set()
    for row in log:
        budget.tick()
        if type(row) is not dict or type(row.get("op")) is not str or row["op"] not in _OPERATIONS:
            raise Refuted("log entry operation differs")
        entry = _record(row, {"op", "event", _OPERATIONS[row["op"]]}, "log entry")
        event = _name(entry["event"], "log-local event identifier")
        if entry["op"] == "emit":
            if event in topic_of:
                raise Refuted("log-local event is emitted more than once")
            topic_of[event] = _name(entry["topic"], "emitted topic")
            continue
        handler = _name(entry["handler"], "handler identifier")
        pair = (event, handler)
        if entry["op"] == "dispatch":
            if event not in topic_of:
                raise Refuted("dispatch precedes its emission or names an unemitted event")
            if handler not in handlers:
                raise Refuted("dispatch names an undeclared handler")
            if topic_of[event] not in handlers[handler]["topics"]:
                raise Refuted("event dispatched to a handler not subscribed to its topic")
            if pair in pending or pair in acknowledged:
                raise Refuted("event dispatched to one handler more than once")
            pending.add(pair)
            continue
        if pair in acknowledged:
            raise Refuted("dispatch acknowledged more than once")
        if pair not in pending:
            raise Refuted("acknowledgment precedes its dispatch or names no dispatch")
        pending.remove(pair)
        acknowledged.add(pair)
        budget.tick(len(handlers[handler]["writes"]))
        state.update(handlers[handler]["writes"])
    dispatched = 0
    for event, topic in topic_of.items():
        budget.tick()
        expected = subscribers.get(topic, [])
        budget.tick(len(expected))
        for handler in expected:
            if (event, handler) not in acknowledged and (event, handler) not in pending:
                raise Refuted("emitted event is not dispatched to a subscribed handler")
        dispatched += len(expected)
    if pending:
        raise Refuted("dispatch is never acknowledged")
    if canonical_bytes(state) != canonical_bytes(final):
        raise Refuted("retained final state differs from the declared write fold")
    return {"events": len(topic_of), "dispatches": dispatched,
            "acknowledgments": len(acknowledged)}


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
        if (len(matches) != 1 or matches[0].kind.value != "EVENT"
                or matches[0].digest != request["object_digest"]):
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
        statement = _record(matches[0].payload, {"scope", "dispatch_digest"}, "event payload")
        if statement["scope"] != "retained-event-dispatch":
            raise Refuted("event scope differs")
        if value["inputs"] is None:
            raise Unavailable("retained dispatch declaration and log absent")
        inputs = _record(value["inputs"], {"handlers", "initial_state", "log", "final_state"},
                         "dispatch inputs")
        if _hash(statement["dispatch_digest"]) != "sha256:" + canonical_digest(inputs):
            raise Refuted("retained dispatch commitment differs")
        counts = _replay_log(inputs, limits, budget)
        return MechanismDecision(
            MechanismOutcome.PASS, "selected retained dispatch log reproduced",
            {**counts, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _EventDispatchMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound event dispatch proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained dispatch evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise EventDispatchError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_EventDispatchMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "EVENT", "scope": SCOPE,
        "declared_dispatch_and_acknowledgment": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED"),
        "occurrence_authenticity": "NOT_ESTABLISHED",
        "handler_execution": "NOT_ESTABLISHED",
        "delivery_guarantee": "NOT_ESTABLISHED",
        "physical_causality": "NOT_ESTABLISHED",
        "operand_truth": "NOT_ESTABLISHED",
        "whole_event_dynamics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
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
        raise EventDispatchError("certificate byte bound exhausted")
    return encoded


def build_event_dispatch_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                     *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise EventDispatchError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise EventDispatchError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_event_dispatch_certificate(certificate_bytes: bytes, *,
                                       expected_request: dict[str, Any],
                                       policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise EventDispatchError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise EventDispatchError("canonical certificate version differs")
        if value["request"] != selected:
            raise EventDispatchError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise EventDispatchError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise EventDispatchError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, EventDispatchError):
            raise
        raise EventDispatchError("invalid retained event dispatch certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "EventDispatchDescriptor",
    "EventDispatchError", "registration", "event_dispatch_policy",
    "event_dispatch_request", "build_event_dispatch_certificate",
    "recheck_event_dispatch_certificate",
]
