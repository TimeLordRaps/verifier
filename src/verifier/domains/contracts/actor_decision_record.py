"""Versioned current ACTOR decision-record retention certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions, decision counts and operation counts
are dimensionless; byte ceilings count encoded bytes. This check compares two
externally selected, retained, finite decision records across a declared window
of ending events; it does not establish that any decision happened.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
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


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ACTOR-3.3"
REQUEST_VERSION = "verifier-current-actor-decision-record-request-1"
POLICY_VERSION = "verifier-current-actor-decision-record-policy-1"
CERTIFICATE_VERSION = "verifier-current-actor-decision-record-certificate-1"
EVIDENCE_VERSION = "verifier-current-actor-decision-record-evidence-1"
MECHANISM_ID = "verifier.current-actor.decision-record-retention.1"
SCOPE = "finite_retained_decision_records_across_ending_events"
OBLIGATION_ROW = (
    "Past decisions remain the actor's own after revocation, rotation or "
    "dissolution. Ending an actor's capacity to decide never ends its record "
    "of having decided."
)
_INPUTS = ("earlier", "events", "later")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_POSITION = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_decisions": 4096, "max_events": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_EVENT_FIELDS = {
    "delegation": {"position", "event", "delegation_id", "delegator", "delegate",
                   "subset", "interval"},
    "revocation": {"position", "event", "delegation_id"},
    "rotation": {"position", "event", "actor", "prior_key", "key"},
    "dissolution": {"position", "event", "actor"},
}
# Declared ACTOR dynamics events this row does not name; a window holding one is
# outside this proposition rather than refuting it.
_OUTSIDE_SCOPE = ("membership", "succession_end", "succession_begin")
_ENDING = ("revocation", "rotation", "dissolution")


class ActorDecisionRecordError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "ACTOR",
        "scope": SCOPE,
        "obligation_row": OBLIGATION_ROW,
        "proposition": (
            "The externally selected exact ACTOR namespace record occurs in the "
            "selected finite typed collection; the externally selected retained "
            "earlier decision record, declared event window and later decision record "
            "rehash exactly; every decision and event actor resolves to a typed ACTOR "
            "record; the window lies after the earlier record and within the later "
            "record in strictly increasing position, holds only delegation, revocation, "
            "rotation and dissolution events, and holds at least one revocation, "
            "rotation or dissolution; the selected ACTOR has at least one earlier "
            "decision; and every earlier decision occurs in the later record with the "
            "same identifier, position, accountable actor and content commitment."
        ),
        "prerequisites": [
            "independently selected exact ACTOR record, collection, retained earlier "
            "and later decision records, declared event window, installed policy and "
            "finite checker limits",
            "decision factuality and non-transferable accountability as declared by "
            "the ACTOR-3.1 and ACTOR-3.2 rows; those rows are not emitted",
        ],
        "exclusions": [
            "emission of ACTOR-3.1, ACTOR-3.2 or any other prerequisite row",
            "that any recorded decision actually happened, or that either record is complete",
            "personhood of any represented human",
            "authenticity of the retained records or of the content commitments",
            "authority, legitimacy or legal effect of any decision or event",
            "consent of any party",
            "decisions added to the later record, including backdated insertions",
            "windows holding membership or succession events",
            "whole ACTOR statics tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ActorDecisionRecordDescriptor:
    """Native public route metadata for one retained retention proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise ActorDecisionRecordError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ActorDecisionRecordError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_ACTOR_DECISION_RECORD.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes",
    }, "policy")
    if (type(policy["schema_version"]) is not str
            or type(policy["mechanism_id"]) is not str
            or policy["schema_version"] != POLICY_VERSION
            or policy["mechanism_id"] != MECHANISM_ID):
        raise ActorDecisionRecordError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise ActorDecisionRecordError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise ActorDecisionRecordError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ActorDecisionRecordError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def actor_decision_record_policy(*, trust_roots: list[str],
                                 max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
           for key, ceiling in _CEILINGS.items()):
        raise ActorDecisionRecordError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "earlier_digest", "events_digest", "later_digest", "evidence_ref",
        "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "ACTOR"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise ActorDecisionRecordError("selected decision-record objective differs")
    for field in ("object_digest", "collection_digest", "earlier_digest", "events_digest",
                  "later_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise ActorDecisionRecordError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def actor_decision_record_request(*, subject_id: str, object_digest: str,
                                  collection_digest: str, earlier_digest: str,
                                  events_digest: str, later_digest: str,
                                  evidence_ref: str, policy: dict[str, Any],
                                  limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise ActorDecisionRecordError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ACTOR", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "earlier_digest": earlier_digest, "events_digest": events_digest,
        "later_digest": later_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise Refuted("bounded " + label + " text required")
    return value


def _position(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_POSITION:
        raise Refuted(label + " must be a bounded nonnegative integer")
    return value


def _commitment(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise Refuted(label + " is declared by SHA-256 commitment")
    return value


def _typed(by_id: dict[str, NamespaceObject], ref: Any, label: str) -> str:
    # Kind comes from the typed namespace record, never from an identifier label.
    if type(ref) is not str or ref not in by_id or by_id[ref].kind.value != "ACTOR":
        raise Refuted(label + " does not resolve to a typed ACTOR record")
    return ref


def _decisions(value: Any, by_id: dict[str, NamespaceObject], label: str,
               limits: dict[str, int], budget: common_module.Budget) -> tuple[int, dict[str, dict[str, Any]]]:
    record = _record(value, {"head_position", "decisions"}, label + " decision record")
    head = _position(record["head_position"], label + " head position")
    rows = record["decisions"]
    if type(rows) is not list:
        raise Refuted(label + " decisions must be an array")
    if len(rows) > limits["max_decisions"]:
        raise Unavailable("selected decision bound exhausted")
    decisions: dict[str, dict[str, Any]] = {}
    previous: int | None = None
    for row in rows:
        budget.tick()
        decision = _record(row, {"decision_id", "position", "actor", "content_digest"},
                           label + " decision")
        identifier = _text(decision["decision_id"], "decision identifier")
        if identifier in decisions:
            raise Refuted(label + " decision identifiers must be unique")
        position = _position(decision["position"], "decision position")
        if (previous is not None and position <= previous) or position > head:
            raise Refuted(label + " decisions must strictly increase in position up to its head")
        previous = position
        decisions[identifier] = {
            "position": position,
            "actor": _typed(by_id, decision["actor"], "decision actor"),
            "content_digest": _commitment(decision["content_digest"], "decision content"),
        }
    return head, decisions


def _retention(inputs: dict[str, Any], by_id: dict[str, NamespaceObject], subject: str,
               request: dict[str, Any], budget: common_module.Budget) -> dict[str, Any]:
    limits = request["limits"]
    for name in _INPUTS:
        if "sha256:" + canonical_digest(inputs[name]) != request[name + "_digest"]:
            raise Refuted("retained " + name + " differs from external selection")
    earlier_head, earlier = _decisions(inputs["earlier"], by_id, "earlier", limits, budget)
    later_head, later = _decisions(inputs["later"], by_id, "later", limits, budget)
    if later_head < earlier_head:
        raise Refuted("later decision record must not precede the earlier record")
    events = inputs["events"]
    if type(events) is not list:
        raise Refuted("declared events must be an array")
    if len(events) > limits["max_events"]:
        raise Unavailable("selected event bound exhausted")
    counts = {kind: 0 for kind in _EVENT_FIELDS}
    dissolved: set[str] = set()
    previous = earlier_head
    for row in events:
        budget.tick()
        if type(row) is not dict or type(row.get("event")) is not str:
            raise Refuted("declared event kind is not admitted")
        kind = row["event"]
        if kind in _OUTSIDE_SCOPE:
            raise Unavailable("declared " + kind + " event is outside this row's scope")
        if kind not in _EVENT_FIELDS:
            raise Refuted("declared event kind is not admitted")
        event = _record(row, _EVENT_FIELDS[kind], kind + " event")
        position = _position(event["position"], "event position")
        if position <= previous or position > later_head:
            raise Refuted("declared events must lie strictly between the records in "
                          "increasing position")
        previous = position
        counts[kind] += 1
        if kind == "delegation":
            _text(event["delegation_id"], "delegation identifier")
            delegator = _typed(by_id, event["delegator"], "delegator")
            if _typed(by_id, event["delegate"], "delegate") == delegator:
                raise Refuted("a delegation conveys authority to another actor")
            subset = event["subset"]
            if (type(subset) is not list or not subset
                    or [_text(name, "decision class") for name in subset] != sorted(set(subset))):
                raise Refuted("delegated subset must be nonempty, sorted and unique")
            interval = event["interval"]
            if (type(interval) is not list or len(interval) != 2
                    or _position(interval[0], "interval start") > _position(interval[1], "interval end")):
                raise Refuted("a delegation names its interval as an ordered start and end")
        elif kind == "revocation":
            _text(event["delegation_id"], "delegation identifier")
        elif kind == "rotation":
            _typed(by_id, event["actor"], "rotated actor")
            if (_commitment(event["prior_key"], "prior key")
                    == _commitment(event["key"], "rotated key")):
                raise Refuted("rotation replaces key material with different key material")
        else:
            actor = _typed(by_id, event["actor"], "dissolved actor")
            if actor in dissolved:
                raise Refuted("dissolved actor's capacity to decide has already ended")
            dissolved.add(actor)
    if not any(counts[kind] for kind in _ENDING):
        raise Unavailable("declared window holds no revocation, rotation or dissolution")
    subject_earlier = sum(1 for row in earlier.values() if row["actor"] == subject)
    if subject_earlier == 0:
        raise Unavailable("selected ACTOR has no earlier decision to retain")
    for identifier in sorted(earlier):
        budget.tick()
        before, after = earlier[identifier], later.get(identifier)
        if after is None:
            raise Refuted("an earlier decision is absent from the later record")
        if after["position"] != before["position"]:
            raise Refuted("an earlier decision was re-dated in the later record")
        if after["actor"] != before["actor"]:
            raise Refuted("an earlier decision's accountability moved to another actor")
        if after["content_digest"] != before["content_digest"]:
            raise Refuted("an earlier decision's content commitment changed")
    return {
        "earlier_decisions": len(earlier), "later_decisions": len(later),
        "subject_earlier_decisions": subject_earlier, "event_counts": counts,
        "earlier_head": earlier_head, "later_head": later_head,
    }


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        raw = strict_json_loads(data.decode("utf-8"))
        if type(raw) is dict and set(raw) == {"schema_version", "objects"}:
            if raw["schema_version"] != EVIDENCE_VERSION or canonical_bytes(raw) != data:
                raise Refuted("retained evidence version or canonical bytes differ")
            raise Unavailable("retained decision records absent")
        value = _record(raw, {"schema_version", "objects", "inputs"}, "evidence")
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
        if (len(matches) != 1 or matches[0].kind.value != "ACTOR"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained ACTOR subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        inputs = value["inputs"]
        if inputs is None:
            raise Unavailable("retained decision records absent")
        if type(inputs) is dict and set(inputs) < set(_INPUTS):
            raise Unavailable("retained earlier record, event window or later record absent")
        inputs = _record(inputs, set(_INPUTS), "retention inputs")
        by_id = {obj.object_id: obj for obj in objects}
        result = _retention(inputs, by_id, request["subject_id"], request, budget)
        return MechanismDecision(
            MechanismOutcome.PASS,
            "every earlier decision remains its actor's own in the later record",
            {"retention": result, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "earlier_digest", "events_digest",
            "later_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _ActorDecisionRecordMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound retention proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained decision-record evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ActorDecisionRecordError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ActorDecisionRecordMechanism(request, policy))
    evaluation = session.evaluate(binding)
    status = evaluation.outcome.value
    result = {
        "status": status, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ACTOR", "scope": SCOPE,
        "decision_record_retention": "PASS" if status == "PASS" else "NOT_ESTABLISHED",
        "whole_actor_statics_tier": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "personhood": "NOT_ESTABLISHED",
        "real_world_completeness": "NOT_ESTABLISHED",
        "record_authenticity": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "consent": "NOT_ESTABLISHED",
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
        raise ActorDecisionRecordError("certificate byte bound exhausted")
    return encoded


def build_actor_decision_record_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                            *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ActorDecisionRecordError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ActorDecisionRecordError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_actor_decision_record_certificate(certificate_bytes: bytes, *,
                                              expected_request: dict[str, Any],
                                              policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ActorDecisionRecordError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ActorDecisionRecordError("canonical certificate version differs")
        if value["request"] != selected:
            raise ActorDecisionRecordError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ActorDecisionRecordError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ActorDecisionRecordError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ActorDecisionRecordError):
            raise
        raise ActorDecisionRecordError("invalid retained decision-record certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "OBLIGATION_ROW", "SCOPE", "ActorDecisionRecordDescriptor",
    "ActorDecisionRecordError", "registration", "actor_decision_record_policy",
    "actor_decision_record_request", "build_actor_decision_record_certificate",
    "recheck_actor_decision_record_certificate",
]
