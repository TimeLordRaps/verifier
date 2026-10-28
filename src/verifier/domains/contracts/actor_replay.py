"""Versioned current ACTOR accountability replay certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions, event counts and operation counts are
dimensionless; byte ceilings count encoded bytes. This check replays one
externally selected, retained, finite declared event array; it does not
establish that the declared events happened, or happened completely.
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
COORDINATE = "ACTOR-2.7"
REQUEST_VERSION = "verifier-current-actor-replay-request-1"
POLICY_VERSION = "verifier-current-actor-replay-policy-1"
CERTIFICATE_VERSION = "verifier-current-actor-replay-certificate-1"
EVIDENCE_VERSION = "verifier-current-actor-replay-evidence-1"
MECHANISM_ID = "verifier.current-actor.accountability-replay.1"
SCOPE = "finite_retained_declared_actor_event_replay"
OBLIGATION_ROW = (
    "Replaying the declared events from the first reproduces the current "
    "delegation, key and membership state."
)
_INPUTS = ("base", "events", "state")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_POSITION = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_actors": 256, "max_events": 4096,
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
    "membership": {"position", "event", "actor", "collective", "change"},
    "dissolution": {"position", "event", "actor"},
    "succession_end": {"position", "event", "succession_id", "actor"},
    "succession_begin": {"position", "event", "succession_id", "actor", "keys",
                         "decision_classes"},
}


class ActorReplayError(ValueError):
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
            "selected finite typed collection and in the selected retained base "
            "declaration of actor keys and decision classes; the externally selected "
            "retained base, declared event array and current state rehash exactly; "
            "every actor and collective an event names resolves to a typed ACTOR or "
            "COLLECTIVE record; and replaying the declared events from the first, in "
            "strictly increasing stated positions under the declared delegation, "
            "revocation, key-rotation, membership, dissolution and paired-succession "
            "rules, reproduces exactly the retained current delegation, key and "
            "membership state."
        ),
        "prerequisites": [
            "independently selected exact ACTOR record, collection, retained base "
            "declaration, declared event array and current state bytes, installed "
            "policy and finite checker limits",
            "transition rules drawn from the declared ACTOR-2.1 to ACTOR-2.6 rows; "
            "those rows are prerequisites here and are not emitted",
        ],
        "exclusions": [
            "emission of ACTOR-2.1 through ACTOR-2.6 or of any other prerequisite row",
            "personhood of any represented human",
            "real-world completeness of the declared events, keys, classes or memberships",
            "authenticity of the retained records or of the key commitments",
            "authority, legitimacy or legal effect of any delegation, revocation, "
            "rotation, membership, dissolution or succession",
            "consent of any party",
            "decisions taken under a delegation and accountability for them",
            "delegation interval expiry, role-branch admission of members, key "
            "uniqueness across actors, and re-delegation of conveyed authority",
            "whole ACTOR dynamics tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ActorReplayDescriptor:
    """Native public route metadata for one retained replay proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise ActorReplayError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ActorReplayError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_ACTOR_REPLAY.md"):
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
        raise ActorReplayError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise ActorReplayError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise ActorReplayError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ActorReplayError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def actor_replay_policy(*, trust_roots: list[str],
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
        raise ActorReplayError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "base_digest", "events_digest", "state_digest", "evidence_ref",
        "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "ACTOR"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise ActorReplayError("selected accountability replay objective differs")
    for field in ("object_digest", "collection_digest", "base_digest", "events_digest",
                  "state_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise ActorReplayError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def actor_replay_request(*, subject_id: str, object_digest: str, collection_digest: str,
                         base_digest: str, events_digest: str, state_digest: str,
                         evidence_ref: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise ActorReplayError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ACTOR", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "base_digest": base_digest, "events_digest": events_digest,
        "state_digest": state_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise Refuted("bounded " + label + " text required")
    return value


def _position(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_POSITION:
        raise Refuted("stated event position must be a bounded nonnegative integer")
    return value


def _sorted_unique(value: Any, label: str, item) -> list[str]:
    if type(value) is not list or not value:
        raise Refuted(label + " must be a nonempty array")
    items = [item(entry) for entry in value]
    if items != sorted(set(items)):
        raise Refuted(label + " must be sorted and unique")
    return items


def _classes(value: Any) -> list[str]:
    return _sorted_unique(value, "decision classes", lambda entry: _text(entry, "decision class"))


def _keys(value: Any) -> list[str]:
    def commitment(entry: Any) -> str:
        if type(entry) is not str or _HASH.fullmatch(entry) is None:
            raise Refuted("key material is declared by SHA-256 commitment")
        return entry
    return _sorted_unique(value, "key commitments", commitment)


def _typed(by_id: dict[str, NamespaceObject], ref: Any, kind: str, label: str) -> str:
    # Kind comes from the typed namespace record, never from an identifier label.
    if type(ref) is not str or ref not in by_id or by_id[ref].kind.value != kind:
        raise Refuted(label + " does not resolve to a typed " + kind + " record")
    return ref


def _replay(inputs: dict[str, Any], by_id: dict[str, NamespaceObject], subject: str,
            request: dict[str, Any], budget: common_module.Budget) -> dict[str, Any]:
    limits = request["limits"]
    for name in _INPUTS:
        if "sha256:" + canonical_digest(inputs[name]) != request[name + "_digest"]:
            raise Refuted("retained " + name + " differs from external selection")
    base = _record(inputs["base"], {"keys", "decision_classes"}, "base declaration")
    declared_keys, declared_classes = base["keys"], base["decision_classes"]
    if (type(declared_keys) is not dict or type(declared_classes) is not dict
            or not declared_keys or set(declared_keys) != set(declared_classes)):
        raise Refuted("base keys and decision classes must declare one nonempty actor set")
    if len(declared_keys) > limits["max_actors"]:
        raise Unavailable("selected actor bound exhausted")
    keys: dict[str, list[str]] = {}
    classes: dict[str, list[str]] = {}
    for actor in sorted(declared_keys):
        budget.tick()
        _typed(by_id, actor, "ACTOR", "base actor")
        keys[actor] = _keys(declared_keys[actor])
        classes[actor] = _classes(declared_classes[actor])
    if subject not in keys:
        raise Refuted("selected ACTOR is absent from the base declaration")
    events = inputs["events"]
    if type(events) is not list:
        raise Refuted("declared events must be an array")
    if len(events) > limits["max_events"]:
        raise Unavailable("selected event bound exhausted")
    delegations: dict[str, dict[str, Any]] = {}
    used_delegations: set[str] = set()
    used_successions: set[str] = set()
    memberships: set[tuple[str, str]] = set()
    ended: set[str] = set()
    counts = {kind: 0 for kind in _EVENT_FIELDS}
    previous: int | None = None
    pending: tuple[int, str, str] | None = None
    for row in events:
        budget.tick()
        if type(row) is not dict or type(row.get("event")) is not str or row["event"] not in _EVENT_FIELDS:
            raise Refuted("declared event kind is not admitted")
        kind = row["event"]
        event = _record(row, _EVENT_FIELDS[kind], kind + " event")
        position = _position(event["position"])
        if pending is not None:
            if (kind != "succession_begin" or position != pending[0]
                    or event["succession_id"] != pending[1]):
                raise Refuted("succession must be a paired ending and beginning at one position")
        elif kind == "succession_begin":
            raise Refuted("succession beginning has no paired ending at its position")
        elif previous is not None and position <= previous:
            raise Refuted("declared event positions must strictly increase from the first")
        previous = position
        counts[kind] += 1
        if kind == "delegation":
            identifier = _text(event["delegation_id"], "delegation identifier")
            if identifier in used_delegations:
                raise Refuted("delegation identifier is reused")
            delegator = _typed(by_id, event["delegator"], "ACTOR", "delegator")
            delegate = _typed(by_id, event["delegate"], "ACTOR", "delegate")
            if delegator not in classes:
                raise Refuted("delegator is outside the replayed actor set")
            if delegator in ended:
                raise Refuted("delegator's capacity to decide has ended")
            if delegate == delegator:
                raise Refuted("a delegation conveys authority to another actor")
            subset = _classes(event["subset"])
            if not set(subset) <= set(classes[delegator]):
                conveyed = {name for live in delegations.values()
                            if live["delegate"] == delegator for name in live["subset"]}
                if set(subset) <= set(classes[delegator]) | conveyed:
                    raise Unavailable("re-delegation of conveyed authority is outside this scope")
                raise Refuted("delegated subset exceeds the delegator's declared decision classes")
            interval = event["interval"]
            if (type(interval) is not list or len(interval) != 2
                    or _position(interval[0]) > _position(interval[1])):
                raise Refuted("a delegation names its interval as an ordered start and end")
            used_delegations.add(identifier)
            delegations[identifier] = {
                "delegation_id": identifier, "delegator": delegator, "delegate": delegate,
                "subset": subset, "interval": list(interval),
            }
        elif kind == "revocation":
            identifier = _text(event["delegation_id"], "delegation identifier")
            if identifier not in delegations:
                raise Refuted("revocation names no live delegation")
            del delegations[identifier]
        elif kind == "rotation":
            actor = _typed(by_id, event["actor"], "ACTOR", "rotated actor")
            if actor not in keys:
                raise Refuted("rotation names an actor outside the replayed key state; "
                              "a rotation never mints a new actor")
            prior, new = _hash(event["prior_key"]), _hash(event["key"])
            if prior not in keys[actor]:
                raise Refuted("rotation prior key is not held by the actor")
            if new in keys[actor]:
                raise Refuted("rotation key is already held by the actor")
            keys[actor] = sorted((set(keys[actor]) - {prior}) | {new})
        elif kind == "membership":
            actor = _typed(by_id, event["actor"], "ACTOR", "member actor")
            collective = _typed(by_id, event["collective"], "COLLECTIVE", "collective")
            pair = (actor, collective)
            if event["change"] == "enter":
                if pair in memberships:
                    raise Refuted("actor already holds this membership")
                memberships.add(pair)
            elif event["change"] == "leave":
                if pair not in memberships:
                    raise Refuted("actor holds no such membership to leave")
                memberships.remove(pair)
            else:
                raise Refuted("membership change must be enter or leave")
        elif kind == "dissolution":
            actor = _typed(by_id, event["actor"], "ACTOR", "dissolved actor")
            if actor not in keys:
                raise Refuted("dissolution names an actor outside the replayed actor set")
            if actor in ended:
                raise Refuted("dissolved actor's capacity to decide has already ended")
            ended.add(actor)
        elif kind == "succession_end":
            identifier = _text(event["succession_id"], "succession identifier")
            if identifier in used_successions:
                raise Refuted("succession identifier is reused")
            actor = _typed(by_id, event["actor"], "ACTOR", "replaced actor")
            if actor not in keys or actor in ended:
                raise Refuted("succession ending names no active replayed actor")
            ended.add(actor)
            used_successions.add(identifier)
            pending = (position, identifier, actor)
            continue
        else:  # succession_begin, already paired with the pending ending above
            assert pending is not None
            actor = _typed(by_id, event["actor"], "ACTOR", "successor actor")
            if actor == pending[2]:
                raise Refuted("succession replaces the actor with another actor")
            if actor in keys:
                raise Refuted("successor must begin at the succession rather than before it")
            keys[actor] = _keys(event["keys"])
            classes[actor] = _classes(event["decision_classes"])
            pending = None
        if len(keys) > limits["max_actors"]:
            raise Unavailable("selected actor bound exhausted")
    if pending is not None:
        raise Refuted("succession ending has no paired beginning")
    replayed = {
        "delegations": [delegations[name] for name in sorted(delegations)],
        "keys": {actor: keys[actor] for actor in sorted(keys)},
        "memberships": [{"actor": actor, "collective": collective}
                        for actor, collective in sorted(memberships)],
    }
    state = _record(inputs["state"], {"delegations", "keys", "memberships"}, "current state")
    budget.tick(len(replayed["delegations"]) + len(replayed["keys"]) + len(replayed["memberships"]))
    if canonical_bytes(state) != canonical_bytes(replayed):
        raise Refuted("retained current state differs from the replay of the declared events")
    return {
        "event_counts": counts, "actors": len(keys),
        "live_delegations": len(delegations), "memberships": len(memberships),
        "state_digest": "sha256:" + canonical_digest(replayed),
    }


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        raw = strict_json_loads(data.decode("utf-8"))
        if type(raw) is dict and set(raw) == {"schema_version", "objects"}:
            if raw["schema_version"] != EVIDENCE_VERSION or canonical_bytes(raw) != data:
                raise Refuted("retained evidence version or canonical bytes differ")
            raise Unavailable("retained replay inputs absent")
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
            raise Unavailable("retained replay inputs absent")
        if type(inputs) is dict and set(inputs) < set(_INPUTS):
            raise Unavailable("retained base, events or current state absent")
        inputs = _record(inputs, set(_INPUTS), "replay inputs")
        by_id = {obj.object_id: obj for obj in objects}
        result = _replay(inputs, by_id, request["subject_id"], request, budget)
        return MechanismDecision(
            MechanismOutcome.PASS,
            "declared events replayed from the first reproduce the retained current state",
            {"replay": result, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "base_digest", "events_digest",
            "state_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _ActorReplayMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound replay proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained replay evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ActorReplayError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ActorReplayMechanism(request, policy))
    evaluation = session.evaluate(binding)
    status = evaluation.outcome.value
    result = {
        "status": status, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ACTOR", "scope": SCOPE,
        "accountability_replay": "PASS" if status == "PASS" else "NOT_ESTABLISHED",
        "whole_actor_dynamics_tier": "NOT_ESTABLISHED",
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
        raise ActorReplayError("certificate byte bound exhausted")
    return encoded


def build_actor_replay_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                   *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ActorReplayError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ActorReplayError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_actor_replay_certificate(certificate_bytes: bytes, *,
                                     expected_request: dict[str, Any],
                                     policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ActorReplayError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ActorReplayError("canonical certificate version differs")
        if value["request"] != selected:
            raise ActorReplayError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ActorReplayError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ActorReplayError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ActorReplayError):
            raise
        raise ActorReplayError("invalid retained replay certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "OBLIGATION_ROW", "SCOPE", "ActorReplayDescriptor",
    "ActorReplayError", "registration", "actor_replay_policy", "actor_replay_request",
    "build_actor_replay_certificate", "recheck_actor_replay_certificate",
]
