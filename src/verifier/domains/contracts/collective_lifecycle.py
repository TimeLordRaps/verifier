"""Current COLLECTIVE-2.1 finite retained ROLE admission/departure replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Times are integer microseconds on an externally
selected declared clock; counts are dimensionless and byte bounds count bytes.
Every exact endpoint replays its independently selected COLLECTIVE-3.1 child.
Membership changes are computed, not inferred from a carried PASS. This checks
declarations only: votes, authority, physical timing and execution stay unknown.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import collective_constraints as statics


SEMANTIC_VERSION = statics.SEMANTIC_VERSION
COORDINATE = "COLLECTIVE-2.1"
REQUEST_VERSION = "verifier-current-collective-lifecycle-request-1"
POLICY_VERSION = "verifier-current-collective-lifecycle-policy-1"
CERTIFICATE_VERSION = "verifier-current-collective-lifecycle-certificate-1"
EVIDENCE_VERSION = "verifier-current-collective-lifecycle-evidence-1"
MECHANISM_ID = "verifier.current-collective.role-lifecycle.1"
SCOPE = "finite_selected_collective_role_admission_departure_replay"
_CEILINGS = {
    "max_operations": 1000000, "max_items": 4096, "max_events": 64,
    "max_evidence_bytes": 16 * 1024 * 1024, "max_depth": 64,
    "max_child_certificate_bytes": 8 * 1024 * 1024,
    "max_child_operations": 1000000, "max_child_composition_operations": 1000000,
}
_MAX_CERTIFICATE_BYTES = 32 * 1024 * 1024
_EVENT_FIELDS = {"position", "event_id", "time_us", "action", "role_id", "role_digest"}


class CollectiveLifecycleError(ValueError):
    """Malformed external lifecycle selection or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "COLLECTIVE", "scope": SCOPE,
        "proposition": (
            "The exact externally selected chronological finite ROLE ADMIT/DEPART "
            "inventory on one declared clock reproduces the selected COLLECTIVE "
            "membership and exact typed collection at every independently selected, "
            "rechecked COLLECTIVE-3.1 endpoint. Each step adds or removes exactly the "
            "selected ROLE record; persistent records, charter, quorum and other "
            "subject fields remain byte-identical, and every endpoint's quorum is feasible."
        ),
        "prerequisites": [
            "external event inventory and declared clock, exact ordered endpoint times, "
            "child certificate commitments, independently selected child requests and "
            "policies, retained endpoint certificates, installed mechanisms and finite limits"
        ],
        "exclusions": [
            "real membership completeness, exhaustive event capture or required objective inventory",
            "ROLE occupants, actor or person independence, authentic human decisions or votes",
            "charter/quorum updates, arbitrary role-record edits or unrelated collection changes",
            "governance authorization, legal authority, signature admission or enforcement",
            "physical clocks, historical or actual execution and real causality",
            "complete dynamics tier, object-profile or nine-tier conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class CollectiveLifecycleDescriptor:
    """Native metadata for the exact retained membership-transition predicate."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    try:
        return statics._record(value, fields, label)
    except ValueError as exc:
        raise CollectiveLifecycleError(str(exc)) from exc


def _hash(value: Any) -> str:
    try:
        return statics._hash(value)
    except ValueError as exc:
        raise CollectiveLifecycleError(str(exc)) from exc


def _name(value: Any) -> str:
    try:
        return statics._name(value)
    except ValueError as exc:
        raise CollectiveLifecycleError(str(exc)) from exc


def _time(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise CollectiveLifecycleError("bounded integer declared microsecond time required")
    return value


def mechanism_digest() -> str:
    return "sha256:" + canonical_digest({
        "static_mechanism": statics.mechanism_digest(),
        __name__: hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "CURRENT_COLLECTIVE_LIFECYCLE.md": hashlib.sha256(
            (Path(__file__).parents[2] / "standard" / "CURRENT_COLLECTIVE_LIFECYCLE.md").read_bytes()
        ).hexdigest(),
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes", "clock_id", "time_unit", "selected_events"}, "policy")
    if (policy["schema_version"] != POLICY_VERSION or policy["mechanism_id"] != MECHANISM_ID
            or _hash(policy["mechanism_digest"]) != mechanism_digest()):
        raise CollectiveLifecycleError("policy differs from installed lifecycle mechanism")
    _name(policy["clock_id"])
    if policy["time_unit"] != "microsecond":
        raise CollectiveLifecycleError("selected declared time unit unsupported")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise CollectiveLifecycleError("bounded sorted distinct trust-root labels required")
    if (type(policy["max_certificate_bytes"]) is not int
            or not 1 <= policy["max_certificate_bytes"] <= _MAX_CERTIFICATE_BYTES):
        raise CollectiveLifecycleError("certificate byte bound unsupported")
    events = policy["selected_events"]
    if type(events) is not list or len(events) > _CEILINGS["max_events"]:
        raise CollectiveLifecycleError("bounded external event inventory required")
    selected = []
    for raw in events:
        event = _record(raw, _EVENT_FIELDS, "selected event")
        if type(event["position"]) is not int or not 0 <= event["position"] <= 64:
            raise CollectiveLifecycleError("bounded integer event position required")
        _time(event["time_us"])
        for key in ("event_id", "action", "role_id"):
            _name(event[key])
        _hash(event["role_digest"])
        selected.append(event)
    policy["selected_events"], policy["trust_roots"] = selected, list(roots)
    return policy


def collective_lifecycle_policy(*, trust_roots: list[str], clock_id: str,
                                selected_events: list[dict[str, Any]],
                                max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "clock_id": clock_id,
        "time_unit": "microsecond", "selected_events": selected_events})


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref",
        "policy_digest", "endpoints", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "COLLECTIVE")):
        if type(request[field]) is not str or request[field] != expected:
            raise CollectiveLifecycleError("selected COLLECTIVE lifecycle objective differs")
    _name(request["subject_id"])
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    limits = _record(request["limits"], set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= maximum
           for key, maximum in _CEILINGS.items()):
        raise CollectiveLifecycleError("finite lifecycle bound unsupported")
    endpoints = request["endpoints"]
    if type(endpoints) is not list or not 1 <= len(endpoints) <= 65:
        raise CollectiveLifecycleError("bounded independent endpoint selections required")
    selected = []
    for raw in endpoints:
        endpoint = _record(raw, {"time_us", "certificate_ref", "static_request", "static_policy"}, "endpoint")
        _time(endpoint["time_us"])
        _hash(endpoint["certificate_ref"])
        try:
            child_request, child_policy = statics._request(endpoint["static_request"]), statics._policy(endpoint["static_policy"])
        except ValueError as exc:
            raise CollectiveLifecycleError("independently selected static prerequisite differs") from exc
        if (child_request["subject_id"] != request["subject_id"]
                or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
            raise CollectiveLifecycleError("endpoint differs from selected subject or child policy")
        endpoint["static_request"], endpoint["static_policy"] = child_request, child_policy
        selected.append(endpoint)
    terminal = selected[-1]["static_request"]
    if (terminal["object_digest"] != request["object_digest"]
            or terminal["collection_digest"] != request["collection_digest"]):
        raise CollectiveLifecycleError("terminal endpoint differs from selected subject or collection")
    request["limits"], request["endpoints"] = limits, selected
    return request


def collective_lifecycle_request(*, subject_id: str, object_digest: str,
                                 collection_digest: str, evidence_ref: str,
                                 endpoints: list[dict[str, Any]], policy: dict[str, Any],
                                 limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise CollectiveLifecycleError("unsupported lifecycle limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "object_kind": "COLLECTIVE",
        "subject_id": subject_id, "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "endpoints": endpoints, "limits": {**_CEILINGS, **(limits or {})}})


def _child_objects(certificate: bytes, endpoint: dict[str, Any], budget: common_module.Budget
                   ) -> dict[str, NamespaceObject]:
    envelope = strict_json_loads(certificate.decode("utf-8"))
    store = EvidenceStore()
    store.import_base64(envelope["evidence_payloads"])
    evidence = strict_json_loads(store.resolve(endpoint["static_request"]["evidence_ref"]).decode("utf-8"))
    common_module.inspect_structure(evidence, budget)
    objects = [NamespaceObject.create(**row) for row in evidence["objects"]]
    return {obj.object_id: obj for obj in objects}


def _transition(before: dict[str, NamespaceObject], after: dict[str, NamespaceObject],
                event: dict[str, Any], subject_id: str, budget: common_module.Budget) -> None:
    budget.tick(len(before) + len(after))
    initial, final = before[subject_id], after[subject_id]
    members = set(dict(initial.operands)["roles"])
    role_id = event["role_id"]
    if role_id == subject_id:
        raise Refuted("ROLE event cannot name the COLLECTIVE subject")
    if event["action"] == "ADMIT":
        if role_id in members or role_id in before:
            raise Refuted("admission must add a previously absent ROLE record")
        role = after.get(role_id)
        expected_ids = set(before) | {role_id}
        members.add(role_id)
    elif event["action"] == "DEPART":
        if role_id not in members:
            raise Refuted("departure must remove an admitted ROLE")
        role = before.get(role_id)
        expected_ids = set(before) - {role_id}
        members.remove(role_id)
    else:
        raise Unavailable("unsupported selected lifecycle action")
    if role is None or role.kind.value != "ROLE" or role.digest != event["role_digest"]:
        raise Refuted("transition ROLE record differs from external event selection")
    if set(after) != expected_ids:
        raise Refuted("transition changes undeclared collection records")
    for identifier in (set(before) & set(after)) - {subject_id}:
        budget.tick()
        if canonical_bytes(before[identifier].to_dict()) != canonical_bytes(after[identifier].to_dict()):
            raise Refuted("persistent ROLE or unrelated record changed outside transition")
    ordered = sorted(members)
    membership = [{"role_id": identifier, "role_digest": after[identifier].digest} for identifier in ordered]
    expected = deepcopy(initial.to_dict())
    expected["operands"]["roles"] = ordered
    expected["payload"]["static_constraints"]["membership_digest"] = "sha256:" + canonical_digest(membership)
    if canonical_bytes(final.to_dict()) != canonical_bytes(expected):
        raise Refuted("endpoint membership, frozen charter/quorum or other subject fields differ")
    quorum = final.payload["static_constraints"]["quorum"]
    if type(quorum) is not int or not 1 <= quorum <= len(ordered):
        raise Refuted("replayed endpoint quorum is infeasible")


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        statics._depth(data, limits["max_depth"])
        value = strict_json_loads(data.decode("utf-8"))
        if (type(value) is not dict or set(value) - {"schema_version", "clock_id", "events", "endpoint_certificates"}
                or value.get("schema_version") != EVIDENCE_VERSION or canonical_bytes(value) != data):
            raise Refuted("retained lifecycle version, shape or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        selected = policy["selected_events"]
        endpoints = request["endpoints"]
        if not selected:
            raise Unavailable("at least one selected membership transition required")
        if len(selected) > limits["max_events"]:
            raise Unavailable("selected event bound exhausted")
        if len(endpoints) != len(selected) + 1:
            raise Refuted("selected endpoint inventory does not cover each selected transition")
        seen = set()
        for position, event in enumerate(selected):
            budget.tick()
            if event["position"] != position or event["event_id"] in seen:
                raise Refuted("selected event positions or identifiers are not unique and contiguous")
            seen.add(event["event_id"])
            if (event["time_us"] != endpoints[position + 1]["time_us"]
                    or endpoints[position]["time_us"] >= event["time_us"]):
                raise Refuted("selected endpoint/event chronology differs on declared clock")
        missing = []
        for field in ("clock_id", "events"):
            if value.get(field) is None:
                missing.append(field)
            elif canonical_bytes(value[field]) != canonical_bytes(policy[field] if field == "clock_id" else selected):
                raise Refuted("retained clock or complete selected event inventory differs")
        certificates = value.get("endpoint_certificates")
        if certificates is None:
            raise Unavailable("retained endpoint certificates absent")
        if type(certificates) is not list or len(certificates) > len(endpoints):
            raise Refuted("retained endpoint certificate inventory differs")
        states: list[dict[str, NamespaceObject] | None] = []
        reserved_ops = reserved_composition = 0
        for position, endpoint in enumerate(endpoints):
            encoded = certificates[position] if position < len(certificates) else None
            if encoded is None:
                states.append(None)
                missing.append("endpoint " + str(position))
                continue
            if type(encoded) is not str:
                raise Refuted("retained endpoint encoding must be base64 text")
            certificate = base64.b64decode(encoded, validate=True)
            if len(certificate) > limits["max_child_certificate_bytes"]:
                raise Unavailable("selected child certificate byte bound exhausted")
            budget.tick(len(certificate))
            if "sha256:" + hashlib.sha256(certificate).hexdigest() != endpoint["certificate_ref"]:
                raise Refuted("retained endpoint certificate differs from external commitment")
            child_request = endpoint["static_request"]
            reserved_ops += child_request["limits"]["max_operations"]
            reserved_composition += child_request["limits"]["max_composition_operations"]
            if (reserved_ops > limits["max_child_operations"]
                    or reserved_composition > limits["max_child_composition_operations"]):
                raise Unavailable("aggregate selected child operation bound exhausted")
            try:
                child = statics.recheck_collective_constraints_certificate(certificate,
                    expected_request=child_request, policy=endpoint["static_policy"])
            except statics.CollectiveConstraintsUnavailable as exc:
                states.append(None)
                missing.append("unavailable static endpoint " + str(position) + ": " + str(exc))
                continue
            except ValueError as exc:
                raise Refuted("selected static child does not reproduce exactly") from exc
            if child["status"] == "FAIL":
                raise Refuted("selected static endpoint is refuted")
            if child["status"] != "PASS":
                states.append(None)
                missing.append("unavailable static endpoint " + str(position))
                continue
            states.append(_child_objects(certificate, endpoint, budget))
        for position, event in enumerate(selected):
            before, after = states[position], states[position + 1]
            if before is not None and after is not None:
                _transition(before, after, event, request["subject_id"], budget)
        if missing:
            raise Unavailable("required retained lifecycle support absent: " + ", ".join(missing))
        return MechanismDecision(MechanismOutcome.PASS,
            "selected retained COLLECTIVE membership transitions reproduced",
            {"events_replayed": len(selected), "endpoints_rechecked": len(endpoints),
             "clock_id": policy["clock_id"], "time_unit": "microsecond", "operations": budget.used,
             "child_operation_bound_reserved": reserved_ops,
             "child_composition_bound_reserved": reserved_composition})
    except (Unavailable, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind",
        "object_digest", "collection_digest", "policy_digest")},
        "endpoint_selection_digest": "sha256:" + canonical_digest(request["endpoints"]),
        "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _CollectiveLifecycleMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound lifecycle proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained lifecycle bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise CollectiveLifecycleError("request differs from selected lifecycle policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_CollectiveLifecycleMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "COLLECTIVE", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "whole_tier_conformance": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED",
        "real_event_completeness": "NOT_ESTABLISHED", "physical_clock": "NOT_ESTABLISHED",
        "actual_quorum_decision": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise CollectiveLifecycleError("certificate byte bound exhausted")
    return encoded


def build_collective_lifecycle_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                           *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise CollectiveLifecycleError("immutable bounded lifecycle evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise CollectiveLifecycleError("retained evidence differs from selected bytes")
    return _build(selected, admitted, store)


def recheck_collective_lifecycle_certificate(certificate_bytes: bytes, *,
                                             expected_request: dict[str, Any],
                                             policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise CollectiveLifecycleError("bounded immutable lifecycle certificate required")
    try:
        statics._depth(certificate_bytes, 128)
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
            "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (value["schema_version"] != CERTIFICATE_VERSION or canonical_bytes(value) != certificate_bytes
                or value["request"] != selected):
            raise CollectiveLifecycleError("certificate differs from selected canonical lifecycle")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise CollectiveLifecycleError("retained lifecycle evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise CollectiveLifecycleError("lifecycle certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, CollectiveLifecycleError):
            raise
        raise CollectiveLifecycleError("invalid retained lifecycle certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "CollectiveLifecycleDescriptor", "CollectiveLifecycleError",
    "registration", "mechanism_digest", "collective_lifecycle_policy", "collective_lifecycle_request",
    "build_collective_lifecycle_certificate", "recheck_collective_lifecycle_certificate"]
