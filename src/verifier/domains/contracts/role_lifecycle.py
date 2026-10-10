"""Current ROLE-2.1 finite selected lifecycle and occupancy protocol replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Endpoint statics are independent prerequisites;
native set and transition predicates check declared change, not actual history.
Counts and budgets are dimensionless, and retained limits are exact bytes.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
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
from verifier.domains.contracts import retained_selection, role_constraints


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ROLE-2.1"
REQUEST_VERSION = "verifier-current-role-lifecycle-request-1"
POLICY_VERSION = "verifier-current-role-lifecycle-policy-1"
CERTIFICATE_VERSION = "verifier-current-role-lifecycle-certificate-1"
EVIDENCE_VERSION = "verifier-current-role-lifecycle-evidence-1"
PROTOCOL_VERSION = "verifier-current-role-lifecycle-protocol-1"
MECHANISM_ID = "verifier.current-role.selected-lifecycle.1"
SCOPE = "finite_selected_role_lifecycle_occupancy_replay"
_CEILINGS = {
    "max_endpoints": 16, "max_items": 4096, "max_operations": 100000,
    "max_child_operations": 4800000, "max_child_certificate_bytes": 2 * 1024 * 1024,
    "max_evidence_bytes": 8 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_ENDPOINT_FIELDS = {"object_digest", "collection_digest", "child_request_digest",
                    "child_policy_digest", "child_certificate_digest"}


class RoleLifecycleError(ValueError):
    """Malformed selected lifecycle or a certificate that cannot reproduce."""


class RoleLifecycleUnavailable(OSError):
    """Retained checking capacity is unavailable; no semantic refusal."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "ROLE", "scope": SCOPE,
        "proposition": (
            "Every externally selected exact ROLE endpoint and complete typed collection "
            "passes its independently selected, freshly rechecked ROLE-3.1 prerequisite. "
            "The same ROLE class's remaining payload facets are preserved; ordered "
            "lifecycle-state pairs obey the externally selected finite protocol; every "
            "permission/scope addition and removal is permitted by that pair; and ordered "
            "declared taking/leaving events exactly reproduce each endpoint's selected "
            "finite ACTOR occupancy set."
        ),
        "prerequisites": [
            "externally selected exact endpoint ROLE/collection commitments and child request/policy/certificate digests",
            "retained ROLE-3.1 endpoint bytes and independently selected finite transition protocol",
            "installed source/specification policy, ordered occupancy events and finite checker limits",
        ],
        "exclusions": [
            "actual occurrence, complete historical event inventory, physical time or execution",
            "real-world authority, lifecycle-state meaning, permission issuance or enforcement",
            "human authenticity, actual occupancy, actor independence or decision attribution",
            "delegation, in-flight decisions, acting personally versus in role or complete hand-over semantics",
            "out-of-collection completeness, all required current .m obligations or whole ROLE dynamics tier",
            "object-profile conformance, privacy, consent, governance or security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class RoleLifecycleDescriptor:
    """One selected protocol proposition; no historical coordinate migration."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, RoleLifecycleError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, RoleLifecycleError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               common_module, retained_selection, role_constraints)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["CURRENT_ROLE_LIFECYCLE.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_ROLE_LIFECYCLE.md"
    return "sha256:" + canonical_digest({
        "sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in sorted(paths.items())},
        "endpoint_mechanism_digest": role_constraints.mechanism_digest(),
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=RoleLifecycleError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def role_lifecycle_policy(*, trust_roots: list[str],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest", "collection_digest",
        "endpoint_selections", "protocol_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "ROLE")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise RoleLifecycleError("selected ROLE lifecycle objective differs")
    for field in ("object_digest", "collection_digest", "protocol_digest", "evidence_ref", "policy_digest"):
        _hash(selected[field])
    if (type(selected["subject_id"]) is not str or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise RoleLifecycleError("bounded ROLE subject required")
    endpoints = selected["endpoint_selections"]
    if type(endpoints) is not list or not 2 <= len(endpoints) <= _CEILINGS["max_endpoints"]:
        raise RoleLifecycleError("two to sixteen externally selected endpoints required")
    owned = []
    for endpoint in endpoints:
        row = _record(endpoint, _ENDPOINT_FIELDS, "endpoint selection")
        for value in row.values():
            _hash(value)
        owned.append(row)
    selected["endpoint_selections"] = owned
    selected["limits"] = retained_selection.limits(selected["limits"], _CEILINGS, RoleLifecycleError)
    return selected


def role_lifecycle_request(*, subject_id: str, object_digest: str, collection_digest: str,
        endpoint_selections: list[dict[str, str]], protocol_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise RoleLifecycleError("unsupported lifecycle limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "object_kind": "ROLE",
        "subject_id": subject_id, "object_digest": object_digest, "collection_digest": collection_digest,
        "endpoint_selections": endpoint_selections, "protocol_digest": protocol_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode(value: Any, maximum: int) -> bytes:
    if type(value) is not str:
        raise Refuted("canonical retained base64 string required")
    if len(value) > 4 * ((maximum + 2) // 3):
        raise Unavailable("selected child byte bound exhausted")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted("invalid retained base64") from exc
    if len(decoded) > maximum:
        raise Unavailable("selected child byte bound exhausted")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted("noncanonical retained base64")
    return decoded


def _protocol(value: Any, budget: common_module.Budget) -> tuple[set[str], dict[tuple[str, str], dict[str, Any]]]:
    selected = _record(value, {"schema_version", "states", "transitions"}, "protocol")
    if selected["schema_version"] != PROTOCOL_VERSION:
        raise Unavailable("selected lifecycle protocol version unsupported")
    states = set(role_constraints._strings(selected["states"], budget, nonempty=True))
    rows = selected["transitions"]
    if type(rows) is not list:
        raise Refuted("protocol transitions must be a plain array")
    rules, order = {}, []
    for row in rows:
        budget.tick()
        rule = _record(row, {"from_state", "to_state", "add_permissions", "remove_permissions",
            "add_scopes", "remove_scopes", "allow_taking", "allow_leaving"}, "transition rule")
        pair = (role_constraints._text(rule["from_state"]), role_constraints._text(rule["to_state"]))
        if not set(pair) <= states or pair in rules:
            raise Refuted("transition pair references unselected state or is duplicated")
        for key in ("add_permissions", "remove_permissions", "add_scopes", "remove_scopes"):
            rule[key] = set(role_constraints._strings(rule[key], budget))
        if type(rule["allow_taking"]) is not bool or type(rule["allow_leaving"]) is not bool:
            raise Refuted("taking/leaving permissions must be plain booleans")
        rules[pair] = rule
        order.append(pair)
    if order != sorted(order):
        raise Refuted("selected transitions must be sorted by state pair")
    return states, rules


def _endpoint(value: Any, selection: dict[str, str], request: dict[str, Any],
              budget: common_module.Budget, reserved: list[int]) -> dict[str, Any]:
    endpoint = _record(value, {"child_request", "child_policy", "child_certificate"}, "endpoint")
    child_request, child_policy = endpoint["child_request"], endpoint["child_policy"]
    if child_request is not None and "sha256:" + canonical_digest(child_request) != selection["child_request_digest"]:
        raise Refuted("endpoint child request differs from external selection")
    if child_policy is not None and "sha256:" + canonical_digest(child_policy) != selection["child_policy_digest"]:
        raise Refuted("endpoint child policy differs from external selection")
    if child_request is not None and (type(child_request) is not dict or child_request.get("subject_id") != request["subject_id"]
            or child_request.get("object_kind") != "ROLE"
            or child_request.get("coordinate") != role_constraints.COORDINATE
            or child_request.get("semantic_version") != role_constraints.SEMANTIC_VERSION
            or child_request.get("object_digest") != selection["object_digest"]
            or child_request.get("collection_digest") != selection["collection_digest"]):
        raise Refuted("selected child is not the exact endpoint ROLE-3.1 prerequisite")
    if child_request is not None:
        child_request = role_constraints._request(child_request)
    if child_policy is not None:
        child_policy = role_constraints._policy(child_policy)
    certificate = None
    if endpoint["child_certificate"] is not None:
        certificate = _decode(endpoint["child_certificate"], request["limits"]["max_child_certificate_bytes"])
        if "sha256:" + hashlib.sha256(certificate).hexdigest() != selection["child_certificate_digest"]:
            raise Refuted("endpoint child certificate differs from external selection")
    if child_request is None or child_policy is None or certificate is None:
        raise Unavailable("selected endpoint prerequisite bytes absent")
    child_limits = retained_selection.limits(child_request.get("limits"), role_constraints._CEILINGS, RoleLifecycleError)
    reserved[0] += sum(child_limits[key] for key in
                       ("max_operations", "max_composition_operations", "max_relation_steps"))
    if reserved[0] > request["limits"]["max_child_operations"]:
        raise Unavailable("aggregate selected child operation ceilings exhausted")
    try:
        result = role_constraints.recheck_role_constraints_certificate(certificate,
            expected_request=child_request, policy=child_policy)
    except role_constraints.RoleConstraintsUnavailable as exc:
        raise Unavailable("selected endpoint checking capacity unavailable") from exc
    except ValueError as exc:
        raise Refuted("selected endpoint certificate does not reproduce") from exc
    if (type(result) is not dict or type(result.get("status")) is not str
            or result["status"] not in ("PASS", "FAIL", "UNKNOWN")
            or result.get("object_kind") != "ROLE" or result.get("scope") != role_constraints.SCOPE
            or result.get("coordinate") != role_constraints.COORDINATE
            or result.get("semantic_version") != role_constraints.SEMANTIC_VERSION
            or any(result.get(key) != "NOT_ESTABLISHED" for key in
                ("object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution"))):
        raise Refuted("endpoint native replay exceeds its selected proposition boundary")
    if result["status"] == "UNKNOWN":
        raise Unavailable("selected endpoint ROLE-3.1 prerequisite remains UNKNOWN")
    if result["status"] != "PASS":
        raise Refuted("selected endpoint ROLE-3.1 prerequisite did not pass")
    child = strict_json_loads(certificate.decode("utf-8"))
    child_data = _decode(child["evidence_payloads"][child_request["evidence_ref"]],
                         child_limits["max_evidence_bytes"])
    retained = strict_json_loads(child_data.decode("utf-8"))
    subject = next(row for row in retained["objects"] if row["object_id"] == request["subject_id"])
    if NamespaceObject.create(**subject).digest != selection["object_digest"]:
        raise Refuted("replayed endpoint record differs from exact selection")
    payload = subject["payload"]
    # Missing state blocks its transition rule, while independently replayed
    # fixed facets and occupancy remain usable for other native predicates.
    state = role_constraints._text(payload["lifecycle_state"]) if "lifecycle_state" in payload else None
    permissions = set(role_constraints._strings(payload["permissions"], budget))
    scopes = set(role_constraints._strings(payload["admitted_scopes"], budget))
    occupants = {row["actor_id"] for row in retained["inputs"]["matrix"]["occupancies"]
                 if row["role_id"] == request["subject_id"]}
    budget.tick(len(retained["objects"]) + len(retained["inputs"]["matrix"]["occupancies"]))
    fixed = {key: value for key, value in payload.items()
             if key not in {"lifecycle_state", "permissions", "admitted_scopes"}}
    return {"state": state, "permissions": permissions, "scopes": scopes,
            "occupants": occupants, "fixed": canonical_bytes(fixed)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        role_constraints._preflight_depth(data)
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "protocol", "endpoints", "events"}, "lifecycle evidence")
        if value["schema_version"] != EVIDENCE_VERSION:
            raise Unavailable("selected lifecycle evidence version unsupported")
        if canonical_bytes(value) != data:
            raise Refuted("retained lifecycle evidence is not canonical")
        limits = request["limits"]
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        selections = request["endpoint_selections"]
        if len(selections) > limits["max_endpoints"]:
            raise Unavailable("selected endpoint count exhausted")
        if (selections[-1]["object_digest"] != request["object_digest"]
                or selections[-1]["collection_digest"] != request["collection_digest"]):
            raise Refuted("final endpoint differs from selected current ROLE and collection")
        # Missing independent support is accumulated; available commitments,
        # native prerequisites and local predicates can still refute the claim.
        unavailable: list[str] = []
        states, rules = None, None
        if value["protocol"] is None:
            unavailable.append("retained lifecycle protocol absent")
        else:
            if "sha256:" + canonical_digest(value["protocol"]) != request["protocol_digest"]:
                raise Refuted("retained protocol differs from independent selection")
            try:
                states, rules = _protocol(value["protocol"], budget)
            except Unavailable as exc:
                if budget.used > budget.limit:
                    raise
                unavailable.append(str(exc))
        endpoints, events = value["endpoints"], value["events"]
        if endpoints is None:
            unavailable.append("retained lifecycle endpoints absent")
            endpoints = []
        if events is None:
            unavailable.append("retained lifecycle events absent")
            events = []
        if type(endpoints) is not list or type(events) is not list:
            raise Refuted("endpoint and event arrays required")
        if len(endpoints) < len(selections) or len(events) < len(selections) - 1:
            unavailable.append("selected endpoint or ordered event omitted")
        if len(endpoints) > len(selections) or len(events) > len(selections) - 1:
            raise Refuted("retained endpoint or event inventory exceeds selection")
        reserved = [0]
        snapshots: list[dict[str, Any] | None] = [None] * len(selections)
        for position, (endpoint, selection) in enumerate(zip(endpoints, selections)):
            try:
                snapshots[position] = _endpoint(endpoint, selection, request, budget, reserved)
                if snapshots[position]["state"] is None:
                    unavailable.append("selected ROLE lifecycle state declaration absent")
            except Unavailable as exc:
                if budget.used > budget.limit:
                    raise
                unavailable.append(str(exc))
        checked_events = []
        for position, event in enumerate(events, 1):
            selected_event = _record(event, {"position", "taking", "leaving"}, "occupancy event")
            if type(selected_event["position"]) is not int or selected_event["position"] != position:
                raise Refuted("occupancy event position differs from selected endpoint order")
            checked_events.append((set(role_constraints._strings(selected_event["taking"], budget)),
                                   set(role_constraints._strings(selected_event["leaving"], budget))))
        taking_count, leaving_count = 0, 0
        occupancy = set(snapshots[0]["occupants"]) if snapshots[0] is not None else None
        for position, (before, after) in enumerate(zip(snapshots, snapshots[1:])):
            budget.tick()
            if before is None or after is None:
                occupancy = None
                continue
            if before["fixed"] != after["fixed"]:
                raise Refuted("nonmutable ROLE class payload facets changed")
            rule = None
            if rules is not None and states is not None:
                if (before["state"] is not None and before["state"] not in states
                        or after["state"] is not None and after["state"] not in states):
                    raise Refuted("endpoint declares a state absent from selected protocol")
                if before["state"] is not None and after["state"] is not None:
                    rule = rules.get((before["state"], after["state"]))
                    if rule is None:
                        raise Refuted("declared lifecycle state transition is not selected as legal")
            if rule is not None:
                for field, suffix in (("permissions", "permissions"), ("scopes", "scopes")):
                    additions = after[field] - before[field]
                    removals = before[field] - after[field]
                    budget.tick(len(before[field]) + len(after[field]))
                    if not additions <= rule["add_" + suffix] or not removals <= rule["remove_" + suffix]:
                        raise Refuted("declared permission or scope change exceeds selected transition rule")
            if position >= len(checked_events):
                occupancy = None
                continue
            taking, leaving = checked_events[position]
            if (taking != after["occupants"] - before["occupants"]
                    or leaving != before["occupants"] - after["occupants"]):
                raise Refuted("declared taking/leaving events differ from exact endpoint occupancy changes")
            if rule is not None and (taking and not rule["allow_taking"] or leaving and not rule["allow_leaving"]):
                raise Refuted("declared taking or leaving is forbidden by selected transition rule")
            local_occupancy = (before["occupants"] - leaving) | taking
            if local_occupancy != after["occupants"]:
                raise Refuted("ordered occupancy event replay does not reproduce endpoint")
            if occupancy is not None:
                occupancy = (occupancy - leaving) | taking
                if occupancy != after["occupants"]:
                    raise Refuted("ordered occupancy chain does not reproduce endpoint")
            taking_count += len(taking)
            leaving_count += len(leaving)
        if unavailable:
            raise Unavailable("; ".join(sorted(set(unavailable))))
        return MechanismDecision(MechanismOutcome.PASS,
            "selected finite ROLE lifecycle and ordered occupancy reproduced", {
                "endpoints": len(snapshots), "transitions": len(events),
                "taking": taking_count, "leaving": leaving_count, "operations": budget.used,
                "child_operations_reserved": reserved[0]})
    except (Unavailable, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, IndexError, StopIteration) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _RoleLifecycleMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound ROLE lifecycle proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected lifecycle bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise RoleLifecycleError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_RoleLifecycleMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ROLE", "scope": SCOPE,
        "evaluation": evaluation.to_dict(), **{field: "NOT_ESTABLISHED" for field in (
            "object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution",
            "historical_occurrence", "enforcement", "actual_occupancy")}}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise RoleLifecycleError("certificate byte bound exhausted")
    return encoded


def build_role_lifecycle_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise RoleLifecycleError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise RoleLifecycleError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_role_lifecycle_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise RoleLifecycleError("bounded immutable lifecycle certificate bytes required")
    try:
        role_constraints._preflight_depth(certificate_bytes)
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
            "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise RoleLifecycleError("selected canonical lifecycle certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise RoleLifecycleError("retained lifecycle evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise RoleLifecycleError("lifecycle certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise RoleLifecycleUnavailable("retained certificate checking capacity unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, RoleLifecycleError):
            raise
        raise RoleLifecycleError("invalid retained lifecycle certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROTOCOL_VERSION", "PROPOSITION_DIGEST", "SCOPE", "RoleLifecycleDescriptor", "RoleLifecycleError", "RoleLifecycleUnavailable",
    "registration", "mechanism_digest", "role_lifecycle_policy", "role_lifecycle_request",
    "build_role_lifecycle_certificate", "recheck_role_lifecycle_certificate"]
