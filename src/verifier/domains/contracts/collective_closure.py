"""Current COLLECTIVE-4.1 fixed-membership point-decision closure.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Declared microseconds are selected clock units, not observed physical timing.
This module changes no historical collective reader or whole-closure verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.core.namespace import NamespaceObject
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, role_closure, role_lifecycle
from verifier.domains.contracts import collective_constraints

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "COLLECTIVE-4.1"
REQUEST_VERSION = "verifier-current-collective-closure-request-1"
POLICY_VERSION = "verifier-current-collective-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-collective-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-collective-closure-evidence-1"
PROTOCOL_VERSION = "verifier-current-collective-point-decision-protocol-1"
MECHANISM_ID = "verifier.current-collective.selected-decision-closure.1"
SCOPE = "finite_selected_fixed_membership_collective_point_decision_closure"
_CEILINGS = {"max_roles": 256, "max_decisions": 4096, "max_items": 4096,
    "max_operations": 1000000, "max_child_operations": 32000000,
    "max_child_certificate_bytes": 16 * 1024 * 1024,
    "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024

class CollectiveClosureError(ValueError):
    """Malformed independent selection or nonreproducing retained certificate."""

class CollectiveClosureUnavailable(OSError):
    """Bounded recheck unavailable; existing public route reports UNKNOWN."""

def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "COLLECTIVE", "scope": SCOPE,
        "proposition": "The complete independently selected finite collective point-decision "
            "inventory decomposes into distinct, nonreused freshly rechecked member ROLE-4.1 "
            "point decisions over the same declared clock/period and current member revisions. "
            "Every exact class/content/instant assembly satisfies the independently selected "
            "COLLECTIVE-3.1 quorum and payload-bound class, required-role, countersign and "
            "declared actor/HUMAN-root separation protocol.",
        "prerequisites": ["independent exact current COLLECTIVE and full collection selection",
            "fresh exact COLLECTIVE-3.1 charter/quorum/distinct typed ROLE leaf replay",
            "one complete exact ROLE-4.1 request/policy/certificate selection per member",
            "payload-bound independently committed finite class protocol and complete decision inventory",
            "same exact clock/period and installed policy/source bytes and finite limits"],
        "exclusions": ["actual occurrence, real membership/history completeness or physical timing",
            "authenticated votes, signatures, legal charter authority or actual quorum decision",
            "real-person identity or independence inferred from distinct declared identifiers",
            "changing membership, asynchronous vote leases or decisions in flight across handover",
            "legacy whole closure, whole tier/profile and other required .m objectives",
            "privacy, consent, governance, security and publication admission"]}

PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())

@dataclass(frozen=True)
class CollectiveClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST

def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, CollectiveClosureError)

def _hash(value: Any) -> str:
    return retained_selection.commitment(value, CollectiveClosureError)

def _owned(value: Any, remaining: list[int] | None = None, depth: int = 0) -> Any:
    if remaining is None:
        remaining = [200000]
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 96:
        raise CollectiveClosureError("independent selection capture bound exhausted")
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise CollectiveClosureError("plain independent selection keys required")
        return {key:_owned(item, remaining, depth + 1) for key,item in value.items()}
    if type(value) is list:
        return [_owned(item, remaining, depth + 1) for item in value]
    if type(value) in (str, int, bool, type(None)):
        return value
    raise CollectiveClosureError("plain independent selection values required")

def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module, common_module,
        retained_selection, role_closure, role_lifecycle, collective_constraints)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["CURRENT_COLLECTIVE_DECISION_CLOSURE.md"] = Path(__file__).parents[2] / "standard" / "CURRENT_COLLECTIVE_DECISION_CLOSURE.md"
    paths["collective_closure_evidence.json"] = Path(__file__).parents[2] / "schemas" / "collective_closure_evidence.json"
    return "sha256:" + canonical_digest({"sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())}, "role_closure_mechanism_digest": role_closure.mechanism_digest(),
        "collective_constraints_mechanism_digest": collective_constraints.mechanism_digest()})

def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(_owned(value), error_type=CollectiveClosureError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)

def collective_closure_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    trust_roots = _owned(trust_roots)
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})

def _request(value: Any) -> dict[str, Any]:
    selected = _owned(_record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest", "clock_id", "clock_unit", "period_us",
        "static_request", "static_policy", "static_certificate_digest", "role_selections", "protocol_digest",
        "decisions_digest", "evidence_ref", "policy_digest", "limits"}, "request"))
    for key, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "COLLECTIVE"), ("proposition_digest", PROPOSITION_DIGEST),
        ("clock_unit", "microseconds")):
        if type(selected[key]) is not str or selected[key] != expected:
            raise CollectiveClosureError("selected collective closure protocol differs")
    for key in ("subject_id", "clock_id"):
        collective_constraints._name(selected[key])
    for key in ("object_digest", "collection_digest", "static_certificate_digest", "protocol_digest",
                "decisions_digest", "evidence_ref", "policy_digest"):
        _hash(selected[key])
    period = selected["period_us"]
    if type(period) is not list or len(period) != 2 or not role_closure._instant(period[0]) < role_closure._instant(period[1]):
        raise CollectiveClosureError("one selected nonempty half-open period required")
    child = collective_constraints._request(selected["static_request"])
    child_policy = collective_constraints._policy(selected["static_policy"])
    if (child["subject_id"] != selected["subject_id"] or child["object_digest"] != selected["object_digest"]
            or child["collection_digest"] != selected["collection_digest"]
            or child["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise CollectiveClosureError("static prerequisite differs from exact selected collective")
    roles = selected["role_selections"]
    if type(roles) is not list or len(roles) > _CEILINGS["max_roles"]:
        raise CollectiveClosureError("bounded complete member ROLE selections required")
    checked = []
    for raw in roles:
        row = _record(raw, {"role_id", "request", "policy", "certificate_digest"}, "ROLE selection")
        collective_constraints._name(row["role_id"]); _hash(row["certificate_digest"])
        req, policy = role_closure._request(row["request"]), role_closure._policy(row["policy"])
        if (req["subject_id"] != row["role_id"] or req["collective_id"] != selected["subject_id"]
                or req["collection_digest"] != selected["collection_digest"]
                or req["clock_id"] != selected["clock_id"] or req["clock_unit"] != selected["clock_unit"]
                or req["period_us"] != period or req["policy_digest"] != "sha256:" + canonical_digest(policy)):
            raise CollectiveClosureError("member ROLE prerequisite selection differs from clock/period/collective")
        checked.append({**row, "request":req, "policy":policy})
    ids = [row["role_id"] for row in checked]
    members = child_policy["selected_members"]
    if ids != [row["role_id"] for row in members] or any(
            role["request"]["object_digest"] != member["role_digest"] for role, member in zip(checked, members)):
        raise CollectiveClosureError("complete sorted distinct ROLE records differ from selected membership")
    selected["static_request"], selected["static_policy"], selected["role_selections"] = child, child_policy, checked
    selected["limits"] = retained_selection.limits(selected["limits"], _CEILINGS, CollectiveClosureError)
    return selected

def collective_closure_request(*, subject_id: str, object_digest: str, collection_digest: str,
        clock_id: str, period_us: list[int], static_request: dict[str, Any], static_policy: dict[str, Any],
        static_certificate_digest: str, role_selections: list[dict[str, Any]], protocol_digest: str,
        decisions_digest: str, evidence_ref: str, policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    (subject_id, object_digest, collection_digest, clock_id, period_us, static_request, static_policy,
     static_certificate_digest, role_selections, protocol_digest, decisions_digest, evidence_ref,
     policy, limits) = _owned([subject_id, object_digest, collection_digest, clock_id, period_us,
        static_request, static_policy, static_certificate_digest, role_selections, protocol_digest,
        decisions_digest, evidence_ref, policy, limits])
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or set(limits) - set(_CEILINGS)):
        raise CollectiveClosureError("unsupported collective closure limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST, "object_kind":"COLLECTIVE",
        "subject_id":subject_id, "object_digest":object_digest, "collection_digest":collection_digest,
        "clock_id":clock_id, "clock_unit":"microseconds", "period_us":period_us,
        "static_request":static_request, "static_policy":static_policy,
        "static_certificate_digest":static_certificate_digest, "role_selections":role_selections,
        "protocol_digest":protocol_digest, "decisions_digest":decisions_digest, "evidence_ref":evidence_ref,
        "policy_digest":"sha256:" + canonical_digest(admitted), "limits":{**_CEILINGS, **(limits or {})}})

def _committed(value: Any, expected: str, label: str) -> Any:
    if value is not None and "sha256:" + canonical_digest(value) != expected:
        raise Refuted(label + " differs from independent complete commitment")
    return value

def _protocol(value: Any, members: set[str], budget: common_module.Budget) -> dict[str, dict[str, Any]]:
    value = _record(value, {"schema_version", "classes"}, "collective decision protocol")
    if value["schema_version"] != PROTOCOL_VERSION:
        raise Unavailable("collective point-decision protocol version unsupported")
    classes = value["classes"]
    if type(classes) is not list or not classes:
        raise Refuted("complete nonempty selected class catalogue required")
    result = {}
    for raw in classes:
        budget.tick()
        row = _record(raw, {"decision_class", "required_roles", "countersign",
            "distinct_actors", "distinct_root_humans"}, "decision class")
        collective_constraints._name(row["decision_class"])
        roles = role_closure._names(row["required_roles"], budget)
        if set(roles) - members:
            raise Refuted("required ROLE is outside fixed selected membership")
        if type(row["distinct_actors"]) is not bool or type(row["distinct_root_humans"]) is not bool:
            raise Refuted("selected separation flags require plain Boolean values")
        if type(row["countersign"]) is not list:
            raise Refuted("complete finite countersign edge inventory required")
        edges = []
        for edge in row["countersign"]:
            budget.tick()
            edge = _record(edge, {"source_role", "target_role"}, "countersign edge")
            source, target = edge["source_role"], edge["target_role"]
            collective_constraints._name(source); collective_constraints._name(target)
            if source == target or source not in members or target not in members:
                raise Refuted("countersign edge is self-referential or outside membership")
            edges.append((source, target))
        if edges != sorted(set(edges)):
            raise Refuted("sorted unique declared countersign edges required")
        result[row["decision_class"]] = row
    names = [row["decision_class"] for row in classes]
    if names != sorted(set(names)):
        raise Refuted("sorted unique complete class catalogue required")
    return result

def _native_boundary(result: Any, module: Any, kind: str) -> str:
    if (type(result) is not dict or type(result.get("status")) is not str
            or result["status"] not in ("PASS", "FAIL", "UNKNOWN")
            or result.get("object_kind") != kind or result.get("coordinate") != module.COORDINATE
            or result.get("semantic_version") != module.SEMANTIC_VERSION or result.get("scope") != module.SCOPE
            or any(result.get(key) != "NOT_ESTABLISHED" for key in
                ("object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution"))):
        raise Refuted("native prerequisite result exceeds its exact selected proposition boundary")
    return result["status"]

def _static(raw: bytes, request: dict[str, Any]) -> None:
    collective_constraints._depth(raw, 128)
    value = _record(strict_json_loads(raw.decode("utf-8")), {
        "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
        "evidence_refs", "evidence_payloads", "result", "digest"}, "static certificate")
    selected = request["static_request"]
    payloads = value["evidence_payloads"]
    if (canonical_bytes(value) != raw or value["request"] != selected
            or value["evidence_refs"] != [selected["evidence_ref"]]
            or type(payloads) is not dict or set(payloads) - {selected["evidence_ref"]}
            or any(type(key) is not str or type(item) is not str for key,item in payloads.items())):
        raise Refuted("static envelope differs from exact selected plain retained binding")
    encoded = payloads.get(selected["evidence_ref"])
    retained = None
    if encoded is not None:
        evidence = role_lifecycle._decode(encoded, selected["limits"]["max_evidence_bytes"])
        collective_constraints._depth(evidence, selected["limits"]["max_depth"])
        retained = strict_json_loads(evidence.decode("utf-8"))
        if type(retained) is not dict:
            raise Refuted("plain retained static evidence record required")
    result = collective_constraints.recheck_collective_constraints_certificate(raw,
        expected_request=request["static_request"], policy=request["static_policy"])
    status = _native_boundary(result, collective_constraints, "COLLECTIVE")
    if status == "FAIL":
        raise Refuted("freshly replayed static prerequisite is FAIL")
    missing = [] if status == "PASS" else ["freshly replayed static prerequisite remains UNKNOWN"]
    if retained is None or retained.get("schema_version") != collective_constraints.EVIDENCE_VERSION:
        raise Unavailable("supported retained static object witnesses absent")
    if retained.get("objects") is None:
        raise Unavailable("selected static object witness inventory absent")
    subject = NamespaceObject.create(**next(row for row in retained["objects"] if row["object_id"] == request["subject_id"]))
    if subject.digest != request["object_digest"] or subject.kind.value != "COLLECTIVE":
        raise Refuted("available collective record differs from independently selected exact subject")
    commitment = subject.payload.get("decision_protocol_digest")
    if commitment is None:
        missing.append("independently selected exact collective lacks decision protocol commitment")
    elif commitment != request["protocol_digest"]:
        raise Refuted("selected collective payload differs from independent decision protocol")
    if missing:
        raise Unavailable("; ".join(missing))

def _declared_ledger(raw: bytes, selected: dict[str, Any], budget: common_module.Budget) -> dict[str, Any] | None:
    # Literal independently committed declarations can refute assembly equality
    # without promoting an UNKNOWN occupancy/authority prerequisite to PASS.
    retained = role_closure._child_data(raw, selected)
    if retained is None or retained.get("schema_version") != role_closure.EVIDENCE_VERSION:
        return None
    rows = role_closure._component(retained["decisions"], selected["decisions_digest"], "ROLE decisions")
    if rows is None:
        return None
    if type(rows) is not list:
        raise Refuted("literal selected ROLE inventory is not a plain array")
    if len(rows) > selected["limits"]["max_decisions"]:
        raise Unavailable("literal selected ROLE decision replay bound exhausted")
    ledger, previous = {}, -1
    for position, raw_row in enumerate(rows):
        budget.tick()
        row = _record(raw_row, {"position", "decision_id", "time_us", "actor_id", "identity_id", "scope", "decision_class", "content_digest"}, "literal selected ROLE decision")
        if type(row["position"]) is not int or row["position"] != position:
            raise Refuted("literal selected ROLE inventory positions differ")
        for key in ("decision_id", "actor_id", "identity_id", "scope", "decision_class"):
            collective_constraints._name(row[key])
        _hash(row["content_digest"])
        instant = role_closure._instant(row["time_us"])
        if row["decision_id"] in ledger or instant < previous or not selected["period_us"][0] <= instant < selected["period_us"][1]:
            raise Refuted("literal selected ROLE inventory duplicate/order/time contradicts its exact claim")
        ledger[row["decision_id"]] = row
        previous = instant
    return ledger

def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        collective_constraints._depth(data, 128)
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "static_certificate", "role_certificates", "protocol", "decisions"}, "collective closure evidence")
        if value["schema_version"] != EVIDENCE_VERSION:
            raise Unavailable("collective closure evidence version unsupported")
        if canonical_bytes(value) != data:
            raise Refuted("retained collective closure evidence is noncanonical")
        limits = request["limits"]
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        if len(request["role_selections"]) > limits["max_roles"]:
            raise Unavailable("selected member count bound exhausted")
        members = {row["role_id"] for row in request["role_selections"]}
        quorum = request["static_policy"]["quorum"]
        if not 1 <= quorum <= len(members):
            raise Refuted("independently selected quorum is infeasible for exact distinct membership")
        missing = []
        protocol = _committed(value["protocol"], request["protocol_digest"], "class protocol")
        classes = None
        if protocol is None:
            missing.append("complete selected class protocol absent")
        else:
            try:
                classes = _protocol(protocol, members, budget)
            except Unavailable as exc:
                missing.append(str(exc))
        decisions = _committed(value["decisions"], request["decisions_digest"], "collective decisions")
        if decisions is None:
            missing.append("complete selected collective decision inventory absent")
        else:
            if type(decisions) is not list:
                raise Refuted("plain complete collective decision array required")
            if len(decisions) > limits["max_decisions"]:
                raise Unavailable("selected collective decision bound exhausted")
            ids, used, previous = set(), set(), -1
            for position, raw in enumerate(decisions):
                budget.tick()
                row = _record(raw, {"position", "decision_id", "time_us", "decision_class", "content_digest", "components"}, "collective point decision")
                if type(row["position"]) is not int or row["position"] != position:
                    raise Refuted("collective positions are not complete and contiguous")
                collective_constraints._name(row["decision_id"]); collective_constraints._name(row["decision_class"])
                _hash(row["content_digest"])
                instant = role_closure._instant(row["time_us"])
                if row["decision_id"] in ids or instant < previous or not request["period_us"][0] <= instant < request["period_us"][1]:
                    raise Refuted("duplicate, reordered or out-of-period collective decision")
                ids.add(row["decision_id"]); previous = instant
                if type(row["components"]) is not list:
                    raise Refuted("complete member component inventory required")
                component_roles = []
                for component in row["components"]:
                    budget.tick()
                    component = _record(component, {"role_id", "decision_id"}, "ROLE component reference")
                    collective_constraints._name(component["role_id"]); collective_constraints._name(component["decision_id"])
                    pair = (component["role_id"], component["decision_id"])
                    if component["role_id"] not in members or pair in used:
                        raise Refuted("nonmember or reused ROLE component cannot inflate or split an assembly")
                    used.add(pair); component_roles.append(component["role_id"])
                if component_roles != sorted(set(component_roles)) or len(component_roles) < quorum:
                    raise Refuted("sorted distinct member ROLE components do not satisfy selected quorum")
                if classes is not None:
                    rule = classes.get(row["decision_class"])
                    if rule is None:
                        raise Refuted("collective decision class is outside complete selected protocol")
                    if set(rule["required_roles"]) - set(component_roles):
                        raise Refuted("collective decision omits selected required ROLE")
                    if any(edge["source_role"] in component_roles and edge["target_role"] not in component_roles for edge in rule["countersign"]):
                        raise Refuted("collective decision omits selected countersign ROLE")
        certificates = value["role_certificates"]
        if certificates is None:
            missing.append("complete member ROLE certificate inventory absent")
            certificates = {}
        elif (type(certificates) is not dict or set(certificates) != members
                or any(type(name) is not str for name in certificates)):
            raise Refuted("exact complete member ROLE certificate keys differ")
        reserve = limits["max_child_operations"]
        static = value["static_certificate"]
        if static is None:
            missing.append("exact static prerequisite certificate absent")
        else:
            raw = role_lifecycle._decode(static, limits["max_child_certificate_bytes"])
            if "sha256:" + hashlib.sha256(raw).hexdigest() != request["static_certificate_digest"]:
                raise Refuted("static certificate differs from independent exact selection")
            child_limits = request["static_request"]["limits"]
            reserve -= child_limits["max_operations"] + child_limits["max_composition_operations"]
            if reserve < 0:
                raise Unavailable("aggregate selected child operation reserve exhausted")
            try:
                _static(raw, request)
            except (Unavailable, OSError, ImportError) as exc:
                missing.append(str(exc))
        ledgers = {}
        for selected in request["role_selections"]:
            budget.tick()
            encoded = certificates.get(selected["role_id"])
            if encoded is None:
                missing.append("selected ROLE prerequisite absent: " + selected["role_id"])
                continue
            raw = role_lifecycle._decode(encoded, limits["max_child_certificate_bytes"])
            if "sha256:" + hashlib.sha256(raw).hexdigest() != selected["certificate_digest"]:
                raise Refuted("ROLE certificate differs from independent exact selection")
            child_limits = selected["request"]["limits"]
            reserve -= child_limits["max_operations"] + child_limits["max_child_operations"]
            if reserve < 0:
                raise Unavailable("aggregate selected child operation reserve exhausted")
            try:
                result = role_closure.recheck_role_closure_certificate(raw,
                    expected_request=selected["request"], policy=selected["policy"])
                status = _native_boundary(result, role_closure, "ROLE")
                if status == "FAIL":
                    raise Refuted("freshly replayed ROLE closure prerequisite is FAIL")
                if status != "PASS":
                    missing.append("freshly replayed ROLE closure prerequisite remains UNKNOWN")
                    declared = _declared_ledger(raw, selected["request"], budget)
                    if declared is not None:
                        ledgers[selected["role_id"]] = declared
                else:
                    ledgers[selected["role_id"]] = {row["decision_id"]:row for row in result["evaluation"]["observations"]["attributed_decisions"]}
            except (Unavailable, OSError, ImportError) as exc:
                missing.append(str(exc))
        assemblies = []
        if decisions is not None:
            for decision in decisions:
                budget.tick()
                components = []
                for reference in decision["components"]:
                    budget.tick()
                    ledger = ledgers.get(reference["role_id"])
                    if ledger is None:
                        continue
                    component = ledger.get(reference["decision_id"])
                    if component is None:
                        raise Refuted("collective component is absent from freshly replayed complete ROLE ledger")
                    if any(component[key] != decision[key] for key in ("decision_class", "content_digest", "time_us")):
                        raise Refuted("ROLE component class/content/instant differs from collective assembly")
                    components.append(component)
                if classes is not None:
                    rule = classes[decision["decision_class"]]
                    for flag, field in (("distinct_actors", "actor_id"), ("distinct_root_humans", "root_human_id")):
                        available = [row for row in components if field in row]
                        if rule[flag] and len({row[field] for row in available}) != len(available):
                            raise Refuted("available ROLE components contradict selected declared separation")
                if len(components) == len(decision["components"]):
                    assemblies.append({"decision_id":decision["decision_id"], "time_us":decision["time_us"],
                        "decision_class":decision["decision_class"], "content_digest":decision["content_digest"],
                        "components":components})
        if missing:
            raise Unavailable("; ".join(sorted(set(missing))))
        return MechanismDecision(MechanismOutcome.PASS, "complete selected collective decision assemblies reproduced",
            {"assemblies":assemblies, "member_roles":sorted(members), "quorum":quorum, "operations":budget.used,
             "actual_occurrence":"NOT_ESTABLISHED", "inventory_real_world_completeness":"NOT_ESTABLISHED"})
    except (Unavailable, OSError, ImportError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, IndexError, StopIteration) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))

def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _CollectiveClosureMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound COLLECTIVE closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise CollectiveClosureError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_CollectiveClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "COLLECTIVE", "scope": SCOPE,
        "evaluation": evaluation.to_dict(), **{field: "NOT_ESTABLISHED" for field in (
            "object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution",
            "historical_occurrence", "enforcement", "actual_occupancy", "actual_quorum_decision", "charter_authority")}}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise CollectiveClosureError("certificate byte bound exhausted")
    return encoded


def build_collective_closure_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    request, policy = _owned(request), _owned(policy)
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise CollectiveClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise CollectiveClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_collective_closure_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    expected_request, policy = _owned(expected_request), _owned(policy)
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes:
        raise CollectiveClosureError("immutable closure certificate bytes required")
    if len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise CollectiveClosureUnavailable("selected closure certificate byte checking bound exhausted")
    try:
        collective_constraints._depth(certificate_bytes, 128)
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
            "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise CollectiveClosureError("selected canonical closure certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise CollectiveClosureError("retained closure evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise CollectiveClosureError("closure certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (Unavailable, RecursionError, OverflowError) as exc:
        raise CollectiveClosureUnavailable("bounded native closure recheck unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        if isinstance(exc, CollectiveClosureError):
            raise
        raise CollectiveClosureError("invalid retained closure certificate") from exc

__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "PROTOCOL_VERSION", "SCOPE", "CollectiveClosureDescriptor", "CollectiveClosureError", "CollectiveClosureUnavailable", "registration", "mechanism_digest",
    "collective_closure_policy", "collective_closure_request", "build_collective_closure_certificate", "recheck_collective_closure_certificate"]
