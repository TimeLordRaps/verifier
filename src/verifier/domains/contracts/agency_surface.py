"""Cumulative agency-surface crosswalk for BOT, ROBOT, and FINBOT.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256).  This checker replays independently selected
current AGENT/BOT and retained ROBOT/FINBOT certificates, then checks only the
cross-route identity and trace joins that no child owns.  It does not copy the
children's predicates and never imports BOT-4 containment into Tier 3.

A passing crosswalk establishes a bounded relation among retained records.  It
does not establish authentic observations, adequate limits, successful
recovery, physical safety, legal authority, or real-world correspondence.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.receipt import strict_json_loads
from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime.tier_zero_profile import (
    applicability_digest,
    canonical_bytes,
    validate_applicability_binding,
    value_digest,
)


SEMANTIC_VERSION = "verifier-agency-surface-routes-1"
ADAPTER = "verifier-retained-agency-surface-1"
REQUEST_VERSION = "verifier-retained-agency-surface-request-1"
POLICY_VERSION = "verifier-retained-agency-surface-policy-1"
CERTIFICATE_VERSION = "verifier-retained-agency-surface-certificate-1"
EVIDENCE_VERSION = "verifier-retained-agency-surface-evidence-1"
MECHANISM_ID = "verifier.agency-surface.retained-crosswalk.1"
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class AgencySurfaceError(ValueError):
    """Malformed external selection or substituted agency certificate."""


ROUTES = (
    behavioral.BehavioralRoute(
        "binding", "BOT-1.7-agency-surface-binding", "BOT", 1,
        "BOT-1.7-agency-surface-binding", "Agency-surface binding",
        "A BOT cannot inherit AGENT and HARNESS evidence unless its actual selected operand identifiers join the independently replayed AGENT and BOT routes.",
        "The independently replayed AGENT-1.8 and BOT-1.6 certificates name exactly the same actual agent_id and harness_id as the source-bound agency crosswalk.",
        ("BOT-1.6", "AGENT-1.8"),
        ("identity", "authority", "live execution", "whole BOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "trace", "BOT-2.6-agency-surface-trace", "BOT", 2,
        "BOT-2.6-agency-surface-trace", "Agency decision-action-effect trace",
        "Separate passing trajectory, action, and BOT records can concern different agents or records unless their exact retained identifiers are joined.",
        "The independently replayed AGENT-2.1, AGENT-2.3, BOT-2.1, BOT-2.2, and BOT-2.3 certificates share the selected agent and harness and bind one exact retained decision/action record to one selected simulated effect key.",
        ("BOT-1.7", "AGENT-2.1", "AGENT-2.3", "BOT-2.1", "BOT-2.2", "BOT-2.3"),
        ("causal attribution", "authentic observation", "unretained effects", "whole BOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "operational_boundary", "BOT-3.5-agency-surface-operational-boundary", "BOT", 3,
        "BOT-3.5-agency-surface-operational-boundary", "Agency operational boundary",
        "A retained agency trace is unsafe to widen when limits, intervention, recovery, or confinement are omitted or silently treated as established.",
        "The cumulative agency trace carries explicit source-bound limit, intervention, recovery, and confinement boundary records; unsupported establishment is refused and BOT-4 containment is not used.",
        ("BOT-2.6", "BOT-3.1"),
        ("boundary authenticity", "boundary adequacy", "successful recovery", "real-world correspondence", "whole BOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "binding", "ROBOT-1.2-agency-surface-binding", "ROBOT", 1,
        "ROBOT-1.2-agency-surface-binding", "Physical agency-surface binding",
        "A declared physical path can name a different AGENT or HARNESS than the independently replayed agency route unless their actual identifiers are joined.",
        "The independently replayed AGENT-1.8 and ROBOT-1.1 certificates name exactly the same actual agent_id and harness_id as the source-bound agency crosswalk.",
        ("ROBOT-1.1", "AGENT-1.8"),
        ("identity", "physical actuation", "runtime correspondence", "whole ROBOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "trace", "ROBOT-2.2-agency-surface-trace", "ROBOT", 2,
        "ROBOT-2.2-agency-surface-trace", "Physical decision-action-effect trace",
        "A physical observation trace can pass independently of the AGENT decision and action certificates while referring to another retained agent or command.",
        "The independently replayed AGENT-2.1, AGENT-2.3, and ROBOT-2.1 certificates share the selected agent and harness and bind one exact retained decision/action record to one selected physical trace effect key.",
        ("ROBOT-1.2", "AGENT-2.1", "AGENT-2.3", "ROBOT-2.1"),
        ("causal attribution", "observation authenticity", "physical effect", "whole ROBOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "operational_boundary", "ROBOT-3.2-agency-surface-operational-boundary", "ROBOT", 3,
        "ROBOT-3.2-agency-surface-operational-boundary", "Physical agency operational boundary",
        "Physical agency needs explicit limits, intervention, recovery, and confinement boundaries even when its retained hazard route passes.",
        "The cumulative agency trace and independently replayed ROBOT-3.1 certificate carry explicit boundary records without promoting authenticity, adequacy, successful recovery, physical safety, or correspondence.",
        ("ROBOT-2.2", "ROBOT-3.1"),
        ("authenticity", "adequacy", "successful recovery", "physical safety", "real-world correspondence", "whole ROBOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "binding", "FINBOT-1.2-agency-surface-binding", "FINBOT", 1,
        "FINBOT-1.2-agency-surface-binding", "Financial agency-surface binding",
        "A declared financial scope can name a different AGENT or HARNESS than the independently replayed agency route unless their actual identifiers are joined.",
        "The independently replayed AGENT-1.8 and FINBOT-1.1 certificates name exactly the same actual agent_id and harness_id as the source-bound agency crosswalk.",
        ("FINBOT-1.1", "AGENT-1.8"),
        ("identity", "legal authority", "real-money effect", "whole FINBOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "trace", "FINBOT-2.2-agency-surface-trace", "FINBOT", 2,
        "FINBOT-2.2-agency-surface-trace", "Financial decision-action-effect trace",
        "A financial exposure can pass independently of the AGENT decision and action certificates while referring to another retained agent or effect.",
        "The independently replayed AGENT-2.1, AGENT-2.3, and FINBOT-2.1 certificates share the selected agent and harness and bind one exact retained decision/action record to one selected financial effect key.",
        ("FINBOT-1.2", "AGENT-2.1", "AGENT-2.3", "FINBOT-2.1"),
        ("causal attribution", "legal authority", "real-money effect", "whole FINBOT conformance"),
    ),
    behavioral.BehavioralRoute(
        "operational_boundary", "FINBOT-3.2-agency-surface-operational-boundary", "FINBOT", 3,
        "FINBOT-3.2-agency-surface-operational-boundary", "Financial agency operational boundary",
        "Financial agency needs explicit limits, intervention, recovery, and confinement boundaries even when its retained reconciliation route passes.",
        "The cumulative agency trace and independently replayed FINBOT-3.1 certificate carry explicit boundary records without promoting authenticity, adequacy, successful recovery, legal authority, or correspondence.",
        ("FINBOT-2.2", "FINBOT-3.1"),
        ("authenticity", "adequacy", "successful recovery", "legal authority", "real-world correspondence", "whole FINBOT conformance"),
    ),
)

_SPECS = {
    kind: behavioral.BehavioralSpec(
        kind=kind,
        request_version=REQUEST_VERSION,
        policy_version=POLICY_VERSION,
        certificate_version=CERTIFICATE_VERSION,
        evidence_version=EVIDENCE_VERSION,
        mechanism_id=MECHANISM_ID,
        source_path=Path(__file__),
        error_type=AgencySurfaceError,
        limitation_fields=(
            "authenticity", "adequacy", "successful_recovery", "physical_safety",
            "legal_authority", "real_world_correspondence",
        ),
        route_family="agency",
        semantic_version=SEMANTIC_VERSION,
        specification_paths=(Path(__file__).parents[2] / "standard" / "AGENCY_SURFACE.md",),
    )
    for kind in ("BOT", "ROBOT", "FINBOT")
}


def routes(kind: str | None = None) -> tuple[behavioral.BehavioralRoute, ...]:
    """Return exact agency routes, optionally for one represented kind."""
    if kind is None:
        return ROUTES
    selected = tuple(route for route in ROUTES if route.kind == kind)
    if not selected:
        raise ValueError("AGENCY_SURFACE_KIND_UNREGISTERED")
    return selected


def route_for(kind: str, check: str) -> behavioral.BehavioralRoute:
    selected = [route for route in ROUTES if route.kind == kind and route.check == check]
    if len(selected) != 1:
        raise ValueError("AGENCY_SURFACE_ROUTE_UNREGISTERED")
    return selected[0]


def registration(kind: str, check: str) -> dict[str, Any]:
    route = route_for(kind, check)
    return {
        "schema_version": "verifier-agency-surface-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": route.coordinate,
        "subject_kind": route.kind,
        "tier": route.tier,
        "obligation_id": route.obligation_id,
        "name": route.name,
        "reason": route.reason,
        "proposition": route.proposition,
        "prerequisites": list(route.prerequisites),
        "exclusions": list(route.exclusions),
    }


def proposition_digest(kind: str, check: str) -> str:
    return value_digest(registration(kind, check))


def mechanism_digest(kind: str) -> str:
    return behavioral.mechanism_digest(_SPECS[kind])


def _short_coordinate(route: behavioral.BehavioralRoute) -> str:
    return "-".join(route.coordinate.split("-", 2)[:2])


def _applicability(route: behavioral.BehavioralRoute) -> dict[str, str]:
    domains = {
        "BOT": "a BOT coupling to a simulation",
        "ROBOT": "an agency path with a REAL_PHYSICAL effect",
        "FINBOT": "an agency path with a REAL_FINANCIAL effect",
    }
    return {
        "mode": "CONDITIONAL",
        "condition": (
            "The admitted object carries " + domains[route.kind]
            + " and selects the retained cross-route evidence for " + route.coordinate + "."
        ),
        "when_condition_met": "NECESSARY",
        "unknown_condition": "NOT_EXEMPT",
        "reason": (
            route.reason
            + " A source-bound classification refutation may establish that the role does not trigger; "
              "an OBJECT label, omission, or unknown applicability cannot exempt it."
        ),
    }


def catalog() -> list[dict[str, Any]]:
    """Return nine package routes with explicit applicability and boundaries."""
    result = []
    for route in ROUTES:
        applicability = _applicability(route)
        result.append({
            "coordinate": _short_coordinate(route),
            "obligation_id": route.coordinate,
            "obligation_name": route.name,
            "object_kind": route.kind,
            "tier": route.tier,
            "reason": route.reason,
            "applicability": applicability,
            "applicability_digest": applicability_digest(applicability),
            "predicate": route.proposition,
            "exact_claim": route.proposition,
            "semantic_version": SEMANTIC_VERSION,
            "proposition_digest": proposition_digest(route.kind, route.check),
            "mechanism_digest": mechanism_digest(route.kind),
            "checking_mechanism": __name__ + ".recheck_agency_surface_certificate",
            "scope": "finite_retained_" + route.kind.lower() + "_agency_" + route.check,
            "adapter": ADAPTER,
            "runtime_dependencies": [],
            "prerequisite_coordinates": list(route.prerequisites),
            "not_established": [
                {"claim": claim, "status": "NOT_ESTABLISHED"}
                for claim in (
                    "authenticity", "adequacy", "successful recovery", "physical safety",
                    "legal authority", "real-world correspondence",
                )
            ],
        })
    return result


def is_route(route: Mapping[str, Any]) -> bool:
    if not isinstance(route, Mapping) or route.get("adapter") != ADAPTER:
        return False
    try:
        validate_applicability_binding(dict(route))
    except (TypeError, ValueError):
        return False
    selected = [row for row in catalog() if row["obligation_id"] == route.get("obligation_id")]
    return len(selected) == 1 and dict(route) == selected[0]


def agency_surface_policy(*, kind: str, trust_roots: list[str],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return behavioral.make_policy(_SPECS[kind], trust_roots=trust_roots,
                                  max_certificate_bytes=max_certificate_bytes)


def agency_surface_request(*, kind: str, check: str, subject_id: str,
                           source_digest: str, evidence_ref: str,
                           policy: dict[str, Any],
                           limits: dict[str, int] | None = None) -> dict[str, Any]:
    return behavioral.make_request(_SPECS[kind], check=check, subject_id=subject_id,
        source_digest=source_digest, evidence_ref=evidence_ref, policy=policy, limits=limits)


def agency_surface_evidence(*, kind: str, subject_id: str, source_digest: str,
                            effect_domains: list[str], agency_join: dict[str, Any],
                            children: list[dict[str, Any]],
                            consequence_bundle: dict[str, Any] | None = None,
                            operational_boundary: dict[str, Any] | None = None) -> bytes:
    """Encode a crosswalk; the builder does not pre-approve its children."""
    return canonical_bytes({
        "schema_version": EVIDENCE_VERSION,
        "object_kind": kind,
        "subject_id": subject_id,
        "source_digest": source_digest,
        "effect_domains": effect_domains,
        "agency_join": agency_join,
        "children": children,
        "consequence_bundle": consequence_bundle,
        "operational_boundary": operational_boundary,
    })


def agency_evidence_reference(evidence_bytes: bytes) -> str:
    if type(evidence_bytes) is not bytes:
        raise AgencySurfaceError("immutable evidence bytes required")
    return "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()


def child_record(*, role: str, certificate: bytes,
                 request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Encode one independently selected child certificate for the crosswalk."""
    if type(certificate) is not bytes:
        raise AgencySurfaceError("immutable child certificate bytes required")
    return {"role": role, "certificate_base64": base64.b64encode(certificate).decode("ascii"),
            "request": request, "policy": policy}


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise behavioral.BehavioralRefuted(label + " fields differ")
    return dict(value)


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise behavioral.BehavioralRefuted(label + " identifier is invalid")
    return value


def _decode_certificate_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    if "evidence_payload" in envelope:
        encoded = envelope["evidence_payload"]
    elif "evidence_payloads" in envelope:
        payloads = envelope["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) != 1:
            raise behavioral.BehavioralUnavailable("child certificate does not carry one retained evidence payload")
        encoded = next(iter(payloads.values()))
    else:
        raise behavioral.BehavioralRefuted("child certificate evidence carrier differs")
    if type(encoded) is not str:
        raise behavioral.BehavioralUnavailable("child retained evidence is unavailable")
    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
        value = strict_json_loads(data.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise behavioral.BehavioralRefuted("child retained evidence encoding differs") from exc
    if type(value) is not dict or canonical_bytes(value) != data:
        raise behavioral.BehavioralRefuted("child retained evidence is not canonical")
    return dict(value)


@dataclass(frozen=True)
class _ChildReplay:
    role: str
    coordinate: str
    request: dict[str, Any]
    result: dict[str, Any]
    evidence: dict[str, Any]


def _replay_child(raw: Any) -> _ChildReplay:
    row = _record(raw, {"role", "certificate_base64", "request", "policy"}, "agency child")
    role = _identifier(row["role"], "agency child role")
    if type(row["certificate_base64"]) is not str:
        raise behavioral.BehavioralRefuted("agency child certificate encoding differs")
    try:
        certificate = base64.b64decode(row["certificate_base64"].encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise behavioral.BehavioralRefuted("agency child certificate encoding differs") from exc
    request, policy = row["request"], row["policy"]
    if type(request) is not dict or type(policy) is not dict:
        raise behavioral.BehavioralRefuted("agency child selection differs")
    coordinate = request.get("coordinate")
    try:
        if coordinate in {"AGENT-1.8", "AGENT-2.1", "AGENT-2.3"}:
            from verifier.domains.contracts import agent_checks
            result = agent_checks.recheck_agent_checks_certificate(
                certificate, expected_request=request, policy=policy)
        elif coordinate in {"BOT-1.6", "BOT-2.1", "BOT-2.2", "BOT-2.3"}:
            from verifier.domains.contracts import bot_checks
            result = bot_checks.recheck_bot_checks_certificate(
                certificate, expected_request=request, policy=policy)
        elif coordinate in {
                "ROBOT-1.1-agent-harness-controller-actuator-path",
                "ROBOT-2.1-physical-reach-and-observation",
                "ROBOT-3.1-hazards-intervention-and-safe-state-or-continuity"}:
            from verifier.domains.contracts import robot_checks
            result = robot_checks.recheck_robot_checks_certificate(
                certificate, expected_request=request, policy=policy)
        elif coordinate in {
                "FINBOT-1.1-agent-harness-and-financial-authority",
                "FINBOT-2.1-real-financial-endpoint-and-exposure",
                "FINBOT-3.1-decision-effect-retry-intervention-and-reconciliation"}:
            from verifier.domains.contracts import finbot_checks
            result = finbot_checks.recheck_finbot_checks_certificate(
                certificate, expected_request=request, policy=policy)
        else:
            raise behavioral.BehavioralRefuted("agency child coordinate is unsupported")
    except AgencySurfaceError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        raise behavioral.BehavioralRefuted(
            "agency child certificate does not replay at " + str(coordinate)) from exc
    status = result.get("status") if type(result) is dict else None
    if status == "UNKNOWN":
        raise behavioral.BehavioralUnavailable("agency child remains UNKNOWN at " + str(coordinate))
    if status != "PASS":
        raise behavioral.BehavioralRefuted("agency child does not PASS at " + str(coordinate))
    try:
        envelope = strict_json_loads(certificate.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise behavioral.BehavioralRefuted("agency child certificate is not strict JSON") from exc
    if type(envelope) is not dict:
        raise behavioral.BehavioralRefuted("agency child certificate fields differ")
    return _ChildReplay(role, str(coordinate), dict(request), dict(result),
                        _decode_certificate_payload(envelope))


_BASE_CHILDREN = {
    "BOT": {1: {"agent_harness": "AGENT-1.8", "bot_binding": "BOT-1.6"},
            2: {"agent_trajectory": "AGENT-2.1", "agent_actions": "AGENT-2.3",
                "bot_alignment": "BOT-2.1", "bot_observation": "BOT-2.2",
                "bot_actuation": "BOT-2.3"}},
    "ROBOT": {1: {"agent_harness": "AGENT-1.8",
                    "robot_binding": "ROBOT-1.1-agent-harness-controller-actuator-path"},
              2: {"agent_trajectory": "AGENT-2.1", "agent_actions": "AGENT-2.3",
                  "robot_trace": "ROBOT-2.1-physical-reach-and-observation"},
              3: {"robot_boundary": "ROBOT-3.1-hazards-intervention-and-safe-state-or-continuity"}},
    "FINBOT": {1: {"agent_harness": "AGENT-1.8",
                     "finbot_binding": "FINBOT-1.1-agent-harness-and-financial-authority"},
               2: {"agent_trajectory": "AGENT-2.1", "agent_actions": "AGENT-2.3",
                   "finbot_trace": "FINBOT-2.1-real-financial-endpoint-and-exposure"},
               3: {"finbot_boundary": "FINBOT-3.1-decision-effect-retry-intervention-and-reconciliation"}},
}

_ACCUMULATED_CHILDREN = {
    "REAL_PHYSICAL": {
        1: {"robot_binding": "ROBOT-1.1-agent-harness-controller-actuator-path"},
        2: {"robot_trace": "ROBOT-2.1-physical-reach-and-observation"},
        3: {"robot_boundary": "ROBOT-3.1-hazards-intervention-and-safe-state-or-continuity"},
    },
    "REAL_FINANCIAL": {
        1: {"finbot_binding": "FINBOT-1.1-agent-harness-and-financial-authority"},
        2: {"finbot_trace": "FINBOT-2.1-real-financial-endpoint-and-exposure"},
        3: {"finbot_boundary": "FINBOT-3.1-decision-effect-retry-intervention-and-reconciliation"},
    },
}


def _required_children(kind: str, tier: int, effect_domains: list[str]) -> dict[str, str]:
    required: dict[str, str] = {}
    for selected_tier in range(1, tier + 1):
        required.update(_BASE_CHILDREN[kind].get(selected_tier, {}))
        for domain in effect_domains:
            required.update(_ACCUMULATED_CHILDREN.get(domain, {}).get(selected_tier, {}))
    return required


def _actual_ids(child: _ChildReplay) -> tuple[str, str]:
    evidence = child.evidence
    if child.coordinate.startswith("AGENT-") or child.coordinate.startswith("BOT-"):
        rows = evidence.get("objects")
        if type(rows) is not list:
            raise behavioral.BehavioralRefuted("current child namespace records are absent")
        records = {row.get("object_id"): row for row in rows if type(row) is dict}
        request_subject = None
        if child.coordinate.startswith("AGENT-"):
            candidates = [row for row in rows if type(row) is dict and row.get("kind") == "AGENT"]
            if len(candidates) != 1:
                raise behavioral.BehavioralRefuted("AGENT child subject is ambiguous")
            agent = candidates[0]
        else:
            candidates = [row for row in rows if type(row) is dict and row.get("kind") == "BOT"]
            if len(candidates) != 1:
                raise behavioral.BehavioralRefuted("BOT child subject is ambiguous")
            bot = candidates[0]
            operands = bot.get("operands")
            if type(operands) is not dict or type(operands.get("agent")) is not list or len(operands["agent"]) != 1:
                raise behavioral.BehavioralRefuted("BOT child actual AGENT differs")
            request_subject = operands["agent"][0]
            agent = records.get(request_subject)
            if type(agent) is not dict or agent.get("kind") != "AGENT":
                raise behavioral.BehavioralRefuted("BOT child actual AGENT is absent")
        agent_id = _identifier(request_subject or agent.get("object_id"), "actual agent")
        operands = agent.get("operands")
        if type(operands) is not dict or type(operands.get("harness")) is not list or len(operands["harness"]) != 1:
            raise behavioral.BehavioralRefuted("actual governing HARNESS differs")
        return agent_id, _identifier(operands["harness"][0], "actual harness")
    if child.coordinate.startswith("ROBOT-"):
        path = evidence.get("path")
        if type(path) is not dict:
            raise behavioral.BehavioralRefuted("ROBOT child path is absent")
        return _identifier(path.get("agent_id"), "actual agent"), _identifier(path.get("harness_id"), "actual harness")
    authority = evidence.get("authority")
    if type(authority) is not dict:
        raise behavioral.BehavioralRefuted("FINBOT child authority is absent")
    return _identifier(authority.get("agent_id"), "actual agent"), _identifier(authority.get("harness_id"), "actual harness")


def _agent_trace(children: dict[str, _ChildReplay]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    trajectory = children["agent_trajectory"].evidence.get("inputs")
    actions = children["agent_actions"].evidence.get("inputs")
    if type(trajectory) is not dict or type(actions) is not dict:
        raise behavioral.BehavioralRefuted("AGENT trace inputs are absent")
    steps, action_rows = trajectory.get("steps"), actions.get("actions")
    if type(steps) is not list or type(action_rows) is not list:
        raise behavioral.BehavioralRefuted("AGENT decision or action records are absent")
    return steps, action_rows


def _check_child_selections(children: dict[str, _ChildReplay]) -> None:
    """Require each route family to replay one exact selected subject."""
    groups = {
        "AGENT": [child for child in children.values()
                  if child.coordinate.startswith("AGENT-")],
        "BOT": [child for child in children.values()
                if child.coordinate.startswith("BOT-")],
        "ROBOT": [child for child in children.values()
                  if child.coordinate.startswith("ROBOT-")],
        "FINBOT": [child for child in children.values()
                   if child.coordinate.startswith("FINBOT-")],
    }
    for family, selected in groups.items():
        if not selected:
            continue
        fields = (("subject_id", "object_digest", "collection_digest")
                  if family in {"AGENT", "BOT"}
                  else ("subject_id", "source_digest"))
        reference = tuple(selected[0].request.get(field) for field in fields)
        if any(tuple(child.request.get(field) for field in fields) != reference
               for child in selected[1:]):
            raise behavioral.BehavioralRefuted(
                family + " agency children select different retained subjects")


def _role_effect(child: _ChildReplay, *, domain: str, record_id: int,
                 action_tool: str) -> str:
    evidence = child.evidence
    if domain == "SIMULATED":
        rows = evidence.get("objects")
        inputs = evidence.get("inputs")
        if type(rows) is not list or type(inputs) is not dict:
            raise behavioral.BehavioralRefuted("BOT effect evidence is absent")
        bot_rows = [row for row in rows if type(row) is dict and row.get("kind") == "BOT"]
        if len(bot_rows) != 1:
            raise behavioral.BehavioralRefuted("BOT effect subject is ambiguous")
        agent_certificate = inputs.get("agent_certificate")
        try:
            actual_actions = agent_certificate["evidence"]["inputs"]["actions"]
        except (TypeError, KeyError) as exc:
            raise behavioral.BehavioralRefuted("BOT retained AGENT actions are absent") from exc
        positions = [index for index, action in enumerate(actual_actions)
                     if type(action) is dict and action.get("record") == record_id
                     and action.get("tool") == action_tool]
        step_map = bot_rows[0].get("payload", {}).get("step_map")
        if len(positions) != 1 or type(step_map) is not list or positions[0] >= len(step_map):
            raise behavioral.BehavioralRefuted("BOT action does not select one simulated effect")
        transition = step_map[positions[0]]
        if type(transition) is not int or type(transition) is bool:
            raise behavioral.BehavioralRefuted("BOT simulated effect key is not a plain integer")
        return "sim-transition:" + str(transition)
    if domain == "REAL_PHYSICAL":
        observations = evidence.get("observations")
        if type(observations) is not dict or type(observations.get("traces")) is not list:
            raise behavioral.BehavioralRefuted("ROBOT physical traces are absent")
        traces = observations["traces"]
        if len(traces) != 1 or type(traces[0]) is not dict:
            raise behavioral.BehavioralUnavailable("agency crosswalk requires one selected physical trace")
        return _identifier(traces[0].get("trace_id"), "physical effect")
    reconciliation = evidence.get("reconciliation")
    if type(reconciliation) is not dict or type(reconciliation.get("decisions")) is not list:
        raise behavioral.BehavioralRefuted("FINBOT financial decision effects are absent")
    decisions = reconciliation["decisions"]
    if len(decisions) != 1 or type(decisions[0]) is not dict:
        raise behavioral.BehavioralUnavailable("agency crosswalk requires one selected financial decision")
    return _identifier(decisions[0].get("effect_id"), "financial effect")


def _check_trace_links(value: Any, *, effect_domains: list[str],
                       children: dict[str, _ChildReplay]) -> int:
    links = behavioral.require_sequence(value, limit=16, label="agency trace links")
    if len(links) != len(effect_domains):
        raise behavioral.BehavioralRefuted("agency trace links do not cover each selected effect domain")
    steps, actions = _agent_trace(children)
    seen: set[str] = set()
    for raw in links:
        link = _record(raw, {"domain", "record_id", "action_tool", "effect_id"}, "agency trace link")
        domain = link["domain"]
        if domain not in effect_domains or domain in seen:
            raise behavioral.BehavioralRefuted("agency trace domain is absent or duplicated")
        seen.add(domain)
        record_id = link["record_id"]
        if type(record_id) is not int or type(record_id) is bool or record_id < 0:
            raise behavioral.BehavioralRefuted("agency decision/action record requires a plain non-negative integer")
        action_tool = _identifier(link["action_tool"], "agency action tool")
        matching_steps = [row for row in steps if type(row) is dict and row.get("record") == record_id]
        matching_actions = [row for row in actions if type(row) is dict and row.get("record") == record_id
                            and row.get("tool") == action_tool]
        if len(matching_steps) != 1 or len(matching_actions) != 1:
            raise behavioral.BehavioralRefuted("agency link does not select one shared AGENT decision/action record")
        role = {"SIMULATED": "bot_actuation", "REAL_PHYSICAL": "robot_trace",
                "REAL_FINANCIAL": "finbot_trace"}[domain]
        expected_effect = _role_effect(children[role], domain=domain,
                                       record_id=record_id, action_tool=action_tool)
        if link["effect_id"] != expected_effect:
            raise behavioral.BehavioralRefuted("agency effect identifier differs from the selected role trace")
    return len(links)


def _check_boundary(value: Any) -> int:
    boundary = _record(value, {"limits", "intervention", "recovery", "confinement"},
                       "agency operational boundary")
    for name, raw in boundary.items():
        row = _record(raw, {"status", "reason"}, "agency " + name + " boundary")
        if row["status"] != "NOT_ESTABLISHED":
            raise behavioral.BehavioralRefuted(
                "agency " + name + " establishment is outside this source-bound mechanism")
        if type(row["reason"]) is not str or not row["reason"].strip():
            raise behavioral.BehavioralRefuted("agency " + name + " boundary reason is required")
    return len(boundary)


def _evaluate(data: bytes, request: dict[str, Any]) -> behavioral.BehavioralEvaluation:
    kind = request["object_kind"]
    value = behavioral.evidence_document(data, request, _SPECS[kind], {
        "effect_domains", "agency_join", "children", "consequence_bundle",
        "operational_boundary",
    })
    domains = value["effect_domains"]
    if (type(domains) is not list or any(type(domain) is not str for domain in domains)
            or domains != sorted(set(domains))
            or not set(domains) <= {"SIMULATED", "REAL_PHYSICAL", "REAL_FINANCIAL"}):
        raise behavioral.BehavioralRefuted("effect domains must be sorted, unique, and supported")
    required_domain = {"BOT": "SIMULATED", "ROBOT": "REAL_PHYSICAL",
                       "FINBOT": "REAL_FINANCIAL"}[kind]
    if required_domain not in domains:
        raise behavioral.BehavioralRefuted("represented agency role lacks its required effect domain")
    join = _record(value["agency_join"], {"agent_id", "harness_id", "trace_links"},
                   "agency join")
    agent_id = _identifier(join["agent_id"], "agency agent")
    harness_id = _identifier(join["harness_id"], "agency harness")
    route = route_for(kind, request["check"])
    expected = _required_children(kind, route.tier, domains)
    rows = behavioral.require_sequence(value["children"], limit=32, label="agency children")
    replayed = [_replay_child(row) for row in rows]
    children = {child.role: child for child in replayed}
    if len(children) != len(replayed) or set(children) != set(expected):
        raise behavioral.BehavioralRefuted("agency child set differs from the cumulative route")
    _check_child_selections(children)
    for role, coordinate in expected.items():
        child = children[role]
        if child.coordinate != coordinate:
            raise behavioral.BehavioralRefuted("agency child coordinate differs for " + role)
        actual_agent, actual_harness = _actual_ids(child)
        if (actual_agent, actual_harness) != (agent_id, harness_id):
            raise behavioral.BehavioralRefuted("agency child names a different actual agent_id or harness_id at " + coordinate)
    if kind in {"ROBOT", "FINBOT"}:
        role = "robot_binding" if kind == "ROBOT" else "finbot_binding"
        selected_bundle = children[role].evidence.get("consequence_bundle")
        if value["consequence_bundle"] != selected_bundle:
            raise behavioral.BehavioralRefuted(
                "agency consequence bundle differs from the independently replayed role child")
    elif value["consequence_bundle"] is not None:
        raise behavioral.BehavioralRefuted(
            "BOT agency evidence cannot collapse accumulated consequence bundles into one role")
    if route.tier >= 2:
        trace_count = _check_trace_links(join["trace_links"], effect_domains=domains,
                                         children=children)
    else:
        if join["trace_links"] != []:
            raise behavioral.BehavioralRefuted("Tier 1 agency binding cannot carry unverified trace links")
        trace_count = 0
    if route.tier >= 3:
        if value["operational_boundary"] is None:
            raise behavioral.BehavioralUnavailable("agency operational boundary is unavailable")
        boundary_count = _check_boundary(value["operational_boundary"])
    else:
        if value["operational_boundary"] is not None:
            raise behavioral.BehavioralRefuted("pre-Tier-3 agency route cannot carry an operational boundary")
        boundary_count = 0
    return behavioral.BehavioralEvaluation(
        "PASS", "selected retained agency-surface crosswalk reproduced",
        {"agent_id": agent_id, "harness_id": harness_id,
         "child_certificates": len(children), "trace_links": trace_count,
         "operational_boundaries": boundary_count,
         "effect_domains": list(domains),
         "tier4_bot_containment_used": False},
    )


def build_agency_surface_certificate(request: dict[str, Any],
                                     evidence_bytes: bytes | None, *,
                                     policy: dict[str, Any]) -> bytes:
    kind = request.get("object_kind") if type(request) is dict else None
    if kind not in _SPECS:
        raise AgencySurfaceError("unsupported agency object kind")
    return behavioral.build_certificate(_SPECS[kind], request, evidence_bytes,
        policy=policy, evaluator=_evaluate)


def recheck_agency_surface_certificate(certificate_bytes: bytes, *,
                                       expected_request: dict[str, Any],
                                       policy: dict[str, Any]) -> dict[str, Any]:
    kind = expected_request.get("object_kind") if type(expected_request) is dict else None
    if kind not in _SPECS:
        raise AgencySurfaceError("unsupported agency object kind")
    return behavioral.recheck_certificate(_SPECS[kind], certificate_bytes,
        expected_request=expected_request, policy=policy, evaluator=_evaluate)


def recheck_package_certificate(route: Mapping[str, Any], certificate_bytes: bytes, *,
                                expected_request: dict[str, Any],
                                policy: dict[str, Any]) -> dict[str, Any]:
    if not is_route(route):
        raise ValueError("AGENCY_SURFACE_PACKAGE_ROUTE_DIFFERS")
    if (expected_request.get("semantic_version") != SEMANTIC_VERSION
            or expected_request.get("coordinate") != route["obligation_id"]
            or expected_request.get("proposition_digest") != route["proposition_digest"]
            or expected_request.get("object_kind") != route["object_kind"]):
        raise ValueError("AGENCY_SURFACE_PACKAGE_REQUEST_ROUTE_DIFFERS")
    replay = recheck_agency_surface_certificate(
        certificate_bytes, expected_request=expected_request, policy=policy)
    if (type(replay) is not dict or replay.get("status") not in {"PASS", "FAIL", "UNKNOWN"}
            or replay.get("semantic_version") != SEMANTIC_VERSION
            or replay.get("coordinate") != route["obligation_id"]
            or replay.get("object_kind") != route["object_kind"]
            or replay.get("object_profile_conformance") != "NOT_ESTABLISHED"):
        raise ValueError("AGENCY_SURFACE_PACKAGE_REPLAY_BOUNDARY_DIFFERS")
    return replay


__all__ = [
    "SEMANTIC_VERSION", "ADAPTER", "ROUTES", "AgencySurfaceError", "routes",
    "route_for", "registration", "proposition_digest", "mechanism_digest",
    "catalog", "is_route", "agency_surface_policy", "agency_surface_request",
    "agency_surface_evidence", "agency_evidence_reference", "child_record",
    "build_agency_surface_certificate", "recheck_agency_surface_certificate",
    "recheck_package_certificate",
]
