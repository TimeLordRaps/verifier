"""Retained ROBOT path, observation, and intervention certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). ROBOT denotes an agent in a harness whose declared
consequence path reaches real-world actuators through controllers. This module
only replays retained source-bound declarations and trace records. It never
drives hardware and never establishes physical actuation, safety, causal
observation, runtime correspondence, external confinement, endpoint identity,
command authority, physical stability, interlock execution, operating-limit
adequacy, or intervention execution. Observation records refuse replayed effect
digests, require one software-to-physical domain crossing per trace, and type each
actuator's confinement claim with authenticity fixed at NOT_ESTABLISHED.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


REQUEST_VERSION = "verifier-retained-robot-checks-request-1"
POLICY_VERSION = "verifier-retained-robot-checks-policy-1"
CERTIFICATE_VERSION = "verifier-retained-robot-checks-certificate-1"
EVIDENCE_VERSION = "verifier-retained-robot-checks-evidence-2"
MECHANISM_ID = "verifier.added-kind.retained-robot-checks.1"
CHECKS = {route.check: route.coordinate for route in behavioral.routes("ROBOT")}
_MAX_UNITS = 2**63 - 1


class RobotChecksError(ValueError):
    """Malformed external selection or substituted ROBOT certificate."""


_SPEC = behavioral.BehavioralSpec(
    kind="ROBOT", request_version=REQUEST_VERSION, policy_version=POLICY_VERSION,
    certificate_version=CERTIFICATE_VERSION, evidence_version=EVIDENCE_VERSION,
    mechanism_id=MECHANISM_ID, source_path=Path(__file__), error_type=RobotChecksError,
    limitation_fields=("runtime_correspondence", "external_confinement", "physical_actuation",
                       "observation_authenticity", "causal_attribution", "safety",
                       "physical_endpoint_identity", "physical_effect_feedback",
                       "physical_interlock_execution", "physical_stability",
                       "command_authority", "operating_limit_adequacy",
                       "intervention_execution"),
)


def registration(check: str) -> dict[str, Any]:
    try:
        return behavioral.registration("ROBOT", check)
    except ValueError as exc:
        raise RobotChecksError("unsupported ROBOT check") from exc


def proposition_digest(check: str) -> str:
    return value_digest(registration(check))


def mechanism_digest() -> str:
    return behavioral.mechanism_digest(_SPEC)


def robot_checks_policy(*, trust_roots: list[str],
                        max_certificate_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    return behavioral.make_policy(_SPEC, trust_roots=trust_roots,
                                  max_certificate_bytes=max_certificate_bytes)


def robot_checks_request(*, check: str, subject_id: str, source_digest: str,
                         evidence_ref: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    return behavioral.make_request(_SPEC, check=check, subject_id=subject_id,
        source_digest=source_digest, evidence_ref=evidence_ref, policy=policy, limits=limits)


def robot_checks_evidence(*, subject_id: str, source_digest: str,
                          consequence_bundle: dict[str, Any], path: dict[str, Any],
                          observations: dict[str, Any] | None = None,
                          hazards: dict[str, Any] | None = None) -> bytes:
    """Encode retained declarations and traces without running their subject."""
    return canonical_bytes({"schema_version": EVIDENCE_VERSION, "object_kind": "ROBOT",
        "subject_id": subject_id, "source_digest": source_digest,
        "consequence_bundle": consequence_bundle, "path": path,
        "observations": observations, "hazards": hazards})


def robot_evidence_reference(evidence_bytes: bytes) -> str:
    if type(evidence_bytes) is not bytes:
        raise RobotChecksError("immutable evidence bytes required")
    return "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise behavioral.BehavioralRefuted(label + " fields differ")
    return dict(value)


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise behavioral.BehavioralRefuted(label + " identifier is invalid")
    return value


def _identifiers(value: Any, label: str, limit: int) -> list[str]:
    rows = behavioral.require_sequence(value, limit=limit, label=label)
    result = [_identifier(item, label) for item in rows]
    if not result:
        raise behavioral.BehavioralUnavailable(label + " is empty")
    if result != sorted(set(result)):
        raise behavioral.BehavioralRefuted(label + " must be sorted and unique")
    return result


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_UNITS:
        raise behavioral.BehavioralRefuted(label + " requires a plain integer")
    return value


def _digest(value: Any, label: str) -> str:
    if (type(value) is not str or not value.startswith("sha256:") or len(value) != 71
            or any(character not in "0123456789abcdef" for character in value[7:])):
        raise behavioral.BehavioralRefuted(label + " is not a canonical SHA-256 commitment")
    return value


def _path(value: Any, bundle: dict[str, Any], subject_id: str, limit: int) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = _record(value, {"trace_complete", "agent_id", "harness_id",
        "controller_ids", "actuator_ids"}, "ROBOT path")
    behavioral.require_complete(selected["trace_complete"], "ROBOT path")
    assessment = behavioral.assess_consequence_bundle(bundle, subject_id=subject_id,
        role="ROBOT", domain="REAL_PHYSICAL")
    rows = {row["object_id"]: row for row in bundle["rows"]}
    subject = rows[subject_id]
    agent_id = _identifier(selected["agent_id"], "agent")
    if subject.get("kind") == "AGENT" or "AGENT" in subject.get("specializations", []):
        actual_agents = [subject_id]
    elif subject.get("kind") == "BOT":
        actual_agents = subject.get("operands", {}).get("agent", [])
    else:
        actual_agents = sorted(edge["target"] for edge in bundle["graph"]["edges"]
                               if edge["source"] == subject_id and edge["relation"] == "embodies")
    if actual_agents != [agent_id] or agent_id not in rows:
        raise behavioral.BehavioralRefuted("retained ROBOT path names a different actual AGENT")
    harness_id = _identifier(selected["harness_id"], "harness")
    if rows[agent_id].get("operands", {}).get("harness", []) != [harness_id]:
        raise behavioral.BehavioralRefuted("retained ROBOT path names a different governing HARNESS")
    controller_ids = _identifiers(selected["controller_ids"], "controllers", limit)
    actuator_ids = _identifiers(selected["actuator_ids"], "actuators", limit)
    actual_controllers = sorted(edge["target"] for edge in bundle["graph"]["edges"]
                                if edge["source"] == agent_id and edge["relation"] == "controls")
    actual_actuators = sorted({edge["target"] for edge in bundle["graph"]["edges"]
        if edge["source"] in controller_ids and edge["relation"] == "actuates"})
    physical = {effect["object_id"] for effect in bundle["graph"]["effects"]
                if effect["domain"] == "REAL_PHYSICAL"}
    if controller_ids != actual_controllers or actuator_ids != actual_actuators or not set(actuator_ids) <= physical:
        raise behavioral.BehavioralRefuted("retained ROBOT path differs from the assessed controller-to-actuator chain")
    endpoint = assessment["reachable_effects"][subject_id]["REAL_PHYSICAL"]["effect_object_id"]
    if endpoint not in actuator_ids:
        raise behavioral.BehavioralRefuted("assessed physical endpoint is absent from selected actuators")
    return selected, {"agent_id": agent_id, "harness_id": harness_id,
        "controllers": len(controller_ids), "actuators": len(actuator_ids),
        "physical_endpoint_id": endpoint}


def _observations(value: Any, path: dict[str, Any], limit: int) -> tuple[set[str], dict[str, Any]]:
    section = _record(value, {"trace_complete", "traces", "crossings", "confinements"},
        "ROBOT observation trace")
    behavioral.require_complete(section["trace_complete"], "ROBOT observation trace")
    rows = behavioral.require_sequence(section["traces"], limit=limit, label="ROBOT traces")
    trace_ids: set[str] = set()
    effect_digests: set[str] = set()
    trace_actuators: list[tuple[str, str]] = []
    observed_actuators: set[str] = set()
    previous_observation = 0
    for raw in rows:
        row = _record(raw, {"trace_id", "agent_id", "controller_id", "actuator_id",
            "command_sequence", "observation_sequence", "retained_effect_digest"}, "ROBOT trace")
        trace_id = _identifier(row["trace_id"], "trace")
        if trace_id in trace_ids:
            raise behavioral.BehavioralRefuted("ROBOT trace identifier is duplicated")
        if row["agent_id"] != path["agent_id"] or row["controller_id"] not in path["controller_ids"] or row["actuator_id"] not in path["actuator_ids"]:
            raise behavioral.BehavioralRefuted("ROBOT trace differs from the selected path")
        command = _integer(row["command_sequence"], "command sequence", minimum=1)
        observation = _integer(row["observation_sequence"], "observation sequence", minimum=1)
        if observation <= command or observation <= previous_observation:
            raise behavioral.BehavioralRefuted("ROBOT observations are not strictly ordered after commands")
        digest = _digest(row["retained_effect_digest"], "retained effect digest")
        if digest in effect_digests:
            raise behavioral.BehavioralRefuted("retained effect digest is replayed across traces")
        effect_digests.add(digest)
        trace_ids.add(trace_id)
        trace_actuators.append((trace_id, row["actuator_id"]))
        observed_actuators.add(row["actuator_id"])
        previous_observation = observation
    missing = set(path["actuator_ids"]) - observed_actuators
    if missing:
        raise behavioral.BehavioralUnavailable("complete retained trace lacks an actuator observation")
    crossings = _crossings(section["crossings"], trace_actuators, limit)
    confinements = _confinements(section["confinements"], path["actuator_ids"], limit)
    return trace_ids, {"traces": len(rows), "observed_actuators": len(observed_actuators),
        "domain_crossings": crossings, "confinement_claims": confinements}


def _crossings(value: Any, traces: list[tuple[str, str]], limit: int) -> int:
    """Require one SOFTWARE_COMMAND to REAL_PHYSICAL crossing per retained trace, in trace order."""
    rows = behavioral.require_sequence(value, limit=limit, label="ROBOT domain crossings")
    actuator_by_trace = dict(traces)
    identifiers: set[str] = set()
    ordered: list[str] = []
    for raw in rows:
        row = _record(raw, {"crossing_id", "trace_id", "actuator_id", "from_domain", "to_domain"},
            "ROBOT domain crossing")
        identifier = _identifier(row["crossing_id"], "domain crossing")
        if identifier in identifiers:
            raise behavioral.BehavioralRefuted("domain crossing identifier is duplicated")
        identifiers.add(identifier)
        if row["trace_id"] not in actuator_by_trace:
            raise behavioral.BehavioralRefuted("domain crossing trace is absent")
        if row["actuator_id"] != actuator_by_trace[row["trace_id"]]:
            raise behavioral.BehavioralRefuted("domain crossing actuator differs from its trace")
        if row["from_domain"] != "SOFTWARE_COMMAND" or row["to_domain"] != "REAL_PHYSICAL":
            raise behavioral.BehavioralRefuted("domain crossing must run from SOFTWARE_COMMAND to REAL_PHYSICAL")
        ordered.append(row["trace_id"])
    if len(set(ordered)) != len(ordered):
        raise behavioral.BehavioralRefuted("a retained trace has more than one domain crossing")
    if set(actuator_by_trace) - set(ordered):
        raise behavioral.BehavioralUnavailable("retained trace lacks a domain crossing record")
    if ordered != [trace_id for trace_id, _ in traces]:
        raise behavioral.BehavioralRefuted("domain crossings are not in trace order")
    return len(ordered)


def _confinements(value: Any, actuators: list[str], limit: int) -> int:
    """Type each selected actuator's confinement claim and refuse any authenticity upgrade."""
    rows = behavioral.require_sequence(value, limit=limit, label="ROBOT confinement claims")
    identifiers: set[str] = set()
    claimed: set[str] = set()
    for raw in rows:
        row = _record(raw, {"confinement_id", "actuator_id", "claim_type", "authenticity", "reason"},
            "ROBOT confinement claim")
        identifier = _identifier(row["confinement_id"], "confinement")
        if identifier in identifiers:
            raise behavioral.BehavioralRefuted("confinement identifier is duplicated")
        identifiers.add(identifier)
        if row["actuator_id"] not in actuators:
            raise behavioral.BehavioralRefuted("confinement claim names an actuator outside the selected path")
        if row["actuator_id"] in claimed:
            raise behavioral.BehavioralRefuted("selected actuator has more than one confinement claim")
        if row["claim_type"] not in {"SOFTWARE_ENVELOPE", "PHYSICAL_BARRIER", "NONE_DECLARED"}:
            raise behavioral.BehavioralRefuted("confinement claim type is invalid")
        if row["authenticity"] != "NOT_ESTABLISHED":
            raise behavioral.BehavioralRefuted("confinement authenticity claim is outside this mechanism")
        if type(row["reason"]) is not str or not row["reason"].strip():
            raise behavioral.BehavioralRefuted("confinement claim reason is required")
        claimed.add(row["actuator_id"])
    if set(actuators) - claimed:
        raise behavioral.BehavioralUnavailable("selected actuator lacks a typed confinement claim")
    return len(rows)


def _hazards(value: Any, path: dict[str, Any], trace_ids: set[str], limit: int) -> dict[str, Any]:
    section = _record(value, {"trace_complete", "hazards", "interventions"}, "ROBOT hazard trace")
    behavioral.require_complete(section["trace_complete"], "ROBOT hazard trace")
    hazard_rows = behavioral.require_sequence(section["hazards"], limit=limit, label="ROBOT hazards")
    intervention_rows = behavioral.require_sequence(section["interventions"], limit=limit, label="ROBOT interventions")
    hazards: dict[str, dict[str, Any]] = {}
    intervention_ids: set[str] = set()
    covered_actuators: set[str] = set()
    for raw in hazard_rows:
        row = _record(raw, {"hazard_id", "actuator_id", "operating_limit_units",
            "intervention_id"}, "ROBOT hazard")
        hazard_id = _identifier(row["hazard_id"], "hazard")
        intervention_id = _identifier(row["intervention_id"], "hazard intervention")
        if hazard_id in hazards or intervention_id in intervention_ids:
            raise behavioral.BehavioralRefuted("hazard or intervention binding is duplicated")
        if row["actuator_id"] not in path["actuator_ids"]:
            raise behavioral.BehavioralRefuted("hazard names an actuator outside the selected path")
        _integer(row["operating_limit_units"], "operating limit", minimum=1)
        hazards[hazard_id] = row
        intervention_ids.add(intervention_id)
        covered_actuators.add(row["actuator_id"])
    if set(path["actuator_ids"]) - covered_actuators:
        raise behavioral.BehavioralUnavailable("selected actuator lacks a retained hazard boundary")
    seen: set[str] = set()
    for raw in intervention_rows:
        row = _record(raw, {"intervention_id", "hazard_id", "trigger_trace_id", "mode", "reason"}, "ROBOT intervention")
        intervention_id = _identifier(row["intervention_id"], "intervention")
        hazard_id = _identifier(row["hazard_id"], "intervention hazard")
        if intervention_id in seen or hazard_id not in hazards or hazards[hazard_id]["intervention_id"] != intervention_id:
            raise behavioral.BehavioralRefuted("intervention identity or hazard binding differs")
        if row["trigger_trace_id"] not in trace_ids:
            raise behavioral.BehavioralRefuted("intervention trigger trace is absent")
        if row["mode"] not in {"SAFE_STATE", "CONTINUITY"}:
            raise behavioral.BehavioralRefuted("intervention mode must declare SAFE_STATE or CONTINUITY")
        if type(row["reason"]) is not str or not row["reason"].strip():
            raise behavioral.BehavioralRefuted("intervention reason is required")
        seen.add(intervention_id)
    if seen != intervention_ids:
        raise behavioral.BehavioralUnavailable("not every retained hazard has an intervention declaration")
    return {"hazards": len(hazards), "interventions": len(seen),
            "safe_state": sum(row["mode"] == "SAFE_STATE" for row in intervention_rows),
            "continuity": sum(row["mode"] == "CONTINUITY" for row in intervention_rows)}


def _evaluate(data: bytes, request: dict[str, Any]) -> behavioral.BehavioralEvaluation:
    value = behavioral.evidence_document(data, request, _SPEC,
        {"consequence_bundle", "path", "observations", "hazards"})
    limit = request["limits"]["max_records"]
    path, details = _path(value["path"], value["consequence_bundle"], request["subject_id"], limit)
    route = behavioral.route_for("ROBOT", request["check"])
    if route.tier >= 2:
        if value["observations"] is None:
            raise behavioral.BehavioralUnavailable("ROBOT observation trace is unavailable")
        trace_ids, observations = _observations(value["observations"], path, limit)
        details.update(observations)
    else:
        trace_ids = set()
    if route.tier >= 3:
        if value["hazards"] is None:
            raise behavioral.BehavioralUnavailable("ROBOT hazard trace is unavailable")
        details.update(_hazards(value["hazards"], path, trace_ids, limit))
    return behavioral.BehavioralEvaluation("PASS", "selected retained ROBOT route reproduced", details)


def build_robot_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                   *, policy: dict[str, Any]) -> bytes:
    return behavioral.build_certificate(_SPEC, request, evidence_bytes, policy=policy, evaluator=_evaluate)


def recheck_robot_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                     policy: dict[str, Any]) -> dict[str, Any]:
    return behavioral.recheck_certificate(_SPEC, certificate_bytes,
        expected_request=expected_request, policy=policy, evaluator=_evaluate)


__all__ = ["CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "RobotChecksError",
    "registration", "proposition_digest", "mechanism_digest", "robot_checks_policy",
    "robot_checks_request", "robot_checks_evidence", "robot_evidence_reference",
    "build_robot_checks_certificate", "recheck_robot_checks_certificate"]
