"""Retained FINBOT authority, exposure, and reconciliation certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). FINBOT denotes an agent whose declared consequence
path reaches real financial decisions or effects. This module replays inert
retained records only; it never submits a transaction or moves money. Passing
does not establish legal authority, asset backing, external limit enforcement,
real balances, real-money effects, settlement, or recovery success. The decision
scope must bind the selected agent, harness, and financial endpoint exactly, and
exposure assets and parties must correspond to the retained registries only; those
retained-text bindings do not establish external registry correspondence.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


REQUEST_VERSION = "verifier-retained-finbot-checks-request-1"
POLICY_VERSION = "verifier-retained-finbot-checks-policy-1"
CERTIFICATE_VERSION = "verifier-retained-finbot-checks-certificate-1"
EVIDENCE_VERSION = "verifier-retained-finbot-checks-evidence-2"
MECHANISM_ID = "verifier.added-kind.retained-finbot-checks.1"
CHECKS = {route.check: route.coordinate for route in behavioral.routes("FINBOT")}
_MAX_UNITS = 2**63 - 1


class FinbotChecksError(ValueError):
    """Malformed external selection or substituted FINBOT certificate."""


_SPEC = behavioral.BehavioralSpec(
    kind="FINBOT", request_version=REQUEST_VERSION, policy_version=POLICY_VERSION,
    certificate_version=CERTIFICATE_VERSION, evidence_version=EVIDENCE_VERSION,
    mechanism_id=MECHANISM_ID, source_path=Path(__file__), error_type=FinbotChecksError,
    limitation_fields=("runtime_correspondence", "external_confinement", "legal_authority",
                       "asset_backing", "real_balance", "real_money_effect",
                       "authorized_settlement", "recovery_success"),
)


def registration(check: str) -> dict[str, Any]:
    try:
        return behavioral.registration("FINBOT", check)
    except ValueError as exc:
        raise FinbotChecksError("unsupported FINBOT check") from exc


def proposition_digest(check: str) -> str:
    return value_digest(registration(check))


def mechanism_digest() -> str:
    return behavioral.mechanism_digest(_SPEC)


def finbot_checks_policy(*, trust_roots: list[str],
                         max_certificate_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    return behavioral.make_policy(_SPEC, trust_roots=trust_roots,
                                  max_certificate_bytes=max_certificate_bytes)


def finbot_checks_request(*, check: str, subject_id: str, source_digest: str,
                          evidence_ref: str, policy: dict[str, Any],
                          limits: dict[str, int] | None = None) -> dict[str, Any]:
    return behavioral.make_request(_SPEC, check=check, subject_id=subject_id,
        source_digest=source_digest, evidence_ref=evidence_ref, policy=policy, limits=limits)


def finbot_checks_evidence(*, subject_id: str, source_digest: str,
                           consequence_bundle: dict[str, Any], authority: dict[str, Any],
                           exposures: dict[str, Any] | None = None,
                           reconciliation: dict[str, Any] | None = None) -> bytes:
    """Encode retained declarations and traces without invoking their subject."""
    return canonical_bytes({"schema_version": EVIDENCE_VERSION, "object_kind": "FINBOT",
        "subject_id": subject_id, "source_digest": source_digest,
        "consequence_bundle": consequence_bundle, "authority": authority,
        "exposures": exposures, "reconciliation": reconciliation})


def finbot_evidence_reference(evidence_bytes: bytes) -> str:
    if type(evidence_bytes) is not bytes:
        raise FinbotChecksError("immutable evidence bytes required")
    return "sha256:" + hashlib.sha256(evidence_bytes).hexdigest()


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise behavioral.BehavioralRefuted(label + " fields differ")
    return dict(value)


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise behavioral.BehavioralRefuted(label + " identifier is invalid")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= _MAX_UNITS:
        raise behavioral.BehavioralRefuted(label + " requires a plain integer")
    return value


def _digest(value: Any, label: str) -> str:
    if (type(value) is not str or not value.startswith("sha256:") or len(value) != 71
            or any(character not in "0123456789abcdef" for character in value[7:])):
        raise behavioral.BehavioralRefuted(label + " is not a canonical SHA-256 commitment")
    return value


def _authority(value: Any, bundle: dict[str, Any], subject_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = _record(value, {"trace_complete", "agent_id", "harness_id",
        "decision_scope", "financial_authority_boundary"}, "FINBOT authority")
    behavioral.require_complete(selected["trace_complete"], "FINBOT authority")
    assessment = behavioral.assess_consequence_bundle(bundle, subject_id=subject_id,
        role="FINBOT", domain="REAL_FINANCIAL")
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
        raise behavioral.BehavioralRefuted("retained FINBOT authority names a different actual AGENT")
    harness_id = _identifier(selected["harness_id"], "harness")
    if rows[agent_id].get("operands", {}).get("harness", []) != [harness_id]:
        raise behavioral.BehavioralRefuted("retained FINBOT authority names a different governing HARNESS")
    endpoint = assessment["reachable_effects"][subject_id]["REAL_FINANCIAL"]["effect_object_id"]
    _decision_scope(selected["decision_scope"], agent_id, harness_id, endpoint)
    if (type(selected["financial_authority_boundary"]) is not str
            or not selected["financial_authority_boundary"].strip()):
        raise behavioral.BehavioralRefuted("financial authority boundary is required")
    return selected, {"agent_id": agent_id, "harness_id": harness_id,
        "financial_endpoint_id": endpoint, "decision_scope": "BOUND_TO_AGENT_HARNESS_ENDPOINT"}


def _decision_scope(value: Any, agent_id: str, harness_id: str, endpoint: str) -> dict[str, str]:
    """Admit only a structured scope whose three fields equal the bound identifiers."""
    scope = _record(value, {"agent_id", "harness_id", "financial_endpoint_id"}, "FINBOT decision scope")
    if scope != {"agent_id": agent_id, "harness_id": harness_id, "financial_endpoint_id": endpoint}:
        raise behavioral.BehavioralRefuted("FINBOT decision scope differs from the bound agent, harness, or financial endpoint")
    return scope


def _registry(value: Any, label: str, limit: int) -> set[str]:
    rows = behavioral.require_sequence(value, limit=limit, label=label)
    if not rows:
        raise behavioral.BehavioralUnavailable(label + " is empty")
    identifiers = [_identifier(item, label) for item in rows]
    if identifiers != sorted(set(identifiers)):
        raise behavioral.BehavioralRefuted(label + " must be sorted and unique")
    return set(identifiers)


def _exposures(value: Any, endpoint: str, limit: int) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    section = _record(value, {"trace_complete", "asset_registry", "party_registry", "exposures"},
        "FINBOT exposure trace")
    behavioral.require_complete(section["trace_complete"], "FINBOT exposure trace")
    assets = _registry(section["asset_registry"], "FINBOT asset registry", limit)
    parties = _registry(section["party_registry"], "FINBOT party registry", limit)
    rows = behavioral.require_sequence(section["exposures"], limit=limit, label="FINBOT exposures")
    exposures: dict[str, dict[str, Any]] = {}
    total = 0
    for raw in rows:
        row = _record(raw, {"exposure_id", "endpoint_id", "asset_id", "party_id",
            "amount_units", "limit_units"}, "FINBOT exposure")
        identifier = _identifier(row["exposure_id"], "exposure")
        if identifier in exposures:
            raise behavioral.BehavioralRefuted("exposure identifier is duplicated")
        if row["endpoint_id"] != endpoint:
            raise behavioral.BehavioralRefuted("exposure endpoint differs from the assessed financial path")
        if _identifier(row["asset_id"], "exposure asset") not in assets:
            raise behavioral.BehavioralRefuted("exposure asset is absent from the retained asset registry")
        if _identifier(row["party_id"], "exposure party") not in parties:
            raise behavioral.BehavioralRefuted("exposure party is absent from the retained party registry")
        amount = _integer(row["amount_units"], "exposure amount", minimum=1)
        declared_limit = _integer(row["limit_units"], "exposure limit", minimum=1)
        if amount > declared_limit:
            raise behavioral.BehavioralRefuted("retained exposure exceeds its declared limit")
        total += amount
        exposures[identifier] = row
    if not exposures:
        raise behavioral.BehavioralUnavailable("FINBOT exposure trace is empty")
    return exposures, {"exposures": len(exposures), "exposure_units": total,
                       "financial_endpoint_id": endpoint}


def _reconciliation(value: Any, exposures: dict[str, dict[str, Any]], limit: int) -> dict[str, Any]:
    section = _record(value, {"trace_complete", "decisions", "interventions",
        "reconciliations"}, "FINBOT reconciliation trace")
    behavioral.require_complete(section["trace_complete"], "FINBOT reconciliation trace")
    decisions_raw = behavioral.require_sequence(section["decisions"], limit=limit, label="FINBOT decisions")
    interventions_raw = behavioral.require_sequence(section["interventions"], limit=limit, label="FINBOT interventions")
    reconciliations_raw = behavioral.require_sequence(section["reconciliations"], limit=limit, label="FINBOT reconciliations")
    interventions: dict[str, dict[str, Any]] = {}
    for raw in interventions_raw:
        row = _record(raw, {"intervention_id", "decision_id", "action", "reason"}, "FINBOT intervention")
        identifier = _identifier(row["intervention_id"], "intervention")
        if identifier in interventions:
            raise behavioral.BehavioralRefuted("intervention identifier is duplicated")
        _identifier(row["decision_id"], "intervention decision")
        if type(row["action"]) is not str or not row["action"].strip() or type(row["reason"]) is not str or not row["reason"].strip():
            raise behavioral.BehavioralRefuted("intervention action and reason are required")
        interventions[identifier] = row
    reconciliations: dict[str, dict[str, Any]] = {}
    for raw in reconciliations_raw:
        row = _record(raw, {"reconciliation_id", "effect_id", "status", "evidence_digest"}, "FINBOT reconciliation")
        identifier = _identifier(row["reconciliation_id"], "reconciliation")
        if identifier in reconciliations:
            raise behavioral.BehavioralRefuted("reconciliation identifier is duplicated")
        _identifier(row["effect_id"], "reconciliation effect")
        if row["status"] not in {"RECONCILED", "DISPUTED", "UNAVAILABLE"}:
            raise behavioral.BehavioralRefuted("reconciliation status is invalid")
        _digest(row["evidence_digest"], "reconciliation evidence digest")
        reconciliations[identifier] = row
    decisions: dict[str, dict[str, Any]] = {}
    attempts: dict[str, list[tuple[int, str, str]]] = {}
    used_interventions: set[str] = set()
    used_reconciliations: set[str] = set()
    for raw in decisions_raw:
        row = _record(raw, {"decision_id", "exposure_id", "effect_id", "idempotency_key",
            "attempt", "outcome", "intervention_id", "reconciliation_id"}, "FINBOT decision")
        decision_id = _identifier(row["decision_id"], "decision")
        if decision_id in decisions or row["exposure_id"] not in exposures:
            raise behavioral.BehavioralRefuted("decision identity is duplicated or exposure is absent")
        effect_id = _identifier(row["effect_id"], "decision effect")
        key = _identifier(row["idempotency_key"], "idempotency key")
        attempt = _integer(row["attempt"], "decision attempt", minimum=1)
        if row["outcome"] not in {"APPLIED", "REFUSED", "UNCERTAIN"}:
            raise behavioral.BehavioralRefuted("decision outcome is invalid")
        intervention_id = _identifier(row["intervention_id"], "decision intervention")
        reconciliation_id = _identifier(row["reconciliation_id"], "decision reconciliation")
        if intervention_id not in interventions or interventions[intervention_id]["decision_id"] != decision_id:
            raise behavioral.BehavioralRefuted("decision intervention binding differs")
        if (reconciliation_id not in reconciliations
                or reconciliations[reconciliation_id]["effect_id"] != effect_id):
            raise behavioral.BehavioralRefuted("decision reconciliation binding differs")
        decisions[decision_id] = row
        attempts.setdefault(key, []).append((attempt, row["outcome"], effect_id))
        used_interventions.add(intervention_id)
        used_reconciliations.add(reconciliation_id)
    if not decisions:
        raise behavioral.BehavioralUnavailable("FINBOT decision trace is empty")
    if used_interventions != set(interventions) or used_reconciliations != set(reconciliations):
        raise behavioral.BehavioralRefuted("orphan intervention or reconciliation record is retained")
    statuses = {row["status"] for row in reconciliations.values()}
    if "DISPUTED" in statuses:
        raise behavioral.BehavioralRefuted("retained reconciliation is disputed")
    if "UNAVAILABLE" in statuses:
        raise behavioral.BehavioralUnavailable("retained reconciliation is unavailable")
    for rows in attempts.values():
        numbers = [row[0] for row in rows]
        effects = {row[2] for row in rows}
        if numbers != sorted(set(numbers)) or effects and len(effects) != 1:
            raise behavioral.BehavioralRefuted("retry attempts are duplicated, unordered, or change effect identity")
        if sum(row[1] == "APPLIED" for row in rows) > 1:
            raise behavioral.BehavioralRefuted("an idempotency key has multiple applied effects")
    return {"decisions": len(decisions), "retry_keys": len(attempts),
        "applied": sum(row["outcome"] == "APPLIED" for row in decisions.values()),
        "uncertain": sum(row["outcome"] == "UNCERTAIN" for row in decisions.values()),
        "reconciled": sum(row["status"] == "RECONCILED" for row in reconciliations.values())}


def _evaluate(data: bytes, request: dict[str, Any]) -> behavioral.BehavioralEvaluation:
    value = behavioral.evidence_document(data, request, _SPEC,
        {"consequence_bundle", "authority", "exposures", "reconciliation"})
    authority, details = _authority(value["authority"], value["consequence_bundle"], request["subject_id"])
    route = behavioral.route_for("FINBOT", request["check"])
    limit = request["limits"]["max_records"]
    if route.tier >= 2:
        if value["exposures"] is None:
            raise behavioral.BehavioralUnavailable("FINBOT exposure trace is unavailable")
        exposures, exposure_details = _exposures(value["exposures"], details["financial_endpoint_id"], limit)
        details.update(exposure_details)
    else:
        exposures = {}
    if route.tier >= 3:
        if value["reconciliation"] is None:
            raise behavioral.BehavioralUnavailable("FINBOT reconciliation trace is unavailable")
        details.update(_reconciliation(value["reconciliation"], exposures, limit))
    return behavioral.BehavioralEvaluation("PASS", "selected retained FINBOT route reproduced", details)


def build_finbot_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    return behavioral.build_certificate(_SPEC, request, evidence_bytes, policy=policy, evaluator=_evaluate)


def recheck_finbot_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    return behavioral.recheck_certificate(_SPEC, certificate_bytes,
        expected_request=expected_request, policy=policy, evaluator=_evaluate)


__all__ = ["CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "FinbotChecksError",
    "registration", "proposition_digest", "mechanism_digest", "finbot_checks_policy",
    "finbot_checks_request", "finbot_checks_evidence", "finbot_evidence_reference",
    "build_finbot_checks_certificate", "recheck_finbot_checks_certificate"]
