"""Deterministic retained MARKET checks without trading or settlement.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Quantities, prices, cash, and sequence positions are
plain integers in caller-declared units. Passing certificates establish only
finite retained trace arithmetic and lifecycle correspondence. They never
establish venue authority, fairness, manipulation absence, or real settlement.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


REQUEST_VERSION = "verifier-retained-market-checks-request-1"
POLICY_VERSION = "verifier-retained-market-checks-policy-1"
CERTIFICATE_VERSION = "verifier-retained-market-checks-certificate-1"
EVIDENCE_VERSION = "verifier-retained-market-checks-evidence-2"
MECHANISM_ID = "verifier.added-kind.retained-market-checks.1"
CHECKS = {route.check: route.coordinate for route in behavioral.routes("MARKET")}
_MAX_UNITS = 2**63 - 1


class MarketChecksError(ValueError):
    """Malformed external selection or substituted MARKET certificate."""


_SPEC = behavioral.BehavioralSpec(
    kind="MARKET", request_version=REQUEST_VERSION, policy_version=POLICY_VERSION,
    certificate_version=CERTIFICATE_VERSION, evidence_version=EVIDENCE_VERSION,
    mechanism_id=MECHANISM_ID, source_path=Path(__file__), error_type=MarketChecksError,
    limitation_fields=("venue_authority", "fairness", "manipulation_absence",
                       "real_settlement", "runtime_correspondence"),
)


def registration(check: str) -> dict[str, Any]:
    try:
        return behavioral.registration("MARKET", check)
    except ValueError as exc:
        raise MarketChecksError("unsupported MARKET check") from exc


def proposition_digest(check: str) -> str:
    return value_digest(registration(check))


def mechanism_digest() -> str:
    return behavioral.mechanism_digest(_SPEC)


def market_checks_policy(*, trust_roots: list[str],
                         max_certificate_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    return behavioral.make_policy(_SPEC, trust_roots=trust_roots,
                                  max_certificate_bytes=max_certificate_bytes)


def market_checks_request(*, check: str, subject_id: str, source_digest: str,
                          evidence_ref: str, policy: dict[str, Any],
                          limits: dict[str, int] | None = None) -> dict[str, Any]:
    return behavioral.make_request(_SPEC, check=check, subject_id=subject_id,
        source_digest=source_digest, evidence_ref=evidence_ref, policy=policy, limits=limits)


def market_checks_evidence(*, subject_id: str, source_digest: str,
                           order_access: dict[str, Any],
                           matching_allocation: dict[str, Any] | None = None,
                           settlement_disruption: dict[str, Any] | None = None) -> bytes:
    """Encode inert retained records; certificate construction performs replay."""
    return canonical_bytes({"schema_version": EVIDENCE_VERSION, "object_kind": "MARKET",
        "subject_id": subject_id, "source_digest": source_digest,
        "order_access": order_access, "matching_allocation": matching_allocation,
        "settlement_disruption": settlement_disruption})


def market_evidence_reference(evidence_bytes: bytes) -> str:
    if type(evidence_bytes) is not bytes:
        raise MarketChecksError("immutable evidence bytes required")
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


def _order_access(value: Any, limit: int) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, Any]]:
    section = _record(value, {"trace_complete", "participants", "orders"}, "order-access trace")
    behavioral.require_complete(section["trace_complete"], "order-access trace")
    participant_rows = behavioral.require_sequence(section["participants"], limit=limit, label="participants")
    order_rows = behavioral.require_sequence(section["orders"], limit=limit, label="orders")
    participants: dict[str, str] = {}
    for raw in participant_rows:
        row = _record(raw, {"participant_id", "access"}, "participant")
        identifier = _identifier(row["participant_id"], "participant")
        if identifier in participants:
            raise behavioral.BehavioralRefuted("participant identifier is duplicated")
        if row["access"] not in {"ALLOWED", "DENIED"}:
            raise behavioral.BehavioralRefuted("participant access state is invalid")
        participants[identifier] = row["access"]
    if not participants:
        raise behavioral.BehavioralUnavailable("participant trace is empty")
    orders: dict[str, dict[str, Any]] = {}
    priorities: set[int] = set()
    transitions = {
        ("SUBMITTED", "ACCEPTED"), ("SUBMITTED", "REJECTED"),
        ("ACCEPTED", "CANCELLED"), ("ACCEPTED", "FILLED"),
    }
    for raw in order_rows:
        row = _record(raw, {"order_id", "participant_id", "side", "quantity_units",
            "limit_price_units", "priority_sequence", "lifecycle"}, "order")
        identifier = _identifier(row["order_id"], "order")
        participant = _identifier(row["participant_id"], "order participant")
        if identifier in orders:
            raise behavioral.BehavioralRefuted("order identifier is duplicated")
        if participant not in participants:
            raise behavioral.BehavioralRefuted("order participant is absent")
        if row["side"] not in {"BUY", "SELL"}:
            raise behavioral.BehavioralRefuted("order side is invalid")
        _integer(row["quantity_units"], "order quantity", minimum=1)
        _integer(row["limit_price_units"], "order limit price")
        priority = _integer(row["priority_sequence"], "order priority", minimum=1)
        lifecycle = behavioral.require_sequence(row["lifecycle"], limit=4, label="order lifecycle")
        if (not lifecycle or any(type(state) is not str for state in lifecycle)
                or lifecycle[0] != "SUBMITTED" or any(pair not in transitions for pair in zip(lifecycle, lifecycle[1:]))):
            raise behavioral.BehavioralRefuted("order lifecycle transition is invalid")
        if participants[participant] == "DENIED" and lifecycle != ["SUBMITTED", "REJECTED"]:
            raise behavioral.BehavioralRefuted("denied participant has a non-rejected order")
        if priority in priorities:
            raise behavioral.BehavioralRefuted("order priority is duplicated")
        priorities.add(priority)
        orders[identifier] = row
    if not orders:
        raise behavioral.BehavioralUnavailable("order trace is empty")
    return orders, participants, {"participants": len(participants), "orders": len(orders)}


def _manipulation_rules(value: Any, limit: int) -> int:
    """Retain rule identifiers and evidence digests; a retained violation refutes the route."""
    rows = behavioral.require_sequence(value, limit=limit, label="manipulation-control rules")
    if not rows:
        raise behavioral.BehavioralUnavailable("no manipulation-control rule evidence is retained")
    identifiers: list[str] = []
    violations = 0
    for raw in rows:
        row = _record(raw, {"rule_id", "evidence_digest", "result"}, "manipulation-control rule")
        identifiers.append(_identifier(row["rule_id"], "manipulation-control rule"))
        _digest(row["evidence_digest"], "manipulation-control evidence digest")
        if row["result"] not in {"NO_VIOLATION_RETAINED", "VIOLATION_RETAINED"}:
            raise behavioral.BehavioralRefuted("manipulation-control result is invalid")
        violations += row["result"] == "VIOLATION_RETAINED"
    if identifiers != sorted(set(identifiers)):
        raise behavioral.BehavioralRefuted("manipulation-control rules must be sorted and unique")
    if violations:
        raise behavioral.BehavioralRefuted("retained manipulation-control rule records a violation")
    return len(identifiers)


def _matching(value: Any, orders: dict[str, dict[str, Any]], limit: int) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    section = _record(value, {"trace_complete", "matches", "replay_digest", "manipulation_rules"},
        "matching trace")
    behavioral.require_complete(section["trace_complete"], "matching trace")
    matches_raw = behavioral.require_sequence(section["matches"], limit=limit, label="matches")
    if section["replay_digest"] != value_digest({"orders": list(orders.values()), "matches": matches_raw}):
        raise behavioral.BehavioralRefuted("matching replay digest differs")
    matches: dict[str, dict[str, Any]] = {}
    allocations: dict[str, int] = {identifier: 0 for identifier in orders}
    sequences: list[int] = []
    for raw in matches_raw:
        row = _record(raw, {"match_id", "buy_order_id", "sell_order_id", "price_units",
            "quantity_units", "allocation_sequence"}, "match")
        identifier = _identifier(row["match_id"], "match")
        buy = _identifier(row["buy_order_id"], "buy order")
        sell = _identifier(row["sell_order_id"], "sell order")
        if identifier in matches:
            raise behavioral.BehavioralRefuted("match identifier is duplicated")
        if buy not in orders or sell not in orders or buy == sell:
            raise behavioral.BehavioralRefuted("match order is absent or self-crossed")
        if orders[buy]["side"] != "BUY" or orders[sell]["side"] != "SELL":
            raise behavioral.BehavioralRefuted("match sides differ")
        if orders[buy]["lifecycle"][-1] not in {"ACCEPTED", "FILLED"} or orders[sell]["lifecycle"][-1] not in {"ACCEPTED", "FILLED"}:
            raise behavioral.BehavioralRefuted("match names a non-matchable order")
        price = _integer(row["price_units"], "match price")
        quantity = _integer(row["quantity_units"], "match quantity", minimum=1)
        sequence = _integer(row["allocation_sequence"], "allocation sequence", minimum=1)
        if not orders[sell]["limit_price_units"] <= price <= orders[buy]["limit_price_units"]:
            raise behavioral.BehavioralRefuted("match price is outside selected limits")
        allocations[buy] += quantity
        allocations[sell] += quantity
        if allocations[buy] > orders[buy]["quantity_units"] or allocations[sell] > orders[sell]["quantity_units"]:
            raise behavioral.BehavioralRefuted("matched quantity exceeds an order")
        matches[identifier] = row
        sequences.append(sequence)
    if len(sequences) != len(set(sequences)) or sequences != sorted(sequences):
        raise behavioral.BehavioralRefuted("allocation sequence is duplicated or nondeterministic")
    rules = _manipulation_rules(section["manipulation_rules"], limit)
    return matches, {"matches": len(matches), "matched_quantity_units": sum(row["quantity_units"] for row in matches.values()),
                     "manipulation_rules": rules}


def _settlement(value: Any, matches: dict[str, dict[str, Any]], participants: dict[str, str],
                limit: int) -> dict[str, Any]:
    section = _record(value, {"trace_complete", "settlements", "disruptions", "participant_failures"},
        "settlement trace")
    behavioral.require_complete(section["trace_complete"], "settlement trace")
    settlement_rows = behavioral.require_sequence(section["settlements"], limit=limit, label="settlements")
    disruption_rows = behavioral.require_sequence(section["disruptions"], limit=limit, label="disruptions")
    failure_rows = behavioral.require_sequence(section["participant_failures"], limit=limit, label="participant failures")
    settlements: dict[str, dict[str, Any]] = {}
    by_match: dict[str, str] = {}
    for raw in settlement_rows:
        row = _record(raw, {"settlement_id", "match_id", "quantity_units", "cash_units", "status"}, "settlement")
        identifier = _identifier(row["settlement_id"], "settlement")
        match_id = _identifier(row["match_id"], "settlement match")
        if identifier in settlements or match_id in by_match:
            raise behavioral.BehavioralRefuted("settlement identity or match finality is duplicated")
        if match_id not in matches:
            raise behavioral.BehavioralRefuted("settlement match is absent")
        quantity = _integer(row["quantity_units"], "settlement quantity")
        cash = _integer(row["cash_units"], "settlement cash")
        if row["status"] not in {"FINAL", "FAILED", "UNCERTAIN"}:
            raise behavioral.BehavioralRefuted("settlement status is invalid")
        match = matches[match_id]
        if row["status"] == "FINAL" and (quantity != match["quantity_units"] or cash != quantity * match["price_units"]):
            raise behavioral.BehavioralRefuted("final settlement does not conserve match quantity and cash")
        settlements[identifier] = row
        by_match[match_id] = identifier
    if set(by_match) != set(matches):
        raise behavioral.BehavioralUnavailable("not every retained match has a settlement outcome")
    covered: set[str] = set()
    sequences: list[int] = []
    event_ids: set[str] = set()
    for raw in disruption_rows:
        row = _record(raw, {"event_id", "affected_settlement_id", "kind", "response", "sequence"}, "disruption")
        event_id = _identifier(row["event_id"], "disruption")
        target = _identifier(row["affected_settlement_id"], "affected settlement")
        if event_id in event_ids or target not in settlements:
            raise behavioral.BehavioralRefuted("disruption identity is duplicated or target is absent")
        if type(row["kind"]) is not str or not row["kind"].strip() or type(row["response"]) is not str or not row["response"].strip():
            raise behavioral.BehavioralRefuted("disruption kind and response are required")
        event_ids.add(event_id)
        covered.add(target)
        sequences.append(_integer(row["sequence"], "disruption sequence", minimum=1))
    if len(sequences) != len(set(sequences)) or sequences != sorted(sequences):
        raise behavioral.BehavioralRefuted("disruption sequence is duplicated or nondeterministic")
    unresolved = {identifier for identifier, row in settlements.items() if row["status"] != "FINAL"} - covered
    if unresolved:
        raise behavioral.BehavioralUnavailable("failed or uncertain settlement lacks a disruption response")
    failure_ids: set[str] = set()
    statuses: list[str] = []
    for raw in failure_rows:
        row = _record(raw, {"failure_id", "participant_id", "status", "evidence_digest"}, "participant failure")
        identifier = _identifier(row["failure_id"], "participant failure")
        if identifier in failure_ids:
            raise behavioral.BehavioralRefuted("participant failure identifier is duplicated")
        failure_ids.add(identifier)
        if _identifier(row["participant_id"], "failed participant") not in participants:
            raise behavioral.BehavioralRefuted("participant failure names an absent participant")
        _digest(row["evidence_digest"], "participant failure evidence digest")
        if row["status"] not in {"RECOVERED", "UNRECOVERED"}:
            raise behavioral.BehavioralRefuted("participant failure status is invalid")
        statuses.append(row["status"])
    if "UNRECOVERED" in statuses:
        raise behavioral.BehavioralUnavailable("retained participant failure lacks a recovery record")
    return {"settlements": len(settlements), "final": sum(row["status"] == "FINAL" for row in settlements.values()),
            "disruptions": len(disruption_rows), "participant_failures": len(failure_rows),
            "dependency_scope": "RETAINED_ORDER_MATCH_SETTLEMENT_AND_DISRUPTION_RECORDS_ONLY",
            "external_dependencies": "NOT_ESTABLISHED"}


def _evaluate(data: bytes, request: dict[str, Any]) -> behavioral.BehavioralEvaluation:
    value = behavioral.evidence_document(data, request, _SPEC,
        {"order_access", "matching_allocation", "settlement_disruption"})
    limit = request["limits"]["max_records"]
    orders, participants, details = _order_access(value["order_access"], limit)
    route = behavioral.route_for("MARKET", request["check"])
    if route.tier >= 2:
        if value["matching_allocation"] is None:
            raise behavioral.BehavioralUnavailable("matching trace is unavailable")
        matches, matching = _matching(value["matching_allocation"], orders, limit)
        details.update(matching)
    else:
        matches = {}
    if route.tier >= 3:
        if value["settlement_disruption"] is None:
            raise behavioral.BehavioralUnavailable("settlement trace is unavailable")
        details.update(_settlement(value["settlement_disruption"], matches, participants, limit))
    return behavioral.BehavioralEvaluation("PASS", "selected retained MARKET route reproduced", details)


def build_market_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    return behavioral.build_certificate(_SPEC, request, evidence_bytes, policy=policy, evaluator=_evaluate)


def recheck_market_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    return behavioral.recheck_certificate(_SPEC, certificate_bytes,
        expected_request=expected_request, policy=policy, evaluator=_evaluate)


__all__ = ["CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "MarketChecksError",
    "registration", "proposition_digest", "mechanism_digest", "market_checks_policy",
    "market_checks_request", "market_checks_evidence", "market_evidence_reference",
    "build_market_checks_certificate", "recheck_market_checks_certificate"]
