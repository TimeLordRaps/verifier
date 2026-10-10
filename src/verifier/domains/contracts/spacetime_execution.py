"""Retained computational cost and execution observations, distinct from a directed acyclic graph (DAG).

Terminology: directed acyclic graph (DAG); Secure Hash Algorithm 256-bit (SHA-256).
Finite cost records and charge-machine replay do not prove live enforcement or
asymptotic complexity. Dependency edges alone do not establish execution TIME.
"""
from __future__ import annotations

from fractions import Fraction
import re
from typing import Any, Callable, Sequence
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.contextual_namespace import ContextReference, ContextualObject, assess_contextual_composition
from verifier.core.namespace import ObjectKind
from verifier.domains.contracts import spacetime_profiles as profile

COST_VERSION = "verifier-retained-computational-cost-1"
ORDER_VERSION = "verifier-declared-prerequisite-order-1"
TRACE_VERSION = "verifier-retained-execution-time-trace-1"
ASSESSMENT_VERSION = "verifier-spacetime-execution-assessment-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


def binding(raw: bytes) -> dict[str, Any]:
    value = profile.capture(raw)
    profile.keys(value, "schema_version implementation_digest operation input_size_definition computational_model assumptions run_id domain unit")
    if value["schema_version"] != "verifier-spacetime-computation-binding-1":
        raise ValueError("separate computation binding version required")
    if type(value["implementation_digest"]) is not str or _HASH.fullmatch(value["implementation_digest"]) is None:
        raise ValueError("exact implementation commitment required")
    for field in ("operation", "input_size_definition", "computational_model", "run_id", "domain", "unit"):
        profile.text(value[field])
    for assumption in profile._list(value["assumptions"]):
        profile.text(assumption)
    return value


def assess_cost(evidence_bytes: bytes | None, *, expected_evidence_digest: str | None,
        expected_binding_bytes: bytes | None, capability: str,
        expected_budget_bytes: bytes | None = None,
        cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    report = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "scope": "MATCHING_RETAINED_COST_OR_FINITE_CHARGE_MACHINE_REPLAY",
        "actual_cost_and_live_enforcement": "UNKNOWN", "asymptotic_complexity": "UNKNOWN"}
    if expected_evidence_digest is None or expected_binding_bytes is None:
        return {**report, "reason": "independent exact cost selection absent"}
    try:
        if cancelled is not None and cancelled():
            raise profile.Unsupported("cost replay cancelled")
        selected = binding(expected_binding_bytes)
        evidence = profile.capture(evidence_bytes)
        if "sha256:" + canonical_digest(evidence) != expected_evidence_digest:
            raise ValueError("selected cost evidence commitment differs")
        profile.keys(evidence, "schema_version binding records budget complexity")
        if evidence["schema_version"] != COST_VERSION or evidence["binding"] != selected:
            raise ValueError("cost version or exact implementation/model/input/assumption binding differs")
        if capability == "complexity_bound":
            raise profile.Unsupported("UNSUPPORTED complexity proof family; finite measurements and timeouts supply no asymptotic bound")
        if capability not in ("observed", "budget_replay"):
            raise profile.Unsupported("UNSUPPORTED computational cost capability")
        if evidence["complexity"] is not None:
            raise ValueError("complexity evidence cannot be admitted through a finite record capability")
        limit = None
        if capability == "budget_replay":
            if selected["computational_model"] != "retained-rational-charge-model/1":
                raise profile.Unsupported("UNSUPPORTED enforcement replay model")
            if expected_budget_bytes is None:
                raise profile.Unsupported("independently selected enforced-budget policy absent")
            budget = profile.capture(expected_budget_bytes)
            profile.keys(budget, "schema_version limit")
            if budget["schema_version"] != "verifier-deny-before-charge-policy-1" or evidence["budget"] != budget:
                raise ValueError("independent charge-machine policy differs")
            limit = profile.fraction(budget["limit"])
            if limit < 0:
                raise ValueError("negative budget limit")
        elif evidence["budget"] is not None:
            raise ValueError("observed cost does not imply budget enforcement")
        used, seen, count = Fraction(0), set(), 0
        for row in profile._list(evidence["records"], nonempty=True):
            if cancelled is not None and cancelled():
                raise profile.Unsupported("cost replay cancelled")
            profile.keys(row, "operation_id input_size charge decision")
            name = profile.text(row["operation_id"])
            if name in seen or type(row["input_size"]) is not int or row["input_size"] < 0 or row["input_size"].bit_length() > profile.LIMITS["max_integer_bits"]:
                raise ValueError("cost invocation identity/input-size definition differs")
            seen.add(name)
            charge = profile.fraction(row["charge"])
            if charge < 0:
                raise ValueError("negative retained cost")
            tentative = profile.checked_fraction(used + charge)
            if capability == "observed":
                if row["decision"] is not None:
                    raise ValueError("observed records cannot assert enforcement decisions")
                used = tentative
            else:
                allowed = tentative <= limit
                if row["decision"] != ("ALLOW" if allowed else "REFUSE"):
                    raise ValueError("retained decision refutes deny-before-charge policy")
                if allowed:
                    used = tentative
            count += 1
        return {**report, "status": "PASS", "capability": capability, "records": count,
            "retained_total": profile.rational(used.numerator, used.denominator),
            "binding_digest": "sha256:" + canonical_digest(selected), "evidence_digest": expected_evidence_digest}
    except (profile.Unsupported, profile.Exhausted) as exc:
        return {**report, "reason": str(exc)[:256]}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        return {**report, "status": "FAIL", "reason": str(exc)[:256]}


def assess_execution_order(objects: Sequence[ContextualObject], prerequisite_bytes: bytes | None,
        trace_bytes: bytes | None, *, expected_collection_digest: str | None,
        expected_prerequisite_digest: str | None, expected_trace_digest: str | None,
        expected_binding_bytes: bytes | None, expected_context_policy_bytes: bytes | None,
        cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    report = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "scope": "SELECTED_PREREQUISITES_AND_RETAINED_EXECUTION_POINT_OBSERVATIONS",
        "actual_execution_and_clock_authenticity": "UNKNOWN"}
    if any(value is None for value in (expected_collection_digest, expected_prerequisite_digest,
            expected_trace_digest, expected_binding_bytes, expected_context_policy_bytes, trace_bytes)):
        return {**report, "reason": "DAG alone supplies no execution observations or independent binding"}
    identity = assess_contextual_composition(objects, expected_digest=expected_collection_digest)
    if identity["status"] != "PASS":
        return {**report, "status": identity["status"], "reason": identity.get("reason")}
    try:
        if cancelled is not None and cancelled():
            raise profile.Unsupported("execution observation replay cancelled")
        selected = binding(expected_binding_bytes)
        graph, trace, policy = (profile.capture(raw) for raw in (prerequisite_bytes, trace_bytes, expected_context_policy_bytes))
        if "sha256:" + canonical_digest(graph) != expected_prerequisite_digest or "sha256:" + canonical_digest(trace) != expected_trace_digest:
            raise ValueError("selected prerequisite/trace commitment differs")
        profile.keys(graph, "schema_version nodes edges")
        if graph["schema_version"] != ORDER_VERSION:
            raise ValueError("separate prerequisite-order version required")
        names = [profile.text(name) for name in profile._list(graph["nodes"], nonempty=True)]
        if len(set(names)) != len(names):
            raise ValueError("duplicate prerequisite operation")
        profile.acyclic(set(names), graph["edges"])
        profile.keys(trace, "schema_version binding prerequisite_digest collection_digest records")
        if trace["schema_version"] != TRACE_VERSION or trace["binding"] != selected or trace["prerequisite_digest"] != expected_prerequisite_digest or trace["collection_digest"] != expected_collection_digest:
            raise ValueError("exact execution/run/prerequisite/collection binding differs")
        profile.keys(policy, "schema_version contexts")
        if policy["schema_version"] != "verifier-execution-time-context-policy-1":
            raise ValueError("independent execution-context policy version differs")
        required = {}
        for row in profile._list(policy["contexts"]):
            profile.keys(row, "operation_id context")
            name = profile.text(row["operation_id"])
            if name in required:
                raise ValueError("ambiguous independent execution context")
            required[name] = ContextReference.from_dict(row["context"])
        if set(required) != set(names):
            raise profile.Unsupported("complete selected execution-context policy absent")
        by_id = {item.record.object_id: item for item in objects}
        records, time_cache, operations = {}, {}, 0
        for row in profile._list(trace["records"]):
            if cancelled is not None and cancelled():
                raise profile.Unsupported("execution observation replay cancelled")
            profile.keys(row, "operation_id context start end")
            name = profile.text(row["operation_id"])
            if name in records or name not in required:
                raise ValueError("duplicate or unselected execution observation")
            ref = ContextReference.from_dict(row["context"])
            if ref != required[name] or ref.kind is not ObjectKind.TIME or ref.role != "execution":
                raise ValueError("selected typed execution TIME context substituted")
            target = by_id.get(ref.object_id)
            if target is None:
                raise profile.Unsupported("selected execution TIME record absent")
            if target.digest != ref.object_digest or target.record.kind is not ObjectKind.TIME:
                raise ValueError("execution TIME record digest/kind differs")
            value = target.record.payload
            if value.get("domain") != ref.domain or value.get("profile") != ref.profile or value.get("run_id") != selected["run_id"]:
                raise ValueError("execution TIME domain/profile/run differs")
            if ref.object_id not in time_cache:
                time_cache[ref.object_id] = profile.time_profile(value)
                operations += len(value["points"]) + len(value["order"])+1
            parsed = time_cache[ref.object_id]
            points = parsed["points"]
            if row["start"] not in points or row["end"] not in points:
                raise profile.Unsupported("execution interval endpoint observation absent")
            operations += len(points) + len(value["order"])+1 if value["profile"] == "logical-partial/1" else 1
            if operations > profile.LIMITS["max_operations"]:
                raise profile.Exhausted("execution relation replay operation bound exhausted")
            relation = profile.compare_parsed_time(parsed, row["start"], parsed, row["end"])
            if relation["status"] != "PASS" or relation["relation"] == "INCOMPARABLE":
                raise profile.Unsupported("execution interval order is not established")
            if relation["relation"] == "AFTER":
                raise ValueError("execution interval is reversed")
            records[name] = (parsed, row)
        if set(records) != set(names):
            raise profile.Unsupported("complete selected execution observation inventory absent")
        for source, target in graph["edges"]:
            left, before = records[source]
            right, after = records[target]
            operations += len(left["points"]) + len(left["descriptor"]["order"])+1 if left["descriptor"]["profile"] == "logical-partial/1" else 1
            if operations > profile.LIMITS["max_operations"]:
                raise profile.Exhausted("execution prerequisite relation replay operation bound exhausted")
            relation = profile.compare_parsed_time(left, before["end"], right, after["start"])
            if relation["status"] != "PASS" or relation["relation"] == "INCOMPARABLE":
                raise profile.Unsupported("cross-context prerequisite execution order is not established")
            if relation["relation"] == "AFTER":
                raise ValueError("retained execution trace violates prerequisite order")
        return {**report, "status": "PASS", "observed_operations": len(records),
            "prerequisite_digest": expected_prerequisite_digest, "trace_digest": expected_trace_digest,
            "collection_digest": expected_collection_digest,
            "binding_digest": "sha256:" + canonical_digest(selected),
            "context_policy_digest": "sha256:" + canonical_digest(policy)}
    except (profile.Unsupported, profile.Exhausted) as exc:
        return {**report, "reason": str(exc)[:256]}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        return {**report, "status": "FAIL", "reason": str(exc)[:256]}
