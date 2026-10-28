"""Isolated worker and independent oracle for the three new POLICY enforcement routes.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
hash-based message authentication code (HMAC); Verifier Standard (VSTD).

The parent starts this file with ``python -I -S -B``. The worker runs the enforcement cases in
``policy_enforcement_routes`` and prints raw observations: receipts, digests, dispositions and bypass
findings. It never judges them. The oracle in this file judges observations against literal expectations
and an independent closed-form rule table. This file does not import the enforcement engine at module
level, so the engine cannot grade itself. The keys below are public fixture constants, not trust roots.

A route PASS here is local field evidence in an isolated process. It is never route conformance, and it
does not register the route in the central catalog.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Iterable, Mapping

REQUEST_SCHEMA = "verifier-policy-enforcement-worker-request-1"
OBSERVATION_SCHEMA = "verifier-policy-enforcement-worker-observations-1"
PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"

DECIDER = "authority:decider"
EXCEPTOR = "authority:exceptor"
CLERK = "authority:clerk"
UNUSED = "authority:unused"
FIXTURE_KEYS: dict[str, bytes] = {
    DECIDER: b"d" * 32,
    EXCEPTOR: b"e" * 32,
    CLERK: b"c" * 32,
    UNUSED: b"u" * 32,
}

# Frozen self-declaration of each new route's fields. The route module must declare exactly these.
DECLARED_STATUS: dict[str, dict[str, str]] = {
    "POLICY-1.3-enforcement-rule-semantics": {
        "scope": "PARTIAL", "decision_inputs": "PARTIAL", "defaults": "PARTIAL", "precedence": "PARTIAL",
    },
    "POLICY-2.3-enforcement-exceptions-and-revisions": {
        "exceptions": "PARTIAL", "revisions": "PARTIAL", "authority": "BOUNDARY", "activation": "BOUNDARY",
    },
    "POLICY-3.3-enforcement-decision-correspondence": {
        "decision_evidence": "PARTIAL", "enforcement_points": "BOUNDARY",
        "bypass_handling": "PARTIAL", "unavailable_behavior": "PARTIAL",
    },
}

ALLOWED = "ALLOWED"
REFUSED = "REFUSED"
UNAVAILABLE = "UNAVAILABLE"
_ALL = ("ALL_ROLES_ALLOWED",)
_SUPPLIED_UNKNOWN = "UNKNOWN"
_TRUST_THREE = (DECIDER, EXCEPTOR, CLERK)
_FAULT = "EVALUATOR_UNAVAILABLE:"

# Literal expectations per case. ``reasons`` and ``role_dispositions`` are exact. A case may add:
# ``table`` (each role disposition must equal the closed-form rule table), ``trust`` (the selected root
# and the commitment over the named roots), ``chain`` (receipt chain verification), ``digest_probe``,
# ``evidence_digest``, ``findings`` (bypass reasons), ``raised`` (an exception type, with no receipt).
EXPECTED: dict[str, dict[str, Any]] = {
    "scope.out_of_scope_refused_before_rules": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "scope",
        "outcome": REFUSED, "reasons": ("OUT_OF_SCOPE",), "role_dispositions": [],
    },
    "decision_inputs.request_digest_binds_request": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "decision_inputs",
        "outcome": ALLOWED, "reasons": _ALL, "digest_probe": True,
    },
    "decision_inputs.selected_trust_root_committed": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "decision_inputs",
        "outcome": ALLOWED, "reasons": _ALL, "trust": {"selected": DECIDER, "roots": _TRUST_THREE},
    },
    "decision_inputs.extra_trust_root_changes_commitment": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "decision_inputs",
        "outcome": ALLOWED, "reasons": _ALL, "trust": {"selected": DECIDER, "roots": _TRUST_THREE},
        "alternate_roots": _TRUST_THREE + (UNUSED,),
    },
    "defaults.role_without_rule_refused": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "defaults",
        "outcome": REFUSED, "reasons": ("NO_MATCHING_RULE",),
        "role_dispositions": [["FINANCIAL", "DENY", "NO_MATCHING_RULE"]], "table": True,
    },
    "defaults.policy_label_does_not_exempt_financial": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "defaults",
        "outcome": REFUSED, "reasons": ("NO_MATCHING_RULE",),
        "role_dispositions": [["FINANCIAL", "DENY", "NO_MATCHING_RULE"],
                              ["POLICY", "ALLOW", "ALLOWED_BY_RULE:ALLOW-TRANSFER"]],
        "table": True,
    },
    "precedence.higher_priority_deny_wins": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "precedence",
        "outcome": REFUSED, "reasons": ("DENIED_BY_RULE:DENY-FIN",), "table": True,
    },
    "precedence.higher_priority_allow_wins": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "precedence",
        "outcome": ALLOWED, "reasons": _ALL, "table": True,
    },
    "precedence.equal_priority_mixed_effects_conflict": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "precedence",
        "outcome": REFUSED, "reasons": ("PRECEDENCE_CONFLICT",), "table": True,
    },
    "precedence.equal_priority_allows_union_by_identifier": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "precedence",
        "outcome": ALLOWED, "reasons": _ALL, "table": True,
        "role_dispositions": [["FINANCIAL", "ALLOW", "ALLOWED_BY_RULE:ALLOW-A,ALLOW-B"]],
    },
    "precedence.lone_deny_refused": {
        "coordinate": "POLICY-1.3-enforcement-rule-semantics", "field": "precedence",
        "outcome": REFUSED, "reasons": ("DENIED_BY_RULE:DENY-ONLY",), "table": True,
    },
    "exceptions.no_waiver_keeps_deny": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": REFUSED, "reasons": ("DENIED_BY_RULE:DENY-FIN",), "exception_dispositions": [],
    },
    "exceptions.in_window_waiver_applied": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": ALLOWED, "reasons": _ALL, "exception_dispositions": [["exc-route", "APPLIED"]],
    },
    "exceptions.expired_waiver_not_applied": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": REFUSED, "reasons": ("DENIED_BY_RULE:DENY-FIN",),
        "exception_dispositions": [["exc-route", "EXPIRED"]],
    },
    "exceptions.waiver_of_allow_rule_is_overreach": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": REFUSED, "reasons": ("EXCEPTION_OVERREACH:NOT_A_DENY_RULE",),
    },
    "exceptions.action_beyond_grant_is_overreach": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": REFUSED, "reasons": ("EXCEPTION_OVERREACH:ACTION_BEYOND_GRANT",),
    },
    "exceptions.lifetime_beyond_policy_bound_is_overreach": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": REFUSED, "reasons": ("EXCEPTION_OVERREACH:LIFETIME_BOUND",),
    },
    "exceptions.duplicate_identifier_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "exceptions",
        "outcome": REFUSED, "reasons": ("DUPLICATE_EXCEPTION",),
    },
    "revisions.declared_current_pointer_allows": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": ALLOWED, "reasons": _ALL,
    },
    "revisions.superseded_revision_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": REFUSED, "reasons": ("SUPERSEDED_REVISION",),
    },
    "revisions.pointer_missing_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": REFUSED, "reasons": ("CURRENT_REVISION_UNDECLARED",),
    },
    "revisions.pointer_bit_flipped_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": REFUSED, "reasons": ("UNVERIFIED_CURRENT_REVISION",),
    },
    "revisions.pointer_over_altered_policy_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": REFUSED, "reasons": ("CURRENT_REVISION_MISMATCH:DIGEST",),
    },
    "revisions.stale_request_revision_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": REFUSED, "reasons": ("STALE_REVISION",),
    },
    "revisions.prior_revision_grant_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "revisions",
        "outcome": REFUSED, "reasons": ("AUTHORIZATION_REVISION_MISMATCH", "NO_DECISION_AUTHORITY"),
    },
    "authority.bit_flipped_grant_unverified": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "authority",
        "outcome": REFUSED, "reasons": ("UNVERIFIED_AUTHORITY", "NO_DECISION_AUTHORITY"),
    },
    "activation.before_active_window_refused": {
        "coordinate": "POLICY-2.3-enforcement-exceptions-and-revisions", "field": "activation",
        "outcome": REFUSED, "reasons": ("POLICY_INACTIVE",),
    },
    "decision_evidence.passing_evidence_authorizes": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": ALLOWED, "reasons": _ALL, "evidence_digest": True,
    },
    "decision_evidence.missing_evidence_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_MISSING",),
    },
    "decision_evidence.other_target_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_MISMATCH:TARGET",),
    },
    "decision_evidence.failing_evidence_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_REJECTED:NOT_PASSED",),
    },
    "decision_evidence.mutated_policy_id_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_MISMATCH:POLICY",),
    },
    "decision_evidence.mutated_target_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_MISMATCH:TARGET",),
    },
    "decision_evidence.mutated_passed_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_REJECTED:NOT_PASSED",),
    },
    "decision_evidence.mutated_clauses_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_REJECTED:RECHECK_FAILED",),
    },
    "decision_evidence.mutated_variable_map_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_REJECTED:RECHECK_FAILED",),
    },
    "decision_evidence.mutated_member_values_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_REJECTED:RECHECK_FAILED",),
    },
    "decision_evidence.mutated_certificate_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "decision_evidence",
        "outcome": REFUSED, "reasons": ("EVIDENCE_REJECTED:RECHECK_FAILED",),
    },
    "enforcement_points.undeclared_point_refused": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "enforcement_points",
        "outcome": REFUSED, "reasons": ("POINT_NOT_DECLARED",),
    },
    "enforcement_points.declared_point_allowed": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "enforcement_points",
        "outcome": ALLOWED, "reasons": _ALL,
    },
    "bypass_handling.supplied_honest_effect_not_a_finding": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "bypass_handling",
        "findings": [], "unsupplied_effects": _SUPPLIED_UNKNOWN,
    },
    "bypass_handling.ghost_effect_is_a_finding": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "bypass_handling",
        "findings": ["NO_ENFORCEMENT_RECEIPT"], "unsupplied_effects": _SUPPLIED_UNKNOWN,
    },
    "bypass_handling.refused_effect_is_a_finding": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "bypass_handling",
        "findings": ["ENFORCEMENT_NOT_ALLOWED"], "unsupplied_effects": _SUPPLIED_UNKNOWN,
    },
    "bypass_handling.wrong_target_effect_is_a_finding": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "bypass_handling",
        "findings": ["MISMATCHED_RECEIPT"], "unsupplied_effects": _SUPPLIED_UNKNOWN,
    },
    "bypass_handling.forged_request_digest_is_a_finding": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "bypass_handling",
        "findings": ["REQUEST_DIGEST_MISMATCH"], "unsupplied_effects": _SUPPLIED_UNKNOWN,
    },
    "unavailable_behavior.authority_stage_fault_unavailable": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "RuntimeError",), "role_dispositions": [],
    },
    "unavailable_behavior.exception_stage_fault_unavailable": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "RuntimeError",), "role_dispositions": [],
    },
    "unavailable_behavior.role_stage_fault_unavailable": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "RuntimeError",), "role_dispositions": [],
    },
    "unavailable_behavior.missing_verdict_unavailable": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "TypeError",), "role_dispositions": [],
    },
    "unavailable_behavior.request_digest_fault_unavailable_and_unsealed": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "ValueError",), "chain": False,
    },
    "unavailable_behavior.uncomparable_trust_root_unavailable": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "TypeError",), "role_dispositions": [],
    },
    "unavailable_behavior.non_mapping_trust_roots_unavailable": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": UNAVAILABLE, "reasons": (_FAULT + "TypeError",), "role_dispositions": [],
    },
    "unavailable_behavior.non_policy_input_refused_with_receipt": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": REFUSED, "reasons": ("POLICY_NOT_POLICY_VERSION",), "unrepresented_policy": True,
    },
    "unavailable_behavior.non_request_input_refused_with_receipt": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "outcome": REFUSED, "reasons": ("REQUEST_NOT_ENFORCEMENT_REQUEST",),
    },
    "unavailable_behavior.non_ledger_argument_raises_without_receipt": {
        "coordinate": "POLICY-3.3-enforcement-decision-correspondence", "field": "unavailable_behavior",
        "raised": "TypeError",
    },
}


def source_pins() -> dict[str, str]:
    """SHA-256 of every file the isolated run executes. Captured before and after the run."""
    runtime = Path(__file__).resolve().parent
    names = ("policy_enforcement_worker.py", "policy_enforcement_routes.py",
             "policy_enforcement_execution.py", "tier_zero_profile.py")
    paths = [runtime / name for name in names] + [Path(runtime.parent, "data", "policy.py")]
    return {path.relative_to(runtime.parent).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def fingerprint(key: bytes) -> str:
    """The trust-root key fingerprint the engine records: SHA-256 of the raw key bytes."""
    return "sha256:" + hashlib.sha256(key).hexdigest()


def commitment(authorities: Iterable[str]) -> str:
    """The commitment to a set of trust roots: SHA-256 of compact JSON over sorted [authority, fingerprint] pairs."""
    pairs = sorted([name, fingerprint(FIXTURE_KEYS[name])] for name in authorities)
    return "sha256:" + hashlib.sha256(json.dumps(pairs, separators=(",", ":")).encode("ascii")).hexdigest()


def closed_form_role(rules: Iterable[Mapping[str, Any]], action: str, role: str) -> tuple[str, str]:
    """The rule table, stated independently of the engine: top priority decides; mixed effects tie; none refuses."""
    applicable = [rule for rule in rules if action in rule["actions"] and role in rule["roles"]]
    if not applicable:
        return "DENY", "NO_MATCHING_RULE"
    top = max(rule["priority"] for rule in applicable)
    tier = [rule for rule in applicable if rule["priority"] == top]
    identifiers = ",".join(sorted(rule["rule_id"] for rule in tier))
    effects = {rule["effect"] for rule in tier}
    if len(effects) > 1:
        return "DENY", "PRECEDENCE_CONFLICT"
    if effects == {"DENY"}:
        return "DENY", "DENIED_BY_RULE:" + identifiers
    return "ALLOW", "ALLOWED_BY_RULE:" + identifiers


def _digest(value: Any) -> str:
    from verifier.runtime.tier_zero_profile import value_digest

    return value_digest(value)


def _normal(value: Any) -> Any:
    """JSON-normalized form, so tuples in a literal expectation compare equal to decoded lists."""
    return json.loads(json.dumps(value))


def check_case(observation: Mapping[str, Any]) -> list[str]:
    """Refusals for one raw observation. An empty list is the only passing result."""
    name = observation.get("case")
    if name not in EXPECTED:
        return ["UNKNOWN_CASE:" + repr(name)]
    expected = EXPECTED[name]
    refusals: list[str] = []
    if observation.get("coordinate") != expected["coordinate"] or observation.get("field") != expected["field"]:
        refusals.append("CASE_ROUTE_MISMATCH")
    if "raised" in expected:
        if observation.get("raised") != expected["raised"] or observation.get("receipt_count") != 0:
            refusals.append("RAISE_EXPECTED")
        return refusals
    for key, source, label in (
            ("outcome", "outcome", "OUTCOME"), ("reasons", "reasons", "REASONS"),
            ("role_dispositions", "role_dispositions", "ROLE_DISPOSITIONS"),
            ("exception_dispositions", "exception_dispositions", "EXCEPTION_DISPOSITIONS"),
            ("findings", "bypass_findings", "BYPASS_FINDINGS")):
        if key in expected and observation.get(source) != _normal(expected[key]):
            refusals.append(label + "_MISMATCH")
    if observation.get("chain_verified") is not expected.get("chain", True):
        refusals.append("CHAIN_MISMATCH")
    if expected.get("table"):
        for role, decision, reason in observation.get("role_dispositions", []):
            if closed_form_role(observation["rules"], observation["action"], role) != (decision, reason):
                refusals.append("RULE_TABLE_DIVERGES:" + role)
    if "trust" in expected:
        trust = expected["trust"]
        if (observation.get("trust_root_id") != trust["selected"]
                or observation.get("trust_root_digest") != fingerprint(FIXTURE_KEYS[trust["selected"]])):
            refusals.append("SELECTED_ROOT_MISMATCH")
        if observation.get("trust_roots_digest") != commitment(trust["roots"]):
            refusals.append("TRUST_COMMITMENT_MISMATCH")
    if "alternate_roots" in expected:
        if observation.get("alternate_trust_roots_digest") != commitment(expected["alternate_roots"]):
            refusals.append("ALTERNATE_COMMITMENT_MISMATCH")
        if observation.get("alternate_trust_roots_digest") == observation.get("trust_roots_digest"):
            refusals.append("ALTERNATE_COMMITMENT_UNCHANGED")
    if expected.get("digest_probe"):
        digests, requests = observation.get("request_digests", []), observation.get("request_dicts", [])
        if len(digests) != 2 or len(set(digests)) != 2 or digests != [_digest(item) for item in requests]:
            refusals.append("REQUEST_DIGEST_UNBOUND")
    if expected.get("evidence_digest") and observation.get("evidence_digest") != _digest(observation.get("evidence")):
        refusals.append("EVIDENCE_DIGEST_MISMATCH")
    if "unsupplied_effects" in expected and observation.get("unsupplied_effects") != expected["unsupplied_effects"]:
        refusals.append("UNSUPPLIED_EFFECTS_NOT_UNKNOWN")
    if expected.get("unrepresented_policy") and observation.get("policy_id") != "UNREPRESENTED":
        refusals.append("POLICY_REPRESENTED_WRONGLY")
    return refusals


def check_all(observations: Iterable[Mapping[str, Any]]) -> tuple[dict[str, tuple[str, list[str]]], list[str]]:
    """Judge a complete observation set. Returns each route's (verdict, refusals) and set-level refusals.

    Missing, duplicate or unknown cases fail. A set-level refusal means the worker output itself is
    untrustworthy, so every route then fails.
    """
    counts: dict[str, int] = {}
    per_case: dict[str, list[str]] = {}
    global_refusals: list[str] = []
    for observation in observations:
        name = observation.get("case")
        if name not in EXPECTED:
            global_refusals.append("UNKNOWN_CASE:" + repr(name))
            continue
        counts[name] = counts.get(name, 0) + 1
        per_case.setdefault(name, []).extend(check_case(observation))
    for name in EXPECTED:
        if counts.get(name, 0) != 1:
            per_case.setdefault(name, []).append("CASE_COUNT_NOT_ONE")
    verdicts: dict[str, tuple[str, list[str]]] = {}
    for coordinate, fields in DECLARED_STATUS.items():
        names = [name for name, expected in EXPECTED.items() if expected["coordinate"] == coordinate]
        route = [item + ":" + name for name in names for item in per_case.get(name, [])]
        if {EXPECTED[name]["field"] for name in names} != set(fields):
            route.append("FIELD_COVERAGE_MISMATCH:" + coordinate)
        verdicts[coordinate] = (FAIL if route or global_refusals else PASS, sorted(route))
    return verdicts, global_refusals


def main() -> int:
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if (type(request) is not dict or set(request) != {"schema", "nonce"} or request["schema"] != REQUEST_SCHEMA
            or type(request["nonce"]) is not str or not 1 <= len(request["nonce"]) <= 128):
        raise ValueError("closed bounded worker request required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-policy-enforcement-") as temporary:
        sys.pycache_prefix = str(Path(temporary) / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from verifier.runtime import policy_enforcement_routes as routes

        observations = routes.observe_all()
    if before != source_pins():
        raise ValueError("worker source changed during the run")
    sys.stdout.write(json.dumps({
        "schema": OBSERVATION_SCHEMA, "nonce": request["nonce"], "source_pins": before,
        "observations": observations,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
