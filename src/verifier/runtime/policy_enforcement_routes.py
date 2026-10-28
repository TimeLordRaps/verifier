"""Route cases for three POLICY enforcement mechanisms, and their parent-side evaluation.

Terminology: Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); hash-based message authentication code (HMAC).

Each case builds real objects, runs them through ``policy_enforcement_execution`` in the calling
process, and returns a raw observation. It judges nothing. ``evaluate_routes`` runs the isolated worker in
a separate interpreter (``-I -S -B``), checks the echoed nonce and source pins, and gives the observations
to ``policy_enforcement_worker.check_all``, which owns every expectation. Fault injection patches only
the engine, in the process that runs the case, and restores it before the observation is taken.

Central status: each route's central row is found by exact key equality against ``CENTRAL_BINDINGS``
(short coordinate, full route name, kind, tier, adapter and checking mechanism). A prefix, a shorter
coordinate or a longer name never selects a row. Every report states ``central_registration`` and
``route_conformance: NOT_ESTABLISHED``. Catalog presence is not conformance, and a PASS is local field
evidence in an isolated process.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Iterator

from verifier.runtime import policy_enforcement_execution as pe
from verifier.runtime import policy_enforcement_worker as oracle

REPORT_SCHEMA = "verifier-policy-enforcement-routes-report-1"
# Boundaries that remain UNKNOWN in every report, whatever the local checks return.
EXTERNAL_BOUNDARIES = pe.EXTERNAL_BOUNDARIES + (
    "trust-root truth", "wall-clock currentness", "downstream routing", "revision publication",
)
NONCE = "policy-enforcement-routes-1"
TIER1 = "POLICY-1.3-enforcement-rule-semantics"
TIER2 = "POLICY-2.3-enforcement-exceptions-and-revisions"
TIER3 = "POLICY-3.3-enforcement-decision-correspondence"
COORDINATES = (TIER1, TIER2, TIER3)
CENTRAL_PRESENT = "CENTRAL_ROW_PRESENT_UNPINNED"
_CENTRAL_ADAPTER = "verifier-retained-policy-enforcement-1"
_CENTRAL_MECHANISM = "verifier.runtime.added_kind_behavioral_routes.recheck_policy_enforcement_certificate"
# Expected central row per route, as literals: a change in the central catalog must be made deliberately here.
CENTRAL_BINDINGS = {
    TIER1: {"coordinate": "POLICY-1.3", "obligation_id": TIER1, "object_kind": "POLICY", "tier": 1,
            "adapter": _CENTRAL_ADAPTER, "checking_mechanism": _CENTRAL_MECHANISM},
    TIER2: {"coordinate": "POLICY-2.3", "obligation_id": TIER2, "object_kind": "POLICY", "tier": 2,
            "adapter": _CENTRAL_ADAPTER, "checking_mechanism": _CENTRAL_MECHANISM},
    TIER3: {"coordinate": "POLICY-3.3", "obligation_id": TIER3, "object_kind": "POLICY", "tier": 3,
            "adapter": _CENTRAL_ADAPTER, "checking_mechanism": _CENTRAL_MECHANISM},
}
TARGET = pe._ROUTE_TARGET
OTHER_TARGET = pe._ROUTE_OTHER_TARGET
POLICY_ID = "policy:route-enforcement"
SCOPE = ("publish", "transfer", "release")
POINTS = ("EXECUTION", "RELEASE")
NOW = 100
_TRUST = {name: oracle.FIXTURE_KEYS[name] for name in (oracle.DECIDER, oracle.EXCEPTOR, oracle.CLERK)}
_DEFAULT = object()
_CASES: dict[str, tuple[str, str, Callable[[], tuple]]] = {}


def _case(coordinate: str, field: str) -> Callable[[Callable[[], tuple]], Callable[[], tuple]]:
    """Register one case under ``<field>.<function name>``; the function returns (ledger, receipt, policy, extra)."""
    def register(function: Callable[[], tuple]) -> Callable[[], tuple]:
        _CASES[field + "." + function.__name__] = (coordinate, field, function)
        return function
    return register


def _rule(rule_id: str, priority: int, effect: str, actions: tuple, roles: tuple, evidence: bool = False) -> pe.Rule:
    return pe.Rule(rule_id, priority, effect, actions, roles, evidence)


DEFAULT_RULES = (
    _rule("ALLOW-PUBLISH", 1, "ALLOW", ("publish",), ("POLICY", "MODEL")),
    _rule("ALLOW-TRANSFER", 1, "ALLOW", ("transfer",), ("POLICY",)),
)


def _fin(allow_priority: int, deny_priority: int) -> tuple:
    return (
        _rule("ALLOW-FIN", allow_priority, "ALLOW", ("transfer",), ("FINANCIAL",)),
        _rule("DENY-FIN", deny_priority, "DENY", ("transfer",), ("FINANCIAL",)),
    )


def _policy(rules: tuple = DEFAULT_RULES, *, revision: int = 1, decision_policy_id: Any = None,
            active_from: int = 0, active_until: Any = None) -> pe.PolicyVersion:
    return pe.PolicyVersion(
        policy_id=POLICY_ID, revision=revision, scope=SCOPE, rules=rules, enforcement_points=POINTS,
        active_from=active_from, active_until=active_until, decision_policy_id=decision_policy_id,
        max_exception_lifetime=50,
    )


def _grant(policy: pe.PolicyVersion, authority: str = oracle.DECIDER, *, may_decide: bool = True,
           may_except: bool = False, actions: tuple = SCOPE) -> pe.Authorization:
    return pe.issue_authorization(_TRUST[authority], policy, authority, may_decide=may_decide,
                                  may_except=may_except, actions=actions)


def _pointer(policy: pe.PolicyVersion, *, revision: Any = None, policy_digest: Any = None) -> pe.CurrentRevision:
    return pe.issue_current_revision(
        _TRUST[oracle.DECIDER], policy_id=policy.policy_id,
        revision=policy.revision if revision is None else revision,
        policy_digest=policy.digest if policy_digest is None else policy_digest,
        authority_id=oracle.DECIDER,
    )


def _waiver(policy: pe.PolicyVersion, *, exception_id: str = "exc-route", rule_id: str = "DENY-FIN",
            action: str = "transfer", not_before: int = 60, expires_at: int = 110) -> pe.PolicyException:
    return pe.issue_exception(
        _TRUST[oracle.EXCEPTOR], policy, exception_id=exception_id, rule_id=rule_id, action=action,
        target=TARGET, granted_by=oracle.EXCEPTOR, not_before=not_before, expires_at=expires_at,
    )


def _request(policy: pe.PolicyVersion, tag: str, *, action: str = "publish", roles: tuple = ("POLICY",),
             point: str = "RELEASE", target: str = TARGET, now: int = NOW, grants: Any = None,
             exceptions: tuple = (), evidence: Any = None, revision: Any = None,
             current: Any = _DEFAULT) -> pe.EnforcementRequest:
    return pe.EnforcementRequest(
        request_id=tag, policy_id=policy.policy_id, revision=policy.revision if revision is None else revision,
        point=point, action=action, target=target, roles=roles, now=now,
        authorizations=(_grant(policy),) if grants is None else grants, exceptions=exceptions,
        decision_evidence=evidence, current_revision=_pointer(policy) if current is _DEFAULT else current,
    )


def _enforce(policy: Any, request: Any, trust: Any = _TRUST, ledger: Any = None) -> tuple:
    return pe.enforce(pe.empty_ledger() if ledger is None else ledger, policy, request, trust)


@contextlib.contextmanager
def _patched(owner: Any, attribute: str, replacement: Any) -> Iterator[None]:
    """Replace one explicitly enumerated engine seam, then restore it."""
    if owner is not pe:
        raise ValueError("policy fault owner is not the retained engine")
    if attribute == "_find_decision_authority":
        original = pe._find_decision_authority
        pe._find_decision_authority = replacement
    elif attribute == "_evaluate_exceptions":
        original = pe._evaluate_exceptions
        pe._evaluate_exceptions = replacement
    elif attribute == "_decide_role":
        original = pe._decide_role
        pe._decide_role = replacement
    elif attribute == "_decide":
        original = pe._decide
        pe._decide = replacement
    elif attribute == "value_digest":
        original = pe.value_digest
        pe.value_digest = replacement
    else:
        raise ValueError("policy fault attribute is not an enumerated seam")
    try:
        yield
    finally:
        if attribute == "_find_decision_authority":
            pe._find_decision_authority = original
        elif attribute == "_evaluate_exceptions":
            pe._evaluate_exceptions = original
        elif attribute == "_decide_role":
            pe._decide_role = original
        elif attribute == "_decide":
            pe._decide = original
        else:
            pe.value_digest = original


def _injected(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("injected evaluator fault")


def _evidence_policy(decision_policy_id: str) -> pe.PolicyVersion:
    return _policy(
        (_rule("ALLOW-RELEASE", 1, "ALLOW", ("release",), ("POLICY",), True),),
        decision_policy_id=decision_policy_id,
    )


# --- POLICY-1.3: scope, decision inputs, defaults and precedence ----------------------------

@_case(TIER1, "scope")
def out_of_scope_refused_before_rules() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "scope-out", action="destroy"))
    return ledger, receipt, policy, {}


@_case(TIER1, "decision_inputs")
def request_digest_binds_request() -> tuple:
    policy = _policy()
    first = _request(policy, "digest-first")
    second = _request(policy, "digest-second", target=OTHER_TARGET)
    ledger, receipt = _enforce(policy, first)
    ledger, other = _enforce(policy, second, ledger=ledger)
    return ledger, receipt, policy, {
        "request_digests": [receipt.request_digest, other.request_digest],
        "request_dicts": [first.to_dict(), second.to_dict()],
    }


@_case(TIER1, "decision_inputs")
def selected_trust_root_committed() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "root-selected"))
    return ledger, receipt, policy, {}


@_case(TIER1, "decision_inputs")
def extra_trust_root_changes_commitment() -> tuple:
    policy = _policy()
    request = _request(policy, "root-widened")
    ledger, receipt = _enforce(policy, request)
    widened = {**_TRUST, oracle.UNUSED: oracle.FIXTURE_KEYS[oracle.UNUSED]}
    _, other = _enforce(policy, request, trust=widened)
    return ledger, receipt, policy, {"alternate_trust_roots_digest": other.trust_roots_digest}


@_case(TIER1, "defaults")
def role_without_rule_refused() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "default-role", action="transfer", roles=("FINANCIAL",)))
    return ledger, receipt, policy, {}


@_case(TIER1, "defaults")
def policy_label_does_not_exempt_financial() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "default-mixed", action="transfer",
                                                roles=("POLICY", "FINANCIAL")))
    return ledger, receipt, policy, {}


def _financial_case(tag: str, rules: tuple, *, roles: tuple = ("FINANCIAL",)) -> tuple:
    policy = _policy(rules)
    ledger, receipt = _enforce(policy, _request(policy, tag, action="transfer", roles=roles))
    return ledger, receipt, policy, {}


@_case(TIER1, "precedence")
def higher_priority_deny_wins() -> tuple:
    return _financial_case("prec-deny", _fin(1, 10))


@_case(TIER1, "precedence")
def higher_priority_allow_wins() -> tuple:
    return _financial_case("prec-allow", _fin(10, 1))


@_case(TIER1, "precedence")
def equal_priority_mixed_effects_conflict() -> tuple:
    return _financial_case("prec-tie", _fin(5, 5))


@_case(TIER1, "precedence")
def equal_priority_allows_union_by_identifier() -> tuple:
    rules = (
        _rule("ALLOW-A", 5, "ALLOW", ("transfer",), ("FINANCIAL",)),
        _rule("ALLOW-B", 5, "ALLOW", ("transfer",), ("FINANCIAL",)),
    )
    return _financial_case("prec-union", rules)


@_case(TIER1, "precedence")
def lone_deny_refused() -> tuple:
    return _financial_case("prec-lone", (_rule("DENY-ONLY", 5, "DENY", ("transfer",), ("FINANCIAL",)),))


# --- POLICY-2.3: exceptions, declared revisions, authority and activation -------------------

def _exception_case(tag: str, waiver_for: Callable[[pe.PolicyVersion], pe.PolicyException], *,
                    exceptor_actions: tuple = ("transfer",), now: int = NOW) -> tuple:
    policy = _policy(_fin(1, 10))
    grants = (_grant(policy), _grant(policy, oracle.EXCEPTOR, may_decide=False, may_except=True,
                                     actions=exceptor_actions))
    request = _request(policy, tag, action="transfer", roles=("FINANCIAL",), now=now, grants=grants,
                       exceptions=(waiver_for(policy),))
    ledger, receipt = _enforce(policy, request)
    return ledger, receipt, policy, {}


@_case(TIER2, "exceptions")
def no_waiver_keeps_deny() -> tuple:
    policy = _policy(_fin(1, 10))
    ledger, receipt = _enforce(policy, _request(policy, "exc-none", action="transfer", roles=("FINANCIAL",)))
    return ledger, receipt, policy, {}


@_case(TIER2, "exceptions")
def in_window_waiver_applied() -> tuple:
    return _exception_case("exc-window", lambda policy: _waiver(policy))


@_case(TIER2, "exceptions")
def expired_waiver_not_applied() -> tuple:
    return _exception_case("exc-expired", lambda policy: _waiver(policy), now=200)


@_case(TIER2, "exceptions")
def waiver_of_allow_rule_is_overreach() -> tuple:
    return _exception_case("exc-allow", lambda policy: _waiver(policy, rule_id="ALLOW-FIN"))


@_case(TIER2, "exceptions")
def action_beyond_grant_is_overreach() -> tuple:
    return _exception_case("exc-grant", lambda policy: _waiver(policy), exceptor_actions=("publish",))


@_case(TIER2, "exceptions")
def lifetime_beyond_policy_bound_is_overreach() -> tuple:
    return _exception_case("exc-life", lambda policy: _waiver(policy, expires_at=200))


@_case(TIER2, "exceptions")
def duplicate_identifier_refused() -> tuple:
    policy = _policy(_fin(1, 10))
    grants = (_grant(policy), _grant(policy, oracle.EXCEPTOR, may_decide=False, may_except=True, actions=("transfer",)))
    waiver = _waiver(policy)
    request = _request(policy, "exc-dup", action="transfer", roles=("FINANCIAL",), grants=grants,
                       exceptions=(waiver, waiver))
    ledger, receipt = _enforce(policy, request)
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def declared_current_pointer_allows() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "rev-current"))
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def superseded_revision_refused() -> tuple:
    policy = _policy(revision=1)
    newer = _policy(revision=2)
    pointer = _pointer(policy, revision=2, policy_digest=newer.digest)
    ledger, receipt = _enforce(policy, _request(policy, "rev-superseded", current=pointer))
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def pointer_missing_refused() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "rev-missing", current=None))
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def pointer_bit_flipped_refused() -> tuple:
    policy = _policy()
    pointer = _pointer(policy)
    mac = pointer.mac[:-1] + ("0" if pointer.mac[-1] != "0" else "1")
    ledger, receipt = _enforce(policy, _request(policy, "rev-flipped", current=dataclasses.replace(pointer, mac=mac)))
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def pointer_over_altered_policy_refused() -> tuple:
    policy = _policy()
    altered = _policy(DEFAULT_RULES[:1])
    ledger, receipt = _enforce(policy, _request(policy, "rev-altered", current=_pointer(policy, policy_digest=altered.digest)))
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def stale_request_revision_refused() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "rev-stale", revision=2))
    return ledger, receipt, policy, {}


@_case(TIER2, "revisions")
def prior_revision_grant_refused() -> tuple:
    current = _policy(revision=2)
    prior_grant = _grant(_policy(revision=1))
    ledger, receipt = _enforce(current, _request(current, "rev-prior", grants=(prior_grant,)))
    return ledger, receipt, current, {}


@_case(TIER2, "authority")
def bit_flipped_grant_unverified() -> tuple:
    policy = _policy()
    grant = _grant(policy)
    mac = grant.mac[:-1] + ("0" if grant.mac[-1] != "0" else "1")
    ledger, receipt = _enforce(policy, _request(policy, "auth-flipped", grants=(dataclasses.replace(grant, mac=mac),)))
    return ledger, receipt, policy, {}


@_case(TIER2, "activation")
def before_active_window_refused() -> tuple:
    policy = _policy(active_from=200)
    ledger, receipt = _enforce(policy, _request(policy, "activation-early"))
    return ledger, receipt, policy, {}


# --- POLICY-3.3: decision evidence, enforcement points, bypass and unavailable behavior ------

EVIDENCE_POLICY_ID = "POL-NO-REVOKED-ANCESTORS"


def _evidence_case(tag: str, evidence: Any, *, target: str = TARGET) -> tuple:
    policy = _evidence_policy(EVIDENCE_POLICY_ID)
    request = _request(policy, tag, action="release", target=target, evidence=evidence)
    ledger, receipt = _enforce(policy, request)
    return ledger, receipt, policy, {"evidence": None if evidence is None else evidence.to_dict()}


@_case(TIER3, "decision_evidence")
def passing_evidence_authorizes() -> tuple:
    evidence = pe._route_evidence(revoked=False)
    return _evidence_case("ev-pass", evidence)


@_case(TIER3, "decision_evidence")
def missing_evidence_refused() -> tuple:
    policy = _evidence_policy(EVIDENCE_POLICY_ID)
    ledger, receipt = _enforce(policy, _request(policy, "ev-missing", action="release"))
    return ledger, receipt, policy, {"evidence": None}


@_case(TIER3, "decision_evidence")
def other_target_refused() -> tuple:
    return _evidence_case("ev-target", pe._route_evidence(revoked=False), target=OTHER_TARGET)


@_case(TIER3, "decision_evidence")
def failing_evidence_refused() -> tuple:
    return _evidence_case("ev-failing", pe._route_evidence(revoked=True))


def _mutated(**changes: Any) -> Any:
    return dataclasses.replace(pe._route_evidence(revoked=False), **changes)


@_case(TIER3, "decision_evidence")
def mutated_policy_id_refused() -> tuple:
    return _evidence_case("ev-mut-policy", _mutated(policy_id="POL-OTHER"))


@_case(TIER3, "decision_evidence")
def mutated_target_refused() -> tuple:
    return _evidence_case("ev-mut-target", _mutated(target_artifact_id="artifact:other"))


@_case(TIER3, "decision_evidence")
def mutated_passed_refused() -> tuple:
    return _evidence_case("ev-mut-passed", _mutated(passed=False))


@_case(TIER3, "decision_evidence")
def mutated_clauses_refused() -> tuple:
    return _evidence_case("ev-mut-clauses", _mutated(clauses=((1,),)))


@_case(TIER3, "decision_evidence")
def mutated_variable_map_refused() -> tuple:
    original = pe._route_evidence(revoked=False)
    return _evidence_case("ev-mut-vars", _mutated(variable_map=original.variable_map + (("EXTRA", 99),)))


@_case(TIER3, "decision_evidence")
def mutated_member_values_refused() -> tuple:
    return _evidence_case("ev-mut-members", _mutated(member_values=(("artifact:ghost", "REVOKED"),)))


@_case(TIER3, "decision_evidence")
def mutated_certificate_refused() -> tuple:
    return _evidence_case("ev-mut-cert", _mutated(certificate=pe._route_evidence(revoked=True).certificate))


@_case(TIER3, "enforcement_points")
def undeclared_point_refused() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "point-undeclared", point="ADMISSION"))
    return ledger, receipt, policy, {}


@_case(TIER3, "enforcement_points")
def declared_point_allowed() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "point-declared", point="EXECUTION"))
    return ledger, receipt, policy, {}


def _bypass_case(effect_factory: Callable[[Any, Any], list]) -> tuple:
    policy = _policy()
    ledger, allowed = _enforce(policy, _request(policy, "req-a"))
    ledger, _ = _enforce(policy, _request(policy, "req-r", action="destroy"), ledger=ledger)
    effects = effect_factory(allowed, policy)
    report = pe.build_report(policy, ledger, effects)
    findings = [item.reason for item in pe.detect_bypass(ledger, effects)]
    return ledger, allowed, policy, {
        "bypass_findings": findings,
        "unsupplied_effects": report["effect_coverage"]["unsupplied_effects"],
    }


@_case(TIER3, "bypass_handling")
def supplied_honest_effect_not_a_finding() -> tuple:
    return _bypass_case(lambda allowed, policy: [
        pe.EffectClaim("req-a", "RELEASE", "publish", TARGET, request_digest=allowed.request_digest)])


@_case(TIER3, "bypass_handling")
def ghost_effect_is_a_finding() -> tuple:
    return _bypass_case(lambda allowed, policy: [pe.EffectClaim("req-ghost", "RELEASE", "publish", TARGET)])


@_case(TIER3, "bypass_handling")
def refused_effect_is_a_finding() -> tuple:
    return _bypass_case(lambda allowed, policy: [pe.EffectClaim("req-r", "RELEASE", "destroy", TARGET)])


@_case(TIER3, "bypass_handling")
def wrong_target_effect_is_a_finding() -> tuple:
    return _bypass_case(lambda allowed, policy: [pe.EffectClaim("req-a", "RELEASE", "publish", OTHER_TARGET)])


@_case(TIER3, "bypass_handling")
def forged_request_digest_is_a_finding() -> tuple:
    return _bypass_case(lambda allowed, policy: [pe.EffectClaim(
        "req-a", "RELEASE", "publish", TARGET, request_digest=pe.value_digest(_request(policy, "other", now=NOW + 1).to_dict()))])


def _fault_case(owner: Any, attribute: str, replacement: Any) -> tuple:
    policy = _policy()
    request = _request(policy, "fault-" + attribute.lstrip("_"))
    with _patched(owner, attribute, replacement):
        ledger, receipt = _enforce(policy, request)
    return ledger, receipt, policy, {}


@_case(TIER3, "unavailable_behavior")
def authority_stage_fault_unavailable() -> tuple:
    return _fault_case(pe, "_find_decision_authority", _injected)


@_case(TIER3, "unavailable_behavior")
def exception_stage_fault_unavailable() -> tuple:
    return _fault_case(pe, "_evaluate_exceptions", _injected)


@_case(TIER3, "unavailable_behavior")
def role_stage_fault_unavailable() -> tuple:
    return _fault_case(pe, "_decide_role", _injected)


@_case(TIER3, "unavailable_behavior")
def missing_verdict_unavailable() -> tuple:
    return _fault_case(pe, "_decide", lambda *args, **kwargs: None)


@_case(TIER3, "unavailable_behavior")
def request_digest_fault_unavailable_and_unsealed() -> tuple:
    real = pe.value_digest

    def fail_on_request(value: Any) -> str:
        if isinstance(value, dict) and "request_id" in value:
            raise ValueError("injected digest fault")
        return real(value)

    return _fault_case(pe, "value_digest", fail_on_request)


@_case(TIER3, "unavailable_behavior")
def uncomparable_trust_root_unavailable() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "trust-bytes"), trust={oracle.DECIDER: "not-bytes"})
    return ledger, receipt, policy, {}


@_case(TIER3, "unavailable_behavior")
def non_mapping_trust_roots_unavailable() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, _request(policy, "trust-shape"), trust=123)
    return ledger, receipt, policy, {}


@_case(TIER3, "unavailable_behavior")
def non_policy_input_refused_with_receipt() -> tuple:
    ledger, receipt = _enforce({"not": "a policy"}, _request(_policy(), "bad-policy"))
    return ledger, receipt, None, {}


@_case(TIER3, "unavailable_behavior")
def non_request_input_refused_with_receipt() -> tuple:
    policy = _policy()
    ledger, receipt = _enforce(policy, {"request_id": "bad-request"})
    return ledger, receipt, policy, {}


@_case(TIER3, "unavailable_behavior")
def non_ledger_argument_raises_without_receipt() -> tuple:
    policy = _policy()
    try:
        pe.enforce(["not", "a", "ledger"], policy, _request(policy, "bad-ledger"), _TRUST)
    except TypeError:
        return None, None, None, {"raised": "TypeError"}
    return None, None, None, {"raised": None}


# --- Observation, worker and parent evaluation ---------------------------------------------

def _observe(name: str, coordinate: str, field: str, ledger: Any, receipt: Any, policy: Any, extra: dict) -> dict:
    if receipt is None:
        return {"case": name, "coordinate": coordinate, "field": field, "receipt_count": 0,
                "raised": extra.get("raised"), **{key: value for key, value in extra.items() if key != "raised"}}
    observation = {
        "case": name, "coordinate": coordinate, "field": field, "raised": None,
        "receipt_count": len(ledger.receipts), "chain_verified": pe.verify_chain(ledger),
        "outcome": receipt.outcome, "reasons": list(receipt.reasons),
        "role_dispositions": [list(item) for item in receipt.role_dispositions],
        "exception_dispositions": [list(item) for item in receipt.exception_dispositions],
        "policy_id": receipt.policy_id, "action": receipt.action,
        "rules": [] if policy is None else [rule.to_dict() for rule in policy.rules],
        "trust_root_id": receipt.trust_root_id, "trust_root_digest": receipt.trust_root_digest,
        "trust_roots_digest": receipt.trust_roots_digest, "evidence_digest": receipt.evidence_digest,
    }
    observation.update(extra)
    return observation


def _run(name: str) -> dict:
    coordinate, field, function = _CASES[name]
    ledger, receipt, policy, extra = function()
    return _observe(name, coordinate, field, ledger, receipt, policy, extra)


def observe_all() -> list[dict]:
    """Raw observations of every registered case, in registration order. Judgement belongs to the oracle."""
    return [_run(name) for name in _CASES]


def observe_route(coordinate: str) -> list[dict]:
    """Raw observations of one route's cases, for in-process falsification."""
    return [_run(name) for name, (route, _, _) in _CASES.items() if route == coordinate]


def _central_registration(route: str) -> str:
    """Classify one route's central row by exact key equality; ambiguity and malformed rows are UNKNOWN."""
    expected = CENTRAL_BINDINGS[route]
    try:
        from verifier.runtime.manifest_gate import obligation_catalog

        rows = obligation_catalog()
    except Exception:  # an unreadable central catalog is UNKNOWN, never a registration
        return "UNKNOWN"
    if type(rows) is not list or not all(type(row) is dict for row in rows):
        return "UNKNOWN"
    # A row claims this route by its exact short coordinate or its exact full route name, never by prefix.
    claims = [row for row in rows if row.get("coordinate") == expected["coordinate"] or row.get("obligation_id") == route]
    if not claims:
        return "NOT_REGISTERED"
    if len(claims) > 1:
        return "UNKNOWN"
    claim = claims[0]
    if any(type(claim.get(field)) is not type(value) for field, value in expected.items()):
        return "UNKNOWN"
    if any(claim[field] != value for field, value in expected.items()):
        return "NOT_REGISTERED"
    return CENTRAL_PRESENT


def _unknown(reason: str) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA, "auxiliary_verdict": oracle.UNKNOWN, "reason": reason,
        "routes": [], "route_conformance": pe.NOT_ESTABLISHED, "obligation_closure": pe.NOT_ESTABLISHED,
    }


def evaluate_routes(*, timeout: int = 180) -> dict[str, Any]:
    """Run the isolated worker, check its echoed nonce and source pins, and judge every route with the oracle."""
    expected_pins = oracle.source_pins()
    request = json.dumps({"schema": oracle.REQUEST_SCHEMA, "nonce": NONCE}).encode()
    worker = Path(oracle.__file__)
    try:
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(worker)], input=request,
                                   capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        return _unknown("WORKER_UNAVAILABLE:" + type(error).__name__)
    if completed.returncode != 0:
        return _unknown("WORKER_FAILED")
    try:
        payload = json.loads(completed.stdout)
    except ValueError:
        return _unknown("WORKER_OUTPUT_INVALID")
    if not (type(payload) is dict and payload.get("schema") == oracle.OBSERVATION_SCHEMA
            and payload.get("nonce") == NONCE and type(payload.get("observations")) is list):
        return _unknown("WORKER_OUTPUT_INVALID")
    if payload.get("source_pins") != expected_pins:
        return _unknown("SOURCE_DRIFT")
    verdicts, global_refusals = oracle.check_all(payload["observations"])
    routes = []
    for coordinate in COORDINATES:
        verdict, refusals = verdicts[coordinate]
        if global_refusals:
            verdict, refusals = oracle.FAIL, refusals + global_refusals
        routes.append({
            "coordinate": coordinate,
            "tier": int(coordinate.split("-", 1)[1].split(".", 1)[0]),
            "auxiliary_verdict": verdict,
            "refusals": refusals,
            "fields": [{"field": field, "declared_status": status} for field, status in oracle.DECLARED_STATUS[coordinate].items()],
            "central_registration": _central_registration(coordinate),
            "route_conformance": pe.NOT_ESTABLISHED,
            "obligation_closure": pe.NOT_ESTABLISHED,
        })
    aggregate = oracle.FAIL if any(item["auxiliary_verdict"] == oracle.FAIL for item in routes) else oracle.PASS
    return {
        "schema": REPORT_SCHEMA,
        "auxiliary_verdict": aggregate,
        "routes": routes,
        "source_pins": expected_pins,
        "case_count": len(payload["observations"]),
        "external_boundaries": {name: oracle.UNKNOWN for name in EXTERNAL_BOUNDARIES},
        "route_conformance": pe.NOT_ESTABLISHED,
        "obligation_closure": pe.NOT_ESTABLISHED,
    }
