"""Adversarial tests for the in-memory POLICY enforcement mechanism.

The mechanism is exercised only through its public surface: policies, grants,
exceptions, requests, the append-only ledger, bypass detection and the
replayable report. Real decision evidence comes from
``ProvenancePolicyVerifier`` so the evidence linkage is tested against the
installed decision engine rather than against a hand-written object.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    RightsSpec,
    TransformationHyperedge,
    TransformationType,
)
from verifier.data.policy import ProvenancePolicyVerifier
from verifier.runtime import policy_enforcement_execution as pe

TARGET = "artifact:target"
ANCESTOR = "artifact:ancestor"
DECIDER = "authority:decider"
EXCEPTOR = "authority:exceptor"
CLERK = "authority:clerk"
TRUST = {DECIDER: b"d" * 32, EXCEPTOR: b"e" * 32, CLERK: b"c" * 32}
NOW = 100


def rule(rule_id, priority, effect, actions=("publish",), roles=("POLICY",), evidence=False):
    return pe.Rule(rule_id, priority, effect, actions, roles, evidence)


def policy(rules=None, *, revision=1, decision_policy_id="POL-NO-REVOKED-ANCESTORS", **overrides):
    fields = {
        "policy_id": "policy:release",
        "revision": revision,
        "scope": ("publish", "transfer"),
        "rules": rules
        if rules is not None
        else (
            rule("ALLOW-PUBLISH", 1, "ALLOW", ("publish",), ("POLICY", "MODEL")),
            rule("ALLOW-TRANSFER", 1, "ALLOW", ("transfer",), ("POLICY",)),
        ),
        "enforcement_points": ("EXECUTION", "RELEASE"),
        "active_from": 0,
        "active_until": None,
        "decision_policy_id": decision_policy_id,
        "max_exception_lifetime": 50,
    }
    fields.update(overrides)
    return pe.PolicyVersion(**fields)


def grant(p, authority=DECIDER, *, may_decide=True, may_except=False, actions=("publish", "transfer")):
    return pe.issue_authorization(
        TRUST[authority], p, authority, may_decide=may_decide, may_except=may_except, actions=actions
    )


_DECLARED = object()


def declared(p, *, revision=None, policy_digest=None, key=None, authority=DECIDER):
    """A current-revision pointer, signed by ``authority``, declaring ``p``'s revision unless overridden."""
    return pe.issue_current_revision(
        TRUST[authority] if key is None else key,
        policy_id=p.policy_id,
        revision=p.revision if revision is None else revision,
        policy_digest=p.digest if policy_digest is None else policy_digest,
        authority_id=authority,
    )


def request(p, *, request_id="req-1", action="publish", roles=("POLICY",), point="RELEASE",
            revision=None, now=NOW, authorizations=None, exceptions=(), evidence=None, target=TARGET,
            current=_DECLARED):
    return pe.EnforcementRequest(
        request_id=request_id,
        policy_id=p.policy_id,
        revision=p.revision if revision is None else revision,
        point=point,
        action=action,
        target=target,
        roles=roles,
        now=now,
        authorizations=(grant(p),) if authorizations is None else authorizations,
        exceptions=exceptions,
        decision_evidence=evidence,
        current_revision=declared(p) if current is _DECLARED else current,
    )


def decide(p, req, ledger=None):
    return pe.enforce(pe.empty_ledger() if ledger is None else ledger, p, req, TRUST)


def receipt(p, req):
    return decide(p, req)[1]


def waiver(p, *, exception_id="exc-1", rule_id="DENY-FIN", action="transfer", target=TARGET,
           not_before=60, expires_at=110):
    return pe.issue_exception(
        TRUST[EXCEPTOR], p, exception_id=exception_id, rule_id=rule_id, action=action, target=target,
        granted_by=EXCEPTOR, not_before=not_before, expires_at=expires_at,
    )


def flip_last_hex(text):
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def financial_policy(**overrides):
    return policy(
        (
            rule("ALLOW-FIN", 1, "ALLOW", ("transfer",), ("FINANCIAL",)),
            rule("DENY-FIN", 10, "DENY", ("transfer",), ("FINANCIAL",)),
        ),
        **overrides,
    )


def graph(ancestor_status):
    g = ProvenanceHypergraph()
    g.add_rights(RightsSpec("rights:ancestor", "MIT"))
    g.add_rights(RightsSpec("rights:target", "MIT"))
    g.add_artifact(
        ArtifactNode(
            artifact_id=ANCESTOR,
            label=ANCESTOR,
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="0" * 64,
            status=ancestor_status,
            rights_id="rights:ancestor",
        )
    )
    g.add_artifact(
        ArtifactNode(
            artifact_id=TARGET,
            label=TARGET,
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="1" * 64,
            status=ArtifactStatus.VALID,
            rights_id="rights:target",
        )
    )
    g.add_transformation(
        TransformationHyperedge(
            transformation_id="transform:derive",
            label="derive target from ancestor",
            transformation_type=TransformationType.EVALUATION,
            inputs=(HyperedgePort(ANCESTOR, "INPUT"),),
            outputs=(HyperedgePort(TARGET, "OUTPUT"),),
            software_provenance={},
            parameters={},
            execution_environment={},
        )
    )
    return g


# --- Module surface and stdlib purity -------------------------------------------------


def test_module_imports_only_standard_library_and_repository_code() -> None:
    tree = ast.parse(Path(pe.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names.add((node.module or "").split(".")[0])
    assert names
    assert all(name == "verifier" or name in sys.stdlib_module_names for name in names), names


# --- Allow, default, role accumulation and precedence ---------------------------------


def test_allows_when_every_role_has_an_authorized_allow_rule() -> None:
    result = receipt(policy(), request(policy(), action="publish", roles=("MODEL", "POLICY")))
    assert result.outcome == pe.ALLOWED
    assert sorted(result.role_dispositions) == [
        ("MODEL", "ALLOW", "ALLOWED_BY_RULE:ALLOW-PUBLISH"),
        ("POLICY", "ALLOW", "ALLOWED_BY_RULE:ALLOW-PUBLISH"),
    ]


def test_policy_label_does_not_exempt_financial_consequence() -> None:
    p = policy()
    result = receipt(p, request(p, action="transfer", roles=("FINANCIAL", "POLICY")))
    assert result.outcome == pe.REFUSED
    assert ("FINANCIAL", "DENY", "NO_MATCHING_RULE") in result.role_dispositions
    assert ("POLICY", "ALLOW", "ALLOWED_BY_RULE:ALLOW-TRANSFER") in result.role_dispositions


@pytest.mark.parametrize("role", ["AGENT", "FINANCIAL", "PHYSICAL"])
def test_consequence_roles_without_rules_are_refused(role: str) -> None:
    p = policy()
    result = receipt(p, request(p, action="publish", roles=("POLICY", role)))
    assert result.outcome == pe.REFUSED
    assert (role, "DENY", "NO_MATCHING_RULE") in result.role_dispositions


def test_default_is_deny_when_no_rule_matches() -> None:
    p = policy(rules=())
    result = receipt(p, request(p))
    assert result.outcome == pe.REFUSED
    assert ("POLICY", "DENY", "NO_MATCHING_RULE") in result.role_dispositions


def test_default_effect_other_than_deny_is_not_constructible() -> None:
    with pytest.raises(pe.PolicyDefinitionError):
        policy(default_effect="ALLOW")


def test_higher_priority_allow_overrides_lower_deny() -> None:
    p = policy((rule("DENY", 1, "DENY"), rule("ALLOW", 5, "ALLOW")))
    assert receipt(p, request(p)).outcome == pe.ALLOWED


def test_higher_priority_deny_overrides_lower_allow() -> None:
    p = policy((rule("ALLOW", 1, "ALLOW"), rule("DENY", 5, "DENY")))
    result = receipt(p, request(p))
    assert result.outcome == pe.REFUSED
    assert ("POLICY", "DENY", "DENIED_BY_RULE:DENY") in result.role_dispositions


def test_same_priority_allow_and_deny_conflict_is_refused_not_resolved() -> None:
    p = policy((rule("ALLOW", 3, "ALLOW"), rule("DENY", 3, "DENY")))
    result = receipt(p, request(p))
    assert result.outcome == pe.REFUSED
    assert ("POLICY", "DENY", "PRECEDENCE_CONFLICT") in result.role_dispositions


# --- Scope, activation, revisions and point declarations ------------------------------


def test_action_outside_declared_scope_is_refused() -> None:
    p = policy()
    result = receipt(p, request(p, action="release"))
    assert result.outcome == pe.REFUSED
    assert "OUT_OF_SCOPE" in result.reasons


@pytest.mark.parametrize("now,window", [(100, {"active_from": 200}), (100, {"active_until": 100})])
def test_inactive_policy_is_refused_before_and_after_its_window(now: int, window: dict) -> None:
    p = policy(**window)
    result = receipt(p, request(p, now=now))
    assert result.outcome == pe.REFUSED
    assert "POLICY_INACTIVE" in result.reasons


def test_stale_request_revision_is_refused() -> None:
    p = policy(revision=2)
    result = receipt(p, request(p, revision=1))
    assert result.outcome == pe.REFUSED
    assert "STALE_REVISION" in result.reasons


def test_authorization_for_prior_revision_does_not_authorize_new_revision() -> None:
    old = policy(revision=1)
    new = policy(revision=2)
    result = receipt(new, request(new, authorizations=(grant(old),)))
    assert result.outcome == pe.REFUSED
    assert "AUTHORIZATION_REVISION_MISMATCH" in result.reasons
    assert "NO_DECISION_AUTHORITY" in result.reasons


def test_undeclared_enforcement_point_is_refused() -> None:
    p = policy()
    result = receipt(p, request(p, point="PERSISTENCE"))
    assert result.outcome == pe.REFUSED
    assert "POINT_NOT_DECLARED" in result.reasons


# --- Authority: forged, unknown, non-decision and tampered policy ----------------------


def test_bit_flipped_authorization_is_refused_as_unverified() -> None:
    p = policy()
    auth = grant(p)
    forged = dataclasses.replace(auth, mac=flip_last_hex(auth.mac))
    result = receipt(p, request(p, authorizations=(forged,)))
    assert result.outcome == pe.REFUSED
    assert "UNVERIFIED_AUTHORITY" in result.reasons


def test_non_ascii_mac_is_unverified_not_an_evaluator_fault() -> None:
    p = policy()
    auth = grant(p)
    forged = dataclasses.replace(auth, mac="é" + auth.mac[1:])
    result = receipt(p, request(p, authorizations=(forged,)))
    assert result.outcome == pe.REFUSED
    assert "UNVERIFIED_AUTHORITY" in result.reasons


def test_authorization_from_unknown_authority_is_refused() -> None:
    p = policy()
    stranger = pe.issue_authorization(b"x" * 32, p, "authority:nobody", may_decide=True, actions=("publish",))
    result = receipt(p, request(p, authorizations=(stranger,)))
    assert result.outcome == pe.REFUSED
    assert "UNVERIFIED_AUTHORITY" in result.reasons


def test_validly_signed_clerk_without_decision_authority_is_refused() -> None:
    p = policy()
    clerk = grant(p, CLERK, may_decide=False)
    result = receipt(p, request(p, authorizations=(clerk,)))
    assert result.outcome == pe.REFUSED
    assert "NOT_DECISION_AUTHORITY" in result.reasons


def test_authorization_signed_over_other_policy_content_is_refused() -> None:
    signed = policy((rule("ALLOW", 1, "ALLOW", ("publish",), ("POLICY",)),))
    tampered = policy((rule("ALLOW", 1, "ALLOW", ("publish",), ("POLICY", "MODEL")),))
    result = receipt(tampered, request(tampered, authorizations=(grant(signed),)))
    assert result.outcome == pe.REFUSED
    assert "POLICY_DIGEST_MISMATCH" in result.reasons


# --- Exceptions: window, scope, authority, lifetime and overreach ---------------------


def _waiver_request(p, *, exceptor_actions=("transfer",), exceptor_may_except=True, exceptions=None):
    exc = waiver(p) if exceptions is None else exceptions
    auths = (grant(p), grant(p, EXCEPTOR, may_except=exceptor_may_except, actions=exceptor_actions))
    return request(p, action="transfer", roles=("FINANCIAL",), authorizations=auths,
                   exceptions=(exc,) if isinstance(exc, pe.PolicyException) else exc)


def test_deny_without_waiver_refuses_financial_transfer() -> None:
    p = financial_policy()
    result = receipt(p, request(p, action="transfer", roles=("FINANCIAL",),
                                authorizations=(grant(p),)))
    assert result.outcome == pe.REFUSED
    assert ("FINANCIAL", "DENY", "DENIED_BY_RULE:DENY-FIN") in result.role_dispositions


def test_in_window_exception_waives_named_deny_rule() -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p))
    assert result.outcome == pe.ALLOWED
    assert ("exc-1", "APPLIED") in result.exception_dispositions


@pytest.mark.parametrize("not_before,expires_at,disposition", [
    (40, 90, "EXPIRED"),
    (101, 151, "NOT_YET_ACTIVE"),
])
def test_expired_or_future_exception_is_not_applied(not_before: int, expires_at: int, disposition: str) -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptions=waiver(p, not_before=not_before, expires_at=expires_at)))
    assert result.outcome == pe.REFUSED
    assert ("exc-1", disposition) in result.exception_dispositions


def test_exception_for_other_target_is_not_applied() -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptions=waiver(p, target="artifact:other")))
    assert result.outcome == pe.REFUSED
    assert ("exc-1", "NON_MATCHING") in result.exception_dispositions


def test_exception_action_beyond_granting_authority_is_overreach() -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptor_actions=("publish",)))
    assert result.outcome == pe.REFUSED
    assert "EXCEPTION_OVERREACH:ACTION_BEYOND_GRANT" in result.reasons


def test_exception_from_authority_without_exception_authority_is_overreach() -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptor_may_except=False))
    assert result.outcome == pe.REFUSED
    assert "EXCEPTION_OVERREACH:NOT_EXCEPTION_AUTHORITY" in result.reasons


@pytest.mark.parametrize("not_before,expires_at", [(50, 200), (60, 60)])
def test_exception_lifetime_must_be_positive_and_within_policy_bound(not_before: int, expires_at: int) -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptions=waiver(p, not_before=not_before, expires_at=expires_at)))
    assert result.outcome == pe.REFUSED
    assert "EXCEPTION_OVERREACH:LIFETIME_BOUND" in result.reasons


def test_exception_lifetime_exactly_at_policy_bound_is_applied() -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptions=waiver(p, not_before=60, expires_at=110)))
    assert result.outcome == pe.ALLOWED
    assert ("exc-1", "APPLIED") in result.exception_dispositions


@pytest.mark.parametrize("not_before,expires_at,disposition", [
    (100, 150, "APPLIED"),
    (50, 100, "EXPIRED"),
])
def test_exception_window_is_half_open_at_both_edges(not_before: int, expires_at: int, disposition: str) -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptions=waiver(p, not_before=not_before, expires_at=expires_at)))
    assert ("exc-1", disposition) in result.exception_dispositions


def test_exception_cannot_waive_an_allow_rule() -> None:
    p = financial_policy()
    result = receipt(p, _waiver_request(p, exceptions=waiver(p, rule_id="ALLOW-FIN")))
    assert result.outcome == pe.REFUSED
    assert "EXCEPTION_OVERREACH:NOT_A_DENY_RULE" in result.reasons


def test_bit_flipped_exception_is_refused_as_unverified() -> None:
    p = financial_policy()
    exc = waiver(p)
    forged = dataclasses.replace(exc, mac=flip_last_hex(exc.mac))
    result = receipt(p, _waiver_request(p, exceptions=forged))
    assert result.outcome == pe.REFUSED
    assert "UNVERIFIED_EXCEPTION" in result.reasons


def test_exception_signed_for_prior_revision_is_stale() -> None:
    old = financial_policy(revision=1)
    new = financial_policy(revision=2)
    exc = waiver(old)
    auths = (grant(new), grant(new, EXCEPTOR, may_except=True, actions=("transfer",)))
    result = receipt(new, request(new, action="transfer", roles=("FINANCIAL",),
                                  authorizations=auths, exceptions=(exc,)))
    assert result.outcome == pe.REFUSED
    assert "STALE_REVISION" in result.reasons


def test_duplicate_exception_identifiers_are_refused() -> None:
    p = financial_policy()
    exc = waiver(p)
    result = receipt(p, _waiver_request(p, exceptions=(exc, exc)))
    assert result.outcome == pe.REFUSED
    assert "DUPLICATE_EXCEPTION" in result.reasons


# --- Decision evidence linkage --------------------------------------------------------


@pytest.fixture(scope="module")
def passing_evidence():
    return ProvenancePolicyVerifier.verify_no_revoked_ancestors(graph(ArtifactStatus.VALID), TARGET)


@pytest.fixture(scope="module")
def failing_evidence():
    return ProvenancePolicyVerifier.verify_no_revoked_ancestors(graph(ArtifactStatus.REVOKED), TARGET)


def _evidence_policy(decision_policy_id: str):
    return policy((rule("ALLOW-PUBLISH", 1, "ALLOW", ("publish",), ("POLICY",), evidence=True),),
                  decision_policy_id=decision_policy_id)


def test_real_decision_evidence_authorizes_evidence_bound_rule(passing_evidence) -> None:
    evidence = passing_evidence.decision_evidence()
    p = _evidence_policy(passing_evidence.policy_id)
    result = receipt(p, request(p, evidence=evidence))
    assert result.outcome == pe.ALLOWED
    assert result.evidence_digest == pe.value_digest(evidence.to_dict())


def test_missing_evidence_is_refused_for_evidence_bound_rule(passing_evidence) -> None:
    p = _evidence_policy(passing_evidence.policy_id)
    result = receipt(p, request(p))
    assert result.outcome == pe.REFUSED
    assert ("POLICY", "DENY", "EVIDENCE_MISSING") in result.role_dispositions


def test_evidence_bound_to_other_target_is_refused(passing_evidence) -> None:
    p = _evidence_policy(passing_evidence.policy_id)
    result = receipt(p, request(p, target="artifact:other", evidence=passing_evidence.decision_evidence()))
    assert result.outcome == pe.REFUSED
    assert "EVIDENCE_MISMATCH:TARGET" in result.reasons


def test_evidence_from_other_policy_is_refused(passing_evidence) -> None:
    p = _evidence_policy("POL-ALL-ANCESTORS-VALID")
    result = receipt(p, request(p, evidence=passing_evidence.decision_evidence()))
    assert result.outcome == pe.REFUSED
    assert "EVIDENCE_MISMATCH:POLICY" in result.reasons


def test_failing_decision_evidence_is_refused(failing_evidence) -> None:
    p = _evidence_policy(failing_evidence.policy_id)
    result = receipt(p, request(p, evidence=failing_evidence.decision_evidence()))
    assert result.outcome == pe.REFUSED
    assert "EVIDENCE_REJECTED:NOT_PASSED" in result.reasons


def test_forged_passed_flag_on_failing_evidence_is_rejected(failing_evidence) -> None:
    forged = dataclasses.replace(failing_evidence.decision_evidence(), passed=True)
    p = _evidence_policy(failing_evidence.policy_id)
    result = receipt(p, request(p, evidence=forged))
    assert result.outcome == pe.REFUSED
    assert "EVIDENCE_REJECTED:RECHECK_FAILED" in result.reasons


# --- Bypass detection, replay, ledger atomicity and unavailable evaluation ------------


def test_tampered_or_reordered_ledger_fails_chain_verification() -> None:
    p, requests = _sequence()
    ledger = pe.run_sequence(p, requests, TRUST)
    assert pe.verify_chain(ledger)
    first, second = ledger.receipts
    assert first.outcome == pe.REFUSED
    flipped = dataclasses.replace(first, outcome=pe.ALLOWED)
    assert not pe.verify_chain(pe.Ledger((flipped, second)))
    assert not pe.verify_chain(pe.Ledger((second, first)))
    relinked = dataclasses.replace(second, previous_digest=first.digest + "x")
    assert not pe.verify_chain(pe.Ledger((first, relinked)))
    assert pe.build_report(p, pe.Ledger((flipped, second)))["chain_verified"] is False


def test_effect_backed_by_allowed_receipt_is_not_a_bypass() -> None:
    p = policy()
    ledger, _ = decide(p, request(p))
    effect = pe.EffectClaim("req-1", "RELEASE", "publish", TARGET)
    assert pe.detect_bypass(ledger, (effect,)) == ()
    pe.assert_no_bypass(ledger, (effect,))


def test_effect_without_any_enforcement_receipt_is_a_bypass() -> None:
    p = policy()
    ledger, _ = decide(p, request(p))
    effect = pe.EffectClaim("ghost", "RELEASE", "publish", TARGET)
    findings = pe.detect_bypass(ledger, (effect,))
    assert [finding.reason for finding in findings] == ["NO_ENFORCEMENT_RECEIPT"]
    with pytest.raises(pe.PolicyBypassDetected):
        pe.assert_no_bypass(ledger, (effect,))


def test_effect_executed_after_refusal_is_a_bypass() -> None:
    p = policy()
    ledger, refused = decide(p, request(p, action="release"))
    assert refused.outcome == pe.REFUSED
    findings = pe.detect_bypass(ledger, (pe.EffectClaim("req-1", "RELEASE", "release", TARGET),))
    assert [finding.reason for finding in findings] == ["ENFORCEMENT_NOT_ALLOWED"]


def test_effect_with_different_action_than_enforced_is_a_bypass() -> None:
    p = policy()
    ledger, _ = decide(p, request(p, action="publish"))
    findings = pe.detect_bypass(ledger, (pe.EffectClaim("req-1", "RELEASE", "transfer", TARGET),))
    assert [finding.reason for finding in findings] == ["MISMATCHED_RECEIPT"]


def test_replayed_request_identifier_is_refused_and_appends_one_receipt() -> None:
    p = policy()
    first_ledger, first = decide(p, request(p))
    second_ledger, second = pe.enforce(first_ledger, p, request(p), TRUST)
    assert first.outcome == pe.ALLOWED
    assert second.outcome == pe.REFUSED
    assert "REPLAY_DETECTED" in second.reasons
    assert len(second_ledger.receipts) == len(first_ledger.receipts) + 1


def test_refusal_and_unavailable_evaluation_leave_prior_ledger_untouched() -> None:
    p = policy()
    before, _ = decide(p, request(p))
    before_digest = before.digest
    before_receipts = before.receipts

    refused_ledger, refused = pe.enforce(before, p, request(p, request_id="req-2", action="release"), TRUST)
    assert refused.outcome == pe.REFUSED
    assert before.digest == before_digest and before.receipts == before_receipts
    assert refused_ledger.receipts[:-1] == before_receipts

    broken_trust = {DECIDER: "not-bytes"}
    unavailable_ledger, unavailable = pe.enforce(before, p, request(p, request_id="req-3"), broken_trust)
    assert unavailable.outcome == pe.UNAVAILABLE
    assert before.digest == before_digest and before.receipts == before_receipts
    assert len(unavailable_ledger.receipts) == len(before_receipts) + 1


def test_unavailable_trust_root_fails_closed_not_allowed() -> None:
    p = policy()
    _, result = pe.enforce(pe.empty_ledger(), p, request(p), {DECIDER: "not-bytes"})
    assert result.outcome == pe.UNAVAILABLE
    assert any(reason.startswith("EVALUATOR_UNAVAILABLE:TypeError") for reason in result.reasons)


def test_unknown_role_or_point_is_not_constructible() -> None:
    p = policy()
    with pytest.raises(ValueError):
        request(p, roles=("ROBOT",))
    with pytest.raises(ValueError):
        request(p, point="SOMEWHERE")


# --- Closed forms, aliasing and definition validation ---------------------------------


def test_policy_round_trips_through_closed_form() -> None:
    p = financial_policy()
    assert pe.PolicyVersion.from_dict(p.to_dict()) == p


def test_unknown_policy_field_is_refused_in_closed_form() -> None:
    data = policy().to_dict()
    data["waiver"] = True
    with pytest.raises(pe.PolicyDefinitionError):
        pe.PolicyVersion.from_dict(data)


def test_unknown_rule_field_is_refused_in_closed_form() -> None:
    data = policy().to_dict()
    data["rules"][0]["override"] = "ALLOW"
    with pytest.raises(pe.PolicyDefinitionError):
        pe.PolicyVersion.from_dict(data)


def test_authorization_closed_form_refuses_unknown_field() -> None:
    data = grant(policy()).to_dict()
    data["extra"] = "value"
    with pytest.raises(pe.PolicyDefinitionError):
        pe.Authorization.from_dict(data)


def test_duplicate_rule_identifiers_are_refused() -> None:
    with pytest.raises(pe.PolicyDefinitionError):
        policy((rule("SAME", 1, "ALLOW"), rule("SAME", 2, "DENY")))


def test_rule_action_outside_scope_is_refused() -> None:
    with pytest.raises(pe.PolicyDefinitionError):
        policy((rule("OUTSIDE", 1, "ALLOW", ("release",), ("POLICY",)),))


def test_mutating_input_lists_after_construction_changes_nothing() -> None:
    actions = ["publish"]
    roles = ["POLICY"]
    scope = ["publish"]
    rules = [pe.Rule("ALLOW", 1, "ALLOW", actions, roles)]
    p = pe.PolicyVersion(
        policy_id="policy:release", revision=1, scope=scope, rules=rules,
        enforcement_points=["RELEASE"], active_from=0, active_until=None,
        decision_policy_id=None, max_exception_lifetime=50,
    )
    digest = p.digest
    actions.append("transfer")
    roles.append("FINANCIAL")
    scope.append("transfer")
    rules.append(rule("LATE", 9, "DENY", ("transfer",), ("FINANCIAL",)))
    assert p.digest == digest
    assert p.rules[0].actions == ("publish",)
    assert len(p.rules) == 1


# --- Replay, report binding and boundaries ---------------------------------------------


def _sequence():
    p = financial_policy()
    requests = (
        request(p, request_id="req-a", action="publish", roles=("POLICY",), authorizations=(grant(p),)),
        request(p, request_id="req-b", action="transfer", roles=("FINANCIAL",),
                authorizations=(grant(p), grant(p, EXCEPTOR, may_except=True, actions=("transfer",))),
                exceptions=(waiver(p),)),
    )
    return p, requests


def test_report_replays_byte_identically() -> None:
    p, requests = _sequence()
    ledger = pe.run_sequence(p, requests, TRUST)
    data = pe.report_bytes(pe.build_report(p, ledger))
    assert pe.replay_matches(data, p, requests, TRUST)


def test_replay_detects_changed_request_input() -> None:
    p, requests = _sequence()
    data = pe.report_bytes(pe.build_report(p, pe.run_sequence(p, requests, TRUST)))
    altered = (requests[0], dataclasses.replace(requests[1], action="publish"))
    assert not pe.replay_matches(data, p, altered, TRUST)


def test_replay_detects_altered_report_bytes() -> None:
    p, requests = _sequence()
    data = pe.report_bytes(pe.build_report(p, pe.run_sequence(p, requests, TRUST)))
    assert b'"outcome":"ALLOWED"' in data
    assert not pe.replay_matches(data.replace(b'"outcome":"ALLOWED"', b'"outcome":"REFUSED"', 1), p, requests, TRUST)


def test_report_binds_current_enforcement_and_policy_sources() -> None:
    p, requests = _sequence()
    report = pe.build_report(p, pe.run_sequence(p, requests, TRUST))
    enforcement = "sha256:" + hashlib.sha256(Path(pe.__file__).read_bytes()).hexdigest()
    import verifier.data.policy as policy_module
    consumed = "sha256:" + hashlib.sha256(Path(policy_module.__file__).read_bytes()).hexdigest()
    assert report["source_binding"] == {
        "enforcement_module_sha256": enforcement,
        "policy_module_sha256": consumed,
    }


EXPECTED_STATUS = {
    "scope": "PARTIAL",
    "decision_inputs": "PARTIAL",
    "defaults": "PARTIAL",
    "precedence": "PARTIAL",
    "exceptions": "PARTIAL",
    "authority": "BOUNDARY",
    "activation": "BOUNDARY",
    "revisions": "PARTIAL",
    "decision_evidence": "PARTIAL",
    "enforcement_points": "BOUNDARY",
    "bypass_handling": "PARTIAL",
    "unavailable_behavior": "PARTIAL",
}
EXPECTED_AUDIT = {
    "scope": "PARTIAL",
    "decision_inputs": "PARTIAL",
    "defaults": "PARTIAL",
    "precedence": "PARTIAL",
    "exceptions": "PARTIAL",
    "authority": "BOUNDARY_EXCLUDED",
    "activation": "BOUNDARY_EXCLUDED",
    "revisions": "PARTIAL",
    "decision_evidence": "PARTIAL",
    "enforcement_points": "BOUNDARY_EXCLUDED",
    "bypass_handling": "PARTIAL",
    "unavailable_behavior": "PARTIAL",
}
EXTERNAL_BOUNDARIES = (
    "legal authority",
    "complete downstream enforcement",
    "external policy adoption",
    "key custody",
    "signer identity",
    "truth of facts behind decision evidence",
)


def test_report_declares_field_dispositions_and_external_boundaries() -> None:
    p, requests = _sequence()
    report = pe.build_report(p, pe.run_sequence(p, requests, TRUST))
    fields = report["field_dispositions"]
    assert set(fields) == set(EXPECTED_STATUS)
    assert {name: row["auxiliary_status"] for name, row in fields.items()} == EXPECTED_STATUS
    assert {name: row["central_audit_snapshot_status"] for name, row in fields.items()} == EXPECTED_AUDIT
    assert report["declaration_refusals"] == []
    assert report["auxiliary_verdict"] == "PASS"
    assert report["route_conformance"] == pe.NOT_ESTABLISHED
    assert "verdict" not in report


def test_report_verdict_is_fail_on_bypass_and_unknown_when_unavailable() -> None:
    p, requests = _sequence()
    ledger = pe.run_sequence(p, requests, TRUST)
    bypass = (pe.EffectClaim("ghost", "RELEASE", "publish", TARGET),)
    assert pe.build_report(p, ledger, bypass)["auxiliary_verdict"] == "FAIL"
    broken = pe.run_sequence(p, (request(p, request_id="req-x"),), {DECIDER: "not-bytes"})
    assert pe.build_report(p, broken)["auxiliary_verdict"] == "UNKNOWN"


def test_build_report_tampered_disposition_reason_is_fail(monkeypatch) -> None:
    p, requests = _sequence()
    status, reason = pe._FIELD_DISPOSITIONS["precedence"]
    monkeypatch.setitem(pe._FIELD_DISPOSITIONS, "precedence", (status, reason + " Closed."))
    report = pe.build_report(p, pe.run_sequence(p, requests, TRUST))
    assert report["auxiliary_verdict"] == "FAIL"
    assert report["declaration_refusals"] == ["DISPOSITION_REASON_DRIFT:precedence"]


def test_build_report_missing_disposition_is_fail(monkeypatch) -> None:
    p, requests = _sequence()
    monkeypatch.delitem(pe._FIELD_DISPOSITIONS, "precedence")
    report = pe.build_report(p, pe.run_sequence(p, requests, TRUST))
    assert report["auxiliary_verdict"] == "FAIL"
    assert "DISPOSITION_MISSING:precedence" in report["declaration_refusals"]
    assert "DISPOSITION_SET_MISMATCH:precedence" in report["declaration_refusals"]


# --- Auxiliary route checks over the existing POLICY 0.x coordinates ------------------------
# Every output here is auxiliary field evidence. None of it is route conformance.

ROUTES = (
    "POLICY-1.1", "POLICY-1.2", "POLICY-1.3",
    "POLICY-2.1", "POLICY-2.2", "POLICY-2.3",
    "POLICY-3.1", "POLICY-3.2", "POLICY-3.3",
)


@pytest.fixture(scope="module")
def honest():
    return pe.auxiliary_observe_all()


def _with(observations, target, **changes):
    return [dataclasses.replace(item, **changes) if item.coordinate == target else item for item in observations]


def test_disposition_table_is_exactly_the_twelve_audited_fields() -> None:
    audited = {field for fields in pe._AUDITED_FIELDS.values() for field in fields}
    assert set(pe._FIELD_DISPOSITIONS) == audited == set(EXPECTED_STATUS)
    assert set(pe._DISPOSITION_REASON_SHA256) == set(pe._FIELD_DISPOSITIONS)
    assert {name: status for name, (status, _) in pe._FIELD_DISPOSITIONS.items()} == EXPECTED_STATUS


def test_self_declared_dispositions_match_the_central_audit() -> None:
    report = pe.auxiliary_evaluate_all()
    for route in report["routes"]:
        assert route["declaration_refusals"] == []
        assert all(row["agrees_with_audit"] for row in route["fields"])


def test_route_set_is_exactly_the_existing_policy_coordinates() -> None:
    from verifier.runtime import manifest_gate

    rows = pe.central_route_rows()
    assert tuple(row["coordinate"] for row in rows) == ROUTES
    central = {row["coordinate"]: row for row in manifest_gate.obligation_catalog()}
    for row in rows:
        source = central[row["coordinate"]]
        assert row["catalog_proposition_digest"] == source["proposition_digest"]
        assert row["catalog_checking_mechanism"] == source["checking_mechanism"]
        assert row["obligation_id"] == pe._DECLARATION_BY_TIER[row["tier"]]
    assert set(pe.SOURCE_ROUTE_COORDINATES) <= set(central)
    assert set(pe.SOURCE_ROUTE_COORDINATES).isdisjoint(ROUTES)


def test_route_bindings_match_current_catalog_exactly() -> None:
    from verifier.runtime import manifest_gate

    central = {row["coordinate"]: row for row in manifest_gate.obligation_catalog()}
    expected = {**pe._ROUTE_BINDING_DIGESTS, **pe._SOURCE_ROUTE_BINDING_DIGESTS}
    assert set(pe._ROUTE_BINDING_DIGESTS) == set(ROUTES)
    assert set(pe._SOURCE_ROUTE_BINDING_DIGESTS) == set(pe.SOURCE_ROUTE_COORDINATES)
    assert {
        coordinate: pe.value_digest({field: central[coordinate].get(field)
                                     for field in pe._ROUTE_BINDING_FIELDS})
        for coordinate in expected
    } == expected
    for coordinate in ("POLICY-1.3", "POLICY-2.3", "POLICY-3.3"):
        assert central[coordinate]["checking_mechanism"] == (
            "verifier.runtime.added_kind_behavioral_routes.recheck_policy_enforcement_certificate")
        assert central[coordinate]["adapter"] == "verifier-retained-policy-enforcement-1"


def test_central_route_rows_are_never_conformance() -> None:
    rows = pe.central_route_rows()
    assert all(row["execution_status"] == "NOT_EXECUTED" and row["route_conformance"] == pe.NOT_ESTABLISHED
               for row in rows)
    zero = "sha256:" + "0" * 64
    claims = [
        pe.AuxiliaryObservation(row["coordinate"], row["catalog_proposition_digest"], zero, zero, zero,
                                pe.PASS, pe.empty_ledger())
        for row in rows
    ]
    result = pe.auxiliary_check_observations(claims)
    assert result["auxiliary_verdict"] != pe.PASS
    assert "ADAPTER_PROPOSITION_MISMATCH:POLICY-1.1" in result["refusals"]


def test_auxiliary_pass_is_never_route_conformance() -> None:
    report = pe.auxiliary_evaluate_all()
    assert report["auxiliary_verdict"] == pe.PASS
    assert report["route_conformance"] == pe.NOT_ESTABLISHED
    assert report["obligation_closure"] == pe.NOT_ESTABLISHED
    assert "verdict" not in report
    for route in report["routes"]:
        assert route["auxiliary_verdict"] == pe.PASS
        assert route["route_conformance"] == pe.NOT_ESTABLISHED
        assert route["obligation_closure"] == pe.NOT_ESTABLISHED
        assert {"verdict", "conformance"}.isdisjoint(route)
    check = pe.auxiliary_check_observations(pe.auxiliary_observe_all())
    assert check["auxiliary_verdict"] == pe.PASS
    assert check["route_conformance"] == pe.NOT_ESTABLISHED


def test_single_route_pass_is_labelled_auxiliary() -> None:
    report = pe.auxiliary_evaluate("POLICY-2.1")
    assert report["auxiliary_verdict"] == pe.PASS
    assert report["route_conformance"] == pe.NOT_ESTABLISHED
    assert "not route conformance" in report["reason"]


def test_catalog_checking_mechanism_is_never_executed(monkeypatch) -> None:
    from verifier.runtime import provenance_policy_execution as central_route

    calls = []

    def sentinel(*args, **kwargs):
        calls.append(args)
        raise AssertionError("central checking mechanism executed")

    monkeypatch.setattr(central_route, "evaluate", sentinel)
    report = pe.auxiliary_evaluate_all()
    assert report["auxiliary_verdict"] == pe.PASS
    assert calls == []
    for route in report["routes"]:
        assert route["catalog_checking_mechanism_executed"] is False


def test_auxiliary_module_never_imports_the_central_checking_mechanism() -> None:
    tree = ast.parse(Path(pe.__file__).read_text(encoding="utf-8"))
    names = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    names += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
    assert not any("provenance_policy_execution" in name for name in names)


def test_auxiliary_status_cannot_mechanize_any_field(monkeypatch) -> None:
    report = pe.auxiliary_evaluate_all()
    for route in report["routes"]:
        assert route["unclosed_fields"]
        assert route["obligation_closure"] == pe.NOT_ESTABLISHED
        for row in route["fields"]:
            assert row["audited_status"] == pe._AUDITED_FIELDS[route["obligation_id"]][row["field"]]
    monkeypatch.setitem(pe._FIELD_DISPOSITIONS, "precedence",
                        ("MECHANIZED", pe._FIELD_DISPOSITIONS["precedence"][1]))
    route = pe.auxiliary_evaluate("POLICY-1.1")
    row = next(item for item in route["fields"] if item["field"] == "precedence")
    assert row["audited_status"] == "PARTIAL"
    assert row["agrees_with_audit"] is False
    assert route["auxiliary_verdict"] == pe.FAIL
    assert "DISPOSITION_DISAGREES_WITH_AUDIT:precedence" in route["declaration_refusals"]
    assert "precedence=PARTIAL" in route["unclosed_fields"]
    assert route["route_conformance"] == pe.NOT_ESTABLISHED


def test_external_boundaries_remain_unknown() -> None:
    assert pe.EXTERNAL_BOUNDARIES == EXTERNAL_BOUNDARIES
    report = pe.auxiliary_evaluate_all()
    for route in report["routes"]:
        assert route["external_boundaries"] == {name: pe.UNKNOWN for name in EXTERNAL_BOUNDARIES}
        assert "legal authority" in route["not_established"]
        assert "complete downstream enforcement" in route["not_established"]
        assert "external policy adoption" in route["not_established"]
        assert any("key custody" in item for item in route["not_established"])
        assert any("signer identity" in item for item in route["not_established"])
        assert "the truth of facts behind decision evidence" in route["not_established"]


def test_each_route_exercises_exactly_its_audited_fields() -> None:
    for obligation, fields in pe._AUDITED_FIELDS.items():
        cases = pe._CASES_BY_OBLIGATION[obligation]()
        assert {field for field, *_ in cases} == set(fields)


def test_field_snapshot_matches_central_field_audit() -> None:
    from verifier.runtime.package_contract_profiles import _DECLARATION_FIELD_STATUS_GROUPS, _FIELD_STATUS_NAMES

    for obligation, fields in pe._AUDITED_FIELDS.items():
        groups = _DECLARATION_FIELD_STATUS_GROUPS[obligation]
        central = {field: _FIELD_STATUS_NAMES[code] for code, names in groups.items() for field in names}
        assert central == fields


def test_live_central_field_audit_drift_is_unknown(monkeypatch) -> None:
    from verifier.runtime import package_contract_profiles as profiles

    groups = dict(profiles._DECLARATION_FIELD_STATUS_GROUPS)
    groups["POLICY-0.2-authority-and-exceptions"] = {"M": ("exceptions", "authority", "activation", "revisions")}
    monkeypatch.setattr(profiles, "_DECLARATION_FIELD_STATUS_GROUPS", groups)
    report = pe.auxiliary_evaluate("POLICY-2.1")
    assert report["auxiliary_verdict"] == pe.UNKNOWN
    assert report["reason"] == "CENTRAL_FIELD_AUDIT_DRIFT:POLICY-0.2-authority-and-exceptions"
    assert pe.auxiliary_evaluate_all()["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_check_observations([])["auxiliary_verdict"] == pe.UNKNOWN


@pytest.mark.parametrize("status", ["PASSED", "", None, ["MECHANIZED"]])
def test_tampered_disposition_status_fails_closed(monkeypatch, status) -> None:
    monkeypatch.setitem(pe._FIELD_DISPOSITIONS, "precedence", (status, pe._FIELD_DISPOSITIONS["precedence"][1]))
    report = pe.auxiliary_evaluate("POLICY-1.1")
    assert report["auxiliary_verdict"] == pe.FAIL
    assert "DISPOSITION_STATUS_INVALID:precedence" in report["declaration_refusals"]
    assert report["route_conformance"] == pe.NOT_ESTABLISHED


@pytest.mark.parametrize("reason", [
    "",
    None,
    "Auxiliary checks exercise an in-window waiver of a DENY rule. Central audit: PARTIAL.",
])
def test_tampered_disposition_reason_fails_closed(monkeypatch, reason) -> None:
    status = pe._FIELD_DISPOSITIONS["exceptions"][0]
    monkeypatch.setitem(pe._FIELD_DISPOSITIONS, "exceptions", (status, reason))
    report = pe.auxiliary_evaluate("POLICY-2.1")
    assert report["auxiliary_verdict"] == pe.FAIL
    assert report["declaration_refusals"] == ["DISPOSITION_REASON_DRIFT:exceptions"]
    assert report["route_conformance"] == pe.NOT_ESTABLISHED


def test_tampered_disposition_missing_fails_closed(monkeypatch) -> None:
    monkeypatch.delitem(pe._FIELD_DISPOSITIONS, "revisions")
    report = pe.auxiliary_evaluate("POLICY-2.2")
    assert report["auxiliary_verdict"] == pe.FAIL
    assert report["declaration_refusals"] == ["DISPOSITION_MISSING:revisions"]


def test_tampered_malformed_disposition_entry_fails_closed(monkeypatch) -> None:
    monkeypatch.setitem(pe._FIELD_DISPOSITIONS, "revisions", "MISSING")
    report = pe.auxiliary_evaluate("POLICY-2.2")
    assert report["auxiliary_verdict"] == pe.FAIL
    assert report["declaration_refusals"] == [
        "DISPOSITION_STATUS_INVALID:revisions", "DISPOSITION_REASON_DRIFT:revisions",
    ]


@pytest.mark.parametrize(("returncode", "stdout", "expected"), [
    (0, " M data/policy.py\n", "DIRTY_NOT_BLESSED"),
    (0, "", "CLEAN_NOT_BLESSED"),
    (128, "", "UNKNOWN"),
])
def test_repository_state_reports_git_status_without_blessing(monkeypatch, returncode, stdout, expected) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert pe._repository_state(Path(pe.__file__)) == expected
    assert calls[0][:3] == ["git", "--no-optional-locks", "status"]


def test_repository_state_is_unknown_without_git(monkeypatch) -> None:
    def missing(args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", missing)
    assert pe._repository_state(Path(pe.__file__)) == "UNKNOWN"


def test_auxiliary_reports_carry_repository_state_and_never_bless_it(monkeypatch) -> None:
    report = pe.auxiliary_evaluate("POLICY-3.2")
    assert report["policy_module_repository_state"] in {"CLEAN_NOT_BLESSED", "DIRTY_NOT_BLESSED", "UNKNOWN"}
    assert report["source_blessing"] == pe.NOT_ESTABLISHED
    monkeypatch.setattr(pe, "_repository_state", lambda path: "DIRTY_NOT_BLESSED")
    dirty = pe.auxiliary_evaluate("POLICY-3.2")
    assert dirty["policy_module_repository_state"] == "DIRTY_NOT_BLESSED"
    assert dirty["auxiliary_verdict"] == report["auxiliary_verdict"] == pe.PASS


def test_honest_fresh_observations_reconcile_to_pass(honest) -> None:
    result = pe.auxiliary_check_observations(honest)
    assert result["auxiliary_verdict"] == pe.PASS
    assert result["refusals"] == []
    assert result["fresh_auxiliary_verdicts"] == {coordinate: pe.PASS for coordinate in ROUTES}


def test_missing_observation_is_refused(honest) -> None:
    result = pe.auxiliary_check_observations([item for item in honest if item.coordinate != "POLICY-2.2"])
    assert result["auxiliary_verdict"] != pe.PASS
    assert result["refusals"] == ["MISSING_OBSERVATION:POLICY-2.2"]


def test_duplicate_observation_is_refused(honest) -> None:
    result = pe.auxiliary_check_observations([*honest, honest[0]])
    assert result["auxiliary_verdict"] != pe.PASS
    assert result["refusals"] == ["DUPLICATE_OBSERVATION:POLICY-1.1"]


@pytest.mark.parametrize("alias", ["POLICY-1.90", "policy-1.1", "POLICY-1.01", "POLICY-1.1 ", "POLICY-4.1"])
def test_unknown_or_aliased_route_is_refused(honest, alias) -> None:
    result = pe.auxiliary_check_observations(_with(honest, "POLICY-1.1", coordinate=alias))
    assert result["auxiliary_verdict"] != pe.PASS
    assert "UNKNOWN_ROUTE:" + repr(alias) in result["refusals"]
    assert "MISSING_OBSERVATION:POLICY-1.1" in result["refusals"]


@pytest.mark.parametrize("status", ["ALLOWED", "pass", "PASS ", "OK", ""])
def test_forged_status_words_are_refused(honest, status) -> None:
    result = pe.auxiliary_check_observations(_with(honest, "POLICY-1.1", auxiliary_verdict=status))
    assert result["auxiliary_verdict"] != pe.PASS
    assert "UNRECOGNIZED_STATUS:POLICY-1.1" in result["refusals"]


def test_forged_pass_on_a_failing_route_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(pe, "_decide_role", lambda policy, request, role, waived: (role, pe.ALLOW, "MUTANT"))
    failing = pe.auxiliary_observe("POLICY-1.1")
    assert failing.auxiliary_verdict == pe.FAIL
    result = pe.auxiliary_check_observations([dataclasses.replace(failing, auxiliary_verdict=pe.PASS)])
    assert result["auxiliary_verdict"] == pe.FAIL
    assert "FORGED_PASS:POLICY-1.1" in result["refusals"]


def test_reordered_receipts_fail_chain_and_are_refused(honest) -> None:
    item = next(obs for obs in honest if obs.coordinate == "POLICY-2.1")
    reordered = pe.Ledger(tuple(reversed(item.ledger.receipts)))
    result = pe.auxiliary_check_observations(_with(honest, "POLICY-2.1", ledger=reordered))
    assert "LEDGER_CHAIN_INVALID:POLICY-2.1" in result["refusals"]
    assert result["auxiliary_verdict"] != pe.PASS


@pytest.mark.parametrize(("field", "value"), [
    ("revision", 3),
    ("policy_digest", "sha256:" + "9" * 64),
    ("exception_dispositions", (("exc-forged", "APPLIED"),)),
    ("outcome", pe.REFUSED),
])
def test_rewritten_last_receipt_with_recomputed_digest_is_not_fresh(honest, field, value) -> None:
    item = next(obs for obs in honest if obs.coordinate == "POLICY-2.1")
    rewritten = dataclasses.replace(item.ledger.receipts[-1], **{field: value})
    rewritten = dataclasses.replace(rewritten, digest=pe.value_digest(rewritten.body()))
    ledger = pe.Ledger(item.ledger.receipts[:-1] + (rewritten,))
    assert pe.verify_chain(ledger)
    result = pe.auxiliary_check_observations(_with(honest, "POLICY-2.1", ledger=ledger))
    assert "LEDGER_NOT_FRESH:POLICY-2.1" in result["refusals"]
    assert result["auxiliary_verdict"] != pe.PASS


def test_authority_mutation_fails_only_the_authority_routes(monkeypatch) -> None:
    monkeypatch.setattr(pe, "_verified_grant", lambda authorization, trust: True)
    assert pe.auxiliary_evaluate("POLICY-2.1")["auxiliary_verdict"] == pe.FAIL
    assert pe.auxiliary_evaluate("POLICY-2.2")["auxiliary_verdict"] == pe.FAIL
    assert pe.auxiliary_evaluate("POLICY-1.1")["auxiliary_verdict"] == pe.PASS


def test_exception_mutation_fails_only_the_exception_routes(monkeypatch) -> None:
    monkeypatch.setattr(pe, "_evaluate_exceptions", lambda policy, request, trust: (frozenset(), (), ()))
    assert pe.auxiliary_evaluate("POLICY-2.1")["auxiliary_verdict"] == pe.FAIL
    assert pe.auxiliary_evaluate("POLICY-1.1")["auxiliary_verdict"] == pe.PASS


def test_bypass_mutation_fails_only_the_enforcement_routes(monkeypatch) -> None:
    monkeypatch.setattr(pe, "detect_bypass", lambda ledger, effects: ())
    assert pe.auxiliary_evaluate("POLICY-3.1")["auxiliary_verdict"] == pe.FAIL
    assert pe.auxiliary_evaluate("POLICY-2.1")["auxiliary_verdict"] == pe.PASS


def test_policy_revision_mutation_fails_only_the_revision_routes(monkeypatch) -> None:
    decide = pe._decide
    monkeypatch.setattr(pe, "_decide", lambda policy, request, trust: decide(
        policy, dataclasses.replace(request, revision=policy.revision), trust))
    assert pe.auxiliary_evaluate("POLICY-2.2")["auxiliary_verdict"] == pe.FAIL
    assert pe.auxiliary_evaluate("POLICY-1.2")["auxiliary_verdict"] == pe.PASS


def test_mechanism_fault_is_unknown_never_pass_or_fail(monkeypatch) -> None:
    def broken(*args, **kwargs):
        raise RuntimeError("fault")

    monkeypatch.setattr(pe, "enforce", broken)
    report = pe.auxiliary_evaluate("POLICY-1.1")
    assert report["auxiliary_verdict"] == pe.UNKNOWN
    assert report["reason"].startswith("FIELD_CHECKS_RAISED:")
    assert pe.auxiliary_evaluate_all()["auxiliary_verdict"] == pe.UNKNOWN


def test_aggregate_is_fail_when_any_route_diverges(monkeypatch) -> None:
    monkeypatch.setattr(pe, "_decide_role", lambda policy, request, role, waived: (role, pe.ALLOW, "MUTANT"))
    report = pe.auxiliary_evaluate_all()
    assert report["auxiliary_verdict"] == pe.FAIL
    assert [route["auxiliary_verdict"] for route in report["routes"]].count(pe.FAIL) >= 1


def test_source_drift_refuses_otherwise_honest_observations(monkeypatch, honest) -> None:
    drifted = {"enforcement_module_sha256": "sha256:" + "1" * 64, "policy_module_sha256": "sha256:" + "2" * 64}
    monkeypatch.setattr(pe, "_source_binding", lambda: drifted)
    result = pe.auxiliary_check_observations(honest)
    assert result["auxiliary_verdict"] != pe.PASS
    assert all("SOURCE_DRIFT:" + coordinate in result["refusals"] for coordinate in ROUTES)


def test_central_proposition_drift_refuses_observations(monkeypatch, honest) -> None:
    from verifier.runtime import manifest_gate

    original = manifest_gate.obligation_catalog

    def drifted():
        return [dict(row, proposition_digest="sha256:" + "3" * 64) if row.get("coordinate") == "POLICY-2.1" else row
                for row in original()]

    monkeypatch.setattr(manifest_gate, "obligation_catalog", drifted)
    result = pe.auxiliary_check_observations(honest)
    assert result["refusals"] == ["POLICY route binding drift: POLICY-2.1"]
    assert result["auxiliary_verdict"] != pe.PASS


def test_central_catalog_route_set_drift_makes_every_route_unknown(monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    original = manifest_gate.obligation_catalog
    monkeypatch.setattr(manifest_gate, "obligation_catalog",
                        lambda: [row for row in original() if row.get("coordinate") != "POLICY-3.3"])
    assert pe.auxiliary_evaluate("POLICY-1.1")["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_evaluate_all()["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_check_observations([])["auxiliary_verdict"] == pe.UNKNOWN


def test_unreadable_central_catalog_is_unknown_not_a_crash(monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    def unreadable():
        raise ImportError("catalog gone")

    monkeypatch.setattr(manifest_gate, "obligation_catalog", unreadable)
    assert pe.auxiliary_evaluate("POLICY-2.1")["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_evaluate_all()["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_check_observations([])["auxiliary_verdict"] == pe.UNKNOWN


def test_duplicate_central_route_row_is_unknown(monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    original = manifest_gate.obligation_catalog
    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: [
        *original(), next(row for row in original() if row.get("coordinate") == "POLICY-1.1")])
    assert pe.auxiliary_evaluate("POLICY-1.1")["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_evaluate_all()["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_check_observations([])["auxiliary_verdict"] == pe.UNKNOWN


@pytest.mark.parametrize(("coordinate", "field", "value"), [
    ("POLICY-3.3", "proposition_digest", "sha256:" + "7" * 64),
    ("POLICY-3.3", "mechanism_digest", "sha256:" + "8" * 64),
    ("POLICY-2.3", "checking_mechanism", "verifier.runtime.forged.evaluate"),
    ("POLICY-1.3", "exact_claim", "forged retained claim"),
    ("POLICY-2.90", "adapter", "forged-source-boundary-adapter"),
])
def test_forged_behavior_or_source_route_binding_is_unknown(monkeypatch, coordinate, field, value) -> None:
    from verifier.runtime import manifest_gate

    original = manifest_gate.obligation_catalog
    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: [
        dict(row, **{field: value}) if row.get("coordinate") == coordinate else row
        for row in original()
    ])
    reason = "POLICY route binding drift: " + coordinate
    assert pe.auxiliary_evaluate("POLICY-1.1")["reason"] == reason
    assert pe.auxiliary_evaluate_all()["reason"] == reason
    assert pe.auxiliary_check_observations([])["refusals"] == [reason]


def test_missing_source_boundary_route_is_unknown(monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    original = manifest_gate.obligation_catalog
    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: [
        row for row in original() if row.get("coordinate") != "POLICY-3.90"
    ])
    report = pe.auxiliary_evaluate("POLICY-3.3")
    assert report["auxiliary_verdict"] == pe.UNKNOWN
    assert report["reason"] == "the central catalog does not carry the exact POLICY source-boundary route set"


def test_observation_marks_absent_tokens_as_dash() -> None:
    policy = pe._route_policy()
    _, receipt = pe.enforce(pe.empty_ledger(), policy, pe._route_request(policy, "token-probe"), pe._ROUTE_TRUST)
    assert pe._observe_receipt(receipt, "ALL_ROLES_ALLOWED") == "ALLOWED|ALL_ROLES_ALLOWED"
    assert pe._observe_receipt(receipt, "NOT_PRESENT") == "ALLOWED|-"


def test_non_observation_items_and_untyped_ledgers_are_refused(honest) -> None:
    result = pe.auxiliary_check_observations(["not-an-observation", *honest])
    assert "OBSERVATION_TYPE_INVALID" in result["refusals"]
    assert result["auxiliary_verdict"] != pe.PASS
    result = pe.auxiliary_check_observations(_with(honest, "POLICY-1.1", ledger=None))
    assert "LEDGER_TYPE_INVALID:POLICY-1.1" in result["refusals"]
    assert result["auxiliary_verdict"] != pe.PASS


def test_central_row_with_wrong_tier_is_unknown(monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    original = manifest_gate.obligation_catalog
    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: [
        dict(row, tier=2) if row.get("coordinate") == "POLICY-1.1" else row for row in original()])
    assert pe.auxiliary_evaluate("POLICY-1.1")["auxiliary_verdict"] == pe.UNKNOWN
    assert pe.auxiliary_evaluate_all()["auxiliary_verdict"] == pe.UNKNOWN


def test_broken_fresh_chain_is_fail_not_pass(monkeypatch) -> None:
    monkeypatch.setattr(pe, "verify_chain", lambda ledger: False)
    report = pe.auxiliary_evaluate("POLICY-2.2")
    assert report["auxiliary_verdict"] == pe.FAIL
    assert report["reason"] == "LEDGER_CHAIN_INVALID"


def test_unknown_coordinate_is_unknown_without_reading_the_catalog() -> None:
    report = pe.auxiliary_evaluate("POLICY-1.90")
    assert report["auxiliary_verdict"] == pe.UNKNOWN
    assert report["reason"].startswith("UNKNOWN_ROUTE:")
    assert report["route_conformance"] == pe.NOT_ESTABLISHED


def test_route_evidence_fixtures_are_real_engine_outputs() -> None:
    passing = pe._route_evidence(revoked=False)
    failing = pe._route_evidence(revoked=True)
    assert passing.passed is True
    assert failing.passed is False
    assert passing.policy_id == failing.policy_id == "POL-NO-REVOKED-ANCESTORS"


def test_route_reports_bind_current_module_and_decision_policy_bytes() -> None:
    import verifier.data.policy as policy_module

    report = pe.auxiliary_evaluate("POLICY-3.2")
    assert report["source_binding"] == {
        "enforcement_module_sha256": "sha256:" + hashlib.sha256(Path(pe.__file__).read_bytes()).hexdigest(),
        "policy_module_sha256": "sha256:" + hashlib.sha256(Path(policy_module.__file__).read_bytes()).hexdigest(),
    }


# --- Audit probes: trust roots, current revision, bad input, drift, faults, evidence, bypass ---
# Each probe was written before the mechanism changed. A probe names the audit gap it closes.


def test_receipt_commits_to_selected_trust_root_identity_and_digest() -> None:
    p = policy()
    _, sealed = decide(p, request(p))
    assert sealed.outcome == pe.ALLOWED
    assert sealed.trust_root_id == DECIDER
    assert sealed.trust_root_digest == "sha256:" + hashlib.sha256(TRUST[DECIDER]).hexdigest()


def test_extra_trust_root_that_changes_no_outcome_still_changes_the_receipt() -> None:
    p = policy()
    req = request(p)
    _, base = pe.enforce(pe.empty_ledger(), p, req, TRUST)
    _, widened = pe.enforce(pe.empty_ledger(), p, req, {**TRUST, "authority:unused": b"u" * 32})
    assert base.outcome == widened.outcome == pe.ALLOWED
    assert base.trust_roots_digest != widened.trust_roots_digest
    assert base.digest != widened.digest


def test_superseded_revision_is_refused_when_a_newer_revision_is_declared() -> None:
    old = policy(revision=1)
    newer = policy(revision=2)
    req = request(old, current=declared(old, revision=2, policy_digest=newer.digest))
    result = receipt(old, req)
    assert result.outcome == pe.REFUSED
    assert "SUPERSEDED_REVISION" in result.reasons


def test_decision_without_declared_current_revision_is_refused() -> None:
    p = policy()
    result = receipt(p, request(p, current=None))
    assert result.outcome == pe.REFUSED
    assert result.reasons == ("CURRENT_REVISION_UNDECLARED",)


def test_bit_flipped_current_revision_pointer_is_unverified() -> None:
    p = policy()
    pointer = declared(p)
    forged = dataclasses.replace(pointer, mac=flip_last_hex(pointer.mac))
    result = receipt(p, request(p, current=forged))
    assert result.outcome == pe.REFUSED
    assert result.reasons == ("UNVERIFIED_CURRENT_REVISION",)


def test_current_revision_declared_over_other_policy_content_is_refused() -> None:
    p = policy()
    altered = policy(rules=(rule("ALLOW-PUBLISH", 1, "ALLOW", ("publish",), ("POLICY", "MODEL")),))
    result = receipt(p, request(p, current=declared(p, policy_digest=altered.digest)))
    assert result.outcome == pe.REFUSED
    assert result.reasons == ("CURRENT_REVISION_MISMATCH:DIGEST",)


def test_non_policy_version_input_is_refused_with_one_receipt() -> None:
    p = policy()
    ledger, sealed = pe.enforce(pe.empty_ledger(), {"not": "a policy"}, request(p), TRUST)
    assert sealed.outcome == pe.REFUSED
    assert sealed.reasons == ("POLICY_NOT_POLICY_VERSION",)
    assert len(ledger.receipts) == 1 and pe.verify_chain(ledger)


def test_non_request_input_is_refused_with_one_receipt() -> None:
    p = policy()
    ledger, sealed = pe.enforce(pe.empty_ledger(), p, {"request_id": "req-x"}, TRUST)
    assert sealed.outcome == pe.REFUSED
    assert sealed.reasons == ("REQUEST_NOT_ENFORCEMENT_REQUEST",)
    assert len(ledger.receipts) == 1 and pe.verify_chain(ledger)


def test_ledger_argument_that_is_not_a_ledger_is_a_type_error() -> None:
    p = policy()
    with pytest.raises(TypeError):
        pe.enforce(["not", "a", "ledger"], p, request(p), TRUST)


def test_build_report_under_live_central_audit_drift_is_not_pass(monkeypatch) -> None:
    from verifier.runtime import package_contract_profiles as profiles

    groups = dict(profiles._DECLARATION_FIELD_STATUS_GROUPS)
    groups["POLICY-0.2-authority-and-exceptions"] = {"M": ("exceptions", "authority", "activation", "revisions")}
    monkeypatch.setattr(profiles, "_DECLARATION_FIELD_STATUS_GROUPS", groups)
    p, requests = _sequence()
    report = pe.build_report(p, pe.run_sequence(p, requests, TRUST))
    assert report["auxiliary_verdict"] == pe.UNKNOWN
    assert report["live_audit_refusals"] == ["CENTRAL_FIELD_AUDIT_DRIFT:POLICY-0.2-authority-and-exceptions"]


@pytest.mark.parametrize("stage", ["_find_decision_authority", "_evaluate_exceptions", "_decide_role"])
def test_evaluator_stage_fault_is_unavailable_with_receipt_never_allowed(monkeypatch, stage) -> None:
    p = policy()

    def boom(*args, **kwargs):
        raise RuntimeError("injected")

    monkeypatch.setattr(pe, stage, boom)
    ledger, sealed = pe.enforce(pe.empty_ledger(), p, request(p), TRUST)
    assert sealed.outcome == pe.UNAVAILABLE
    assert sealed.reasons == ("EVALUATOR_UNAVAILABLE:RuntimeError",)
    assert len(ledger.receipts) == 1


def test_evaluator_returning_no_verdict_is_unavailable_with_receipt(monkeypatch) -> None:
    p = policy()
    monkeypatch.setattr(pe, "_decide", lambda *args, **kwargs: None)
    ledger, sealed = pe.enforce(pe.empty_ledger(), p, request(p), TRUST)
    assert sealed.outcome == pe.UNAVAILABLE
    assert len(ledger.receipts) == 1 and sealed.outcome != pe.ALLOWED


def test_request_digest_fault_is_unavailable_with_receipt(monkeypatch) -> None:
    p = policy()
    real_digest = pe.value_digest

    def fail_on_request(value):
        if isinstance(value, dict) and "request_id" in value:
            raise ValueError("injected")
        return real_digest(value)

    monkeypatch.setattr(pe, "value_digest", fail_on_request)
    ledger, sealed = pe.enforce(pe.empty_ledger(), p, request(p), TRUST)
    assert sealed.outcome == pe.UNAVAILABLE
    assert len(ledger.receipts) == 1 and sealed.outcome != pe.ALLOWED


@pytest.mark.parametrize("mutation", [
    "policy_id", "target_artifact_id", "passed", "clauses", "variable_map", "member_values", "certificate",
])
def test_mutated_decision_evidence_field_is_never_allowed(passing_evidence, failing_evidence, mutation) -> None:
    evidence = passing_evidence.decision_evidence()
    replacements = {
        "policy_id": {"policy_id": "POL-OTHER"},
        "target_artifact_id": {"target_artifact_id": "artifact:other"},
        "passed": {"passed": False},
        "clauses": {"clauses": ((1,),)},
        "variable_map": {"variable_map": evidence.variable_map + (("EXTRA", 99),)},
        "member_values": {"member_values": (("artifact:ghost", "REVOKED"),)},
        "certificate": {"certificate": failing_evidence.decision_evidence().certificate},
    }
    mutated = dataclasses.replace(evidence, **replacements[mutation])
    p = _evidence_policy(passing_evidence.policy_id)
    result = receipt(p, request(p, action="release", evidence=mutated))
    assert result.outcome == pe.REFUSED
    assert result.outcome != pe.ALLOWED


def test_report_states_unsupplied_effects_are_unknown_not_clean() -> None:
    p, requests = _sequence()
    report = pe.build_report(p, pe.run_sequence(p, requests, TRUST))
    coverage = report["effect_coverage"]
    assert coverage["supplied_effects"] == 0
    assert coverage["unsupplied_effects"] == pe.UNKNOWN
    assert report["auxiliary_verdict"] == pe.PASS


def test_effect_bound_to_another_requests_digest_is_a_mismatch() -> None:
    p = policy()
    allowed = request(p, request_id="req-a")
    ledger, _ = pe.enforce(pe.empty_ledger(), p, allowed, TRUST)
    other_digest = pe.value_digest(dataclasses.replace(allowed, now=NOW + 1).to_dict())
    forged = pe.EffectClaim("req-a", "RELEASE", "publish", TARGET, request_digest=other_digest)
    bound = pe.EffectClaim("req-a", "RELEASE", "publish", TARGET, request_digest=pe.value_digest(allowed.to_dict()))
    assert [item.reason for item in pe.detect_bypass(ledger, (forged,))] == ["REQUEST_DIGEST_MISMATCH"]
    assert pe.detect_bypass(ledger, (bound,)) == ()


def test_claim_and_module_do_not_overstate_revision_authority_or_receipt_count() -> None:
    assert "current-revision authority" not in pe.CLAIM
    assert "Every decision appends exactly one receipt" not in pe.__doc__
