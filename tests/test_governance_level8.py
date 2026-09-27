"""Independent governance admission examples and adversarial authority checks."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import hmac
import json
import secrets

import pytest

from verifier.governance import (
    GovernanceContext, GovernancePolicy, GovernancePrincipal,
    evaluate_governance, policy_digest, recheck_governance,
)


def signed(payload: dict, key: bytes) -> dict:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("utf-8")
    return {**payload, "signature": hmac.new(key, raw, hashlib.sha256).hexdigest()}


@pytest.fixture
def specimen():
    principals = tuple(GovernancePrincipal(actor, actor + "-key", secrets.token_bytes(32))
                       for actor in ("board-a", "board-b", "board-veto"))
    policy = GovernancePolicy(
        policy_id="release-council", revision=3, object_names=("SIM",),
        operations=("publish",), jurisdictions=("garden/lab",),
        principals=principals, quorum=2, veto_actors=("board-veto",),
        status_key_id="status-key", status_key=secrets.token_bytes(32),
        effective_from=100, effective_until=1000, max_status_age=30,
        appeal_route="operator/review",
    )
    context = GovernanceContext("SIM", "a" * 64, "publish", "publisher", "reader",
                                "teaching", 200, "garden/lab", "one-invocation")
    digest = policy_digest(policy)
    decisions = tuple(signed({
        "schema": "verifier-governance-decision-1", "decision_id": p.actor_id + "-vote",
        "policy_digest": digest, "binding": asdict(context),
        "actor_id": p.actor_id, "key_id": p.key_id, "decision": "APPROVE",
        "issued_at": 190, "expires_at": 250,
    }, p.key) for p in principals[:2])
    status = signed({
        "schema": "verifier-governance-status-1", "policy_digest": digest,
        "key_id": policy.status_key_id, "observed_at": 195, "expires_at": 225,
        "revoked_decisions": [], "revoked_actors": [], "consumed_invocations": [],
    }, policy.status_key)
    return context, policy, decisions, status


def run(specimen, **changes):
    context, policy, decisions, status = specimen
    values = dict(context=context, policy=policy, decisions=decisions, status=status,
                  evaluation_time=200, computational_verdict="FAIL")
    values.update(changes)
    return evaluate_governance(**values)


def resign(record: dict, key: bytes, **changes) -> dict:
    return signed({**{k: v for k, v in record.items() if k != "signature"}, **changes}, key)


def test_two_distinct_authorized_votes_and_reproduction(specimen):
    result = run(specimen)
    assert result.verdict.value == "PASS"
    assert result.receipt["computational_verdict"] == "FAIL"
    assert result.receipt["enforcement"] == "UNKNOWN"
    assert result.receipt["privacy"] == result.receipt["consent"] == "NOT_EVALUATED"
    assert run(specimen).receipt == result.receipt
    context, policy, decisions, status = specimen
    assert recheck_governance(result.receipt, context, decisions, policy=policy,
                             status=status, evaluation_time=200,
                             computational_verdict="FAIL")
    forged = {**result.receipt, "computational_verdict": "PASS"}
    assert not recheck_governance(forged, context, decisions, policy=policy,
                                status=status, evaluation_time=200,
                                computational_verdict="FAIL")


@pytest.mark.parametrize("field,value", [("artifact_digest", "b" * 64),
    ("operation", "delete"), ("purpose", "training"), ("observer_id", "outsider"),
    ("jurisdiction", "another-garden"), ("invocation_id", "another-invocation")])
def test_exact_action_binding(specimen, field, value):
    assert run(specimen, context=replace(specimen[0], **{field: value})).verdict.value == "REJECTED"


def test_current_policy_update_rejects_old_decisions(specimen):
    assert run(specimen, policy=replace(specimen[1], revision=4)).verdict.value == "REJECTED"


def test_outsider_cannot_vote_even_with_real_but_untrusted_key(specimen):
    _, _, decisions, _ = specimen
    outsider = resign(decisions[0], secrets.token_bytes(32), actor_id="outsider", key_id="outsider")
    assert run(specimen, decisions=(outsider, decisions[1])).verdict.value == "REJECTED"


def test_duplicate_vote_cannot_supply_quorum(specimen):
    assert run(specimen, decisions=(specimen[2][0], specimen[2][0])).verdict.value == "REJECTED"


def test_distinct_actor_labels_cannot_duplicate_same_key(specimen):
    policy = specimen[1]
    with pytest.raises(ValueError, match="distinct"):
        replace(policy, principals=(policy.principals[0], replace(policy.principals[1], key=policy.principals[0].key)))


def test_missing_quorum_is_unknown(specimen):
    assert run(specimen, decisions=specimen[2][:1]).verdict.value == "UNKNOWN"


@pytest.mark.parametrize("decision", ["DENY", "VETO"])
def test_explicit_authorized_denial_and_veto_reject(specimen, decision):
    context, policy, decisions, _ = specimen
    p = policy.principals[2]
    vote = resign(decisions[0], p.key, actor_id=p.actor_id, key_id=p.key_id,
                  decision_id="veto-vote", decision=decision)
    assert run(specimen, decisions=(*decisions, vote)).verdict.value == "REJECTED"


def test_tampered_signature_rejects(specimen):
    vote = {**specimen[2][0], "signature": "0" * 64}
    assert run(specimen, decisions=(vote, specimen[2][1])).verdict.value == "REJECTED"


@pytest.mark.parametrize("field,value", [("revoked_decisions", ["board-a-vote"]),
    ("revoked_actors", ["board-a"]), ("consumed_invocations", ["one-invocation"])])
def test_authenticated_revocation_and_known_replay_reject(specimen, field, value):
    status = resign(specimen[3], specimen[1].status_key, **{field: value})
    assert run(specimen, status=status).verdict.value == "REJECTED"


def test_request_chosen_clock_cannot_resurrect_expired_authority(specimen):
    assert run(specimen, evaluation_time=251).verdict.value == "REJECTED"


def test_status_staleness_and_missing_authority_remain_unknown(specimen):
    status = resign(specimen[3], specimen[1].status_key, observed_at=169, expires_at=225)
    assert run(specimen, status=status).verdict.value == "UNKNOWN"
    assert run(specimen, status=None).verdict.value == "UNKNOWN"
    assert run(specimen, policy=None).verdict.value == "UNKNOWN"
    assert run(specimen, evaluation_time=None).verdict.value == "UNKNOWN"


def test_tampered_and_future_status_are_not_fresh_authority(specimen):
    assert run(specimen, status={**specimen[3], "consumed_invocations": ["x"]}).verdict.value == "REJECTED"
    future = resign(specimen[3], specimen[1].status_key, observed_at=201)
    assert run(specimen, status=future).verdict.value == "UNKNOWN"


def test_policy_expiry_and_future_request_fail_closed(specimen):
    assert run(specimen, evaluation_time=1000).verdict.value == "REJECTED"
    assert run(specimen, context=replace(specimen[0], timestamp=201)).verdict.value == "REJECTED"


def test_receipt_contains_no_secret_key_material(specimen):
    serialized = json.dumps(run(specimen).receipt)
    for key in (*[p.key for p in specimen[1].principals], specimen[1].status_key):
        assert key.hex() not in serialized


def test_boolean_clock_and_unknown_document_fields_rejected(specimen):
    assert run(specimen, evaluation_time=True).verdict.value == "REJECTED"
    malformed = resign(specimen[2][0], specimen[1].principals[0].key, pretend_authorized=True)
    assert run(specimen, decisions=(malformed, specimen[2][1])).verdict.value == "REJECTED"


def test_float_timestamp_cannot_alias_exact_integer_binding(specimen):
    vote = resign(specimen[2][0], specimen[1].principals[0].key,
                  binding={**asdict(specimen[0]), "timestamp": 200.0})
    assert run(specimen, decisions=(vote, specimen[2][1])).verdict.value == "REJECTED"


def test_detected_tamper_is_not_hidden_by_missing_clock(specimen):
    vote = {**specimen[2][0], "signature": "0" * 64}
    assert run(specimen, decisions=(vote, specimen[2][1]), evaluation_time=None).verdict.value == "REJECTED"


def test_expiry_checked_at_independent_time_with_exact_bound_context(specimen):
    context, policy, decisions, _ = specimen
    context = replace(context, timestamp=251)
    votes = tuple(resign(d, p.key, binding=asdict(context))
                  for d, p in zip(decisions, policy.principals))
    result = run(specimen, context=context, decisions=votes, evaluation_time=251)
    assert result.verdict.value == "REJECTED"
    assert "DECISION_NOT_EFFECTIVE" in {row["code"] for row in result.receipt["checks"]}


@pytest.mark.parametrize("missing", ["status", "evaluation_time"])
def test_authenticated_governance_denial_survives_missing_dependency(specimen, missing):
    context, policy, decisions, status = specimen
    denial = resign(decisions[0], policy.principals[0].key, decision="DENY")
    result = run(specimen, decisions=(denial, decisions[1]), **{missing: None})
    assert result.verdict.value == "REJECTED"
    assert "EXPLICIT_DENIAL_OR_VETO" in {row["code"] for row in result.receipt["checks"]}
