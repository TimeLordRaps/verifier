"""Consent admission tests using freshly generated test-only authentication keys."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import secrets

import pytest
import verifier.consent.engine as candidate

from verifier.consent import (
    ConsentContext, ConsentKey, ConsentPolicy, ConsentVerdict,
    authenticate_consent, evaluate_consent, recheck_consent,
)


def test_caller_context_mutation_after_authentication_cannot_expand_purpose(
        specimen, monkeypatch):
    context, policy, grant, state = specimen
    requested = replace(context, purpose="sell")
    grant_envelope = authenticate_consent(grant, policy.keys[0])
    status_envelope = authenticate_consent(state, policy.keys[2])
    options = dict(policy=policy, revocation=status_envelope, evaluation_time=100)
    baseline = evaluate_consent(requested, (grant_envelope,), **options)
    assert baseline.verdict == ConsentVerdict.REJECTED
    original = candidate._authenticate

    def mutate_after_authentication(envelope, selected_policy):
        authenticated = original(envelope, selected_policy)
        if authenticated[1] == policy.root_key_ids[0]:
            object.__setattr__(requested, "purpose", "research")
        return authenticated

    monkeypatch.setattr(candidate, "_authenticate", mutate_after_authentication)
    result = evaluate_consent(requested, (grant_envelope,), **options)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["context"]["purpose"] == "sell"


def test_policy_scope_tuple_subclass_cannot_admit_unlisted_artifact(specimen):
    class PermissiveTuple(tuple):
        def __contains__(self, value):
            return True

    context, policy, grant, state = specimen
    other_only = (("BOT", "b" * 64),)
    ordinary = replace(policy, artifact_bindings=other_only)
    assert run(specimen, policy=ordinary).verdict == ConsentVerdict.REJECTED
    object.__setattr__(policy, "artifact_bindings", PermissiveTuple(other_only))
    result = run(specimen)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["policy_digest"] is None


def test_signed_grant_list_subclass_cannot_expand_operation_scope(specimen):
    class PermissiveList(list):
        def __contains__(self, value):
            return True

    context, policy, grant, state = specimen
    limited = {**grant, "operations": ["read"]}
    plain = authenticate_consent(limited, policy.keys[0])
    status = authenticate_consent(state, policy.keys[2])
    options = dict(policy=policy, revocation=status, evaluation_time=100)
    assert evaluate_consent(context, (plain,), **options).verdict == ConsentVerdict.REJECTED
    subclass_envelope = authenticate_consent(limited, policy.keys[0])
    subclass_envelope["payload"]["operations"] = PermissiveList(["read"])
    assert json.loads(json.dumps(subclass_envelope["payload"]))["operations"] == ["read"]
    result = evaluate_consent(context, (subclass_envelope,), **options)
    assert result.verdict == ConsentVerdict.REJECTED


def test_trusted_key_rejects_bytes_subclass_with_misleading_length():
    class MaskedLengthBytes(bytes):
        def __len__(self):
            return 32

    assert ConsentKey("root", "owner", b"x" * 32).secret == b"x" * 32
    with pytest.raises(ValueError):
        ConsentKey("root", "owner", b"x" * 31)
    with pytest.raises(ValueError):
        ConsentKey("root", "owner", MaskedLengthBytes(b"x"))
    assert len(ConsentKey("root", "owner", b"x" * 4097).secret) == 4097


def test_trusted_policy_collection_is_bounded_before_capture(specimen):
    policy = specimen[1]
    original_key = policy.keys[0]
    object.__setattr__(policy, "keys", (original_key,) * 50001)
    result = run(specimen)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["policy_digest"] is None


def test_trusted_policy_descriptor_text_budget_precedes_clone(specimen):
    context, policy, grant, state = specimen
    grants = (authenticate_consent(grant, policy.keys[0]),)
    revocation = authenticate_consent(state, policy.keys[2])
    extras = tuple(ConsentKey(f"key-{index}".ljust(512, "x"), "owner", b"x" * 32)
                   for index in range(2100))
    object.__setattr__(policy, "keys", (*policy.keys, *extras))
    result = evaluate_consent(context, grants, policy=policy,
                              revocation=revocation, evaluation_time=100)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["policy_digest"] is None


def test_policy_freshness_cannot_relax_after_grant_authentication(
        specimen, monkeypatch):
    context, policy, grant, state = specimen
    strict = replace(policy, max_revocation_age_seconds=0)
    grant_envelope = authenticate_consent(grant, strict.keys[0])
    status_envelope = authenticate_consent(state, strict.keys[2])
    options = dict(policy=strict, revocation=status_envelope, evaluation_time=100)
    baseline = evaluate_consent(context, (grant_envelope,), **options)
    assert baseline.verdict == ConsentVerdict.UNKNOWN
    original = candidate._authenticate

    def mutate_after_authentication(envelope, selected_policy):
        authenticated = original(envelope, selected_policy)
        if authenticated[1] == strict.root_key_ids[0]:
            object.__setattr__(strict, "max_revocation_age_seconds", 60)
        return authenticated

    monkeypatch.setattr(candidate, "_authenticate", mutate_after_authentication)
    result = evaluate_consent(context, (grant_envelope,), **options)
    assert result.verdict == ConsentVerdict.UNKNOWN
    assert result.receipt["policy_digest"] == baseline.receipt["policy_digest"]


def test_deep_candidate_rejects_before_unbounded_copy_or_serialization(specimen):
    context, policy, grant, state = specimen
    envelope = authenticate_consent(grant, policy.keys[0])
    nested = ["leaf"]
    for _ in range(1100):
        nested = [nested]
    envelope["payload"]["operations"] = nested
    result = evaluate_consent(
        context, (envelope,), policy=policy,
        revocation=authenticate_consent(state, policy.keys[2]), evaluation_time=100,
    )
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["evidence_digest"] is None


class _TripwireClock:
    def __str__(self):
        raise AssertionError("caller clock string callback was invoked")

    def __int__(self):
        raise AssertionError("caller clock integer callback was invoked")


@pytest.mark.parametrize("bad_clock", [object(), complex(1, 2), 1 << 20000,
                                       _TripwireClock()],
                         ids=["object", "complex", "giant-integer", "tripwire"])
def test_malformed_trusted_clock_rejects_without_receipt_serialization(
        specimen, bad_clock):
    context, policy, grant, state = specimen
    grants = (authenticate_consent(grant, policy.keys[0]),)
    revocation = authenticate_consent(state, policy.keys[2])
    result = evaluate_consent(context, grants, policy=policy,
                              revocation=revocation, evaluation_time=bad_clock)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["evaluation_time"] is None
    assert not recheck_consent(result.receipt, context, grants, policy=policy,
                               revocation=revocation, evaluation_time=bad_clock)


def test_giant_context_timestamp_rejects_without_serializing_it(specimen):
    context, policy, grant, state = specimen
    giant = replace(context, timestamp=1 << 20000)
    result = evaluate_consent(giant, (authenticate_consent(grant, policy.keys[0]),),
                              policy=policy,
                              revocation=authenticate_consent(state, policy.keys[2]),
                              evaluation_time=100)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["context"] is None


@pytest.fixture
def specimen():
    keys = tuple(ConsentKey(name, actor, secrets.token_bytes(32)) for name, actor in
                 (("owner-key", "owner"), ("delegate-key", "agent"), ("status-key", "registry")))
    policy = ConsentPolicy("local-consent-policy", "owner", keys, ("owner-key",),
                           ("status-key",), artifact_bindings=(("SIM", "a" * 64),),
                           max_revocation_age_seconds=60)
    context = ConsentContext("SIM", "a" * 64, "run", "agent", "recipient", "research", 100)
    grant = {"schema_version": "verifier-consent-grant-1", "grant_id": "root",
             "issuer_id": "owner", "actor_id": "agent", "object_name": "SIM",
             "artifact_digest": "a" * 64, "operations": ["run", "read"],
             "observer_ids": ["recipient"], "purposes": ["research"],
             "not_before": 10, "not_after": 200, "parent_digest": None,
             "allow_delegation": True, "effect": "ALLOW"}
    state = {"schema_version": "verifier-consent-revocations-1", "issuer_id": "registry",
             "policy_id": policy.policy_id, "as_of": 95, "next_update": 150,
             "revoked_grant_ids": []}
    return context, policy, grant, state


def run(specimen, **changes):
    context, policy, grant, state = specimen
    grants = (authenticate_consent(grant, policy.keys[0]),)
    options = dict(policy=policy, evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2]),
                   computational_verdict="UNKNOWN")
    options.update(changes)
    return evaluate_consent(context, grants, **options)


def test_consent_authenticated_exact_scope_and_replay(specimen):
    context, policy, grant, state = specimen
    result = run(specimen)
    assert result.verdict == ConsentVerdict.PASS
    assert result.receipt == run(specimen).receipt
    assert result.receipt["computational_verdict"] == "UNKNOWN"
    assert recheck_consent(result.receipt, context,
        (authenticate_consent(grant, policy.keys[0]),), policy=policy, evaluation_time=100,
        revocation=authenticate_consent(state, policy.keys[2]), computational_verdict="UNKNOWN")


@pytest.mark.parametrize("field,value", [("artifact_digest", "b" * 64), ("object_name", "BOT"),
    ("operation", "publish"), ("actor_id", "intruder"), ("observer_id", "other"),
    ("purpose", "advertising"), ("timestamp", 200), ("timestamp", 9)])
def test_consent_scope_and_exclusive_expiry_refute(specimen, field, value):
    context, *rest = specimen
    context = replace(context, **{field: value})
    assert run((context, *rest), evaluation_time=context.timestamp).verdict == ConsentVerdict.REJECTED


def test_consent_authority_and_revocation_missing_are_unknown(specimen):
    assert run(specimen, policy=None).verdict == ConsentVerdict.UNKNOWN
    assert run(specimen, revocation=None).verdict == ConsentVerdict.UNKNOWN
    context, policy, grant, state = specimen
    state["as_of"] = 0
    assert run(specimen).verdict == ConsentVerdict.UNKNOWN
    state["as_of"] = 101
    assert run(specimen).verdict == ConsentVerdict.UNKNOWN


def test_consent_denial_and_revocation_refute_even_stale(specimen):
    context, policy, grant, state = specimen
    state["revoked_grant_ids"] = ["root"]
    state["as_of"] = 0
    assert run(specimen).verdict == ConsentVerdict.REJECTED
    state["revoked_grant_ids"] = []
    grant["effect"] = "DENY"
    assert run(specimen).verdict == ConsentVerdict.REJECTED


def test_consent_single_bit_tamper_and_self_report_rejected(specimen):
    context, policy, grant, state = specimen
    envelope = authenticate_consent(grant, policy.keys[0])
    envelope["payload"]["not_after"] ^= 1
    result = evaluate_consent(context, (envelope,), policy=policy, evaluation_time=100,
                              revocation=authenticate_consent(state, policy.keys[2]))
    assert result.verdict == ConsentVerdict.REJECTED
    grant["signature_verified"] = True
    assert run(specimen).verdict == ConsentVerdict.REJECTED


def delegated(specimen):
    context, policy, grant, state = specimen
    parent = authenticate_consent(grant, policy.keys[0])
    child = dict(grant, grant_id="child", issuer_id="agent", actor_id="worker",
                 operations=["run"], not_before=20, not_after=160,
                 parent_digest=parent["payload_digest"], allow_delegation=False)
    return replace(context, actor_id="worker"), policy, parent, child, state


def test_consent_delegation_narrows_and_parent_revocation_propagates(specimen):
    context, policy, parent, child, state = delegated(specimen)
    evaluate = lambda: evaluate_consent(context, (parent, authenticate_consent(child, policy.keys[1])),
         policy=policy, evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2]))
    assert evaluate().verdict == ConsentVerdict.PASS
    state["revoked_grant_ids"] = ["root"]
    assert evaluate().verdict == ConsentVerdict.REJECTED


@pytest.mark.parametrize("field,value", [("operations", ["publish"]),
    ("observer_ids", ["recipient", "other"]), ("purposes", ["research", "sell"]),
    ("not_after", 201), ("not_before", 0), ("issuer_id", "owner"),
    ("parent_digest", "0" * 64), ("grant_id", "root")])
def test_consent_delegation_widening_and_substitution_refute(specimen, field, value):
    context, policy, parent, child, state = delegated(specimen)
    child[field] = value
    assert evaluate_consent(context, (parent, authenticate_consent(child, policy.keys[1])),
         policy=policy, evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2])).verdict == ConsentVerdict.REJECTED


def test_consent_unknown_key_never_earns_pass(specimen):
    context, policy, grant, state = specimen
    foreign = ConsentKey("untrusted", "owner", secrets.token_bytes(32))
    assert evaluate_consent(context, (authenticate_consent(grant, foreign),), policy=policy, evaluation_time=100,
         revocation=authenticate_consent(state, policy.keys[2])).verdict == ConsentVerdict.UNKNOWN


def test_consent_receipt_forgery_and_context_replay_fail(specimen):
    context, policy, grant, state = specimen
    receipt = deepcopy(run(specimen).receipt)
    receipt["computational_verdict"] = "PASS"
    assert not recheck_consent(receipt, context, (authenticate_consent(grant, policy.keys[0]),),
        policy=policy, evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2]), computational_verdict="UNKNOWN")


@pytest.mark.parametrize("verdict", ["PASS", "FAIL", "UNKNOWN", "REJECTED", "CONFLICTED"])
def test_consent_never_upgrades_computation(specimen, verdict):
    result = run(specimen, computational_verdict=verdict)
    assert result.verdict == ConsentVerdict.PASS
    assert result.receipt["computational_verdict"] == verdict


def test_consent_owner_consent_limb_and_privacy_label_are_not_grants(specimen):
    context, policy, grant, state = specimen
    claimed = {"limbs": ["consent"], "transmission_principle": "consent_governed", "status": "PASS"}
    assert evaluate_consent(context, (claimed,), policy=policy, evaluation_time=100,
         revocation=authenticate_consent(state, policy.keys[2])).verdict == ConsentVerdict.REJECTED


def test_consent_trusted_clock_and_grantor_binding_required(specimen):
    assert run(specimen, evaluation_time=None).verdict == ConsentVerdict.UNKNOWN
    for instant in (99, 101, True):
        assert run(specimen, evaluation_time=instant).verdict == ConsentVerdict.REJECTED
    context, policy, grant, state = specimen
    assert run(specimen, policy=replace(policy, artifact_bindings=())).verdict == ConsentVerdict.UNKNOWN
    changed = replace(policy, artifact_bindings=(("SIM", "b" * 64),))
    assert run(specimen, policy=changed).verdict == ConsentVerdict.REJECTED


def test_consent_revocation_tamper_wrong_authority_and_rollback(specimen):
    context, policy, grant, state = specimen
    envelope = authenticate_consent(state, policy.keys[2])
    envelope["payload"]["as_of"] = 99
    assert run(specimen, revocation=envelope).verdict == ConsentVerdict.REJECTED
    state["issuer_id"] = "owner"
    assert run(specimen, revocation=authenticate_consent(state, policy.keys[0])).verdict == ConsentVerdict.REJECTED
    state["issuer_id"] = "registry"
    assert run(specimen, policy=replace(policy, minimum_revocation_as_of=99)).verdict == ConsentVerdict.UNKNOWN
    state["next_update"] = 100
    assert run(specimen).verdict == ConsentVerdict.UNKNOWN


def test_consent_chain_resource_bound_and_non_delegable_parent(specimen):
    context, policy, parent, child, state = delegated(specimen)
    children = (parent, authenticate_consent(child, policy.keys[1]))
    assert evaluate_consent(context, children, policy=replace(policy, max_chain_length=1),
        evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2])).verdict == ConsentVerdict.REJECTED
    parent["payload"]["allow_delegation"] = False
    parent = authenticate_consent(parent["payload"], policy.keys[0])
    child["parent_digest"] = parent["payload_digest"]
    assert evaluate_consent(context, (parent, authenticate_consent(child, policy.keys[1])),
        policy=policy, evaluation_time=100,
        revocation=authenticate_consent(state, policy.keys[2])).verdict == ConsentVerdict.REJECTED


def test_consent_key_rotation_and_replay_do_not_keep_old_authority(specimen):
    context, policy, grant, state = specimen
    receipt = run(specimen).receipt
    rotated = replace(policy, keys=(replace(policy.keys[0], secret=secrets.token_bytes(32)), *policy.keys[1:]))
    assert run(specimen, policy=rotated).verdict == ConsentVerdict.REJECTED
    assert not recheck_consent(receipt, context, (authenticate_consent(grant, policy.keys[0]),),
        policy=rotated, evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2]))


def test_consent_rehashed_forgery_still_requires_real_authenticator(specimen):
    context, policy, grant, state = specimen
    envelope = authenticate_consent(grant, policy.keys[0])
    envelope["payload"]["not_after"] += 1
    envelope["payload_digest"] = hashlib.sha256(json.dumps(envelope["payload"], sort_keys=True,
        ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()).hexdigest()
    result = evaluate_consent(context, (envelope,), policy=policy, evaluation_time=100,
        revocation=authenticate_consent(state, policy.keys[2]))
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["reason"] == "consent authenticator mismatch"


def test_consent_expiry_is_checked_without_clock_mismatch_masking(specimen):
    context, policy, grant, state = specimen
    for instant in (9, 200):
        result = run((replace(context, timestamp=instant), policy, grant, state), evaluation_time=instant)
        assert result.verdict == ConsentVerdict.REJECTED
        assert result.receipt["reason"] == "consent grant is inactive or expired"


def test_consent_policy_secrets_are_not_in_receipt_and_keys_are_not_mutable_lists(specimen):
    context, policy, grant, state = specimen
    serialized = json.dumps(run(specimen).receipt)
    assert all(key.secret.hex() not in serialized for key in policy.keys)
    assert all(key.secret.hex() not in repr(policy) for key in policy.keys)
    with pytest.raises(ValueError, match="invalid trusted consent policy"):
        replace(policy, keys=list(policy.keys))


def test_consent_unknown_clock_does_not_mask_known_forgery(specimen):
    context, policy, grant, state = specimen
    envelope = authenticate_consent(grant, policy.keys[0])
    envelope["authenticator"] = "0" * 64
    result = evaluate_consent(context, (envelope,), policy=policy,
        revocation=authenticate_consent(state, policy.keys[2]))
    assert result.verdict == ConsentVerdict.REJECTED


def test_consent_recheck_rejects_integer_to_float_substitution(specimen):
    context, policy, grant, state = specimen
    receipt = run(specimen).receipt
    receipt["evaluation_time"] = 100.0
    assert not recheck_consent(receipt, context, (authenticate_consent(grant, policy.keys[0]),),
        policy=policy, evaluation_time=100, revocation=authenticate_consent(state, policy.keys[2]))


@pytest.mark.parametrize("field,value,reason", [
    ("effect", "DENY", "authenticated consent denial"),
    ("artifact_digest", "b" * 64, "consent artifact binding mismatch"),
    ("not_after", 100, "consent grant is inactive or expired"),
    ("operations", ["publish"], "action actor, recipient, purpose, or operation exceeds consent"),
])
def test_known_consent_refutation_survives_unknown_status_key(specimen, field, value, reason):
    context, policy, grant, state = specimen
    grant[field] = value
    known = run(specimen)
    assert known.verdict == ConsentVerdict.REJECTED
    assert known.receipt["reason"] == reason
    foreign_status = ConsentKey("unconfigured-status", "registry", secrets.token_bytes(32))
    result = run(specimen, revocation=authenticate_consent(state, foreign_status))
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["reason"] == reason


def test_unknown_status_key_still_cannot_admit_valid_consent(specimen):
    context, policy, grant, state = specimen
    foreign_status = ConsentKey("unconfigured-status", "registry", secrets.token_bytes(32))
    result = run(specimen, revocation=authenticate_consent(state, foreign_status))
    assert result.verdict == ConsentVerdict.UNKNOWN


def test_known_status_forgery_survives_unknown_grant_key(specimen):
    context, policy, grant, state = specimen
    foreign_grant = ConsentKey("unconfigured-root", "owner", secrets.token_bytes(32))
    status = authenticate_consent(state, policy.keys[2])
    status["authenticator"] = "0" * 64
    result = evaluate_consent(context, (authenticate_consent(grant, foreign_grant),),
        policy=policy, revocation=status, evaluation_time=100)
    assert result.verdict == ConsentVerdict.REJECTED
    assert result.receipt["reason"] == "consent authenticator mismatch"


@pytest.mark.parametrize("forged,expected", [(False, ConsentVerdict.UNKNOWN), (True, ConsentVerdict.REJECTED)])
def test_missing_chain_does_not_hide_known_status_forgery(specimen, forged, expected):
    context, policy, grant, state = specimen
    status = authenticate_consent(state, policy.keys[2])
    if forged:
        status["authenticator"] = "0" * 64
    result = evaluate_consent(context, (), policy=policy, revocation=status, evaluation_time=100)
    assert result.verdict == expected
