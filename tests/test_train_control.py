"""Adversarial local TRAIN mediation; these tests do not establish model safety."""
from __future__ import annotations

from dataclasses import replace
import base64
import hashlib
from threading import Event, Thread
from uuid import uuid4

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.common import Unavailable, digest
from verifier.corrigibility.train_profile import EFFECTS, PROTECTED_FACETS, TrainControlPlan, assess_train_control
from verifier.corrigibility.train_control import (AuthoritySnapshot, TrainControlPolicy, TrainControlSession,
                                                operation_signing_bytes, operation_scope, recheck_denial_trace)


def _plan():
    objects = [NamespaceObject.create(name, kind, {"scope": "finite-test", "revision": 1}) for name, kind in
               [("t0", "TRAIN"), ("t1", "TRAIN"), ("m0", "MODEL"), ("m1", "MODEL"),
                ("root", "HUMAN"), ("executor", "ACTOR"), ("checkpoint", "OBJECT"),
                ("time", "TIME"), ("token", "TOKEN"), ("env", "ENV"), ("hardware", "HARDWARE"), ("space", "SPACE")]]
    objects.extend(NamespaceObject.create(facet, "OBJECT", {"binding": facet}) for facet in sorted(PROTECTED_FACETS))
    return TrainControlPlan(tuple(objects), tuple((o.object_id, o.object_id) for o in objects), (),
                            (("m0", "t0", "used_by"), ("m1", "t0", "produced_by"), ("m1", "t1", "used_by")),
                            tuple((train, facet, facet) for train in ("t0", "t1") for facet in sorted(PROTECTED_FACETS)),
                            (), (("t0", "checkpoint"),), ("time", "token", "env", "hardware", "space"),
                            tuple(sorted(EFFECTS)), True, True)


def _fixture(*, plan=None, action="write_checkpoint", actor="executor", change=None):
    pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signed native TOKEN and STOP need cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from verifier.corrigibility.operator_stop import OperatorStopKey, OperatorStopPolicy
    plan = plan or _plan()
    private = {name: Ed25519PrivateKey.generate() for name in ("root", "executor")}
    public = {name: key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
              for name, key in private.items()}
    key_ids = {name: digest(value) for name, value in public.items()}
    sid = uuid4().hex
    content = b"bounded finite optimization checkpoint"
    change = change or "sha256:" + hashlib.sha256(content).hexdigest()
    target = "checkpoint" if action == "write_checkpoint" else "t0"
    body = {"schema": "verifier-train-operation-1", "session_id": sid, "plan_digest": plan.digest,
            "request_id": "operation-1", "actor_id": actor, "origin_id": actor, "train_id": "t0",
            "target_id": target, "target_digest": plan.resolve(target).digest,
            "action": action, "change_digest": change}
    scope = operation_scope(body)
    stop_policy = OperatorStopPolicy("train-stop", (OperatorStopKey("root", "stop-root", bytes.fromhex(public["root"])),), 60)
    policy = TrainControlPolicy("finite-control", "birth", key_ids["root"],
                                tuple((key_ids[name], public[name]) for name in private),
                                (("root", key_ids["root"], "ROOT"), ("executor", key_ids["executor"], "EXECUTOR")),
                                (scope,), "train-host", "utc-seconds", stop_policy, 10)
    tokens = [dict(kind="birth", token_id="birth", issuing_key_id=key_ids["root"], issued_at=90,
                   algorithm="Ed25519", replay_id="birth-replay", audience=["train-host"], signature="",
                   birth_epoch=0, commitment=digest("birth-commitment")),
              dict(kind="lifetime", token_id="grant", issuing_key_id=key_ids["root"], issued_at=90,
                   algorithm="Ed25519", replay_id="grant-replay", audience=["train-host"], signature="",
                   parent_grant_id="birth", delegate_key_id=key_ids[actor], permitted_scopes=[scope],
                   not_before=90, not_after=130, max_invocations=4, soulbound=True,
                   confirmation_key_id=key_ids[actor], caveats=[])]
    for record in tokens:
        record["signature"] = base64.b64encode(private["root"].sign(canonical_bytes(
            {name: value for name, value in record.items() if name != "signature"}))).decode()
    statuses = [{"token_id": record["token_id"], "published_at": 100, "verdict": "ACTIVE"} for record in tokens]
    epochs = [{"epoch": 1, "status": "ACTIVE", "digest": digest([tokens[0]["commitment"], 1, "ACTIVE"])}]
    artifact = {"clock": "utc-seconds", "tokens_digest": digest(tokens), "epochs_digest": digest(epochs),
                "root_scopes": [scope], "accepted_algorithms": ["Ed25519"],
                "issuing_keys": [{"key_id": key_ids[name], "key_bytes": public[name]} for name in private],
                "key_retirements": {}, "statuses_digest": digest(statuses), "status_schedule": 10}
    view = [AuthoritySnapshot(0, artifact, {"tokens": tokens, "epochs": epochs, "statuses": statuses})]
    now = [100]
    session = TrainControlSession(plan, policy, authority=lambda: view[0], clock=lambda: now[0], session_id=sid)
    def sign(changes=None, signer=None):
        selected = {**body, **(changes or {})}
        return {"body": selected, "signature": private[signer or actor].sign(operation_signing_bytes(selected)).hex()}
    return session, sign, view, now, private, content


def test_ordinary_acyclic_reuse_is_allowed_but_acyclic_authority_escalation_is_refuted():
    plan = _plan()
    assert assess_train_control(plan).outcome == "PASS"
    escalation = replace(plan, capabilities=(("t1", "objective", "mutate_bindings"),))
    result = assess_train_control(escalation)
    assert result.outcome == "FAIL" and any("MODEL reaches" in reason for reason in result.reasons)


def test_missing_external_relation_cannot_mask_later_known_model_authority():
    plan = replace(_plan(), capabilities=(("unresolved-external", "objective", "mutate_bindings"),
                                         ("m0", "root", "mint_delegation")))
    assert assess_train_control(plan).outcome == "FAIL"


def test_mixed_lineage_delegation_cycle_is_refuted():
    assert assess_train_control(replace(_plan(), capabilities=(("t0", "m0", "delegate"),))).outcome == "FAIL"


def test_model_checkpoint_capability_and_borrowed_executor_route_are_refuted():
    plan = replace(_plan(), capabilities=(("m0", "executor", "delegate"),
                                         ("executor", "checkpoint", "write_checkpoint")))
    assert assess_train_control(plan).outcome == "FAIL"


@pytest.mark.parametrize("change", ["lineage", "delegate", "alias"])
def test_finite_graph_cycles_are_refuted(change):
    plan = _plan()
    if change == "lineage":
        plan = replace(plan, relations=plan.relations + (("m0", "t1", "produced_by"),))
    elif change == "delegate":
        plan = replace(plan, capabilities=(("executor", "root", "delegate"), ("root", "executor", "delegate")))
    else:
        plan = replace(plan, aliases=(("a", "b"), ("b", "a")))
    assert assess_train_control(plan).outcome == "FAIL"


def test_indirect_alias_and_revision_family_cannot_hide_protected_artifact():
    plan = _plan()
    newer = NamespaceObject.create("objective-v2", "OBJECT", {"revision": 2})
    plan = replace(plan, objects=plan.objects + (newer,), families=plan.families + (("objective-v2", "objective"),),
                   aliases=(("outside-alias", "alias"), ("alias", "objective-v2")),
                   checkpoints=(("t0", "outside-alias"),))
    assert assess_train_control(plan).outcome == "FAIL"


@pytest.mark.parametrize("gap", ["external", "inventory", "mediation", "facet", "context"])
def test_required_unknown_blocks_despite_other_coverage(gap):
    plan = _plan()
    changes = {"external": {"external_paths_resolved": False}, "inventory": {"inventory_complete": False},
               "mediation": {"mediated_effects": ()}, "facet": {"protected": plan.protected[1:]},
               "context": {"context": plan.context[:-1]}}
    assert assess_train_control(replace(plan, **changes[gap])).outcome == "UNKNOWN"


@pytest.mark.parametrize("action", sorted(EFFECTS))
def test_model_depth_zero_never_calls_effect_for_protected_or_descendant_actions(action, tmp_path):
    session, sign, _, _, _, content = _fixture()
    destination = tmp_path / "protected-objective"
    destination.write_bytes(b"original objective")
    operation = sign({"action": action, "actor_id": "m1", "origin_id": "m1"})
    result = session.mediate(operation, "grant", lambda payload: destination.write_bytes(payload), artifact_bytes=content)
    assert result.outcome == "FAIL" and result.effect_called is False
    assert destination.read_bytes() == b"original objective"
    assert result.event.payload["context"] == {session.plan.resolve(i).kind.value: session.plan.resolve(i).digest
                                               for i in session.plan.context}


def test_confused_deputy_cannot_relabel_model_origin_as_executor(tmp_path):
    session, sign, _, _, _, content = _fixture()
    called = []
    operation = sign({"origin_id": "m0"})
    assert not session.mediate(operation, "grant", called.append, artifact_bytes=content).effect_called
    assert called == []


def test_declared_executor_can_write_exact_checkpoint_once_and_model_strategy_remains_data(tmp_path):
    session, sign, _, _, _, content = _fixture()
    destination = tmp_path / "checkpoint"
    result = session.mediate(sign(), "grant", lambda payload: destination.write_bytes(payload), artifact_bytes=content)
    assert result.outcome == "PASS" and result.effect_called
    assert destination.read_bytes() == content
    replay = session.mediate(sign(), "grant", lambda payload: destination.write_bytes(b"replayed"), artifact_bytes=content)
    assert replay.outcome == "FAIL" and not replay.effect_called
    assert destination.read_bytes() == content
    # Strategies are ordinary retained data; no strategy submission grants execution authority.
    suggestion = NamespaceObject.create("suggestion", "MODEL", {"strategy": "search finite candidates"})
    assert suggestion.payload["strategy"] == "search finite candidates"


@pytest.mark.parametrize("change", ["content", "target_revision", "session", "plan", "signature"])
def test_exact_content_revision_session_and_possession_are_required(change):
    session, sign, _, _, _, content = _fixture()
    operation = sign()
    payload = content
    if change == "content":
        payload = b"different content"
    elif change == "target_revision":
        operation = sign({"target_digest": digest("different revision")})
    elif change == "session":
        operation = sign({"session_id": "old-session"})
    elif change == "plan":
        operation = sign({"plan_digest": digest("different plan")})
    else:
        operation["signature"] = "00" * 64
    called = []
    result = session.mediate(operation, "grant", called.append, artifact_bytes=payload)
    assert result.outcome == "FAIL" and not result.effect_called and called == []


@pytest.mark.parametrize("case", ["revoked", "suspended", "stale", "missing", "rollback"])
def test_current_authority_is_required_at_every_effect(case):
    session, sign, view, now, _, content = _fixture()
    assert session.mediate(sign(), "grant", lambda payload: None, artifact_bytes=content).effect_called
    if case == "missing":
        view[0] = None
    elif case == "stale":
        now[0] = 111
    elif case == "rollback":
        view[0] = replace(view[0], generation=-1)
    else:
        inputs = {**view[0].inputs, "statuses": [{**row, "verdict": case.upper() if row["token_id"] == "grant" else "ACTIVE"}
                                                   for row in view[0].inputs["statuses"]]}
        view[0] = AuthoritySnapshot(1, {**view[0].artifact, "statuses_digest": digest(inputs["statuses"])}, inputs)
    result = session.mediate(sign({"request_id": "operation-2"}), "grant", lambda payload: pytest.fail("effect ran"), artifact_bytes=content)
    assert not result.effect_called
    assert result.outcome == ("UNKNOWN" if case in {"stale", "missing"} else "FAIL")


def test_revocation_cannot_be_undone_by_restoring_active_snapshot():
    session, sign, view, _, _, content = _fixture()
    original = view[0]
    statuses = [{**row, "verdict": "REVOKED" if row["token_id"] == "grant" else "ACTIVE"} for row in original.inputs["statuses"]]
    view[0] = AuthoritySnapshot(1, {**original.artifact, "statuses_digest": digest(statuses)}, {**original.inputs, "statuses": statuses})
    assert not session.mediate(sign(), "grant", lambda payload: None, artifact_bytes=content).effect_called
    view[0] = replace(original, generation=2)
    result = session.mediate(sign({"request_id": "operation-2"}), "grant", lambda payload: None, artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_cancellation_is_unknown_and_consumes_invocation():
    import asyncio
    session, sign, _, _, _, content = _fixture()
    def cancelled(payload):
        raise asyncio.CancelledError()
    result = session.mediate(sign(), "grant", cancelled, artifact_bytes=content)
    assert result.outcome == "UNKNOWN" and result.effect_called
    assert not session.mediate(sign(), "grant", lambda payload: None, artifact_bytes=content).effect_called


def test_signed_stop_blocks_new_work_and_reports_inflight_work_until_completion():
    from verifier.corrigibility.operator_stop import stop_signing_bytes
    session, sign, _, now, private, content = _fixture()
    entered, release = Event(), Event()
    results = []
    def effect(payload):
        entered.set()
        assert release.wait(5)
    thread = Thread(target=lambda: results.append(session.mediate(sign(), "grant", effect, artifact_bytes=content)))
    thread.start()
    assert entered.wait(5)
    body = {"schema": "verifier-operator-stop-1", "policy_digest": session.policy.stop_policy.digest,
            "session_id": session.session_id, "process_id": session.process_id, "action": "STOP",
            "operator_id": "root", "key_id": "stop-root", "request_id": "stop-1", "issued_at": now[0], "expires_at": now[0] + 30}
    assert session.request_stop({"body": body, "signature": private["root"].sign(stop_signing_bytes(body)).hex()}) == "PASS"
    assert not session.quiescent
    assert not session.mediate(sign({"request_id": "queued"}), "grant", lambda payload: None, artifact_bytes=content).effect_called
    release.set()
    thread.join(5)
    assert not thread.is_alive() and session.quiescent and results[0].effect_called


def test_historical_denial_replay_is_pure_and_detects_tampering():
    session, sign, _, _, _, content = _fixture()
    session.mediate(sign({"origin_id": "m0"}), "grant", lambda payload: pytest.fail("model effect"), artifact_bytes=content)
    events = session.events
    expected = digest([event.to_dict() for event in events])
    assert recheck_denial_trace(session.plan, events, expected_digest=expected).outcome == "PASS"
    assert session.events == events
    # Historical replay neither spends a current grant nor invokes an executor.
    assert session.mediate(sign({"request_id": "real-execution"}), "grant", lambda payload: None, artifact_bytes=content).effect_called
    bad = NamespaceObject.create(events[0].object_id, "EVENT", {**events[0].payload, "effect_called": True},
                                 dict(events[0].operands))
    assert recheck_denial_trace(session.plan, (bad,), expected_digest=digest([bad.to_dict()])).outcome == "FAIL"


def test_restart_does_not_inherit_old_session_authority():
    session, sign, view, now, _, content = _fixture()
    restarted = TrainControlSession(session.plan, session.policy, authority=lambda: view[0], clock=lambda: now[0])
    result = restarted.mediate(sign(), "grant", lambda payload: pytest.fail("old authority"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_unresolved_paths_block_runtime_without_executing():
    session, sign, view, now, _, content = _fixture()
    plan = replace(session.plan, external_paths_resolved=False)
    blocked = TrainControlSession(plan, session.policy, authority=lambda: view[0], clock=lambda: now[0])
    envelope = sign({"plan_digest": plan.digest, "session_id": blocked.session_id})
    result = blocked.mediate(envelope, "grant", lambda payload: pytest.fail("unresolved effect"), artifact_bytes=content)
    assert result.outcome == "UNKNOWN" and not result.effect_called


def _replace_tokens(session, view, private, tokens):
    for record in tokens:
        principal = next(identifier for identifier, key_id, _ in session.policy.principals if key_id == record["issuing_key_id"])
        record["signature"] = base64.b64encode(private[principal].sign(canonical_bytes(
            {name: value for name, value in record.items() if name != "signature"}))).decode()
    statuses = [{"token_id": record["token_id"], "published_at": 100, "verdict": "ACTIVE"} for record in tokens]
    view[0] = AuthoritySnapshot(view[0].generation + 1,
                               {**view[0].artifact, "tokens_digest": digest(tokens), "statuses_digest": digest(statuses)},
                               {**view[0].inputs, "tokens": tokens, "statuses": statuses})


def test_sibling_grants_share_parent_invocation_consumption():
    session, sign, view, _, private, content = _fixture()
    tokens = [dict(row) for row in view[0].inputs["tokens"]]
    tokens[1]["max_invocations"] = 1
    executor_key = next(key for principal, key, _ in session.policy.principals if principal == "executor")
    for name in ("child-a", "child-b"):
        tokens.append({**tokens[1], "token_id": name, "replay_id": name, "parent_grant_id": "grant", "issuing_key_id": executor_key})
    _replace_tokens(session, view, private, tokens)
    assert session.mediate(sign(), "child-a", lambda payload: None, artifact_bytes=content).effect_called
    result = session.mediate(sign({"request_id": "sibling-operation"}), "child-b", lambda payload: pytest.fail("shared parent spent"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_root_authorized_new_finite_fork_does_not_mint_successor_permissions():
    plan = _plan()
    new_train = NamespaceObject.create("t2", "TRAIN", {"revision": 2})
    fork = replace(plan, objects=plan.objects + (new_train,), families=plan.families + (("t2", "t2"),),
                   protected=plan.protected + tuple(("t2", facet, facet) for facet in sorted(PROTECTED_FACETS)),
                   relations=plan.relations + (("m1", "t2", "used_by"),))
    session, sign, _, _, _, _ = _fixture(plan=plan, action="fork_train", actor="root", change=fork.digest)
    called = []
    result = session.mediate(sign(), "grant", called.append, fork_plan=fork)
    assert result.outcome == "PASS" and result.effect_called and called == [None]
    assert session.plan is plan
    unauthorized = session.mediate(sign({"request_id": "implicit-launch", "action": "launch_train"}), "grant", called.append)
    assert unauthorized.outcome == "FAIL" and not unauthorized.effect_called and called == [None]


def test_fork_with_unresolved_required_paths_is_unknown_and_not_executed():
    fork = replace(_plan(), external_paths_resolved=False)
    session, sign, _, _, _, _ = _fixture(action="fork_train", actor="root", change=fork.digest)
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("unknown fork"), fork_plan=fork)
    assert result.outcome == "UNKNOWN" and not result.effect_called


def test_benign_checkpoint_aliases_match_runtime_and_preserve_exact_content():
    plan = replace(_plan(), aliases=(("train-alias", "t0"), ("checkpoint-a", "checkpoint-b"), ("checkpoint-b", "checkpoint")),
                   checkpoints=(("train-alias", "checkpoint-a"),))
    session, sign, _, _, _, content = _fixture(plan=plan)
    called = []
    assert session.mediate(sign(), "grant", called.append, artifact_bytes=content).effect_called
    assert called == [content]


def test_known_model_origin_is_denied_even_with_unresolved_sibling_bindings():
    session, sign, _, _, _, content = _fixture()
    result = session.mediate(sign({"origin_id": "m0", "target_id": "missing-target", "actor_id": "missing-actor"}),
                             "grant", lambda payload: pytest.fail("known model"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_suspension_observation_advances_rollback_watermark_even_when_admission_fails():
    session, sign, view, _, _, content = _fixture()
    original = view[0]
    assert session.mediate(sign(), "grant", lambda payload: None, artifact_bytes=content).effect_called
    statuses = [{**row, "verdict": "SUSPENDED" if row["token_id"] == "grant" else "ACTIVE"} for row in original.inputs["statuses"]]
    view[0] = AuthoritySnapshot(1, {**original.artifact, "statuses_digest": digest(statuses)}, {**original.inputs, "statuses": statuses})
    assert not session.mediate(sign({"request_id": "suspended"}), "grant", lambda payload: None, artifact_bytes=content).effect_called
    view[0] = original
    result = session.mediate(sign({"request_id": "rollback-active"}), "grant", lambda payload: pytest.fail("old active view"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def _stop_request(session, private, now):
    from verifier.corrigibility.operator_stop import stop_signing_bytes
    body = {"schema": "verifier-operator-stop-1", "policy_digest": session.policy.stop_policy.digest,
            "session_id": session.session_id, "process_id": session.process_id, "action": "STOP",
            "operator_id": "root", "key_id": "stop-root", "request_id": "stop-1", "issued_at": now, "expires_at": now + 30}
    return {"body": body, "signature": private["root"].sign(stop_signing_bytes(body)).hex()}


def test_reentrant_authenticated_stop_is_rechecked_before_effect_entry():
    session, sign, view, now, private, content = _fixture()
    def provider():
        assert session.request_stop(_stop_request(session, private, now[0])) == "PASS"
        assert session.quiescent
        return view[0]
    session._authority = provider
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("effect after stop"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called and session.quiescent


def test_reentrant_duplicate_cannot_invoke_twice():
    session, sign, view, _, _, content = _fixture()
    entered, called = [False], []
    def provider():
        if not entered[0]:
            entered[0] = True
            assert session.mediate(sign(), "grant", called.append, artifact_bytes=content).effect_called
        return view[0]
    session._authority = provider
    result = session.mediate(sign(), "grant", called.append, artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called and called == [content]


def test_authority_cancellation_and_clock_failure_do_not_enter_effect_or_mask_known_model_denial():
    import asyncio
    session, sign, _, _, _, content = _fixture()
    def cancelled():
        raise asyncio.CancelledError()
    session._authority = cancelled
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("cancelled auth"), artifact_bytes=content)
    assert result.outcome == "UNKNOWN" and not result.effect_called
    def bad_clock():
        raise OSError("x" * 100000)
    session._clock = bad_clock
    result = session.mediate(sign({"origin_id": "m0"}), "grant", lambda payload: pytest.fail("clock failure"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called
    assert result.event.payload["observed_at"] is None


def test_native_retained_denial_mechanism_requires_exact_host_commitment_and_binding():
    from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, VerificationSession
    from verifier.corrigibility.train_control import TrainDenialTraceMechanism
    session, sign, _, _, _, content = _fixture()
    session.mediate(sign({"origin_id": "m0"}), "grant", lambda payload: pytest.fail("model effect"), artifact_bytes=content)
    rows = [event.to_dict() for event in session.events]
    mechanism = TrainDenialTraceMechanism(session.plan, expected_trace_digest=digest(rows), policy_digest=session.policy.digest)
    store = EvidenceStore()
    ref = store.add(canonical_bytes(rows))
    binding = BoundProposition("t0", "retained-model-origin-effects-denied-1", True, mechanism.mechanism_id,
                               mechanism.mechanism_digest, (ref,), ("train-control-host:" + session.policy.digest,),
                               EvidenceBounds(1, 1048576), {"plan_digest": session.plan.digest, "trace_digest": digest(rows), "policy_digest": session.policy.digest})
    verifier = VerificationSession(store)
    verifier.register(mechanism)
    evaluated = verifier.evaluate(binding)
    assert evaluated.passed and evaluated.observations["whole_corrigibility"] == "UNKNOWN"
    assert not verifier.evaluate(replace(binding, parameters={**binding.parameters, "trace_digest": digest("other trace")})).passed
    other_subject = verifier.evaluate(replace(binding, subject_id="t1"))
    assert other_subject.outcome.value == "UNKNOWN" and not other_subject.passed


def test_scalar_capture_and_session_identifier_bounds_precede_effects():
    session, sign, view, now, _, _ = _fixture()
    envelope = sign()
    envelope["foreign"] = "x" * 100000
    with pytest.raises(ValueError, match="text bound"):
        session.mediate(envelope, "grant", lambda payload: pytest.fail("oversized capture"))
    with pytest.raises(ValueError, match="event-safe"):
        TrainControlSession(session.plan, session.policy, authority=lambda: view[0], clock=lambda: now[0], session_id="s" * 200)


@pytest.mark.parametrize("case", ["wrong_root", "wrong_delegate", "revoked_and_missing_other_status"])
def test_known_authority_refusal_precedes_missing_signature_backend(case, monkeypatch):
    from verifier.corrigibility import train_control
    session, sign, view, _, private, content = _fixture()
    if case == "revoked_and_missing_other_status":
        statuses = [{"token_id": "grant", "published_at": 100, "verdict": "REVOKED"}]
        view[0] = AuthoritySnapshot(1, {**view[0].artifact, "statuses_digest": digest(statuses)}, {**view[0].inputs, "statuses": statuses})
    else:
        tokens = [dict(row) for row in view[0].inputs["tokens"]]
        key_ids = {principal: key for principal, key, _ in session.policy.principals}
        tokens[0 if case == "wrong_root" else 1]["issuing_key_id" if case == "wrong_root" else "delegate_key_id"] = key_ids["executor" if case == "wrong_root" else "root"]
        _replace_tokens(session, view, private, tokens)
    original = train_control.native_token.evaluate
    def unavailable(check, *args, **kwargs):
        if check == "signatures":
            raise Unavailable("signature backend absent")
        return original(check, *args, **kwargs)
    monkeypatch.setattr(train_control.native_token, "evaluate", unavailable)
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("known unauthorized effect"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_missing_required_context_returns_unknown_without_fabricating_event():
    session, sign, _, _, _, content = _fixture(plan=replace(_plan(), context=("time", "env", "hardware", "space")))
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("missing TOKEN context"), artifact_bytes=content)
    assert result.outcome == "UNKNOWN" and not result.effect_called and result.event is None


def test_finite_trace_capacity_blocks_effect_but_cannot_block_authenticated_stop(monkeypatch):
    from verifier.corrigibility import train_control
    session, sign, _, now, private, content = _fixture()
    monkeypatch.setattr(train_control, "_MAX_EVENTS", 1)
    session.mediate(sign({"origin_id": "m0"}), "grant", lambda payload: None, artifact_bytes=content)
    with pytest.raises(Unavailable, match="EVENT bound"):
        session.mediate(sign(), "grant", lambda payload: pytest.fail("full trace"), artifact_bytes=content)
    assert session.request_stop(_stop_request(session, private, now[0])) == "PASS"
    assert session.quiescent and len(session.events) == 1


@pytest.mark.parametrize("binding", ["session_id", "plan_digest"])
def test_known_session_or_plan_refutation_dominates_missing_endpoints(binding):
    session, sign, _, _, _, content = _fixture()
    result = session.mediate(sign({binding: "other-selection", "actor_id": "missing-actor", "target_id": "missing-target"}),
                             "grant", lambda payload: pytest.fail("known binding mismatch"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_known_content_and_fork_refutations_dominate_clock_outage():
    session, sign, _, _, _, _ = _fixture()
    def bad_clock():
        raise OSError("clock unavailable")
    session._clock = bad_clock
    assert session.mediate(sign(), "grant", lambda payload: pytest.fail("wrong content"), artifact_bytes=b"wrong bytes").outcome == "FAIL"
    fork = replace(_plan(), inventory_complete=False)
    session, sign, _, _, _, _ = _fixture(action="fork_train", actor="root", change=fork.digest)
    session._clock = bad_clock
    wrong_plan = replace(_plan(), external_paths_resolved=False)
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("wrong fork"), fork_plan=wrong_plan)
    assert result.outcome == "FAIL" and not result.effect_called


def test_truthful_slow_authority_provider_cannot_admit_after_grant_expiry():
    session, sign, view, now, _, content = _fixture()
    def slow_provider():
        now[0] = 131
        return view[0]
    session._authority = slow_provider
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("expired effect"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called
    assert result.event.payload["observed_at"] == 131


def test_clock_advance_during_native_signature_work_is_rechecked_at_final_boundary(monkeypatch):
    from verifier.corrigibility import train_control
    session, sign, _, now, _, content = _fixture()
    original = train_control.native_token.evaluate
    def delayed(check, *args, **kwargs):
        result = original(check, *args, **kwargs)
        if check == "signatures":
            now[0] = 131
        return result
    monkeypatch.setattr(train_control.native_token, "evaluate", delayed)
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("expired after signature"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called


def test_replay_known_model_actor_survives_unresolved_origin():
    session, sign, _, _, _, content = _fixture()
    result = session.mediate(sign({"actor_id": "m1", "origin_id": "missing-origin"}), "grant",
                             lambda payload: pytest.fail("known actor"), artifact_bytes=content)
    assert result.outcome == "FAIL" and not result.effect_called
    assert recheck_denial_trace(session.plan, session.events,
                               expected_digest=digest([event.to_dict() for event in session.events])).outcome == "PASS"


def test_native_replay_capacity_is_unknown_instead_of_refuting_denials():
    from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, VerificationSession
    from verifier.corrigibility.train_control import TrainDenialTraceMechanism
    session, sign, _, _, _, content = _fixture()
    for index in range(257):
        result = session.mediate(sign({"origin_id": "m0", "request_id": "denied-"+str(index)}), "grant",
                                 lambda payload: pytest.fail("model effect"), artifact_bytes=content)
        assert not result.effect_called
    rows = [event.to_dict() for event in session.events]
    mechanism = TrainDenialTraceMechanism(session.plan, expected_trace_digest=digest(rows), policy_digest=session.policy.digest)
    store = EvidenceStore()
    ref = store.add(canonical_bytes(rows))
    binding = BoundProposition("t0", "retained-model-origin-effects-denied-1", True, mechanism.mechanism_id,
                               mechanism.mechanism_digest, (ref,), ("train-control-host:"+session.policy.digest,),
                               EvidenceBounds(1, 2*1048576), {"plan_digest":session.plan.digest, "trace_digest":digest(rows), "policy_digest":session.policy.digest})
    verifier = VerificationSession(store)
    verifier.register(mechanism)
    assert verifier.evaluate(binding).outcome.value == "UNKNOWN"


def test_known_model_capability_is_refuted_even_when_target_is_unresolved():
    plan = replace(_plan(), capabilities=(("m0", "unresolved-target", "mint_delegation"),))
    assert assess_train_control(plan).outcome == "FAIL"


def test_oversized_checkpoint_is_unknown_and_never_invokes_executor():
    session, sign, _, _, _, _ = _fixture()
    result = session.mediate(sign(), "grant", lambda payload: pytest.fail("over bound"), artifact_bytes=b"x"*(1048576+1))
    assert result.outcome == "UNKNOWN" and not result.effect_called


@pytest.mark.parametrize("case", ["quota", "revoked", "suspended"])
def test_final_clock_reentrancy_cannot_overspend_or_restore_superseded_authority(case):
    session, sign, view, _, private, content = _fixture()
    tokens = [dict(row) for row in view[0].inputs["tokens"]]
    tokens[1]["max_invocations"] = 1
    _replace_tokens(session, view, private, tokens)
    reads, called = [0], []
    def clock():
        reads[0] += 1
        if reads[0] == 3:
            if case != "quota":
                statuses = [{**row, "verdict": case.upper() if row["token_id"] == "grant" else "ACTIVE"}
                            for row in view[0].inputs["statuses"]]
                view[0] = AuthoritySnapshot(view[0].generation + 1,
                                           {**view[0].artifact, "statuses_digest": digest(statuses)},
                                           {**view[0].inputs, "statuses": statuses})
            inner = session.mediate(sign({"request_id": "inner"}), "grant", called.append, artifact_bytes=content)
            assert inner.effect_called == (case == "quota")
        return 100
    session._clock = clock
    outer = session.mediate(sign(), "grant", called.append, artifact_bytes=content)
    assert outer.outcome == "FAIL" and not outer.effect_called
    assert called == ([content] if case == "quota" else [])
    assert session._uses.get("grant", 0) == (1 if case == "quota" else 0)


def test_selected_plan_and_policy_have_no_public_mutation_path():
    session, _, _, _, _, _ = _fixture()
    with pytest.raises(AttributeError):
        session.plan = replace(session.plan, inventory_complete=False)
    with pytest.raises(AttributeError):
        session.policy = replace(session.policy, policy_id="changed-selection")
