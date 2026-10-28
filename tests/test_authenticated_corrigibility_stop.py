"""Refutable configured-key stop control for one cooperating local session."""
from __future__ import annotations

from threading import Event, Thread
import inspect
import os
import sys
import time

import pytest


def _keys():
    pytest.importorskip(
        "cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: Ed25519 stop verification requires cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from verifier.corrigibility.operator_stop import OperatorStopKey, OperatorStopPolicy

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    policy = OperatorStopPolicy("operator-policy-1", (
        OperatorStopKey("operator-a", "operator-key-a", public),), 60)
    return policy, private


def _request(session, policy, private, *, request_id="request-a", changes=None):
    from verifier.corrigibility.operator_stop import stop_signing_bytes

    now = int(time.time())
    body = {"schema": "verifier-operator-stop-1", "policy_digest": policy.digest,
            "session_id": session.session_id, "process_id": os.getpid(),
            "action": "STOP", "operator_id": "operator-a", "key_id": "operator-key-a",
            "request_id": request_id, "issued_at": now, "expires_at": now + 30}
    if changes:
        body.update(changes)
    return {"body": body, "signature": private.sign(stop_signing_bytes(body)).hex()}


def test_missing_or_forged_stop_does_not_latch_and_valid_stop_does(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    policy, private = _keys()
    session = controlled_operation.ControlledEmissionSession(stop_authority=policy)
    missing = session.request_stop()
    assert missing.authorization == "REJECTED" and not missing.stop_latched
    assert not session.wait_for_quiescence(0)

    signed = _request(session, policy, private)
    forged = {"body": dict(signed["body"]), "signature": "00" * 64}
    assert session.request_stop(forged).authorization == "REJECTED"
    assert not session.wait_for_quiescence(0)

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kw: {
        "admission": "PASS", "emitted_certificate": {"id": "selected"},
        "receipt": {"action": {"invocation_id": "before-stop"}}})
    called = []
    assert session.invoke({}, called.append).effect_called
    assert called == [{"id": "selected"}]

    stopped = session.request_stop(signed)
    assert stopped.authorization == "PASS"
    assert stopped.state == "QUIESCENT"
    assert stopped.stop_latched
    assert stopped.request_digest.startswith("sha256:")
    assert session.wait_for_quiescence(0)
    assert not session.invoke({}, called.append).effect_called
    assert len(called) == 1
    rejected_after_stop = session.request_stop(forged)
    assert rejected_after_stop.authorization == "REJECTED"
    assert rejected_after_stop.stop_latched


@pytest.mark.parametrize("change", [
    {"session_id": "other-session"}, {"process_id": -1}, {"action": "RESUME"},
    {"policy_digest": "sha256:" + "0" * 64}, {"operator_id": "operator-b"},
    {"key_id": "unknown-key"}, {"issued_at": 0, "expires_at": 1},
    {"issued_at": 9999999999, "expires_at": 10000000000},
])
def test_exact_binding_and_freshness_refuse_substituted_signed_request(change: dict) -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    policy, private = _keys()
    session = ControlledEmissionSession(stop_authority=policy)
    result = session.request_stop(_request(session, policy, private, changes=change))
    assert result.authorization == "REJECTED"
    assert not session.wait_for_quiescence(0)


def test_signed_request_cannot_stop_a_different_session() -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    policy, private = _keys()
    first = ControlledEmissionSession(stop_authority=policy)
    second = ControlledEmissionSession(stop_authority=policy)
    assert first.session_id != second.session_id
    request = _request(first, policy, private)
    assert second.request_stop(request).authorization == "REJECTED"
    assert not second.wait_for_quiescence(0)
    assert first.request_stop(request).authorization == "PASS"


def test_public_session_coordinates_cannot_be_reassigned() -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    policy, _ = _keys()
    session = ControlledEmissionSession(stop_authority=policy)
    with pytest.raises(AttributeError):
        session.session_id = "substituted-session"
    with pytest.raises(AttributeError):
        session.process_id = -1


def test_request_body_mutation_between_signing_and_binding_cannot_switch_session(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import operator_stop
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    policy, private = _keys()
    session = ControlledEmissionSession(stop_authority=policy)
    request = _request(session, policy, private, changes={"session_id": "other-session"})
    original = operator_stop.stop_signing_bytes

    def mutate_after_capture(body):
        signed = original(body)
        request["body"]["session_id"] = session.session_id
        return signed

    monkeypatch.setattr(operator_stop, "stop_signing_bytes", mutate_after_capture)
    assert session.request_stop(request).authorization == "REJECTED"
    assert not session.wait_for_quiescence(0)


def test_outer_envelope_replacement_cannot_execute_foreign_body_copy() -> None:
    from verifier.corrigibility import operator_stop
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    policy, private = _keys()
    session = ControlledEmissionSession(stop_authority=policy)
    request = _request(session, policy, private, changes={"session_id": "other-session"})
    original_body = dict(request["body"])
    calls: list[str] = []

    class ForeignBody:
        def copy(self):
            calls.append("foreign-copy")
            return dict(original_body)

    lines, start = inspect.getsourcelines(operator_stop.evaluate_stop_request)
    target = start + next(i for i, line in enumerate(lines) if 'body, signature = request[' in line)
    replaced = False

    def trace(frame, event, _argument):
        nonlocal replaced
        if (frame.f_code is operator_stop.evaluate_stop_request.__code__
                and event == "line" and frame.f_lineno == target):
            request["body"] = ForeignBody()
            replaced = True
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        result = operator_stop.evaluate_stop_request(
            policy, session.session_id, session.process_id, request, int(time.time()))
    finally:
        sys.settrace(previous)
    assert replaced
    assert result == ("REJECTED", None)
    assert calls == []


def test_missing_signature_backend_returns_unknown_without_latching(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    policy, private = _keys()
    session = ControlledEmissionSession(stop_authority=policy)
    request = _request(session, policy, private)
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    result = session.request_stop(request)
    assert result.authorization == "UNKNOWN"
    assert not result.stop_latched
    assert not session.wait_for_quiescence(0)


def test_authenticated_stop_reports_active_local_callback_until_it_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    policy, private = _keys()
    session = controlled_operation.ControlledEmissionSession(stop_authority=policy)
    entered, release = Event(), Event()
    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kw: {
        "admission": "PASS", "emitted_certificate": {"id": "selected"},
        "receipt": {"action": {"invocation_id": "in-flight"}}})

    def effect(_certificate):
        entered.set()
        assert release.wait(5)

    worker = Thread(target=lambda: session.invoke({}, effect))
    worker.start()
    try:
        assert entered.wait(5)
        result = session.request_stop(_request(session, policy, private))
        assert result.authorization == "PASS"
        assert result.state == "STOP_REQUESTED"
        assert not session.wait_for_quiescence(0)
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert session.wait_for_quiescence(0)


def test_cooperating_callback_observes_only_authenticated_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    policy, private = _keys()
    session = controlled_operation.ControlledEmissionSession(stop_authority=policy)
    entered = Event()
    observations: list[bool] = []
    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kw: {
        "admission": "PASS", "emitted_certificate": {"id": "selected"},
        "receipt": {"action": {"invocation_id": "cooperating-callback"}}})

    def effect(_certificate):
        entered.set()
        observations.append(session.wait_for_stop(5))

    worker = Thread(target=lambda: session.invoke({}, effect))
    assert session.stop_requested is False
    worker.start()
    try:
        assert entered.wait(5)
        signed = _request(session, policy, private)
        forged = {"body": dict(signed["body"]), "signature": "00" * 64}
        assert session.request_stop(forged).authorization == "REJECTED"
        assert session.stop_requested is False
        assert session.wait_for_stop(0) is False
        assert worker.is_alive()
        accepted = session.request_stop(signed)
        assert accepted.authorization == "PASS"
        assert session.stop_requested is True
    finally:
        worker.join(5)
    assert not worker.is_alive()
    assert observations == [True]
    assert session.wait_for_quiescence(0)


@pytest.mark.parametrize("timeout", [-1, 3601, float("inf"), float("nan"), True])
def test_stop_signal_rejects_invalid_timeout(timeout) -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    session = ControlledEmissionSession()
    with pytest.raises(ValueError):
        session.wait_for_stop(timeout)


def test_stop_policy_rejects_unusable_and_duplicate_keys() -> None:
    from verifier.corrigibility.operator_stop import OperatorStopKey, OperatorStopPolicy

    policy, _ = _keys()
    key = policy.operators[0]
    with pytest.raises(ValueError):
        OperatorStopKey("operator-a", "operator-key-a", bytes(32))
    with pytest.raises(ValueError):
        OperatorStopPolicy("operator-policy-1", (key, key), 60)


def test_unsigned_legacy_session_is_explicitly_not_authenticated() -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    session = ControlledEmissionSession()
    observation = session.request_stop()
    assert observation.authorization == "NOT_REQUIRED"
    assert observation.state == "QUIESCENT"
