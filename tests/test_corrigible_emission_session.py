"""Refutable bounds for cooperative, in-process correction of certificate emission."""
from __future__ import annotations

from threading import Event, Thread
from dataclasses import asdict
from pathlib import Path
import hashlib
import hmac
import importlib.util
import json

import pytest


def _admitted() -> dict[str, object]:
    return {"admission": "PASS", "emitted_certificate": {"id": "selected"},
            "receipt": {"action": {"invocation_id": "invocation-1"},
                        "private": "operator-audit"}}


def test_rejection_and_unknown_never_call_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    session = controlled_operation.ControlledEmissionSession()
    effects: list[dict[str, object]] = []
    for verdict in ("REJECTED", "UNKNOWN"):
        monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission",
                            lambda **_kwargs: {"admission": verdict,
                                               "emitted_certificate": None, "receipt": {}})
        result = session.invoke({}, effects.append)
        assert result.admission == verdict
        assert result.effect_called is False
    assert effects == []


def test_operator_stop_blocks_future_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kwargs: _admitted())
    session = controlled_operation.ControlledEmissionSession()
    effects: list[dict[str, object]] = []
    first = session.invoke({}, effects.append)
    assert first.admission == "PASS" and first.effect_called
    assert effects == [{"id": "selected"}]
    assert session.request_stop().state == "QUIESCENT"
    assert session.wait_for_quiescence(0.0) is True
    second = session.invoke({}, effects.append)
    assert second.control_status == "STOP_REQUESTED"
    assert second.effect_called is False
    assert effects == [{"id": "selected"}]


def test_successful_invocation_id_is_spent_locally(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kwargs: _admitted())
    session = controlled_operation.ControlledEmissionSession()
    effects: list[dict[str, object]] = []
    assert session.invoke({}, effects.append).effect_called
    replay = session.invoke({}, effects.append)
    assert replay.control_status == "LOCAL_REPLAY_REFUSED"
    assert replay.effect_called is False
    assert len(effects) == 1


def test_concurrent_replay_cannot_admit_second_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kwargs: _admitted())
    session = controlled_operation.ControlledEmissionSession()
    entered, release = Event(), Event()
    called: list[str] = []

    def effect(_certificate: dict[str, object]) -> None:
        called.append("first")
        entered.set()
        assert release.wait(5.0)

    worker = Thread(target=lambda: session.invoke({}, effect))
    worker.start()
    try:
        assert entered.wait(5.0)
        replay = session.invoke({}, lambda _certificate: called.append("second"))
        assert replay.control_status == "LOCAL_REPLAY_REFUSED"
        assert replay.effect_called is False
    finally:
        release.set()
        worker.join(5.0)
    assert not worker.is_alive()
    assert called == ["first"]


def test_malformed_pass_cannot_bypass_receipt_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission",
                        lambda **_kwargs: {"admission": "PASS", "emitted_certificate": {},
                                           "receipt": {"action": {}}})
    called: list[dict[str, object]] = []
    result = controlled_operation.ControlledEmissionSession().invoke({}, called.append)
    assert result.control_status == "GATE_RESULT_INVALID"
    assert result.admission == "UNKNOWN"
    assert called == []


def test_local_replay_inventory_fails_closed_at_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    selected = {"id": "invocation-1"}

    def admitted(**_kwargs: object) -> dict[str, object]:
        result = _admitted()
        result["receipt"]["action"]["invocation_id"] = selected["id"]
        return result

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", admitted)
    monkeypatch.setattr(controlled_operation, "_MAX_SPENT_INVOCATIONS", 1)
    session = controlled_operation.ControlledEmissionSession()
    effects: list[dict[str, object]] = []
    assert session.invoke({}, effects.append).effect_called
    selected["id"] = "invocation-2"
    refused = session.invoke({}, effects.append)
    assert refused.control_status == "LOCAL_CAPACITY_EXHAUSTED"
    assert refused.effect_called is False
    assert len(effects) == 1


def test_stop_during_admission_cannot_start_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    entered, release = Event(), Event()

    def evaluate(**_kwargs: object) -> dict[str, object]:
        entered.set()
        assert release.wait(2.0)
        return _admitted()

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", evaluate)
    session = controlled_operation.ControlledEmissionSession()
    effects: list[dict[str, object]] = []
    results: list[object] = []
    worker = Thread(target=lambda: results.append(session.invoke({}, effects.append)))
    worker.start()
    try:
        assert entered.wait(2.0)
        assert session.request_stop().state == "STOP_REQUESTED"
        assert session.wait_for_quiescence(0.01) is False
    finally:
        release.set()
        worker.join(2.0)
    assert not worker.is_alive()
    assert session.wait_for_quiescence(0.1) is True
    assert results[0].control_status == "STOP_REQUESTED"
    assert effects == []


def test_inflight_effect_is_not_misreported_as_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kwargs: _admitted())
    entered, release = Event(), Event()

    def effect(_certificate: dict[str, object]) -> None:
        entered.set()
        assert release.wait(2.0)

    session = controlled_operation.ControlledEmissionSession()
    worker = Thread(target=lambda: session.invoke({}, effect))
    worker.start()
    try:
        assert entered.wait(2.0)
        assert session.request_stop().state == "STOP_REQUESTED"
        assert session.wait_for_quiescence(0.01) is False
    finally:
        release.set()
        worker.join(2.0)
    assert not worker.is_alive()
    assert session.wait_for_quiescence(0.1) is True


def test_callback_exception_releases_local_active_count(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.corrigibility import controlled_operation

    monkeypatch.setattr(controlled_operation, "evaluate_controlled_emission", lambda **_kwargs: _admitted())
    session = controlled_operation.ControlledEmissionSession()

    def fail(_certificate: dict[str, object]) -> None:
        raise RuntimeError("local effect failed")

    with pytest.raises(RuntimeError, match="local effect failed"):
        session.invoke({}, fail)
    assert session.request_stop().state == "QUIESCENT"
    assert session.wait_for_quiescence(0.0) is True


def _signed(payload: dict[str, object], key: bytes) -> dict[str, object]:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("utf-8")
    return {**payload, "signature": hmac.new(key, raw, hashlib.sha256).hexdigest()}


def _real_inputs() -> dict[str, object]:
    """One real domain certificate with independently chosen authority inputs."""
    from verifier import build_domain_certificate, domain_policy, domain_request
    from verifier.consent import ConsentKey, ConsentPolicy, authenticate_consent
    from verifier.governance import GovernanceContext, GovernancePolicy, GovernancePrincipal, policy_digest
    from verifier.privacy import DisclosureBound, DisclosureSurface, EmissionContext, ObserverParty

    path = Path(__file__).resolve().parents[1] / "examples/domain_grounding.py"
    spec = importlib.util.spec_from_file_location("corrigible_domain_example", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = module.specimens()["SIM"]
    checker_policy = domain_policy(trust_roots=["local:corrigibility-test"])
    certificate = build_domain_certificate(domain_request(evidence, target_depth=4),
                                           evidence, policy=checker_policy)
    assert certificate["result"]["status"] == "PASS"
    artifact_digest = hashlib.sha256(json.dumps(certificate, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    action = GovernanceContext("SIM", artifact_digest, "publish", "publisher", "reader",
                               "teaching", 200, "lab", "invocation-1")
    owner = ConsentKey("owner-key", "owner", b"o" * 32)
    registry = ConsentKey("registry-key", "registry", b"r" * 32)
    consent_policy = ConsentPolicy("consent-test", "owner", (owner, registry),
        (owner.key_id,), (registry.key_id,), artifact_bindings=(("SIM", artifact_digest),))
    grant = {"schema_version": "verifier-consent-grant-1", "grant_id": "grant-1", "issuer_id": "owner",
        "actor_id": "publisher", "object_name": "SIM", "artifact_digest": artifact_digest,
        "operations": ["publish"], "observer_ids": ["reader"], "purposes": ["teaching"],
        "not_before": 100, "not_after": 300, "parent_digest": None,
        "allow_delegation": False, "effect": "ALLOW"}
    revocation = {"schema_version": "verifier-consent-revocations-1", "issuer_id": "registry",
        "policy_id": consent_policy.policy_id, "as_of": 195, "next_update": 220,
        "revoked_grant_ids": []}
    principal = GovernancePrincipal("board", "board-key", b"b" * 32)
    governance_policy = GovernancePolicy(policy_id="governance-test", revision=1,
        object_names=("SIM",), operations=("publish",), jurisdictions=("lab",),
        principals=(principal,), quorum=1, veto_actors=(), status_key_id="governance-status",
        status_key=b"s" * 32, effective_from=100, effective_until=300, max_status_age=30)
    terms = policy_digest(governance_policy)
    vote = _signed({"schema": "verifier-governance-decision-1", "decision_id": "decision-1",
        "policy_digest": terms, "binding": asdict(action), "actor_id": principal.actor_id,
        "key_id": principal.key_id, "decision": "APPROVE", "issued_at": 190,
        "expires_at": 220}, principal.key)
    status = _signed({"schema": "verifier-governance-status-1", "policy_digest": terms,
        "key_id": governance_policy.status_key_id, "observed_at": 195, "expires_at": 220,
        "revoked_decisions": [], "revoked_actors": [], "consumed_invocations": []},
        governance_policy.status_key)
    return dict(certificate=certificate, action=action, certificate_policy=checker_policy,
        privacy_surface=DisclosureSurface("SIM", tuple(certificate), ()),
        privacy_bounds=tuple(DisclosureBound("bound:" + key, key, admitted_observers=("reader",),
            conditions=(("purpose", "teaching"),)) for key in certificate),
        privacy_context=EmissionContext(ObserverParty("reader", "reader", "teaching"),
                                        "1970-01-01T00:03:20Z"),
        consent_policy=consent_policy, consent_grants=(authenticate_consent(grant, owner),),
        consent_revocation=authenticate_consent(revocation, registry),
        governance_policy=governance_policy, governance_decisions=(vote,),
        governance_status=status, evaluation_time=200)


def test_real_consent_governance_privacy_and_stop_composition() -> None:
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    inputs = _real_inputs()
    effects: list[dict[str, object]] = []
    session = ControlledEmissionSession()
    admitted = session.invoke(inputs, effects.append)
    assert admitted.control_status == "CALLBACK_RETURNED"
    assert admitted.admission == "PASS"
    assert len(effects) == 1
    assert admitted.gate_receipt["checks"]["consent"]["verdict"] == "PASS"
    assert admitted.gate_receipt["checks"]["governance"]["verdict"] == "PASS"
    assert "privacy" in admitted.gate_receipt["checks"]

    # A missing field bound must refuse disclosure before a callback runs.
    privacy_refusal = {**inputs, "privacy_bounds": inputs["privacy_bounds"][1:]}
    denied = session.invoke(privacy_refusal, effects.append)
    assert denied.admission == "REJECTED"
    assert denied.effect_called is False
    assert len(effects) == 1

    assert session.request_stop().state == "QUIESCENT"
    assert session.wait_for_quiescence(0.0)
    stopped = session.invoke(inputs, effects.append)
    assert stopped.control_status == "STOP_REQUESTED"
    assert len(effects) == 1


def test_real_revocation_and_governance_veto_refuse_effects() -> None:
    from verifier.consent import authenticate_consent
    from verifier.corrigibility.controlled_operation import ControlledEmissionSession

    inputs = _real_inputs()
    effects: list[dict[str, object]] = []
    revocation = {key: value for key, value in inputs["consent_revocation"].items()
                  if key != "signature"}
    revocation["revoked_grant_ids"] = ["grant-1"]
    registry = inputs["consent_policy"].keys[1]
    revoked_inputs = {**inputs, "consent_revocation": authenticate_consent(revocation, registry)}
    revoked = ControlledEmissionSession().invoke(revoked_inputs, effects.append)
    assert revoked.admission == "REJECTED"
    assert revoked.effect_called is False
    assert revoked.gate_receipt["checks"]["consent"]["verdict"] == "REJECTED"

    governance_status = {key: value for key, value in inputs["governance_status"].items()
                         if key != "signature"}
    governance_status["revoked_decisions"] = ["decision-1"]
    vetoed_inputs = {**inputs, "governance_status": _signed(
        governance_status, inputs["governance_policy"].status_key)}
    vetoed = ControlledEmissionSession().invoke(vetoed_inputs, effects.append)
    assert vetoed.admission == "REJECTED"
    assert vetoed.effect_called is False
    assert vetoed.gate_receipt["checks"]["governance"]["verdict"] == "REJECTED"
    assert effects == []
