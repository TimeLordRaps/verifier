"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

cancellation preserves local refusals; no positive mock.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy

import pytest
from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_public_authority as authority
from test_polish_public_authority_precrypto import selected_without_crypto, envelope, digest
from test_polish_authority_recheck_availability import real_selected


def cancelled(*args, **kwargs):
    raise asyncio.CancelledError("negative-only cancelled work")


def changed_evidence(call, evidence, mutation):
    call, evidence = dict(call), deepcopy(evidence)
    if mutation in ("decision_role", "decision_binding", "decision_time"):
        row = dict(evidence["decisions"][0]["payload"])
        if mutation == "decision_role":
            row["actor_id"] = "foreign:actor"
        elif mutation == "decision_binding":
            row["context_digest"] = digest(b"different-context")
        else:
            row["issued_at"], row["expires_at"] = 100, 150
        evidence["decisions"][0] = envelope(row, "a")
    else:
        row = dict(evidence["status"]["payload"])
        if mutation == "status_binding":
            row["ledger_id"] = "different:ledger"
        evidence["status"] = envelope(row, "a" if mutation == "status_role" else "status")
    call["evidence_bytes"] = canonical_bytes(evidence)
    return call


@pytest.mark.parametrize("mutation,reason", [
    ("decision_role", "DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH"),
    ("decision_binding", "DEMONSTRATED_ACTION_BINDING_MISMATCH"),
    ("decision_time", "DEMONSTRATED_DECISION_TIME_MISMATCH"),
    ("status_role", "DEMONSTRATED_POLICY_STATUS_ROLE_MISMATCH"),
    ("status_binding", "DEMONSTRATED_STATUS_SCOPE_MISMATCH"),
])
def test_cheap_known_refusal_survives_backend_cancellation(selected_without_crypto, monkeypatch, mutation, reason):
    call, evidence, _ = selected_without_crypto
    call = changed_evidence(call, evidence, mutation)
    monkeypatch.setattr(authority, "_authenticate", cancelled)
    report = authority.assess_polish_authority(**call)
    assert report["status"] == "FAIL" and reason in report["checks"]
    assert "AUTHORITY_RESOURCE_BOUND_EXHAUSTED" in report["checks"]
    assert report["replayable"] is False and report["polished"] is False
    assert len(canonical_bytes(report)) <= authority.MAX_BYTES


@pytest.mark.parametrize("mutation", ["subject", "operation", "clock", "decision_binding", "status_binding", "decision_role", "policy_roles", "policy_scope"])
@pytest.mark.parametrize("loss", ["source", "cancel"])
def test_available_authority_refutations_precede_source_loss(selected_without_crypto, monkeypatch, mutation, loss):
    import json
    call, evidence, context = selected_without_crypto
    call, context = dict(call), dict(context)
    if mutation in ("decision_binding", "status_binding", "decision_role"):
        call = changed_evidence(call, evidence, mutation)
    elif mutation in ("subject", "operation"):
        context["subject_digest" if mutation == "subject" else "operation"] = digest(b"false-subject") if mutation == "subject" else "UNSUPPORTED_OPERATION"
        call["context_bytes"] = canonical_bytes(context)
    elif mutation == "clock":
        call["evaluation_time"] = 201
    else:
        policy = json.loads(call["trusted_policy_bytes"])
        if mutation == "policy_roles":
            policy["status_key_id"] = "a"
        else:
            policy["scopes"][0]["jurisdiction"] = "different:jurisdiction"
        raw = canonical_bytes(policy)
        call["trusted_policy_bytes"], call["expected_trusted_policy_digest"] = raw, digest(raw)
        context["policy_digest"] = digest(raw)
        call["context_bytes"] = canonical_bytes(context)
        rebound = deepcopy(evidence)
        for index, item in enumerate(rebound["decisions"]):
            row = {**item["payload"], "context_digest": digest(call["context_bytes"]), "policy_digest": digest(raw)}
            rebound["decisions"][index] = envelope(row, item["key_id"])
        rebound["status"] = envelope({**rebound["status"]["payload"], "policy_digest": digest(raw)}, "status")
        call["evidence_bytes"] = canonical_bytes(rebound)
    def absent():
        if loss == "cancel":
            raise asyncio.CancelledError("negative-only cancelled source")
        raise OSError("negative-only absent source")
    monkeypatch.setattr(authority, "mechanism_digest", absent)
    monkeypatch.setattr(authority, "_authenticate", cancelled)
    report = authority.assess_polish_authority(**call)
    assert report["status"] == "FAIL" and report["polished"] is False
    assert report["replayable"] is False


def test_false_subject_precedes_missing_policy(selected_without_crypto, monkeypatch):
    call, _, context = selected_without_crypto
    context = {**context, "subject_digest": digest(b"known-false-subject")}
    monkeypatch.setattr(authority, "mechanism_digest", cancelled)
    report = authority.assess_polish_authority(**{**call, "context_bytes": canonical_bytes(context),
        "trusted_policy_bytes": None, "expected_trusted_policy_digest": None})
    assert report["status"] == "FAIL" and report["polished"] is False


@pytest.mark.parametrize("stage", ["source", "decision", "status", "decode", "output"])
def test_real_prior_positive_clean_cancellation_is_unknown_and_replay_unavailable(real_selected, monkeypatch, stage):
    call, stored = real_selected
    if stage == "source":
        monkeypatch.setattr(authority, "mechanism_digest", cancelled)
    elif stage == "decode":
        original = authority._load
        def load(raw):
            if raw == stored:
                return original(raw)  # Retained guard still gets actual decoding.
            return cancelled()
        monkeypatch.setattr(authority, "_load", load)
    elif stage == "output":
        original = authority.canonical_bytes
        def encode(value):
            if type(value) is dict and value.get("schema_version") == authority.ASSESSMENT:
                return cancelled()
            return original(value)
        monkeypatch.setattr(authority, "canonical_bytes", encode)
    else:
        original = authority._authenticate
        def authenticate(item, keys):
            if stage == "decision" or item["payload"]["schema_version"] == authority.STATUS:
                return cancelled()
            return original(item, keys)
        monkeypatch.setattr(authority, "_authenticate", authenticate)
    report = authority.assess_polish_authority(**call)
    assert report["status"] == "UNKNOWN" and report["replayable"] is False and report["polished"] is False
    replay = authority.recheck_polish_authority(stored, **call)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE" and replay["polished"] is False


def test_direct_rechecker_capacity_cancellation_is_typed_unavailable(real_selected, monkeypatch):
    call, stored = real_selected
    monkeypatch.setattr(authority, "assess_polish_authority", cancelled)
    report = authority.recheck_polish_authority(stored, **call)
    assert report["status"] == "UNKNOWN" and report["replay_status"] == "UNAVAILABLE"


def test_new_semantic_refusal_survives_later_cancel_and_rejects_old_positive(real_selected, monkeypatch):
    call, stored = real_selected
    count = 0
    def refuse_then_cancel(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 1:
            raise ValueError("negative-only actual checking refusal")
        return cancelled()
    monkeypatch.setattr(authority, "_authenticate", refuse_then_cancel)
    report = authority.recheck_polish_authority(stored, **call)
    assert report["status"] == "FAIL" and report["replay_status"] == "REJECTED"


def test_fresh_semantic_fail_survives_output_cancellation(real_selected, monkeypatch):
    call, stored = real_selected
    def refused(*args, **kwargs):
        raise ValueError("negative-only signature checking refusal")
    original = authority.canonical_bytes
    def encode(value):
        if type(value) is dict and value.get("schema_version") == authority.ASSESSMENT:
            return cancelled()
        return original(value)
    monkeypatch.setattr(authority, "_authenticate", refused)
    monkeypatch.setattr(authority, "canonical_bytes", encode)
    report = authority.assess_polish_authority(**call)
    assert report["status"] == "FAIL" and report["replayable"] is False
    # Retained decoding/hash work also may be cancelled: it cannot carry PASS.
    replay = authority.recheck_polish_authority(stored, **call)
    assert replay["status"] != "PASS" and replay["replay_status"] != "REPRODUCED"


def test_retained_input_refusal_precedes_fresh_cancel(real_selected, monkeypatch):
    call, stored = real_selected
    calls = []
    def source():
        calls.append(True)
        return cancelled()
    monkeypatch.setattr(authority, "mechanism_digest", source)
    report = authority.recheck_polish_authority(stored, **{**call, "subject_bytes": b'{"known":"changed"}'})
    assert report["status"] == "FAIL" and report["replay_status"] == "REJECTED" and calls == []


def test_clean_source_absence_and_missing_policy_never_grant_authority(selected_without_crypto, monkeypatch):
    call, _, _ = selected_without_crypto
    def absent():
        raise OSError("negative-only absent source")
    monkeypatch.setattr(authority, "mechanism_digest", absent)
    for selected in (call, {**call, "trusted_policy_bytes": None, "expected_trusted_policy_digest": None}):
        report = authority.assess_polish_authority(**selected)
        assert report["status"] == "UNKNOWN" and report["replayable"] is False and report["polished"] is False
