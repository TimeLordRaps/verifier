"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

real finite native/Ed25519/atomic E2E, no full polish fixture.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3

import pytest
from verifier.core.certificate import canonical_bytes
from verifier.runtime import finite_record_issuance as issuer, polish_invocation_ledger as ledger
from verifier.runtime import polish_public_authority as authority, public_checkability as public
from finite_record_fixture import FinitePackage, digest


@pytest.fixture
def finite(tmp_path):
    value = FinitePackage(tmp_path)
    value.authorize()
    return value


def test_real_native_crypto_atomic_and_readonly_positive_finite_issuance(finite, monkeypatch):
    ready = finite.ready
    assert ready["full_application_status"] == "UNKNOWN" and ready["polished"] is False
    assert ready["subject"]["operation"] == authority.FINITE_OPERATION
    assert "issue_evidence" not in ready["subject"] and "authority_status_digest" not in ready["subject"]
    committed = finite.commit()
    receipt = committed["local_commit"]
    assert committed["status"] == "PASS" and receipt["invocation_consumption"] == "CONSUMED_EXACT_LOCAL_LEDGER"
    assert committed["finite_issuance_state"] == "AWAITING_DISTINCT_SIGNED_POSTCOMMIT"
    finite.postcommit(receipt)
    selection = finite.final_selection(receipt)
    def never_consume(*args, **kwargs):
        pytest.fail("finalize/replay must read the SAME existing entry, never consume again")
    monkeypatch.setattr(ledger, "commit_issuance", never_consume)
    final = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert final["status"] == "PASS" and final["finite_issuance_state"] == "EXACT_FINITE_RECORD_ISSUED"
    assert final["polished"] is False and final["full_application_status"] == "UNKNOWN"
    assert final["human_acceptance"] == "NOT_ESTABLISHED" and final["promotion"] == "NOT_PERFORMED"
    for _ in range(3):
        replay = issuer.recheck_finite_record_issuance(canonical_bytes(final), finite.proposal, **selection)
        assert replay["status"] == "PASS" and replay["replay_status"] == "REPRODUCED"
        assert replay["polished"] is False
    with sqlite3.connect(finite.ledger.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM issuance").fetchone()[0] == 1


def test_real_concurrent_duplicate_finite_commit_consumes_once(finite):
    with ThreadPoolExecutor(max_workers=3) as workers:
        results = list(workers.map(lambda _: finite.commit(), range(3)))
    assert sum(result["status"] == "PASS" for result in results) == 1
    assert all(result["local_commit"]["reason"] == "KNOWN_INVOCATION_REPLAY" for result in results if result["status"] == "FAIL")
    assert finite.commit()["status"] == "FAIL"


def test_policy_epoch_rotation_between_authorization_and_atomic_commit_refuses(finite):
    ledger.advance_policy_epoch(finite.ledger, new_epoch=2)
    assert finite.commit()["status"] == "FAIL"
    recovered = ledger.recover_issuance_commit(finite.proposal, expected_proposal_digest=digest(finite.proposal),
        invocation_id="fixture:one", selection=replace(finite.ledger, policy_epoch=2))
    assert recovered["status"] == "UNKNOWN"  # No stale authorization consumed an ID.


@pytest.mark.parametrize("change", ["deny", "veto", "revoked", "consumed", "signature", "expired"])
def test_real_authority_refusals_never_commit(finite, change):
    if change == "deny":
        finite.evidence["decisions"][0] = finite.decision("a", "DENY")
    elif change == "veto":
        finite.evidence["decisions"].append(finite.decision("veto", "VETO"))
    elif change in ("revoked", "consumed"):
        row = dict(finite.evidence["status"]["payload"])
        row["revoked_actors" if change == "revoked" else "consumed_invocations"] = ["actor:a" if change == "revoked" else "fixture:one"]
        finite.evidence["status"] = finite.envelope(row, "status")
    elif change == "expired":
        row = {**finite.evidence["decisions"][0]["payload"], "expires_at": 99}
        finite.evidence["decisions"][0] = finite.envelope(row, "a")
    else:
        finite.evidence["decisions"][0]["signature"] = "0" * 128
    assert finite.assess()["status"] == "FAIL"
    assert finite.commit()["status"] == "FAIL"
    with sqlite3.connect(finite.ledger.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM issuance").fetchone()[0] == 0


@pytest.mark.parametrize("change,expected", [("missing", "UNKNOWN"), ("wrong-domain", "FAIL"), ("binding", "FAIL"), ("revoked", "FAIL"), ("stale", "UNKNOWN")])
def test_distinct_real_postcommit_attestation_is_mandatory(finite, change, expected):
    receipt = finite.commit()["local_commit"]
    finite.postcommit(receipt)
    payload = json.loads(finite.public_commit)["payload"]
    if change == "missing":
        finite.public_commit = None
    elif change == "binding":
        payload["proposal_digest"] = digest(b"another-proposal")
        finite.public_commit = finite.commit_envelope(payload)
    elif change == "revoked":
        payload["revoked_subjects"] = [payload["subject_digest"]]
        finite.public_commit = finite.commit_envelope(payload)
    elif change == "stale":
        payload["expires_at"] = 101
        finite.public_commit = finite.commit_envelope(payload)
    else:
        finite.public_commit = finite.commit_envelope(payload, wrong_domain=True)
    selection = finite.final_selection(receipt)
    if change == "stale":
        selection["evaluation_time"] = 102
    result = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert result["status"] == expected and result["polished"] is False
    assert finite.commit()["status"] == "FAIL"  # Finalization cannot retry local consumption.


def test_real_native_forgery_stays_fail_through_later_public_unavailability(tmp_path, monkeypatch):
    finite = FinitePackage(tmp_path)
    envelope = json.loads(finite.public.files["generic.json"])
    envelope["result"]["execution"] = "ESTABLISHED"
    envelope.pop("digest")
    envelope["digest"] = digest(canonical_bytes(envelope))
    forged = canonical_bytes(envelope)
    finite.public.files["generic.json"] = forged
    node = finite.public.dependency["nodes"][0]
    node["certificate_digest"] = digest(forged)
    node["artifact_bindings"][0]["digest"] = digest(forged)
    finite.public.rebind()
    finite.refresh()
    def unavailable(*args, **kwargs):
        raise OSError("negative-only later source unavailable")
    monkeypatch.setattr(public, "assess_public_checkability", unavailable)
    result = finite.assess()
    assert result["status"] == "FAIL" and "NATIVE_RECORD_REFUTED" in result["checks"]


def test_known_changed_original_bytes_precede_current_source_outage(finite, monkeypatch):
    receipt = finite.commit()["local_commit"]
    finite.postcommit(receipt)
    final = issuer.finalize_finite_record_issuance(finite.proposal, **finite.final_selection(receipt))
    assert final["status"] == "PASS"
    def absent():
        raise OSError("negative-only installed source absent")
    monkeypatch.setattr(issuer, "mechanism_digest", absent)
    unchanged = issuer.recheck_finite_record_issuance(canonical_bytes(final), finite.proposal, **finite.final_selection(receipt))
    assert unchanged["status"] == "UNKNOWN" and unchanged["replay_status"] == "UNAVAILABLE"
    changed = {**finite.final_selection(receipt), "request_bytes": b'{"known":"changed"}', "public_commit_bytes": None}
    refused = issuer.recheck_finite_record_issuance(canonical_bytes(final), finite.proposal, **changed)
    assert refused["status"] == "FAIL" and refused["replay_status"] == "REJECTED"


@pytest.mark.parametrize("field", ["policy_epoch", "commit_sequence", "commit_time", "observed_at", "expires_at"])
def test_real_signed_postcommit_boolean_generation_or_time_refuses(finite, field):
    receipt = finite.commit()["local_commit"]
    finite.postcommit(receipt)
    payload = json.loads(finite.public_commit)["payload"]
    payload[field] = True
    finite.public_commit = finite.commit_envelope(payload)
    assert issuer.finalize_finite_record_issuance(finite.proposal, **finite.final_selection(receipt))["status"] == "FAIL"


def test_known_changed_proposal_input_precedes_absent_same_commit_receipt(finite):
    changed = {"receipt_bytes": None, "public_commit_bytes": None, "bundle_bytes": finite.bundle,
        "request_bytes": b'{"changed":"known"}', "issue_evidence_bytes": canonical_bytes(finite.evidence),
        "host_selection": finite.host, "evaluation_time": 100}
    result = issuer.finalize_finite_record_issuance(finite.proposal, **changed)
    assert result["status"] == "FAIL" and result["polished"] is False


def test_full_mode_and_carried_structural_pass_never_establish_full_polish(finite):
    request = json.loads(finite.request)
    policy = deepcopy(finite.policy)
    request["mode"] = policy["mode"] = issuer.FULL
    raw = canonical_bytes(policy)
    host = replace(finite.host, policy_bytes=raw, expected_policy_digest=digest(raw))
    request["host_policy_digest"] = digest(raw)
    result = issuer.assess_finite_record_issuance(finite.bundle, request_bytes=canonical_bytes(request),
        issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=host, evaluation_time=100)
    assert result["status"] == "UNKNOWN" and result["polished"] is False and result["full_application_status"] == "UNKNOWN"
    request["structural_pass"] = True
    assert issuer.assess_finite_record_issuance(finite.bundle, request_bytes=canonical_bytes(request),
        issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=host, evaluation_time=100)["status"] == "FAIL"


def test_foreign_and_overbound_inputs_do_not_call_source_or_hash(monkeypatch):
    def never_source():
        pytest.fail("foreign/bound input must be refused before source callback")
    def never_hash(*args, **kwargs):
        pytest.fail("transport admission must precede submitted-input hashing")
    monkeypatch.setattr(issuer, "mechanism_digest", never_source)
    # Output diagnostics may legitimately hash their own small fixed body.
    original = issuer._digest
    bad = b" " * (issuer.MAX_BUNDLE_BYTES + 1)
    def tracked(raw):
        if raw is bad:
            never_hash()
        return original(raw)
    monkeypatch.setattr(issuer, "_digest", tracked)
    class Foreign(bytes):
        def __len__(self):
            pytest.fail("foreign length callback")
    for raw, expected in ((Foreign(b"{}"), "FAIL"), (bad, "UNKNOWN")):
        result = issuer.assess_finite_record_issuance(raw, request_bytes=b"{}", issue_evidence_bytes=None,
            host_selection=None, evaluation_time=100)
        assert result["status"] == expected and len(canonical_bytes(result)) <= issuer.MAX_BYTES
