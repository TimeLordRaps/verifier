"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

exact authority replay availability/refusal precedence.
"""
from __future__ import annotations

from copy import deepcopy
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_public_authority as authority
from finite_record_fixture import FinitePackage, digest
from test_polish_public_authority_precrypto import selected_without_crypto, unavailable_backend


@pytest.fixture
def real_selected(tmp_path):
    fixture = FinitePackage(tmp_path)
    fixture.authorize()
    call = {"subject_bytes": canonical_bytes(fixture.ready["subject"]),
        "context_bytes": canonical_bytes(fixture.context), "evidence_bytes": canonical_bytes(fixture.evidence),
        "trusted_policy_bytes": fixture.host.authority_policy_bytes,
        "expected_trusted_policy_digest": fixture.host.expected_authority_policy_digest, "evaluation_time": 100}
    stored = authority.assess_polish_authority(**call)
    assert stored["status"] == "PASS" and stored["polished"] is False
    return call, canonical_bytes(stored)


def test_real_positive_authority_source_outage_is_unknown_unavailable(real_selected, monkeypatch):
    call, stored = real_selected
    def absent():
        raise OSError("negative-only unavailable source")
    monkeypatch.setattr(authority, "mechanism_digest", absent)
    replay = authority.recheck_polish_authority(stored, **call)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE" and replay["polished"] is False


@pytest.mark.parametrize("missing", ["subject_bytes", "context_bytes", "evidence_bytes", "trusted_policy_bytes", "evaluation_time", "expected_trusted_policy_digest"])
def test_real_positive_missing_exact_selection_never_carries_pass(real_selected, missing):
    call, stored = real_selected
    result = authority.recheck_polish_authority(stored, **{**call, missing: None})
    assert result["status"] == "UNKNOWN" and result["replay_status"] == "UNAVAILABLE"


@pytest.mark.parametrize("change", ["subject", "context", "evidence", "policy", "clock", "policy_pin", "forged_record"])
def test_known_retained_binding_contradiction_precedes_source_outage(real_selected, monkeypatch, change):
    call, stored = real_selected
    call = dict(call)
    def absent():
        raise OSError("negative-only unavailable source")
    monkeypatch.setattr(authority, "mechanism_digest", absent)
    if change in ("subject", "context", "evidence", "policy"):
        call[{"subject": "subject_bytes", "context": "context_bytes", "evidence": "evidence_bytes", "policy": "trusted_policy_bytes"}[change]] = b'{"known":"changed"}'
    elif change == "clock":
        call["evaluation_time"] = 101
    elif change == "policy_pin":
        call["expected_trusted_policy_digest"] = digest(b"another-root")
    else:
        import json
        record = json.loads(stored)
        record["polished"] = True
        record.pop("assessment_digest")
        record["assessment_digest"] = digest(canonical_bytes(record))
        stored = canonical_bytes(record)
    result = authority.recheck_polish_authority(stored, **call)
    assert result["status"] == "FAIL" and result["replay_status"] == "REJECTED"


def test_newly_observed_authority_refusal_survives_later_oserror(real_selected, monkeypatch):
    call, stored = real_selected
    count = 0
    def refusal_then_absent(envelope, keys):
        nonlocal count
        count += 1
        if count == 1:
            raise ValueError("negative-only observed signature refusal")
        raise OSError("negative-only later unavailable source")
    monkeypatch.setattr(authority, "_authenticate", refusal_then_absent)
    result = authority.recheck_polish_authority(stored, **call)
    assert result["status"] == "FAIL" and result["replay_status"] == "REJECTED"


def test_existing_full_operation_and_a03_refusal_precedence_are_preserved(selected_without_crypto, monkeypatch):
    call, evidence, context = selected_without_crypto
    assert context["operation"] == authority.OPERATION == "ISSUE_POLISHED_ARTIFACT"
    evidence = deepcopy(evidence)
    # Public-data refusal only, never a positive mocked signature.
    row = {**evidence["decisions"][0]["payload"], "actor_id": "foreign:actor"}
    from test_polish_public_authority_precrypto import envelope
    evidence["decisions"][0] = envelope(row, "a")
    unavailable_backend(monkeypatch)
    report = authority.assess_polish_authority(**{**call, "evidence_bytes": canonical_bytes(evidence)})
    assert report["status"] == "FAIL" and "DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH" in report["checks"]


def test_fresh_present_interval_refusal_survives_current_source_absence(selected_without_crypto, monkeypatch):
    call, evidence, _ = selected_without_crypto
    from test_polish_public_authority_precrypto import envelope
    evidence = deepcopy(evidence)
    row = {**evidence["decisions"][0]["payload"], "issued_at": 100, "expires_at": 150}
    evidence["decisions"][0] = envelope(row, "a")
    call = {**call, "evidence_bytes": canonical_bytes(evidence)}
    unavailable_backend(monkeypatch)
    recorded = authority.assess_polish_authority(**call)
    assert recorded["status"] == "FAIL"  # Cheap interval contradiction; no authentication is claimed.
    def absent():
        raise OSError("negative-only source absent")
    monkeypatch.setattr(authority, "mechanism_digest", absent)
    replay = authority.recheck_polish_authority(canonical_bytes(recorded), **call)
    # The current supplied interval is still independently false. This is a new
    # local refusal, rather than carrying recorded FAIL through missing sources.
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REJECTED"


def test_stored_fail_without_original_evidence_does_not_supply_new_refusal(selected_without_crypto, monkeypatch):
    call, evidence, _ = selected_without_crypto
    from test_polish_public_authority_precrypto import envelope
    evidence = deepcopy(evidence)
    row = {**evidence["decisions"][0]["payload"], "issued_at": 100, "expires_at": 150}
    evidence["decisions"][0] = envelope(row, "a")
    call = {**call, "evidence_bytes": canonical_bytes(evidence)}
    unavailable_backend(monkeypatch)
    recorded = authority.assess_polish_authority(**call)
    assert recorded["status"] == "FAIL"
    def absent():
        raise OSError("negative-only source absent")
    monkeypatch.setattr(authority, "mechanism_digest", absent)
    replay = authority.recheck_polish_authority(canonical_bytes(recorded), **{**call, "evidence_bytes": None})
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
