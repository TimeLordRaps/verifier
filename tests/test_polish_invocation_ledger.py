"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Exact local atomic consumption counterexamples.

Structured Query Language (SQL); JavaScript Object Notation (JSON). Local state
fixtures establish no complete polish, public execution or real operator authority.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_invocation_ledger as ledger


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def selected(tmp_path):
    choice = ledger.IssuerLedgerSelection(str(tmp_path / "operator.db"), "ledger:test", "issuer:test", 1)
    ledger.provision_issuance_ledger(choice)
    raw = canonical_bytes({"schema_version": "test:precommit-proposal", "exact_context": "a"})
    return choice, raw


def commit(choice, raw, **changes):
    return ledger.commit_issuance(raw, **{ "expected_proposal_digest": digest(raw),
        "invocation_id": "test:one", "authority_status_digest": "sha256:" + "a" * 64,
        "commit_time": 200, "selection": choice, **changes})


def test_same_commit_replays_without_consuming_again(selected):
    choice, raw = selected
    receipt = commit(choice, raw)
    assert receipt["status"] == "PASS" and receipt["polished"] is False
    replay = ledger.recheck_issuance_commit(canonical_bytes(receipt), proposal_bytes=raw,
        expected_proposal_digest=digest(raw), selection=choice)
    assert replay["status"] == "PASS" and replay["replay_status"] == "REPRODUCED"
    assert commit(choice, raw)["status"] == "FAIL"


def test_concurrent_attempts_commit_at_most_one_exact_invocation(selected):
    choice, raw = selected
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(lambda _: commit(choice, raw), range(4)))
    assert sum(r["status"] == "PASS" for r in results) == 1
    assert all(r["status"] == "FAIL" and r["reason"] == "KNOWN_INVOCATION_REPLAY"
               for r in results if r["status"] != "PASS")


def test_recovery_is_readonly_and_cannot_substitute_another_proposal(selected):
    choice, raw = selected
    receipt = commit(choice, raw)
    recovered = ledger.recover_issuance_commit(raw, expected_proposal_digest=digest(raw),
        invocation_id="test:one", selection=choice)
    assert recovered["status"] == "PASS" and recovered["commit"] == receipt
    other = canonical_bytes({"schema_version": "test:precommit-proposal", "exact_context": "b"})
    refused = ledger.recover_issuance_commit(other, expected_proposal_digest=digest(other),
        invocation_id="test:one", selection=choice)
    assert refused["status"] == "FAIL"
    assert commit(choice, raw)["reason"] == "KNOWN_INVOCATION_REPLAY"


def test_epoch_fence_rejects_stale_authority_and_does_not_reenable_ids(selected):
    choice, raw = selected
    assert commit(choice, raw)["status"] == "PASS"
    ledger.advance_policy_epoch(choice, new_epoch=2)
    assert commit(choice, raw, invocation_id="test:two")["status"] == "FAIL"
    current = replace(choice, policy_epoch=2)
    assert commit(current, raw)["reason"] == "KNOWN_INVOCATION_REPLAY"
    assert commit(current, raw, invocation_id="test:two")["status"] == "PASS"


def test_wrong_ledger_or_policy_domain_cannot_replay(selected):
    choice, raw = selected
    receipt = commit(choice, raw)
    for changed in (replace(choice, ledger_id="other"), replace(choice, policy_domain="other")):
        report = ledger.recheck_issuance_commit(canonical_bytes(receipt), proposal_bytes=raw,
            expected_proposal_digest=digest(raw), selection=changed)
        assert report["status"] == "FAIL"


def test_absent_database_and_absent_commit_do_not_create_or_issue(selected, tmp_path):
    choice, raw = selected
    missing = replace(choice, path=str(tmp_path / "absent.db"))
    assert commit(missing, raw)["status"] == "UNKNOWN"
    assert not (tmp_path / "absent.db").exists()
    report = ledger.recover_issuance_commit(raw, expected_proposal_digest=digest(raw),
        invocation_id="not:committed", selection=choice)
    assert report["status"] == "UNKNOWN" and report["polished"] is False


def test_rehashed_forged_consumption_and_changed_proposal_fail(selected):
    choice, raw = selected
    receipt = commit(choice, raw)
    forged = {**receipt, "commit_sequence": receipt["commit_sequence"] + 1}
    forged.pop("receipt_digest")
    forged["receipt_digest"] = digest(canonical_bytes(forged))
    assert ledger.recheck_issuance_commit(canonical_bytes(forged), proposal_bytes=raw,
        expected_proposal_digest=digest(raw), selection=choice)["status"] == "FAIL"
    changed = canonical_bytes({"schema_version": "other:proposal"})
    assert ledger.recheck_issuance_commit(canonical_bytes(receipt), proposal_bytes=changed,
        expected_proposal_digest=digest(changed), selection=choice)["status"] == "FAIL"


def test_foreign_and_overbound_proposals_refuse_before_hash(selected, monkeypatch):
    choice, raw = selected
    pinned = digest(raw)
    calls = []
    original = ledger.hashlib.sha256
    def tracked(value=b"", *args, **kwargs):
        calls.append(1)
        return original(value, *args, **kwargs)
    monkeypatch.setattr(ledger.hashlib, "sha256", tracked)
    class Foreign(bytes):
        def __len__(self):
            pytest.fail("foreign proposal callback")
    for invalid in (Foreign(raw), b" " * (ledger.MAX_PROPOSAL_BYTES + 1)):
        calls.clear()
        result = ledger.commit_issuance(invalid, expected_proposal_digest=pinned,
            invocation_id="test:one", authority_status_digest="sha256:" + "a" * 64,
            commit_time=200, selection=choice)
        assert result["status"] == "FAIL" and calls == []


def test_capacity_is_unknown_and_no_invocation_is_consumed(selected, monkeypatch):
    choice, raw = selected
    original = ledger.codec._parse
    def exhausted(*args, **kwargs):
        raise ledger.codec._Exhausted("finite candidate capacity")
    monkeypatch.setattr(ledger.codec, "_parse", exhausted)
    assert commit(choice, raw)["status"] == "UNKNOWN"
    monkeypatch.setattr(ledger.codec, "_parse", original)
    assert commit(choice, raw)["status"] == "PASS"


def test_persistent_capacity_stays_unknown_and_known_replay_remains_fail(selected, monkeypatch):
    choice, raw = selected
    monkeypatch.setattr(ledger, "MAX_INVOCATIONS", 1)
    assert commit(choice, raw)["status"] == "PASS"
    assert commit(choice, raw)["reason"] == "KNOWN_INVOCATION_REPLAY"
    blocked = commit(choice, raw, invocation_id="test:two")
    assert blocked["status"] == "UNKNOWN" and blocked["reason"] == "LEDGER_RESOURCE_BOUND_EXHAUSTED"


def test_known_receipt_proposal_contradiction_precedes_database_availability(tmp_path, monkeypatch):
    selected = ledger.IssuerLedgerSelection(str(tmp_path / "not-created.sqlite"), "ledger:test", "domain:test", 1)
    proposal = canonical_bytes({"schema_version": "test:proposal", "member": "B"})
    carried = {"schema_version": ledger.RECEIPT, "status": "PASS", "polished": False,
        "invocation_consumption": "CONSUMED_EXACT_LOCAL_LEDGER", "ledger_id": selected.ledger_id,
        "policy_domain": selected.policy_domain, "policy_epoch": selected.policy_epoch,
        "invocation_id": "invocation:test", "commit_sequence": 1,
        "proposal_digest": "sha256:" + "0" * 64, "authority_status_digest": "sha256:" + "1" * 64,
        "commit_time": 200, "mechanism_digest": "sha256:" + "2" * 64,
        "public_consumption_authentication": "NOT_ESTABLISHED", "claim_boundary": "adversarial untrusted receipt"}
    carried["receipt_digest"] = ledger._digest(canonical_bytes(carried))
    def must_not_open(*args, **kwargs):
        pytest.fail("known local receipt contradiction reached storage")
    monkeypatch.setattr(ledger, "_connect", must_not_open)
    result = ledger.recheck_issuance_commit(canonical_bytes(carried), proposal_bytes=proposal,
        expected_proposal_digest=ledger._digest(proposal), selection=selected)
    assert result["status"] == "FAIL" and result["replay_status"] == "REJECTED"
    assert not (tmp_path / "not-created.sqlite").exists()


@pytest.mark.parametrize("interruption", [asyncio.CancelledError, KeyboardInterrupt])
def test_commit_interruption_is_bounded_unknown_without_consumption(selected, monkeypatch, interruption):
    choice, raw = selected

    def cancelled(*args, **kwargs):
        raise interruption()

    monkeypatch.setattr(ledger, "_connect", cancelled)
    result = commit(choice, raw)
    assert result == {"schema_version": ledger.RECEIPT, "status": "UNKNOWN", "polished": False,
        "invocation_consumption": "NOT_ESTABLISHED", "reason": "LEDGER_COMMIT_CANCELLED_OR_UNCERTAIN"}


@pytest.mark.parametrize(("operation", "reason", "replay_status"), [
    ("recheck", "LEDGER_REPLAY_CANCELLED", "REJECTED"),
    ("recover", "LEDGER_RECOVERY_CANCELLED", "UNAVAILABLE"),
])
@pytest.mark.parametrize("interruption", [asyncio.CancelledError, KeyboardInterrupt])
def test_read_interruption_is_bounded_unknown_not_carried_pass(
        selected, monkeypatch, operation, reason, replay_status, interruption):
    choice, raw = selected
    receipt = commit(choice, raw)

    def cancelled(*args, **kwargs):
        raise interruption()

    monkeypatch.setattr(ledger, "_connect", cancelled)
    if operation == "recheck":
        result = ledger.recheck_issuance_commit(canonical_bytes(receipt), proposal_bytes=raw,
            expected_proposal_digest=digest(raw), selection=choice)
    else:
        result = ledger.recover_issuance_commit(raw, expected_proposal_digest=digest(raw),
            invocation_id="test:one", selection=choice)
    assert result == {"schema_version": ledger.REPLAY, "status": "UNKNOWN",
        "replay_status": replay_status, "polished": False, "reason": reason}
