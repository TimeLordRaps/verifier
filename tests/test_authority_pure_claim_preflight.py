"""Pure submitted claim refusal precedes unavailable proof; no release approval.

The fixtures intentionally make real ephemeral Ed25519 signatures before imposing
the absent/wrong-version condition. Their optional prerequisite is declared here;
the injected-outage cases do not require the installed backend to be version 50.
Actual authentication controls require the selected backend version exactly.
"""
from __future__ import annotations

import builtins
import dataclasses
import json

import pytest

cryptography = pytest.importorskip(
    "cryptography",
    reason="OPTIONAL_DEPENDENCY_ABSENT: r2 synthetic signed fixtures require the seal extra (cryptography); no signature/authentication result is inferred when absent",
)
from cryptography.exceptions import UnsupportedAlgorithm
import test_core_application_scope_receipts as fixtures
from verifier.runtime import core_application_authority as binding


H = "sha256:" + "a" * 64
APPROVAL_CASES = (
    ("approval-role", "AUTHORITY_APPROVAL_ROLE_DIFFERS"),
    ("approval-actor", "AUTHORITY_APPROVAL_ROLE_DIFFERS"),
    ("self-approval", "AUTHORITY_APPROVAL_ROLE_DIFFERS"),
    ("approval-body", "AUTHORITY_RECEIPT_SIGNATURE_REFUSED"),
    ("approval-window-inverted", "AUTHORITY_APPROVAL_TIME_DIFFERS"),
    ("approval-window-empty", "AUTHORITY_APPROVAL_TIME_DIFFERS"),
)
STATUS_CASES = (
    ("status-binding", "AUTHORITY_STATUS_BINDING_DIFFERS"),
    ("status-window-inverted", "AUTHORITY_STATUS_TIME_DIFFERS"),
    ("status-window-empty", "AUTHORITY_STATUS_TIME_DIFFERS"),
)


def _selection(case=None, approval_index=0):
    try:
        selected = fixtures._selection(binding.SCOPE_OPERATION, H)
    except UnsupportedAlgorithm:
        pytest.skip("OPTIONAL_DEPENDENCY_CAPABILITY_UNAVAILABLE: this platform cannot generate the real Ed25519 fixture; no authentication result is inferred")
    if case is None:
        return selected
    receipt = json.loads(selected.receipt_bytes)
    approval = receipt["approvals"][approval_index]
    if case == "approval-role":
        approval["key_id"] = "status"
    elif case == "approval-actor":
        approval["payload"]["actor_id"] = "different-actor"
    elif case == "self-approval":
        receipt["requester_id"] = approval["payload"]["actor_id"]
        body = {name: value for name, value in receipt.items() if name not in {"approvals", "status"}}
        for item in receipt["approvals"]:
            item["payload"]["receipt_body_digest"] = binding.value_digest(body)
    elif case == "approval-body":
        approval["payload"]["receipt_body_digest"] = H
    elif case == "approval-window-inverted":
        approval["payload"]["issued_at"] = fixtures.NOW + 1
        approval["payload"]["expires_at"] = fixtures.NOW - 1
    elif case == "approval-window-empty":
        approval["payload"]["issued_at"] = fixtures.NOW
        approval["payload"]["expires_at"] = fixtures.NOW
    elif case == "status-binding":
        receipt["status"]["payload"]["receipt_id"] = "different-receipt"
    elif case == "status-window-inverted":
        receipt["status"]["payload"]["observed_at"] = fixtures.NOW + 1
        receipt["status"]["payload"]["expires_at"] = fixtures.NOW - 1
    elif case == "status-window-empty":
        receipt["status"]["payload"]["observed_at"] = fixtures.NOW
        receipt["status"]["payload"]["expires_at"] = fixtures.NOW
    else:
        raise AssertionError(case)
    # Hash-consistent carried bytes expose the pure contradiction. We deliberately
    # do not re-sign the changed claim, so authentication still matters independently.
    for envelope in [*receipt["approvals"], receipt["status"]]:
        envelope["payload_digest"] = binding.value_digest(envelope["payload"])
    raw = binding.canonical_bytes(receipt)
    return dataclasses.replace(selected, receipt_bytes=raw, expected_receipt_digest=binding.bytes_digest(raw))


def _disable_crypto(mode, monkeypatch):
    if mode == "absent":
        original = builtins.__import__

        def unavailable(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError("test-only absent backend")
            return original(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", unavailable)
    elif mode == "wrong-version":
        monkeypatch.setattr(cryptography, "__version__", "unsupported-test-version")
    else:
        raise AssertionError(mode)


def _assert_refuted(selected, blocker, backend, monkeypatch, label):
    _disable_crypto(backend, monkeypatch)
    report = binding.replay_qualified_authority_receipt(
        selected, required_operation=binding.SCOPE_OPERATION, required_subject_digest=H)
    print("PURE-CLAIM-OBSERVATION", label, backend, report["status"], report["blockers"])
    assert report["status"] == "FAIL"
    assert report["replay_status"] == "REJECTED"
    assert blocker in report["blockers"]
    assert not any("BACKEND" in code for code in report["blockers"])


@pytest.mark.parametrize("backend", ("absent", "wrong-version"))
@pytest.mark.parametrize("approval_index", (0, 1), ids=("first-approval", "second-approval"))
@pytest.mark.parametrize("case,blocker", APPROVAL_CASES, ids=[row[0] for row in APPROVAL_CASES])
def test_approval_contradiction_refuted_before_unavailable_crypto(case, blocker, approval_index, backend, monkeypatch):
    _assert_refuted(_selection(case, approval_index), blocker, backend, monkeypatch, f"{case}:approval-{approval_index + 1}")


@pytest.mark.parametrize("backend", ("absent", "wrong-version"))
@pytest.mark.parametrize("case,blocker", STATUS_CASES, ids=[row[0] for row in STATUS_CASES])
def test_status_contradiction_refuted_before_unavailable_crypto(case, blocker, backend, monkeypatch):
    _assert_refuted(_selection(case), blocker, backend, monkeypatch, case)


@pytest.mark.parametrize("backend", ("absent", "wrong-version"))
def test_clean_claim_with_unavailable_crypto_remains_unknown(backend, monkeypatch):
    selected = _selection()
    _disable_crypto(backend, monkeypatch)
    report = binding.replay_qualified_authority_receipt(
        selected, required_operation=binding.SCOPE_OPERATION, required_subject_digest=H)
    assert report["status"] == "UNKNOWN"
    assert report["replay_status"] == "NOT_ESTABLISHED"
    assert any("BACKEND" in code for code in report["blockers"])


def _require_selected_backend():
    if cryptography.__version__ != "50.0.0":
        pytest.skip(f"OPTIONAL_DEPENDENCY_VERSION_UNAVAILABLE: actual authentication selects cryptography==50.0.0, installed={cryptography.__version__}; backend-outage tests remain runnable")


def test_purely_consistent_claim_still_requires_actual_signature():
    _require_selected_backend()
    selected = _selection()
    receipt = json.loads(selected.receipt_bytes)
    receipt["approvals"][0]["signature"] = "00" * 64
    raw = binding.canonical_bytes(receipt)
    selected = dataclasses.replace(selected, receipt_bytes=raw, expected_receipt_digest=binding.bytes_digest(raw))
    report = binding.replay_qualified_authority_receipt(
        selected, required_operation=binding.SCOPE_OPERATION, required_subject_digest=H)
    assert report["status"] == "FAIL"
    assert "AUTHORITY_RECEIPT_SIGNATURE_REFUSED" in report["blockers"]


def test_consistent_claim_requires_and_obtains_actual_authentication():
    _require_selected_backend()
    report = binding.replay_qualified_authority_receipt(
        _selection(), required_operation=binding.SCOPE_OPERATION, required_subject_digest=H)
    assert report["status"] == "PASS"
    assert report["replay_status"] == "REPRODUCED"
