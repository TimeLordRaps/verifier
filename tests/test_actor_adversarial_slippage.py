"""Terminology: JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

Adversarial audit tests guarding all 16 prohibited inferences and anti-slippage invariants."""

from __future__ import annotations

import pytest

from verifier.identity.invariants import (
    PROHIBITED_INFERENCES,
    PRIME_INVARIANT,
)
from verifier.identity.evaluator import evaluate_identity
from verifier.identity.audit import audit_actor_slippage


def test_adversarial_audit_harness_passes_with_zero_loopholes() -> None:
    report = audit_actor_slippage()
    assert report.passed is True
    assert report.loopholes_found == 0
    assert report.total_attacks_tested >= 6
    assert report.attacks_blocked == report.total_attacks_tested


def test_prohibited_inference_16_actor_standing_does_not_upgrade_computational_verdict() -> None:
    # An adversary attempts to pass a high-standing actor identity to convert an UNKNOWN verdict to VERIFIED
    record = {
        "actor": {
            "key_binding": {
                "key_id": "key:high_standing",
                "signature_verified": True,
                "trust_root": "root:official",
            }
        },
        "authorization": {
            "permitted_scopes": ["vstd:verify_claim"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
        },
        "revocation": {"state": "ACTIVE"},
        "requested_scope": "vstd:verify_claim",
        "aging": {"accumulated_epochs": 1000, "revocation_status": "ACTIVE"},
        "upgrade_verdict_via_identity": True,  # Attempted bypass
    }
    eval_res = evaluate_identity(record, evaluation_time_iso="2026-06-01T00:00:00Z")
    assert eval_res.verdict == "REJECTED"
    assert "prime_invariant" in str(eval_res.reasons)


def test_prohibited_inference_5_signature_does_not_imply_authorization() -> None:
    # Valid signature by key_id, but the key has NO authorization grant for the requested scope
    record = {
        "actor": {
            "key_binding": {
                "key_id": "key:signer_only",
                "signature_verified": True,
                "trust_root": "root:01",
            }
        },
        "authorization": {
            "permitted_scopes": ["read:public_catalog"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
        },
        "revocation": {"state": "ACTIVE"},
        "requested_scope": "write:submit_receipt",  # Scope not permitted
    }
    eval_res = evaluate_identity(record, evaluation_time_iso="2026-06-01T00:00:00Z")
    assert eval_res.properties["authentication"] == "SUPPORTED"
    assert eval_res.properties["authorization"] == "REFUTED"
    assert eval_res.verdict == "REJECTED"


def test_prohibited_inference_7_absent_revocation_does_not_imply_active_authority() -> None:
    # Grant with missing revocation evidence: must stay UNKNOWN, never proceed on assumption
    record = {
        "actor": {
            "key_binding": {
                "key_id": "key:01",
                "signature_verified": True,
                "trust_root": "root:01",
            }
        },
        "authorization": {
            "permitted_scopes": ["sat:verify"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
        },
        # revocation coordinate is missing
        "requested_scope": "sat:verify",
    }
    eval_res = evaluate_identity(record, evaluation_time_iso="2026-06-01T00:00:00Z")
    assert eval_res.properties["authority_active"] == "UNKNOWN"
    assert eval_res.verdict == "UNKNOWN"


def test_prohibited_inference_4_distinct_pseudonyms_do_not_imply_independent_actors() -> None:
    # Two verifiers claiming independent corroboration, but sharing the same underlying key
    record = {
        "actor": {
            "key_binding": {
                "key_id": "key:actor_shared",
                "signature_verified": True,
                "trust_root": "root:01",
            }
        },
        "authorization": {
            "permitted_scopes": ["sat:verify"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
        },
        "revocation": {"state": "ACTIVE"},
        "requested_scope": "sat:verify",
        "co_verifiers": [
            {"key_id": "key:actor_shared"}  # Sybil collusion using distinct pseudonyms over same key
        ],
    }
    eval_res = evaluate_identity(record, evaluation_time_iso="2026-06-01T00:00:00Z")
    assert eval_res.properties["verifier_independence"] == "REFUTED"
    assert eval_res.verdict == "REJECTED"


def test_all_16_prohibited_inferences_are_formally_cataloged() -> None:
    assert len(PROHIBITED_INFERENCES) == 16
    assert "Actor standing, tenure, or token validity implies verification correctness." in PROHIBITED_INFERENCES
    assert "An actor identity NEVER upgrades a computational verdict." in PRIME_INVARIANT
