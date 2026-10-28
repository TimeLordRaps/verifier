"""Terminology: JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

Unit tests for zero-identity cryptographic token models, serialization, and evaluation."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from verifier.identity.tokens import (
    AgingToken,
    BirthToken,
    LifetimeToken,
    advance_aging_accumulator,
    canonical_token_bytes,
    compute_birth_commitment,
)
from verifier.identity.evaluator import evaluate_identity

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_birth_token_commitment_and_canonical_bytes() -> None:
    genesis_key = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    commitment = compute_birth_commitment(genesis_key, birth_epoch=100, salt="test-salt-01")
    assert commitment.startswith("sha256:")
    assert len(commitment) == 71

    token = BirthToken(
        schema_version="verifier-birth-token-1",
        token_id="birth:001",
        genesis_key_digest=genesis_key,
        birth_epoch=100,
        commitment=commitment,
        issued_at="2026-01-01T00:00:00Z",
        signature_base64url="sig_base64_abc",
        declared_parameters={"param": "value"},
    )
    raw_bytes = token.canonical_bytes()
    data = json.loads(raw_bytes.decode("utf-8"))
    assert data["schema_version"] == "verifier-birth-token-1"
    assert "signature_base64url" not in data  # signature stripped for canonical representation
    assert data["commitment"] == commitment


def test_aging_token_progression() -> None:
    genesis_key = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    acc0 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    acc1 = advance_aging_accumulator(acc0, epoch=1, status="ACTIVE")
    acc2 = advance_aging_accumulator(acc1, epoch=2, status="ACTIVE")
    assert acc1 != acc0
    assert acc2 != acc1

    token = AgingToken(
        schema_version="verifier-aging-token-1",
        token_id="aging:001",
        birth_token_id="birth:001",
        genesis_key_digest=genesis_key,
        accumulated_epochs=2,
        epoch_start=1,
        epoch_end=2,
        accumulator_digest=acc2,
        revocation_status="ACTIVE",
        attested_by="notary:epoch_witness",
        issued_at="2026-01-02T00:00:00Z",
        signature_base64url="sig_aging_123",
    )
    raw_bytes = token.canonical_bytes()
    data = json.loads(raw_bytes.decode("utf-8"))
    assert data["accumulated_epochs"] == 2
    assert data["accumulator_digest"] == acc2


def test_lifetime_token_lease_and_bounds() -> None:
    token = LifetimeToken(
        schema_version="verifier-lifetime-token-1",
        token_id="lease:001",
        actor_id="actor:sha256:3333333333333333333333333333333333333333333333333333333333333333",
        delegate_key_id="runner:worker_01",
        permitted_scopes=("sat:verify", "receipt:check"),
        not_before="2026-01-01T00:00:00Z",
        not_after="2026-01-02T00:00:00Z",
        soulbound=True,
        issuing_key_id="key:genesis_01",
        issued_at="2026-01-01T00:00:00Z",
        signature_base64url="sig_lease_xyz",
        max_invocations=5,
    )
    raw_bytes = token.canonical_bytes()
    data = json.loads(raw_bytes.decode("utf-8"))
    assert data["soulbound"] is True
    assert data["permitted_scopes"] == ["sat:verify", "receipt:check"]


def test_offline_evaluator_accepted_bounded() -> None:
    record = {
        "actor": {
            "key_binding": {
                "key_id": "key:01",
                "signature_verified": True,
                "trust_root": "root:01",
            }
        },
        "authorization": {
            "permitted_scopes": ["sat:verify", "lean4:verify"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
        },
        "revocation": {"state": "ACTIVE"},
        "requested_scope": "sat:verify",
        "aging": {"accumulated_epochs": 15, "revocation_status": "ACTIVE"},
        "required_tenure_epochs": 10,
    }
    eval_res = evaluate_identity(record, evaluation_time_iso="2026-06-01T00:00:00Z")
    assert eval_res.verdict == "ACCEPTED_BOUNDED"
    assert eval_res.properties["civil_identity"] == "UNSUPPORTED_BY_DESIGN"
    assert eval_res.properties["authentication"] == "SUPPORTED"
    assert eval_res.properties["authority_active"] == "SUPPORTED"
    assert eval_res.properties["authorization"] == "SUPPORTED"
    assert eval_res.properties["tenure_aging"] == "SUPPORTED"


def test_offline_evaluator_fails_closed_on_missing_signature() -> None:
    record = {
        "actor": {
            "key_binding": {
                "key_id": "key:01",
                # signature_verified coordinate intentionally omitted
            }
        },
        "authorization": {
            "permitted_scopes": ["sat:verify"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
        },
        "requested_scope": "sat:verify",
    }
    eval_res = evaluate_identity(record)
    assert eval_res.verdict == "UNKNOWN"
    assert eval_res.properties["authentication"] == "UNKNOWN"
