"""Adversarial digest tests for the Verifier Standard (VSTD)-1 receipt model."""

from __future__ import annotations

from dataclasses import replace

import pytest

from verifier.core.checker import IndependentAuditor
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import (
    ClaimSpec,
    EvidencePayload,
    StrictJsonError,
    VstdReceipt,
    canonical_json_dumps,
    strict_json_loads,
)


def _receipt() -> VstdReceipt:
    return VstdReceipt(
        schema_version="VSTD-1",
        receipt_kind="claim_mechanics",
        receipt_id="receipt-integrity-test",
        claim=ClaimSpec(
            id="claim-1",
            title="Bounded claim",
            statement="The recorded formula is satisfiable.",
            status="PASS",
            scope="This fixture only.",
            limitations=("No actor independence is established.",),
            falsification_condition="The formula is unsatisfiable.",
            last_verified="2026-08-26",
        ),
        evidence=EvidencePayload(
            domain="Boolean satisfiability problem",
            input_text_or_formula="x1",
            n_vars=1,
            clauses=((1,),),
            atomic_reasons=(),
            assumptions=(),
            source_artifacts={"fixture": "sha256:" + "0" * 64},
        ),
        target_result={"satisfiable": True},
        independent_audit=IndependentAuditor.audit_claim_derivation(
            claim_id="claim-1",
            n_vars=1,
            clauses=((1,),),
            atomic_reasons=(),
        ),
        provenance=ProvenanceRecord(
            target_name="fixture",
            portable_repository_id="example/fixture",
            local_repository_path="excluded-from-stable-payload",
            git=GitProvenance("a" * 40, "main", False),
            runtime=RuntimeEnvironment("3.12", "CPython", "test", "test", "test", "masked"),
            captured_at_utc="2026-08-26T00:00:00Z",
            command_executed="fixture",
        ),
        reproducibility={"highest_demonstrated_level": "CONTENT_IDENTICAL"},
    )


def test_retired_claim_identifier_is_rejected() -> None:
    retired = "VSTD-" + "0.1"
    with pytest.raises(ValueError, match="schema_version must be VSTD-1"):
        replace(_receipt(), schema_version=retired)


def test_stable_payload_tampering_invalidates_receipt_digest() -> None:
    receipt = _receipt()
    receipt.compute_and_set_digest()
    assert receipt.verify_digest_integrity()

    receipt.target_result["satisfiable"] = False

    assert not receipt.verify_digest_integrity()


def test_recorded_digest_cannot_self_validate_after_claim_replacement() -> None:
    receipt = _receipt()
    original_digest = receipt.compute_and_set_digest()
    receipt.claim = ClaimSpec(
        **{**receipt.claim.__dict__, "statement": "A substituted proposition."}
    )

    assert receipt.canonical_digest == original_digest
    assert not receipt.verify_digest_integrity()


@pytest.mark.parametrize(
    "payload",
    (
        '{"value": NaN}',
        '{"value": Infinity}',
        '{"value": -Infinity}',
        '{"value": 1e999}',
        '{"value": 1, "value": 2}',
        '{"outer": {"value": 1, "value": 2}}',
    ),
)
def test_strict_json_loader_rejects_non_finite_numbers_and_duplicate_keys(
    payload: str,
) -> None:
    with pytest.raises(StrictJsonError):
        strict_json_loads(payload)


@pytest.mark.parametrize("value", (float("nan"), float("inf"), float("-inf")))
def test_canonical_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json_dumps({"value": value})
