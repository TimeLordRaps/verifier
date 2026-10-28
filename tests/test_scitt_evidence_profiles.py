"""Terminology: Supply Chain Integrity, Transparency, and Trust (SCITT).

Adversarial tests for the pinned experimental SCITT evidence-draft adapters."""

from __future__ import annotations

from copy import deepcopy

import pytest

from verifier.interoperability.scitt import InteropError
from verifier.interoperability.scitt.evidence_profiles import (
    COMPUTATIONAL_NOT_EVALUATED,
    EvidenceCondition,
    UnknownReason,
    consume_composite_result,
    consume_coverage_reconciliation,
    consume_transformation_evidence,
    local_vstd_condition,
)


def _coverage() -> dict[str, object]:
    return {
        "v": "coverage-reconciliation/2",
        "window": {
            "start": "2026-08-23T00:00:00Z",
            "end": "2026-08-23T01:00:00Z",
        },
        "source": "urn:example:data-source",
        "snapshots": {"start": "sha256:" + "11" * 32, "end": "sha256:" + "22" * 32},
        "receipts": "sha256:" + "33" * 32,
        "profile": {"id": "example-map/1", "digest": "sha256:" + "44" * 32},
        "bounds": {"multiplicity": "measured", "clock-skew": "operator-declared"},
        "outcome": "no-exceptions",
        "items": [],
        "counts": {
            "matched": 3,
            "observed-without-receipt": 0,
            "receipted-without-observation": 0,
            "excluded": 0,
            "indeterminate": 0,
        },
    }


def _transformation() -> dict[str, object]:
    return {
        "v": "transformation-evidence/1",
        "disclosure": "sha256:" + "55" * 32,
        "request": "sha256:" + "66" * 32,
        "policy": {"id": "masking-policy/7", "decision": "allow"},
        "classes": [{"class": "customer-id", "action": "mask", "count": 1}],
    }


@pytest.mark.parametrize(
    ("source", "condition"),
    [
        ("pass", EvidenceCondition.PROFILE_SATISFIED),
        ("fail", EvidenceCondition.PROFILE_FAILED),
        ("warning", EvidenceCondition.WARNING),
        ("missing", EvidenceCondition.INCOMPLETE),
        ("stale", EvidenceCondition.STALE),
        ("conflict", EvidenceCondition.CONFLICTED),
        ("not-applicable", EvidenceCondition.NOT_APPLICABLE),
    ],
)
def test_composite_codes_remain_profile_results(
    source: str, condition: EvidenceCondition
) -> None:
    result = consume_composite_result(source)
    assert result.evidence_condition is condition
    assert result.computational_verdict == COMPUTATIONAL_NOT_EVALUATED


def test_composite_pass_never_becomes_vstd_pass() -> None:
    result = consume_composite_result("pass")
    assert result.source_result == "pass"
    assert result.computational_verdict == "NOT_EVALUATED"
    assert "false payload claim" in result.limitations[0]


@pytest.mark.parametrize(
    ("reason", "condition"),
    [
        (UnknownReason.UNAVAILABLE_EVIDENCE, EvidenceCondition.UNAVAILABLE),
        (UnknownReason.UNSUPPORTED_VERIFIER, EvidenceCondition.UNSUPPORTED_VERIFIER),
        (UnknownReason.UNDECIDED, EvidenceCondition.BOUNDED_NOT_ESTABLISHED),
    ],
)
def test_composite_unknown_causes_are_not_collapsed(
    reason: UnknownReason, condition: EvidenceCondition
) -> None:
    assert consume_composite_result(
        "unknown", unknown_reason=reason
    ).evidence_condition is condition


def test_composite_unknown_without_cause_and_extension_code_are_rejected() -> None:
    with pytest.raises(InteropError, match="explicit reason"):
        consume_composite_result("unknown")
    with pytest.raises(InteropError, match="unsupported composite"):
        consume_composite_result("implementation-private-result")


def test_vstd_local_conditions_remain_distinct() -> None:
    assert local_vstd_condition("revoked") is EvidenceCondition.REVOKED
    assert local_vstd_condition("superseded") is EvidenceCondition.SUPERSEDED
    assert local_vstd_condition("budget-exhausted") is EvidenceCondition.BUDGET_EXHAUSTED
    assert local_vstd_condition("not-established") is EvidenceCondition.BOUNDED_NOT_ESTABLISHED
    assert local_vstd_condition("falsified") is EvidenceCondition.EXPLICITLY_FALSIFIED


def test_transformation_evidence_is_only_an_issuer_assertion() -> None:
    result = consume_transformation_evidence(_transformation())
    assert result.evidence_condition is EvidenceCondition.ISSUER_ASSERTED
    assert result.computational_verdict == "NOT_EVALUATED"
    assert "do not prove transformation execution" in result.limitations[0]


def test_structurally_valid_transformation_can_accompany_disclosure_that_leaks() -> None:
    evidence = _transformation()
    disclosed_result = b'{"customer-id":"sensitive-unmasked-value"}'
    result = consume_transformation_evidence(evidence)
    assert b"sensitive-unmasked-value" in disclosed_result
    assert result.evidence_condition is EvidenceCondition.ISSUER_ASSERTED
    assert result.computational_verdict == "NOT_EVALUATED"


def test_transformation_hidden_value_and_unknown_digest_prefix_are_rejected() -> None:
    with_value = _transformation()
    classes = with_value["classes"]
    assert isinstance(classes, list)
    classes[0]["value"] = "sensitive"  # type: ignore[index]
    with pytest.raises(InteropError, match="extra=.*value"):
        consume_transformation_evidence(with_value)
    wrong_digest = _transformation()
    wrong_digest["request"] = "sha512:" + "00" * 64
    with pytest.raises(InteropError, match="sha256"):
        consume_transformation_evidence(wrong_digest)


def test_coverage_no_exceptions_is_not_computational_truth() -> None:
    result = consume_coverage_reconciliation(_coverage())
    assert result.evidence_condition is EvidenceCondition.RECONCILIATION_NO_EXCEPTIONS
    assert result.computational_verdict == "NOT_EVALUATED"
    assert "neither population is assumed complete" in result.limitations[0]
    assert "operator-declared" in result.limitations[-1]


def test_coverage_indeterminate_is_an_exception_not_a_degraded_pass() -> None:
    value = _coverage()
    value["outcome"] = "exceptions"
    value["items"] = [{"outcome": "indeterminate", "reason": "clock bound absent"}]
    counts = value["counts"]
    assert isinstance(counts, dict)
    counts["indeterminate"] = 1
    result = consume_coverage_reconciliation(value)
    assert result.evidence_condition is EvidenceCondition.RECONCILIATION_EXCEPTIONS
    assert result.computational_verdict == "NOT_EVALUATED"


def test_pinned_exclusion_is_visible_but_not_justified() -> None:
    value = _coverage()
    value["items"] = [{"outcome": "excluded", "rule": "housekeeping/1"}]
    counts = value["counts"]
    assert isinstance(counts, dict)
    counts["excluded"] = 1
    result = consume_coverage_reconciliation(value)
    assert "not proven appropriate" in result.limitations[-2]


def test_coverage_v1_cannot_be_upgraded_to_v2() -> None:
    value = _coverage()
    value["v"] = "coverage-reconciliation/1"
    value["outcome"] = "covered"
    with pytest.raises(InteropError, match="/1 cannot be read as /2"):
        consume_coverage_reconciliation(value)


def test_coverage_outcome_count_inconsistencies_are_rejected() -> None:
    no_exceptions = _coverage()
    counts = no_exceptions["counts"]
    assert isinstance(counts, dict)
    counts["observed-without-receipt"] = 1
    no_exceptions["items"] = [{"outcome": "observed-without-receipt"}]
    with pytest.raises(InteropError, match="no-exceptions"):
        consume_coverage_reconciliation(no_exceptions)

    exceptions = _coverage()
    exceptions["outcome"] = "exceptions"
    with pytest.raises(InteropError, match="requires at least one open"):
        consume_coverage_reconciliation(exceptions)


def test_coverage_item_accounting_and_exclusion_rule_are_checked() -> None:
    missing_item = _coverage()
    counts = missing_item["counts"]
    assert isinstance(counts, dict)
    counts["indeterminate"] = 1
    with pytest.raises(InteropError, match="does not match items"):
        consume_coverage_reconciliation(missing_item)

    no_rule = _coverage()
    no_rule["items"] = [{"outcome": "excluded"}]
    counts = no_rule["counts"]
    assert isinstance(counts, dict)
    counts["excluded"] = 1
    with pytest.raises(InteropError, match="rule"):
        consume_coverage_reconciliation(no_rule)


def test_invalid_window_is_preserved_as_its_own_state() -> None:
    value = deepcopy(_coverage())
    value["outcome"] = "invalid-window"
    result = consume_coverage_reconciliation(value)
    assert result.evidence_condition is EvidenceCondition.INVALID_WINDOW
    assert result.computational_verdict == "NOT_EVALUATED"


def test_malformed_coverage_profile_and_bound_are_rejected() -> None:
    value = _coverage()
    value["profile"] = {"id": "example-map/1"}
    with pytest.raises(InteropError, match="profile keys mismatch"):
        consume_coverage_reconciliation(value)
    value = _coverage()
    value["bounds"] = {"clock-skew": "assumed-good"}
    with pytest.raises(InteropError, match="unsupported standing"):
        consume_coverage_reconciliation(value)
