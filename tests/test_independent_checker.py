"""Unit tests for the independent VERIFIABLE SAT solver and Grounding checker."""

from __future__ import annotations

from verifiable.core.checker import (
    GroundingVerdict,
    IndependentGroundingChecker,
    IndependentVerifiableAuditor,
    MinimalIndependentDPLL,
    VerificationVerdict,
)


def test_independent_dpll_satisfiable() -> None:
    # (A or B) and (not A or B) => SAT with B=True
    # 1=A, 2=B
    clauses = [[1, 2], [-1, 2]]
    solver = MinimalIndependentDPLL(n_vars=2, clauses=clauses)
    sat, model = solver.solve()
    assert sat is True
    assert model is not None
    assert model[2] is True


def test_independent_dpll_unsat() -> None:
    # A and not A => UNSAT
    clauses = [[1], [-1]]
    solver = MinimalIndependentDPLL(n_vars=1, clauses=clauses)
    sat, model = solver.solve()
    assert sat is False
    assert model is None


def test_grounding_checker_grounded() -> None:
    reasons = [
        {
            "reason_id": "r1",
            "proposition": "a",
            "polarity": True,
            "evidence_kind": "OBSERVED",
            "parent_reason_ids": [],
            "assumptions": [],
        },
        {
            "reason_id": "r2",
            "proposition": "b",
            "polarity": True,
            "evidence_kind": "INFERRED",
            "parent_reason_ids": ["r1"],
            "assumptions": [],
        },
    ]
    res = IndependentGroundingChecker.audit_derivation(reasons)
    assert res.grounding_status == GroundingVerdict.GROUNDED
    assert res.observed_leaves == ["r1"]
    assert res.cycle_detected is False
    assert res.is_valid is True


def test_grounding_checker_ungrounded_placeholder() -> None:
    reasons = [
        {
            "reason_id": "r1",
            "proposition": "a",
            "polarity": True,
            "evidence_kind": "PLACEHOLDER",
            "parent_reason_ids": [],
            "assumptions": [],
        }
    ]
    res = IndependentGroundingChecker.audit_derivation(reasons)
    assert res.grounding_status == GroundingVerdict.UNGROUNDED
    assert res.is_valid is False


def test_grounding_checker_detects_cycle() -> None:
    reasons = [
        {
            "reason_id": "r1",
            "proposition": "a",
            "polarity": True,
            "evidence_kind": "INFERRED",
            "parent_reason_ids": ["r2"],
            "assumptions": [],
        },
        {
            "reason_id": "r2",
            "proposition": "b",
            "polarity": True,
            "evidence_kind": "INFERRED",
            "parent_reason_ids": ["r1"],
            "assumptions": [],
        },
    ]
    res = IndependentGroundingChecker.audit_derivation(reasons)
    assert res.cycle_detected is True
    assert res.is_valid is False


def test_independent_auditor_end_to_end() -> None:
    reasons = [
        {
            "reason_id": "r1",
            "proposition": "a",
            "polarity": True,
            "evidence_kind": "OBSERVED",
            "parent_reason_ids": [],
            "assumptions": [],
        }
    ]
    clauses = [[-1, 2], [1]]  # A -> B, A => SAT
    audit = IndependentVerifiableAuditor.audit_claim_derivation(
        claim_id="TEST-001",
        n_vars=2,
        clauses=clauses,
        atomic_reasons=reasons,
        expected_satisfiable=True,
    )
    assert audit.overall_verdict == VerificationVerdict.VERIFIED
    assert audit.sat_result.satisfiable is True
    assert audit.grounding_result.grounding_status == GroundingVerdict.GROUNDED
    assert "MinimalIndependentDPLL" in audit.trusted_computing_base["solver"]
