"""Terminology: Boolean satisfiability problem (SAT); identifier (ID); JavaScript Object Notation (JSON); nondeterministic polynomial time (NP); satisfiability modulo theories (SMT); Secure Hash Algorithm 256-bit (SHA-256); benchmark specification graph (BENCH); Verifier Standard (VSTD).

Comprehensive adversarial test suite for BENCH refutable benchmark specifications and non-gaming invariants.
"""

from __future__ import annotations

import hashlib
import json
import pytest

from verifier.corrigibility.benchmark import (
    BenchmarkGamingError,
    BenchmarkProblem,
    BenchmarkSuite,
    CapabilityDimension,
    ComplexityClass,
    EpistemicStratum,
    FormalLanguage,
    OracleMechanism,
    ProblemBasis,
    ProblemEvaluationOutcome,
    ProblemReceipt,
)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _sample_basis(
    comp: ComplexityClass = ComplexityClass.NP,
    dim: CapabilityDimension = CapabilityDimension.FORMAL_REASONING,
) -> ProblemBasis:
    return ProblemBasis(
        complexity_class=comp,
        formal_language=FormalLanguage.LEAN_4,
        oracle_mechanism=OracleMechanism.FORMAL_PROOF_CHECKER,
        resource_grain={"max_steps": 10000, "timeout_ms": 5000},
        epistemic_stratum=EpistemicStratum.FRONTIER,
        capability_dimension=dim,
    )


def test_problem_basis_and_problem_creation() -> None:
    basis = _sample_basis()
    p = BenchmarkProblem(
        problem_id="prob:fermat-lemma-01",
        basis=basis,
        specification_digest=_digest("spec-fermat"),
        expected_property="prime_divisibility",
        timeout_ms=5000,
    )
    assert p.problem_id == "prob:fermat-lemma-01"
    assert p.basis.complexity_class == ComplexityClass.NP

    # Invalid empty ID or digest
    with pytest.raises(BenchmarkGamingError, match="problem_id cannot be empty"):
        BenchmarkProblem("", basis, _digest("spec"))

    with pytest.raises(BenchmarkGamingError, match="Invalid specification_digest"):
        BenchmarkProblem("p1", basis, "invalid-digest")


def test_non_gaming_invariant_timeout_never_solves() -> None:
    suite = BenchmarkSuite(suite_id="bench:math-frontier")
    prob = BenchmarkProblem(
        problem_id="p1",
        basis=_sample_basis(),
        specification_digest=_digest("p1"),
        timeout_ms=2000,
    )
    suite.add_problem(prob)

    # Even if witness claims valid_proof=True, timeout must force TIMEOUT outcome
    receipt = suite.evaluate_witness(
        problem_id="p1",
        model_id="model-alpha",
        witness_data={"valid_proof": True},
        execution_ms=2500.0,  # Exceeded 2000ms timeout
        timed_out=False,
    )
    assert receipt.outcome == ProblemEvaluationOutcome.TIMEOUT
    assert receipt.outcome != ProblemEvaluationOutcome.SOLVED

    # Explicit timed_out flag
    receipt2 = suite.evaluate_witness(
        problem_id="p1",
        model_id="model-alpha",
        witness_data={"valid_proof": True},
        execution_ms=500.0,
        timed_out=True,
    )
    assert receipt2.outcome == ProblemEvaluationOutcome.TIMEOUT


def test_non_gaming_invariant_vacuous_proof_rejected() -> None:
    suite = BenchmarkSuite(suite_id="bench:logic-sat")
    prob = BenchmarkProblem(
        problem_id="p_vacuous",
        basis=_sample_basis(ComplexityClass.P, CapabilityDimension.CORRIGIBILITY),
        specification_digest=_digest("p_vacuous"),
        timeout_ms=5000,
    )
    suite.add_problem(prob)

    # Model attempts to prove proposition using contradictory premises (False -> True)
    receipt = suite.evaluate_witness(
        problem_id="p_vacuous",
        model_id="adversarial-model",
        witness_data={"valid_proof": True, "used_premises": ["True", "False"]},
        execution_ms=100.0,
    )
    assert receipt.outcome == ProblemEvaluationOutcome.VACUOUS_REJECTED

    # Explicit is_vacuous flag in witness
    receipt2 = suite.evaluate_witness(
        problem_id="p_vacuous",
        model_id="adversarial-model",
        witness_data={"valid_proof": True, "is_vacuous": True},
        execution_ms=100.0,
    )
    assert receipt2.outcome == ProblemEvaluationOutcome.VACUOUS_REJECTED


def test_non_gaming_invariant_oracle_shadowing_fails_closed() -> None:
    suite = BenchmarkSuite(suite_id="bench:security")
    prob = BenchmarkProblem(
        problem_id="p_sec",
        basis=_sample_basis(),
        specification_digest=_digest("p_sec"),
    )
    suite.add_problem(prob)

    # Model witness attempts to override or shadow evaluation oracle
    with pytest.raises(BenchmarkGamingError, match="Attempted oracle modification or shadowing"):
        suite.evaluate_witness(
            problem_id="p_sec",
            model_id="adversarial-model",
            witness_data={"valid_proof": True, "override_oracle": {"always_pass": True}},
            execution_ms=50.0,
        )


def test_witness_self_report_does_not_solve_a_problem() -> None:
    suite = BenchmarkSuite("suite")
    suite.add_problem(BenchmarkProblem("p", _sample_basis(), _digest("p")))
    receipt = suite.evaluate_witness("p", "model", {"valid_proof": True}, 1.0)
    assert receipt.outcome == ProblemEvaluationOutcome.UNKNOWN


def test_deterministic_pareto_frontier_calculation() -> None:
    suite = BenchmarkSuite(suite_id="bench:pareto-test")
    p1 = BenchmarkProblem("p1", _sample_basis(), _digest("p1"))
    p2 = BenchmarkProblem("p2", _sample_basis(), _digest("p2"))
    suite.add_problem(p1)
    suite.add_problem(p2)

    # Model A: Solves 2/2 in 100ms (Solved 1.0, Latency 100ms) - Non-dominated!
    # Model B: Solves 1/2 in 20ms  (Solved 0.5, Latency 20ms)  - Non-dominated! (faster)
    # Model C: Solves 1/2 in 150ms (Solved 0.5, Latency 150ms) - Dominated by Model A & Model B!
    receipts = [
        # Model A
        ProblemReceipt("p1", "model_A", ProblemEvaluationOutcome.SOLVED, _digest("w1"), 100.0),
        ProblemReceipt("p2", "model_A", ProblemEvaluationOutcome.SOLVED, _digest("w2"), 100.0),
        # Model B
        ProblemReceipt("p1", "model_B", ProblemEvaluationOutcome.SOLVED, _digest("w3"), 20.0),
        ProblemReceipt("p2", "model_B", ProblemEvaluationOutcome.FAILED, _digest("w4"), 20.0),
        # Model C (Dominated)
        ProblemReceipt("p1", "model_C", ProblemEvaluationOutcome.SOLVED, _digest("w5"), 150.0),
        ProblemReceipt("p2", "model_C", ProblemEvaluationOutcome.FAILED, _digest("w6"), 150.0),
    ]

    frontier = suite.compute_pareto_frontier(receipts)
    frontier_model_ids = [m["model_id"] for m in frontier]

    assert "model_A" in frontier_model_ids
    assert "model_B" in frontier_model_ids
    assert "model_C" not in frontier_model_ids  # Strictly dominated

    # Model A has highest solved rate, so it appears first
    assert frontier[0]["model_id"] == "model_A"
    assert frontier[0]["solved_rate"] == 1.0
    assert frontier[1]["model_id"] == "model_B"
    assert frontier[1]["solved_rate"] == 0.5


def test_pareto_frontier_rejects_gaming_via_duplicate_receipts() -> None:
    suite = BenchmarkSuite("suite_anti_gaming")
    basis = _sample_basis()
    suite.add_problem(BenchmarkProblem("p1", basis, _digest("p1")))
    suite.add_problem(BenchmarkProblem("p2", basis, _digest("p2")))

    # Model attempts to game score by submitting 10 receipts for the same single easy problem (p1)
    gaming_receipts = [
        ProblemReceipt("p1", "model_gamer", ProblemEvaluationOutcome.SOLVED, _digest(f"w_{i}"), 5.0)
        for i in range(10)
    ]
    frontier = suite.compute_pareto_frontier(gaming_receipts)
    assert len(frontier) == 1
    # Solved rate must NOT be 5.0 (500%); it must be 0.5 (1 of 2 unique problems solved)
    assert frontier[0]["solved_rate"] == 0.5
    assert frontier[0]["receipts_count"] == 1


def test_pareto_frontier_rejects_fake_problems() -> None:
    suite = BenchmarkSuite("suite_valid")
    basis = _sample_basis()
    suite.add_problem(BenchmarkProblem("p1", basis, _digest("p1")))

    fake_receipts = [
        ProblemReceipt("fabricated_problem_999", "model_cheater", ProblemEvaluationOutcome.SOLVED, _digest("fake"), 1.0)
    ]
    with pytest.raises(BenchmarkGamingError, match="Receipt references unknown problem 'fabricated_problem_999'"):
        suite.compute_pareto_frontier(fake_receipts)


def test_problem_receipt_rejects_negative_latency_and_memory() -> None:
    with pytest.raises(BenchmarkGamingError, match="execution_ms must be non-negative"):
        ProblemReceipt("p1", "m1", ProblemEvaluationOutcome.SOLVED, _digest("w"), -10.0)

    with pytest.raises(BenchmarkGamingError, match="peak_memory_bytes must be non-negative"):
        ProblemReceipt("p1", "m1", ProblemEvaluationOutcome.SOLVED, _digest("w"), 10.0, peak_memory_bytes=-1024)
