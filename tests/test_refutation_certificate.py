"""Terminology: conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
unsatisfiable (UNSAT); Verifier Standard (VSTD).

VSTD layer 4: refusals must carry certificates a stranger can check.

The property under test is not merely that the solver is correct. It is that an
UNSAT verdict ships an artifact an independent party validates *without*
re-solving, and that exhausting a declared bound yields UNKNOWN rather than a
silent pass.
"""

from __future__ import annotations

import random

import pytest

from verifier.core.checker import MinimalIndependentDPLL
from verifier.core.refutation import (
    DEFAULT_MAX_PROOF_STEPS,
    REFUTATION_FORMAT,
    ProofProducingDPLL,
    RefutationCertificate,
    RefutationChecker,
    refute,
)


# A minimal unsatisfiable core: (x) and (-x).
TRIVIAL_UNSAT = [[1], [-1]]

# (x or y) and (x or -y) and (-x or y) and (-x or -y): all four assignments fail.
FOUR_CORNER_UNSAT = [[1, 2], [1, -2], [-1, 2], [-1, -2]]

SATISFIABLE = [[1, 2], [-1, 3], [2, 3]]


def test_satisfiable_result_carries_a_model_and_no_refutation():
    result = refute(3, SATISFIABLE)
    assert result.satisfiable is True
    assert result.certificate is None
    assert result.model is not None
    # The model is the certificate: check it directly against the clauses.
    for clause in SATISFIABLE:
        assert any((lit > 0) == result.model[abs(lit)] for lit in clause)


@pytest.mark.parametrize("clauses,n_vars", [(TRIVIAL_UNSAT, 1), (FOUR_CORNER_UNSAT, 2)])
def test_unsatisfiable_result_carries_a_checkable_refutation(clauses, n_vars):
    result = refute(n_vars, clauses)
    assert result.satisfiable is False
    assert result.bound_exceeded is False

    certificate = result.certificate
    assert certificate is not None
    assert certificate.proof_format == REFUTATION_FORMAT
    assert certificate.proof[-1] == [], "a refutation must derive the empty clause"

    checked = RefutationChecker.check(clauses, certificate)
    assert checked.accepted, checked.details
    assert checked.steps_checked == certificate.step_count


def test_checker_rejects_a_proof_that_never_reaches_the_empty_clause():
    result = refute(2, FOUR_CORNER_UNSAT)
    assert result.certificate is not None
    truncated = RefutationCertificate(
        proof=result.certificate.proof[:-1] or [[1]],
        n_vars=result.certificate.n_vars,
        source_clause_count=result.certificate.source_clause_count,
        max_proof_steps=result.certificate.max_proof_steps,
    )
    checked = RefutationChecker.check(FOUR_CORNER_UNSAT, truncated)
    assert not checked.accepted
    assert "empty clause" in checked.details


def test_checker_rejects_a_fabricated_refutation_of_a_satisfiable_formula():
    """The failure mode that matters: a solver claiming UNSAT when it is not."""
    forged = RefutationCertificate(
        proof=[[]],
        n_vars=3,
        source_clause_count=len(SATISFIABLE),
        max_proof_steps=DEFAULT_MAX_PROOF_STEPS,
    )
    checked = RefutationChecker.check(SATISFIABLE, forged)
    assert not checked.accepted
    assert "reverse unit propagation" in checked.details


def test_checker_rejects_a_tampered_intermediate_step():
    """Rejection is located at the first step that does not follow.

    Note the tamper must be staged against a *satisfiable* formula. From an
    unsatisfiable formula every clause follows, so splicing an arbitrary clause
    into a genuine refutation is not forgery -- it is a valid, if useless, step.
    """
    # [-2] does not follow from SATISFIABLE: setting x2 true propagates nothing
    # to a conflict.
    tampered = RefutationCertificate(
        proof=[[-2], []],
        n_vars=3,
        source_clause_count=len(SATISFIABLE),
        max_proof_steps=DEFAULT_MAX_PROOF_STEPS,
    )
    checked = RefutationChecker.check(SATISFIABLE, tampered)
    assert not checked.accepted
    assert checked.steps_checked == 0, "must fail at the first bad step, not later"


def test_certificate_round_trips_through_serialization():
    result = refute(2, FOUR_CORNER_UNSAT)
    assert result.certificate is not None
    restored = RefutationCertificate.from_dict(result.certificate.to_dict())
    assert restored == result.certificate
    assert RefutationChecker.check(FOUR_CORNER_UNSAT, restored).accepted


def test_exceeding_the_proof_bound_yields_unknown_never_a_pass():
    solver = ProofProducingDPLL(2, FOUR_CORNER_UNSAT, max_proof_steps=1)
    result = solver.solve()
    assert result.is_unknown
    assert result.satisfiable is None, "UNKNOWN must not collapse to satisfiable"
    assert result.bound_exceeded is True
    assert result.certificate is None
    assert "UNKNOWN" in result.details


def test_exceeding_the_decision_depth_yields_unknown():
    clauses = [[1, 2], [1, -2], [-1, 2], [-1, -2]]
    result = ProofProducingDPLL(2, clauses, max_decision_depth=0).solve()
    assert result.is_unknown
    assert result.bound_exceeded is True


def test_empty_clause_in_the_source_formula_refutes_immediately():
    result = refute(1, [[]])
    assert result.satisfiable is False
    assert result.certificate is not None
    assert RefutationChecker.check([[]], result.certificate).accepted


def _random_cnf(rng: random.Random, n_vars: int, n_clauses: int) -> list[list[int]]:
    clauses = []
    for _ in range(n_clauses):
        size = rng.randint(1, min(3, n_vars))
        clause = set()
        while len(clause) < size:
            var = rng.randint(1, n_vars)
            if var not in {abs(lit) for lit in clause}:
                clause.add(var if rng.random() < 0.5 else -var)
        clauses.append(sorted(clause, key=lambda literal: (abs(literal), literal)))
    return clauses


def test_agrees_with_the_existing_solver_and_every_refusal_is_certified():
    """Cross-check against MinimalIndependentDPLL over many random 3-CNF instances.

    Fixed seed: this must be reproducible, per VSTD layer 1.
    """
    rng = random.Random(20260822)
    unsat_seen = 0
    sat_seen = 0

    for _ in range(300):
        n_vars = rng.randint(2, 6)
        clauses = _random_cnf(rng, n_vars, rng.randint(2, 14))

        baseline_sat, _ = MinimalIndependentDPLL(n_vars, clauses).solve()
        result = refute(n_vars, clauses)

        assert not result.is_unknown, "default bounds should suffice at this size"
        assert result.satisfiable == baseline_sat

        if baseline_sat:
            sat_seen += 1
            assert result.model is not None
            for clause in clauses:
                assert any((lit > 0) == result.model[abs(lit)] for lit in clause)
        else:
            unsat_seen += 1
            assert result.certificate is not None
            checked = RefutationChecker.check(clauses, result.certificate)
            assert checked.accepted, f"unverifiable refutation for {clauses}: {checked.details}"

    assert unsat_seen > 20, "expected a meaningful number of UNSAT instances"
    assert sat_seen > 20, "expected a meaningful number of SAT instances"
