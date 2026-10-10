"""Benchmark specification graph (BENCH) with executable finite problem oracles.

Terminology: conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
unsatisfiable (UNSAT). Time is milliseconds and
memory is bytes; oracle work is dimensionless and bounded by the checker policy.
Linear residuals and weighted scores preserve exact parsed numeric values. The
score_exact numerator/denominator accompanies the approximate score display.
"""
from __future__ import annotations

from fractions import Fraction
from itertools import product
from .common import Budget, Refuted, Unavailable, digest, integer, need, number, obj, same, seq, unique


def _rational(value: int | float) -> Fraction:
    """Preserve the exact parsed value after bounded finite-number validation."""
    number(value)
    return Fraction(value)


def oracle(problem: dict, answer: object, budget: Budget) -> bool:
    kind, spec = problem["kind"], obj(problem["specification"])
    if kind == "exact":
        obj(spec, {"expected"})
        return digest(answer) == digest(spec["expected"])
    if kind in ("cnf-sat", "cnf-unsat"):
        obj(spec, {"variables", "clauses"})
        n = integer(spec["variables"], 1, 24)
        clauses = seq(spec["clauses"], budget, nonempty=False)
        for clause in clauses:
            for literal in seq(clause, budget, nonempty=False):
                if type(literal) is not int or not 1 <= abs(literal) <= n:
                    raise Refuted("literal outside declared variable universe")
        def satisfies(values: tuple | list) -> bool:
            budget.tick(sum(len(c) + 1 for c in clauses) + 1)
            return all(any(values[abs(v)-1] == (v > 0) for v in c) for c in clauses)
        if kind == "cnf-sat":
            values = seq(answer, budget)
            if len(values) != n or any(type(v) is not bool for v in values):
                raise Refuted("complete Boolean assignment required")
            return satisfies(values)
        same(answer, "UNSAT", "unsatisfiability answer required")
        for values in product((False, True), repeat=n):
            if satisfies(values):
                return False
        return True
    if kind == "linear-system":
        obj(spec, {"matrix", "rhs", "tolerance"})
        x = [_rational(v) for v in seq(answer, budget)]
        rows, rhs = seq(spec["matrix"], budget), seq(spec["rhs"], budget)
        if len(rows) != len(rhs):
            raise Refuted("linear-system shape differs")
        tolerance = _rational(spec["tolerance"])
        if tolerance < 0:
            raise Refuted("negative tolerance")
        for row, target in zip(rows, rhs):
            if len(seq(row, budget)) != len(x):
                raise Refuted("linear-system answer shape differs")
            if abs(sum(_rational(a)*b for a, b in zip(row, x))-_rational(target)) > tolerance:
                return False
        return True
    raise Unavailable("unsupported benchmark oracle")


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    if type(check) is not str or check not in ("problems", "oracles", "budgets", "coverage"):
        raise Unavailable("unsupported benchmark check")
    problems = unique(seq(need(artifact, "problems"), budget), "id")
    runs = unique(seq(need(inputs, "runs"), budget), "id")
    if set(runs) - set(problems):
        raise Refuted("unbound benchmark run")
    if set(problems) - set(runs):
        raise Unavailable("benchmark suite coverage incomplete")
    scores, weights = {}, {}
    for key, problem in problems.items():
        obj(problem, {"id", "kind", "specification", "weight", "timeout_ms", "memory_bytes"})
        run = obj(runs[key], {"id", "problem_digest", "answer", "execution_ms", "peak_memory_bytes"})
        same(run["problem_digest"], digest(problem), "problem substituted")
        weights[key] = _rational(problem["weight"])
        if weights[key] <= 0:
            raise Refuted("problem weight must be positive")
        if check in ("oracles", "coverage"):
            scores[key] = oracle(problem, run["answer"], budget)
        if check == "budgets":
            for field, bound in (("execution_ms", "timeout_ms"), ("peak_memory_bytes", "memory_bytes")):
                number(problem[bound]); number(run[field])
                if problem[bound] <= 0 or not 0 <= run[field] <= problem[bound]:
                    raise Refuted("retained benchmark resource observation exceeds bound")
    if scores:
        total = sum(weights.values())
        score = sum(weights[k] for k, passed in scores.items() if passed)/total
        expected = _rational(need(artifact, "minimum_score"))
        if not 0 <= expected <= 1:
            raise Refuted("score threshold outside [0,1]")
        if check == "coverage":
            if abs(score - _rational(need(inputs, "score"))) > _rational(1e-12):
                raise Refuted("reported benchmark score differs")
        if score < expected:
            raise Refuted("recomputed benchmark score below required threshold")
        return {"problems": len(problems), "score": float(score), "solved": scores,
                "score_exact": {"numerator": score.numerator, "denominator": score.denominator}}
    return {"problems": len(problems)}
