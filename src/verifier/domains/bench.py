"""Benchmark specification graph (BENCH) with executable finite problem oracles.

Terminology: conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
unsatisfiable (UNSAT). Time is milliseconds and
memory is bytes; oracle work is dimensionless and bounded by the checker policy.
"""
from __future__ import annotations

from itertools import product
from .common import Budget, Refuted, Unavailable, close, digest, integer, need, number, obj, same, seq, unique


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
        x = [number(v) for v in seq(answer, budget)]
        rows, rhs = seq(spec["matrix"], budget), seq(spec["rhs"], budget)
        if len(rows) != len(rhs):
            raise Refuted("linear-system shape differs")
        for row, target in zip(rows, rhs):
            if len(seq(row, budget)) != len(x):
                raise Refuted("linear-system answer shape differs")
            if abs(sum(number(a)*b for a, b in zip(row, x))-number(target)) > number(spec["tolerance"]):
                return False
        if number(spec["tolerance"]) < 0:
            raise Refuted("negative tolerance")
        return True
    raise Unavailable("unsupported benchmark oracle")


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    problems = unique(seq(need(artifact, "problems"), budget), "id")
    runs = unique(seq(need(inputs, "runs"), budget), "id")
    if set(runs) - set(problems):
        raise Refuted("unbound benchmark run")
    if set(problems) - set(runs):
        raise Unavailable("benchmark suite coverage incomplete")
    scores = {}
    for key, problem in problems.items():
        obj(problem, {"id", "kind", "specification", "weight", "timeout_ms", "memory_bytes"})
        run = obj(runs[key], {"id", "problem_digest", "answer", "execution_ms", "peak_memory_bytes"})
        same(run["problem_digest"], digest(problem), "problem substituted")
        if number(problem["weight"]) <= 0:
            raise Refuted("problem weight must be positive")
        if check in ("oracles", "coverage"):
            scores[key] = oracle(problem, run["answer"], budget)
        if check == "budgets":
            for field, bound in (("execution_ms", "timeout_ms"), ("peak_memory_bytes", "memory_bytes")):
                if number(problem[bound]) <= 0 or not 0 <= number(run[field]) <= number(problem[bound]):
                    raise Refuted("retained benchmark resource observation exceeds bound")
    if scores:
        total = sum(number(p["weight"]) for p in problems.values())
        score = sum(number(problems[k]["weight"]) for k, passed in scores.items() if passed)/total
        expected = number(need(artifact, "minimum_score"))
        if not 0 <= expected <= 1:
            raise Refuted("score threshold outside [0,1]")
        if check == "coverage":
            close(score, need(inputs, "score"), 1e-12, "reported benchmark score differs")
        if score < expected:
            raise Refuted("recomputed benchmark score below required threshold")
        return {"problems": len(problems), "score": score, "solved": scores}
    return {"problems": len(problems)}
