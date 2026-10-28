# Acronyms: Boolean satisfiability problem (SAT); unsatisfiable (UNSAT).
"""Pinned CaDiCaL backend with fail-closed machine-readable outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from time import perf_counter_ns
from typing import Any

from .route import CompiledRoute, RouteError


class SatStatus(str, Enum):
    SAT = "SAT"
    UNSAT = "UNSAT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SatObservation:
    status: SatStatus
    elapsed_ns: int
    model: tuple[int, ...]
    candidate: dict[str, Any] | None
    variables: int
    clauses: int
    decisions: int | None
    conflicts: int | None
    propagations: int | None
    witness_size: int | None
    unsat_certificate_available: bool
    unsat_certificate_size: int | None
    error: str | None

    def to_dict(self, *, include_model: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status.value,
            "elapsed_ns": self.elapsed_ns,
            "candidate": self.candidate,
            "variables": self.variables,
            "clauses": self.clauses,
            "decisions": self.decisions,
            "conflicts": self.conflicts,
            "propagations": self.propagations,
            "witness_size": self.witness_size,
            "unsat_certificate_available": self.unsat_certificate_available,
            "unsat_certificate_size": self.unsat_certificate_size,
            "error": self.error,
        }
        if include_model:
            payload["model"] = list(self.model)
        return payload


class CadicalBackend:
    """Unchanged PySAT CaDiCaL 3.0.0 configuration used by every arm."""

    name = "cadical300"
    engine = "CaDiCaL"
    engine_version = "3.0.0"
    binding_version = "python-sat==1.9.dev15"

    def __init__(self, conflict_budget: int | None = None) -> None:
        if conflict_budget is not None and conflict_budget <= 0:
            raise ValueError("conflict_budget must be positive")
        self.conflict_budget = conflict_budget

    @property
    def configuration(self) -> dict[str, Any]:
        return {
            "solver_name": self.name,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "binding": self.binding_version,
            "conflict_budget": self.conflict_budget,
            "clause_order": "compiler-deterministic",
            "phase_configuration": "binding-default",
            "unsat_certificate": "unavailable-through-selected-binding",
        }

    def solve(self, formula: CompiledRoute) -> SatObservation:
        from pysat.solvers import Solver

        started = perf_counter_ns()
        status = SatStatus.UNKNOWN
        model: tuple[int, ...] = ()
        candidate: dict[str, Any] | None = None
        stats: dict[str, Any] = {}
        error: str | None = None
        try:
            with Solver(name=self.name, bootstrap_with=formula.clauses, use_timer=True) as solver:
                if self.conflict_budget is None:
                    solved = solver.solve()
                else:
                    solver.conf_budget(self.conflict_budget)
                    solved = solver.solve_limited(expect_interrupt=True)
                stats = dict(solver.accum_stats())
                if solved is True:
                    status = SatStatus.SAT
                    model = tuple(solver.get_model() or ())
                    candidate = formula.decode_model(model)
                elif solved is False:
                    status = SatStatus.UNSAT
                else:
                    status = SatStatus.UNKNOWN
        except (Exception, RouteError) as exc:  # solver/plugin is an explicit boundary
            status = SatStatus.UNKNOWN
            error = f"{type(exc).__name__}: {exc}"
        elapsed = perf_counter_ns() - started
        witness_size = sum(1 for literal in model if literal > 0) if status is SatStatus.SAT else None
        return SatObservation(
            status=status,
            elapsed_ns=elapsed,
            model=model,
            candidate=candidate,
            variables=formula.variable_count,
            clauses=formula.clause_count,
            decisions=_stat(stats, "decisions"),
            conflicts=_stat(stats, "conflicts"),
            propagations=_stat(stats, "propagations"),
            witness_size=witness_size,
            unsat_certificate_available=False,
            unsat_certificate_size=None,
            error=error,
        )


def _stat(stats: dict[str, Any], key: str) -> int | None:
    value = stats.get(key)
    return int(value) if isinstance(value, (int, float)) else None
