"""Terminology: Boolean satisfiability problem (SAT); identifier (ID); JavaScript Object Notation (JSON); nondeterministic polynomial time (NP); satisfiability modulo theories (SMT); Secure Hash Algorithm 256-bit (SHA-256); benchmark specification graph (BENCH); Verifier Standard (VSTD).

BENCH: Refutable benchmark specifications, score provenance, and non-gaming invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class ComplexityClass(str, Enum):
    P = "P"
    NP = "NP"
    PSPACE = "PSPACE"
    EXPTIME = "EXPTIME"
    UNDECIDABLE = "UNDECIDABLE"


class FormalLanguage(str, Enum):
    LEAN_4 = "LEAN_4"
    COQ = "COQ"
    SMT_LIB2 = "SMT_LIB2"
    PYTHON_AST = "PYTHON_AST"
    PROPOSITIONAL_SAT = "PROPOSITIONAL_SAT"


class OracleMechanism(str, Enum):
    DETERMINISTIC_KERNEL = "DETERMINISTIC_KERNEL"
    FORMAL_PROOF_CHECKER = "FORMAL_PROOF_CHECKER"
    DIFFERENTIAL_EXECUTION = "DIFFERENTIAL_EXECUTION"
    OUT_OF_BAND_ORACLE = "OUT_OF_BAND_ORACLE"


class EpistemicStratum(str, Enum):
    ELEMENTARY = "ELEMENTARY"
    INTERMEDIATE = "INTERMEDIATE"
    FRONTIER = "FRONTIER"
    ADVERSARIAL_RED_TEAM = "ADVERSARIAL_RED_TEAM"


class CapabilityDimension(str, Enum):
    FORMAL_REASONING = "FORMAL_REASONING"
    CODE_SYNTHESIS = "CODE_SYNTHESIS"
    CORRIGIBILITY = "CORRIGIBILITY"
    DECEPTIVE_ALIGNMENT_EVASION = "DECEPTIVE_ALIGNMENT_EVASION"
    ROBUSTNESS = "ROBUSTNESS"


class ProblemEvaluationOutcome(str, Enum):
    SOLVED = "SOLVED"
    FALSIFIED = "FALSIFIED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"
    VACUOUS_REJECTED = "VACUOUS_REJECTED"


class BenchmarkGamingError(ValueError):
    """Raised when benchmark gaming or vacuous score generation is detected."""


@dataclass(frozen=True)
class ProblemBasis:
    """Multidimensional 6-tuple problem basis parameterizing benchmark problem space."""

    complexity_class: ComplexityClass
    formal_language: FormalLanguage
    oracle_mechanism: OracleMechanism
    resource_grain: Mapping[str, Any]
    epistemic_stratum: EpistemicStratum
    capability_dimension: CapabilityDimension

    def to_dict(self) -> dict[str, Any]:
        return {
            "complexity_class": self.complexity_class.value,
            "formal_language": self.formal_language.value,
            "oracle_mechanism": self.oracle_mechanism.value,
            "resource_grain": dict(self.resource_grain),
            "epistemic_stratum": self.epistemic_stratum.value,
            "capability_dimension": self.capability_dimension.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProblemBasis:
        return cls(
            complexity_class=ComplexityClass(data["complexity_class"]),
            formal_language=FormalLanguage(data["formal_language"]),
            oracle_mechanism=OracleMechanism(data["oracle_mechanism"]),
            resource_grain=dict(data.get("resource_grain", {})),
            epistemic_stratum=EpistemicStratum(data["epistemic_stratum"]),
            capability_dimension=CapabilityDimension(data["capability_dimension"]),
        )


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class BenchmarkProblem:
    """A refutable, content-addressed benchmark problem node."""

    problem_id: str
    basis: ProblemBasis
    specification_digest: str
    axiom_premises: tuple[str, ...] = field(default_factory=tuple)
    expected_property: str = ""
    timeout_ms: int = 5000

    def __post_init__(self) -> None:
        if not self.problem_id:
            raise BenchmarkGamingError("problem_id cannot be empty")
        if not _DIGEST_PATTERN.match(self.specification_digest):
            raise BenchmarkGamingError(
                f"Invalid specification_digest: '{self.specification_digest}' must be a sha256 hex digest"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "problem_id": self.problem_id,
            "basis": self.basis.to_dict(),
            "specification_digest": self.specification_digest,
            "axiom_premises": list(self.axiom_premises),
            "expected_property": self.expected_property,
            "timeout_ms": self.timeout_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BenchmarkProblem:
        return cls(
            problem_id=str(data["problem_id"]),
            basis=ProblemBasis.from_dict(data["basis"]),
            specification_digest=str(data["specification_digest"]),
            axiom_premises=tuple(str(a) for a in data.get("axiom_premises", ())),
            expected_property=str(data.get("expected_property", "")),
            timeout_ms=int(data.get("timeout_ms", 5000)),
        )


@dataclass(frozen=True)
class ProblemReceipt:
    """Individual execution and verification receipt for a problem."""

    problem_id: str
    model_id: str
    outcome: ProblemEvaluationOutcome
    witness_digest: str
    execution_ms: float
    peak_memory_bytes: int = 0
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if not self.problem_id or not self.model_id:
            raise BenchmarkGamingError("problem_id and model_id cannot be empty")
        if self.execution_ms < 0:
            raise BenchmarkGamingError("execution_ms must be non-negative")
        if self.peak_memory_bytes < 0:
            raise BenchmarkGamingError("peak_memory_bytes must be non-negative")
        if self.witness_digest and not _DIGEST_PATTERN.match(self.witness_digest):
            raise BenchmarkGamingError(
                f"Invalid witness_digest: '{self.witness_digest}' must be a sha256 hex digest"
            )

    def canonical_digest(self) -> str:
        payload = {
            "problem_id": self.problem_id,
            "model_id": self.model_id,
            "outcome": self.outcome.value,
            "witness_digest": self.witness_digest,
            "execution_ms": self.execution_ms,
            "peak_memory_bytes": self.peak_memory_bytes,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        cdigest = self.receipt_digest or self.canonical_digest()
        return {
            "problem_id": self.problem_id,
            "model_id": self.model_id,
            "outcome": self.outcome.value,
            "witness_digest": self.witness_digest,
            "execution_ms": self.execution_ms,
            "peak_memory_bytes": self.peak_memory_bytes,
            "receipt_digest": cdigest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProblemReceipt:
        return cls(
            problem_id=str(data["problem_id"]),
            model_id=str(data["model_id"]),
            outcome=ProblemEvaluationOutcome(data["outcome"]),
            witness_digest=str(data.get("witness_digest", "")),
            execution_ms=float(data.get("execution_ms", 0.0)),
            peak_memory_bytes=int(data.get("peak_memory_bytes", 0)),
            receipt_digest=str(data.get("receipt_digest", "")),
        )


class BenchmarkSuite:
    """Suite of benchmark problems enforcing non-gaming and Pareto calculation."""

    def __init__(self, suite_id: str) -> None:
        if not suite_id:
            raise BenchmarkGamingError("suite_id cannot be empty")
        self.suite_id = suite_id
        self._problems: dict[str, BenchmarkProblem] = {}

    def add_problem(self, problem: BenchmarkProblem) -> None:
        if problem.problem_id in self._problems:
            raise BenchmarkGamingError(f"Duplicate problem_id: '{problem.problem_id}'")
        self._problems[problem.problem_id] = problem

    @property
    def problems(self) -> Mapping[str, BenchmarkProblem]:
        return dict(self._problems)

    def evaluate_witness(
        self,
        problem_id: str,
        model_id: str,
        witness_data: Mapping[str, Any],
        execution_ms: float,
        timed_out: bool = False,
    ) -> ProblemReceipt:
        """Check declared witness metadata; no problem oracle is executed here."""
        problem = self._problems.get(problem_id)
        if problem is None:
            raise BenchmarkGamingError(f"Problem '{problem_id}' not found in suite")

        # Non-gaming invariant 1: Timeout never upgrades to SOLVED
        if timed_out or execution_ms > problem.timeout_ms:
            return ProblemReceipt(
                problem_id=problem_id,
                model_id=model_id,
                outcome=ProblemEvaluationOutcome.TIMEOUT,
                witness_digest=f"sha256:{hashlib.sha256(_canonical_json_bytes(witness_data)).hexdigest()}",
                execution_ms=execution_ms,
            )

        # Non-gaming invariant 2: Premise vacuity check (detect contradictory premises)
        is_vacuous = witness_data.get("is_vacuous", False)
        premises = witness_data.get("used_premises", [])
        if is_vacuous or ("False" in premises and "True" in premises):
            return ProblemReceipt(
                problem_id=problem_id,
                model_id=model_id,
                outcome=ProblemEvaluationOutcome.VACUOUS_REJECTED,
                witness_digest=f"sha256:{hashlib.sha256(_canonical_json_bytes(witness_data)).hexdigest()}",
                execution_ms=execution_ms,
            )

        # Non-gaming invariant 3: Oracle immutability check
        if "override_oracle" in witness_data or "oracle_shadow" in witness_data:
            raise BenchmarkGamingError("Attempted oracle modification or shadowing detected")

        # A witness's self-reported valid_proof flag establishes no correctness.
        # A registered, specification-bound oracle is required before SOLVED.
        outcome = ProblemEvaluationOutcome.UNKNOWN

        w_digest = f"sha256:{hashlib.sha256(_canonical_json_bytes(witness_data)).hexdigest()}"
        return ProblemReceipt(
            problem_id=problem_id,
            model_id=model_id,
            outcome=outcome,
            witness_digest=w_digest,
            execution_ms=execution_ms,
        )

    def compute_pareto_frontier(
        self,
        receipts: Sequence[ProblemReceipt],
    ) -> list[dict[str, Any]]:
        """Compute deterministic Pareto frontier across models (solved rate vs mean latency).

        Does not inflate scores or promote UNKNOWN/TIMEOUT to SOLVED.
        """
        # Aggregate by model and enforce suite problem membership + deduplication
        by_model: dict[str, dict[str, ProblemReceipt]] = {}
        for r in receipts:
            if r.problem_id not in self._problems:
                raise BenchmarkGamingError(
                    f"Receipt references unknown problem '{r.problem_id}' not in benchmark suite '{self.suite_id}'"
                )
            m_dict = by_model.setdefault(r.model_id, {})
            # Keep latest receipt or consistent receipt for the problem
            m_dict[r.problem_id] = r

        stats: list[dict[str, Any]] = []
        total_problems = len(self._problems) or 1
        for model_id, p_receipts in by_model.items():
            solved_count = sum(
                1 for r in p_receipts.values() if r.outcome == ProblemEvaluationOutcome.SOLVED
            )
            solved_rate = solved_count / total_problems
            mean_latency = (
                sum(r.execution_ms for r in p_receipts.values()) / max(len(p_receipts), 1)
            )
            stats.append({
                "model_id": model_id,
                "solved_rate": solved_rate,
                "mean_latency_ms": mean_latency,
                "receipts_count": len(p_receipts),
            })

        # Deterministic Pareto non-dominated sort: higher solved_rate, lower latency is better
        pareto_frontier: list[dict[str, Any]] = []
        for candidate in stats:
            dominated = False
            for other in stats:
                if other["model_id"] == candidate["model_id"]:
                    continue
                # Other dominates candidate if other has >= solved_rate AND <= latency, with at least one strict
                if (
                    other["solved_rate"] >= candidate["solved_rate"]
                    and other["mean_latency_ms"] <= candidate["mean_latency_ms"]
                    and (
                        other["solved_rate"] > candidate["solved_rate"]
                        or other["mean_latency_ms"] < candidate["mean_latency_ms"]
                    )
                ):
                    dominated = True
                    break
            if not dominated:
                pareto_frontier.append(candidate)

        pareto_frontier.sort(key=lambda x: (-x["solved_rate"], x["mean_latency_ms"], x["model_id"]))
        return pareto_frontier
