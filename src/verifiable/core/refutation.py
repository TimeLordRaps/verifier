"""Refutation certificates for VSTD layer 4 (refutability).

Layer 4 requires that every verdict -- pass **and** fail -- carry an artifact an
independent party can check without the declarant's cooperation.

A satisfiable result already carries such an artifact: the model. Anyone can
evaluate that assignment against the clause set in linear time and needs no
solver of their own.

An unsatisfiable result, by default, carries nothing but the solver's word.
``MinimalIndependentDPLL.solve`` returns ``(False, None)`` -- a refusal a third
party must simply trust. For a fail-closed standard whose refusals are its most
consequential output, that asymmetry is backwards. This module closes it by
emitting a clausal resolution refutation and providing a checker that validates
that refutation **without re-solving**.

For the finite CNF language checked here, a satisfying assignment is checkable
in polynomial time and UNSAT is co-NP-complete. Polynomial-size certificates for
every UNSAT formula under a polynomial-time checker are not known; their general
existence would imply NP = co-NP. More specifically, resolution has proven
exponential lower bounds for some formula families. The implemented producer and
checker are therefore bounded and MUST answer ``UNKNOWN`` when their declared
bound is exhausted rather than silently report a pass. This complexity statement
is limited to the formal CNF problem; it is not a claim about unenumerated
physical-world activity.

Proof format
------------
The proof is a sequence of clauses, each of which is implied by the original
formula together with all preceding proof clauses, terminating in the empty
clause. Every step is verifiable by reverse unit propagation (RUP), the same
core property underlying the DRAT format used by SAT competition checkers.

The checker (:class:`RefutationChecker`) is deliberately small and shares no
code path with the solver that produces proofs. It is the trusted computing
base: an auditor may re-implement it from the format description alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

from . import certificate as gdc

# Bounds are declared, not silent. Exceeding either yields UNKNOWN.
DEFAULT_MAX_PROOF_STEPS = 4096
DEFAULT_MAX_DECISION_DEPTH = 256

REFUTATION_FORMAT = "VSTD4-RUP-1"


class RefutationBoundExceeded(RuntimeError):
    """Raised when a refutation exceeds its declared resource bound.

    Callers MUST translate this into an explicit UNKNOWN verdict. It is never
    an unsatisfiability result and never a pass.
    """


def _canonical_clause(literals: Iterable[int]) -> list[int]:
    """Deduplicate and order literals so identical clauses serialize identically."""
    seen: set[int] = set()
    out: list[int] = []
    for lit in literals:
        lit = int(lit)
        if lit in seen:
            continue
        seen.add(lit)
        out.append(lit)
    return sorted(out, key=lambda literal: (abs(literal), literal))


def _resolve(left: Sequence[int], right: Sequence[int], var: int) -> list[int]:
    """Resolve two clauses on ``var``, dropping both polarities of that variable."""
    merged = [lit for lit in left if abs(lit) != var]
    merged.extend(lit for lit in right if abs(lit) != var)
    return _canonical_clause(merged)


def _is_tautology(clause: Sequence[int]) -> bool:
    literals = set(clause)
    return any(-lit in literals for lit in literals)


@dataclass(frozen=True)
class RefutationCertificate:
    """A clausal refutation proof, independently checkable without re-solving."""

    proof: list[list[int]]
    n_vars: int
    source_clause_count: int
    max_proof_steps: int
    proof_format: str = REFUTATION_FORMAT

    @property
    def step_count(self) -> int:
        return len(self.proof)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_format": self.proof_format,
            "proof": [list(step) for step in self.proof],
            "n_vars": self.n_vars,
            "source_clause_count": self.source_clause_count,
            "step_count": self.step_count,
            "max_proof_steps": self.max_proof_steps,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RefutationCertificate":
        return cls(
            proof=[list(map(int, step)) for step in data["proof"]],
            n_vars=int(data["n_vars"]),
            source_clause_count=int(data["source_clause_count"]),
            max_proof_steps=int(data.get("max_proof_steps", DEFAULT_MAX_PROOF_STEPS)),
            proof_format=str(data.get("proof_format", REFUTATION_FORMAT)),
        )


@dataclass(frozen=True)
class RefutationCheckResult:
    accepted: bool
    steps_checked: int
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "steps_checked": self.steps_checked,
            "details": self.details,
        }


@dataclass(frozen=True)
class ProofSearchResult:
    """Outcome of a proof-producing solve.

    ``satisfiable`` is ``None`` when a declared bound was exceeded. That is an
    explicit UNKNOWN: it asserts neither satisfiability nor unsatisfiability.
    """

    satisfiable: Optional[bool]
    model: Optional[dict[int, bool]]
    certificate: Optional[RefutationCertificate]
    bound_exceeded: bool
    decisions: int
    propagations: int
    details: str = ""

    @property
    def is_unknown(self) -> bool:
        return self.satisfiable is None


def _propagate_to_conflict(
    formula: Sequence[Sequence[int]], assignment: dict[int, bool]
) -> bool:
    """Unit propagate to fixpoint. Return True iff a conflict is reached.

    This is the whole of the RUP check and is intentionally trivial to audit.
    """
    changed = True
    while changed:
        changed = False
        for clause in formula:
            unassigned: list[int] = []
            satisfied = False
            for lit in clause:
                value = assignment.get(abs(lit))
                if value is None:
                    unassigned.append(lit)
                elif (lit > 0) == value:
                    satisfied = True
                    break
            if satisfied:
                continue
            if not unassigned:
                return True
            if len(unassigned) == 1:
                lit = unassigned[0]
                assignment[abs(lit)] = lit > 0
                changed = True
    return False


class RefutationChecker:
    """Validates a refutation certificate without solving anything.

    Checking is polynomial in the size of the proof. Producing the proof is
    not. That gap is the entire reason a certificate is worth carrying.
    """

    @staticmethod
    def check(
        clauses: Sequence[Sequence[int]],
        certificate: RefutationCertificate,
    ) -> RefutationCheckResult:
        if certificate.proof_format != REFUTATION_FORMAT:
            return RefutationCheckResult(
                False, 0, f"unsupported proof format {certificate.proof_format!r}"
            )
        if not certificate.proof:
            return RefutationCheckResult(False, 0, "empty proof")
        if certificate.proof[-1]:
            return RefutationCheckResult(
                False,
                0,
                "proof does not terminate in the empty clause, so it refutes nothing",
            )

        formula: list[list[int]] = [list(map(int, clause)) for clause in clauses]
        for index, step in enumerate(certificate.proof):
            step = list(map(int, step))
            if _is_tautology(step):
                formula.append(step)
                continue
            assignment: dict[int, bool] = {}
            contradictory = False
            for lit in step:
                var, value = abs(lit), lit < 0
                if assignment.get(var, value) != value:
                    contradictory = True
                    break
                assignment[var] = value
            if contradictory:
                formula.append(step)
                continue
            if not _propagate_to_conflict(formula, assignment):
                return RefutationCheckResult(
                    False,
                    index,
                    f"proof step {index} {step} is not implied by reverse unit "
                    "propagation over the preceding formula",
                )
            formula.append(step)

        return RefutationCheckResult(
            True,
            len(certificate.proof),
            f"resolution refutation accepted in {len(certificate.proof)} steps "
            "without re-solving",
        )


class ProofProducingDPLL:
    """DPLL that emits a resolution refutation when the formula is unsatisfiable.

    A DPLL refutation is a tree resolution proof: each branch returns a clause
    implied by the formula and falsified by the current decisions, and the two
    branches of a decision variable resolve into a clause independent of it.
    At the root there are no decisions, so the returned clause is empty.

    Independent of external solver libraries, matching the constraint on
    :class:`~verifiable.core.checker.MinimalIndependentDPLL`.
    """

    def __init__(
        self,
        n_vars: int,
        clauses: Sequence[Sequence[int]],
        max_proof_steps: int = DEFAULT_MAX_PROOF_STEPS,
        max_decision_depth: int = DEFAULT_MAX_DECISION_DEPTH,
    ) -> None:
        self.n_vars = int(n_vars)
        self.clauses = [list(map(int, clause)) for clause in clauses]
        self.max_proof_steps = int(max_proof_steps)
        self.max_decision_depth = int(max_decision_depth)
        self.decisions = 0
        self.propagations = 0
        self.proof: list[list[int]] = []
        self._model: Optional[dict[int, bool]] = None

    def solve(self) -> ProofSearchResult:
        self.decisions = 0
        self.propagations = 0
        self.proof = []
        self._model = None

        try:
            clause = self._refute({}, [], 0)
        except RefutationBoundExceeded as exc:
            return ProofSearchResult(
                satisfiable=None,
                model=None,
                certificate=None,
                bound_exceeded=True,
                decisions=self.decisions,
                propagations=self.propagations,
                details=f"UNKNOWN: {exc}",
            )

        if clause is None:
            model: dict[int, bool] = dict(self._model or {})
            for var in range(1, self.n_vars + 1):
                model.setdefault(var, True)
            return ProofSearchResult(
                satisfiable=True,
                model=model,
                certificate=None,
                bound_exceeded=False,
                decisions=self.decisions,
                propagations=self.propagations,
                details="satisfiable; the model is itself the certificate",
            )

        certificate = RefutationCertificate(
            proof=[list(step) for step in self.proof],
            n_vars=self.n_vars,
            source_clause_count=len(self.clauses),
            max_proof_steps=self.max_proof_steps,
        )
        return ProofSearchResult(
            satisfiable=False,
            model=None,
            certificate=certificate,
            bound_exceeded=False,
            decisions=self.decisions,
            propagations=self.propagations,
            details=f"unsatisfiable; refutation in {certificate.step_count} steps",
        )

    def _log(self, clause: Sequence[int]) -> list[int]:
        if len(self.proof) >= self.max_proof_steps:
            raise RefutationBoundExceeded(
                f"refutation exceeded the declared bound of {self.max_proof_steps} "
                "proof steps; no unsatisfiability claim is made"
            )
        step = _canonical_clause(clause)
        self.proof.append(step)
        return step

    def _propagate(
        self, assignment: dict[int, bool], trail: list[tuple[int, Optional[list[int]]]]
    ) -> Optional[list[int]]:
        """Propagate to fixpoint, recording antecedents. Return a conflict clause or None."""
        changed = True
        while changed:
            changed = False
            for clause in self.clauses:
                unassigned: list[int] = []
                satisfied = False
                for lit in clause:
                    value = assignment.get(abs(lit))
                    if value is None:
                        unassigned.append(lit)
                    elif (lit > 0) == value:
                        satisfied = True
                        break
                if satisfied:
                    continue
                if not unassigned:
                    return list(clause)
                if len(unassigned) == 1:
                    lit = unassigned[0]
                    assignment[abs(lit)] = lit > 0
                    trail.append((abs(lit), list(clause)))
                    self.propagations += 1
                    changed = True
        return None

    def _analyze(
        self,
        conflict: Sequence[int],
        trail: Sequence[tuple[int, Optional[list[int]]]],
    ) -> list[int]:
        """Resolve a conflict clause back to one falsified by decisions alone."""
        clause = _canonical_clause(conflict)
        for var, antecedent in reversed(trail):
            if antecedent is None:
                continue
            if any(abs(lit) == var for lit in clause):
                clause = _resolve(clause, antecedent, var)
        return clause

    def _pick_variable(self, assignment: Mapping[int, bool]) -> Optional[int]:
        for clause in self.clauses:
            for lit in clause:
                if abs(lit) not in assignment:
                    return abs(lit)
        for var in range(1, self.n_vars + 1):
            if var not in assignment:
                return var
        return None

    def _refute(
        self,
        assignment: dict[int, bool],
        trail: list[tuple[int, Optional[list[int]]]],
        depth: int,
    ) -> Optional[list[int]]:
        """Return None if satisfiable, else a clause falsified by the decisions."""
        conflict = self._propagate(assignment, trail)
        if conflict is not None:
            return self._log(self._analyze(conflict, trail))

        var = self._pick_variable(assignment)
        if var is None:
            self._model = dict(assignment)
            return None

        if depth >= self.max_decision_depth:
            raise RefutationBoundExceeded(
                f"search exceeded the declared decision depth of "
                f"{self.max_decision_depth}; no unsatisfiability claim is made"
            )

        self.decisions += 1

        true_assignment = dict(assignment)
        true_trail = list(trail)
        true_assignment[var] = True
        true_trail.append((var, None))
        true_clause = self._refute(true_assignment, true_trail, depth + 1)
        if true_clause is None:
            return None
        # A clause not mentioning this decision is already implied without it.
        if -var not in true_clause:
            return true_clause

        false_assignment = dict(assignment)
        false_trail = list(trail)
        false_assignment[var] = False
        false_trail.append((var, None))
        false_clause = self._refute(false_assignment, false_trail, depth + 1)
        if false_clause is None:
            return None
        if var not in false_clause:
            return false_clause

        return self._log(_resolve(true_clause, false_clause, var))


def refute(
    n_vars: int,
    clauses: Sequence[Sequence[int]],
    max_proof_steps: int = DEFAULT_MAX_PROOF_STEPS,
    max_decision_depth: int = DEFAULT_MAX_DECISION_DEPTH,
) -> ProofSearchResult:
    """Solve, and on unsatisfiability return a checkable refutation certificate."""
    return ProofProducingDPLL(
        n_vars,
        clauses,
        max_proof_steps=max_proof_steps,
        max_decision_depth=max_decision_depth,
    ).solve()


# --------------------------------------------------------------------------
# VSTD4-GDC-1 production, tier UP
# --------------------------------------------------------------------------
#
# A Horn formula under unit propagation *is* a policy evaluation with a
# derivation trace -- the two are the same computation, which is why the CNF
# framing of ``LADDER.md`` §4 costs nothing to keep. What follows produces the
# tier-``UP`` decision block for such a formula so that a caller can hand out a
# certificate ``verifiable.core.kernel`` will check, rather than its own word.


def horn_propagate(
    formula: Sequence[Sequence[int]],
) -> tuple[list[gdc.PropagationStep], Optional[int], dict[int, bool]]:
    """Propagate to fixpoint. Returns the trace, the conflict index, and the assignment.

    Each recorded step is unit and unsatisfied at the moment it is taken, which
    is exactly the precondition the kernel re-checks on replay.
    """
    assignment: dict[int, bool] = {}
    steps: list[gdc.PropagationStep] = []
    while True:
        unit: Optional[tuple[int, int]] = None
        for index, clause in enumerate(formula):
            unassigned: list[int] = []
            satisfied = False
            for literal in clause:
                value = assignment.get(abs(literal))
                if value is None:
                    unassigned.append(literal)
                elif (literal > 0) == value:
                    satisfied = True
                    break
            if satisfied:
                continue
            if not unassigned:
                return steps, index, assignment
            if unit is None and len(unassigned) == 1:
                unit = (index, unassigned[0])
        if unit is None:
            return steps, None, assignment
        index, literal = unit
        assignment[abs(literal)] = literal > 0
        steps.append(gdc.PropagationStep(index, literal))


def build_horn_certificate(
    formula: Sequence[Sequence[int]],
    grounding: gdc.Grounding,
    binding: gdc.ClaimBinding,
    *,
    hints: Optional[Mapping[str, Any]] = None,
) -> gdc.DecisionCertificate:
    """Produce a tier-``UP`` certificate for a Horn formula.

    Raises if the formula is not Horn, rather than quietly emitting a tier the
    formula cannot support: the tightest admissible tier is mandatory, and a
    producer that inflates it has forged the header.
    """
    clauses = tuple(tuple(int(literal) for literal in clause) for clause in formula)
    for index, clause in enumerate(clauses):
        if sum(1 for literal in clause if literal > 0) > 1:
            raise ValueError(
                f"clause {index} {list(clause)} has more than one positive literal, "
                "so this formula is not Horn and tier UP cannot certify it"
            )

    n_vars = max((abs(literal) for clause in clauses for literal in clause), default=0)
    literals = sum(len(clause) for clause in clauses)
    steps, conflict, assignment = horn_propagate(clauses)

    if conflict is None:
        model = {var: assignment.get(var, False) for var in range(1, n_vars + 1)}
        header = gdc.CertificateHeader(
            gdc.Verdict.PASS, gdc.CostTier.UP, n_vars, len(clauses), literals, 0, binding.digest()
        )
        decision = gdc.DecisionBlock(model=model)
    else:
        header = gdc.CertificateHeader(
            gdc.Verdict.FAIL,
            gdc.CostTier.UP,
            n_vars,
            len(clauses),
            literals,
            len(steps),
            binding.digest(),
        )
        decision = gdc.DecisionBlock(
            propagation=gdc.UnitPropagationProof(tuple(steps), conflict)
        )

    return gdc.DecisionCertificate(
        header, clauses, grounding, decision, dict(hints or {})
    )
