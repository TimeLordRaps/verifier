"""Terminology: application programming interface (API);
Boolean satisfiability problem (SAT); Davis-Putnam-Logemann-Loveland (DPLL);
grounded decision certificate (GDC); Secure Hash Algorithm 256-bit (SHA-256);
trusted computing base (TCB); Verifier Standard (VSTD).

Bundled VSTD Checker for SAT, Derivation Graphs, and Grounding.

This module provides a minimal, self-contained verification engine with zero
dependencies on external solver libraries or the target repository under test.
It is a separate checker implementation in the trusted computing base (TCB), but
calling it does not itself establish actor, implementation, or runtime independence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .certificate import VerifierDescriptor

_MODULE_PATH = Path(__file__).resolve()
_REPO_ROOT = _MODULE_PATH.parents[3]

UNAVAILABLE_PREFIX = "UNAVAILABLE:"
"""House idiom, matching ``translation.py``. A hash that cannot be computed is
reported as unavailable rather than as a plausible-looking constant."""


def _source_digest(*candidates: Any) -> str:
    """SHA-256 of the first candidate available in source or an installed wheel.

    Each named candidate is tried as an absolute path, a repository-relative path,
    and a current-working-directory-relative path. ``standard/`` coordinates also
    resolve to the byte-identical installed specification copy. This is location
    resolution, not semantic substitution; callers must name only equivalent sources.
    """
    for candidate in candidates:
        path = Path(candidate)
        paths = [path] if path.is_absolute() else [_REPO_ROOT / path, Path.cwd() / path]
        if not path.is_absolute() and path.parts and path.parts[0] == "standard":
            paths.append(_MODULE_PATH.parents[1] / "specifications" / path.name)
        for resolved in paths:
            try:
                return "sha256:" + hashlib.sha256(resolved.read_bytes()).hexdigest()
            except OSError:
                continue
    return f"{UNAVAILABLE_PREFIX}{candidates[0] if candidates else ''}"


def unit_propagation_conflict(
    clauses: Sequence[Sequence[int]],
) -> Optional[int]:
    """Index of a clause unit propagation genuinely falsifies, or ``None``.

    Used so that ``conflicting_clause`` reports a conflict that actually
    occurred. Returning ``None`` when propagation alone reaches no conflict is
    the honest answer: it means search was required, and no single clause is
    *the* reason the formula failed.
    """
    assignment: dict[int, bool] = {}
    while True:
        unit: Optional[int] = None
        for index, clause in enumerate(clauses):
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
                return index
            if unit is None and len(unassigned) == 1:
                unit = unassigned[0]
        if unit is None:
            return None
        assignment[abs(unit)] = unit > 0


class VerificationVerdict(str, Enum):
    """Outcome vocabulary returned by the VSTD-1 claim-mechanics checker."""

    VERIFIED = "VERIFIED"
    FALSIFIED = "FALSIFIED"
    INDETERMINATE = "INDETERMINATE"
    UNSUPPORTED = "UNSUPPORTED"


class IndependenceStatus(str, Enum):
    """Evidence state for separation between producer and checker."""

    EVIDENCED = "EVIDENCED"
    DECLARED = "DECLARED"
    NOT_DEMONSTRATED = "NOT_DEMONSTRATED"
    CONFLICTED = "CONFLICTED"


def independence_is_evidenced(basis: Mapping[str, Any]) -> bool:
    """Apply the bundled runtime's current independence capability ceiling.

    Serialized status words and evidence references are declarations. VSTD 1.2.0
    ships no validator that resolves and binds them to distinct actors and execution
    seams, so no supplied mapping can establish evidenced independence.
    """

    del basis
    return False


@dataclass(frozen=True)
class IndependenceBasis:
    """Actor and execution separation; artifact agreement proves neither."""

    actor_independence: IndependenceStatus = IndependenceStatus.NOT_DEMONSTRATED
    implementation_separation: IndependenceStatus = IndependenceStatus.NOT_DEMONSTRATED
    runtime_separation: IndependenceStatus = IndependenceStatus.NOT_DEMONSTRATED
    evidence: tuple[str, ...] = ()

    @property
    def independently_verified(self) -> bool:
        """False until an implemented adapter validates the recorded bindings."""

        return independence_is_evidenced(
            {
                "actor_independence": self.actor_independence.value,
                "implementation_separation": self.implementation_separation.value,
                "runtime_separation": self.runtime_separation.value,
                "evidence": self.evidence,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "independently_verified": self.independently_verified,
            "actor_independence": self.actor_independence.value,
            "implementation_separation": self.implementation_separation.value,
            "runtime_separation": self.runtime_separation.value,
            "evidence": list(self.evidence),
        }


class GroundingVerdict(str, Enum):
    GROUNDED = "GROUNDED"
    ASSUMED = "ASSUMED"
    UNGROUNDED = "UNGROUNDED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class IndependentSatResult:
    satisfiable: bool
    verdict: VerificationVerdict
    model: Optional[dict[int, bool]]
    conflicting_clause: Optional[list[int]]
    decisions_count: int
    propagations_count: int


@dataclass(frozen=True)
class IndependentGroundingResult:
    grounding_status: GroundingVerdict
    leaves: list[str]
    observed_leaves: list[str]
    inferred_leaves: list[str]
    placeholder_leaves: list[str]
    unspecified_leaves: list[str]
    undischarged_assumptions: list[str]
    cycle_detected: bool
    missing_parent_references: list[str]
    is_valid: bool
    details: str


@dataclass(frozen=True)
class IndependentAuditReport:
    """Historical API name for a checker report with explicit separation evidence."""

    claim_id: str
    sat_result: IndependentSatResult
    grounding_result: IndependentGroundingResult
    structural_integrity_passed: bool
    overall_verdict: VerificationVerdict
    trusted_computing_base: dict[str, str]
    audit_notes: list[str]
    independence_basis: IndependenceBasis = field(default_factory=IndependenceBasis)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "overall_verdict": self.overall_verdict.value,
            "independence_basis": self.independence_basis.to_dict(),
            "structural_integrity_passed": self.structural_integrity_passed,
            "sat_result": {
                "satisfiable": self.sat_result.satisfiable,
                "verdict": self.sat_result.verdict.value,
                "model": {str(k): v for k, v in (self.sat_result.model or {}).items()},
                "conflicting_clause": self.sat_result.conflicting_clause,
                "decisions_count": self.sat_result.decisions_count,
                "propagations_count": self.sat_result.propagations_count,
            },
            "grounding_result": {
                "grounding_status": self.grounding_result.grounding_status.value,
                "leaves": self.grounding_result.leaves,
                "observed_leaves": self.grounding_result.observed_leaves,
                "inferred_leaves": self.grounding_result.inferred_leaves,
                "placeholder_leaves": self.grounding_result.placeholder_leaves,
                "unspecified_leaves": self.grounding_result.unspecified_leaves,
                "undischarged_assumptions": self.grounding_result.undischarged_assumptions,
                "cycle_detected": self.grounding_result.cycle_detected,
                "missing_parent_references": self.grounding_result.missing_parent_references,
                "is_valid": self.grounding_result.is_valid,
                "details": self.grounding_result.details,
            },
            "trusted_computing_base": self.trusted_computing_base,
            "audit_notes": self.audit_notes,
        }


class MinimalIndependentDPLL:
    """A self-contained DPLL SAT solver in pure standard-library Python.

    It shares no target-solver, third-party SAT package, or external-binary logic.
    That implementation separation does not establish actor independence.
    """

    def __init__(self, n_vars: int, clauses: Sequence[Sequence[int]]):
        self.n_vars = int(n_vars)
        self.clauses = [list(map(int, c)) for c in clauses]
        self.decisions = 0
        self.propagations = 0

    def solve(self) -> tuple[bool, Optional[dict[int, bool]]]:
        assignment: dict[int, bool] = {}
        sat, model = self._dpll(self.clauses, assignment)
        return sat, model

    def _unit_propagate(
        self, clauses: list[list[int]], assignment: dict[int, bool]
    ) -> tuple[Optional[list[list[int]]], dict[int, bool]]:
        assignment = dict(assignment)
        changed = True
        while changed:
            changed = False
            # Find unit clauses
            unit_literals = []
            for clause in clauses:
                unassigned = []
                satisfied = False
                for lit in clause:
                    var = abs(lit)
                    val = assignment.get(var)
                    if val is not None:
                        if (lit > 0 and val) or (lit < 0 and not val):
                            satisfied = True
                            break
                    else:
                        unassigned.append(lit)
                if satisfied:
                    continue
                if len(unassigned) == 0:
                    # Conflict: all literals are false
                    return None, assignment
                if len(unassigned) == 1:
                    unit_literals.append(unassigned[0])

            for lit in unit_literals:
                var = abs(lit)
                val = (lit > 0)
                if var in assignment:
                    if assignment[var] != val:
                        return None, assignment
                else:
                    assignment[var] = val
                    self.propagations += 1
                    changed = True

        # Simplify clauses
        simplified: list[list[int]] = []
        for clause in clauses:
            new_clause = []
            satisfied = False
            for lit in clause:
                var = abs(lit)
                val = assignment.get(var)
                if val is not None:
                    if (lit > 0 and val) or (lit < 0 and not val):
                        satisfied = True
                        break
                else:
                    new_clause.append(lit)
            if not satisfied:
                if not new_clause:
                    return None, assignment
                simplified.append(new_clause)

        return simplified, assignment

    def _dpll(
        self, clauses: list[list[int]], assignment: dict[int, bool]
    ) -> tuple[bool, Optional[dict[int, bool]]]:
        simplified, new_assignment = self._unit_propagate(clauses, assignment)
        if simplified is None:
            return False, None
        if not simplified:
            for v in range(1, self.n_vars + 1):
                if v not in new_assignment:
                    new_assignment[v] = True
            return True, new_assignment

        chosen_var = None
        for c in simplified:
            for lit in c:
                if abs(lit) not in new_assignment:
                    chosen_var = abs(lit)
                    break
            if chosen_var is not None:
                break

        if chosen_var is None:
            return True, new_assignment

        self.decisions += 1
        branch_true = dict(new_assignment)
        branch_true[chosen_var] = True
        sat, model = self._dpll(simplified, branch_true)
        if sat:
            return True, model

        branch_false = dict(new_assignment)
        branch_false[chosen_var] = False
        return self._dpll(simplified, branch_false)


class IndependentGroundingChecker:
    """Separately implemented grounding, acyclicity, and derivation checks."""

    @staticmethod
    def audit_derivation(
        atomic_reasons: Sequence[Mapping[str, Any]],
        assumptions: Sequence[str] = (),
    ) -> IndependentGroundingResult:
        reasons_by_id: dict[str, Mapping[str, Any]] = {
            r["reason_id"]: r for r in atomic_reasons if "reason_id" in r
        }

        visited: set[str] = set()
        stack: set[str] = set()
        cycle_detected = False

        def dfs(node: str) -> bool:
            visited.add(node)
            stack.add(node)
            reason = reasons_by_id.get(node)
            if reason:
                for parent in reason.get("parent_reason_ids", ()):
                    if parent in reasons_by_id:
                        if parent not in visited:
                            if dfs(parent):
                                return True
                        elif parent in stack:
                            return True
            stack.remove(node)
            return False

        for r_id in reasons_by_id:
            if r_id not in visited:
                if dfs(r_id):
                    cycle_detected = True
                    break

        leaves: set[str] = set()
        missing_parents: set[str] = set()

        for r_id, reason in reasons_by_id.items():
            parents = reason.get("parent_reason_ids", ())
            present_parents = [p for p in parents if p in reasons_by_id]
            for p in parents:
                if p not in reasons_by_id:
                    missing_parents.add(p)
            if not present_parents:
                leaves.add(r_id)

        observed: list[str] = []
        inferred: list[str] = []
        placeholders: list[str] = []
        unspecified: list[str] = []

        for leaf_id in sorted(leaves):
            r = reasons_by_id.get(leaf_id, {})
            ekind = str(r.get("evidence_kind", "")).upper()
            if "OBSERVED" in ekind:
                observed.append(leaf_id)
            elif "INFERRED" in ekind:
                inferred.append(leaf_id)
            elif "PLACEHOLDER" in ekind:
                placeholders.append(leaf_id)
            else:
                unspecified.append(leaf_id)

        asserted_propositions = {
            (r.get("proposition", "").strip().lower(), bool(r.get("polarity", True)))
            for r in reasons_by_id.values()
        }
        undischarged: list[str] = []
        for r in reasons_by_id.values():
            for a in r.get("assumptions", ()):
                canon_a = a.strip().lower()
                if (canon_a, True) not in asserted_propositions:
                    undischarged.append(a)

        if placeholders:
            status = GroundingVerdict.UNGROUNDED
            details = f"{len(placeholders)} placeholder leaf/leaves present; derivation rests on ungrounded stand-in."
        elif unspecified or missing_parents:
            status = GroundingVerdict.UNKNOWN
            details = "Supporting leaves contain unspecified evidence kinds or missing parent references."
        elif inferred or undischarged:
            status = GroundingVerdict.ASSUMED
            details = "Support terminates in inferred leaves or undischarged assumptions."
        elif observed:
            status = GroundingVerdict.GROUNDED
            details = "All supporting leaves are asserted as observed and assumptions discharged."
        else:
            status = GroundingVerdict.UNKNOWN
            details = "No supporting leaves recorded in derivation graph."

        is_valid = (not cycle_detected) and (len(missing_parents) == 0) and (status != GroundingVerdict.UNGROUNDED)

        return IndependentGroundingResult(
            grounding_status=status,
            leaves=sorted(leaves),
            observed_leaves=sorted(observed),
            inferred_leaves=sorted(inferred),
            placeholder_leaves=sorted(placeholders),
            unspecified_leaves=sorted(unspecified),
            undischarged_assumptions=sorted(set(undischarged)),
            cycle_detected=cycle_detected,
            missing_parent_references=sorted(missing_parents),
            is_valid=is_valid,
            details=details,
        )


class IndependentAuditor:
    """Historical API name for the bundled SAT and grounding checker.

    Calling this class does not establish that separate actors performed the
    producer and checker runs. Matching results cannot establish that fact. The
    returned report records actor, implementation, and runtime separation as
    ``NOT_DEMONSTRATED`` unless a separate integration supplies bound evidence.
    """

    @classmethod
    def verifier_descriptor(cls) -> VerifierDescriptor:
        """This auditor's trust boundary, in hashes rather than in promises.

        Rung 4.7. The previous form of this was a hardcoded dict asserting
        ``"isolation": "Zero shared code with target solver"`` -- a claim about
        the code, made by the code, checkable by nobody. The hashes below are
        read from files on disk, so mutating this module changes
        ``implementation_hash`` and any receipt pinning the old value stops
        matching.

        ``certificate_format`` deliberately does **not** say ``VSTD4-GDC-1``.
        This auditor emits an ``IndependentAuditReport``, which is a different
        artifact, and claiming a format one does not implement is the
        serialized-format form of the semantic mismatch rung 4.2 prohibits.
        """
        return VerifierDescriptor(
            specification_hash=_source_digest("standard/VSTD-1.md"),
            implementation_hash=_source_digest(_MODULE_PATH),
            parser_hash=_source_digest(_MODULE_PATH.with_name("receipt.py")),
            certificate_format="VSTD1-CHECKER-REPORT",
            format_fragment="SAT,GROUNDING,ACYCLICITY",
            dependencies=("python-stdlib",),
            deterministic=True,
        )

    @classmethod
    def tcb(cls) -> dict[str, str]:
        """Flattened descriptor, for the report field and the receipt renderers."""
        descriptor = cls.verifier_descriptor()
        return {
            "verifier_name": "verifier.core.checker.IndependentAuditor",
            "solver": "MinimalIndependentDPLL (pure Python, stdlib-only)",
            "grounding_checker": "IndependentGroundingChecker",
            "runtime_dependencies": "Python standard library (hashlib, json, dataclasses)",
            "specification_hash": descriptor.specification_hash,
            "implementation_hash": descriptor.implementation_hash,
            "parser_hash": descriptor.parser_hash,
            "certificate_format": descriptor.certificate_format,
            "format_fragment": descriptor.format_fragment,
            "deterministic": str(descriptor.deterministic).lower(),
        }

    @classmethod
    def audit_claim_derivation(
        cls,
        claim_id: str,
        n_vars: int,
        clauses: Sequence[Sequence[int]],
        atomic_reasons: Sequence[Mapping[str, Any]],
        expected_satisfiable: bool = True,
        assumptions: Sequence[str] = (),
    ) -> IndependentAuditReport:
        solver = MinimalIndependentDPLL(n_vars, clauses)
        is_sat, model = solver.solve()

        sat_passed = (is_sat == expected_satisfiable)
        sat_verdict = VerificationVerdict.VERIFIED if sat_passed else VerificationVerdict.FALSIFIED

        # Rung 4.2. This used to report ``clauses[0]`` -- the *first clause of
        # the formula*, presented as the conflict. It was not a conflict
        # analysis and was unrelated to why the formula failed, which is
        # certificate/claim semantic mismatch with a nice field name. Report the
        # clause propagation actually falsifies, or nothing.
        conflict_index = None if is_sat else unit_propagation_conflict(clauses)
        conflicting_clause = None if conflict_index is None else list(clauses[conflict_index])

        sat_result = IndependentSatResult(
            satisfiable=is_sat,
            verdict=sat_verdict,
            model=model,
            conflicting_clause=conflicting_clause,
            decisions_count=solver.decisions,
            propagations_count=solver.propagations,
        )

        grounding_result = IndependentGroundingChecker.audit_derivation(atomic_reasons, assumptions)

        structural_passed = (
            sat_passed
            and not grounding_result.cycle_detected
            and len(grounding_result.missing_parent_references) == 0
        )

        if structural_passed and grounding_result.grounding_status in (GroundingVerdict.GROUNDED, GroundingVerdict.ASSUMED):
            overall = VerificationVerdict.VERIFIED
        elif not sat_passed or grounding_result.grounding_status == GroundingVerdict.UNGROUNDED:
            overall = VerificationVerdict.FALSIFIED
        else:
            overall = VerificationVerdict.INDETERMINATE

        notes = [
            f"SAT formula solved by the bundled separate implementation: satisfiable={is_sat} (decisions={solver.decisions}, propagations={solver.propagations}).",
            f"Grounding checker status: {grounding_result.grounding_status.value} ({grounding_result.details}).",
            f"Acyclicity verified: cycle_detected={grounding_result.cycle_detected}.",
            "This same-process call did not demonstrate separate actors, implementation separation, or runtime separation; matching results cannot establish actor independence.",
        ]
        if not is_sat:
            notes.append(
                f"Conflict clause index {conflict_index} falsified by unit propagation."
                if conflict_index is not None
                else "No unit-propagation conflict exists; search was required, so no "
                "single clause is reportable as the reason for unsatisfiability."
            )

        return IndependentAuditReport(
            claim_id=claim_id,
            sat_result=sat_result,
            grounding_result=grounding_result,
            structural_integrity_passed=structural_passed,
            overall_verdict=overall,
            trusted_computing_base=cls.tcb(),
            audit_notes=notes,
        )
