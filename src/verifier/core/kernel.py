"""Terminology: conjunctive normal form (CNF); grounded decision certificate (GDC);
Boolean satisfiability problem (SAT); Verifier Standard (VSTD).

The refutability kernel -- the whole trusted computing base of VSTD layer 4.

Rung 4.7 is a claim about code, not a slogan: a certificate checker must be
radically simpler than the system that produced the claim, and must share no
verdict-producing code with it. This module therefore imports **only**
:mod:`verifier.core.certificate` and :mod:`verifier.core.grounding`, both of
which are pure records and structural validation. It does not import
``checker``, ``refutation``, or ``policy``, and a test enforces that.

The unit-propagation routine below duplicates one in
:mod:`verifier.core.refutation`. That duplication is deliberate and must not
be refactored away: the producer and the checker agreeing because they share a
function is not agreement, and an auditor re-implementing this file from the
specification alone is the operative test of the rung.

Three outcomes, and they are not the same thing:

``ACCEPTED``
    The kernel endorses the verdict the certificate declares.
``REJECTED``
    The certificate is invalid. A detected forgery is a positive result, and it
    must never be softened into "I do not know."
``REFUSED``
    The kernel cannot decide within its declared budget or capability. This
    yields ``UNKNOWN`` with a reason, and is never a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from .certificate import (
    ClaimBinding,
    CostTier,
    DecisionCertificate,
    FORMAT,
    IndeterminacyReason,
    Verdict,
    VerifierDescriptor,
    canonical_bytes,
    canonical_digest,
)
from .grounding import verify_grounding


class KernelOutcome(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class KernelResult:
    outcome: KernelOutcome
    verdict: Optional[Verdict]
    steps_checked: int
    literals_processed: int
    reason: Optional[IndeterminacyReason]
    details: str
    hints_present: bool = False

    @property
    def accepted(self) -> bool:
        return self.outcome is KernelOutcome.ACCEPTED

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "verdict": None if self.verdict is None else self.verdict.value,
            "steps_checked": self.steps_checked,
            "literals_processed": self.literals_processed,
            "reason": None if self.reason is None else self.reason.value,
            "details": self.details,
            "hints_present": self.hints_present,
        }


def _reject(details: str, steps: int = 0, literals: int = 0, hints: bool = False) -> KernelResult:
    return KernelResult(KernelOutcome.REJECTED, None, steps, literals, None, details, hints)


def _refuse(
    reason: IndeterminacyReason,
    details: str,
    steps: int = 0,
    literals: int = 0,
    hints: bool = False,
) -> KernelResult:
    return KernelResult(
        KernelOutcome.REFUSED, Verdict.UNKNOWN, steps, literals, reason, details, hints
    )


# --------------------------------------------------------------------------
# Cost tiers
# --------------------------------------------------------------------------


def is_horn(formula: Sequence[Sequence[int]]) -> bool:
    """True when every clause has at most one positive literal.

    Horn satisfiability is decidable in linear time by unit propagation alone
    (Dowling and Gallier), so for a Horn formula the checking bound is a theorem
    rather than a declaration. Every CNF currently emitted by
    ``verifier.data.policy`` is Horn.
    """
    return all(sum(1 for literal in clause if literal > 0) <= 1 for clause in formula)


def tightest_tier(formula: Sequence[Sequence[int]]) -> CostTier:
    """The cheapest tier that can check this formula.

    Only the ``UP`` boundary is mandated, because it is the boundary with teeth
    and it is decidable in one pass. Above it, ``WIDTH-K`` is a declared
    refinement of ``RES`` that the kernel validates but does not require, since
    the tightest admissible width is a property of a proof rather than of a
    formula and is not decidable by inspection.
    """
    return CostTier.UP if is_horn(formula) else CostTier.RES


def _tier_admissible(
    formula: Sequence[Sequence[int]], tier: CostTier, width: int
) -> Optional[str]:
    # The width field must be operative, never decorative. A WIDTH-K header with
    # no width silently degrades to RES while still advertising a polynomial
    # bound, which is tier inflation running the other way.
    if tier is CostTier.WIDTH_K and width < 1:
        return "tier WIDTH-K requires a declared width of at least 1"
    if tier is not CostTier.WIDTH_K and width != 0:
        return f"tier {tier.value} does not use a width bound; header declares {width}"

    tightest = tightest_tier(formula)
    if tightest is CostTier.UP and tier is not CostTier.UP:
        return (
            f"formula is Horn, so tier UP is admissible and therefore mandatory; "
            f"certificate declares {tier.value}. A linear-time check may not be "
            "dressed in general-resolution machinery."
        )
    if tightest is not CostTier.UP and tier is CostTier.UP:
        return "formula is not Horn, so tier UP cannot check it"
    return None


# --------------------------------------------------------------------------
# Propagation -- separately reimplemented from the producer path; see module docstring
# --------------------------------------------------------------------------


def _propagates_to_conflict(
    formula: Sequence[Sequence[int]], assignment: dict[int, bool]
) -> bool:
    """Unit propagate to fixpoint; return True iff a clause becomes falsified."""
    changed = True
    while changed:
        changed = False
        for clause in formula:
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
                return True
            if len(unassigned) == 1:
                literal = unassigned[0]
                assignment[abs(literal)] = literal > 0
                changed = True
    return False


# --------------------------------------------------------------------------
# Decision-block checking
# --------------------------------------------------------------------------


def _check_model(
    formula: Sequence[Sequence[int]], model: dict[int, bool], n_vars: int
) -> Optional[str]:
    for var in range(1, n_vars + 1):
        if var not in model:
            return f"model leaves variable {var} unassigned"
    for index, clause in enumerate(formula):
        if not any((literal > 0) == model.get(abs(literal), False) for literal in clause):
            return f"model falsifies clause {index} {list(clause)}"
    return None


def _check_propagation(
    formula: Sequence[Sequence[int]], proof
) -> tuple[Optional[str], int]:
    """Replay a tier-``UP`` refutation. Linear in the number of steps."""
    assignment: dict[int, bool] = {}
    for position, step in enumerate(proof.steps):
        if not 0 <= step.clause_index < len(formula):
            return f"step {position} cites clause {step.clause_index}, which does not exist", position
        clause = formula[step.clause_index]
        unassigned: list[int] = []
        for literal in clause:
            value = assignment.get(abs(literal))
            if value is None:
                unassigned.append(literal)
            elif (literal > 0) == value:
                return (
                    f"step {position} propagates from clause {step.clause_index}, "
                    "which is already satisfied and forces nothing",
                    position,
                )
        if len(unassigned) != 1:
            return (
                f"step {position}: clause {step.clause_index} has {len(unassigned)} "
                "unassigned literals and is therefore not unit",
                position,
            )
        if unassigned[0] != step.forced:
            return (
                f"step {position}: clause {step.clause_index} forces {unassigned[0]}, "
                f"not the declared {step.forced}",
                position,
            )
        assignment[abs(step.forced)] = step.forced > 0

    index = proof.conflict_clause_index
    if not 0 <= index < len(formula):
        return f"conflict clause {index} does not exist", len(proof.steps)
    for literal in formula[index]:
        value = assignment.get(abs(literal))
        if value is None:
            return (
                f"conflict clause {index} has unassigned literal {literal}; "
                "it is not falsified",
                len(proof.steps),
            )
        if (literal > 0) == value:
            return (
                f"conflict clause {index} is satisfied by literal {literal}; "
                "it is not falsified",
                len(proof.steps),
            )
    return None, len(proof.steps)


def _check_resolution(
    formula: Sequence[Sequence[int]], proof, max_width: int
) -> tuple[Optional[str], int]:
    """Replay a tier-``RES`` refutation by reverse unit propagation."""
    if not proof.steps:
        return "empty proof", 0
    if proof.steps[-1]:
        return "proof does not terminate in the empty clause, so it refutes nothing", 0

    working = [list(clause) for clause in formula]
    for position, raw in enumerate(proof.steps):
        step = list(raw)
        if max_width and len(step) > max_width:
            return (
                f"step {position} has width {len(step)}, exceeding the declared "
                f"width bound of {max_width}",
                position,
            )
        literals = set(step)
        if any(-literal in literals for literal in literals):
            working.append(step)
            continue
        assignment: dict[int, bool] = {}
        for literal in step:
            assignment[abs(literal)] = literal < 0
        if not _propagates_to_conflict(working, assignment):
            return (
                f"step {position} {step} is not implied by reverse unit propagation "
                "over the preceding formula",
                position,
            )
        working.append(step)
    return None, len(proof.steps)


def _check_transcript(certificate: DecisionCertificate) -> Optional[str]:
    transcript = certificate.decision.transcript
    if transcript is None:
        return "UNKNOWN carries no indeterminacy transcript"
    expected = canonical_digest([list(clause) for clause in certificate.formula])
    if transcript.formula_digest != expected:
        return "transcript does not describe this formula"
    exhaustion = {
        IndeterminacyReason.PROOF_BOUND_EXCEEDED,
        IndeterminacyReason.DEPTH_BOUND_EXCEEDED,
    }
    if transcript.reason in exhaustion and transcript.observed_cost <= transcript.declared_bound:
        return (
            f"transcript claims {transcript.reason.value} but reports an observed cost of "
            f"{transcript.observed_cost} within the declared bound of "
            f"{transcript.declared_bound}"
        )
    return None


def _embedded_step_count(certificate: DecisionCertificate) -> int:
    """Count proof steps without replaying them.

    Counting tuple lengths is the only decision-body operation allowed before
    the cost gate.  Summing every present arm prevents a malformed certificate
    from hiding a huge ignored proof behind a small declared count.
    """
    decision = certificate.decision
    return sum(
        len(proof.steps)
        for proof in (decision.propagation, decision.resolution)
        if proof is not None
    )


def _decision_shape(certificate: DecisionCertificate) -> Optional[str]:
    decision = certificate.decision
    present = {
        "model": decision.model is not None,
        "propagation": decision.propagation is not None,
        "resolution": decision.resolution is not None,
        "transcript": decision.transcript is not None,
    }
    expected = {
        Verdict.PASS: "model",
        Verdict.UNKNOWN: "transcript",
        Verdict.FAIL: (
            "propagation" if certificate.header.tier is CostTier.UP else "resolution"
        ),
    }[certificate.header.verdict]
    actual = [name for name, exists in present.items() if exists]
    if not actual and expected == "transcript":
        return (
            "UNKNOWN carries no indeterminacy transcript; a refusal without evidence "
            "is not a layer-4 verdict"
        )
    if (
        certificate.header.verdict is Verdict.FAIL
        and certificate.header.tier is CostTier.UP
        and present["resolution"]
    ):
        return (
            "tier UP FAIL carries a resolution proof; a Horn refutation is a "
            "propagation trace and general resolution is inadmissible here"
        )
    if actual != [expected]:
        return (
            f"{certificate.header.verdict.value}/{certificate.header.tier.value} "
            f"requires only the {expected} decision arm; present arms are {actual}"
        )
    return None


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def check(
    certificate: DecisionCertificate,
    *,
    budget: Optional[int] = None,
    binding: Optional[ClaimBinding] = None,
) -> KernelResult:
    """Check a ``VSTD4-GDC-1`` certificate.

    ``budget`` is a ceiling on literals the kernel may process. Because the
    header states the cost, an over-budget certificate is refused **before any
    checking work happens** -- the caller can see this in
    ``literals_processed == 0``.

    ``hints`` are never consulted. A corrupted hint can therefore change the
    speed of a check but never its outcome.
    """
    header = certificate.header
    hints_present = bool(certificate.hints)

    if header.format != FORMAT:
        return _reject(f"unsupported certificate format {header.format!r}", hints=hints_present)

    if binding is not None and binding.digest() != header.binding:
        return _reject(
            "certificate binding does not match the supplied claim binding; the "
            "certificate is not about this claim",
            hints=hints_present,
        )

    # Rung 4.5: refuse before working, using the cost the header declares.
    declared_cost = header.literal_count + header.step_count
    effective_budget = budget
    if binding is not None and binding.bounds.verification_cost_bound > 0:
        effective_budget = (
            binding.bounds.verification_cost_bound
            if effective_budget is None
            else min(effective_budget, binding.bounds.verification_cost_bound)
        )
    if effective_budget is not None and declared_cost > effective_budget:
        return _refuse(
            IndeterminacyReason.PROOF_BOUND_EXCEEDED,
            f"certificate declares a checking cost of {declared_cost} literals, "
            f"exceeding the budget of {effective_budget}; refused without checking",
            hints=hints_present,
        )

    actual_steps = _embedded_step_count(certificate)
    if effective_budget is not None and header.literal_count + actual_steps > effective_budget:
        return _refuse(
            IndeterminacyReason.PROOF_BOUND_EXCEEDED,
            "certificate proof contains more steps than its header declares and "
            f"would exceed the budget of {effective_budget}; refused without replay",
            hints=hints_present,
        )

    if binding is not None:
        bounds = binding.bounds
        retained_clauses = header.clause_count
        if header.tier in (CostTier.WIDTH_K, CostTier.RES, CostTier.SAT_PRESERVING):
            retained_clauses += actual_steps
        if bounds.memory_bound > 0 and retained_clauses > bounds.memory_bound:
            return _refuse(
                IndeterminacyReason.PROOF_BOUND_EXCEEDED,
                f"checking requires retention of {retained_clauses} clauses, "
                f"exceeding the committed memory bound of {bounds.memory_bound}",
                hints=hints_present,
            )
        if bounds.certificate_size_bound > 0:
            certificate_size = len(canonical_bytes(certificate.to_dict()))
            if certificate_size > bounds.certificate_size_bound:
                return _refuse(
                    IndeterminacyReason.PROOF_BOUND_EXCEEDED,
                    f"canonical certificate size {certificate_size} exceeds the "
                    f"committed bound of {bounds.certificate_size_bound}",
                    hints=hints_present,
                )

    # Rung 4.7 honesty: a tier this kernel does not implement is UNKNOWN, not
    # FAIL. Silently mis-accepting an unimplemented construct would be exactly
    # the semantic mismatch layer 4 prohibits.
    if header.tier is CostTier.SAT_PRESERVING:
        return _refuse(
            IndeterminacyReason.VERIFIER_UNAVAILABLE,
            "this kernel implements tiers UP, WIDTH-K and RES; SAT-PRESERVING is "
            "specified but not implemented here",
            hints=hints_present,
        )

    # Verify the header against the formula, aborting early if a understated
    # header tried to buy its way past the budget gate.
    ceiling = (
        max(header.literal_count, effective_budget)
        if effective_budget is not None
        else None
    )
    literals = 0
    max_var = 0
    for clause in certificate.formula:
        literals += len(clause)
        for literal in clause:
            max_var = max(max_var, abs(int(literal)))
        if ceiling is not None and literals > ceiling:
            return _refuse(
                IndeterminacyReason.PROOF_BOUND_EXCEEDED,
                f"formula exceeds {ceiling} literals, so the declared header cost of "
                f"{header.literal_count} understates the work required",
                literals=literals,
                hints=hints_present,
            )

    if literals != header.literal_count:
        return _reject(
            f"header declares {header.literal_count} literals; the formula has {literals}",
            literals=literals,
            hints=hints_present,
        )
    if len(certificate.formula) != header.clause_count:
        return _reject(
            f"header declares {header.clause_count} clauses; the formula has "
            f"{len(certificate.formula)}",
            literals=literals,
            hints=hints_present,
        )
    if max_var > header.n_vars:
        return _reject(
            f"formula mentions variable {max_var}, above the declared n_vars of "
            f"{header.n_vars}",
            literals=literals,
            hints=hints_present,
        )

    problem = _tier_admissible(certificate.formula, header.tier, header.width)
    if problem is not None:
        return _reject(problem, literals=literals, hints=hints_present)

    problem = _decision_shape(certificate)
    if problem is not None:
        return _reject(problem, literals=literals, hints=hints_present)

    if actual_steps != header.step_count:
        return _reject(
            f"header declares {header.step_count} proof steps; the decision block "
            f"contains {actual_steps}",
            literals=literals,
            hints=hints_present,
        )

    grounded = verify_grounding(certificate.formula, certificate.grounding)
    if not grounded.accepted:
        return _reject(
            f"grounding rejected: {grounded.details}", literals=literals, hints=hints_present
        )

    decision = certificate.decision

    if header.verdict is Verdict.PASS:
        if decision.model is None:
            return _reject("PASS carries no model", literals=literals, hints=hints_present)
        problem = _check_model(certificate.formula, decision.model, header.n_vars)
        if problem is not None:
            return _reject(problem, literals=literals, hints=hints_present)
        return KernelResult(
            KernelOutcome.ACCEPTED,
            Verdict.PASS,
            0,
            literals,
            None,
            f"model satisfies all {len(certificate.formula)} grounded clauses",
            hints_present,
        )

    if header.verdict is Verdict.FAIL:
        if header.tier is CostTier.UP:
            if decision.propagation is None:
                return _reject(
                    "tier UP FAIL carries no propagation proof",
                    literals=literals,
                    hints=hints_present,
                )
            if decision.resolution is not None:
                return _reject(
                    "tier UP FAIL carries a resolution proof; a Horn refutation is a "
                    "propagation trace and general resolution is inadmissible here",
                    literals=literals,
                    hints=hints_present,
                )
            problem, steps = _check_propagation(certificate.formula, decision.propagation)
            if problem is not None:
                return _reject(problem, steps, literals, hints_present)
            return KernelResult(
                KernelOutcome.ACCEPTED,
                Verdict.FAIL,
                steps,
                literals,
                None,
                f"propagation refutation replayed in {steps} steps without search",
                hints_present,
            )

        if decision.resolution is None:
            return _reject(
                f"tier {header.tier.value} FAIL carries no resolution proof",
                literals=literals,
                hints=hints_present,
            )
        width = header.width if header.tier is CostTier.WIDTH_K else 0
        problem, steps = _check_resolution(certificate.formula, decision.resolution, width)
        if problem is not None:
            return _reject(problem, steps, literals, hints_present)
        return KernelResult(
            KernelOutcome.ACCEPTED,
            Verdict.FAIL,
            steps,
            literals,
            None,
            f"resolution refutation replayed in {steps} steps without re-solving",
            hints_present,
        )

    if decision.transcript is None:
        return _reject(
            "UNKNOWN carries no indeterminacy transcript; a refusal without evidence "
            "is not a layer-4 verdict",
            literals=literals,
            hints=hints_present,
        )
    problem = _check_transcript(certificate)
    if problem is not None:
        return _reject(problem, literals=literals, hints=hints_present)
    return KernelResult(
        KernelOutcome.ACCEPTED,
        Verdict.UNKNOWN,
        decision.transcript.stopped_at_step,
        literals,
        decision.transcript.reason,
        f"indeterminacy transcript accepted: {decision.transcript.reason.value}",
        hints_present,
    )


def violating_subjects(certificate: DecisionCertificate) -> tuple[str, ...]:
    """Subjects named by the clause a tier-``UP`` refutation falsifies.

    For an enumerable universal -- "every ancestor is VALID" -- this is the
    counterexample, and it is why such a claim needs no resolution proof at all.
    """
    proof = certificate.decision.propagation
    if proof is None:
        return ()
    for item in certificate.grounding.clauses:
        if item.clause_index == proof.conflict_clause_index:
            return tuple(sorted(set(item.subjects.values())))
    return ()


# --------------------------------------------------------------------------
# Self-description -- rung 4.7
# --------------------------------------------------------------------------


def reference_descriptor() -> VerifierDescriptor:
    """This kernel's own trust boundary.

    A checker hashing its own source cannot detect its own replacement -- an
    attacker who swaps ``kernel.py`` swaps the hash with it. That is not what
    these hashes are for. They exist so an outside party can compare the value
    published in a certificate against the bytes they downloaded, which is a
    check *they* perform and the declarant cannot forge on their end.

    ``format_fragment`` omits ``SAT-PRESERVING`` because this kernel does not
    implement it. Declaring a fragment one does not implement is how a checker
    silently mis-accepts a construct it never understood.
    """
    import hashlib
    from pathlib import Path

    here = Path(__file__).resolve()

    def digest(*candidates: str) -> str:
        for name in candidates:
            relative = Path(name)
            paths = (
                here.parent / relative,
                Path.cwd() / relative,
                here.parents[3] / relative,
                here.parents[1] / "specifications" / relative.name,
            )
            for path in paths:
                try:
                    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    continue
        return f"UNAVAILABLE:{candidates[0] if candidates else ''}"

    return VerifierDescriptor(
        specification_hash=digest("standard/VSTD-4.md", "standard/LADDER.md"),
        implementation_hash=digest("kernel.py"),
        parser_hash=digest("certificate.py"),
        certificate_format=FORMAT,
        format_fragment="UP,WIDTH-K,RES",
        dependencies=("python-stdlib",),
        deterministic=True,
    )
