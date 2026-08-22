"""``vstd4_depth`` -- how far up the layer-4 ladder a claim actually got.

VSTD-4 is fourteen rungs, ordered so that each is unstatable without the one
below it. That ordering is not editorial tidiness. Standing up a genuinely
external verification node -- VSTD-5 -- must be *computationally costly*,
because verification is the new scaling, and layer 4 is where the cost is paid.
The ladder makes the cost curve explicit instead of letting an implementer
declare the top rung and skip the climb.

So the depth is **computed, never declared**::

    vstd4_depth(claim) = max { k : CNF_4k(claim) is satisfiable }

and the UNSAT certificate at ``k+1`` **is** the explanation of why the claim
cannot climb higher. The layer certifies its own ceiling using its own
mechanism, and the conflict clause of that certificate names the missing rung
outright.

The encoding is Horn -- assertions ``[j]``, dependencies ``[-k, d]``, absences
``[-j]`` -- so every certificate this module produces is tier ``UP`` and checks
in linear time. The dependency clauses look inert while the numbering is a valid
topological order, and that is exactly the point: reorder the ladder so a rung
depends on one above it and the formula goes unsatisfiable at a low depth,
loudly, instead of quietly certifying a ladder that is no longer a ladder.

This module *produces* certificates. It is not part of the trusted computing
base; :mod:`verifiable.core.kernel` checks what it emits, and the propagation
routine here is deliberately a separate implementation from the kernel's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from .certificate import (
    CertificateHeader,
    ClaimBinding,
    ClauseGrounding,
    CostTier,
    DecisionBlock,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    PropagationStep,
    UnitPropagationProof,
    VariableGrounding,
    Verdict,
)

MAX_DEPTH = 14
"""Entry condition for VSTD-5: ``vstd4_depth(claim) == 14``."""


class VSTD5EntryError(RuntimeError):
    """A caller attempted witness corroboration before completing VSTD-4."""


@dataclass(frozen=True)
class Rung:
    index: int
    id: str
    name: str
    requirement: str
    depends_on: tuple[int, ...]


RUNGS: tuple[Rung, ...] = (
    Rung(1, "4.1", "Decision certification",
         "PASS, FAIL and UNKNOWN each carry a checkable artifact", ()),
    Rung(2, "4.2", "Semantic binding",
         "the certificate proves the exact declared claim coordinate", (1,)),
    Rung(3, "4.3", "Anti-equivocation",
         "claim, coordinate, policy, evidence, verifier, bounds and prior "
         "commitment bind into one digest C", (2,)),
    Rung(4, "4.4", "Portable verification",
         "checking needs no post-verdict cooperation from the declarant", (3,)),
    Rung(5, "4.5", "Bounded verification",
         "declared cost, memory and size bounds, enforced by the checker on itself", (4,)),
    Rung(6, "4.6", "Re-derivability",
         "no undeclared hidden state, unpinned dependency, local path, wall-clock "
         "read or ambient entropy is verdict-material", (4,)),
    Rung(7, "4.7", "Minimal trusted checker",
         "certificate semantics implementable with zero shared verdict-producing code", (5,)),
    Rung(8, "4.8", "Availability",
         "verdict-critical artifacts are AVAILABLE, PORTABLE or SELF_CONTAINED, "
         "not merely IDENTIFIED", (6,)),
    Rung(9, "4.9", "Disclosure-safe checkability",
         "confidential evidence still satisfies a declared verification interface", (8,)),
    Rung(10, "4.10", "Explicit refutation surface",
         "machine-readable admissible_refutations and excluded_claims", (2,)),
    Rung(11, "4.11", "Prior commitment",
         "a PrecommitmentEnvelope over every verdict-material degree of freedom", (10,)),
    Rung(12, "4.12", "Challenge handling",
         "valid counterevidence deterministically changes claim status", (10, 1)),
    Rung(13, "4.13", "Monotonic degradation",
         "weakening evidence can never preserve an unsupported verdict", (12, 8)),
    Rung(14, "4.14", "Compositionality",
         "a RefutabilityClosure states how refutability propagates through "
         "transformations", tuple(range(1, 14))),
)

BY_ID: dict[str, Rung] = {rung.id: rung for rung in RUNGS}

RULE_ASSERTED = EncodingRule("RULE:RUNG_ASSERTED", ("rung",), ((1, "rung"),))
RULE_ABSENT = EncodingRule("RULE:RUNG_ABSENT", ("rung",), ((-1, "rung"),))
RULE_REQUIRES = EncodingRule(
    "RULE:RUNG_REQUIRES", ("rung", "dependency"), ((-1, "rung"), (1, "dependency"))
)
RULES = (RULE_ASSERTED, RULE_ABSENT, RULE_REQUIRES)


def _validate_ladder() -> None:
    for rung in RUNGS:
        for dependency in rung.depends_on:
            if dependency >= rung.index:
                raise ValueError(
                    f"rung {rung.id} depends on rung index {dependency}, which is not "
                    "below it; the ladder numbering is no longer a topological order"
                )


_validate_ladder()


@dataclass(frozen=True)
class DepthResult:
    """A computed depth, with the evidence for both halves of the answer.

    ``witness`` certifies the rungs that were climbed. ``refutation`` certifies
    why the next one was not, and its ``blocking_rungs`` name the reason. A
    depth reported without ``refutation`` at anything below :data:`MAX_DEPTH`
    would be a declaration, which is the thing this module exists to avoid.
    """

    depth: int
    witness: Optional[DecisionCertificate]
    refutation: Optional[DecisionCertificate]
    blocking_rungs: tuple[str, ...]

    @property
    def admits_vstd5(self) -> bool:
        return self.depth >= MAX_DEPTH

    def to_dict(self) -> dict[str, object]:
        return {
            "depth": self.depth,
            "max_depth": MAX_DEPTH,
            "admits_vstd5": self.admits_vstd5,
            "blocking_rungs": list(self.blocking_rungs),
            "witness_digest": None if self.witness is None else self.witness.digest(),
            "refutation_digest": None if self.refutation is None else self.refutation.digest(),
        }


def require_vstd5_entry(result: DepthResult) -> DepthResult:
    """Fail closed unless ``result`` carries the complete layer-4 witness.

    VSTD-5 is draft, but its entry boundary is not: no future witness transport
    may admit a partial layer-4 claim.  Returning the checked result makes this
    function usable as the first line of any later VSTD-5 procedure without
    turning the gate into a second, declarative depth field.
    """
    if result.depth != MAX_DEPTH or result.witness is None:
        raise VSTD5EntryError(
            f"VSTD-5 requires computed vstd4_depth == {MAX_DEPTH}; "
            f"the supplied result has depth {result.depth}"
        )
    if result.witness.header.verdict is not Verdict.PASS:
        raise VSTD5EntryError("VSTD-5 entry witness does not certify PASS")
    if result.refutation is not None or result.blocking_rungs:
        raise VSTD5EntryError(
            "VSTD-5 entry result carries a ceiling refutation or blocking rung"
        )
    return result


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------


def _encode(
    level: int, evidence: Mapping[str, str], claim_id: str
) -> tuple[tuple[tuple[int, ...], ...], Grounding]:
    """CNF_4k, together with the grounding that says what its variables mean."""
    formula: list[tuple[int, ...]] = []
    clauses: list[ClauseGrounding] = []

    def emit(literals: Sequence[int], rule: EncodingRule, bindings, subjects) -> None:
        clauses.append(ClauseGrounding(len(formula), rule.rule_id, dict(bindings), dict(subjects)))
        formula.append(tuple(literals))

    for rung in RUNGS[:level]:
        emit([rung.index], RULE_ASSERTED, {"rung": rung.index}, {"rung": claim_id})

    for rung in RUNGS:
        for dependency in rung.depends_on:
            emit(
                [-rung.index, dependency],
                RULE_REQUIRES,
                {"rung": rung.index, "dependency": dependency},
                {"rung": claim_id, "dependency": claim_id},
            )

    for rung in RUNGS:
        if not evidence.get(rung.id):
            emit([-rung.index], RULE_ABSENT, {"rung": rung.index}, {"rung": claim_id})

    variables = tuple(
        VariableGrounding(
            rung.index,
            GroundedFact(claim_id, f"vstd4_rung_{rung.id}", evidence.get(rung.id) or "ABSENT"),
        )
        for rung in RUNGS
    )
    return tuple(formula), Grounding(variables, tuple(clauses), RULES)


# --------------------------------------------------------------------------
# Producer-side propagation -- independent of the kernel's, by design
# --------------------------------------------------------------------------


def _propagate(
    formula: Sequence[Sequence[int]],
) -> tuple[list[PropagationStep], Optional[int], dict[int, bool]]:
    assignment: dict[int, bool] = {}
    steps: list[PropagationStep] = []
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
        steps.append(PropagationStep(index, literal))


def _certify(
    level: int, evidence: Mapping[str, str], claim_id: str, binding: ClaimBinding
) -> tuple[DecisionCertificate, tuple[str, ...]]:
    formula, grounding = _encode(level, evidence, claim_id)
    steps, conflict, assignment = _propagate(formula)
    literals = sum(len(clause) for clause in formula)

    if conflict is None:
        model = {rung.index: assignment.get(rung.index, False) for rung in RUNGS}
        for index, clause in enumerate(formula):
            if not any((literal > 0) == model[abs(literal)] for literal in clause):
                raise AssertionError(f"produced model falsifies clause {index}")
        header = CertificateHeader(
            Verdict.PASS, CostTier.UP, MAX_DEPTH, len(formula), literals, 0, binding.digest()
        )
        return (
            DecisionCertificate(header, formula, grounding, DecisionBlock(model=model)),
            (),
        )

    header = CertificateHeader(
        Verdict.FAIL, CostTier.UP, MAX_DEPTH, len(formula), literals, len(steps), binding.digest()
    )
    proof = UnitPropagationProof(tuple(steps), conflict)
    blocking = tuple(
        rung.id
        for rung in RUNGS
        if rung.index in {abs(literal) for literal in formula[conflict]}
    )
    return (
        DecisionCertificate(header, formula, grounding, DecisionBlock(propagation=proof)),
        blocking,
    )


def vstd4_depth(
    evidence: Mapping[str, str],
    *,
    claim_id: str,
    binding: ClaimBinding,
) -> DepthResult:
    """Compute how far up the layer-4 ladder ``evidence`` carries a claim.

    ``evidence`` maps a rung id (``"4.1"`` .. ``"4.14"``) to the content address
    of the artifact establishing it. An absent or empty entry means the rung is
    not established, and the resulting UNSAT certificate at the next level names
    it.

    Descends from :data:`MAX_DEPTH`, so the first satisfiable level found is the
    depth -- the ladder is monotone by construction, but searching downward
    means a fully-conformant claim costs one solve rather than fourteen.
    """
    unknown = set(evidence) - set(BY_ID)
    if unknown:
        raise ValueError(f"evidence names rungs that do not exist: {sorted(unknown)}")

    for level in range(MAX_DEPTH, 0, -1):
        certificate, blocking = _certify(level, evidence, claim_id, binding)
        if certificate.header.verdict is Verdict.PASS:
            refutation: Optional[DecisionCertificate] = None
            blocked: tuple[str, ...] = ()
            if level < MAX_DEPTH:
                refutation, blocked = _certify(level + 1, evidence, claim_id, binding)
            return DepthResult(level, certificate, refutation, blocked)

    refutation, blocked = _certify(1, evidence, claim_id, binding)
    return DepthResult(0, None, refutation, blocked)
