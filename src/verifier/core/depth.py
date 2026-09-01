"""Terminology: conjunctive normal form (CNF); grounded decision certificate (GDC);
identifier (ID); unsatisfiable (UNSAT); Verifier Standard (VSTD).

``vstd4_depth`` -- candidate depth over caller-supplied rung references.

VSTD-4 is fourteen rungs, ordered so that each is unstatable without the one
below it. That ordering is not editorial tidiness. Entry to VSTD-5 requires
separately checkable VSTD-4 obligations rather than a declared top-rung reference.
The rung sequence makes those dependencies explicit.

The structural candidate is **computed, never copied from a declared depth**::

    vstd4_depth(claim) = max { k : CNF_4k(claim) is satisfiable }

and the UNSAT certificate at ``k+1`` **is** the explanation of why the claim
cannot climb higher. The candidate-depth calculation certifies its own ceiling
using its own mechanism, and the conflict clause names the missing rung outright.

The encoding is Horn -- assertions ``[j]``, dependencies ``[-k, d]``, absences
``[-j]`` -- so every certificate this module produces is tier ``UP`` and checks
in linear time. The dependency clauses look inert while the numbering is a valid
topological order, and that is exactly the point: reorder the sequence so a rung
depends on one above it and the formula goes unsatisfiable at a low depth,
loudly, instead of quietly certifying a sequence that no longer preserves its
dependencies.

The compatibility producer checks reference presence and rung dependencies. It does not
resolve those references, validate the propositions they allegedly establish, or
check VSTD-1/2/3 preconditions. Its result is therefore a candidate with
``conformance_status = NOT_ESTABLISHED`` and cannot admit VSTD-5. The separate
``establish_vstd4`` path reruns exact evidence-bound prerequisite and rung
mechanisms, then checks the structural witness before it can report established
conformance.

This module *produces* certificates. It is not part of the trusted computing
base; :mod:`verifier.core.kernel` checks what it emits, and the propagation
routine here is deliberately a separate implementation from the kernel's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from .certificate import (
    CertificateHeader,
    ClaimBinding,
    ClaimCoordinate,
    ClauseGrounding,
    CostTier,
    DecisionBlock,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    PropagationStep,
    ResourceBounds,
    UnitPropagationProof,
    VariableGrounding,
    Verdict,
    VerifierDescriptor,
    canonical_digest,
)
from .evidence import (
    BoundProposition,
    EvaluatedProposition,
    MechanismOutcome,
    EvidenceStore,
    VerificationMechanism,
    VerificationSession,
)
from .kernel import KernelOutcome, check as kernel_check

MAX_DEPTH = 14
"""Highest structural candidate depth; not sufficient for VSTD-5 entry."""

DEPTH_KIND = "CANDIDATE"
CONFORMANCE_STATUS = "NOT_ESTABLISHED"


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


def _validate_rung_sequence() -> None:
    for rung in RUNGS:
        for dependency in rung.depends_on:
            if dependency >= rung.index:
                raise ValueError(
                    f"rung {rung.id} depends on rung index {dependency}, which is not "
                    "below it; the rung numbering is no longer a topological order"
                )


_validate_rung_sequence()


@dataclass(frozen=True)
class DepthResult:
    """A computed candidate depth, with certificates for the structural answer.

    ``witness`` certifies consistency of the caller-supplied rung references.
    ``refutation`` certifies why the next structural rung was not reached, and
    its ``blocking_rungs`` name the reason. A
    depth reported without ``refutation`` at anything below :data:`MAX_DEPTH`
    would be a declaration, which is the thing this module exists to avoid. The
    references themselves and prerequisite-profile coordinates are not validated here.
    """

    depth: int
    witness: Optional[DecisionCertificate]
    refutation: Optional[DecisionCertificate]
    blocking_rungs: tuple[str, ...]

    @property
    def admits_vstd5(self) -> bool:
        return False

    @property
    def conformance_status(self) -> str:
        return CONFORMANCE_STATUS

    def to_dict(self) -> dict[str, object]:
        return {
            "depth": self.depth,
            "depth_kind": DEPTH_KIND,
            "conformance_status": self.conformance_status,
            "max_depth": MAX_DEPTH,
            "admits_vstd5": self.admits_vstd5,
            "blocking_rungs": list(self.blocking_rungs),
            "witness_digest": None if self.witness is None else self.witness.digest(),
            "refutation_digest": None if self.refutation is None else self.refutation.digest(),
        }


@dataclass(frozen=True)
class EvidenceBoundDepthResult:
    """VSTD-4 result obtained by rerunning every bound evidence mechanism.

    The structural candidate is retained as an audit artifact.  Normative
    conformance is established only when the VSTD-1, VSTD-2, and VSTD-3
    preconditions and all fourteen rung propositions pass under their exact
    bindings, and the candidate witness itself checks in the independent
    kernel.
    """

    candidate: DepthResult
    prerequisite_evaluations: tuple[tuple[int, EvaluatedProposition], ...]
    rung_evaluations: tuple[tuple[str, EvaluatedProposition], ...]
    binding_errors: tuple[str, ...]
    kernel_outcome: str
    claim_id: str

    @property
    def depth(self) -> int:
        return self.candidate.depth

    @property
    def witness(self) -> Optional[DecisionCertificate]:
        return self.candidate.witness

    @property
    def refutation(self) -> Optional[DecisionCertificate]:
        return self.candidate.refutation

    @property
    def blocking_rungs(self) -> tuple[str, ...]:
        return self.candidate.blocking_rungs

    @property
    def conformance_status(self) -> str:
        if self.binding_errors or self.depth != MAX_DEPTH:
            return CONFORMANCE_STATUS
        if self.kernel_outcome != KernelOutcome.ACCEPTED.value:
            return CONFORMANCE_STATUS
        if any(not result.passed for _, result in self.prerequisite_evaluations):
            return CONFORMANCE_STATUS
        if any(not result.passed for _, result in self.rung_evaluations):
            return CONFORMANCE_STATUS
        if len(self.prerequisite_evaluations) != 3 or len(self.rung_evaluations) != MAX_DEPTH:
            return CONFORMANCE_STATUS
        return "ESTABLISHED"

    @property
    def admits_vstd5(self) -> bool:
        return self.conformance_status == "ESTABLISHED"

    def to_dict(self) -> dict[str, object]:
        payload = self.candidate.to_dict()
        payload.update(
            {
                "depth_kind": "EVIDENCE_BOUND",
                "conformance_status": self.conformance_status,
                "admits_vstd5": self.admits_vstd5,
                "prerequisite_evaluations": {
                    str(profile): result.to_dict()
                    for profile, result in self.prerequisite_evaluations
                },
                "rung_evaluations": {
                    rung_id: result.to_dict()
                    for rung_id, result in self.rung_evaluations
                },
                "binding_errors": list(self.binding_errors),
                "kernel_outcome": self.kernel_outcome,
                "claim_id": self.claim_id,
            }
        )
        return payload


def require_vstd5_entry(
    result: DepthResult | EvidenceBoundDepthResult,
) -> EvidenceBoundDepthResult:
    """Reject the current unbound candidate result at the VSTD-5 boundary.

    A structural candidate over caller-supplied references is not normative
    VSTD-4 conformance. The evidence-binding implementation uses a distinct
    result type and gate; it never makes this candidate stronger by setting
    another declaration field.
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
    if not isinstance(result, EvidenceBoundDepthResult):
        raise VSTD5EntryError(
            "VSTD-5 requires established VSTD-4 conformance; this structural "
            f"candidate has conformance_status {result.conformance_status}"
        )
    if not result.admits_vstd5:
        detail = "; ".join(result.binding_errors) or "one or more mechanisms did not pass"
        raise VSTD5EntryError(
            "VSTD-5 requires established VSTD-4 conformance; evidence-bound "
            f"result is {result.conformance_status}: {detail}"
        )
    return result


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------


def _encode(
    candidate_depth: int, evidence: Mapping[str, str], claim_id: str
) -> tuple[tuple[tuple[int, ...], ...], Grounding]:
    """CNF_4k, together with the grounding that says what its variables mean."""
    formula: list[tuple[int, ...]] = []
    clauses: list[ClauseGrounding] = []

    def emit(literals: Sequence[int], rule: EncodingRule, bindings, subjects) -> None:
        clauses.append(ClauseGrounding(len(formula), rule.rule_id, dict(bindings), dict(subjects)))
        formula.append(tuple(literals))

    for rung in RUNGS[:candidate_depth]:
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
    candidate_depth: int, evidence: Mapping[str, str], claim_id: str, binding: ClaimBinding
) -> tuple[DecisionCertificate, tuple[str, ...]]:
    formula, grounding = _encode(candidate_depth, evidence, claim_id)
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
    """Compute a structural candidate depth from caller-supplied references.

    ``evidence`` maps a rung id (``"4.1"`` .. ``"4.14"``) to the content address
    claimed for the artifact establishing it. This function checks only whether
    each value is nonempty; it does not retrieve the artifact or validate the
    rung proposition. An absent or empty entry blocks the candidate, and the
    resulting UNSAT certificate at the next candidate depth names it.

    Descends from :data:`MAX_DEPTH`, so the first satisfiable candidate depth found is the
    depth -- the rung sequence is monotone by construction, but searching downward
    means a fully-conformant claim costs one solve rather than fourteen.
    """
    unknown = set(evidence) - set(BY_ID)
    if unknown:
        raise ValueError(f"evidence names rungs that do not exist: {sorted(unknown)}")

    for candidate_depth in range(MAX_DEPTH, 0, -1):
        certificate, blocking = _certify(candidate_depth, evidence, claim_id, binding)
        if certificate.header.verdict is Verdict.PASS:
            refutation: Optional[DecisionCertificate] = None
            blocked: tuple[str, ...] = ()
            if candidate_depth < MAX_DEPTH:
                refutation, blocked = _certify(
                    candidate_depth + 1, evidence, claim_id, binding
                )
            return DepthResult(candidate_depth, certificate, refutation, blocked)

    refutation, blocked = _certify(1, evidence, claim_id, binding)
    return DepthResult(0, None, refutation, blocked)


def establish_vstd4(
    rung_evidence: Mapping[str, BoundProposition],
    *,
    prerequisite_evidence: Mapping[int, BoundProposition],
    session: VerificationSession,
    claim_id: str,
    binding: ClaimBinding,
) -> EvidenceBoundDepthResult:
    """Rerun evidence mechanisms and establish VSTD-4 only if all pass.

    Expected predicates are ``vstd.object_profile.1`` through
    ``vstd.object_profile.3`` and ``vstd4.rung.4.1`` through
    ``vstd4.rung.4.14``.  Every proposition must target ``claim_id``, expect the
    Boolean value ``True``, and carry ``claim_binding_digest`` equal to the exact
    :class:`ClaimBinding` used for the structural certificate.  Mismatches are
    excluded rather than evaluated, so field naming or neighboring evidence
    cannot earn a rung.
    """

    errors: list[str] = []
    prerequisite_results: list[tuple[int, EvaluatedProposition]] = []
    rung_results: list[tuple[str, EvaluatedProposition]] = []
    exact_binding = binding.digest()

    unknown_profiles = set(prerequisite_evidence) - {1, 2, 3}
    if unknown_profiles:
        errors.append(f"unknown prerequisite profiles: {sorted(unknown_profiles)}")
    unknown_rungs = set(rung_evidence) - set(BY_ID)
    if unknown_rungs:
        errors.append(f"unknown VSTD-4 rungs: {sorted(unknown_rungs)}")

    def binding_error(
        proposition: BoundProposition, expected_predicate: str, label: str
    ) -> Optional[str]:
        if proposition.subject_id != claim_id:
            return f"{label} targets {proposition.subject_id!r}, not {claim_id!r}"
        if proposition.predicate != expected_predicate:
            return (
                f"{label} binds predicate {proposition.predicate!r}, not "
                f"{expected_predicate!r}"
            )
        if proposition.expected is not True:
            return f"{label} does not bind the required Boolean true proposition"
        if proposition.parameters.get("claim_binding_digest") != exact_binding:
            return f"{label} does not bind the exact VSTD-4 claim commitment"
        return None

    for profile in (1, 2, 3):
        proposition = prerequisite_evidence.get(profile)
        if proposition is None:
            errors.append(f"missing VSTD-{profile} prerequisite evidence")
            continue
        issue = binding_error(proposition, f"vstd.object_profile.{profile}", f"VSTD-{profile}")
        if issue:
            errors.append(issue)
            continue
        prerequisite_results.append((profile, session.evaluate(proposition)))

    passed_refs: dict[str, str] = {}
    for rung in RUNGS:
        proposition = rung_evidence.get(rung.id)
        if proposition is None:
            errors.append(f"missing rung {rung.id} evidence")
            continue
        issue = binding_error(proposition, f"vstd4.rung.{rung.id}", f"rung {rung.id}")
        if issue:
            errors.append(issue)
            continue
        result = session.evaluate(proposition)
        rung_results.append((rung.id, result))
        if result.outcome is MechanismOutcome.PASS:
            passed_refs[rung.id] = "sha256:" + proposition.digest()

    candidate = vstd4_depth(passed_refs, claim_id=claim_id, binding=binding)
    kernel_outcome = KernelOutcome.REJECTED.value
    if candidate.witness is not None:
        kernel_outcome = kernel_check(candidate.witness, binding=binding).outcome.value

    return EvidenceBoundDepthResult(
        candidate,
        tuple(prerequisite_results),
        tuple(rung_results),
        tuple(errors),
        kernel_outcome,
        claim_id,
    )


def build_evidence_bound_vstd4_receipt(
    result: EvidenceBoundDepthResult,
    *,
    receipt_id: str,
    claim_id: str,
    binding: ClaimBinding,
    prerequisite_evidence: Mapping[int, BoundProposition],
    rung_evidence: Mapping[str, BoundProposition],
    session: VerificationSession,
    status: str = "VALID",
) -> dict[str, object]:
    """Serialize every input needed to rerun an evidence-bound VSTD-4 result."""
    recomputed = establish_vstd4(
        rung_evidence,
        prerequisite_evidence=prerequisite_evidence,
        session=session,
        claim_id=claim_id,
        binding=binding,
    )
    if canonical_digest(recomputed.to_dict()) != canonical_digest(result.to_dict()):
        raise ValueError("VSTD-4 result does not match the supplied replay inputs")
    all_refs = tuple(
        sorted(
            {
                reference
                for proposition in (*prerequisite_evidence.values(), *rung_evidence.values())
                for reference in proposition.evidence_refs
            }
        )
    )
    return {
        "schema_version": "VSTD-4",
        "receipt_id": receipt_id,
        "claim_id": claim_id,
        "binding": binding.to_dict(),
        "vstd4_depth": result.depth,
        "depth_kind": "EVIDENCE_BOUND",
        "conformance_status": result.conformance_status,
        "rung_evidence": {
            rung_id: "sha256:" + proposition.digest()
            for rung_id, proposition in sorted(rung_evidence.items())
        },
        "witness": None if result.witness is None else result.witness.to_dict(),
        "ceiling_refutation": (
            None if result.refutation is None else result.refutation.to_dict()
        ),
        "blocking_rungs": list(result.blocking_rungs),
        "status": status,
        "kernel_outcome": result.kernel_outcome,
        "evidence_bindings": {
            "prerequisites": {
                str(profile): proposition.to_dict()
                for profile, proposition in sorted(prerequisite_evidence.items())
            },
            "rungs": {
                rung_id: proposition.to_dict()
                for rung_id, proposition in sorted(rung_evidence.items())
            },
        },
        "evidence_payloads": session.evidence.export_base64(all_refs),
    }


def claim_binding_from_dict(data: Mapping[str, object]) -> ClaimBinding:
    """Reconstruct the exact VSTD-4 claim binding carried by a receipt."""

    coordinate = data["coordinate"]
    verifier = data["verifier"]
    bounds = data["bounds"]
    if not isinstance(coordinate, Mapping) or not isinstance(verifier, Mapping) or not isinstance(bounds, Mapping):
        raise ValueError("receipt ClaimBinding blocks must be objects")
    return ClaimBinding(
        str(data["claim"]),
        ClaimCoordinate(
            str(coordinate["subject"]),
            str(coordinate["predicate"]),
            {str(key): str(value) for key, value in dict(coordinate.get("parameters", {})).items()},
        ),
        str(data["policy_root"]),
        str(data["evidence_root"]),
        VerifierDescriptor(
            str(verifier["specification_hash"]),
            str(verifier["implementation_hash"]),
            str(verifier["parser_hash"]),
            str(verifier.get("certificate_format", "VSTD4-GDC-1")),
            str(verifier.get("format_fragment", "UP,WIDTH-K,RES")),
            tuple(str(item) for item in verifier.get("dependencies", ())),
            bool(verifier.get("deterministic", True)),
        ),
        ResourceBounds(
            int(bounds["verification_cost_bound"]),
            int(bounds["memory_bound"]),
            int(bounds["certificate_size_bound"]),
        ),
        str(data.get("prior_commitment", "")),
    )


def recheck_evidence_bound_vstd4_receipt(
    receipt: Mapping[str, object],
    *,
    mechanisms: Sequence[VerificationMechanism],
) -> EvidenceBoundDepthResult:
    """Reconstruct evidence bytes and rerun an evidence-bound VSTD-4 receipt."""
    if receipt.get("schema_version") != "VSTD-4":
        raise ValueError("not a VSTD-4 receipt")
    if receipt.get("depth_kind") != "EVIDENCE_BOUND":
        raise ValueError("receipt is not evidence-bound")
    payloads = receipt.get("evidence_payloads")
    bindings = receipt.get("evidence_bindings")
    binding_data = receipt.get("binding")
    if not isinstance(payloads, Mapping) or not isinstance(bindings, Mapping) or not isinstance(binding_data, Mapping):
        raise ValueError("evidence-bound receipt is missing replay inputs")
    store = EvidenceStore()
    store.import_base64({str(key): str(value) for key, value in payloads.items()})
    session = VerificationSession(store)
    for mechanism in mechanisms:
        session.register(mechanism)
    prerequisites_data = bindings.get("prerequisites")
    rungs_data = bindings.get("rungs")
    if not isinstance(prerequisites_data, Mapping) or not isinstance(rungs_data, Mapping):
        raise ValueError("evidence binding maps are missing")
    prerequisites = {
        int(profile): BoundProposition.from_dict(proposition)
        for profile, proposition in prerequisites_data.items()
        if isinstance(proposition, Mapping)
    }
    rungs = {
        str(rung_id): BoundProposition.from_dict(proposition)
        for rung_id, proposition in rungs_data.items()
        if isinstance(proposition, Mapping)
    }
    binding = claim_binding_from_dict(binding_data)
    result = establish_vstd4(
        rungs,
        prerequisite_evidence=prerequisites,
        session=session,
        claim_id=str(receipt["claim_id"]),
        binding=binding,
    )
    observed = result.to_dict()
    comparisons = {
        "vstd4_depth": observed["depth"],
        "conformance_status": observed["conformance_status"],
        "blocking_rungs": observed["blocking_rungs"],
        "kernel_outcome": observed["kernel_outcome"],
    }
    for field, value in comparisons.items():
        if receipt.get(field) != value:
            raise ValueError(f"recomputed VSTD-4 field does not match receipt: {field}")
    for field, certificate in (
        ("witness", result.witness),
        ("ceiling_refutation", result.refutation),
    ):
        expected = receipt.get(field)
        expected_digest = None if expected is None else canonical_digest(expected)
        observed_digest = None if certificate is None else certificate.digest()
        if expected_digest != observed_digest:
            raise ValueError(f"recomputed VSTD-4 {field} does not match receipt")
    return result
