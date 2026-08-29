"""Terminology: American Standard Code for Information Interchange (ASCII);
conjunctive normal form (CNF); deletion resolution asymmetric tautology (DRAT);
Boolean satisfiability problem (SAT); flexible SAT proof format (FRAT);
grounded decision certificate (GDC); GRAT proof format (GRAT); JavaScript Object Notation (JSON);
linear resolution asymmetric tautology (LRAT); resolution asymmetric tautology (RAT);
reverse unit propagation (RUP); Unicode Transformation Format, 8-bit (UTF-8);
Verifier Standard (VSTD).

``VSTD4-GDC-1`` -- Grounded Decision Certificates for the VSTD-4 Refutability profile.

Competition proof formats (DRAT, LRAT, GRAT, FRAT) answer exactly one question:
*is this large formula really unsatisfiable?* They are deliberately
claim-agnostic, because in a solver competition the formula **is** the claim.

VSTD's risk profile is the opposite. Its formulas are small and structured --
every CNF currently produced by :mod:`verifier.data.policy` is Horn -- and
essentially all of the danger lives in whether the formula means what the claim
says. A flawless resolution proof of the wrong formula is worthless, and no
competition format can detect that, because none of them knows what a claim is.

``VSTD4-GDC-1`` therefore carries four blocks:

``header``
    Verdict, cost tier, and counts. Because a certificate is a straight-line
    sequence referencing only previously-defined identifiers, its checking cost
    is derivable from the header alone -- so a checker can refuse over-budget
    work *before starting it* rather than measuring as it goes.
``grounding``
    Each variable is bound to a content-addressed fact and each clause to an
    instance of a named encoding rule. This is the block nothing else carries,
    and it is what makes "correct proof of the wrong formula" detectable.
``decision``
    ``PASS`` carries a model, ``FAIL`` carries a propagation trace or a
    resolution proof, ``UNKNOWN`` carries a bounded transcript. All three
    verdicts are evidence-bearing.
``hints``
    An untrusted, strippable accelerator. Soundness MUST NOT depend on any
    field whose corruption the checker cannot detect, so the kernel reaches a
    verdict without consulting hints at all.

This module holds records and canonical serialization only. It deliberately
contains no verdict-producing logic and imports nothing from the solver
modules, so that it may sit inside the trusted computing base alongside
:mod:`verifier.core.kernel`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Mapping, Optional, Sequence

FORMAT = "VSTD4-GDC-1"


class CostTier(str, Enum):
    """Declared checking-cost class. See :func:`verifier.core.kernel.tightest_tier`."""

    UP = "UP"
    """Horn formula, refutable by unit propagation alone. Linear; the bound is a theorem."""

    WIDTH_K = "WIDTH-K"
    """Resolution with every derived clause of width <= ``header.width``."""

    RES = "RES"
    """General resolution. Exponential worst case; the bound is declared, not proven."""

    SAT_PRESERVING = "SAT-PRESERVING"
    """RAT-class additions, for solvers that inprocess. Specified, not implemented here."""


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class IndeterminacyReason(str, Enum):
    """Why neither conclusion is justified. An ``UNKNOWN`` is never a pass."""

    PROOF_BOUND_EXCEEDED = "PROOF_BOUND_EXCEEDED"
    DEPTH_BOUND_EXCEEDED = "DEPTH_BOUND_EXCEEDED"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    DISCLOSURE_UNSATISFIABLE = "DISCLOSURE_UNSATISFIABLE"
    ARTIFACT_UNRETRIEVABLE = "ARTIFACT_UNRETRIEVABLE"
    VERIFIER_UNAVAILABLE = "VERIFIER_UNAVAILABLE"


class CertificateError(ValueError):
    """Raised when a certificate cannot be decoded at all."""


# --------------------------------------------------------------------------
# Canonical serialization
# --------------------------------------------------------------------------
#
# Deliberately re-stated here rather than imported from
# ``verifier.core.receipt``: that module imports the solver-side auditor, and
# nothing in the trusted checking path may depend on verdict-producing code.
# The rules are identical (sorted keys, compact separators, ASCII), so bytes
# agree with the rest of the project.


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def normalize_clause(literals: Sequence[int]) -> tuple[int, ...]:
    """Order literals so that identical clauses serialize identically."""
    seen: set[int] = set()
    out: list[int] = []
    for literal in literals:
        literal = int(literal)
        if literal == 0:
            raise CertificateError("0 is not a literal")
        if literal not in seen:
            seen.add(literal)
            out.append(literal)
    return tuple(sorted(out, key=lambda item: (abs(item), item)))


# --------------------------------------------------------------------------
# Binding -- rung 4.3
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimCoordinate:
    """Where a claim applies. VSTD-2 defines this surface; VSTD-4 binds it."""

    subject: str
    predicate: str
    parameters: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "predicate": self.predicate,
            "parameters": dict(sorted(self.parameters.items())),
        }


@dataclass(frozen=True)
class ResourceBounds:
    """Rung 4.5 resource ceilings enforced before decision checking.

    ``verification_cost_bound`` counts formula literals plus proof steps.
    ``memory_bound`` counts simultaneously retained clauses in the reference
    streaming checker. ``certificate_size_bound`` counts canonical bytes; zero
    means that no size ceiling was committed by this legacy producer.
    """

    verification_cost_bound: int
    memory_bound: int
    certificate_size_bound: int

    def __post_init__(self) -> None:
        if min(
            self.verification_cost_bound,
            self.memory_bound,
            self.certificate_size_bound,
        ) < 0:
            raise CertificateError("resource bounds cannot be negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_cost_bound": self.verification_cost_bound,
            "memory_bound": self.memory_bound,
            "certificate_size_bound": self.certificate_size_bound,
        }


@dataclass(frozen=True)
class VerifierDescriptor:
    """Rung 4.7 -- the checker's own trust boundary, stated in hashes not promises.

    ``format_fragment`` exists so a checker can be honest about what it does not
    implement. Silently mis-accepting a construct the checker does not
    understand is the serialized-format form of semantic mismatch.
    """

    specification_hash: str
    implementation_hash: str
    parser_hash: str
    certificate_format: str = FORMAT
    format_fragment: str = "UP,WIDTH-K,RES"
    dependencies: tuple[str, ...] = ()
    deterministic: bool = True

    def implements(self, tier: "CostTier") -> bool:
        return tier.value in {item.strip() for item in self.format_fragment.split(",")}

    def to_dict(self) -> dict[str, Any]:
        return {
            "specification_hash": self.specification_hash,
            "implementation_hash": self.implementation_hash,
            "parser_hash": self.parser_hash,
            "certificate_format": self.certificate_format,
            "format_fragment": self.format_fragment,
            "dependencies": list(self.dependencies),
            "deterministic": self.deterministic,
        }


@dataclass(frozen=True)
class ClaimBinding:
    """The anti-equivocation commitment ``C`` of rung 4.3.

    ``C = H(claim || coordinate || policy_root || evidence_root || verifier ||
    resource_bounds || prior_commitment)``

    Every certificate carries ``C``, so a declarant cannot show claim A with
    evidence X to one checker and claim A' with evidence Y to another while
    pretending both inspect the same assertion.
    """

    claim: str
    coordinate: ClaimCoordinate
    policy_root: str
    evidence_root: str
    verifier: VerifierDescriptor
    bounds: ResourceBounds
    prior_commitment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "coordinate": self.coordinate.to_dict(),
            "policy_root": self.policy_root,
            "evidence_root": self.evidence_root,
            "verifier": self.verifier.to_dict(),
            "bounds": self.bounds.to_dict(),
            "prior_commitment": self.prior_commitment,
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())


# --------------------------------------------------------------------------
# Grounding -- rung 4.2
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GroundedFact:
    """``predicate(subject) == value``, e.g. ``status(artifact:sha256:ab..) == VALID``."""

    subject: str
    predicate: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "predicate": self.predicate, "value": self.value}


@dataclass(frozen=True)
class VariableGrounding:
    var: int
    fact: GroundedFact

    def to_dict(self) -> dict[str, Any]:
        return {"var": self.var, "fact": self.fact.to_dict()}


@dataclass(frozen=True)
class EncodingRule:
    """A clause *schema* over role-named variables.

    The template is purely syntactic -- a sequence of ``(polarity, role)`` pairs
    -- so the kernel instantiates and compares it without executing anything.
    """

    rule_id: str
    roles: tuple[str, ...]
    template: tuple[tuple[int, str], ...]

    def instantiate(self, bindings: Mapping[str, int]) -> tuple[int, ...]:
        literals: list[int] = []
        for polarity, role in self.template:
            if role not in bindings:
                raise CertificateError(f"rule {self.rule_id} has no binding for role {role!r}")
            literals.append(polarity * bindings[role])
        return normalize_clause(literals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "roles": list(self.roles),
            "template": [[polarity, role] for polarity, role in self.template],
        }


@dataclass(frozen=True)
class ClauseGrounding:
    """Justifies one clause as an instance of a named rule over named subjects.

    ``subjects`` is what makes the keystone check possible: the kernel confirms
    that the variable bound to each role is grounded in a fact *about that same
    subject*. Without it, a certificate could prove a perfectly valid statement
    about the wrong artifact.
    """

    clause_index: int
    rule_id: str
    bindings: dict[str, int]
    subjects: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "clause_index": self.clause_index,
            "rule_id": self.rule_id,
            "bindings": dict(sorted(self.bindings.items())),
            "subjects": dict(sorted(self.subjects.items())),
        }


@dataclass(frozen=True)
class Grounding:
    variables: tuple[VariableGrounding, ...]
    clauses: tuple[ClauseGrounding, ...]
    rules: tuple[EncodingRule, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "variables": [item.to_dict() for item in self.variables],
            "clauses": [item.to_dict() for item in self.clauses],
            "rules": [item.to_dict() for item in self.rules],
        }

    def root(self) -> str:
        return canonical_digest(self.to_dict())


# --------------------------------------------------------------------------
# Decision blocks -- rung 4.1
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PropagationStep:
    """One forced assignment, justified by the clause that forced it."""

    clause_index: int
    forced: int

    def to_dict(self) -> dict[str, Any]:
        return {"clause_index": self.clause_index, "forced": self.forced}


@dataclass(frozen=True)
class UnitPropagationProof:
    """A tier-``UP`` refutation: propagate, in this order, until a clause is falsified.

    For an enumerable universal ("every ancestor is VALID") this *is* the
    counterexample witness -- the grounding of ``conflict_clause_index`` names
    the offending subject directly. No resolution proof is needed or admitted.
    """

    steps: tuple[PropagationStep, ...]
    conflict_clause_index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [step.to_dict() for step in self.steps],
            "conflict_clause_index": self.conflict_clause_index,
        }


@dataclass(frozen=True)
class ResolutionProof:
    """A tier-``RES`` refutation: derived clauses, each RUP, ending in the empty clause."""

    steps: tuple[tuple[int, ...], ...]

    def to_dict(self) -> dict[str, Any]:
        return {"steps": [list(step) for step in self.steps]}


@dataclass(frozen=True)
class IndeterminacyTranscript:
    """Rung 4.1's third arm.

    This does **not** assert that no proof exists. It asserts the far weaker and
    checkable claim that *the declared budget was exhausted at this exact
    deterministic point*, which a checker confirms by replaying to that point
    and observing the stop.
    """

    reason: IndeterminacyReason
    formula_digest: str
    declared_bound: int
    observed_cost: int
    stopped_at_step: int = 0
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason.value,
            "formula_digest": self.formula_digest,
            "declared_bound": self.declared_bound,
            "observed_cost": self.observed_cost,
            "stopped_at_step": self.stopped_at_step,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class DecisionBlock:
    model: Optional[dict[int, bool]] = None
    propagation: Optional[UnitPropagationProof] = None
    resolution: Optional[ResolutionProof] = None
    transcript: Optional[IndeterminacyTranscript] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": (
                None if self.model is None else {str(k): v for k, v in sorted(self.model.items())}
            ),
            "propagation": None if self.propagation is None else self.propagation.to_dict(),
            "resolution": None if self.resolution is None else self.resolution.to_dict(),
            "transcript": None if self.transcript is None else self.transcript.to_dict(),
        }


# --------------------------------------------------------------------------
# Certificate
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CertificateHeader:
    verdict: Verdict
    tier: CostTier
    n_vars: int
    clause_count: int
    literal_count: int
    step_count: int
    binding: str
    width: int = 0
    format: str = FORMAT

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "verdict": self.verdict.value,
            "tier": self.tier.value,
            "width": self.width,
            "n_vars": self.n_vars,
            "clause_count": self.clause_count,
            "literal_count": self.literal_count,
            "step_count": self.step_count,
            "binding": self.binding,
        }


@dataclass(frozen=True)
class DecisionCertificate:
    """Canonical grounded decision certificate (GDC) blocks for the bounded checker."""

    header: CertificateHeader
    formula: tuple[tuple[int, ...], ...]
    grounding: Grounding
    decision: DecisionBlock
    hints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "formula": [list(clause) for clause in self.formula],
            "grounding": self.grounding.to_dict(),
            "decision": self.decision.to_dict(),
            "hints": self.hints,
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def without_hints(self) -> "DecisionCertificate":
        """Hint-stripped form.

        Rung 4.8: the same certificate is publishable at two sizes. The kernel
        must reach the same verdict on both, because hints are never consulted
        on the sound path.
        """
        return DecisionCertificate(
            header=self.header,
            formula=self.formula,
            grounding=self.grounding,
            decision=self.decision,
            hints={},
        )


def _record(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CertificateError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise CertificateError(f"{label} keys mismatch; missing={missing}, extra={extra}")
    return value


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        qualifier = "positive " if positive else "non-negative "
        raise CertificateError(f"{label} must be a {qualifier}integer")
    return value


def certificate_from_dict(value: Mapping[str, Any]) -> DecisionCertificate:
    """Strictly decode one ``VSTD4-GDC-1`` object without producing a verdict."""
    root = _record(value, {"header", "formula", "grounding", "decision", "hints"}, "certificate")
    raw_header = _record(
        root["header"],
        {"format", "verdict", "tier", "width", "n_vars", "clause_count", "literal_count", "step_count", "binding"},
        "header",
    )
    try:
        header = CertificateHeader(
            verdict=Verdict(raw_header["verdict"]),
            tier=CostTier(raw_header["tier"]),
            n_vars=_integer(raw_header["n_vars"], "header.n_vars"),
            clause_count=_integer(raw_header["clause_count"], "header.clause_count"),
            literal_count=_integer(raw_header["literal_count"], "header.literal_count"),
            step_count=_integer(raw_header["step_count"], "header.step_count"),
            binding=str(raw_header["binding"]),
            width=_integer(raw_header["width"], "header.width"),
            format=str(raw_header["format"]),
        )
    except (KeyError, ValueError) as exc:
        raise CertificateError(f"invalid certificate header: {exc}") from exc

    if not isinstance(root["formula"], list):
        raise CertificateError("formula must be an array")
    formula: list[tuple[int, ...]] = []
    for index, raw_clause in enumerate(root["formula"]):
        if not isinstance(raw_clause, list):
            raise CertificateError(f"formula clause {index} must be an array")
        clause: list[int] = []
        for position, raw_literal in enumerate(raw_clause):
            literal = _integer(abs(raw_literal), f"formula[{index}][{position}]", positive=True) if type(raw_literal) is int else None
            if literal is None or raw_literal == 0:
                raise CertificateError(f"formula[{index}][{position}] must be a non-zero integer")
            clause.append(raw_literal)
        if len(set(clause)) != len(clause):
            raise CertificateError(f"formula clause {index} repeats a literal")
        formula.append(tuple(clause))

    raw_grounding = _record(root["grounding"], {"variables", "clauses", "rules"}, "grounding")
    if not all(isinstance(raw_grounding[name], list) for name in ("variables", "clauses", "rules")):
        raise CertificateError("grounding variables, clauses and rules must be arrays")

    variables: list[VariableGrounding] = []
    for index, raw in enumerate(raw_grounding["variables"]):
        item = _record(raw, {"var", "fact"}, f"grounding.variables[{index}]")
        fact = _record(item["fact"], {"subject", "predicate", "value"}, f"grounding.variables[{index}].fact")
        variables.append(
            VariableGrounding(
                _integer(item["var"], f"grounding.variables[{index}].var", positive=True),
                GroundedFact(str(fact["subject"]), str(fact["predicate"]), str(fact["value"])),
            )
        )

    rules: list[EncodingRule] = []
    for index, raw in enumerate(raw_grounding["rules"]):
        item = _record(raw, {"rule_id", "roles", "template"}, f"grounding.rules[{index}]")
        if not isinstance(item["roles"], list) or not isinstance(item["template"], list):
            raise CertificateError(f"grounding.rules[{index}] roles and template must be arrays")
        template: list[tuple[int, str]] = []
        for position, pair in enumerate(item["template"]):
            if not isinstance(pair, list) or len(pair) != 2 or pair[0] not in (-1, 1):
                raise CertificateError(f"grounding.rules[{index}].template[{position}] is invalid")
            template.append((pair[0], str(pair[1])))
        rules.append(
            EncodingRule(
                str(item["rule_id"]),
                tuple(str(role) for role in item["roles"]),
                tuple(template),
            )
        )

    clauses: list[ClauseGrounding] = []
    for index, raw in enumerate(raw_grounding["clauses"]):
        item = _record(raw, {"clause_index", "rule_id", "bindings", "subjects"}, f"grounding.clauses[{index}]")
        if not isinstance(item["bindings"], Mapping) or not isinstance(item["subjects"], Mapping):
            raise CertificateError(f"grounding.clauses[{index}] bindings and subjects must be objects")
        clauses.append(
            ClauseGrounding(
                _integer(item["clause_index"], f"grounding.clauses[{index}].clause_index"),
                str(item["rule_id"]),
                {str(role): _integer(var, f"grounding.clauses[{index}].bindings.{role}", positive=True) for role, var in item["bindings"].items()},
                {str(role): str(subject) for role, subject in item["subjects"].items()},
            )
        )
    grounding = Grounding(tuple(variables), tuple(clauses), tuple(rules))

    raw_decision = _record(root["decision"], {"model", "propagation", "resolution", "transcript"}, "decision")
    model = None
    if raw_decision["model"] is not None:
        if not isinstance(raw_decision["model"], Mapping):
            raise CertificateError("decision.model must be an object or null")
        model = {}
        for raw_var, raw_value in raw_decision["model"].items():
            if not isinstance(raw_var, str) or not raw_var.isdigit() or int(raw_var) < 1 or type(raw_value) is not bool:
                raise CertificateError("decision.model must map positive integer strings to booleans")
            model[int(raw_var)] = raw_value

    propagation = None
    if raw_decision["propagation"] is not None:
        raw = _record(raw_decision["propagation"], {"steps", "conflict_clause_index"}, "decision.propagation")
        if not isinstance(raw["steps"], list):
            raise CertificateError("decision.propagation.steps must be an array")
        steps = []
        for index, raw_step in enumerate(raw["steps"]):
            step = _record(raw_step, {"clause_index", "forced"}, f"decision.propagation.steps[{index}]")
            forced = step["forced"]
            if type(forced) is not int or forced == 0:
                raise CertificateError(f"decision.propagation.steps[{index}].forced must be a non-zero integer")
            steps.append(PropagationStep(_integer(step["clause_index"], f"decision.propagation.steps[{index}].clause_index"), forced))
        propagation = UnitPropagationProof(
            tuple(steps),
            _integer(raw["conflict_clause_index"], "decision.propagation.conflict_clause_index"),
        )

    resolution = None
    if raw_decision["resolution"] is not None:
        raw = _record(raw_decision["resolution"], {"steps"}, "decision.resolution")
        if not isinstance(raw["steps"], list):
            raise CertificateError("decision.resolution.steps must be an array")
        proof_steps = []
        for index, raw_clause in enumerate(raw["steps"]):
            if not isinstance(raw_clause, list) or any(type(item) is not int or item == 0 for item in raw_clause):
                raise CertificateError(f"decision.resolution.steps[{index}] is not a clause")
            proof_steps.append(tuple(raw_clause))
        resolution = ResolutionProof(tuple(proof_steps))

    transcript = None
    if raw_decision["transcript"] is not None:
        raw = _record(
            raw_decision["transcript"],
            {"reason", "formula_digest", "declared_bound", "observed_cost", "stopped_at_step", "detail"},
            "decision.transcript",
        )
        try:
            reason = IndeterminacyReason(raw["reason"])
        except ValueError as exc:
            raise CertificateError(f"invalid indeterminacy reason: {exc}") from exc
        transcript = IndeterminacyTranscript(
            reason,
            str(raw["formula_digest"]),
            _integer(raw["declared_bound"], "decision.transcript.declared_bound"),
            _integer(raw["observed_cost"], "decision.transcript.observed_cost"),
            _integer(raw["stopped_at_step"], "decision.transcript.stopped_at_step"),
            str(raw["detail"]),
        )

    if not isinstance(root["hints"], Mapping):
        raise CertificateError("hints must be an object")
    return DecisionCertificate(
        header,
        tuple(formula),
        grounding,
        DecisionBlock(model, propagation, resolution, transcript),
        dict(root["hints"]),
    )


def certificate_from_canonical_bytes(data: bytes) -> DecisionCertificate:
    """Decode only the canonical JSON representation used in commitment digests."""
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificateError(f"certificate is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise CertificateError("certificate root must be an object")
    if canonical_bytes(value) != data:
        raise CertificateError("certificate bytes are not in canonical form")
    return certificate_from_dict(value)
