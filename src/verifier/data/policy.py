"""Terminology: conjunctive normal form (CNF); grounded decision certificate (GDC);
Boolean satisfiability problem (SAT); Software Package Data Exchange (SPDX);
Verifier Standard (VSTD).

Formal Policy Verification Engine for Dataset & Computational Provenance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from verifier.core.certificate import (
    ClaimBinding,
    ClaimCoordinate,
    ClauseGrounding,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    ResourceBounds,
    VariableGrounding,
    normalize_clause,
)
from verifier.core.checker import MinimalIndependentDPLL, VerificationVerdict
from verifier.core.kernel import check as kernel_check, reference_descriptor
from verifier.core.refutation import build_horn_certificate
from verifier.data.models import ArtifactStatus, ProvenanceHypergraph


class PolicyEncodingError(RuntimeError):
    """A policy cannot be safely encoded, or its CNF and direct computation disagree.

    It is raised before any verdict when the graph is structurally invalid or a
    CNF leaves a variable it declares unbound: both let a policy PASS on
    nothing.

    Disagreement used to be impossible to observe. Each verifier below computed
    ``passed = bool(sat and not violations)`` -- hedging the SAT result against
    a Python list comprehension, so the operative verdict came from the list and
    the certificate was decoration. If the encoding and the list ever diverged,
    which is precisely what an encoding bug produces, nothing detected it.

    Now the CNF is authoritative and divergence is a hard error carrying the
    certificate the CNF actually supports, so a reader can see which of the two
    is lying rather than being handed the one that happened to be preferred.
    """

    def __init__(
        self,
        message: str,
        *,
        certificate: Optional[DecisionCertificate] = None,
        cnf_satisfiable: bool = False,
        direct_result: bool = False,
    ) -> None:
        super().__init__(message)
        self.certificate = certificate
        self.cnf_satisfiable = cnf_satisfiable
        self.direct_result = direct_result


# --------------------------------------------------------------------------
# VSTD4-GDC-1 grounding for policy CNFs
# --------------------------------------------------------------------------
#
# Every clause these verifiers emit has one of four shapes, and each shape is
# one named encoding rule. Matching them back is not merely bookkeeping: a
# clause shape the grounding does not recognize raises, so an encoder that
# later emits something new cannot slip past unexamined.

RULE_ASSERT_TARGET = EncodingRule("RULE:POLICY_ASSERT_TARGET", ("target",), ((1, "target"),))
RULE_TARGET_REQUIRES = EncodingRule(
    "RULE:POLICY_TARGET_REQUIRES", ("target", "member"), ((-1, "target"), (1, "member"))
)
RULE_MEMBER_SATISFIES = EncodingRule(
    "RULE:POLICY_MEMBER_SATISFIES", ("member",), ((1, "member"),)
)
RULE_MEMBER_VIOLATES = EncodingRule(
    "RULE:POLICY_MEMBER_VIOLATES", ("member",), ((-1, "member"),)
)
POLICY_RULES = (
    RULE_ASSERT_TARGET,
    RULE_TARGET_REQUIRES,
    RULE_MEMBER_SATISFIES,
    RULE_MEMBER_VIOLATES,
)


def _policy_subjects(
    var_map: Mapping[str, int], target_artifact_id: str
) -> dict[int, tuple[str, str]]:
    """Index -> (subject, predicate), read out of the variable map."""
    subjects: dict[int, tuple[str, str]] = {}
    for name, index in var_map.items():
        if index == 1:
            subjects[index] = (target_artifact_id, name.lower())
            continue
        prefix, _, member = name.partition("_")
        if not member:
            raise PolicyEncodingError(
                f"variable {name!r} names no subject, so nothing grounds variable {index}"
            )
        subjects[index] = (member, prefix.lower())
    return subjects


def ground_policy_cnf(
    clauses: Sequence[Sequence[int]],
    var_map: Mapping[str, int],
    target_artifact_id: str,
    *,
    member_value: Optional[Mapping[str, str]] = None,
) -> Grounding:
    """Bind every variable to a content-addressed fact and every clause to a rule."""
    subjects = _policy_subjects(var_map, target_artifact_id)
    values = dict(member_value or {})

    variables = tuple(
        VariableGrounding(
            index,
            GroundedFact(subject, predicate, values.get(subject, "ASSERTED")),
        )
        for index, (subject, predicate) in sorted(subjects.items())
    )

    target_subject = subjects[1][0]
    groundings: list[ClauseGrounding] = []
    for position, clause in enumerate(clauses):
        literals = normalize_clause(clause)
        if literals == (1,):
            rule, bindings = RULE_ASSERT_TARGET, {"target": 1}
        elif len(literals) == 2 and literals[0] == -1 and literals[1] > 1:
            rule, bindings = RULE_TARGET_REQUIRES, {"target": 1, "member": literals[1]}
        elif len(literals) == 1 and literals[0] > 1:
            rule, bindings = RULE_MEMBER_SATISFIES, {"member": literals[0]}
        elif len(literals) == 1 and literals[0] < -1:
            rule, bindings = RULE_MEMBER_VIOLATES, {"member": -literals[0]}
        else:
            raise PolicyEncodingError(
                f"clause {position} {list(literals)} matches no declared policy encoding "
                "rule, so it cannot be grounded and its meaning is unstated"
            )
        clause_subjects = {
            role: (target_subject if role == "target" else subjects[bindings[role]][0])
            for role in rule.roles
        }
        groundings.append(ClauseGrounding(position, rule.rule_id, bindings, clause_subjects))

    _require_every_variable_bound(groundings, subjects)
    return Grounding(variables, tuple(groundings), POLICY_RULES)


_FACT_RULES = (RULE_MEMBER_SATISFIES.rule_id, RULE_MEMBER_VIOLATES.rule_id)


def _require_every_variable_bound(
    groundings: Sequence[ClauseGrounding], subjects: Mapping[int, tuple[str, str]]
) -> None:
    """Refuse a CNF that says less than its variable map.

    Every clause shape above is sound on its own, and a CNF missing one still
    certifies PASS: an unasserted target is satisfied by making it false, and a
    member with no fact clause, or one the target never requires, takes
    whatever value passes. The encoders emit the target once and each member
    once per rule, so any other count is an encoding bug.
    """
    asserted = sum(1 for g in groundings if g.rule_id == RULE_ASSERT_TARGET.rule_id)
    if asserted != 1:
        raise PolicyEncodingError(
            f"the target is asserted by {asserted} clauses, not exactly one, so a "
            "PASS would not be a statement about the target"
        )
    for index, (subject, predicate) in sorted(subjects.items()):
        if index == 1:
            continue
        required = sum(
            1
            for g in groundings
            if g.rule_id == RULE_TARGET_REQUIRES.rule_id and g.bindings["member"] == index
        )
        facts = sum(
            1 for g in groundings if g.rule_id in _FACT_RULES and g.bindings["member"] == index
        )
        if required != 1 or facts != 1:
            raise PolicyEncodingError(
                f"variable {index} ({predicate} of {subject}) is required by {required} "
                f"clauses and fixed by {facts} fact clauses; each must be exactly one, "
                "or the policy can PASS without deciding that member"
            )


def _policy_binding(
    policy_id: str, target_artifact_id: str, clauses: Sequence[Sequence[int]]
) -> ClaimBinding:
    from verifier.core.certificate import canonical_digest

    return ClaimBinding(
        claim=policy_id,
        coordinate=ClaimCoordinate(target_artifact_id, policy_id),
        policy_root=canonical_digest([list(clause) for clause in clauses]),
        evidence_root=canonical_digest(sorted({policy_id, target_artifact_id})),
        verifier=reference_descriptor(),
        bounds=ResourceBounds(
            verification_cost_bound=sum(len(clause) for clause in clauses) + len(clauses),
            memory_bound=len(clauses),
            certificate_size_bound=0,
        ),
    )


def certify_policy_cnf(
    *,
    satisfiable: bool,
    direct_result: bool,
    policy_id: str,
    target_artifact_id: str,
    clauses: Sequence[Sequence[int]],
    var_map: Mapping[str, int],
    member_value: Optional[Mapping[str, str]] = None,
) -> tuple[bool, DecisionCertificate]:
    """Make the CNF authoritative, and prove it rather than assert it.

    Returns the verdict the *encoding* supports, together with a certificate
    :mod:`verifier.core.kernel` accepts. Divergence between the encoding and
    the direct computation raises :class:`PolicyEncodingError` with that
    certificate attached -- silently preferring either branch is what made the
    certificate decorative in the first place.
    """
    grounding = ground_policy_cnf(
        clauses, var_map, target_artifact_id, member_value=member_value
    )
    binding = _policy_binding(policy_id, target_artifact_id, clauses)
    certificate = build_horn_certificate(clauses, grounding, binding)

    verdict = kernel_check(certificate, binding=binding)
    if not verdict.accepted:
        raise PolicyEncodingError(
            f"{policy_id}: the kernel refused this policy's own certificate: "
            f"{verdict.details}",
            certificate=certificate,
            cnf_satisfiable=satisfiable,
            direct_result=direct_result,
        )

    cnf_passed = certificate.header.verdict.value == "PASS"
    if cnf_passed != satisfiable:
        raise PolicyEncodingError(
            f"{policy_id}: the certified encoding says {cnf_passed} but the solver "
            f"said {satisfiable}",
            certificate=certificate,
            cnf_satisfiable=satisfiable,
            direct_result=direct_result,
        )
    if cnf_passed != direct_result:
        raise PolicyEncodingError(
            f"{policy_id}: CNF encoding and direct computation disagree for "
            f"{target_artifact_id} -- encoding says {cnf_passed}, direct "
            f"computation says {direct_result}. One of them is wrong and the "
            "certificate attached shows what the encoding actually proves.",
            certificate=certificate,
            cnf_satisfiable=satisfiable,
            direct_result=direct_result,
        )
    return cnf_passed, certificate


@dataclass(frozen=True)
class PolicyEvaluationResult:
    policy_id: str
    policy_name: str
    target_artifact_id: str
    passed: bool
    verdict: VerificationVerdict
    clauses: list[list[int]]
    variable_map: dict[str, int]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "target_artifact_id": self.target_artifact_id,
            "passed": self.passed,
            "verdict": self.verdict.value,
            "clauses": self.clauses,
            "variable_map": self.variable_map,
            "explanation": self.explanation,
        }


def _refuse_undecidable(
    graph: ProvenanceHypergraph, target_artifact_id: str, policy_id: str, policy_name: str
) -> Optional[PolicyEvaluationResult]:
    """Stop a policy from certifying a lineage the graph does not record.

    An empty or dangling lineage makes every policy below vacuously true. A
    structurally invalid graph raises, mirroring
    ``verifier.data.graph_level._require_valid_graph_structure`` rather than
    calling it, for the rung 4.7 reason that module gives. A target the graph
    does not contain is INDETERMINATE: the question is well formed, but the
    graph holds nothing to decide it with.
    """
    errors = graph.validate_structure()
    if errors:
        raise PolicyEncodingError(
            f"{policy_id} requires a structurally valid provenance graph: " + "; ".join(errors)
        )
    if target_artifact_id in graph.artifacts:
        return None
    return _indeterminate(
        policy_id,
        policy_name,
        target_artifact_id,
        f"{target_artifact_id} is not an artifact of this graph, so no lineage is "
        "recorded for it and the policy has nothing to decide.",
    )


def _indeterminate(
    policy_id: str, policy_name: str, target_artifact_id: str, reason: str
) -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        policy_id=policy_id,
        policy_name=policy_name,
        target_artifact_id=target_artifact_id,
        passed=False,
        verdict=VerificationVerdict.INDETERMINATE,
        clauses=[],
        variable_map={},
        explanation=f"Indeterminate: {reason}",
    )


class ProvenancePolicyVerifier:
    """Encodes provenance graph invariants into SAT formulas and verifies them using MinimalIndependentDPLL."""

    @staticmethod
    def verify_no_revoked_ancestors(
        graph: ProvenanceHypergraph,
        target_artifact_id: str,
    ) -> PolicyEvaluationResult:
        refused = _refuse_undecidable(
            graph, target_artifact_id, "POL-NO-REVOKED-ANCESTORS", "Zero Revoked Ancestors Invariant"
        )
        if refused is not None:
            return refused
        ancestors = graph.ancestors([target_artifact_id])
        revoked_nodes = []

        for a_id in ancestors:
            node = graph.artifacts.get(a_id)
            if node and node.status == ArtifactStatus.REVOKED:
                revoked_nodes.append(a_id)

        # SAT Encoding:
        # Variable 1 = TargetAdmissible
        # Variable 1 + i = Ancestor_i_Clean (True if node is not REVOKED)
        # Clauses: TargetAdmissible -> AND(Ancestor_i_Clean)
        # i.e., (-1 or 2), (-1 or 3), ..., and for any revoked node k: (-k)
        var_map: dict[str, int] = {"TARGET_ADMISSIBLE": 1}
        clauses: list[list[int]] = []

        idx = 2
        for a_id in sorted(ancestors):
            var_map[f"CLEAN_{a_id}"] = idx
            clauses.append([-1, idx])  # TARGET_ADMISSIBLE -> CLEAN_a_id
            node = graph.artifacts.get(a_id)
            if node and node.status == ArtifactStatus.REVOKED:
                clauses.append([-idx])  # CLEAN_a_id is FALSE
            else:
                clauses.append([idx])   # CLEAN_a_id is TRUE
            idx += 1

        # We assert TargetAdmissible = True to test if the policy holds
        test_clauses = [list(c) for c in clauses] + [[1]]
        solver = MinimalIndependentDPLL(n_vars=idx - 1, clauses=test_clauses)
        sat, model = solver.solve()

        passed, _certificate = certify_policy_cnf(
            satisfiable=sat,
            direct_result=not revoked_nodes,
            policy_id="POL-NO-REVOKED-ANCESTORS",
            target_artifact_id=target_artifact_id,
            clauses=test_clauses,
            var_map=var_map,
            member_value={a_id: "REVOKED" for a_id in revoked_nodes},
        )
        verdict = VerificationVerdict.VERIFIED if passed else VerificationVerdict.FALSIFIED

        if passed:
            expl = (
                f"Verified: None of the {len(ancestors)} recorded ancestor artifacts is "
                "marked REVOKED. This narrow policy does not establish that every "
                "ancestor is VALID."
            )
        else:
            expl = (
                f"Falsified: Found {len(revoked_nodes)} revoked ancestor(s) in "
                f"recorded lineage: {', '.join(revoked_nodes)}."
            )

        return PolicyEvaluationResult(
            policy_id="POL-NO-REVOKED-ANCESTORS",
            policy_name="Zero Revoked Ancestors Invariant",
            target_artifact_id=target_artifact_id,
            passed=passed,
            verdict=verdict,
            clauses=test_clauses,
            variable_map=var_map,
            explanation=expl,
        )

    @staticmethod
    def verify_all_ancestors_valid(
        graph: ProvenanceHypergraph,
        target_artifact_id: str,
    ) -> PolicyEvaluationResult:
        """Fail closed unless every recorded ancestor is explicitly ``VALID``."""
        refused = _refuse_undecidable(
            graph,
            target_artifact_id,
            "POL-ALL-ANCESTORS-VALID",
            "All Recorded Ancestors Explicitly Valid",
        )
        if refused is not None:
            return refused
        ancestors = graph.ancestors([target_artifact_id])
        inadmissible = [
            artifact_id
            for artifact_id in sorted(ancestors)
            if (node := graph.artifacts.get(artifact_id)) is None
            or node.status != ArtifactStatus.VALID
        ]

        var_map: dict[str, int] = {"TARGET_ADMISSIBLE": 1}
        clauses: list[list[int]] = []
        for idx, artifact_id in enumerate(sorted(ancestors), start=2):
            var_map[f"VALID_{artifact_id}"] = idx
            clauses.append([-1, idx])
            clauses.append([idx] if artifact_id not in inadmissible else [-idx])

        test_clauses = clauses + [[1]]
        solver = MinimalIndependentDPLL(
            n_vars=max((abs(literal) for clause in test_clauses for literal in clause), default=1),
            clauses=test_clauses,
        )
        sat, _ = solver.solve()
        passed, _certificate = certify_policy_cnf(
            satisfiable=sat,
            direct_result=not inadmissible,
            policy_id="POL-ALL-ANCESTORS-VALID",
            target_artifact_id=target_artifact_id,
            clauses=test_clauses,
            var_map=var_map,
            member_value={artifact_id: "NOT_VALID" for artifact_id in inadmissible},
        )
        verdict = VerificationVerdict.VERIFIED if passed else VerificationVerdict.FALSIFIED
        if passed:
            explanation = (
                f"Verified: All {len(ancestors)} recorded ancestor artifacts are explicitly VALID."
            )
        else:
            explanation = (
                "Falsified: Recorded ancestors are not explicitly VALID: "
                + ", ".join(inadmissible)
                + "."
            )

        return PolicyEvaluationResult(
            policy_id="POL-ALL-ANCESTORS-VALID",
            policy_name="All Recorded Ancestors Explicitly Valid",
            target_artifact_id=target_artifact_id,
            passed=passed,
            verdict=verdict,
            clauses=test_clauses,
            variable_map=var_map,
            explanation=explanation,
        )

    @staticmethod
    def verify_approved_licenses(
        graph: ProvenanceHypergraph,
        target_artifact_id: str,
        approved_spdx_licenses: Sequence[str] = ("CC-BY-4.0", "CC-BY-NC-4.0", "MIT", "Apache-2.0"),
    ) -> PolicyEvaluationResult:
        refused = _refuse_undecidable(
            graph, target_artifact_id, "POL-APPROVED-LICENSES", "Approved Source Licenses Invariant"
        )
        if refused is not None:
            return refused
        ancestors = graph.ancestors([target_artifact_id])
        roots = [a_id for a_id in ancestors if a_id in graph.root_sources()]
        if not roots:
            # Reachable on a valid graph only through a cycle: every ancestor is
            # some transformation's output, so no source licence is recorded.
            return _indeterminate(
                "POL-APPROVED-LICENSES",
                "Approved Source Licenses Invariant",
                target_artifact_id,
                f"no ancestor of {target_artifact_id} is a root source, so no source "
                "licence is recorded and approval cannot follow from zero sources.",
            )
        unapproved = []

        for r_id in roots:
            node = graph.artifacts.get(r_id)
            rights = graph.rights.get(node.rights_id) if (node and node.rights_id) else None
            if not rights or rights.license_spdx not in approved_spdx_licenses:
                unapproved.append(r_id)

        var_map = {"TARGET_LICENSE_COMPLIANT": 1}
        clauses = []
        idx = 2
        for r_id in sorted(roots):
            var_map[f"APPROVED_{r_id}"] = idx
            clauses.append([-1, idx])
            if r_id in unapproved:
                clauses.append([-idx])
            else:
                clauses.append([idx])
            idx += 1

        test_clauses = [list(c) for c in clauses] + [[1]]
        solver = MinimalIndependentDPLL(n_vars=idx - 1, clauses=test_clauses)
        sat, _ = solver.solve()

        passed, _certificate = certify_policy_cnf(
            satisfiable=sat,
            direct_result=not unapproved,
            policy_id="POL-APPROVED-LICENSES",
            target_artifact_id=target_artifact_id,
            clauses=test_clauses,
            var_map=var_map,
            member_value={r_id: "UNAPPROVED" for r_id in unapproved},
        )
        verdict = VerificationVerdict.VERIFIED if passed else VerificationVerdict.FALSIFIED

        if passed:
            expl = (
                f"Verified: All {len(roots)} recorded root sources carry approved SPDX "
                f"license metadata ({', '.join(approved_spdx_licenses)}). This policy "
                "does not establish legal ownership or license validity."
            )
        else:
            expl = f"Falsified: Root sources {', '.join(unapproved)} lack approved SPDX license metadata."

        return PolicyEvaluationResult(
            policy_id="POL-APPROVED-LICENSES",
            policy_name="Approved Source Licenses Invariant",
            target_artifact_id=target_artifact_id,
            passed=passed,
            verdict=verdict,
            clauses=test_clauses,
            variable_map=var_map,
            explanation=expl,
        )
