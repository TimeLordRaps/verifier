"""Formal Policy Verification Engine for Dataset & Computational Provenance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from verifiable.core.checker import MinimalIndependentDPLL, VerificationVerdict
from verifiable.data.models import ArtifactStatus, ProvenanceHypergraph


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


class ProvenancePolicyVerifier:
    """Encodes provenance graph invariants into SAT formulas and verifies them using MinimalIndependentDPLL."""

    @staticmethod
    def verify_no_revoked_ancestors(
        graph: ProvenanceHypergraph,
        target_artifact_id: str,
    ) -> PolicyEvaluationResult:
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

        passed = bool(sat and not revoked_nodes)
        verdict = VerificationVerdict.VERIFIED if passed else VerificationVerdict.FALSIFIED

        if passed:
            expl = (
                f"Verified: None of the {len(ancestors)} recorded ancestor artifacts is "
                "marked REVOKED. This narrow policy does not establish that every "
                "ancestor is VALID."
            )
        else:
            expl = f"Falsified: Found {len(revoked_nodes)} revoked ancestor(s) in causal lineage: {', '.join(revoked_nodes)}."

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
        passed = bool(sat and not inadmissible)
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
        ancestors = graph.ancestors([target_artifact_id])
        roots = [a_id for a_id in ancestors if a_id in graph.root_sources()]
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

        passed = bool(sat and not unapproved)
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
