"""Terminology: conjunctive normal form (CNF);
Davis-Putnam-Logemann-Loveland (DPLL); JavaScript Object Notation (JSON);
reverse unit propagation (RUP); Boolean satisfiability problem (SAT);
Secure Hash Algorithm 256-bit (SHA-256); unsatisfiable (UNSAT);
Verifier Standard (VSTD).

Execute one harmless proof-producing-solver to proof-checker composition.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from verifier.core import certificate as certificate_module
from verifier.core import refutation as refutation_module
from verifier.core.refutation import (
    ProofProducingDPLL,
    RefutationCertificate,
    RefutationChecker,
)
from verifier.interoperability.reference_catalog import reference_component_registry


FORMULA = [[1, 2], [1, -2], [-1, 2], [-1, -2]]
CLAIM_BOUNDARY = (
    "PASS means only that the bounded proof-producing solver returned UNSAT for the "
    "declared CNF and the separate RUP algorithm accepted the exact produced proof. "
    "The solver and prover are fused in one implementation; the checker runs in the "
    "same Python process and package. Actor independence, runtime independence, real-world "
    "grounding, and safety are not established."
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _implementation_digest() -> str:
    digest = hashlib.sha256()
    for module in (refutation_module, certificate_module):
        path = Path(str(module.__file__))
        payload = path.read_bytes()
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _binding_rejection(details: str) -> dict[str, Any]:
    return {
        "accepted": False,
        "native_result": "REJECTED",
        "steps_checked": 0,
        "details": details,
    }


def check_bound_transition(
    *,
    formula_bytes: bytes,
    proof_bytes: bytes,
    transition_bytes: bytes,
) -> dict[str, Any]:
    """Check only bytes that match the exact declared catalog transition."""

    registry = reference_component_registry()
    producer = registry.get("component:vstd4-refutation-producer")
    checker = registry.get("component:vstd4-refutation-checker")
    relation = "PRODUCES_CHECKABLE_REFUTATION"
    source_mechanism = "mechanism:vstd4-refutation-proof-production"
    target_mechanism = "mechanism:vstd4-refutation-proof-check"
    implementation_digest = _implementation_digest()
    try:
        transition = json.loads(transition_bytes.decode("utf-8"))
        if not isinstance(transition, dict):
            return _binding_rejection("transition record is not an object")
        if _canonical_bytes(transition) != transition_bytes:
            return _binding_rejection("transition bytes are not the canonical encoding")
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return _binding_rejection(f"transition bytes are malformed: {exc}")

    expected = {
        "transition_version": "refutation-transition-0.2",
        "planning_surface_schema_id": "VSTD-2",
        "interaction_mode": "STATIC",
        "relation": relation,
        "registry_version": registry.registry_version,
        "registry_sha256": registry.canonical_digest(),
        "source_component_id": producer.component_id,
        "source_implementation_ref": producer.implementation_ref,
        "source_implementation_sha256": implementation_digest,
        "source_mechanism_id": source_mechanism,
        "target_component_id": checker.component_id,
        "target_implementation_ref": checker.implementation_ref,
        "target_implementation_sha256": implementation_digest,
        "target_mechanism_id": target_mechanism,
        "formula_sha256": _sha256(formula_bytes),
        "artifact_sha256": _sha256(proof_bytes),
    }
    if transition != expected:
        return _binding_rejection(
            "transition metadata does not match the supplied bytes and current exact "
            "catalog entries"
        )
    source_matches = registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode="STATIC",
        relation_id=relation,
        mechanism_id=source_mechanism,
    )
    target_matches = registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode="STATIC",
        relation_id=relation,
        mechanism_id=target_mechanism,
    )
    if producer not in source_matches or checker not in target_matches:
        return _binding_rejection(
            "transition relation and mechanisms are not exact catalog capabilities"
        )

    try:
        formula_record = json.loads(formula_bytes.decode("utf-8"))
        proof_record = json.loads(proof_bytes.decode("utf-8"))
        if _canonical_bytes(formula_record) != formula_bytes:
            return _binding_rejection("formula bytes are not the canonical encoding")
        if _canonical_bytes(proof_record) != proof_bytes:
            return _binding_rejection("proof bytes are not the canonical encoding")
        if not isinstance(formula_record, dict) or set(formula_record) != {
            "n_vars",
            "clauses",
        }:
            return _binding_rejection("formula record has an unexpected shape")
        n_vars = formula_record["n_vars"]
        clauses = formula_record["clauses"]
        if type(n_vars) is not int or n_vars < 0:
            return _binding_rejection(
                "formula variable count must be a nonnegative integer"
            )
        if not isinstance(clauses, list):
            return _binding_rejection("formula clauses must be an array")
        if any(not isinstance(clause, list) for clause in clauses):
            return _binding_rejection("every formula clause must be an array")
        if any(
            type(literal) is not int
            or literal == 0
            or abs(literal) > n_vars
            for clause in clauses
            for literal in clause
        ):
            return _binding_rejection(
                "formula literals must be nonzero integers within the declared variable count"
            )
        certificate = RefutationCertificate.from_dict(proof_record)
        if _canonical_bytes(certificate.to_dict()) != proof_bytes:
            return _binding_rejection(
                "proof record is not an exact refutation certificate encoding"
            )
        if certificate.n_vars != n_vars:
            return _binding_rejection(
                "formula and certificate variable counts disagree"
            )
        if certificate.source_clause_count != len(clauses):
            return _binding_rejection(
                "formula and certificate clause counts disagree"
            )
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return _binding_rejection(f"transition bytes are malformed: {exc}")

    # Recompute both bindings immediately before passing the rehydrated certificate
    # to the checker. The producer's live, shallowly frozen object is not reused.
    if transition["formula_sha256"] != _sha256(formula_bytes):
        return _binding_rejection("formula digest changed before proof checking")
    if transition["artifact_sha256"] != _sha256(proof_bytes):
        return _binding_rejection("proof digest changed before proof checking")
    try:
        checked = RefutationChecker.check(clauses, certificate)
    except (IndexError, TypeError, ValueError) as exc:
        return _binding_rejection(f"proof checker rejected malformed input: {exc}")
    return {
        "accepted": checked.accepted,
        "native_result": "ACCEPTED" if checked.accepted else "REJECTED",
        "steps_checked": checked.steps_checked,
        "details": checked.details,
    }


def build_report() -> dict[str, Any]:
    """Run the two-stage composition and bind its exact transition bytes."""

    registry = reference_component_registry()
    producer = registry.get("component:vstd4-refutation-producer")
    checker = registry.get("component:vstd4-refutation-checker")
    formula_record = {"n_vars": 2, "clauses": FORMULA}
    formula_bytes = _canonical_bytes(formula_record)
    formula_digest = _sha256(formula_bytes)
    implementation_digest = _implementation_digest()
    proof_search = ProofProducingDPLL(2, FORMULA).solve()
    certificate = proof_search.certificate
    if proof_search.satisfiable is not False or certificate is None:
        return {
            "report_version": "refutation-chain-example-0.1",
            "status": "UNKNOWN" if proof_search.is_unknown else "FAIL",
            "input": {"formula_sha256": formula_digest, **formula_record},
            "proof_producer": {
                "component_id": producer.component_id,
                "native_result": (
                    "UNKNOWN" if proof_search.is_unknown else "UNEXPECTED_SAT"
                ),
                "bound_exceeded": proof_search.bound_exceeded,
                "proof_sha256": None,
            },
            "proof_checker": {"executed": False, "native_result": "NOT_RUN"},
            "execution_performed": True,
            "claim_boundary": CLAIM_BOUNDARY,
        }

    proof_bytes = _canonical_bytes(certificate.to_dict())
    proof_digest = _sha256(proof_bytes)
    transition = {
        "transition_version": "refutation-transition-0.2",
        "planning_surface_schema_id": "VSTD-2",
        "interaction_mode": "STATIC",
        "relation": "PRODUCES_CHECKABLE_REFUTATION",
        "registry_version": registry.registry_version,
        "registry_sha256": registry.canonical_digest(),
        "source_component_id": producer.component_id,
        "source_implementation_ref": producer.implementation_ref,
        "source_implementation_sha256": implementation_digest,
        "source_mechanism_id": "mechanism:vstd4-refutation-proof-production",
        "target_component_id": checker.component_id,
        "target_implementation_ref": checker.implementation_ref,
        "target_implementation_sha256": implementation_digest,
        "target_mechanism_id": "mechanism:vstd4-refutation-proof-check",
        "formula_sha256": formula_digest,
        "artifact_sha256": proof_digest,
    }
    transition_bytes = _canonical_bytes(transition)
    checked = check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=proof_bytes,
        transition_bytes=transition_bytes,
    )
    return {
        "report_version": "refutation-chain-example-0.1",
        "status": "PASS" if checked["accepted"] else "FAIL",
        "input": {"formula_sha256": formula_digest, **formula_record},
        "proof_producer": {
            "component_id": producer.component_id,
            "implementation_ref": producer.implementation_ref,
            "implementation_sha256": implementation_digest,
            "native_result": "UNSAT",
            "solver_prover_relationship": "FUSED_PROOF_PRODUCING_SOLVER",
            "formula_sha256": formula_digest,
            "proof_format": certificate.proof_format,
            "proof_sha256": proof_digest,
            "proof_step_count": certificate.step_count,
            "bound_exceeded": proof_search.bound_exceeded,
        },
        "transition": transition,
        "transition_sha256": _sha256(transition_bytes),
        "proof_checker": {
            "component_id": checker.component_id,
            "implementation_ref": checker.implementation_ref,
            "implementation_sha256": implementation_digest,
            "native_result": checked["native_result"],
            "formula_sha256": formula_digest,
            "proof_sha256": proof_digest,
            "steps_checked": checked["steps_checked"],
            "details": checked["details"],
            "separation": (
                "SEPARATE_CHECKING_ALGORITHM_SAME_PROCESS_PACKAGE; "
                "ACTOR_AND_RUNTIME_INDEPENDENCE_NOT_ESTABLISHED"
            ),
        },
        "execution_performed": True,
        "claim_boundary": CLAIM_BOUNDARY,
    }


def render_report() -> str:
    """Render the deterministic composition report as JSON."""

    return json.dumps(build_report(), indent=2, sort_keys=True, allow_nan=False) + "\n"


if __name__ == "__main__":
    print(render_report(), end="")
