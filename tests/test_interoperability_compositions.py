"""Terminology: Davis-Putnam-Logemann-Loveland (DPLL);
JavaScript Object Notation (JSON); unsatisfiable (UNSAT); Verifier Standard (VSTD).

Adversarial tests for the non-critical executable composition example.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from verifier.core.refutation import (
    ProofProducingDPLL,
    RefutationCertificate,
    RefutationChecker,
)


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "interoperability_compositions" / "refutation_chain.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("vstd_refutation_chain", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_refutation_composition_executes_and_binds_transition() -> None:
    demo = _load_demo()
    report = demo.build_report()

    assert report["status"] == "PASS"
    assert report["execution_performed"] is True
    assert report["proof_producer"]["native_result"] == "UNSAT"
    assert report["proof_producer"]["solver_prover_relationship"] == (
        "FUSED_PROOF_PRODUCING_SOLVER"
    )
    assert report["proof_checker"]["native_result"] == "ACCEPTED"
    assert report["transition"]["artifact_sha256"] == report["proof_producer"][
        "proof_sha256"
    ]
    assert report["transition"]["artifact_sha256"] == report["proof_checker"][
        "proof_sha256"
    ]
    assert report["proof_producer"]["formula_sha256"] == report["proof_checker"][
        "formula_sha256"
    ]
    assert report["proof_producer"]["implementation_sha256"] == report[
        "proof_checker"
    ]["implementation_sha256"]
    assert report["transition"]["registry_version"]
    assert len(report["transition"]["registry_sha256"]) == 64
    assert report["transition"]["source_implementation_ref"] == report[
        "proof_producer"
    ]["implementation_ref"]
    assert report["transition"]["source_implementation_sha256"] == report[
        "proof_producer"
    ]["implementation_sha256"]
    assert report["transition"]["target_implementation_ref"] == report[
        "proof_checker"
    ]["implementation_ref"]
    assert report["transition"]["target_implementation_sha256"] == report[
        "proof_checker"
    ]["implementation_sha256"]
    assert report["transition"]["formula_sha256"] == report["input"][
        "formula_sha256"
    ]
    assert report["transition"]["source_mechanism_id"] == (
        "mechanism:vstd4-refutation-proof-production"
    )
    assert report["transition"]["target_mechanism_id"] == (
        "mechanism:vstd4-refutation-proof-check"
    )
    assert report["transition_sha256"] == demo._sha256(
        demo._canonical_bytes(report["transition"])
    )
    assert len(report["proof_producer"]["implementation_sha256"]) == 64
    assert "not established" in report["claim_boundary"].lower()


def test_refutation_composition_report_is_deterministic() -> None:
    demo = _load_demo()

    assert demo.render_report() == demo.render_report()
    assert json.loads(demo.render_report())["status"] == "PASS"


def test_checker_rejects_forged_proof_and_changed_formula() -> None:
    demo = _load_demo()
    result = ProofProducingDPLL(2, demo.FORMULA).solve()
    assert result.certificate is not None
    satisfiable = [[1, 2], [-1, 3], [2, 3]]
    forged = RefutationCertificate(
        proof=[[]],
        n_vars=3,
        source_clause_count=len(satisfiable),
        max_proof_steps=result.certificate.max_proof_steps,
    )

    assert RefutationChecker.check(satisfiable, forged).accepted is False
    assert RefutationChecker.check(satisfiable, result.certificate).accepted is False


def test_composed_checker_consumes_exact_serialized_transition_bytes() -> None:
    demo = _load_demo()
    report = demo.build_report()
    result = ProofProducingDPLL(2, demo.FORMULA).solve()
    assert result.certificate is not None
    formula_bytes = demo._canonical_bytes({"n_vars": 2, "clauses": demo.FORMULA})
    proof_bytes = demo._canonical_bytes(result.certificate.to_dict())

    accepted = demo.check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=proof_bytes,
        transition_bytes=demo._canonical_bytes(report["transition"]),
    )

    assert accepted["accepted"] is True
    assert accepted["native_result"] == "ACCEPTED"


def test_composed_checker_rejects_serialized_or_catalog_binding_mutation() -> None:
    demo = _load_demo()
    report = demo.build_report()
    result = ProofProducingDPLL(2, demo.FORMULA).solve()
    assert result.certificate is not None
    formula_bytes = demo._canonical_bytes({"n_vars": 2, "clauses": demo.FORMULA})
    proof_record = result.certificate.to_dict()
    proof_bytes = demo._canonical_bytes(proof_record)

    tampered_proof = copy.deepcopy(proof_record)
    tampered_proof["proof"][0].append(999)
    tampered_transition = dict(report["transition"])
    tampered_transition["target_implementation_ref"] = "verifier.fake:accept_all"
    drifted_implementation = dict(report["transition"])
    drifted_implementation["target_implementation_sha256"] = "0" * 64

    proof_result = demo.check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=demo._canonical_bytes(tampered_proof),
        transition_bytes=demo._canonical_bytes(report["transition"]),
    )
    transition_result = demo.check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=proof_bytes,
        transition_bytes=demo._canonical_bytes(tampered_transition),
    )
    implementation_result = demo.check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=proof_bytes,
        transition_bytes=demo._canonical_bytes(drifted_implementation),
    )

    assert proof_result["native_result"] == "REJECTED"
    assert "transition metadata" in proof_result["details"]
    assert transition_result["native_result"] == "REJECTED"
    assert "transition metadata" in transition_result["details"]
    assert implementation_result["native_result"] == "REJECTED"
    assert "transition metadata" in implementation_result["details"]


@pytest.mark.parametrize(
    "clauses",
    (
        "abcd",
        [None, None, None, None],
        [1, 1, 1, 1],
        [[True], [1], [-1], []],
        [[3], [1], [-1], []],
    ),
)
def test_composed_checker_rejects_canonical_malformed_formula_shapes(
    clauses: object,
) -> None:
    demo = _load_demo()
    report = demo.build_report()
    result = ProofProducingDPLL(2, demo.FORMULA).solve()
    assert result.certificate is not None
    formula_bytes = demo._canonical_bytes({"n_vars": 2, "clauses": clauses})
    proof_bytes = demo._canonical_bytes(result.certificate.to_dict())
    transition = dict(report["transition"])
    transition["formula_sha256"] = demo._sha256(formula_bytes)

    rejected = demo.check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=proof_bytes,
        transition_bytes=demo._canonical_bytes(transition),
    )

    assert rejected["accepted"] is False
    assert rejected["native_result"] == "REJECTED"


def test_composed_checker_rejects_noncanonical_transition_bytes() -> None:
    demo = _load_demo()
    report = demo.build_report()
    result = ProofProducingDPLL(2, demo.FORMULA).solve()
    assert result.certificate is not None
    formula_bytes = demo._canonical_bytes({"n_vars": 2, "clauses": demo.FORMULA})
    proof_bytes = demo._canonical_bytes(result.certificate.to_dict())
    pretty_transition_bytes = json.dumps(
        report["transition"], indent=2, sort_keys=True
    ).encode("utf-8")

    rejected = demo.check_bound_transition(
        formula_bytes=formula_bytes,
        proof_bytes=proof_bytes,
        transition_bytes=pretty_transition_bytes,
    )

    assert rejected["native_result"] == "REJECTED"
    assert "not the canonical encoding" in rejected["details"]


def test_truncated_proof_is_not_accepted() -> None:
    demo = _load_demo()
    result = ProofProducingDPLL(2, demo.FORMULA).solve()
    assert result.certificate is not None
    truncated = RefutationCertificate(
        proof=result.certificate.proof[:-1],
        n_vars=result.certificate.n_vars,
        source_clause_count=result.certificate.source_clause_count,
        max_proof_steps=result.certificate.max_proof_steps,
    )

    assert RefutationChecker.check(demo.FORMULA, truncated).accepted is False


def test_exhausted_bound_remains_unknown_without_certificate() -> None:
    demo = _load_demo()
    result = ProofProducingDPLL(2, demo.FORMULA, max_proof_steps=1).solve()

    assert result.is_unknown
    assert result.bound_exceeded is True
    assert result.certificate is None
