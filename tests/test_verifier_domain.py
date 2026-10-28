"""Comprehensive adversarial test suite for VERIFIER domain adapter.

Terminology: identifier (ID); JavaScript Object Notation (JSON); Verifier Standard (VSTD).
"""
from __future__ import annotations

from copy import deepcopy
import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.verifier import VERIFIER_KINDS, evaluate


def _sample_verifier_bundle() -> tuple[dict, dict]:
    toolchain = {
        "name": "sat-smt-prover",
        "version": "1.2.0",
        "components": ["dimacs-parser", "dpll-solver", "proof-logger"],
    }
    toolchain_dig = digest(toolchain)
    prop_classes = ["cnf_sat", "horn_clauses", "difference_logic"]
    refutation_boundaries = {
        "cnf_sat": {"max_vars": 500, "max_clauses": 2000},
        "horn_clauses": {"max_rules": 1000},
        "difference_logic": {"max_inequalities": 400},
    }
    soundness_claims = [
        {"class": "cnf_sat", "boundary_limit": 500, "refutation_witness": "resolution_proof_dag"},
        {"class": "horn_clauses", "boundary_limit": 1000, "refutation_witness": "unit_hyperresolution_tree"},
    ]
    runs = [
        {
            "run_id": "run-001",
            "input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "software_digest": toolchain_dig,
            "output_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "entropy_leakage": 0,
        },
        {
            "run_id": "run-002",
            "input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "software_digest": toolchain_dig,
            "output_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "entropy_leakage": 0,
        },
    ]
    ceilings = {
        "max_memory_bytes": 32 * 1024 * 1024,
        "max_wall_seconds": 2.0,
        "max_loop_iterations": 50000,
    }
    measurements = [
        {"memory_bytes": 4194304, "wall_seconds": 0.05, "loop_iterations": 1200},
        {"memory_bytes": 8388608, "wall_seconds": 0.11, "loop_iterations": 2400},
    ]
    bootstrap_receipt = {
        "schema_version": "verifier-bootstrap-receipt-1",
        "verifier_id": "prover:sat-smt",
        "parent_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "status": "PASS",
    }
    self_attestation = {
        "attested_verifier_id": "prover:sat-smt",
        "toolchain_digest": toolchain_dig,
        "attestation_verdict": "SELF_VERIFIED",
    }

    artifact = {
        "verifier_kind": "PROVER",
        "toolchain_digest": toolchain_dig,
        "version": "1.2.0",
        "proposition_classes": prop_classes,
        "refutation_boundaries": refutation_boundaries,
        "runs_digest": digest(runs),
        "ceilings": ceilings,
        "bootstrap_digest": digest(bootstrap_receipt),
        "self_attestation_digest": digest(self_attestation),
    }
    inputs = {
        "toolchain": toolchain,
        "soundness_claims": soundness_claims,
        "runs": runs,
        "measurements": measurements,
        "bootstrap_receipt": bootstrap_receipt,
        "self_attestation": self_attestation,
    }
    return artifact, inputs


def test_declaration_bundle_establishes_inventory_only() -> None:
    artifact, inputs = _sample_verifier_bundle()
    budget = Budget(100000)

    obs1 = evaluate("identity", artifact, inputs, budget)
    assert obs1["verifier_kind"] == "PROVER"
    assert obs1["version"] == "1.2.0"
    assert obs1["toolchain_digest"] == artifact["toolchain_digest"]
    assert obs1["components"] == 3

    for check in ("soundness", "determinism", "resources", "meta"):
        with pytest.raises(Unavailable):
            evaluate(check, artifact, inputs, budget)


@pytest.mark.parametrize("kind", sorted(VERIFIER_KINDS))
def test_all_registered_verifier_kinds_are_accepted(kind: str) -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["verifier_kind"] = kind
    obs = evaluate("identity", artifact, inputs, Budget(10000))
    assert obs["verifier_kind"] == kind


def test_invalid_verifier_kind_is_refuted() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["verifier_kind"] = "ORACLE_MAGIC"
    with pytest.raises(Refuted, match="unknown verifier kind"):
        evaluate("identity", artifact, inputs, Budget(10000))


def test_toolchain_digest_mismatch_is_refuted() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["toolchain"]["version"] = "2.0.0-modified"
    with pytest.raises(Refuted, match="toolchain digest mismatch"):
        evaluate("identity", artifact, inputs, Budget(10000))


def test_missing_toolchain_input_is_unavailable() -> None:
    artifact, inputs = _sample_verifier_bundle()
    del inputs["toolchain"]
    with pytest.raises(Unavailable, match="required evidence absent: toolchain"):
        evaluate("identity", artifact, inputs, Budget(10000))


@pytest.mark.parametrize("unbounded_claim", [
    "unbounded_omniscience",
    "halting_problem",
    "universal_truth",
    "unbounded_safety",
    "infinite_search",
    "general_induction",
])
def test_soundness_rejects_unbounded_omniscience_classes(unbounded_claim: str) -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["proposition_classes"].append(unbounded_claim)
    with pytest.raises(Refuted, match="unbounded proposition class rejected"):
        evaluate("soundness", artifact, inputs, Budget(10000))


def test_soundness_rejects_unbounded_claim_in_inputs() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["proposition_classes"].append("valid_class")
    inputs["soundness_claims"].append({
        "class": "unbounded_omniscience_claim",
        "boundary_limit": 100,
        "refutation_witness": "impossible_witness",
    })
    with pytest.raises(Refuted):
        evaluate("soundness", artifact, inputs, Budget(10000))


def test_soundness_rejects_empty_refutation_boundaries() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["refutation_boundaries"] = {}
    with pytest.raises(Refuted, match="refutation boundaries must be non-empty"):
        evaluate("soundness", artifact, inputs, Budget(10000))


def test_soundness_rejects_claim_outside_declared_classes() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["soundness_claims"].append({
        "class": "undeclared_logic",
        "boundary_limit": 50,
        "refutation_witness": "witness_tree",
    })
    with pytest.raises(Refuted, match="not in declared proposition classes"):
        evaluate("soundness", artifact, inputs, Budget(10000))


def test_determinism_requires_at_least_two_runs() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["runs"] = [inputs["runs"][0]]
    artifact["runs_digest"] = digest(inputs["runs"])
    with pytest.raises(Refuted, match="at least 2 runs required"):
        evaluate("determinism", artifact, inputs, Budget(10000))


def test_determinism_rejects_divergent_outputs() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["runs"][1]["output_digest"] = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    artifact["runs_digest"] = digest(inputs["runs"])
    with pytest.raises(Refuted, match="non-deterministic output deviation detected"):
        evaluate("determinism", artifact, inputs, Budget(10000))


def test_determinism_rejects_entropy_leakage() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["runs"][0]["entropy_leakage"] = 4
    artifact["runs_digest"] = digest(inputs["runs"])
    with pytest.raises(Refuted, match="non-deterministic entropy leakage detected"):
        evaluate("determinism", artifact, inputs, Budget(10000))


def test_determinism_rejects_input_mismatch_across_runs() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["runs"][1]["input_digest"] = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    artifact["runs_digest"] = digest(inputs["runs"])
    with pytest.raises(Refuted, match="input digest mismatch"):
        evaluate("determinism", artifact, inputs, Budget(10000))


def test_resources_anti_oom_violation_refuted() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["ceilings"]["max_memory_bytes"] = 5000000  # 5 MB ceiling
    # measurement has 8388608 (> 8 MB)
    with pytest.raises(Refuted, match="anti-OOM violation"):
        evaluate("resources", artifact, inputs, Budget(10000))


def test_resources_wall_seconds_ceiling_refuted() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["ceilings"]["max_wall_seconds"] = 0.08  # measurement has 0.11
    with pytest.raises(Refuted, match="execution time .* exceeds ceiling"):
        evaluate("resources", artifact, inputs, Budget(10000))


def test_resources_loop_bound_violation_refuted() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["ceilings"]["max_loop_iterations"] = 1500  # measurement has 2400
    with pytest.raises(Refuted, match="anti-infinite-loop violation"):
        evaluate("resources", artifact, inputs, Budget(10000))


def test_meta_parent_bootstrap_status_must_be_pass() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["bootstrap_receipt"]["status"] = "FAIL"
    artifact["bootstrap_digest"] = digest(inputs["bootstrap_receipt"])
    with pytest.raises(Refuted, match="parent bootstrap receipt status is FAIL"):
        evaluate("meta", artifact, inputs, Budget(10000))


def test_meta_self_attestation_verdict_must_be_self_verified() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["self_attestation"]["attestation_verdict"] = "UNVERIFIED"
    artifact["self_attestation_digest"] = digest(inputs["self_attestation"])
    with pytest.raises(Refuted, match="expected SELF_VERIFIED or PASS"):
        evaluate("meta", artifact, inputs, Budget(10000))


def test_meta_self_attestation_toolchain_mismatch_refuted() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["self_attestation"]["toolchain_digest"] = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
    artifact["self_attestation_digest"] = digest(inputs["self_attestation"])
    with pytest.raises(Refuted, match="self-attestation toolchain digest mismatch"):
        evaluate("meta", artifact, inputs, Budget(10000))


def test_unsupported_check_raises_unavailable() -> None:
    artifact, inputs = _sample_verifier_bundle()
    with pytest.raises(Unavailable, match="unsupported VERIFIER check: quantum_entanglement"):
        evaluate("quantum_entanglement", artifact, inputs, Budget(10000))


def test_determinism_rejects_duplicate_run_ids() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["runs"][1]["run_id"] = inputs["runs"][0]["run_id"]
    artifact["runs_digest"] = digest(inputs["runs"])
    with pytest.raises(Refuted, match="distinct run IDs required"):
        evaluate("determinism", artifact, inputs, Budget(10000))


def test_resources_rejects_negative_execution_time() -> None:
    artifact, inputs = _sample_verifier_bundle()
    inputs["measurements"][0]["wall_seconds"] = -0.5
    with pytest.raises(Refuted, match="execution time must be non-negative"):
        evaluate("resources", artifact, inputs, Budget(10000))


def test_soundness_rejects_empty_limits_in_boundary() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["refutation_boundaries"]["cnf_sat"] = {}
    with pytest.raises(Refuted, match="must define non-empty limits"):
        evaluate("soundness", artifact, inputs, Budget(10000))


def test_soundness_rejects_non_positive_limit_in_boundary() -> None:
    artifact, inputs = _sample_verifier_bundle()
    artifact["refutation_boundaries"]["cnf_sat"]["max_vars"] = 0
    with pytest.raises(Refuted):
        evaluate("soundness", artifact, inputs, Budget(10000))
