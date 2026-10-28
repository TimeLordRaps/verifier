from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from verifier_guided_sat.external_verifiers import load_verifier
from verifier_guided_sat.harness import VerifierGuidedHarness
from verifier_guided_sat.independent_validation import independently_validate_record
from verifier_guided_sat.instances import load_instances


ROOT = Path(__file__).resolve().parents[1]


def _trial():
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    return VerifierGuidedHarness(ROOT).run_arm_a(
        entry["instance_id"], verifier, entry["instance"]
    )


def test_independent_validator_rehashes_replays_sat_and_replays_native_verdict() -> None:
    trial = _trial()
    assert independently_validate_record(ROOT, trial.record, reexecute=True) == []
    assert trial.metrics["vstd_reverification_errors"] == []


def test_independent_validator_detects_graph_payload_mutation() -> None:
    trial = _trial()
    mutated = deepcopy(trial.record)
    artifact_id = next(iter(mutated["artifact_payloads"]))
    mutated["artifact_payloads"][artifact_id] = {"substituted": True}
    errors = independently_validate_record(ROOT, mutated, reexecute=False)
    assert any("graph payload digest mismatch" in error for error in errors)


def test_independent_validator_detects_solver_configuration_substitution() -> None:
    trial = _trial()
    mutated = deepcopy(trial.record)
    mutated["stable_payload"]["solver_configuration"]["solver_name"] = "other"
    errors = independently_validate_record(ROOT, mutated, reexecute=True)
    assert "independent: binding digest mismatch" in errors
    assert "independent: solver_configuration_digest mismatch" in errors
    assert "independent: unsupported solver name" in errors
