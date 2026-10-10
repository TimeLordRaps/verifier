from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from time import perf_counter_ns

from verifier_guided_sat.external_verifiers import load_verifier
from verifier_guided_sat.harness import VerifierGuidedHarness
from verifier_guided_sat.instances import load_instances
from verifier_guided_sat.route import ROUTE_VERSION
from verifier_guided_sat.sat_backend import CadicalBackend
from verifier_guided_sat.vstd_binding import validate_record


ROOT = Path(__file__).resolve().parents[1]


def _entry() -> dict:
    return next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")


def test_record_rehashes_recompiles_and_reverifies() -> None:
    entry = _entry()
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_a(entry["instance_id"], verifier, entry["instance"])
    assert validate_record(ROOT, trial.record, reexecute=True) == []
    assert trial.record["stable_payload"]["bounded_claim_status"] == "PASS"
    assert trial.record["stable_payload"]["route_status"] == "SAT_ACCEPTED"
    timings = trial.record["stable_payload"]["timings_ns"]
    assert trial.metrics["total_time_to_outcome_ns"] == timings["total_system_probe"]
    assert trial.metrics["vstd_reverification_ns"] == timings["vstd_reverification_probe"]


def test_mutated_bound_artifact_is_detected() -> None:
    entry = _entry()
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_a(entry["instance_id"], verifier, entry["instance"])
    mutated = deepcopy(trial.record)
    mutated["stable_payload"]["instance"]["proposer_prefs"][0].reverse()
    errors = validate_record(ROOT, mutated, reexecute=False)
    assert "binding_digest mismatch" in errors
    assert "instance_digest mismatch" in errors


def test_route_local_unsat_remains_unknown() -> None:
    entry = _entry()
    verifier = load_verifier(ROOT, entry["domain"])
    route = {
        "route_version": ROUTE_VERSION,
        "declared_statement": "test-only contradictory route",
        "slots": [{"id": f"p{i}", "domain": list(range(6))} for i in range(6)],
        "constraints": [
            {"kind": "fixed", "slot": "p0", "value": 0},
            {"kind": "fixed", "slot": "p0", "value": 1},
        ],
        "decoder": {"kind": "list_field", "field": "matching", "slots": [f"p{i}" for i in range(6)]},
    }
    started = perf_counter_ns()
    trial = VerifierGuidedHarness(ROOT)._run_route(
        "C",
        entry["instance_id"],
        verifier,
        entry["instance"],
        route,
        None,
        trial_started_ns=started,
        harness_started_ns=started,
        preparation_ns=0,
    )
    stable = trial.record["stable_payload"]
    assert stable["route_status"] == "ROUTE_UNSAT"
    assert stable["bounded_claim_status"] == "UNKNOWN"
    assert trial.metrics["final_unknown"] is True
    assert validate_record(ROOT, trial.record, reexecute=True) == []


def test_conflict_budget_exhaustion_remains_unknown() -> None:
    entry = _entry()
    verifier = load_verifier(ROOT, entry["domain"])
    route = {
        "route_version": ROUTE_VERSION,
        "declared_statement": "test-only bounded pigeonhole route",
        "slots": [{"id": f"p{i}", "domain": list(range(5))} for i in range(6)],
        "constraints": [{"kind": "all_different", "slots": [f"p{i}" for i in range(6)]}],
        "decoder": {
            "kind": "list_field",
            "field": "matching",
            "slots": [f"p{i}" for i in range(6)],
        },
    }
    harness = VerifierGuidedHarness(ROOT, solver=CadicalBackend(conflict_budget=1))
    started = perf_counter_ns()
    trial = harness._run_route(
        "C",
        entry["instance_id"],
        verifier,
        entry["instance"],
        route,
        None,
        trial_started_ns=started,
        harness_started_ns=started,
        preparation_ns=0,
    )
    stable = trial.record["stable_payload"]
    assert stable["route_status"] == "ROUTE_UNKNOWN"
    assert stable["bounded_claim_status"] == "UNKNOWN"
    assert trial.metrics["final_unknown"] is True
    assert trial.metrics["vstd_reverification_errors"] == []
