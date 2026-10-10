from __future__ import annotations

from pathlib import Path

from verifier_guided_sat.canonical import read_json
from verifier_guided_sat.external_verifiers import load_verifier
from verifier_guided_sat.harness import VerifierGuidedHarness
from verifier_guided_sat.instances import load_instances
from verifier_guided_sat.metrics import aggregate_trials
from verifier_guided_sat.result_validator import validate_result


ROOT = Path(__file__).resolve().parents[1]


def _blocked_result(*, trials=None):
    freeze = read_json(ROOT / "freeze-manifest.json")
    records = [] if trials is None else trials
    return {
        "status": "BLOCKED_NO_REAL_LM_RUNTIME",
        "freeze_digest": freeze["freeze_digest"],
        "live_trial_count": len(records),
        "trials": records,
    }


def test_blocked_result_without_trials_is_valid() -> None:
    assert validate_result(ROOT, _blocked_result()) == []


def test_blocked_result_cannot_hide_trial_evidence() -> None:
    result = _blocked_result(trials=[{}])
    errors = validate_result(ROOT, result)
    assert "trial 0 is malformed" in errors
    assert "trial 0: blocked result contains non-runtime evidence" in errors


def test_blocked_result_is_bound_to_current_freeze_and_trial_count() -> None:
    result = _blocked_result()
    result["freeze_digest"] = "sha256:" + "0" * 64
    result["live_trial_count"] = 1
    errors = validate_result(ROOT, result)
    assert "blocked result freeze digest does not match frozen experiment" in errors
    assert "blocked result live-trial count does not match trials" in errors


def test_unknown_status_fails_closed() -> None:
    assert validate_result(ROOT, {"status": "SUCCESSISH", "trials": []}) == ["unknown result status"]


def test_unbound_total_metric_is_rejected() -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_a(
        entry["instance_id"], verifier, entry["instance"]
    ).to_dict()
    trial["metrics"]["total_time_to_outcome_ns"] += 1
    result = {
        "status": "BASELINE_ONLY_NOT_A_PRIMARY_RESULT",
        "mode": "baseline",
        "aggregate": aggregate_trials([trial]),
        "trials": [trial],
    }
    errors = validate_result(ROOT, result)
    assert "trial 0: total time disagrees with bound probe" in errors


def test_completed_result_requires_recomputable_aggregate() -> None:
    entry = next(item for item in load_instances(ROOT) if item["domain"] == "stable_matching")
    verifier = load_verifier(ROOT, entry["domain"])
    trial = VerifierGuidedHarness(ROOT).run_arm_a(
        entry["instance_id"], verifier, entry["instance"]
    ).to_dict()
    result = {
        "status": "BASELINE_ONLY_NOT_A_PRIMARY_RESULT",
        "mode": "baseline",
        "trials": [trial],
    }
    assert "completed benchmark result is missing aggregate metrics" in validate_result(ROOT, result)
    result["aggregate"] = {"A": {"accepted": 999}}
    assert "result aggregate does not recompute from trials" in validate_result(ROOT, result)


def test_aggregate_reports_each_domain_and_requested_work_metrics() -> None:
    trials = []
    for entry in load_instances(ROOT)[:3]:
        verifier = load_verifier(ROOT, entry["domain"])
        trials.append(
            VerifierGuidedHarness(ROOT).run_arm_a(
                entry["instance_id"], verifier, entry["instance"]
            ).to_dict()
        )
    aggregate = aggregate_trials(trials)["A"]
    assert set(aggregate["by_domain"]) == {trial["domain"] for trial in trials}
    for field in (
        "routes",
        "failed_routes",
        "repeated_routes",
        "native_verifier_calls",
        "median_total_time_to_outcome_ns",
        "median_sat_time_ns",
        "median_decisions",
        "median_conflicts",
        "median_propagations",
        "median_variables",
        "median_clauses",
        "median_witness_size",
        "median_vstd_creation_probe_ns",
        "median_vstd_reverification_probe_ns",
    ):
        assert field in aggregate
