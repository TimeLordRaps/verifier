"""Preregistered correctness-first classification of live benchmark trials."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping


HELD_OUT_DOMAINS = ("graph_isomorphism", "integer_factorization")
SOLVER_WORK_FIELDS = ("decisions", "conflicts", "propagations", "elapsed_ns")


def classify_live_result(
    live_trials: Iterable[Mapping[str, Any]],
    baseline_trials: Iterable[Mapping[str, Any]],
    *,
    success_threshold: float,
) -> dict[str, Any]:
    """Classify one frozen live run without turning missing evidence into success."""

    live = list(live_trials)
    baseline = list(baseline_trials)
    lm_failures = [trial for trial in live if _failure_stage(trial) == "lm_generation"]
    if lm_failures:
        return {
            "classification_version": "vgsat-classification-0.1",
            "status": "BLOCKED_NO_REAL_LM_RUNTIME",
            "reason": "a real configured LM request failed; no retry or substitute was used",
            "completed_live_trials": len(live),
            "lm_runtime_failures": len(lm_failures),
        }

    expected = {
        (str(trial.get("instance_id")), arm)
        for trial in baseline
        for arm in ("B", "C")
    }
    observed = [(str(trial.get("instance_id")), str(trial.get("arm"))) for trial in live]
    coverage_complete = set(observed) == expected and len(observed) == len(expected)
    duplicate_trials = sum(count - 1 for count in Counter(observed).values() if count > 1)

    baseline_by_instance = {
        str(trial.get("instance_id")): trial for trial in baseline if trial.get("arm") == "A"
    }
    held_out_c = [
        trial
        for trial in live
        if trial.get("arm") == "C" and trial.get("domain") in HELD_OUT_DOMAINS
    ]
    held_out_b = [
        trial
        for trial in live
        if trial.get("arm") == "B" and trial.get("domain") in HELD_OUT_DOMAINS
    ]
    false_acceptances = sum(bool(_metrics(trial).get("false_acceptance")) for trial in live)
    record_errors = sum(bool(_metrics(trial).get("vstd_reverification_errors")) for trial in live)
    c_acceptance_by_domain = {
        domain: sum(
            bool(_metrics(trial).get("accepted"))
            for trial in held_out_c
            if trial.get("domain") == domain
        )
        for domain in HELD_OUT_DOMAINS
    }
    b_acceptance_by_domain = {
        domain: sum(
            bool(_metrics(trial).get("accepted"))
            for trial in held_out_b
            if trial.get("domain") == domain
        )
        for domain in HELD_OUT_DOMAINS
    }
    accepted_residuals = [
        trial
        for trial in held_out_c
        if bool(_metrics(trial).get("accepted"))
        and not bool(_metrics(trial).get("generate_and_check_equivalent"))
    ]

    comparisons: dict[str, Any] = {}
    solver_easier_all_domains = True
    for domain in HELD_OUT_DOMAINS:
        candidates = [trial for trial in accepted_residuals if trial.get("domain") == domain]
        matched = [
            (baseline_by_instance[str(trial.get("instance_id"))], trial)
            for trial in candidates
            if str(trial.get("instance_id")) in baseline_by_instance
        ]
        arm_a_work = _work_sums(left for left, _ in matched)
        arm_c_work = _work_sums(right for _, right in matched)
        work_available = len(matched) == 20 and all(
            arm_a_work[field] is not None and arm_c_work[field] is not None
            for field in SOLVER_WORK_FIELDS
        )
        pareto_lower = bool(
            work_available
            and all(arm_c_work[field] <= arm_a_work[field] for field in SOLVER_WORK_FIELDS)
            and any(arm_c_work[field] < arm_a_work[field] for field in SOLVER_WORK_FIELDS)
        )
        comparisons[domain] = {
            "matched_accepted_residuals": len(matched),
            "arm_a_solver_work": arm_a_work,
            "arm_c_solver_work": arm_c_work,
            "solver_work_pareto_lower": pareto_lower,
        }
        solver_easier_all_domains = solver_easier_all_domains and pareto_lower

    matched_all = [
        (baseline_by_instance[str(trial.get("instance_id"))], trial)
        for trial in accepted_residuals
        if str(trial.get("instance_id")) in baseline_by_instance
    ]
    arm_a_total = sum(int(_metrics(left).get("total_time_to_outcome_ns", 0)) for left, _ in matched_all)
    arm_c_total = sum(int(_metrics(right).get("total_time_to_outcome_ns", 0)) for _, right in matched_all)
    end_to_end_improvement = (
        1.0 - (arm_c_total / arm_a_total) if arm_a_total > 0 and len(matched_all) == 40 else None
    )
    full_c_completion = all(c_acceptance_by_domain[domain] == 20 for domain in HELD_OUT_DOMAINS)
    end_to_end_success = bool(
        full_c_completion
        and end_to_end_improvement is not None
        and end_to_end_improvement > success_threshold
    )
    primary_success = bool(
        coverage_complete
        and duplicate_trials == 0
        and false_acceptances == 0
        and record_errors == 0
        and full_c_completion
        and solver_easier_all_domains
        and end_to_end_success
    )

    if primary_success:
        status = "PRIMARY_SUCCESS"
    elif not full_c_completion:
        any_b_success = any(value > 0 for value in b_acceptance_by_domain.values())
        status = (
            "VERIFIER_GUIDED_SEARCH_ONLY"
            if any_b_success and not accepted_residuals
            else "GENERALIZATION_NOT_ESTABLISHED"
        )
    elif solver_easier_all_domains and not end_to_end_success:
        status = "SOLVER_EASIER_END_TO_END_SLOWER"
    else:
        status = "PRIMARY_SPEED_HYPOTHESIS_NOT_SUPPORTED"

    return {
        "classification_version": "vgsat-classification-0.1",
        "status": status,
        "coverage_complete": coverage_complete,
        "duplicate_trials": duplicate_trials,
        "false_acceptances": false_acceptances,
        "records_with_reverification_errors": record_errors,
        "held_out_arm_b_accepted": b_acceptance_by_domain,
        "held_out_arm_c_accepted": c_acceptance_by_domain,
        "held_out_accepted_residuals": len(accepted_residuals),
        "solver_work": comparisons,
        "solver_easier_all_domains": solver_easier_all_domains,
        "arm_a_matched_total_ns": arm_a_total,
        "arm_c_matched_total_ns": arm_c_total,
        "end_to_end_improvement_fraction": end_to_end_improvement,
        "success_threshold": success_threshold,
        "end_to_end_success": end_to_end_success,
        "primary_success": primary_success,
    }


def _metrics(trial: Mapping[str, Any]) -> Mapping[str, Any]:
    value = trial.get("metrics")
    return value if isinstance(value, Mapping) else {}


def _failure_stage(trial: Mapping[str, Any]) -> str | None:
    record = trial.get("record")
    if not isinstance(record, Mapping):
        return None
    stable = record.get("stable_payload")
    if not isinstance(stable, Mapping):
        return None
    failure = stable.get("failure_observation")
    return str(failure.get("stage")) if isinstance(failure, Mapping) else None


def _work_sums(trials: Iterable[Mapping[str, Any]]) -> dict[str, int | None]:
    items = list(trials)
    result: dict[str, int | None] = {}
    for field in SOLVER_WORK_FIELDS:
        values = [_metrics(trial).get(field) for trial in items]
        result[field] = sum(int(value) for value in values) if values and all(
            isinstance(value, int) and not isinstance(value, bool) for value in values
        ) else None
    return result
