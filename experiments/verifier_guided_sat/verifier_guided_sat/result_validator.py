# Acronyms: Verifier Standard (VSTD).
"""Fail-closed validation for blocked and completed result envelopes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .analysis import classify_live_result
from .canonical import file_digest, read_json
from .independent_validation import independently_validate_record
from .metrics import aggregate_trials
from .vstd_binding import validate_record


ALLOWED_STATUSES = {
    "BASELINE_ONLY_NOT_A_PRIMARY_RESULT",
    "BLOCKED_NO_REAL_LM_RUNTIME",
    "PRIMARY_SUCCESS",
    "PRIMARY_SPEED_HYPOTHESIS_NOT_SUPPORTED",
    "SOLVER_EASIER_END_TO_END_SLOWER",
    "GENERALIZATION_NOT_ESTABLISHED",
    "VERIFIER_GUIDED_SEARCH_ONLY",
    "DIRECT_SAT_COMPARISON_UNAVAILABLE",
    "VSTD_OPERATIONAL_ADVANTAGE_NOT_ESTABLISHED",
}


def validate_result(experiment_root: Path, result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    from jsonschema import Draft202012Validator

    metrics_validator = Draft202012Validator(read_json(experiment_root / "metrics.schema.json"))
    status = result.get("status")
    if status not in ALLOWED_STATUSES:
        errors.append("unknown result status")
    trials = result.get("trials", [])
    if not isinstance(trials, list):
        return errors + ["trials must be an array"]
    for index, trial in enumerate(trials):
        if not isinstance(trial, Mapping) or not isinstance(trial.get("record"), Mapping):
            errors.append(f"trial {index} is malformed")
            continue
        record_errors = validate_record(experiment_root, trial["record"], reexecute=True)
        record_errors.extend(
            independently_validate_record(experiment_root, trial["record"], reexecute=True)
        )
        errors.extend(f"trial {index}: {error}" for error in record_errors)
        metric = trial.get("metrics", {})
        stable = trial["record"].get("stable_payload", {})
        if not isinstance(metric, Mapping) or not isinstance(stable, Mapping):
            errors.append(f"trial {index}: metrics or stable payload is malformed")
            continue
        for schema_error in metrics_validator.iter_errors(metric):
            errors.append(f"trial {index}: metrics schema: {schema_error.message}")
        for field in ("arm", "domain", "instance_id"):
            if trial.get(field) != stable.get(field):
                errors.append(f"trial {index}: {field} disagrees with bound record")
        if bool(metric.get("accepted")) != (stable.get("bounded_claim_status") == "PASS"):
            errors.append(f"trial {index}: accepted metric disagrees with bound claim")
        if bool(metric.get("final_unknown")) == bool(metric.get("accepted")):
            errors.append(f"trial {index}: final_unknown does not complement accepted")
        if bool(metric.get("false_acceptance")):
            errors.append(f"trial {index}: false acceptance is a worst-case invalid trial")
        if metric.get("vstd_reverification_errors") != []:
            errors.append(f"trial {index}: stored VSTD reverification did not pass")
        timings = stable.get("timings_ns")
        if not isinstance(timings, Mapping):
            errors.append(f"trial {index}: bound timings are malformed")
        else:
            if metric.get("total_time_to_outcome_ns") != timings.get("total_system_probe"):
                errors.append(f"trial {index}: total time disagrees with bound probe")
            if metric.get("vstd_reverification_ns") != timings.get(
                "vstd_reverification_probe"
            ):
                errors.append(f"trial {index}: reverification time disagrees with bound probe")
        lm_observation = stable.get("lm_observation")
        if isinstance(lm_observation, Mapping):
            if metric.get("lm_tokens_input") != lm_observation.get("input_tokens"):
                errors.append(f"trial {index}: input tokens disagree with bound observation")
            if metric.get("lm_tokens_output") != lm_observation.get("output_tokens"):
                errors.append(f"trial {index}: output tokens disagree with bound observation")

    if status == "BLOCKED_NO_REAL_LM_RUNTIME":
        freeze = read_json(experiment_root / "freeze-manifest.json")
        if result.get("freeze_digest") != freeze.get("freeze_digest"):
            errors.append("blocked result freeze digest does not match frozen experiment")
        if result.get("live_trial_count") != len(trials):
            errors.append("blocked result live-trial count does not match trials")
        for index, trial in enumerate(trials):
            if not _is_lm_runtime_failure(trial):
                errors.append(f"trial {index}: blocked result contains non-runtime evidence")
    if "aggregate" in result:
        expected_aggregate = aggregate_trials(trials)
        if result.get("aggregate") != expected_aggregate:
            errors.append("result aggregate does not recompute from trials")
    elif result.get("mode") in {"baseline", "live"}:
        errors.append("completed benchmark result is missing aggregate metrics")
    if result.get("mode") == "live":
        baseline = read_json(experiment_root / "results" / "baseline.json.gz")
        freeze = read_json(experiment_root / "freeze-manifest.json")
        expected = classify_live_result(
            trials,
            baseline.get("trials", []),
            success_threshold=float(freeze["success_threshold"]),
        )
        if result.get("analysis") != expected:
            errors.append("live result analysis does not recompute")
        if status != expected.get("status"):
            errors.append("live result status does not match preregistered classification")
    return errors


def _is_lm_runtime_failure(trial: Any) -> bool:
    if not isinstance(trial, Mapping):
        return False
    record = trial.get("record")
    if not isinstance(record, Mapping):
        return False
    stable = record.get("stable_payload")
    if not isinstance(stable, Mapping):
        return False
    failure = stable.get("failure_observation")
    return isinstance(failure, Mapping) and failure.get("stage") == "lm_generation"


def validate_artifact_manifest(experiment_root: Path, manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    files = manifest.get("files")
    if not isinstance(files, Mapping):
        return ["artifact manifest files must be an object"]
    for relative, expected in files.items():
        path = experiment_root / str(relative)
        if not path.is_file():
            errors.append(f"missing artifact: {relative}")
        elif file_digest(path) != expected:
            errors.append(f"artifact digest mismatch: {relative}")
    return errors
