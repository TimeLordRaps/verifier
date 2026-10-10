"""Aggregate correctness-first benchmark metrics without hiding unavailable data."""

from __future__ import annotations

from collections import defaultdict
from statistics import median
from typing import Any, Iterable, Mapping


def aggregate_trials(trials: Iterable[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trial in trials:
        grouped[str(trial["arm"])].append(trial)
    return {
        arm: {
            **_summarize(items),
            "by_domain": {
                domain: _summarize(
                    [item for item in items if str(item.get("domain")) == domain]
                )
                for domain in sorted({str(item.get("domain")) for item in items})
            },
        }
        for arm, items in sorted(grouped.items())
    }


def _summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = [_mapping(item.get("metrics")) for item in items]
    return {
        "instances": len(items),
        "accepted": sum(bool(metric.get("accepted")) for metric in metrics),
        "false_acceptances": sum(bool(metric.get("false_acceptance")) for metric in metrics),
        "unknown": sum(bool(metric.get("final_unknown")) for metric in metrics),
        "routes": _sum_int(metrics, "routes"),
        "failed_routes": _sum_int(metrics, "failed_routes"),
        "repeated_routes": _sum_int(metrics, "repeated_routes"),
        "native_verifier_calls": _sum_int(metrics, "native_verifier_calls"),
        "lm_tokens_input": _sum_optional(metrics, "lm_tokens_input"),
        "lm_tokens_output": _sum_optional(metrics, "lm_tokens_output"),
        "median_total_time_to_outcome_ns": _median(metrics, "total_time_to_outcome_ns"),
        "median_lm_generation_ns": _timing_median(items, "lm_generation"),
        "median_harness_ns": _timing_median(items, "harness"),
        "median_sat_time_ns": _median(metrics, "elapsed_ns"),
        "median_native_verifier_ns": _timing_median(items, "native_verifier"),
        "median_orchestration_unattributed_ns": _timing_median(
            items, "orchestration_unattributed"
        ),
        "median_vstd_creation_probe_ns": _timing_median(items, "vstd_creation_probe"),
        "median_vstd_reverification_probe_ns": _timing_median(
            items, "vstd_reverification_probe"
        ),
        "median_decisions": _median(metrics, "decisions"),
        "median_conflicts": _median(metrics, "conflicts"),
        "median_propagations": _median(metrics, "propagations"),
        "median_variables": _median(metrics, "variables"),
        "median_clauses": _median(metrics, "clauses"),
        "median_witness_size": _median(metrics, "witness_size"),
        "unsat_certificates_available": sum(
            metric.get("unsat_certificate_available") is True for metric in metrics
        ),
        "unsat_certificate_bytes": _sum_optional(metrics, "unsat_certificate_size"),
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _median(metrics: list[Mapping[str, Any]], field: str) -> int | float | None:
    values = [
        metric[field]
        for metric in metrics
        if isinstance(metric.get(field), (int, float))
        and not isinstance(metric.get(field), bool)
    ]
    return median(values) if values else None


def _sum_int(metrics: list[Mapping[str, Any]], field: str) -> int:
    return sum(
        int(metric[field])
        for metric in metrics
        if isinstance(metric.get(field), int) and not isinstance(metric.get(field), bool)
    )


def _sum_optional(metrics: list[Mapping[str, Any]], field: str) -> int | None:
    values = [
        int(metric[field])
        for metric in metrics
        if isinstance(metric.get(field), int) and not isinstance(metric.get(field), bool)
    ]
    return sum(values) if values else None


def _timing_median(items: list[dict[str, Any]], field: str) -> int | float | None:
    timings = []
    for item in items:
        record = _mapping(item.get("record"))
        stable = _mapping(record.get("stable_payload"))
        timing = _mapping(stable.get("timings_ns"))
        value = timing.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            timings.append(value)
    return median(timings) if timings else None
