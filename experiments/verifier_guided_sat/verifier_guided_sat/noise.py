"""Development-domain timing-noise measurement used before the held-out freeze."""

from __future__ import annotations

from pathlib import Path
from statistics import median
from time import perf_counter_ns
from typing import Any

from .external_verifiers import load_verifier
from .harness import VerifierGuidedHarness
from .instances import load_instances


def measure_development_noise(experiment_root: Path, *, repeats: int = 5) -> dict[str, Any]:
    """Run Arm A repeatedly and derive the preregistered aggregate threshold."""

    if repeats < 3:
        raise ValueError("at least three repeats are required")
    entries = [entry for entry in load_instances(experiment_root) if entry["role"] == "development"]
    rows: list[dict[str, Any]] = []
    for entry in entries:
        timings: list[int] = []
        for _ in range(repeats):
            preparation_started = perf_counter_ns()
            verifier = load_verifier(experiment_root, entry["domain"])
            preparation_ns = perf_counter_ns() - preparation_started
            trial = VerifierGuidedHarness(experiment_root).run_arm_a(
                entry["instance_id"],
                verifier,
                entry["instance"],
                preparation_ns=preparation_ns,
            )
            timings.append(trial.metrics["total_time_to_outcome_ns"])
        center = int(median(timings))
        mad = float(median(abs(value - center) for value in timings))
        rows.append(
            {
                "instance_id": entry["instance_id"],
                "median_total_ns": center,
                "relative_mad": mad / center if center else 0.0,
                "repeat_total_ns": timings,
            }
        )
    relative_mad_median = float(median(row["relative_mad"] for row in rows))
    threshold = max(0.10, 3 * relative_mad_median)
    return {
        "measurement_version": "vgsat-noise-0.1",
        "domain": "stable_matching",
        "instances": len(entries),
        "repeats_per_instance": repeats,
        "timing_metric": "total_time_to_outcome_ns",
        "relative_mad_median": relative_mad_median,
        "rule": "max(0.10, 3 * median per-instance relative MAD)",
        "preregistered_aggregate_improvement_threshold": threshold,
        "rows": rows,
    }
