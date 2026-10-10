# Acronyms: command-line interface (CLI).
"""CLI runner for public baselines and the separately configured real-LM benchmark."""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from .analysis import classify_live_result
from .canonical import read_json, write_json
from .external_verifiers import load_verifier
from .freeze import validate_freeze
from .harness import VerifierGuidedHarness
from .instances import load_instances, materialize_instances
from .lm_backend import LmConfigurationError, OpenAICompatibleBackend
from .metrics import aggregate_trials
from .noise import measure_development_noise
from .prompts import load_prompts, render_user_prompt
from .result_validator import validate_result


def experiment_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("materialize", "noise", "freeze", "baseline", "live", "validate"),
        required=True,
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    root = experiment_root()
    if args.mode == "materialize":
        entries = materialize_instances(root)
        print(f"materialized {len(entries)} public instances")
        return 0
    if args.mode == "noise":
        output = args.output or root / "development-noise.json"
        write_json(output, measure_development_noise(root))
        print(f"wrote development timing-noise measurements to {output.name}")
        return 0
    if args.mode == "freeze":
        from .freeze import create_freeze

        manifest = create_freeze(root)
        print(f"froze held-out surfaces at {manifest['freeze_digest']}")
        return 0
    if args.mode == "validate":
        if args.output is None:
            parser.error("--output identifies the result to validate")
        errors = validate_result(root, read_json(args.output))
        for error in errors:
            print(error, file=sys.stderr)
        return 1 if errors else 0

    entries = load_instances(root)
    output = args.output or root / "results" / f"{args.mode}.json.gz"
    harness = VerifierGuidedHarness(root)
    trials: list[dict[str, Any]] = []
    started = perf_counter_ns()
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if args.mode == "baseline":
        for entry in entries:
            preparation_started = perf_counter_ns()
            verifier = load_verifier(root, entry["domain"])
            preparation_ns = perf_counter_ns() - preparation_started
            trials.append(
                harness.run_arm_a(
                    entry["instance_id"],
                    verifier,
                    entry["instance"],
                    preparation_ns=preparation_ns,
                ).to_dict()
            )
    else:
        try:
            lm = OpenAICompatibleBackend.from_environment()
        except LmConfigurationError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        _require_freeze(root)
        system_prompt, arm_b_prompt, arm_c_prompt = load_prompts(root)
        for entry in entries:
            preparation_started = perf_counter_ns()
            verifier = load_verifier(root, entry["domain"])
            contract = verifier.contract.to_dict()
            arm_b_user = render_user_prompt(arm_b_prompt, instance=entry["instance"], contract=contract)
            arm_b_preparation_ns = perf_counter_ns() - preparation_started
            arm_b = harness.run_arm_b(
                entry["instance_id"],
                verifier,
                entry["instance"],
                lm,
                system_prompt,
                arm_b_user,
                preparation_ns=arm_b_preparation_ns,
            ).to_dict()
            trials.append(arm_b)
            if _lm_runtime_failed(arm_b):
                break
            preparation_started = perf_counter_ns()
            verifier = load_verifier(root, entry["domain"])
            contract = verifier.contract.to_dict()
            arm_c_user = render_user_prompt(arm_c_prompt, instance=entry["instance"], contract=contract)
            arm_c_preparation_ns = perf_counter_ns() - preparation_started
            arm_c = harness.run_arm_c(
                entry["instance_id"],
                verifier,
                entry["instance"],
                lm,
                system_prompt,
                arm_c_user,
                preparation_ns=arm_c_preparation_ns,
            ).to_dict()
            trials.append(arm_c)
            if _lm_runtime_failed(arm_c):
                break
    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if args.mode == "baseline":
        status = "BASELINE_ONLY_NOT_A_PRIMARY_RESULT"
        analysis = None
    else:
        baseline = read_json(root / "results" / "baseline.json.gz")
        freeze = read_json(root / "freeze-manifest.json")
        analysis = classify_live_result(
            trials,
            baseline.get("trials", []),
            success_threshold=float(freeze["success_threshold"]),
        )
        status = analysis["status"]
    result = {
        "result_version": "vgsat-result-0.1",
        "status": status,
        "mode": args.mode,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "environment": {
            "python": platform.python_version(),
            "platform_class": platform.system(),
            "processor_disclosure": "withheld",
        },
        "elapsed_ns": perf_counter_ns() - started,
        "aggregate": aggregate_trials(trials),
        "analysis": analysis,
        "trials": trials,
    }
    write_json(output, result)
    print(f"wrote {len(trials)} trials to {output.name}")
    return 0


def _require_freeze(root: Path) -> None:
    freeze = read_json(root / "freeze-manifest.json")
    if freeze.get("freeze_state") != "FROZEN_BEFORE_HELD_OUT":
        raise RuntimeError("held-out freeze manifest is absent or not frozen")
    errors = validate_freeze(root)
    if errors:
        raise RuntimeError("held-out freeze validation failed: " + "; ".join(errors))


def _lm_runtime_failed(trial: dict[str, Any]) -> bool:
    stable = trial.get("record", {}).get("stable_payload", {})
    failure = stable.get("failure_observation")
    return isinstance(failure, dict) and failure.get("stage") == "lm_generation"


if __name__ == "__main__":
    raise SystemExit(main())
