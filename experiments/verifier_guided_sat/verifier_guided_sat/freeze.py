"""Create and verify the pre-held-out freeze manifest."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import canonical_digest, file_digest, read_json, write_json
from .external_verifiers import load_verifier
from .sat_backend import CadicalBackend


FROZEN_FILES = (
    "PREREGISTRATION.md",
    "RESEARCH.md",
    "metrics.schema.json",
    "requirements-experiment.txt",
    "prompts/system.txt",
    "prompts/arm_b.txt",
    "prompts/arm_c.txt",
    "verifier_guided_sat/analysis.py",
    "verifier_guided_sat/benchmark.py",
    "verifier_guided_sat/canonical.py",
    "verifier_guided_sat/contracts.py",
    "verifier_guided_sat/route.py",
    "verifier_guided_sat/sat_backend.py",
    "verifier_guided_sat/lm_backend.py",
    "verifier_guided_sat/metrics.py",
    "verifier_guided_sat/noise.py",
    "verifier_guided_sat/harness.py",
    "verifier_guided_sat/independent_validation.py",
    "verifier_guided_sat/prompts.py",
    "verifier_guided_sat/result_validator.py",
    "verifier_guided_sat/vstd_binding.py",
    "verifier_guided_sat/baselines.py",
    "verifier_guided_sat/external_verifiers.py",
    "verifier_guided_sat/freeze.py",
    "verifier_guided_sat/reserve_verifiers.py",
    "verifier_guided_sat/instances.py",
    "instances/manifest.json",
    "development-noise.json",
    "selected-tools.lock",
)


def create_freeze(experiment_root: Path) -> dict[str, Any]:
    noise = read_json(experiment_root / "development-noise.json")
    contracts = {
        domain: load_verifier(experiment_root, domain).contract.digest
        for domain in ("stable_matching", "graph_isomorphism", "integer_factorization")
    }
    stable = {
        "freeze_version": "vgsat-freeze-0.1",
        "freeze_state": "FROZEN_BEFORE_HELD_OUT",
        "freeze_date_utc": datetime.now(timezone.utc).date().isoformat(),
        "held_out_live_evaluation_started": False,
        "files": {relative: file_digest(experiment_root / relative) for relative in FROZEN_FILES},
        "verifier_contract_digests": contracts,
        "solver_configuration": CadicalBackend().configuration,
        "solver_configuration_digest": canonical_digest(CadicalBackend().configuration),
        "timing_procedure": {
            "clock": "perf_counter_ns",
            "total_components": [
                "lm_generation",
                "harness",
                "sat",
                "native_verifier",
                "orchestration_unattributed",
                "vstd_creation_probe",
                "vstd_reverification_probe",
            ],
            "total_metric": "total_system_probe",
            "noise_rule": noise["rule"],
            "threshold": noise["preregistered_aggregate_improvement_threshold"],
        },
        "success_threshold": noise["preregistered_aggregate_improvement_threshold"],
        "generic_code_changed_after_live_held_out_start": 0,
    }
    manifest = {**stable, "freeze_digest": canonical_digest(stable)}
    write_json(experiment_root / "freeze-manifest.json", manifest)
    return manifest


def validate_freeze(experiment_root: Path) -> list[str]:
    manifest = read_json(experiment_root / "freeze-manifest.json")
    errors: list[str] = []
    stable = {key: value for key, value in manifest.items() if key != "freeze_digest"}
    if canonical_digest(stable) != manifest.get("freeze_digest"):
        errors.append("freeze_digest mismatch")
    for relative, expected in manifest.get("files", {}).items():
        path = experiment_root / relative
        if not path.is_file() or file_digest(path) != expected:
            errors.append(f"frozen file mismatch: {relative}")
    current_contracts = {
        domain: load_verifier(experiment_root, domain).contract.digest
        for domain in ("stable_matching", "graph_isomorphism", "integer_factorization")
    }
    if current_contracts != manifest.get("verifier_contract_digests"):
        errors.append("verifier contract digest mismatch")
    configuration = CadicalBackend().configuration
    if canonical_digest(configuration) != manifest.get("solver_configuration_digest"):
        errors.append("solver configuration digest mismatch")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    create_freeze(root)
    errors = validate_freeze(root)
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
