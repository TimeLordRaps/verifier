"""Deterministic public benchmark-instance materialization and loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .canonical import canonical_digest, read_json, write_json
from .external_verifiers import SOURCE_COMMIT, load_verifier


DOMAIN_PLAN = {
    "stable_matching": {"role": "development", "n": 6},
    "graph_isomorphism": {"role": "held_out", "n": 8},
    "integer_factorization": {"role": "held_out", "n": 1},
}
INSTANCE_COUNT = 20


def materialize_instances(experiment_root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for domain, plan in DOMAIN_PLAN.items():
        verifier = load_verifier(experiment_root, domain)
        for index in range(INSTANCE_COUNT):
            seed = 10_000 + index
            instance = verifier.generate_problem(n=int(plan["n"]), seed=seed)
            entries.append(
                {
                    "instance_id": f"{domain}-{plan['role']}-{index:03d}",
                    "domain": domain,
                    "role": plan["role"],
                    "generator_n": plan["n"],
                    "generator_seed": seed,
                    "instance": instance,
                    "instance_digest": canonical_digest(instance),
                }
            )
    manifest = {
        "manifest_version": "vgsat-instances-0.1",
        "source": "AlgoTune",
        "source_commit": SOURCE_COMMIT,
        "instances_per_domain": INSTANCE_COUNT,
        "entries": entries,
    }
    write_json(experiment_root / "instances" / "manifest.json", manifest)
    return entries


def load_instances(experiment_root: Path) -> list[dict[str, Any]]:
    manifest = read_json(experiment_root / "instances" / "manifest.json")
    if manifest.get("manifest_version") != "vgsat-instances-0.1":
        raise ValueError("unsupported instance manifest")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError("instance entries must be an array")
    for entry in entries:
        if canonical_digest(entry.get("instance")) != entry.get("instance_digest"):
            raise ValueError(f"instance digest mismatch: {entry.get('instance_id')}")
    return entries


def select_entries(entries: Iterable[dict[str, Any]], roles: set[str]) -> list[dict[str, Any]]:
    return [entry for entry in entries if entry.get("role") in roles]
