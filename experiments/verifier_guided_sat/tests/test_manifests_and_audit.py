from __future__ import annotations

from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

from verifier_guided_sat.audit import (
    DOMAIN_SURFACE_FILES,
    GENERIC_SURFACE_FILES,
    _count_surface_lines,
    scan_public_text,
)
from verifier_guided_sat.canonical import file_digest, read_json
from verifier_guided_sat.instances import load_instances
from verifier_guided_sat.result_validator import validate_artifact_manifest


ROOT = Path(__file__).resolve().parents[1]


def test_instance_manifest_has_preregistered_distribution() -> None:
    entries = load_instances(ROOT)
    assert Counter(entry["domain"] for entry in entries) == {
        "stable_matching": 20,
        "graph_isomorphism": 20,
        "integer_factorization": 20,
    }
    assert Counter(entry["role"] for entry in entries) == {"development": 20, "held_out": 40}


def test_vendored_source_hashes_match_lock() -> None:
    lock = read_json(ROOT / "selected-tools.lock")
    for relative, expected in lock["external_verifier_suite"]["vendored_files"].items():
        assert file_digest(ROOT / "vendor" / "algotune" / relative) == expected


def test_public_experiment_text_has_no_simple_leak_pattern() -> None:
    assert scan_public_text(ROOT) == []


def test_artifact_manifest_rehashes_every_declared_file() -> None:
    manifest = read_json(ROOT / "artifact-manifest.json")
    assert validate_artifact_manifest(ROOT, manifest) == []


def test_engineering_surface_recomputes_from_declared_groups() -> None:
    report = read_json(ROOT / "engineering-surface.json")
    source = ROOT / "verifier_guided_sat"
    generic = {name: _count_surface_lines(source / name) for name in GENERIC_SURFACE_FILES}
    domain = {name: _count_surface_lines(source / name) for name in DOMAIN_SURFACE_FILES}
    assert report["generic_files"] == generic
    assert report["domain_specific_files"] == domain
    assert report["generic_lines"] == sum(generic.values())
    assert report["domain_specific_lines"] == sum(domain.values())


def test_baseline_metrics_conform_to_experiment_schema() -> None:
    schema = read_json(ROOT / "metrics.schema.json")
    validator = Draft202012Validator(schema)
    result = read_json(ROOT / "results" / "baseline.json.gz")
    for trial in result["trials"]:
        validator.validate(trial["metrics"])
