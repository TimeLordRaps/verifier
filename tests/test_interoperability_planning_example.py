"""Terminology: identifier (ID).

Characterization tests for the experimental interoperability planning example.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import verifier
import verifier.interoperability as interoperability


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "interoperability_planning" / "demo.py"
EXPECTED_FACADE = [
    "CandidateStatus",
    "CatalogError",
    "ComponentAvailability",
    "ComponentKind",
    "ComponentLifecycle",
    "ControlSurfaceContext",
    "InteractionMode",
    "InteroperabilityComponentDescriptor",
    "InteroperabilityComponentRegistry",
    "SurfaceAnalysis",
    "SurfaceAnalysisError",
    "SurfaceHole",
    "SurfaceHoleKind",
    "ValidationCandidate",
    "ValidationPlan",
    "analyze_verification_surface",
    "plan_validation",
]


def _load_demo():
    spec = importlib.util.spec_from_file_location("vstd_interoperability_demo", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_experimental_facade_is_exact_and_not_promoted_to_top_level() -> None:
    assert interoperability.__all__ == EXPECTED_FACADE
    for name in EXPECTED_FACADE:
        assert getattr(interoperability, name) is not None
        assert name not in verifier.__all__
    assert "InteroperabilityCatalog" not in interoperability.__all__
    assert "generate_validation_plan" not in interoperability.__all__


def test_example_detects_two_candidates_without_running_checker() -> None:
    demo = _load_demo()
    geometry = demo.build_geometry()
    registry = demo.build_registry()
    assert geometry.validate() == []
    assert demo._checker_invocations == 0

    first = demo.build_demo()
    second = demo.build_demo()

    assert first == second
    assert first["summary"] == {
        "checker_invocations": 0,
        "exact_candidate_count": 2,
        "execution_performed": False,
        "hole_count": 5,
        "ordinary_closed": False,
        "plan_only": True,
        "self_closed": False,
        "unmatched_hole_count": 3,
    }
    assert demo._checker_invocations == 0
    assert first["plan"]["registry_version"] == registry.registry_version
    assert first["plan"]["registry_digest"] == registry.canonical_digest()
    assert first["plan"]["plan_only"] is True
    assert first["plan"]["execution_performed"] is False

    candidates = first["plan"]["candidates"]
    matched = [item for item in candidates if item["status"] == "CANDIDATE"]
    unmatched = [item for item in candidates if item["status"] == "UNMATCHED"]
    holes_by_id = {
        item["hole_id"]: item for item in first["analysis"]["holes"]
    }
    matched_holes = {holes_by_id[item["hole_id"]]["kind"] for item in matched}
    assert matched_holes == {"COORDINATE_STATUS", "MECHANISM"}
    assert {
        (
            holes_by_id[item["hole_id"]]["kind"],
            holes_by_id[item["hole_id"]]["native_status"],
        )
        for item in unmatched
    } == {
        ("SELF_CLOSURE_REQUIREMENT", "MISSING_ADJACENT_V0_V1_ORDERS"),
        ("SELF_CLOSURE_REQUIREMENT", "MISSING_META_FOCUS"),
        ("SELF_CLOSURE_REQUIREMENT", "MISSING_SECONDARY_SUBJECT"),
    }
    assert {item["mechanism_id"] for item in matched} == {
        demo.CHECKER_MECHANISM_ID
    }
    assert {item["relation_id"] for item in matched} == {None}
    assert {item["component_id"] for item in matched} == {
        "component:lexicographic-check"
    }
    assert all(item["component_id"] is None for item in unmatched)


def test_example_rendering_is_deterministic_and_claim_bounded() -> None:
    demo = _load_demo()
    first = demo.render_demo()
    second = demo.render_demo()
    assert first == second
    parsed = json.loads(first)
    assert parsed["summary"]["checker_invocations"] == 0
    assert parsed["analysis"]["strict_wire_loading_status"] == "UNSUPPORTED"
    assert "do not establish" in parsed["plan"]["claim_boundary"]


def test_documented_example_command_is_deterministic_from_checkout() -> None:
    environment = dict(os.environ)
    source_path = str(ROOT / "src")
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_path if not existing else os.pathsep.join((source_path, existing))
    )
    command = [sys.executable, str(DEMO)]
    first = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    second = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert first == second
    parsed = json.loads(first)
    assert parsed["summary"]["checker_invocations"] == 0
    assert parsed["summary"]["exact_candidate_count"] == 2
    assert parsed["summary"]["unmatched_hole_count"] == 3
