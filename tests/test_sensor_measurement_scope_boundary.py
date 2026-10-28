"""Adversarial scope boundary for software MEASUREMENT and SENSOR evidence."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

import pytest

from verifier.runtime import resource_measurement_execution as execution


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = {
        "schema_version": execution.REQUEST_SCHEMA,
        "nonce": "sensor-measurement-scope-boundary",
        "object_id": "software-resource-meter",
        "object_digest": "sha256:" + "1" * 64,
        "collection_digest": "sha256:" + "2" * 64,
    }
    worker = Path(execution.__file__).with_name(execution.WORKER)
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(worker)],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout)["observations"]


def test_software_resource_evidence_carries_an_executable_nonphysical_scope(
    observations: dict[str, Any],
) -> None:
    assert observations["claim_scope"] == execution.CLAIM_SCOPE
    assert execution.CLAIM_SCOPE["claim_domain"] == "SOFTWARE_RESOURCE_OBSERVATION"
    assert execution.CLAIM_SCOPE["physical_calibration"] == "NOT_ESTABLISHED"
    assert execution.CLAIM_SCOPE["external_phenomenon_truth"] == "NOT_ESTABLISHED"
    assert execution.CLAIM_SCOPE["physical_sensor_identity"] == "NOT_ESTABLISHED"
    assert execution.CLAIM_SCOPE["uncertainty"] == "NOT_ESTABLISHED_BEYOND_RAW_COUNTER_VALUES"


def test_exported_scope_mutation_cannot_move_the_checker_boundary(
    observations: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    changed = deepcopy(observations)
    changed["claim_scope"]["claim_domain"] = "PHYSICAL_SENSOR_OBSERVATION"
    monkeypatch.setitem(execution.CLAIM_SCOPE, "claim_domain", "PHYSICAL_SENSOR_OBSERVATION")
    assert execution.check_observations("SENSOR-2.1", changed) is False


@pytest.mark.parametrize(
    "name,mutate",
    [
        (
            "unit-swap",
            lambda scope: scope["units"].update(
                thread_cpu_ns="byte", traced_peak_bytes="nanosecond"
            ),
        ),
        (
            "timestamp-substitution",
            lambda scope: scope["units"].update(
                observation_interval="wall_clock_nanosecond"
            ),
        ),
        ("uncertainty-omission", lambda scope: scope.pop("uncertainty")),
        (
            "estimate-substitution",
            lambda scope: scope.update(observation_vs_estimate="ESTIMATE"),
        ),
        (
            "fabricated-calibration",
            lambda scope: scope.update(physical_calibration="PASS"),
        ),
        (
            "phenomenon-swap",
            lambda scope: scope.update(phenomenon="ambient temperature"),
        ),
        (
            "resource-counter-relabeled-physical",
            lambda scope: scope.update(claim_domain="PHYSICAL_SENSOR_OBSERVATION"),
        ),
        (
            "unavailable-device-relabeled-selected",
            lambda scope: scope.update(external_device="SELECTED"),
        ),
    ],
)
@pytest.mark.parametrize("coordinate", [row["coordinate"] for row in execution.catalog()])
def test_scope_substitution_never_promotes_software_counters(
    observations: dict[str, Any],
    coordinate: str,
    name: str,
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    del name
    changed = deepcopy(observations)
    mutate(changed["claim_scope"])
    assert execution.check_observations(coordinate, changed) is False


@pytest.mark.parametrize("coordinate", [row["coordinate"] for row in execution.catalog()])
def test_missing_sample_and_count_preserving_control_substitution_refuse(
    observations: dict[str, Any], coordinate: str
) -> None:
    missing = deepcopy(observations)
    missing["runs"][0]["capture"]["steps"].pop()
    assert execution.check_observations(coordinate, missing) is False

    substituted = deepcopy(observations)
    metrics = substituted["sampling"]["normal"]["metrics"]
    metrics[0][1], metrics[1][1] = metrics[1][1], metrics[0][1]
    assert len(metrics) == 2
    assert execution.check_observations(coordinate, substituted) is False


@pytest.mark.parametrize("coordinate", [row["coordinate"] for row in execution.catalog()])
def test_stale_acquisition_binding_refuses(observations: dict[str, Any], coordinate: str) -> None:
    changed = deepcopy(observations)
    changed["runs"][1]["challenge"] = changed["runs"][0]["challenge"]
    assert execution.check_observations(coordinate, changed) is False
