"""Source-owned measurement and acquisition checks for Verifier Standard (VSTD)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from test_package_polish import declared_package
from test_package_ledger_execution import select_execution as ledger_selection
from test_package_kind_requirements import save
from verifier.runtime import package_polish as package, resource_measurement_execution as execution
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime.manifest_gate import obligation_catalog, assess_object_gate


NAMES = {
    "MEASUREMENT-1.1-transition-resource-meaning", "MEASUREMENT-2.1-fresh-step-correspondence",
    "MEASUREMENT-3.1-invalid-resource-records", "SENSOR-1.1-acquisition-source-binding",
    "SENSOR-2.1-transition-sampling-interval", "SENSOR-3.1-acquisition-fault-cleanup",
}


def test_resource_measurement_has_reasoned_executable_routes() -> None:
    routes = {row["obligation_id"]: row for row in obligation_catalog()}
    assert NAMES <= routes.keys()
    assert all(routes[name]["reason"].strip() and routes[name]["exact_claim"].strip() for name in NAMES)


@pytest.mark.parametrize(
    "coordinate,terms",
    [
        ("MEASUREMENT-1.1", ("observation", "estimate")),
        ("MEASUREMENT-2.1", ("unit", "reference frame", "uncertainty")),
        ("SENSOR-2.1", ("calibration", "envelope", "drift")),
    ],
)
def test_tier_zero_measurement_surfaces_are_named_by_executable_routes(
    coordinate: str, terms: tuple[str, ...]
) -> None:
    route = next(row for row in execution.catalog() if row["coordinate"] == coordinate)
    text = (route["reason"] + " " + route["exact_claim"]).lower()
    assert all(term in text for term in terms)


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = {"schema_version": execution.REQUEST_SCHEMA, "nonce": "resource-control-regression",
        "object_id": "meter", "object_digest": "sha256:" + "1" * 64, "collection_digest": "sha256:" + "2" * 64}
    result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(request).encode(), capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)
    assert report["request"] == request and report["source_pins"] == source_pins()
    assert len(result.stdout) < 1024 * 1024
    return report["observations"]


@pytest.mark.parametrize("coordinate", [row["coordinate"] for row in execution.catalog()])
def test_actual_resource_execution_satisfies_finite_claim(observations: dict[str, Any], coordinate: str) -> None:
    assert execution.check_observations(coordinate, observations)


@pytest.mark.parametrize("coordinate,path,replacement", [
    ("MEASUREMENT-1.1", ("runs", 0, "capture", "method"), "total-device"),
    ("MEASUREMENT-1.1", ("claim_scope", "observation_vs_estimate"), "ESTIMATE"),
    ("MEASUREMENT-1.1", ("runs", 0, "capture", "steps", 0, "thread_cpu_ns"), True),
    ("MEASUREMENT-1.1", ("runs", 0, "capture", "steps", 0, "traced_peak_bytes"), -1),
    ("MEASUREMENT-1.1", ("faults", "process-bool", "returned"), 0),
    ("MEASUREMENT-1.1", ("runs",), []),
    ("MEASUREMENT-2.1", ("runs", 1, "workload_digest"), "wrong"),
    ("MEASUREMENT-2.1", ("faults", "challenge", "returned"), True),
    ("MEASUREMENT-2.1", ("faults", "state", "exception"), None),
    ("MEASUREMENT-3.1", ("faults", "cpu-overbound", "returned"), True),
    ("MEASUREMENT-3.1", ("faults", "peak-bool", "returned"), True),
    ("MEASUREMENT-3.1", ("faults", "missing-step", "exception"), "OSError"),
    ("MEASUREMENT-3.1", ("faults", "unavailable", "returned"), True),
    ("MEASUREMENT-3.1", ("faults", "timeout", "calls"), True),
    ("SENSOR-1.1", ("runs", 0, "loaded_source_manifest"), {}),
    ("SENSOR-1.1", ("runs", 0, "bootstrap_digest"), "wrong"),
    ("SENSOR-1.1", ("faults", "stale-policy", "calls"), 1),
    ("SENSOR-1.1", ("faults", "recapture", "returned"), True),
    ("SENSOR-1.1", ("runs", 0, "source_manifest", "verifier", "package"), 1),
    ("SENSOR-1.1", ("runs", 0, "loaded_source_manifest", "verifier", "package"), 1),
    ("SENSOR-1.1", ("faults", "source-type", "returned"), True),
    ("SENSOR-1.1", ("faults", "loaded-source-type", "returned"), True),
    ("SENSOR-1.1", ("faults", "stale-policy-type", "returned"), True),
    ("SENSOR-1.1", ("faults", "recapture-type", "returned"), True),
    ("SENSOR-2.1", ("sampling", "normal", "metrics", 0, 1), 113),
    ("SENSOR-2.1", ("sampling", "normal", "metrics", 0, 2), 7),
    ("SENSOR-2.1", ("sampling", "normal", "events"), []),
    ("SENSOR-2.1", ("sampling", "normal", "active"), 0),
    ("SENSOR-3.1", ("sampling", "clock-end", "active"), True),
    ("SENSOR-3.1", ("sampling", "memory", "returned"), True),
    ("SENSOR-3.1", ("sampling", "invalid", "metrics"), []),
])
def test_resource_oracle_refutes_wrong_evidence(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    changed = deepcopy(observations)
    row = changed
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("field", ["challenge", "run_id"])
def test_freshness_requires_different_acquisitions(observations: dict[str, Any], field: str) -> None:
    changed = deepcopy(observations)
    first, second = changed["runs"]
    if field == "run_id":
        first, second = first["capture"], second["capture"]
    second[field] = first[field]
    assert not execution.check_observations("MEASUREMENT-2.1", changed)


def test_freshness_accepts_platform_pid_reuse_when_challenge_and_run_id_are_fresh(
    observations: dict[str, Any],
) -> None:
    """A recycled operating-system PID is identity context, not freshness."""
    changed = deepcopy(observations)
    first, second = changed["runs"]
    second["capture"]["process_id"] = first["capture"]["process_id"]
    frame = {key: second["capture"][key] for key in execution.FRAME_KEYS}
    for index, row in enumerate(second["capture"]["steps"]):
        row["binding_digest"] = execution._step_binding(frame, index, row)
    assert execution.check_observations("MEASUREMENT-2.1", changed)


def test_full_platform_pid_range_is_well_formed(observations: dict[str, Any]) -> None:
    changed = deepcopy(observations)
    capture = changed["runs"][0]["capture"]
    capture["process_id"] = 2**64 - 1
    frame = {key: capture[key] for key in execution.FRAME_KEYS}
    for index, row in enumerate(capture["steps"]):
        row["binding_digest"] = execution._step_binding(frame, index, row)
    assert execution.check_observations("MEASUREMENT-1.1", changed)


def test_fresh_parent_accepts_full_platform_pid_range(
    monkeypatch: pytest.MonkeyPatch, observations: dict[str, Any]
) -> None:
    from verifier.domains.contracts import sim_fresh_worker, sim_resource_fresh as subject
    from verifier.runtime.resource_measurement_worker import rebound, workload

    def altered(bootstrap: bytes, payload: bytes, timeout: int) -> dict:
        value = rebound(observations["runs"][0], json.loads(payload)["challenge"])
        capture = value["capture"]
        capture["process_id"] = 2**64 - 1
        frame = {key: capture[key] for key in sim_fresh_worker.FRAME_KEYS}
        for index, row in enumerate(capture["steps"]):
            row["binding_digest"] = sim_fresh_worker.step_binding(frame, index, row)
        return value

    monkeypatch.setattr(subject, "_run", altered)
    assert subject._execute(workload(), subject.sim_resource_fresh_policy())["capture"]["process_id"] == 2**64 - 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["runs"].clear(),
        lambda value: value["faults"]["recapture"].update(returned=True),
        lambda value: value["faults"]["stale-policy"].update(returned=True),
    ],
)
def test_sensor_calibration_envelope_requires_live_source_bound_acquisition(
    observations: dict[str, Any], mutation: Any
) -> None:
    """SENSOR-0.2 cannot use isolated injected metrics as package evidence."""
    changed = deepcopy(observations)
    mutation(changed)
    assert not execution.check_observations("SENSOR-2.1", changed)


@pytest.mark.parametrize("defect,coordinate", [
    ("current-allocation", "SENSOR-2.1"),
    ("clock-addition", "SENSOR-2.1"),
    ("missing-stop", "SENSOR-3.1"),
])
def test_controls_detect_broken_actual_meter(monkeypatch: pytest.MonkeyPatch, defect: str,
        coordinate: str, observations: dict[str, Any]) -> None:
    from verifier.domains.contracts import sim_fresh_worker as subject
    from verifier.domains.contracts import sim_resource_fresh
    from verifier.runtime.resource_measurement_worker import sampling, workload
    assert execution.check_observations(coordinate, observations)
    if defect == "current-allocation":
        monkeypatch.setattr(subject, "_traced_peak_bytes",
                            lambda: subject.tracemalloc.get_traced_memory()[0])
    elif defect == "clock-addition":
        monkeypatch.setattr(subject, "_elapsed_thread_ns",
                            lambda start: subject.time.thread_time_ns() + start)
    else:
        monkeypatch.setattr(subject, "_stop_tracing", lambda: None)
    changed = deepcopy(observations)
    binding = {"challenge": observations["frame"]["challenge"], "source_manifest": sim_resource_fresh.source_manifest()}
    changed["sampling"] = {name: sampling(workload(), name, observations["frame"], binding) for name in changed["sampling"]}
    assert not execution.check_observations(coordinate, changed)


def test_controls_detect_disabled_actual_capture_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains.contracts import sim_resource_fresh as subject
    from verifier.runtime.resource_measurement_worker import observe
    original = subject._require

    def altered(condition: bool, code: str) -> None:
        if code != "FRESH_STEP_BINDING_DIFFERS":
            original(condition, code)

    monkeypatch.setattr(subject, "_require", altered)
    assert not execution.check_observations("MEASUREMENT-3.1", observe())


def test_selected_meter_reaches_package_and_focused_gates(declared_package: tuple) -> None:
    root, retained, _ = declared_package
    document = ledger_selection(root, retained)
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row["specializations"].extend(["MEASUREMENT", "SENSOR"])
    row["surfaces"].append("file:" + execution.IMPLEMENTATION)
    save(root, document)
    missing = package.assess_package_polish(1, root)
    own = [r for r in missing["obligation_instances"] if r["object_id"] == "external" and r["object_kind"] in {"MEASUREMENT", "SENSOR"}]
    assert len(own) == 2 and all(r["status"] == "UNKNOWN" for r in own)
    document["namespace"]["execution_checks"].append({"object_id": "external", "mechanism": execution.ADAPTER,
        "reason": "The object owns the actual fresh-resource acquisition and validation implementation.",
        "evidence": [{"path": execution.IMPLEMENTATION, "sha256": package.binding.bytes_digest((root / execution.IMPLEMENTATION).read_bytes())}]})
    save(root, document)
    report = package.assess_package_polish(3, root)
    own = [r for r in report["obligation_instances"] if r["object_id"] == "external" and r["object_kind"] in {"MEASUREMENT", "SENSOR"}]
    assert len(own) == 6 and all(r["status"] == "PASS" for r in own), own
    assert report["status"] == "UNKNOWN" and not report["polished"]
    for kind in ("MEASUREMENT", "SENSOR"):
        contract = next(r for r in report["kind_requirements"]["contract_coverage"]["contracts"] if r["object_id"] == "external" and r["kind"] == kind)
        assert contract["finite_check_status"] == "PASS" and contract["status"] == "UNKNOWN" and contract["residual_requirements"]
    gate = assess_object_gate("external", "SENSOR-2.1-transition-sampling-interval", root)
    assert gate["status"] == "PASS", gate["findings"]
    assert gate["instance"]["selected_package_check"]["replay"]["request"]["nonce"] != own[0]["selected_package_check"]["replay"]["request"]["nonce"]


@pytest.mark.parametrize("conflict", [None, "source", "ownership", "measurement", "sensor", "declaration", "selection"])
def test_reviewed_measurement_selection_is_atomic_and_no_overwrite(conflict: str | None) -> None:
    from verifier.runtime import package_manifest_migration, package_namespace_review

    select = package_manifest_migration._select_resource_measurement
    root = Path(execution.__file__).resolve().parents[3]
    review = package_namespace_review.review_document()["vstd-simulation"]
    paths = [execution.IMPLEMENTATION, "src/verifier/domains/contracts/sim_fresh_worker.py",
             "src/verifier/domains/contracts/sim_fresh_bootstrap.py"]
    files = {path: package.binding.bytes_digest((root / path).read_bytes()) for path in review["owned_paths"]}
    row = {"object_id": "vstd-simulation", "kind": "SIM",
           "surfaces": ["file:" + path for path in review["owned_paths"]], "specializations": [],
           "classification": {kind: {"status": "UNRESOLVED", "reason": "", "evidence": []}
                              for kind in ("MEASUREMENT", "SENSOR")}, "obligations": {}}
    namespace = {"objects": [row], "execution_checks": []}
    if conflict == "source":
        files[paths[1]] = "sha256:" + "0" * 64
    elif conflict == "ownership":
        row["surfaces"].remove("file:" + paths[-1])
    elif conflict in ("measurement", "sensor"):
        row["classification"][conflict.upper()]["status"] = "DOES_NOT_APPLY"
    elif conflict == "declaration":
        row["obligations"]["SENSOR-0.3-sampling-and-faults"] = {"reason": "Prior review", "declaration": {"sampling": "different"}}
    elif conflict == "selection":
        namespace["execution_checks"] = [{"object_id": row["object_id"], "mechanism": execution.ADAPTER, "reason": "different", "evidence": []}]
    before = deepcopy(namespace)
    if conflict:
        with pytest.raises(ValueError, match="PACKAGE_MIGRATION_"):
            select(root, namespace, row, files)
        assert namespace == before
    else:
        select(root, namespace, row, files)
        selected = deepcopy(namespace)
        select(root, namespace, row, files)
        assert namespace == selected
        assert row["specializations"] == ["MEASUREMENT", "SENSOR"]
        for kind in ("MEASUREMENT", "SENSOR"):
            expected = review["classification"][kind]
            assert row["classification"][kind] == {
                "status": expected["status"],
                "reason": expected["reason"],
                "evidence": [
                    {"path": path, "sha256": files[path]}
                    for path in expected["evidence_paths"]
                ],
            }
        expected_declarations = {
            name: value for name, value in review["declarations"].items()
            if name.startswith(("MEASUREMENT-", "SENSOR-"))
        }
        assert {
            name: binding["declaration"] for name, binding in row["obligations"].items()
        } == expected_declarations
        assert len(row["obligations"]) == 6 and len(namespace["execution_checks"]) == 1


ALL_COORDINATES = [row["coordinate"] for row in execution.catalog()]


def _add_unknown_top(value: dict[str, Any]) -> None:
    value["arrival_time"] = 0


def _add_unknown_run(value: dict[str, Any]) -> None:
    value["runs"][1]["arrival_time_ns"] = 0


def _add_unknown_sample(value: dict[str, Any]) -> None:
    value["sampling"]["normal"]["estimated_device_bytes"] = 0


def _add_unknown_fault(value: dict[str, Any]) -> None:
    value["faults"]["physical-estimate"] = {"returned": False, "exception": None, "message": None, "calls": 0}


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("mutation", [_add_unknown_top, _add_unknown_run, _add_unknown_sample, _add_unknown_fault],
    ids=["top", "run", "sample", "fault"])
def test_closed_schema_refuses_unknown_fields(observations: dict[str, Any], coordinate: str, mutation: Any) -> None:
    """Estimate, timestamp and unit-renamed fields are not evidence unless the schema names them."""
    changed = deepcopy(observations)
    mutation(changed)
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("removal", [
    lambda value: value["runs"][0].pop("capture"),
    lambda value: value["runs"][0].pop("loaded_source_manifest"),
    lambda value: value["sampling"].pop("normal"),
    lambda value: value["faults"].pop("timeout"),
    lambda value: value.pop("faults"),
], ids=["capture", "loaded-manifest", "sample", "fault", "faults"])
def test_missing_observation_fields_refute_instead_of_raising(observations: dict[str, Any], coordinate: str,
        removal: Any) -> None:
    """A missing field is absent evidence: refute, never raise KeyError into a verdict path."""
    changed = deepcopy(observations)
    removal(changed)
    assert execution.check_observations(coordinate, changed) is False


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("mutation", [
    lambda value: value["runs"][1].update(challenge=value["runs"][0]["challenge"]),
    lambda value: value["runs"][1]["capture"].update(run_id=value["runs"][0]["capture"]["run_id"]),
    lambda value: value["runs"][1]["capture"].update(process_id=value["runs"][0]["capture"]["process_id"]),
    lambda value: value["runs"][1].update(loaded_source_manifest=value["runs"][1]["source_manifest"]),
    lambda value: value["runs"][1].update(capture=value["runs"][0]["capture"]),
], ids=["stale-challenge", "reused-run-id", "reused-process", "aliased-manifest", "aliased-capture"])
def test_fresh_pair_is_distinct_and_unaliased(observations: dict[str, Any], coordinate: str, mutation: Any) -> None:
    """Every observation is two distinct fresh acquisitions; shared objects are substitution, not replication."""
    changed = deepcopy(observations)
    mutation(changed)
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("coordinate,path,replacement", [
    ("MEASUREMENT-2.1", ("runs", 0, "capture", "steps", 0, "thread_cpu_ns"), 1.0),
    ("MEASUREMENT-2.1", ("runs", 0, "capture", "steps", 0, "thread_cpu_ns"), float("nan")),
    ("MEASUREMENT-2.1", ("runs", 0, "capture", "steps", 1), {"step": 0, "input_state_digest": "x", "output_state_digest": "y", "thread_cpu_ns": 0, "traced_peak_bytes": 0}),
    ("MEASUREMENT-2.1", ("runs", 0, "capture", "steps", 0, "thread_cpu_us"), 1),
    ("SENSOR-2.1", ("sampling", "normal", "metrics", 0, 1), 13.0),
    ("SENSOR-2.1", ("sampling", "normal", "metrics", 0), [1, 13, 64]),
])
def test_unit_and_type_confusion_stays_refused(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    changed = deepcopy(observations)
    row = changed
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0.5, 1.0], ids=["nan", "inf", "half", "whole"])
def test_nonfinite_or_float_observations_refute_without_raising(observations: dict[str, Any], coordinate: str,
        value: float) -> None:
    """Measurements are integers; a float in a fault row once escaped as a canonical-JSON ValueError."""
    changed = deepcopy(observations)
    changed["faults"]["timeout"]["calls"] = value
    assert execution.check_observations(coordinate, changed) is False


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("mutation", [
    lambda value: value["runs"][0].update(bootstrap_digest="sha256:" + "0" * 64),
    lambda value: value["runs"][1].update(workload_digest="sha256:" + "0" * 64),
    lambda value: value["runs"][0]["loaded_source_manifest"].clear(),
    lambda value: value["runs"][0].update(source_recheck=True),
    lambda value: value["sampling"]["normal"].update(metrics=[[0, 14, 64], [1, 31, 96]]),
    lambda value: value["sampling"]["clock-end"].update(events=["validate", "start", "clock", "stop"]),
    lambda value: value["faults"]["challenge"].update(message="other binding"),
    lambda value: value["runs"][0]["capture"]["steps"][0].update(thread_cpu_ns=float("nan")),
], ids=["bootstrap", "workload", "loaded-manifest", "recheck-type", "normal-metrics", "clock-end-events",
        "fault-message", "nonfinite-step"])
def test_universal_oracles_pin_provenance_workload_and_controls(observations: dict[str, Any], coordinate: str,
        mutation: Any) -> None:
    """Provenance, exact workload and control outcomes are evidence for every claim, not one claim's private check."""
    changed = deepcopy(observations)
    mutation(changed)
    assert execution.check_observations(coordinate, changed) is False


def test_control_tables_cover_exactly_the_emitted_names() -> None:
    assert set(execution.CONTROL_FAULTS) == execution.FAULT_NAMES
    assert set(execution.CONTROL_SAMPLING) == execution.SAMPLING_NAMES


def test_unregistered_coordinate_still_raises(observations: dict[str, Any]) -> None:
    """Fail-closed refutation must not hide a request for a claim that does not exist."""
    with pytest.raises(ValueError, match="PACKAGE_EXECUTION_COORDINATE_UNREGISTERED"):
        execution.check_observations("MEASUREMENT-9.9", observations)


# Each interval property is broken alone; the other two must still hold for the same capture.
INTERVAL_PROPERTIES = {
    "ordering": ("_timing_ordered", lambda run: run["capture"]["steps"][1]["observation_interval"].update(
        start_ns=run["capture"]["steps"][0]["arrival_interval"]["end_ns"] - 1)),
    "distinction": ("_arrival_distinct", lambda run: run["capture"]["steps"][1]["arrival_interval"].update(
        start_ns=run["capture"]["steps"][1]["observation_interval"]["start_ns"])),
    "latency": ("_latency_bounded", lambda run: run["capture"]["steps"][1]["arrival_interval"].update(
        end_ns=run["capture"]["steps"][1]["arrival_interval"]["start_ns"] + execution.LATENCY_BOUND_NS + 1)),
}

RECOVERY_BREAKS = {
    "tracer-left-on": lambda value: value["recovery"].update(tracing_after_capture=True),
    "fault-not-cleaned": lambda value: value["recovery"]["cases"]["memory"].update(tracing_after_fault=True),
    "clean-not-normal": lambda value: value["recovery"]["cases"]["memory"]["clean"]["metrics"][0].__setitem__(1, 14),
    "clean-missing": lambda value: value["recovery"]["cases"]["memory"].pop("clean"),
    "capture-other-process": lambda value: value["recovery"]["capture"].update(process_id=value["frame"]["process_id"] + 1),
}

TRANSPLANTS = {
    "step-from-other-run": lambda value: value["runs"][0]["capture"]["steps"].__setitem__(
        0, deepcopy(value["runs"][1]["capture"]["steps"][0])),
    "step-binding-copied": lambda value: value["runs"][0]["capture"]["steps"][0].update(
        binding_digest=value["runs"][1]["capture"]["steps"][0]["binding_digest"]),
    "capture-challenge": lambda value: value["runs"][0]["capture"].update(challenge=value["runs"][1]["challenge"]),
    "capture-source": lambda value: value["runs"][0]["capture"].update(source_digest="sha256:" + "0" * 64),
    "frame-challenge": lambda value: value["frame"].update(challenge=value["runs"][0]["challenge"]),
    "frame-run-id": lambda value: value["frame"].update(run_id=value["runs"][0]["capture"]["run_id"]),
    "sampling-binding": lambda value: value["sampling"]["normal"].update(
        binding_digest=value["sampling"]["memory"]["binding_digest"]),
    "recovery-capture-frame": lambda value: value["recovery"]["capture"].update(challenge=value["runs"][0]["challenge"]),
}

PARENT_REFUSALS = {
    "ordering": ("FRESH_STEP_INTERVAL_DIFFERS", lambda steps: steps[1]["observation_interval"].update(
        start_ns=steps[0]["arrival_interval"]["end_ns"] - 1)),
    "distinction": ("FRESH_STEP_INTERVAL_DIFFERS", lambda steps: steps[1]["arrival_interval"].update(
        start_ns=steps[1]["observation_interval"]["start_ns"])),
    "latency": ("FRESH_STEP_INTERVAL_DIFFERS", lambda steps: steps[1]["arrival_interval"].update(
        end_ns=steps[1]["arrival_interval"]["start_ns"] + execution.LATENCY_BOUND_NS + 1)),
    "transplant": ("FRESH_STEP_BINDING_DIFFERS", lambda steps: steps.__setitem__(0, deepcopy(steps[1]))),
}


def test_every_row_carries_frame_binding_and_intervals(observations: dict[str, Any]) -> None:
    frame = observations["frame"]
    assert set(frame) == execution.FRAME_KEYS
    for run in observations["runs"]:
        capture = run["capture"]
        assert set(capture) == execution.CAPTURE_KEYS
        assert capture["challenge"] == run["challenge"]
        assert all(set(row) == execution.STEP_KEYS for row in capture["steps"])
    assert set(observations["recovery"]) == execution.RECOVERY_KEYS
    assert all(row["binding_digest"] for row in observations["sampling"].values())
    assert set(observations["recovery"]["cases"]) == execution.ACQUISITION_FAULTS
    assert all(set(case) == execution.RECOVERY_CASE_KEYS for case in observations["recovery"]["cases"].values())


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("payload", ["metric", "interval"])
def test_step_binding_refuses_in_range_payload_forgery(
    observations: dict[str, Any], coordinate: str, payload: str
) -> None:
    """Changing a plausible raw value without its source-produced binding is still forgery."""
    changed = deepcopy(observations)
    row = changed["runs"][0]["capture"]["steps"][0]
    if payload == "metric":
        row["thread_cpu_ns"] += 1
    else:
        row["observation_interval"]["end_ns"] += 1
        row["arrival_interval"]["start_ns"] += 1
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("name", sorted(execution.ACQUISITION_FAULTS))
def test_every_acquisition_fault_refuses_cleans_and_recovers(
    observations: dict[str, Any], name: str
) -> None:
    case = observations["recovery"]["cases"][name]
    assert case["fault"]["returned"] is False
    assert case["fault"]["exception"] == "OSError"
    assert case["tracing_after_fault"] is False
    assert case["clean"]["returned"] is True
    assert case["tracing_after_clean"] is False
    assert execution.check_observations("SENSOR-3.1", observations)


@pytest.mark.parametrize("name", sorted(INTERVAL_PROPERTIES))
def test_each_interval_property_breaks_on_its_own(observations: dict[str, Any], name: str) -> None:
    helper, mutation = INTERVAL_PROPERTIES[name]
    changed = deepcopy(observations)
    mutation(changed["runs"][0])
    capture = changed["runs"][0]["capture"]
    assert not getattr(execution, helper)(capture)
    assert all(getattr(execution, other)(capture) for other, _ in INTERVAL_PROPERTIES.values() if other != helper)
    assert not execution.check_observations("SENSOR-2.1", changed)


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("name", sorted(RECOVERY_BREAKS))
def test_recovery_after_fault_is_refused(observations: dict[str, Any], coordinate: str, name: str) -> None:
    changed = deepcopy(observations)
    RECOVERY_BREAKS[name](changed)
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("coordinate", ALL_COORDINATES)
@pytest.mark.parametrize("name", sorted(TRANSPLANTS))
def test_transplanted_bindings_are_refused(observations: dict[str, Any], coordinate: str, name: str) -> None:
    changed = deepcopy(observations)
    TRANSPLANTS[name](changed)
    assert not execution.check_observations(coordinate, changed)


def test_absolute_monotonic_offsets_are_not_claimed(observations: dict[str, Any]) -> None:
    """Intervals order steps within one process; absolute counter values and cross-process offsets are not evidence."""
    changed = deepcopy(observations)
    for run in changed["runs"]:
        capture = run["capture"]
        frame = {key: capture[key] for key in execution.FRAME_KEYS}
        for index, row in enumerate(capture["steps"]):
            for name in ("observation_interval", "arrival_interval"):
                row[name]["start_ns"] -= 1000
                row[name]["end_ns"] -= 1000
            row["binding_digest"] = execution._step_binding(frame, index, row)
    assert execution.check_observations("SENSOR-2.1", changed)


@pytest.mark.parametrize("name", sorted(PARENT_REFUSALS))
def test_fresh_worker_parent_refuses_altered_step_records(monkeypatch: pytest.MonkeyPatch, observations: dict[str, Any],
        name: str) -> None:
    """The emitter's own parent refuses altered timing and transplanted rows before any capture is returned."""
    from verifier.domains.contracts import sim_resource_fresh as subject
    from verifier.runtime.resource_measurement_worker import rebound, workload
    code, mutation = PARENT_REFUSALS[name]

    def altered(bootstrap: bytes, payload: bytes, timeout: int) -> dict:
        value = rebound(observations["runs"][0], json.loads(payload)["challenge"])
        capture = value["capture"]
        mutation(capture["steps"])
        if name != "transplant":
            frame = {key: capture[key] for key in execution.FRAME_KEYS}
            for index, row in enumerate(capture["steps"]):
                row["binding_digest"] = execution._step_binding(frame, index, row)
        return value

    monkeypatch.setattr(subject, "_run", altered)
    with pytest.raises(ValueError, match=code):
        subject._execute(workload(), subject.sim_resource_fresh_policy())


def test_missing_tracer_stop_is_not_recovered(monkeypatch: pytest.MonkeyPatch, observations: dict[str, Any]) -> None:
    """Leaked tracer state in the fault cleanup must reach the post-fault acquisition and refute it."""
    import tracemalloc
    from verifier.domains.contracts import sim_fresh_worker as subject
    from verifier.runtime.resource_measurement_worker import recovery, workload
    monkeypatch.setattr(subject, "_stop_tracing", lambda: None)
    binding = {"challenge": observations["frame"]["challenge"], "source_manifest": observations["runs"][0]["source_manifest"]}
    try:
        with pytest.raises(RuntimeError, match="tracer cleanup incomplete"):
            recovery(workload(), observations["frame"], binding)
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()


def test_timed_out_fresh_worker_leaves_no_child(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung acquisition is killed and reaped by the bounded runner; no child process outlives the refusal."""
    from verifier.domains.contracts import sim_resource_fresh as subject
    spawned: list[subprocess.Popen] = []

    class Recording(subprocess.Popen):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            spawned.append(self)

    monkeypatch.setattr(subprocess, "Popen", Recording)
    with pytest.raises(subprocess.TimeoutExpired):
        subject._run(b"import time\ntime.sleep(30)\n", b"{}", 1)
    assert len(spawned) == 1 and spawned[0].returncode is not None


def test_recheck_states_unestablished_scopes_without_execution() -> None:
    from verifier.domains.contracts import sim_resource_fresh as subject
    zero = "sha256:" + "0" * 64
    request = {"schema_version": subject.SEMANTIC_VERSION, "trajectory_request": {}, "trajectory_policy": {},
               "trajectory_certificate_digest": zero, "workload_digest": zero, "evidence_ref": zero}
    policy = subject.sim_resource_fresh_policy()
    raw = subject.build_sim_resource_fresh_certificate(request, None, policy=policy)
    result = subject.recheck_sim_resource_fresh_certificate(raw, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN" and result["invalidators"] == ["FRESH_TRAJECTORY_UNAVAILABLE"]
    assert all(result[scope] == "NOT_ESTABLISHED" for scope in subject.NOT_ESTABLISHED_SCOPES)
    assert {"absolute_wall_clock", "physical_calibration", "external_device_drift", "real_physical_phenomenon",
            "whole_sim_fidelity", "cross_machine_time", "transition_exclusive_cost", "measurement_sensitivity",
            "total_resource_use"} == set(subject.NOT_ESTABLISHED_SCOPES)
