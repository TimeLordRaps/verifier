"""Finite resource MEASUREMENT and SENSOR checks for Verifier Standard (VSTD).

Simulation (SIM); central processing unit (CPU). The subject records raw CPython
thread-clock deltas and peak traced Python allocation bytes over intervals that
contain each transition. These are not transition-exclusive costs. Controlled
instrument inputs test software interpretation, not calibration, sensitivity,
physical accuracy, or total resource use. Actual fresh acquisitions are checked
separately. Neither kind's evidence establishes host honesty or full conformance.
Every observation tree is a closed, unaliased pair of distinct fresh acquisitions;
missing, extra, shared or stale fields refute before any claim-specific check.
"""
from __future__ import annotations

import platform
import re
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ADAPTER = "verifier-resource-measurement-1"
SEMANTIC_VERSION = "verifier-resource-measurement-obligations-1"
IMPLEMENTATION = "src/verifier/domains/contracts/sim_resource_fresh.py"
WORKER = "resource_measurement_worker.py"
REQUEST_SCHEMA = "verifier-resource-measurement-request-1"
OBSERVATION_SCHEMA = "verifier-resource-measurement-observations-2"
BOUNDARY = ("Exact owned fresh-resource implementation, two-step local execution and injected instrument/fault controls. "
            "Raw CPython thread-clock deltas and peak traced Python allocation bytes over intervals containing transitions; "
            "not transition-exclusive cost, calibration, sensitivity, physical accuracy, total resource use, historical "
            "metrics, hostile-host attestation, full kind conformance or package polish.")
_CONTRACTS = (
    ("MEASUREMENT-1.1", "transition-resource-meaning", 1,
     "Well-formed numbers cannot support a resource claim without the actual method, units, interpreter and transition identity.",
     "Two fresh two-transition captures retain the declared method, interpreter, ordered state digests and raw nonnegative integer nanosecond/byte records over intervals containing each transition, with distinct challenges and 128-bit run identifiers; their closed scope identifies the values as observations of software counters rather than estimates and keeps physical calibration, external phenomenon truth and uncertainty beyond the raw counters NOT_ESTABLISHED; altered scope, method, identity, source or workload refuse, and extra, missing, mistyped or aliased fields refuse. Process identifiers identify a frame but may be reused."),
    ("MEASUREMENT-2.1", "fresh-step-correspondence", 2,
     "A retained reading, changed process reference frame or different trajectory cannot establish the current selected transition's unit-bearing resource observation; uncertainty beyond the raw software counters must remain explicit.",
     "Two acquisitions use distinct challenges and 128-bit run identifiers, retain CPython process reference frames even when a platform reuses a process identifier, and bind the raw metric and interval payload with its units to the exact workload and every selected step. They infer no transition-exclusive cost, calibration, physical accuracy, sensitivity, total resource use, or statistical uncertainty estimate; stale challenges, workload digests, state digests, metrics and intervals refuse."),
    ("MEASUREMENT-3.1", "invalid-resource-records", 3,
     "Missing, malformed or unavailable observations must not be replaced with precise zero-valued successful measurements.",
     "Missing/extra steps, extra fields at every level, boolean indexes/metrics, negative/overbound metrics refuse; missing observation fields refute rather than raise; transport unavailability and timeout return no capture."),
    ("SENSOR-1.1", "acquisition-source-binding", 1,
     "Output provenance requires the acquisition implementation actually loaded, not merely a named source file or collector identity.",
     "Fresh source and loaded-source manifests agree; stale selection, substituted loaded/source manifests and changed recapture refuse."),
    ("SENSOR-2.1", "transition-sampling-interval", 2,
     "A software sensor needs an explicit calibration applicability boundary, acquisition envelope and drift refusal; sampling the wrong interval or current allocation instead of peak changes the claim even when units look correct.",
     "Source-bound live acquisitions plus controlled clocks and tracers establish this digital instrument's two-step software envelope: prevalidation outside each interval, elapsed differences, peak rather than current bytes, payload-bound intervals containing each transition, per-step cleanup and refusal when its source-selection binding drifts. Calibration, physical accuracy and sensitivity remain NOT_ESTABLISHED."),
    ("SENSOR-3.1", "acquisition-fault-cleanup", 3,
     "Acquisition faults must not leak tracer state into a later sample or silently return a complete observation.",
     "Performance-counter start/end/arrival, thread-clock start/end, tracer start/stop, transition and allocation-read failures return no capture, demonstrate bounded cleanup and permit a clean subsequent acquisition; invalid trajectory validation starts no tracing."),
)


def catalog() -> list[dict[str, Any]]:
    return [{"coordinate": coordinate, "obligation_id": coordinate + "-" + slug,
             "obligation_name": slug.replace("-", " ").capitalize(), "object_kind": coordinate.split("-", 1)[0],
             "tier": tier, "reason": reason, "exact_claim": claim, "semantic_version": SEMANTIC_VERSION,
             "proposition_digest": value_digest({"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}),
             "checking_mechanism": "verifier.runtime.resource_measurement_execution.evaluate",
             "scope": "fresh_resource_" + slug.replace("-", "_"), "adapter": ADAPTER}
            for coordinate, slug, tier, reason, claim in _CONTRACTS]


# Closed key sets mirror the emitter's actual records; any other key is unnamed evidence.
FAULT_NAMES = frozenset((
    "method", "target", "process-bool", "run-id", "challenge", "workload", "state",
    "step-bool", "cpu-bool", "cpu-negative", "cpu-overbound", "peak-bool", "peak-negative", "peak-overbound",
    "extra-field", "missing-step", "extra-step", "unavailable", "timeout", "source", "loaded-source",
    "stale-policy", "recapture", "source-type", "loaded-source-type", "stale-policy-type", "recapture-type",
))
ACQUISITION_FAULTS = frozenset(("perf-start", "perf-end", "perf-arrival", "tracer-start", "tracer-stop",
                                "clock-start", "clock-end", "transition", "memory"))
SAMPLING_NAMES = frozenset(("normal", *ACQUISITION_FAULTS, "invalid"))
TOP_KEYS = frozenset(("claim_scope", "runs", "faults", "sampling", "frame", "recovery"))
RUN_KEYS = frozenset(("bootstrap_digest", "capture", "challenge", "loaded_source_manifest",
                      "source_manifest", "source_recheck", "workload_digest"))
# Restated independently from the emitter: a drifted instrument, bound or frame refutes here.
INSTRUMENT = {"method": "cpython-thread-cpu-tracemalloc-1",
              "instruments": ["time.perf_counter_ns", "time.thread_time_ns", "tracemalloc.get_traced_memory"]}
# This closed record is part of every observation, rather than explanatory prose
# outside the evidence.  It prevents the same software counters from being
# relabeled as physical acquisition, calibrated device output or external truth.
def _claim_scope() -> dict[str, Any]:
    # Construct a fresh closed value so mutation of the exported descriptive
    # copy cannot move the checker's independent acceptance boundary.
    return {
        "schema_version": "verifier-resource-measurement-claim-scope-1",
        "claim_domain": "SOFTWARE_RESOURCE_OBSERVATION",
        "phenomenon": "CPython execution of the selected two-step simulation trajectory",
        "method": "thread CPU clock and traced Python peak allocation over bounded step intervals",
        "source": "source-bound installed Python implementation",
        "units": {
            "thread_cpu_ns": "nanosecond",
            "traced_peak_bytes": "byte",
            "observation_interval": "monotonic_nanosecond",
            "arrival_interval": "monotonic_nanosecond",
        },
        "observation_vs_estimate": "OBSERVATION_OF_SOFTWARE_COUNTERS",
        "uncertainty": "NOT_ESTABLISHED_BEYOND_RAW_COUNTER_VALUES",
        "missingness": "FAILED_OR_INCOMPLETE_CAPTURE_IS_NOT_A_MEASUREMENT",
        "calibration_applicability": "PHYSICAL_CALIBRATION_INAPPLICABLE_TO_NONPHYSICAL_CLAIM",
        "physical_calibration": "NOT_ESTABLISHED",
        "external_phenomenon_truth": "NOT_ESTABLISHED",
        "external_device": "NOT_SELECTED",
        "physical_sensor_identity": "NOT_ESTABLISHED",
    }


CLAIM_SCOPE = _claim_scope()
LATENCY_BOUND_NS = 1_000_000_000
RECOVERY_BOUND_NS = 15_000_000_000
FRAME_KEYS = frozenset(("sensor_digest", "measurement_digest", "challenge", "source_digest", "run_id", "process_id"))
CAPTURE_KEYS = FRAME_KEYS | frozenset(("method", "target", "steps"))
STEP_KEYS = frozenset(("step", "input_state_digest", "output_state_digest", "thread_cpu_ns", "traced_peak_bytes",
                       "observation_interval", "arrival_interval", "binding_digest"))
INTERVAL_KEYS = frozenset(("start_ns", "end_ns"))
RECOVERY_KEYS = frozenset(("cases", "capture", "tracing_before_capture", "tracing_after_capture"))
RECOVERY_CASE_KEYS = frozenset(("fault", "clean", "tracing_after_fault", "tracing_after_clean"))
SAMPLE_KEYS = frozenset(("events", "returned", "exception", "active", "metrics", "binding_digest"))
FAULT_ROW_KEYS = frozenset(("returned", "exception", "message", "calls"))
# Every injected control has one deterministic refusal; the whole table is the fault-detection oracle.
CONTROL_FAULTS: dict[str, tuple[str, str, int]] = {
    **{name: ("ValueError", "FRESH_CAPTURE_IDENTITY_DIFFERS", 1) for name in ("method", "target", "process-bool", "run-id")},
    **{name: ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1) for name in (
        "challenge", "workload", "source", "loaded-source", "source-type", "loaded-source-type")},
    **{name: ("ValueError", "FRESH_STEP_BINDING_DIFFERS", 1) for name in (
        "state", "step-bool", "cpu-bool", "cpu-negative", "cpu-overbound", "peak-bool", "peak-negative", "peak-overbound",
        "extra-field")},
    **{name: ("ValueError", "FRESH_STEP_COVERAGE_DIFFERS", 1) for name in ("missing-step", "extra-step")},
    "unavailable": ("OSError", "controlled unavailable", 1),
    "timeout": ("TimeoutExpired", "Command 'controlled-meter' timed out after 1 seconds", 1),
    **{name: ("ValueError", "FRESH_SOURCE_SELECTION_DIFFERS", 0) for name in ("stale-policy", "stale-policy-type")},
    **{name: ("ValueError", "FRESH_SOURCE_CHANGED_DURING_EXECUTION", 1) for name in ("recapture", "recapture-type")},
}
# One sampled step: tracer start, monotonic observation start, thread clock, transition, thread clock,
# monotonic observation end, peak read, monotonic arrival, tracer stop.
_STEP = ["start", "mono", "clock", "transition", "clock", "mono", "memory", "mono", "stop"]
_PREFIX = ["validate", "start", "mono", "clock"]
# The controlled sampler's exact outcomes; a sample that differs from its control row is not evidence of that sampler.
CONTROL_SAMPLING: dict[str, dict[str, Any]] = {
    "normal": {"events": ["validate"] + _STEP + _STEP,
               "returned": True, "exception": None, "active": False, "metrics": [[0, 13, 64], [1, 31, 96]]},
    "clock-start": {"events": _PREFIX + ["stop"], "returned": False, "exception": "OSError", "active": False, "metrics": None},
    "clock-end": {"events": _PREFIX + ["transition", "clock", "stop"], "returned": False, "exception": "OSError",
                  "active": False, "metrics": None},
    "transition": {"events": _PREFIX + ["transition", "stop"], "returned": False, "exception": "OSError", "active": False,
                   "metrics": None},
    "memory": {"events": _PREFIX + ["transition", "clock", "mono", "memory", "stop"], "returned": False,
               "exception": "OSError", "active": False, "metrics": None},
    "perf-start": {"events": ["validate", "start", "mono", "stop"], "returned": False,
                   "exception": "OSError", "active": False, "metrics": None},
    "perf-end": {"events": _PREFIX + ["transition", "clock", "mono", "stop"], "returned": False,
                 "exception": "OSError", "active": False, "metrics": None},
    "perf-arrival": {"events": _PREFIX + ["transition", "clock", "mono", "memory", "mono", "stop"],
                     "returned": False, "exception": "OSError", "active": False, "metrics": None},
    "tracer-start": {"events": ["validate", "start", "stop"], "returned": False,
                     "exception": "OSError", "active": False, "metrics": None},
    "tracer-stop": {"events": ["validate"] + _STEP + ["stop"], "returned": False,
                    "exception": "OSError", "active": False, "metrics": None},
    "invalid": {"events": ["validate"], "returned": False, "exception": "Refuted", "active": False, "metrics": None},
}
_REGISTERED = frozenset(coordinate for coordinate, *_ in _CONTRACTS)


def _equal(left: Any, right: Any) -> bool:
    # Python considers False == 0; observation types are part of this contract.
    return canonical_bytes(left) == canonical_bytes(right)


def _strip(row: dict[str, Any]) -> dict[str, Any]:
    """Control outcomes compare without their frame binding, which differs for every acquisition."""
    return {key: value for key, value in row.items() if key != "binding_digest"}


def _sensor_digest() -> str:
    return value_digest({"sensor": INSTRUMENT, "target": "CPython " + platform.python_version()})


def _workload_digest() -> str:
    """Digest of the exact replay artifact and bounds that every fresh acquisition must execute."""
    inputs = {"states": [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}], "entropy": [1.0, 1.0], "times": [0.0, 1.0, 2.0]}
    artifact = {"transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
        "initial_state": {"x": 0.0}, "trajectory_digest": value_digest(inputs["states"]),
        "entropy_digest": value_digest(inputs["entropy"]), "times_digest": value_digest(inputs["times"])}
    return value_digest({"artifact": artifact, "inputs": inputs, "max_operations": 100000, "max_items": 4096})


def _frame_fields(frame: dict[str, Any]) -> dict[str, Any]:
    return {key: frame[key] for key in FRAME_KEYS}


def _step_binding(frame: dict[str, Any], index: int, row: dict[str, Any]) -> str:
    payload_keys = ("step", "input_state_digest", "output_state_digest", "thread_cpu_ns",
                    "traced_peak_bytes", "observation_interval", "arrival_interval")
    return value_digest({"frame": _frame_fields(frame), "step": index,
                         "payload": {key: row[key] for key in payload_keys}})


def _sampling_binding(frame: dict[str, Any], label: str, row: dict[str, Any]) -> str:
    return value_digest({"frame": _frame_fields(frame), "row": label,
        "payload": {key: row[key] for key in ("events", "returned", "exception", "active", "metrics")}})


def _interval_ok(value: Any) -> bool:
    return (type(value) is dict and set(value) == INTERVAL_KEYS
            and all(type(value[key]) is int and 0 <= value[key] <= 2**63 - 1 for key in INTERVAL_KEYS))


def _capture_shape(capture: Any, challenge: str, source_digest: str) -> bool:
    """Closed identity, frame and per-step binding; timing is judged by the separate interval properties."""
    if type(capture) is not dict or set(capture) != CAPTURE_KEYS:
        return False
    if (capture["method"] != INSTRUMENT["method"] or capture["target"] != "CPython " + platform.python_version()
            or type(capture["process_id"]) is not int or not 0 <= capture["process_id"] <= 2**64 - 1
            or type(capture["run_id"]) is not str or re.fullmatch("[0-9a-f]{32}", capture["run_id"]) is None
            or type(challenge) is not str or re.fullmatch("[0-9a-f]{64}", challenge) is None
            or capture["challenge"] != challenge or capture["source_digest"] != source_digest
            or capture["sensor_digest"] != _sensor_digest() or capture["measurement_digest"] != _workload_digest()
            or type(capture["steps"]) is not list or len(capture["steps"]) != 2):
        return False
    frame = _frame_fields(capture)
    for index, row in enumerate(capture["steps"]):
        if (type(row) is not dict or set(row) != STEP_KEYS or type(row["step"]) is not int or row["step"] != index
                or row["input_state_digest"] != value_digest({"x": float(index)})
                or row["output_state_digest"] != value_digest({"x": float(index + 1)})
                or any(type(row[key]) is not int or not 0 <= row[key] <= 2**63 - 1
                       for key in ("thread_cpu_ns", "traced_peak_bytes"))
                or not _interval_ok(row["observation_interval"]) or not _interval_ok(row["arrival_interval"])
                or row["binding_digest"] != _step_binding(frame, index, row)):
            return False
    return True


def _timing_ordered(capture: dict[str, Any]) -> bool:
    """Within one process: each observation is well-formed, and no step observes before the previous arrival."""
    previous = 0
    for row in capture["steps"]:
        observed, arrived = row["observation_interval"], row["arrival_interval"]
        if observed["start_ns"] > observed["end_ns"] or arrived["end_ns"] < arrived["start_ns"] or observed["start_ns"] < previous:
            return False
        previous = arrived["end_ns"]
    return True


def _arrival_distinct(capture: dict[str, Any]) -> bool:
    """An arrival is a later recording that begins exactly where its observation ends, never a copy of it."""
    return all(row["arrival_interval"]["start_ns"] == row["observation_interval"]["end_ns"]
               and row["arrival_interval"] is not row["observation_interval"] for row in capture["steps"])


def _latency_bounded(capture: dict[str, Any]) -> bool:
    return all(0 <= row["arrival_interval"]["end_ns"] - row["arrival_interval"]["start_ns"] <= LATENCY_BOUND_NS
               for row in capture["steps"])


def _capture_bound(capture: Any, challenge: str, source_digest: str) -> bool:
    return (_capture_shape(capture, challenge, source_digest) and _timing_ordered(capture)
            and _arrival_distinct(capture) and _latency_bounded(capture))


def _captures(observed: dict[str, Any]) -> bool:
    runs = observed["runs"]
    if type(runs) is not list or len(runs) != 2:
        return False
    return all(_capture_bound(run["capture"], run["challenge"], value_digest(run["source_manifest"])) for run in runs)


def _faults(observed: dict[str, Any], expected: dict[str, tuple[str, str, int]]) -> bool:
    return all(_equal(observed["faults"][name], {
        "returned": False, "exception": exception, "message": message, "calls": calls})
        for name, (exception, message, calls) in expected.items())


def _measurement_reference_frame(observed: dict[str, Any]) -> bool:
    """Retain explicit runtime/method frames for both fresh unit-bearing captures."""
    if not _captures(observed):
        return False
    first, second = observed["runs"]
    return (first["capture"]["method"] == second["capture"]["method"]
            and first["capture"]["target"] == second["capture"]["target"])


def _source_bound(observed: dict[str, Any]) -> bool:
    """Provenance: both manifests equal the current closed sources and the bootstrap digest on disk."""
    from hashlib import sha256
    from pathlib import Path
    from verifier.domains.contracts import sim_resource_fresh as subject

    expected = subject.source_manifest()
    bootstrap = "sha256:" + sha256(
        Path(subject.__file__).with_name("sim_fresh_bootstrap.py").read_bytes()
    ).hexdigest()
    return all(
        _equal(run["source_manifest"], expected)
        and _equal(run["loaded_source_manifest"], expected)
        and run["bootstrap_digest"] == bootstrap
        and run["source_recheck"] == "PASS"
        for run in observed["runs"]
    )


def _sensor_source_binding(observed: dict[str, Any]) -> bool:
    """Treat source identity as software-instrument calibration, never physical calibration."""
    return (
        _captures(observed)
        and _source_bound(observed)
        and _faults(
            observed,
            {
                "source": ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1),
                "loaded-source": ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1),
                "source-type": ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1),
                "loaded-source-type": ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1),
                "stale-policy": ("ValueError", "FRESH_SOURCE_SELECTION_DIFFERS", 0),
                "stale-policy-type": ("ValueError", "FRESH_SOURCE_SELECTION_DIFFERS", 0),
                "recapture": ("ValueError", "FRESH_SOURCE_CHANGED_DURING_EXECUTION", 1),
                "recapture-type": ("ValueError", "FRESH_SOURCE_CHANGED_DURING_EXECUTION", 1),
            },
        )
    )


def _plain_unaliased(value: Any) -> bool:
    """Reject floats (including nonfinite) and any container reachable twice; shared objects are substitution."""
    seen: set[int] = set()
    pending = [value]
    while pending:
        node = pending.pop()
        if type(node) is float:
            return False
        if type(node) not in (dict, list):
            continue
        if id(node) in seen:
            return False
        seen.add(id(node))
        pending.extend(node.values() if type(node) is dict else node)
    return True


def _plain_int(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**63 - 1


def _fault_row(row: Any) -> bool:
    if type(row) is not dict or set(row) != FAULT_ROW_KEYS:
        return False
    return (type(row["returned"]) is bool
            and (row["exception"] is None or type(row["exception"]) is str)
            and (row["message"] is None or type(row["message"]) is str)
            and _plain_int(row["calls"]))


def _sample_row(row: Any) -> bool:
    if type(row) is not dict or set(row) != SAMPLE_KEYS:
        return False
    metrics = row["metrics"]
    return (type(row["events"]) is list and all(type(event) is str for event in row["events"])
            and type(row["returned"]) is bool and type(row["active"]) is bool
            and (row["exception"] is None or type(row["exception"]) is str)
            and type(row["binding_digest"]) is str
            and (metrics is None or (type(metrics) is list and all(
                type(item) is list and len(item) == 3 and all(_plain_int(part) for part in item)
                for item in metrics))))


def _sampling_matches(sampling: dict[str, Any]) -> bool:
    return _equal({name: _strip(row) for name, row in sampling.items()}, CONTROL_SAMPLING)


def _sampling_bound(observed: dict[str, Any]) -> bool:
    return all(row["binding_digest"] == _sampling_binding(observed["frame"], name, row)
               for name, row in observed["sampling"].items())


def _frame_ok(observed: dict[str, Any]) -> bool:
    """The observer frame is fresh: its challenge, run and process differ from both fresh acquisitions."""
    frame, runs = observed["frame"], observed["runs"]
    if type(frame) is not dict or set(frame) != FRAME_KEYS:
        return False
    return (frame["sensor_digest"] == _sensor_digest() and frame["measurement_digest"] == _workload_digest()
            and type(frame["challenge"]) is str and re.fullmatch("[0-9a-f]{64}", frame["challenge"]) is not None
            and frame["source_digest"] == value_digest(runs[0]["source_manifest"])
            and type(frame["run_id"]) is str and re.fullmatch("[0-9a-f]{32}", frame["run_id"]) is not None
            and type(frame["process_id"]) is int and 0 <= frame["process_id"] <= 2**64 - 1
            and all(frame["challenge"] != run["challenge"]
                    and frame["run_id"] != run["capture"]["run_id"] for run in runs))


def _row_matches(row: Any, control: dict[str, Any], frame: dict[str, Any], label: str) -> bool:
    return (type(row) is dict and set(row) == SAMPLE_KEYS and _equal(_strip(row), control)
            and row["binding_digest"] == _sampling_binding(frame, label, row))


def _span_bounded(capture: dict[str, Any]) -> bool:
    span = capture["steps"][-1]["arrival_interval"]["end_ns"] - capture["steps"][0]["observation_interval"]["start_ns"]
    return 0 <= span <= RECOVERY_BOUND_NS


def _recovered(observed: dict[str, Any]) -> bool:
    """Every injected acquisition fault is clean, followed by a clean acquisition."""
    frame, recovery = observed["frame"], observed["recovery"]
    if type(recovery) is not dict or set(recovery) != RECOVERY_KEYS:
        return False
    capture, cases = recovery["capture"], recovery["cases"]
    if type(cases) is not dict or set(cases) != ACQUISITION_FAULTS:
        return False
    for name, case in cases.items():
        if (type(case) is not dict or set(case) != RECOVERY_CASE_KEYS
                or case["tracing_after_fault"] is not False or case["tracing_after_clean"] is not False
                or not _row_matches(case["fault"], CONTROL_SAMPLING[name], frame, "recovery-" + name + "-fault")
                or not _row_matches(case["clean"], CONTROL_SAMPLING["normal"], frame,
                                    "recovery-" + name + "-clean")):
            return False
    return (recovery["tracing_before_capture"] is False and recovery["tracing_after_capture"] is False
            and _capture_bound(capture, frame["challenge"], frame["source_digest"])
            and capture["process_id"] == frame["process_id"] and _span_bounded(capture))


def _well_formed(observed: Any) -> bool:
    """Closed, typed, unaliased, fresh pair: every missing, extra, stale, reused or mistyped field refutes."""
    if type(observed) is not dict or set(observed) != TOP_KEYS or not _plain_unaliased(observed):
        return False
    if not _equal(observed["claim_scope"], _claim_scope()):
        return False
    faults, sampling, runs = observed["faults"], observed["sampling"], observed["runs"]
    if type(faults) is not dict or set(faults) != FAULT_NAMES or not all(_fault_row(row) for row in faults.values()):
        return False
    if type(sampling) is not dict or set(sampling) != SAMPLING_NAMES or not all(_sample_row(row) for row in sampling.values()):
        return False
    if type(runs) is not list or len(runs) != 2 or any(type(run) is not dict or set(run) != RUN_KEYS for run in runs):
        return False
    if not _captures(observed) or not _faults(observed, CONTROL_FAULTS) or not _sampling_matches(sampling):
        return False
    if any(type(run[key]) is not str for run in runs for key in ("workload_digest", "bootstrap_digest", "source_recheck")):
        return False
    if any(type(run[key]) is not dict for run in runs for key in ("source_manifest", "loaded_source_manifest")):
        return False
    if any(run["workload_digest"] != _workload_digest() for run in runs) or not _source_bound(observed):
        return False
    if not _frame_ok(observed) or not _sampling_bound(observed) or not _recovered(observed):
        return False
    first, second = runs
    return not (first["challenge"] == second["challenge"]
                or first["capture"]["run_id"] == second["capture"]["run_id"])


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Fail closed: unregistered coordinates raise; malformed observations refute, never raise into a verdict."""
    if coordinate not in _REGISTERED:
        raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")
    try:
        return _well_formed(observed) and _claim_holds(coordinate, observed)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def _claim_holds(coordinate: str, observed: dict[str, Any]) -> bool:
    """Recompute expected interval arithmetic and refusal behavior independently."""
    if coordinate == "MEASUREMENT-1.1":
        return _captures(observed) and _faults(observed, {name: ("ValueError", "FRESH_CAPTURE_IDENTITY_DIFFERS", 1)
            for name in ("method", "target", "process-bool", "run-id")})
    if coordinate == "MEASUREMENT-2.1":
        runs = observed["runs"]
        return (_measurement_reference_frame(observed) and runs[0]["challenge"] != runs[1]["challenge"]
            and runs[0]["capture"]["run_id"] != runs[1]["capture"]["run_id"]
            and all(run["workload_digest"] == _workload_digest() for run in runs)
            and _faults(observed, {"challenge": ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1),
                "workload": ("ValueError", "FRESH_WORKER_BINDING_DIFFERS", 1),
                "state": ("ValueError", "FRESH_STEP_BINDING_DIFFERS", 1)}))
    if coordinate == "MEASUREMENT-3.1":
        return _faults(observed, {
            **{name: ("ValueError", "FRESH_STEP_BINDING_DIFFERS", 1) for name in (
                "step-bool", "cpu-bool", "cpu-negative", "cpu-overbound", "peak-bool", "peak-negative", "peak-overbound", "extra-field")},
            **{name: ("ValueError", "FRESH_STEP_COVERAGE_DIFFERS", 1) for name in ("missing-step", "extra-step")},
            "unavailable": ("OSError", "controlled unavailable", 1),
            "timeout": ("TimeoutExpired", "Command 'controlled-meter' timed out after 1 seconds", 1)})
    if coordinate == "SENSOR-1.1":
        return _sensor_source_binding(observed)
    if coordinate == "SENSOR-2.1":
        return _sensor_source_binding(observed) and _equal(_strip(observed["sampling"]["normal"]), CONTROL_SAMPLING["normal"])
    if coordinate == "SENSOR-3.1":
        return all(_equal(_strip(observed["sampling"][name]), CONTROL_SAMPLING[name])
                   for name in (*ACQUISITION_FAULTS, "invalid")) and _recovered(observed)
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    from verifier.runtime.package_execution import execute_bound
    return execute_bound(snapshot, item, selection)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    from verifier.runtime.package_execution import evaluate_selected
    return evaluate_selected(snapshot, item, route)
