"""Fresh simulation (SIM) meter over source-loaded finite transitions.

The central processing unit (CPU) value is a raw CPython thread-clock delta,
not device time. Peak traced Python allocation bytes are raw tracer values,
not resident memory or total memory. Each observation interval contains one
transition but may also contain interpreter and instrument overhead; it is not
a transition-exclusive cost. Validation and process startup are excluded.
Observation and arrival intervals read this process's monotonic performance
counter. They order steps and bound local recording latency within this one
fresh process only: not calibrated wall-clock time, cross-process time,
physical latency, sensitivity, physical accuracy, or total resource use.
"""
from __future__ import annotations

import hashlib
import os
import platform
import secrets
import time
import tracemalloc

from verifier.core.certificate import canonical_bytes
from verifier.domains import sim
from verifier.domains.common import Budget, same

# A recorded arrival may trail its observation by at most this software bound.
LATENCY_BOUND_NS = 1_000_000_000
SENSOR = {"method": "cpython-thread-cpu-tracemalloc-1",
          "instruments": ["time.perf_counter_ns", "time.thread_time_ns", "tracemalloc.get_traced_memory"]}
FRAME_KEYS = ("sensor_digest", "measurement_digest", "challenge", "source_digest", "run_id", "process_id")


def _digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def sensor_digest() -> str:
    """Identity of this software instrument on this interpreter; not a physical calibration."""
    return _digest({"sensor": SENSOR, "target": "CPython " + platform.python_version()})


STEP_PAYLOAD_KEYS = ("step", "input_state_digest", "output_state_digest", "thread_cpu_ns",
                     "traced_peak_bytes", "observation_interval", "arrival_interval")


def step_binding(frame: dict, index: int, row: dict) -> str:
    """Bind the complete raw observation payload to its acquisition frame."""
    return _digest({"frame": {key: frame[key] for key in FRAME_KEYS}, "step": index,
                    "payload": {key: row[key] for key in STEP_PAYLOAD_KEYS}})


def _elapsed_thread_ns(start: int) -> int:
    """Read the selected thread clock once and preserve subtraction order."""
    return time.thread_time_ns() - start


def _traced_peak_bytes() -> int:
    """Select peak traced allocation bytes, never the current allocation."""
    _, peak = tracemalloc.get_traced_memory()
    return peak


def _stop_tracing() -> None:
    """Keep cleanup independently replaceable for the fail-closed control."""
    tracemalloc.stop()


def _cleanup_tracing() -> None:
    """Refuse after a cleanup fault, and retry once before claiming the tracer is off.

    A tracer start can partially activate before raising, and a stop can fail
    before deactivation. Therefore cleanup runs after every start attempt. A
    first stop error remains the acquisition error even when the bounded retry
    succeeds; an active tracer after the retry is an explicit cleanup failure.
    """
    first_error: Exception | None = None
    try:
        _stop_tracing()
    except Exception as exc:  # instrument failure is evidence refusal, never a sample
        first_error = exc
    if tracemalloc.is_tracing():
        try:
            _stop_tracing()
        except Exception as exc:
            if first_error is None:
                first_error = exc
    if tracemalloc.is_tracing():
        raise RuntimeError("tracer cleanup incomplete") from first_error
    if first_error is not None:
        raise first_error


def measure(value: dict, binding: dict) -> dict:
    artifact, inputs = value["artifact"], value["inputs"]
    limit, items = value["max_operations"], value["max_items"]
    if (type(limit) is not int or not 1 <= limit <= 100000
            or type(items) is not int or not 1 <= items <= 4096):
        raise ValueError("meter bounds differ")
    if type(binding) is not dict or set(binding) != {"challenge", "source_manifest"} or type(binding["challenge"]) is not str:
        raise ValueError("meter binding differs")
    sim.evaluate("replay", artifact, inputs, Budget(limit, items), witness_keys={})
    budget = Budget(limit, items)
    frame = {"sensor_digest": sensor_digest(), "measurement_digest": _digest(value),
             "challenge": binding["challenge"], "source_digest": _digest(binding["source_manifest"]),
             "run_id": secrets.token_hex(16), "process_id": os.getpid()}
    steps = []
    for index, entropy in enumerate(inputs["entropy"]):
        state = inputs["states"][index]
        try:
            # The finally block covers partial activation: a start that raises
            # may still have changed tracer state.
            tracemalloc.start()
            observed_start = time.perf_counter_ns()
            start = time.thread_time_ns()
            following = sim.transition(artifact["transition"], state, entropy, budget)
            elapsed = _elapsed_thread_ns(start)
            observed_end = time.perf_counter_ns()
            peak = _traced_peak_bytes()
            arrived = time.perf_counter_ns()
        finally:
            _cleanup_tracing()
        same(following, inputs["states"][index + 1], "metered state differs")
        row = {
            "step": index,
            "input_state_digest": "sha256:" + hashlib.sha256(canonical_bytes(state)).hexdigest(),
            "output_state_digest": "sha256:" + hashlib.sha256(canonical_bytes(following)).hexdigest(),
            "thread_cpu_ns": elapsed, "traced_peak_bytes": peak,
            "observation_interval": {"start_ns": observed_start, "end_ns": observed_end},
            "arrival_interval": {"start_ns": observed_end, "end_ns": arrived},
        }
        row["binding_digest"] = step_binding(frame, index, row)
        steps.append(row)
    return {"method": SENSOR["method"], "target": "CPython " + platform.python_version(),
            "steps": steps, **frame}
