"""Private resource observation experiments for Verifier Standard (VSTD).

Terminology: central processing unit (CPU).

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Two actual source-loaded acquisitions and separate injected instrument controls
exercise the installed implementation. No native specimen receipt supplies a
package verdict. Controls run in this disposable process, never an operator job.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import itertools
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from typing import Any


# Kept independent from the checker module: the emitter states exactly what it
# observed, while the checker restates and compares the same closed boundary.
def _claim_scope() -> dict[str, Any]:
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


def source_pins() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    paths = [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]
    paths.extend(root / name for name in ("standard/POLISH_INVOCATION_LEDGER.md", "standard/PACKAGE_POLISH.md"))
    return {path.relative_to(root).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def workload() -> dict[str, Any]:
    from verifier.core.certificate import canonical_bytes

    def digest(value: Any) -> str:
        return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

    inputs = {"states": [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}], "entropy": [1.0, 1.0], "times": [0.0, 1.0, 2.0]}
    return {"inputs": inputs, "artifact": {
        "transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
        "initial_state": inputs["states"][0], "trajectory_digest": digest(inputs["states"]),
        "entropy_digest": digest(inputs["entropy"]), "times_digest": digest(inputs["times"])},
        "max_operations": 100000, "max_items": 4096}


def rebound(template: dict[str, Any], challenge: str) -> dict[str, Any]:
    """A child result for this challenge, with frame and step bindings recomputed so only an injected field differs."""
    from verifier.domains.contracts import sim_fresh_worker
    value = deepcopy(template)
    value.pop("bootstrap_digest", None)
    value.pop("source_recheck", None)
    value["challenge"] = challenge
    capture = value["capture"]
    capture["challenge"] = challenge
    frame = {key: capture[key] for key in sim_fresh_worker.FRAME_KEYS}
    for index, step in enumerate(capture["steps"]):
        step["binding_digest"] = sim_fresh_worker.step_binding(frame, index, step)
    return value


def _frame(work: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    """This disposable observer's frame; the oracle recomputes every field independently."""
    from verifier.domains.contracts import sim_fresh_worker
    from verifier.runtime.tier_zero_profile import value_digest
    return {"sensor_digest": sim_fresh_worker.sensor_digest(), "measurement_digest": value_digest(work),
            "challenge": binding["challenge"], "source_digest": value_digest(binding["source_manifest"]),
            "run_id": secrets.token_hex(16), "process_id": os.getpid()}


def sampling(work: dict[str, Any], fault: str, frame: dict[str, Any], binding: dict[str, Any],
             label: str | None = None) -> dict[str, Any]:
    """Inject only instruments; keep real transition and replay validation code."""
    from verifier.domains.contracts import sim_fresh_worker as subject
    from verifier.runtime.tier_zero_profile import value_digest
    old_time, old_trace = subject.time, subject.tracemalloc
    old_evaluate, old_transition = subject.sim.evaluate, subject.sim.transition
    events: list[str] = []
    state = {"active": False, "clocks": 0, "monotonic": 0, "samples": 0, "starts": 0, "stops": 0}
    clocks = iter((100, 113, 1000, 1031))
    ticks = itertools.count(2000, 10)

    def clock() -> int:
        events.append("clock")
        state["clocks"] += 1
        if (fault == "clock-start" and state["clocks"] == 1) or (fault == "clock-end" and state["clocks"] == 2):
            raise OSError("controlled clock failure")
        return next(clocks)

    def mono() -> int:
        events.append("mono")
        state["monotonic"] += 1
        if ((fault == "perf-start" and state["monotonic"] == 1)
                or (fault == "perf-end" and state["monotonic"] == 2)
                or (fault == "perf-arrival" and state["monotonic"] == 3)):
            raise OSError("controlled performance counter failure")
        return next(ticks)

    def start() -> None:
        events.append("start")
        state["starts"] += 1
        state["active"] = True
        if fault == "tracer-start" and state["starts"] == 1:
            raise OSError("controlled tracer start failure")

    def stop() -> None:
        events.append("stop")
        state["stops"] += 1
        if fault == "tracer-stop" and state["stops"] == 1:
            # Fail before deactivation. The subject must retry cleanup and
            # still refuse this acquisition rather than overclaiming success.
            raise OSError("controlled tracer stop failure")
        state["active"] = False

    def is_tracing() -> bool:
        return state["active"]

    def memory() -> tuple[int, int]:
        events.append("memory")
        if fault == "memory":
            raise OSError("controlled allocation failure")
        state["samples"] += 1
        return 7, 64 if state["samples"] == 1 else 96

    def transition(*args: Any, **kwargs: Any) -> Any:
        # Replay validation also calls transition; only the measured calls are
        # instrumented, so validation cannot accidentally count as acquisition.
        if state["active"]:
            events.append("transition")
            if fault == "transition":
                raise OSError("controlled transition failure")
        return old_transition(*args, **kwargs)

    def validate(*args: Any, **kwargs: Any) -> Any:
        events.append("validate")
        return old_evaluate(*args, **kwargs)

    subject.time = SimpleNamespace(thread_time_ns=clock, perf_counter_ns=mono)
    subject.tracemalloc = SimpleNamespace(start=start, stop=stop, is_tracing=is_tracing, get_traced_memory=memory)
    subject.sim.evaluate, subject.sim.transition = validate, transition
    result: dict[str, Any] = {"events": events, "returned": False, "exception": None, "active": False, "metrics": None}
    try:
        chosen = deepcopy(work)
        if fault == "invalid":
            chosen["inputs"]["states"][1]["x"] = 99.0
        value = subject.measure(chosen, binding)
        result.update(returned=True, metrics=[[row["step"], row["thread_cpu_ns"], row["traced_peak_bytes"]] for row in value["steps"]])
    except (OSError, RuntimeError, ValueError) as exc:
        result["exception"] = type(exc).__name__
    finally:
        result["active"] = state["active"]
        subject.time, subject.tracemalloc = old_time, old_trace
        subject.sim.evaluate, subject.sim.transition = old_evaluate, old_transition
    result["binding_digest"] = value_digest({"frame": frame, "row": label or fault,
        "payload": {key: result[key] for key in ("events", "returned", "exception", "active", "metrics")}})
    return result


def recovery(work: dict[str, Any], frame: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    """Every acquisition fault refuses cleanly, then permits a clean acquisition."""
    import tracemalloc
    from verifier.domains.contracts import sim_fresh_worker as subject
    fault_names = ("perf-start", "perf-end", "perf-arrival", "tracer-start", "tracer-stop",
                   "clock-start", "clock-end", "transition", "memory")
    cases = {}
    for name in fault_names:
        fault = sampling(work, name, frame, binding, "recovery-" + name + "-fault")
        clean = sampling(work, "normal", frame, binding, "recovery-" + name + "-clean")
        cases[name] = {"fault": fault, "clean": clean,
                       "tracing_after_fault": fault["active"], "tracing_after_clean": clean["active"]}
    before = tracemalloc.is_tracing()
    capture = subject.measure(work, binding)
    return {"cases": cases, "capture": capture,
            "tracing_before_capture": before, "tracing_after_capture": tracemalloc.is_tracing()}


def observe() -> dict[str, Any]:
    from verifier.domains.contracts import sim_resource_fresh as subject
    work, policy = workload(), subject.sim_resource_fresh_policy()
    runs = [subject._execute(work, policy), subject._execute(work, policy)]
    binding = {"challenge": secrets.token_hex(32), "source_manifest": policy["source_manifest"]}
    frame = _frame(work, binding)
    original_run, original_manifest = subject._run, subject.source_manifest
    faults = {}
    names = ("method", "target", "process-bool", "run-id", "challenge", "workload", "state",
        "step-bool", "cpu-bool", "cpu-negative", "cpu-overbound", "peak-bool", "peak-negative", "peak-overbound",
        "extra-field", "missing-step", "extra-step", "unavailable", "timeout", "source", "loaded-source", "stale-policy", "recapture",
        "source-type", "loaded-source-type", "stale-policy-type", "recapture-type")
    aliased_manifest = deepcopy(policy["source_manifest"])
    aliased_manifest["verifier"]["package"] = 1
    try:
        for name in names:
            calls = []

            def transport(bootstrap: bytes, payload: bytes, timeout: int) -> dict:
                calls.append(1)
                if name == "unavailable":
                    raise OSError("controlled unavailable")
                if name == "timeout":
                    raise subprocess.TimeoutExpired("controlled-meter", 1)
                value = rebound(runs[0], json.loads(payload)["challenge"])
                capture, row = value["capture"], value["capture"]["steps"][0]
                if name in ("method", "target"):
                    capture[name] = "other"
                elif name == "process-bool":
                    capture["process_id"] = True
                elif name == "run-id":
                    capture["run_id"] = "retained"
                elif name in ("challenge", "workload"):
                    value["challenge" if name == "challenge" else "workload_digest"] = "wrong"
                elif name == "state":
                    row["output_state_digest"] = row["input_state_digest"]
                elif name == "step-bool":
                    row["step"] = False
                elif name.startswith(("cpu-", "peak-")):
                    row["thread_cpu_ns" if name.startswith("cpu-") else "traced_peak_bytes"] = (
                        True if name.endswith("bool") else -1 if name.endswith("negative") else 2**63)
                elif name == "extra-field":
                    row["physical_device_bytes"] = 0
                elif name == "missing-step":
                    capture["steps"].pop()
                elif name == "extra-step":
                    capture["steps"].append(deepcopy(row))
                elif name in ("source", "loaded-source"):
                    value["source_manifest" if name == "source" else "loaded_source_manifest"] = {}
                elif name in ("source-type", "loaded-source-type"):
                    value["source_manifest" if name == "source-type" else "loaded_source_manifest"] = deepcopy(aliased_manifest)
                return value

            subject._run = transport
            subject.source_manifest = (lambda: {}) if name == "recapture" else original_manifest
            if name == "recapture-type":
                subject.source_manifest = lambda: deepcopy(aliased_manifest)
            chosen = deepcopy(policy)
            if name == "stale-policy":
                chosen["source_manifest"] = {}
            elif name == "stale-policy-type":
                chosen["source_manifest"] = deepcopy(aliased_manifest)
            row = {"returned": False, "exception": None, "message": None, "calls": 0}
            try:
                subject._execute(work, chosen)
                row["returned"] = True
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                row.update(exception=type(exc).__name__, message=str(exc))
            row["calls"] = len(calls)
            faults[name] = row
    finally:
        subject._run, subject.source_manifest = original_run, original_manifest
    return {"claim_scope": _claim_scope(), "runs": runs, "faults": faults,
            "sampling": {name: sampling(work, name, frame, binding)
                         for name in ("normal", "perf-start", "perf-end", "perf-arrival", "tracer-start",
                                      "tracer-stop", "clock-start", "clock-end", "transition", "memory", "invalid")},
            "frame": frame, "recovery": recovery(work, frame, binding)}


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if (type(request) is not dict or set(request) != {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}
            or request["schema_version"] != "verifier-resource-measurement-request-1"
            or any(type(value) is not str or not 1 <= len(value) <= 256 for value in request.values())):
        raise ValueError("closed bounded resource request required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-resource-check-") as temporary:
        sys.pycache_prefix = str(Path(temporary) / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        observations = observe()
    if before != source_pins():
        raise ValueError("worker source changed")
    sys.stdout.write(json.dumps({"schema_version": "verifier-resource-measurement-observations-2",
        "request": request, "source_pins": before, "observations": observations},
        sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
