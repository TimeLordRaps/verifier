"""SIM-2.4 fresh execution variant, with direct source-to-measurement bindings.

Simulation (SIM); central processing unit (CPU). This local observation trusts
the invoking mechanism, CPython, its standard library, and the operating system.
Source hashes bind bytes, not host honesty or historical execution. Rechecking
an invocation certificate performs NEW work; retained metrics never earn PASS.
"""
from __future__ import annotations

import base64
import hashlib
import platform
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import sim_dynamics, sim_fresh_worker

SEMANTIC_VERSION = "verifier-sim-resource-fresh-execution-1"
CERTIFICATE_VERSION = "verifier-sim-resource-execution-selection-1"
SCOPE = "fresh_source_bound_local_transition_resources"
COORDINATE = "SIM-2.4"
CHECKING_MECHANISM = __name__ + ".recheck_sim_resource_fresh_certificate"
NEGATIVE_REFUSAL_DETAIL = "evidence fields differ"
# Explicit non-claims returned with every verdict; none is established by a fresh software observation.
NOT_ESTABLISHED_SCOPES = ("absolute_wall_clock", "physical_calibration", "external_device_drift",
                          "real_physical_phenomenon", "whole_sim_fidelity", "cross_machine_time",
                          "transition_exclusive_cost", "measurement_sensitivity", "total_resource_use")
STEP_KEYS = frozenset(("step", "input_state_digest", "output_state_digest", "thread_cpu_ns", "traced_peak_bytes",
                       "observation_interval", "arrival_interval", "binding_digest"))
CAPTURE_KEYS = frozenset(("method", "target", "steps", *sim_fresh_worker.FRAME_KEYS))
REASONS = {
    "necessity": "The selected finite transition interpreter consumes resources; every selected transition must have a directly observed resource record, not a budget counter or authenticated self-report.",
    "applicability": "Self-polish executes the installed finite SIM interpreter now. Raw CPython thread-clock deltas and peak traced Python allocation bytes are recorded over intervals containing each selected transition, with complete selected-step coverage.",
    "historical_condition": "Historical correspondence requires evidence that the earlier execution occurred. This variant makes no earlier-run claim: it invokes a new source-loaded process and records that run. Historical signed-record claims remain UNKNOWN.",
    "physical_condition": "No transition-exclusive cost, measurement sensitivity, calibrated or physically accurate timing, correspondence to physical laws, whole-device or total resource usage, total resident memory, energy, accelerator usage, or customer production workload is claimed. Those require their own applicable mechanisms and cannot inherit this PASS.",
    "trust": "Direct source provenance eliminates a collector signatory, not trust in the invoking verifier, CPython, its standard library, process pipes, clocks, allocation tracer, or operating system. This is not independent host attestation.",
}
PROPOSITION_DIGEST = "sha256:" + canonical_digest({
    "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
    "scope": SCOPE, "reasons": REASONS,
})
_ROOT = Path(__file__).resolve().parents[2]
_MODULES = {
    "verifier": "__init__.py", "verifier.core": None,
    "verifier.core.certificate": "core/certificate.py",
    "verifier.core.signature_keys": "core/signature_keys.py",
    "verifier.domains": "domains/__init__.py",
    "verifier.domains.common": "domains/common.py",
    "verifier.domains.sim": "domains/sim.py",
    "verifier.domains.contracts": "domains/contracts/__init__.py",
    "verifier.domains.contracts.sim_fresh_worker": "domains/contracts/sim_fresh_worker.py",
}
_LIMIT = 8 * 1024 * 1024


def _hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _hash(canonical_bytes(value))


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _sources() -> dict[str, bytes]:
    return {name: (_ROOT.joinpath(path).read_bytes() if path else b"")
            for name, path in _MODULES.items()}


def _manifest(sources: dict[str, bytes]) -> dict[str, Any]:
    return {name: {"path": "src/verifier/" + (path or "core/"),
                   "sha256": _hash(sources[name]),
                   "package": path is None or path.endswith("__init__.py")}
            for name, path in _MODULES.items()}


def source_manifest() -> dict[str, Any]:
    """Exact closed package source snapshot used by the isolated loader."""
    return _manifest(_sources())


def mechanism_digest() -> str:
    return _digest({
        "module": _hash(Path(__file__).read_bytes()),
        "bootstrap": _hash(Path(__file__).with_name("sim_fresh_bootstrap.py").read_bytes()),
        "source_manifest": source_manifest(),
        "trajectory": sim_dynamics.mechanism_digest(),
        "specification": _hash(_ROOT.joinpath("standard/CURRENT_SIM_RESOURCE_FRESH.md").read_bytes()),
    })


def sim_resource_fresh_policy() -> dict[str, Any]:
    return {"schema_version": SEMANTIC_VERSION, "mechanism_digest": mechanism_digest(),
            "source_manifest": source_manifest(), "timeout_seconds": 15}


def selection_from_trajectory(request: dict, child_policy: dict,
                              evidence: bytes) -> tuple[dict, dict, bytes]:
    """Select data from a real source-owned SIM-2.1 specimen, without a signer."""
    child = sim_dynamics.build_sim_dynamics_certificate(request, evidence, policy=child_policy)
    artifact, inputs = _child_data(child, request)
    work = {"artifact": artifact, "inputs": inputs,
            "max_operations": request["limits"]["max_operations"],
            "max_items": request["limits"]["max_items"]}
    selected = {"schema_version": SEMANTIC_VERSION,
                "trajectory_request": request, "trajectory_policy": child_policy,
                "trajectory_certificate_digest": _hash(child),
                "workload_digest": _digest(work), "evidence_ref": _hash(child)}
    return selected, sim_resource_fresh_policy(), child


def _child_data(child: bytes, request: dict) -> tuple[dict, dict]:
    envelope = strict_json_loads(child.decode("utf-8"))
    data = strict_json_loads(base64.b64decode(
        envelope["evidence_payloads"][request["evidence_ref"]], validate=True).decode("utf-8"))
    return data["artifact"], data["inputs"]


def build_sim_resource_fresh_certificate(request: dict, evidence: bytes | None, *,
                                       policy: dict) -> bytes:
    """Retain an invocation selection, not a claimed past measurement or verdict."""
    _require(type(request) is dict and type(policy) is dict, "FRESH_SELECTION_INVALID")
    _require(evidence is None or type(evidence) is bytes and len(evidence) <= _LIMIT,
             "FRESH_EVIDENCE_BOUND_EXCEEDED")
    return canonical_bytes({"schema_version": CERTIFICATE_VERSION,
        "request": request, "policy": policy,
        "evidence_base64": None if evidence is None else base64.b64encode(evidence).decode("ascii")})


def _run(bootstrap: bytes, payload: bytes, timeout: int) -> dict:
    completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", bootstrap.decode("utf-8")],
        input=payload, capture_output=True, timeout=timeout, check=False)
    if completed.returncode not in (0, 2):
        raise OSError("FRESH_WORKER_UNAVAILABLE")
    _require(completed.returncode == 0 and len(completed.stdout) <= 1024 * 1024,
             "FRESH_WORKER_REFUSED")
    return strict_json_loads(completed.stdout.decode("utf-8"))


def _interval(value: Any) -> bool:
    return (type(value) is dict and set(value) == {"start_ns", "end_ns"}
            and all(type(value[key]) is int and 0 <= value[key] <= 2**63 - 1 for key in value))


def _intervals_ordered(rows: list) -> bool:
    """Each observation precedes its arrival, arrival is chained after observation, and steps never overlap."""
    previous = 0
    for row in rows:
        observed, arrived = row["observation_interval"], row["arrival_interval"]
        if not (_interval(observed) and _interval(arrived)):
            return False
        if (observed["start_ns"] > observed["end_ns"] or arrived["start_ns"] != observed["end_ns"]
                or arrived["end_ns"] < arrived["start_ns"]
                or arrived["end_ns"] - arrived["start_ns"] > sim_fresh_worker.LATENCY_BOUND_NS
                or observed["start_ns"] < previous):
            return False
        previous = arrived["end_ns"]
    return True


def _execute(work: dict, selected_policy: dict) -> dict:
    if platform.python_implementation() != "CPython":
        raise OSError("FRESH_CPYTHON_METER_UNAVAILABLE")
    sources = _sources()
    manifest = _manifest(sources)
    # Source metadata is a typed wire value: Python's True == 1 must not turn
    # a substituted package flag into an exact selected-source binding.
    _require(canonical_bytes(manifest) == canonical_bytes(selected_policy["source_manifest"]),
             "FRESH_SOURCE_SELECTION_DIFFERS")
    bootstrap_path = Path(__file__).with_name("sim_fresh_bootstrap.py")
    bootstrap = bootstrap_path.read_bytes()
    challenge = secrets.token_hex(32)
    payload = canonical_bytes({"sources": {k: base64.b64encode(v).decode("ascii") for k, v in sources.items()},
                              "source_manifest": manifest, "challenge": challenge, "workload": work})
    _require(len(payload) <= _LIMIT, "FRESH_INPUT_BOUND_EXCEEDED")
    value = _run(bootstrap, payload, selected_policy["timeout_seconds"])
    _require(type(value) is dict and set(value) == {
        "challenge", "workload_digest", "source_manifest", "loaded_source_manifest", "capture"},
        "FRESH_WORKER_SHAPE_DIFFERS")
    _require(value["challenge"] == challenge and value["workload_digest"] == _digest(work)
             and canonical_bytes(value["source_manifest"]) == canonical_bytes(manifest)
             and canonical_bytes(value["loaded_source_manifest"]) == canonical_bytes(manifest),
             "FRESH_WORKER_BINDING_DIFFERS")
    _require(canonical_bytes(source_manifest()) == canonical_bytes(manifest) and bootstrap_path.read_bytes() == bootstrap
             and mechanism_digest() == selected_policy["mechanism_digest"],
             "FRESH_SOURCE_CHANGED_DURING_EXECUTION")
    capture = value["capture"]
    _require(type(capture) is dict and set(capture) == CAPTURE_KEYS, "FRESH_CAPTURE_SHAPE_DIFFERS")
    _require(capture["method"] == sim_fresh_worker.SENSOR["method"]
             and capture["target"] == "CPython " + platform.python_version()
             and type(capture["run_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", capture["run_id"]) is not None
             and type(capture["process_id"]) is int and 0 <= capture["process_id"] <= 2**64 - 1,
             "FRESH_CAPTURE_IDENTITY_DIFFERS")
    # Every row is bound to the sensor, measurement, challenge, source and this run/process frame, all recomputed here.
    expected_frame = {"sensor_digest": sim_fresh_worker.sensor_digest(), "measurement_digest": _digest(work),
                      "challenge": challenge, "source_digest": _digest(manifest),
                      "run_id": capture["run_id"], "process_id": capture["process_id"]}
    _require(canonical_bytes({key: capture[key] for key in sim_fresh_worker.FRAME_KEYS})
             == canonical_bytes(expected_frame), "FRESH_CAPTURE_IDENTITY_DIFFERS")
    rows, states = capture["steps"], work["inputs"]["states"]
    _require(type(rows) is list and len(rows) == len(work["inputs"]["entropy"])
             and 0 < len(rows) <= work["max_items"], "FRESH_STEP_COVERAGE_DIFFERS")
    for index, row in enumerate(rows):
        _require(type(row) is dict and set(row) == STEP_KEYS
            and type(row["step"]) is int and row["step"] == index
            and row["input_state_digest"] == _digest(states[index])
            and row["output_state_digest"] == _digest(states[index + 1])
            and all(type(row[key]) is int and 0 <= row[key] <= 2**63 - 1
                    for key in ("thread_cpu_ns", "traced_peak_bytes"))
            and row["binding_digest"] == sim_fresh_worker.step_binding(expected_frame, index, row),
            "FRESH_STEP_BINDING_DIFFERS")
    _require(_intervals_ordered(rows), "FRESH_STEP_INTERVAL_DIFFERS")
    value.update({"bootstrap_digest": _hash(bootstrap), "source_recheck": "PASS"})
    return value


def recheck_sim_resource_fresh_certificate(raw: bytes, *, expected_request: dict,
                                         policy: dict) -> dict[str, Any]:
    """Execute anew. No retained PASS or signature is accepted as execution proof."""
    _require(type(raw) is bytes and len(raw) <= 2 * _LIMIT, "FRESH_CERTIFICATE_BOUND_EXCEEDED")
    value = strict_json_loads(raw.decode("utf-8"))
    _require(type(value) is dict and set(value) == {
        "schema_version", "request", "policy", "evidence_base64"}
        and value["schema_version"] == CERTIFICATE_VERSION
        and canonical_bytes(value) == raw and canonical_bytes(value["request"]) == canonical_bytes(expected_request)
        and canonical_bytes(value["policy"]) == canonical_bytes(policy), "FRESH_CERTIFICATE_SELECTION_DIFFERS")
    _require(canonical_bytes(policy) == canonical_bytes(sim_resource_fresh_policy()), "FRESH_POLICY_SELECTION_DIFFERS")
    _require(type(expected_request) is dict and set(expected_request) == {
        "schema_version", "trajectory_request", "trajectory_policy",
        "trajectory_certificate_digest", "workload_digest", "evidence_ref"}
        and expected_request["schema_version"] == SEMANTIC_VERSION, "FRESH_REQUEST_INVALID")
    result = {"semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE, "status": "UNKNOWN", "observation": None,
        "reasons": REASONS, "object_profile_conformance": "NOT_ESTABLISHED",
        "historical_metric_correspondence": "NOT_ESTABLISHED",
        "host_attestation": "NOT_ESTABLISHED", "physical_device_use": "NOT_ESTABLISHED",
        **{scope: "NOT_ESTABLISHED" for scope in NOT_ESTABLISHED_SCOPES},
        "timing_scope": "raw CPython process observations over intervals containing transitions; monotonic intervals order steps and bound arrival latency only within that process",
        "selection_digest": _hash(raw), "invalidators": []}
    if value["evidence_base64"] is None:
        result["invalidators"] = ["FRESH_TRAJECTORY_UNAVAILABLE"]
        return result
    try:
        child = base64.b64decode(value["evidence_base64"], validate=True)
        _require(_hash(child) == expected_request["evidence_ref"]
                 == expected_request["trajectory_certificate_digest"], "FRESH_TRAJECTORY_DIFFERS")
        child_request = expected_request["trajectory_request"]
        native = sim_dynamics.recheck_sim_dynamics_certificate(
            child, expected_request=child_request, policy=expected_request["trajectory_policy"])
        if native["status"] != "PASS":
            result["status"] = native["status"]
            result["invalidators"] = ["FRESH_TRAJECTORY_NOT_PASS"]
            return result
        artifact, inputs = _child_data(child, child_request)
        work = {"artifact": artifact, "inputs": inputs,
                "max_operations": child_request["limits"]["max_operations"],
                "max_items": child_request["limits"]["max_items"]}
        _require(_digest(work) == expected_request["workload_digest"], "FRESH_WORKLOAD_DIFFERS")
        result["observation"] = _execute(work, policy)
        result["status"] = "PASS"
    except (subprocess.TimeoutExpired, OSError, MemoryError):
        result["invalidators"] = ["FRESH_EXECUTION_UNAVAILABLE"]
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        result["status"] = "FAIL"
        result["invalidators"] = ["FRESH_EXECUTION_REFUTED"]
        result["evaluation"] = {"details": NEGATIVE_REFUSAL_DETAIL}
    return result
