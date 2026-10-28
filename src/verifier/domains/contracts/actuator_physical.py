"""Source-bound physical ACTUATOR obligations for Verifier Standard (VSTD).

An ACTUATOR claim is a bounded proposition that one command produced an observed
effect at one named endpoint. This module replays a caller-supplied run bundle
through seven propositions. Each proposition consults only evidence that passed
intake: an allowed kind, an exact payload shape, this run's identifier, an
observation time inside the run window, and a digest not seen before. The
injected record verifier then classifies each signature as PHYSICAL_ROOT,
TEST_FIXTURE_ROOT (a simulator or emulator), INVALID (a rejected signature, which
refutes any proposition that uses it), or UNVERIFIED (refused). Labels inside a
record never decide the class.

Process launches, callbacks, dispatch or replay logs, emulator output and bare
hashes are not evidence kinds here and are refused. A declared physical label that
the verifier does not confirm is ignored and reported. A PASS means every
necessary proposition held under PHYSICAL_ROOT classifications for this exact run.
It does not authenticate hardware, prove that an effect occurred in the world, or
establish safety. This module never drives hardware. Digests are Secure Hash
Algorithm 256-bit (SHA-256) values over canonical JavaScript Object Notation (JSON)
bytes, so a record's identity does not depend on key order.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol


SCHEMA = "verifier-actuator-physical-evaluation-1"
SEMANTIC_VERSION = "verifier-actuator-physical-obligations-1"
PHYSICAL_ROOT = "PHYSICAL_ROOT"
TEST_FIXTURE_ROOT = "TEST_FIXTURE_ROOT"
INVALID = "INVALID"
UNVERIFIED = "UNVERIFIED"
PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
TEST_ONLY = "TEST_ONLY"
NOT_APPLICABLE = "NOT_APPLICABLE"
PROPOSITIONS = (
    "ENDPOINT_IDENTITY",
    "COMMAND_AUTHORIZATION",
    "COMMAND_EFFECT_CORRELATION",
    "EFFECT_FEEDBACK",
    "OPERATING_LIMITS_AND_INTERLOCKS",
    "FAILURE_STATE",
    "RECOVERY_SAFE_STATE",
)
BOUNDARY = (
    "Bounded run-bundle replay under an injected record verifier. Intake refuses "
    "unsupported, replayed, stale, duplicate, malformed and unverified records. "
    "Propositions cover endpoint identity, command authorization, command-to-effect "
    "attribution, calibrated independent effect feedback, operating limits with an "
    "armed interlock, failure-state observation, and recovery or safe-state "
    "observation. TEST_FIXTURE_ROOT evidence is capped at TEST_ONLY. Not established: "
    "hardware or endpoint authenticity beyond the injected verifier, whether the "
    "verifier's roots are physical, real-world actuation or any effect in the world, "
    "measurement accuracy beyond the calibration record, physical operation of the "
    "interlock, physical stability, safety, or command authority beyond the grant record."
)
_RUN_REQUIRED = frozenset({"run_id", "started_at_us", "command", "records"})
_RECORD_KEYS = frozenset({"kind", "run_id", "observed_at_us", "channel_id", "payload", "signature"})
_COMMAND_KEYS = frozenset({
    "command_id", "endpoint_id", "channel_id", "kind", "setpoint", "unit", "issued_at_us",
})
_POLICY_KEYS = frozenset({
    "endpoint_id", "unit", "min_value", "max_value", "tolerance", "settle_us",
    "max_run_us", "fault_deadline_us", "recovery_deadline_us",
})
_POLICY_NONNEGATIVE = ("settle_us", "max_run_us", "fault_deadline_us", "recovery_deadline_us")
_PAYLOAD_SHAPES: dict[str, dict[str, type]] = {
    "device_attestation": {"endpoint_id": str},
    "command_authorization": {
        "command_id": str, "endpoint_id": str, "command_digest": str,
        "not_before_us": int, "not_after_us": int, "grant_id": str,
    },
    "sensor_calibration": {"sensor_id": str, "unit": str, "valid_until_us": int},
    "interlock_state": {"endpoint_id": str, "armed": bool},
    "effect_feedback": {
        "command_id": str, "endpoint_id": str, "sensor_id": str, "unit": str,
        "measured_value": int,
    },
    "endpoint_state": {"endpoint_id": str, "state": str},
    "fault_monitor": {"window_start_us": int, "window_end_us": int, "fault": bool},
}
_LABEL_KEYS = frozenset({
    "origin", "root_class", "physical", "source", "simulated", "emulated", "hardware_root",
})
_PHYSICAL_LABEL_VALUES = ("PHYSICAL_HARDWARE", "PHYSICAL")
_FAULT_STATES = frozenset({"FAULT", "SAFE"})
_RECOVERED_STATES = frozenset({"READY", "SAFE"})
_APPLICABILITY = {
    "ENDPOINT_IDENTITY": ("NECESSARY", "every ACTUATOR claim names one endpoint whose identity must be bound"),
    "COMMAND_AUTHORIZATION": ("NECESSARY", "an effect without a grant binding the exact command is unauthorized"),
    "COMMAND_EFFECT_CORRELATION": ("NECESSARY", "an effect is attributable only by command identifier, channel and time"),
    "EFFECT_FEEDBACK": ("NECESSARY", "effect values need an independent calibrated sensor in the policy unit"),
    "OPERATING_LIMITS_AND_INTERLOCKS": ("NECESSARY", "the command and observed values need limits and an armed interlock at issue"),
    "FAILURE_STATE": ("CONDITIONAL", "applies with a declared fault window; otherwise a covering fault-free monitor must exist"),
    "RECOVERY_SAFE_STATE": ("CONDITIONAL", "applies with a declared fault window and reset; otherwise as for failure state"),
}
_KIND_OF = {
    "ENDPOINT_IDENTITY": ("device_attestation",),
    "COMMAND_AUTHORIZATION": ("command_authorization",),
    "COMMAND_EFFECT_CORRELATION": ("effect_feedback",),
    "EFFECT_FEEDBACK": ("effect_feedback", "sensor_calibration"),
    "OPERATING_LIMITS_AND_INTERLOCKS": ("effect_feedback", "interlock_state"),
    "FAILURE_STATE": ("endpoint_state", "fault_monitor"),
    "RECOVERY_SAFE_STATE": ("endpoint_state", "fault_monitor"),
}
_NEUTRAL = "NEUTRAL"
_PRECEDENCE = (FAIL, UNKNOWN, TEST_ONLY, PASS, NOT_APPLICABLE)


class ActuatorPhysicalError(ValueError):
    """Malformed policy, command, run or backend output; the evaluation is refused."""


class RecordVerifier(Protocol):
    """Injected classifier: returns one of the root-class constants for a record."""

    def verify(self, record: Mapping[str, Any]) -> str:
        ...


class ActuatorBackend(Protocol):
    """Injected source of a run bundle for one command. Its output is never trusted as-is."""

    def run(self, command: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class _Evidence:
    kind: str
    observed_at_us: int
    channel_id: str
    payload: Mapping[str, Any]
    root: str
    digest: str


@dataclass(frozen=True)
class _Context:
    policy: Mapping[str, Any]
    command: Mapping[str, Any]
    fault_window: Mapping[str, int] | None
    evidence: tuple[_Evidence, ...]


_Finding = tuple[str, str]


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ActuatorPhysicalError("value is not canonical JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _record_digest(raw: Any) -> str | None:
    """Digest of a record, or None when it is not canonical JSON and so must be refused."""
    try:
        return _digest(raw)
    except ActuatorPhysicalError:
        return None


def module_digest() -> str:
    """Digest of this module's own bytes, so a result names the exact source it ran."""
    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _nonnegative(value: Any) -> bool:
    return type(value) is int and value >= 0


def _validated_command(command: Any) -> dict[str, Any]:
    if not isinstance(command, dict) or set(command) != _COMMAND_KEYS:
        raise ActuatorPhysicalError("command fields")
    for key in ("command_id", "endpoint_id", "channel_id", "kind", "unit"):
        if not _text(command[key]):
            raise ActuatorPhysicalError(f"command.{key}")
    if type(command["setpoint"]) is not int:
        raise ActuatorPhysicalError("command.setpoint")
    if not _nonnegative(command["issued_at_us"]):
        raise ActuatorPhysicalError("command.issued_at_us")
    return dict(command)


def _validated_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) != _POLICY_KEYS:
        raise ActuatorPhysicalError("policy fields")
    if not _text(policy["endpoint_id"]) or not _text(policy["unit"]):
        raise ActuatorPhysicalError("policy identity or unit")
    for key in ("min_value", "max_value", "tolerance", *_POLICY_NONNEGATIVE):
        if type(policy[key]) is not int:
            raise ActuatorPhysicalError(f"policy.{key}")
    if policy["min_value"] > policy["max_value"] or policy["tolerance"] < 0:
        raise ActuatorPhysicalError("policy limits")
    if any(policy[key] < 0 for key in _POLICY_NONNEGATIVE):
        raise ActuatorPhysicalError("policy durations")
    return dict(policy)


def _validated_run(run: Any) -> dict[str, Any]:
    if not isinstance(run, dict) or not _RUN_REQUIRED <= set(run) or not set(run) <= _RUN_REQUIRED | {"fault_window"}:
        raise ActuatorPhysicalError("run fields")
    if not _text(run["run_id"]) or not _nonnegative(run["started_at_us"]):
        raise ActuatorPhysicalError("run identity or start")
    if not isinstance(run["records"], list):
        raise ActuatorPhysicalError("run.records")
    fault = run.get("fault_window")
    if fault is not None:
        if not isinstance(fault, dict) or set(fault) != {"start_us", "end_us", "reset_at_us"}:
            raise ActuatorPhysicalError("fault_window fields")
        if not all(_nonnegative(value) for value in fault.values()):
            raise ActuatorPhysicalError("fault_window values")
        if not fault["start_us"] <= fault["end_us"] <= fault["reset_at_us"]:
            raise ActuatorPhysicalError("fault_window ordering")
        fault = dict(fault)
    return {
        "run_id": run["run_id"],
        "started_us": run["started_at_us"],
        "command": _validated_command(run["command"]),
        "records": run["records"],
        "fault_window": fault,
    }


def command_digest(command: Any) -> str:
    """Digest binding an authorization to the exact validated command content."""
    return _digest(_validated_command(command))


def _refusal(raw: Any, run: Mapping[str, Any], policy: Mapping[str, Any]) -> str | None:
    if not isinstance(raw, dict):
        return "MALFORMED_RECORD"
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in _PAYLOAD_SHAPES:
        return "UNSUPPORTED_EVIDENCE_KIND"
    if set(raw) != _RECORD_KEYS or not _text(raw["channel_id"]) or not isinstance(raw["payload"], dict):
        return "MALFORMED_RECORD"
    if raw["run_id"] != run["run_id"]:
        return "OTHER_RUN_OR_REPLAY"
    observed = raw["observed_at_us"]
    if not _nonnegative(observed) or not run["started_us"] <= observed <= run["started_us"] + policy["max_run_us"]:
        return "OUTSIDE_RUN_WINDOW"
    if not isinstance(raw["signature"], str):
        return "UNSIGNED_RECORD"
    shape = _PAYLOAD_SHAPES[kind]
    payload = raw["payload"]
    if not set(shape) <= set(payload) or not set(payload) - set(shape) <= _LABEL_KEYS:
        return "MALFORMED_PAYLOAD"
    if any(type(payload[key]) is not expected for key, expected in shape.items()):
        return "MALFORMED_PAYLOAD"
    return None


def _claims_physical(key: str, value: Any) -> bool:
    return value in _PHYSICAL_LABEL_VALUES or (key == "physical" and value is True)


def _intake(run: Mapping[str, Any], policy: Mapping[str, Any], verifier: RecordVerifier) -> tuple[
    tuple[_Evidence, ...], list[dict[str, Any]], list[dict[str, Any]], list[str],
]:
    accepted: list[_Evidence] = []
    refused: list[dict[str, Any]] = []
    contradicted: list[dict[str, Any]] = []
    label_keys: set[str] = set()
    seen: set[str] = set()
    for index, raw in enumerate(run["records"]):
        reason = _refusal(raw, run, policy)
        digest = _record_digest(raw) if reason is None else None
        if reason is None and digest is None:
            reason = "NON_CANONICAL_RECORD"
        elif reason is None and digest in seen:
            reason = "DUPLICATE_RECORD"
        if reason is not None or digest is None:
            refused.append({"index": index, "reason": reason})
            continue
        seen.add(digest)
        root = verifier.verify(json.loads(_canonical(raw)))
        if root == UNVERIFIED:
            refused.append({"index": index, "reason": "UNVERIFIED_SIGNATURE"})
            continue
        if root not in (PHYSICAL_ROOT, TEST_FIXTURE_ROOT, INVALID):
            raise ActuatorPhysicalError("verifier returned an unknown root class")
        declared = sorted(
            key for key, value in raw["payload"].items()
            if key in _LABEL_KEYS and _claims_physical(key, value)
        )
        label_keys.update(key for key in raw["payload"] if key in _LABEL_KEYS)
        if declared and root != PHYSICAL_ROOT:
            contradicted.append({"index": index, "declared_keys": declared, "verified_root": root})
        accepted.append(_Evidence(
            kind=raw["kind"], observed_at_us=raw["observed_at_us"], channel_id=raw["channel_id"],
            payload=raw["payload"], root=root, digest=digest,
        ))
    return tuple(accepted), refused, contradicted, sorted(label_keys)


def _of(ctx: _Context, kind: str) -> list[_Evidence]:
    return [evidence for evidence in ctx.evidence if evidence.kind == kind]


def _forged(record: _Evidence) -> _Finding:
    return (FAIL, f"{record.kind} signature rejected by the verifier: forged or corrupt evidence")


def _graded(record: _Evidence, reason: str) -> _Finding:
    if record.root == PHYSICAL_ROOT:
        return (PASS, reason)
    if record.root == TEST_FIXTURE_ROOT:
        return (TEST_ONLY, reason + " (TEST_FIXTURE_ROOT is not physical)")
    return _forged(record)


def _graded_absence(record: _Evidence, reason: str) -> _Finding:
    if record.root == PHYSICAL_ROOT:
        return (NOT_APPLICABLE, reason)
    if record.root == TEST_FIXTURE_ROOT:
        return (TEST_ONLY, reason + " (TEST_FIXTURE_ROOT is not physical)")
    return _forged(record)


def _combine(findings: list[_Finding], missing: str) -> _Finding:
    live = [finding for finding in findings if finding[0] != _NEUTRAL]
    if not live:
        return (UNKNOWN, missing)
    for status in _PRECEDENCE:
        reasons = sorted({reason for found, reason in live if found == status})
        if reasons:
            return (status, "; ".join(reasons))
    raise AssertionError("every live status is in the precedence table")


def _proposition(ctx: _Context, name: str, findings: list[_Finding], missing: str) -> dict[str, Any]:
    status, reason = _combine(findings, missing)
    mode, applicability = _APPLICABILITY[name]
    return {
        "status": status,
        "reason": reason,
        "applicability": mode,
        "applicability_reason": applicability,
        "evidence_digests": sorted(e.digest for e in ctx.evidence if e.kind in _KIND_OF[name]),
    }


def _endpoint_identity(ctx: _Context) -> dict[str, Any]:
    findings: list[_Finding] = []
    if ctx.command["endpoint_id"] != ctx.policy["endpoint_id"]:
        findings.append((FAIL, "command targets an endpoint other than the policy endpoint"))
    for record in _of(ctx, "device_attestation"):
        if record.root == INVALID:
            findings.append(_forged(record))
        elif record.payload["endpoint_id"] != ctx.policy["endpoint_id"]:
            findings.append((FAIL, "attestation names a different endpoint"))
        else:
            findings.append(_graded(record, "device attestation binds the policy endpoint"))
    return _proposition(ctx, "ENDPOINT_IDENTITY", findings, "no device attestation for the policy endpoint")


def _command_authorization(ctx: _Context) -> dict[str, Any]:
    findings: list[_Finding] = []
    digest = command_digest(ctx.command)
    issued = ctx.command["issued_at_us"]
    for record in _of(ctx, "command_authorization"):
        payload = record.payload
        if record.root == INVALID:
            findings.append(_forged(record))
        elif payload["command_id"] != ctx.command["command_id"] or payload["endpoint_id"] != ctx.command["endpoint_id"]:
            continue
        elif payload["command_digest"] != digest:
            findings.append((FAIL, "authorization names this command but binds different content"))
        elif not payload["not_before_us"] <= issued <= payload["not_after_us"]:
            findings.append((FAIL, "authorization is not valid at command issue"))
        else:
            findings.append(_graded(record, "grant binds the exact command content and validity window"))
    return _proposition(ctx, "COMMAND_AUTHORIZATION", findings, "no authorization record for this command")


def _effect_candidates(ctx: _Context) -> list[tuple[_Evidence, bool, _Finding]]:
    """Each effect naming this command, with whether it is attributable and why."""
    issued = ctx.command["issued_at_us"]
    settle_end = issued + ctx.policy["settle_us"]
    out: list[tuple[_Evidence, bool, _Finding]] = []
    for record in _of(ctx, "effect_feedback"):
        if record.root == INVALID:
            out.append((record, False, _forged(record)))
        elif record.payload["command_id"] != ctx.command["command_id"]:
            continue
        elif record.channel_id == ctx.command["channel_id"]:
            out.append((record, False, (UNKNOWN, "effect channel is the command channel and is not independent")))
        elif record.observed_at_us < issued:
            out.append((record, False, (FAIL, "effect observed before command issue")))
        elif record.observed_at_us > settle_end:
            out.append((record, False, (UNKNOWN, "effect observed after the settle window")))
        else:
            out.append((record, True, _graded(record, "effect attributed by command identifier, independent channel and settle window")))
    return out


def _command_effect_correlation(ctx: _Context) -> dict[str, Any]:
    findings = [finding for _, _, finding in _effect_candidates(ctx)]
    return _proposition(ctx, "COMMAND_EFFECT_CORRELATION", findings, "no effect attributed to this command")


def _calibration(ctx: _Context, effect: _Evidence) -> _Finding:
    matches = [c for c in _of(ctx, "sensor_calibration") if c.payload["sensor_id"] == effect.payload["sensor_id"]]
    findings: list[_Finding] = []
    for record in matches:
        if record.root == INVALID:
            findings.append(_forged(record))
        elif record.payload["unit"] != ctx.policy["unit"]:
            findings.append((UNKNOWN, "calibration unit differs from the policy unit"))
        elif record.payload["valid_until_us"] < effect.observed_at_us:
            findings.append((UNKNOWN, "calibration expired before the effect observation"))
        else:
            findings.append(_graded(record, "sensor calibration covers the effect observation"))
    return _combine(findings, "no calibration record for the effect sensor")


def _effect_feedback(ctx: _Context) -> dict[str, Any]:
    findings: list[_Finding] = []
    for record, attributable, attribution in _effect_candidates(ctx):
        if not attributable:
            findings.append(attribution)
        elif record.payload["unit"] != ctx.policy["unit"] or ctx.command["unit"] != ctx.policy["unit"]:
            findings.append((UNKNOWN, "unit differs from the policy unit: dimension not established"))
        else:
            deviation = abs(record.payload["measured_value"] - ctx.command["setpoint"])
            if deviation > ctx.policy["tolerance"]:
                findings.append((FAIL, f"measured deviation {deviation} exceeds tolerance {ctx.policy['tolerance']}"))
            else:
                value = _graded(record, "measured value within tolerance of the setpoint")
                findings.append(_combine([value, _calibration(ctx, record)], "no calibration record for the effect sensor"))
    return _proposition(ctx, "EFFECT_FEEDBACK", findings, "no independent effect feedback within the settle window")


def _interlock(ctx: _Context) -> list[_Finding]:
    issued = ctx.command["issued_at_us"]
    findings: list[_Finding] = []
    valid: list[_Evidence] = []
    for record in _of(ctx, "interlock_state"):
        if record.root == INVALID:
            findings.append(_forged(record))
        elif record.payload["endpoint_id"] == ctx.policy["endpoint_id"] and record.observed_at_us <= issued:
            valid.append(record)
    if not valid:
        return findings + [(UNKNOWN, "no interlock state observed at or before command issue")]
    latest = max(valid, key=lambda record: record.observed_at_us)
    if not latest.payload["armed"]:
        return findings + [(FAIL, "interlock disarmed at command issue")]
    return findings + [_graded(latest, "interlock armed at command issue")]


def _operating_limits(ctx: _Context) -> dict[str, Any]:
    lower, upper = ctx.policy["min_value"], ctx.policy["max_value"]
    findings: list[_Finding] = []
    if ctx.command["unit"] != ctx.policy["unit"]:
        findings.append((UNKNOWN, "command unit differs from the policy unit"))
    elif not lower <= ctx.command["setpoint"] <= upper:
        findings.append((FAIL, "setpoint outside operating limits"))
    measured = [record for record, attributable, _ in _effect_candidates(ctx) if attributable]
    if not measured:
        findings.append((UNKNOWN, "no independent measured value to check against operating limits"))
    for record in measured:
        if record.payload["unit"] != ctx.policy["unit"]:
            findings.append((UNKNOWN, "measured unit differs from the policy unit"))
        elif not lower <= record.payload["measured_value"] <= upper:
            findings.append((FAIL, "measured value outside operating limits"))
        else:
            findings.append(_graded(record, "measured value within operating limits"))
    findings.extend(_interlock(ctx))
    return _proposition(ctx, "OPERATING_LIMITS_AND_INTERLOCKS", findings, "no limit or interlock evidence for this command")


def _independent_states(ctx: _Context) -> tuple[list[_Evidence], list[_Finding]]:
    """Endpoint state reports from a channel other than the command channel, plus integrity findings."""
    states: list[_Evidence] = []
    findings: list[_Finding] = []
    for record in _of(ctx, "endpoint_state"):
        if record.payload["endpoint_id"] != ctx.policy["endpoint_id"]:
            continue
        if record.root == INVALID:
            findings.append(_forged(record))
        elif record.channel_id == ctx.command["channel_id"]:
            findings.append((UNKNOWN, "endpoint state from the command channel is not independent"))
        else:
            states.append(record)
    return states, findings


def _fault_free_claim(ctx: _Context, name: str) -> dict[str, Any]:
    """Without a declared fault window, a covering monitor must report no fault for the command window."""
    issued = ctx.command["issued_at_us"]
    settle_end = issued + ctx.policy["settle_us"]
    findings: list[_Finding] = []
    for record in _of(ctx, "fault_monitor"):
        payload = record.payload
        overlaps = payload["window_start_us"] <= settle_end and payload["window_end_us"] >= issued
        if record.root == INVALID:
            findings.append(_forged(record))
        elif payload["fault"] and overlaps:
            if name == "FAILURE_STATE":
                findings.append((FAIL, "fault monitor reported a fault in a run declared fault-free"))
            else:
                findings.append((UNKNOWN, "fault reported with no declared reset window"))
        elif not payload["fault"] and payload["window_start_us"] <= issued and payload["window_end_us"] >= settle_end:
            findings.append(_graded_absence(record, "covering fault monitor reports no fault for the command window"))
    return _proposition(ctx, name, findings, "no declared fault window and no covering fault-free monitor")


def _failure_state(ctx: _Context) -> dict[str, Any]:
    if ctx.fault_window is None:
        return _fault_free_claim(ctx, "FAILURE_STATE")
    window = ctx.fault_window
    states, findings = _independent_states(ctx)
    for record in states:
        if window["start_us"] <= record.observed_at_us <= window["end_us"] and record.payload["state"] == "READY":
            findings.append((FAIL, "endpoint reported READY inside the declared fault window"))
    deadline = window["start_us"] + ctx.policy["fault_deadline_us"]
    observed = [
        record for record in states
        if window["start_us"] <= record.observed_at_us <= deadline and record.payload["state"] in _FAULT_STATES
    ]
    if observed:
        findings.extend(_graded(record, "independent channel observed fault or safe state within the fault deadline") for record in observed)
    else:
        findings.append((UNKNOWN, "no independent fault or safe-state observation within the fault deadline"))
    return _proposition(ctx, "FAILURE_STATE", findings, "no independent failure-state evidence")


def _recovery_safe_state(ctx: _Context) -> dict[str, Any]:
    if ctx.fault_window is None:
        return _fault_free_claim(ctx, "RECOVERY_SAFE_STATE")
    reset_at = ctx.fault_window["reset_at_us"]
    deadline = reset_at + ctx.policy["recovery_deadline_us"]
    states, findings = _independent_states(ctx)
    after = sorted((record for record in states if record.observed_at_us > reset_at), key=lambda r: r.observed_at_us)
    if not after:
        findings.append((UNKNOWN, "no independent state observation after reset"))
    else:
        latest = after[-1]
        recovered = latest.payload["state"] in _RECOVERED_STATES
        if recovered and latest.observed_at_us <= deadline:
            findings.append(_graded(latest, "recovered or safe state observed within the recovery deadline"))
        elif recovered:
            findings.append((FAIL, "recovery observed after the deadline"))
        elif latest.observed_at_us > deadline:
            findings.append((FAIL, "endpoint still faulted after the recovery deadline"))
        else:
            findings.append((UNKNOWN, "endpoint still faulted within the recovery deadline"))
    return _proposition(ctx, "RECOVERY_SAFE_STATE", findings, "no independent recovery evidence")


def _overall(propositions: Mapping[str, Mapping[str, Any]]) -> str:
    statuses = {row["status"] for row in propositions.values()}
    for status in (FAIL, UNKNOWN, TEST_ONLY):
        if status in statuses:
            return status
    return PASS if PASS in statuses else UNKNOWN


def evaluate_run(run: Any, *, policy: Any, verifier: RecordVerifier) -> dict[str, Any]:
    """Replay one run bundle. Malformed inputs raise; every unsupported claim stays UNKNOWN or FAIL."""
    checked_policy = _validated_policy(policy)
    checked = _validated_run(run)
    evidence, refused, contradicted, label_keys = _intake(checked, checked_policy, verifier)
    ctx = _Context(
        policy=checked_policy,
        command=checked["command"],
        fault_window=checked["fault_window"],
        evidence=evidence,
    )
    propositions = {
        "ENDPOINT_IDENTITY": _endpoint_identity(ctx),
        "COMMAND_AUTHORIZATION": _command_authorization(ctx),
        "COMMAND_EFFECT_CORRELATION": _command_effect_correlation(ctx),
        "EFFECT_FEEDBACK": _effect_feedback(ctx),
        "OPERATING_LIMITS_AND_INTERLOCKS": _operating_limits(ctx),
        "FAILURE_STATE": _failure_state(ctx),
        "RECOVERY_SAFE_STATE": _recovery_safe_state(ctx),
    }
    return {
        "schema": SCHEMA,
        "semantic_version": SEMANTIC_VERSION,
        "status": _overall(propositions),
        "propositions": propositions,
        "refused_records": refused,
        "contradicted_labels": contradicted,
        "ignored_label_keys": label_keys,
        "policy_digest": _digest(checked_policy),
        "run_digest": _digest({
            "run_id": checked["run_id"],
            "started_us": checked["started_us"],
            "command": checked["command"],
            "fault_window": checked["fault_window"],
            "records": [_record_digest(raw) or "NON_CANONICAL_RECORD" for raw in checked["records"]],
        }),
        "command_digest": command_digest(checked["command"]),
        "module_digest": module_digest(),
        "boundary": BOUNDARY,
    }


def observe(backend: ActuatorBackend, command: Any, *, policy: Any, verifier: RecordVerifier) -> dict[str, Any]:
    """Request one run from an injected backend and replay it. The backend output must bind this command."""
    expected = command_digest(command)
    run = backend.run(command)
    if not isinstance(run, dict) or "command" not in run or command_digest(run["command"]) != expected:
        raise ActuatorPhysicalError("backend returned a bundle for a different command")
    return evaluate_run(run, policy=policy, verifier=verifier)
