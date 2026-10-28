"""Adversarial regressions for source-bound physical ACTUATOR obligations.

Verifier Standard (VSTD). Records here are signed with fixture strings whose
prefix selects a trust-root class inside an injected verifier. ``PHYS`` fixtures
stand for a hardware root only as an injected test assumption; a PASS below
proves the mechanism's propositions hold under that assumption, and proves no
hardware, no real-world actuation and no physical effect. ``TEST`` fixtures
model a simulator or emulator, and must never yield PASS.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any

import pytest

from verifier.domains.contracts import actuator_physical as ap


MODULE_PATH = Path(ap.__file__)
RUN_ID = "run-0001"
ENDPOINT = "endpoint-7"
CMD_CHANNEL = "controller-channel-a"
SENSE_CHANNEL = "laser-sensor-b"
FAULT_WINDOW = {"start_us": 1_200_000, "end_us": 1_300_000, "reset_at_us": 1_400_000}
POLICY = {
    "endpoint_id": ENDPOINT,
    "unit": "um",
    "min_value": 0,
    "max_value": 5000,
    "tolerance": 10,
    "settle_us": 500_000,
    "max_run_us": 5_000_000,
    "fault_deadline_us": 200_000,
    "recovery_deadline_us": 1_000_000,
}
ALL_PROPOSITIONS = (
    "ENDPOINT_IDENTITY",
    "COMMAND_AUTHORIZATION",
    "COMMAND_EFFECT_CORRELATION",
    "EFFECT_FEEDBACK",
    "OPERATING_LIMITS_AND_INTERLOCKS",
    "FAILURE_STATE",
    "RECOVERY_SAFE_STATE",
)


class _Verifier:
    """Injected record verifier. The signature prefix selects the root class."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def verify(self, record: Any) -> str:
        self.calls.append(record["signature"])
        prefix = record["signature"].split(":", 1)[0]
        return {
            "PHYS": ap.PHYSICAL_ROOT,
            "TEST": ap.TEST_FIXTURE_ROOT,
            "BAD": ap.INVALID,
        }.get(prefix, ap.UNVERIFIED)


class _TestDoubleActuator:
    """Deterministic in-process backend. Its records are TEST-signed, never PHYS."""

    def run(self, command: dict[str, Any]) -> dict[str, Any]:
        return _run(command=command, root="TEST")


def _command(setpoint: int = 2500, command_id: str = "cmd-1", unit: str = "um") -> dict[str, Any]:
    return {
        "command_id": command_id,
        "endpoint_id": ENDPOINT,
        "channel_id": CMD_CHANNEL,
        "kind": "SET_POSITION",
        "setpoint": setpoint,
        "unit": unit,
        "issued_at_us": 1_000_000,
    }


def _rec(kind: str, observed: int, channel: str, payload: dict[str, Any], tag: str,
         root: str = "PHYS", run_id: str = RUN_ID) -> dict[str, Any]:
    return {
        "kind": kind,
        "run_id": run_id,
        "observed_at_us": observed,
        "channel_id": channel,
        "payload": payload,
        "signature": f"{root}:{tag}",
    }


def _records(command: dict[str, Any], root: str = "PHYS") -> list[dict[str, Any]]:
    """A complete, consistent, fault-free bundle. Consistent does not mean real."""
    digest = ap.command_digest(command)
    return [
        _rec("device_attestation", 900_000, "attestation-channel",
             {"endpoint_id": ENDPOINT}, "att-1", root),
        _rec("command_authorization", 950_000, "authorization-service",
             {"command_id": command["command_id"], "endpoint_id": ENDPOINT,
              "command_digest": digest, "not_before_us": 900_000,
              "not_after_us": 2_000_000, "grant_id": "grant-1"}, "auth-1", root),
        _rec("sensor_calibration", 900_000, "calibration-lab",
             {"sensor_id": "laser-1", "unit": "um", "valid_until_us": 9_000_000},
             "cal-1", root),
        _rec("interlock_state", 990_000, "interlock-monitor",
             {"endpoint_id": ENDPOINT, "armed": True}, "ilk-1", root),
        _rec("fault_monitor", 1_000_000, "fault-monitor",
             {"window_start_us": 1_000_000, "window_end_us": 2_000_000, "fault": False},
             "fm-1", root),
        _rec("effect_feedback", 1_400_000, SENSE_CHANNEL,
             {"command_id": command["command_id"], "endpoint_id": ENDPOINT,
              "sensor_id": "laser-1", "unit": "um", "measured_value": 2505}, "fb-1", root),
    ]


def _fault_records(root: str = "PHYS") -> list[dict[str, Any]]:
    """Fault-window bundle: the fault monitor is replaced by independent state reports."""
    base = [r for r in _records(_command(), root) if r["kind"] != "fault_monitor"]
    return base + [
        _rec("endpoint_state", 1_250_000, "state-monitor",
             {"endpoint_id": ENDPOINT, "state": "FAULT"}, "st-fault", root),
        _rec("endpoint_state", 1_500_000, "state-monitor",
             {"endpoint_id": ENDPOINT, "state": "READY"}, "st-ready", root),
    ]


def _run(command: dict[str, Any] | None = None, records: list[Any] | None = None,
         fault_window: dict[str, Any] | None = None, root: str = "PHYS") -> dict[str, Any]:
    command = command if command is not None else _command()
    run: dict[str, Any] = {
        "run_id": RUN_ID,
        "started_at_us": 900_000,
        "command": command,
        "records": records if records is not None else _records(command, root),
    }
    if fault_window is not None:
        run["fault_window"] = fault_window
    return run


def _evaluate(run: dict[str, Any], verifier: _Verifier | None = None,
              policy: dict[str, Any] | None = None) -> dict[str, Any]:
    return ap.evaluate_run(run, policy=policy or POLICY, verifier=verifier or _Verifier())


def _status(result: dict[str, Any], proposition: str) -> str:
    return result["propositions"][proposition]["status"]


def _statuses(result: dict[str, Any]) -> dict[str, str]:
    return {name: _status(result, name) for name in ALL_PROPOSITIONS}


def _refusal_reasons(result: dict[str, Any]) -> list[str]:
    return [row["reason"] for row in result["refused_records"]]


def _replace_kind(records: list[dict[str, Any]], kind: str, **changes: Any) -> list[dict[str, Any]]:
    out = []
    for record in records:
        if record["kind"] == kind:
            record = {**record, **changes}
        out.append(record)
    return out


# ---------------------------------------------------------------- absence and labels


def test_no_records_is_unknown_and_never_pass() -> None:
    result = _evaluate(_run(records=[]))
    assert result["status"] == "UNKNOWN"
    assert set(_statuses(result).values()) == {"UNKNOWN"}


def test_all_consistent_values_under_test_root_are_test_only_not_pass() -> None:
    """An emulator-shaped run whose numbers all match must not become physical PASS."""
    result = _evaluate(_run(root="TEST"))
    assert result["status"] == "TEST_ONLY"
    assert "PASS" not in _statuses(result).values()


def test_physical_root_bundle_passes_and_identical_test_root_bundle_does_not() -> None:
    physical = _evaluate(_run(root="PHYS"))
    assert physical["status"] == "PASS"
    assert _statuses(physical)["ENDPOINT_IDENTITY"] == "PASS"
    assert _statuses(physical)["EFFECT_FEEDBACK"] == "PASS"
    assert _statuses(physical)["FAILURE_STATE"] == "NOT_APPLICABLE"
    assert _statuses(physical)["RECOVERY_SAFE_STATE"] == "NOT_APPLICABLE"

    test_root = _evaluate(_run(root="TEST"))
    assert test_root["status"] == "TEST_ONLY"


def test_one_test_fixture_record_taints_the_proposition_it_supports() -> None:
    records = _records(_command())
    records[-1] = _rec("effect_feedback", 1_400_000, SENSE_CHANNEL,
                       dict(records[-1]["payload"]), "fb-1", root="TEST")
    result = _evaluate(_run(records=records))
    assert _status(result, "EFFECT_FEEDBACK") == "TEST_ONLY"
    assert _status(result, "ENDPOINT_IDENTITY") == "PASS"
    assert result["status"] == "TEST_ONLY"


def test_self_declared_physical_labels_are_ignored_and_reported() -> None:
    labelled = []
    for record in _records(_command(), root="TEST"):
        labelled.append({**record, "payload": {
            **record["payload"],
            "origin": "PHYSICAL_HARDWARE",
            "root_class": "PHYSICAL_HARDWARE",
            "physical": True,
        }})
    result = _evaluate(_run(records=labelled))
    assert result["status"] == "TEST_ONLY"
    assert result["contradicted_labels"], "a declared physical label must be reported"


@pytest.mark.parametrize("forbidden_kind", [
    "process_launch", "callback", "dispatch", "replay", "replay_log", "log",
    "hash", "emulator", "simulated_effect",
])
def test_process_callback_dispatch_replay_and_hash_kinds_are_not_evidence(forbidden_kind: str) -> None:
    command = _command()
    records = _records(command)
    records[0] = {**records[0], "kind": forbidden_kind}
    verifier = _Verifier()
    result = _evaluate(_run(command=command, records=records), verifier)
    assert _status(result, "ENDPOINT_IDENTITY") == "UNKNOWN"
    assert result["status"] != "PASS"
    assert "PHYS:att-1" not in verifier.calls, "refused evidence must never reach the verifier"
    assert "UNSUPPORTED_EVIDENCE_KIND" in _refusal_reasons(result)


def test_hash_only_record_is_refused_without_payload() -> None:
    records = _records(_command())
    records[-1] = {"kind": "effect_feedback", "run_id": RUN_ID,
                   "observed_at_us": 1_400_000, "digest": "sha256:" + "0" * 64,
                   "signature": "PHYS:fb-1"}
    result = _evaluate(_run(records=records))
    assert _status(result, "EFFECT_FEEDBACK") == "UNKNOWN"
    assert _status(result, "COMMAND_EFFECT_CORRELATION") == "UNKNOWN"
    assert result["status"] != "PASS"


def test_replayed_record_from_another_run_is_refused() -> None:
    records = _records(_command())
    records[-1] = _rec("effect_feedback", 1_400_000, SENSE_CHANNEL,
                       dict(records[-1]["payload"]), "fb-old", run_id="run-0000")
    result = _evaluate(_run(records=records))
    assert _status(result, "COMMAND_EFFECT_CORRELATION") == "UNKNOWN"
    assert "OTHER_RUN_OR_REPLAY" in _refusal_reasons(result)


def test_duplicate_record_is_refused_and_not_double_counted() -> None:
    records = _records(_command())
    records.append(dict(records[-1]))
    result = _evaluate(_run(records=records))
    assert result["status"] == "PASS"
    assert "DUPLICATE_RECORD" in _refusal_reasons(result)


def test_non_canonical_label_refuses_one_record_without_aborting_the_run() -> None:
    records = _records(_command())
    records[0] = {**records[0], "payload": {"endpoint_id": ENDPOINT, "origin": float("nan")}}
    result = _evaluate(_run(records=records))
    assert _status(result, "ENDPOINT_IDENTITY") == "UNKNOWN"
    assert "NON_CANONICAL_RECORD" in _refusal_reasons(result)


def test_record_before_run_start_is_stale_and_refused() -> None:
    records = _records(_command())
    records[0] = _rec("device_attestation", 100, "attestation-channel",
                      {"endpoint_id": ENDPOINT}, "att-old")
    result = _evaluate(_run(records=records))
    assert _status(result, "ENDPOINT_IDENTITY") == "UNKNOWN"
    assert "OUTSIDE_RUN_WINDOW" in _refusal_reasons(result)


def test_unverified_signature_is_refused_not_passed() -> None:
    records = _records(_command())
    records[0] = {**records[0], "signature": "UNKNOWN-KEY:att-1"}
    result = _evaluate(_run(records=records))
    assert _status(result, "ENDPOINT_IDENTITY") == "UNKNOWN"


# ---------------------------------------------------------------- identity and authorization


def test_missing_attestation_is_unknown() -> None:
    records = [r for r in _records(_command()) if r["kind"] != "device_attestation"]
    assert _status(_evaluate(_run(records=records)), "ENDPOINT_IDENTITY") == "UNKNOWN"


def test_attestation_for_another_endpoint_is_fail() -> None:
    records = _replace_kind(_records(_command()), "device_attestation",
                            payload={"endpoint_id": "endpoint-99"})
    assert _status(_evaluate(_run(records=records)), "ENDPOINT_IDENTITY") == "FAIL"


def test_forged_attestation_signature_is_fail_not_unknown() -> None:
    records = _records(_command())
    records[0] = {**records[0], "signature": "BAD:att-1"}
    result = _evaluate(_run(records=records))
    assert _status(result, "ENDPOINT_IDENTITY") == "FAIL"
    assert result["status"] == "FAIL"


def test_authorization_digest_for_different_setpoint_is_fail() -> None:
    other = _command(setpoint=2600)
    records = _replace_kind(_records(_command()), "command_authorization",
                            payload={"command_id": "cmd-1", "endpoint_id": ENDPOINT,
                                     "command_digest": ap.command_digest(other),
                                     "not_before_us": 900_000, "not_after_us": 2_000_000,
                                     "grant_id": "grant-1"})
    assert _status(_evaluate(_run(records=records)), "COMMAND_AUTHORIZATION") == "FAIL"


def test_expired_authorization_is_fail() -> None:
    command = _command()
    records = _replace_kind(_records(command), "command_authorization",
                            payload={"command_id": "cmd-1", "endpoint_id": ENDPOINT,
                                     "command_digest": ap.command_digest(command),
                                     "not_before_us": 900_000, "not_after_us": 999_999,
                                     "grant_id": "grant-1"})
    assert _status(_evaluate(_run(command=command, records=records)), "COMMAND_AUTHORIZATION") == "FAIL"


def test_command_without_authorization_is_unknown() -> None:
    records = [r for r in _records(_command()) if r["kind"] != "command_authorization"]
    assert _status(_evaluate(_run(records=records)), "COMMAND_AUTHORIZATION") == "UNKNOWN"


# ---------------------------------------------------------------- command-to-effect correlation


def test_effect_before_command_issue_is_fail() -> None:
    records = _replace_kind(_records(_command()), "effect_feedback", observed_at_us=999_000)
    assert _status(_evaluate(_run(records=records)), "COMMAND_EFFECT_CORRELATION") == "FAIL"


def test_effect_from_command_channel_is_not_independent() -> None:
    records = _replace_kind(_records(_command()), "effect_feedback", channel_id=CMD_CHANNEL)
    result = _evaluate(_run(records=records))
    assert _status(result, "COMMAND_EFFECT_CORRELATION") == "UNKNOWN"
    assert _status(result, "EFFECT_FEEDBACK") == "UNKNOWN"


def test_non_independent_effect_cannot_satisfy_operating_limits() -> None:
    """Limits need a measured value the command channel did not report; an armed interlock alone is not enough."""
    records = _replace_kind(_records(_command()), "effect_feedback", channel_id=CMD_CHANNEL)
    result = _evaluate(_run(records=records))
    assert _status(result, "OPERATING_LIMITS_AND_INTERLOCKS") == "UNKNOWN"
    assert result["status"] != "PASS"


def test_effect_after_settle_window_is_not_attributable_evidence() -> None:
    records = _replace_kind(_records(_command()), "effect_feedback", observed_at_us=1_600_000)
    assert _status(_evaluate(_run(records=records)), "COMMAND_EFFECT_CORRELATION") == "UNKNOWN"


def test_effect_attributed_to_another_command_leaves_this_command_unknown() -> None:
    records = _replace_kind(_records(_command()), "effect_feedback",
                            payload={"command_id": "cmd-0", "endpoint_id": ENDPOINT,
                                     "sensor_id": "laser-1", "unit": "um",
                                     "measured_value": 2505})
    assert _status(_evaluate(_run(records=records)), "COMMAND_EFFECT_CORRELATION") == "UNKNOWN"


# ---------------------------------------------------------------- effect feedback


def test_effect_outside_tolerance_is_fail() -> None:
    records = _replace_kind(_records(_command()), "effect_feedback",
                            payload={"command_id": "cmd-1", "endpoint_id": ENDPOINT,
                                     "sensor_id": "laser-1", "unit": "um",
                                     "measured_value": 2600})
    assert _status(_evaluate(_run(records=records)), "EFFECT_FEEDBACK") == "FAIL"


def test_effect_unit_mismatch_leaves_dimension_unestablished() -> None:
    records = _replace_kind(_records(_command()), "effect_feedback",
                            payload={"command_id": "cmd-1", "endpoint_id": ENDPOINT,
                                     "sensor_id": "laser-1", "unit": "mm",
                                     "measured_value": 2505})
    assert _status(_evaluate(_run(records=records)), "EFFECT_FEEDBACK") == "UNKNOWN"


def test_missing_calibration_is_unknown() -> None:
    records = [r for r in _records(_command()) if r["kind"] != "sensor_calibration"]
    assert _status(_evaluate(_run(records=records)), "EFFECT_FEEDBACK") == "UNKNOWN"


def test_calibration_expired_before_effect_is_unknown() -> None:
    records = _replace_kind(_records(_command()), "sensor_calibration",
                            payload={"sensor_id": "laser-1", "unit": "um",
                                     "valid_until_us": 1_300_000})
    assert _status(_evaluate(_run(records=records)), "EFFECT_FEEDBACK") == "UNKNOWN"


def test_calibration_for_another_sensor_is_unknown() -> None:
    records = _replace_kind(_records(_command()), "sensor_calibration",
                            payload={"sensor_id": "laser-9", "unit": "um",
                                     "valid_until_us": 9_000_000})
    assert _status(_evaluate(_run(records=records)), "EFFECT_FEEDBACK") == "UNKNOWN"


# ---------------------------------------------------------------- limits and interlocks


def test_setpoint_outside_operating_limit_is_fail() -> None:
    command = _command(setpoint=6000)
    assert _status(_evaluate(_run(command=command)), "OPERATING_LIMITS_AND_INTERLOCKS") == "FAIL"


def test_measured_value_above_limit_is_fail() -> None:
    command = _command(setpoint=4990)
    records = _replace_kind(_records(command), "effect_feedback",
                            payload={"command_id": "cmd-1", "endpoint_id": ENDPOINT,
                                     "sensor_id": "laser-1", "unit": "um",
                                     "measured_value": 5010})
    assert _status(_evaluate(_run(command=command, records=records)),
                   "OPERATING_LIMITS_AND_INTERLOCKS") == "FAIL"


def test_disarmed_interlock_at_issue_is_fail() -> None:
    records = _replace_kind(_records(_command()), "interlock_state",
                            payload={"endpoint_id": ENDPOINT, "armed": False})
    assert _status(_evaluate(_run(records=records)), "OPERATING_LIMITS_AND_INTERLOCKS") == "FAIL"


def test_missing_interlock_state_is_unknown() -> None:
    records = [r for r in _records(_command()) if r["kind"] != "interlock_state"]
    assert _status(_evaluate(_run(records=records)), "OPERATING_LIMITS_AND_INTERLOCKS") == "UNKNOWN"


def test_interlock_observed_after_issue_does_not_cover_the_command() -> None:
    records = _replace_kind(_records(_command()), "interlock_state", observed_at_us=1_100_000)
    assert _status(_evaluate(_run(records=records)), "OPERATING_LIMITS_AND_INTERLOCKS") == "UNKNOWN"


# ---------------------------------------------------------------- failure state and recovery


def test_declared_fault_without_independent_fault_observation_is_unknown() -> None:
    records = [r for r in _fault_records() if r["kind"] != "endpoint_state"]
    result = _evaluate(_run(records=records, fault_window=FAULT_WINDOW))
    assert _status(result, "FAILURE_STATE") == "UNKNOWN"
    assert _status(result, "RECOVERY_SAFE_STATE") == "UNKNOWN"


def test_endpoint_reporting_ready_during_declared_fault_is_fail() -> None:
    records = _fault_records() + [
        _rec("endpoint_state", 1_250_000, "state-monitor",
             {"endpoint_id": ENDPOINT, "state": "READY"}, "st-healthy"),
    ]
    assert _status(_evaluate(_run(records=records, fault_window=FAULT_WINDOW)),
                   "FAILURE_STATE") == "FAIL"


def test_observed_fault_and_recovery_within_deadlines_pass() -> None:
    result = _evaluate(_run(records=_fault_records(), fault_window=FAULT_WINDOW))
    assert _status(result, "FAILURE_STATE") == "PASS"
    assert _status(result, "RECOVERY_SAFE_STATE") == "PASS"
    assert result["status"] == "PASS"


def test_recovery_reported_after_deadline_is_fail() -> None:
    records = _fault_records()[:-1] + [
        _rec("endpoint_state", 2_500_000, "state-monitor",
             {"endpoint_id": ENDPOINT, "state": "FAULT"}, "st-stuck"),
    ]
    assert _status(_evaluate(_run(records=records, fault_window=FAULT_WINDOW)),
                   "RECOVERY_SAFE_STATE") == "FAIL"


def test_no_recovery_observation_after_reset_is_unknown() -> None:
    records = _fault_records()[:-1]
    assert _status(_evaluate(_run(records=records, fault_window=FAULT_WINDOW)),
                   "RECOVERY_SAFE_STATE") == "UNKNOWN"


def test_fault_monitor_reporting_fault_in_declared_fault_free_run_is_fail() -> None:
    records = _replace_kind(_records(_command()), "fault_monitor",
                            payload={"window_start_us": 1_000_000,
                                     "window_end_us": 2_000_000, "fault": True})
    assert _status(_evaluate(_run(records=records)), "FAILURE_STATE") == "FAIL"


def test_fault_free_claim_needs_a_covering_fault_monitor() -> None:
    records = [r for r in _records(_command()) if r["kind"] != "fault_monitor"]
    result = _evaluate(_run(records=records))
    assert _status(result, "FAILURE_STATE") == "UNKNOWN"
    assert _status(result, "RECOVERY_SAFE_STATE") == "UNKNOWN"
    assert result["status"] == "UNKNOWN"


# ---------------------------------------------------------------- injected backend and determinism


def test_test_double_backend_observes_as_test_only() -> None:
    verifier = _Verifier()
    result = ap.observe(_TestDoubleActuator(), _command(), policy=POLICY, verifier=verifier)
    assert result["status"] == "TEST_ONLY"
    assert verifier.calls, "observation must go through the injected verifier"


def test_backend_substituting_a_different_command_is_rejected() -> None:
    class _Substituting:
        def run(self, command: dict[str, Any]) -> dict[str, Any]:
            del command
            return _run(command=_command(setpoint=3000), root="PHYS")

    with pytest.raises(ap.ActuatorPhysicalError):
        ap.observe(_Substituting(), _command(), policy=POLICY, verifier=_Verifier())


def test_evaluation_is_deterministic_and_bound_to_the_records() -> None:
    first = _evaluate(_run())
    assert first == _evaluate(_run())
    changed = _replace_kind(_records(_command()), "effect_feedback", payload={
        "command_id": "cmd-1", "endpoint_id": ENDPOINT, "sensor_id": "laser-1",
        "unit": "um", "measured_value": 2506})
    assert _evaluate(_run(records=changed))["run_digest"] != first["run_digest"]


def test_result_names_policy_module_and_boundary() -> None:
    result = _evaluate(_run())
    assert result["module_digest"] == ap.module_digest()
    assert result["policy_digest"].startswith("sha256:")
    assert "not" in result["boundary"].lower() and "real-world actuation" in result["boundary"]


@pytest.mark.parametrize("mutate", [
    lambda run: run["command"].update(setpoint=True),
    lambda run: run.pop("run_id"),
    lambda run: run.update(fault_window={"start_us": 5, "end_us": 4, "reset_at_us": 9}),
])
def test_malformed_run_inputs_raise_instead_of_passing(mutate: Any) -> None:
    run = _run()
    mutate(run)
    with pytest.raises(ap.ActuatorPhysicalError):
        _evaluate(run)


def test_policy_with_inverted_limits_raises() -> None:
    with pytest.raises(ap.ActuatorPhysicalError):
        _evaluate(_run(), policy={**POLICY, "min_value": 9000})


def test_module_is_zero_runtime_dependency() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    allowed = set(sys.stdlib_module_names) | {"verifier"}
    assert imported <= allowed, imported - allowed
