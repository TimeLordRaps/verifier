"""Direct tests for bounded parent-side process observations."""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.core import run_process_observation as observation
from verifier.core.receipt import compute_canonical_digest
from verifier.core.run import capture_run
from verifier.core.run_support import RunOutcome
from verifier.core.run_validation import (
    _parent_process_receipt_binding_errors,
    _rebuild_stable_payload_from_dict,
    validate_run_receipt,
)


def _attempt(tmp_path: Path, **changes: object) -> observation.ParentProcessLaunch:
    values: dict[str, object] = {
        "argv": ["python", "worker.py", "--mode", "check"],
        "declared_cwd": "work/subject",
        "resolved_cwd": tmp_path / "work" / "subject",
        "timeout_seconds": 30,
        "stdout_retention_limit_bytes": 8,
        "stderr_retention_limit_bytes": 8,
    }
    values.update(changes)
    return observation.begin_parent_process_observation(**values)


def _assert_rechecks(
    record: dict[str, object], attempt: observation.ParentProcessLaunch
) -> None:
    observation.recheck_parent_process_observation(
        record,
        bound_inner_digest=record["inner_digest"],
        expected_launch=attempt,
    )


def _seal(kind: str, attempt: observation.ParentProcessLaunch, **cleanup: object) -> dict:
    """Seal one record of the named kind; ``cleanup`` is passed through unchanged."""

    if kind == "completed":
        return observation.observe_completed_process(
            attempt, returncode=0, stdout=b"", stderr=b"", **cleanup
        )
    if kind == "timeout":
        return observation.observe_timeout(
            attempt,
            subprocess.TimeoutExpired(attempt.argv, attempt.timeout_seconds),
            **cleanup,
        )
    if kind == "output_cap":
        return observation.observe_output_cap_exceeded(
            attempt, stdout=b"", stderr=b"", **cleanup
        )
    if kind == "cleanup_not_established":
        return observation.observe_cleanup_not_established(
            attempt, stdout=b"", stderr=b"", **cleanup
        )
    if kind == "exit_status_unknown":
        return observation.observe_exit_status_unknown(
            attempt, stdout=b"", stderr=b"", **cleanup
        )
    raise AssertionError(kind)


def _write_typed_outcome_receipt(
    tmp_path: Path,
    *,
    kind: str,
    execution_outcome: str,
) -> Path:
    """Build a digest-valid receipt whose parent observation has a typed uncertainty."""

    manifest = {
        "claim": {
            "id": "RUN-OBSERVATION-VALIDATION",
            "title": "Typed process observation validation",
            "statement": "The parent process outcome remains explicitly uncertain.",
            "scope": "validation regression",
            "limitations": ["No process-success claim is made."],
            "falsification_condition": "The typed uncertainty is accepted as success.",
        },
        "command": [sys.executable, "-c", "pass"],
        "cwd": ".",
        "inputs": [],
        "outputs": [],
        "determinism_declared": "DETERMINISTIC",
    }
    data = capture_run(manifest, manifest_dir=tmp_path).to_dict()
    attempt = observation.begin_parent_process_observation(
        argv=data["execution"]["command"],
        declared_cwd=data["execution"]["cwd"],
        resolved_cwd=tmp_path,
        timeout_seconds=30,
        stdout_retention_limit_bytes=8,
        stderr_retention_limit_bytes=8,
    )
    if kind == "output_cap":
        record = observation.observe_output_cap_exceeded(
            attempt,
            stdout=b"0123456789",
            stderr=b"",
            owned_tree_cleanup="CONFIRMED",
        )
    elif kind == "cleanup_not_established":
        record = observation.observe_cleanup_not_established(
            attempt,
            stdout=b"partial",
            stderr=b"",
            owned_tree_cleanup="UNKNOWN",
        )
    elif kind == "exit_status_unknown":
        record = observation.observe_exit_status_unknown(
            attempt,
            stdout=b"",
            stderr=b"",
            owned_tree_cleanup="CONFIRMED",
        )
    else:  # pragma: no cover - test helper misuse
        raise AssertionError(kind)

    data["assessment_context"]["refutation_surface"][
        "parent_process_observation"
    ] = record
    data["execution"]["outcome"] = execution_outcome
    data["execution"]["exit_code"] = None
    for stream_name in ("stdout", "stderr"):
        data["execution"][f"{stream_name}_sha256"] = record["result"][stream_name][
            "sha256"
        ].removeprefix("sha256:")
    data["claims"]["execution_completed"] = execution_outcome == "COMPLETED"
    data["claims"]["output_digests_recorded"] = False
    data["claims"]["all_declared_artifacts_present"] = False
    data["canonical_digest"] = compute_canonical_digest(
        _rebuild_stable_payload_from_dict(data)
    )
    path = tmp_path / f"{kind}-{execution_outcome}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("kind", "outcome"),
    (
        ("output_cap", RunOutcome.OUTPUT_CAP_EXCEEDED.value),
        ("cleanup_not_established", RunOutcome.CLEANUP_NOT_ESTABLISHED.value),
        ("exit_status_unknown", RunOutcome.EXIT_STATUS_UNKNOWN.value),
    ),
)
def test_run_receipt_validator_accepts_typed_uncertainty_only_under_matching_outer_outcome(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
    outcome: str,
) -> None:
    path = _write_typed_outcome_receipt(
        tmp_path,
        kind=kind,
        execution_outcome=outcome,
    )

    assert validate_run_receipt(path) == 0
    output = capsys.readouterr().out
    assert f"Outcome: {outcome}" in output
    assert "Outcome: COMPLETED" not in output


@pytest.mark.parametrize(
    "kind",
    ("output_cap", "cleanup_not_established", "exit_status_unknown"),
)
def test_run_receipt_validator_rejects_typed_uncertainty_relabelled_as_completed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    path = _write_typed_outcome_receipt(
        tmp_path,
        kind=kind,
        execution_outcome=RunOutcome.COMPLETED.value,
    )

    assert validate_run_receipt(path) == 1
    output = capsys.readouterr().out
    assert "result.outcome differs from execution.outcome" in output
    assert "[INTEGRITY OK]" not in output


def test_unknown_parent_outcome_fails_closed_without_key_error() -> None:
    errors = _parent_process_receipt_binding_errors(
        {
            "launch": {"argv": ["python", "worker.py"], "declared_cwd": "."},
            "result": {
                "outcome": "FUTURE_UNMAPPED_OUTCOME",
                "returncode": None,
                "stdout": {"availability": "UNOBSERVED"},
                "stderr": {"availability": "UNOBSERVED"},
            },
        },
        {
            "command": ["python", "worker.py"],
            "cwd": ".",
            "outcome": RunOutcome.EXCEPTION.value,
            "exit_code": None,
        },
    )

    assert errors == ["result.outcome is not recognized for execution binding"]


def test_capture_owns_unique_launch_identity_and_does_not_expose_resolved_cwd(
    tmp_path: Path,
) -> None:
    first = _attempt(tmp_path)
    second = _attempt(tmp_path)

    assert first.launch_identity != second.launch_identity
    assert len(first.launch_identity) == 64
    assert set(first.launch_identity) <= set("0123456789abcdef")
    launch = first.to_dict()
    assert launch["declared_cwd"] == "work/subject"
    assert launch["declared_cwd_portability"] == "PORTABLE_RELATIVE"
    assert launch["resolved_cwd_sha256"].startswith("sha256:")
    assert str((tmp_path / "work" / "subject").resolve()) not in repr(launch)
    assert launch["launch_attempted"] == "YES"


@pytest.mark.parametrize("returncode,outcome", [(0, "SUCCESS"), (7, "NONZERO_EXIT")])
def test_completed_process_records_exact_stream_facts(
    tmp_path: Path, returncode: int, outcome: str
) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_completed_process(
        attempt,
        returncode=returncode,
        stdout=b"0123456789",
        stderr=b"warning",
        owned_tree_cleanup="CONFIRMED",
    )

    assert record["result"]["outcome"] == outcome
    assert record["result"]["process_started"] == "YES"
    assert record["result"]["streams_complete"] == "YES"
    assert record["result"]["returncode"] == returncode
    assert record["result"]["owned_tree_cleanup"] == "CONFIRMED"
    stdout = record["result"]["stdout"]
    assert stdout["byte_count"] == 10
    assert stdout["retention_truncated"] is True
    assert stdout["completeness"] == "COMPLETE"
    assert base64.b64decode(stdout["retained_base64"]) == b"01234567"
    assert record["result"]["stderr"]["retention_truncated"] is False
    _assert_rechecks(record, attempt)


def test_timeout_retains_available_partial_streams_without_claiming_completeness(
    tmp_path: Path,
) -> None:
    attempt = _attempt(tmp_path)
    error = subprocess.TimeoutExpired(
        attempt.argv,
        attempt.timeout_seconds,
        output=b"partial stdout",
        stderr=None,
    )
    record = observation.observe_timeout(
        attempt, error, owned_tree_cleanup="CONFIRMED"
    )

    result = record["result"]
    assert result["outcome"] == "TIMEOUT"
    assert result["process_started"] == "YES"
    assert result["streams_complete"] == "NO"
    assert result["returncode"] is None
    assert result["owned_tree_cleanup"] == "CONFIRMED"
    assert result["stdout"]["completeness"] == "PARTIAL"
    assert result["stderr"]["availability"] == "UNOBSERVED"
    assert result["exception_type"] == "subprocess.TimeoutExpired"
    assert result["exception_phase"] == "EXECUTION"
    _assert_rechecks(record, attempt)


@pytest.mark.parametrize("cleanup", ["CONFIRMED", "NOT_CONFIRMED", "UNKNOWN"])
def test_timeout_keeps_timeout_identity_whatever_the_cleanup_state(
    tmp_path: Path, cleanup: str
) -> None:
    attempt = _attempt(tmp_path)
    record = _seal("timeout", attempt, owned_tree_cleanup=cleanup)

    assert record["result"]["outcome"] == "TIMEOUT"
    assert record["result"]["owned_tree_cleanup"] == cleanup
    assert record["result"]["returncode"] is None
    observation.validate_parent_process_observation(record)


def test_launch_error_is_distinct_from_started_process(tmp_path: Path) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_launch_error(attempt, FileNotFoundError("not retained"))

    result = record["result"]
    assert result["outcome"] == "LAUNCH_ERROR"
    assert result["process_started"] == "NO"
    assert result["streams_complete"] == "UNKNOWN"
    assert result["returncode"] is None
    assert result["owned_tree_cleanup"] == "NOT_STARTED"
    assert result["stdout"]["availability"] == "UNOBSERVED"
    assert result["exception_type"] == "builtins.FileNotFoundError"
    assert "not retained" not in repr(record)
    _assert_rechecks(record, attempt)


def test_post_processing_error_does_not_erase_that_process_started(tmp_path: Path) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_post_processing_error(
        attempt,
        returncode=0,
        stdout=b"completed output",
        stderr=b"",
        error=RuntimeError("not retained"),
        owned_tree_cleanup="CONFIRMED",
    )

    result = record["result"]
    assert result["outcome"] == "POST_PROCESSING_ERROR"
    assert result["process_started"] == "YES"
    assert result["streams_complete"] == "YES"
    assert result["returncode"] == 0
    assert result["owned_tree_cleanup"] == "CONFIRMED"
    assert result["stdout"]["byte_count"] == len(b"completed output")
    assert result["exception_phase"] == "POST_PROCESSING"
    _assert_rechecks(record, attempt)


def test_indeterminate_execution_error_does_not_invent_start_or_stream_facts(
    tmp_path: Path,
) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_indeterminate_execution_error(
        attempt, RuntimeError("state unavailable")
    )

    result = record["result"]
    assert result["outcome"] == "EXECUTION_ERROR"
    assert result["process_started"] == "UNKNOWN"
    assert result["streams_complete"] == "UNKNOWN"
    assert result["owned_tree_cleanup"] == "UNKNOWN"
    assert result["stdout"]["availability"] == "UNOBSERVED"
    _assert_rechecks(record, attempt)


def test_missing_declared_input_records_fail_closed_no_launch(tmp_path: Path) -> None:
    planned = observation.prepare_parent_process_observation(
        argv=["python", "worker.py"],
        declared_cwd="work/subject",
        resolved_cwd=tmp_path / "work" / "subject",
        timeout_seconds=30,
        stdout_retention_limit_bytes=8,
        stderr_retention_limit_bytes=8,
    )
    record = observation.observe_missing_input_no_launch(planned)

    assert record["launch"]["launch_attempted"] == "NO"
    assert record["result"]["outcome"] == "MISSING_INPUT"
    assert record["result"]["process_started"] == "NO"
    assert record["result"]["returncode"] is None
    assert record["result"]["streams_complete"] == "UNKNOWN"
    assert record["result"]["owned_tree_cleanup"] == "NOT_STARTED"
    assert record["result"]["stdout"]["availability"] == "UNOBSERVED"
    assert record["result"]["stderr"]["availability"] == "UNOBSERVED"
    assert record["result"]["exception_type"] is None
    assert record["result"]["exception_phase"] is None
    observation.validate_parent_process_observation(record)
    _assert_rechecks(record, planned)


def test_missing_input_no_launch_refuses_an_attempted_launch_binding(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError, match="PARENT_PROCESS_NO_LAUNCH_BINDING_INVALID"
    ):
        observation.observe_missing_input_no_launch(_attempt(tmp_path))


def test_output_cap_records_captured_prefix_as_partial_never_complete(
    tmp_path: Path,
) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_output_cap_exceeded(
        attempt,
        stdout=b"0123456789ABCDEF",
        stderr=b"",
        owned_tree_cleanup="CONFIRMED",
    )

    result = record["result"]
    assert result["outcome"] == "OUTPUT_CAP_EXCEEDED"
    assert result["process_started"] == "YES"
    assert result["returncode"] is None
    assert result["streams_complete"] == "NO"
    assert result["owned_tree_cleanup"] == "CONFIRMED"
    assert result["exception_type"] is None
    assert result["exception_phase"] is None
    stdout = result["stdout"]
    # byte_count counts only the captured prefix; the full stream length is unknown.
    assert stdout["byte_count"] == 16
    assert stdout["completeness"] == "PARTIAL"
    assert stdout["retention_truncated"] is True
    assert base64.b64decode(stdout["retained_base64"]) == b"01234567"
    assert result["stderr"]["completeness"] == "PARTIAL"
    observation.validate_parent_process_observation(record)
    _assert_rechecks(record, attempt)


@pytest.mark.parametrize("cleanup", ["NOT_CONFIRMED", "UNKNOWN"])
def test_cleanup_not_established_withholds_exit_status_and_stream_completeness(
    tmp_path: Path, cleanup: str
) -> None:
    attempt = _attempt(tmp_path)
    record = _seal("cleanup_not_established", attempt, owned_tree_cleanup=cleanup)

    result = record["result"]
    assert result["outcome"] == "CLEANUP_NOT_ESTABLISHED"
    assert result["process_started"] == "YES"
    assert result["returncode"] is None
    assert result["streams_complete"] == "UNKNOWN"
    assert result["owned_tree_cleanup"] == cleanup
    assert result["stdout"]["completeness"] == "PARTIAL"
    observation.validate_parent_process_observation(record)
    _assert_rechecks(record, attempt)


def test_exit_status_unknown_requires_confirmed_cleanup_and_complete_streams(
    tmp_path: Path,
) -> None:
    attempt = _attempt(tmp_path)
    record = _seal("exit_status_unknown", attempt, owned_tree_cleanup="CONFIRMED")

    result = record["result"]
    assert result["outcome"] == "EXIT_STATUS_UNKNOWN"
    assert result["process_started"] == "YES"
    assert result["returncode"] is None
    assert result["streams_complete"] == "YES"
    assert result["owned_tree_cleanup"] == "CONFIRMED"
    assert result["stdout"]["completeness"] == "COMPLETE"
    observation.validate_parent_process_observation(record)
    _assert_rechecks(record, attempt)


@pytest.mark.parametrize(
    ("kind", "cleanup"),
    [
        ("completed", "NOT_CONFIRMED"),
        ("completed", "UNKNOWN"),
        ("completed", "NOT_STARTED"),
        ("timeout", "NOT_STARTED"),
        ("output_cap", "NOT_STARTED"),
        ("output_cap", "YES"),
        ("output_cap", None),
        ("cleanup_not_established", "CONFIRMED"),
        ("cleanup_not_established", "NOT_STARTED"),
        ("exit_status_unknown", "UNKNOWN"),
        ("exit_status_unknown", "NOT_CONFIRMED"),
    ],
)
def test_producers_refuse_cleanup_states_outside_their_outcome(
    tmp_path: Path, kind: str, cleanup: object
) -> None:
    with pytest.raises(ValueError, match="PARENT_PROCESS_CLEANUP_STATE_INVALID"):
        _seal(kind, _attempt(tmp_path), owned_tree_cleanup=cleanup)


def test_producers_require_explicit_cleanup_evidence(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        observation.observe_completed_process(
            _attempt(tmp_path), returncode=0, stdout=b"", stderr=b""
        )


@pytest.mark.parametrize(
    "fault",
    [
        "argv",
        "declared_cwd",
        "resolved_cwd",
        "stdout",
        "stderr",
        "returncode",
        "streams_complete",
        "stream_completeness",
        "owned_tree_cleanup",
    ],
)
def test_bound_rechecker_rejects_resealed_tampering(
    tmp_path: Path, fault: str
) -> None:
    attempt = _attempt(tmp_path)
    original = observation.observe_completed_process(
        attempt,
        returncode=0,
        stdout=b"output",
        stderr=b"diagnostic",
        owned_tree_cleanup="CONFIRMED",
    )
    changed = deepcopy(original)
    changed.pop("inner_digest")

    if fault == "argv":
        changed["launch"]["argv"][-1] = "different"
    elif fault == "declared_cwd":
        changed["launch"]["declared_cwd"] = "other"
    elif fault == "resolved_cwd":
        changed["launch"]["resolved_cwd_sha256"] = "sha256:" + "f" * 64
    elif fault in {"stdout", "stderr"}:
        changed["result"][fault]["retained_base64"] = base64.b64encode(
            b"changed"
        ).decode("ascii")
    elif fault == "returncode":
        changed["result"]["returncode"] = 9
        changed["result"]["outcome"] = "NONZERO_EXIT"
    elif fault == "streams_complete":
        changed["result"]["streams_complete"] = "NO"
        changed["result"]["stdout"]["completeness"] = "PARTIAL"
        changed["result"]["stderr"]["completeness"] = "PARTIAL"
    elif fault == "owned_tree_cleanup":
        changed["result"]["owned_tree_cleanup"] = "NOT_CONFIRMED"
    else:
        changed["result"]["stdout"]["completeness"] = "PARTIAL"
    resealed = observation.seal_parent_process_observation(changed)

    with pytest.raises(
        observation.ProcessObservationError,
        match="PARENT_PROCESS_OBSERVATION_BOUND_DIGEST_DIFFERS",
    ):
        observation.recheck_parent_process_observation(
            resealed,
            bound_inner_digest=original["inner_digest"],
            expected_launch=attempt,
        )


def test_standalone_validator_rejects_semantically_inconsistent_resealed_record(
    tmp_path: Path,
) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_completed_process(
        attempt,
        returncode=0,
        stdout=b"",
        stderr=b"",
        owned_tree_cleanup="CONFIRMED",
    )
    changed = deepcopy(record)
    changed.pop("inner_digest")
    changed["result"]["returncode"] = 3
    resealed = observation.seal_parent_process_observation(changed)

    with pytest.raises(
        observation.ProcessObservationError,
        match="PARENT_PROCESS_OBSERVATION_RESULT_INVALID",
    ):
        observation.validate_parent_process_observation(resealed)


@pytest.mark.parametrize(
    "fault",
    ["digest", "schema", "launch_state", "result_state", "boundary", "unobserved"],
)
def test_standalone_validator_enforces_digest_schema_enums_and_boundaries(
    tmp_path: Path, fault: str
) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_completed_process(
        attempt,
        returncode=0,
        stdout=b"",
        stderr=b"",
        owned_tree_cleanup="CONFIRMED",
    )
    changed = deepcopy(record)
    changed.pop("inner_digest")
    if fault == "schema":
        changed["schema_version"] = "different"
    elif fault == "launch_state":
        changed["launch"]["launch_attempted"] = "MAYBE"
    elif fault == "result_state":
        changed["result"]["process_started"] = "MAYBE"
    elif fault == "boundary":
        changed["claim_boundary"] = "broader"
    elif fault == "unobserved":
        changed["unobserved"].remove("network")
    resealed = observation.seal_parent_process_observation(changed)
    if fault == "digest":
        resealed["result"]["returncode"] = 4

    with pytest.raises(observation.ProcessObservationError):
        observation.validate_parent_process_observation(resealed)


def test_standalone_validator_accepts_every_supported_result_state(
    tmp_path: Path,
) -> None:
    attempted = _attempt(tmp_path)
    planned = observation.prepare_parent_process_observation(
        argv=attempted.argv,
        declared_cwd=attempted.declared_cwd,
        resolved_cwd=tmp_path / "work" / "subject",
        timeout_seconds=attempted.timeout_seconds,
        stdout_retention_limit_bytes=8,
        stderr_retention_limit_bytes=8,
    )
    records = [
        observation.observe_completed_process(
            attempted, returncode=0, stdout=b"", stderr=b"", owned_tree_cleanup="CONFIRMED"
        ),
        observation.observe_completed_process(
            attempted, returncode=2, stdout=b"", stderr=b"", owned_tree_cleanup="CONFIRMED"
        ),
        observation.observe_timeout(
            attempted,
            subprocess.TimeoutExpired(attempted.argv, attempted.timeout_seconds),
            owned_tree_cleanup="NOT_CONFIRMED",
        ),
        observation.observe_output_cap_exceeded(
            attempted, stdout=b"x", stderr=b"", owned_tree_cleanup="UNKNOWN"
        ),
        observation.observe_cleanup_not_established(
            attempted, stdout=b"", stderr=b"", owned_tree_cleanup="NOT_CONFIRMED"
        ),
        observation.observe_exit_status_unknown(
            attempted, stdout=b"", stderr=b"", owned_tree_cleanup="CONFIRMED"
        ),
        observation.observe_launch_error(attempted, FileNotFoundError()),
        observation.observe_post_processing_error(
            attempted,
            returncode=0,
            stdout=b"",
            stderr=b"",
            error=RuntimeError(),
            owned_tree_cleanup="CONFIRMED",
        ),
        observation.observe_indeterminate_execution_error(attempted, RuntimeError()),
        observation.observe_missing_input_no_launch(planned),
    ]

    for record in records:
        observation.validate_parent_process_observation(record)


def _base_record(kind: str, tmp_path: Path) -> dict:
    """Sealed valid record that each forgery case perturbs."""

    if kind == "completed":
        return _seal("completed", _attempt(tmp_path), owned_tree_cleanup="CONFIRMED")
    if kind == "output_cap":
        attempt = _attempt(tmp_path)
        return observation.observe_output_cap_exceeded(
            attempt, stdout=b"0123456789", stderr=b"", owned_tree_cleanup="CONFIRMED"
        )
    if kind == "cleanup_not_established":
        return _seal(
            "cleanup_not_established", _attempt(tmp_path), owned_tree_cleanup="UNKNOWN"
        )
    if kind == "exit_status_unknown":
        return _seal("exit_status_unknown", _attempt(tmp_path), owned_tree_cleanup="CONFIRMED")
    if kind == "timeout":
        return _seal("timeout", _attempt(tmp_path), owned_tree_cleanup="CONFIRMED")
    if kind == "launch_error":
        return observation.observe_launch_error(_attempt(tmp_path), FileNotFoundError())
    raise AssertionError(kind)


def _set(*path: object):
    """Return a mutation that assigns the last path element under the given keys."""

    *keys, leaf = path

    def mutate(record: dict, value: object = None) -> None:
        node = record
        for key in keys:
            node = node[key]
        node[leaf] = value

    return mutate


FORGERIES = [
    # Cleanup evidence that does not confirm an exit must never yield a clean completion.
    ("success-cleanup-not-confirmed", "completed", lambda r: _set("result", "owned_tree_cleanup")(r, "NOT_CONFIRMED")),
    ("success-cleanup-unknown", "completed", lambda r: _set("result", "owned_tree_cleanup")(r, "UNKNOWN")),
    ("success-cleanup-absent", "completed", lambda r: r["result"].pop("owned_tree_cleanup")),
    ("success-cleanup-legacy-token", "completed", lambda r: _set("result", "owned_tree_cleanup")(r, "YES")),
    ("success-cleanup-null", "completed", lambda r: _set("result", "owned_tree_cleanup")(r, None)),
    ("success-relabelled-as-output-cap", "completed", lambda r: _set("result", "outcome")(r, "OUTPUT_CAP_EXCEEDED")),
    ("success-relabelled-as-exit-unknown", "completed", lambda r: _set("result", "outcome")(r, "EXIT_STATUS_UNKNOWN")),
    ("success-with-v1-schema", "completed", lambda r: _set("schema_version")(r, "verifier-parent-process-observation-1")),
    # Output-cap accounting: a capped stream is a prefix, never a complete stream.
    ("cap-claims-complete-stream", "output_cap", lambda r: _set("result", "stdout", "completeness")(r, "COMPLETE")),
    ("cap-claims-streams-complete", "output_cap", lambda r: _set("result", "streams_complete")(r, "YES")),
    ("cap-carries-exit-status", "output_cap", lambda r: _set("result", "returncode")(r, 0)),
    ("cap-hides-truncation", "output_cap", lambda r: _set("result", "stdout", "retention_truncated")(r, False)),
    ("cap-relabelled-as-timeout", "output_cap", lambda r: _set("result", "outcome")(r, "TIMEOUT")),
    ("cap-cleanup-absent", "output_cap", lambda r: r["result"].pop("owned_tree_cleanup")),
    # Uncertain cleanup must never be recorded as confirmed or as a complete exit.
    ("uncertain-cleanup-marked-confirmed", "cleanup_not_established", lambda r: _set("result", "owned_tree_cleanup")(r, "CONFIRMED")),
    ("uncertain-cleanup-reports-exit-zero", "cleanup_not_established", lambda r: _set("result", "returncode")(r, 0)),
    ("uncertain-cleanup-claims-complete-streams", "cleanup_not_established", lambda r: _set("result", "streams_complete")(r, "YES")),
    ("uncertain-cleanup-relabelled-as-success", "cleanup_not_established", lambda r: _set("result", "outcome")(r, "SUCCESS")),
    ("exit-unknown-with-unknown-cleanup", "exit_status_unknown", lambda r: _set("result", "owned_tree_cleanup")(r, "UNKNOWN")),
    ("exit-unknown-with-exit-status", "exit_status_unknown", lambda r: _set("result", "returncode")(r, 3)),
    ("timeout-with-exit-status", "timeout", lambda r: _set("result", "returncode")(r, 0)),
    ("timeout-claims-complete-streams", "timeout", lambda r: _set("result", "streams_complete")(r, "YES")),
    ("launch-error-claims-confirmed-cleanup", "launch_error", lambda r: _set("result", "owned_tree_cleanup")(r, "CONFIRMED")),
    ("launch-error-claims-started", "launch_error", lambda r: _set("result", "process_started")(r, "YES")),
]


@pytest.mark.parametrize(("name", "base", "mutate"), FORGERIES, ids=[f[0] for f in FORGERIES])
def test_resealed_forgery_is_rejected_by_standalone_validator(
    tmp_path: Path, name: str, base: str, mutate
) -> None:
    record = _base_record(base, tmp_path)
    observation.validate_parent_process_observation(record)
    changed = deepcopy(record)
    changed.pop("inner_digest")
    mutate(changed)
    resealed = observation.seal_parent_process_observation(changed)

    with pytest.raises(observation.ProcessObservationError):
        observation.validate_parent_process_observation(resealed)


def test_boundary_explicitly_leaves_external_surfaces_unobserved(tmp_path: Path) -> None:
    attempt = _attempt(tmp_path)
    record = observation.observe_completed_process(
        attempt, returncode=0, stdout=b"", stderr=b"", owned_tree_cleanup="CONFIRMED"
    )

    assert record["unobserved"] == [
        "inherited-environment",
        "inherited-stdin",
        "pid-and-process-tree",
        "descendants",
        "network",
        "undeclared-filesystem",
        "external-effects",
    ]
    assert "not a whole HARNESS" in record["claim_boundary"]
    assert record["schema_version"] == "verifier-parent-process-observation-2"


@pytest.mark.parametrize("declared_cwd", ["", "contains\x00nul"])
def test_declared_cwd_rejects_unrepresentable_text(
    tmp_path: Path, declared_cwd: str
) -> None:
    with pytest.raises(ValueError, match="PARENT_PROCESS_DECLARED_CWD_INVALID"):
        _attempt(tmp_path, declared_cwd=declared_cwd)


@pytest.mark.parametrize(
    ("declared_cwd", "portability"),
    [
        ("/host/path", "NONPORTABLE"),
        ("C" + ":/host/path", "NONPORTABLE"),
        ("../outside", "NONPORTABLE"),
        ("work\\subject", "NONPORTABLE"),
        ("work/subject", "PORTABLE_RELATIVE"),
    ],
    ids=["absolute", "drive-qualified", "parent-segment", "backslash", "portable"],
)
def test_declared_cwd_portability_is_classified_without_changing_run_semantics(
    tmp_path: Path, declared_cwd: str, portability: str
) -> None:
    attempt = _attempt(tmp_path, declared_cwd=declared_cwd)
    assert attempt.declared_cwd == declared_cwd
    assert attempt.declared_cwd_portability == portability
