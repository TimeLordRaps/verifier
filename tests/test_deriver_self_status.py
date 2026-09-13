"""Adversarial checks for an identifier (ID)-bound actual deriver session."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import verifier.interoperability.deriver_self_status as deriver_module
from verifier.interoperability.deriver_self_status import (
    DeriverSelfStatus,
    DeriverSessionDeclaration,
    InvocationState,
    RUNNER_ID,
    record_deriver_session,
    recheck_deriver_self_status,
    runtime_coordinate_for,
)
from verifier.interoperability.network import canonical_bytes, digest_bytes


_PROGRAM = (
    "import hashlib,json,sys; "
    "data=sys.stdin.buffer.read(); "
    "sys.stdout.write(json.dumps({'input_sha256':hashlib.sha256(data).hexdigest(),"
    "'status':'DERIVED'},sort_keys=True,separators=(',',':'))+'\\n')"
)


def _environment() -> tuple[tuple[str, str], ...]:
    names = ("SYSTEMROOT",) if os.name == "nt" and "SYSTEMROOT" in os.environ else ()
    return tuple((name, os.environ[name]) for name in names)


def _fixture(*, timeout_ms: int = 10_000, max_output_bytes: int = 4_096,
             program: str = _PROGRAM, expected_stdout: bytes | None = None,
             runner_id: str = RUNNER_ID, system: str | None = None) -> tuple[Path, DeriverSessionDeclaration]:
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    stdin = b"exact subject bytes"
    output = expected_stdout
    if output is None:
        output = (
            json.dumps(
                {"input_sha256": __import__("hashlib").sha256(stdin).hexdigest(), "status": "DERIVED"},
                sort_keys=True,
                separators=(",", ":"),
            )
            + os.linesep
        ).encode()
    coordinate = runtime_coordinate_for(executable)
    coordinate = replace(
        coordinate,
        runner_id=runner_id,
        system=coordinate.system if system is None else system,
    )
    return executable, DeriverSessionDeclaration(
        deriver_id="test.deriver.actual-session.0.1",
        subject_digest=digest_bytes(b"subject identity"),
        runtime_coordinate=coordinate,
        arguments=("-I", "-c", program),
        public_environment=_environment(),
        stdin_bytes=stdin,
        stdin_digest=digest_bytes(stdin),
        expected_stdout_digest=digest_bytes(output),
        expected_stderr_digest=digest_bytes(b""),
        expected_exit_code=0,
        timeout_ms=timeout_ms,
        max_output_bytes=max_output_bytes,
    )


def test_exact_actual_session_is_independently_reproduced() -> None:
    executable, declaration = _fixture()
    declaration_bytes = declaration.to_bytes()
    receipt = record_deriver_session(declaration_bytes, executable)
    assessment = recheck_deriver_self_status(
        declaration_bytes, receipt.to_bytes(), executable,
    )
    assert receipt.invocation_state is InvocationState.COMPLETED
    assert assessment.status is DeriverSelfStatus.ESTABLISHED
    assert assessment.declaration_digest == declaration.canonical_digest
    assert assessment.receipt_digest == receipt.canonical_digest
    assert assessment.reason_codes == ("EXACT_SESSION_REPRODUCED",)
    assert "structural self_derivability" in assessment.claim_boundary


def test_rechecker_does_not_reuse_recorder_execution_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, declaration = _fixture()
    declaration_bytes = declaration.to_bytes()
    receipt = record_deriver_session(declaration_bytes, executable)

    def fail_if_reused(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("recorder execution path was reused")

    monkeypatch.setattr(deriver_module, "_execute", fail_if_reused)
    assessment = recheck_deriver_self_status(
        declaration_bytes, receipt.to_bytes(), executable,
    )
    assert assessment.status is DeriverSelfStatus.ESTABLISHED


def test_absent_invocation_remains_unknown() -> None:
    executable, declaration = _fixture()
    assessment = recheck_deriver_self_status(declaration.to_bytes(), None, executable)
    assert assessment.status is DeriverSelfStatus.UNKNOWN
    assert assessment.reason_codes == ("INVOCATION_NOT_OBSERVED",)


def test_wrong_executable_bytes_are_invalid(tmp_path: Path) -> None:
    executable, declaration = _fixture()
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    substituted = tmp_path / "not-the-executable.bin"
    substituted.write_bytes(b"different executable bytes")
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), receipt.to_bytes(), substituted,
    )
    assert assessment.status is DeriverSelfStatus.INVALID
    assert assessment.reason_codes == ("EXECUTABLE_COORDINATE_INVALID",)


def test_unavailable_executable_remains_unknown(tmp_path: Path) -> None:
    executable, declaration = _fixture()
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    missing = tmp_path / "missing-executable"
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), receipt.to_bytes(), missing,
    )
    assert assessment.status is DeriverSelfStatus.UNKNOWN
    assert assessment.reason_codes == ("EXECUTABLE_UNAVAILABLE_OR_LIMITED",)


def test_substituted_retained_output_is_invalid() -> None:
    executable, declaration = _fixture()
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    wire = json.loads(receipt.to_bytes())
    substituted = b'{"status":"SUBSTITUTED"}\n'
    wire["stdout_base64url"] = __import__("base64").urlsafe_b64encode(substituted).rstrip(b"=").decode()
    wire["stdout_digest"] = digest_bytes(substituted)
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), canonical_bytes(wire), executable,
    )
    assert assessment.status is DeriverSelfStatus.INVALID
    assert assessment.reason_codes == ("RECHECK_TRANSCRIPT_MISMATCH",)


def test_receipt_state_and_reason_mismatch_is_invalid() -> None:
    executable, declaration = _fixture()
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    wire = json.loads(receipt.to_bytes())
    wire["reason_codes"] = ["RUNNER_UNSUPPORTED"]
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), canonical_bytes(wire), executable,
    )
    assert assessment.status is DeriverSelfStatus.INVALID
    assert assessment.reason_codes == ("RECEIPT_INVALID",)


@pytest.mark.parametrize(
    ("runner_id", "system", "reason"),
    [
        ("unsupported.runner.9", None, "RUNNER_UNSUPPORTED"),
        (RUNNER_ID, "UnsupportedOS", "PLATFORM_UNSUPPORTED"),
    ],
)
def test_unsupported_runner_or_platform_remains_unknown(
    runner_id: str, system: str | None, reason: str,
) -> None:
    executable, declaration = _fixture(runner_id=runner_id, system=system)
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), receipt.to_bytes(), executable,
    )
    assert receipt.invocation_state is InvocationState.NOT_RUN
    assert assessment.status is DeriverSelfStatus.UNKNOWN
    assert assessment.reason_codes == (reason,)


@pytest.mark.parametrize(
    ("program", "timeout_ms", "max_output_bytes", "state", "reason"),
    [
        (
            "import time; time.sleep(0.25)",
            25,
            4_096,
            InvocationState.TIMED_OUT,
            "TIME_BOUND_EXHAUSTED",
        ),
        (
            "import sys; sys.stdout.write('x'*8192)",
            2_000,
            128,
            InvocationState.OUTPUT_LIMIT_EXCEEDED,
            "OUTPUT_BOUND_EXHAUSTED",
        ),
    ],
)
def test_exhausted_execution_bound_remains_unknown(
    program: str,
    timeout_ms: int,
    max_output_bytes: int,
    state: InvocationState,
    reason: str,
) -> None:
    executable, declaration = _fixture(
        program=program,
        timeout_ms=timeout_ms,
        max_output_bytes=max_output_bytes,
        expected_stdout=b"irrelevant",
    )
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), receipt.to_bytes(), executable,
    )
    assert receipt.invocation_state is state
    assert assessment.status is DeriverSelfStatus.UNKNOWN
    assert assessment.reason_codes == (reason,)


def test_malformed_declaration_and_receipt_are_invalid() -> None:
    executable, declaration = _fixture()
    invalid_declaration = recheck_deriver_self_status(b"{}", None, executable)
    invalid_receipt = recheck_deriver_self_status(declaration.to_bytes(), b"{}", executable)
    assert invalid_declaration.status is DeriverSelfStatus.INVALID
    assert invalid_declaration.reason_codes == ("DECLARATION_INVALID",)
    assert invalid_receipt.status is DeriverSelfStatus.INVALID
    assert invalid_receipt.reason_codes == ("RECEIPT_INVALID",)


def test_reproducible_declared_output_mismatch_is_refuted() -> None:
    executable, declaration = _fixture(expected_stdout=b"not the actual output")
    receipt = record_deriver_session(declaration.to_bytes(), executable)
    assessment = recheck_deriver_self_status(
        declaration.to_bytes(), receipt.to_bytes(), executable,
    )
    assert receipt.invocation_state is InvocationState.COMPLETED
    assert assessment.status is DeriverSelfStatus.REFUTED
    assert assessment.reason_codes == ("DECLARED_OUTPUT_REFUTED",)
