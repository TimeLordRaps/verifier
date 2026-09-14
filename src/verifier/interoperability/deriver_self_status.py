"""Experimental actual deriver self-status for Verifier Standard (VSTD).

The ``VSTD-DERIVER-SELF-STATUS-0.1`` sidecar records one bounded process
invocation and independently reruns it before establishing its exact declared
output. Secure Hash Algorithm 256-bit (SHA-256) binds retained bytes and
canonical JavaScript Object Notation (JSON) records; it does not prove their
meaning. Text bounds use Unicode Transformation Format, 8-bit (UTF-8), records
use an explicit identifier (ID), and environment names use American Standard
Code for Information Interchange (ASCII). This sidecar discharges no numbered
VSTD-4 rung and never upgrades or relabels the retained structural
``self_derivability`` axis.

The runner supplies a fresh empty working directory and only the explicitly
declared public, non-secret environment. Confidential environment values are
unsupported because the canonical declaration retains values in clear text.
The runner bounds elapsed time and combined captured output, but it is not a
sandbox and does not bound processor or memory consumption.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import re
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .network import NetworkError, canonical_bytes, digest_bytes


DECLARATION_SCHEMA = "VSTD-DERIVER-SELF-STATUS-0.1"
RECEIPT_SCHEMA = "VSTD-DERIVER-SELF-STATUS-RECEIPT-0.1"
CHECKER_SCHEMA = "VSTD-DERIVER-SELF-STATUS-CHECKER-0.1"
RUNNER_ID = "vstd.bounded-subprocess.0.1"
MAX_DECLARATION_BYTES = 131_072
MAX_RECEIPT_BYTES = 2_228_224
MAX_EXECUTABLE_BYTES = 67_108_864
MAX_INPUT_BYTES = 65_536
MAX_OUTPUT_BYTES = 1_048_576
MAX_TIMEOUT_MS = 60_000
MAX_ARGUMENTS = 64
MAX_ENVIRONMENT_ENTRIES = 32
MAX_TEXT_BYTES = 4_096
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ENVIRONMENT_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_SUPPORTED_SYSTEMS = frozenset({"Darwin", "Linux", "Windows"})
_NOT_RUN_REASONS = frozenset({
    "EXECUTABLE_COORDINATE_INVALID",
    "EXECUTABLE_UNAVAILABLE_OR_LIMITED",
    "INVOCATION_NOT_OBSERVED",
    "PLATFORM_UNSUPPORTED",
    "RUNNER_UNSUPPORTED",
    "RUNTIME_COORDINATE_UNAVAILABLE",
})

CLAIM_BOUNDARY = (
    "ESTABLISHED means that exact executable bytes, at one declared runtime "
    "coordinate, produced the declared exit, standard-output, and standard-error "
    "bytes in two bounded invocations with exact arguments, public non-secret "
    "environment, and input. Confidential environments are unsupported. "
    "It does not establish structural self_derivability, source semantics, global "
    "behavior, completeness, safety, authorization, sandboxing, or another runtime."
)


class DeriverSelfStatus(str, Enum):
    """Result of checking the bounded actual-session proposition."""

    ESTABLISHED = "ESTABLISHED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


class InvocationState(str, Enum):
    """Observed disposition of one attempted invocation."""

    COMPLETED = "COMPLETED"
    NOT_RUN = "NOT_RUN"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    START_FAILED = "START_FAILED"
    CAPTURE_FAILED = "CAPTURE_FAILED"


class DeriverSelfStatusError(ValueError):
    """A bounded declaration or receipt is malformed."""


def _text(value: Any, field: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum
    ):
        raise DeriverSelfStatusError(
            f"{field} must be nonempty text of at most {maximum} UTF-8 bytes"
        )
    return value


def _digest(value: Any, field: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise DeriverSelfStatusError(f"{field} must be an exact lowercase SHA-256 digest")
    return value


def _integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeriverSelfStatusError(
            f"{field} must be an integer from {minimum} through {maximum}"
        )
    return value


def _strict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise DeriverSelfStatusError(f"{label} must contain exactly its defined fields")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeriverSelfStatusError("canonical JSON objects cannot repeat keys")
        result[key] = value
    return result


def _decode(data: bytes, maximum: int, label: str) -> dict[str, Any]:
    if type(data) is not bytes or len(data) > maximum:
        raise DeriverSelfStatusError(f"{label} must be immutable bytes within its bound")
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                raise DeriverSelfStatusError(f"{label} exceeds its nesting bound")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise DeriverSelfStatusError(f"{label} has invalid JSON nesting")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        if depth != 0 or quoted or type(value) is not dict or canonical_bytes(value) != data:
            raise DeriverSelfStatusError(f"{label} must be one canonical JSON object")
        return value
    except (UnicodeError, json.JSONDecodeError, NetworkError, RecursionError) as error:
        raise DeriverSelfStatusError(f"{label} is not bounded canonical JSON") from error


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_bytes(value: Any, field: str, maximum: int) -> bytes:
    if type(value) is not str or len(value) > ((maximum + 2) // 3) * 4:
        raise DeriverSelfStatusError(f"{field} exceeds its encoded byte bound")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True,
        )
    except (ValueError, TypeError) as error:
        raise DeriverSelfStatusError(f"{field} must be canonical base64url") from error
    if len(raw) > maximum or _encode_bytes(raw) != value:
        raise DeriverSelfStatusError(f"{field} must be canonical base64url within its bound")
    return raw


def _read_executable(path: str | Path) -> bytes:
    try:
        source = Path(path).resolve(strict=True)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise DeriverSelfStatusError("executable must resolve to an ordinary file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(source, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev,
                opened.st_ino,
            ) != (before.st_dev, before.st_ino):
                raise DeriverSelfStatusError("executable changed during open")
            data = stream.read(MAX_EXECUTABLE_BYTES + 1)
    except (OSError, RuntimeError) as error:
        raise DeriverSelfStatusError("executable is unavailable") from error
    if len(data) > MAX_EXECUTABLE_BYTES:
        raise DeriverSelfStatusError("executable exceeds its byte bound")
    return data


@dataclass(frozen=True)
class RuntimeCoordinate:
    """Exact supported runtime and executable identity for one sidecar."""

    runner_id: str
    system: str
    release: str
    machine: str
    os_name: str
    executable_digest: str
    executable_size_bytes: int

    def __post_init__(self) -> None:
        _text(self.runner_id, "runner_id", maximum=128)
        _text(self.system, "system", maximum=128)
        _text(self.release, "release", maximum=256)
        _text(self.machine, "machine", maximum=128)
        _text(self.os_name, "os_name", maximum=32)
        _digest(self.executable_digest, "executable_digest")
        _integer(
            self.executable_size_bytes,
            "executable_size_bytes",
            minimum=1,
            maximum=MAX_EXECUTABLE_BYTES,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable_digest": self.executable_digest,
            "executable_size_bytes": self.executable_size_bytes,
            "machine": self.machine,
            "os_name": self.os_name,
            "release": self.release,
            "runner_id": self.runner_id,
            "system": self.system,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "RuntimeCoordinate":
        value = _strict(
            value,
            {
                "executable_digest",
                "executable_size_bytes",
                "machine",
                "os_name",
                "release",
                "runner_id",
                "system",
            },
            "runtime_coordinate",
        )
        result = cls(
            runner_id=value["runner_id"],
            system=value["system"],
            release=value["release"],
            machine=value["machine"],
            os_name=value["os_name"],
            executable_digest=value["executable_digest"],
            executable_size_bytes=value["executable_size_bytes"],
        )
        if result.to_dict() != value:
            raise DeriverSelfStatusError("runtime_coordinate is not canonical")
        return result


def runtime_coordinate_for(executable_path: str | Path) -> RuntimeCoordinate:
    """Bind the current runtime and resolved executable bytes."""

    executable = _read_executable(executable_path)
    return RuntimeCoordinate(
        runner_id=RUNNER_ID,
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        os_name=os.name,
        executable_digest=digest_bytes(executable),
        executable_size_bytes=len(executable),
    )


@dataclass(frozen=True)
class DeriverSessionDeclaration:
    """Exact proposition and bounded invocation input to reproduce."""

    deriver_id: str
    subject_digest: str
    runtime_coordinate: RuntimeCoordinate
    arguments: tuple[str, ...]
    public_environment: tuple[tuple[str, str], ...]
    stdin_bytes: bytes
    stdin_digest: str
    expected_stdout_digest: str
    expected_stderr_digest: str
    expected_exit_code: int
    timeout_ms: int
    max_output_bytes: int
    schema_version: str = DECLARATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != DECLARATION_SCHEMA:
            raise DeriverSelfStatusError("unsupported declaration schema_version")
        _text(self.deriver_id, "deriver_id", maximum=256)
        _digest(self.subject_digest, "subject_digest")
        if not isinstance(self.runtime_coordinate, RuntimeCoordinate):
            raise DeriverSelfStatusError("runtime_coordinate must be explicit")
        if type(self.arguments) is not tuple or len(self.arguments) > MAX_ARGUMENTS:
            raise DeriverSelfStatusError("arguments exceed their count bound")
        for argument in self.arguments:
            _text(argument, "argument")
        if (
            type(self.public_environment) is not tuple
            or len(self.public_environment) > MAX_ENVIRONMENT_ENTRIES
        ):
            raise DeriverSelfStatusError("public_environment exceeds its entry bound")
        names: list[str] = []
        for entry in self.public_environment:
            if type(entry) is not tuple or len(entry) != 2:
                raise DeriverSelfStatusError("public_environment entries must be name/value pairs")
            name, value = entry
            if type(name) is not str or _ENVIRONMENT_NAME.fullmatch(name) is None:
                raise DeriverSelfStatusError("environment names must be uppercase ASCII identifiers")
            if type(value) is not str or "\x00" in value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
                raise DeriverSelfStatusError("environment values exceed their text bound")
            names.append(name)
        if names != sorted(set(names)):
            raise DeriverSelfStatusError("environment entries must be unique and sorted by name")
        if type(self.stdin_bytes) is not bytes or len(self.stdin_bytes) > MAX_INPUT_BYTES:
            raise DeriverSelfStatusError("stdin_bytes must be immutable bytes within its bound")
        _digest(self.stdin_digest, "stdin_digest")
        if digest_bytes(self.stdin_bytes) != self.stdin_digest:
            raise DeriverSelfStatusError("stdin_digest does not bind stdin_bytes")
        _digest(self.expected_stdout_digest, "expected_stdout_digest")
        _digest(self.expected_stderr_digest, "expected_stderr_digest")
        _integer(self.expected_exit_code, "expected_exit_code", minimum=0, maximum=255)
        _integer(self.timeout_ms, "timeout_ms", minimum=1, maximum=MAX_TIMEOUT_MS)
        _integer(self.max_output_bytes, "max_output_bytes", minimum=1, maximum=MAX_OUTPUT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return {
            "arguments": list(self.arguments),
            "deriver_id": self.deriver_id,
            "public_environment": [
                {"name": name, "value": value} for name, value in self.public_environment
            ],
            "expected_exit_code": self.expected_exit_code,
            "expected_stderr_digest": self.expected_stderr_digest,
            "expected_stdout_digest": self.expected_stdout_digest,
            "max_output_bytes": self.max_output_bytes,
            "runtime_coordinate": self.runtime_coordinate.to_dict(),
            "schema_version": self.schema_version,
            "stdin_base64url": _encode_bytes(self.stdin_bytes),
            "stdin_digest": self.stdin_digest,
            "subject_digest": self.subject_digest,
            "timeout_ms": self.timeout_ms,
        }

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    @property
    def canonical_digest(self) -> str:
        return digest_bytes(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeriverSessionDeclaration":
        value = _strict(
            _decode(data, MAX_DECLARATION_BYTES, "declaration"),
            {
                "arguments",
                "deriver_id",
                "public_environment",
                "expected_exit_code",
                "expected_stderr_digest",
                "expected_stdout_digest",
                "max_output_bytes",
                "runtime_coordinate",
                "schema_version",
                "stdin_base64url",
                "stdin_digest",
                "subject_digest",
                "timeout_ms",
            },
            "declaration",
        )
        arguments = value["arguments"]
        environment = value["public_environment"]
        if type(arguments) is not list or type(environment) is not list:
            raise DeriverSelfStatusError("arguments and public_environment must be arrays")
        pairs: list[tuple[str, str]] = []
        for entry in environment:
            entry = _strict(entry, {"name", "value"}, "environment entry")
            pairs.append((entry["name"], entry["value"]))
        result = cls(
            deriver_id=value["deriver_id"],
            subject_digest=value["subject_digest"],
            runtime_coordinate=RuntimeCoordinate.from_dict(value["runtime_coordinate"]),
            arguments=tuple(arguments),
            public_environment=tuple(pairs),
            stdin_bytes=_decode_bytes(value["stdin_base64url"], "stdin_base64url", MAX_INPUT_BYTES),
            stdin_digest=value["stdin_digest"],
            expected_stdout_digest=value["expected_stdout_digest"],
            expected_stderr_digest=value["expected_stderr_digest"],
            expected_exit_code=value["expected_exit_code"],
            timeout_ms=value["timeout_ms"],
            max_output_bytes=value["max_output_bytes"],
            schema_version=value["schema_version"],
        )
        if result.to_bytes() != data:
            raise DeriverSelfStatusError("declaration is not canonical")
        return result


@dataclass(frozen=True)
class _Execution:
    state: InvocationState
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    termination_signal: int | None
    elapsed_ms: int


def _execute(executable_path: str | Path, declaration: DeriverSessionDeclaration) -> _Execution:
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    lock = threading.Lock()
    limit_exceeded = threading.Event()
    capture_failed = threading.Event()
    started = time.monotonic_ns()
    process: subprocess.Popen[bytes] | None = None

    with tempfile.TemporaryDirectory(prefix="vstd-deriver-") as working_directory:
        try:
            process = subprocess.Popen(
                [str(Path(executable_path).resolve(strict=True)), *declaration.arguments],
                cwd=working_directory,
                env=dict(declaration.public_environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
            )
        except (OSError, RuntimeError):
            return _Execution(
                InvocationState.START_FAILED,
                b"",
                b"",
                None,
                None,
                max(0, (time.monotonic_ns() - started) // 1_000_000),
            )

        def read_stream(stream: Any, target: bytearray) -> None:
            nonlocal total
            try:
                while True:
                    chunk = stream.read(4_096)
                    if not chunk:
                        return
                    with lock:
                        remaining = declaration.max_output_bytes - total
                        if len(chunk) > remaining:
                            target.extend(chunk[:max(0, remaining)])
                            total += max(0, remaining)
                            limit_exceeded.set()
                            return
                        target.extend(chunk)
                        total += len(chunk)
            except (OSError, ValueError):
                capture_failed.set()
                return

        def write_input() -> None:
            if process is None or process.stdin is None:
                return
            try:
                process.stdin.write(declaration.stdin_bytes)
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            finally:
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass

        readers = [
            threading.Thread(target=read_stream, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=read_stream, args=(process.stderr, stderr), daemon=True),
        ]
        writer = threading.Thread(target=write_input, daemon=True)
        for thread in readers:
            thread.start()
        writer.start()

        deadline = started + declaration.timeout_ms * 1_000_000
        state = InvocationState.COMPLETED
        observed_stop = started
        while True:
            if limit_exceeded.is_set():
                state = InvocationState.OUTPUT_LIMIT_EXCEEDED
                process.kill()
                observed_stop = time.monotonic_ns()
                break
            now = time.monotonic_ns()
            if process.poll() is not None:
                observed_stop = now
                if now >= deadline:
                    state = InvocationState.TIMED_OUT
                break
            if now >= deadline:
                state = InvocationState.TIMED_OUT
                process.kill()
                observed_stop = now
                break
            time.sleep(0.002)
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)
        writer.join(timeout=1.0)
        for thread in readers:
            thread.join(timeout=1.0)
        if limit_exceeded.is_set():
            state = InvocationState.OUTPUT_LIMIT_EXCEEDED
        elif capture_failed.is_set() or any(thread.is_alive() for thread in readers):
            state = InvocationState.CAPTURE_FAILED

    return_code = process.returncode
    return _Execution(
        state=state,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        exit_code=return_code if return_code is not None and return_code >= 0 else None,
        termination_signal=-return_code if return_code is not None and return_code < 0 else None,
        elapsed_ms=max(0, (observed_stop - started) // 1_000_000),
    )


def _recheck_execute(
    executable_path: str | Path, declaration: DeriverSessionDeclaration,
) -> _Execution:
    """Reproduce a session without calling the recorder execution path."""

    # Deliberate isolation: recorder and rechecker must not agree only because
    # one producer helper returned the same fabricated transcript twice.
    captured = (bytearray(), bytearray())
    captured_size = 0
    captured_lock = threading.Lock()
    limit_hit = threading.Event()
    capture_error = threading.Event()
    started = time.monotonic_ns()

    with tempfile.TemporaryDirectory(prefix="vstd-recheck-") as working_directory:
        try:
            child = subprocess.Popen(
                [str(Path(executable_path).resolve(strict=True)), *declaration.arguments],
                cwd=working_directory,
                env={name: value for name, value in declaration.public_environment},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
            )
        except (OSError, RuntimeError):
            return _Execution(
                InvocationState.START_FAILED,
                b"",
                b"",
                None,
                None,
                max(0, (time.monotonic_ns() - started) // 1_000_000),
            )

        def collect(index: int, stream: Any) -> None:
            nonlocal captured_size
            try:
                while True:
                    block = stream.read(2_048)
                    if not block:
                        return
                    with captured_lock:
                        available = declaration.max_output_bytes - captured_size
                        if len(block) > available:
                            captured[index].extend(block[:max(0, available)])
                            captured_size += max(0, available)
                            limit_hit.set()
                            return
                        captured[index].extend(block)
                        captured_size += len(block)
            except (OSError, ValueError):
                capture_error.set()

        def supply_input() -> None:
            if child.stdin is None:
                return
            try:
                child.stdin.write(declaration.stdin_bytes)
                child.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            finally:
                try:
                    child.stdin.close()
                except (OSError, ValueError):
                    pass

        collectors = (
            threading.Thread(target=collect, args=(0, child.stdout), daemon=True),
            threading.Thread(target=collect, args=(1, child.stderr), daemon=True),
        )
        supplier = threading.Thread(target=supply_input, daemon=True)
        for collector in collectors:
            collector.start()
        supplier.start()

        deadline = started + declaration.timeout_ms * 1_000_000
        state = InvocationState.COMPLETED
        observed_stop = started
        while True:
            if limit_hit.is_set():
                state = InvocationState.OUTPUT_LIMIT_EXCEEDED
                child.kill()
                observed_stop = time.monotonic_ns()
                break
            now = time.monotonic_ns()
            if child.poll() is not None:
                observed_stop = now
                if now >= deadline:
                    state = InvocationState.TIMED_OUT
                break
            if now >= deadline:
                state = InvocationState.TIMED_OUT
                child.kill()
                observed_stop = now
                break
            time.sleep(0.002)
        try:
            child.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=1.0)
        supplier.join(timeout=1.0)
        for collector in collectors:
            collector.join(timeout=1.0)
        if limit_hit.is_set():
            state = InvocationState.OUTPUT_LIMIT_EXCEEDED
        elif capture_error.is_set() or any(item.is_alive() for item in collectors):
            state = InvocationState.CAPTURE_FAILED

    return_code = child.returncode
    return _Execution(
        state=state,
        stdout=bytes(captured[0]),
        stderr=bytes(captured[1]),
        exit_code=return_code if return_code is not None and return_code >= 0 else None,
        termination_signal=-return_code if return_code is not None and return_code < 0 else None,
        elapsed_ms=max(0, (observed_stop - started) // 1_000_000),
    )


def checker_profile_bytes() -> bytes:
    """Return the exact semantic profile interpreted by the rechecker."""

    return canonical_bytes({
        "claim_boundary": CLAIM_BOUNDARY,
        "rules": [
            "require_exact_declaration_and_receipt_binding",
            "require_supported_exact_runtime_and_executable_bytes",
            "require_completed_bounded_recorded_invocation",
            "rerun_exact_invocation_in_a_new_fresh_empty_directory",
            "require_exact_transcript_reproduction",
            "compare_reproduced_transcript_with_declared_output",
        ],
        "schema_version": CHECKER_SCHEMA,
    })


@dataclass(frozen=True)
class DeriverSessionReceipt:
    """Retained transcript of one bounded invocation, not a final verdict."""

    declaration_digest: str
    runtime_coordinate: RuntimeCoordinate
    invocation_state: InvocationState
    stdout_bytes: bytes
    stdout_digest: str
    stderr_bytes: bytes
    stderr_digest: str
    exit_code: int | None
    termination_signal: int | None
    elapsed_ms: int
    timeout_ms: int
    max_output_bytes: int
    checker_profile_digest: str
    reason_codes: tuple[str, ...]
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA:
            raise DeriverSelfStatusError("unsupported receipt schema_version")
        _digest(self.declaration_digest, "declaration_digest")
        if not isinstance(self.runtime_coordinate, RuntimeCoordinate):
            raise DeriverSelfStatusError("receipt runtime_coordinate must be explicit")
        if not isinstance(self.invocation_state, InvocationState):
            raise DeriverSelfStatusError("invocation_state is unsupported")
        for field, value, claimed in (
            ("stdout_bytes", self.stdout_bytes, self.stdout_digest),
            ("stderr_bytes", self.stderr_bytes, self.stderr_digest),
        ):
            if type(value) is not bytes or len(value) > MAX_OUTPUT_BYTES:
                raise DeriverSelfStatusError(f"{field} exceeds its byte bound")
            _digest(claimed, field.replace("bytes", "digest"))
            if digest_bytes(value) != claimed:
                raise DeriverSelfStatusError(f"{field} digest mismatch")
        if self.exit_code is not None:
            _integer(self.exit_code, "exit_code", minimum=0, maximum=2**31 - 1)
        if self.termination_signal is not None:
            _integer(self.termination_signal, "termination_signal", minimum=1, maximum=255)
        if self.exit_code is not None and self.termination_signal is not None:
            raise DeriverSelfStatusError("exit_code and termination_signal are mutually exclusive")
        if self.invocation_state is InvocationState.COMPLETED and (
            self.exit_code is None and self.termination_signal is None
        ):
            raise DeriverSelfStatusError("completed invocation requires a process disposition")
        _integer(self.elapsed_ms, "elapsed_ms", minimum=0, maximum=MAX_TIMEOUT_MS + 5_000)
        _integer(self.timeout_ms, "timeout_ms", minimum=1, maximum=MAX_TIMEOUT_MS)
        _integer(self.max_output_bytes, "max_output_bytes", minimum=1, maximum=MAX_OUTPUT_BYTES)
        _digest(self.checker_profile_digest, "checker_profile_digest")
        if type(self.reason_codes) is not tuple:
            raise DeriverSelfStatusError("reason_codes must be a tuple")
        for reason in self.reason_codes:
            _text(reason, "reason_code", maximum=128)
        if list(self.reason_codes) != sorted(set(self.reason_codes)):
            raise DeriverSelfStatusError("reason_codes must be unique and sorted")
        expected_reasons = {
            InvocationState.COMPLETED: (),
            InvocationState.NOT_RUN: self.reason_codes,
            InvocationState.TIMED_OUT: ("TIME_BOUND_EXHAUSTED",),
            InvocationState.OUTPUT_LIMIT_EXCEEDED: ("OUTPUT_BOUND_EXHAUSTED",),
            InvocationState.START_FAILED: ("INVOCATION_START_FAILED",),
            InvocationState.CAPTURE_FAILED: ("TRANSCRIPT_CAPTURE_FAILED",),
        }[self.invocation_state]
        if self.invocation_state is InvocationState.NOT_RUN:
            if len(self.reason_codes) != 1 or self.reason_codes[0] not in _NOT_RUN_REASONS:
                raise DeriverSelfStatusError("not-run receipt requires one bounded reason")
        elif self.reason_codes != expected_reasons:
            raise DeriverSelfStatusError("reason_codes do not match invocation_state")
        if len(self.stdout_bytes) + len(self.stderr_bytes) > self.max_output_bytes:
            raise DeriverSelfStatusError("combined transcript exceeds its declared output bound")
        if self.invocation_state in {InvocationState.NOT_RUN, InvocationState.START_FAILED} and (
            self.stdout_bytes or self.stderr_bytes or self.exit_code is not None
            or self.termination_signal is not None
        ):
            raise DeriverSelfStatusError("unstarted invocation cannot carry a process transcript")

    def to_dict(self) -> dict[str, Any]:
        return {
            "checker_profile_digest": self.checker_profile_digest,
            "declaration_digest": self.declaration_digest,
            "elapsed_ms": self.elapsed_ms,
            "exit_code": self.exit_code,
            "invocation_state": self.invocation_state.value,
            "max_output_bytes": self.max_output_bytes,
            "reason_codes": list(self.reason_codes),
            "runtime_coordinate": self.runtime_coordinate.to_dict(),
            "schema_version": self.schema_version,
            "stderr_base64url": _encode_bytes(self.stderr_bytes),
            "stderr_digest": self.stderr_digest,
            "stdout_base64url": _encode_bytes(self.stdout_bytes),
            "stdout_digest": self.stdout_digest,
            "termination_signal": self.termination_signal,
            "timeout_ms": self.timeout_ms,
        }

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    @property
    def canonical_digest(self) -> str:
        return digest_bytes(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeriverSessionReceipt":
        value = _strict(
            _decode(data, MAX_RECEIPT_BYTES, "receipt"),
            {
                "checker_profile_digest",
                "declaration_digest",
                "elapsed_ms",
                "exit_code",
                "invocation_state",
                "max_output_bytes",
                "reason_codes",
                "runtime_coordinate",
                "schema_version",
                "stderr_base64url",
                "stderr_digest",
                "stdout_base64url",
                "stdout_digest",
                "termination_signal",
                "timeout_ms",
            },
            "receipt",
        )
        reasons = value["reason_codes"]
        if type(reasons) is not list:
            raise DeriverSelfStatusError("reason_codes must be an array")
        try:
            state = InvocationState(value["invocation_state"])
        except (TypeError, ValueError) as error:
            raise DeriverSelfStatusError("invocation_state is unsupported") from error
        result = cls(
            declaration_digest=value["declaration_digest"],
            runtime_coordinate=RuntimeCoordinate.from_dict(value["runtime_coordinate"]),
            invocation_state=state,
            stdout_bytes=_decode_bytes(value["stdout_base64url"], "stdout_base64url", MAX_OUTPUT_BYTES),
            stdout_digest=value["stdout_digest"],
            stderr_bytes=_decode_bytes(value["stderr_base64url"], "stderr_base64url", MAX_OUTPUT_BYTES),
            stderr_digest=value["stderr_digest"],
            exit_code=value["exit_code"],
            termination_signal=value["termination_signal"],
            elapsed_ms=value["elapsed_ms"],
            timeout_ms=value["timeout_ms"],
            max_output_bytes=value["max_output_bytes"],
            checker_profile_digest=value["checker_profile_digest"],
            reason_codes=tuple(reasons),
            schema_version=value["schema_version"],
        )
        if result.to_bytes() != data:
            raise DeriverSelfStatusError("receipt is not canonical")
        return result


def _observed_coordinate(
    declaration: DeriverSessionDeclaration, executable_path: str | Path,
) -> tuple[RuntimeCoordinate | None, str | None]:
    coordinate = declaration.runtime_coordinate
    if coordinate.runner_id != RUNNER_ID:
        return None, "RUNNER_UNSUPPORTED"
    if coordinate.system not in _SUPPORTED_SYSTEMS:
        return None, "PLATFORM_UNSUPPORTED"
    current = (
        platform.system(),
        platform.release(),
        platform.machine(),
        os.name,
    )
    declared = (coordinate.system, coordinate.release, coordinate.machine, coordinate.os_name)
    if declared != current:
        return None, "RUNTIME_COORDINATE_UNAVAILABLE"
    try:
        executable = _read_executable(executable_path)
    except DeriverSelfStatusError:
        return None, "EXECUTABLE_UNAVAILABLE_OR_LIMITED"
    observed = RuntimeCoordinate(
        runner_id=RUNNER_ID,
        system=current[0],
        release=current[1],
        machine=current[2],
        os_name=current[3],
        executable_digest=digest_bytes(executable),
        executable_size_bytes=len(executable),
    )
    if observed != coordinate:
        return observed, "EXECUTABLE_COORDINATE_INVALID"
    return observed, None


def record_deriver_session(
    declaration_bytes: bytes, executable_path: str | Path,
) -> DeriverSessionReceipt:
    """Attempt and retain one exact bounded invocation."""

    declaration = DeriverSessionDeclaration.from_bytes(declaration_bytes)
    coordinate, reason = _observed_coordinate(declaration, executable_path)
    if reason is not None:
        return DeriverSessionReceipt(
            declaration_digest=declaration.canonical_digest,
            runtime_coordinate=coordinate or declaration.runtime_coordinate,
            invocation_state=InvocationState.NOT_RUN,
            stdout_bytes=b"",
            stdout_digest=digest_bytes(b""),
            stderr_bytes=b"",
            stderr_digest=digest_bytes(b""),
            exit_code=None,
            termination_signal=None,
            elapsed_ms=0,
            timeout_ms=declaration.timeout_ms,
            max_output_bytes=declaration.max_output_bytes,
            checker_profile_digest=digest_bytes(checker_profile_bytes()),
            reason_codes=(reason,),
        )
    execution = _execute(executable_path, declaration)
    reasons = {
        InvocationState.COMPLETED: (),
        InvocationState.TIMED_OUT: ("TIME_BOUND_EXHAUSTED",),
        InvocationState.OUTPUT_LIMIT_EXCEEDED: ("OUTPUT_BOUND_EXHAUSTED",),
        InvocationState.START_FAILED: ("INVOCATION_START_FAILED",),
        InvocationState.CAPTURE_FAILED: ("TRANSCRIPT_CAPTURE_FAILED",),
        InvocationState.NOT_RUN: ("INVOCATION_NOT_OBSERVED",),
    }[execution.state]
    return DeriverSessionReceipt(
        declaration_digest=declaration.canonical_digest,
        runtime_coordinate=coordinate,
        invocation_state=execution.state,
        stdout_bytes=execution.stdout,
        stdout_digest=digest_bytes(execution.stdout),
        stderr_bytes=execution.stderr,
        stderr_digest=digest_bytes(execution.stderr),
        exit_code=execution.exit_code,
        termination_signal=execution.termination_signal,
        elapsed_ms=execution.elapsed_ms,
        timeout_ms=declaration.timeout_ms,
        max_output_bytes=declaration.max_output_bytes,
        checker_profile_digest=digest_bytes(checker_profile_bytes()),
        reason_codes=reasons,
    )


@dataclass(frozen=True)
class DeriverSelfStatusAssessment:
    """Four-state result from independent bounded transcript reproduction."""

    status: DeriverSelfStatus
    declaration_digest: str | None
    receipt_digest: str | None
    checker_profile_digest: str
    checker_source_digest: str
    reason_codes: tuple[str, ...]
    claim_boundary: str = CLAIM_BOUNDARY


def _checker_source_digest() -> str:
    try:
        return digest_bytes(Path(__file__).read_bytes())
    except OSError:
        return digest_bytes(b"CHECKER_SOURCE_UNAVAILABLE")


def _assessment(
    status: DeriverSelfStatus,
    declaration_digest: str | None,
    receipt_digest: str | None,
    *reasons: str,
) -> DeriverSelfStatusAssessment:
    return DeriverSelfStatusAssessment(
        status=status,
        declaration_digest=declaration_digest,
        receipt_digest=receipt_digest,
        checker_profile_digest=digest_bytes(checker_profile_bytes()),
        checker_source_digest=_checker_source_digest(),
        reason_codes=tuple(sorted(set(reasons))),
    )


def recheck_deriver_self_status(
    declaration_bytes: bytes,
    receipt_bytes: bytes | None,
    executable_path: str | Path | None,
) -> DeriverSelfStatusAssessment:
    """Independently rerun and classify one retained actual-session claim."""

    try:
        declaration = DeriverSessionDeclaration.from_bytes(declaration_bytes)
    except (DeriverSelfStatusError, NetworkError, TypeError, ValueError):
        return _assessment(DeriverSelfStatus.INVALID, None, None, "DECLARATION_INVALID")
    declaration_digest = declaration.canonical_digest
    if receipt_bytes is None:
        return _assessment(
            DeriverSelfStatus.UNKNOWN,
            declaration_digest,
            None,
            "INVOCATION_NOT_OBSERVED",
        )
    try:
        receipt = DeriverSessionReceipt.from_bytes(receipt_bytes)
    except (DeriverSelfStatusError, NetworkError, TypeError, ValueError):
        return _assessment(
            DeriverSelfStatus.INVALID,
            declaration_digest,
            None,
            "RECEIPT_INVALID",
        )
    receipt_digest = receipt.canonical_digest
    if (
        receipt.declaration_digest != declaration_digest
        or receipt.timeout_ms != declaration.timeout_ms
        or receipt.max_output_bytes != declaration.max_output_bytes
        or receipt.checker_profile_digest != digest_bytes(checker_profile_bytes())
    ):
        return _assessment(
            DeriverSelfStatus.INVALID,
            declaration_digest,
            receipt_digest,
            "RECEIPT_BINDING_INVALID",
        )
    if executable_path is None:
        return _assessment(
            DeriverSelfStatus.UNKNOWN,
            declaration_digest,
            receipt_digest,
            "EXECUTABLE_UNAVAILABLE_OR_LIMITED",
        )
    coordinate, coordinate_reason = _observed_coordinate(declaration, executable_path)
    if coordinate_reason is not None:
        status = (
            DeriverSelfStatus.INVALID
            if coordinate_reason == "EXECUTABLE_COORDINATE_INVALID"
            else DeriverSelfStatus.UNKNOWN
        )
        return _assessment(status, declaration_digest, receipt_digest, coordinate_reason)
    if receipt.runtime_coordinate != coordinate:
        return _assessment(
            DeriverSelfStatus.INVALID,
            declaration_digest,
            receipt_digest,
            "RECEIPT_RUNTIME_COORDINATE_INVALID",
        )
    if receipt.invocation_state is not InvocationState.COMPLETED:
        invalid = "EXECUTABLE_COORDINATE_INVALID" in receipt.reason_codes
        return _assessment(
            DeriverSelfStatus.INVALID if invalid else DeriverSelfStatus.UNKNOWN,
            declaration_digest,
            receipt_digest,
            *(receipt.reason_codes or ("INVOCATION_NOT_OBSERVED",)),
        )

    reproduced = _recheck_execute(executable_path, declaration)
    if reproduced.state is not InvocationState.COMPLETED:
        reason = {
            InvocationState.TIMED_OUT: "RECHECK_TIME_BOUND_EXHAUSTED",
            InvocationState.OUTPUT_LIMIT_EXCEEDED: "RECHECK_OUTPUT_BOUND_EXHAUSTED",
            InvocationState.START_FAILED: "RECHECK_START_FAILED",
            InvocationState.CAPTURE_FAILED: "RECHECK_TRANSCRIPT_CAPTURE_FAILED",
            InvocationState.NOT_RUN: "RECHECK_NOT_OBSERVED",
            InvocationState.COMPLETED: "",
        }[reproduced.state]
        return _assessment(
            DeriverSelfStatus.UNKNOWN,
            declaration_digest,
            receipt_digest,
            reason,
        )
    if (
        reproduced.stdout != receipt.stdout_bytes
        or reproduced.stderr != receipt.stderr_bytes
        or reproduced.exit_code != receipt.exit_code
        or reproduced.termination_signal != receipt.termination_signal
    ):
        return _assessment(
            DeriverSelfStatus.INVALID,
            declaration_digest,
            receipt_digest,
            "RECHECK_TRANSCRIPT_MISMATCH",
        )
    established = (
        reproduced.exit_code == declaration.expected_exit_code
        and reproduced.termination_signal is None
        and digest_bytes(reproduced.stdout) == declaration.expected_stdout_digest
        and digest_bytes(reproduced.stderr) == declaration.expected_stderr_digest
    )
    return _assessment(
        DeriverSelfStatus.ESTABLISHED if established else DeriverSelfStatus.REFUTED,
        declaration_digest,
        receipt_digest,
        "EXACT_SESSION_REPRODUCED" if established else "DECLARED_OUTPUT_REFUTED",
    )


__all__ = [
    "CHECKER_SCHEMA",
    "CLAIM_BOUNDARY",
    "DECLARATION_SCHEMA",
    "DeriverSelfStatus",
    "DeriverSelfStatusAssessment",
    "DeriverSelfStatusError",
    "DeriverSessionDeclaration",
    "DeriverSessionReceipt",
    "InvocationState",
    "RECEIPT_SCHEMA",
    "RUNNER_ID",
    "RuntimeCoordinate",
    "checker_profile_bytes",
    "record_deriver_session",
    "recheck_deriver_self_status",
    "runtime_coordinate_for",
]
