"""Bounded parent-side process observation for Verifier Standard (VSTD) runs.

Secure Hash Algorithm 256-bit (SHA-256) digests bind the bytes and fields the
parent actually observed.  A digest is not actor authentication, and this
record is intentionally narrower than a whole HARNESS observation.
JavaScript Object Notation (JSON) is the canonical serialization boundary.

The capture boundary keeps three facts separate:

* launch was attempted by this parent;
* a process is known to have started; and
* captured streams are known to be complete.

That separation prevents a later post-processing failure from being rewritten
as a launch failure and prevents timeout fragments from being presented as
complete output.
"""

from __future__ import annotations

import base64
from binascii import Error as Base64Error
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
from typing import Any, Mapping, Sequence

from verifier.core.receipt import canonical_json_dumps, strict_json_loads


SCHEMA_VERSION = "verifier-parent-process-observation-2"
DEFAULT_STDOUT_RETENTION_LIMIT_BYTES = 65536
DEFAULT_STDERR_RETENTION_LIMIT_BYTES = 65536

TRI_STATES = frozenset({"YES", "NO", "UNKNOWN"})
STREAM_COMPLETENESS = frozenset({"COMPLETE", "PARTIAL", "UNOBSERVED"})

# Parent-observed state of the owned tree (one Job Object or one process group).
# CONFIRMED: positively observed empty. NOT_CONFIRMED: members positively observed
# after the cleanup deadline. UNKNOWN: emptiness could not be read or terminated.
# NOT_STARTED: no owned child was created. Only CONFIRMED may accompany an exit status.
OWNED_TREE_CLEANUP = frozenset({"CONFIRMED", "NOT_CONFIRMED", "UNKNOWN", "NOT_STARTED"})
_CLEANUP_AFTER_START = frozenset({"CONFIRMED", "NOT_CONFIRMED", "UNKNOWN"})
_CLEANUP_NOT_ESTABLISHED = frozenset({"NOT_CONFIRMED", "UNKNOWN"})

UNOBSERVED = (
    "inherited-environment",
    "inherited-stdin",
    "pid-and-process-tree",
    "descendants",
    "network",
    "undeclared-filesystem",
    "external-effects",
)

CLAIM_BOUNDARY = (
    "Parent subprocess-interface observation only; this is not a whole HARNESS "
    "observation. The record binds launch arguments, parent-visible completion "
    "state, owned-tree cleanup state, return code when cleanup is confirmed, and "
    "captured stream bytes. Owned-tree cleanup covers only the owned Job Object or "
    "process group. It does not observe inherited environment or stdin, process "
    "identifiers or process trees, descendants, network activity, undeclared "
    "filesystem activity, or external effects. Bounded retention may preserve only "
    "a prefix even when the parent hashed a complete stream. Digests provide "
    "integrity bindings, not actor authentication."
)

_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_LAUNCH_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


class ProcessObservationError(ValueError):
    """A process observation violates its schema, binding, or state semantics."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _value_digest(value: Any) -> str:
    return _sha256(canonical_json_dumps(value).encode("utf-8"))


def _canonical_copy(value: Any) -> Any:
    """Detach caller-owned containers while enforcing the JSON value boundary."""

    return strict_json_loads(canonical_json_dumps(value))


def _validated_declared_cwd(value: str) -> str:
    """Validate the declared cwd text without changing prior run semantics."""

    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("PARENT_PROCESS_DECLARED_CWD_INVALID")
    return value


def _declared_cwd_portability(value: str) -> str:
    """Classify, rather than reject, an already-supported nonportable cwd."""

    if (
        "\\" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        return "NONPORTABLE"
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.as_posix():
        return "NONPORTABLE"
    return "PORTABLE_RELATIVE"


def _resolved_cwd_digest(path: Path) -> str:
    # Domain separation avoids making this digest interchangeable with a file
    # content digest. The path itself is deliberately discarded after hashing.
    resolved = str(Path(path).resolve()).encode("utf-8", errors="surrogatepass")
    return _sha256(b"verifier-resolved-cwd-v1\0" + resolved)


def _validated_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise ValueError("PARENT_PROCESS_ARGV_INVALID")
    result = tuple(argv)
    if not result or not all(type(item) is str for item in result) or not result[0]:
        raise ValueError("PARENT_PROCESS_ARGV_INVALID")
    return result


def _positive_timeout(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("PARENT_PROCESS_TIMEOUT_INVALID")
    return value


def _retention_limit(value: int) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("PARENT_PROCESS_RETENTION_LIMIT_INVALID")
    return value


@dataclass(frozen=True)
class ParentProcessLaunch:
    """Capture-owned immutable binding for one planned subprocess invocation."""

    launch_identity: str
    argv: tuple[str, ...]
    declared_cwd: str
    declared_cwd_portability: str
    resolved_cwd_sha256: str
    timeout_seconds: int
    shell: bool
    capture_output: bool
    stdout_retention_limit_bytes: int
    stderr_retention_limit_bytes: int
    launch_attempted: str = "YES"

    def to_dict(self) -> dict[str, Any]:
        return {
            "launch_identity": self.launch_identity,
            "argv": list(self.argv),
            "declared_cwd": self.declared_cwd,
            "declared_cwd_portability": self.declared_cwd_portability,
            "resolved_cwd_sha256": self.resolved_cwd_sha256,
            "timeout_seconds": self.timeout_seconds,
            "shell": self.shell,
            "capture_output": self.capture_output,
            "stdout_retention_limit_bytes": self.stdout_retention_limit_bytes,
            "stderr_retention_limit_bytes": self.stderr_retention_limit_bytes,
            "launch_attempted": self.launch_attempted,
        }


def _new_parent_process_launch(
    *,
    argv: Sequence[str],
    declared_cwd: str,
    resolved_cwd: Path,
    timeout_seconds: int,
    shell: bool = False,
    capture_output: bool = True,
    stdout_retention_limit_bytes: int = DEFAULT_STDOUT_RETENTION_LIMIT_BYTES,
    stderr_retention_limit_bytes: int = DEFAULT_STDERR_RETENTION_LIMIT_BYTES,
    launch_attempted: str,
) -> ParentProcessLaunch:
    if type(shell) is not bool or type(capture_output) is not bool:
        raise ValueError("PARENT_PROCESS_CAPTURE_FLAGS_INVALID")
    if launch_attempted not in {"YES", "NO"}:
        raise ValueError("PARENT_PROCESS_LAUNCH_STATE_INVALID")
    checked_cwd = _validated_declared_cwd(declared_cwd)
    return ParentProcessLaunch(
        launch_identity=secrets.token_hex(32),
        argv=_validated_argv(argv),
        declared_cwd=checked_cwd,
        declared_cwd_portability=_declared_cwd_portability(checked_cwd),
        resolved_cwd_sha256=_resolved_cwd_digest(Path(resolved_cwd)),
        timeout_seconds=_positive_timeout(timeout_seconds),
        shell=shell,
        capture_output=capture_output,
        stdout_retention_limit_bytes=_retention_limit(
            stdout_retention_limit_bytes
        ),
        stderr_retention_limit_bytes=_retention_limit(
            stderr_retention_limit_bytes
        ),
        launch_attempted=launch_attempted,
    )


def prepare_parent_process_observation(
    *,
    argv: Sequence[str],
    declared_cwd: str,
    resolved_cwd: Path,
    timeout_seconds: int,
    shell: bool = False,
    capture_output: bool = True,
    stdout_retention_limit_bytes: int = DEFAULT_STDOUT_RETENTION_LIMIT_BYTES,
    stderr_retention_limit_bytes: int = DEFAULT_STDERR_RETENTION_LIMIT_BYTES,
) -> ParentProcessLaunch:
    """Create a capture-owned binding without claiming launch was attempted.

    This is the fail-closed entry point for a command blocked before subprocess
    invocation, such as a run with a missing declared input.
    """

    return _new_parent_process_launch(
        argv=argv,
        declared_cwd=declared_cwd,
        resolved_cwd=resolved_cwd,
        timeout_seconds=timeout_seconds,
        shell=shell,
        capture_output=capture_output,
        stdout_retention_limit_bytes=stdout_retention_limit_bytes,
        stderr_retention_limit_bytes=stderr_retention_limit_bytes,
        launch_attempted="NO",
    )


def begin_parent_process_observation(
    *,
    argv: Sequence[str],
    declared_cwd: str,
    resolved_cwd: Path,
    timeout_seconds: int,
    shell: bool = False,
    capture_output: bool = True,
    stdout_retention_limit_bytes: int = DEFAULT_STDOUT_RETENTION_LIMIT_BYTES,
    stderr_retention_limit_bytes: int = DEFAULT_STDERR_RETENTION_LIMIT_BYTES,
) -> ParentProcessLaunch:
    """Create a binding immediately before calling ``subprocess.run``.

    The launch identity is generated here rather than accepted from a manifest.
    The resolved cwd participates by digest only. The declaration is retained
    exactly and classified, so previously supported absolute or parent-relative
    manifests are not silently rejected or presented as portable.
    """

    return _new_parent_process_launch(
        argv=argv,
        declared_cwd=declared_cwd,
        resolved_cwd=resolved_cwd,
        timeout_seconds=timeout_seconds,
        shell=shell,
        capture_output=capture_output,
        stdout_retention_limit_bytes=stdout_retention_limit_bytes,
        stderr_retention_limit_bytes=stderr_retention_limit_bytes,
        launch_attempted="YES",
    )


def _stream(
    raw: bytes | None,
    *,
    retention_limit_bytes: int,
    completeness: str,
) -> dict[str, Any]:
    """Describe available bytes without treating an unavailable stream as empty."""

    limit = _retention_limit(retention_limit_bytes)
    if raw is None:
        if completeness != "UNOBSERVED":
            raise ValueError("PARENT_PROCESS_STREAM_STATE_INVALID")
        return {
            "availability": "UNOBSERVED",
            "byte_count": None,
            "sha256": None,
            "retained_base64": None,
            "retention_limit_bytes": limit,
            "retention_truncated": None,
            "completeness": "UNOBSERVED",
        }
    if type(raw) is not bytes or completeness not in {"COMPLETE", "PARTIAL"}:
        raise ValueError("PARENT_PROCESS_STREAM_STATE_INVALID")
    retained = raw[:limit]
    return {
        "availability": "OBSERVED",
        "byte_count": len(raw),
        "sha256": _sha256(raw),
        "retained_base64": base64.b64encode(retained).decode("ascii"),
        "retention_limit_bytes": limit,
        "retention_truncated": len(raw) > limit,
        "completeness": completeness,
    }


def _exception_type(error: BaseException) -> str:
    kind = type(error)
    return f"{kind.__module__}.{kind.__qualname__}"


def _validated_error(error: BaseException) -> BaseException:
    if not isinstance(error, BaseException):
        raise ValueError("PARENT_PROCESS_EXCEPTION_INVALID")
    return error


def _cleanup_within(value: Any, allowed: frozenset[str]) -> str:
    """Accept only a cleanup state the sealed outcome can truthfully carry."""

    if type(value) is not str or value not in allowed:
        raise ValueError("PARENT_PROCESS_CLEANUP_STATE_INVALID")
    return value


def _body(
    launch: ParentProcessLaunch,
    *,
    outcome: str,
    process_started: str,
    returncode: int | None,
    stdout: bytes | None,
    stderr: bytes | None,
    stream_completeness: str,
    streams_complete: str,
    owned_tree_cleanup: str,
    error: BaseException | None,
    exception_phase: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "launch": launch.to_dict(),
        "result": {
            "outcome": outcome,
            "process_started": process_started,
            "returncode": returncode,
            "stdout": _stream(
                stdout,
                retention_limit_bytes=launch.stdout_retention_limit_bytes,
                completeness=stream_completeness if stdout is not None else "UNOBSERVED",
            ),
            "stderr": _stream(
                stderr,
                retention_limit_bytes=launch.stderr_retention_limit_bytes,
                completeness=stream_completeness if stderr is not None else "UNOBSERVED",
            ),
            "streams_complete": streams_complete,
            "owned_tree_cleanup": owned_tree_cleanup,
            "exception_type": _exception_type(error) if error is not None else None,
            "exception_phase": exception_phase,
        },
        "unobserved": list(UNOBSERVED),
        "claim_boundary": CLAIM_BOUNDARY,
    }


def seal_parent_process_observation(body: Mapping[str, Any]) -> dict[str, Any]:
    """Return detached canonical data plus its unauthenticated inner digest."""

    if type(body) is not dict or "inner_digest" in body:
        raise ProcessObservationError("PARENT_PROCESS_OBSERVATION_BODY_INVALID")
    detached = _canonical_copy(body)
    return {**detached, "inner_digest": _value_digest(detached)}


def observe_completed_process(
    launch: ParentProcessLaunch,
    *,
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    owned_tree_cleanup: str,
) -> dict[str, Any]:
    """Seal a normally returned ``CompletedProcess`` interface.

    An exit status is attested only with confirmed owned-tree cleanup.
    """

    if type(returncode) is not int or type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError("PARENT_PROCESS_COMPLETED_RESULT_INVALID")
    cleanup = _cleanup_within(owned_tree_cleanup, frozenset({"CONFIRMED"}))
    outcome = "SUCCESS" if returncode == 0 else "NONZERO_EXIT"
    return seal_parent_process_observation(
        _body(
            launch,
            outcome=outcome,
            process_started="YES",
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            stream_completeness="COMPLETE",
            streams_complete="YES",
            owned_tree_cleanup=cleanup,
            error=None,
            exception_phase=None,
        )
    )


def observe_timeout(
    launch: ParentProcessLaunch,
    error: subprocess.TimeoutExpired,
    *,
    owned_tree_cleanup: str,
) -> dict[str, Any]:
    """Seal timeout fragments as partial, never complete, streams.

    Timeout keeps its identity whatever the cleanup state; the cleanup state is
    carried beside it so an uncertain tree is never presented as a clean timeout.
    """

    if not isinstance(error, subprocess.TimeoutExpired):
        raise ValueError("PARENT_PROCESS_TIMEOUT_RESULT_INVALID")
    stdout = error.stdout
    stderr = error.stderr
    if stdout is not None and type(stdout) is not bytes:
        raise ValueError("PARENT_PROCESS_TIMEOUT_RESULT_INVALID")
    if stderr is not None and type(stderr) is not bytes:
        raise ValueError("PARENT_PROCESS_TIMEOUT_RESULT_INVALID")
    cleanup = _cleanup_within(owned_tree_cleanup, _CLEANUP_AFTER_START)
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="TIMEOUT",
            process_started="YES",
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            stream_completeness="PARTIAL",
            streams_complete="NO",
            owned_tree_cleanup=cleanup,
            error=error,
            exception_phase="EXECUTION",
        )
    )


def observe_output_cap_exceeded(
    launch: ParentProcessLaunch,
    *,
    stdout: bytes,
    stderr: bytes,
    owned_tree_cleanup: str,
) -> dict[str, Any]:
    """Seal a run stopped because a stream reached the parent capture bound.

    Both streams are retained as prefixes only. Exit status is withheld: the run
    was stopped before the child ended on its own.
    """

    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError("PARENT_PROCESS_OUTPUT_CAP_RESULT_INVALID")
    cleanup = _cleanup_within(owned_tree_cleanup, _CLEANUP_AFTER_START)
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="OUTPUT_CAP_EXCEEDED",
            process_started="YES",
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            stream_completeness="PARTIAL",
            streams_complete="NO",
            owned_tree_cleanup=cleanup,
            error=None,
            exception_phase=None,
        )
    )


def observe_cleanup_not_established(
    launch: ParentProcessLaunch,
    *,
    stdout: bytes,
    stderr: bytes,
    owned_tree_cleanup: str,
) -> dict[str, Any]:
    """Seal a child that exited while owned-tree emptiness is not established.

    The exit status is withheld because a surviving owned member may still write
    to either stream, so neither the status nor stream completeness is claimed.
    """

    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError("PARENT_PROCESS_CLEANUP_RESULT_INVALID")
    cleanup = _cleanup_within(owned_tree_cleanup, _CLEANUP_NOT_ESTABLISHED)
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="CLEANUP_NOT_ESTABLISHED",
            process_started="YES",
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            stream_completeness="PARTIAL",
            streams_complete="UNKNOWN",
            owned_tree_cleanup=cleanup,
            error=None,
            exception_phase=None,
        )
    )


def observe_exit_status_unknown(
    launch: ParentProcessLaunch,
    *,
    stdout: bytes,
    stderr: bytes,
    owned_tree_cleanup: str,
) -> dict[str, Any]:
    """Seal a confirmed-empty owned tree whose direct child reported no exit status."""

    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError("PARENT_PROCESS_EXIT_STATUS_RESULT_INVALID")
    cleanup = _cleanup_within(owned_tree_cleanup, frozenset({"CONFIRMED"}))
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="EXIT_STATUS_UNKNOWN",
            process_started="YES",
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            stream_completeness="COMPLETE",
            streams_complete="YES",
            owned_tree_cleanup=cleanup,
            error=None,
            exception_phase=None,
        )
    )


def observe_launch_error(
    launch: ParentProcessLaunch,
    error: BaseException,
) -> dict[str, Any]:
    """Seal an error known to have occurred before a process was created."""

    checked_error = _validated_error(error)
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="LAUNCH_ERROR",
            process_started="NO",
            returncode=None,
            stdout=None,
            stderr=None,
            stream_completeness="UNOBSERVED",
            streams_complete="UNKNOWN",
            owned_tree_cleanup="NOT_STARTED",
            error=checked_error,
            exception_phase="LAUNCH",
        )
    )


def observe_post_processing_error(
    launch: ParentProcessLaunch,
    *,
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    error: BaseException,
    owned_tree_cleanup: str,
) -> dict[str, Any]:
    """Preserve a completed subprocess when later receipt processing fails."""

    if type(returncode) is not int or type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError("PARENT_PROCESS_POST_PROCESSING_RESULT_INVALID")
    checked_error = _validated_error(error)
    cleanup = _cleanup_within(owned_tree_cleanup, frozenset({"CONFIRMED"}))
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="POST_PROCESSING_ERROR",
            process_started="YES",
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            stream_completeness="COMPLETE",
            streams_complete="YES",
            owned_tree_cleanup=cleanup,
            error=checked_error,
            exception_phase="POST_PROCESSING",
        )
    )


def observe_indeterminate_execution_error(
    launch: ParentProcessLaunch,
    error: BaseException,
) -> dict[str, Any]:
    """Preserve UNKNOWN when an exception does not establish process creation."""

    checked_error = _validated_error(error)
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="EXECUTION_ERROR",
            process_started="UNKNOWN",
            returncode=None,
            stdout=None,
            stderr=None,
            stream_completeness="UNOBSERVED",
            streams_complete="UNKNOWN",
            owned_tree_cleanup="UNKNOWN",
            error=checked_error,
            exception_phase="EXECUTION",
        )
    )


def observe_missing_input_no_launch(
    launch: ParentProcessLaunch,
) -> dict[str, Any]:
    """Seal fail-closed non-execution caused by a missing declared input.

    The caller must use :func:`prepare_parent_process_observation`; accepting an
    attempted-launch binding here would rewrite history after the fact.
    """

    if (
        not isinstance(launch, ParentProcessLaunch)
        or launch.launch_attempted != "NO"
    ):
        raise ValueError("PARENT_PROCESS_NO_LAUNCH_BINDING_INVALID")
    return seal_parent_process_observation(
        _body(
            launch,
            outcome="MISSING_INPUT",
            process_started="NO",
            returncode=None,
            stdout=None,
            stderr=None,
            stream_completeness="UNOBSERVED",
            streams_complete="UNKNOWN",
            owned_tree_cleanup="NOT_STARTED",
            error=None,
            exception_phase=None,
        )
    )


def _invalid(label: str) -> ProcessObservationError:
    return ProcessObservationError(f"PARENT_PROCESS_OBSERVATION_{label}_INVALID")


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise _invalid(label)
    return value


def _recheck_launch(value: Any) -> Mapping[str, Any]:
    launch = _exact_keys(
        value,
        {
            "launch_identity",
            "argv",
            "declared_cwd",
            "declared_cwd_portability",
            "resolved_cwd_sha256",
            "timeout_seconds",
            "shell",
            "capture_output",
            "stdout_retention_limit_bytes",
            "stderr_retention_limit_bytes",
            "launch_attempted",
        },
        "LAUNCH",
    )
    identity = launch["launch_identity"]
    argv = launch["argv"]
    resolved_digest = launch["resolved_cwd_sha256"]
    if (
        type(identity) is not str
        or _LAUNCH_ID_PATTERN.fullmatch(identity) is None
        or type(argv) is not list
        or not argv
        or not all(type(item) is str for item in argv)
        or not argv[0]
        or type(resolved_digest) is not str
        or _SHA256_PATTERN.fullmatch(resolved_digest) is None
        or type(launch["timeout_seconds"]) is not int
        or launch["timeout_seconds"] <= 0
        or type(launch["shell"]) is not bool
        or type(launch["capture_output"]) is not bool
        or type(launch["stdout_retention_limit_bytes"]) is not int
        or launch["stdout_retention_limit_bytes"] < 0
        or type(launch["stderr_retention_limit_bytes"]) is not int
        or launch["stderr_retention_limit_bytes"] < 0
        or launch["launch_attempted"] not in TRI_STATES
    ):
        raise _invalid("LAUNCH")
    try:
        declared_cwd = _validated_declared_cwd(launch["declared_cwd"])
    except ValueError as exc:
        raise _invalid("LAUNCH") from exc
    if (
        declared_cwd != launch["declared_cwd"]
        or launch["declared_cwd_portability"]
        != _declared_cwd_portability(declared_cwd)
    ):
        raise _invalid("LAUNCH")
    return launch


def _recheck_stream(value: Any, *, limit: int) -> Mapping[str, Any]:
    stream = _exact_keys(
        value,
        {
            "availability",
            "byte_count",
            "sha256",
            "retained_base64",
            "retention_limit_bytes",
            "retention_truncated",
            "completeness",
        },
        "STREAM",
    )
    if stream["retention_limit_bytes"] != limit:
        raise _invalid("STREAM")
    if stream["availability"] == "UNOBSERVED":
        if (
            stream["byte_count"] is not None
            or stream["sha256"] is not None
            or stream["retained_base64"] is not None
            or stream["retention_truncated"] is not None
            or stream["completeness"] != "UNOBSERVED"
        ):
            raise _invalid("STREAM")
        return stream
    if stream["availability"] != "OBSERVED":
        raise _invalid("STREAM")
    count = stream["byte_count"]
    digest = stream["sha256"]
    retained_base64 = stream["retained_base64"]
    truncated = stream["retention_truncated"]
    if (
        type(count) is not int
        or count < 0
        or type(digest) is not str
        or _SHA256_PATTERN.fullmatch(digest) is None
        or type(retained_base64) is not str
        or type(truncated) is not bool
        or truncated != (count > limit)
        or stream["completeness"] not in {"COMPLETE", "PARTIAL"}
    ):
        raise _invalid("STREAM")
    try:
        retained = base64.b64decode(retained_base64, validate=True)
    except (Base64Error, ValueError) as exc:
        raise _invalid("STREAM") from exc
    if (
        base64.b64encode(retained).decode("ascii") != retained_base64
        or len(retained) != min(count, limit)
        or (not truncated and _sha256(retained) != digest)
    ):
        raise _invalid("STREAM")
    return stream


def _recheck_result(value: Any, launch: Mapping[str, Any]) -> None:
    result = _exact_keys(
        value,
        {
            "outcome",
            "process_started",
            "returncode",
            "stdout",
            "stderr",
            "streams_complete",
            "owned_tree_cleanup",
            "exception_type",
            "exception_phase",
        },
        "RESULT",
    )
    stdout = _recheck_stream(
        result["stdout"], limit=launch["stdout_retention_limit_bytes"]
    )
    stderr = _recheck_stream(
        result["stderr"], limit=launch["stderr_retention_limit_bytes"]
    )
    if (
        result["process_started"] not in TRI_STATES
        or result["streams_complete"] not in TRI_STATES
        or result["owned_tree_cleanup"] not in OWNED_TREE_CLEANUP
        or (result["returncode"] is not None and type(result["returncode"]) is not int)
        or (
            result["exception_type"] is not None
            and (type(result["exception_type"]) is not str or not result["exception_type"])
        )
        or result["exception_phase"] not in {None, "LAUNCH", "EXECUTION", "POST_PROCESSING"}
    ):
        raise _invalid("RESULT")

    common_complete = (
        result["process_started"] == "YES"
        and result["streams_complete"] == "YES"
        and stdout["completeness"] == "COMPLETE"
        and stderr["completeness"] == "COMPLETE"
    )
    both_partial = stdout["completeness"] == "PARTIAL" and stderr["completeness"] == "PARTIAL"
    both_unobserved = (
        stdout["completeness"] == "UNOBSERVED" and stderr["completeness"] == "UNOBSERVED"
    )
    no_exception = result["exception_type"] is None and result["exception_phase"] is None
    has_exception = result["exception_type"] is not None
    outcome = result["outcome"]
    launch_attempted = launch["launch_attempted"]
    started = result["process_started"]
    streams = result["streams_complete"]
    returncode = result["returncode"]
    cleanup = result["owned_tree_cleanup"]
    phase = result["exception_phase"]
    valid = False
    # An exit status is attested only with confirmed owned-tree cleanup; every
    # other state withholds it, so no uncertain run can present as a clean exit.
    if outcome == "SUCCESS":
        valid = (
            launch_attempted == "YES"
            and common_complete
            and returncode == 0
            and cleanup == "CONFIRMED"
            and no_exception
        )
    elif outcome == "NONZERO_EXIT":
        valid = (
            launch_attempted == "YES"
            and common_complete
            and type(returncode) is int
            and returncode != 0
            and cleanup == "CONFIRMED"
            and no_exception
        )
    elif outcome == "TIMEOUT":
        valid = (
            launch_attempted == "YES"
            and started == "YES"
            and streams == "NO"
            and returncode is None
            and cleanup in _CLEANUP_AFTER_START
            and stdout["completeness"] in {"PARTIAL", "UNOBSERVED"}
            and stderr["completeness"] in {"PARTIAL", "UNOBSERVED"}
            and has_exception
            and phase == "EXECUTION"
        )
    elif outcome == "OUTPUT_CAP_EXCEEDED":
        valid = (
            launch_attempted == "YES"
            and started == "YES"
            and streams == "NO"
            and returncode is None
            and cleanup in _CLEANUP_AFTER_START
            and both_partial
            and no_exception
        )
    elif outcome == "CLEANUP_NOT_ESTABLISHED":
        valid = (
            launch_attempted == "YES"
            and started == "YES"
            and streams == "UNKNOWN"
            and returncode is None
            and cleanup in _CLEANUP_NOT_ESTABLISHED
            and both_partial
            and no_exception
        )
    elif outcome == "EXIT_STATUS_UNKNOWN":
        valid = (
            launch_attempted == "YES"
            and common_complete
            and returncode is None
            and cleanup == "CONFIRMED"
            and no_exception
        )
    elif outcome == "POST_PROCESSING_ERROR":
        valid = (
            launch_attempted == "YES"
            and common_complete
            and type(returncode) is int
            and cleanup == "CONFIRMED"
            and has_exception
            and phase == "POST_PROCESSING"
        )
    elif outcome == "LAUNCH_ERROR":
        valid = (
            launch_attempted == "YES"
            and started == "NO"
            and streams == "UNKNOWN"
            and returncode is None
            and cleanup == "NOT_STARTED"
            and both_unobserved
            and has_exception
            and phase == "LAUNCH"
        )
    elif outcome == "EXECUTION_ERROR":
        valid = (
            launch_attempted == "YES"
            and started == "UNKNOWN"
            and streams == "UNKNOWN"
            and returncode is None
            and cleanup == "UNKNOWN"
            and both_unobserved
            and has_exception
            and phase == "EXECUTION"
        )
    elif outcome == "MISSING_INPUT":
        valid = (
            launch_attempted == "NO"
            and started == "NO"
            and streams == "UNKNOWN"
            and returncode is None
            and cleanup == "NOT_STARTED"
            and both_unobserved
            and no_exception
        )
    if not valid:
        raise _invalid("RESULT")


def _verified_record_digest(record: Mapping[str, Any]) -> Mapping[str, Any]:
    top = _exact_keys(
        record,
        {
            "schema_version",
            "launch",
            "result",
            "unobserved",
            "claim_boundary",
            "inner_digest",
        },
        "RECORD",
    )
    recorded_digest = top["inner_digest"]
    if (
        type(recorded_digest) is not str
        or _SHA256_PATTERN.fullmatch(recorded_digest) is None
    ):
        raise ProcessObservationError("PARENT_PROCESS_OBSERVATION_DIGEST_INVALID")
    body = {key: value for key, value in top.items() if key != "inner_digest"}
    if _value_digest(body) != recorded_digest:
        raise ProcessObservationError("PARENT_PROCESS_OBSERVATION_DIGEST_DIFFERS")
    return top


def _validate_record_payload(record: Mapping[str, Any]) -> Mapping[str, Any]:
    if record["schema_version"] != SCHEMA_VERSION:
        raise ProcessObservationError("PARENT_PROCESS_OBSERVATION_SCHEMA_INVALID")
    if (
        record["unobserved"] != list(UNOBSERVED)
        or record["claim_boundary"] != CLAIM_BOUNDARY
    ):
        raise ProcessObservationError("PARENT_PROCESS_OBSERVATION_BOUNDARY_INVALID")
    launch = _recheck_launch(record["launch"])
    _recheck_result(record["result"], launch)
    return launch


def validate_parent_process_observation(record: Mapping[str, Any]) -> None:
    """Validate a record whose complete bytes are bound by an outer receipt.

    This entry point does not need live capture state. It checks the closed
    schema, canonical inner digest, exact boundary declarations, stream
    representation, enumerated states, and cross-field result semantics. The
    enclosing receipt remains responsible for selecting these exact bytes.
    """

    top = _verified_record_digest(record)
    _validate_record_payload(top)


def recheck_parent_process_observation(
    record: Mapping[str, Any],
    *,
    bound_inner_digest: str,
    expected_launch: ParentProcessLaunch,
) -> None:
    """Strictly recheck one observation against separately bound capture state.

    ``bound_inner_digest`` must come from the enclosing selected artifact or
    receipt. Recomputing a replacement digest from changed data is not a recheck.
    ``expected_launch`` preserves the capture-owned identity and exact launch
    parameters outside the serialized record while the parent is assembling it.
    """

    if not isinstance(expected_launch, ParentProcessLaunch):
        raise ProcessObservationError(
            "PARENT_PROCESS_OBSERVATION_EXPECTED_LAUNCH_INVALID"
        )
    top = _verified_record_digest(record)
    if top["inner_digest"] != bound_inner_digest:
        raise ProcessObservationError(
            "PARENT_PROCESS_OBSERVATION_BOUND_DIGEST_DIFFERS"
        )
    launch = _validate_record_payload(top)
    if canonical_json_dumps(launch) != canonical_json_dumps(expected_launch.to_dict()):
        raise ProcessObservationError(
            "PARENT_PROCESS_OBSERVATION_LAUNCH_BINDING_DIFFERS"
        )


__all__ = [
    "CLAIM_BOUNDARY",
    "DEFAULT_STDERR_RETENTION_LIMIT_BYTES",
    "DEFAULT_STDOUT_RETENTION_LIMIT_BYTES",
    "ParentProcessLaunch",
    "ProcessObservationError",
    "SCHEMA_VERSION",
    "OWNED_TREE_CLEANUP",
    "UNOBSERVED",
    "begin_parent_process_observation",
    "observe_cleanup_not_established",
    "observe_completed_process",
    "observe_exit_status_unknown",
    "observe_indeterminate_execution_error",
    "observe_launch_error",
    "observe_missing_input_no_launch",
    "observe_output_cap_exceeded",
    "observe_post_processing_error",
    "observe_timeout",
    "prepare_parent_process_observation",
    "recheck_parent_process_observation",
    "seal_parent_process_observation",
    "validate_parent_process_observation",
]
