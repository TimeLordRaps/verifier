"""Parent-side package exchange evidence for Verifier Standard (VSTD).

This recorder observes the subprocess interface, not child internals. Retained
bytes support rechecking the interpretation of a response; they do not attest
execution on a hostile host or discharge a whole HARNESS contract. JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import base64
from pathlib import Path
import re
import sys
from typing import Any

from verifier.core.receipt import strict_json_loads
from verifier.runtime.self_polish_estate import bytes_digest
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


SCHEMA = "verifier-package-parent-exchange-1"
OUTPUT_LIMIT = 1024 * 1024
STDERR_LIMIT = 65536
UNOBSERVED = ["child-filesystem", "child-network", "descendants", "external-effects"]
BOUNDARY = ("Parent subprocess-interface observation, assuming the interpreter and host. "
            "Submitted input is not proof of delivery. Retention limits do not bound subprocess capture memory. "
            "No independent attestation, child-effect confinement or full HARNESS conformance.")
DEFAULT_WORKER_TIMEOUT_SECONDS = 30
MAX_WORKER_TIMEOUT_SECONDS = 90


def worker_timeout_seconds(module: Any) -> int:
    """Reconstruct the closed adapter deadline recorded by the dispatcher."""

    declared = getattr(
        module, "WORKER_TIMEOUT_SECONDS", DEFAULT_WORKER_TIMEOUT_SECONDS
    )
    if (
        type(declared) is not int
        or declared < 1
        or declared > MAX_WORKER_TIMEOUT_SECONDS
    ):
        raise ValueError("PACKAGE_EXECUTION_WORKER_TIMEOUT_DECLARATION_INVALID")
    return declared


def stream(raw: bytes | None, limit: int) -> dict[str, Any] | None:
    """Keep unavailable distinct from observed empty, and truncation explicit."""
    if raw is None:
        return None
    if type(raw) is not bytes:
        raise ValueError("PACKAGE_EXECUTION_PARENT_STREAM_INVALID")
    return {"bytes": len(raw), "sha256": bytes_digest(raw),
            "retained_base64": base64.b64encode(raw[:limit]).decode("ascii"),
            "truncated": len(raw) > limit}


def begin(request: dict[str, Any], selection: dict[str, Any], pins: dict[str, str],
          command: list[str], parameters: dict[str, Any]) -> dict[str, Any]:
    """Describe exactly the fixed launch boundary without disclosing host paths."""
    return {"schema_version": SCHEMA, "origin": "PARENT_SUBPROCESS_OBSERVATION",
        "selection_digest": value_digest(selection), "source_pins_digest": value_digest(pins),
        "request": request, "worker": Path(command[-1]).name, "flags": command[1:-1],
        "invoking_interpreter": command[0] == sys.executable,
        "environment_keys": sorted(parameters["env"]),
        "parameters": {key: parameters[key] for key in ("capture_output", "timeout", "check")},
        "stdin": stream(parameters["input"], 16384), "stdout": None, "stderr": None,
        "returncode": None, "streams_complete": False, "outcome": "LAUNCH_ATTEMPTED",
        "exception_type": None, "unobserved": list(UNOBSERVED), "claim_boundary": BOUNDARY}


def seal(record: dict[str, Any]) -> dict[str, Any]:
    """Freeze a detached portable record; its digest authenticates no actor."""
    body = strict_json_loads(canonical_bytes(record).decode("utf-8"))
    return {**body, "observation_digest": value_digest(body)}


def _retained_stream(value: Any, limit: int, *, require_complete: bool = True) -> bytes:
    if (type(value) is not dict or set(value) != {"bytes", "sha256", "retained_base64", "truncated"}
            or type(value["bytes"]) is not int or value["bytes"] < 0
            or type(value["truncated"]) is not bool or value["truncated"] != (value["bytes"] > limit)
            or require_complete and value["truncated"]
            or type(value["sha256"]) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value["sha256"]) is None
            or type(value["retained_base64"]) is not str
            or len(value["retained_base64"]) > 4 * ((limit + 2) // 3)):
        raise ValueError("PACKAGE_EXECUTION_PARENT_STREAM_INVALID")
    raw = base64.b64decode(value["retained_base64"], validate=True)
    # A truncated stream cannot substantiate its omitted bytes by digest alone.
    # The record retains that limit; only complete streams can be rehashed.
    if (len(raw) != min(value["bytes"], limit) or not value["truncated"] and bytes_digest(raw) != value["sha256"]
            or base64.b64encode(raw).decode("ascii") != value["retained_base64"]):
        raise ValueError("PACKAGE_EXECUTION_PARENT_STREAM_DIFFERS")
    return raw


def verify_accepted(record: dict[str, Any] | None, report: dict[str, Any], *,
                    selection: dict[str, Any], item: Any, collection_digest: str, module: Any) -> None:
    """Recheck accepted bytes and exact selection, not the worker's verdict word.

Missing capture is missing evidence. Altered bindings or interpretation are a
contradiction. Recomputing a digest on fabricated bytes proves no past execution.
"""
    if record is None:
        raise OSError("PACKAGE_EXECUTION_PARENT_OBSERVATION_UNAVAILABLE")
    body = {key: value for key, value in record.items() if key != "observation_digest"}
    if record.get("observation_digest") != value_digest(body):
        raise ValueError("PACKAGE_EXECUTION_PARENT_DIGEST_DIFFERS")
    request = record.get("request")
    expected_request = {"schema_version": module.REQUEST_SCHEMA, "nonce": request.get("nonce") if type(request) is dict else None,
        "object_id": item.object_id, "object_digest": item.digest, "collection_digest": collection_digest}
    nonce = expected_request["nonce"]
    expected = begin(expected_request, selection, report["source_pins"],
        [sys.executable, "-I", "-S", "-B", module.WORKER],
        {"env": {name: "" for name in record["environment_keys"]}, "input": canonical_bytes(expected_request),
         "capture_output": True, "timeout": worker_timeout_seconds(module), "check": False})
    expected.update(outcome="ACCEPTED", returncode=0, streams_complete=True,
                    stdout=record["stdout"], stderr=record["stderr"])
    environment_keys = set(record["environment_keys"])
    if (canonical_bytes(expected) != canonical_bytes(body)
            or type(nonce) is not str or len(nonce) != 64 or not set(nonce) <= set("0123456789abcdef")
            or not {"TEMP", "TMP", "TMPDIR"} <= environment_keys
            or not environment_keys <= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATH"}):
        raise ValueError("PACKAGE_EXECUTION_PARENT_BINDING_DIFFERS")
    if _retained_stream(record["stdin"], 16384) != canonical_bytes(report["request"]):
        raise ValueError("PACKAGE_EXECUTION_PARENT_REQUEST_DIFFERS")
    _retained_stream(record["stderr"], STDERR_LIMIT, require_complete=False)
    response = strict_json_loads(_retained_stream(record["stdout"], OUTPUT_LIMIT).decode("utf-8"))
    if (set(report) != {"schema_version", "request", "source_pins", "observations"}
            or report["schema_version"] != module.OBSERVATION_SCHEMA
            or canonical_bytes(response) != canonical_bytes(report)):
        raise ValueError("PACKAGE_EXECUTION_PARENT_RESPONSE_DIFFERS")


def retained(snapshot: Any) -> list[dict[str, Any]]:
    """Export each observed exchange once, including failed attempts."""
    return [record for _, record in sorted(snapshot.execution_transports.items())]
