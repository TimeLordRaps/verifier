"""Optional JavaScript discovery without importing subject code or dependencies.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). The fixed worker
uses the current interpreter's installed optional parser in isolated mode.
Parser-library execution is trusted local tooling, not a subject-code sandbox.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from verifier.runtime.self_polish_estate import bytes_digest


PROTOCOL = "verifier-javascript-discovery-1"
SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx"})
LIMIT = 16 * 1024 * 1024


def _run(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    worker = Path(__file__).with_name("namespace_javascript_worker.py")
    worker_digest = bytes_digest(worker.read_bytes())
    request = json.dumps({"schema_version": PROTOCOL, "files": [
        {"path": path, "source": base64.b64encode(raw).decode("ascii")} for path, raw in files]}).encode("ascii")
    if len(request) > LIMIT:
        raise ValueError("NAMESPACE_JAVASCRIPT_INPUT_CAPACITY")
    result = subprocess.run([sys.executable, "-I", "-B", str(worker)], input=request,
        capture_output=True, timeout=45, cwd=worker.parent)
    if len(result.stdout) > LIMIT:
        raise ValueError("NAMESPACE_JAVASCRIPT_PARSER_UNAVAILABLE")
    response = json.loads(result.stdout)
    if result.returncode:
        code = response.get("code", "NAMESPACE_JAVASCRIPT_PARSER_UNAVAILABLE")
        raise ValueError(code if isinstance(code, str) and code.startswith("NAMESPACE_JAVASCRIPT_") else "NAMESPACE_JAVASCRIPT_PARSER_UNAVAILABLE")
    if response.get("schema_version") != PROTOCOL or len(response.get("files", [])) != len(files):
        raise ValueError("NAMESPACE_JAVASCRIPT_PROTOCOL_DIFFERS")
    if bytes_digest(worker.read_bytes()) != worker_digest:
        raise ValueError("NAMESPACE_JAVASCRIPT_WORKER_CHANGED")
    response["mechanism"]["worker"] = worker_digest
    for (path, raw), row in zip(files, response["files"]):
        if row["path"] != path or row["source_digest"] != bytes_digest(raw):
            raise ValueError("NAMESPACE_JAVASCRIPT_SOURCE_DIFFERS")
        if any(item["path"] != path or not item["surface_id"].startswith(("javascript:" + path + ":", "javascript-export:" + path + ":")) for item in row["surfaces"]):
            raise ValueError("NAMESPACE_JAVASCRIPT_SURFACE_DIFFERS")
    return response


def discover(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    if not files:
        return {"surfaces": [], "gaps": [], "mechanism": None}
    try:
        response = _run(files)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        reason = str(exc) if str(exc).startswith("NAMESPACE_JAVASCRIPT_") else type(exc).__name__
        return {"surfaces": [], "mechanism": None, "gaps": [
            {"path": path, "code": "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED",
             "reason": "Optional JavaScript parser unavailable (" + reason + "); install verifier-standard[discovery-javascript] in this interpreter. File bytes are not interface coverage."}
            for path, _ in files]}
    return {"surfaces": [row for file in response["files"] for row in file["surfaces"]],
            "gaps": [row for file in response["files"] for row in file["gaps"]], "mechanism": response["mechanism"]}


def recapture(expected: dict[str, Any] | None) -> None:
    if expected is not None and _run([])["mechanism"] != expected:
        raise ValueError("NAMESPACE_JAVASCRIPT_MECHANISM_CHANGED")
