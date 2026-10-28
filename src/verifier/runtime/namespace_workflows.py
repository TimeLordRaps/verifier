"""Optional, isolated workflow source discovery for Verifier Standard (VSTD).

YAML Ain't Markup Language (YAML); JavaScript Object Notation (JSON). The worker
parses declarations, not commands. No action download or workflow execution is
authorized by discovery. Parser dependencies are optional trusted local tooling.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any

from verifier.runtime.self_polish_estate import bytes_digest


PROTOCOL = "verifier-workflow-discovery-1"
LIMIT = 16 * 1024 * 1024
# The complete Verifier repository currently produces 3,692 bounded workflow
# surfaces from eleven small YAML files and takes about 44 seconds in the
# isolated parser on Windows.  The old 45-second deadline made the same exact
# finite input nondeterministically disappear after another admission pass had
# used the machine.  This deadline remains finite and affects only repository
# parsing time, never the truth conditions or output bounds.
TIMEOUT_SECONDS = 120
EMPTY = {
    "mechanism": None,
    "commands": [],
    "references": [],
    "external_references": [],
    "expressions": [],
    "documents": [],
}


def _run(files: list[tuple[str, bytes]], selected: dict[str, str]) -> dict[str, Any]:
    worker = Path(__file__).with_name("namespace_workflow_worker.py")
    opening = bytes_digest(worker.read_bytes())
    request = json.dumps({"schema_version": PROTOCOL, "selected": selected, "files": [
        {"path": path, "source": base64.b64encode(raw).decode("ascii")} for path, raw in files]}).encode("ascii")
    if len(request) > LIMIT:
        raise ValueError("NAMESPACE_WORKFLOW_INPUT_CAPACITY")
    command = [sys.executable, "-I", "-B", str(worker)]

    def stop(process: subprocess.Popen[bytes]) -> None:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass

    with (
        tempfile.TemporaryFile() as input_stream,
        tempfile.TemporaryFile() as output_stream,
        tempfile.TemporaryFile() as error_stream,
    ):
        input_stream.write(request)
        input_stream.seek(0)
        process = subprocess.Popen(
            command,
            stdin=input_stream,
            stdout=output_stream,
            stderr=error_stream,
            cwd=worker.parent,
        )
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while True:
            returncode = process.poll()
            output_size = os.fstat(output_stream.fileno()).st_size
            error_size = os.fstat(error_stream.fileno()).st_size
            if output_size + error_size > LIMIT:
                stop(process)
                raise ValueError("NAMESPACE_WORKFLOW_OUTPUT_CAPACITY")
            if returncode is not None:
                break
            if time.monotonic() >= deadline:
                stop(process)
                raise subprocess.TimeoutExpired(command, TIMEOUT_SECONDS)
            time.sleep(0.01)

        # The child is closed before the final size check, so a last write
        # cannot race the bounded read or turn a prefix into accepted JSON.
        output_size = os.fstat(output_stream.fileno()).st_size
        error_size = os.fstat(error_stream.fileno()).st_size
        if output_size + error_size > LIMIT:
            stop(process)
            raise ValueError("NAMESPACE_WORKFLOW_OUTPUT_CAPACITY")
        output_stream.seek(0)
        stdout = output_stream.read(LIMIT + 1)
        if len(stdout) != output_size:
            raise ValueError("NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE")

    response = json.loads(stdout)
    if returncode or response.get("schema_version") != PROTOCOL:
        raise ValueError("NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE")
    if len(response["files"]) != len(files) or bytes_digest(worker.read_bytes()) != opening:
        raise ValueError("NAMESPACE_WORKFLOW_SNAPSHOT_CHANGED")
    for (path, raw), row in zip(files, response["files"]):
        if row["path"] != path or row["source_digest"] != bytes_digest(raw):
            raise ValueError("NAMESPACE_WORKFLOW_SOURCE_DIFFERS")
        if any(item["path"] != path or not item["surface_id"].startswith("workflow:" + path + ":") for item in row["surfaces"]):
            raise ValueError("NAMESPACE_WORKFLOW_SURFACE_DIFFERS")
        bound = [
            *row["commands"],
            *row["external_references"],
            *row["expressions"],
            *row["documents"],
        ]
        if any(item["path"] != path or not item["surface_id"].startswith("workflow:" + path + ":") for item in bound):
            raise ValueError("NAMESPACE_WORKFLOW_BINDING_DIFFERS")
        if any(item["target_path"] not in selected or selected[item["target_path"]] != item["target_source_digest"]
               for item in row["references"]):
            raise ValueError("NAMESPACE_WORKFLOW_REFERENCE_DIFFERS")
        if any(
            item.get("scope")
            != "DECLARED_PINNED_EXTERNAL_REFERENCE_NOT_SOURCE_ADMISSION_OR_EXECUTION"
            or not isinstance(item.get("revision"), str)
            or len(item["revision"]) != 40
            or any(character not in "0123456789abcdef" for character in item["revision"])
            for item in row["external_references"]
        ):
            raise ValueError("NAMESPACE_WORKFLOW_EXTERNAL_REFERENCE_DIFFERS")
    response["mechanism"]["worker"] = opening
    return response


def discover(files: list[tuple[str, bytes]], selected: dict[str, str]) -> dict[str, Any]:
    if not files:
        return {"surfaces": [], "gaps": [], "binding": dict(EMPTY)}
    try:
        result = _run(files, selected)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        return {"surfaces": [], "binding": dict(EMPTY), "gaps": [{"path": path,
            "code": "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE", "reason": "Optional YAML parser unavailable ("
                + type(exc).__name__ + "); install verifier-standard[discovery-workflows]. File ownership is not executable-document coverage."}
            for path, _ in files]}
    return {"surfaces": [row for file in result["files"] for row in file["surfaces"]],
            "gaps": [row for file in result["files"] for row in file["gaps"]],
            "binding": {"mechanism": result["mechanism"],
                "commands": [row for file in result["files"] for row in file["commands"]],
                "references": [row for file in result["files"] for row in file["references"]],
                "external_references": [
                    row
                    for file in result["files"]
                    for row in file["external_references"]
                ],
                "expressions": [row for file in result["files"] for row in file["expressions"]],
                "documents": [row for file in result["files"] for row in file["documents"]]}}


def recapture(expected: dict[str, Any]) -> None:
    if expected["mechanism"] is not None and _run([], {})["mechanism"] != expected["mechanism"]:
        raise ValueError("NAMESPACE_WORKFLOW_MECHANISM_CHANGED")


def next_action(code: str, path: str) -> str:
    if code == "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE":
        return "Install verifier-standard[discovery-workflows] in this interpreter and retry. Source: " + path
    if code == "NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED":
        return "Install the discovery-shell extension or replace dynamic dispatch with parser-bounded literal commands. Source: " + path
    if code == "NAMESPACE_WORKFLOW_EXPRESSION_UNRESOLVED":
        return "Replace malformed or computed expression selection with bounded context paths and supported functions. Source: " + path
    if code == "NAMESPACE_WORKFLOW_REFERENCE_UNRESOLVED":
        return "Select one exact local source for every action or reusable workflow; a remote tag or commit label is not downloaded source. Source: " + path
    if code == "NAMESPACE_ISSUE_FORM_SCHEMA_UNRESOLVED":
        return "Conform the GitHub Issue Form/config document to its path-selected bounded structural grammar. Source: " + path
    return "Bind the document dialect and every dynamic interface without executing the document. Source: " + path
