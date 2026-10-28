"""Optional non-executing Rust and Bash discovery for Verifier Standard (VSTD).

JavaScript Object Notation (JSON). No subject imports, builds, shell evaluation
or network requests occur. Installed grammar/runtime bytes are bound and
recaptured; an unavailable parser never turns file ownership into coverage.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from verifier.runtime.self_polish_estate import bytes_digest
from verifier.runtime.tier_zero_profile import canonical_bytes
from verifier.runtime import namespace_rust_expansions


PROTOCOL = "verifier-systems-discovery-1"
SUFFIXES = {".rs": "rust", ".sh": "bash", ".bash": "bash"}
LIMIT = 16 * 1024 * 1024


def _roles(value: Any) -> bool:
    return (type(value) is list and all(type(item) is str and re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", item)
            for item in value) and value == sorted(set(value)))


def _check_mechanism(value: Any, languages: list[str]) -> None:
    """Validate the worker boundary before trusting any nested parser metadata."""
    expected = {"tree-sitter": "0.25.2"}
    for language in languages:
        name, version = {"rust": ("tree-sitter-rust", "0.24.2"), "bash": ("tree-sitter-bash", "0.25.1")}[language]
        expected[name] = version
    if (type(value) is not dict or set(value) != {"languages", "distributions"}
            or value["languages"] != languages or type(value["distributions"]) is not dict
            or set(value["distributions"]) != set(expected)):
        raise ValueError("NAMESPACE_SYSTEMS_MECHANISM_DIFFERS")
    for name, version in expected.items():
        row = value["distributions"][name]
        if (type(row) is not dict or set(row) != {"version", "files"} or row["version"] != version
                or type(row["files"]) is not dict or not row["files"]):
            raise ValueError("NAMESPACE_SYSTEMS_MECHANISM_DIFFERS")
        for path, digest in row["files"].items():
            if (not path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/"))
                    or "\\" in path or ":" in path or type(digest) is not str
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None):
                raise ValueError("NAMESPACE_SYSTEMS_MECHANISM_DIFFERS")


def _check_file(row: Any, path: str, raw: bytes) -> None:
    """A well-formed response is necessary, but is not independent discovery."""
    if (type(row) is not dict or set(row) != {"path", "source_digest", "surfaces", "gaps"}
            or row["path"] != path or row["source_digest"] != bytes_digest(raw)
            or type(row["surfaces"]) is not list or type(row["gaps"]) is not list):
        raise ValueError("NAMESPACE_SYSTEMS_SOURCE_DIFFERS")
    prefix = SUFFIXES[Path(path).suffix.lower()] + ":" + path + ":"
    identities: set[str] = set()
    for item in row["surfaces"]:
        if (type(item) is not dict or set(item) != {"path", "surface_id", "line", "form", "source_kinds", "hints", "unresolved_marker"}
                or item["path"] != path or type(item["surface_id"]) is not str
                or not item["surface_id"].startswith(prefix) or len(item["surface_id"]) <= len(prefix)
                or item["surface_id"] in identities or type(item["line"]) is not int
                or not 1 <= item["line"] <= raw.count(b"\n") + 1
                or type(item["form"]) is not str or not re.fullmatch(r"[A-Za-z_]+", item["form"])
                or not _roles(item["source_kinds"]) or not _roles(item["hints"])
                or type(item["unresolved_marker"]) is not bool):
            raise ValueError("NAMESPACE_SYSTEMS_SURFACE_DIFFERS")
        identities.add(item["surface_id"])
    for item in row["gaps"]:
        if (type(item) is not dict or set(item) != {"path", "code", "reason"} or item["path"] != path
                or type(item["code"]) is not str or not re.fullmatch(r"NAMESPACE_(?:SYSTEMS|RUST|SHELL)_[A-Z_]+", item["code"])
                or type(item["reason"]) is not str or not item["reason"].strip()):
            raise ValueError("NAMESPACE_SYSTEMS_GAP_DIFFERS")
    if not row["gaps"] and sum(item["form"] == "Module" for item in row["surfaces"]) != 1:
        raise ValueError("NAMESPACE_SYSTEMS_EMPTY_COVERAGE")


def _run(files: list[tuple[str, bytes]], languages: list[str]) -> dict[str, Any]:
    worker = Path(__file__).with_name("namespace_systems_worker.py")
    opening = bytes_digest(worker.read_bytes())
    request = {"schema_version": PROTOCOL, "languages": languages, "files": [
        {"path": path, "source": base64.b64encode(raw).decode("ascii"), "language": SUFFIXES[Path(path).suffix.lower()]}
        for path, raw in files]}
    wire = canonical_bytes(request)
    if len(wire) > LIMIT:
        raise ValueError("NAMESPACE_SYSTEMS_INPUT_CAPACITY")
    result = subprocess.run([sys.executable, "-I", "-B", str(worker)], input=wire,
        capture_output=True, timeout=45, cwd=worker.parent, check=False)
    if len(result.stdout) > LIMIT:
        raise ValueError("NAMESPACE_SYSTEMS_OUTPUT_CAPACITY")
    response = json.loads(result.stdout)
    if (result.returncode or type(response) is not dict or set(response) != {"schema_version", "mechanism", "files"}
            or response["schema_version"] != PROTOCOL or type(response["files"]) is not list
            or len(response["files"]) != len(files)):
        raise ValueError("NAMESPACE_SYSTEMS_PROTOCOL_DIFFERS")
    _check_mechanism(response["mechanism"], languages)
    if bytes_digest(worker.read_bytes()) != opening:
        raise ValueError("NAMESPACE_SYSTEMS_WORKER_CHANGED")
    response["mechanism"]["worker"] = opening
    for (path, raw), row in zip(files, response["files"]):
        _check_file(row, path, raw)
    return response


def discover(files: list[tuple[str, bytes]],
             support_files: list[tuple[str, bytes]] | None = None) -> dict[str, Any]:
    if not files:
        return {"surfaces": [], "gaps": [], "mechanism": None}
    surfaces, gaps, parsers = [], [], {}
    # One absent optional grammar must not erase another installed language's
    # evidence. Each language runs and rebinds its own exact dependency set.
    for language in sorted({SUFFIXES[Path(path).suffix.lower()] for path, _ in files}):
        selected = [(path, raw) for path, raw in files if SUFFIXES[Path(path).suffix.lower()] == language]
        try:
            response = _run(selected, [language])
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
            extra = "discovery-rust" if language == "rust" else "discovery-shell"
            gaps.extend({"path": path, "code": "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED",
                "reason": "Optional parser unavailable (" + type(exc).__name__ + "); install verifier-standard[" + extra
                    + "] in this interpreter. File bytes are not interfaces."} for path, _ in selected)
            continue
        surfaces.extend(row for file in response["files"] for row in file["surfaces"])
        gaps.extend(row for file in response["files"] for row in file["gaps"])
        parsers[language] = response["mechanism"]
    mechanism = {"parsers": parsers} if parsers else None
    if parsers.get("rust") is not None and support_files:
        resolved = namespace_rust_expansions.resolve(files, support_files, surfaces, gaps)
        surfaces, gaps = resolved["surfaces"], resolved["gaps"]
        if resolved["binding"]["bindings"]:
            mechanism["rust_expansion_binding"] = resolved["binding"]
    return {"surfaces": surfaces, "gaps": gaps, "mechanism": mechanism}


def recapture(expected: dict[str, Any] | None) -> None:
    if expected is not None:
        if set(expected) not in ({"parsers"}, {"parsers", "rust_expansion_binding"}):
            raise ValueError("NAMESPACE_SYSTEMS_MECHANISM_CHANGED")
        for language, mechanism in expected["parsers"].items():
            if canonical_bytes(_run([], [language])["mechanism"]) != canonical_bytes(mechanism):
                raise ValueError("NAMESPACE_SYSTEMS_MECHANISM_CHANGED")
        if "rust_expansion_binding" in expected:
            namespace_rust_expansions.validate(expected["rust_expansion_binding"])


def next_action(code: str, path: str) -> str:
    """Name the missing evidence instead of suggesting parser success is closure."""
    actions = {
        "NAMESPACE_RUST_EXPANSION_UNRESOLVED": "Bind generated interfaces to exact macro/build inputs, toolchain and feature selection",
        "NAMESPACE_RUST_MODULE_UNRESOLVED": "Bind the out-of-line module to its exact source and feature selection",
        "NAMESPACE_RUST_EXPORTS_UNRESOLVED": "Resolve every re-export target and wildcard against exact dependency/feature inputs",
        "NAMESPACE_SHELL_DYNAMIC_SURFACES_UNRESOLVED": "Bind dynamic command, sourced-file and alias targets without executing untrusted discovery code",
        "NAMESPACE_SHELL_DIALECT_UNRESOLVED": "Select and evidence the actual shell dialect; Bash parsing does not establish another interpreter's interfaces",
        "NAMESPACE_SYSTEMS_PARSE_UNAVAILABLE": "Repair unsupported or erroneous syntax, or supply a source-bound discovery adapter",
    }
    return actions.get(code, "Install the pinned discovery-rust or discovery-shell extra and rerun discovery") + " for " + path + "; keep unestablished coverage UNKNOWN."
