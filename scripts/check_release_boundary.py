#!/usr/bin/env python3
"""Terminology: Extensible Markup Language (XML); JavaScript Object Notation (JSON);
Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD).

Reject prohibited text patterns in release artifacts without echoing matches."""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from io import StringIO
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile

from check_presentation import PUBLIC_BOUNDARY_PATTERNS, TEXT_SUFFIXES, public_boundary_violations


METADATA_NAMES = {"metadata", "pkg-info", "entry_points.txt", "top_level.txt"}
TEXT_BASENAMES = frozenset({
    "authors",
    "copying",
    "dockerfile",
    "license",
    "makefile",
    "notice",
})
RELEASE_TEXT_SUFFIXES = frozenset(
    TEXT_SUFFIXES
    | {
        ".xml",
        ".pem",
        ".key",
        ".env",
        ".cfg",
        ".ini",
        ".sh",
        ".bash",
        ".csv",
        ".tsv",
        ".rst",
        ".conf",
        ".properties",
        ".log",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".ps1",
        ".psm1",
        ".psd1",
        ".bat",
        ".cmd",
        ".tex",
        ".json5",
        ".jsonc",
    }
)
# Operational admission bounds, not a claim that larger artifacts are unsafe.
# Apply the byte bound before decompression/reading and again on actual bytes.
# Structural bounds apply before JSON allocation; strings do not count as nesting.
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_STRUCTURE_TOKENS = 100_000


def _should_scan(name: str) -> bool:
    path = PurePosixPath(name)
    if path.as_posix().endswith("/scripts/check_presentation.py"):
        # This file is the canonical source of the forbidden-pattern definitions.
        # Scanning the definitions as if they were leaked values is self-matching.
        return False
    name_lower = path.name.lower()
    return (
        path.suffix.lower() in RELEASE_TEXT_SUFFIXES
        or name_lower in TEXT_BASENAMES
        or name_lower in METADATA_NAMES
        or name_lower == ".env"
        or name_lower.startswith(".env.")
    )


def _location(artifact: Path, member: str) -> str:
    location = f"{artifact.name}:{member}" if member else artifact.name
    if any(public_boundary_violations(part) for part in (artifact.name, member, location)):
        return "<redacted archive member>"
    return location


def _size_rejected(artifact: Path, member: str, size: int, errors: list[str]) -> bool:
    if size > MAX_TEXT_BYTES:
        errors.append(f"text member exceeds size limit: {_location(artifact, member)}")
        return True
    return False


def _check_json_structure(text: str) -> None:
    quoted = escaped = False
    depth = tokens = 0
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "{}[],:":
            tokens += 1
            if character in "{[":
                depth += 1
            elif character in "}]":
                depth -= 1
            if depth > MAX_JSON_DEPTH or tokens > MAX_JSON_STRUCTURE_TOKENS:
                raise ValueError("JSON structure limit exceeded")


def _reject_constant(value: str) -> None:
    raise ValueError("non-JSON numeric constant")


def _json_strings(text: str) -> Iterator[str]:
    _check_json_structure(text)
    # Keep every object pair: a later duplicate key must not erase a leak.
    # Numeric values cannot contain paths; retain no potentially enormous integer.
    root = json.loads(
        text, object_pairs_hook=list, parse_int=lambda value: None,
        parse_float=lambda value: None, parse_constant=_reject_constant,
    )
    stack = [iter((root,))]
    while stack:
        try:
            value = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(value, str):
            yield value
        elif isinstance(value, (list, tuple)):
            stack.append(iter(value))


def _scan_text(artifact: Path, member: str, payload: bytes, errors: list[str]) -> None:
    location = _location(artifact, member)
    if _size_rejected(artifact, member, len(payload), errors):
        return
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"non-UTF-8 text member: {location}")
        return
    labels = set(public_boundary_violations(member))
    labels.update(public_boundary_violations(text))
    suffix = PurePosixPath(member).suffix.lower()
    if suffix in {".json", ".jsonl"}:
        try:
            # JSON Lines (JSONL) stores one JSON document per line. Iteration
            # avoids allocating a separate list of every record before parsing.
            documents = StringIO(text) if suffix == ".jsonl" else (text,)
            for document in documents:
                for value in _json_strings(document):
                    labels.update(public_boundary_violations(value))
        except (ValueError, RecursionError):
            # Parser exception text includes source excerpts; never echo it.
            errors.append(f"malformed JSON or JSON structure limit exceeded: {location}")
            return
    if suffix == ".xml":
        # Reject document declarations before parsing, and check decoded values
        # too: numeric character references must not hide prohibited content.
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            errors.append(f"XML declarations are not supported: {location}")
            return
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            errors.append(f"malformed XML member: {location}")
            return
        subjects = ["".join(root.itertext())]
        for element in root.iter():
            subjects.append(element.tag)
            subjects.extend(element.attrib.keys())
            subjects.extend(element.attrib.values())
        for subject in subjects:
            labels.update(public_boundary_violations(subject))
    for label, _pattern in PUBLIC_BOUNDARY_PATTERNS:
        if label in labels:
            # Diagnostics may enter public build logs; never echo matched bytes.
            errors.append(f"{label} in {location}")


def _scan_zip(path: Path, errors: list[str]) -> int:
    count = 0
    with zipfile.ZipFile(path) as bundle:
        for info in bundle.infolist():
            if info.is_dir() or not _should_scan(info.filename):
                continue
            count += 1
            if _size_rejected(path, info.filename, info.file_size, errors):
                continue
            with bundle.open(info) as stream:
                _scan_text(path, info.filename, stream.read(MAX_TEXT_BYTES + 1), errors)
    return count


def _scan_tar(path: Path, errors: list[str]) -> int:
    count = 0
    with tarfile.open(path, "r:gz") as bundle:
        for member in bundle:
            if not member.isfile() or not _should_scan(member.name):
                continue
            count += 1
            if _size_rejected(path, member.name, member.size, errors):
                continue
            extracted = bundle.extractfile(member)
            if extracted is None:
                errors.append(f"unreadable text member: {_location(path, member.name)}")
                continue
            with extracted:
                _scan_text(path, member.name, extracted.read(MAX_TEXT_BYTES + 1), errors)
    return count


def check_artifact(path: Path, errors: list[str]) -> int:
    if path.name.endswith((".zip", ".whl")):
        return _scan_zip(path, errors)
    if path.name.endswith(".tar.gz"):
        return _scan_tar(path, errors)
    if path.suffix.lower() in {".json", ".xml"}:
        if not _size_rejected(path, path.name, path.stat().st_size, errors):
            with path.open("rb") as stream:
                _scan_text(path, path.name, stream.read(MAX_TEXT_BYTES + 1), errors)
        return 1
    raise ValueError(f"unsupported release artifact: {_location(path, '')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args(argv)

    errors: list[str] = []
    scanned = 0
    for artifact in args.artifacts:
        try:
            if not artifact.is_file():
                errors.append(f"release artifact does not exist: {_location(artifact, '')}")
                continue
            scanned += check_artifact(artifact, errors)
        except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
            errors.append(
                f"cannot scan release artifact ({type(exc).__name__}): {_location(artifact, '')}"
            )

    if errors:
        for error in errors:
            print(f"[BOUNDARY FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[BOUNDARY OK] scanned {scanned} text members in {len(args.artifacts)} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
