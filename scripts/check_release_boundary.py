#!/usr/bin/env python3
"""Fail closed when a release archive contains private or secret-shaped text."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile

from check_presentation import PUBLIC_BOUNDARY_PATTERNS, TEXT_SUFFIXES


METADATA_NAMES = {"METADATA", "PKG-INFO", "entry_points.txt", "top_level.txt"}


def _should_scan(name: str) -> bool:
    path = PurePosixPath(name)
    if path.as_posix().endswith("/scripts/check_presentation.py"):
        # This file is the canonical source of the forbidden-pattern definitions.
        # Scanning the definitions as if they were leaked values is self-matching.
        return False
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in METADATA_NAMES


def _scan_text(artifact: Path, member: str, payload: bytes, errors: list[str]) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"non-UTF-8 text member: {artifact.name}:{member}")
        return
    subject = f"{member}\n{text}"
    for label, pattern in PUBLIC_BOUNDARY_PATTERNS:
        match = pattern.search(subject)
        if match:
            errors.append(
                f"{label} in {artifact.name}:{member}: {match.group(0)!r}"
            )


def _scan_zip(path: Path, errors: list[str]) -> int:
    count = 0
    with zipfile.ZipFile(path) as bundle:
        for info in bundle.infolist():
            if info.is_dir() or not _should_scan(info.filename):
                continue
            _scan_text(path, info.filename, bundle.read(info), errors)
            count += 1
    return count


def _scan_tar(path: Path, errors: list[str]) -> int:
    count = 0
    with tarfile.open(path, "r:gz") as bundle:
        for member in bundle.getmembers():
            if not member.isfile() or not _should_scan(member.name):
                continue
            extracted = bundle.extractfile(member)
            if extracted is None:
                errors.append(f"unreadable text member: {path.name}:{member.name}")
                continue
            _scan_text(path, member.name, extracted.read(), errors)
            count += 1
    return count


def check_artifact(path: Path, errors: list[str]) -> int:
    if path.name.endswith((".zip", ".whl")):
        return _scan_zip(path, errors)
    if path.name.endswith(".tar.gz"):
        return _scan_tar(path, errors)
    raise ValueError(f"unsupported release artifact: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args(argv)

    errors: list[str] = []
    scanned = 0
    for artifact in args.artifacts:
        if not artifact.is_file():
            errors.append(f"release artifact does not exist: {artifact}")
            continue
        try:
            scanned += check_artifact(artifact, errors)
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
            errors.append(str(exc))

    if errors:
        for error in errors:
            print(f"[BOUNDARY FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[BOUNDARY OK] scanned {scanned} text members in {len(args.artifacts)} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
