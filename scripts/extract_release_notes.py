#!/usr/bin/env python3
"""Extract one exact, dated release section from the project changelog."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

try:
    from scripts.classify_release_version import classify_release_version
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from classify_release_version import classify_release_version


class ReleaseNotesError(ValueError):
    """Raised when an exact nonempty release section cannot be selected."""


def extract_release_notes(changelog: str, version: str) -> str:
    """Return the nonempty body under one exact semantic-version heading."""

    try:
        classify_release_version(version)
    except ValueError:
        raise ReleaseNotesError(f"invalid release version {version!r}")
    matches = re.findall(
        rf"^## {re.escape(version)} - \d{{4}}-\d{{2}}-\d{{2}}\s*$\n"
        r"(.*?)(?=^## |\Z)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    if len(matches) != 1:
        raise ReleaseNotesError(
            f"expected one dated changelog section for {version}, found {len(matches)}"
        )
    body = matches[0].strip()
    if not body:
        raise ReleaseNotesError(f"changelog section for {version} is empty")
    return body + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    args = parser.parse_args(argv)
    try:
        notes = extract_release_notes(
            args.changelog.read_text(encoding="utf-8"),
            args.version,
        )
    except (OSError, UnicodeError, ReleaseNotesError) as exc:
        print(f"[RELEASE NOTES INVALID] {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
