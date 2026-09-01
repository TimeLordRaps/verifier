#!/usr/bin/env python3
"""Require finalized, internally consistent metadata before tag publication."""

from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def _single(pattern: str, text: str, label: str) -> str:
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"{label} must appear exactly once; observed {len(matches)}")
    return str(matches[0])


def require_finalized(root: Path, version: str) -> None:
    """Reject release-candidate or inconsistent metadata for ``version``."""

    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    project = pyproject.split("[project]", 1)
    project_text = "" if len(project) != 2 else project[1].split("\n[", 1)[0]
    package_version = _single(
        r'^version\s*=\s*"([^"]+)"$', project_text, "pyproject [project] version"
    )
    if package_version != version:
        raise ValueError(
            f"release version {version} does not match package version {package_version}"
        )

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if re.search(
        rf"^## {re.escape(version)} - UNRELEASED$", changelog, re.MULTILINE
    ):
        raise ValueError(f"CHANGELOG {version} is still UNRELEASED")
    release_date = _single(
        rf"^## {re.escape(version)} - (\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        f"dated CHANGELOG {version} heading",
    )
    try:
        date.fromisoformat(release_date)
    except ValueError as exc:
        raise ValueError(f"CHANGELOG release date is invalid: {release_date}") from exc

    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    citation_version = _single(
        r"^version:\s*([^\s]+)$", citation, "CITATION version"
    )
    citation_date = _single(
        r"^date-released:\s*(\d{4}-\d{2}-\d{2})$",
        citation,
        "CITATION date-released",
    )
    if citation_version != version or citation_date != release_date:
        raise ValueError(
            "CITATION version/date must match the package and CHANGELOG release coordinate"
        )
    if "release candidate" in citation.lower():
        raise ValueError("CITATION still describes a release candidate")

    zenodo = json.loads((root / ".zenodo.json").read_text(encoding="utf-8"))
    if zenodo.get("version") != version:
        raise ValueError("Zenodo version does not match the release coordinate")
    if zenodo.get("publication_date") != release_date:
        raise ValueError(
            "Zenodo publication_date must match the CHANGELOG release date"
        )
    description = str(zenodo.get("description", "")).lower()
    if "release-candidate" in description or "after the release exists" in description:
        raise ValueError("Zenodo metadata still describes an unpublished candidate")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        require_finalized(args.root, args.version)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"[RELEASE METADATA BLOCKED] {exc}", file=sys.stderr)
        return 1
    print(f"[RELEASE METADATA FINAL] {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
