#!/usr/bin/env python3
"""Classify a supported package version as a stable release or prerelease."""

from __future__ import annotations

import argparse
import re


SUPPORTED_RELEASE_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:(a|b|rc)(?:0|[1-9][0-9]*))?"
)


def classify_release_version(version: str) -> str:
    """Return the GitHub release kind for one supported package version."""

    match = SUPPORTED_RELEASE_VERSION.fullmatch(version)
    if match is None:
        raise ValueError(f"unsupported release version: {version!r}")
    return "prerelease" if match.group(1) is not None else "stable"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    arguments = parser.parse_args(argv)
    try:
        release_kind = classify_release_version(arguments.version)
    except ValueError as exc:
        parser.error(str(exc))
    print(release_kind)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
