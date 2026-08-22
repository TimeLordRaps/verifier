"""Installed specification resources must match the public normative files exactly."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_packaged_specification_bytes_match_normative_sources() -> None:
    for name in ("LADDER.md", "VSTD-3.md", "VSTD-4.md", "WIRE_IDENTIFIERS.md"):
        normative = REPO_ROOT / "standard" / name
        packaged = REPO_ROOT / "src" / "verifiable" / "specifications" / name
        assert packaged.read_bytes() == normative.read_bytes(), name
