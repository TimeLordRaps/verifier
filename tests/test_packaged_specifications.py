"""Terminology: Verifier Standard (VSTD).

Installed specification resources must match the public normative files exactly."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_packaged_specification_bytes_match_normative_sources() -> None:
    for name in ("LADDER.md", "VSTD-3.md", "VSTD-4.md", "WIRE_IDENTIFIERS.md"):
        normative = REPO_ROOT / "standard" / name
        packaged = REPO_ROOT / "src" / "verifier" / "specifications" / name
        assert packaged.read_bytes() == normative.read_bytes(), name


def test_ladder_fixes_both_causal_directions_without_actor_trust() -> None:
    ladder = (REPO_ROOT / "standard" / "LADDER.md").read_text(encoding="utf-8")
    assert "parent artifact --bounded positive support--> child" in ladder
    assert "child Rust      --genetic causal backtrace--> ancestor" in ladder
    assert "MUST NOT\nstrengthen a result" in ladder
    assert "They do not cancel, form one\nscalar score" in ladder
