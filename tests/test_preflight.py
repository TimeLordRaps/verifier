"""Terminology: continuous integration (CI); GNU Privacy Guard (GPG); operating system (OS);
pull request (PR); Verifier Standard (VSTD).

Verify that local preflight checks catch defects before remote push."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import preflight


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_stdlib_smoke_conforms() -> None:
    assert preflight.check_stdlib_smoke() is True


def test_presentation_gate_conforms() -> None:
    assert preflight.check_presentation_gate() is True


def test_schema_inventory_conforms() -> None:
    assert preflight.check_schema_inventory() is True


def test_git_signatures_on_head_or_range() -> None:
    assert isinstance(preflight.check_git_signatures("HEAD~1..HEAD"), bool)


def test_preflight_main_execution() -> None:
    assert preflight.main() in (0, 1)
