"""A short drive component is still absolute; portable controls remain usable."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def presentation():
    spec = importlib.util.spec_from_file_location("short_drive_review", ROOT / "scripts/check_presentation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_one_character_first_component_is_still_drive_qualified(presentation):
    value = "C:" + "/x/private"
    assert "drive-qualified local path" in presentation.public_boundary_violations(value)


@pytest.mark.parametrize("value", ["https://example.invalid/x/private", "x/private"])
def test_portable_reference_controls(presentation, value):
    assert presentation.public_boundary_violations(value) == []


def test_short_directory_with_windows_separators(presentation):
    value = "C:" + chr(92) + "x" + chr(92) + "private"
    assert "drive-qualified local path" in presentation.public_boundary_violations(value)


@pytest.mark.parametrize("escape", ["n", "r", "t"])
def test_escaped_python_line_is_not_a_drive_path(presentation, escape):
    value = "with open(filename) as f:" + chr(92) + escape
    assert presentation.public_boundary_violations(value) == []
