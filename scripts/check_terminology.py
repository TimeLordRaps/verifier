#!/usr/bin/env python3
"""Terminology: Verifier Standard (VSTD).

Reject prose that treats numbered VSTD profiles as interchangeable layers or
scalar levels. Public compatibility identifiers remain unchanged and are not
matched by this prose-focused gate.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cff",
    ".html",
    ".json",
    ".md",
    ".py",
    ".svg",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
IGNORED_PARTS = {
    ".git",
    ".pytest_cache",
    ".venv",
    "build",
    "dist",
    "__pycache__",
}
GENERATED_PREFIXES = (
    "examples/flagship_demo/specimens/",
    "src/verifier/specifications/",
)
SCAN_EXCLUSIONS = {
    "examples/zizk_artifact_first/zero_identity/ROUND1_ZERO_IDENTITY_REPORT.md",
    "experiments/artifact_first_mechanisms/reverification/ROUND2_DESIGN_NOTE.md",
    "tests/test_presentation_surface.py",
}
AMBIGUOUS_PATTERNS = (
    ("VSTD profiles called layers", re.compile(r"(?i)\bVSTD\s+layers?\b")),
    ("object profiles called layers", re.compile(r"(?i)\bobject\s+layers?\b")),
    ("Graph profiles called layers", re.compile(r"(?i)\bGraph\s+layers?\b")),
    ("Graph profile called a level", re.compile(r"(?i)\bGraph\s+levels?\b")),
    (
        "candidate Graph profile called a level",
        re.compile(r"(?i)\bcandidate\s+graph\s+levels?\b"),
    ),
    ("profile dependency called lower-layer", re.compile(r"(?i)\blower[- ]layers?\b")),
    ("profile dependency called higher-layer", re.compile(r"(?i)\bhigher[- ]layers?\b")),
    ("numbered profile called a layer", re.compile(r"(?i)\bnumbered\s+layers?\b")),
    ("profile result called a layer result", re.compile(r"(?i)\blayer\s+results?\b")),
    (
        "profile conformance called layer conformance",
        re.compile(r"(?i)\blayer\s+conformance\b"),
    ),
    ("verification complex called a VSTD ladder", re.compile(r"(?i)\bVSTD\s+ladder\b")),
    ("VSTD-4 rung called a ladder rung", re.compile(r"(?i)\bladder\s+rungs?\b")),
    ("VSTD-4 depth left unqualified", re.compile(r"(?i)\bVSTD-4\s+depth\b")),
    (
        "VSTD-4 candidate depth inverted into a structural depth candidate",
        re.compile(r"(?i)\bstructural\s+depth\s+candidate\b"),
    ),
)


def terminology_violations(text: str) -> list[tuple[str, int]]:
    """Return ambiguous phrase labels and one-based line numbers."""

    violations: list[tuple[str, int]] = []
    for label, pattern in AMBIGUOUS_PATTERNS:
        for match in pattern.finditer(text):
            violations.append((label, text.count("\n", 0, match.start()) + 1))
    return violations


def _tracked_text_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths: list[Path] = []
    for raw_relative in result.stdout.decode("utf-8").split("\0"):
        if not raw_relative:
            continue
        relative = Path(raw_relative).as_posix()
        path = ROOT / raw_relative
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in IGNORED_PARTS for part in Path(relative).parts):
            continue
        if relative == "scripts/check_terminology.py":
            continue
        if relative in SCAN_EXCLUSIONS:
            continue
        if relative.startswith(GENERATED_PREFIXES):
            continue
        paths.append(path)
    return sorted(paths)


def validate_repo() -> list[str]:
    """Validate current source surfaces; generated copies are checked elsewhere."""

    errors: list[str] = []
    for path in _tracked_text_files():
        text = path.read_text(encoding="utf-8")
        for label, line in terminology_violations(text):
            errors.append(f"{label} in {path.relative_to(ROOT)}:{line}")
    return errors


def main() -> int:
    errors = validate_repo()
    if errors:
        for error in errors:
            print(f"[TERMINOLOGY FAIL] {error}")
        return 1
    print("[TERMINOLOGY OK] numbered profiles and closure coordinates remain distinct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
