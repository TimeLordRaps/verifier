#!/usr/bin/env python3
"""Terminology: Verifier Standard (VSTD).

Enforce newcomer-readable acronym expansion across Verifier Standard (VSTD) prose."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
GLOSSARY = ROOT / "docs" / "ACRONYMS.md"
GLOSSARY_ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+?) \|", re.MULTILINE)
SOURCE_SUFFIXES = {".py", ".rs", ".sh"}
DOCUMENT_SUFFIXES = {".cff", ".html", ".md", ".svg"}
IGNORED_PARTS = {".git", ".pytest_cache", ".venv", "build", "dist", "__pycache__"}


def load_expansions() -> dict[str, str]:
    """Read the one canonical acronym key used by prose and the checker."""

    text = GLOSSARY.read_text(encoding="utf-8")
    expansions = {term: expansion.strip() for term, expansion in GLOSSARY_ROW.findall(text)}
    if not expansions or "VSTD" not in expansions:
        raise ValueError("docs/ACRONYMS.md has no parseable VSTD expansion table")
    return expansions


def _is_schema(path: Path) -> bool:
    relative = path.relative_to(ROOT).as_posix()
    return (
        relative.startswith("receipts/schema/") and path.suffix == ".json"
    ) or relative.endswith(".schema.json")


def _is_issue_form(path: Path) -> bool:
    relative = path.relative_to(ROOT).as_posix()
    return relative.startswith(".github/ISSUE_TEMPLATE/") and path.suffix in {".yml", ".yaml"}


def public_reader_files() -> list[Path]:
    """Return standalone prose and source surfaces, excluding generated dependency data."""

    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(
            part in IGNORED_PARTS for part in path.relative_to(ROOT).parts
        ):
            continue
        if path == GLOSSARY:
            continue
        if (
            path.suffix.lower() in SOURCE_SUFFIXES | DOCUMENT_SUFFIXES
            or _is_schema(path)
            or _is_issue_form(path)
            or path.name == ".zenodo.json"
        ):
            files.append(path)
    return sorted(files)


def _term_pattern(term: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])"
    )


def _definition_pattern(expansion: str, term: str) -> re.Pattern[str]:
    """Match a definition even when Markdown wraps it across physical lines."""

    words = re.split(r"\s+", expansion.strip())
    expanded = r"\s+".join(re.escape(word) for word in words)
    return re.compile(rf"{expanded}\s+\({re.escape(term)}\)")


def _required_terms(text: str, expansions: dict[str, str]) -> set[str]:
    return {
        term for term in expansions if _term_pattern(term).search(text) is not None
    }


def validate_repo() -> list[str]:
    """Return every missing or late first-use expansion."""

    expansions = load_expansions()
    errors: list[str] = []
    for path in public_reader_files():
        text = path.read_text(encoding="utf-8")
        for term in sorted(_required_terms(text, expansions)):
            definition = f"{expansions[term]} ({term})"
            definition_match = _definition_pattern(expansions[term], term).search(text)
            definition_at = -1 if definition_match is None else definition_match.start()
            first = _term_pattern(term).search(text)
            if definition_at < 0:
                errors.append(
                    f"{path.relative_to(ROOT).as_posix()}: {term} is not expanded as "
                    f"{definition!r}"
                )
            elif first is not None and definition_at > first.start():
                line = text.count("\n", 0, first.start()) + 1
                errors.append(
                    f"{path.relative_to(ROOT).as_posix()}:{line}: {term} appears before "
                    "its expansion"
                )
    return errors


def main() -> int:
    errors = validate_repo()
    if errors:
        for error in errors:
            print(f"[ACRONYM FAIL] {error}", file=sys.stderr)
        return 1
    print("[ACRONYM OK] registered terms are expanded at first use")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
