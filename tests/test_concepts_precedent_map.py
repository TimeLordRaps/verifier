"""Keep the concept guide's reference map consistent with its own warning.

The guide closes with a warning against claiming that the project implements a list of
named precedents.  Every precedent in that list must have a row in the primary reference
map.  Without this check a row can be displaced by an unrelated edit and nothing fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "CONCEPTS_AND_PRECEDENTS.md"
MAP_HEADING = "## Primary reference map"
WARNING = re.compile(
    r'implements\s+(?P<names>[^"]+?),"\s+unless\s+separately\s+demonstrated', re.DOTALL
)


def _named_precedents(text: str) -> list[str]:
    match = WARNING.search(text)
    assert match is not None, "the implementation-claim warning was not found in the guide"
    names = " ".join(match.group("names").split())
    return [name for name in re.split(r",\s*(?:or\s+)?", names) if name]


def _map_span(lines: list[str]) -> tuple[int, int]:
    assert lines.count(MAP_HEADING) == 1, "the guide must contain one primary reference map"
    start = lines.index(MAP_HEADING) + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    return start, end


def _map_rows(text: str) -> list[str]:
    lines = text.splitlines()
    start, end = _map_span(lines)
    rows = [line for line in lines[start:end] if line.startswith("|")]
    assert len(rows) > 2, "the primary reference map has no data rows"
    return rows


def missing_from_map(text: str) -> list[str]:
    """Return the precedents named in the warning that no map row mentions."""
    rows = _map_rows(text)
    return [
        name
        for name in _named_precedents(text)
        if not any(
            re.search(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", row)
            for row in rows
        )
    ]


def _without_map_row(text: str, marker: str) -> str:
    lines = text.splitlines()
    start, end = _map_span(lines)
    hits = [i for i in range(start, end) if lines[i].startswith("|") and marker in lines[i]]
    assert len(hits) == 1, "the marker must identify exactly one map row"
    del lines[hits[0]]
    return "\n".join(lines)


def _guide(rows: list[str], warning_names: str = "Alpha, Beta, or Gamma Delta") -> str:
    table = "\n".join(["| seam | reference |", "| --- | --- |", *rows])
    return (
        f"## Primary reference map\n\n{table}\n\n## Next\n\n"
        f'- "The project implements {warning_names},"\n  unless separately demonstrated.\n'
    )


def test_every_precedent_named_in_the_warning_has_a_map_row() -> None:
    assert missing_from_map(GUIDE.read_text(encoding="utf-8")) == []


def test_named_precedents_are_read_from_the_warning() -> None:
    names = _named_precedents(GUIDE.read_text(encoding="utf-8"))
    assert len(names) >= 5
    assert "Certificate Transparency" in names
    assert "Common Criteria" in names


def test_dropping_the_row_that_cites_a_named_precedent_is_detected() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    mutated = _without_map_row(text, "rfc9162.html")
    assert set(missing_from_map(mutated)) - set(missing_from_map(text)) == {
        "Certificate Transparency"
    }


def test_synthetic_guide_reports_exactly_the_unmapped_names() -> None:
    rows = ["| one | Alpha specification |", "| two | Beta report |"]
    assert missing_from_map(_guide(rows)) == ["Gamma Delta"]
    assert missing_from_map(_guide([*rows, "| three | Gamma Delta standard |"])) == []


def test_names_match_whole_tokens_with_case() -> None:
    assert missing_from_map(_guide(["| one | qxzzy notes |"], "QXZ")) == ["QXZ"]
    assert missing_from_map(_guide(["| one | QXZY notes |"], "QXZ")) == ["QXZ"]
    assert missing_from_map(_guide(["| one | QXZ-1 notes |"], "QXZ")) == []


def test_a_missing_warning_or_map_fails_closed() -> None:
    guide = _guide(["| one | Alpha specification |"])
    with pytest.raises(AssertionError):
        missing_from_map(guide.replace("unless separately demonstrated", "unless shown"))
    with pytest.raises(AssertionError):
        missing_from_map(guide.replace(MAP_HEADING, "## Reference map"))
