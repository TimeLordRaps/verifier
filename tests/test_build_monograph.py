"""Check lossless Verifier Standard (VSTD) monograph layout transformations."""

from __future__ import annotations

import pytest

from scripts.build_monograph import clean_markdown_for_pandoc


def test_chapter_keeps_contiguous_section_depth() -> None:
    result = clean_markdown_for_pandoc("# Original\n\n## Section\n\n### Detail\n", "Chapter")
    assert result == "# Chapter\n\n## Section\n\n### Detail\n"


def test_table_records_preserve_cells_and_line_breaks() -> None:
    result = clean_markdown_for_pandoc(
        "| Name | Evidence |\n|---|---|\n| alpha | first<br>second |\n"
        "| beta | left\\|right |\n", "Chapter"
    )
    assert "**Name:** alpha" in result
    assert "**Evidence:** first; second" in result
    assert "**Name:** beta" in result
    assert "**Evidence:** left\\|right" in result


def test_malformed_table_never_silently_discards_a_cell() -> None:
    with pytest.raises(ValueError, match="column headings"):
        clean_markdown_for_pandoc("| Name |\n|---|\n| alpha | lost |\n", "Chapter")


def test_long_literal_breaks_retain_exact_characters() -> None:
    digest = "0123456789abcdef" * 4
    result = clean_markdown_for_pandoc(f"`{digest}`", "Chapter")
    assert result.replace(r"\allowbreak{}", "") == f"# Chapter\n\n\\texttt{{{digest}}}\n"
