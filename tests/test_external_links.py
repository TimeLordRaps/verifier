"""Tests for the external Hypertext Transfer Protocol (HTTP) link audit."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_external_links.py"
SPEC = importlib.util.spec_from_file_location("check_external_links", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
external_links = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = external_links
SPEC.loader.exec_module(external_links)


def test_collect_links_deduplicates_and_removes_fragments(tmp_path: Path) -> None:
    markdown = tmp_path / "guide.md"
    markdown.write_text(
        "[one](https://example.com/path#one) [two](https://example.com/path#two)\n",
        encoding="utf-8",
    )
    html = tmp_path / "guide.html"
    html.write_text('<a href="https://example.org/page">page</a>', encoding="utf-8")

    assert external_links.collect_links((markdown, html)) == (
        "https://example.com/path",
        "https://example.org/page",
    )


def test_allowlist_requires_a_reviewable_reason(tmp_path: Path) -> None:
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("https://example.com/*\n", encoding="utf-8")

    with pytest.raises(ValueError, match="needs a tab and reason"):
        external_links.read_allowlist(allowlist)


def test_allowlist_matches_only_exact_or_declared_prefix() -> None:
    entries = (("https://example.com/bounded/*", "upstream blocks probes"),)

    assert external_links.allowlist_reason(
        "https://example.com/bounded/page", entries
    ) == "upstream blocks probes"
    assert external_links.allowlist_reason("https://example.com/other", entries) is None


def test_external_audit_is_scheduled_and_not_a_pull_request_gate() -> None:
    workflow = (ROOT / ".github/workflows/external-links.yml").read_text(encoding="utf-8")
    entries = external_links.read_allowlist(
        ROOT / ".github/external-links-allowlist.txt"
    )

    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "--retries 2 --workers 8" in workflow
    assert entries
    assert all(reason for _, reason in entries)
