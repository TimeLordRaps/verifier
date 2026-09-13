"""Tests for bounded skipped-test summaries."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _module():
    path = ROOT / "scripts" / "summarize_test_skips.py"
    spec = importlib.util.spec_from_file_location("summarize_test_skips", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_skip_summary_preserves_test_and_reason(tmp_path: Path) -> None:
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_one" name="test_case">'
        '<skipped message="capability unavailable" />'
        "</testcase><testcase classname=\"tests.test_one\" name=\"test_pass\" />"
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    rendered = _module().render(report, coordinate="windows-3.12")
    assert "tests\\.test\\_one::test\\_case" in rendered
    assert "capability unavailable" in rendered
    assert "test_pass" not in rendered


def test_skip_summary_states_when_no_tests_skipped(tmp_path: Path) -> None:
    report = tmp_path / "report.xml"
    report.write_text("<testsuite><testcase name=\"test_pass\" /></testsuite>", encoding="utf-8")
    assert "No skipped tests were reported." in _module().render(
        report, coordinate="linux-3.12"
    )


def test_skip_summary_escapes_markdown_and_newlines(tmp_path: Path) -> None:
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuite><testcase classname="evil`|name" name="case">'
        '<skipped message="line one&#10;## injected [link](https://evil.example)" />'
        "</testcase></testsuite>",
        encoding="utf-8",
    )
    rendered = _module().render(report, coordinate="windows|injected")
    assert "\n## injected" not in rendered
    assert "\\|" in rendered
    assert "\\[link\\]\\(https://evil\\.example\\)" in rendered


def test_skip_summary_rejects_oversized_report(tmp_path: Path) -> None:
    module = _module()
    module.MAX_REPORT_BYTES = 8
    report = tmp_path / "report.xml"
    report.write_text("<testsuite />", encoding="utf-8")
    with pytest.raises(ValueError, match="report exceeds"):
        module.render(report, coordinate="linux")


def test_skip_summary_rejects_excessive_rows(tmp_path: Path) -> None:
    module = _module()
    module.MAX_SKIPPED_ROWS = 1
    report = tmp_path / "report.xml"
    report.write_text(
        "<testsuite>"
        '<testcase name="one"><skipped message="reason" /></testcase>'
        '<testcase name="two"><skipped message="reason" /></testcase>'
        "</testsuite>",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="skipped rows"):
        module.render(report, coordinate="linux")


def test_cli_appends_utf8_without_shell_redirection(tmp_path: Path) -> None:
    module = _module()
    report = tmp_path / "report.xml"
    report.write_text(
        '<testsuite><testcase name="case"><skipped message="café" /></testcase></testsuite>',
        encoding="utf-8",
    )
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"existing\n")
    assert module.main(
        [str(report), "--coordinate", "windows", "--append-output", str(summary)]
    ) == 0
    assert summary.read_bytes().startswith(b"existing\n### Skipped tests")
    assert "café" in summary.read_text(encoding="utf-8")
