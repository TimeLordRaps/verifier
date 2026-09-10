#!/usr/bin/env python3
"""Render bounded skipped-test evidence from a Java unit test report format document."""

from __future__ import annotations

import argparse
import html
from pathlib import Path
import re
import xml.etree.ElementTree as ET


MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_SKIPPED_ROWS = 500
MAX_FIELD_CHARACTERS = 500
MAX_OUTPUT_CHARACTERS = 300_000
MARKDOWN_PUNCTUATION = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|])")


def _bounded_markdown(value: str, *, field: str) -> str:
    normalized = " ".join(value.split())
    if len(normalized) > MAX_FIELD_CHARACTERS:
        raise ValueError(f"{field} exceeds {MAX_FIELD_CHARACTERS} characters")
    return MARKDOWN_PUNCTUATION.sub(r"\\\1", html.escape(normalized, quote=True))


def skip_rows(path: Path) -> list[tuple[str, str]]:
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"test report exceeds {MAX_REPORT_BYTES} bytes")
    root = ET.parse(path).getroot()
    rows: list[tuple[str, str]] = []
    for case in root.findall(".//testcase"):
        skipped = case.find("skipped")
        if skipped is None:
            continue
        location = "::".join(
            part for part in (case.get("classname", ""), case.get("name", "")) if part
        )
        reason = skipped.get("message") or (skipped.text or "").strip() or "reason unavailable"
        rows.append(
            (
                _bounded_markdown(location or "unknown test", field="test location"),
                _bounded_markdown(reason, field="skip reason"),
            )
        )
        if len(rows) > MAX_SKIPPED_ROWS:
            raise ValueError(f"test report exceeds {MAX_SKIPPED_ROWS} skipped rows")
    return rows


def render(path: Path, *, coordinate: str) -> str:
    rows = skip_rows(path)
    safe_coordinate = _bounded_markdown(coordinate, field="coordinate")
    lines = [f"### Skipped tests: {safe_coordinate}", ""]
    if not rows:
        lines.append("No skipped tests were reported.")
    else:
        lines.extend(f"- {location} — {reason}" for location, reason in rows)
    rendered = "\n".join(lines) + "\n"
    if len(rendered) > MAX_OUTPUT_CHARACTERS:
        raise ValueError(f"skip summary exceeds {MAX_OUTPUT_CHARACTERS} characters")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--coordinate", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--append-output", type=Path)
    args = parser.parse_args(argv)
    if args.output is not None and args.append_output is not None:
        parser.error("--output and --append-output are mutually exclusive")
    try:
        summary = render(args.report, coordinate=args.coordinate)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(f"[SKIP SUMMARY FAIL] {exc}")
        return 1
    if args.output is None:
        if args.append_output is None:
            print(summary, end="")
        else:
            with args.append_output.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(summary)
    else:
        args.output.write_text(summary, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
