#!/usr/bin/env python3
"""Build the Verifier Standard (VSTD) monograph in Portable Document Format (PDF).

Concatenates the newcomer guide, two-axis ladder, architecture, claims/limits,
conceptual precedents, and platform interoperability specifications into a single
cohesive research monograph: paper/vstd_monograph.pdf.

Requires pandoc and pdflatex on PATH.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "paper"

CHAPTER_SOURCES = [
    ("Orientation, Seven Domain Lenses, and First Principles", ROOT / "docs" / "NEWCOMER_GUIDE.md"),
    ("The Two-Axis Profile Taxonomy (LADDER)", ROOT / "src/verifier/standard" / "LADDER.md"),
    ("Grounded Certification Contracts and Mechanism Boundaries", ROOT / "src/verifier/standard" / "GROUNDED_CERTIFICATION.md"),
    ("Version 2 Candidate Scope and Release Boundaries", ROOT / "docs" / "V2_CANDIDATE.md"),
    ("Formal System Architecture and Kernel Isolation", ROOT / "docs" / "ARCHITECTURE.md"),
    ("Claims, Limits, Boundaries, and Refutation Mechanics", ROOT / "docs" / "CLAIMS_AND_LIMITS.md"),
    ("Conceptual Foundations, Precedents, and Adjacent Standards", ROOT / "docs" / "CONCEPTS_AND_PRECEDENTS.md"),
    ("Platform Interoperability and Hardware Envelopes", ROOT / "docs" / "PLATFORM_INTEROPERABILITY.md"),
]

MONOGRAPH_METADATA = """---
title: "The Verifier Standard (VSTD): A Verification Domain Language and Two-Axis Reference Architecture for Portable Computational Evidence"
subtitle: "Foundational Monograph on Bounded Refutable Proofs, Closure Coordinates, and Superintelligence Oracle Stratification"
author: "Tyler Roost"
date: "Preprint, version 2.0.0 release candidate --- UNRELEASED"
abstract: "The Verifier Standard (VSTD) is a verification domain language and reference architecture for portable, bounded, refutable evidence about computational claims. Operating along two orthogonal axes---VSTD-1..5 for single-object mechanics and GRAPH-1..5 for dynamic collection dynamics---VSTD standardizes claim boundaries and portable result semantics across domain verifiers without replacing their native execution engines. The central impetus of the standard is to discover routes toward definably complete representations capable of handling hypercomputation-like oracle classes expected of superintelligences, organizing recursive reflection and verification stages into well-founded transfinite strata without collapsing into unearned assurance, self-observational bias, or semantic ambiguity."
geometry: "margin=1in"
toc: true
toc-depth: 2
numbersections: true
colorlinks: true
linkcolor: blue
urlcolor: blue
toccolor: black
documentclass: report
---
"""


def clean_markdown_for_pandoc(text: str, chapter_title: str) -> str:
    """Prepare a markdown chapter for inclusion in the report-class monograph."""
    # Unicode box-drawing and mathematical symbols for pdflatex compatibility
    unicode_replacements = {
        "│": "|", "─": "-", "┌": "+", "┐": "+", "└": "+", "┘": "+",
        "├": "+", "┤": "+", "┬": "+", "┴": "+", "┼": "+",
        "═": "=", "║": "|", "╔": "+", "╗": "+", "╚": "+", "╝": "+",
        "╠": "+", "╣": "+", "╦": "+", "╩": "+", "╬": "+",
        "•": "*", "→": "->", "←": "<-", "↔": "<->", "⇒": "=>", "⇐": "<=", "⇔": "<=>",
        "≈": "~", "≠": "!=", "≤": "<=", "≥": ">=", "×": "x", "…": "...",
        "“": '"', "”": '"', "‘": "'", "’": "'", "—": "---", "–": "--",
        "▼": "v", "▲": "^", "►": ">", "◄": "<", "✓": "[x]", "✗": "[ ]",
        "α": "alpha", "β": "beta", "γ": "gamma", "δ": "delta", "ε": "epsilon",
        "λ": "lambda", "ω": "omega", "θ": "theta", "φ": "phi", "ψ": "psi",
    }
    for char, repl in unicode_replacements.items():
        text = text.replace(char, repl)

    # Convert GitHub alert blocks
    text = re.sub(r"^>\s*\[!NOTE\]", r"> **Note:**", text, flags=re.MULTILINE)
    text = re.sub(r"^>\s*\[!TIP\]", r"> **Tip:**", text, flags=re.MULTILINE)
    text = re.sub(r"^>\s*\[!IMPORTANT\]", r"> **Important:**", text, flags=re.MULTILINE)
    text = re.sub(r"^>\s*\[!WARNING\]", r"> **Warning:**", text, flags=re.MULTILINE)
    text = re.sub(r"^>\s*\[!CAUTION\]", r"> **Caution:**", text, flags=re.MULTILINE)

    # Convert internal repository markdown links to plain text / anchors
    def clean_link(match: re.Match[str]) -> str:
        label = match.group(1)
        target = match.group(2)
        if target.startswith("http://") or target.startswith("https://") or target.startswith("mailto:"):
            return f"[{label}]({target})"
        if "#" in target:
            anchor = target.split("#", 1)[1]
            return f"[{label}](#{anchor})"
        return f"**{label}**"

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", clean_link, text)

    text = re.sub(r"<br\s*/?>", "; ", text, flags=re.IGNORECASE)

    # Render wide repository tables as labeled records so no cells are clipped.
    def table_records(match: re.Match[str]) -> str:
        rows = [re.split(r"(?<!\\)\|", line.strip().strip("|"))
                for line in match.group().splitlines()]
        headers = [cell.strip() for cell in rows[0]]
        records = []
        for row in rows[2:]:
            if len(row) != len(headers):
                raise ValueError("Monograph table row does not match its column headings")
            records.append("\n\n".join(
                f"**{heading}:** {value.strip()}"
                for heading, value in zip(headers, row)
            ))
        return "\n\n---\n\n".join(records) + "\n"

    text = re.sub(
        r"^\|[^\n]+\|\n\|[ :|\-]+\|\n(?:\|[^\n]+\|\n?)+",
        table_records, text, flags=re.MULTILINE,
    )

    # Permit line breaks in long literal identifiers without altering their bytes.
    def break_literal(match: re.Match[str]) -> str:
        value = match.group(1)
        if len(value) <= 24:
            return match.group()
        escaped = {"\\": r"\textbackslash{}", "{": r"\{", "}": r"\}",
                   "_": r"\_", "#": r"\#", "%": r"\%", "&": r"\&",
                   "$": r"\$", "^": r"\textasciicircum{}", "~": r"\textasciitilde{}"}
        chunks = ["".join(escaped.get(c, c) for c in value[i:i + 12])
                  for i in range(0, len(value), 12)]
        return r"\texttt{" + r"\allowbreak{}".join(chunks) + "}"

    text = re.sub(r"(?<!`)`([^`\n]+)`(?!`)", break_literal, text)

    # Keep section depth relative to the replacement chapter heading.
    lines: list[str] = []
    first_h1_skipped = False
    for line in text.splitlines():
        if line.startswith("# ") and not first_h1_skipped:
            first_h1_skipped = True
            continue
        if line.startswith("# "):
            line = "#" + line
        lines.append(line)

    cleaned_body = "\n".join(lines).strip()
    return f"# {chapter_title}\n\n{cleaned_body}\n"


def build_monograph(output_pdf: Path) -> None:
    for exe in ("pandoc", "pdflatex"):
        if not shutil.which(exe):
            raise SystemExit(f"Executable {exe!r} not found on PATH.")

    PAPER.mkdir(exist_ok=True)
    temp_md = PAPER / "vstd_monograph_combined.tmp.md"

    parts = [MONOGRAPH_METADATA]
    for title, source_path in CHAPTER_SOURCES:
        if not source_path.exists():
            raise SystemExit(f"Missing chapter source: {source_path}")
        raw_text = source_path.read_text(encoding="utf-8")
        parts.append(clean_markdown_for_pandoc(raw_text, title))

    combined_content = "\n\n\\newpage\n\n".join(parts)
    temp_md.write_text(combined_content, encoding="utf-8")

    try:
        print(f"Compiling {output_pdf.name} via pandoc and pdflatex (timeout 180s)...", flush=True)
        cmd = [
            "pandoc",
            str(temp_md),
            "-o",
            str(output_pdf),
            "--pdf-engine=pdflatex",
            "-V", "linkcolor=blue",
            "-V", "urlcolor=blue",
            "-V", "toccolor=black",
            "--toc",
            "-N",
        ]
        result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            print(f"Pandoc error:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}", file=sys.stderr)
            raise SystemExit(f"Failed to generate {output_pdf.name} (exit code {result.returncode})")
        print(f"Successfully generated {output_pdf} ({output_pdf.stat().st_size:,} bytes).")
    finally:
        if temp_md.exists():
            temp_md.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=PAPER / "vstd_monograph.pdf",
        help="Target PDF output path (default: paper/vstd_monograph.pdf)",
    )
    args = parser.parse_args()
    build_monograph(args.output)


if __name__ == "__main__":
    main()
