#!/usr/bin/env python3
"""Fail closed when public presentation surfaces drift from executable truth."""

from __future__ import annotations

from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from urllib.parse import unquote
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {".git", ".pytest_cache", ".venv", "build", "dist", "__pycache__"}
TEXT_SUFFIXES = {
    ".cff",
    ".css",
    ".html",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".svg",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
LOCAL_WINDOWS_PATH = re.compile(
    r"(?i)(?:[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]|"
    r"\\\\Users[\\/]|[\\/]\.codex[\\/])"
)
DRIVE_QUALIFIED_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9_%])(?:[A-Za-z]:(?:\\\\|[\\/])[A-Za-z0-9._-]{2,})"
)
PUBLIC_BOUNDARY_PATTERNS = (
    ("local user or home path", LOCAL_WINDOWS_PATH),
    ("drive-qualified local path", DRIVE_QUALIFIED_PATH),
    ("synthetic private locator", re.compile(r"(?i)evaluator" r"-vault://")),
    (
        "private deployment field",
        re.compile(
            r"(?i)\b(?:model_path|launcher_path|mmproj_path|server_path|"
            r"private_target_manifest)\b"
        ),
    ),
    ("local model artifact filename", re.compile(r"(?i)\b[^\s/\\]+\.gguf\b")),
    (
        "business operations identifier",
        re.compile(
            r"(?i)(?:\bPRO" r"SP-[A-Z0-9-]+\b|FIRST" r"_REVENUE|sales[\\/])"
        ),
    ),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token shape", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("PyPI token shape", re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key shape", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OpenAI-style secret shape", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    (
        "email address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
)
LINEAGE_CAUSALITY_PATTERNS = (
    (
        "recorded lineage described as causal",
        re.compile(r"(?i)\bcausal\s+(?:lineage|ancestor(?:s)?)\b"),
    ),
    (
        "recorded transformation described as causal",
        re.compile(r"(?i)\bcausal\s+process\b"),
    ),
    (
        "recorded ancestry described as causal contribution",
        re.compile(r"(?i)\bcausally\s+contribut(?:e|ed|es|ing)\b"),
    ),
)


class LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.links.append(value)


def _public_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and not any(part in IGNORED_PARTS for part in path.relative_to(ROOT).parts)
        and path.suffix.lower() in TEXT_SUFFIXES
    )


def _local_target(source: Path, raw: str) -> Path | None:
    value = raw.strip().strip("<>").split(maxsplit=1)[0]
    if not value or value.startswith(("#", "http://", "https://", "mailto:", "data:")):
        return None
    relative = unquote(value.split("#", 1)[0].split("?", 1)[0])
    if not relative:
        return source
    return (source.parent / relative).resolve()


def check_local_links(errors: list[str]) -> None:
    for source in _public_files():
        suffix = source.suffix.lower()
        text = source.read_text(encoding="utf-8")
        links: list[str] = []
        if suffix == ".md":
            links.extend(match.group(1) for match in MARKDOWN_LINK.finditer(text))
        elif suffix == ".html":
            parser = LinkCollector()
            parser.feed(text)
            links.extend(parser.links)
        for raw in links:
            target = _local_target(source, raw)
            if target is not None and not target.exists():
                errors.append(
                    f"broken local link in {source.relative_to(ROOT)}: {raw}"
                )


def check_versions(errors: list[str]) -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = pyproject.split("[project]", 1)
    project_text = "" if len(project_section) != 2 else project_section[1].split("\n[", 1)[0]
    project_match = re.search(r'^version\s*=\s*"([^"]+)"$', project_text, re.MULTILINE)
    if project_match is None:
        errors.append("pyproject.toml has no parseable [project] version")
        return
    expected = project_match.group(1)
    init_text = (ROOT / "src/verifier/__init__.py").read_text(encoding="utf-8")
    init_match = re.search(r'^__version__ = "([^"]+)"$', init_text, re.MULTILINE)
    citation_match = re.search(
        r"^version:\s*([^\s]+)$",
        (ROOT / "CITATION.cff").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    zenodo = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    found = {
        "src/verifier/__init__.py": None if init_match is None else init_match.group(1),
        "CITATION.cff": None if citation_match is None else citation_match.group(1),
        ".zenodo.json": zenodo.get("version"),
    }
    for label, version in found.items():
        if version != expected:
            errors.append(f"version mismatch: pyproject={expected}, {label}={version}")
    if not re.search(rf"^## {re.escape(expected)} - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.MULTILINE):
        errors.append(f"CHANGELOG.md has no dated {expected} release heading")


def check_claim_boundaries(errors: list[str]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    wire = (ROOT / "standard/WIRE_IDENTIFIERS.md").read_text(encoding="utf-8")
    required_readme = (
        "Portable, bounded, refutable evidence for computational claims.",
        "vstd demo",
        "founder-maintained **alpha project specification**",
        "A higher-layer result does **not** supply",
        "It cannot prove general AI safety",
    )
    for phrase in required_readme:
        if phrase not in readme:
            errors.append(f"README.md is missing presentation boundary: {phrase!r}")
    if "`vstd` is the canonical cross-platform command" not in readme:
        errors.append("README.md does not disclose the canonical cross-platform CLI")
    if "`vstd` is the canonical cross-platform CLI name" not in wire:
        errors.append("WIRE_IDENTIFIERS.md does not preserve the CLI compatibility rule")
    if "## Explicit non-goals" not in roadmap or "operational condition" not in roadmap:
        errors.append("ROADMAP.md lacks its capability and non-goal boundary")
    if (ROOT / "docs/layers/vstd-3/migration.md").exists():
        errors.append("obsolete adopter-migration path has reappeared")


def public_boundary_violations(text: str) -> list[str]:
    return [label for label, pattern in PUBLIC_BOUNDARY_PATTERNS if pattern.search(text)]


def lineage_causality_violations(text: str) -> list[str]:
    """Reject phrases that silently upgrade recorded ancestry into causality."""

    return [label for label, pattern in LINEAGE_CAUSALITY_PATTERNS if pattern.search(text)]


def check_public_paths(errors: list[str]) -> None:
    checker = Path(__file__).resolve()
    for path in _public_files():
        if path.resolve() == checker:
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in PUBLIC_BOUNDARY_PATTERNS:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{label} leaked into {path.relative_to(ROOT)}:{line}"
                )


def check_lineage_claims(errors: list[str]) -> None:
    checker = Path(__file__).resolve()
    for path in _public_files():
        if path.resolve() == checker:
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in LINEAGE_CAUSALITY_PATTERNS:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{label} in {path.relative_to(ROOT)}:{line}")


def check_visual_assets(errors: list[str]) -> None:
    svg = ROOT / "docs/assets/vstd-overview.svg"
    try:
        tree = ET.parse(svg)
    except (OSError, ET.ParseError) as exc:
        errors.append(f"invalid overview SVG: {exc}")
        return
    root = tree.getroot()
    if root.attrib.get("viewBox") != "0 0 1200 630":
        errors.append("overview SVG must retain the 1200x630 presentation viewBox")
    if root.attrib.get("role") != "img":
        errors.append("overview SVG has no image accessibility role")
    expected_status = {
        "vstd-1": "REF. SUBSET",
        "vstd-2": "EXPERIMENTAL",
        "vstd-3": "IMPLEMENTED",
        "vstd-4": "IMPLEMENTED",
        "vstd-5": "DRAFT",
        "graph-1": "REF. SUBSET",
        "graph-2": "IMPLEMENTED",
        "graph-3": "IMPLEMENTED",
        "graph-4": "IMPLEMENTED",
        "graph-5": "DRAFT",
    }
    observed_status = {
        element.attrib["data-layer"]: "".join(element.itertext()).strip()
        for element in root.iter()
        if "data-layer" in element.attrib
    }
    if observed_status != expected_status:
        errors.append(
            "overview SVG status labels do not match the specification headers: "
            f"{observed_status!r}"
        )
    png = ROOT / "docs/assets/vstd-overview.png"
    try:
        data = png.read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) < 24:
            raise ValueError("not a PNG")
        width, height = struct.unpack(">II", data[16:24])
    except (OSError, ValueError, struct.error) as exc:
        errors.append(f"invalid overview PNG: {exc}")
    else:
        if (width, height) != (1200, 630):
            errors.append(
                f"overview PNG must be 1200x630, observed {width}x{height}"
            )


def check_generated_reference(errors: list[str]) -> None:
    """The published CLI/API reference must still match the importable package."""

    path = ROOT / "scripts/build_reference.py"
    spec = importlib.util.spec_from_file_location("build_reference", path)
    if spec is None or spec.loader is None:
        errors.append("cannot load scripts/build_reference.py")
        return
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        rendered = module.render()
    except Exception as exc:  # noqa: BLE001 - any failure is a presentation failure
        errors.append(f"reference page cannot be generated: {exc}")
        return
    target = ROOT / "docs/reference.html"
    if not target.is_file():
        errors.append("docs/reference.html is missing; run python scripts/build_reference.py")
        return
    if target.read_text(encoding="utf-8") != rendered:
        errors.append(
            "docs/reference.html drifted from the implementation; "
            "run python scripts/build_reference.py"
        )
    index = (ROOT / "docs/index.html").read_text(encoding="utf-8")
    if '<a href="reference.html">Docs</a>' not in index:
        errors.append("docs/index.html no longer links the generated reference from its nav")


def check_experiment_index(errors: list[str]) -> None:
    """Profile manifests, bound repo artifacts, and the public index must agree."""

    path = ROOT / "scripts/build_experiment_index.py"
    spec = importlib.util.spec_from_file_location("build_experiment_index", path)
    if spec is None or spec.loader is None:
        errors.append("cannot load scripts/build_experiment_index.py")
        return
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        rendered = module.render(module.discover(ROOT))
    except Exception as exc:  # the gate reports any bounded generation failure
        errors.append(f"experiment index cannot be generated: {exc}")
        return
    target = ROOT / "experiments/INDEX.md"
    if not target.is_file() or target.read_text(encoding="utf-8") != rendered:
        errors.append(
            "experiments/INDEX.md drifted from profile manifests; "
            "run python scripts/build_experiment_index.py"
        )


def run() -> list[str]:
    errors: list[str] = []
    check_local_links(errors)
    check_versions(errors)
    check_claim_boundaries(errors)
    check_public_paths(errors)
    check_lineage_claims(errors)
    check_visual_assets(errors)
    check_generated_reference(errors)
    check_experiment_index(errors)
    return errors


def main() -> int:
    errors = run()
    if errors:
        for error in errors:
            print(f"[PRESENTATION FAIL] {error}", file=sys.stderr)
        return 1
    print(
        "[PRESENTATION OK] links, versions, boundaries, paths, visual assets, "
        "generated reference, and experiment index"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
