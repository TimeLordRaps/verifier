#!/usr/bin/env python3
"""Terminology: artificial intelligence (AI); application programming interface (API);
Amazon Web Services (AWS); Concise Binary Object Representation (CBOR); CBOR Object Signing and
Encryption (COSE); command-line interface (CLI); Supply Chain Integrity, Transparency, and
Trust (SCITT); reduced instruction set computer (RISC); Verifier Standard (VSTD).

Fail closed when public presentation surfaces drift from executable truth."""

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
RETIRED_SURFACES = (
    "VSTD-" + "0.1",
    "VSTD-" + "0.2",
    "layer" + "4_binding",
    "vstd" + "4_conformance",
)
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
CURRENT_TIME_STATUS = re.compile(
    r"(?i)\bTIME(?:\.md)?`?\s+(?:is|=|==|has\s+status|status\s*(?:is|=|:))\s+"
    r"(?:`?Status:\s*)?`?(?:CLEAR|OPEN)\b"
)
CURRENT_FACING_SURFACES = (
    "README.md",
    "docs/CLAIMS_AND_LIMITS.md",
    "docs/QUICKSTART.md",
    "docs/guides.html",
    "docs/index.html",
)
MATURITY_CONFORMANCE = {
    "VSTD-1": "Implemented reference subset",
    "VSTD-2": "Implemented vertical slice",
    "VSTD-3": "Implemented reference surface",
    "VSTD-4": "`NOT_ESTABLISHED`",
    "VSTD-5": "Not implemented",
    "VSTD-Graph-1": "Implemented reference subset",
    "VSTD-Graph-2": "`NOT_ESTABLISHED`",
    "VSTD-Graph-3": "`NOT_ESTABLISHED`",
    "VSTD-Graph-4": "`NOT_ESTABLISHED`",
    "VSTD-Graph-5": "`NOT_ESTABLISHED`",
    "Generic run": "Implemented VSTD-1 profile",
    "Experimental workflow": "No VSTD conformance claim",
    "Supply Chain Integrity, Transparency, and Trust (SCITT) interoperability": (
        "VSTD-4 remains `NOT_ESTABLISHED`"
    ),
    "zero-identity/zero-knowledge (ZIZK) artifact-first TRUST": (
        "Governing architectural invariant; not a separate VSTD conformance result"
    ),
    "RISC Zero proof-carrying reference mechanism": (
        "Native proof verified; no VSTD receipt mapping"
    ),
}


class LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.html_lang = ""
        self.has_viewport = False
        self.in_title = False
        self.title = ""
        self.main_ids: list[str] = []
        self.skip_targets: list[str] = []
        self.images_without_alt = 0
        self.unlabelled_navs = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = dict(attrs)
        if tag == "html":
            self.html_lang = attributes.get("lang", "")
        elif tag == "meta" and attributes.get("name") == "viewport":
            self.has_viewport = True
        elif tag == "title":
            self.in_title = True
        elif tag == "main":
            self.main_ids.append(attributes.get("id", ""))
        elif tag == "a" and "skip-link" in attributes.get("class", "").split():
            self.skip_targets.append(attributes.get("href", ""))
        elif tag == "img" and "alt" not in attributes:
            self.images_without_alt += 1
        elif tag == "nav" and not attributes.get("aria-label"):
            self.unlabelled_navs += 1
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.links.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data


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


def _generated_documentation_routes() -> set[str]:
    path = ROOT / "scripts/build_docs.py"
    spec = importlib.util.spec_from_file_location("build_docs_links", path)
    if spec is None or spec.loader is None:
        return set()
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        return {document.route.as_posix() for document in module.documents()}
    except Exception:
        return set()
    finally:
        sys.modules.pop(spec.name, None)


def check_local_links(errors: list[str]) -> None:
    generated = _generated_documentation_routes()
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
                try:
                    site_relative = target.relative_to(ROOT / "docs").as_posix()
                except ValueError:
                    site_relative = ""
                if site_relative in generated or f"{site_relative}/index.html" in generated:
                    continue
                errors.append(
                    f"broken local link in {source.relative_to(ROOT)}: {raw}"
                )


def check_html_accessibility(errors: list[str]) -> None:
    """Enforce the small structural accessibility floor for every Pages document."""

    for path in sorted((ROOT / "docs").glob("*.html")):
        parser = LinkCollector()
        parser.feed(path.read_text(encoding="utf-8"))
        name = path.relative_to(ROOT).as_posix()
        if not parser.html_lang:
            errors.append(f"{name} has no html language")
        if not parser.title.strip():
            errors.append(f"{name} has no document title")
        if not parser.has_viewport:
            errors.append(f"{name} has no viewport metadata")
        if len(parser.main_ids) != 1 or not parser.main_ids[0]:
            errors.append(f"{name} must have exactly one identified main region")
        elif f"#{parser.main_ids[0]}" not in parser.skip_targets:
            errors.append(f"{name} has no skip link to its main region")
        if parser.images_without_alt:
            errors.append(f"{name} has {parser.images_without_alt} image(s) without alt text")
        if parser.unlabelled_navs:
            errors.append(f"{name} has {parser.unlabelled_navs} navigation region(s) without labels")


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
    citation_text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    citation_match = re.search(
        r"^version:\s*([^\s]+)$",
        citation_text,
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
    dated = re.search(
        rf"^## {re.escape(expected)} - (\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        re.MULTILINE,
    )
    unreleased = re.search(
        rf"^## {re.escape(expected)} - UNRELEASED$", changelog, re.MULTILINE
    )
    citation_date = re.search(r"^date-released:\s*(\d{4}-\d{2}-\d{2})$", citation_text, re.MULTILINE)
    if dated is None and unreleased is None:
        errors.append(f"CHANGELOG.md has no dated or UNRELEASED {expected} heading")
    elif unreleased is not None:
        if citation_date is not None:
            errors.append("unreleased CITATION.cff must not fabricate date-released")
        if "release candidate" not in citation_text.lower():
            errors.append("unreleased CITATION.cff must identify the release candidate")
    elif citation_date is None or citation_date.group(1) != dated.group(1):
        errors.append("CITATION.cff date-released must match the dated CHANGELOG heading")


def maturity_table_violations(readme: str) -> list[str]:
    """Require one reviewable status row for every advertised major surface."""

    heading = "## Current maturity"
    if heading not in readme:
        return ["README.md has no canonical current-maturity section"]
    section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
    header = (
        "| Surface | Normative status | Reference implementation | Evidence binding | "
        "Conformance status | Missing mechanism or evidence |"
    )
    errors: list[str] = []
    if header not in section:
        errors.append("README.md maturity table does not expose all six required fields")
    rows: dict[str, list[str]] = {}
    for line in section.splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] != "Surface":
            rows.setdefault(cells[0], []).append(line)
            if len(cells) != 6:
                errors.append(
                    f"README.md maturity row {cells[0]!r} has {len(cells)} fields, expected 6"
                )
    for surface, conformance in MATURITY_CONFORMANCE.items():
        observed = rows.get(surface, [])
        if len(observed) != 1:
            errors.append(
                f"README.md maturity table requires exactly one {surface!r} row, "
                f"observed {len(observed)}"
            )
        elif conformance not in observed[0]:
            errors.append(
                f"README.md maturity row {surface!r} is missing conformance boundary "
                f"{conformance!r}"
            )
    return errors


def transient_time_status_violations(text: str) -> list[str]:
    """Find transient TIME state copied into long-lived explanatory prose."""

    return [match.group(0) for match in CURRENT_TIME_STATUS.finditer(text)]


def check_claim_boundaries(errors: list[str]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    wire = (ROOT / "standard/WIRE_IDENTIFIERS.md").read_text(encoding="utf-8")
    reference = (ROOT / "docs/reference.html").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    scitt_demo = (ROOT / "examples/scitt_interop/demo.py").read_text(encoding="utf-8")
    scitt_result = json.loads(
        (ROOT / "examples/scitt_interop/generated/verification_result.json").read_text(
            encoding="utf-8"
        )
    )
    required_readme = (
        "Portable, bounded, refutable evidence for computational claims.",
        "VSTD is a verification-domain language and Python reference implementation",
        "does **not**\nreplace native domain verifiers",
        "## 30–60 second demonstration",
        "## What a result means",
        "## Current maturity",
        "## Why VSTD exists",
        "vstd demo",
        "A later-profile result does **not** supply",
        "It cannot prove general AI",
        "[Normative specifications](standard/LADDER.md)",
        "[Report an ambiguity or counterexample]",
        "[Report a vulnerability privately]",
        "SCITT registration proves neither payload",
        "VSTD evaluates bounded validity propositions about computational processes",
        "RUST is the inverse-TRUST diagnostic mechanic",
        "cryptographic zero knowledge can enclose",
        "The current checkout is an unreleased",
    )
    for phrase in required_readme:
        if phrase not in readme:
            errors.append(f"README.md is missing presentation boundary: {phrase!r}")
    if "`vstd` is the canonical cross-platform CLI name" not in readme:
        errors.append("README.md does not disclose the canonical cross-platform CLI")
    errors.extend(maturity_table_violations(readme))
    expected_order = (
        "VSTD is a verification-domain language",
        "## 30–60 second demonstration",
        "## What a result means",
        "## Current maturity",
        "## Why VSTD exists",
        "## Architecture",
        "## Install and use",
        "## Interoperability",
        "## Reproducibility and releases",
        "## Claims, security, and contribution",
        "## Citation and license",
    )
    positions = [readme.find(marker) for marker in expected_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append("README.md first-view information hierarchy has drifted")
    for relative in CURRENT_FACING_SURFACES:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for match in transient_time_status_violations(text):
            errors.append(f"transient TIME state copied into {relative}: {match!r}")
    for relative in (
        "README.md",
        "AGENTS.md",
        "CODE_OF_CONDUCT.md",
        "GOVERNANCE.md",
        "docs/index.html",
        "docs/guides.html",
        "docs/assets/vstd-overview.svg",
    ):
        if "founder-maintained" in (ROOT / relative).read_text(encoding="utf-8").lower():
            errors.append(f"{relative} uses reputation-centric founder-maintained wording")
    if "`vstd` is the canonical cross-platform CLI name" not in wire:
        errors.append("WIRE_IDENTIFIERS.md does not preserve the CLI compatibility rule")
    if "VSTD-4 CANDIDATE; CONFORMANCE NOT_ESTABLISHED" not in reference:
        errors.append("generated reference does not bound its VSTD-4 implementation status")
    if "reproducible COSE specimen" in changelog or "reproducible specimen" in roadmap:
        errors.append("SCITT ephemeral-key specimen is described as byte-reproducible")
    if "ephemeral-key COSE artifacts" not in scitt_demo:
        errors.append("SCITT producer does not disclose its ephemeral-key artifact boundary")
    if scitt_result.get("vstd_observation", {}).get("conformance_status") != "NOT_ESTABLISHED":
        errors.append("SCITT verification result drops VSTD conformance status")
    composition = scitt_result.get("composition", {})
    if composition.get("vstd_conformance_status") != "NOT_ESTABLISHED":
        errors.append("SCITT composition drops VSTD conformance status")
    if composition.get("status_scope") != "NATIVE_VSTD_RESULT_AND_SCITT_REGISTRATION":
        errors.append("SCITT composition does not state the scope of PASS")
    if "## Explicit non-goals" not in roadmap or "operational condition" not in roadmap:
        errors.append("ROADMAP.md lacks its capability and non-goal boundary")
    if (ROOT / "docs/profiles/vstd-3/migration.md").exists():
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


def check_retired_surfaces(errors: list[str]) -> None:
    """Prevent removed partial-profile identifiers and developmental fields from returning."""

    for path in _public_files():
        text = path.read_text(encoding="utf-8")
        for retired in RETIRED_SURFACES:
            offset = text.find(retired)
            if offset >= 0:
                line = text.count("\n", 0, offset) + 1
                errors.append(
                    f"retired surface {retired!r} returned in {path.relative_to(ROOT)}:{line}"
                )


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
        "vstd-4": "CANDIDATE",
        "vstd-5": "DRAFT",
        "graph-1": "REF. SUBSET",
        "graph-2": "CANDIDATE",
        "graph-3": "CANDIDATE",
        "graph-4": "CANDIDATE",
        "graph-5": "DRAFT",
    }
    observed_status = {
        element.attrib["data-profile"]: "".join(element.itertext()).strip()
        for element in root.iter()
        if "data-profile" in element.attrib
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
    for link in ('<a href="guides.html">Guides</a>', '<a href="reference.html">Reference</a>'):
        if link not in index:
            errors.append(f"docs/index.html navigation is missing {link}")


def check_generated_documentation(errors: list[str]) -> None:
    """Every maintained Markdown source must have one unambiguous site route."""

    path = ROOT / "scripts/build_docs.py"
    spec = importlib.util.spec_from_file_location("build_docs", path)
    if spec is None or spec.loader is None:
        errors.append("cannot load scripts/build_docs.py")
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        documents = module.documents()
    except Exception as exc:  # any generation failure blocks publication
        errors.append(f"documentation routes cannot be generated: {exc}")
        return
    finally:
        sys.modules.pop(spec.name, None)
    routes = [document.route.as_posix() for document in documents]
    if not routes:
        errors.append("documentation renderer declares no source pages")
    if len(routes) != len(set(routes)):
        errors.append("documentation renderer declares duplicate site routes")
    for document in documents:
        if not document.source.is_file():
            errors.append(f"documentation source is missing: {document.source}")

    pages = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in ("docs/index.html", "docs/guides.html", "docs/reference.html")
    }
    required = (
        'href="standard/"',
        'href="experiments/"',
        'href="project/ROADMAP.html"',
    )
    for name, page in pages.items():
        for link in required:
            if link not in page:
                errors.append(f"{name} navigation is missing the on-site route {link}")
        if '>Standard</a>' not in page or '>Specifications</a>' in page:
            errors.append(f"{name} navigation must label standard/ as Standard")
    guides = pages["docs/guides.html"]
    if "github.com/TimeLordRaps/verifier/blob/main/docs/" in guides:
        errors.append("docs/guides.html sends maintained guides to the GitHub file viewer")
    if "github.com/TimeLordRaps/verifier/blob/main/standard/" in guides:
        errors.append("docs/guides.html sends specifications to the GitHub file viewer")


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


def check_acronyms(errors: list[str]) -> None:
    """Require first-use expansion on every registered reader-facing surface."""

    path = ROOT / "scripts/check_acronyms.py"
    spec = importlib.util.spec_from_file_location("check_acronyms", path)
    if spec is None or spec.loader is None:
        errors.append("cannot load scripts/check_acronyms.py")
        return
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        errors.extend(module.validate_repo())
    except Exception as exc:  # any glossary or scan failure is a presentation failure
        errors.append(f"acronym presentation gate failed: {exc}")


def check_terminology(errors: list[str]) -> None:
    """Reject ambiguous structural terms on current public surfaces."""

    path = ROOT / "scripts/check_terminology.py"
    spec = importlib.util.spec_from_file_location("check_terminology", path)
    if spec is None or spec.loader is None:
        errors.append("cannot load scripts/check_terminology.py")
        return
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        errors.extend(module.validate_repo())
    except Exception as exc:  # any terminology scan failure is a presentation failure
        errors.append(f"terminology presentation gate failed: {exc}")


def run() -> list[str]:
    errors: list[str] = []
    check_local_links(errors)
    check_html_accessibility(errors)
    check_versions(errors)
    check_claim_boundaries(errors)
    check_public_paths(errors)
    check_lineage_claims(errors)
    check_retired_surfaces(errors)
    check_visual_assets(errors)
    check_generated_reference(errors)
    check_experiment_index(errors)
    check_generated_documentation(errors)
    check_acronyms(errors)
    check_terminology(errors)
    return errors


def main() -> int:
    errors = run()
    if errors:
        for error in errors:
            print(f"[PRESENTATION FAIL] {error}", file=sys.stderr)
        return 1
    print(
        "[PRESENTATION OK] links, accessibility, versions, boundaries, paths, "
        "maturity, transient status, visual assets, generated reference, experiment "
        "index, acronym expansion, and structural terminology"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
