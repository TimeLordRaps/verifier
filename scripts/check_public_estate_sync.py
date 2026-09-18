#!/usr/bin/env python3
"""Terminology: application programming interface (API); command-line interface (CLI);
Hypertext Transfer Protocol (HTTP); JavaScript Object Notation (JSON); Python Package Index (PyPI);
uniform resource locator (URL); Verifier Standard (VSTD).

Preflight hook to verify mandatory documentation coverage and monitor public estate synchronization."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def _default_paths() -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    vlt_candidate = ROOT.parent.parent / "".join(["VSTD", "-", "Labs"]) / "website"
    vlt_paths = (
        vlt_candidate,
        ROOT.parent / "website",
    )
    cg_paths = (
        ROOT.parent / "claimgarden" / "web",
        ROOT.parent.parent / "claimgarden" / "web",
    )
    return vlt_paths, cg_paths


REQUIRED_DOCUMENTATION_FILES = (
    "docs/index.html",
    "docs/guides.html",
    "docs/reference.html",
    "docs/QUICKSTART.md",
    "docs/USE_CASES.md",
    "docs/PYTHON_API_GUIDE.md",
    "docs/REPOSITORY_WALKTHROUGH.md",
    "docs/INSTALLATION.md",
    "docs/FIRST_RECEIPT.md",
    "docs/DOCUMENTATION_HOSTING.md",
    "docs/tutorials/SEAL_AN_ARTIFACT.md",
    "docs/tutorials/PUBLISH_A_SILO.md",
)


def get_package_version(root: Path) -> str:
    """Read version from pyproject.toml."""
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    project = pyproject.split("[project]", 1)
    project_text = "" if len(project) != 2 else project[1].split("\n[", 1)[0]
    match = re.search(r'^version\s*=\s*"([^"]+)"$', project_text, re.MULTILINE)
    if not match:
        raise ValueError("Cannot parse version from pyproject.toml")
    return match.group(1)


def check_mandatory_documentation_coverage(root: Path, target_version: str) -> list[str]:
    """Verify that every release includes simultaneous documentation coverage.

    Prevents the v1.4.0/v1.4.1 split defect where a feature release was published
    without its documentation and tutorials.
    """
    errors: list[str] = []

    # 1. Check all required documentation files exist
    for rel_path in REQUIRED_DOCUMENTATION_FILES:
        file_path = root / rel_path
        if not file_path.is_file():
            errors.append(f"Required documentation file missing: {rel_path}")

    # 2. Check reference.html matches current package version
    ref_path = root / "docs/reference.html"
    if ref_path.is_file():
        ref_content = ref_path.read_text(encoding="utf-8")
        if f"package version {target_version}" not in ref_content:
            errors.append(
                f"docs/reference.html does not declare package version {target_version}"
            )
    else:
        errors.append("docs/reference.html does not exist")

    # 3. Check guides.html registers all tutorial routes
    guides_path = root / "docs/guides.html"
    if guides_path.is_file():
        guides_content = guides_path.read_text(encoding="utf-8")
        required_guides = (
            "USE_CASES.html",
            "PYTHON_API_GUIDE.html",
            "tutorials/SEAL_AN_ARTIFACT.html",
            "tutorials/PUBLISH_A_SILO.html",
        )
        for req in required_guides:
            if req not in guides_content:
                errors.append(f"docs/guides.html is missing registration for {req}")

    # 4. Anti-split check: Changelog must not defer documentation
    changelog_path = root / "CHANGELOG.md"
    if changelog_path.is_file():
        changelog_content = changelog_path.read_text(encoding="utf-8")
        version_section_match = re.search(
            rf"^## {re.escape(target_version)}.*?(?=^## |\Z)",
            changelog_content,
            re.MULTILINE | re.DOTALL,
        )
        if version_section_match:
            sec_text = version_section_match.group(0)
            if re.search(r"(?i)\bdocs?\s+to\s+follow\b|\bdocumentation\s+deferred\b", sec_text):
                errors.append(
                    f"CHANGELOG.md for {target_version} explicitly defers documentation"
                )

    # 5. Check documentation estate version references
    errors.extend(check_documentation_version_references(root, target_version))

    return errors


def check_documentation_version_references(root: Path, target_version: str) -> list[str]:
    """Verify that all documentation files with pinned install/release/clone commands match target_version."""
    errors: list[str] = []
    pip_pat = re.compile(r'verifier-standard(?:\[[a-zA-Z0-9,._-]+\])?==([0-9a-zA-Z.-]+)')
    git_pat = re.compile(r'(?:--branch\s+v|checkout\s+v|origin\s+tag\s+v|tag\s+`v)([0-9a-zA-Z.-]+)')
    ver_pat = re.compile(r"verifier\.__version__\)?\s*(?:\n\s*)?#\s*'([^']+)'")

    docs_dir = root / "docs"
    if not docs_dir.is_dir():
        return errors

    for doc_path in sorted(docs_dir.rglob("*.md")):
        rel_path = doc_path.relative_to(root).as_posix()
        text = doc_path.read_text(encoding="utf-8")

        for line_no, line in enumerate(text.splitlines(), 1):
            for m in pip_pat.finditer(line):
                observed = m.group(1)
                if observed != target_version:
                    errors.append(
                        f"{rel_path}:{line_no}: pinned pip install specifies {observed!r}, expected {target_version!r}"
                    )
            for m in git_pat.finditer(line):
                observed = m.group(1)
                if observed != target_version:
                    errors.append(
                        f"{rel_path}:{line_no}: git command specifies tag/branch v{observed}, expected v{target_version}"
                    )

        for m in ver_pat.finditer(text):
            observed = m.group(1)
            if observed != target_version:
                errors.append(
                    f"{rel_path}: verifier.__version__ output comment specifies {observed!r}, expected {target_version!r}"
                )

    return errors


def fetch_pypi_status(package_name: str = "verifier-standard", timeout: float = 4.0) -> dict[str, Any]:
    """Query PyPI for published package status with graceful timeout handling."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "vstd-public-estate-sync/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                return {
                    "status": "UNKNOWN",
                    "error": f"HTTP {response.status}",
                    "latest_version": None,
                    "release_count": None,
                    "releases": [],
                }
            data = json.loads(response.read().decode("utf-8"))
            releases = sorted(data.get("releases", {}).keys())
            return {
                "status": "OBSERVED",
                "latest_version": data.get("info", {}).get("version"),
                "release_count": len(releases),
                "releases": releases,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "status": "UNKNOWN",
            "error": str(exc),
            "latest_version": None,
            "release_count": None,
            "releases": [],
        }


def find_estate_path(configured: Path | None, env_var: str, defaults: tuple[Path, ...]) -> Path | None:
    """Resolve an estate component path from CLI, environment, or standard locations."""
    if configured and configured.is_dir():
        return configured
    env_val = os.environ.get(env_var)
    if env_val:
        p = Path(env_val)
        if p.is_dir():
            return p
    for default in defaults:
        if default.is_dir():
            return default
    return None


def inspect_vstd_labs(website_dir: Path) -> dict[str, Any]:
    """Inspect corporate website (vstd-labs.com) synchronization state."""
    index_file = website_dir / "index.html"
    app_file = website_dir / "app.js"

    result: dict[str, Any] = {
        "path": str(website_dir),
        "status": "OBSERVED",
        "hero_badge": None,
        "hero_badge_version": None,
        "metric_val": None,
        "release_count_phrase": None,
        "session_pinned_version": None,
        "app_captured_version": None,
    }

    if index_file.is_file():
        content = index_file.read_text(encoding="utf-8")
        badge_match = re.search(r'badge-accent">([^<]+)</span>', content)
        if badge_match:
            raw_badge = badge_match.group(1).strip()
            result["hero_badge"] = raw_badge
            v_match = re.search(r'v([0-9]+\.[0-9]+\.[0-9]+)', raw_badge)
            if v_match:
                result["hero_badge_version"] = v_match.group(1)

        metric_match = re.search(r'class="metric-val">([^<]+)</div>', content)
        if metric_match:
            result["metric_val"] = metric_match.group(1).strip()

        phrase_match = re.search(r'([a-zA-Z0-9/ ]+releases published)', content)
        if phrase_match:
            result["release_count_phrase"] = phrase_match.group(1).strip()

        session_match = re.search(r'The recorded session below pins <code>([^<]+)</code>', content)
        if session_match:
            result["session_pinned_version"] = session_match.group(1).strip()

    if app_file.is_file():
        app_content = app_file.read_text(encoding="utf-8")
        app_match = re.search(r'verifier-standard==([0-9a-zA-Z._-]+)', app_content)
        if app_match:
            result["app_captured_version"] = app_match.group(1).strip()

    return result


def inspect_claimgarden(web_dir: Path) -> dict[str, Any]:
    """Inspect ClaimGarden (claimgarden.com) synchronization state."""
    index_file = web_dir / "index.html"
    catalog_file = web_dir / "catalog.html"

    result: dict[str, Any] = {
        "path": str(web_dir),
        "status": "OBSERVED",
        "index_vstd_version": None,
        "catalog_vstd_version": None,
    }

    if index_file.is_file():
        content = index_file.read_text(encoding="utf-8")
        match = re.search(
            r'vstd-labs/gdc-sat-kernel.*?<span>(v[0-9.]+)</span>',
            content,
            re.DOTALL,
        )
        if match:
            result["index_vstd_version"] = match.group(1)

    if catalog_file.is_file():
        content = catalog_file.read_text(encoding="utf-8")
        match = re.search(
            r'vstd-labs%2Fgdc-sat-kernel.*?<span>(v[0-9.]+)</span>',
            content,
            re.DOTALL,
        )
        if match:
            result["catalog_vstd_version"] = match.group(1)

    return result


def evaluate_estate_sync(
    root: Path,
    target_version: str,
    vstd_labs_dir: Path | None = None,
    claimgarden_dir: Path | None = None,
    offline: bool = False,
    target_sync: bool = False,
) -> dict[str, Any]:
    """Inspect and evaluate complete public estate synchronization.

    If target_sync is True, evaluates synchronization against target_version.
    Otherwise evaluates against the live published PyPI version (or target_version if PyPI is unavailable).
    """
    vlt_defaults, cg_defaults = _default_paths()
    doc_errors = check_mandatory_documentation_coverage(root, target_version)
    pypi_data = (
        {"status": "SKIPPED_OFFLINE", "latest_version": None, "release_count": None, "releases": []}
        if offline
        else fetch_pypi_status()
    )

    resolved_labs_path = find_estate_path(vstd_labs_dir, "VSTD_LABS_ROOT", vlt_defaults)
    labs_data = inspect_vstd_labs(resolved_labs_path) if resolved_labs_path else {"status": "NOT_FOUND"}

    resolved_cg_path = find_estate_path(claimgarden_dir, "CLAIMGARDEN_ROOT", cg_defaults)
    cg_data = inspect_claimgarden(resolved_cg_path) if resolved_cg_path else {"status": "NOT_FOUND"}

    action_items: list[str] = []

    pypi_version = pypi_data.get("latest_version")
    expected_version = target_version if target_sync else (pypi_version or target_version)

    # Check PyPI status vs target_version
    pypi_status_note = "UNKNOWN"
    if pypi_version:
        if pypi_version == target_version:
            pypi_status_note = "SYNCHRONIZED"
        else:
            pypi_status_note = f"AHEAD_OF_PYPI (Target {target_version} vs PyPI {pypi_version})"
            action_items.append(
                f"Release v{target_version} to PyPI (current PyPI release is v{pypi_version})"
            )

    if labs_data.get("status") == "OBSERVED":
        hero_badge = labs_data.get("hero_badge", "")
        if f"v{expected_version}" not in hero_badge:
            action_items.append(
                f"vstd-labs.com hero badge reads '{hero_badge}', expected 'v{expected_version} ON PYPI'"
            )
        metric_val = labs_data.get("metric_val", "")
        if f"v{expected_version}" != metric_val:
            action_items.append(
                f"vstd-labs.com metric card reads '{metric_val}', expected 'v{expected_version}'"
            )
        session_pin = labs_data.get("session_pinned_version", "")
        if session_pin and session_pin != expected_version:
            action_items.append(
                f"vstd-labs.com demo session pins '{session_pin}' (outdated relative to v{expected_version}; re-capture required per RELEASE_UPDATE_CHECKLIST.md)"
            )

    if cg_data.get("status") == "OBSERVED":
        idx_ver = cg_data.get("index_vstd_version", "")
        cat_ver = cg_data.get("catalog_vstd_version", "")
        expected_v = f"v{expected_version}"
        if idx_ver and idx_ver != expected_v:
            action_items.append(
                f"claimgarden.com index card footer reads '{idx_ver}', expected '{expected_v}'"
            )
        if cat_ver and cat_ver != expected_v:
            action_items.append(
                f"claimgarden.com catalog card footer reads '{cat_ver}', expected '{expected_v}'"
            )

    return {
        "target_version": target_version,
        "expected_version": expected_version,
        "pypi_status_note": pypi_status_note,
        "doc_coverage_status": "PASS" if not doc_errors else "FAIL",
        "doc_coverage_errors": doc_errors,
        "pypi": pypi_data,
        "vstd_labs": labs_data,
        "claimgarden": cg_data,
        "action_items": action_items,
    }


def format_report(eval_result: dict[str, Any]) -> str:
    """Format evaluation into human-readable report."""
    target_ver = eval_result["target_version"]
    lines = [
        "=================================================================",
        "           VSTD PUBLIC ESTATE SYNCHRONIZATION REPORT",
        "=================================================================",
        f"Repository Target Version: {target_ver}",
        f"Documentation Coverage   : {eval_result['doc_coverage_status']}",
    ]
    for err in eval_result["doc_coverage_errors"]:
        lines.append(f"  [ERROR] {err}")

    lines.append("-----------------------------------------------------------------")
    lines.append("Estate Surfaces:")
    pypi = eval_result["pypi"]
    if pypi.get("status") == "OBSERVED":
        lines.append(
            f"  PyPI (verifier-standard) : {pypi['latest_version']} "
            f"({pypi['release_count']} releases published) [{eval_result.get('pypi_status_note')}]"
        )
    else:
        lines.append(f"  PyPI (verifier-standard) : {pypi.get('status')} ({pypi.get('error', 'offline')})")

    labs = eval_result["vstd_labs"]
    if labs.get("status") == "OBSERVED":
        lines.append(
            f"  Company Site (vstd-labs) : Hero: {labs.get('hero_badge')}; "
            f"Metric: {labs.get('metric_val')}; "
            f"Session Pin: {labs.get('session_pinned_version')}"
        )
    else:
        lines.append(f"  Company Site (vstd-labs) : {labs.get('status')}")

    cg = eval_result["claimgarden"]
    if cg.get("status") == "OBSERVED":
        lines.append(
            f"  ClaimGarden (claimgarden): Index: {cg.get('index_vstd_version')}; "
            f"Catalog: {cg.get('catalog_vstd_version')}"
        )
    else:
        lines.append(f"  ClaimGarden (claimgarden): {cg.get('status')}")

    lines.append("-----------------------------------------------------------------")
    action_items = eval_result.get("action_items", [])
    if action_items:
        lines.append("Action Items Needed for Estate Synchronization:")
        for idx, item in enumerate(action_items, 1):
            lines.append(f"  {idx}. {item}")
    else:
        lines.append("Estate Synchronization: CLEAN (No drift detected)")

    lines.append("=================================================================")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify mandatory documentation coverage and monitor public estate synchronization."
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root path")
    parser.add_argument("--version", help="Override target version (defaults to pyproject.toml)")
    parser.add_argument("--vstd-labs-dir", type=Path, help="Path to corporate website (vstd-labs.com) directory")
    parser.add_argument("--claimgarden-dir", type=Path, help="Path to claimgarden web directory")
    parser.add_argument("--offline", action="store_true", help="Skip remote network checks")
    parser.add_argument("--target-sync", action="store_true", help="Evaluate synchronization against target_version instead of live PyPI")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument(
        "--require-doc-coverage",
        action="store_true",
        help="Fail closed with exit code 1 if mandatory documentation coverage is incomplete",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail closed with exit code 1 if doc coverage fails or action items remain",
    )

    args = parser.parse_args(argv)
    target_version = args.version or get_package_version(args.root)

    eval_result = evaluate_estate_sync(
        root=args.root,
        target_version=target_version,
        vstd_labs_dir=args.vstd_labs_dir,
        claimgarden_dir=args.claimgarden_dir,
        offline=args.offline,
        target_sync=args.target_sync,
    )

    if args.json:
        print(json.dumps(eval_result, indent=2))
    else:
        print(format_report(eval_result))

    if args.require_doc_coverage and eval_result["doc_coverage_status"] != "PASS":
        return 1

    if args.check:
        if eval_result["doc_coverage_status"] != "PASS" or eval_result["action_items"]:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
