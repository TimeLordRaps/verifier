#!/usr/bin/env python3
"""Terminology: Secure Hash Algorithm 256-bit (SHA-256); uniform resource locator (URL);
Verifier Standard (VSTD).

Assemble the exact GitHub Pages artifact without duplicating schema sources.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SCHEMA_SOURCES = (ROOT / "receipts/schema", ROOT / "standard/schemas")
PUBLIC_SCHEMA_PREFIX = "https://timelordraps.github.io/verifier/schemas/"
CANONICAL_BASE_URL = "https://timelordraps.github.io/verifier/"
DEPLOYMENT_MANIFEST_PATH = "deployment-manifest.json"
DEPLOYMENT_MANIFEST_SCHEMA = "VSTD-PAGES-DEPLOYMENT-MANIFEST-1"
MAX_DEPLOYMENT_FILES = 4096
MAX_DEPLOYMENT_FILE_BYTES = 8 * 1024 * 1024
MAX_DEPLOYMENT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DEPLOYMENT_PATH_BYTES = 512
CRITICAL_DEPLOYMENT_PATHS = (
    "components/deployment-coordinate.json",
    "components/index.json",
    "components/index.sha256",
    "documentation-coordinate.json",
    "index.html",
)
DEPLOYMENT_MANIFEST_CLAIM_BOUNDARY = (
    "The manifest binds every regular deployed payload file other than the manifest itself "
    "to this source commit by path, size, and SHA-256; it does not establish future "
    "availability, absence of hosting-layer transformations, or semantic correctness."
)


class PagesBuildError(RuntimeError):
    pass


def _build_documentation(output: Path, *, source_ref: str) -> tuple[Path, ...]:
    path = ROOT / "scripts/build_docs.py"
    spec = importlib.util.spec_from_file_location("vstd_build_docs", path)
    if spec is None or spec.loader is None:
        raise PagesBuildError("cannot load scripts/build_docs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        return module.build(output, source_ref=source_ref)
    except Exception as exc:
        raise PagesBuildError(f"documentation rendering failed: {exc}") from exc
    finally:
        sys.modules.pop(spec.name, None)


def _build_component_index(output: Path, *, source_ref: str) -> tuple[Path, ...]:
    path = ROOT / "scripts/build_component_index.py"
    spec = importlib.util.spec_from_file_location("vstd_build_component_index", path)
    if spec is None or spec.loader is None:
        raise PagesBuildError("cannot load scripts/build_component_index.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        component_source_ref = (
            source_ref if re.fullmatch(r"[0-9a-fA-F]{40}", source_ref) else "WORKTREE"
        )
        return module.build(
            output,
            source_ref=component_source_ref,
            base_url=CANONICAL_BASE_URL,
        )
    except Exception as exc:
        raise PagesBuildError(f"component-index generation failed: {exc}") from exc
    finally:
        sys.modules.pop(spec.name, None)


def _documentation_coordinate(source_ref: str) -> dict[str, str | int]:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', project, re.MULTILINE)
    if version_match is None:
        raise PagesBuildError("project version is not readable")
    version = version_match.group(1)
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.search(rf"^## {re.escape(version)} - (.+)$", changelog, re.MULTILINE)
    if heading is None:
        raise PagesBuildError(f"changelog has no coordinate for version {version}")
    unreleased = re.search(
        r"^## Unreleased\s*(.*?)(?=^## |\Z)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    if heading.group(1) == "UNRELEASED":
        release_state = "UNRELEASED_CANDIDATE"
    elif unreleased is not None and unreleased.group(1).strip():
        release_state = "UNRELEASED_SOURCE"
    else:
        release_state = "RELEASED"
    return {
        "schema_version": 1,
        "documentation_version": version,
        "release_state": release_state,
        "source_ref": source_ref,
        "canonical_base_url": CANONICAL_BASE_URL,
        "normative_source": "standard/",
    }


def _write_deployment_manifest(output: Path, *, source_ref: str) -> Path:
    """Write the deterministic manifest after every other Pages payload exists."""
    entries: list[dict[str, str | int]] = []
    total_bytes = 0
    for path in sorted(output.rglob("*"), key=lambda candidate: candidate.as_posix()):
        if path.is_symlink():
            raise PagesBuildError("Pages output contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(output).as_posix()
        if relative == DEPLOYMENT_MANIFEST_PATH:
            raise PagesBuildError("Pages manifest path already exists before finalization")
        if (
            len(relative.encode("utf-8")) > MAX_DEPLOYMENT_PATH_BYTES
            or re.fullmatch(r"[A-Za-z0-9._/-]+", relative) is None
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise PagesBuildError(f"Pages output path is not canonical: {relative!r}")
        payload = path.read_bytes()
        if len(payload) > MAX_DEPLOYMENT_FILE_BYTES:
            raise PagesBuildError(f"Pages output file exceeds byte limit: {relative}")
        total_bytes += len(payload)
        if total_bytes > MAX_DEPLOYMENT_TOTAL_BYTES:
            raise PagesBuildError("Pages output exceeds the total byte limit")
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
        if len(entries) > MAX_DEPLOYMENT_FILES:
            raise PagesBuildError("Pages output exceeds the file-count limit")
    paths = [entry["path"] for entry in entries]
    if any(path not in paths for path in CRITICAL_DEPLOYMENT_PATHS):
        raise PagesBuildError("Pages output omits a critical deployment path")
    manifest = {
        "claim_boundary": DEPLOYMENT_MANIFEST_CLAIM_BOUNDARY,
        "critical_paths": list(CRITICAL_DEPLOYMENT_PATHS),
        "file_count": len(entries),
        "files": entries,
        "manifest_path": DEPLOYMENT_MANIFEST_PATH,
        "schema": DEPLOYMENT_MANIFEST_SCHEMA,
        "source_ref": source_ref,
        "total_bytes": total_bytes,
    }
    target = output / DEPLOYMENT_MANIFEST_PATH
    target.write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return target


def build(output: Path, *, source_ref: str = "WORKTREE") -> tuple[Path, ...]:
    """Build into a new or empty directory and return every copied schema path."""
    output = output.resolve()
    if output == ROOT:
        raise PagesBuildError("Pages output cannot be the repository root")
    if output.exists() and any(output.iterdir()):
        raise PagesBuildError(f"refusing to merge into non-empty Pages output: {output}")
    if output.exists():
        output.rmdir()

    # Build the exact-coordinate index before creating any repository-local Pages
    # output. Otherwise a caller-selected output directory can make a clean checkout
    # appear dirty to the component snapshotter merely by being created.
    with tempfile.TemporaryDirectory(prefix="vstd-pages-components-") as temporary:
        staged_components = Path(temporary) / "components"
        _build_component_index(staged_components, source_ref=source_ref)
        shutil.copytree(DOCS, output)
        shutil.copytree(staged_components, output / "components")
    schema_output = output / "schemas"
    schema_output.mkdir()
    copied: list[Path] = []
    sources = sorted(
        (source for directory in SCHEMA_SOURCES for source in directory.glob("*.json")),
        key=lambda path: path.name,
    )
    if len({source.name for source in sources}) != len(sources):
        raise PagesBuildError("public schema source names must be unique")
    for source in sources:
        payload = json.loads(source.read_text(encoding="utf-8"))
        schema_id = payload.get("$id", "")
        expected_id = PUBLIC_SCHEMA_PREFIX + source.name
        if schema_id != expected_id:
            raise PagesBuildError(
                f"schema $id does not match its Pages route: {source.name}: {schema_id!r}"
            )
        target = schema_output / source.name
        shutil.copyfile(source, target)
        copied.append(target)

    if not copied:
        raise PagesBuildError("no public schemas were assembled")
    coordinate = _documentation_coordinate(source_ref)
    (output / "documentation-coordinate.json").write_text(
        json.dumps(coordinate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _build_documentation(output, source_ref=source_ref)
    _write_deployment_manifest(output, source_ref=source_ref)
    return tuple(copied)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ref", default="WORKTREE")
    args = parser.parse_args(argv)
    copied = build(args.output, source_ref=args.source_ref)
    print(
        f"[PAGES OK] site assembled with {len(copied)} schema routes "
        "and navigable documentation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
