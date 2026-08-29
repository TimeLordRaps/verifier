#!/usr/bin/env python3
"""Terminology: uniform resource locator (URL).

Assemble the exact GitHub Pages artifact without duplicating schema sources.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SCHEMA_SOURCES = (ROOT / "receipts/schema", ROOT / "standard/schemas")
PUBLIC_SCHEMA_PREFIX = "https://timelordraps.github.io/verifier/schemas/"
CANONICAL_BASE_URL = "https://timelordraps.github.io/verifier/"


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
    release_state = "UNRELEASED_CANDIDATE" if heading.group(1) == "UNRELEASED" else "RELEASED"
    return {
        "schema_version": 1,
        "documentation_version": version,
        "release_state": release_state,
        "source_ref": source_ref,
        "canonical_base_url": CANONICAL_BASE_URL,
        "normative_source": "standard/",
    }


def build(output: Path, *, source_ref: str = "WORKTREE") -> tuple[Path, ...]:
    """Build into a new or empty directory and return every copied schema path."""
    output = output.resolve()
    if output == ROOT:
        raise PagesBuildError("Pages output cannot be the repository root")
    if output.exists() and any(output.iterdir()):
        raise PagesBuildError(f"refusing to merge into non-empty Pages output: {output}")
    if output.exists():
        output.rmdir()

    shutil.copytree(DOCS, output)
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
