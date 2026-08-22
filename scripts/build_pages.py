#!/usr/bin/env python3
"""Assemble the exact GitHub Pages artifact without duplicating schema sources."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SCHEMAS = ROOT / "receipts/schema"
PUBLIC_SCHEMA_PREFIX = "https://timelordraps.github.io/verifier/schemas/"


class PagesBuildError(RuntimeError):
    pass


def build(output: Path) -> tuple[Path, ...]:
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
    for source in sorted(SCHEMAS.glob("*.json")):
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
    return tuple(copied)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    copied = build(args.output)
    print(f"[PAGES OK] site assembled with {len(copied)} schema routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
