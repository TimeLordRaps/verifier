"""Small human-facing entry points for Verifier Standard (VSTD) admission.

JavaScript Object Notation (JSON) mode is a read-only preview. Writing a draft is
exclusive-create: an existing manifest is never overwritten or silently migrated.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from verifier.runtime.tier_zero_profile import canonical_bytes

# Publishing local file bytes is a transaction with explicit failure limits,
# even though this command neither keeps a ledger nor establishes admission.
__vstd_kinds__ = ("TRANSACTION",)


def add_namespace_parsers(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("template", help="Discover source objects and draft an extensible objects.vstd.")
    parser.add_argument("--source-root", default=".", help="Git repository to discover without executing its code.")
    parser.add_argument("--json", action="store_true", help="Preview the draft, evidence references and suggestions without writing.")
    parser.add_argument("--namespace-extension", action="append", default=[], metavar="JSON",
                        help="Add a declarative kind contract; repeat in parent-before-child order. No extension code executes.")
    formatter = subparsers.add_parser("format", help="Canonicalize a JSON declaration without changing its meaning or evidence digests.")
    formatter.add_argument("manifest", nargs="?", default="objects.vstd")
    formatter.add_argument("--write", action="store_true", help="Replace this exact file after verifying its original bytes are unchanged.")


def handle_template(args: argparse.Namespace) -> int:
    from verifier.runtime.namespace_admission import build_template
    from verifier.runtime.namespace_manifest import read_manifest
    root = Path(args.source_root).resolve(strict=True)
    extensions = [read_manifest(Path(path), require_canonical=False)[1] for path in args.namespace_extension]
    result = build_template(root, extensions=extensions)
    if args.json:
        print(json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False))
    else:
        target = root / "objects.vstd"
        # Exclusive creation also protects against a concurrent writer between
        # discovery and publication. A failed creation preserves their bytes.
        try:
            with target.open("xb") as stream:
                stream.write(canonical_bytes(result["manifest"]) + b"\n")
        except FileExistsError:
            print("[REFUSED] objects.vstd already exists; no bytes changed. Use vstd template --json to inspect a migration draft.")
            return 1
        print("[DRAFT] Created objects.vstd; no classification or obligation is certified.")
        print("Next: run vstd polish 0 for exact object, obligation, reason and evidence instructions.")
        print("Use vstd template --json to inspect discovered labels and current evidence references.")
    return 0


def handle_format(args: argparse.Namespace) -> int:
    """Whitespace is a usability concern, not evidence. Never repair declarations."""
    from verifier.runtime.namespace_manifest import read_manifest
    target = Path(args.manifest).absolute()
    before, value = read_manifest(target, require_canonical=False)
    after = canonical_bytes(value) + b"\n"
    if not args.write:
        sys.stdout.write(after.decode("utf-8"))
        return 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".vstd-format-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(after)
        if target.is_symlink() or target.read_bytes() != before:
            raise ValueError("NAMESPACE_FORMAT_SOURCE_CHANGED")
        os.replace(temporary, target)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()  # Only our own unpublished temporary file.
    print("[FORMATTED] Canonical JSON written; no labels, reasons, references or verdicts were changed.")
    return 0
