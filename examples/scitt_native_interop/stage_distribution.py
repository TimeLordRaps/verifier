"""Local Supply Chain Integrity, Transparency, and Trust (SCITT) byte staging.

Secure Hash Algorithm 256-bit (SHA-256); JavaScript Object Notation (JSON).
Copy only three already admitted sibling files into an absent digest-named child
of an explicitly selected local directory. This is not publication, native
execution, qualification, publisher authentication, or an atomic filesystem
snapshot. The existing entry binds reconstruction sources, not this staging
tool. A failed newly created directory is retained without cleanup; a later
attempt refuses it. No ready marker, server, source copy, or network operation.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

if __package__:
    from . import catalog_entry
    from .native_runner import _ordinary, _write_new, read_regular
else:
    import catalog_entry
    from native_runner import _ordinary, _write_new, read_regular
from verifier.core.receipt import strict_json_loads


MAX_ROOT_ENTRIES = 4096
BOUNDARY = "Local exact-byte staging only; no publication, native execution, qualification, authority, or atomic filesystem snapshot."


class DistributionStageError(ValueError):
    """Staging failed after exclusive creation; retained bytes may be partial."""


def _refuse_existing_child(root: Path, name: str) -> None:
    _ordinary(root, directory=True)
    with os.scandir(root) as entries:
        for count, item in enumerate(entries, 1):
            if count > MAX_ROOT_ENTRIES:
                raise ValueError("staging root inventory exceeds its entry bound")
            if item.name.casefold() == name.casefold():
                raise FileExistsError("digest destination or case alias already exists")


def _disjoint(source: Path, target: Path) -> None:
    left, right = (tuple(part.casefold() for part in path.parts) for path in (source, target))
    if left[:len(right)] == right or right[:len(left)] == left:
        raise ValueError("source and output root must be disjoint, non-nested directories")


def _exact_names(directory: Path, expected: set[str]) -> None:
    _ordinary(directory, directory=True)
    names = set()
    with os.scandir(directory) as entries:
        for item in entries:
            names.add(item.name)
            if len(names) > 3 or item.name not in expected:
                raise ValueError("staged destination must contain exactly the three admitted filenames")
    if names != expected:
        raise ValueError("staged destination must contain exactly the three admitted filenames")


def stage_distribution(entry_path: Path, *, expected_entry_digest: str, output_root: Path) -> dict[str, Any]:
    """Inspect, snapshot, exclusively stage, and reinspect without executing native checkers."""
    catalog_entry._digest(expected_entry_digest)
    entry_path, output_root = (Path(os.path.abspath(path)) for path in (entry_path, output_root))
    _ordinary(output_root, directory=True)
    _ordinary(entry_path.parent, directory=True)
    _disjoint(entry_path.parent, output_root)
    _refuse_existing_child(output_root, expected_entry_digest)
    inspected = catalog_entry.inspect_entry(entry_path, expected_entry_digest=expected_entry_digest)
    prior_result = catalog_entry.comparison.canonical(inspected)
    entry_bytes = read_regular(entry_path, catalog_entry.MAX_ENTRY_BYTES)
    # Check identity BEFORE deriving any sibling location from reread bytes.
    if catalog_entry.comparison.sha(entry_bytes) != expected_entry_digest:
        raise ValueError("entry changed before snapshot; no sibling locations admitted")
    manifest = catalog_entry._manifest(strict_json_loads(entry_bytes))
    if catalog_entry.comparison.canonical(manifest) != entry_bytes:
        raise ValueError("entry snapshot must retain canonical transport")
    names = [entry_path.name, manifest["package"]["filename"], manifest["sidecar"]["filename"]]
    if len({name.casefold() for name in names}) != 3:
        raise ValueError("three distinct sibling locations required")
    limits = {entry_path.name: catalog_entry.MAX_ENTRY_BYTES,
              names[1]: catalog_entry.MAX_PACKAGE_BYTES, names[2]: catalog_entry.MAX_SIDECAR_BYTES}
    snapshot = {entry_path.name: entry_bytes}
    for key in ("package", "sidecar"):
        name = manifest[key]["filename"]
        raw = read_regular(entry_path.parent / name, limits[name])
        if catalog_entry.comparison.sha(raw) != manifest[key]["sha256"]:
            raise ValueError("artifact changed before snapshot; no bytes staged")
        snapshot[name] = raw

    def check_sources() -> None:
        catalog_entry._check_import_locations()
        if catalog_entry.source_inventory() != manifest["reconstruction_sources"]:
            raise ValueError("reconstruction source inventory changed during staging")
        if any(read_regular(entry_path.parent / name, limits[name]) != raw for name, raw in snapshot.items()):
            raise ValueError("admitted source artifact changed during staging")

    check_sources()
    _refuse_existing_child(output_root, expected_entry_digest)
    destination = output_root / expected_entry_digest
    os.mkdir(destination)
    try:
        # Write the entry last, after both referenced files have been retained.
        for name in (names[1], names[2], names[0]):
            _write_new(destination / name, snapshot[name])
        _exact_names(destination, set(names))
        check_sources()
        reproduced = catalog_entry.inspect_entry(destination / entry_path.name, expected_entry_digest=expected_entry_digest)
        if catalog_entry.comparison.canonical(reproduced) != prior_result:
            raise ValueError("staged comparison differs from admitted reconstruction")
        _exact_names(destination, set(names))
        if any(read_regular(destination / name, limits[name]) != raw for name, raw in snapshot.items()):
            raise ValueError("staged bytes changed during final inspection")
        check_sources()
    except Exception as exc:
        raise DistributionStageError("staging failed; newly created destination is retained and may be partial; no cleanup performed") from exc
    return {"entry_digest": expected_entry_digest, "destination": str(destination),
            "filenames": sorted(names), "native_execution_performed": False,
            "network_operations_performed": False, "claim_boundary": BOUNDARY}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("entry", type=Path)
    parser.add_argument("--expected-entry-sha256", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args(argv)
    result = stage_distribution(args.entry, expected_entry_digest=args.expected_entry_sha256, output_root=args.output_root)
    print(catalog_entry.comparison.canonical(result).decode("ascii"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
