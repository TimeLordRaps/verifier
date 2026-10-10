"""Freeze exact Supply Chain Integrity, Transparency, and Trust (SCITT) sources.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256); JavaScript
Object Notation (JSON). Retain an admitted source-only reconstruction contract
using existing unsealed artifact control. No native execution, source imports
from retained data, installation, network, publication, seal, or thaw occurs.
The locally produced artifact identifier is a consistency coordinate, not
publisher authentication. Snapshots are bounded observations, not filesystem
atomicity or loaded-byte attestation. Source-stage and completed bundle remain
on failure; artifact control may clean only its own internal temporary staging.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import catalog_entry
from native_runner import _ordinary, _write_new, read_regular
from stage_distribution import _disjoint, _refuse_existing_child
from verifier.artifact_control import freeze_artifact, verify_frozen_artifact
from verifier.core.receipt import strict_json_loads


class ReconstructionFreezeError(ValueError):
    """Created outputs are retained after failure; no publication is established."""


def _directories(snapshot: dict[str, bytes]) -> set[str]:
    return {parent.as_posix() for name in snapshot for parent in Path(name).parents if parent != Path(".")}


def _check_tree(root: Path, snapshot: dict[str, bytes]) -> None:
    """Require exact bounded file bytes and only their implied directories."""
    expected_dirs = _directories(snapshot)
    pending, seen_files, seen_dirs = [root], set(), set()
    visited = 0
    while pending:
        directory = pending.pop()
        _ordinary(directory, directory=True)
        with os.scandir(directory) as entries:
            for item in entries:
                visited += 1
                if visited > catalog_entry.MAX_WALK_ENTRIES:
                    raise ValueError("reconstruction tree exceeds its walk bound")
                path = Path(item.path)
                relative = path.relative_to(root).as_posix()
                if item.is_dir(follow_symlinks=False):
                    _ordinary(path, directory=True)
                    if relative not in expected_dirs:
                        raise ValueError("unexpected reconstruction directory")
                    seen_dirs.add(relative)
                    pending.append(path)
                else:
                    _ordinary(path, directory=False)
                    if relative not in snapshot:
                        raise ValueError("unexpected reconstruction file")
                    if read_regular(path, len(snapshot[relative])) != snapshot[relative]:
                        raise ValueError("reconstruction file bytes differ")
                    seen_files.add(relative)
    if seen_files != set(snapshot) or seen_dirs != expected_dirs:
        raise ValueError("reconstruction tree is incomplete")


def freeze_reconstruction(entry_path: Path, *, expected_entry_digest: str, source_stage: Path, bundle_path: Path) -> dict[str, Any]:
    """Retain exact allowlisted sources and transport; never run retained code."""
    catalog_entry._digest(expected_entry_digest)
    entry_path, source_stage, bundle_path = (Path(os.path.abspath(path)) for path in (entry_path, source_stage, bundle_path))
    for destination in (source_stage, bundle_path):
        _ordinary(destination.parent, directory=True)
        _disjoint(destination, catalog_entry.ROOT)
        _disjoint(destination, entry_path.parent)
        _refuse_existing_child(destination.parent, destination.name)
    _disjoint(source_stage, bundle_path)
    catalog_entry.inspect_entry(entry_path, expected_entry_digest=expected_entry_digest)
    entry_bytes = read_regular(entry_path, catalog_entry.MAX_ENTRY_BYTES)
    if catalog_entry.comparison.sha(entry_bytes) != expected_entry_digest:
        raise ValueError("entry changed before snapshot; no locations admitted")
    manifest = catalog_entry._manifest(strict_json_loads(entry_bytes))
    if catalog_entry.comparison.canonical(manifest) != entry_bytes:
        raise ValueError("entry snapshot is not canonical")
    snapshot, originals = {}, {}
    total = 0
    for name, digest in manifest["reconstruction_sources"].items():
        source = catalog_entry.ROOT / name
        raw = read_regular(source, catalog_entry.MAX_SOURCE_BYTES)
        total += len(raw)
        if total > catalog_entry.MAX_TOTAL_SOURCE_BYTES:
            raise ValueError("source snapshot exceeds its aggregate byte bound")
        if catalog_entry.comparison.sha(raw) != digest:
            raise ValueError("reconstruction source changed before snapshot")
        snapshot[name], originals[name] = raw, source
    for name, digest in catalog_entry.comparison.VSTD_NOTICE_PINS.items():
        source = catalog_entry.ROOT / name
        raw = read_regular(source, catalog_entry.MAX_SOURCE_BYTES)
        if catalog_entry.comparison.sha(raw) != digest:
            raise ValueError("root license or notice differs from decoder pins")
        snapshot[name], originals[name] = raw, source
    key = "entry/" + entry_path.name
    snapshot[key], originals[key] = entry_bytes, entry_path
    for role, limit in (("package", catalog_entry.MAX_PACKAGE_BYTES), ("sidecar", catalog_entry.MAX_SIDECAR_BYTES)):
        name = manifest[role]["filename"]
        key, source = "entry/" + name, entry_path.parent / name
        if key in snapshot:
            raise ValueError("entry transport paths must be distinct")
        raw = read_regular(source, limit)
        if catalog_entry.comparison.sha(raw) != manifest[role]["sha256"]:
            raise ValueError("admitted transport changed before snapshot")
        snapshot[key], originals[key] = raw, source

    def check_originals() -> None:
        catalog_entry._check_import_locations()
        if catalog_entry.source_inventory() != manifest["reconstruction_sources"]:
            raise ValueError("complete reconstruction source inventory changed")
        if any(read_regular(originals[name], len(raw)) != raw for name, raw in snapshot.items()):
            raise ValueError("admitted original changed during reconstruction freeze")

    check_originals()
    for destination in (source_stage, bundle_path):
        _refuse_existing_child(destination.parent, destination.name)
    os.mkdir(source_stage)
    try:
        for name in sorted(_directories(snapshot), key=lambda item: (len(Path(item).parts), item)):
            parent = source_stage / name
            _ordinary(parent.parent, directory=True)
            os.mkdir(parent)
        for name, raw in sorted(snapshot.items()):
            _write_new(source_stage / name, raw)
        _check_tree(source_stage, snapshot)
        check_originals()
        _refuse_existing_child(bundle_path.parent, bundle_path.name)
        frozen = freeze_artifact(source_stage, bundle_path)
        _ordinary(bundle_path, directory=True)
        _check_tree(bundle_path / "payload", snapshot)
        verified = verify_frozen_artifact(bundle_path, require_seal=False, expected_artifact_id=frozen["artifact_id"])
        if verified.state != "FROZEN_UNSEALED" or not verified.freeze_valid or not verified.guard_valid or verified.errors:
            raise ValueError("unsealed reconstruction bundle did not verify")
        _check_tree(source_stage, snapshot)
        _check_tree(bundle_path / "payload", snapshot)
        check_originals()
    except Exception as exc:
        raise ReconstructionFreezeError("reconstruction freeze failed; created source-stage and any completed bundle are retained; no publication established") from exc
    return {"entry_digest": expected_entry_digest, "source_stage": str(source_stage),
            "bundle_path": str(bundle_path), "artifact_id": verified.artifact_id,
            "freeze_id": verified.freeze_id, "state": verified.state,
            "retained_file_count": len(snapshot), "native_execution_performed": False,
            "claim_boundary": "Exact local source/transport retention only; self-produced identity is not publisher authentication, execution evidence, qualification, or publication."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("entry", type=Path)
    parser.add_argument("--expected-entry-sha256", required=True)
    parser.add_argument("--source-stage", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    result = freeze_reconstruction(args.entry, expected_entry_digest=args.expected_entry_sha256, source_stage=args.source_stage, bundle_path=args.bundle)
    print(catalog_entry.comparison.canonical(result).decode("ascii"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
