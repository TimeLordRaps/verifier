"""Bounded exact-byte snapshots for the command-line interface (CLI).

Secure Hash Algorithm 256-bit (SHA-256); JavaScript Object Notation (JSON).
These local observations establish no numbered profile or exclusive filesystem ownership.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.metadata
import os
from pathlib import Path
import stat
import sys
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def record(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        raise ValueError("record byte limit exceeded")
    value = strict_json_loads(raw.decode("utf-8"))
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value


def read_bytes(path: str | Path, maximum: int = MAX_RECORD_BYTES) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("selected input byte limit exceeded")
    return raw


def ordinary(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("linked or reparse-point artifact refused")
    return info


@dataclass(frozen=True)
class Snapshot:
    kind: str
    files: dict[str, bytes]

    def inventory(self) -> dict[str, Any]:
        rows = [{"path": name, "size_bytes": len(raw), "digest": digest(raw)}
                for name, raw in sorted(self.files.items())]
        commitment = digest(next(iter(self.files.values()))) if self.kind == "file" else digest(canonical_bytes(rows))
        return {"kind": self.kind, "digest": commitment, "files": rows}

    def materialize(self, directory: Path) -> None:
        for name, raw in sorted(self.files.items()):
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)


def capture(path: str | Path) -> Snapshot:
    target = Path(path).absolute()
    # Reject aliases in every parent, not just the selected final entry.
    for parent in (target, *target.parents):
        ordinary(parent)
    info = ordinary(target)
    files: dict[str, bytes] = {}
    total = 0

    def add(selected: Path, name: str) -> None:
        nonlocal total
        metadata = ordinary(selected)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("ordinary artifact file required")
        if len(files) >= MAX_FILES or metadata.st_size > min(MAX_FILE_BYTES, MAX_TOTAL_BYTES-total):
            raise ValueError("artifact inventory or byte limit exceeded")
        if ("\\" in name or ":" in name or any(ord(c) < 32 for c in name)
                or any(p in {"", ".", ".."} for p in name.split("/"))):
            raise ValueError("portable artifact path required")
        raw = read_bytes(selected, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES-total))
        total += len(raw)
        files[name] = raw

    if stat.S_ISREG(info.st_mode):
        # A single-file address binds its bytes, independent of the local filename.
        add(target, "artifact" + (".pr.md" if target.name.endswith(".pr.md") else target.suffix.lower()))
        kind = "file"
    elif stat.S_ISDIR(info.st_mode):
        def unavailable(error: OSError) -> None:
            raise error
        entries = 0
        for root, directories, names in os.walk(target, followlinks=False, onerror=unavailable):
            entries += 1 + len(directories) + len(names)
            if entries > 4096:
                raise ValueError("artifact traversal limit exceeded")
            directories.sort()
            for name in directories:
                if not stat.S_ISDIR(ordinary(Path(root)/name).st_mode):
                    raise ValueError("ordinary artifact directory required")
            for name in sorted(names):
                selected = Path(root)/name
                add(selected, selected.relative_to(target).as_posix())
        kind = "directory"
    else:
        raise ValueError("ordinary artifact file or directory required")
    if not files:
        raise ValueError("empty artifact inventory")
    return Snapshot(kind, files)


def output_outside(path: str | Path | None, artifact: str | Path) -> None:
    if path is None:
        return
    destination, source = Path(path).absolute(), Path(artifact).absolute()
    if destination == source or source.is_dir() and source in destination.parents:
        raise ValueError("workflow output must be outside the artifact snapshot")


def write_new(path: str | Path | None, value: dict[str, Any]) -> None:
    if path is not None:
        with Path(path).open("xb") as stream:
            stream.write(canonical_bytes(value) + b"\n")


def implementation_digest() -> str:
    """Pin all installed checker, policy, schema and specification bytes."""
    root = Path(__file__).parents[1]
    rows = {p.relative_to(root).as_posix(): digest(p.read_bytes())
            for p in sorted(root.rglob("*")) if p.is_file() and p.suffix in {".py", ".md", ".json"}}
    versions = {}
    for name in ("cryptography", "cbor2", "scitt-cose", "pyyaml", "jsonschema", "llguidance", "torch"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return digest(canonical_bytes({"installed_sources": rows, "optional_dependency_versions": versions,
        "interpreter_version": sys.version, "interpreter_digest": digest(Path(sys.executable).read_bytes()),
        "platform": sys.platform}))
