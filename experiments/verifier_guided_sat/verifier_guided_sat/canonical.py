# Acronyms: JavaScript Object Notation (JSON); line feed (LF);
# Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
"""Location-independent serialization and artifact hashing for the experiment."""

from __future__ import annotations

import hashlib
import gzip
import json
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """Return the experiment's deterministic UTF-8 JSON representation."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    """Return a tagged SHA-256 digest of canonical JSON."""

    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    """Return a tagged SHA-256 digest of exact file bytes."""

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    """Write deterministic, human-readable JSON with LF endings."""

    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    if path.suffix == ".gz":
        path.write_bytes(gzip.compress(text.encode("utf-8"), compresslevel=9, mtime=0))
    else:
        path.write_text(text, encoding="utf-8", newline="\n")


def read_json(path: Path) -> Any:
    """Read a JSON artifact."""

    if path.suffix == ".gz":
        return json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
    return json.loads(path.read_text(encoding="utf-8"))
