"""Local Supply Chain Integrity, Transparency, and Trust (SCITT) comparison entry.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256); JavaScript
Object Notation (JSON). Canonical entry bytes bind retained package and sidecar
bytes to a selected checkout's complete Python source inventory. This is local
distribution preparation, not publisher authentication, native qualification,
independence, runtime attestation, or proof of which bytes the interpreter loaded.
Consumers supply the expected entry digest separately. Entries never authorize
execution or select imports. Raw transport digests also bind package formatting;
the complete canonical package digest separately binds its normalized contents.
Creation refuses overwrite, but provides no atomic filesystem snapshot or guard
against privileged later writes. Only this source-checkout contract is supported.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
from typing import Any

from verifier.core.receipt import strict_json_loads
from verifier.interoperability.storage import MAX_PACKAGE_BYTES, StoredComponentPackage

import package_comparison as comparison
import native_runner
from native_runner import _ordinary, _write_new, read_regular


FORMAT = "SCITT-COMPARISON-ENTRY-1"
ROOT = Path(__file__).absolute().parents[2]
MAX_ENTRY_BYTES = 128 * 1024
MAX_SIDECAR_BYTES = 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
MAX_WALK_ENTRIES = 4096
TOOLS = tuple("examples/scitt_native_interop/" + name for name in (
    "native_runner.py", "package_comparison.py", "catalog_entry.py",
))


def _check_import_locations() -> None:
    """Refuse obvious shadowed imports; file locations do not attest loaded bytes."""
    expected_tools = ((comparison, ROOT / TOOLS[1]), (native_runner, ROOT / TOOLS[0]))
    for module, expected in expected_tools:
        location = getattr(module, "__file__", None)
        if type(location) is not str or Path(os.path.abspath(location)) != expected:
            raise ValueError("reconstruction tool import is outside the selected checkout")
        _ordinary(expected, directory=False)
    for name, module in tuple(sys.modules.items()):
        if name != "verifier" and not name.startswith("verifier."):
            continue
        location = getattr(module, "__file__", None)
        base = ROOT / "src" / Path(*name.split("."))
        if location is None and getattr(getattr(module, "__spec__", None), "origin", None) is None:
            namespace_paths = tuple(getattr(module, "__path__", ()))
            if len(namespace_paths) != 1 or Path(os.path.abspath(namespace_paths[0])) != base:
                raise ValueError("verifier namespace import is outside the selected source checkout")
            _ordinary(base, directory=True)
            continue
        allowed = (base.with_suffix(".py"), base / "__init__.py")
        if type(location) is not str or Path(os.path.abspath(location)) not in allowed:
            raise ValueError("verifier import is outside the selected source checkout")
        _ordinary(Path(location), directory=False)


def _digest(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("digest must be 64 lowercase hexadecimal characters")
    return value


def _filename(value: Any) -> str:
    if (type(value) is not str or len(value) > 128
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is None
            or value.endswith(".")
            or value.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}):
        raise ValueError("artifact location must be an ordinary relative sibling filename")
    return value


def source_inventory() -> dict[str, str]:
    """Observe bounded checkout sources, not loaded code or native dependencies."""
    source_root = ROOT / "src/verifier"
    _ordinary(source_root, directory=True)
    pending, paths, visited = [source_root], [], 0
    while pending:
        directory = pending.pop()
        _ordinary(directory, directory=True)
        with os.scandir(directory) as entries:
            for item in entries:
                visited += 1
                if visited > MAX_WALK_ENTRIES:
                    raise ValueError("source walk exceeds its entry bound")
                path = Path(item.path)
                if item.is_dir(follow_symlinks=False):
                    _ordinary(path, directory=True)
                    pending.append(path)
                else:
                    _ordinary(path, directory=False)
                    if path.suffix.casefold() == ".py" and path.suffix != ".py":
                        raise ValueError("Python source suffix must have canonical lowercase spelling")
                    if path.suffix == ".py":
                        paths.append(path)
                        if len(paths) + len(TOOLS) > MAX_SOURCE_FILES:
                            raise ValueError("source inventory exceeds its file bound")
    if source_root / "__init__.py" not in paths:
        raise ValueError("complete source checkout required")
    paths.extend(ROOT / name for name in TOOLS)
    result, total, folded = {}, 0, set()
    for path in paths:
        name = path.relative_to(ROOT).as_posix()
        if name.casefold() in folded:
            raise ValueError("case-folded reconstruction source collision")
        folded.add(name.casefold())
        data = read_regular(path, MAX_SOURCE_BYTES)
        total += len(data)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise ValueError("source inventory exceeds its total byte bound")
        result[name] = comparison.sha(data)
    return result


def _manifest(value: Any) -> dict[str, Any]:
    value = comparison.object_fields(value, {"schema_version", "package", "sidecar", "reconstruction_sources"})
    if type(value["schema_version"]) is not str or value["schema_version"] != FORMAT:
        raise ValueError("unsupported comparison entry format")
    for name, keys in (("package", {"filename", "sha256", "canonical_digest"}), ("sidecar", {"filename", "sha256"})):
        item = comparison.object_fields(value[name], keys)
        _filename(item["filename"])
        for key in keys - {"filename"}:
            _digest(item[key])
    if value["package"]["filename"].casefold() == value["sidecar"]["filename"].casefold():
        raise ValueError("package and sidecar locations must be distinct")
    sources = value["reconstruction_sources"]
    if type(sources) is not dict or not 1 <= len(sources) <= MAX_SOURCE_FILES:
        raise ValueError("bounded complete source inventory required")
    if any(type(name) is not str for name in sources) or len({name.casefold() for name in sources}) != len(sources):
        raise ValueError("case-folded reconstruction source collision")
    for name, digest in sources.items():
        if type(name) is not str or len(name) > 256 or (name not in TOOLS and re.fullmatch(r"src/verifier/(?:[A-Za-z_][A-Za-z_0-9]*/)*[A-Za-z_][A-Za-z_0-9]*\.py", name) is None):
            raise ValueError("unsupported reconstruction source location")
        _digest(digest)
    return value


def _reconstruct(parent: Path, manifest: dict[str, Any], sources: dict[str, str]) -> dict[str, Any]:
    _check_import_locations()
    if sources != manifest["reconstruction_sources"]:
        raise ValueError("reconstruction source inventory differs")
    paths = {key: parent / manifest[key]["filename"] for key in ("package", "sidecar")}
    limits = {"package": MAX_PACKAGE_BYTES, "sidecar": MAX_SIDECAR_BYTES}
    raw = {key: read_regular(paths[key], limits[key]) for key in paths}
    if any(comparison.sha(raw[key]) != manifest[key]["sha256"] for key in paths):
        raise ValueError("retained artifact bytes differ from entry")
    package = StoredComponentPackage.from_dict(strict_json_loads(raw["package"]))
    if package.canonical_digest() != manifest["package"]["canonical_digest"]:
        raise ValueError("complete package coordinate differs from entry")
    report = comparison.reconstruct_sidecar(package, strict_json_loads(raw["sidecar"]), expected_digest=manifest["package"]["canonical_digest"])
    _check_import_locations()
    if source_inventory() != sources:
        raise ValueError("reconstruction source inventory changed during comparison")
    if any(read_regular(paths[key], limits[key]) != raw[key] for key in paths):
        raise ValueError("retained artifact changed during comparison")
    return report


def create_entry(entry_path: Path, package_path: Path, sidecar_path: Path) -> dict[str, Any]:
    """Reconstruct existing siblings and exclusively create canonical entry bytes."""
    entry_path, package_path, sidecar_path = (Path(os.path.abspath(path)) for path in (entry_path, package_path, sidecar_path))
    _ordinary(entry_path.parent, directory=True)
    paths = (entry_path, package_path, sidecar_path)
    for path in paths:
        _filename(path.name)
        if path.parent != entry_path.parent:
            raise ValueError("entry artifacts must be relative siblings")
    if len({path.name.casefold() for path in paths}) != 3:
        raise ValueError("entry and artifact locations must be distinct")
    if os.path.lexists(entry_path):
        raise FileExistsError("entry destination must be absent")
    _check_import_locations()
    sources = source_inventory()
    package_raw = read_regular(package_path, MAX_PACKAGE_BYTES)
    sidecar_raw = read_regular(sidecar_path, MAX_SIDECAR_BYTES)
    package = StoredComponentPackage.from_dict(strict_json_loads(package_raw))
    manifest = _manifest({"schema_version": FORMAT,
        "package": {"filename": package_path.name, "sha256": comparison.sha(package_raw), "canonical_digest": package.canonical_digest()},
        "sidecar": {"filename": sidecar_path.name, "sha256": comparison.sha(sidecar_raw)},
        "reconstruction_sources": sources})
    report = _reconstruct(entry_path.parent, manifest, sources)
    data = comparison.canonical(manifest)
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError("entry exceeds its byte bound")
    if source_inventory() != sources or read_regular(package_path, MAX_PACKAGE_BYTES) != package_raw or read_regular(sidecar_path, MAX_SIDECAR_BYTES) != sidecar_raw:
        raise ValueError("entry dependencies changed before exclusive creation")
    _write_new(entry_path, data)
    return {"entry_digest": comparison.sha(data), "comparison": report}


def inspect_entry(entry_path: Path, *, expected_entry_digest: str) -> dict[str, Any]:
    """Check separately selected canonical entry identity before reconstruction."""
    _digest(expected_entry_digest)
    entry_path = Path(os.path.abspath(entry_path))
    _filename(entry_path.name)
    data = read_regular(entry_path, MAX_ENTRY_BYTES)
    if comparison.sha(data) != expected_entry_digest:
        raise ValueError("entry differs from separately supplied expected digest")
    manifest = _manifest(strict_json_loads(data))
    if comparison.canonical(manifest) != data:
        raise ValueError("entry transport must be canonical")
    if entry_path.name.casefold() in {manifest[key]["filename"].casefold() for key in ("package", "sidecar")}:
        raise ValueError("entry and artifact locations must be distinct")
    report = _reconstruct(entry_path.parent, manifest, source_inventory())
    if read_regular(entry_path, MAX_ENTRY_BYTES) != data:
        raise ValueError("entry changed during reconstruction")
    return {"entry_digest": expected_entry_digest, "comparison": report}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("entry", type=Path)
    create.add_argument("package", type=Path)
    create.add_argument("sidecar", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("entry", type=Path)
    inspect.add_argument("--expected-entry-sha256", required=True)
    args = parser.parse_args(argv)
    result = (create_entry(args.entry, args.package, args.sidecar) if args.command == "create"
              else inspect_entry(args.entry, expected_entry_digest=args.expected_entry_sha256))
    print(comparison.canonical(result).decode("ascii"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
