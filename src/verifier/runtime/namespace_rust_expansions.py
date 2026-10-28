"""Source-bound interface discovery for two closed Rust expansion families.

Terminology: Executable and Linkable Format (ELF); reduced instruction set
computer (RISC).

This module does not run Cargo, rustc, a build script, or procedural macro
code.  It recognizes only exact, version-pinned source relationships whose
interface projection is finite:

* Serde ``Serialize``/``Deserialize`` derives become trait-implementation
  surfaces when the crate manifest, workspace lock and toolchain are bound.
* RISC Zero 3.0.6 ``embed_methods`` includes become the two documented
  ``*_ELF``/``*_ID`` constant names derived from each selected guest package.

Anything outside those grammars remains an unresolved Rust expansion.  The
projection establishes names and dependency edges only; it does not claim a
successful build, generated values, dependency correctness or execution.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any

from verifier.runtime.self_polish_estate import bytes_digest


BINDING_VERSION = "verifier-rust-expansion-binding-1"
_EXPANSION_FORMS = frozenset({
    "attribute_item", "macro_invocation", "macro_definition", "inner_attribute_item",
})
_BUILTIN_DERIVES = frozenset({
    "Clone", "Copy", "Debug", "Default", "Eq", "Hash", "Ord", "PartialEq", "PartialOrd",
})
_SERDE_DERIVES = frozenset({"Deserialize", "Serialize"})
_SERDE_PACKAGES = {
    "serde": ("1.0.228", "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e"),
    "serde_derive": ("1.0.228", "d540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79"),
}
_RISC0_BUILD = ("3.0.6", "bd8216cdd9f573808a94769767480b06ad1e74ae60841c9582fdf51b8e29ba53")
_TOOLCHAIN = "1.97"
_CLAIM_SCOPE = (
    "STATIC_INTERFACE_NAMES_AND_PINNED_DEPENDENCY_EDGES_ONLY;NO_BUILD_SUCCESS,"
    "GENERATED_VALUE,DEPENDENCY_CORRECTNESS,EXECUTION_OR_CONFORMANCE_CLAIM"
)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="strict")


def _section(raw: bytes, name: str) -> str:
    """Return one exact TOML table body without implementing general TOML."""
    text = _text(raw)
    headers = list(re.finditer(r"(?m)^\s*\[([^\[\]\r\n]+)\]\s*(?:#.*)?$", text))
    selected = [index for index, match in enumerate(headers) if match.group(1).strip() == name]
    if len(selected) != 1:
        raise ValueError("NAMESPACE_RUST_EXPANSION_SUPPORT_INVALID")
    index = selected[0]
    start = headers[index].end()
    end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
    return text[start:end]


def _quoted_value(section: str, name: str) -> str:
    matches = re.findall(r"(?m)^\s*" + re.escape(name) + r'\s*=\s*"([^"\r\n]+)"\s*(?:#.*)?$', section)
    if len(matches) != 1:
        raise ValueError("NAMESPACE_RUST_EXPANSION_SUPPORT_INVALID")
    return matches[0]


def _exact_inline_dependency(raw: bytes, table: str, name: str, version: str,
                             *, derive: bool = False) -> None:
    body = _section(raw, table)
    feature = r'\s*,\s*features\s*=\s*\[\s*"derive"\s*\]' if derive else ""
    pattern = (r"(?m)^\s*" + re.escape(name) + r'\s*=\s*\{\s*version\s*=\s*"'
               + re.escape(version) + r'"' + feature + r"\s*\}\s*(?:#.*)?$")
    if len(re.findall(pattern, body)) != 1:
        raise ValueError("NAMESPACE_RUST_EXPANSION_MANIFEST_DIFFERS")


def _string_array(section: str, name: str) -> list[str]:
    matches = re.findall(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*\[([^\]\r\n]*)\]\s*(?:#.*)?$", section)
    if len(matches) != 1:
        raise ValueError("NAMESPACE_RUST_EXPANSION_SUPPORT_INVALID")
    body = matches[0].strip()
    if not body:
        return []
    values = [part.strip() for part in body.split(",")]
    if any(re.fullmatch(r'"[^"\r\n]+"', part) is None for part in values):
        raise ValueError("NAMESPACE_RUST_EXPANSION_SUPPORT_INVALID")
    return [part[1:-1] for part in values]


def _parent_file(path: str, name: str, sources: dict[str, bytes]) -> tuple[str, bytes]:
    parent = PurePosixPath(path).parent
    while str(parent) not in {"", "."}:
        candidate = (parent / name).as_posix()
        if candidate in sources:
            return candidate, sources[candidate]
        parent = parent.parent
    if name in sources:
        return name, sources[name]
    raise ValueError("NAMESPACE_RUST_EXPANSION_SUPPORT_MISSING")


def _locked_package(lock_raw: bytes, name: str,
                    selected: tuple[str, str]) -> dict[str, str]:
    version, checksum = selected
    text = _text(lock_raw)
    blocks = re.split(r"(?m)^\s*\[\[package\]\]\s*(?:#.*)?$", text)[1:]
    matches = []
    for block in blocks:
        block = re.split(r"(?m)^\s*\[\[[^\]]+\]\]\s*(?:#.*)?$", block, maxsplit=1)[0]
        try:
            row = {field: _quoted_value(block, field) for field in ("name", "version", "checksum")}
        except ValueError:
            continue
        if row["name"] == name and row["version"] == version:
            matches.append(row)
    if len(matches) != 1 or matches[0]["checksum"] != checksum:
        raise ValueError("NAMESPACE_RUST_EXPANSION_LOCK_DIFFERS")
    return {"name": name, "version": version, "checksum": checksum}


def _toolchain(path: str, sources: dict[str, bytes]) -> dict[str, str]:
    selected_path, raw = _parent_file(path, "rust-toolchain.toml", sources)
    if _quoted_value(_section(raw, "toolchain"), "channel") != _TOOLCHAIN:
        raise ValueError("NAMESPACE_RUST_EXPANSION_TOOLCHAIN_DIFFERS")
    return {"path": selected_path, "digest": bytes_digest(raw), "channel": _TOOLCHAIN}


def _offset(surface_id: str) -> int:
    match = re.search(r"<expansion@(\d+)>$", surface_id)
    if match is None:
        raise ValueError("NAMESPACE_RUST_EXPANSION_ID_DIFFERS")
    return int(match.group(1))


def _surface(template: dict[str, Any], identifier: str, form: str) -> dict[str, Any]:
    return {"surface_id": identifier, "path": template["path"], "line": template["line"],
            "form": form, "source_kinds": list(template["source_kinds"]),
            "hints": list(template["hints"]), "unresolved_marker": template["unresolved_marker"]}


def _base_binding(kind: str, invocation: dict[str, Any], raw: bytes,
                  manifest_path: str, manifest_raw: bytes, lock_path: str,
                  lock_raw: bytes, toolchain: dict[str, str]) -> dict[str, Any]:
    return {"binding_version": BINDING_VERSION, "kind": kind,
            "invocation_surface_id": invocation["surface_id"],
            "source_path": invocation["path"], "source_digest": bytes_digest(raw),
            "manifest_path": manifest_path, "manifest_digest": bytes_digest(manifest_raw),
            "lock_path": lock_path, "lock_digest": bytes_digest(lock_raw),
            "toolchain": toolchain, "claim_scope": _CLAIM_SCOPE}


def _serde(invocation: dict[str, Any], raw: bytes,
           sources: dict[str, bytes]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    offset = _offset(invocation["surface_id"])
    match = re.match(
        rb"#\s*\[\s*derive\s*\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s*,?)\s*\)\s*\]",
        raw[offset:],
    )
    if match is None:
        raise ValueError("NAMESPACE_RUST_EXPANSION_NOT_SERDE")
    traits = [part.strip().decode("ascii") for part in match.group(1).rstrip(b",").split(b",")]
    external = sorted(set(traits) & _SERDE_DERIVES)
    if (not external or len(traits) != len(set(traits))
            or any(trait not in _BUILTIN_DERIVES | _SERDE_DERIVES for trait in traits)):
        raise ValueError("NAMESPACE_RUST_EXPANSION_NOT_SERDE")
    target = re.match(rb"\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:struct|enum|union)\s+([A-Za-z_][A-Za-z0-9_]*)",
                      raw[offset + match.end():])
    if target is None:
        raise ValueError("NAMESPACE_RUST_EXPANSION_TARGET_DIFFERS")
    target_name = target.group(1).decode("ascii")
    manifest_path, manifest_raw = _parent_file(invocation["path"], "Cargo.toml", sources)
    _exact_inline_dependency(manifest_raw, "dependencies", "serde", "=1.0.228", derive=True)
    lock_path, lock_raw = _parent_file(manifest_path, "Cargo.lock", sources)
    packages = [_locked_package(lock_raw, name, selected) for name, selected in _SERDE_PACKAGES.items()]
    toolchain = _toolchain(manifest_path, sources)
    prefix = "rust:" + invocation["path"] + ":" + target_name
    generated = [_surface(invocation, prefix + ".<derive:serde::" + trait + "@" + str(offset) + ">",
                          "RustExternalDerive") for trait in external]
    retained = _surface(invocation, invocation["surface_id"], "RustBoundExpansion")
    binding = _base_binding("SERDE_DERIVE_1_0_228", invocation, raw, manifest_path,
                            manifest_raw, lock_path, lock_raw, toolchain)
    binding.update({"packages": packages, "target": target_name, "traits": external,
                    "generated_surface_ids": [row["surface_id"] for row in generated],
                    "reason": "The exact pinned Serde derive maps each named data item to the selected trait implementation interface."})
    return [retained, *generated], binding


def _risc0(invocation: dict[str, Any], raw: bytes,
            sources: dict[str, bytes]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    offset = _offset(invocation["surface_id"])
    match = re.match(
        rb'include!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"OUT_DIR"\s*\)\s*,\s*"/methods\.rs"\s*\)\s*\)\s*;',
        raw[offset:],
    )
    if match is None:
        raise ValueError("NAMESPACE_RUST_EXPANSION_NOT_RISC0")
    manifest_path, manifest_raw = _parent_file(invocation["path"], "Cargo.toml", sources)
    _exact_inline_dependency(manifest_raw, "build-dependencies", "risc0-build", "=3.0.6")
    methods = _string_array(_section(manifest_raw, "package.metadata.risc0"), "methods")
    if (type(methods) is not list or not methods or any(type(item) is not str
            or not item or PurePosixPath(item).is_absolute() or ".." in PurePosixPath(item).parts for item in methods)
            or methods != sorted(set(methods))):
        raise ValueError("NAMESPACE_RUST_EXPANSION_METHODS_DIFFERS")
    crate_root = PurePosixPath(manifest_path).parent
    build_path = (crate_root / "build.rs").as_posix()
    build_raw = sources.get(build_path)
    if build_raw is None or re.fullmatch(
            rb"\s*fn\s+main\s*\(\s*\)\s*\{\s*risc0_build\s*::\s*embed_methods\s*\(\s*\)\s*;\s*\}\s*",
            build_raw) is None:
        raise ValueError("NAMESPACE_RUST_EXPANSION_BUILD_SCRIPT_DIFFERS")
    lock_path, lock_raw = _parent_file(manifest_path, "Cargo.lock", sources)
    package = _locked_package(lock_raw, "risc0-build", _RISC0_BUILD)
    toolchain = _toolchain(manifest_path, sources)
    guest_manifests = []
    names = []
    for method in methods:
        guest_path = (crate_root / method / "Cargo.toml").as_posix()
        guest_raw = sources.get(guest_path)
        name = (_quoted_value(_section(guest_raw, "package"), "name")
                if guest_raw is not None else None)
        if type(name) is not str or re.fullmatch(r"[A-Za-z0-9_-]+", name) is None:
            raise ValueError("NAMESPACE_RUST_EXPANSION_GUEST_DIFFERS")
        stem = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
        names.extend([stem + "_ELF", stem + "_ID"])
        guest_manifests.append({"path": guest_path, "digest": bytes_digest(guest_raw), "package": name})
    if len(names) != len(set(names)):
        raise ValueError("NAMESPACE_RUST_EXPANSION_GUEST_DIFFERS")
    prefix = "rust:" + invocation["path"] + ":"
    generated = [_surface(invocation, prefix + "<generated-const:" + name + "@" + str(offset) + ">",
                          "RustGeneratedConst") for name in names]
    retained = _surface(invocation, invocation["surface_id"], "RustBoundExpansion")
    binding = _base_binding("RISC0_EMBED_METHODS_3_0_6", invocation, raw, manifest_path,
                            manifest_raw, lock_path, lock_raw, toolchain)
    binding.update({"packages": [package], "build_script": {"path": build_path,
                    "digest": bytes_digest(build_raw)}, "guest_manifests": guest_manifests,
                    "generated_surface_ids": [row["surface_id"] for row in generated],
                    "reason": "The exact pinned RISC Zero embed-methods grammar maps each selected guest package to its ELF and image-ID constant interfaces."})
    return [retained, *generated], binding


def resolve(files: list[tuple[str, bytes]], support_files: list[tuple[str, bytes]],
            surfaces: list[dict[str, Any]], gaps: list[dict[str, str]]) -> dict[str, Any]:
    """Replace only independently recognized expansion placeholders."""
    sources: dict[str, bytes] = {}
    for path, raw in [*files, *support_files]:
        if path in sources and sources[path] != raw:
            raise ValueError("NAMESPACE_RUST_EXPANSION_SOURCE_COLLISION")
        sources[path] = raw
    raw_by_path = dict(files)
    replacements: dict[str, list[dict[str, Any]]] = {}
    bindings = []
    expansion_ids_by_path: dict[str, set[str]] = {}
    for row in surfaces:
        if row["form"] not in _EXPANSION_FORMS or not row["path"].endswith(".rs"):
            continue
        expansion_ids_by_path.setdefault(row["path"], set()).add(row["surface_id"])
        raw = raw_by_path[row["path"]]
        selected = None
        for resolver in (_serde, _risc0):
            try:
                selected = resolver(row, raw, sources)
                break
            except (KeyError, TypeError, UnicodeError, ValueError):
                continue
        if selected is not None:
            replacements[row["surface_id"]], binding = selected
            bindings.append(binding)
    rewritten = []
    for row in surfaces:
        rewritten.extend(replacements.get(row["surface_id"], [row]))
    fully_bound_paths = {path for path, identifiers in expansion_ids_by_path.items()
                         if identifiers and identifiers <= replacements.keys()}
    retained_gaps = [row for row in gaps if not (
        row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED" and row["path"] in fully_bound_paths)]
    return {"surfaces": rewritten, "gaps": retained_gaps,
            "binding": {"binding_version": BINDING_VERSION,
                        "claim_scope": _CLAIM_SCOPE,
                        "bindings": sorted(bindings, key=lambda row: row["invocation_surface_id"])}}


def validate(value: Any) -> None:
    """Reject malformed carried mechanisms before higher-tier reuse."""
    if (type(value) is not dict or set(value) != {"binding_version", "claim_scope", "bindings"}
            or value["binding_version"] != BINDING_VERSION or value["claim_scope"] != _CLAIM_SCOPE
            or type(value["bindings"]) is not list
            or value["bindings"] != sorted(value["bindings"], key=lambda row: row.get("invocation_surface_id", ""))):
        raise ValueError("NAMESPACE_RUST_EXPANSION_BINDING_DIFFERS")
    for row in value["bindings"]:
        if (type(row) is not dict or row.get("binding_version") != BINDING_VERSION
                or row.get("claim_scope") != _CLAIM_SCOPE
                or row.get("kind") not in {"SERDE_DERIVE_1_0_228", "RISC0_EMBED_METHODS_3_0_6"}
                or not row.get("reason") or not row.get("generated_surface_ids")):
            raise ValueError("NAMESPACE_RUST_EXPANSION_BINDING_DIFFERS")
