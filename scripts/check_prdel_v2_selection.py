#!/usr/bin/env python3
"""Check one exact PRDEL native-v2 development-candidate selection.

Pull Request Domain Explanation Language (PRDEL); abstract syntax tree (AST);
command-line interface (CLI); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256).

This checker validates selected bytes and a closed source-description inventory. It
does not execute PRDEL, grant semantic completeness, or authorize a release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PROFILE_SCHEMA = "verifier-prdel-native-v2-selection-1"
TARGET_COORDINATE_SHA256 = (
    "2312413c8610fc0e4a7f8fd147e3af4ac8c5d6e557ea77bfaadbd3261e6ecade"
)
LEGACY_SELECTION_SHA256 = (
    "41a9387521882b91e736079172cc42d1570841cbb530165cb7939db237ec4875"
)
MAX_PROFILE_BYTES = 256 * 1024
MAX_SELECTED_FILES = 32
MAX_SELECTED_FILE_BYTES = 2 * 1024 * 1024


def _entry(
    origin: str,
    role: str,
    status: str,
    symbols: Iterable[str],
    limits: Iterable[str],
) -> dict[str, Any]:
    return {
        "origin": origin,
        "role": role,
        "admission_status": status,
        "symbols": list(symbols),
        "limits": list(limits),
    }


EXPECTED_INVENTORY = {
    "scripts/check_prdel_v2_selection.py": _entry(
        "selection",
        "source_selection_checker",
        "SELECTED_BYTES",
        ("check_selection",),
        ("Byte admission only; it does not execute or qualify PRDEL behavior.",),
    ),
    "src/verifier/profiles/prdel-manifest-2-selection.json": _entry(
        "target",
        "legacy_manifest_v2_selection_boundary",
        "COMPATIBILITY_BOUNDARY",
        (),
        ("Historical ordered-vector successor only; native-v2 meaning is excluded.",),
    ),
    "src/verifier/runtime/gate.py": _entry(
        "target",
        "native_v2_cli_dispatch",
        "SELECTED_BYTES",
        ("_handle_prdel_v2_command",),
        ("Unsupported version-two CLI capabilities remain UNKNOWN.",),
    ),
    "src/verifier/runtime/prdel.py": _entry(
        "target",
        "native_v2_document",
        "SELECTED_BYTES",
        ("generate_prdel_v2", "render_prdel_v2", "validate_prdel_v2"),
        (
            "Document bytes <= 33554432; snapshot bytes <= 67108864.",
            "Files and changed regions <= 10000; AST source bytes <= 524288.",
        ),
    ),
    "src/verifier/runtime/prdel_graph.py": _entry(
        "target",
        "source_bound_impact_projection",
        "SELECTED_BYTES",
        ("build_source_bound_impact_graph",),
        (
            "Defaults: nodes 10000, edges 20000, operations 200000, output bytes 8388608.",
            "Incomplete discovery, projection, condensation, or output remains UNKNOWN.",
        ),
    ),
    "src/verifier/runtime/prdel_rules.py": _entry(
        "target",
        "version_one_compiler_boundary",
        "COMPATIBILITY_BOUNDARY",
        ("compile_prdel", "validate_compilation"),
        ("Version-one compiler only; it supplies no native-v2 compilation.",),
    ),
    "src/verifier/runtime/prdel_v2_shards.py": _entry(
        "target",
        "private_native_v2_shard_transport",
        "SELECTED_BYTES",
        (
            "compile_prdel_v2_shards",
            "partition_prdel_v2_document",
            "reconstruct_prdel_v2_document",
            "validate_prdel_v2_shards",
        ),
        (
            "Private Python transport only; CLI shard selectors remain unsupported.",
            "Packet bytes <= 67108864 and artifact bytes <= 33554432.",
        ),
    ),
    "src/verifier/schemas/verifier-prdel-2.schema.json": _entry(
        "target", "native_v2_document_schema", "SELECTED_BYTES", (),
        ("Structural validation alone supplies no semantic or release clearance.",),
    ),
    "src/verifier/schemas/verifier-prdel-cli-2.schema.json": _entry(
        "target", "native_v2_cli_schema", "SELECTED_BYTES", (),
        ("Structural validation alone supplies no semantic or release clearance.",),
    ),
    "src/verifier/schemas/verifier-prdel-v2-document-shard-1.schema.json": _entry(
        "target", "native_v2_document_shard_schema", "SELECTED_BYTES", (),
        ("A shard has no independent verdict or completeness claim.",),
    ),
    "src/verifier/schemas/verifier-prdel-v2-shard-manifest-1.schema.json": _entry(
        "target", "native_v2_shard_manifest_schema", "SELECTED_BYTES", (),
        ("Transport integrity does not establish source truth or gate clearance.",),
    ),
    "src/verifier/standard/PRDEL_NATIVE_V2.md": _entry(
        "selection", "native_v2_selection_specification", "SELECTED_BYTES", (),
        ("Development-candidate contract; semantic completeness remains UNKNOWN.",),
    ),
    "src/verifier/standard/PRDEL_SHARDS.md": _entry(
        "target", "legacy_manifest_v2_specification_boundary", "COMPATIBILITY_BOUNDARY", (),
        ("Ordered-vector compatibility does not grant native-v2 meaning.",),
    ),
    "tests/test_prdel_graph_budget.py": _entry(
        "target", "frontier_budget_checker", "QUALIFICATION_EVIDENCE_ONLY", (),
        ("Test bytes are a refutation surface, not authenticated execution evidence.",),
    ),
    "tests/test_prdel_graph_source_bound.py": _entry(
        "target", "source_bound_graph_checker", "QUALIFICATION_EVIDENCE_ONLY", (),
        ("Test bytes are a refutation surface, not authenticated execution evidence.",),
    ),
    "tests/test_prdel_v2_native.py": _entry(
        "target", "native_v2_checker", "QUALIFICATION_EVIDENCE_ONLY", (),
        ("Test bytes are a refutation surface, not authenticated execution evidence.",),
    ),
    "tests/test_prdel_v2_shards.py": _entry(
        "target", "native_v2_shard_checker", "QUALIFICATION_EVIDENCE_ONLY", (),
        ("Test bytes are a refutation surface, not authenticated execution evidence.",),
    ),
}

PROFILE_KEYS = {
    "schema_version",
    "candidate_status",
    "authority_scope",
    "selection_scope",
    "target_source_coordinate",
    "selected_specification",
    "legacy_compatibility",
    "inventory",
    "semantic_completeness",
    "release_authorized",
    "claim_boundary",
    "release_dependencies",
}
ENTRY_KEYS = {
    "path",
    "origin",
    "role",
    "admission_status",
    "symbols",
    "limits",
    "bytes",
    "sha256",
}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_profile(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_PROFILE_BYTES:
        raise ValueError("profile byte bound exceeded")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    if type(value) is not dict:
        raise ValueError("profile must be an object")
    return value


def _safe_file(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
        raise ValueError(f"unsafe selected path: {relative!r}")
    root = root.resolve(strict=True)
    candidate = root.joinpath(*posix.parts).resolve(strict=True)
    if os.path.commonpath((str(root), str(candidate))) != str(root) or not candidate.is_file():
        raise ValueError(f"selected path escapes its root or is not a file: {relative}")
    return candidate


def _finding(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def check_selection(
    target_root: Path,
    profile_path: Path,
    *,
    selection_root: Path | None = None,
) -> dict[str, Any]:
    """Return a deterministic PASS/FAIL report for selected source bytes."""

    findings: list[dict[str, str]] = []
    try:
        profile = _load_profile(profile_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema_version": "verifier-prdel-native-v2-selection-report-1",
            "status": "FAIL",
            "checked_files": 0,
            "findings": [_finding("PROFILE_UNREADABLE", str(exc))],
        }
    if selection_root is None:
        selection_root = profile_path.resolve().parents[3]

    if set(profile) != PROFILE_KEYS:
        findings.append(_finding("PROFILE_FIELDS", "exact profile fields are required"))
    if profile.get("schema_version") != PROFILE_SCHEMA:
        findings.append(_finding("PROFILE_SCHEMA", "native-v2 selection schema is required"))
    if profile.get("candidate_status") != "DEVELOPMENT_CANDIDATE":
        findings.append(_finding("CANDIDATE_STATUS", "DEVELOPMENT_CANDIDATE is required"))
    if profile.get("authority_scope") != "VERIFIER_PRDEL_IMPLEMENTATION_METADATA":
        findings.append(_finding("AUTHORITY_SCOPE", "implementation-metadata scope is required"))
    if profile.get("selection_scope") != "EXACT_DECLARED_PATHS_ONLY":
        findings.append(_finding("SELECTION_SCOPE", "exact declared paths scope is required"))
    if profile.get("semantic_completeness") != "UNKNOWN":
        findings.append(_finding("SEMANTIC_COMPLETENESS", "semantic completeness must remain UNKNOWN"))
    if profile.get("release_authorized") is not False:
        findings.append(_finding("RELEASE_AUTHORITY", "release_authorized must be false"))
    coordinate = profile.get("target_source_coordinate")
    if coordinate != {
        "kind": "NON_GIT_SNAPSHOT_AGGREGATE",
        "sha256": TARGET_COORDINATE_SHA256,
        "scope": "EXACT_SELECTED_PATHS_PLUS_EXTERNAL_AGGREGATE",
        "working_tree_completeness": "UNKNOWN",
    }:
        findings.append(_finding("SOURCE_COORDINATE", "exact sealed target coordinate is required"))
    if profile.get("selected_specification") != "src/verifier/standard/PRDEL_NATIVE_V2.md":
        findings.append(_finding("SPECIFICATION_SELECTION", "exact native-v2 specification path is required"))
    if profile.get("legacy_compatibility") != {
        "path": "src/verifier/profiles/prdel-manifest-2-selection.json",
        "sha256": LEGACY_SELECTION_SHA256,
        "meaning": "UNCHANGED_ORDER_PRESERVING_MANIFEST_V2_SUCCESSOR",
    }:
        findings.append(_finding("LEGACY_BOUNDARY", "unchanged legacy selection is required"))
    dependencies = profile.get("release_dependencies")
    if dependencies != [
        "PACKAGED_SCHEMA_INVENTORY_OWNER_ADMISSION_REQUIRED",
        "FULL_APPLICABLE_TEST_AND_RELEASE_EVIDENCE_REQUIRED",
        "HUMAN_ACCEPTANCE_AND_RELEASE_AUTHORITY_REQUIRED",
    ]:
        findings.append(_finding("RELEASE_DEPENDENCIES", "exact unresolved release dependencies are required"))
    boundary = profile.get("claim_boundary")
    if type(boundary) is not str or not boundary.strip():
        findings.append(_finding("CLAIM_BOUNDARY", "a nonempty claim boundary is required"))

    raw_inventory = profile.get("inventory")
    entries: dict[str, dict[str, Any]] = {}
    if type(raw_inventory) is not list or len(raw_inventory) > MAX_SELECTED_FILES:
        findings.append(_finding("INVENTORY_BOUND", "bounded inventory list required"))
        raw_inventory = []
    for index, entry in enumerate(raw_inventory):
        if type(entry) is not dict or set(entry) != ENTRY_KEYS:
            findings.append(_finding("INVENTORY_ENTRY", f"entry {index} has invalid fields"))
            continue
        path = entry.get("path")
        if type(path) is not str or path in entries:
            findings.append(_finding("INVENTORY_DUPLICATE", f"entry {index} has invalid or duplicate path"))
            continue
        entries[path] = entry
    expected_paths = set(EXPECTED_INVENTORY)
    actual_paths = set(entries)
    if actual_paths != expected_paths:
        detail = json.dumps(
            {
                "missing": sorted(expected_paths - actual_paths),
                "extra": sorted(actual_paths - expected_paths),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        findings.append(_finding("INVENTORY_PATH_SET", detail))
    if [entry.get("path") for entry in raw_inventory if type(entry) is dict] != sorted(actual_paths):
        findings.append(_finding("INVENTORY_ORDER", "inventory paths must be unique and sorted"))

    checked = 0
    for relative in sorted(expected_paths & actual_paths):
        entry = entries[relative]
        expected = EXPECTED_INVENTORY[relative]
        for key, value in expected.items():
            if entry.get(key) != value:
                findings.append(_finding("INVENTORY_METADATA", f"{relative}: {key} mismatch"))
        size, digest = entry.get("bytes"), entry.get("sha256")
        if type(size) is not int or isinstance(size, bool) or size < 1 or size > MAX_SELECTED_FILE_BYTES:
            findings.append(_finding("INVENTORY_BYTES", f"{relative}: invalid byte count"))
            continue
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            findings.append(_finding("INVENTORY_SHA256", f"{relative}: invalid SHA-256"))
            continue
        root = target_root if entry.get("origin") == "target" else selection_root
        try:
            selected = _safe_file(Path(root), relative)
            raw = selected.read_bytes()
        except (OSError, ValueError) as exc:
            findings.append(_finding("SELECTED_PATH", f"{relative}: {exc}"))
            continue
        if len(raw) != size:
            findings.append(_finding("SELECTED_BYTES", f"{relative}: expected {size}, observed {len(raw)}"))
        observed = hashlib.sha256(raw).hexdigest()
        if observed != digest:
            findings.append(_finding("SELECTED_SHA256", f"{relative}: expected {digest}, observed {observed}"))
        checked += 1

    return {
        "schema_version": "verifier-prdel-native-v2-selection-report-1",
        "status": "FAIL" if findings else "PASS",
        "checked_files": checked,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--selection-root", type=Path)
    arguments = parser.parse_args(argv)
    report = check_selection(
        arguments.target_root,
        arguments.profile,
        selection_root=arguments.selection_root,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
