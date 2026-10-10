#!/usr/bin/env python3
"""Check non-circular PRDEL native-v2 source and release-subject coordinates.

Pull Request Domain Explanation Language (PRDEL); command-line interface (CLI);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

The implementation coordinate covers only the declared executable, checker and
schema members. The release-subject coordinate is an external host selection over
that coordinate, exact profile bytes, a local Git base/head and exact release-
description bytes. The production description checker must pass those selected
bytes against the selected commit. Neither result authorizes release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
from typing import Any


NATIVE_PROFILE_SCHEMA = "verifier-prdel-native-v2-selection-2"
CLI_PROFILE_SCHEMA = "verifier-prdel-native-v2-cli-selection-2"
IMPLEMENTATION_COORDINATE_SCHEMA = "verifier-prdel-v2-implementation-coordinate-1"
LEGACY_RELEASE_SUBJECT_SCHEMA = "verifier-prdel-v2-release-subject-1"
RELEASE_SUBJECT_SCHEMA = "verifier-prdel-v2-release-subject-2"
REPORT_SCHEMA = "verifier-prdel-v2-selection-report-2"
MAX_JSON_BYTES = 512 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_DESCRIPTION_BYTES = 64 * 1024 * 1024
MAX_OBSERVER_OUTPUT_BYTES = 2 * 1024 * 1024

IMPLEMENTATION_MEMBERS = {
    "scripts/build_component_index.py": "CHECKER",
    "scripts/check_pr_description.py": "CHECKER",
    "scripts/check_prdel_v2_selection.py": "CHECKER",
    "scripts/check_prdel_v2_selection_r2.py": "CHECKER",
    "src/verifier/runtime/gate.py": "EXECUTABLE",
    "src/verifier/runtime/prdel.py": "EXECUTABLE",
    "src/verifier/runtime/prdel_coverage.py": "EXECUTABLE",
    "src/verifier/runtime/prdel_evidence.py": "EXECUTABLE",
    "src/verifier/runtime/prdel_graph.py": "EXECUTABLE",
    "src/verifier/runtime/prdel_rules.py": "EXECUTABLE",
    "src/verifier/runtime/prdel_v2_shards.py": "EXECUTABLE",
    "src/verifier/schemas/verifier-prdel-2.schema.json": "SCHEMA",
    "src/verifier/schemas/verifier-prdel-cli-2.schema.json": "SCHEMA",
    "src/verifier/schemas/verifier-prdel-replay-plan-1.schema.json": "SCHEMA",
    "src/verifier/schemas/verifier-prdel-v2-document-shard-1.schema.json": "SCHEMA",
    "src/verifier/schemas/verifier-prdel-v2-release-subject-2.schema.json": "SCHEMA",
    "src/verifier/schemas/verifier-prdel-v2-shard-manifest-1.schema.json": "SCHEMA",
    "tests/test_prdel_frontier_redefinition.py": "CHECKER",
    "tests/test_prdel_graph_budget.py": "CHECKER",
    "tests/test_prdel_graph_source_bound.py": "CHECKER",
    "tests/test_prdel_graph_variadic_annotations.py": "CHECKER",
    "tests/test_prdel_large_window.py": "CHECKER",
    "tests/test_prdel_v2_cli_overlay.py": "CHECKER",
    "tests/test_prdel_v2_evidence_replay.py": "CHECKER",
    "tests/test_prdel_v2_native.py": "CHECKER",
    "tests/test_prdel_v2_selection.py": "CHECKER",
    "tests/test_prdel_v2_selection_r2.py": "CHECKER",
    "tests/test_prdel_v2_shards.py": "CHECKER",
}

ANCESTOR_COORDINATE_SHA256 = (
    "2312413c8610fc0e4a7f8fd147e3af4ac8c5d6e557ea77bfaadbd3261e6ecade"
)
OVERLAY_PATCH_SHA256 = [
    "504b090a9c48629a109150fb0ee0d3c38b75e0223b421fc1f6b6f94e557b0925",
    "5f7fbdd075c30695ee1e81469ed81418a60580293e696ce14aca8a0e9309cf27",
    "b0b17035099841d79d2c1d159557704449220da641cd20440ac9e247c59609d1",
]
REQUIRED_DECLARED_METADATA = {
    "ancestor_coordinate_sha256": ANCESTOR_COORDINATE_SHA256,
    "accepted_overlay_patch_sha256": OVERLAY_PATCH_SHA256,
    "semantic_completeness": "UNKNOWN",
    "release_authorized": False,
}

NATIVE_PROFILE_PATH = "src/verifier/profiles/prdel-native-v2-selection-2.json"
CLI_PROFILE_PATH = "src/verifier/profiles/prdel-native-v2-cli-selection-2.json"
R1_NATIVE_PROFILE_PATH = "src/verifier/profiles/prdel-native-v2-selection-1.json"
R1_NATIVE_PROFILE_SHA256 = (
    "c44b538287aaf79d5f3b12d948355cbe2cb9174a7038475e576361261923b3cf"
)
COORDINATE_SPEC_PATH = "src/verifier/standard/PRDEL_NATIVE_V2_COORDINATES.md"
NATIVE_SPEC_PATH = "src/verifier/standard/PRDEL_NATIVE_V2.md"
CLI_SPEC_PATH = "src/verifier/standard/PRDEL_NATIVE_V2_CLI.md"

NATIVE_PROFILE_KEYS = {
    "schema_version",
    "candidate_status",
    "authority_scope",
    "selection_scope",
    "implementation_coordinate",
    "implementation_inventory",
    "specifications",
    "legacy_compatibility",
    "release_subject_contract",
    "semantic_completeness",
    "release_authorized",
    "claim_boundary",
    "release_dependencies",
}
CLI_PROFILE_KEYS = {
    "schema_version",
    "candidate_status",
    "authority_scope",
    "selection_scope",
    "implementation_coordinate",
    "native_profile",
    "specifications",
    "capabilities",
    "release_subject_contract",
    "semantic_completeness",
    "release_authorized",
    "claim_boundary",
    "release_dependencies",
}
INVENTORY_KEYS = {"path", "kind", "bytes", "sha256"}
SPECIFICATION_KEYS = {"path", "bytes", "sha256"}
COORDINATE_KEYS = {
    "schema_version",
    "algorithm",
    "member_scope",
    "profile_and_receipt_bytes_excluded",
    "member_count",
    "sha256",
}
LEGACY_RELEASE_SUBJECT_KEYS = {
    "schema_version",
    "candidate_status",
    "implementation_coordinate",
    "profiles",
    "declared_metadata",
}
RELEASE_SUBJECT_KEYS = LEGACY_RELEASE_SUBJECT_KEYS | {"source", "description"}
RELEASE_PROFILE_KEYS = {"kind", "path", "bytes", "sha256"}
RELEASE_SOURCE_KEYS = {"base_commit", "head_commit"}
RELEASE_DESCRIPTION_KEYS = {"bytes", "sha256"}
RELEASE_SUBJECT_CONTRACT = {
    "schema_version": RELEASE_SUBJECT_SCHEMA,
    "selection": "EXTERNAL_HOST_REQUIRED",
    "candidate_self_selection": False,
    "missing_selection_status": "UNKNOWN",
    "source_binding": "EXACT_LOCAL_BASE_AND_HEAD_REQUIRED",
    "description_binding": "EXACT_BYTES_AND_PRODUCTION_GATE_REQUIRED",
}
RELEASE_DEPENDENCIES = [
    "EXTERNAL_HOST_RELEASE_SUBJECT_SELECTION_REQUIRED",
    "PACKAGED_SCHEMA_INVENTORY_OWNER_ADMISSION_REQUIRED",
    "FULL_APPLICABLE_TEST_AND_RELEASE_EVIDENCE_REQUIRED",
    "HUMAN_ACCEPTANCE_AND_RELEASE_AUTHORITY_REQUIRED",
]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, selected in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = selected
    return value


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON byte bound exceeded")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    if type(value) is not dict:
        raise ValueError("document must be an object")
    return value, raw


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_commit(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_file(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
        raise ValueError(f"unsafe path: {relative!r}")
    resolved_root = root.resolve(strict=True)
    selected = resolved_root.joinpath(*posix.parts).resolve(strict=True)
    if os.path.commonpath((str(resolved_root), str(selected))) != str(resolved_root):
        raise ValueError(f"path escapes root: {relative}")
    if not selected.is_file():
        raise ValueError(f"path is not a file: {relative}")
    return selected


def _actual_inventory(root: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for relative, kind in sorted(IMPLEMENTATION_MEMBERS.items()):
        selected = _safe_file(root, relative)
        raw = selected.read_bytes()
        if len(raw) > MAX_MEMBER_BYTES:
            raise ValueError(f"member byte bound exceeded: {relative}")
        inventory.append(
            {
                "path": relative,
                "kind": kind,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return inventory


def _coordinate(inventory: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {
        "schema_version": IMPLEMENTATION_COORDINATE_SCHEMA,
        "members": inventory,
    }
    canonical = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    return {
        "schema_version": IMPLEMENTATION_COORDINATE_SCHEMA,
        "algorithm": "SHA256_CANONICAL_JSON_LF",
        "member_scope": "EXACT_EXECUTABLE_CHECKER_SCHEMA_MEMBERS",
        "profile_and_receipt_bytes_excluded": True,
        "member_count": len(inventory),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def compute_implementation_coordinate(root: Path) -> dict[str, Any]:
    """Compute coordinate A without reading selected profile or receipt bytes."""

    return _coordinate(_actual_inventory(root))


def _finding(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _check_profile_header(
    profile: dict[str, Any],
    *,
    schema: str,
    keys: set[str],
    selection_scope: str,
    prefix: str,
    findings: list[dict[str, str]],
) -> None:
    if set(profile) != keys:
        findings.append(_finding(f"{prefix}_FIELDS", "exact profile fields are required"))
    if profile.get("schema_version") != schema:
        findings.append(_finding(f"{prefix}_SCHEMA", f"{schema} is required"))
    if profile.get("candidate_status") != "DEVELOPMENT_CANDIDATE":
        findings.append(_finding(f"{prefix}_STATUS", "DEVELOPMENT_CANDIDATE is required"))
    if profile.get("authority_scope") != "VERIFIER_PRDEL_IMPLEMENTATION_METADATA":
        findings.append(_finding(f"{prefix}_AUTHORITY", "implementation metadata scope is required"))
    if profile.get("selection_scope") != selection_scope:
        findings.append(_finding(f"{prefix}_SCOPE", f"{selection_scope} is required"))
    if profile.get("semantic_completeness") != "UNKNOWN":
        findings.append(_finding(f"{prefix}_COMPLETENESS", "semantic completeness must remain UNKNOWN"))
    if profile.get("release_authorized") is not False:
        findings.append(_finding(f"{prefix}_RELEASE", "release_authorized must remain false"))
    if profile.get("release_subject_contract") != RELEASE_SUBJECT_CONTRACT:
        findings.append(_finding(f"{prefix}_RELEASE_SUBJECT", "external host selection is required"))
    if profile.get("release_dependencies") != RELEASE_DEPENDENCIES:
        findings.append(_finding(f"{prefix}_DEPENDENCIES", "exact unresolved dependencies are required"))
    boundary = profile.get("claim_boundary")
    if type(boundary) is not str or not boundary.strip():
        findings.append(_finding(f"{prefix}_BOUNDARY", "nonempty claim boundary is required"))


def _check_specifications(
    root: Path,
    raw: Any,
    expected_paths: list[str],
    prefix: str,
    findings: list[dict[str, str]],
) -> None:
    if type(raw) is not list or len(raw) != len(expected_paths):
        findings.append(_finding(f"{prefix}_SPECIFICATIONS", "exact specification list is required"))
        return
    observed_paths = [item.get("path") for item in raw if type(item) is dict]
    if observed_paths != expected_paths:
        findings.append(_finding(f"{prefix}_SPECIFICATIONS", "specification paths or order differ"))
    for index, item in enumerate(raw):
        if type(item) is not dict or set(item) != SPECIFICATION_KEYS:
            findings.append(_finding(f"{prefix}_SPECIFICATION_ENTRY", f"invalid entry {index}"))
            continue
        relative = item.get("path")
        if type(relative) is not str:
            findings.append(_finding(f"{prefix}_SPECIFICATION_ENTRY", f"invalid path {index}"))
            continue
        try:
            selected = _safe_file(root, relative)
            value = selected.read_bytes()
        except (OSError, ValueError) as exc:
            findings.append(_finding(f"{prefix}_SPECIFICATION_PATH", f"{relative}: {exc}"))
            continue
        if item.get("bytes") != len(value) or item.get("sha256") != hashlib.sha256(value).hexdigest():
            findings.append(_finding(f"{prefix}_SPECIFICATION_BINDING", relative))


def _release_profile_rows(native_path: Path, cli_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kind, relative, path in (
        ("NATIVE_V2", NATIVE_PROFILE_PATH, native_path),
        ("NATIVE_V2_CLI", CLI_PROFILE_PATH, cli_path),
    ):
        raw = path.read_bytes()
        rows.append(
            {
                "kind": kind,
                "path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return rows


def _bounded_regular_bytes(path: Path, maximum: int) -> bytes:
    selected = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(selected.st_mode) or selected.st_size > maximum:
        raise ValueError("selected input is not a bounded regular file")
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("selected input exceeds its byte bound")
    return raw


def _git(root: Path, *arguments: str, text: bool = True) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=text,
        timeout=120,
    )


def _full_commit(root: Path, selected: Any) -> str:
    if not _is_commit(selected):
        raise ValueError("commit identifier must be 40 lowercase hexadecimal characters")
    result = _git(root, "rev-parse", "--verify", "--end-of-options", selected + "^{commit}")
    if result.returncode != 0:
        raise OSError("selected commit is unavailable")
    observed = result.stdout.strip()
    if observed != selected:
        raise ValueError("selected commit does not resolve to its exact identifier")
    return observed


def _selected_source_paths() -> list[str]:
    return sorted(
        set(IMPLEMENTATION_MEMBERS)
        | {
            R1_NATIVE_PROFILE_PATH,
            NATIVE_PROFILE_PATH,
            CLI_PROFILE_PATH,
            COORDINATE_SPEC_PATH,
            NATIVE_SPEC_PATH,
            CLI_SPEC_PATH,
        }
    )


def _check_source_binding(
    root: Path,
    source: Any,
    findings: list[dict[str, str]],
    unresolved: list[dict[str, str]],
) -> dict[str, str] | None:
    if type(source) is not dict or set(source) != RELEASE_SOURCE_KEYS:
        findings.append(_finding("RELEASE_SOURCE_FIELDS", "exact base and head fields are required"))
        return None
    base = source.get("base_commit")
    head = source.get("head_commit")
    try:
        base = _full_commit(root, base)
        head = _full_commit(root, head)
        current = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
        if current.returncode != 0:
            raise OSError("checked-out head is unavailable")
        observed_head = current.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        unresolved.append(_finding("RELEASE_SOURCE_OBSERVER_UNAVAILABLE", str(exc)))
        return None
    except ValueError as exc:
        findings.append(_finding("RELEASE_SOURCE_BINDING", str(exc)))
        return None

    if observed_head != head:
        findings.append(
            _finding(
                "RELEASE_SOURCE_HEAD",
                "release subject head differs from the checked-out source head",
            )
        )
        return None
    ancestor = _git(root, "merge-base", "--is-ancestor", base, head)
    if ancestor.returncode != 0:
        findings.append(
            _finding(
                "RELEASE_SOURCE_BASE",
                "release subject base is not an ancestor of the selected head",
            )
        )
        return None

    finding_count = len(findings)
    for relative in _selected_source_paths():
        try:
            working = _safe_file(root, relative).read_bytes()
        except (OSError, ValueError) as exc:
            findings.append(_finding("RELEASE_SOURCE_MEMBER", f"{relative}: {exc}"))
            continue
        blob = f"{head}:{relative}"
        size_result = _git(root, "cat-file", "-s", blob)
        if size_result.returncode != 0:
            findings.append(_finding("RELEASE_SOURCE_MEMBER", f"{relative}: absent from selected head"))
            continue
        try:
            committed_size = int(size_result.stdout.strip())
        except ValueError:
            findings.append(_finding("RELEASE_SOURCE_MEMBER", f"{relative}: selected size is invalid"))
            continue
        if committed_size > MAX_MEMBER_BYTES:
            findings.append(_finding("RELEASE_SOURCE_MEMBER", f"{relative}: selected blob is oversized"))
            continue
        committed = _git(root, "show", blob, text=False)
        if committed.returncode != 0 or len(committed.stdout) != committed_size:
            findings.append(_finding("RELEASE_SOURCE_MEMBER", f"{relative}: selected blob is unavailable"))
            continue
        if working != committed.stdout:
            findings.append(
                _finding(
                    "RELEASE_SOURCE_MEMBER_BINDING",
                    f"{relative}: checked bytes differ from the selected head",
                )
            )
    if len(findings) != finding_count:
        return None
    return {"base_commit": base, "head_commit": head}


def _observe_release_description(
    root: Path,
    description_raw: bytes,
    base: str,
    head: str,
) -> tuple[str, dict[str, Any] | None]:
    try:
        with tempfile.TemporaryDirectory(
            prefix="vstd-prdel-v2-description-",
            ignore_cleanup_errors=True,
        ) as scratch:
            description_path = Path(scratch) / "description.md"
            description_path.write_bytes(description_raw)
            command = [
                sys.executable,
                str(_safe_file(root, "scripts/check_pr_description.py")),
                "--body",
                str(description_path),
                "--base",
                base,
                "--commit",
                head,
                "--json",
            ]
            result = subprocess.run(
                command,
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=180,
            )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return "UNKNOWN", None
    if len(result.stdout.encode("utf-8")) > MAX_OBSERVER_OUTPUT_BYTES:
        return "FAIL", None
    try:
        report = json.loads(result.stdout, object_pairs_hook=_strict_object)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return "FAIL", None
    if type(report) is not dict or set(report) != {"findings", "status"}:
        return "FAIL", None
    status = report.get("status")
    report_findings = report.get("findings")
    if status not in {"PASS", "FAIL"} or type(report_findings) is not list:
        return "FAIL", None
    expected_returncode = 0 if status == "PASS" else 1
    if result.returncode != expected_returncode:
        return "FAIL", report
    return status, report


def check_selection(
    root: Path,
    native_profile_path: Path,
    cli_profile_path: Path,
    *,
    host_release_subject: Path | None,
    expected_release_subject_sha256: str | None,
    release_description: Path | None = None,
) -> dict[str, Any]:
    """Validate A, host-selected B, source history and exact description bytes."""

    findings: list[dict[str, str]] = []
    unresolved: list[dict[str, str]] = []
    try:
        native, _ = _load_json(native_profile_path)
        cli, _ = _load_json(cli_profile_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema_version": REPORT_SCHEMA,
            "status": "FAIL",
            "checked_files": 0,
            "implementation_coordinate": None,
            "observed_release_subject_sha256": None,
            "observed_source": None,
            "observed_description": None,
            "release_description_report": None,
            "findings": [_finding("PROFILE_UNREADABLE", str(exc))],
        }

    _check_profile_header(
        native,
        schema=NATIVE_PROFILE_SCHEMA,
        keys=NATIVE_PROFILE_KEYS,
        selection_scope="EXACT_IMPLEMENTATION_MEMBERS_ONLY",
        prefix="NATIVE_PROFILE",
        findings=findings,
    )
    _check_profile_header(
        cli,
        schema=CLI_PROFILE_SCHEMA,
        keys=CLI_PROFILE_KEYS,
        selection_scope="DEPENDENT_IMPLEMENTATION_COORDINATE_ONLY",
        prefix="CLI_PROFILE",
        findings=findings,
    )

    try:
        actual_inventory = _actual_inventory(root)
        actual_coordinate = _coordinate(actual_inventory)
    except (OSError, ValueError) as exc:
        findings.append(_finding("IMPLEMENTATION_UNREADABLE", str(exc)))
        actual_inventory = []
        actual_coordinate = None

    declared_inventory = native.get("implementation_inventory")
    if type(declared_inventory) is not list or len(declared_inventory) != len(IMPLEMENTATION_MEMBERS):
        findings.append(_finding("IMPLEMENTATION_INVENTORY", "exact bounded inventory is required"))
        declared_inventory = []
    declared_by_path: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(declared_inventory):
        if type(item) is not dict or set(item) != INVENTORY_KEYS:
            findings.append(_finding("IMPLEMENTATION_ENTRY", f"invalid entry {index}"))
            continue
        path = item.get("path")
        if type(path) is not str or path in declared_by_path:
            findings.append(_finding("IMPLEMENTATION_ENTRY", f"invalid or duplicate path {index}"))
            continue
        declared_by_path[path] = item
    if set(declared_by_path) != set(IMPLEMENTATION_MEMBERS):
        findings.append(_finding("IMPLEMENTATION_PATH_SET", "implementation member paths differ"))
    if [item.get("path") for item in declared_inventory if type(item) is dict] != sorted(declared_by_path):
        findings.append(_finding("IMPLEMENTATION_ORDER", "implementation members must be sorted"))

    actual_by_path = {item["path"]: item for item in actual_inventory}
    for relative in sorted(set(declared_by_path) & set(actual_by_path)):
        declared = declared_by_path[relative]
        actual = actual_by_path[relative]
        if declared.get("kind") != IMPLEMENTATION_MEMBERS[relative]:
            findings.append(_finding("IMPLEMENTATION_KIND", relative))
        if declared.get("bytes") != actual["bytes"]:
            findings.append(_finding("IMPLEMENTATION_BYTES", relative))
        if declared.get("sha256") != actual["sha256"]:
            findings.append(_finding("IMPLEMENTATION_SHA256", relative))
    if native.get("implementation_coordinate") != actual_coordinate:
        findings.append(_finding("IMPLEMENTATION_COORDINATE", "native profile does not bind observed coordinate A"))
    if cli.get("implementation_coordinate") != actual_coordinate:
        findings.append(_finding("CLI_IMPLEMENTATION_COORDINATE", "CLI profile does not bind observed coordinate A"))

    _check_specifications(
        root,
        native.get("specifications"),
        [COORDINATE_SPEC_PATH, NATIVE_SPEC_PATH],
        "NATIVE_PROFILE",
        findings,
    )
    _check_specifications(
        root,
        cli.get("specifications"),
        [COORDINATE_SPEC_PATH, CLI_SPEC_PATH],
        "CLI_PROFILE",
        findings,
    )

    expected_legacy_profile = {
        "path": R1_NATIVE_PROFILE_PATH,
        "sha256": R1_NATIVE_PROFILE_SHA256,
        "meaning": "RETAINED_ANCESTOR_SELECTION_PROFILE",
    }
    if native.get("legacy_compatibility") != expected_legacy_profile:
        findings.append(_finding("LEGACY_PROFILE", "exact retained r1 profile binding is required"))
    try:
        retained_r1 = _bounded_regular_bytes(
            _safe_file(root, R1_NATIVE_PROFILE_PATH),
            MAX_MEMBER_BYTES,
        )
        retained_r1_digest = hashlib.sha256(retained_r1).hexdigest()
        if retained_r1_digest != R1_NATIVE_PROFILE_SHA256:
            findings.append(_finding(
                "LEGACY_PROFILE_SOURCE",
                "retained r1 profile bytes differ from the independently pinned digest",
            ))
    except (OSError, ValueError) as exc:
        findings.append(_finding(
            "LEGACY_PROFILE_SOURCE",
            f"retained r1 profile is unavailable: {exc}",
        ))

    native_raw = native_profile_path.read_bytes()
    if cli.get("native_profile") != {
        "path": NATIVE_PROFILE_PATH,
        "bytes": len(native_raw),
        "sha256": hashlib.sha256(native_raw).hexdigest(),
    }:
        findings.append(_finding("CLI_NATIVE_PROFILE", "CLI profile must bind exact native r2 profile bytes"))

    capabilities = cli.get("capabilities")
    if capabilities != {
        "render_explicit_v2_document": "SELECTED",
        "validate_complete_private_v2_shards": "SELECTED",
        "independent_bounded_replay": "SELECTED",
        "closed_catalogue_frontier_resolvers": "SELECTED",
        "rule_compilation": "UNSUPPORTED_UNKNOWN",
        "authored_definitions": "UNSUPPORTED_UNKNOWN",
        "preventative_comparison": "UNSUPPORTED_UNKNOWN",
        "impact_dag": "UNSUPPORTED_UNKNOWN",
        "frontier_discharge": "UNSUPPORTED_UNKNOWN",
        "core_registration": "OUT_OF_SCOPE",
    }:
        findings.append(_finding("CLI_CAPABILITIES", "exact bounded capability map is required"))

    observed_b: str | None = None
    observed_source: dict[str, str] | None = None
    observed_description: dict[str, Any] | None = None
    description_report: dict[str, Any] | None = None
    subject: dict[str, Any] | None = None
    subject_raw: bytes | None = None
    if host_release_subject is None:
        unresolved.append(_finding("HOST_RELEASE_SUBJECT_REQUIRED", "host release-subject bytes are absent"))
    else:
        try:
            subject, subject_raw = _load_json(host_release_subject)
            observed_b = hashlib.sha256(subject_raw).hexdigest()
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            findings.append(_finding("RELEASE_SUBJECT_UNREADABLE", str(exc)))

    if subject is not None:
        subject_schema = subject.get("schema_version")
        expected_keys = (
            LEGACY_RELEASE_SUBJECT_KEYS
            if subject_schema == LEGACY_RELEASE_SUBJECT_SCHEMA
            else RELEASE_SUBJECT_KEYS
        )
        if set(subject) != expected_keys:
            findings.append(_finding("RELEASE_SUBJECT_FIELDS", "exact external subject fields are required"))
        if (
            subject_schema != LEGACY_RELEASE_SUBJECT_SCHEMA
            and subject_schema != RELEASE_SUBJECT_SCHEMA
        ):
            findings.append(_finding("RELEASE_SUBJECT_SCHEMA", "release-subject schema differs"))
        if subject.get("candidate_status") != "DEVELOPMENT_CANDIDATE":
            findings.append(_finding("RELEASE_SUBJECT_STATUS", "DEVELOPMENT_CANDIDATE is required"))
        if subject.get("implementation_coordinate") != actual_coordinate:
            findings.append(_finding("RELEASE_IMPLEMENTATION_COORDINATE", "release subject does not bind observed A"))
        profiles = subject.get("profiles")
        if (
            type(profiles) is not list
            or any(type(item) is not dict or set(item) != RELEASE_PROFILE_KEYS for item in profiles)
            or profiles != _release_profile_rows(native_profile_path, cli_profile_path)
        ):
            findings.append(_finding("RELEASE_PROFILE_BINDING", "release subject profile bytes differ"))
        if subject.get("declared_metadata") != REQUIRED_DECLARED_METADATA:
            findings.append(_finding("RELEASE_METADATA", "exact conservative declared metadata is required"))

        if subject_schema == LEGACY_RELEASE_SUBJECT_SCHEMA:
            unresolved.append(
                _finding(
                    "LEGACY_RELEASE_SUBJECT_SOURCE_BINDING_REQUIRED",
                    "version-one B does not bind source history or description bytes",
                )
            )
        elif subject_schema == RELEASE_SUBJECT_SCHEMA and set(subject) == RELEASE_SUBJECT_KEYS:
            observed_source = _check_source_binding(
                root,
                subject.get("source"),
                findings,
                unresolved,
            )
            declared_description = subject.get("description")
            if (
                type(declared_description) is not dict
                or set(declared_description) != RELEASE_DESCRIPTION_KEYS
                or type(declared_description.get("bytes")) is not int
                or not 0 <= declared_description.get("bytes") <= MAX_DESCRIPTION_BYTES
                or not _is_sha256(declared_description.get("sha256"))
            ):
                findings.append(
                    _finding(
                        "RELEASE_DESCRIPTION_FIELDS",
                        "exact bounded byte length and lowercase SHA-256 are required",
                    )
                )
            elif release_description is None:
                unresolved.append(
                    _finding(
                        "HOST_RELEASE_DESCRIPTION_REQUIRED",
                        "exact release-description bytes are absent",
                    )
                )
            else:
                try:
                    description_raw = _bounded_regular_bytes(
                        release_description,
                        MAX_DESCRIPTION_BYTES,
                    )
                    description_raw.decode("utf-8", errors="strict")
                    observed_description = {
                        "bytes": len(description_raw),
                        "sha256": hashlib.sha256(description_raw).hexdigest(),
                    }
                except (OSError, UnicodeError, ValueError) as exc:
                    findings.append(_finding("RELEASE_DESCRIPTION_UNREADABLE", str(exc)))
                if (
                    observed_description is not None
                    and observed_description != declared_description
                ):
                    findings.append(
                        _finding(
                            "RELEASE_DESCRIPTION_BINDING",
                            "selected description bytes differ from release subject",
                        )
                    )
                elif observed_description is not None and observed_source is not None:
                    description_status, description_report = _observe_release_description(
                        root,
                        description_raw,
                        observed_source["base_commit"],
                        observed_source["head_commit"],
                    )
                    if description_status == "FAIL":
                        findings.append(
                            _finding(
                                "RELEASE_DESCRIPTION_GATE",
                                "production description checker returned FAIL",
                            )
                        )
                    elif description_status == "UNKNOWN":
                        unresolved.append(
                            _finding(
                                "RELEASE_DESCRIPTION_OBSERVER_UNAVAILABLE",
                                "production description checker was unavailable",
                            )
                        )

    if expected_release_subject_sha256 is None:
        unresolved.append(
            _finding(
                "HOST_SELECTION_REQUIRED",
                "the checker never derives or defaults the host-selected release-subject coordinate B",
            )
        )
    elif not _is_sha256(expected_release_subject_sha256):
        findings.append(_finding("HOST_RELEASE_SUBJECT", "expected B is not a lowercase SHA-256"))
    elif observed_b is not None and observed_b != expected_release_subject_sha256:
        findings.append(_finding("HOST_RELEASE_SUBJECT", "observed subject bytes do not match host-selected B"))

    status = "FAIL" if findings else "UNKNOWN" if unresolved else "PASS"
    return {
        "schema_version": REPORT_SCHEMA,
        "status": status,
        "checked_files": len(actual_inventory),
        "implementation_coordinate": actual_coordinate,
        "observed_release_subject_sha256": observed_b,
        "observed_source": observed_source,
        "observed_description": observed_description,
        "release_description_report": description_report,
        "findings": findings + unresolved,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--native-profile", type=Path, required=True)
    parser.add_argument("--cli-profile", type=Path, required=True)
    parser.add_argument("--host-release-subject", type=Path)
    parser.add_argument("--release-description", type=Path)
    parser.add_argument("--expected-release-subject-sha256")
    selected = parser.parse_args(argv)
    report = check_selection(
        selected.root,
        selected.native_profile,
        selected.cli_profile,
        host_release_subject=selected.host_release_subject,
        release_description=selected.release_description,
        expected_release_subject_sha256=selected.expected_release_subject_sha256,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2 if report["status"] == "UNKNOWN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
