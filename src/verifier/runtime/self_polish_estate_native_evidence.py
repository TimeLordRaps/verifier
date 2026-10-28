"""Native, selected-root replay for self-polish estate evidence.

An authority receipt may authorize a proposition, but it cannot make that
proposition true.  This module therefore re-observes the exact estate candidate
from the selected repository root.  The evidence artifact is only a bounded,
canonical request identifying what to replay; PASS is derived by the installed
category verifier and never copied from the artifact.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping

from verifier.runtime import self_polish_estate


ARTIFACT_SCHEMA = "verifier-self-polish-estate-native-evidence-3"
RESULT_SCHEMA = "verifier-self-polish-estate-native-evidence-replay-3"
MECHANISM_SCHEMA = "verifier-self-polish-estate-native-replay-mechanism-3"
MAX_ARTIFACT_BYTES = 128 * 1024
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


class NativeEvidenceError(ValueError):
    """Stable fail-closed native replay error."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise NativeEvidenceError(code)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def value_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _candidate_shape(candidate: Mapping[str, Any]) -> None:
    _require(
        type(candidate) is dict
        and type(candidate.get("candidate_id")) is str
        and type(candidate.get("category")) is str
        and type(candidate.get("source_refs")) is list
        and type(candidate.get("metadata")) is dict
        and type(candidate.get("candidate_digest")) is str
        and _SHA256.fullmatch(candidate["candidate_digest"]) is not None,
        "NATIVE_CANDIDATE_INVALID",
    )
    body = {
        key: value for key, value in candidate.items()
        if key != "candidate_digest"
    }
    _require(candidate["candidate_digest"] == value_digest(body),
             "NATIVE_CANDIDATE_DIGEST_DIFFERS")


def _source_backed(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    refs = candidate["source_refs"]
    if not refs:
        return "UNKNOWN", ["NATIVE_CANDIDATE_SOURCE_UNRESOLVED"]
    for ref in refs:
        _require(
            type(ref) is dict and set(ref) == {"path", "sha256"}
            and type(ref["path"]) is str
            and type(ref["sha256"]) is str
            and _SHA256.fullmatch(ref["sha256"]) is not None,
            "NATIVE_CANDIDATE_SOURCE_REF_INVALID",
        )
    return "PASS", []


def _prefix(candidate: Mapping[str, Any], prefix: str,
            blocker: str) -> tuple[str, list[str]]:
    status, blockers = _source_backed(candidate)
    if status != "PASS":
        return status, blockers
    if all(ref["path"].startswith(prefix) for ref in candidate["source_refs"]):
        return "PASS", []
    return "FAIL", [blocker]


def _verify_source_file(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, blockers = _source_backed(candidate)
    if status != "PASS":
        return status, blockers
    expected = "candidate-source-file:" + candidate["source_refs"][0]["path"]
    if (
            len(candidate["source_refs"]) == 1
            and candidate["candidate_id"] == expected
            and candidate["metadata"].get("provenance") in {
                "GIT_TRACKED", "WORKTREE_UNTRACKED_NONIGNORED",
            }
            and candidate["metadata"].get("git_mode") in {
                "100644", "100755", "UNTRACKED_REGULAR",
            }
            and (
                candidate["metadata"]["provenance"] == "GIT_TRACKED"
                and candidate["metadata"]["git_mode"] in {"100644", "100755"}
                or candidate["metadata"]["provenance"]
                    == "WORKTREE_UNTRACKED_NONIGNORED"
                and candidate["metadata"]["git_mode"]
                    == "UNTRACKED_REGULAR"
            )
    ):
        return "PASS", []
    return "FAIL", ["NATIVE_CANDIDATE_SOURCE_FILE_BINDING_DIFFERS"]


def _verify_package_file(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    return _prefix(candidate, "src/verifier/", "NATIVE_PACKAGE_FILE_DIFFERS")


def _verify_python_module(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, blockers = _prefix(
        candidate, "src/verifier/", "NATIVE_PYTHON_MODULE_DIFFERS"
    )
    if status != "PASS":
        return status, blockers
    if all(ref["path"].endswith(".py") for ref in candidate["source_refs"]):
        return "PASS", []
    return "FAIL", ["NATIVE_PYTHON_MODULE_DIFFERS"]


def _verify_python_function(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, blockers = _verify_python_module(candidate)
    if status != "PASS":
        return status, blockers
    metadata = candidate["metadata"]
    if type(metadata.get("qualname")) is str \
            and type(metadata.get("line")) is int \
            and metadata["line"] > 0:
        return "PASS", []
    return "FAIL", ["NATIVE_PYTHON_CALLABLE_BINDING_DIFFERS"]


def _verify_registry(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    return _source_backed(candidate)


def _verify_cli(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, blockers = _source_backed(candidate)
    if status != "PASS":
        return status, blockers
    if any(ref["path"] == "src/verifier/runtime/public_cli.py"
           for ref in candidate["source_refs"]):
        return "PASS", []
    return "FAIL", ["NATIVE_PUBLIC_CLI_SOURCE_DIFFERS"]


def _verify_schema(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, blockers = _source_backed(candidate)
    if status != "PASS":
        return status, blockers
    if all(ref["path"].endswith(".json") for ref in candidate["source_refs"]):
        return "PASS", []
    return "FAIL", ["NATIVE_SCHEMA_SOURCE_DIFFERS"]


_BOUNDARY_SURFACE_IDS = {
    "external-plugin-estate",
    "generated-build-backend-estate",
    "runtime-environment-estate",
}


def _verify_unresolved(candidate: Mapping[str, Any]) -> tuple[str, list[str]]:
    metadata = candidate["metadata"]
    identifier = metadata.get("surface_id")
    if candidate.get("candidate_type") == "EXPLICIT_UNKNOWN_SURFACE" \
            and identifier in _BOUNDARY_SURFACE_IDS \
            and candidate.get("candidate_id") \
                == "unresolved-surface:" + identifier \
            and metadata.get("enumeration_status") == "UNKNOWN" \
            and type(metadata.get("reason")) is str \
            and bool(metadata["reason"]):
        return "NOT_APPLICABLE", []
    return "FAIL", ["NATIVE_BOUNDARY_SURFACE_BINDING_DIFFERS"]


_CATEGORY_HANDLERS: dict[
    str, tuple[
        str, str, Callable[[Mapping[str, Any]], tuple[str, list[str]]]
    ]
] = {
    "candidate_source_file": (
        "native-candidate-source-file-1", "APPLICABLE", _verify_source_file,
    ),
    "package_file": (
        "native-package-file-1", "APPLICABLE", _verify_package_file,
    ),
    "python_module": (
        "native-python-module-1", "APPLICABLE", _verify_python_module,
    ),
    "python_function": (
        "native-python-callable-1", "APPLICABLE", _verify_python_function,
    ),
    "installed_cell": (
        "native-installed-cell-1", "APPLICABLE", _verify_registry,
    ),
    "installed_route": (
        "native-installed-route-1", "APPLICABLE", _verify_registry,
    ),
    "installed_mechanism": (
        "native-installed-mechanism-1", "APPLICABLE", _verify_registry,
    ),
    "structural_family": (
        "native-structural-family-1", "APPLICABLE", _verify_registry,
    ),
    "structural_membership": (
        "native-structural-membership-1", "APPLICABLE", _verify_registry,
    ),
    "structural_route_crosswalk": (
        "native-structural-route-crosswalk-1", "APPLICABLE", _verify_registry,
    ),
    "non_route_gate": (
        "native-non-route-gate-1", "APPLICABLE", _verify_registry,
    ),
    "public_cli_route": (
        "native-public-cli-route-1", "APPLICABLE", _verify_cli,
    ),
    "public_cli_preparser_route": (
        "native-public-cli-preparser-route-1", "APPLICABLE", _verify_cli,
    ),
    "console_alias": (
        "native-console-alias-1", "APPLICABLE", _verify_registry,
    ),
    "public_lazy_export": (
        "native-public-lazy-export-1", "APPLICABLE", _verify_registry,
    ),
    "domain": ("native-domain-1", "APPLICABLE", _verify_registry),
    "domain_check": (
        "native-domain-check-1", "APPLICABLE", _verify_registry,
    ),
    "interoperability_component": (
        "native-interoperability-component-1", "APPLICABLE", _verify_registry,
    ),
    "schema": ("native-schema-1", "APPLICABLE", _verify_schema),
    "native_route": ("native-route-1", "APPLICABLE", _verify_registry),
    "compatibility_route": (
        "native-compatibility-route-1", "APPLICABLE", _verify_registry,
    ),
    "package_data_candidate": (
        "native-package-data-candidate-1", "APPLICABLE", _verify_registry,
    ),
    "unresolved_surface": (
        "native-unresolved-surface-1", "NOT_APPLICABLE", _verify_unresolved,
    ),
}


def native_applicability_status(candidate: Mapping[str, Any]) -> str:
    """Return the fixed applicability classification of the native registry."""
    _candidate_shape(candidate)
    category = candidate["category"]
    _require(category in _CATEGORY_HANDLERS,
             "NATIVE_CATEGORY_VERIFIER_UNAVAILABLE")
    _, applicability, handler = _CATEGORY_HANDLERS[category]
    if applicability == "NOT_APPLICABLE":
        status, blockers = handler(candidate)
        _require(
            status == "NOT_APPLICABLE" and not blockers,
            "NATIVE_BOUNDARY_SURFACE_BINDING_DIFFERS",
        )
    return applicability


def mechanism_digest() -> str:
    _require(
        set(_CATEGORY_HANDLERS) == set(self_polish_estate.REQUIRED_CATEGORIES),
        "NATIVE_CATEGORY_REGISTRY_DIFFERS",
    )
    registry = [{
        "category": category,
        "verifier_id": verifier_id,
        "native_applicability_status": applicability,
    } for category, (verifier_id, applicability, _) in sorted(
        _CATEGORY_HANDLERS.items()
    )]
    return value_digest({
        "schema_version": MECHANISM_SCHEMA,
        "module_digest": bytes_digest(Path(__file__).read_bytes()),
        "category_registry": registry,
    })


def _expected_artifact(estate: Mapping[str, Any],
                       candidate: Mapping[str, Any]) -> dict[str, Any]:
    _candidate_shape(candidate)
    category = candidate["category"]
    _require(category in _CATEGORY_HANDLERS,
             "NATIVE_CATEGORY_VERIFIER_UNAVAILABLE")
    verifier_id, applicability, _ = _CATEGORY_HANDLERS[category]
    body = {
        "schema_version": ARTIFACT_SCHEMA,
        "native_replay_mechanism_digest": mechanism_digest(),
        "source_coordinate_digest": value_digest(estate["source_coordinate"]),
        "estate_digest": estate["estate_digest"],
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": candidate["candidate_digest"],
        "category": category,
        "category_verifier_id": verifier_id,
        "native_applicability_status": applicability,
        "source_refs_digest": value_digest(candidate["source_refs"]),
    }
    return {**body, "artifact_digest": value_digest(body)}


def evidence_artifact_template(estate: Mapping[str, Any],
                               candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Create a bounded replay request; it contains no caller PASS field."""
    return _expected_artifact(estate, candidate)


def _decode_artifact(raw: bytes) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_ARTIFACT_BYTES,
             "NATIVE_EVIDENCE_ARTIFACT_CAPACITY_EXHAUSTED")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            _require(key not in result,
                     "NATIVE_EVIDENCE_ARTIFACT_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise NativeEvidenceError("NATIVE_EVIDENCE_ARTIFACT_INVALID") from exc
    _require(type(value) is dict and canonical_bytes(value) == raw,
             "NATIVE_EVIDENCE_ARTIFACT_NOT_CANONICAL")
    return value


def validate_evidence_artifact(*, estate: Mapping[str, Any],
                               candidate: Mapping[str, Any],
                               artifact_bytes: bytes,
                               expected_artifact_digest: str) -> dict[str, Any]:
    """Validate exact artifact bytes without claiming native observation."""
    _require(
        type(expected_artifact_digest) is str
        and _SHA256.fullmatch(expected_artifact_digest) is not None,
        "NATIVE_EVIDENCE_ARTIFACT_DIGEST_INVALID",
    )
    artifact = _decode_artifact(artifact_bytes)
    _require(
        artifact == _expected_artifact(estate, candidate)
        and bytes_digest(artifact_bytes) == expected_artifact_digest,
        "NATIVE_EVIDENCE_ARTIFACT_BINDING_DIFFERS",
    )
    return artifact


def prepare_replay_context(estate: Mapping[str, Any],
                           source_root: str | Path) -> dict[str, Any]:
    """Recapture the complete source and native enumerator once per replay."""
    root = Path(source_root).resolve(strict=True)
    _require(root.is_dir(), "NATIVE_SOURCE_ROOT_INVALID")
    coordinate = self_polish_estate._git_coordinate(root)
    _require(
        coordinate.get("repository") == estate["source_coordinate"].get(
            "repository"
        )
        and coordinate.get("revision") == estate["source_coordinate"].get(
            "revision"
        ),
        "NATIVE_SOURCE_COORDINATE_DIFFERS",
    )
    census = self_polish_estate.capture_candidate_source_census(root)
    _require(census == estate["pre_source_census"],
             "NATIVE_SOURCE_CENSUS_DIFFERS")
    self_polish_estate._runtime_source_binding(root, census)
    candidates, crosswalk = self_polish_estate._enumerate(root, census)
    self_polish_estate._runtime_source_binding(root, census)
    _require(
        candidates == estate["candidates"]
        and crosswalk == estate["structural_route_crosswalk"],
        "NATIVE_ESTATE_REPLAY_DIFFERS",
    )
    return {
        "source_root": root,
        "source_coordinate_digest": value_digest(estate["source_coordinate"]),
        "estate_digest": estate["estate_digest"],
        "candidates": {row["candidate_id"]: row for row in candidates},
    }


def replay_native_evidence(*, context: Mapping[str, Any],
                           estate: Mapping[str, Any],
                           candidate: Mapping[str, Any], artifact_bytes: bytes,
                           expected_artifact_digest: str) -> dict[str, Any]:
    """Replay one exact artifact and derive PASS/FAIL/UNKNOWN natively."""
    report: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA,
        "status": "UNKNOWN",
        "artifact_digest": None,
        "native_replay_mechanism_digest": mechanism_digest(),
        "category_verifier_id": None,
        "native_applicability_status": None,
        "blockers": [],
    }
    try:
        _candidate_shape(candidate)
        validate_evidence_artifact(
            estate=estate,
            candidate=candidate,
            artifact_bytes=artifact_bytes,
            expected_artifact_digest=expected_artifact_digest,
        )
        selected = context.get("candidates")
        _require(
            isinstance(selected, Mapping)
            and selected.get(candidate["candidate_id"]) == candidate
            and context.get("estate_digest") == estate["estate_digest"]
            and context.get("source_coordinate_digest")
                == value_digest(estate["source_coordinate"]),
            "NATIVE_REPLAY_CONTEXT_DIFFERS",
        )
        verifier_id, applicability, handler = _CATEGORY_HANDLERS[
            candidate["category"]
        ]
        status, blockers = handler(candidate)
        _require(
            (applicability == "APPLICABLE"
             and status in {"PASS", "FAIL", "UNKNOWN"})
            or (applicability == "NOT_APPLICABLE"
                and status in {"NOT_APPLICABLE", "FAIL"}),
            "NATIVE_APPLICABILITY_REPLAY_INCONSISTENT",
        )
        report.update(
            status=status,
            artifact_digest=expected_artifact_digest,
            category_verifier_id=verifier_id,
            native_applicability_status=applicability,
            blockers=blockers,
        )
    except (NativeEvidenceError, self_polish_estate.EstateError) as exc:
        report.update(status="FAIL", blockers=[str(exc)])
    except (KeyError, OSError, TypeError, ValueError):
        report.update(
            status="FAIL", blockers=["NATIVE_EVIDENCE_REPLAY_REJECTED"]
        )
    report["blockers"] = sorted(set(report["blockers"]))
    report["result_digest"] = value_digest(report)
    return report


__all__ = [
    "ARTIFACT_SCHEMA", "MAX_ARTIFACT_BYTES", "NativeEvidenceError",
    "RESULT_SCHEMA", "bytes_digest", "canonical_bytes",
    "evidence_artifact_template", "mechanism_digest",
    "native_applicability_status", "prepare_replay_context",
    "replay_native_evidence", "value_digest",
    "validate_evidence_artifact",
]
