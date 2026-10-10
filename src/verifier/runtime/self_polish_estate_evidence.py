"""Replay semantic evidence over an exact self-polish candidate estate.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
and identifier (ID) bindings preserve the source census and every candidate.
Installed category verifiers recompute native applicability and evidence;
caller-authored dispositions and digests never authenticate themselves.
Optional configured-key receipts are selected by the host and reported as an
independent authority path, not a prerequisite for native self-verification.

This module can close only the enumerated estate evidence denominator at one
source coordinate.  It does not establish Tier 1, polished status, release
authority, or repository/package completeness beyond the candidate enumerator.
"""
from __future__ import annotations

import dataclasses
from hashlib import sha256
import json
from pathlib import Path
import re
import time
from typing import Any, Mapping

from verifier.runtime import core_application_authority
from verifier.runtime import self_polish_estate
from verifier.runtime import self_polish_estate_authority
from verifier.runtime import self_polish_estate_native_evidence


MANIFEST_SCHEMA = "verifier-self-polish-estate-evidence-manifest-3"
SUBJECT_SCHEMA = "verifier-self-polish-estate-candidate-evidence-subject-3"
RESULT_SCHEMA = "verifier-self-polish-estate-evidence-replay-4"
OPERATION = core_application_authority.SEMANTIC_COMPLETENESS_OPERATION
MAX_MANIFEST_BYTES = 128 * 1024 * 1024
MAX_JUSTIFICATION_BYTES = 4096
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DEFINITE_REPLAY_FAILURES = {
    "AUTHORITY_APPROVAL_REVOKED",
    "AUTHORITY_EVIDENCE_NOT_CURRENT",
    "AUTHORITY_EXECUTION_NOT_COMPLETED",
    "AUTHORITY_POLICY_NOT_CURRENT",
    "AUTHORITY_QUORUM_NOT_ESTABLISHED",
    "AUTHORITY_RECEIPT_NOT_CURRENT",
    "AUTHORITY_STATUS_NOT_CURRENT",
}
_CLAIM_BOUNDARY = (
    "Native self-verification PASS closes only installed category replay for "
    "every candidate in the exact recaptured estate at the bound source "
    "coordinate. Applicability is recomputed by the fixed native registry, not "
    "accepted from caller declarations. Configured-key independent authority is "
    "reported separately and is not required for native self-verification. "
    "Neither status establishes Tier 1 beyond this subledger, polished status, "
    "repository/package completeness beyond this universe, release authority, "
    "or verified bytes for explicitly excluded cache/build artifacts."
)


class EstateEvidenceError(ValueError):
    """Stable fail-closed contract error without reflected submitted values."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EstateEvidenceError(code)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def value_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _hash(value: Any, code: str, *, optional: bool = False) -> str | None:
    _require(
        (value is None and optional)
        or (type(value) is str and _SHA256.fullmatch(value) is not None),
        code,
    )
    return value


def mechanism_digest() -> str:
    """Bind this adapter and both installed configured-key replay mechanisms."""
    return value_digest({
        "schema_version": "verifier-self-polish-estate-evidence-mechanism-4",
        "adapter_digest": bytes_digest(Path(__file__).read_bytes()),
        "estate_authority_mechanism_digest": (
            self_polish_estate_authority.mechanism_digest()
        ),
        "candidate_authority_mechanism_digest": (
            core_application_authority.qualified_authority_mechanism_digest(
                OPERATION
            )
        ),
        "native_evidence_mechanism_digest": (
            self_polish_estate_native_evidence.mechanism_digest()
        ),
    })


def _decode_canonical(raw: bytes, code: str) -> dict[str, Any]:
    _require(
        type(raw) is bytes and len(raw) <= MAX_MANIFEST_BYTES,
        code + "_CAPACITY_EXHAUSTED",
    )

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            _require(key not in result, code + "_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                EstateEvidenceError(code + "_INVALID")
            ),
        )
    except EstateEvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise EstateEvidenceError(code + "_INVALID") from exc
    _require(
        type(value) is dict and canonical_bytes(value) == raw,
        code + "_NOT_CANONICAL",
    )
    return value


def _validated_estate(estate: Any) -> dict[str, Any]:
    _require(type(estate) is dict, "ESTATE_FIELDS_DIFFER")
    required = {
        "schema_version", "mechanical_census_status",
        "semantic_applicability_status", "full_estate_closure", "polished",
        "release_authorized", "source_coordinate", "pre_source_census",
        "post_source_census", "required_categories", "category_summaries",
        "structural_route_crosswalk", "candidate_count",
        "candidate_universe_digest", "candidates", "applicability_ledger",
        "claim_boundary", "estate_digest",
    }
    _require(set(estate) == required, "ESTATE_FIELDS_DIFFER")
    body = {key: value for key, value in estate.items() if key != "estate_digest"}
    _require(
        estate["schema_version"] == self_polish_estate.ESTATE_SCHEMA
        and estate["estate_digest"] == value_digest(body)
        and estate["mechanical_census_status"] == "PASS"
        and estate["pre_source_census"] == estate["post_source_census"]
        and estate["semantic_applicability_status"] == "NOT_ESTABLISHED"
        and estate["full_estate_closure"] == "NOT_ESTABLISHED"
        and estate["polished"] is False
        and estate["release_authorized"] is False,
        "ESTATE_BINDING_DIFFERS",
    )
    coordinate = estate["source_coordinate"]
    census = estate["pre_source_census"]
    coordinate_fields = {
        "repository", "revision", "candidate_source_file_count",
        "candidate_source_byte_count", "candidate_source_census_digest",
        "tracked_file_count", "untracked_nonignored_file_count",
    }
    census_fields = {
        "schema_version", "file_count", "total_bytes", "provenance_counts",
        "git_index_digest", "git_status_digest", "files", "ignored_scan",
        "census_digest",
    }
    provenance_counts = census.get("provenance_counts", {}) \
        if type(census) is dict else {}
    files = census.get("files", []) if type(census) is dict else []
    ignored_scan = census.get("ignored_scan", {}) \
        if type(census) is dict else {}
    _require(
        type(coordinate) is dict and set(coordinate) == coordinate_fields
        and type(coordinate["repository"]) is str
        and bool(coordinate["repository"])
        and type(coordinate["revision"]) is str
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}",
                         coordinate["revision"]) is not None
        and type(census) is dict and set(census) == census_fields
        and census.get("schema_version")
            == self_polish_estate.CANDIDATE_SOURCE_CENSUS_SCHEMA
        and type(census.get("file_count")) is int
        and 0 < census["file_count"] <= self_polish_estate.MAX_SOURCE_FILES
        and type(census.get("total_bytes")) is int
        and 0 <= census["total_bytes"] <= self_polish_estate.MAX_SOURCE_BYTES
        and type(provenance_counts) is dict
        and set(provenance_counts) == {
            "GIT_TRACKED", "WORKTREE_UNTRACKED_NONIGNORED",
        }
        and all(type(count) is int and count >= 0
                for count in provenance_counts.values())
        and sum(provenance_counts.values()) == census["file_count"]
        and type(files) is list and len(files) == census["file_count"]
        and coordinate.get("candidate_source_file_count")
            == census.get("file_count")
        and coordinate.get("candidate_source_byte_count")
            == census.get("total_bytes")
        and coordinate.get("candidate_source_census_digest")
            == census.get("census_digest")
        and coordinate.get("tracked_file_count")
            == provenance_counts.get("GIT_TRACKED")
        and coordinate.get("untracked_nonignored_file_count")
            == provenance_counts.get("WORKTREE_UNTRACKED_NONIGNORED")
        and census.get("census_digest")
            == value_digest({
                "schema_version": census.get("schema_version"),
                "file_count": census.get("file_count"),
                "total_bytes": census.get("total_bytes"),
                "provenance_counts": census.get("provenance_counts"),
                "git_index_digest": census.get("git_index_digest"),
                "git_status_digest": census.get("git_status_digest"),
                "files": census.get("files"),
                "ignored_scan": census.get("ignored_scan"),
            }),
        "ESTATE_CENSUS_BINDING_DIFFERS",
    )
    ignored_fields = {
        "ignored_path_count", "ignored_path_set_digest",
        "exclusion_taxonomy_digest", "excluded_cache_build_path_count",
        "excluded_cache_build_paths_digest", "inert_ignored_path_count",
        "inert_ignored_paths_digest", "excluded_bytes_status",
    }
    _require(
        type(ignored_scan) is dict and set(ignored_scan) == ignored_fields
        and all(
            type(ignored_scan[name]) is int and ignored_scan[name] >= 0
            for name in (
                "ignored_path_count", "excluded_cache_build_path_count",
                "inert_ignored_path_count",
            )
        )
        and ignored_scan["ignored_path_count"]
            <= self_polish_estate.MAX_IGNORED_PATHS
        and ignored_scan["ignored_path_count"]
            == ignored_scan["excluded_cache_build_path_count"]
                + ignored_scan["inert_ignored_path_count"]
        and ignored_scan["exclusion_taxonomy_digest"]
            == self_polish_estate.IGNORED_EXCLUSION_TAXONOMY_DIGEST
        and ignored_scan["excluded_bytes_status"] == "NOT_VERIFIED"
        and all(
            type(ignored_scan[name]) is str
            and _SHA256.fullmatch(ignored_scan[name]) is not None
            for name in (
                "ignored_path_set_digest",
                "excluded_cache_build_paths_digest",
                "inert_ignored_paths_digest",
            )
        ),
        "ESTATE_IGNORED_SCAN_BINDING_DIFFERS",
    )
    observed_paths: list[str] = []
    observed_total = 0
    observed_provenance = {
        "GIT_TRACKED": 0, "WORKTREE_UNTRACKED_NONIGNORED": 0,
    }
    for row in files:
        path_value = row.get("path") if type(row) is dict else None
        relative = Path(path_value) if type(path_value) is str else None
        _require(
            type(row) is dict
            and set(row) == {
                "path", "size", "sha256", "provenance", "git_mode",
            }
            and type(row["path"]) is str and bool(row["path"])
            and "\\" not in row["path"]
            and relative is not None and not relative.is_absolute()
            and all(part not in ("", ".", "..") for part in relative.parts)
            and type(row["size"]) is int
            and 0 <= row["size"] <= self_polish_estate.MAX_FILE_BYTES
            and type(row["sha256"]) is str
            and _SHA256.fullmatch(row["sha256"]) is not None
            and row["provenance"] in observed_provenance
            and (
                row["provenance"] == "GIT_TRACKED"
                and row["git_mode"] in {"100644", "100755"}
                or row["provenance"] == "WORKTREE_UNTRACKED_NONIGNORED"
                and row["git_mode"] == "UNTRACKED_REGULAR"
            ),
            "ESTATE_SOURCE_FILE_BINDING_DIFFERS",
        )
        observed_paths.append(row["path"])
        observed_total += row["size"]
        observed_provenance[row["provenance"]] += 1
    _require(
        observed_paths == sorted(observed_paths)
        and len(observed_paths) == len(set(observed_paths))
        and observed_total == census["total_bytes"]
        and observed_provenance == provenance_counts,
        "ESTATE_SOURCE_FILE_SET_DIFFERS",
    )
    categories = estate["required_categories"]
    candidates = estate["candidates"]
    summaries = estate["category_summaries"]
    _require(
        categories == list(self_polish_estate.REQUIRED_CATEGORIES)
        and type(candidates) is list
        and 0 < len(candidates) <= self_polish_estate.MAX_CANDIDATES
        and estate["candidate_count"] == len(candidates)
        and estate["candidate_universe_digest"] == value_digest(candidates)
        and type(summaries) is list and len(summaries) == len(categories),
        "ESTATE_CANDIDATE_UNIVERSE_DIFFERS",
    )
    identifiers: list[str] = []
    for row in candidates:
        _require(type(row) is dict and "candidate_digest" in row,
                 "ESTATE_CANDIDATE_FIELDS_DIFFER")
        candidate_body = {
            key: value for key, value in row.items() if key != "candidate_digest"
        }
        identifier = row.get("candidate_id")
        _require(
            type(identifier) is str and bool(identifier)
            and row["candidate_digest"] == value_digest(candidate_body)
            and row.get("category") in categories,
            "ESTATE_CANDIDATE_BINDING_DIFFERS",
        )
        identifiers.append(identifier)
    _require(
        identifiers == sorted(identifiers)
        and len(identifiers) == len(set(identifiers)),
        "ESTATE_CANDIDATE_ID_SET_DIFFERS",
    )
    source_candidates = [
        row for row in candidates if row["category"] == "candidate_source_file"
    ]
    _require(
        len(source_candidates) == len(files)
        and all(
            candidate.get("candidate_id")
                == "candidate-source-file:" + source["path"]
            and candidate.get("candidate_type") == "CANDIDATE_SOURCE_FILE"
            and candidate.get("source_refs") == [{
                "path": source["path"], "sha256": source["sha256"],
            }]
            and candidate.get("metadata") == {
                "size": source["size"], "provenance": source["provenance"],
                "git_mode": source["git_mode"],
            }
            for candidate, source in zip(source_candidates, files, strict=True)
        ),
        "ESTATE_SOURCE_CANDIDATE_SET_DIFFERS",
    )
    expected_summaries = []
    for category in categories:
        selected = [row for row in candidates if row["category"] == category]
        _require(bool(selected), "ESTATE_CATEGORY_EMPTY")
        expected_summaries.append({
            "category": category,
            "mechanical_status": "PASS",
            "candidate_count": len(selected),
            "candidate_digest": value_digest(selected),
            "semantic_status": "NOT_ESTABLISHED",
        })
    _require(summaries == expected_summaries, "ESTATE_CATEGORY_DIGESTS_DIFFER")
    return estate


def _estate_bindings(estate: dict[str, Any]) -> dict[str, Any]:
    identities = [{
        "candidate_id": row["candidate_id"],
        "candidate_digest": row["candidate_digest"],
        "category": row["category"],
    } for row in estate["candidates"]]
    category_bindings = [{
        "category": row["category"],
        "candidate_count": row["candidate_count"],
        "candidate_digest": row["candidate_digest"],
    } for row in estate["category_summaries"]]
    return {
        "source_coordinate": estate["source_coordinate"],
        "source_coordinate_digest": value_digest(estate["source_coordinate"]),
        "candidate_source_census_digest": estate[
            "pre_source_census"
        ]["census_digest"],
        "estate_digest": estate["estate_digest"],
        "candidate_universe_digest": estate["candidate_universe_digest"],
        "required_categories_digest": value_digest(
            estate["required_categories"]
        ),
        "category_summaries_digest": value_digest(
            estate["category_summaries"]
        ),
        "category_bindings": category_bindings,
        "category_bindings_digest": value_digest(category_bindings),
        "candidate_identity_set_digest": value_digest(identities),
        "candidate_count": estate["candidate_count"],
    }


def _validated_ledger(estate: dict[str, Any], ledger_bytes: bytes,
        expected_ledger_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        result = self_polish_estate.validate_applicability_ledger(
            estate, ledger_bytes,
            expected_ledger_digest=expected_ledger_digest,
        )
    except self_polish_estate.EstateError as exc:
        raise EstateEvidenceError("APPLICABILITY_LEDGER_REJECTED") from exc
    ledger = _decode_canonical(ledger_bytes, "APPLICABILITY_LEDGER")
    return ledger, result


def _validated_authority_subject(subject: Any, *,
        bindings: dict[str, Any], ledger_digest: str) -> dict[str, Any]:
    _require(type(subject) is dict, "ESTATE_AUTHORITY_SUBJECT_REJECTED")
    try:
        expected = self_polish_estate_authority.estate_authority_subject(
            source_coordinate_digest=subject["source_coordinate_digest"],
            estate_source_coordinate_digest=bindings["source_coordinate_digest"],
            candidate_source_census_digest=bindings[
                "candidate_source_census_digest"
            ],
            estate_digest=bindings["estate_digest"],
            candidate_universe_digest=bindings["candidate_universe_digest"],
            required_categories_digest=bindings["required_categories_digest"],
            category_summaries_digest=bindings["category_summaries_digest"],
            applicability_ledger_digest=ledger_digest,
            installed_inventory_digest=subject["installed_inventory_digest"],
            objective_catalog_digest=subject["objective_catalog_digest"],
            structural_route_crosswalk_digest=subject[
                "structural_route_crosswalk_digest"
            ],
            structural_identity_digest=subject["structural_identity_digest"],
            route_identity_digest=subject["route_identity_digest"],
            shared_identity_digest=subject["shared_identity_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EstateEvidenceError("ESTATE_AUTHORITY_SUBJECT_REJECTED") from exc
    _require(subject == expected, "ESTATE_AUTHORITY_SUBJECT_BINDING_DIFFERS")
    return subject


def _crosswalk_authority_binding(subject: dict[str, Any],
        estate: dict[str, Any]) -> None:
    _require(
        subject["structural_route_crosswalk_digest"]
            == value_digest(estate["structural_route_crosswalk"])
        and subject["structural_identity_digest"]
            == estate["structural_route_crosswalk"][
                "structural_identity_digest"
            ]
        and subject["route_identity_digest"]
            == estate["structural_route_crosswalk"]["route_identity_digest"]
        and subject["shared_identity_digest"]
            == estate["structural_route_crosswalk"]["shared_identity_digest"],
        "ESTATE_AUTHORITY_CROSSWALK_BINDING_DIFFERS",
    )


def evidence_manifest_template(estate: dict[str, Any], ledger_bytes: bytes, *,
        expected_ledger_digest: str,
        estate_authority_subject: dict[str, Any]) -> dict[str, Any]:
    """Build an all-UNKNOWN exact-denominator manifest for external evidence."""
    selected = _validated_estate(estate)
    bindings = _estate_bindings(selected)
    ledger, ledger_result = _validated_ledger(
        selected, ledger_bytes, expected_ledger_digest
    )
    authority_subject = _validated_authority_subject(
        estate_authority_subject,
        bindings=bindings,
        ledger_digest=ledger["ledger_digest"],
    )
    _crosswalk_authority_binding(authority_subject, selected)
    candidates = {row["candidate_id"]: row for row in selected["candidates"]}
    rows = []
    for row in ledger["rows"]:
        candidate = candidates[row["candidate_id"]]
        rows.append({
            "candidate_id": row["candidate_id"],
            "candidate_digest": row["candidate_digest"],
            "category": candidate["category"],
            "applicability_disposition": row["applicability_status"],
            "semantic_basis_digest": row["authority_digest"],
            "evidence_disposition": "UNKNOWN",
            "evidence_artifact_digest": None,
            "justification": row["justification"],
        })
    body = {
        "schema_version": MANIFEST_SCHEMA,
        "mechanism_digest": mechanism_digest(),
        **bindings,
        "applicability_ledger_digest": ledger["ledger_digest"],
        "applicability_validation_result_digest": ledger_result[
            "result_digest"
        ],
        "estate_authority_subject_digest": value_digest(authority_subject),
        "rows": rows,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    return {**body, "manifest_digest": value_digest(body)}


def _validated_manifest(manifest_bytes: bytes, *, expected_manifest_digest: str,
        estate: dict[str, Any], bindings: dict[str, Any],
        ledger: dict[str, Any], ledger_result: dict[str, Any],
        authority_subject_digest: str) -> dict[str, Any]:
    manifest = _decode_canonical(manifest_bytes, "EVIDENCE_MANIFEST")
    required = {
        "schema_version", "mechanism_digest", "source_coordinate",
        "source_coordinate_digest", "candidate_source_census_digest",
        "estate_digest", "candidate_universe_digest",
        "required_categories_digest", "category_summaries_digest",
        "category_bindings", "category_bindings_digest",
        "candidate_identity_set_digest", "candidate_count",
        "applicability_ledger_digest",
        "applicability_validation_result_digest",
        "estate_authority_subject_digest", "rows", "claim_boundary",
        "manifest_digest",
    }
    _require(set(manifest) == required, "EVIDENCE_MANIFEST_FIELDS_DIFFER")
    body = {
        key: value for key, value in manifest.items() if key != "manifest_digest"
    }
    _hash(expected_manifest_digest, "EVIDENCE_MANIFEST_DIGEST_INVALID")
    _require(
        manifest["manifest_digest"] == expected_manifest_digest
        and manifest["manifest_digest"] == value_digest(body),
        "EVIDENCE_MANIFEST_DIGEST_DIFFERS",
    )
    expected_bindings = {
        key: bindings[key] for key in (
            "source_coordinate", "source_coordinate_digest",
            "candidate_source_census_digest", "estate_digest",
            "candidate_universe_digest", "required_categories_digest",
            "category_summaries_digest", "category_bindings",
            "category_bindings_digest", "candidate_identity_set_digest",
            "candidate_count",
        )
    }
    _require(
        manifest["schema_version"] == MANIFEST_SCHEMA
        and manifest["mechanism_digest"] == mechanism_digest()
        and all(manifest[key] == value for key, value in expected_bindings.items())
        and manifest["applicability_ledger_digest"] == ledger["ledger_digest"]
        and manifest["applicability_validation_result_digest"]
            == ledger_result["result_digest"]
        and manifest["estate_authority_subject_digest"]
            == authority_subject_digest
        and manifest["claim_boundary"] == _CLAIM_BOUNDARY,
        "EVIDENCE_MANIFEST_BINDING_DIFFERS",
    )
    rows = manifest["rows"]
    candidates = {row["candidate_id"]: row for row in estate["candidates"]}
    ledger_rows = {row["candidate_id"]: row for row in ledger["rows"]}
    _require(
        type(rows) is list and len(rows) == len(candidates),
        "EVIDENCE_MANIFEST_DENOMINATOR_DIFFERS",
    )
    observed: set[str] = set()
    observed_order: list[str] = []
    row_fields = {
        "candidate_id", "candidate_digest", "category",
        "applicability_disposition", "semantic_basis_digest",
        "evidence_disposition", "evidence_artifact_digest", "justification",
    }
    for row in rows:
        _require(type(row) is dict and set(row) == row_fields,
                 "EVIDENCE_MANIFEST_ROW_FIELDS_DIFFER")
        identifier = row["candidate_id"]
        _require(
            type(identifier) is str and identifier in candidates
            and identifier not in observed,
            "EVIDENCE_MANIFEST_ID_SET_DIFFERS",
        )
        observed.add(identifier)
        observed_order.append(identifier)
        candidate = candidates[identifier]
        ledger_row = ledger_rows[identifier]
        _require(
            row["candidate_digest"] == candidate["candidate_digest"]
            and row["category"] == candidate["category"],
            "EVIDENCE_MANIFEST_CANDIDATE_SUBSTITUTED",
        )
        _require(
            row["applicability_disposition"]
                == ledger_row["applicability_status"]
            and row["applicability_disposition"] in {
                "APPLICABLE", "NOT_APPLICABLE", "UNKNOWN",
            }
            and row["evidence_disposition"] in {"PASS", "FAIL", "UNKNOWN"},
            "EVIDENCE_MANIFEST_DISPOSITION_INVALID",
        )
        _hash(row["semantic_basis_digest"],
              "EVIDENCE_MANIFEST_SEMANTIC_BASIS_INVALID", optional=True)
        _hash(row["evidence_artifact_digest"],
              "EVIDENCE_MANIFEST_ARTIFACT_DIGEST_INVALID", optional=True)
        _require(
            type(row["justification"]) is str
            and 0 < len(row["justification"].encode("utf-8"))
                <= MAX_JUSTIFICATION_BYTES,
            "EVIDENCE_MANIFEST_JUSTIFICATION_INVALID",
        )
        applicable = row["applicability_disposition"] == "APPLICABLE"
        _require(
            (applicable and row["evidence_disposition"] in {"PASS", "FAIL"}
             and row["evidence_artifact_digest"] is not None)
            or (applicable and row["evidence_disposition"] == "UNKNOWN"
                and row["evidence_artifact_digest"] is None)
            or (not applicable and row["evidence_disposition"] == "UNKNOWN"
                and row["evidence_artifact_digest"] is None),
            "EVIDENCE_MANIFEST_EVIDENCE_BINDING_INVALID",
        )
        _require(
            row["applicability_disposition"] != "UNKNOWN"
            or row["semantic_basis_digest"] is None,
            "EVIDENCE_MANIFEST_UNKNOWN_BASIS_INVALID",
        )
    _require(
        observed == set(candidates)
        and observed_order == [row["candidate_id"] for row in estate["candidates"]],
        "EVIDENCE_MANIFEST_ID_SET_DIFFERS",
    )
    return manifest


def candidate_evidence_subject(manifest: dict[str, Any],
        row: dict[str, Any]) -> dict[str, Any]:
    """Return the exact per-candidate proposition for configured-key replay."""
    values = {
        "adapter_mechanism_digest": mechanism_digest(),
        "native_evidence_mechanism_digest": (
            self_polish_estate_native_evidence.mechanism_digest()
        ),
        "source_coordinate_digest": manifest["source_coordinate_digest"],
        "candidate_source_census_digest": manifest[
            "candidate_source_census_digest"
        ],
        "estate_digest": manifest["estate_digest"],
        "candidate_universe_digest": manifest["candidate_universe_digest"],
        "required_categories_digest": manifest["required_categories_digest"],
        "category_summaries_digest": manifest["category_summaries_digest"],
        "category_bindings_digest": manifest["category_bindings_digest"],
        "candidate_identity_set_digest": manifest[
            "candidate_identity_set_digest"
        ],
        "applicability_ledger_digest": manifest[
            "applicability_ledger_digest"
        ],
        "estate_authority_subject_digest": manifest[
            "estate_authority_subject_digest"
        ],
        "manifest_digest": manifest["manifest_digest"],
        "candidate_id": row["candidate_id"],
        "candidate_digest": row["candidate_digest"],
        "category": row["category"],
        "applicability_disposition": row["applicability_disposition"],
        "semantic_basis_digest": row["semantic_basis_digest"],
        "evidence_disposition": row["evidence_disposition"],
        "evidence_artifact_digest": row["evidence_artifact_digest"],
    }
    for name, value in values.items():
        if name.endswith("_digest"):
            _hash(value, "CANDIDATE_EVIDENCE_SUBJECT_DIGEST_INVALID",
                  optional=name in {
                      "semantic_basis_digest", "evidence_artifact_digest",
                  })
    return {
        "schema_version": SUBJECT_SCHEMA,
        "operation": OPERATION,
        **values,
    }


def _missing_candidate_replay(blocker: str) -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "replay_status": "NOT_ESTABLISHED",
        "receipt_digest": None,
        "policy_digest": None,
        "approving_actors": [],
        "blockers": [blocker],
    }


def _candidate_result(row: dict[str, Any], subject_digest: str,
        replay: dict[str, Any], native: dict[str, Any]) -> dict[str, Any]:
    blockers = list(replay["blockers"])
    blockers.extend(native["blockers"])
    authority_failure = replay["status"] == "FAIL" or any(
        blocker in _DEFINITE_REPLAY_FAILURES for blocker in blockers
    )
    independent_authority_status = (
        "FAIL" if authority_failure else
        "PASS" if replay["status"] == "PASS" else
        "NOT_ESTABLISHED"
    )
    native_applicability = native["native_applicability_status"]
    declared = row["applicability_disposition"]
    disposition_conflict = (
        declared in {"APPLICABLE", "NOT_APPLICABLE"}
        and declared != native_applicability
    )
    if disposition_conflict:
        blockers.append("CANDIDATE_DECLARATION_DIFFERS_FROM_NATIVE_APPLICABILITY")
    if native["status"] == "FAIL" or disposition_conflict:
        native_semantic_status = "FAIL"
    elif native_applicability == "NOT_APPLICABLE" \
            and native["status"] == "NOT_APPLICABLE":
        native_semantic_status = "NOT_APPLICABLE"
    elif native_applicability == "APPLICABLE" \
            and native["status"] == "PASS" \
            and row["evidence_disposition"] == "PASS":
        native_semantic_status = "PASS"
    elif native_applicability == "APPLICABLE" \
            and native["status"] == "PASS":
        blockers.append("CANDIDATE_DECLARATION_DIFFERS_FROM_NATIVE_REPLAY")
        native_semantic_status = "FAIL"
    else:
        blockers.append("CANDIDATE_NATIVE_EVIDENCE_NOT_ESTABLISHED")
        native_semantic_status = "UNKNOWN"

    if authority_failure or native_semantic_status == "FAIL":
        applicability_status = "FAIL"
        evidence_status = "FAIL"
        semantic_status = "FAIL"
        replay_status = (
            "REJECTED" if authority_failure else replay["replay_status"]
        )
    elif replay["status"] != "PASS":
        applicability_status = "UNKNOWN"
        evidence_status = "UNKNOWN"
        semantic_status = "UNKNOWN"
        replay_status = replay["replay_status"]
    elif row["semantic_basis_digest"] is None:
        blockers.append("CANDIDATE_SEMANTIC_BASIS_UNAVAILABLE")
        applicability_status = "UNKNOWN"
        evidence_status = "UNKNOWN"
        semantic_status = "UNKNOWN"
        replay_status = replay["replay_status"]
    elif declared == "UNKNOWN":
        applicability_status = "UNKNOWN"
        evidence_status = "UNKNOWN"
        semantic_status = "UNKNOWN"
        replay_status = replay["replay_status"]
    elif native_semantic_status == "NOT_APPLICABLE":
        applicability_status = "NOT_APPLICABLE"
        evidence_status = "NOT_APPLICABLE"
        semantic_status = "NOT_APPLICABLE"
        replay_status = replay["replay_status"]
    elif native_semantic_status != "PASS":
        applicability_status = "APPLICABLE"
        evidence_status = "UNKNOWN"
        semantic_status = "UNKNOWN"
        replay_status = replay["replay_status"]
    else:
        applicability_status = "APPLICABLE"
        evidence_status = "PASS"
        semantic_status = "PASS"
        replay_status = replay["replay_status"]
    return {
        "candidate_id": row["candidate_id"],
        "candidate_digest": row["candidate_digest"],
        "category": row["category"],
        "declared_applicability": row["applicability_disposition"],
        "declared_evidence_disposition": row["evidence_disposition"],
        "subject_digest": subject_digest,
        "replay_status": replay_status,
        "independent_authority_status": independent_authority_status,
        "native_applicability_status": native_applicability,
        "native_replay_status": native["status"],
        "native_replay_digest": native.get("result_digest"),
        "native_semantic_status": native_semantic_status,
        "receipt_digest": replay["receipt_digest"],
        "policy_digest": replay["policy_digest"],
        "approving_actors": replay["approving_actors"],
        "applicability_status": applicability_status,
        "evidence_status": evidence_status,
        "semantic_status": semantic_status,
        "blockers": sorted(set(blockers)),
    }


def replay_estate_evidence(*, estate: dict[str, Any], ledger_bytes: bytes,
        expected_ledger_digest: str, manifest_bytes: bytes,
        expected_manifest_digest: str,
        estate_authority_subject: dict[str, Any],
        estate_authority_replay: (
            core_application_authority.QualifiedAuthorityReplaySelection | None
        ),
        candidate_replays: Mapping[
            str,
            core_application_authority.QualifiedAuthorityReplaySelection | None,
        ], source_root: str | Path | None = None,
        evidence_artifacts: Mapping[str, bytes] | None = None,
        ) -> dict[str, Any]:
    """Replay the exact estate authority and each candidate evidence receipt."""
    report: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA,
        "status": "UNKNOWN",
        "mechanical_validation_status": "UNKNOWN",
        "estate_authority_status": "UNKNOWN",
        "independent_authority_status": "NOT_ESTABLISHED",
        "native_semantic_applicability_status": "UNKNOWN",
        "native_per_candidate_evidence_status": "UNKNOWN",
        "native_self_verification_status": "UNKNOWN",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "per_candidate_evidence_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "tier1_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "assessment_time": None,
        "native_source_recapture_status": "NOT_ESTABLISHED",
        "source_coordinate_digest": None,
        "candidate_source_census_digest": None,
        "estate_digest": None,
        "candidate_universe_digest": None,
        "candidate_identity_set_digest": None,
        "applicability_ledger_digest": None,
        "manifest_digest": None,
        "estate_authority_replay_digest": None,
        "candidate_count": 0,
        "applicable_candidate_count": 0,
        "native_applicable_candidate_count": 0,
        "authenticated_candidate_count": 0,
        "native_replayed_candidate_count": 0,
        "native_candidate_pass_count": 0,
        "native_candidate_fail_count": 0,
        "native_candidate_unknown_count": 0,
        "native_evidence_artifact_count": 0,
        "candidate_pass_count": 0,
        "candidate_fail_count": 0,
        "candidate_unknown_count": 0,
        "candidate_results": [],
        "blockers": [],
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    try:
        selected = _validated_estate(estate)
        bindings = _estate_bindings(selected)
        ledger, ledger_result = _validated_ledger(
            selected, ledger_bytes, expected_ledger_digest
        )
        authority_subject = _validated_authority_subject(
            estate_authority_subject,
            bindings=bindings,
            ledger_digest=ledger["ledger_digest"],
        )
        _crosswalk_authority_binding(authority_subject, selected)
        authority_subject_digest = value_digest(authority_subject)
        manifest = _validated_manifest(
            manifest_bytes,
            expected_manifest_digest=expected_manifest_digest,
            estate=selected,
            bindings=bindings,
            ledger=ledger,
            ledger_result=ledger_result,
            authority_subject_digest=authority_subject_digest,
        )
        artifacts = evidence_artifacts or {}
        artifact_eligible_ids = {
            row["candidate_id"] for row in manifest["rows"]
            if row["applicability_disposition"] == "APPLICABLE"
            and row["evidence_artifact_digest"] is not None
        }
        _require(
            isinstance(candidate_replays, Mapping)
            and set(candidate_replays).issubset({
                row["candidate_id"] for row in selected["candidates"]
            }),
            "CANDIDATE_REPLAY_SELECTION_SET_DIFFERS",
        )
        _require(
            isinstance(artifacts, Mapping)
            and set(artifacts).issubset(artifact_eligible_ids)
            and all(type(raw) is bytes for raw in artifacts.values()),
            "NATIVE_EVIDENCE_ARTIFACT_SET_DIFFERS",
        )
        _require(
            all(0 < len(raw)
                <= self_polish_estate_native_evidence.MAX_ARTIFACT_BYTES
                for raw in artifacts.values())
            and sum(len(raw) for raw in artifacts.values())
                <= MAX_MANIFEST_BYTES,
            "NATIVE_EVIDENCE_ARTIFACT_CAPACITY_EXHAUSTED",
        )
        assessment_time = int(time.time())
        report["assessment_time"] = assessment_time
        report["native_evidence_artifact_count"] = len(artifacts)
        authority_selection = (
            None if estate_authority_replay is None
            else dataclasses.replace(
                estate_authority_replay, evaluation_time=assessment_time
            )
        )
        authority_report = self_polish_estate_authority.replay_estate_authority(
            authority_subject, authority_replay=authority_selection
        )
        native_context = None
        if source_root is not None:
            native_context = (
                self_polish_estate_native_evidence.prepare_replay_context(
                    selected, source_root
                )
            )
            report["native_source_recapture_status"] = "PASS"
        report.update(
            mechanical_validation_status="PASS",
            estate_authority_status=authority_report["status"],
            source_coordinate_digest=bindings["source_coordinate_digest"],
            candidate_source_census_digest=bindings[
                "candidate_source_census_digest"
            ],
            estate_digest=bindings["estate_digest"],
            candidate_universe_digest=bindings["candidate_universe_digest"],
            candidate_identity_set_digest=bindings[
                "candidate_identity_set_digest"
            ],
            applicability_ledger_digest=ledger["ledger_digest"],
            manifest_digest=manifest["manifest_digest"],
            estate_authority_replay_digest=authority_report["result_digest"],
            candidate_count=len(manifest["rows"]),
            applicable_candidate_count=sum(
                row["applicability_disposition"] == "APPLICABLE"
                for row in manifest["rows"]
            ),
        )
        report["blockers"].extend(authority_report["blockers"])
        candidates_by_id = {
            item["candidate_id"]: item for item in selected["candidates"]
        }
        results = []
        for row in manifest["rows"]:
            subject = candidate_evidence_subject(manifest, row)
            subject_digest = value_digest(subject)
            candidate = candidates_by_id[row["candidate_id"]]
            native_applicability = (
                self_polish_estate_native_evidence
                .native_applicability_status(candidate)
            )
            selection = candidate_replays.get(row["candidate_id"])
            if selection is None:
                replay = _missing_candidate_replay(
                    "CANDIDATE_EVIDENCE_RECEIPT_UNAVAILABLE"
                )
            else:
                replay = (
                    core_application_authority
                    .replay_qualified_authority_receipt(
                        dataclasses.replace(
                            selection, evaluation_time=assessment_time
                        ),
                        required_operation=OPERATION,
                        required_subject_digest=subject_digest,
                    )
                )
            if native_applicability == "NOT_APPLICABLE":
                native = {
                    "status": "NOT_APPLICABLE",
                    "native_applicability_status": "NOT_APPLICABLE",
                    "blockers": [],
                }
            elif row["candidate_id"] not in artifacts:
                native = {
                    "status": "UNKNOWN",
                    "native_applicability_status": native_applicability,
                    "blockers": ["NATIVE_EVIDENCE_ARTIFACT_UNAVAILABLE"],
                }
            else:
                try:
                    (
                        self_polish_estate_native_evidence
                        .validate_evidence_artifact(
                            estate=selected,
                            candidate=candidate,
                            artifact_bytes=artifacts[row["candidate_id"]],
                            expected_artifact_digest=row[
                                "evidence_artifact_digest"
                            ],
                        )
                    )
                except (
                    self_polish_estate_native_evidence.NativeEvidenceError
                ) as exc:
                    native = {
                        "status": "FAIL",
                        "native_applicability_status": native_applicability,
                        "blockers": [str(exc)],
                    }
                else:
                    if native_context is None:
                        native = {
                            "status": "UNKNOWN",
                            "native_applicability_status": (
                                native_applicability
                            ),
                            "blockers": [
                                "NATIVE_EVIDENCE_SOURCE_ROOT_UNAVAILABLE"
                            ],
                        }
                    else:
                        native = (
                            self_polish_estate_native_evidence
                            .replay_native_evidence(
                                context=native_context,
                                estate=selected,
                                candidate=native_context["candidates"][
                                    row["candidate_id"]
                                ],
                                artifact_bytes=artifacts[
                                    row["candidate_id"]
                                ],
                                expected_artifact_digest=row[
                                    "evidence_artifact_digest"
                                ],
                            )
                        )
            result = _candidate_result(
                row, subject_digest, replay, native
            )
            results.append(result)
            report["blockers"].extend(result["blockers"])
        report["candidate_results"] = results
        report["native_applicable_candidate_count"] = sum(
            row["native_applicability_status"] == "APPLICABLE"
            for row in results
        )
        report["authenticated_candidate_count"] = sum(
            row["replay_status"] == "REPRODUCED" for row in results
        )
        report["native_replayed_candidate_count"] = sum(
            row["native_replay_status"] in {"PASS", "NOT_APPLICABLE"}
            for row in results
        )
        report["native_candidate_pass_count"] = sum(
            row["native_semantic_status"] in {"PASS", "NOT_APPLICABLE"}
            for row in results
        )
        report["native_candidate_fail_count"] = sum(
            row["native_semantic_status"] == "FAIL" for row in results
        )
        report["native_candidate_unknown_count"] = sum(
            row["native_semantic_status"] == "UNKNOWN" for row in results
        )
        report["candidate_pass_count"] = sum(
            row["semantic_status"] in {"PASS", "NOT_APPLICABLE"}
            for row in results
        )
        report["candidate_fail_count"] = sum(
            row["semantic_status"] == "FAIL" for row in results
        )
        report["candidate_unknown_count"] = sum(
            row["semantic_status"] == "UNKNOWN" for row in results
        )
        candidate_authority_statuses = {
            row["independent_authority_status"] for row in results
        }
        if authority_report["status"] == "FAIL" \
                or "FAIL" in candidate_authority_statuses:
            report["independent_authority_status"] = "FAIL"
        elif authority_report["status"] == "PASS" \
                and candidate_authority_statuses == {"PASS"}:
            report["independent_authority_status"] = "PASS"
        else:
            report["independent_authority_status"] = "NOT_ESTABLISHED"
        applicability_contradicted = any(
            "CANDIDATE_DECLARATION_DIFFERS_FROM_NATIVE_APPLICABILITY"
            in row["blockers"] for row in results
        )
        if report["native_source_recapture_status"] == "FAIL" \
                or applicability_contradicted:
            report["native_semantic_applicability_status"] = "FAIL"
        elif report["native_source_recapture_status"] == "PASS" \
                and all(row["native_applicability_status"] in {
                    "APPLICABLE", "NOT_APPLICABLE",
                } for row in results):
            report["native_semantic_applicability_status"] = "PASS"
        else:
            report["native_semantic_applicability_status"] = "UNKNOWN"
        if report["native_source_recapture_status"] == "FAIL" \
                or report["native_candidate_fail_count"] > 0:
            report["native_per_candidate_evidence_status"] = "FAIL"
            report["native_self_verification_status"] = "FAIL"
        elif report["native_source_recapture_status"] == "PASS" \
                and report["native_candidate_unknown_count"] == 0 \
                and report["native_candidate_pass_count"] == len(results):
            report["native_per_candidate_evidence_status"] = "PASS"
            report["native_self_verification_status"] = "PASS"
        else:
            report["native_per_candidate_evidence_status"] = "UNKNOWN"
            report["native_self_verification_status"] = "UNKNOWN"
        any_failure = (
            authority_report["status"] == "FAIL"
            or report["candidate_fail_count"] > 0
        )
        all_applicability_resolved = all(
            row["applicability_status"] in {"APPLICABLE", "NOT_APPLICABLE"}
            for row in results
        )
        all_evidence_resolved = all(
            row["semantic_status"] in {"PASS", "NOT_APPLICABLE"}
            for row in results
        )
        if any_failure:
            report.update(
                status="FAIL",
                semantic_applicability_status="FAIL",
                per_candidate_evidence_status="FAIL",
                full_estate_closure="FAIL",
            )
        elif authority_report["status"] == "PASS" \
                and report["native_source_recapture_status"] == "PASS" \
                and all_applicability_resolved and all_evidence_resolved:
            report.update(
                status="PASS",
                semantic_applicability_status="PASS",
                per_candidate_evidence_status="PASS",
                full_estate_closure="PASS",
            )
        else:
            report.update(
                status="UNKNOWN",
                semantic_applicability_status="NOT_ESTABLISHED",
                per_candidate_evidence_status="NOT_ESTABLISHED",
                full_estate_closure="NOT_ESTABLISHED",
            )
            if authority_report["status"] != "PASS":
                report["blockers"].append(
                    "ESTATE_AUTHORITY_NOT_ESTABLISHED"
                )
            if report["native_source_recapture_status"] != "PASS":
                report["blockers"].append(
                    "NATIVE_ESTATE_SOURCE_RECAPTURE_NOT_ESTABLISHED"
                )
            if not all_evidence_resolved:
                report["blockers"].append(
                    "PER_CANDIDATE_EVIDENCE_NOT_ESTABLISHED"
                )
    except (EstateEvidenceError,
            self_polish_estate_native_evidence.NativeEvidenceError,
            self_polish_estate.EstateError) as exc:
        report.update(
            status="FAIL",
            mechanical_validation_status="FAIL",
            estate_authority_status="FAIL",
            independent_authority_status="FAIL",
            native_semantic_applicability_status="FAIL",
            native_per_candidate_evidence_status="FAIL",
            native_self_verification_status="FAIL",
            semantic_applicability_status="FAIL",
            per_candidate_evidence_status="FAIL",
            full_estate_closure="FAIL",
        )
        if str(exc).startswith("NATIVE_"):
            report["native_source_recapture_status"] = "FAIL"
        report["blockers"].append(str(exc))
    except (KeyError, TypeError, ValueError, UnicodeError):
        report.update(
            status="FAIL",
            mechanical_validation_status="FAIL",
            estate_authority_status="FAIL",
            independent_authority_status="FAIL",
            native_semantic_applicability_status="FAIL",
            native_per_candidate_evidence_status="FAIL",
            native_self_verification_status="FAIL",
            semantic_applicability_status="FAIL",
            per_candidate_evidence_status="FAIL",
            full_estate_closure="FAIL",
        )
        report["blockers"].append("ESTATE_EVIDENCE_CONTRACT_REJECTED")
    report["blockers"] = sorted(set(report["blockers"]))
    report["result_digest"] = value_digest(report)
    return report


__all__ = [
    "EstateEvidenceError", "MANIFEST_SCHEMA", "OPERATION", "RESULT_SCHEMA",
    "SUBJECT_SCHEMA", "bytes_digest", "candidate_evidence_subject",
    "canonical_bytes", "evidence_manifest_template", "mechanism_digest",
    "replay_estate_evidence", "value_digest",
]
