"""Validate JavaScript Object Notation (JSON) for an externally selected source scope.

The reader consumes exact manifest bytes and an injected callback for named
members.  It deliberately has no repository-root, Git, glob, walk, network, or
provider interface.  A successful local validation therefore remains bounded
to the selected manifest and cannot establish repository completeness.
Member paths must be Unicode scalar text in Unicode Normalization Form C (NFC);
portable comparison keys detect aliases but never rewrite accepted path bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Callable, Mapping
import unicodedata


SCHEMA_VERSION = "verifier-selected-source-scope-1"
ALLOWED_ROLES = frozenset({"SOURCE", "DOCUMENT", "SCHEMA", "METADATA"})
ALLOWED_MEMBER_KINDS = frozenset({"REGULAR"})
SHA256 = re.compile(r"[0-9a-f]{64}")


class ScopeInputError(ValueError):
    """A fail-closed selected-source input error with a stable code."""

    __slots__ = ("code",)

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class MemberObservation:
    """Exact callback observation for one already selected member."""

    __slots__ = ("kind", "content")

    def __init__(self, *, kind: str, content: bytes) -> None:
        self.kind = kind
        self.content = content


class SelectedSourceScope:
    """Validated bounded scope; never a repository-completeness assertion."""

    __slots__ = (
        "manifest_sha256",
        "source_coordinate",
        "member_paths",
        "completeness",
        "release_admissible",
    )

    def __init__(
        self,
        *,
        manifest_sha256: str,
        source_coordinate: str,
        member_paths: tuple[str, ...],
    ) -> None:
        self.manifest_sha256 = manifest_sha256
        self.source_coordinate = source_coordinate
        self.member_paths = member_paths
        self.completeness = "UNKNOWN"
        self.release_admissible = False


def _reject(code: str, message: str) -> None:
    raise ScopeInputError(code, message)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_object(value: Any, fields: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        _reject(code, "object fields differ from the exact selected-source schema")
    return value


def _valid_sha256(value: Any) -> bool:
    return type(value) is str and SHA256.fullmatch(value) is not None


def _portable_path_key(value: str) -> str:
    """Return a portable comparison key; accepted path bytes are never rewritten."""

    return unicodedata.normalize("NFC", value.casefold())


def _validate_path(value: Any) -> str:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        _reject("MEMBER_PATH_INVALID", "member path is not canonical bounded text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ScopeInputError(
            "MEMBER_PATH_INVALID", "member path is not Unicode scalar text"
        ) from error
    if unicodedata.normalize("NFC", value) != value:
        _reject("MEMBER_PATH_INVALID", "member path is not NFC-normalized text")
    if value.startswith("/") or ":" in value:
        _reject("MEMBER_PATH_INVALID", "member path is absolute or drive-qualified")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        _reject("MEMBER_PATH_INVALID", "member path is noncanonical or traversing")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("MANIFEST_JSON_INVALID", "manifest contains a duplicate object key")
        result[key] = value
    return result


def _parse_manifest(
    manifest_bytes: bytes,
    *,
    expected_manifest_sha256: str,
    expected_source_coordinate: str,
    max_member_bytes: int,
    max_total_bytes: int,
) -> tuple[str, tuple[dict[str, Any], ...]]:
    if type(manifest_bytes) is not bytes:
        _reject("MANIFEST_BYTES_INVALID", "manifest must be supplied as exact bytes")
    if not _valid_sha256(expected_manifest_sha256):
        _reject("EXPECTED_MANIFEST_DIGEST_INVALID", "external manifest digest is invalid")
    actual_manifest_sha256 = _sha256(manifest_bytes)
    if actual_manifest_sha256 != expected_manifest_sha256:
        _reject("MANIFEST_DIGEST_MISMATCH", "manifest differs from external selection")
    if not _valid_sha256(expected_source_coordinate):
        _reject("EXPECTED_SOURCE_COORDINATE_INVALID", "external source coordinate is invalid")
    if (
        type(max_member_bytes) is not int
        or isinstance(max_member_bytes, bool)
        or max_member_bytes < 0
        or type(max_total_bytes) is not int
        or isinstance(max_total_bytes, bool)
        or max_total_bytes < 0
    ):
        _reject("BYTE_BOUND_INVALID", "byte bounds must be nonnegative integers")
    try:
        document = json.loads(manifest_bytes, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScopeInputError("MANIFEST_JSON_INVALID", "manifest is not valid JSON") from error
    document = _exact_object(
        document,
        frozenset(
            {
                "schema_version",
                "candidate_status",
                "completeness",
                "release_admissible",
                "source_coordinate",
                "members",
            }
        ),
        "MANIFEST_SHAPE_INVALID",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        _reject("SCHEMA_VERSION_INVALID", "unsupported selected-source schema")
    if document["candidate_status"] != "CANDIDATE":
        _reject("CANDIDATE_STATUS_INVALID", "manifest is not a candidate")
    if document["completeness"] != "UNKNOWN":
        _reject(
            "UNSUPPORTED_COMPLETENESS_CLAIM",
            "selected-source manifests cannot authenticate completeness",
        )
    if document["release_admissible"] is not False:
        _reject(
            "RELEASE_CLAIM_FORBIDDEN",
            "selected-source manifests cannot grant release admissibility",
        )
    source_coordinate = document["source_coordinate"]
    if not _valid_sha256(source_coordinate):
        _reject("SOURCE_COORDINATE_INVALID", "manifest source coordinate is invalid")
    if source_coordinate != expected_source_coordinate:
        _reject("SOURCE_COORDINATE_MISMATCH", "source coordinate differs from selection")
    members_value = document["members"]
    if type(members_value) is not list:
        _reject("MEMBERS_INVALID", "members must be an ordered list")

    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    declared_total = 0
    for value in members_value:
        member = _exact_object(
            value,
            frozenset({"path", "role", "sha256", "size_bytes"}),
            "MEMBER_SHAPE_INVALID",
        )
        path = _validate_path(member["path"])
        folded = _portable_path_key(path)
        if folded in seen:
            _reject("MEMBER_PATH_COLLISION", "member paths collide under case folding")
        seen.add(folded)
        if member["role"] not in ALLOWED_ROLES:
            _reject("MEMBER_ROLE_INVALID", "member role is unsupported")
        if not _valid_sha256(member["sha256"]):
            _reject("MEMBER_DIGEST_INVALID", "member digest is invalid")
        size = member["size_bytes"]
        if type(size) is not int or isinstance(size, bool) or size < 0:
            _reject("MEMBER_SIZE_INVALID", "member size must be a nonnegative integer")
        if size > max_member_bytes:
            _reject("MEMBER_SIZE_LIMIT", "declared member exceeds its byte bound")
        declared_total += size
        if declared_total > max_total_bytes:
            _reject("TOTAL_SIZE_LIMIT", "declared members exceed the total byte bound")
        members.append(member)
    return source_coordinate, tuple(members)


def _validate_observation(member: Mapping[str, Any], observation: Any) -> None:
    if not isinstance(observation, MemberObservation):
        _reject("MEMBER_OBSERVATION_INVALID", "callback returned an invalid observation")
    if observation.kind not in ALLOWED_MEMBER_KINDS:
        _reject("MEMBER_NOT_REGULAR", "selected member is not a regular file")
    if type(observation.content) is not bytes:
        _reject("MEMBER_CONTENT_INVALID", "selected member content must be exact bytes")

    expected_size = member["size_bytes"]
    actual_size = len(observation.content)
    expected_digest = member["sha256"]
    actual_digest = _sha256(observation.content)
    if actual_size != expected_size:
        # Distinguish a pure length-envelope defect from substituted content.
        # Appended bytes after an otherwise exact declared payload are a size
        # mismatch; content substitutions retain the stronger digest finding.
        prefix_matches = (
            actual_size > expected_size
            and _sha256(observation.content[:expected_size]) == expected_digest
        )
        if prefix_matches or actual_size < expected_size:
            _reject("MEMBER_SIZE_MISMATCH", "observed member size differs")
        _reject("MEMBER_DIGEST_MISMATCH", "observed member bytes differ")
    if actual_digest != expected_digest:
        _reject("MEMBER_DIGEST_MISMATCH", "observed member bytes differ")


def load_selected_source_scope(
    *,
    manifest_bytes: bytes,
    expected_manifest_sha256: str,
    expected_source_coordinate: str,
    read_member: Callable[[str], MemberObservation],
    max_member_bytes: int,
    max_total_bytes: int,
) -> SelectedSourceScope:
    """Validate only members named by an externally bound candidate manifest."""

    if not callable(read_member):
        _reject("MEMBER_READER_INVALID", "exact-member callback is not callable")
    source_coordinate, members = _parse_manifest(
        manifest_bytes,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_source_coordinate=expected_source_coordinate,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
    )
    paths: list[str] = []
    for member in members:
        path = member["path"]
        try:
            observation = read_member(path)
        except FileNotFoundError as error:
            raise ScopeInputError("MEMBER_MISSING", "selected member is unavailable") from error
        except ScopeInputError:
            raise
        except Exception as error:
            raise ScopeInputError("MEMBER_READ_FAILED", "selected member read failed") from error
        _validate_observation(member, observation)
        paths.append(path)
    return SelectedSourceScope(
        manifest_sha256=expected_manifest_sha256,
        source_coordinate=source_coordinate,
        member_paths=tuple(paths),
    )


def summarize_candidate_scope(local_results: Mapping[str, str]) -> dict[str, Any]:
    """Aggregate bounded local checks without promoting them to global PASS."""

    if not isinstance(local_results, Mapping) or not local_results:
        _reject("LOCAL_RESULTS_INVALID", "local results must be a nonempty mapping")
    if any(type(name) is not str or not name for name in local_results):
        _reject("LOCAL_RESULTS_INVALID", "local result names must be nonempty text")
    if any(value not in {"PASS", "FAIL", "UNKNOWN"} for value in local_results.values()):
        _reject("LOCAL_RESULTS_INVALID", "local result values are unsupported")
    failures = sorted(name for name, value in local_results.items() if value == "FAIL")
    unknowns = sorted(name for name, value in local_results.items() if value == "UNKNOWN")
    if failures:
        bounded_status = "FAIL"
        status = "FAIL"
    elif unknowns:
        bounded_status = "UNKNOWN"
        status = "UNKNOWN"
    else:
        bounded_status = "PASS"
        status = "UNKNOWN"
    findings = ["REPOSITORY_COMPLETENESS_NOT_ESTABLISHED"]
    findings.extend(f"LOCAL_FAILURE:{name}" for name in failures)
    findings.extend(f"LOCAL_UNKNOWN:{name}" for name in unknowns)
    return {
        "status": status,
        "bounded_status": bounded_status,
        "repository_completeness": "UNKNOWN",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
        "findings": findings,
    }


__all__ = [
    "MemberObservation",
    "ScopeInputError",
    "SelectedSourceScope",
    "load_selected_source_scope",
    "summarize_candidate_scope",
]
