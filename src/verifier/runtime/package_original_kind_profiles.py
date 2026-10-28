"""Source-owned profiles for original Verifier Standard (VSTD) kind review.

The 25 original non-``OBJECT`` roots are independent applicability questions.
This module deliberately provides no complement rule: an omitted question is
unresolved, not evidence that the kind does not apply.  A repository-specific
catalog must list every affirmative and negative decision literally, bind the
exact object identifier, primary kind, owned-path set, object scope, profile
revision, and canonical profile digest, and survive full-closure validation
before it can close the current 468-object denominator.

The data model is reusable so feature-near review partitions can be authored
and audited independently.  It does not itself decide outstanding cross-root
questions and therefore cannot establish package admission.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from typing import Any, Iterable, Mapping

from verifier.core.namespace import ObjectKind


ORIGINAL_NON_OBJECT_KINDS = (
    "ACTOR",
    "AGENT",
    "ARCH",
    "BENCH",
    "BOT",
    "COLLECTIVE",
    "DATA",
    "ENV",
    "EVENT",
    "GRAPH",
    "HARDWARE",
    "HARNESS",
    "HUMAN",
    "HYPER",
    "IDENTITY",
    "MODEL",
    "OWNER",
    "RECEIPT",
    "ROLE",
    "SIM",
    "SPACE",
    "TIME",
    "TOKEN",
    "TRAIN",
    "VERIFIER",
)

# The central denominator is the disjoint sum of eight source-owned catalog
# partitions.  Its exact equation and the four additions since 464 are pinned in
# tests/test_package_original_kind_catalog.py; this number is not an estimate.
VERIFIER_PACKAGE_OBJECT_DENOMINATOR = 468
PROFILE_SCHEMA = "verifier-package-original-kind-profile-1"
APPLIES = "APPLIES"
DOES_NOT_APPLY = "DOES_NOT_APPLY"
_STATUSES = frozenset((APPLIES, DOES_NOT_APPLY))

if ORIGINAL_NON_OBJECT_KINDS != tuple(
    sorted(kind.value for kind in ObjectKind if kind is not ObjectKind.OBJECT)
):
    raise AssertionError("original non-OBJECT kind denominator drifted")


@dataclass(frozen=True)
class OriginalKindDecision:
    """One explicit audited decision; no absent kind is synthesized.

    ``evidence_paths`` is an optional positive-witness subset of the
    assignment's exact owned-path denominator.  An empty tuple retains the
    historical closed-denominator behavior.  A DOES_NOT_APPLY decision may
    never narrow its evidence: refutation remains a claim over every reviewed
    owned path.
    """

    kind: str
    status: str
    reason: str
    evidence_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class OriginalKindAssignment:
    """The exact source and semantic coordinate reviewed for one object."""

    object_id: str
    expected_primary: str
    expected_owned_paths: tuple[str, ...]
    expected_owned_path_set_digest: str
    scope_reason: str
    decisions: tuple[OriginalKindDecision, ...]


@dataclass(frozen=True)
class OriginalKindProfile:
    """A revisioned collection whose digest binds every literal assignment."""

    profile_id: str
    revision: int
    claim_boundary: str
    assignments: tuple[OriginalKindAssignment, ...]
    canonical_digest: str


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical_bytes(value)).hexdigest()


def _bounded_text(value: Any, code: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 16384:
        raise ValueError(code)
    return value


def _portable_path(value: Any) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_PATH_INVALID")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or re.match(r"^[A-Za-z]:", path.parts[0])
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_PATH_INVALID")
    return value


def owned_path_set_digest(paths: Iterable[str]) -> str:
    """Digest one already-audited sorted path set without discovering paths."""
    selected = tuple(paths)
    if (
        not selected
        or selected != tuple(sorted(set(selected)))
        or any(_portable_path(path) != path for path in selected)
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_PATHS_INVALID")
    return _digest({"owned_paths": list(selected)})


def _decision_document(decision: OriginalKindDecision) -> dict[str, Any]:
    document: dict[str, Any] = {
        "kind": decision.kind,
        "status": decision.status,
        "reason": decision.reason,
    }
    if decision.evidence_paths:
        document["evidence_paths"] = list(decision.evidence_paths)
    return document


def _assignment_document(assignment: OriginalKindAssignment) -> dict[str, Any]:
    return {
        "object_id": assignment.object_id,
        "expected_primary": assignment.expected_primary,
        "expected_owned_paths": list(assignment.expected_owned_paths),
        "expected_owned_path_set_digest": assignment.expected_owned_path_set_digest,
        "scope_reason": assignment.scope_reason,
        "decisions": [
            _decision_document(decision) for decision in assignment.decisions
        ],
    }


def _profile_payload(
    profile_id: str,
    revision: int,
    claim_boundary: str,
    assignments: tuple[OriginalKindAssignment, ...],
) -> dict[str, Any]:
    return {
        "schema_version": PROFILE_SCHEMA,
        "profile_id": profile_id,
        "revision": revision,
        "claim_boundary": claim_boundary,
        "assignments": [
            _assignment_document(assignment) for assignment in assignments
        ],
    }


def profile_digest(profile: OriginalKindProfile) -> str:
    """Recompute the digest; the carried digest is never self-authorizing."""
    if type(profile) is not OriginalKindProfile:
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_INVALID")
    return _digest(
        _profile_payload(
            profile.profile_id,
            profile.revision,
            profile.claim_boundary,
            profile.assignments,
        )
    )


def validate_profile(profile: OriginalKindProfile) -> OriginalKindProfile:
    """Validate explicit assignments without filling any omitted decision."""
    if type(profile) is not OriginalKindProfile:
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_INVALID")
    if re.fullmatch(r"[a-z][a-z0-9-]{2,95}", profile.profile_id) is None:
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_ID_INVALID")
    if type(profile.revision) is not int or profile.revision < 1:
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_REVISION_INVALID")
    _bounded_text(
        profile.claim_boundary,
        "PACKAGE_ORIGINAL_KIND_PROFILE_CLAIM_BOUNDARY_INVALID",
    )
    if (
        type(profile.assignments) is not tuple
        or not profile.assignments
        or any(
            type(assignment) is not OriginalKindAssignment
            for assignment in profile.assignments
        )
        or tuple(sorted(profile.assignments, key=lambda row: row.object_id))
        != profile.assignments
        or len({row.object_id for row in profile.assignments})
        != len(profile.assignments)
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_ASSIGNMENTS_INVALID")
    for assignment in profile.assignments:
        if re.fullmatch(r"[a-z][a-z0-9-]{2,95}", assignment.object_id) is None:
            raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_OBJECT_ID_INVALID")
        if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", assignment.expected_primary) is None:
            raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_PRIMARY_INVALID")
        if (
            type(assignment.expected_owned_paths) is not tuple
            or owned_path_set_digest(assignment.expected_owned_paths)
            != assignment.expected_owned_path_set_digest
        ):
            raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_OWNERSHIP_DIGEST_INVALID")
        _bounded_text(
            assignment.scope_reason,
            "PACKAGE_ORIGINAL_KIND_PROFILE_SCOPE_REASON_INVALID",
        )
        if (
            type(assignment.decisions) is not tuple
            or not assignment.decisions
            or any(
                type(decision) is not OriginalKindDecision
                for decision in assignment.decisions
            )
            or tuple(sorted(assignment.decisions, key=lambda row: row.kind))
            != assignment.decisions
            or len({row.kind for row in assignment.decisions})
            != len(assignment.decisions)
        ):
            raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_DECISIONS_INVALID")
        for decision in assignment.decisions:
            if decision.kind not in ORIGINAL_NON_OBJECT_KINDS:
                raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_KIND_INVALID")
            if decision.status not in _STATUSES:
                raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_STATUS_INVALID")
            _bounded_text(
                decision.reason,
                "PACKAGE_ORIGINAL_KIND_PROFILE_DECISION_REASON_INVALID",
            )
            if (
                type(decision.evidence_paths) is not tuple
                or decision.evidence_paths
                != tuple(sorted(set(decision.evidence_paths)))
                or any(
                    _portable_path(path) != path
                    for path in decision.evidence_paths
                )
                or not set(decision.evidence_paths)
                <= set(assignment.expected_owned_paths)
            ):
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_PROFILE_DECISION_EVIDENCE_INVALID"
                )
            if (
                decision.status == DOES_NOT_APPLY
                and decision.evidence_paths
                and decision.evidence_paths != assignment.expected_owned_paths
            ):
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_PROFILE_REFUTATION_EVIDENCE_INCOMPLETE"
                )
    if profile.canonical_digest != profile_digest(profile):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_DIGEST_INVALID")
    return profile


def seal_profile(
    profile_id: str,
    revision: int,
    claim_boundary: str,
    assignments: Iterable[OriginalKindAssignment],
) -> OriginalKindProfile:
    """Seal explicit review data; sealing does not make its decisions true."""
    selected = tuple(assignments)
    if not selected or any(
        type(assignment) is not OriginalKindAssignment for assignment in selected
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_ASSIGNMENT_INVALID")
    digest = _digest(_profile_payload(profile_id, revision, claim_boundary, selected))
    return validate_profile(
        OriginalKindProfile(
            profile_id=profile_id,
            revision=revision,
            claim_boundary=claim_boundary,
            assignments=selected,
            canonical_digest=digest,
        )
    )


def validate_full_closure(
    profile: OriginalKindProfile,
    expected_object_ids: Iterable[str],
    *,
    expected_object_count: int = VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
) -> OriginalKindProfile:
    """Require the literal 25-by-object matrix; never compute its complement."""
    selected = validate_profile(profile)
    expected = tuple(expected_object_ids)
    if (
        type(expected_object_count) is not int
        or expected_object_count < 1
        or any(type(object_id) is not str for object_id in expected)
        or len(expected) != expected_object_count
        or expected != tuple(sorted(set(expected)))
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_EXPECTED_OBJECTS_INVALID")
    assignments = {row.object_id: row for row in selected.assignments}
    if set(assignments) != set(expected):
        raise ValueError("PACKAGE_ORIGINAL_KIND_PROFILE_OBJECT_DENOMINATOR_INCOMPLETE")
    required = set(ORIGINAL_NON_OBJECT_KINDS)
    for object_id in expected:
        assignment = assignments[object_id]
        decisions = {row.kind: row for row in assignment.decisions}
        if set(decisions) != required:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_PROFILE_KIND_DENOMINATOR_INCOMPLETE:"
                + object_id
            )
        if (
            assignment.expected_primary in required
            and decisions[assignment.expected_primary].status != APPLIES
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_PROFILE_PRIMARY_REFUTED:" + object_id
            )
    return selected


def profile_document(profile: OriginalKindProfile) -> dict[str, Any]:
    """Return deterministic inspectable data after validating its own digest."""
    selected = validate_profile(profile)
    return {
        **_profile_payload(
            selected.profile_id,
            selected.revision,
            selected.claim_boundary,
            selected.assignments,
        ),
        "canonical_digest": selected.canonical_digest,
    }


__all__ = [
    "APPLIES",
    "DOES_NOT_APPLY",
    "ORIGINAL_NON_OBJECT_KINDS",
    "OriginalKindAssignment",
    "OriginalKindDecision",
    "OriginalKindProfile",
    "PROFILE_SCHEMA",
    "VERIFIER_PACKAGE_OBJECT_DENOMINATOR",
    "owned_path_set_digest",
    "profile_digest",
    "profile_document",
    "seal_profile",
    "validate_full_closure",
    "validate_profile",
]
