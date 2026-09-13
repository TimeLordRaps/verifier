"""Experimental finite composition qualification for Verifier Standard (VSTD).

This local, read-only diagnostic binds original canonical JavaScript Object
Notation (JSON) bytes to both existing assessors. Secure Hash Algorithm 256-bit
(SHA-256) identifies retained bytes, not source correctness or runtime integrity.
It is not a portable replay receipt, source proof, general agency theorem or an
atomic filesystem snapshot. The nested finite check retains all its residuals.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Sequence

from . import authority_composition as finite
from .network import (
    COMMIT_SCHEMA, ContentAddressedStore, NetworkError, SiloCommit,
    _read_bounded_regular, assess_composition, digest_bytes,
)


QUALIFICATION_SCOPE = "EXACT_SELECTED_FINITE_ASYNCHRONOUS_INTERLEAVING"
CLAIM_BOUNDARY = (
    "Qualification requires both legacy bounded silo admission and the exact selected "
    "finite asynchronous-interleaving check. Existing assessments and their residuals "
    "remain unchanged. This diagnostic is not a portable replay receipt, source proof, "
    "runtime/model correspondence, general composed agency, execution authorization, "
    "or an atomic filesystem snapshot."
)


def qualify_silo_composition(
    declaration_path: str | Path,
    members: Sequence[tuple[str | Path, str | Path]],
    composite_store: str | Path,
    composite_commit: str | Path,
) -> dict[str, Any]:
    """Read selected local bytes and recompute two distinct bounded assessments.

    Each member pair is (store root, commit path). The finite record and member
    bounds apply before decoding or model reads. Missing or refused inputs are
    not invented; present substitutions are retained for native rejection.
    """
    report: dict[str, Any] = {
        "qualification_scope": QUALIFICATION_SCOPE,
        "qualification": "NOT_QUALIFIED",
        "selection_binding": "UNKNOWN",
        "coordinates": {"members": [], "composite": None},
        "declaration_digest": None,
        "legacy_assessment": None,
        "finite_assessment": None,
        "reason_codes": [],
        "claim_boundary": CLAIM_BOUNDARY,
    }
    reasons: set[str] = set()
    evidence: dict[str, bytes] = {}
    try:
        declaration_bytes = _read_bounded_regular(
            declaration_path, finite.MAX_RECORD_BYTES, "finite composition declaration",
        )
    except NetworkError:
        report["reason_codes"] = ["DECLARATION_UNAVAILABLE_OR_LIMITED"]
        return report
    report["declaration_digest"] = digest_bytes(declaration_bytes)
    try:
        declaration = finite._declaration(declaration_bytes)
    except (finite.AuthorityCompositionLimit, finite.UnsupportedAuthorityComposition):
        report["finite_assessment"] = finite.assess_authority_composition(declaration_bytes, evidence)
        report["reason_codes"] = ["DECLARATION_UNSUPPORTED_OR_LIMITED"]
        return report
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        report["selection_binding"] = "INVALID"
        report["finite_assessment"] = finite.assess_authority_composition(declaration_bytes, evidence)
        report["reason_codes"] = ["DECLARATION_INVALID"]
        return report
    if len(members) > finite.MAX_MEMBERS:
        report["finite_assessment"] = finite.assess_authority_composition(declaration_bytes, evidence)
        report["reason_codes"] = ["SELECTED_MEMBER_LIMIT"]
        return report
    if len(members) < finite.MIN_MEMBERS or len(members) != len(declaration["members"]):
        report["selection_binding"] = "INVALID"
        report["finite_assessment"] = finite.assess_authority_composition(declaration_bytes, evidence)
        report["reason_codes"] = ["SELECTED_MEMBER_COUNT_INVALID"]
        return report

    invalid = False
    unavailable = False
    commits: list[SiloCommit | None] = []
    stores: list[ContentAddressedStore] = []
    captured: dict[str, bytes | None] = {}
    for index, (store_path, commit_path) in enumerate((*members, (composite_store, composite_commit))):
        store = ContentAddressedStore(store_path)
        stores.append(store)
        key = os.path.normcase(os.path.abspath(commit_path))
        if key not in captured:
            try:
                captured[key] = _read_bounded_regular(commit_path, finite.MAX_RECORD_BYTES, "selected commit")
            except NetworkError:
                captured[key] = None
        raw = captured[key]
        commit = None
        if raw is None:
            unavailable = True
            reasons.add("SELECTED_COMMIT_UNAVAILABLE_OR_LIMITED")
        else:
            digest = digest_bytes(raw)
            if index == len(members):
                report["coordinates"]["composite"] = digest
            else:
                report["coordinates"]["members"].append(digest)
            evidence[digest] = raw
            try:
                commit = SiloCommit.from_dict(finite._decode(raw, COMMIT_SCHEMA))
            except (finite.AuthorityCompositionLimit, finite.UnsupportedAuthorityComposition):
                unavailable = True
                reasons.add("SELECTED_COMMIT_UNSUPPORTED_OR_LIMITED")
            except (ValueError, TypeError, KeyError, AttributeError, IndexError):
                invalid = True
                reasons.add("SELECTED_COMMIT_INVALID")
        commits.append(commit)
        if commit is None or commit.authority_model_path is None:
            continue
        model_record = next(entry.object_record for entry in commit.census if entry.path == commit.authority_model_path)
        try:
            payload = _read_bounded_regular(
                store._object_path(model_record.object_digest), finite.MAX_RECORD_BYTES,
                "selected authority model",
            )
        except NetworkError:
            reasons.add("SELECTED_MODEL_UNAVAILABLE_OR_LIMITED")
            continue
        previous = evidence.get(model_record.object_digest)
        if previous is not None and previous != payload:
            invalid = True
            reasons.add("CONFLICTING_SELECTED_BYTES")
            # Keep an observed bad binding, not whichever store was read last.
            if digest_bytes(previous) != model_record.object_digest:
                continue
        evidence[model_record.object_digest] = payload

    selected = sorted(report["coordinates"]["members"])
    report["coordinates"]["members"] = selected
    expected = [item["commit_digest"] for item in declaration["members"]]
    actual_composite = report["coordinates"]["composite"]
    if (
        len(selected) != len(set(selected))
        or not set(selected) <= set(expected)
        or (not unavailable and selected != expected)
        or (actual_composite is not None and actual_composite != declaration["composite"]["commit_digest"])
        or actual_composite in selected
    ):
        invalid = True
        reasons.add("COMPOSITION_SELECTION_MISMATCH")
    report["selection_binding"] = "INVALID" if invalid else "UNKNOWN" if unavailable else "BOUND"
    report["finite_assessment"] = finite.assess_authority_composition(declaration_bytes, evidence)
    if all(commit is not None for commit in commits) and members:
        try:
            report["legacy_assessment"] = assess_composition(
                commits[:-1], stores[:-1], commits[-1], stores[-1],
            )
        except NetworkError:
            reasons.add("LEGACY_ASSESSMENT_UNAVAILABLE")
    legacy = report["legacy_assessment"]
    checked = report["finite_assessment"]
    if legacy is None or legacy["result"] != "ADMISSIBLE":
        reasons.add("LEGACY_ADMISSION_NOT_ESTABLISHED")
    if not (
        checked["coordinate_binding"] == "BOUND"
        and checked["transition_correspondence"] == "MATCHED"
        and checked["agency_preservation"] == "PRESERVED"
        and checked["local_addition_preservation"] == "PRESERVED"
    ):
        reasons.add("FINITE_COMPOSITION_NOT_ESTABLISHED")
    if report["selection_binding"] == "BOUND" and not {
        "LEGACY_ADMISSION_NOT_ESTABLISHED", "FINITE_COMPOSITION_NOT_ESTABLISHED",
    } & reasons:
        report["qualification"] = "FINITE_COMPOSITION_QUALIFIED"
    report["reason_codes"] = sorted(reasons)
    return report
