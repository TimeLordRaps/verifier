"""Replay independent authority for one self-polish estate selection.

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
digests bind the exact source, candidate census, applicability ledger, installed
inventory, objective catalog, and structural/route crosswalk.  This adapter uses
the existing configured-key application-scope authority mechanism.  Authority
for the selected estate is not semantic applicability, per-candidate evidence,
whole-estate closure, polished status, or release authority.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from verifier.runtime import core_application_authority


SUBJECT_SCHEMA = "verifier-self-polish-estate-authority-subject-2"
RESULT_SCHEMA = "verifier-self-polish-estate-authority-replay-2"
OPERATION = core_application_authority.SCOPE_OPERATION
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SUBJECT_DIGEST_FIELDS = (
    "adapter_mechanism_digest",
    "source_coordinate_digest",
    "estate_source_coordinate_digest",
    "candidate_source_census_digest",
    "estate_digest",
    "candidate_universe_digest",
    "required_categories_digest",
    "category_summaries_digest",
    "applicability_ledger_digest",
    "installed_inventory_digest",
    "objective_catalog_digest",
    "structural_route_crosswalk_digest",
    "structural_identity_digest",
    "route_identity_digest",
    "shared_identity_digest",
)
_DEFINITE_UNKNOWN_REFUTATIONS = {
    "AUTHORITY_STATUS_NOT_CURRENT",
    "AUTHORITY_QUORUM_NOT_ESTABLISHED",
    "AUTHORITY_EXECUTION_NOT_COMPLETED",
    "AUTHORITY_EVIDENCE_NOT_CURRENT",
}
_BOUNDARY = (
    "PASS establishes only replayed configured-key authority over the exact "
    "source-bound estate selection. It does not authenticate caller applicability "
    "labels, supply per-candidate evidence, close the repository/package estate, "
    "establish Tier 1, mark the subject polished, or authorize release."
)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _hash(value: Any, code: str) -> str:
    _require(type(value) is str and _SHA256.fullmatch(value) is not None, code)
    return value


def mechanism_digest() -> str:
    """Bind this adapter and the delegated configured-key replay mechanism."""
    return core_application_authority.value_digest({
        "schema_version": "verifier-self-polish-estate-authority-mechanism-2",
        "adapter": core_application_authority.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "qualified_authority": (
            core_application_authority.qualified_authority_mechanism_digest(
                OPERATION
            )
        ),
    })


def estate_authority_subject(*, source_coordinate_digest: str,
        estate_source_coordinate_digest: str,
        candidate_source_census_digest: str, estate_digest: str,
        candidate_universe_digest: str, required_categories_digest: str,
        category_summaries_digest: str, applicability_ledger_digest: str,
        installed_inventory_digest: str, objective_catalog_digest: str,
        structural_route_crosswalk_digest: str,
        structural_identity_digest: str, route_identity_digest: str,
        shared_identity_digest: str) -> dict[str, Any]:
    """Construct the exact estate selection admitted by an external authority."""
    values = {
        "adapter_mechanism_digest": mechanism_digest(),
        "source_coordinate_digest": source_coordinate_digest,
        "estate_source_coordinate_digest": estate_source_coordinate_digest,
        "candidate_source_census_digest": candidate_source_census_digest,
        "estate_digest": estate_digest,
        "candidate_universe_digest": candidate_universe_digest,
        "required_categories_digest": required_categories_digest,
        "category_summaries_digest": category_summaries_digest,
        "applicability_ledger_digest": applicability_ledger_digest,
        "installed_inventory_digest": installed_inventory_digest,
        "objective_catalog_digest": objective_catalog_digest,
        "structural_route_crosswalk_digest": (
            structural_route_crosswalk_digest
        ),
        "structural_identity_digest": structural_identity_digest,
        "route_identity_digest": route_identity_digest,
        "shared_identity_digest": shared_identity_digest,
    }
    for name, value in values.items():
        _hash(value, "ESTATE_AUTHORITY_" + name.upper() + "_INVALID")
    return {
        "schema_version": SUBJECT_SCHEMA,
        "operation": OPERATION,
        **values,
    }


def _validated_subject(subject: Any) -> dict[str, Any]:
    required = {"schema_version", "operation", *_SUBJECT_DIGEST_FIELDS}
    _require(type(subject) is dict and set(subject) == required,
             "ESTATE_AUTHORITY_SUBJECT_FIELDS_DIFFER")
    _require(subject["schema_version"] == SUBJECT_SCHEMA
             and subject["operation"] == OPERATION,
             "ESTATE_AUTHORITY_SUBJECT_VERSION_OR_OPERATION_DIFFERS")
    for name in _SUBJECT_DIGEST_FIELDS:
        _hash(subject[name], "ESTATE_AUTHORITY_SUBJECT_DIGEST_INVALID")
    _require(subject["adapter_mechanism_digest"] == mechanism_digest(),
             "ESTATE_AUTHORITY_ADAPTER_MECHANISM_DIFFERS")
    return subject


def replay_estate_authority(subject: dict[str, Any], *,
        authority_replay: (
            core_application_authority.QualifiedAuthorityReplaySelection | None
        )) -> dict[str, Any]:
    """Replay authority without widening it into semantic or evidence closure."""
    report: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA,
        "status": "UNKNOWN",
        "independent_authority_status": "NOT_ESTABLISHED",
        "replay_status": "NOT_ESTABLISHED",
        "subject_digest": None,
        "policy_digest": None,
        "receipt_digest": None,
        "approving_actors": [],
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "per_candidate_evidence_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "blockers": [],
        "claim_boundary": _BOUNDARY,
    }
    try:
        selected = _validated_subject(subject)
        subject_digest = core_application_authority.value_digest(selected)
        report["subject_digest"] = subject_digest
        if authority_replay is None:
            report["blockers"].append("ESTATE_AUTHORITY_RECEIPT_UNAVAILABLE")
        else:
            replay = core_application_authority.replay_qualified_authority_receipt(
                authority_replay,
                required_operation=OPERATION,
                required_subject_digest=subject_digest,
            )
            report.update(
                replay_status=replay["replay_status"],
                policy_digest=replay["policy_digest"],
                receipt_digest=replay["receipt_digest"],
                approving_actors=replay["approving_actors"],
            )
            replay_blockers = list(replay["blockers"])
            report["blockers"].extend(replay_blockers)
            if replay["status"] == "PASS":
                report.update(
                    status="PASS",
                    independent_authority_status="PASS",
                )
            elif replay["status"] == "FAIL" \
                    or any(code in _DEFINITE_UNKNOWN_REFUTATIONS
                           for code in replay_blockers):
                report.update(
                    status="FAIL",
                    independent_authority_status="FAIL",
                    replay_status="REJECTED",
                )
    except (KeyError, TypeError, ValueError, UnicodeError):
        report.update(
            status="FAIL",
            independent_authority_status="FAIL",
            replay_status="REJECTED",
        )
        report["blockers"].append("ESTATE_AUTHORITY_SUBJECT_REJECTED")
    report["blockers"] = sorted(set(report["blockers"]))
    report["result_digest"] = core_application_authority.value_digest(report)
    return report


__all__ = [
    "OPERATION", "RESULT_SCHEMA", "SUBJECT_SCHEMA", "estate_authority_subject",
    "mechanism_digest", "replay_estate_authority",
]
