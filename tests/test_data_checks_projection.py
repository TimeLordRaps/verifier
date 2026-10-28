from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import data_checks, data_checks_projection


def _candidate(check: str) -> dict[str, object]:
    pin = data_checks_projection.accepted_projection(check)
    return {
        "check": check,
        "object_kind": "DATA",
        "tier": pin["tier"],
        "member_id": pin["member_id"],
        "scope": pin["scope"],
        "route_instance_id": pin["route_instance_id"],
        "union_ref_id": pin["union_ref_id"],
        "claim_text": data_checks.registration(check)["proposition"],
        "claim_sha256": pin["union_claim_digest"],
        "source": pin["source"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"],
        "row_index": pin["row_index"],
    }


def test_exactly_five_reviewed_data_projections_are_accepted() -> None:
    assert data_checks_projection.MAPPED_CHECKS == (
        "inventory", "schema", "lineage", "splits", "overlap"
    )
    assert data_checks_projection.ACCEPTANCE_MECHANISM_ID == (
        "verifier.domains.contracts.data_checks.recheck_data_checks_certificate"
    )
    for check in data_checks_projection.MAPPED_CHECKS:
        result = data_checks_projection.project_registration(
            check, data_checks.registration(check), _candidate(check)
        )
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["acceptance_mechanism"]["identifier"] == (
            data_checks_projection.ACCEPTANCE_MECHANISM_ID
        )
        assert result["relation"] == {
            "direction": "ROUTE_TO_UNION",
            "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
            "information_relation": "NARROWING_NON_REVERSIBLE",
            "semantic_equivalence_claimed": False,
            "digest_alias_claimed": False,
        }


def test_unreviewed_check_does_not_acquire_a_universal_mapping() -> None:
    with pytest.raises(data_checks_projection.DataChecksProjectionRefusal, match="outside"):
        data_checks_projection.accepted_projection("future_check")


def test_reverse_equivalence_is_refused() -> None:
    with pytest.raises(data_checks_projection.DataChecksProjectionRefusal, match="ROUTE_TO_UNION"):
        data_checks_projection.project_registration(
            "inventory", data_checks.registration("inventory"), _candidate("inventory"),
            direction="UNION_TO_ROUTE",
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("check", "schema"),
        ("object_kind", "OBJECT"),
        ("tier", 2),
        ("member_id", "DATA-1.3"),
        ("scope", "finite_retained_data_foreign"),
        ("route_instance_id", "route-instance:substituted"),
        ("union_ref_id", "union-candidate:substituted"),
        ("claim_sha256", "sha256:" + "0" * 64),
        ("source", {"uri": "producer-source://foreign", "sha256": "sha256:" + "0" * 64}),
        ("producer_source_coordinate_digest", "sha256:" + "0" * 64),
        ("candidate_input_digest", "sha256:" + "0" * 64),
        ("contribution_index", 99),
        ("row_index", 99),
        ("claim_text", "substituted proposition"),
    ],
)
def test_substituted_union_bindings_are_refused(field: str, replacement: object) -> None:
    candidate = copy.deepcopy(_candidate("inventory"))
    candidate[field] = replacement
    with pytest.raises(data_checks_projection.DataChecksProjectionRefusal):
        data_checks_projection.project_registration(
            "inventory", data_checks.registration("inventory"), candidate
        )


def test_substituted_native_registration_is_refused() -> None:
    registration = data_checks.registration("inventory")
    registration["proposition"] += " substituted"
    with pytest.raises(data_checks_projection.DataChecksProjectionRefusal, match="native registration"):
        data_checks_projection.project_registration("inventory", registration, _candidate("inventory"))


def test_selector_typo_is_rejected_and_actual_route_catalog_is_bound() -> None:
    assert data_checks_projection.REJECTED_ROUTE_CATALOG_SELECTOR_SHA256 != (
        data_checks_projection.ROUTE_CATALOG_SOURCE_SHA256
    )
    bindings = data_checks_projection.installed_source_bindings()
    assert bindings["route_catalog"]["sha256"] == (
        "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
    )
    assert bindings["data_checks"]["sha256"] == (
        "0e799306164671ced01e7a81007d712d52e8ecde8f1ecf024fb4181d58023e3e"
    )


def test_projection_grants_no_credit_and_preserves_remaining_accounting() -> None:
    result = data_checks_projection.project_registration(
        "overlap", data_checks.registration("overlap"), _candidate("overlap")
    )
    for field in (
        "evidence_credit", "authority_credit", "package_credit",
        "installed_mechanism_credit", "test_credit",
    ):
        assert result[field] == "NONE"
    assert result["dependency_binding_status"] == "UNKNOWN"
    assert result["current_evidence_status"] == "UNKNOWN"
    assert result["semantic_completeness"] == "UNKNOWN"
    assert result["release_admissible"] is False
    assert data_checks_projection.bounded_accounting()["remaining_after"] == 97


def test_sources_resolve_inside_successor_and_note_retains_boundaries() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(data_checks_projection.__file__).resolve() == (
        root / "src/verifier/domains/contracts/data_checks_projection.py"
    ).resolve()
    assert Path(data_checks.__file__).resolve() == (
        root / "src/verifier/domains/contracts/data_checks.py"
    ).resolve()
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_DATA_CHECK_PROJECTIONS.md")
        .read_text(encoding="utf-8")
        .split()
    )
    for phrase in (
        "one-way narrowing",
        "selector typo, not source drift",
        "97 rows remain unresolved",
        "No universal schema",
        "no evidence, authority, package, installed-mechanism, profile, completeness, or release credit",
    ):
        assert phrase in note
