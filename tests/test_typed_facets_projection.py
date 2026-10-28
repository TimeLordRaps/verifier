from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import typed_facets, typed_facets_projection


def _candidate(kind: str) -> dict[str, object]:
    pin = typed_facets_projection.accepted_projection(kind)
    return {
        "object_kind": kind,
        "member_id": pin["member_id"],
        "route_instance_id": pin["route_instance_id"],
        "union_ref_id": pin["union_ref_id"],
        "claim_text": typed_facets.registration(kind)["proposition"],
        "claim_sha256": pin["union_claim_digest"],
        "source": pin["source"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"],
        "row_index": pin["row_index"],
    }


def test_exactly_sixteen_reviewed_typed_facet_projections_are_accepted() -> None:
    assert len(typed_facets_projection.MAPPED_KINDS) == 16
    assert typed_facets_projection.ACCEPTANCE_MECHANISM_ID == (
        "verifier.domains.contracts.typed_facets.recheck_typed_facets_certificate"
    )
    for kind in typed_facets_projection.MAPPED_KINDS:
        result = typed_facets_projection.project_registration(
            kind, typed_facets.registration(kind), _candidate(kind)
        )
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["acceptance_mechanism"]["identifier"] == (
            typed_facets_projection.ACCEPTANCE_MECHANISM_ID
        )
        assert result["relation"] == {
            "direction": "ROUTE_TO_UNION",
            "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
            "information_relation": "NARROWING_NON_REVERSIBLE",
            "semantic_equivalence_claimed": False,
            "digest_alias_claimed": False,
        }


def test_unmapped_kinds_do_not_acquire_a_universal_mapping() -> None:
    assert len(typed_facets_projection.UNMAPPED_KINDS) == 10
    for kind in typed_facets_projection.UNMAPPED_KINDS:
        with pytest.raises(typed_facets_projection.TypedFacetsProjectionRefusal, match="outside"):
            typed_facets_projection.accepted_projection(kind)


def test_reverse_equivalence_is_refused() -> None:
    kind = "ACTOR"
    with pytest.raises(typed_facets_projection.TypedFacetsProjectionRefusal, match="ROUTE_TO_UNION"):
        typed_facets_projection.project_registration(
            kind, typed_facets.registration(kind), _candidate(kind), direction="UNION_TO_ROUTE"
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("member_id", "ACTOR-1.2"),
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
    candidate = copy.deepcopy(_candidate("ACTOR"))
    candidate[field] = replacement
    with pytest.raises(typed_facets_projection.TypedFacetsProjectionRefusal):
        typed_facets_projection.project_registration(
            "ACTOR", typed_facets.registration("ACTOR"), candidate
        )


def test_substituted_native_registration_is_refused() -> None:
    registration = typed_facets.registration("ACTOR")
    registration["proposition"] += " substituted"
    with pytest.raises(typed_facets_projection.TypedFacetsProjectionRefusal, match="native registration"):
        typed_facets_projection.project_registration("ACTOR", registration, _candidate("ACTOR"))


def test_selector_typo_is_rejected_and_actual_route_catalog_is_bound() -> None:
    assert typed_facets_projection.REJECTED_ROUTE_CATALOG_SELECTOR_SHA256 == (
        "1daa659a375fb21de867f1e8b7930d3fbba37dceac93821255358b1fc079ca53"
    )
    assert typed_facets_projection.REJECTED_ROUTE_CATALOG_SELECTOR_SHA256 != (
        typed_facets_projection.ROUTE_CATALOG_SOURCE_SHA256
    )
    bindings = typed_facets_projection.installed_source_bindings()
    assert bindings["route_catalog"]["sha256"] == (
        "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
    )


def test_projection_grants_no_credit_and_preserves_remaining_accounting() -> None:
    result = typed_facets_projection.project_registration(
        "OBJECT", typed_facets.registration("OBJECT"), _candidate("OBJECT")
    )
    assert result["member_id"] == "OBJECT-1.2"
    for field in (
        "evidence_credit", "authority_credit", "package_credit",
        "installed_mechanism_credit", "test_credit",
    ):
        assert result[field] == "NONE"
    assert result["dependency_binding_status"] == "UNKNOWN"
    assert result["current_evidence_status"] == "UNKNOWN"
    assert result["semantic_completeness"] == "UNKNOWN"
    assert result["release_admissible"] is False
    assert typed_facets_projection.bounded_accounting()["remaining_after"] == 102


def test_sources_resolve_inside_successor_and_note_retains_boundaries() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(typed_facets_projection.__file__).resolve() == (
        root / "src/verifier/domains/contracts/typed_facets_projection.py"
    ).resolve()
    assert Path(typed_facets.__file__).resolve() == (
        root / "src/verifier/domains/contracts/typed_facets.py"
    ).resolve()
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_TYPED_FACET_PROJECTIONS.md")
        .read_text(encoding="utf-8")
        .split()
    )
    for phrase in (
        "one-way narrowing",
        "selector typo, not source drift",
        "102 rows remain unresolved",
        "No universal mapping",
        "no evidence, authority, package, installed-mechanism, profile, completeness, or release credit",
    ):
        assert phrase in note
