from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import independence_checks, independence_projection


def _candidate(kind: str) -> dict[str, object]:
    pin = independence_projection.accepted_projection(kind)
    return {
        "object_kind": kind,
        "member_id": pin["member_id"],
        "union_ref_id": pin["union_ref_id"],
        "claim_text": independence_checks.registration(kind)["proposition"],
        "claim_sha256": pin["union_claim_digest"],
        "contribution_index": pin["contribution_index"],
        "row_index": pin["row_index"],
        "source": pin["source"],
    }


def test_exactly_fifteen_reviewed_one_way_projections_are_accepted() -> None:
    assert len(independence_projection.MAPPED_KINDS) == 15
    for kind in independence_projection.MAPPED_KINDS:
        result = independence_projection.project_registration(
            kind, independence_checks.registration(kind), _candidate(kind)
        )
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["relation"] == {
            "direction": "ROUTE_TO_UNION",
            "operation": "EXTRACT_EXACT_PROPOSITION_FIELD_AS_UTF8",
            "information_relation": "NARROWING_NON_REVERSIBLE",
            "semantic_equivalence_claimed": False,
            "digest_alias_claimed": False,
        }
        assert result["release_admissible"] is False


def test_rejected_kinds_and_missing_harness_remain_fail_closed() -> None:
    assert len(independence_projection.REJECTED_KINDS) == 9
    for kind in independence_projection.REJECTED_KINDS:
        with pytest.raises(independence_projection.ProjectionRefusal, match="rejected"):
            independence_projection.accepted_projection(kind)
    with pytest.raises(independence_projection.ProjectionRefusal, match="UNKNOWN"):
        independence_projection.accepted_projection("HARNESS")


def test_reverse_equivalence_and_unreviewed_kind_are_not_admitted() -> None:
    kind = "ACTOR"
    with pytest.raises(independence_projection.ProjectionRefusal, match="ROUTE_TO_UNION"):
        independence_projection.project_registration(
            kind, independence_checks.registration(kind), _candidate(kind),
            direction="UNION_TO_ROUTE",
        )
    with pytest.raises(independence_projection.ProjectionRefusal, match="outside"):
        independence_projection.accepted_projection("SIM")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("member_id", "ACTOR-5.2"),
        ("union_ref_id", "union-candidate:substituted"),
        ("claim_sha256", "sha256:" + "0" * 64),
        ("contribution_index", 8),
        ("row_index", 5),
        ("source", {"uri": "producer-source://foreign", "sha256": "0" * 64}),
        ("claim_text", "substituted proposition"),
    ],
)
def test_substituted_union_bindings_are_refused(field: str, replacement: object) -> None:
    kind = "ACTOR"
    candidate = copy.deepcopy(_candidate(kind))
    candidate[field] = replacement
    with pytest.raises(independence_projection.ProjectionRefusal):
        independence_projection.project_registration(
            kind, independence_checks.registration(kind), candidate
        )


def test_substituted_native_registration_is_refused() -> None:
    kind = "ACTOR"
    registration = independence_checks.registration(kind)
    registration["proposition"] += " substituted"
    with pytest.raises(independence_projection.ProjectionRefusal, match="native registration"):
        independence_projection.project_registration(kind, registration, _candidate(kind))


def test_projection_grants_no_evidence_completeness_authority_or_package_credit() -> None:
    result = independence_projection.project_registration(
        "ACTOR", independence_checks.registration("ACTOR"), _candidate("ACTOR")
    )
    for field in ("evidence_credit", "completeness_credit", "authority_credit", "package_credit"):
        assert result[field] == "NONE"
    assert result["current_evidence_status"] == "UNKNOWN"
    assert result["semantic_completeness"] == "UNKNOWN"
    assert independence_projection.bounded_accounting() == {
        "non_sim_current_tier5_positions": 25,
        "mapped": 15,
        "rejected": 9,
        "missing_unknown": 1,
        "missing_kind": "HARNESS",
        "reconciled_in_140": 15,
        "unresolved_in_140": 125,
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def test_sources_resolve_inside_successor_and_note_retains_exclusions() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(independence_projection.__file__).resolve() == (
        root / "src/verifier/domains/contracts/independence_projection.py"
    ).resolve()
    assert Path(independence_checks.__file__).resolve() == (
        root / "src/verifier/domains/contracts/independence_checks.py"
    ).resolve()
    assert independence_projection.installed_route_source_binding()["sha256"] == (
        independence_projection.ROUTE_SOURCE_SHA256
    )
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_INDEPENDENCE_PROJECTIONS.md")
        .read_text(encoding="utf-8")
        .split()
    )
    for phrase in (
        "one-way narrowing",
        "125 of 140 remain unresolved",
        "HARNESS remains UNKNOWN",
        "no evidence, completeness, authority, package, profile, or release credit",
        "106 route-only",
        "93 membership-only",
    ):
        assert phrase in note
