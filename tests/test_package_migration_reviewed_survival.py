"""A reviewed answer may leave a regenerated row only as a recorded gap."""

from __future__ import annotations

import pytest

from verifier.runtime import package_manifest_migration as migration


def _binding(reason: str = "", declaration: dict | None = None) -> dict:
    return {"reason": reason, "evidence": [], "declaration": declaration or {}}


def _row(obligations: dict, kinds=("LEDGER", "PROTOCOL")) -> dict:
    return {
        "classification": {kind: {"status": "UNRESOLVED"} for kind in kinds},
        "obligations": obligations,
    }


def test_nothing_is_dropped_so_nothing_is_reported():
    prior = _row({"PROTOCOL-0.1-participants": _binding("Reviewed.")})
    current = _row({"PROTOCOL-0.1-participants": _binding("Reviewed.")})
    gaps: list = []
    migration._require_reviewed_answers_survive(
        "vstd-example", prior, current, record=False, gaps=gaps
    )
    assert gaps == []


def test_strict_mode_refuses_a_dropped_reviewed_obligation():
    prior = _row({"PROTOCOL-0.1-participants": _binding("Reviewed.")})
    current = _row({})
    with pytest.raises(
        ValueError, match="PACKAGE_MIGRATION_REVIEWED_OBLIGATION_DROPPED:vstd-example"
    ):
        migration._require_reviewed_answers_survive(
            "vstd-example", prior, current, record=False, gaps=[]
        )


def test_strict_mode_refuses_a_dropped_classification_question():
    prior = _row({}, kinds=("LEDGER", "PROTOCOL"))
    current = _row({}, kinds=("LEDGER",))
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_REVIEWED_CLASSIFICATION_DROPPED:vstd-example",
    ):
        migration._require_reviewed_answers_survive(
            "vstd-example", prior, current, record=True, gaps=[]
        )


def test_record_mode_reports_every_dropped_reviewed_obligation_and_continues():
    prior = _row(
        {
            "PROTOCOL-0.2-ordering": _binding(declaration={"ordering": "Authored."}),
            "PROTOCOL-0.1-participants": _binding("Reviewed."),
            "PROTOCOL-0.3-blank": _binding(),
        }
    )
    current = _row({"PROTOCOL-0.3-blank": _binding()})
    gaps: list = []

    migration._require_reviewed_answers_survive(
        "vstd-example", prior, current, record=True, gaps=gaps
    )

    assert gaps == [
        {
            "stage": "review_refresh",
            "object_id": "vstd-example",
            "gap": "REVIEWED_OBLIGATIONS_DROPPED",
            "obligations": ["PROTOCOL-0.1-participants", "PROTOCOL-0.2-ordering"],
        }
    ]


def test_gap_summary_counts_each_gap_kind_and_keeps_every_item():
    gaps = [
        {"gap": "STALE_SPECIALIZATION_LABEL", "object_id": "a"},
        {"gap": "UNREVIEWED_OWNED_PATHS", "object_id": "b"},
        {"gap": "STALE_SPECIALIZATION_LABEL", "object_id": "c"},
    ]
    summary = migration._review_gap_summary(gaps)
    assert summary["count"] == 3
    assert summary["by_gap"] == {
        "STALE_SPECIALIZATION_LABEL": 2,
        "UNREVIEWED_OWNED_PATHS": 1,
    }
    assert summary["items"] == gaps
    assert migration._review_gap_summary([]) == {
        "count": 0,
        "by_gap": {},
        "items": [],
    }
