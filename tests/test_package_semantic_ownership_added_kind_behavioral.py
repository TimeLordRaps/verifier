"""Ownership boundary for retained added-kind behavioral verification."""
from __future__ import annotations

from pathlib import Path

from verifier.runtime.package_semantic_ownership import (
    SEMANTIC_OWNERSHIP_SPECS,
    validate_catalog,
)


ROOT = Path(__file__).parents[1]
OBJECT_ID = "vstd-added-kind-behavioral-verifier"
PATHS = (
    "src/verifier/domains/contracts/finbot_checks.py",
    "src/verifier/domains/contracts/market_checks.py",
    "src/verifier/domains/contracts/robot_checks.py",
    "src/verifier/runtime/added_kind_behavioral_routes.py",
)


def _selected():
    rows = [row for row in SEMANTIC_OWNERSHIP_SPECS if row.object_id == OBJECT_ID]
    assert len(rows) == 1
    return rows[0]


def test_added_kind_behavioral_sources_have_one_exact_verifier_owner() -> None:
    selected = _selected()
    assert selected.primary_kind == "VERIFIER"
    assert selected.specializations == (
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    )
    assert selected.owned_paths == PATHS
    assert validate_catalog(ROOT, (selected,)) == (selected,)
    assert all((ROOT / path).is_file() for path in PATHS)

    other_paths = {
        path
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id != OBJECT_ID
        for path in row.owned_paths
    }
    assert not other_paths.intersection(PATHS)


def test_checker_retains_all_review_obligations_without_promoting_external_subjects() -> None:
    selected = _selected()
    roles = {selected.primary_kind, *selected.specializations}
    assert roles == {
        "VERIFIER",
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    }
    assert "All twelve review-kind roles remain explicit" in selected.necessity_reason
    for boundary in (
        "specializations establish obligations only",
        "actual agency",
        "financial authority",
        "real-world endpoints",
        "effects remain unestablished",
        "submits no live order or settlement",
        "actuates no hardware",
        "moves no money",
        "establishes no runtime correspondence",
        "legal authority",
    ):
        assert boundary in selected.consequence_boundary


def test_checker_roles_preserve_external_nonpromotion_boundary() -> None:
    selected = _selected()
    assert set(selected.specializations) == {
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    }
    assert "caller-supplied retained bytes" in selected.consequence_boundary
    assert "local values" in selected.consequence_boundary
    assert "reaches no physical endpoint" in selected.consequence_boundary
