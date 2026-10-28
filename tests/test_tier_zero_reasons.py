from __future__ import annotations

from pathlib import Path

from verifier.runtime import (
    core_obligation_union, core_tier_progression,
    package_obligation_candidate, tier_zero_reasons,
)


def test_source_derived_reason_ledger_covers_and_validates_all_denominators(
        tmp_path) -> None:
    root = Path(__file__).parents[1]
    ledger = tier_zero_reasons.installed_reason_ledger(root)
    assert len(ledger["objectives"]) == 408
    assert len(ledger["slots"]) == 234
    assert all(
        row["reason"].strip() and row["repository_realization"]["explanation"].strip()
        for rows in (ledger["objectives"], ledger["slots"])
        for row in rows.values()
    )

    raw = core_obligation_union.canonical_bytes(ledger)
    path = tmp_path / "obligation-reasons.vstd"
    path.write_bytes(raw)
    selected = package_obligation_candidate._reason_ledger(
        path,
        expected_digest=core_obligation_union.bytes_digest(raw),
        installed=package_obligation_candidate._installed_routes(
            core_tier_progression.installed_core_route_inventory()
        ),
        source_root=root,
    )
    assert selected["status"] == "PASS"
    assert selected["objective_count"] == 408
    assert selected["slot_count"] == 234
    assert selected["realization_binding_status"] == "PASS"
    assert selected["realization_claim_status"] == "UNKNOWN"


def test_reason_provider_receipt_preserves_claim_boundary() -> None:
    root = Path(__file__).parents[1]
    receipt = tier_zero_reasons.provider_receipt(root)
    assert receipt["status"] == "PASS"
    assert receipt["objective_count"] == 408
    assert receipt["slot_count"] == 234
    assert receipt["claim_status"] == "UNKNOWN"


def test_reason_ledger_inventory_work_is_not_multiplied_by_routes(monkeypatch) -> None:
    from verifier.domains import inventory
    calls = []
    build = inventory.build_234_inventory

    def counted():
        calls.append(1)
        return build()

    monkeypatch.setattr(inventory, "build_234_inventory", counted)
    tier_zero_reasons.installed_reason_ledger(Path(__file__).parents[1])
    assert len(calls) == 2  # One local route lookup table and one slot traversal.


def test_slot_snapshot_identity_matches_fresh_lookup_and_is_not_global_cache(monkeypatch) -> None:
    from verifier.domains import inventory
    from dataclasses import replace
    slots = inventory.build_234_inventory()
    for slot in slots:
        coordinate = f"{slot.object_kind.value}-{slot.tier.value}"
        assert package_obligation_candidate._slot_record_semantic_identity(slot) == (
            package_obligation_candidate._slot_semantic_identity(coordinate))
    root = Path(__file__).parents[1]
    before = tier_zero_reasons.installed_reason_ledger(root)
    monkeypatch.setattr(inventory, "build_234_inventory", lambda: [
        replace(slot, rationale=slot.rationale + " changed") for slot in slots])
    after = tier_zero_reasons.installed_reason_ledger(root)
    assert before["slots"] != after["slots"]
