"""Refutable tests for 234-slot applicability and objective inventory.

Acronyms: application programming interface (API); command-line interface (CLI);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Simulation (SIM); Verifier Standard (VSTD).
"""
from __future__ import annotations

import json
import ast
from pathlib import Path
from typing import Any

import pytest

from verifier.core.namespace import MetaTier, ObjectKind
from verifier.domains.inventory import (
    GOVERNING_QUESTIONS, MECHANIZED_12_POINT_BINDINGS, OBJECT_DESCRIPTIONS,
    SCHEMA_VERSION, SlotRequirement, build_234_inventory, get_slot, slot_inventory,
)
from verifier.runtime.public_cli import main


def _expected_primary_coordinates() -> set[str]:
    # This is the existing independently written contract, never a production census.
    return {"EVENT-4.1", "TIME-3.1", "GRAPH-2.1", "SIM-3.4", "SIM-4.1", "SPACE-4.1", "OBJECT-8.1", "HARDWARE-2.1", "DATA-3.4", "GRAPH-3.1", "GRAPH-4.1", "ARCH-3.1"} | {kind.value + "-7.1" for kind in ObjectKind} | {"EVENT-3.1"} | {"TIME-2.1", "SPACE-3.1"} | {"SIM-2.1", "SIM-5.1", "HYPER-4.1", "VERIFIER-2.1", "RECEIPT-9.1", "IDENTITY-3.1", "DATA-2.1", "DATA-4.1", "ENV-2.3", "ENV-3.3", "ENV-4.1", "BENCH-3.6", "BENCH-4.4", "TRAIN-2.1", "TRAIN-4.1", "MODEL-2.1", "MODEL-3.1", "MODEL-4.2", "HARNESS-2.1", "HARNESS-4.1", "AGENT-2.1", "AGENT-4.1", "BOT-2.1", "BOT-4.1"} | {kind + "-1.1" for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()} | {kind + "-6.7" for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()} | {kind.value + "-8.1" for kind in ObjectKind} | {kind.value + "-9.1" for kind in ObjectKind}



_existing_expected_primary_coordinates = _expected_primary_coordinates

def _expected_primary_coordinates() -> set[str]:
    expected = _existing_expected_primary_coordinates() | {
        kind + "-5.1" for kind in
        "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT BOT TOKEN".split()
    } | {"TOKEN-2.1", "TOKEN-3.1", "TOKEN-4.1"}
    # Coordinates below are written from the packet RESULT files, never read back from the registry.
    expected |= {"RECEIPT-2.1", "RECEIPT-3.1", "RECEIPT-4.1"}  # w1
    expected |= {"OBJECT-3.1", "OBJECT-4.2"}  # w2
    expected |= {"OBJECT-2.1"}  # w2L
    expected |= {"ARCH-2.1", "TRAIN-3.2"}  # w3
    expected |= {"HYPER-2.3", "HYPER-3.1"}  # w4
    expected |= {"HARDWARE-3.1", "HARDWARE-4.1"}  # w5
    expected |= {"AGENT-3.1", "BOT-3.1", "HARNESS-3.1"}  # w7
    expected |= {"EVENT-2.1", "SPACE-2.1", "BENCH-2.1"}  # w8
    expected |= {"ACTOR-2.7", "ACTOR-3.3", "ACTOR-4.6"}  # w9
    expected |= {"HUMAN-2.5", "HUMAN-3.6", "HUMAN-4.3"}  # w10
    expected |= {"OWNER-2.6", "OWNER-4.3"}  # w11
    expected |= {"VERIFIER-3.1", "VERIFIER-4.1"}  # w6
    expected |= {"ROLE-3.1", "COLLECTIVE-3.1", "ROLE-2.1", "COLLECTIVE-2.1", "ARCH-4.1"}  # t4
    expected |= {"OWNER-3.1", "TIME-4.1", "ROLE-4.1", "COLLECTIVE-4.1", "IDENTITY-2.1", "IDENTITY-4.1"}
    return expected


def test_inventory_total_slot_count_is_exactly_234() -> None:
    slots = build_234_inventory()
    assert len(slots) == 234
    serialized = slot_inventory()
    assert len(serialized) == 234


def test_every_object_and_meta_tier_is_represented() -> None:
    slots = build_234_inventory()
    observed_pairs = {(slot.object_kind, slot.tier) for slot in slots}
    expected_pairs = {(kind, tier) for kind in ObjectKind for tier in MetaTier}
    assert observed_pairs == expected_pairs
    assert len(observed_pairs) == 26 * 9


def test_all_234_slots_have_required_applicability() -> None:
    slots = build_234_inventory()
    for slot in slots:
        assert slot.applicability == "REQUIRED", f"{slot.coordinate} applicability is not REQUIRED"


def test_all_234_slots_have_non_empty_rationales_and_governing_questions() -> None:
    slots = build_234_inventory()
    for slot in slots:
        assert isinstance(slot.rationale, str) and len(slot.rationale.strip()) > 10, (
            f"{slot.coordinate} rationale must be a non-empty descriptive string"
        )
        assert isinstance(slot.governing_question, str) and len(slot.governing_question.strip()) > 10, (
            f"{slot.coordinate} governing question must be non-empty"
        )
        assert slot.governing_question == GOVERNING_QUESTIONS[slot.tier]


def test_tier_numbers_and_names_agree_with_meta_tier_enum() -> None:
    slots = build_234_inventory()
    for slot in slots:
        assert 1 <= slot.tier.value <= 9
        assert slot.tier.name in {
            "FACETS", "DYNAMICS", "STATICS", "CLOSURE", "INDEPENDENCE",
            "PRIVACY", "CONSENT", "GOVERNANCE", "SECURITY"
        }
        assert slot.tier.value == 8 and slot.tier.name == "GOVERNANCE" or slot.tier.value != 8
        assert slot.tier.value == 9 and slot.tier.name == "SECURITY" or slot.tier.value != 9


def test_registered_objectives_preserve_exact_slot_inventory() -> None:
    slots = build_234_inventory()
    mechanized = [slot for slot in slots if slot.mechanized]
    assert len(mechanized) == len(_expected_primary_coordinates())
    mechanized_coords = {slot.coordinate for slot in mechanized}
    assert mechanized_coords == _expected_primary_coordinates()
    assert set(MECHANIZED_12_POINT_BINDINGS) == mechanized_coords | {"RECEIPT-9.2", "SIM-2.2", "SIM-2.3", "SIM-2.4", "SIM-2.5", "SIM-4.2", "SIM-4.3", "SIM-4.4"} | {kind.value + "-7." + str(stage) for kind in ObjectKind for stage in range(2,7)} | {"OBJECT-1.2", "HARDWARE-2.2", "HARDWARE-1.2", "HARDWARE-1.3", "DATA-1.2", "DATA-1.4", "DATA-4.4", "ENV-1.2", "ENV-1.3", "ENV-1.4", "ENV-1.5", "BENCH-1.2", "BENCH-1.4", "TRAIN-1.2", "TRAIN-1.3", "TRAIN-1.5", "TRAIN-2.3", "MODEL-1.5", "MODEL-1.2", "MODEL-3.2", "MODEL-3.3", "MODEL-3.4", "MODEL-3.5", "MODEL-3.7", "MODEL-4.4", "HARNESS-1.6", "HARNESS-2.2", "HARNESS-2.3", "AGENT-1.8", "AGENT-2.3", "AGENT-4.3", "BOT-1.6", "BOT-2.2", "BOT-2.3"} | {"RECEIPT-9.3", "GRAPH-9.2"}

    required_12_points = {
        "exact_claim",
        "artifact_coordinate",
        "facet_examined",
        "translation",
        "checking_mechanism",
        "resulting_evidence",
        "admitted_verdicts",
        "assumptions_and_exclusions",
        "reproduction_instructions",
        "invalidating_dependencies",
        "resource_limits",
        "public_route_and_tests",
    }

    for slot in mechanized:
        assert slot.status == "REPLAYABLE"
        assert slot.mechanized_route is not None
        binding = slot.mechanized_route
        assert set(binding.keys()) == required_12_points
        assert binding["artifact_coordinate"] == slot.coordinate
        assert isinstance(binding["resource_limits"], dict)
        assert binding["resource_limits"]["max_certificate_bytes"] > 0
        assert binding["resource_limits"]["max_selection_text_bytes"] > 0
        assert "PASS" in binding["admitted_verdicts"]
        assert "FAIL" in binding["admitted_verdicts"]
        assert "UNKNOWN" in binding["admitted_verdicts"]
    for binding in MECHANIZED_12_POINT_BINDINGS.values():
        assert set(binding) == required_12_points
    serialized = slot_inventory()
    registered = [entry for slot in serialized for entry in slot["registered_objectives"]]
    # Counts are secondary; exact independently constrained binding identities remain.
    assert {entry["coordinate"] for entry in registered} == set(MECHANIZED_12_POINT_BINDINGS)
    assert len(registered) == len(MECHANIZED_12_POINT_BINDINGS)
    assert len(registered) == 408
    assert all(entry["semantic_version"] == "verifier-current-object-obligations-1" for entry in registered)
    assert all(slot["objective_inventory_closure"] == "NOT_ESTABLISHED" for slot in serialized)


def test_67_unmechanized_slots_have_unknown_status() -> None:
    slots = build_234_inventory()
    unmechanized = [slot for slot in slots if not slot.mechanized]
    assert len(unmechanized) == len(slots) - len(_expected_primary_coordinates())
    for slot in unmechanized:
        assert slot.status == "UNKNOWN"
        assert slot.mechanized_route is None


def test_get_slot_lookup_by_string_and_enum() -> None:
    slot_enum = get_slot(ObjectKind.SIM, MetaTier.INDEPENDENCE)
    slot_str = get_slot("SIM", 5)
    assert slot_enum == slot_str
    assert slot_enum.coordinate == "SIM-5.1"
    assert slot_enum.mechanized is True

    sec_slot = get_slot("HUMAN", 9)
    assert sec_slot.tier == MetaTier.SECURITY
    assert sec_slot.tier.value == 9
    assert sec_slot.mechanized is True
    assert sec_slot.status == "REPLAYABLE"
    assert sec_slot.coordinate == "HUMAN-9.1"
    assert sec_slot.mechanized_route == MECHANIZED_12_POINT_BINDINGS["HUMAN-9.1"]
    assert sec_slot.to_dict()["objective_inventory_closure"] == "NOT_ESTABLISHED"

    gov_slot = get_slot("HUMAN", 8)
    assert gov_slot.tier == MetaTier.GOVERNANCE
    assert gov_slot.tier.value == 8
    assert gov_slot.coordinate == "HUMAN-8.1"
    assert gov_slot.mechanized is True and gov_slot.status == "REPLAYABLE"
    assert gov_slot.mechanized_route == MECHANIZED_12_POINT_BINDINGS["HUMAN-8.1"]
    assert gov_slot.to_dict()["objective_inventory_closure"] == "NOT_ESTABLISHED"

    with pytest.raises(ValueError):
        get_slot("INVALID_OBJECT", 1)
    with pytest.raises(ValueError):
        get_slot("SIM", 10)


def test_cli_current_object_catalog_inventory(capsys: Any) -> None:
    exit_code = main(["current-object", "catalog", "--inventory", "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["schema_version"] == "verifier-current-object-inventory-1"
    assert report["slot_count"] == 234
    assert len(report["inventory"]) == 234
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    native_rows = current_object_route_catalog()
    assert report["routes"] == native_rows
    assert len(report["routes"]) == len(native_rows)

    # Plain text mode
    exit_code_txt = main(["current-object", "catalog", "--inventory"])
    assert exit_code_txt == 0
    captured_txt = capsys.readouterr()
    assert "234-slot applicability and objective inventory (234 slots):" in captured_txt.out
    assert "OBJECT-1.1: OBJECT Tier 1 (FACETS) - REQUIRED (REPLAYABLE) [mechanized: OBJECT-1.1]" in captured_txt.out


def test_cli_polish_catalog_inventory(capsys: Any) -> None:
    exit_code = main(["polish", "catalog", "--inventory", "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["schema_version"] == "verifier-polish-catalog-1"
    assert report["slot_count"] == 234
    assert len(report["inventory"]) == 234
    assert len(report["tiers"]) == 9
    assert report["tiers"][-1] == {"name": "SECURITY", "tier": 9}
    assert report["tiers"][-2] == {"name": "GOVERNANCE", "tier": 8}


def test_mechanized_inventory_links_real_registered_routes_and_tests() -> None:
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    assert set(MECHANIZED_12_POINT_BINDINGS) == {row["objective"] for row in current_object_route_catalog()}
    root = Path(__file__).resolve().parents[1]
    for binding in MECHANIZED_12_POINT_BINDINGS.values():
        path, name = binding["public_route_and_tests"].split("::")
        tree = ast.parse((root/path).read_text(encoding="utf-8"))
        assert name in {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
