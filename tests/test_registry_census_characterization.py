"""Characterization of the 234-slot registry census (a sandbox proposal for the census refactor).

Terminology. A slot is one pair of an object kind and a meta-tier; the grid has 26 x 9 = 234 of them. A slot is mechanized
when the inventory names a primary coordinate for it; a coordinate is the string "<KIND>-<tier>.<n>". A mechanism module
declares its own coordinate, semantic version and certificate version as module-level string constants, and the
12-point bindings, the route table and the primary flags of the inventory must describe the same coordinates.

Design. The independently hand-written literal of tests/test_inventory.py (loaded by path, never copied) states which
coordinates were primary before a change. The module declarations state which coordinates a change adds. The registry
must equal their union, slot by slot, so that adding a mechanism edits no census literal. A registry edit without a
module (inflation), a module without wiring (deflation), two modules on one coordinate and a certificate version shared
by two modules are each reported. Every count is computed from the registry; no count is written down here.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import verifier.domains.inventory as inventory
from verifier.domains.contracts.current_object_routes import current_object_route_catalog
from test_inventory import _expected_primary_coordinates

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "src" / "verifier" / "domains" / "contracts"
SEMANTIC = "verifier-current-object-obligations-1"
COORDINATE_FORM = re.compile(r"^([A-Z]+)-([0-9]+)\.([0-9]+)$")

# A module that declares a coordinate but is wired into neither the bindings nor the route table. An entry is a
# recorded exception with its reason, not a permission: the test fails when the module is wired (a stale exception)
# and when an unlisted module is unwired.
KNOWN_UNWIRED_MODULES = {}


def _declared_by_modules() -> list[tuple[str, str, str, str | None]]:
    """Module, semantic version, coordinate and certificate version, read by the parser and never by import."""
    rows = []
    for path in sorted(CONTRACTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants: dict[str, str] = {}
        for node in tree.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                constants[node.targets[0].id] = node.value.value
        if "COORDINATE" in constants:
            rows.append((path.stem, constants.get("SEMANTIC_VERSION", ""), constants["COORDINATE"],
                         constants.get("CERTIFICATE_VERSION")))
    return rows


def _legacy_primary_coordinates() -> set[str]:
    """The expectation recorded before the change: the independently written literal of tests/test_inventory.py,
    loaded by path and not copied. A revision whose census test holds counts and no coordinate set gets a golden file
    recorded from the registry of the revision before the change (tests/census_legacy_primary.json)."""
    return _expected_primary_coordinates()


def _slot_of(coordinate: str) -> tuple[str, int] | None:
    match = COORDINATE_FORM.match(coordinate)
    return (match.group(1), int(match.group(2))) if match else None


def production_view() -> dict[str, Any]:
    slots = inventory.build_234_inventory()
    return {
        "slots": [(slot.object_kind.value, slot.tier.value, slot.mechanized, slot.status, slot.coordinate)
                  for slot in slots],
        "bindings": set(inventory.MECHANIZED_12_POINT_BINDINGS),
        "routes": {row["objective"] for row in current_object_route_catalog() if row["semantic_version"] == SEMANTIC},
    }


def census_findings(view: dict[str, Any], legacy_primary: set[str],
                    declared_rows: list[tuple[str, str, str, str | None]],
                    known_unwired: dict[str, str]) -> list[str]:
    findings: list[str] = []
    slots, bindings, routes = view["slots"], view["bindings"], view["routes"]
    primary_of: dict[tuple[str, int], str] = {}
    for kind, tier, mechanized, status, coordinate in slots:
        if (status == "REPLAYABLE") != bool(mechanized):
            findings.append(f"slot {kind}-{tier} has status {status} with mechanized={mechanized}")
        if mechanized:
            if _slot_of(coordinate) != (kind, tier):
                findings.append(f"slot {kind}-{tier} names primary {coordinate}, which belongs to another slot")
            primary_of[(kind, tier)] = coordinate
    primary = set(primary_of.values())
    findings += [f"primary {c} has no 12-point binding" for c in sorted(primary - bindings)]
    findings += [f"binding {c} has no registered route" for c in sorted(bindings - routes)]
    findings += [f"route {c} has no 12-point binding" for c in sorted(routes - bindings)]

    legacy_by_slot: dict[tuple[str, int], list[str]] = {}
    for coordinate in sorted(legacy_primary):
        slot = _slot_of(coordinate)
        if slot is not None:
            legacy_by_slot.setdefault(slot, []).append(coordinate)
    claimed: dict[tuple[str, str], str] = {}
    certificates: dict[str, str] = {}
    claimants: dict[tuple[str, int], set[str]] = {}
    for module, semantic, coordinate, certificate in declared_rows:
        if (semantic, coordinate) in claimed:
            findings.append(f"{module} and {claimed[(semantic, coordinate)]} both declare {coordinate} under {semantic}")
        claimed.setdefault((semantic, coordinate), module)
        if certificate:
            if certificate in certificates:
                findings.append(f"{module} and {certificates[certificate]} share certificate version {certificate}")
            certificates.setdefault(certificate, module)
        # Coordinate spelling is insufficient across separately versioned families.
        # Keep declaration/certificate collisions above global; wiring and primary
        # claims below belong only to the selected nine-tier inventory.
        if semantic != SEMANTIC:
            continue
        wired = coordinate in bindings and coordinate in routes
        if module in known_unwired:
            if wired:
                findings.append(f"{module} is listed as unwired but {coordinate} is wired: remove the stale exception")
            continue
        if not wired:
            findings.append(f"{module} declares {coordinate}, which is not wired into the bindings and the routes")
        slot = _slot_of(coordinate)
        if slot is not None and wired:
            claimants.setdefault(slot, set()).add(coordinate)

    for slot, coordinates in sorted(legacy_by_slot.items()):
        if len(coordinates) > 1:
            findings.append(f"slot {slot[0]}-{slot[1]} has two independently expected primaries {coordinates}")
        elif primary_of.get(slot) != coordinates[0]:
            findings.append(f"slot {slot[0]}-{slot[1]} expects primary {coordinates[0]}, the registry names "
                            f"{primary_of.get(slot)}")
    for slot, coordinates in sorted(claimants.items()):
        if slot in legacy_by_slot:
            continue
        if primary_of.get(slot) not in coordinates:
            findings.append(f"slot {slot[0]}-{slot[1]} has wired mechanism(s) {sorted(coordinates)} but the registry "
                            f"names primary {primary_of.get(slot)}")
    for slot, coordinate in sorted(primary_of.items()):
        if slot not in legacy_by_slot and slot not in claimants:
            findings.append(f"primary {coordinate} is declared by no module and not in the independent expectation")
    return findings


def _findings_for(view: dict[str, Any]) -> list[str]:
    return census_findings(view, _legacy_primary_coordinates(), _declared_by_modules(), KNOWN_UNWIRED_MODULES)


def test_registry_census_has_no_findings() -> None:
    assert _findings_for(production_view()) == []


def test_sim_resource_has_no_wiring_finding() -> None:
    findings = _findings_for(production_view())
    assert not [finding for finding in findings
                if "sim_resource" in finding or "SIM-2.4" in finding]


def test_counts_are_computed_from_the_registry() -> None:
    view = production_view()
    replayable = sum(1 for _, _, _, status, _ in view["slots"] if status == "REPLAYABLE")
    unknown = sum(1 for _, _, _, status, _ in view["slots"] if status == "UNKNOWN")
    assert len(view["slots"]) == 26 * 9
    assert replayable + unknown == len(view["slots"])
    assert replayable == len({c for _, _, m, _, c in view["slots"] if m})


def test_a_substituted_valid_primary_is_reported() -> None:
    view = production_view()
    legacy = _legacy_primary_coordinates()
    victim = next(row for row in view["slots"] if row[2] and row[4] in legacy)
    kind, tier, _, _, original_primary = victim
    bogus = f"{kind}-{tier}.999999"
    assert bogus not in view["bindings"] | view["routes"] | legacy
    assert bogus not in {row[2] for row in _declared_by_modules()}
    inflated = {"slots": [(k, t, True, "REPLAYABLE", bogus) if (k, t) == (kind, tier) else (k, t, m, s, c)
                          for k, t, m, s, c in view["slots"]],
                "bindings": view["bindings"] | {bogus}, "routes": view["routes"] | {bogus}}
    findings = _findings_for(inflated)
    assert (f"slot {kind}-{tier} expects primary {original_primary}, the registry names {bogus}"
            in findings)


def test_an_inflated_registry_is_reported() -> None:
    view = production_view()
    # The synthetic tier exists only in this negative fixture.
    bogus = "OBJECT-10.999999"
    assert bogus not in view["bindings"] | view["routes"] | _legacy_primary_coordinates()
    assert bogus not in {row[2] for row in _declared_by_modules()}
    inflated = {"slots": view["slots"] + [("OBJECT", 10, True, "REPLAYABLE", bogus)],
                "bindings": view["bindings"] | {bogus}, "routes": view["routes"] | {bogus}}
    findings = _findings_for(inflated)
    assert any(bogus in finding and "declared by no module" in finding for finding in findings)
    assert production_view() == view


def test_a_deflated_registry_is_reported() -> None:
    view = production_view()
    victim = next(coordinate for _, _, mechanized, _, coordinate in view["slots"] if mechanized)
    deflated = {"slots": [(k, t, m and c != victim, "UNKNOWN" if c == victim else s, c)
                          for k, t, m, s, c in view["slots"]],
                "bindings": view["bindings"] - {victim}, "routes": view["routes"] - {victim}}
    findings = _findings_for(deflated)
    assert any(victim in finding for finding in findings)


def test_a_module_that_is_not_wired_is_reported() -> None:
    view = production_view()
    rows = _declared_by_modules()
    module, semantic, coordinate, certificate = next(row for row in rows if row[0] not in KNOWN_UNWIRED_MODULES)
    unwired = {"slots": view["slots"], "bindings": view["bindings"] - {coordinate},
               "routes": view["routes"] - {coordinate}}
    findings = _findings_for(unwired)
    assert any(module in finding and coordinate in finding for finding in findings)


def test_a_second_claim_on_one_coordinate_is_reported() -> None:
    rows = _declared_by_modules()
    _, semantic, coordinate, _ = rows[0]
    shadow = rows + [("shadow_module", semantic, coordinate, "verifier-shadow-certificate-1")]
    findings = census_findings(production_view(), _legacy_primary_coordinates(), shadow, KNOWN_UNWIRED_MODULES)
    assert any("both declare" in finding and coordinate in finding for finding in findings)


def test_a_shared_certificate_version_is_reported() -> None:
    rows = _declared_by_modules()
    donor = next(row for row in rows if row[3])
    shadow = rows + [("shadow_module", "verifier-shadow-obligations-1", "OBJECT-9.8", donor[3])]
    findings = census_findings(production_view(), _legacy_primary_coordinates(), shadow, KNOWN_UNWIRED_MODULES)
    assert any("share certificate version" in finding for finding in findings)


def test_a_stale_unwired_exception_is_reported() -> None:
    rows = _declared_by_modules()
    wired = next(row[0] for row in rows if row[0] not in KNOWN_UNWIRED_MODULES)
    findings = census_findings(production_view(), _legacy_primary_coordinates(), rows,
                               dict(KNOWN_UNWIRED_MODULES, **{wired: "listed by mistake"}))
    assert any(wired in finding and "stale exception" in finding for finding in findings)


def test_a_separate_semantic_family_is_not_a_nine_tier_wiring_claim() -> None:
    rows = _declared_by_modules()
    foreign = [row for row in rows if row[1] != SEMANTIC]
    assert {row[0] for row in foreign} >= {"verifier_composed_security", "verifier_replacement"}
    view = production_view()
    shadow = ("foreign_family", "verifier-independent-family-1", rows[0][2],
              "verifier-independent-family-certificate-1")
    assert census_findings(view, _legacy_primary_coordinates(), rows + [shadow], KNOWN_UNWIRED_MODULES) == []
    assert production_view() == view


def test_a_separate_semantic_family_cannot_supply_a_nine_tier_primary() -> None:
    view = production_view()
    coordinate = "OBJECT-10.999998"
    assert coordinate not in view["bindings"] | view["routes"] | _legacy_primary_coordinates()
    inflated = {"slots": view["slots"] + [("OBJECT", 10, True, "REPLAYABLE", coordinate)],
                "bindings": view["bindings"] | {coordinate}, "routes": view["routes"] | {coordinate}}
    foreign = ("foreign_family", "verifier-independent-family-1", coordinate,
               "verifier-independent-family-certificate-1")
    findings = census_findings(inflated, _legacy_primary_coordinates(),
                               _declared_by_modules() + [foreign], KNOWN_UNWIRED_MODULES)
    assert any(coordinate in finding and "declared by no module" in finding for finding in findings)
