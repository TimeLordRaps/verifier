"""Deterministic current-object catalogue under equivalent registration order.

command-line interface (CLI); JavaScript Object Notation (JSON).
Table order is dimensionless and supplies no objective-conformance evidence.
"""
from __future__ import annotations

import json

import pytest

from verifier.domains.contracts import current_object_routes as routes
from verifier.runtime.public_cli import main

SEMANTIC = "verifier-current-object-obligations-1"


def public_catalog(capsys):
    assert main(["current-object", "catalog", "--json"]) == 0
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("objective", ["GRAPH-2.1", "TIME-3.1", "EVENT-4.1", "SIM-4.4"])
def test_equivalent_table_reordering_preserves_exact_native_and_public_catalog(objective, monkeypatch, capsys):
    key = (SEMANTIC, objective)
    original = routes._ROUTES
    assert key in original
    native_before = routes.current_object_route_catalog()
    public_before = public_catalog(capsys)
    others = {item: value for item, value in original.items() if item != key}
    reordered = ({key: original[key], **others} if next(iter(original)) != key
                 else {**others, key: original[key]})
    assert set(reordered) == set(original)
    assert all(reordered[item] is value for item, value in original.items())
    assert list(reordered) != list(original)
    monkeypatch.setattr(routes, "_ROUTES", reordered)
    assert routes.current_object_route_catalog() == native_before
    assert public_catalog(capsys) == public_before


def test_exact_table_copy_preserves_catalog_control(monkeypatch, capsys):
    native = routes.current_object_route_catalog()
    public = public_catalog(capsys)
    monkeypatch.setattr(routes, "_ROUTES", dict(routes._ROUTES))
    assert routes.current_object_route_catalog() == native
    assert public_catalog(capsys) == public


def test_deleted_selected_objective_is_observable_control(monkeypatch, capsys):
    key = (SEMANTIC, "GRAPH-2.1")
    original = routes._ROUTES
    expected_keys = set(original)
    monkeypatch.setattr(routes, "_ROUTES", {item: value for item, value in original.items() if item != key})
    native = routes.current_object_route_catalog()
    public = public_catalog(capsys)
    observed = {(row["semantic_version"], row["objective"]) for row in native}
    assert observed == expected_keys - {key}
    assert observed != expected_keys
    assert public["routes"] == native


@pytest.mark.parametrize("objective", ["GRAPH-2.1", "TIME-3.1", "EVENT-4.1", "SIM-4.4"])
@pytest.mark.parametrize("initial_position", ["first", "last"])
def test_reordering_control_exercises_both_existing_endpoints(objective, initial_position, monkeypatch, capsys):
    key = (SEMANTIC, objective)
    original = routes._ROUTES
    others = {item: value for item, value in original.items() if item != key}
    seeded = ({key: original[key], **others} if initial_position == "first"
              else {**others, key: original[key]})
    assert set(seeded) == set(original)
    assert all(seeded[item] is value for item, value in original.items())
    monkeypatch.setattr(routes, "_ROUTES", seeded)
    test_equivalent_table_reordering_preserves_exact_native_and_public_catalog(objective, monkeypatch, capsys)
