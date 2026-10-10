"""Bounded public routing tests for two distinct current objectives.

JavaScript Object Notation (JSON) selection remains external. Registry counts
describe replayable propositions and never complete object certification.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from verifier.domains import inventory
from verifier.domains.contracts import current_object_routes as routes

EXPECTED = {"ROLE-3.1": "ROLE", "COLLECTIVE-3.1": "COLLECTIVE"}
SEMANTIC = "verifier-current-object-obligations-1"


def _selected_native(coordinate: str, status: str):
    module_name = {"ROLE-3.1": "role_constraints", "COLLECTIVE-3.1": "collective_constraints"}[coordinate]
    source = Path(__file__).with_name("test_current_" + module_name + ".py")
    spec = importlib.util.spec_from_file_location("_finite_fixture_" + module_name, source)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    if coordinate == "ROLE-3.1":
        def exceed(rows):
            next(row for row in rows if row["object_id"] == "author")["payload"]["permissions"] = ["admin"]
        request, policy, data = fixture.selected(mutate_objects=exceed if status == "FAIL" else None)
        module = fixture.role
    else:
        request, policy, data = fixture.specimen(quorum=3 if status == "FAIL" else 2)
        module = fixture.contract
    if status == "UNKNOWN":
        data = None
    certificate = getattr(module, "build_" + module_name + "_certificate")(request, data, policy=policy)
    return certificate, request, policy


@pytest.mark.parametrize("coordinate,kind", EXPECTED.items())
@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_real_native_certificate_replays_through_selected_public_route(coordinate, kind, status):
    certificate, request, policy = _selected_native(coordinate, status)
    result = routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=coordinate, represented_kind=kind, expected_request=request, policy=policy)
    assert result["computational_status"] == status
    assert result["native_result"]["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert result["native_result"]["actual_execution"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("coordinate,kind", EXPECTED.items())
def test_public_route_refuses_rehashed_native_certificate_promotion(coordinate, kind):
    import json
    from verifier.core.certificate import canonical_bytes, canonical_digest
    certificate, request, policy = _selected_native(coordinate, "FAIL")
    envelope = json.loads(certificate)
    envelope["result"]["status"] = "PASS"
    del envelope["digest"]
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(canonical_bytes(envelope), semantic_version=SEMANTIC,
            objective=coordinate, represented_kind=kind, expected_request=request, policy=policy)


def test_added_objectives_occupy_only_their_two_selected_slots():
    slots = inventory.build_234_inventory()
    assert len(slots) == 234
    assert sum(s.mechanized for s in slots) == 234
    assert sum(not s.mechanized for s in slots) == 0
    assert len(routes.current_object_route_catalog()) == 408
    for coordinate, kind in EXPECTED.items():
        slot = inventory.get_slot(kind, int(coordinate.split("-")[1].split(".")[0]))
        assert slot.mechanized
        assert slot.coordinate == coordinate
        assert slot.to_dict()["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("coordinate,kind", EXPECTED.items())
def test_public_route_descriptor_rejects_cross_kind_selection(coordinate, kind):
    selected = routes.select_current_object_route(semantic_version=SEMANTIC, objective=coordinate, represented_kind=kind)
    assert selected.fixed_kind == kind
    row = next(row for row in routes.current_object_route_catalog() if row["objective"] == coordinate)
    assert row["certificate_schema_version"] == selected.module.CERTIFICATE_VERSION
    assert row["proposition_digest"] == selected.module.PROPOSITION_DIGEST
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version=SEMANTIC, objective=coordinate, represented_kind="HUMAN")


@pytest.mark.parametrize("coordinate,kind", EXPECTED.items())
@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_public_wrapper_preserves_native_status_and_finite_boundary(monkeypatch, coordinate, kind, status):
    key = (SEMANTIC, coordinate)
    original = routes._ROUTES[key]
    result = {"status": status, "semantic_version": SEMANTIC, "coordinate": coordinate,
              "object_kind": kind, "scope": original.scope,
              "object_profile_conformance": "NOT_ESTABLISHED",
              "whole_tier_conformance": "NOT_ESTABLISHED",
              "authority": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED"}
    monkeypatch.setitem(routes._ROUTES, key, routes._Route(original.module, lambda *a, **k: result, kind, original.scope))
    replay = routes.replay_current_object_certificate(b"{}", semantic_version=SEMANTIC, objective=coordinate,
        represented_kind=kind, expected_request={"semantic_version": SEMANTIC, "coordinate": coordinate}, policy={})
    assert replay["computational_status"] == status
    assert "whole tier" in replay["claim_boundary"]


@pytest.mark.parametrize("coordinate,kind", EXPECTED.items())
@pytest.mark.parametrize("field,value", [("object_kind", "HUMAN"), ("scope", "widened"),
    ("whole_tier_conformance", "ESTABLISHED"), ("authority", "PASS"), ("actual_execution", "PASS")])
def test_public_wrapper_refuses_native_kind_or_boundary_upgrade(monkeypatch, coordinate, kind, field, value):
    key = (SEMANTIC, coordinate)
    original = routes._ROUTES[key]
    result = {"status": "PASS", "semantic_version": SEMANTIC, "coordinate": coordinate,
              "object_kind": kind, "scope": original.scope,
              "object_profile_conformance": "NOT_ESTABLISHED",
              "whole_tier_conformance": "NOT_ESTABLISHED",
              "authority": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED"}
    result[field] = value
    monkeypatch.setitem(routes._ROUTES, key, routes._Route(original.module, lambda *a, **k: result, kind, original.scope))
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(b"{}", semantic_version=SEMANTIC, objective=coordinate,
            represented_kind=kind, expected_request={"semantic_version": SEMANTIC, "coordinate": coordinate}, policy={})
