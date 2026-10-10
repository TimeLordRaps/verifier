"""Replay second-batch native evidence with external current-object selection.

JavaScript Object Notation (JSON) certificates never promote a bounded result
to object-profile or whole-tier conformance. Prior routes remain exact.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.domains import inventory
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
NEXT = {"ROLE-2.1": ("ROLE", "role_lifecycle"),
        "COLLECTIVE-2.1": ("COLLECTIVE", "collective_lifecycle"),
        "ARCH-4.1": ("ARCH", "arch_resolution")}
ALL = {"ROLE-3.1": "ROLE", "COLLECTIVE-3.1": "COLLECTIVE",
       **{coordinate: kind for coordinate, (kind, _) in NEXT.items()}}


def selected(coordinate: str, status: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    name = NEXT[coordinate][1]
    spec = importlib.util.spec_from_file_location("_second_batch_fixture_" + name,
        Path(__file__).with_name("test_current_" + name + ".py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    return fixture.fixture_for_integration(status)


@pytest.mark.parametrize("coordinate", NEXT)
@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_real_next_native_certificate_replays_through_selected_public_route(coordinate: str, status: str) -> None:
    certificate, request, policy = selected(coordinate, status)
    result = routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=coordinate, represented_kind=NEXT[coordinate][0], expected_request=request, policy=policy)
    assert result["computational_status"] == status
    assert result["native_result"]["coordinate"] == coordinate
    for field in ("object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution"):
        assert result["native_result"][field] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("coordinate", NEXT)
@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_rehashed_next_certificate_status_promotion_is_refused(coordinate: str, status: str) -> None:
    certificate, request, policy = selected(coordinate, status)
    envelope = json.loads(certificate)
    envelope["result"]["status"] = "PASS"
    del envelope["digest"]
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(canonical_bytes(envelope), semantic_version=SEMANTIC,
            objective=coordinate, represented_kind=NEXT[coordinate][0], expected_request=request, policy=policy)


@pytest.mark.parametrize("coordinate", NEXT)
@pytest.mark.parametrize("field", ["semantic_version", "coordinate", "object_digest", "collection_digest"])
def test_next_external_request_substitution_is_refused(coordinate: str, field: str) -> None:
    certificate, request, policy = selected(coordinate, "PASS")
    request = {**request, field: "wrong-selection" if field in ("semantic_version", "coordinate") else "sha256:" + "0" * 64}
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
            objective=coordinate, represented_kind=NEXT[coordinate][0], expected_request=request, policy=policy)


@pytest.mark.parametrize("coordinate", NEXT)
def test_next_route_requires_exact_kind(coordinate: str) -> None:
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.select_current_object_route(semantic_version=SEMANTIC, objective=coordinate, represented_kind="HUMAN")


@pytest.mark.parametrize("coordinate,kind", ALL.items())
@pytest.mark.parametrize("field", ["object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution"])
def test_all_finite_routes_refuse_native_boundary_promotion(monkeypatch: Any, coordinate: str, kind: str, field: str) -> None:
    key = (SEMANTIC, coordinate)
    original = routes._ROUTES[key]
    native = {"status": "PASS", "semantic_version": SEMANTIC, "coordinate": coordinate,
        "object_kind": kind, "scope": original.scope, "object_profile_conformance": "NOT_ESTABLISHED",
        "whole_tier_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED"}
    native[field] = "ESTABLISHED"
    monkeypatch.setitem(routes._ROUTES, key, routes._Route(original.module, lambda *args, **kwargs: native, kind, original.scope))
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(b"{}", semantic_version=SEMANTIC, objective=coordinate,
            represented_kind=kind, expected_request={"semantic_version": SEMANTIC, "coordinate": coordinate}, policy={})


def test_second_batch_occupies_only_five_explicit_selected_slots() -> None:
    slots = inventory.build_234_inventory()
    assert len(slots) == 234
    assert sum(slot.mechanized for slot in slots) == 234
    assert sum(not slot.mechanized for slot in slots) == 0
    assert len(routes.current_object_route_catalog()) == 408
    for coordinate, kind in ALL.items():
        slot = inventory.get_slot(kind, int(coordinate.split("-")[1].split(".")[0]))
        assert slot.coordinate == coordinate
        assert slot.mechanized
        assert slot.to_dict()["objective_inventory_closure"] == "NOT_ESTABLISHED"
