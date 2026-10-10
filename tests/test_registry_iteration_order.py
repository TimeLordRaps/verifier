"""Registry iteration order survives tests that delete and restore entries.

``monkeypatch.delitem`` undoes a deletion by assigning the key back, which
restores the entry but appends it. A registry that one test deleted from then
iterates in a different order for every later test, and differs from a freshly
imported interpreter such as an installed wheel. The first test below performs
that deletion; the second runs after it and requires the import-time order.
"""

from __future__ import annotations

import pytest

from verifier.domains import inventory
from verifier.domains.contracts import current_object_routes as routes

_ROUTE_ORDER = list(routes._ROUTES)
_BINDING_ORDER = list(inventory.MECHANIZED_12_POINT_BINDINGS)


def test_first_deletion_through_monkeypatch_is_undone(monkeypatch: pytest.MonkeyPatch) -> None:
    route_key = _ROUTE_ORDER[0]
    binding_key = _BINDING_ORDER[0]
    monkeypatch.delitem(routes._ROUTES, route_key)
    monkeypatch.delitem(inventory.MECHANIZED_12_POINT_BINDINGS, binding_key)
    assert route_key not in routes._ROUTES
    assert binding_key not in inventory.MECHANIZED_12_POINT_BINDINGS


def test_second_registries_iterate_in_import_order_again() -> None:
    assert list(routes._ROUTES) == _ROUTE_ORDER
    assert list(inventory.MECHANIZED_12_POINT_BINDINGS) == _BINDING_ORDER
