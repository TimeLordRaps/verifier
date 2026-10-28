"""Registration gate for the EVENT-4.1 closure objective, from hand-written identities.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Every expected
identity below is written out by hand. None is read from a census, a count or
a generated inventory, so a registry cannot pass this gate by agreeing with
itself. The gate checks one objective pair, never how many routes, slots or
schemas exist in total. Negative controls change only monkeypatched copies of
the registries, restored when each test ends; nothing on disk is changed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifier.domains import inventory
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import event_closure, event_prerequisites, space_closure
from verifier.privacy import engine
from verifier.privacy import (DisclosureBound, DisclosureSurface, EmissionContext,
                              EmissionEvaluator, EmissionRefusalError, ObserverParty)
from verifier.runtime import polish

import test_current_event_closure as fixture


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
OBJECTIVE = "EVENT-4.1"
PAIR = (SEMANTIC_VERSION, OBJECTIVE)
REPRESENTED_KIND = "EVENT"
SCOPE = "finite_declared_event_log_closure"
MECHANISM_MODULE = "verifier.domains.contracts.event_closure"
CHECKER = "recheck_event_closure_certificate"
CERTIFICATE_SCHEMA = "verifier-current-event-closure-certificate-1"
CHILD_PAIR = (SEMANTIC_VERSION, "EVENT-3.1")
CHILD_MODULE = "verifier.domains.contracts.event_prerequisites"
CHILD_CHECKER = "recheck_event_prerequisites_certificate"
CHILD_SCHEMA = "verifier-current-event-prerequisites-certificate-1"
POLISH_DEPENDENCIES = (
    "domains/contracts/event_closure.py", "standard/CURRENT_EVENT_CLOSURE.md",
    "domains/contracts/event_prerequisites.py", "standard/CURRENT_EVENT_PREREQUISITES.md",
)
SOURCE_ROOT = Path(event_closure.__file__).parents[2]


def _named(function: Any, module: str, name: str) -> bool:
    return (getattr(function, "__module__", None) == module
            and getattr(function, "__qualname__", None) == name)


def _carries_event_closure(route: Any) -> bool:
    return (route.replay is event_closure.recheck_event_closure_certificate
            or _named(route.replay, MECHANISM_MODULE, CHECKER)
            or getattr(route.module, "CERTIFICATE_VERSION", None) == CERTIFICATE_SCHEMA)


def _redaction_refused(certificate: bytes) -> bool:
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface(REPRESENTED_KIND, fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    try:
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)
    except EmissionRefusalError:
        return True
    return False


def _sensitive(monkeypatch: Any, digest: Any, relative: str) -> bool:
    before = digest()
    target = SOURCE_ROOT / relative
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged registration dependency\n" if path == target else data

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", changed)
        after = digest()
    return target.is_file() and after != before


def registration_violations(monkeypatch: Any) -> set[str]:
    """Name every way the live registries fail the hand-written EVENT-4.1 identities."""
    found: set[str] = set()
    registration = event_closure.registration()
    if (event_closure.__name__ != MECHANISM_MODULE
            or event_closure.SEMANTIC_VERSION != SEMANTIC_VERSION
            or event_closure.COORDINATE != OBJECTIVE
            or event_closure.CERTIFICATE_VERSION != CERTIFICATE_SCHEMA
            or event_closure.SCOPE != SCOPE
            or registration["semantic_version"] != SEMANTIC_VERSION
            or registration["coordinate"] != OBJECTIVE
            or registration["subject_kind"] != REPRESENTED_KIND
            or registration["scope"] != SCOPE):
        found.add("mechanism_identity")

    route = routes._ROUTES.get(PAIR)
    rows = [row for row in routes.current_object_route_catalog()
            if (row["semantic_version"], row["objective"]) == PAIR]
    if route is None or not rows:
        found.add("missing_route")
    carriers = [key for key, candidate in routes._ROUTES.items()
                if _carries_event_closure(candidate)]
    if len(rows) > 1 or len(carriers) > 1:
        found.add("duplicate_route")
    if route is not None and not (
            type(route.module) is event_closure.EventClosureDescriptor
            and route.module.CERTIFICATE_VERSION == CERTIFICATE_SCHEMA
            and route.module.PROPOSITION_DIGEST == event_closure.PROPOSITION_DIGEST
            and route.replay is event_closure.recheck_event_closure_certificate
            and _named(route.replay, MECHANISM_MODULE, CHECKER)
            and route.fixed_kind == REPRESENTED_KIND
            and route.scope == SCOPE
            and all(row["certificate_schema_version"] == CERTIFICATE_SCHEMA
                    and row["represented_kind_rule"] == REPRESENTED_KIND
                    and row["scope"] == SCOPE
                    and row["proposition_digest"] == event_closure.PROPOSITION_DIGEST
                    for row in rows)):
        found.add("misbound_route")

    case = fixture.selected()
    certificate, native = fixture.replay(case)
    assert native["status"] == "PASS", "direct checker control must PASS"
    try:
        report = routes.replay_current_object_certificate(
            certificate, semantic_version=SEMANTIC_VERSION, objective=OBJECTIVE,
            represented_kind=REPRESENTED_KIND, expected_request=case["request"],
            policy=case["policy"])
    except routes.CurrentObjectRouteRefusal:
        found.add("unreachable_route")
    else:
        if (report["computational_status"] != "PASS"
                or report["native_result"] != native
                or report["native_result"]["coordinate"] != OBJECTIVE):
            found.add("unreachable_route")

    if CERTIFICATE_SCHEMA not in engine._CANONICAL_CERTIFICATE_SCHEMAS:
        found.add("schema_unregistered")
    if not _redaction_refused(certificate):
        found.add("redaction_not_refused")

    slot = inventory.get_slot(REPRESENTED_KIND, 4)
    bound = slot.mechanized_route or {}
    mechanized = [row for row in inventory.slot_inventory()
                  if row.get("mechanized") and row.get("coordinate") == OBJECTIVE]
    if not (slot.mechanized and slot.coordinate == OBJECTIVE
            and bound.get("artifact_coordinate") == OBJECTIVE
            and bound.get("checking_mechanism") == MECHANISM_MODULE + "." + CHECKER
            and bound.get("resulting_evidence") == CERTIFICATE_SCHEMA
            and len(mechanized) == 1):
        found.add("inventory_binding")

    child = routes._ROUTES.get(CHILD_PAIR)
    child_slot = inventory.get_slot(REPRESENTED_KIND, 3).mechanized_route or {}
    if (child is None
            or getattr(child.module, "CERTIFICATE_VERSION", None) != CHILD_SCHEMA
            or child.replay is not event_prerequisites.recheck_event_prerequisites_certificate
            or not _named(child.replay, CHILD_MODULE, CHILD_CHECKER)
            or child_slot.get("artifact_coordinate") != CHILD_PAIR[1]
            or not _sensitive(monkeypatch, event_closure.mechanism_digest,
                              "domains/contracts/event_prerequisites.py")):
        found.add("child_route")

    if not all(_sensitive(monkeypatch, polish.mechanism_digest, relative)
               for relative in POLISH_DEPENDENCIES):
        found.add("polish_dependency")
    return found


def _without(key: tuple[str, str]) -> dict[Any, Any]:
    return {pair: route for pair, route in routes._ROUTES.items() if pair != key}


# Positive control.

def test_valid_additive_registration_passes_the_gate(monkeypatch: Any) -> None:
    assert registration_violations(monkeypatch) == set()
    neighbour = routes._ROUTES[(SEMANTIC_VERSION, "SPACE-4.1")]
    assert neighbour.replay is space_closure.recheck_space_closure_certificate
    assert type(neighbour.module) is space_closure.SpaceClosureDescriptor
    assert routes._ROUTES[CHILD_PAIR].replay is (
        event_prerequisites.recheck_event_prerequisites_certificate)


# Negative controls: each changes one monkeypatched registry copy.

def test_missing_route_fails_the_gate(monkeypatch: Any) -> None:
    monkeypatch.setattr(routes, "_ROUTES", _without(PAIR))
    assert registration_violations(monkeypatch) == {"missing_route", "unreachable_route"}


@pytest.mark.parametrize("second", [
    (SEMANTIC_VERSION, "EVENT-4.2"),
    ("verifier-current-object-obligations-2", OBJECTIVE),
], ids=["second_objective", "second_semantic_version"])
def test_duplicate_route_fails_the_gate(second: tuple[str, str], monkeypatch: Any) -> None:
    table = dict(routes._ROUTES)
    table[second] = table[PAIR]
    monkeypatch.setattr(routes, "_ROUTES", table)
    assert registration_violations(monkeypatch) == {"duplicate_route"}


@pytest.mark.parametrize("form", ["space_closure_mechanism", "space_closure_checker",
                                  "space_kind"])
def test_misbound_route_fails_the_gate(form: str, monkeypatch: Any) -> None:
    table = dict(routes._ROUTES)
    original = table[PAIR]
    table[PAIR] = {
        "space_closure_mechanism": routes._Route(
            space_closure.SpaceClosureDescriptor(),
            space_closure.recheck_space_closure_certificate, REPRESENTED_KIND, SCOPE),
        "space_closure_checker": routes._Route(
            original.module, space_closure.recheck_space_closure_certificate,
            REPRESENTED_KIND, SCOPE),
        "space_kind": routes._Route(original.module, original.replay, "SPACE", SCOPE),
    }[form]
    monkeypatch.setattr(routes, "_ROUTES", table)
    assert registration_violations(monkeypatch) == {"misbound_route", "unreachable_route"}


@pytest.mark.parametrize("form", ["dispatcher_refuses_pair", "dispatcher_version_gate"])
def test_registered_but_unreachable_route_fails_the_gate(form: str, monkeypatch: Any) -> None:
    if form == "dispatcher_refuses_pair":
        select = routes.select_current_object_route

        def refusing(**selection: Any) -> Any:
            if (selection["semantic_version"], selection["objective"]) == PAIR:
                raise routes.CurrentObjectRouteRefusal("route registered but not dispatched")
            return select(**selection)

        monkeypatch.setattr(routes, "select_current_object_route", refusing)
    else:
        monkeypatch.setattr(routes, "_SEMANTIC_VERSION", "verifier-current-object-obligations-0")
    assert PAIR in routes._ROUTES
    assert [row["objective"] for row in routes.current_object_route_catalog()].count(OBJECTIVE) == 1
    assert registration_violations(monkeypatch) == {"unreachable_route"}


def test_omitted_canonical_certificate_schema_fails_the_gate(monkeypatch: Any) -> None:
    case = fixture.selected()
    certificate, result = fixture.replay(case)
    assert result["status"] == "PASS"
    assert _redaction_refused(certificate)
    schemas = tuple(schema for schema in engine._CANONICAL_CERTIFICATE_SCHEMAS
                    if schema != CERTIFICATE_SCHEMA)
    monkeypatch.setattr(engine, "_CANONICAL_CERTIFICATE_SCHEMAS", schemas)
    assert not _redaction_refused(certificate)
    assert registration_violations(monkeypatch) == {"schema_unregistered",
                                                     "redaction_not_refused"}


# Further controls on the identities the gate also binds.

def test_missing_inventory_binding_fails_the_gate(monkeypatch: Any) -> None:
    bindings = {key: value for key, value in inventory.MECHANIZED_12_POINT_BINDINGS.items()
                if key != OBJECTIVE}
    monkeypatch.setattr(inventory, "MECHANIZED_12_POINT_BINDINGS", bindings)
    assert registration_violations(monkeypatch) == {"inventory_binding"}


def test_missing_child_route_fails_the_gate(monkeypatch: Any) -> None:
    monkeypatch.setattr(routes, "_ROUTES", _without(CHILD_PAIR))
    assert registration_violations(monkeypatch) == {"child_route"}
