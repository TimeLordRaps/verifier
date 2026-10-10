"""Registration gate for the TIME-3.1 strict-order objective, from hand-written identities.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). Every expected
identity below is written out by hand: the objective pair, coordinate, semantic
version, mechanism module, checker, certificate schema and the polish
dependency on the TIME-2.1 child. None is read from a census, a count or a
generated inventory, so a registry cannot pass this gate by agreeing with
itself. The gate checks one objective, never how many routes, slots or schemas
exist in total. Negative controls change monkeypatched registries or in-memory
copies of module source, restored when each test ends; nothing on disk changes.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Callable

import pytest

from verifier.domains import inventory
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import space_closure, time_order
from verifier.privacy import engine
from verifier.privacy import (DisclosureBound, DisclosureSurface, EmissionContext,
                              EmissionEvaluator, EmissionRefusalError, ObserverParty)
from verifier.runtime import polish

import test_current_time_strict as fixture


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
OBJECTIVE = "TIME-3.1"
PAIR = (SEMANTIC_VERSION, OBJECTIVE)
REPRESENTED_KIND = "TIME"
TIER = 3
SCOPE = "selected_strict_declared_clock_order"
MECHANISM_MODULE = "verifier.domains.contracts.time_strict"
CHECKER = "recheck_time_strict_certificate"
CERTIFICATE_SCHEMA = "verifier-current-time-strict-certificate-1"
CHILD_OBJECTIVE = "TIME-2.1"
CHILD_PAIR = (SEMANTIC_VERSION, CHILD_OBJECTIVE)
CHILD_TIER = 2
CHILD_MODULE = "verifier.domains.contracts.time_order"
CHILD_CHECKER = "recheck_time_order_certificate"
CHILD_SCHEMA = "verifier-current-time-order-certificate-1"
POLISH_DEPENDENCIES = (
    "domains/contracts/time_strict.py", "standard/CURRENT_TIME_STRICT.md",
    "domains/contracts/time_order.py", "standard/CURRENT_TIME_ORDER.md",
)
INVENTORY_BRANCH = (
    "            elif kind == ObjectKind.TIME and tier == MetaTier.STATICS:\n"
    "                mechanized_coord = time_strict.COORDINATE\n")
POLISH_PAIR = '             "domains/contracts/time_strict.py", "standard/CURRENT_TIME_STRICT.md",\n'


def strict() -> ModuleType:
    return importlib.import_module(MECHANISM_MODULE)


def _named(function: Any, module: str, name: str) -> bool:
    return (getattr(function, "__module__", None) == module
            and getattr(function, "__qualname__", None) == name)


def _carries_time_strict(route: Any) -> bool:
    return (_named(route.replay, MECHANISM_MODULE, CHECKER)
            or getattr(route.module, "CERTIFICATE_VERSION", None) == CERTIFICATE_SCHEMA)


def _redaction_refused(certificate: bytes) -> bool:
    """Ask the real privacy engine to drop retained evidence from a real certificate."""
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


def _sensitive(monkeypatch: pytest.MonkeyPatch, digest: Callable[[], str],
               relative: str) -> bool:
    """Whether changing one source file's bytes changes the given installed digest."""
    target = Path(strict().__file__).parents[2] / relative
    before = digest()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged registration dependency\n" if path == target else data

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", changed)
        after = digest()
    return target.is_file() and after != before


def _copy_without(monkeypatch: pytest.MonkeyPatch, module: ModuleType, removed: str,
                  name: str) -> ModuleType:
    """Execute an in-memory copy of a module's source with one exact fragment removed."""
    path = Path(module.__file__)
    source = path.read_text(encoding="utf-8")
    assert source.count(removed) == 1, "fragment must occur exactly once"
    copy = ModuleType(name)
    copy.__file__ = str(path)
    monkeypatch.setitem(sys.modules, name, copy)
    exec(compile(source.replace(removed, ""), str(path), "exec"), copy.__dict__)
    return copy


def registration_violations(monkeypatch: pytest.MonkeyPatch, *,
                            inventory_module: ModuleType = inventory,
                            polish_module: ModuleType = polish) -> set[str]:
    """Name every way the live registries fail the hand-written TIME-3.1 identities."""
    module = strict()
    found: set[str] = set()
    registration = module.registration()
    if (module.__name__ != MECHANISM_MODULE
            or module.SEMANTIC_VERSION != SEMANTIC_VERSION
            or module.COORDINATE != OBJECTIVE
            or module.CERTIFICATE_VERSION != CERTIFICATE_SCHEMA
            or module.SCOPE != SCOPE
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
                if _carries_time_strict(candidate)]
    if len(rows) > 1 or len(carriers) > 1:
        found.add("duplicate_route")
    if route is not None and not (
            type(route.module).__name__ == "TimeStrictDescriptor"
            and type(route.module).__module__ == MECHANISM_MODULE
            and route.module.CERTIFICATE_VERSION == CERTIFICATE_SCHEMA
            and route.module.PROPOSITION_DIGEST == module.PROPOSITION_DIGEST
            and route.replay is module.recheck_time_strict_certificate
            and _named(route.replay, MECHANISM_MODULE, CHECKER)
            and route.fixed_kind == REPRESENTED_KIND
            and route.scope == SCOPE
            and all(row["certificate_schema_version"] == CERTIFICATE_SCHEMA
                    and row["represented_kind_rule"] == REPRESENTED_KIND
                    and row["scope"] == SCOPE
                    and row["proposition_digest"] == module.PROPOSITION_DIGEST
                    for row in rows)):
        found.add("misbound_route")

    case = fixture.bind(fixture.child((2, 5, 7)))
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

    binding = inventory_module.MECHANIZED_12_POINT_BINDINGS.get(OBJECTIVE)
    if not (type(binding) is dict
            and binding.get("artifact_coordinate") == OBJECTIVE
            and binding.get("checking_mechanism") == MECHANISM_MODULE + "." + CHECKER
            and binding.get("resulting_evidence") == CERTIFICATE_SCHEMA
            and binding.get("exact_claim") == registration["proposition"]
            and OBJECTIVE in binding.get("reproduction_instructions", "")):
        found.add("inventory_binding")
    slot = inventory_module.get_slot(REPRESENTED_KIND, TIER)
    mechanized = [row for row in inventory_module.slot_inventory()
                  if row.get("mechanized") and row.get("coordinate") == OBJECTIVE]
    if not (slot.mechanized and slot.coordinate == OBJECTIVE
            and slot.mechanized_route is not None
            and slot.mechanized_route is binding
            and len(mechanized) == 1):
        found.add("inventory_unreachable")

    child = routes._ROUTES.get(CHILD_PAIR)
    child_slot = inventory_module.get_slot(REPRESENTED_KIND, CHILD_TIER)
    if (child is None
            or getattr(child.module, "CERTIFICATE_VERSION", None) != CHILD_SCHEMA
            or child.replay is not time_order.recheck_time_order_certificate
            or not _named(child.replay, CHILD_MODULE, CHILD_CHECKER)
            or not child_slot.mechanized
            or (child_slot.mechanized_route or {}).get("artifact_coordinate") != CHILD_OBJECTIVE
            or not _sensitive(monkeypatch, module.mechanism_digest,
                              "domains/contracts/time_order.py")
            or not _sensitive(monkeypatch, module.mechanism_digest,
                              "standard/CURRENT_TIME_ORDER.md")):
        found.add("child_route")

    if not all(_sensitive(monkeypatch, polish_module.mechanism_digest, relative)
               for relative in POLISH_DEPENDENCIES):
        found.add("polish_dependency")
    return found


def _without(key: tuple[str, str]) -> dict[Any, Any]:
    return {pair: route for pair, route in routes._ROUTES.items() if pair != key}


# Positive control.

def test_valid_additive_registration_passes_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    assert registration_violations(monkeypatch) == set()
    neighbour = routes._ROUTES[(SEMANTIC_VERSION, "SPACE-4.1")]
    assert neighbour.replay is space_closure.recheck_space_closure_certificate
    assert routes._ROUTES[CHILD_PAIR].replay is time_order.recheck_time_order_certificate
    assert inventory.get_slot(REPRESENTED_KIND, CHILD_TIER).coordinate == CHILD_OBJECTIVE


# Negative controls: each changes one monkeypatched registry or in-memory copy.

def test_missing_route_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_ROUTES", _without(PAIR))
    assert registration_violations(monkeypatch) == {"missing_route", "unreachable_route"}


@pytest.mark.parametrize("second", [
    (SEMANTIC_VERSION, "TIME-3.2"),
    ("verifier-current-object-obligations-2", OBJECTIVE),
], ids=["second_objective", "second_semantic_version"])
def test_duplicate_route_fails_the_gate(second: tuple[str, str],
                                        monkeypatch: pytest.MonkeyPatch) -> None:
    table = dict(routes._ROUTES)
    table[second] = table[PAIR]
    monkeypatch.setattr(routes, "_ROUTES", table)
    assert registration_violations(monkeypatch) == {"duplicate_route"}


@pytest.mark.parametrize("form", ["child_route_object", "child_checker", "event_kind"])
def test_misbound_route_fails_the_gate(form: str, monkeypatch: pytest.MonkeyPatch) -> None:
    table = dict(routes._ROUTES)
    original = table[PAIR]
    table[PAIR] = {
        "child_route_object": table[CHILD_PAIR],
        "child_checker": routes._Route(original.module,
                                       time_order.recheck_time_order_certificate,
                                       REPRESENTED_KIND, SCOPE),
        "event_kind": routes._Route(original.module, original.replay, "EVENT", SCOPE),
    }[form]
    monkeypatch.setattr(routes, "_ROUTES", table)
    assert registration_violations(monkeypatch) == {"misbound_route", "unreachable_route"}


@pytest.mark.parametrize("form", ["dispatcher_refuses_pair", "dispatcher_version_gate"])
def test_registered_but_unreachable_route_fails_the_gate(
        form: str, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_omitted_canonical_certificate_schema_fails_the_gate(
        monkeypatch: pytest.MonkeyPatch) -> None:
    case = fixture.bind(fixture.child((2, 5, 7)))
    certificate, result = fixture.replay(case)
    assert result["status"] == "PASS"
    assert _redaction_refused(certificate)
    schemas = tuple(schema for schema in engine._CANONICAL_CERTIFICATE_SCHEMAS
                    if schema != CERTIFICATE_SCHEMA)
    assert len(schemas) == len(engine._CANONICAL_CERTIFICATE_SCHEMAS) - 1
    monkeypatch.setattr(engine, "_CANONICAL_CERTIFICATE_SCHEMAS", schemas)
    assert not _redaction_refused(certificate)
    assert registration_violations(monkeypatch) == {"schema_unregistered",
                                                     "redaction_not_refused"}


def test_missing_inventory_binding_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    bindings = {key: value for key, value in inventory.MECHANIZED_12_POINT_BINDINGS.items()
                if key != OBJECTIVE}
    monkeypatch.setattr(inventory, "MECHANIZED_12_POINT_BINDINGS", bindings)
    assert registration_violations(monkeypatch) == {"inventory_binding",
                                                     "inventory_unreachable"}


def test_misbound_inventory_binding_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    bindings = dict(inventory.MECHANIZED_12_POINT_BINDINGS)
    bindings[OBJECTIVE] = dict(bindings[OBJECTIVE], checking_mechanism=(
        CHILD_MODULE + "." + CHILD_CHECKER))
    monkeypatch.setattr(inventory, "MECHANIZED_12_POINT_BINDINGS", bindings)
    assert registration_violations(monkeypatch) == {"inventory_binding"}


def test_unreachable_inventory_branch_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    copy = _copy_without(monkeypatch, inventory, INVENTORY_BRANCH,
                         "verifier.domains.inventory_without_time_statics_branch")
    assert OBJECTIVE in copy.MECHANIZED_12_POINT_BINDINGS
    assert not copy.get_slot(REPRESENTED_KIND, TIER).mechanized
    assert registration_violations(monkeypatch, inventory_module=copy) == {
        "inventory_unreachable"}


def test_missing_polish_dependency_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    copy = _copy_without(monkeypatch, polish, POLISH_PAIR,
                         "verifier.runtime.polish_without_time_strict_pair")
    assert copy.mechanism_digest() != polish.mechanism_digest()
    assert registration_violations(monkeypatch, polish_module=copy) == {"polish_dependency"}


def test_missing_child_route_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_ROUTES", _without(CHILD_PAIR))
    assert registration_violations(monkeypatch) == {"child_route"}


def test_drifted_mechanism_identity_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(strict(), "SCOPE", "selected_declared_clock_order")
    assert registration_violations(monkeypatch) == {"mechanism_identity"}
