# Acronyms: Boolean satisfiability problem (SAT); unsatisfiable (UNSAT).
from __future__ import annotations

import pytest

from verifier_guided_sat.route import ROUTE_VERSION, RouteError, compile_route
from verifier_guided_sat.sat_backend import CadicalBackend, SatStatus


def route(constraints: list[dict[str, object]]) -> dict[str, object]:
    return {
        "route_version": ROUTE_VERSION,
        "declared_statement": "test-only finite relation",
        "slots": [{"id": "x", "domain": [0, 1]}, {"id": "y", "domain": [0, 1]}],
        "constraints": constraints,
        "decoder": {"kind": "object_fields", "fields": {"left": "x", "right": "y"}},
    }


def test_real_solver_decodes_allowed_pair() -> None:
    compiled = compile_route(
        route([{"kind": "allowed_pairs", "left_slot": "x", "right_slot": "y", "pairs": [[1, 0]]}])
    )
    observed = CadicalBackend().solve(compiled)
    assert observed.status is SatStatus.SAT
    assert observed.candidate == {"left": 1, "right": 0}
    assert observed.unsat_certificate_available is False


def test_route_local_unsat_is_machine_readable_without_certificate_claim() -> None:
    compiled = compile_route(
        route(
            [
                {"kind": "fixed", "slot": "x", "value": 0},
                {"kind": "fixed", "slot": "x", "value": 1},
            ]
        )
    )
    observed = CadicalBackend().solve(compiled)
    assert observed.status is SatStatus.UNSAT
    assert observed.candidate is None
    assert observed.unsat_certificate_available is False
    assert observed.unsat_certificate_size is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"unknown": True},
        {"constraints": [{"kind": "wishful_constraint"}]},
        {"slots": [{"id": "x", "domain": [0, 0]}]},
    ],
)
def test_malformed_routes_fail_closed(mutation: dict[str, object]) -> None:
    payload = route([])
    payload.update(mutation)
    with pytest.raises(RouteError):
        compile_route(payload)


def test_formula_digest_changes_when_route_changes() -> None:
    left = compile_route(route([{"kind": "fixed", "slot": "x", "value": 0}]))
    right = compile_route(route([{"kind": "fixed", "slot": "x", "value": 1}]))
    assert left.route_digest != right.route_digest
    assert left.formula_digest != right.formula_digest
