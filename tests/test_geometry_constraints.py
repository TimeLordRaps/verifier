"""Verifier Standard (VSTD) explicit geometry constraint tests.

Terminology: conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
unsatisfiable (UNSAT); reverse unit propagation (RUP); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
All Boolean values are dimensionless declared propositions, not physical truth.
"""

from __future__ import annotations

import importlib
import itertools
import json
from dataclasses import replace
from typing import Any

import pytest

from verifier.core.geometry import (
    Coordinate, CoordinateJudgment, CoordinateStatus, Facet, Grain, Locus,
    LocusKind, Stratum, Subject, VerificationGeometry, VerificationSurface,
)
from verifier.interoperability.geometry_conflicts import SharedPropositionIdentity
from verifier.interoperability import geometry_constraints as constraints


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def geometry() -> VerificationGeometry:
    return VerificationGeometry(
        geometry_id="geometry:configuration", primary_subject_id="subject:configuration",
        subjects=[Subject("subject:configuration", "Fictional configuration", "1")],
        loci=[Locus("locus:configuration", "subject:configuration", "Configuration", LocusKind.OBJECT,
                    Grain.SUBJECT, Stratum.REQUIREMENT, "configuration")],
        facets=[Facet("facet:p", "Option p", "Option p is chosen."), Facet("facet:q", "Option q", "Option q is chosen.")],
        coordinates=[Coordinate("coordinate:p", "locus:configuration", "facet:p"), Coordinate("coordinate:q", "locus:configuration", "facet:q")],
        surface=VerificationSurface("surface:configuration", "subject:configuration", ("coordinate:p", "coordinate:q")),
        judgments=[CoordinateJudgment("coordinate:p", CoordinateStatus.INDETERMINATE), CoordinateJudgment("coordinate:q", CoordinateStatus.INDETERMINATE)],
    )


def problem(formula: tuple[tuple[int, ...], ...] = ((1,),), *, source: VerificationGeometry | None = None) -> constraints.GeometryConstraintProblem:
    source = geometry() if source is None else source
    bindings = tuple(SharedPropositionIdentity(name, source.canonical_digest(), "coordinate:" + name) for name in ("p", "q"))
    clauses = tuple(constraints.GeometryClause("clause:" + str(index), tuple(constraints.SignedProposition("p" if abs(lit) == 1 else "q", lit > 0) for lit in clause)) for index, clause in enumerate(formula))
    return constraints.prepare_geometry_constraints((canonical(source.to_dict()),), bindings, clauses)


def checked(item: constraints.GeometryConstraintProblem, result: constraints.GeometryConstraintResult, **kwargs: Any) -> constraints.GeometryConstraintResult:
    return constraints.recheck_geometry_constraints(item, result, expected_problem_digest=item.canonical_digest(), **kwargs)


def forbidden(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("this path must not execute")


def test_experimental_geometry_constraint_module_exists() -> None:
    module = importlib.import_module("verifier.interoperability.geometry_constraints")
    assert callable(module.prepare_geometry_constraints)


def test_all_512_two_variable_formulas_against_independent_truth_table() -> None:
    possible = tuple(tuple(lit for lit in (left, right) if lit) for left in (0, 1, -1) for right in (0, 2, -2))
    for mask in range(512):
        formula = tuple(clause for index, clause in enumerate(possible) if mask & (1 << index))
        satisfying = tuple(values for values in itertools.product((False, True), repeat=2)
                           if all(any(values[abs(lit) - 1] == (lit > 0) for lit in clause) for clause in formula))
        item = problem(formula)
        result = constraints.solve_geometry_constraints(item)
        assert result.status == ("SAT" if satisfying else "UNSAT"), (mask, formula)
        if satisfying:
            assert tuple(value for _, value in result.model) in satisfying
        else:
            assert result.certificate_json is not None
        assert checked(item, result) == result


@pytest.mark.parametrize("formula,status", [((), "SAT"), (((),), "UNSAT"), (((1, -1),), "SAT"), (((1,), (-1,)), "UNSAT")])
def test_empty_tautological_and_contradictory_formulas(formula: tuple[tuple[int, ...], ...], status: str) -> None:
    source = geometry()
    before = canonical(source.to_dict())
    item = problem(formula, source=source)
    result = constraints.solve_geometry_constraints(item)
    assert result.status == status
    assert canonical(source.to_dict()) == before
    assert all(judgment.status is CoordinateStatus.INDETERMINATE for judgment in source.judgments)


@pytest.mark.parametrize("formula", [((1,),), ((1,), (-1,))])
def test_recheck_never_calls_producer(formula: tuple[tuple[int, ...], ...], monkeypatch: pytest.MonkeyPatch) -> None:
    item = problem(formula)
    result = constraints.solve_geometry_constraints(item)
    monkeypatch.setattr(constraints.ProofProducingDPLL, "solve", forbidden)
    assert checked(item, result) == result


@pytest.mark.parametrize("mutation", ["coordinate", "clause_name", "geometry", "status", "unused_geometry"])
def test_identical_numeric_formula_does_not_alias_semantic_problem(mutation: str) -> None:
    original = problem(((1,), (-1,)))
    result = constraints.solve_geometry_constraints(original)
    if mutation == "coordinate":
        bindings = tuple(replace(binding, coordinate_id="coordinate:q" if binding.coordinate_id.endswith("p") else "coordinate:p") for binding in original.bindings)
        changed = constraints.prepare_geometry_constraints(original.geometries, bindings, original.clauses)
    elif mutation == "clause_name":
        changed = constraints.prepare_geometry_constraints(original.geometries, original.bindings, (replace(original.clauses[0], clause_id="clause:0-renamed"), original.clauses[1]))
    elif mutation == "unused_geometry":
        additional = geometry()
        additional.geometry_id = "geometry:unused"
        changed = constraints.prepare_geometry_constraints(original.geometries + (canonical(additional.to_dict()),), original.bindings, original.clauses)
    else:
        source = geometry()
        if mutation == "status":
            source.judgments[0] = CoordinateJudgment("coordinate:p", CoordinateStatus.STALE)
        else:
            source.geometry_id = "geometry:changed"
        changed = problem(((1,), (-1,)), source=source)
    assert constraints._formula(changed) == constraints._formula(original)
    assert changed.canonical_digest() != original.canonical_digest()
    forged = replace(result, problem_digest=changed.canonical_digest())
    with pytest.raises(ValueError, match="separately supplied"):
        constraints.recheck_geometry_constraints(changed, forged, expected_problem_digest=original.canonical_digest())


def test_no_status_to_truth_units() -> None:
    source = geometry()
    source.judgments[0] = CoordinateJudgment("coordinate:p", CoordinateStatus.STALE)
    for formula in (((1,),), ((-1,),)):
        assert constraints.solve_geometry_constraints(problem(formula, source=source)).status == "SAT"


@pytest.mark.parametrize("model", [(('p', False), ('q', False)), (('p', 1), ('q', False)), (('p', True),), (('q', False), ('p', True)), (('wrong', True), ('q', False)), (("p", True), ("q", False), ("extra", True))])
def test_tampered_models_rejected(model: Any) -> None:
    item = problem()
    result = constraints.GeometryConstraintResult(item.canonical_digest(), "SAT", model)
    with pytest.raises(ValueError):
        checked(item, result)


@pytest.mark.parametrize("field,value", [("n_vars", True), ("n_vars", "2"), ("n_vars", 2.0), ("n_vars", 1), ("source_clause_count", 3), ("step_count", 0), ("step_count", True), ("max_proof_steps", 0), ("max_proof_steps", 257), ("proof_format", "other"), ("proof", [[True], []]), ("proof", [[0], []]), ("proof", [[3], []]), ("proof", [[1.0], []]), ("proof", [["1"], []]), ("proof", [[1, 1], []]), ("proof", [[2, 1], []]), ("proof", [])])
def test_malformed_proof_rejected_before_checker(field: str, value: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    item = problem(((1,), (-1,)))
    result = constraints.solve_geometry_constraints(item)
    document = json.loads(result.certificate_json)
    document[field] = value
    if field == "proof":
        document["step_count"] = len(value)
    monkeypatch.setattr(constraints.RefutationChecker, "check", forbidden)
    with pytest.raises(ValueError):
        checked(item, replace(result, certificate_json=canonical(document)))


def test_validly_shaped_unrelated_proof_is_not_solver_authority() -> None:
    contradiction = problem(((1,), (-1,)))
    result = constraints.solve_geometry_constraints(contradiction)
    compatible = problem(((1,), (2,)))
    with pytest.raises(ValueError, match="not accepted"):
        checked(compatible, replace(result, problem_digest=compatible.canonical_digest()))


def test_proof_transport_is_strict() -> None:
    item = problem(((1,), (-1,)))
    result = constraints.solve_geometry_constraints(item)
    document = json.loads(result.certificate_json)
    invalid = [b" " + result.certificate_json, canonical({**document, "unknown": 1}), bytearray(result.certificate_json), b"[" * 33 + b"]" * 33, b" " * (constraints.MAX_PROOF_BYTES + 1)]
    for raw in invalid:
        with pytest.raises(ValueError):
            checked(item, replace(result, certificate_json=raw))


def test_budgets_preserve_unknown_and_do_not_claim_historical_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    item = problem(((1, 2),))
    result = constraints.solve_geometry_constraints(item, bounds=constraints.GeometryConstraintBounds(max_decision_depth=0))
    assert result.status == "UNKNOWN" and result.model is None and result.certificate_json is None
    assert checked(item, result) == result
    contradiction = problem(((1,), (-1,)))
    assert constraints.solve_geometry_constraints(contradiction, bounds=constraints.GeometryConstraintBounds(max_proof_steps=0)).status == "UNKNOWN"
    proof = constraints.solve_geometry_constraints(contradiction)
    model = constraints.solve_geometry_constraints(item)
    monkeypatch.setattr(constraints.RefutationChecker, "check", forbidden)
    for source, witness in ((contradiction, proof), (item, model)):
        assert checked(source, witness, bounds=constraints.GeometryConstraintBounds(max_check_work=0)).status == "UNKNOWN"
    assert checked(contradiction, proof, bounds=constraints.GeometryConstraintBounds(max_proof_steps=0)).status == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("max_decision_depth", True), ("max_decision_depth", -1), ("max_decision_depth", 13), ("max_proof_steps", 257), ("max_proof_steps", "1"), ("max_check_work", 1.0), ("max_check_work", 8000001)])
def test_bounds_exact_types_and_hard_caps(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        constraints.GeometryConstraintBounds(**{field: value})


def test_admission_rejects_noncanonical_or_unbounded_geometry() -> None:
    item = problem()
    for raw in (b" " + item.geometries[0], bytearray(item.geometries[0]), b"[" * 33 + b"]" * 33, b" " * (constraints.MAX_GEOMETRY_BYTES + 1)):
        with pytest.raises(ValueError):
            constraints.prepare_geometry_constraints((raw,), item.bindings, item.clauses)
    document = json.loads(item.geometries[0])
    document.pop("residuals")
    with pytest.raises(ValueError):
        constraints.prepare_geometry_constraints((canonical(document),), item.bindings, item.clauses)
    with pytest.raises(ValueError):
        constraints.prepare_geometry_constraints(item.geometries * 2, item.bindings, item.clauses)


def test_binding_and_clause_admission_is_exact() -> None:
    item = problem()
    invalid_bindings = [list(item.bindings), item.bindings * 2, (replace(item.bindings[0], coordinate_id="absent"),), (replace(item.bindings[0], geometry_digest="0" * 64),)]
    for bindings in invalid_bindings:
        with pytest.raises(ValueError):
            constraints.prepare_geometry_constraints(item.geometries, bindings, item.clauses)
    invalid_clauses = [list(item.clauses), item.clauses * 2, (constraints.GeometryClause("unknown", (constraints.SignedProposition("unbound", True),)),), (constraints.GeometryClause("wrong", (constraints.SignedProposition("p", 1),)),), (constraints.GeometryClause("duplicates", (constraints.SignedProposition("p", True),) * 2),), (constraints.GeometryClause("wrong", [constraints.SignedProposition("p", True)]),)]
    for clauses in invalid_clauses:
        with pytest.raises(ValueError):
            constraints.prepare_geometry_constraints(item.geometries, item.bindings, clauses)


def test_preparation_snapshots_nested_declared_records() -> None:
    item = problem()
    binding, clause, literal = item.bindings[0], item.clauses[0], item.clauses[0].literals[0]
    snapshot = constraints.prepare_geometry_constraints(item.geometries, item.bindings, item.clauses)
    expected = snapshot.canonical_digest()
    object.__setattr__(binding, "coordinate_id", "changed")
    object.__setattr__(literal, "positive", False)
    object.__setattr__(clause, "clause_id", "changed")
    assert snapshot.canonical_digest() == expected
    assert constraints.solve_geometry_constraints(snapshot).status == "SAT"


def test_explicit_shared_identity_and_empty_declarations() -> None:
    item = problem()
    binding = replace(item.bindings[1], proposition_id="p")
    shared = constraints.prepare_geometry_constraints(item.geometries, (item.bindings[0], binding), item.clauses)
    assert constraints.solve_geometry_constraints(shared).model == (("p", True),)
    empty = constraints.prepare_geometry_constraints(item.geometries, (), ())
    assert constraints.solve_geometry_constraints(empty).model == ()


def test_canonical_order_not_input_tuple_order() -> None:
    item = problem(((1,), (-1,)))
    reordered = constraints.prepare_geometry_constraints(item.geometries, item.bindings[::-1], item.clauses[::-1])
    assert reordered == item
    assert reordered.canonical_digest() == item.canonical_digest()


def test_result_digest_exact_type_and_mixed_witnesses() -> None:
    class Digest(str):
        pass
    item = problem()
    result = constraints.solve_geometry_constraints(item)
    for malformed in (replace(result, problem_digest=Digest(result.problem_digest)), replace(result, status="UNKNOWN"), replace(result, certificate_json=b"{}"), replace(result, status="other")):
        with pytest.raises(ValueError):
            checked(item, malformed)


def test_producer_boolean_model_key_is_not_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    item = problem()
    monkeypatch.setattr(constraints.ProofProducingDPLL, "solve", lambda self: SimpleNamespace(satisfiable=True, model={True: True, 2: False}))
    with pytest.raises(ValueError, match="exact total model"):
        constraints.solve_geometry_constraints(item)


def test_missing_terminal_empty_clause_rejected_even_without_check_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    item = problem(((1,), (-1,)))
    result = constraints.solve_geometry_constraints(item)
    document = json.loads(result.certificate_json)
    document["proof"] = [[1]]
    document["step_count"] = 1
    monkeypatch.setattr(constraints.RefutationChecker, "check", forbidden)
    for bounds in (constraints.GeometryConstraintBounds(max_check_work=0), constraints.GeometryConstraintBounds(max_proof_steps=0)):
        with pytest.raises(ValueError, match="terminal empty"):
            checked(item, replace(result, certificate_json=canonical(document)), bounds=bounds)


def wide_problem(count: int, *, clauses: bool = True) -> constraints.GeometryConstraintProblem:
    source = geometry()
    source.facets = [Facet("facet:" + str(index), "Choice", "A fictional choice.") for index in range(count)]
    source.coordinates = [Coordinate("coordinate:" + str(index), "locus:configuration", "facet:" + str(index)) for index in range(count)]
    source.judgments = [CoordinateJudgment(item.coordinate_id, CoordinateStatus.INDETERMINATE) for item in source.coordinates]
    source.surface = replace(source.surface, coordinate_ids=tuple(item.coordinate_id for item in source.coordinates))
    bindings = tuple(SharedPropositionIdentity("p" + str(index), source.canonical_digest(), item.coordinate_id) for index, item in enumerate(source.coordinates))
    declared = (constraints.GeometryClause("wide", tuple(constraints.SignedProposition(item.proposition_id, True) for item in bindings)),) if clauses else ()
    return constraints.prepare_geometry_constraints((canonical(source.to_dict()),), bindings, declared)


def test_variable_record_clause_and_literal_hard_caps() -> None:
    with pytest.raises(ValueError, match="variable admission"):
        wide_problem(33)
    item = problem()
    document = json.loads(item.geometries[0])
    document["judgments"] *= 129
    with pytest.raises(ValueError, match="record admission"):
        constraints.prepare_geometry_constraints((canonical(document),), item.bindings, item.clauses)
    many = tuple(replace(item.clauses[0], clause_id="clause:" + str(index)) for index in range(129))
    with pytest.raises(ValueError, match="clauses must"):
        constraints.prepare_geometry_constraints(item.geometries, item.bindings, many)
    wide = wide_problem(32)
    many = tuple(replace(wide.clauses[0], clause_id="clause:" + str(index)) for index in range(33))
    with pytest.raises(ValueError, match="literal admission"):
        constraints.prepare_geometry_constraints(wide.geometries, wide.bindings, many)


def test_search_work_ceiling_precedes_producer(monkeypatch: pytest.MonkeyPatch) -> None:
    item = wide_problem(32)
    clauses = tuple(replace(item.clauses[0], clause_id="clause:" + str(index)) for index in range(32))
    item = constraints.prepare_geometry_constraints(item.geometries, item.bindings, clauses)
    monkeypatch.setattr(constraints.ProofProducingDPLL, "solve", forbidden)
    assert constraints.solve_geometry_constraints(item).status == "UNKNOWN"


def test_producer_mutated_numeric_input_cannot_replace_bound_formula(monkeypatch: pytest.MonkeyPatch) -> None:
    item = problem(((1,),))
    original_constructor = constraints.ProofProducingDPLL

    def substitute(n_vars: int, formula: list[list[int]], **kwargs: Any) -> Any:
        formula[:] = [[-1]]
        return original_constructor(n_vars, formula, **kwargs)

    monkeypatch.setattr(constraints, "ProofProducingDPLL", substitute)
    with pytest.raises(ValueError, match="does not satisfy"):
        constraints.solve_geometry_constraints(item)
    assert item.clauses[0].literals[0].positive is True


def test_geometry_duplicate_keys_and_nonfinite_values_refused() -> None:
    item = problem()
    for raw in (b'{"schema_version":"VSTD-2","schema_version":"VSTD-2"}', b'{"x":NaN}', b'{"x":Infinity}'):
        with pytest.raises(ValueError):
            constraints.prepare_geometry_constraints((raw,), item.bindings, item.clauses)
