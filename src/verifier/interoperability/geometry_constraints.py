"""Experimental Verifier Standard (VSTD) geometry-bound Boolean constraints.

Terminology: conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
unsatisfiable (UNSAT); Davis-Putnam-Logemann-Loveland (DPLL); reverse unit
propagation (RUP); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). Values are dimensionless explicitly declared propositions.
No geometry judgment, name, or topological edge becomes a truth literal.
SAT and checked UNSAT concern only the supplied finite formula, never geometry
closure, physical truth, authorization, independence, or numbered conformance.
Rechecking uses the existing VSTD4-RUP-1 proof or a directly checked model and
never calls its producer. UNKNOWN carries no witness and does not prove why a
previous search stopped. Hard admission caps and conservative work estimates
bound this local calculation; they are not wall-clock timeouts or a sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from verifier.core.geometry_io import load_verification_geometry
from verifier.core.receipt import strict_json_loads
from verifier.core.refutation import ProofProducingDPLL, RefutationCertificate, RefutationChecker
from verifier.interoperability.geometry_conflicts import SharedPropositionIdentity


MAX_GEOMETRY_BYTES = 256 * 1024
MAX_VARIABLES = 32
MAX_CLAUSES = 128
MAX_LITERALS = 1024
MAX_PROOF_STEPS = 256
MAX_PROOF_BYTES = 128 * 1024
MAX_SEARCH_WORK = 8_000_000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(value: Any) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128 or value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError("identifier must be bounded nonempty text")
    return value


def _hex(value: Any) -> str:
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("expected digest must be 64 lowercase hexadecimal characters")
    return value


def _integer(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("bound or count must be an exact nonnegative bounded integer")
    return value


def _json(data: bytes, limit: int) -> Any:
    if type(data) is not bytes or len(data) > limit:
        raise ValueError("canonical document must be bounded immutable bytes")
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32: raise ValueError("document nesting exceeds admission bound")
        elif byte in (93, 125): depth -= 1
    value = strict_json_loads(data)
    pending, count = [value], 0
    while pending:
        item = pending.pop()
        count += 1
        if count > 16384: raise ValueError("document value count exceeds admission bound")
        if type(item) is dict:
            pending.extend(item.keys())
            pending.extend(item.values())
        elif type(item) is list: pending.extend(item)
        elif type(item) is str and len(item) > 8192:
            raise ValueError("document text exceeds admission bound")
    if _canonical(value) != data:
        raise ValueError("document must already have canonical transport")
    return value


@dataclass(frozen=True)
class SignedProposition:
    proposition_id: str
    positive: bool


@dataclass(frozen=True)
class GeometryClause:
    clause_id: str
    literals: tuple[SignedProposition, ...]


@dataclass(frozen=True)
class GeometryConstraintBounds:
    max_decision_depth: int = 10
    max_proof_steps: int = MAX_PROOF_STEPS
    max_check_work: int = 2_000_000

    def __post_init__(self) -> None:
        _integer(self.max_decision_depth, 12)
        _integer(self.max_proof_steps, MAX_PROOF_STEPS)
        _integer(self.max_check_work, 8_000_000)


@dataclass(frozen=True)
class GeometryConstraintProblem:
    geometries: tuple[bytes, ...]
    bindings: tuple[SharedPropositionIdentity, ...]
    clauses: tuple[GeometryClause, ...]

    def canonical_digest(self) -> str:
        return _digest(_canonical(_material(_admit(self))))


@dataclass(frozen=True)
class GeometryConstraintResult:
    problem_digest: str
    status: str
    model: tuple[tuple[str, bool], ...] | None = None
    certificate_json: bytes | None = None


def prepare_geometry_constraints(geometries: tuple[bytes, ...], bindings: tuple[SharedPropositionIdentity, ...], clauses: tuple[GeometryClause, ...]) -> GeometryConstraintProblem:
    """Bind complete canonical geometries and explicit declarations, not statuses."""
    if type(geometries) is not tuple or not 1 <= len(geometries) <= 4:
        raise ValueError("one to four canonical geometries required")
    if any(type(raw) is not bytes for raw in geometries) or sum(map(len, geometries)) > MAX_GEOMETRY_BYTES:
        raise ValueError("geometry byte admission bound exceeded")
    coordinates, retained = {}, {}
    for raw in geometries:
        value = _json(raw, MAX_GEOMETRY_BYTES)
        if type(value) is not dict or sum(len(item) for item in value.values() if type(item) is list) > 256:
            raise ValueError("geometry record admission bound exceeded")
        geometry = load_verification_geometry(value)
        if _canonical(geometry.to_dict()) != raw:
            raise ValueError("geometry must use its complete canonical representation")
        digest = geometry.canonical_digest()
        if digest in retained: raise ValueError("duplicate geometry")
        retained[digest], coordinates[digest] = raw, {item.coordinate_id for item in geometry.coordinates}
    if type(bindings) is not tuple or len(bindings) > 128:
        raise ValueError("bindings must be a bounded tuple")
    copied_bindings, bound_coordinates, propositions = [], set(), set()
    for item in bindings:
        if type(item) is not SharedPropositionIdentity: raise ValueError("exact shared proposition bindings required")
        proposition, digest, coordinate = _text(item.proposition_id), _hex(item.geometry_digest), _text(item.coordinate_id)
        if digest not in coordinates or coordinate not in coordinates[digest]: raise ValueError("binding does not identify a supplied geometry coordinate")
        if (digest, coordinate) in bound_coordinates: raise ValueError("duplicate or ambiguous coordinate binding")
        bound_coordinates.add((digest, coordinate))
        propositions.add(proposition)
        copied_bindings.append(SharedPropositionIdentity(proposition, digest, coordinate))
    if len(propositions) > MAX_VARIABLES: raise ValueError("variable admission bound exceeded")
    if type(clauses) is not tuple or len(clauses) > MAX_CLAUSES: raise ValueError("clauses must be a bounded tuple")
    copied_clauses, clause_ids, total = [], set(), 0
    for clause in clauses:
        if type(clause) is not GeometryClause: raise ValueError("exact named clauses required")
        name = _text(clause.clause_id)
        if name in clause_ids: raise ValueError("duplicate clause identifier")
        clause_ids.add(name)
        if type(clause.literals) is not tuple or len(clause.literals) > 2 * MAX_VARIABLES: raise ValueError("clause width admission bound exceeded")
        literals = []
        for literal in clause.literals:
            if type(literal) is not SignedProposition or type(literal.positive) is not bool: raise ValueError("literal requires an exact proposition and Boolean sign")
            proposition = _text(literal.proposition_id)
            if proposition not in propositions: raise ValueError("clause references an unbound proposition")
            literals.append((proposition, literal.positive))
        if len(set(literals)) != len(literals): raise ValueError("duplicate literal")
        total += len(literals)
        if total > MAX_LITERALS: raise ValueError("literal admission bound exceeded")
        copied_clauses.append(GeometryClause(name, tuple(SignedProposition(*item) for item in sorted(literals))))
    return GeometryConstraintProblem(tuple(retained[key] for key in sorted(retained)),
        tuple(sorted(copied_bindings, key=lambda item: (item.proposition_id, item.geometry_digest, item.coordinate_id))),
        tuple(sorted(copied_clauses, key=lambda item: item.clause_id)))


def _admit(problem: GeometryConstraintProblem) -> GeometryConstraintProblem:
    if type(problem) is not GeometryConstraintProblem: raise ValueError("exact geometry constraint problem required")
    return prepare_geometry_constraints(problem.geometries, problem.bindings, problem.clauses)


def _material(problem: GeometryConstraintProblem) -> dict[str, Any]:
    return {"contract": "experimental explicit geometry CNF",
        "geometries": [raw.decode("ascii") for raw in problem.geometries],
        "bindings": [item.to_dict() for item in problem.bindings],
        "clauses": [{"clause_id": item.clause_id, "literals": [[lit.proposition_id, lit.positive] for lit in item.literals]} for item in problem.clauses]}


def _formula(problem: GeometryConstraintProblem) -> tuple[tuple[str, ...], list[list[int]]]:
    names = tuple(sorted({item.proposition_id for item in problem.bindings}))
    indices = {name: index + 1 for index, name in enumerate(names)}
    return names, [[indices[lit.proposition_id] * (1 if lit.positive else -1) for lit in clause.literals] for clause in problem.clauses]


def _bounds(bounds: GeometryConstraintBounds) -> GeometryConstraintBounds:
    if type(bounds) is not GeometryConstraintBounds: raise ValueError("exact host bounds required")
    return GeometryConstraintBounds(bounds.max_decision_depth, bounds.max_proof_steps, bounds.max_check_work)


def recheck_geometry_constraints(problem: GeometryConstraintProblem, result: GeometryConstraintResult, *, expected_problem_digest: str, bounds: GeometryConstraintBounds = GeometryConstraintBounds()) -> GeometryConstraintResult:
    """Check a retained witness without producer calls; UNKNOWN proves no result."""
    expected = _hex(expected_problem_digest)
    problem, bounds = _admit(problem), _bounds(bounds)
    digest = _digest(_canonical(_material(problem)))
    if digest != expected: raise ValueError("semantic problem differs from separately supplied digest")
    if type(result) is not GeometryConstraintResult or type(result.status) is not str or _hex(result.problem_digest) != expected:
        raise ValueError("result does not bind the expected semantic problem")
    status, model, proof_bytes = result.status, result.model, result.certificate_json
    names, formula = _formula(problem)
    unknown = GeometryConstraintResult(digest, "UNKNOWN")
    if status == "UNKNOWN":
        if model is not None or proof_bytes is not None: raise ValueError("UNKNOWN cannot carry a passing witness")
        return unknown
    if status == "SAT":
        if proof_bytes is not None or type(model) is not tuple or len(model) != len(names): raise ValueError("SAT requires only a complete named assignment")
        if any(type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str or type(pair[1]) is not bool for pair in model):
            raise ValueError("model requires exact named Boolean pairs")
        if tuple(pair[0] for pair in model) != names: raise ValueError("model proposition binding or order differs")
        if len(names) + sum(map(len, formula)) + len(formula) > bounds.max_check_work: return unknown
        assignment = {index + 1: pair[1] for index, pair in enumerate(model)}
        if not all(any(assignment[abs(lit)] == (lit > 0) for lit in clause) for clause in formula): raise ValueError("model does not satisfy every declared clause")
        return GeometryConstraintResult(digest, "SAT", tuple((pair[0], pair[1]) for pair in model))
    if status != "UNSAT" or model is not None: raise ValueError("unsupported result or mixed witnesses")
    value = _json(proof_bytes, MAX_PROOF_BYTES)
    if type(value) is not dict or set(value) != {"proof_format", "proof", "n_vars", "source_clause_count", "step_count", "max_proof_steps"}:
        raise ValueError("exact existing refutation certificate fields required")
    for key, maximum in (("n_vars", MAX_VARIABLES), ("source_clause_count", MAX_CLAUSES), ("step_count", MAX_PROOF_STEPS), ("max_proof_steps", MAX_PROOF_STEPS)):
        _integer(value[key], maximum)
    proof = value["proof"]
    if value["proof_format"] != "VSTD4-RUP-1" or value["n_vars"] != len(names) or value["source_clause_count"] != len(formula): raise ValueError("proof metadata does not match the independently reconstructed formula")
    if type(proof) is not list or not 1 <= len(proof) <= MAX_PROOF_STEPS or value["step_count"] != len(proof) or value["max_proof_steps"] < len(proof): raise ValueError("proof count metadata or admission bound differs")
    for step in proof:
        if type(step) is not list or len(step) > 2 * len(names): raise ValueError("proof width exceeds admission bound")
        if any(type(lit) is not int or not 1 <= abs(lit) <= len(names) for lit in step): raise ValueError("proof literal is not an exact in-range integer")
        if step != sorted(set(step), key=lambda lit: (abs(lit), lit)): raise ValueError("proof clauses must be canonical")
    if proof[-1] != []: raise ValueError("refutation requires a terminal empty clause")
    certificate = RefutationCertificate.from_dict(value)
    if _canonical(certificate.to_dict()) != proof_bytes: raise ValueError("proof reader changed certificate representation")
    work = len(proof) * (len(names) + 1) * (sum(map(len, formula)) + sum(map(len, proof)) + len(formula) + len(proof))
    if len(proof) > bounds.max_proof_steps or work > bounds.max_check_work: return unknown
    if not RefutationChecker.check(formula, certificate).accepted: raise ValueError("refutation proof was not accepted")
    return GeometryConstraintResult(digest, "UNSAT", certificate_json=bytes(proof_bytes))


def solve_geometry_constraints(problem: GeometryConstraintProblem, *, bounds: GeometryConstraintBounds = GeometryConstraintBounds()) -> GeometryConstraintResult:
    """Run the bounded producer, then check its witness against reconstructed input."""
    problem, bounds = _admit(problem), _bounds(bounds)
    digest = _digest(_canonical(_material(problem)))
    names, formula = _formula(problem)
    depth = min(bounds.max_decision_depth, len(names))
    # Conservative propagation-scan estimate over a finite binary search tree;
    # admission caps separately bound proof analysis and retained clauses.
    work = ((1 << (depth + 1)) - 1) * (len(names) + 1) * (sum(map(len, formula)) + len(formula) + 1)
    if work > MAX_SEARCH_WORK: return GeometryConstraintResult(digest, "UNKNOWN")
    produced = ProofProducingDPLL(len(names), formula, max_proof_steps=bounds.max_proof_steps, max_decision_depth=bounds.max_decision_depth).solve()
    if produced.satisfiable is None: return GeometryConstraintResult(digest, "UNKNOWN")
    if produced.satisfiable is True:
        if type(produced.model) is not dict or any(type(key) is not int for key in produced.model) or set(produced.model) != set(range(1, len(names) + 1)):
            raise ValueError("producer did not return an exact total model")
        result = GeometryConstraintResult(digest, "SAT", tuple((name, produced.model[index + 1]) for index, name in enumerate(names)))
    elif produced.satisfiable is False and type(produced.certificate) is RefutationCertificate:
        result = GeometryConstraintResult(digest, "UNSAT", certificate_json=_canonical(produced.certificate.to_dict()))
    else: raise ValueError("producer returned an unsupported witness")
    return recheck_geometry_constraints(problem, result, expected_problem_digest=digest, bounds=bounds)
