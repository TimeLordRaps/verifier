# Acronyms: Boolean satisfiability problem (SAT); unsatisfiable (UNSAT);
# Verifier Standard (VSTD).
"""Independent experiment-record rehash, SAT replay, and native-verdict replay.

This module deliberately does not import the producer's canonicalization, route
compiler, VSTD binding, or SAT-backend modules. It checks a complementary surface
so producer and consumer agreement is not evidence from one shared function.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


RECORD_VERSION = "vgsat-vstd-binding-0.1"


def independently_validate_record(
    experiment_root: Path, record: Mapping[str, Any], *, reexecute: bool = True
) -> list[str]:
    """Validate one public record without using producer binding helpers."""

    errors: list[str] = []
    if record.get("experiment_record_version") != RECORD_VERSION:
        return ["independent: unsupported experiment record version"]
    stable = record.get("stable_payload")
    graph = record.get("graph")
    payloads = record.get("artifact_payloads")
    if not isinstance(stable, Mapping) or not isinstance(graph, Mapping) or not isinstance(
        payloads, Mapping
    ):
        return ["independent: record sections must be objects"]

    binding = _untagged_digest({"stable_payload": stable, "graph": graph})
    if record.get("binding_digest") != binding:
        errors.append("independent: binding digest mismatch")

    for digest_field, value_field in (
        ("instance_digest", "instance"),
        ("verifier_contract_digest", "verifier_contract"),
        ("lm_observation_digest", "lm_observation"),
        ("proposal_digest", "proposal"),
        ("formula_digest", "formula"),
        ("solver_configuration_digest", "solver_configuration"),
        ("candidate_digest", "candidate"),
    ):
        value = stable.get(value_field)
        expected = _tagged_digest(value) if value is not None else None
        if stable.get(digest_field) != expected:
            errors.append(f"independent: {digest_field} mismatch")

    errors.extend(_validate_graph(graph, payloads, stable.get("bounded_claim_status")))

    observed_sat: str | None = None
    observed_candidate: Any = None
    formula = stable.get("formula")
    configuration = stable.get("solver_configuration")
    if reexecute and isinstance(formula, Mapping):
        observed_sat, observed_candidate, replay_errors = _replay_sat(formula, configuration)
        errors.extend(replay_errors)
        solver = stable.get("solver_observation")
        if not isinstance(solver, Mapping) or solver.get("status") != observed_sat:
            errors.append("independent: SAT replay status mismatch")
        if observed_sat == "SAT" and stable.get("candidate") != observed_candidate:
            errors.append("independent: decoded SAT candidate mismatch")

    observed_native: str | None = None
    if reexecute and stable.get("candidate") is not None:
        try:
            from .external_verifiers import load_verifier

            verifier = load_verifier(experiment_root, str(stable.get("domain")))
            observation = verifier.verify(stable.get("instance"), stable.get("candidate"))
            observed_native = observation.verdict.value
            native = stable.get("native_observation")
            if not isinstance(native, Mapping) or native.get("verdict") != observed_native:
                errors.append("independent: native-verifier replay mismatch")
        except Exception as exc:
            errors.append(f"independent: native-verifier replay failed: {type(exc).__name__}")

    if reexecute:
        expected_pass = observed_native == "ACCEPTED" and (
            stable.get("arm") == "B" or observed_sat == "SAT"
        )
        expected_claim = "PASS" if expected_pass else "UNKNOWN"
        if stable.get("bounded_claim_status") != expected_claim:
            errors.append("independent: bounded claim is stronger than replay evidence")
    return errors


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _tagged_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _untagged_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_graph(
    graph: Mapping[str, Any], payloads: Mapping[str, Any], claim_status: Any
) -> list[str]:
    errors: list[str] = []
    artifacts = graph.get("artifacts")
    transformations = graph.get("transformations")
    if not isinstance(artifacts, list) or not isinstance(transformations, list):
        return ["independent: graph arrays are malformed"]
    identifiers: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or not isinstance(artifact.get("artifact_id"), str):
            errors.append("independent: malformed graph artifact")
            continue
        identifier = artifact["artifact_id"]
        identifiers.add(identifier)
        if identifier not in payloads:
            errors.append(f"independent: missing graph payload {identifier}")
            continue
        raw = _canonical_bytes(payloads[identifier])
        digest = hashlib.sha256(raw).hexdigest()
        if artifact.get("content_digest") != digest:
            errors.append(f"independent: graph payload digest mismatch {identifier}")
        if artifact.get("byte_size") != len(raw):
            errors.append(f"independent: graph payload size mismatch {identifier}")
        attributes = artifact.get("attributes")
        if not isinstance(attributes, Mapping) or attributes.get("claim_status") != claim_status:
            errors.append(f"independent: graph claim status mismatch {identifier}")
    for edge in transformations:
        if not isinstance(edge, Mapping):
            errors.append("independent: malformed graph transformation")
            continue
        for port_group in ("inputs", "outputs"):
            ports = edge.get(port_group)
            if not isinstance(ports, list) or not ports:
                errors.append("independent: graph transformation has no ports")
                continue
            for port in ports:
                if not isinstance(port, Mapping) or port.get("artifact_id") not in identifiers:
                    errors.append("independent: graph transformation references an unknown artifact")
    return errors


def _replay_sat(
    formula: Mapping[str, Any], configuration: Any
) -> tuple[str, Any, list[str]]:
    errors: list[str] = []
    if not isinstance(configuration, Mapping):
        return "UNKNOWN", None, ["independent: solver configuration is malformed"]
    if configuration.get("solver_name") != "cadical300":
        return "UNKNOWN", None, ["independent: unsupported solver name"]
    clauses = formula.get("clauses")
    if not isinstance(clauses, list) or not all(isinstance(clause, list) for clause in clauses):
        return "UNKNOWN", None, ["independent: formula clauses are malformed"]
    budget = configuration.get("conflict_budget")
    if budget is not None and (
        isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0
    ):
        return "UNKNOWN", None, ["independent: conflict budget is malformed"]
    try:
        from pysat.solvers import Solver

        with Solver(name="cadical300", bootstrap_with=clauses, use_timer=True) as solver:
            if budget is None:
                solved = solver.solve()
            else:
                solver.conf_budget(budget)
                solved = solver.solve_limited(expect_interrupt=True)
            model = solver.get_model() if solved is True else None
    except Exception as exc:
        return "UNKNOWN", None, [f"independent: SAT replay failed: {type(exc).__name__}"]
    if solved is False:
        return "UNSAT", None, errors
    if solved is not True or model is None:
        return "UNKNOWN", None, errors
    try:
        return "SAT", _decode_candidate(formula, model), errors
    except (KeyError, TypeError, ValueError) as exc:
        return "SAT", None, [f"independent: candidate decoding failed: {type(exc).__name__}"]


def _decode_candidate(formula: Mapping[str, Any], model: list[int]) -> dict[str, Any]:
    variables = formula["variables"]
    decoder = formula["decoder"]
    if not isinstance(variables, list) or not isinstance(decoder, Mapping):
        raise TypeError
    positive = {literal for literal in model if literal > 0}
    assignment: dict[str, int] = {}
    for variable in variables:
        if not isinstance(variable, Mapping):
            raise TypeError
        number = variable.get("variable")
        if number in positive:
            slot = variable.get("slot")
            value = variable.get("value")
            if not isinstance(slot, str) or not isinstance(value, int) or slot in assignment:
                raise ValueError
            assignment[slot] = value
    if decoder.get("kind") == "list_field":
        slots = decoder.get("slots")
        if not isinstance(slots, list) or any(slot not in assignment for slot in slots):
            raise ValueError
        return {str(decoder["field"]): [assignment[slot] for slot in slots]}
    if decoder.get("kind") == "object_fields":
        fields = decoder.get("fields")
        if not isinstance(fields, Mapping) or any(slot not in assignment for slot in fields.values()):
            raise ValueError
        return {str(field): assignment[str(slot)] for field, slot in fields.items()}
    raise ValueError
