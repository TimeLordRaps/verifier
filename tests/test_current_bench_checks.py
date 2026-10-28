"""Benchmark specification graph (BENCH) independently selected native checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); conjunctive normal
form (CNF); Boolean satisfiability problem (SAT); unsatisfiable (UNSAT). Time is
milliseconds, memory is bytes, scores and operation counts are dimensionless.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import bench
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import bench_checks as bench_checks_contract
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
CHECKS = {"problems": "BENCH-1.2", "oracles": "BENCH-1.4",
          "budgets": "BENCH-3.6", "coverage": "BENCH-4.4"}


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def specimen() -> tuple[dict, dict]:
    specifications = [
        ("exact", {"expected": {"answer": 42}}, {"answer": 42}),
        ("cnf-sat", {"variables": 2, "clauses": [[1], [-1, 2]]}, [True, True]),
        ("cnf-unsat", {"variables": 1, "clauses": [[1], [-1]]}, "UNSAT"),
        ("linear-system", {"matrix": [[2, 1], [1, -1]], "rhs": [5, 1], "tolerance": 0}, [2, 1]),
    ]
    problems = [{"id": kind, "kind": kind, "specification": spec, "weight": i + 1,
                 "timeout_ms": 100, "memory_bytes": 4096}
                for i, (kind, spec, answer) in enumerate(specifications)]
    retained = {"runs": [{"id": p["id"], "problem_digest": digest(p), "answer": answer,
                          "execution_ms": 100, "peak_memory_bytes": 4096}
                         for p, (_, _, answer) in zip(problems, specifications)], "score": 1}
    return {"problems": problems, "minimum_score": 1}, retained


@pytest.mark.parametrize("check", CHECKS)
def test_current_bench_route_is_explicitly_selected(check):
    route = routes.select_current_object_route(semantic_version=SEMANTIC,
        objective=CHECKS[check], represented_kind="BENCH")
    assert route.fixed_kind == "BENCH"
    assert route.scope == "finite_retained_bench_" + check


@pytest.mark.parametrize("check", CHECKS)
def test_native_positive_controls_execute_every_selected_check(check):
    artifact, retained = specimen()
    result = bench.evaluate(check, artifact, retained, Budget(10000))
    assert result["problems"] == 4
    if check in ("oracles", "coverage"):
        assert result["score"] == 1 and all(result["solved"].values())


@pytest.mark.parametrize("check", ["inventories", "", "ORACLES", " oracles", None, True, ["problems"]])
def test_unsupported_native_selection_cannot_return_inventory_success(check):
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported benchmark check"):
        bench.evaluate(check, artifact, retained, Budget(10000))


def test_subclass_selection_cannot_choose_a_different_check():
    class Forged(str):
        def __eq__(self, other):
            return True
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported benchmark check"):
        bench.evaluate(Forged("inventories"), artifact, retained, Budget(10000))


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self, key):
            raise AssertionError("unsupported selector consumed evidence")
    budget = Budget(0)
    with pytest.raises(Unavailable, match="unsupported benchmark check"):
        bench.evaluate("inventories", Unreadable(), Unreadable(), budget)
    assert budget.used == 0


@pytest.mark.parametrize("bound,observed", [("timeout_ms", "execution_ms"), ("memory_bytes", "peak_memory_bytes")])
@pytest.mark.parametrize("ceiling", [2**53, float(2**53), 2**80, float(2**80)])
def test_native_budget_cannot_round_excess_into_success(bound, observed, ceiling):
    artifact, retained = specimen()
    artifact["problems"][0][bound] = ceiling
    retained["runs"][0][observed] = int(ceiling) + 1
    retained["runs"][0]["problem_digest"] = digest(artifact["problems"][0])
    with pytest.raises(Refuted, match="resource observation exceeds"):
        bench.evaluate("budgets", artifact, retained, Budget(10000))


@pytest.mark.parametrize("weight", [2**53, 2**80, 1e100])
@pytest.mark.parametrize("check", ["oracles", "coverage"])
def test_incomplete_weighted_score_cannot_round_to_perfect(weight, check):
    artifact, retained = specimen()
    artifact["problems"] = artifact["problems"][:2]
    retained["runs"] = retained["runs"][:2]
    artifact["problems"][0]["weight"] = weight
    artifact["problems"][1]["weight"] = 1
    retained["runs"][1]["answer"] = [False, False]
    for p, r in zip(artifact["problems"], retained["runs"]):
        r["problem_digest"] = digest(p)
    assert Fraction(weight) / (Fraction(weight) + 1) < 1
    with pytest.raises(Refuted, match="below required threshold"):
        bench.evaluate(check, artifact, retained, Budget(10000))


@pytest.mark.parametrize("large", [2**53, 2**80])
def test_linear_oracle_rejects_exact_integer_residual_lost_by_float(large):
    problem = {"kind": "linear-system", "specification": {
        "matrix": [[large, 1]], "rhs": [large], "tolerance": 0}}
    # The selected equation is large*x0 + x1 = large; [1,1] has residual one.
    assert bench.oracle(problem, [1, 1], Budget(10000)) is False
    assert bench.oracle(problem, [1, 0], Budget(10000)) is True


@pytest.mark.parametrize("kind,spec,answer,expected", [
    ("exact", {"expected": 1}, True, False),
    ("cnf-sat", {"variables": 1, "clauses": [[1]]}, [False], False),
    ("cnf-unsat", {"variables": 1, "clauses": [[1]]}, "UNSAT", False),
    ("linear-system", {"matrix": [[1]], "rhs": [1], "tolerance": 0}, [2], False),
])
def test_independent_native_oracle_refutations(kind, spec, answer, expected):
    assert bench.oracle({"kind": kind, "specification": spec}, answer, Budget(10000)) is expected


def inputs(check: str, *, artifact=None, retained=None, objects=None, **limits):
    contract = bench_checks_contract
    if artifact is None:
        artifact, retained = specimen()
    if objects is None:
        subject = NamespaceObject.create("benchmark", "BENCH", artifact,
            {"verifier": ["checker"], "data": ["problems"]})
        objects = [subject,
            NamespaceObject.create("checker", "VERIFIER", {"mechanism_id": contract.MECHANISM_ID,
                "mechanism_digest": contract.mechanism_digest()}),
            NamespaceObject.create("problems", "DATA", {"problems": deepcopy(artifact["problems"])})]
    subject = next(item for item in objects if item.object_id == "benchmark")
    evidence = canonical_bytes({"schema_version": "verifier-current-bench-checks-evidence-1",
        "objects": [item.to_dict() for item in objects], "inputs": retained})
    policy = contract.bench_checks_policy(trust_roots=["selected-retained-bench-only"])
    request = contract.bench_checks_request(check=check, subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_bench_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="BENCH", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_bench_positive_replay_is_bounded_and_deterministic(check):
    contract, request, policy, evidence = inputs(check)
    first = contract.build_bench_checks_certificate(request, evidence, policy=policy)
    assert first == contract.build_bench_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS"
    result = report["native_result"]
    assert result["object_profile_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    observed = result["evaluation"]["observations"]["benchmark"]
    assert observed["problems"] == 4
    if check in ("oracles", "coverage"):
        assert observed["score_exact"] == {"numerator": 1, "denominator": 1}


@pytest.mark.parametrize("check", CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact, retained = specimen()
    if check == "problems": retained["runs"][0]["problem_digest"] = "sha256:" + "0" * 64
    elif check == "oracles": retained["runs"][0]["answer"] = {"answer": 41}
    elif check == "budgets": retained["runs"][0]["execution_ms"] = 101
    else: retained["score"] = 0
    contract, request, policy, evidence = inputs(check, artifact=artifact, retained=retained)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("bound", ["max_operations", "max_composition_operations", "max_evidence_bytes",
                                  "max_payload_bytes", "max_reference_bytes", "max_items"])
def test_selected_resource_exhaustion_remains_unknown(check, bound):
    contract, request, policy, evidence = inputs(check, **{bound: 1})
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", CHECKS)
def test_missing_retained_evidence_is_unknown(check):
    contract, request, policy, evidence = inputs(check)
    assert replay(contract, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest"])
def test_certificate_cannot_select_its_own_subject_or_evidence(field):
    contract, request, policy, evidence = inputs("oracles")
    certificate = contract.build_bench_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_bench_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("problems")
    certificate = json.loads(contract.build_bench_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_bench_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_bench_record(bad):
    contract, request, policy, evidence = inputs("problems")
    value = json.loads(evidence); value["objects"][0]["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_bench_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_bench_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "BENCH", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_bench_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("problems")
    value = json.loads(contract.build_bench_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("BENCH", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/bench_checks.py", "domains/bench.py", "standard/CURRENT_BENCH_CHECKS.md"])
def test_bench_dependencies_invalidate_polish(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        value = original(path)
        return value + b"\nchanged benchmark dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("check", CHECKS)
def test_bench_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("BENCH", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "bench_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/bench_checks.py", "domains/bench.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_BENCH_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_direct_dependency_invalidates_benchmark_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("problems")
    certificate = contract.build_bench_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_bench_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("target", ["checker", "problems"])
def test_rebound_typed_operands_cannot_supply_wrong_mechanism_or_dataset(target):
    contract, request, policy, evidence = inputs("oracles")
    value = json.loads(evidence)
    row = next(item for item in value["objects"] if item["object_id"] == target)
    if target == "checker": row["payload"]["mechanism_digest"] = "sha256:" + "0" * 64
    else: row["payload"]["problems"][0]["specification"]["expected"] = {"answer": 41}
    objects = [NamespaceObject.create(**item) for item in value["objects"]]
    contract, request, policy, evidence = inputs("oracles", retained=value["inputs"],
        artifact=objects[0].payload, objects=objects)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("mutation,expected", [("missing-run", "UNKNOWN"), ("duplicate-run", "FAIL"),
    ("unbound-run", "FAIL"), ("unsupported-oracle", "UNKNOWN"), ("extra-input", "FAIL"),
    ("missing-input", "UNKNOWN"), ("missing-threshold", "UNKNOWN"), ("empty-problems", "UNKNOWN")])
def test_missing_unsupported_or_contradictory_benchmark_evidence(mutation, expected):
    artifact, retained = specimen()
    if mutation == "missing-run": retained["runs"].pop()
    elif mutation == "duplicate-run": retained["runs"].append(deepcopy(retained["runs"][0]))
    elif mutation == "unbound-run": retained["runs"][0]["id"] = "unselected"
    elif mutation == "unsupported-oracle":
        artifact["problems"][0]["kind"] = "external-theorem-prover"
        retained["runs"][0]["problem_digest"] = digest(artifact["problems"][0])
    elif mutation == "extra-input": retained["solved"] = True
    elif mutation == "missing-input": retained = None
    elif mutation == "missing-threshold": artifact.pop("minimum_score")
    else: artifact["problems"] = []; retained["runs"] = []
    contract, request, policy, evidence = inputs("oracles", artifact=artifact, retained=retained)
    assert replay(contract, request, policy, evidence)["computational_status"] == expected


def test_admitted_multiple_verifier_operands_are_outside_selected_mechanism_scope():
    contract, request, policy, evidence = inputs("oracles")
    value = json.loads(evidence)
    extra = deepcopy(value["objects"][1]); extra["object_id"] = "second-checker"
    value["objects"].append(extra); value["objects"][0]["operands"]["verifier"].append("second-checker")
    objects = [NamespaceObject.create(**item) for item in value["objects"]]
    contract, request, policy, evidence = inputs("oracles", artifact=objects[0].payload,
        retained=value["inputs"], objects=objects)
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", ["oracles", "coverage"])
def test_current_route_executes_all_four_native_oracles(check, monkeypatch):
    original = bench.oracle; observed = []
    def traced(problem, answer, budget):
        observed.append(problem["kind"])
        return original(problem, answer, budget)
    monkeypatch.setattr(bench, "oracle", traced)
    contract, request, policy, evidence = inputs(check)
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    assert observed == ["exact", "cnf-sat", "cnf-unsat", "linear-system"] * 2


@pytest.mark.parametrize("scale", [1, 2**60, 0.5])
def test_weight_scaling_preserves_exact_score_and_solution_vector(scale):
    artifact, retained = specimen()
    artifact["minimum_score"] = 0
    retained["runs"][0]["answer"] = {"answer": 41}; retained["score"] = 0.9
    for p, r in zip(artifact["problems"], retained["runs"]):
        p["weight"] *= scale; r["problem_digest"] = digest(p)
    result = bench.evaluate("coverage", artifact, retained, Budget(10000))
    assert result["score_exact"] == {"numerator": 9, "denominator": 10}
    assert result["solved"] == {"exact": False, "cnf-sat": True, "cnf-unsat": True, "linear-system": True}


def test_approximate_score_cannot_erase_exact_imperfection():
    artifact, retained = specimen()
    artifact["minimum_score"] = 0
    artifact["problems"][1]["weight"] = 2**80
    retained["runs"][1]["problem_digest"] = digest(artifact["problems"][1])
    retained["runs"][0]["answer"] = {"answer": 41}
    result = bench.evaluate("oracles", artifact, retained, Budget(10000))
    assert result["score"] == 1
    exact = result["score_exact"]
    assert exact["numerator"] == exact["denominator"] - 1


@pytest.mark.parametrize("check", CHECKS)
def test_current_benchmark_rejects_legacy_semantic_selection(check):
    contract, request, policy, evidence = inputs(check)
    certificate = contract.build_bench_checks_certificate(request, evidence, policy=policy)
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(certificate, semantic_version="verifier-domain-certification-1",
            objective=CHECKS[check], represented_kind="BENCH", expected_request=request, policy=policy)
