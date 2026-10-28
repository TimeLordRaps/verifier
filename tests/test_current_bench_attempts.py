"""Current BENCH-2.1 declared per-problem attempt bounds and best-of-N selection.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Boolean satisfiability problem (SAT); unsatisfiable (UNSAT);
benchmark specification graph (BENCH). Attempt
counts, bounds, scores, positions and checker budgets are dimensionless.
Retained attempts are recorded answers, not observed candidate executions.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import bench_attempts
from verifier.domains.inventory import get_slot


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def exact_inputs() -> dict:
    return {
        "problems": [
            {"id": "p1", "reference": {"answer": 42}, "max_attempts": 3},
            {"id": "p2", "reference": "UNSAT", "max_attempts": 2},
        ],
        "attempts": [
            {"id": "a1", "problem": "p1", "answer": {"answer": 41}},
            {"id": "a2", "problem": "p1", "answer": {"answer": 42}},
            {"id": "a3", "problem": "p2", "answer": "UNSAT"},
            {"id": "a4", "problem": "p1", "answer": {"answer": 42}},
            {"id": "a5", "problem": "p2", "answer": "SAT"},
        ],
        "selections": [
            {"problem": "p1", "attempt": "a2", "score": 1},
            {"problem": "p2", "attempt": "a3", "score": 1},
        ],
    }


def error_inputs() -> dict:
    return {
        "problems": [{"id": "q1", "reference": 100, "max_attempts": 4}],
        "attempts": [
            {"id": "b1", "problem": "q1", "answer": 90},
            {"id": "b2", "problem": "q1", "answer": 103},
            {"id": "b3", "problem": "q1", "answer": 97},
            {"id": "b4", "problem": "q1", "answer": 140},
        ],
        "selections": [{"problem": "q1", "attempt": "b2", "score": 3}],
    }


def oracle(metric: str, inputs: dict) -> str:
    """Independent sort-based recomputation of bound and best-of-N choice."""
    problems = {row["id"]: row for row in inputs["problems"]}
    attempts = inputs["attempts"]
    if len({row["id"] for row in attempts}) != len(attempts):
        return "FAIL"
    if any(row["problem"] not in problems for row in attempts):
        return "FAIL"
    counts = Counter(row["problem"] for row in attempts)
    if any(counts[name] > row["max_attempts"] for name, row in problems.items()):
        return "FAIL"

    def score(row):
        reference = problems[row["problem"]]["reference"]
        if metric == "exact-match":
            spell = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
            return int(spell(row["answer"]) == spell(reference))
        return abs(row["answer"] - reference)

    selections = inputs["selections"]
    chosen = Counter(row["problem"] for row in selections)
    if any(name not in problems for name in chosen) or any(n > 1 for n in chosen.values()):
        return "FAIL"
    by_id = {row["id"]: (index, row) for index, row in enumerate(attempts)}
    for selection in selections:
        candidates = [(index, row) for index, row in enumerate(attempts)
                      if row["problem"] == selection["problem"]]
        if not candidates:
            return "FAIL"
        sign = -1 if metric == "exact-match" else 1
        best_index, best = sorted(candidates, key=lambda item: (sign * score(item[1]), item[0]))[0]
        if selection["attempt"] not in by_id or by_id[selection["attempt"]][0] != best_index:
            return "FAIL"
        if selection["score"] != score(best):
            return "FAIL"
    if any(counts[name] > 0 and name not in chosen for name in problems):
        return "FAIL"
    if any(counts[name] == 0 for name in problems):
        return "UNKNOWN"
    return "PASS"


def selected(inputs: dict | None = None, *, metric: str = "exact-match",
             include_inputs: bool = True, subject_id: str = "benchmark", **limits: int):
    inputs = exact_inputs() if inputs is None else inputs
    checker = NamespaceObject.create("checker", "VERIFIER", {})
    items = NamespaceObject.create("items", "DATA", {})
    subject = NamespaceObject.create(subject_id, "BENCH", {
        "scope": "retained-attempt-policy", "selection": "best-of-n",
        "metric": metric, "tie_break": "earliest-retained-attempt",
        "problems_digest": digest(inputs["problems"])},
        {"verifier": ["checker"], "data": ["items"]})
    objects = [checker, items, subject]
    evidence = canonical_bytes({
        "schema_version": bench_attempts.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": inputs if include_inputs else None,
    })
    policy = bench_attempts.bench_attempts_policy(trust_roots=["selected-bench"])
    request = bench_attempts.bench_attempts_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def status(request: dict, policy: dict, evidence: bytes | None) -> str:
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    return bench_attempts.recheck_bench_attempts_certificate(
        certificate, expected_request=request, policy=policy)["status"]


def test_inventory_selects_attempt_policy_for_bench_dynamics():
    slot = get_slot("BENCH", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "BENCH-2.1"
    assert slot.mechanized_route["artifact_coordinate"] == "BENCH-2.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.bench_attempts.recheck_bench_attempts_certificate")


@pytest.mark.parametrize("metric,inputs", [("exact-match", exact_inputs),
                                           ("absolute-error", error_inputs)])
def test_declared_attempt_policy_passes_and_rechecks_from_decoded_bytes(metric, inputs, tmp_path):
    assert oracle(metric, inputs()) == "PASS"
    request, policy, evidence = selected(inputs(), metric=metric)
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    (tmp_path / "certificate.json").write_bytes(certificate)
    reread = canonical_bytes(json.loads((tmp_path / "certificate.json").read_bytes()))
    assert reread == certificate
    result = bench_attempts.recheck_bench_attempts_certificate(
        reread, expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert result["status"] == "PASS"
    assert result["declared_attempt_policy"] == "PASS"
    for field in ("attempt_inventory_completeness", "sequential_adaptivity",
                  "candidate_execution", "reference_validity", "contamination",
                  "aggregate_score", "whole_bench_dynamics",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"


def _over_bound(inputs):
    inputs["attempts"].append({"id": "a6", "problem": "p2", "answer": "UNSAT"})


def _not_best(inputs):
    inputs["selections"][0] = {"problem": "p1", "attempt": "a1", "score": 0}


def _later_tie(inputs):
    inputs["selections"][0] = {"problem": "p1", "attempt": "a4", "score": 1}


def _wrong_score(inputs):
    inputs["selections"][1] = {"problem": "p2", "attempt": "a3", "score": 0}


def _cross_problem(inputs):
    inputs["selections"][1] = {"problem": "p2", "attempt": "a2", "score": 1}


def _undeclared_problem(inputs):
    inputs["attempts"].append({"id": "a9", "problem": "p9", "answer": 1})


def _missing_selection(inputs):
    inputs["selections"].pop()


def _duplicate_attempt_id(inputs):
    inputs["attempts"][4]["id"] = "a1"


MUTANTS = {
    "attempts-exceed-declared-bound": _over_bound,
    "selected-attempt-not-best": _not_best,
    "tie-not-broken-to-earliest": _later_tie,
    "retained-score-differs": _wrong_score,
    "selection-crosses-problems": _cross_problem,
    "attempt-for-undeclared-problem": _undeclared_problem,
    "best-of-n-selection-missing": _missing_selection,
    "attempt-identifier-repeats": _duplicate_attempt_id,
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_rehashed_attempt_policy_counterexamples_fail(name):
    inputs = exact_inputs()
    MUTANTS[name](inputs)
    assert oracle("exact-match", inputs) == "FAIL"
    request, policy, evidence = selected(inputs)
    assert status(request, policy, evidence) == "FAIL"


def test_absolute_error_selection_must_minimise_not_maximise():
    inputs = error_inputs()
    inputs["selections"] = [{"problem": "q1", "attempt": "b4", "score": 40}]
    assert oracle("absolute-error", inputs) == "FAIL"
    request, policy, evidence = selected(inputs, metric="absolute-error")
    assert status(request, policy, evidence) == "FAIL"


def test_seeded_random_attempt_sets_agree_with_independent_oracle():
    rng = random.Random(20261001)
    seen = Counter()
    for _ in range(40):
        metric = rng.choice(["exact-match", "absolute-error"])
        problems = [{"id": "p" + str(i), "reference": rng.randint(0, 3),
                     "max_attempts": rng.randint(1, 3)} for i in range(rng.randint(1, 3))]
        attempts = []
        for problem in problems:
            for _ in range(rng.randint(1, problem["max_attempts"] + (rng.random() < 0.1))):
                attempts.append({"id": "a" + str(len(attempts)), "problem": problem["id"],
                                 "answer": rng.randint(0, 3)})
        rng.shuffle(attempts)
        selections = []
        for problem in problems:
            mine = [row for row in attempts if row["problem"] == problem["id"]]
            pick = rng.choice(mine)
            if metric == "exact-match":
                value = int(pick["answer"] == problem["reference"])
            else:
                value = abs(pick["answer"] - problem["reference"])
            if rng.random() < 0.1:
                value += 1
            selections.append({"problem": problem["id"], "attempt": pick["id"],
                               "score": value})
        inputs = {"problems": problems, "attempts": attempts, "selections": selections}
        expected = oracle(metric, inputs)
        request, policy, evidence = selected(inputs, metric=metric)
        assert status(request, policy, evidence) == expected, (metric, inputs)
        seen[expected] += 1
    assert seen["PASS"] > 0 and seen["FAIL"] > 0


def test_undecidable_selection_and_exhausted_limits_remain_unknown():
    inputs = exact_inputs()
    inputs["problems"].append({"id": "p3", "reference": 0, "max_attempts": 1})
    assert oracle("exact-match", inputs) == "UNKNOWN"
    request, policy, evidence = selected(inputs)
    assert status(request, policy, evidence) == "UNKNOWN"
    request, policy, evidence = selected(metric="f1-score")
    assert status(request, policy, evidence) == "UNKNOWN"
    request, policy, evidence = selected(include_inputs=False)
    assert status(request, policy, evidence) == "UNKNOWN"
    request, policy, evidence = selected()
    assert status(request, policy, None) == "UNKNOWN"
    for bound in ("max_operations", "max_items", "max_objects",
                  "max_composition_operations", "max_evidence_bytes",
                  "max_payload_bytes", "max_reference_bytes"):
        request, policy, evidence = selected(**{bound: 1})
        assert status(request, policy, evidence) == "UNKNOWN", bound


def test_one_bit_certificate_tamper_is_refused():
    request, policy, evidence = selected()
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    for position in (0, len(certificate) // 3, len(certificate) // 2, len(certificate) - 2):
        tampered = bytearray(certificate)
        tampered[position] ^= 0x01
        with pytest.raises(bench_attempts.BenchAttemptsError):
            bench_attempts.recheck_bench_attempts_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_verdict_are_refused():
    request, policy, evidence = selected()
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    other_request, _, other_evidence = selected(subject_id="other-benchmark")
    with pytest.raises(bench_attempts.BenchAttemptsError):
        bench_attempts.recheck_bench_attempts_certificate(
            certificate, expected_request=other_request, policy=policy)
    with pytest.raises(bench_attempts.BenchAttemptsError):
        bench_attempts.build_bench_attempts_certificate(request, other_evidence, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(bench_attempts.BenchAttemptsError):
        bench_attempts.recheck_bench_attempts_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(bench_attempts.BenchAttemptsError):
        bench_attempts.recheck_bench_attempts_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    for field, value in (("coordinate", "BENCH-2.2"), ("object_kind", "DATA")):
        changed = deepcopy(request)
        changed[field] = value
        with pytest.raises(bench_attempts.BenchAttemptsError):
            bench_attempts.build_bench_attempts_certificate(changed, evidence, policy=policy)


def test_attempt_policy_does_not_reuse_one_run_coverage_selection():
    from verifier.domains.contracts import bench_checks
    route = routes.select_current_object_route(semantic_version=bench_attempts.SEMANTIC_VERSION,
        objective="BENCH-2.1", represented_kind="BENCH")
    assert route.scope == bench_attempts.SCOPE
    assert "BENCH-2.1" not in bench_checks.CHECKS.values()
    request, policy, evidence = selected()
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=bench_attempts.SEMANTIC_VERSION,
            objective="BENCH-4.4", represented_kind="BENCH",
            expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/bench_attempts.py", "domains/contracts/retained_selection.py",
    "domains/common.py", "core/namespace.py", "standard/CURRENT_BENCH_ATTEMPTS.md",
    "standard/NAMESPACE_OBJECTS.md", "standard/DOMAIN_OBLIGATIONS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(bench_attempts.__file__).parents[2] / relative

    def changed(path):
        data = original(path)
        return data + b"\nchanged attempt dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        bench_attempts.recheck_bench_attempts_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_route_command_and_polish_keep_dynamics_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate = bench_attempts.build_bench_attempts_certificate(
        request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=bench_attempts.SEMANTIC_VERSION,
        objective=bench_attempts.COORDINATE, represented_kind="BENCH",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["attempt_inventory_completeness"] == "NOT_ESTABLISHED"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", bench_attempts.SEMANTIC_VERSION,
        "--objective", bench_attempts.COORDINATE, "--represented-kind", "BENCH",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "benchmark", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "benchmark", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected attempt policy only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][1]["objectives"] = [{
        "semantic_version": bench_attempts.SEMANTIC_VERSION,
        "coordinate": bench_attempts.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    polished = assess_polish(canonical_bytes(bundle),
                             request_bytes=canonical_bytes(selected_request))
    assert polished["objectives"][0]["status"] == "PASS", polished["objectives"][0]
    assert polished["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert polished["status"] == "UNKNOWN" and polished["polished"] is False
