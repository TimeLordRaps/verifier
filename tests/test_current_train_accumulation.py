"""Current TRAIN-3.2: a retained sequence reduced two ways, with a bounded effect.

Verifier Standard (VSTD); training run specification (TRAIN); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Institute of
Electrical and Electronics Engineers (IEEE) 754 binary64 floating point.
Values, results and bounds are dimensionless binary64 numbers; counts are
dimensionless. The oracle evaluates nested addition trees with exact rational
sums and one correct rounding per addition, independently of the checker's
host float addition over flat step programs.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import train_accumulation
from verifier.domains.inventory import get_slot


ROW = ("The order reductions actually occur in is observed by reducing a "
       "retained sequence two ways, and its effect is bounded.")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def rounded_add(left: float, right: float) -> float:
    """One IEEE 754 binary64 round-to-nearest-even addition, from exact rationals."""
    exact = Fraction(left) + Fraction(right)
    if exact == 0:
        both_negative = math.copysign(1.0, left) < 0 and math.copysign(1.0, right) < 0
        return -0.0 if both_negative else 0.0
    return float(exact)  # integer true division: correctly rounded, ties to even


def evaluate(tree, values: list) -> float:
    if isinstance(tree, int):
        return values[tree]
    return rounded_add(evaluate(tree[0], values), evaluate(tree[1], values))


def program(tree, count: int) -> list:
    """Compile a nested tree to post-order steps; operand j >= count names step j - count."""
    steps: list = []

    def walk(node):
        if isinstance(node, int):
            return node
        left, right = walk(node[0]), walk(node[1])
        steps.append([left, right])
        return count + len(steps) - 1

    walk(tree)
    return steps


def sequential(count: int):
    tree = 0
    for index in range(1, count):
        tree = (tree, index)
    return tree


def pairwise(low: int, high: int):
    if high - low == 1:
        return low
    middle = (low + high) // 2
    return (pairwise(low, middle), pairwise(middle, high))


def mirrored(tree):
    return tree if isinstance(tree, int) else (mirrored(tree[1]), mirrored(tree[0]))


def effect(values: list, first, second) -> Fraction:
    return abs(Fraction(evaluate(first, values)) - Fraction(evaluate(second, values)))


def ceiling_float(value: Fraction) -> float:
    candidate = float(value)
    return candidate if Fraction(candidate) >= value else math.nextafter(candidate, math.inf)


TIE = [1.0, 2.0**-53, 2.0**-53]


def reduction(values: list | None = None, first=None, second=None, *,
              bound: float | None = None, **fields) -> dict:
    values = list(TIE if values is None else values)
    first = sequential(len(values)) if first is None else first
    second = pairwise(0, len(values)) if second is None else second
    if bound is None:
        bound = ceiling_float(effect(values, first, second))
    record = {"operation": train_accumulation.OPERATION,
              "values": [value.hex() for value in values],
              "retained_order": program(first, len(values)),
              "retained_result": evaluate(first, values).hex(),
              "alternative_order": program(second, len(values)),
              "order_effect_bound": bound.hex()}
    record.update(fields)
    return record


def collection(payload: dict) -> list:
    make = NamespaceObject.create
    return [make("data", "DATA", {}), make("arch", "ARCH", {}),
            make("checker", "VERIFIER", {}), make("t0", "TIME", {"index": 0}),
            make("trace", "SPACE", {"scope": "retained-training-trace"}),
            make("meaning", "OBJECT", {"operation": "gradient-reduction"}),
            make("e0", "EVENT", {}, {"time": ["t0"], "space": ["trace"],
                                     "meaning": ["meaning"]}),
            make("loss", "BENCH", {"loss": "mean-squared-error"},
                 {"verifier": ["checker"], "data": ["data"]}),
            make("train", "TRAIN", payload, {"data": ["data"], "events": ["e0"],
                                             "bench": ["loss"], "arch": ["arch"]})]


def selected(record: dict | None = None, *, payload: dict | None = None,
             include_inputs: bool = True, rows: list | None = None,
             subject_id: str = "train", **limits: int):
    record = reduction() if record is None else record
    payload = {"reduction_digest": digest(record)} if payload is None else payload
    rows = collection(payload) if rows is None else rows
    subject = [row for row in rows if row.object_id == subject_id][0]
    evidence = canonical_bytes({
        "schema_version": train_accumulation.EVIDENCE_VERSION,
        "objects": [row.to_dict() for row in rows],
        "inputs": {"reduction": record} if include_inputs else None})
    policy = train_accumulation.train_accumulation_policy(trust_roots=["test:reduction"])
    request = train_accumulation.train_accumulation_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(rows),
        evidence_ref=digest(json.loads(evidence)), policy=policy,
        limits=limits or None)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = train_accumulation.build_train_accumulation_certificate(
        request, evidence, policy=policy)
    result = train_accumulation.recheck_train_accumulation_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def outcome(record: dict, **options) -> dict:
    return replay(*selected(record, **options))[1]


def test_oracle_rounds_ties_to_even_and_agrees_with_fsum():
    assert rounded_add(1.0, 2.0**-53) == 1.0
    assert rounded_add(1.0 + 2.0**-52, 2.0**-53) == 1.0 + 2.0**-51
    assert rounded_add(1.0, 2.0**-53 + 2.0**-64) == 1.0 + 2.0**-52
    assert math.copysign(1.0, rounded_add(-0.0, -0.0)) < 0
    assert math.copysign(1.0, rounded_add(-1.0, 1.0)) > 0
    values = [math.ldexp(0.5 - k / 17, k % 23 - 11) for k in range(40)]
    assert float(sum(Fraction(value) for value in values)) == math.fsum(values)
    assert evaluate(sequential(3), TIE) == 1.0  # each partial sum is a tie kept at 1
    assert pairwise(0, 3) == (0, (1, 2))
    assert evaluate((0, (1, 2)), TIE) == 1.0 + 2.0**-52


def test_inventory_selects_the_accumulation_order_row():
    slot = get_slot("TRAIN", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "TRAIN-3.2"
    route = slot.mechanized_route
    assert route["artifact_coordinate"] == "TRAIN-3.2"
    assert route["checking_mechanism"] == (
        "verifier.domains.contracts.train_accumulation.recheck_train_accumulation_certificate")
    assert "TRAIN-3.1" in route["assumptions_and_exclusions"]
    spec = (Path(train_accumulation.__file__).parents[2] / "standard"
            / "CURRENT_TRAIN_ACCUMULATION.md").read_text(encoding="utf-8")
    assert ROW in spec
    standard = (Path(train_accumulation.__file__).parents[2] / "standard"
                / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    assert "| TRAIN-3.2 | Accumulation order | " + ROW + " |" in standard


def test_two_way_reduction_with_bounded_effect_passes_and_rechecks():
    record = reduction(TIE, sequential(3), (0, (1, 2)))
    assert effect(TIE, sequential(3), (0, (1, 2))) == Fraction(1, 2**52)
    request, policy, evidence = selected(record)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", result["evaluation"]["details"]
    assert result["accumulation_order_effect"] == "PASS"
    for field in ("whole_train_statics", "object_profile_conformance",
                  "executing_hardware_arithmetic", "executed_order_identity",
                  "unretained_orders_and_reductions",
                  "fused_or_extended_precision_arithmetic", "training_correctness"):
        assert result[field] == "NOT_ESTABLISHED"
    observed = result["evaluation"]["observations"]
    assert observed["order_effect"] == str(Fraction(1, 2**52))
    assert observed["results_differ"] is True
    assert json.loads(certificate.decode("utf-8"))["result"] == result
    assert certificate == train_accumulation.build_train_accumulation_certificate(
        request, evidence, policy=policy)


def test_orders_that_differ_without_changing_the_sum_still_pass():
    values = [1.0, 2.0, 3.0, 4.0]
    record = reduction(values, sequential(4), pairwise(0, 4), bound=0.0)
    result = outcome(record)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["results_differ"] is False


def _swap_operands(steps: list) -> list:
    return [[right, left] for left, right in steps]


MUTANTS = {
    "declared-bound-too-tight": lambda: reduction(
        TIE, sequential(3), (0, (1, 2)), bound=2.0**-53),
    "retained-sequence-altered": lambda: {**reduction(TIE, sequential(3), (0, (1, 2))),
        "values": [value.hex() for value in [1.0, 2.0**-52, 2.0**-53]]},
    "second-order-identical": lambda: reduction(TIE, sequential(3), sequential(3), bound=0.0),
    "second-order-only-commuted": lambda: reduction(
        TIE, sequential(3), mirrored(sequential(3)), bound=0.0),
    "second-order-only-reinterleaved": lambda: {
        **reduction([1.0, 2.0, 3.0, 4.0], pairwise(0, 4), pairwise(0, 4), bound=0.0),
        "alternative_order": [[2, 3], [0, 1], [5, 4]]},
    "retained-result-one-ulp-off": lambda: {**reduction(TIE, sequential(3), (0, (1, 2))),
        "retained_result": math.nextafter(1.0, 2.0).hex()},
    "operand-consumed-twice": lambda: {**reduction(TIE, sequential(3), (0, (1, 2))),
        "alternative_order": [[1, 1], [0, 3]]},
    "step-reads-a-later-step": lambda: {**reduction(TIE, sequential(3), (0, (1, 2))),
        "alternative_order": [[0, 4], [1, 2]]},
    "noncanonical-value-text": lambda: {**reduction(TIE, sequential(3), (0, (1, 2))),
        "values": ["0x1.0p+0", (2.0**-53).hex(), (2.0**-53).hex()]},
    "negative-bound": lambda: {**reduction(TIE, sequential(3), (0, (1, 2))),
        "order_effect_bound": (-1.0).hex()},
}


@pytest.mark.parametrize("label", sorted(MUTANTS))
def test_counterexamples_fail(label):
    result = outcome(MUTANTS[label]())
    assert result["status"] == "FAIL", (label, result["evaluation"]["details"])


def test_mutants_are_counterexamples_under_the_oracle():
    tight = MUTANTS["declared-bound-too-tight"]()
    assert Fraction(float.fromhex(tight["order_effect_bound"])) < effect(
        TIE, sequential(3), (0, (1, 2)))
    altered = [float.fromhex(text) for text in MUTANTS["retained-sequence-altered"]()["values"]]
    assert evaluate(sequential(3), altered).hex() != reduction()["retained_result"]
    assert program(mirrored(sequential(3)), 3) == _swap_operands(program(sequential(3), 3))
    reinterleaved = MUTANTS["second-order-only-reinterleaved"]()
    assert reinterleaved["alternative_order"] != reinterleaved["retained_order"]


def test_checker_matches_oracle_on_seeded_random_trees():
    generator = random.Random(20261001)

    def random_tree(indices: list):
        if len(indices) == 1:
            return indices[0]
        cut = generator.randint(1, len(indices) - 1)
        return (random_tree(indices[:cut]), random_tree(indices[cut:]))

    checked = {"PASS": 0, "FAIL": 0}
    for _ in range(12):
        count = generator.randint(3, 40)
        values = [math.ldexp(generator.random() - 0.5, generator.randint(-30, 30))
                  for _ in range(count)]
        first, second = sequential(count), random_tree(list(range(count)))
        exact = effect(values, first, second)
        bound = ceiling_float(exact)
        result = outcome(reduction(values, first, second, bound=bound))
        assert result["status"] == "PASS", result["evaluation"]["details"]
        assert result["evaluation"]["observations"]["order_effect"] == str(exact)
        checked["PASS"] += 1
        if bound > 0:
            below = math.nextafter(bound, 0.0)
            assert Fraction(below) < exact
            assert outcome(reduction(values, first, second, bound=below))["status"] == "FAIL"
            checked["FAIL"] += 1
    assert checked["PASS"] == 12 and checked["FAIL"] >= 6


@pytest.mark.parametrize("field", ["values", "retained_order", "alternative_order"])
def test_declarations_without_retained_observation_are_unknown(field):
    record = reduction()
    record[field] = None
    assert outcome(record)["status"] == "UNKNOWN"


def test_missing_commitment_inputs_or_unsupported_operation_is_unknown():
    assert outcome(reduction(), payload={"unrelated": True})["status"] == "UNKNOWN"
    assert outcome(reduction(), include_inputs=False)["status"] == "UNKNOWN"
    assert outcome(reduction(operation="binary64-fused-multiply-add-1"))["status"] == "UNKNOWN"
    assert outcome(reduction(), payload={"reduction_digest": digest(
        reduction(bound=1.0))})["status"] == "FAIL"
    # Fields interpreted by the TRAIN-1.x, 2.x and 4.1 checks are carried, not read.
    record = reduction()
    assert outcome(record, payload={"reduction_digest": digest(record),
                                    "start_step": 0, "tolerance": 0})["status"] == "PASS"


def test_host_arithmetic_self_check_failure_is_unknown(monkeypatch):
    monkeypatch.setattr(train_accumulation, "_host_adds_binary64", lambda: False)
    assert outcome(reduction())["status"] == "UNKNOWN"


def test_composition_and_subject_kind_control_the_verdict():
    rows = collection({"reduction_digest": digest(reduction())})
    rows[-1] = NamespaceObject.create("train", "TRAIN", rows[-1].payload, {
        "data": ["data"], "events": ["e0"], "bench": ["loss"], "arch": ["data"]})
    assert outcome(reduction(), rows=rows)["status"] == "FAIL"
    assert outcome(reduction(), max_composition_operations=2)["status"] == "UNKNOWN"
    assert outcome(reduction(), subject_id="loss")["status"] == "FAIL"


def test_operation_budget_one_short_of_measured_use_is_unknown():
    used = outcome(reduction())["evaluation"]["observations"]["operations"]
    assert outcome(reduction(), max_operations=used)["status"] == "PASS"
    assert outcome(reduction(), max_operations=used - 1)["status"] == "UNKNOWN"
    assert outcome(reduction(), max_items=2)["status"] == "UNKNOWN"


def test_single_bit_certificate_tamper_is_rejected():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    for offset in (len(certificate) // 3, len(certificate) // 2, len(certificate) - 5):
        tampered = bytearray(certificate)
        tampered[offset] ^= 0x01
        with pytest.raises(train_accumulation.TrainAccumulationError):
            train_accumulation.recheck_train_accumulation_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_request_policy_or_verdict_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    other = deepcopy(request)
    other["subject_id"] = "train-other"
    with pytest.raises(train_accumulation.TrainAccumulationError):
        train_accumulation.recheck_train_accumulation_certificate(
            certificate, expected_request=other, policy=policy)
    roots = deepcopy(policy)
    roots["trust_roots"] = ["test:other-root"]
    with pytest.raises(train_accumulation.TrainAccumulationError):
        train_accumulation.recheck_train_accumulation_certificate(
            certificate, expected_request=request, policy=roots)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(train_accumulation.TrainAccumulationError):
        train_accumulation.recheck_train_accumulation_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong = deepcopy(request)
    wrong["subject_id"] = "train-other"
    assert replay(wrong, policy, evidence)[1]["status"] == "FAIL"


def test_public_route_replays_selected_reduction():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=train_accumulation.SEMANTIC_VERSION,
        objective=train_accumulation.COORDINATE, represented_kind="TRAIN",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["executing_hardware_arithmetic"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", [
    "domains/contracts/train_accumulation.py",
    "standard/CURRENT_TRAIN_ACCUMULATION.md",
    "standard/NAMESPACE_OBJECTS.md",
    "standard/DOMAIN_OBLIGATIONS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(train_accumulation.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        train_accumulation.recheck_train_accumulation_certificate(
            certificate, expected_request=request, policy=policy)
