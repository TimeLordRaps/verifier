"""Model reproducibility specification (MODEL) independently selected checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); rectified linear
unit (ReLU). Specimen values and counts are dimensionless.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import model
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
CHECKS = {"artifacts": "MODEL-1.5", "tensors": "MODEL-1.2",
          "inference": "MODEL-2.1", "evaluation": "MODEL-4.2", "challenges": "MODEL-4.4"}


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def specimen() -> tuple[dict, dict]:
    architecture = {"input_size": 1, "layers": [{"outputs": 2, "activation": "relu"},
        {"outputs": 1, "activation": "linear"}], "arithmetic": "python-binary64"}
    weights = [{"weight": [[1], [-1]], "bias": [0, 0]}, {"weight": [[2, -1]], "bias": [0.5]}]
    # Independent function: f(x)=2*max(x,0)-max(-x,0)+1/2.
    samples = [{"id": "sample-" + str(i), "input": [x], "output": [y], "target": [target]}
        for i, (x, y, target) in enumerate([(-2, -1.5, -1), (-1, -0.5, -0.5), (0, 0.5, 1), (2, 4.5, 4.5)])]
    dependencies = {"selected-note": {"scope": "retained-model-only"}}
    challenges = [{"id": "negative", "input": [-3],
        "condition": {"op": "eq", "args": [{"var": "output.0"}, -2.5]}},
        {"id": "positive", "input": [3], "condition": {"op": "eq", "args": [{"var": "output.0"}, 6.5]}}]
    return {"architecture_digest": digest(architecture), "weights_digest": digest(weights),
        "dependencies": {key: digest(value) for key, value in dependencies.items()}, "samples_digest": digest(samples),
        "tolerance": 0, "metric": "mean_squared_error", "metric_bounds": {"minimum": 0.125, "maximum": 0.125},
        "challenges": challenges}, {"architecture": architecture, "weights": weights, "dependencies": dependencies,
        "samples": samples, "metric_value": 0.125}


@pytest.mark.parametrize("check", CHECKS)
def test_current_model_route_is_explicitly_selected(check):
    route = routes.select_current_object_route(semantic_version=SEMANTIC,
        objective=CHECKS[check], represented_kind="MODEL")
    assert route.fixed_kind == "MODEL"
    assert route.scope == "finite_retained_model_" + check


@pytest.mark.parametrize("check", CHECKS)
def test_native_positive_controls_execute_every_selected_check(check):
    artifact, retained = specimen()
    result = model.evaluate(check, artifact, retained, Budget(10000))
    if check == "artifacts": assert result == {"dependencies": 1}
    elif check == "tensors": assert result == {"layers": 2}
    elif check == "inference": assert result == {"samples": 4}
    elif check == "evaluation": assert result == {"samples": 4, "metric_value": 0.125}
    else: assert result == {"challenges": 2}


@pytest.mark.parametrize("check", ["inventories", "", "INFERENCE", " inference", None, True, ["artifacts"]])
def test_unsupported_native_selection_cannot_return_probe_success(check):
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported model check"):
        model.evaluate(check, artifact, retained, Budget(10000))


def test_subclass_selection_cannot_choose_a_different_check():
    class Forged(str):
        def __eq__(self, other): return True
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported model check"):
        model.evaluate(Forged("inventories"), artifact, retained, Budget(10000))


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self, key): raise AssertionError("unsupported selector consumed evidence")
    budget = Budget(0)
    with pytest.raises(Unavailable, match="unsupported model check"):
        model.evaluate("inventories", Unreadable(), Unreadable(), budget)
    assert budget.used == 0


@pytest.mark.parametrize("large", [2**80, 2**100])
@pytest.mark.parametrize("side", ["minimum", "maximum"])
def test_metric_threshold_cannot_round_away_one_unit_violation(large, side):
    artifact, retained = specimen()
    retained["weights"] = [{"weight": [[0], [0]], "bias": [0, 0]}, {"weight": [[0, 0]], "bias": [0]}]
    retained["samples"] = [{"id": "one", "input": [0], "output": [0], "target": [large]}]
    retained["metric_value"] = large
    artifact.update(weights_digest=digest(retained["weights"]), samples_digest=digest(retained["samples"]),
        metric="mean_absolute_error", metric_bounds={"minimum": 0, "maximum": large*2})
    artifact["metric_bounds"][side] = large + (1 if side == "minimum" else -1)
    assert float(artifact["metric_bounds"][side]) == float(large)
    with pytest.raises(Refuted, match="metric outside contract"):
        model.evaluate("evaluation", artifact, retained, Budget(10000))


@pytest.mark.parametrize("metric,expected", [("mean_squared_error", 0.125), ("mean_absolute_error", 0.25)])
def test_independent_metric_answers_and_refutations(metric, expected):
    artifact, retained = specimen()
    artifact.update(metric=metric, metric_bounds={"minimum": expected, "maximum": expected})
    retained["metric_value"] = expected
    assert model.evaluate("evaluation", artifact, retained, Budget(10000))["metric_value"] == expected
    retained["metric_value"] += 0.125
    with pytest.raises(Refuted, match="reported metric differs"):
        model.evaluate("evaluation", artifact, retained, Budget(10000))


def inputs(check: str, *, artifact=None, retained=None, objects=None, **limits):
    contract = importlib.import_module("verifier.domains.contracts.model_checks")
    if artifact is None: artifact, retained = specimen()
    artifact, retained = deepcopy(artifact), deepcopy(retained)
    if objects is None:
        support = specimen()[1] if retained is None else retained
        arch = support.get("architecture", specimen()[1]["architecture"])
        weights = support.get("weights", specimen()[1]["weights"])
        samples = support.get("samples", specimen()[1]["samples"])
        config = {"optimizer": "sgd", "learning_rate": 0.125, "weight_decay": 0,
            "beta1": 0.5, "beta2": 0.5, "epsilon": 0.125, "momentum": 0,
            "schedule": "constant", "accumulation": 1, "max_grad_norm": 100, "arithmetic": "python-binary64"}
        checkpoints = [{"weights": deepcopy(weights), "optimizer_state": {
            "step": i, "first": [0]*7, "second": [0]*7}} for i in (0, 1)]
        batch = [[{"input": [0], "target": [0.5]}]]
        step = {"index": 0, "parent": digest(checkpoints[0]), "result": digest(checkpoints[1]),
            "configuration_digest": digest(config), "batch": digest(batch), "gradients": [0]*7, "loss": 0}
        training = {"configuration": config, "architecture": deepcopy(arch),
            "checkpoint_digests": [digest(c) for c in checkpoints], "steps_digest": digest([step]),
            "start_step": 0, "tolerance": 0}
        environment = {"declared_arithmetic": "python-binary64", "execution_observation": "NOT_ESTABLISHED"}
        hardware = {"declared_format": "binary64", "hardware_authenticity": "NOT_ESTABLISHED"}
        dependencies = {"training": training, "checkpoint": checkpoints[-1], "environment": environment, "hardware": hardware}
        artifact["dependencies"] = {key: digest(item) for key, item in dependencies.items()}
        if retained is not None: retained["dependencies"] = deepcopy(dependencies)
        events = ["event-" + str(i) for i in range(len(samples))]
        subject = NamespaceObject.create("model", "MODEL", artifact, {"arch": ["architecture"],
            "data": ["dataset"], "bench": ["benchmark"], "train": ["training"], "events": events,
            "env": ["environment"], "hardware": ["hardware"]})
        train_contract = importlib.import_module("verifier.domains.contracts.train_checks")
        objects = [subject, NamespaceObject.create("architecture", "ARCH", arch),
            NamespaceObject.create("dataset", "DATA", {"samples": samples}),
            NamespaceObject.create("benchmark", "BENCH", {key: artifact[key] for key in
                ("metric", "metric_bounds", "tolerance", "challenges")}, {"data": ["dataset"], "verifier": ["checker"]}),
            NamespaceObject.create("checker", "VERIFIER", {"mechanism_id": contract.MECHANISM_ID,
                "mechanism_digest": contract.mechanism_digest()}),
            NamespaceObject.create("environment", "ENV", environment), NamespaceObject.create("hardware", "HARDWARE", hardware),
            NamespaceObject.create("training", "TRAIN", training, {"arch": ["architecture"],
                "data": ["training-data"], "bench": ["training-loss"], "events": ["training-event"]}),
            NamespaceObject.create("training-data", "DATA", {"batches": {digest(batch): batch}}),
            NamespaceObject.create("training-loss", "BENCH", {"loss": "mean-squared-error",
                "reduction": "mean-samples-and-outputs", "arithmetic": "python-binary64", "relu_derivative_at_zero": 0},
                {"data": ["training-data"], "verifier": ["training-checker"]}),
            NamespaceObject.create("training-checker", "VERIFIER", {"mechanism_id": train_contract.MECHANISM_ID,
                "mechanism_digest": train_contract.mechanism_digest()}),
            NamespaceObject.create("training-event", "EVENT", {"training_step": step},
                {"time": ["training-time"], "space": ["training-space"], "meaning": ["training-meaning"]}),
            NamespaceObject.create("training-time", "TIME", {"index": 0}),
            NamespaceObject.create("training-space", "SPACE", {"scope": "retained-training-trace"}),
            NamespaceObject.create("training-meaning", "OBJECT", {"operation": "optimizer-update", "configuration_digest": digest(config)}),
            NamespaceObject.create("space", "SPACE", {"scope": "retained-model-evaluation"}),
            NamespaceObject.create("meaning", "OBJECT", {"operation": "model-inference",
                "weights_digest": artifact["weights_digest"], "architecture_digest": artifact["architecture_digest"]})]
        for i, sample in enumerate(samples):
            objects.extend([NamespaceObject.create(events[i], "EVENT", {"index": i, "sample": sample},
                {"time": ["time-"+str(i)], "space": ["space"], "meaning": ["meaning"]}),
                NamespaceObject.create("time-"+str(i), "TIME", {"index": i})])
    subject = next(item for item in objects if item.object_id == "model")
    evidence = canonical_bytes({"schema_version": "verifier-current-model-checks-evidence-1",
        "objects": [item.to_dict() for item in objects], "inputs": retained})
    policy = contract.model_checks_policy(trust_roots=["selected-retained-model-only"])
    request = contract.model_checks_request(check=check, subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_model_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="MODEL", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_model_positive_replay_is_bounded_and_deterministic(check):
    contract, request, policy, evidence = inputs(check)
    first = contract.build_model_checks_certificate(request, evidence, policy=policy)
    assert first == contract.build_model_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS", report
    result = report["native_result"]
    assert result["object_profile_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    observed = result["evaluation"]["observations"]["model"]
    expected = {"artifacts": {"dependencies": 4}, "tensors": {"layers": 2}, "inference": {"samples": 4},
        "evaluation": {"samples": 4, "metric_value": 0.125}, "challenges": {"challenges": 2}}
    assert observed == expected[check]


@pytest.mark.parametrize("check", CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact, retained = specimen()
    if check == "artifacts": artifact["weights_digest"] = "sha256:" + "0"*64
    elif check == "tensors":
        retained["weights"][0]["weight"] = [[1, 1], [-1, -1]]
        artifact["weights_digest"] = digest(retained["weights"])
    elif check == "inference":
        retained["samples"][0]["output"] = [42]
        artifact["samples_digest"] = digest(retained["samples"])
    elif check == "evaluation": retained["metric_value"] = 42
    else: artifact["challenges"][0]["condition"]["args"][1] = 42
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "FAIL"


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
    contract, request, policy, evidence = inputs("inference")
    certificate = contract.build_model_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_model_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("artifacts")
    certificate = json.loads(contract.build_model_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_model_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_model_record(bad):
    contract, request, policy, evidence = inputs("artifacts")
    value = json.loads(evidence); value["objects"][0]["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_model_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_model_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "MODEL", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_model_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("artifacts")
    value = json.loads(contract.build_model_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("MODEL", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/model_checks.py", "domains/model.py", "domains/numerical.py", "standard/CURRENT_MODEL_CHECKS.md"])
def test_model_dependencies_invalidate_polish(relative, monkeypatch):
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
def test_model_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("MODEL", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "model_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/model_checks.py", "domains/model.py", "domains/numerical.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_MODEL_CHECKS.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_direct_dependency_invalidates_model_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("artifacts")
    certificate = contract.build_model_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_model_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"




@pytest.mark.parametrize("target", ["architecture", "dataset", "benchmark", "checker", "training", "environment", "hardware", "space", "meaning", "time-0", "event-0"])
def test_rebound_operand_contradiction_is_refuted(target):
    contract, request, policy, evidence = inputs("evaluation")
    bundle = json.loads(evidence)
    row = next(item for item in bundle["objects"] if item["object_id"] == target)
    if target == "architecture": row["payload"]["input_size"] = 2
    elif target == "dataset": row["payload"]["samples"][0]["target"] = [99]
    elif target == "benchmark": row["payload"]["metric"] = "accuracy"
    elif target == "checker": row["payload"]["mechanism_digest"] = "sha256:" + "0"*64
    elif target == "training": row["payload"]["checkpoint_digests"][-1] = "sha256:" + "0"*64
    elif target in ("environment", "hardware"): row["payload"]["substitution"] = True
    elif target == "space": row["payload"]["scope"] = "actual-deployment"
    elif target == "meaning": row["payload"]["operation"] = "training"
    elif target == "time-0": row["payload"]["index"] = 99
    else: row["payload"]["sample"]["output"] = [99]
    objects = [NamespaceObject.create(**item) for item in bundle["objects"]]
    assert replay(*inputs("evaluation", artifact=objects[0].payload,
        retained=bundle["inputs"], objects=objects))["computational_status"] == "FAIL"


@pytest.mark.parametrize("mutation,expected", [("missing-weights", "UNKNOWN"), ("missing-input", "UNKNOWN"),
    ("extra-input", "FAIL"), ("unsupported-metric", "UNKNOWN"), ("unsupported-arithmetic", "UNKNOWN"),
    ("duplicate-sample", "FAIL"), ("wrong-metric", "FAIL"), ("wrong-output", "FAIL")])
def test_missing_unsupported_or_contradictory_model_evidence(mutation, expected):
    artifact, retained = specimen()
    if mutation == "missing-weights": retained.pop("weights")
    elif mutation == "missing-input": retained = None
    elif mutation == "extra-input": retained["deployed"] = True
    elif mutation == "unsupported-metric": artifact["metric"] = "unregistered"
    elif mutation == "unsupported-arithmetic":
        retained["architecture"]["arithmetic"] = "accelerator"
        artifact["architecture_digest"] = digest(retained["architecture"])
    elif mutation == "duplicate-sample": retained["samples"].append(deepcopy(retained["samples"][0]))
    elif mutation == "wrong-metric": retained["metric_value"] = 42
    else: retained["samples"][0]["output"] = [42]
    if retained is not None: artifact["samples_digest"] = digest(retained["samples"])
    assert replay(*inputs("evaluation", artifact=artifact, retained=retained))["computational_status"] == expected


@pytest.mark.parametrize("check,expected", [("artifacts", "PASS"), ("tensors", "PASS"),
    ("inference", "PASS"), ("challenges", "PASS"), ("evaluation", "FAIL")])
def test_unselected_metric_correctness_is_not_claimed(check, expected):
    artifact, retained = specimen(); retained["metric_value"] = 42
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == expected


@pytest.mark.parametrize("check", ["artifacts", "tensors", "challenges"])
def test_narrow_selection_does_not_require_unselected_sample_bytes(check):
    artifact, retained = specimen(); retained.pop("samples"); retained.pop("metric_value")
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "PASS"


def test_real_forward_arithmetic_runs_during_build_and_recheck(monkeypatch):
    observed = []; original = model.forward
    def tracked(net, x, budget):
        result = original(net, x, budget); observed.append(result[0]); return result
    monkeypatch.setattr(model, "forward", tracked)
    assert replay(*inputs("inference"))["computational_status"] == "PASS"
    assert observed == [[-1.5], [-0.5], [0.5], [4.5]] * 2


def test_training_operand_contains_a_native_replayable_zero_gradient_step():
    from verifier.domains import train
    contract, request, policy, evidence = inputs("artifacts")
    bundle = json.loads(evidence); records = {row["object_id"]: row for row in bundle["objects"]}
    final = bundle["inputs"]["dependencies"]["checkpoint"]
    initial = deepcopy(final); initial["optimizer_state"]["step"] = 0
    retained = {"checkpoints": [initial, final],
        "steps": [records["training-event"]["payload"]["training_step"]],
        "batches": records["training-data"]["payload"]["batches"]}
    assert train.evaluate("training", records["training"]["payload"], retained, Budget(10000)) == {"steps": 1, "start_step": 0}


@pytest.mark.parametrize("check", CHECKS)
def test_current_model_rejects_legacy_semantic_selection(check):
    contract, request, policy, evidence = inputs(check)
    certificate = contract.build_model_checks_certificate(request, evidence, policy=policy)
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(certificate, semantic_version="verifier-domain-certification-1",
            objective=CHECKS[check], represented_kind="MODEL", expected_request=request, policy=policy)
