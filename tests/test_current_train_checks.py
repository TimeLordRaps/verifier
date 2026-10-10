"""Training run specification (TRAIN) independently selected native checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); stochastic gradient
descent (SGD). This specimen uses dimensionless scalars and exact binary fractions.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import train
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import current_object_routes as routes

SEMANTIC = "verifier-current-object-obligations-1"
CHECKS = {"configuration": "TRAIN-1.2", "checkpoints": "TRAIN-1.3",
          "training": "TRAIN-2.1", "updates": "TRAIN-2.3", "lineage": "TRAIN-4.1"}


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def specimen() -> tuple[dict, dict]:
    config = {"optimizer": "sgd", "learning_rate": 0.125, "weight_decay": 0,
        "beta1": 0.5, "beta2": 0.5, "epsilon": 0.125, "momentum": 0,
        "schedule": "constant", "accumulation": 1, "max_grad_norm": 100,
        "arithmetic": "python-binary64"}
    architecture = {"input_size": 1, "layers": [{"outputs": 1, "activation": "linear"}],
                    "arithmetic": "python-binary64"}
    # Hand-computed: predictions 1 then 1.5; losses 1 then 0.25;
    # derivatives (-2,-2) then (-1,-1). No production optimizer builds this oracle.
    checkpoints = [{"weights": [{"weight": [[w]], "bias": [b]}],
        "optimizer_state": {"step": i, "first": [g, g], "second": [0, 0]}}
        for i, (w, b, g) in enumerate([(1, 0, 0), (1.25, 0.25, -2), (1.375, 0.375, -1)])]
    batch = [[{"input": [1], "target": [2]}]]
    commitments = [digest(c) for c in checkpoints]
    steps = [{"index": i, "parent": commitments[i], "result": commitments[i+1],
        "configuration_digest": digest(config), "batch": digest(batch),
        "gradients": [g, g], "loss": loss} for i, (g, loss) in enumerate([(-2, 1), (-1, 0.25)])]
    return {"configuration": config, "architecture": architecture, "checkpoint_digests": commitments,
        "steps_digest": digest(steps), "start_step": 0, "tolerance": 0}, {
        "checkpoints": checkpoints, "steps": steps, "batches": {digest(batch): batch}}


@pytest.mark.parametrize("check", CHECKS)
def test_current_train_route_is_explicitly_selected(check):
    route = routes.select_current_object_route(semantic_version=SEMANTIC,
        objective=CHECKS[check], represented_kind="TRAIN")
    assert route.fixed_kind == "TRAIN"
    assert route.scope == "finite_retained_train_" + check


@pytest.mark.parametrize("check", CHECKS)
def test_native_positive_controls_execute_every_selected_check(check):
    artifact, retained = specimen()
    result = train.evaluate(check, artifact, retained, Budget(10000))
    if check == "configuration":
        assert result == {"optimizer": "sgd", "arithmetic": "python-binary64"}
    elif check == "checkpoints":
        assert result == {"checkpoints": 3}
    else:
        assert result == {"steps": 2, "start_step": 0}


@pytest.mark.parametrize("check", ["inventories", "", "TRAINING", " training", None, True, ["lineage"]])
def test_unsupported_native_selection_cannot_return_lineage_success(check):
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported training check"):
        train.evaluate(check, artifact, retained, Budget(10000))


def test_subclass_selection_cannot_choose_a_different_check():
    class Forged(str):
        def __eq__(self, other):
            return True
    artifact, retained = specimen()
    with pytest.raises(Unavailable, match="unsupported training check"):
        train.evaluate(Forged("inventories"), artifact, retained, Budget(10000))


def test_unknown_selection_refuses_before_evidence_access():
    class Unreadable(dict):
        def __contains__(self, key):
            raise AssertionError("unsupported selector consumed evidence")
    budget = Budget(0)
    with pytest.raises(Unavailable, match="unsupported training check"):
        train.evaluate("inventories", Unreadable(), Unreadable(), budget)
    assert budget.used == 0


def inputs(check: str, *, artifact=None, retained=None, objects=None, **limits):
    contract = importlib.import_module("verifier.domains.contracts.train_checks")
    if artifact is None:
        artifact, retained = specimen()
    if objects is None:
        support = specimen()[1] if retained is None else retained
        steps = support.get("steps", specimen()[1]["steps"])
        batches = support.get("batches", specimen()[1]["batches"])
        events = ["step-" + str(i) for i in range(len(steps))]
        subject = NamespaceObject.create("training", "TRAIN", artifact,
            {"arch": ["architecture"], "data": ["batches"], "bench": ["loss"], "events": events})
        objects = [subject,
            NamespaceObject.create("architecture", "ARCH", deepcopy(artifact["architecture"])),
            NamespaceObject.create("batches", "DATA", {"batches": deepcopy(batches)}),
            NamespaceObject.create("loss", "BENCH", {"loss": "mean-squared-error",
                "reduction": "mean-samples-and-outputs", "arithmetic": "python-binary64",
                "relu_derivative_at_zero": 0}, {"data": ["batches"], "verifier": ["checker"]}),
            NamespaceObject.create("checker", "VERIFIER", {"mechanism_id": contract.MECHANISM_ID,
                "mechanism_digest": contract.mechanism_digest()}),
            NamespaceObject.create("space", "SPACE", {"scope": "retained-training-trace"}),
            NamespaceObject.create("meaning", "OBJECT", {"operation": "optimizer-update",
                "configuration_digest": digest(artifact["configuration"])})]
        for i, step in enumerate(steps):
            objects.extend([NamespaceObject.create(events[i], "EVENT", {"training_step": deepcopy(step)},
                {"time": ["time-" + str(i)], "space": ["space"], "meaning": ["meaning"]}),
                NamespaceObject.create("time-" + str(i), "TIME", {"index": step["index"]})])
    subject = next(item for item in objects if item.object_id == "training")
    evidence = canonical_bytes({"schema_version": "verifier-current-train-checks-evidence-1",
        "objects": [item.to_dict() for item in objects], "inputs": retained})
    policy = contract.train_checks_policy(trust_roots=["selected-retained-training-only"])
    request = contract.train_checks_request(check=check, subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return contract, request, policy, evidence


def replay(contract, request, policy, evidence):
    certificate = contract.build_train_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="TRAIN", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_train_positive_replay_is_bounded_and_deterministic(check):
    contract, request, policy, evidence = inputs(check)
    first = contract.build_train_checks_certificate(request, evidence, policy=policy)
    assert first == contract.build_train_checks_certificate(request, evidence, policy=policy)
    report = replay(contract, request, policy, evidence)
    assert report["computational_status"] == "PASS", report
    result = report["native_result"]
    assert result["object_profile_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    observed = result["evaluation"]["observations"]["training"]
    if check == "configuration": assert observed["optimizer"] == "sgd"
    elif check == "checkpoints": assert observed["checkpoints"] == 3
    else: assert observed == {"steps": 2, "start_step": 0}


@pytest.mark.parametrize("check", CHECKS)
def test_rehashed_rebound_false_native_evidence_is_refuted(check):
    artifact, retained = specimen()
    if check == "configuration": artifact["configuration"]["learning_rate"] = -0.125
    elif check == "checkpoints": retained["checkpoints"][1]["weights"][0]["bias"] = [0.5]
    elif check == "training": retained["steps"][0]["loss"] = 42
    elif check == "updates": retained["steps"][0]["gradients"] = [0, 0]
    else: retained["steps"][0]["parent"] = "sha256:" + "0" * 64
    artifact["steps_digest"] = digest(retained["steps"])
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
    contract, request, policy, evidence = inputs("training")
    certificate = contract.build_train_checks_certificate(request, evidence, policy=policy)
    request[field] = "other-subject" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_train_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_claim_promotion_is_rejected(field, value):
    contract, request, policy, evidence = inputs("configuration")
    certificate = json.loads(contract.build_train_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({key: val for key, val in certificate.items() if key != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_train_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("bad", [None, [], "", False])
def test_falsey_operands_cannot_normalize_into_valid_train_record(bad):
    contract, request, policy, evidence = inputs("configuration")
    value = json.loads(evidence); value["objects"][0]["operands"] = bad
    evidence = canonical_bytes(value); request["evidence_ref"] = digest(value)
    assert replay(contract, request, policy, evidence)["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
def test_public_train_command_executes_native_replay(check, tmp_path, capsys):
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    values = {"request": canonical_bytes(request), "policy": canonical_bytes(policy),
              "certificate": contract.build_train_checks_certificate(request, evidence, policy=policy)}
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "TRAIN", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_train_certificate_cannot_shed_canonical_evidence():
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("configuration")
    value = json.loads(contract.build_train_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("TRAIN", tuple(key for key in value if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/train_checks.py", "domains/train.py", "domains/numerical.py", "standard/CURRENT_TRAIN_CHECKS.md"])
def test_train_dependencies_invalidate_polish(relative, monkeypatch):
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
def test_train_inventory_preserves_each_registered_objective(check):
    from verifier.domains.inventory import get_slot
    tier = int(CHECKS[check].split("-")[1].split(".")[0])
    row = get_slot("TRAIN", tier).to_dict()
    assert row["mechanized"]
    selected = next(item for item in row["registered_objectives"] if item["coordinate"] == CHECKS[check])
    assert "train_checks" in selected["binding"]["checking_mechanism"]
    assert row["objective_inventory_closure"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", ["domains/contracts/train_checks.py", "domains/train.py", "domains/numerical.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_TRAIN_CHECKS.md", "standard/NAMESPACE_OBJECTS.md", "standard/DOMAIN_GROUNDING.md"])
def test_changed_direct_dependency_invalidates_training_policy(relative, monkeypatch):
    contract, request, policy, evidence = inputs("configuration")
    certificate = contract.build_train_checks_certificate(request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(contract.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_train_checks_certificate(certificate, expected_request=request, policy=policy)


def test_runtime_identity_change_requires_policy_readmission_before_native_replay(monkeypatch):
    contract, request, policy, evidence = inputs("training")
    certificate = contract.build_train_checks_certificate(request, evidence, policy=policy)
    changed = deepcopy(contract._runtime_identity())
    changed["platform"] += "-changed"
    monkeypatch.setattr(contract, "_runtime_identity", lambda: changed)
    monkeypatch.setattr(contract, "_evaluate", lambda *_: pytest.fail("native replay ran before policy admission"))
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_train_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_native_operation_limit_has_exact_and_one_under_controls(check):
    contract, request, policy, evidence = inputs(check)
    result = replay(contract, request, policy, evidence)
    used = result["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"



@pytest.mark.parametrize("target", ["architecture", "batches", "loss", "checker", "space", "meaning", "time-0", "step-0"])
def test_rebound_operand_contradiction_is_refuted(target):
    contract, request, policy, evidence = inputs("training")
    bundle = json.loads(evidence)
    row = next(item for item in bundle["objects"] if item["object_id"] == target)
    if target == "architecture": row["payload"]["layers"][0]["outputs"] = 2
    elif target == "batches": row["payload"]["batches"] = {}
    elif target == "loss": row["payload"]["loss"] = "absolute-error"
    elif target == "checker": row["payload"]["mechanism_digest"] = "sha256:" + "0" * 64
    elif target == "space": row["payload"]["scope"] = "actual-live-execution"
    elif target == "meaning": row["payload"]["operation"] = "inference"
    elif target == "time-0": row["payload"]["index"] = 2
    else: row["payload"]["training_step"]["loss"] = 42
    objects = [NamespaceObject.create(**item) for item in bundle["objects"]]
    assert replay(*inputs("training", artifact=objects[0].payload,
        retained=bundle["inputs"], objects=objects))["computational_status"] == "FAIL"


@pytest.mark.parametrize("mutation,expected", [("missing-checkpoints", "UNKNOWN"),
    ("missing-input", "UNKNOWN"), ("extra-input", "FAIL"), ("unsupported-optimizer", "UNKNOWN"),
    ("unsupported-arithmetic", "UNKNOWN"), ("gap", "FAIL"), ("reorder", "FAIL"),
    ("wrong-loss", "FAIL"), ("wrong-gradient", "FAIL"), ("unused-batch", "FAIL")])
def test_missing_unsupported_or_contradictory_training_evidence(mutation, expected):
    artifact, retained = specimen()
    if mutation == "missing-checkpoints": retained.pop("checkpoints")
    elif mutation == "missing-input": retained = None
    elif mutation == "extra-input": retained["executed"] = True
    elif mutation == "unsupported-optimizer": artifact["configuration"]["optimizer"] = "unregistered"
    elif mutation == "unsupported-arithmetic": artifact["configuration"]["arithmetic"] = "accelerator"
    elif mutation == "gap": retained["steps"][1]["index"] = 2
    elif mutation == "reorder": retained["steps"].reverse()
    elif mutation == "wrong-loss": retained["steps"][0]["loss"] = 42
    elif mutation == "wrong-gradient": retained["steps"][0]["gradients"] = [0, 0]
    else: retained["batches"][digest([])] = []
    if retained is not None: artifact["steps_digest"] = digest(retained["steps"])
    assert replay(*inputs("training", artifact=artifact, retained=retained))["computational_status"] == expected


@pytest.mark.parametrize("check,expected", [("configuration", "PASS"), ("checkpoints", "PASS"),
    ("lineage", "PASS"), ("updates", "PASS"), ("training", "FAIL")])
def test_selected_predicates_do_not_claim_unselected_loss_correctness(check, expected):
    artifact, retained = specimen()
    retained["steps"][0]["loss"] = 42
    artifact["steps_digest"] = digest(retained["steps"])
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == expected


@pytest.mark.parametrize("check,retained", [("configuration", {}), ("checkpoints", {"checkpoints": specimen()[1]["checkpoints"]})])
def test_narrow_native_selection_does_not_require_unselected_evidence(check, retained):
    assert replay(*inputs(check, artifact=specimen()[0], retained=retained))["computational_status"] == "PASS"


def test_real_native_arithmetic_executes_on_build_and_recheck(monkeypatch):
    observed = []
    original = train.loss_gradient
    def tracked(architecture, weights, batch, budget):
        result = original(architecture, weights, batch, budget)
        observed.append(result)
        return result
    monkeypatch.setattr(train, "loss_gradient", tracked)
    assert replay(*inputs("training"))["computational_status"] == "PASS"
    assert observed == [(1.0, [-2.0, -2.0]), (0.25, [-1.0, -1.0])] * 2


@pytest.mark.parametrize("check", CHECKS)
def test_current_training_rejects_legacy_semantic_selection(check):
    contract, request, policy, evidence = inputs(check)
    certificate = contract.build_train_checks_certificate(request, evidence, policy=policy)
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(certificate, semantic_version="verifier-domain-certification-1",
            objective=CHECKS[check], represented_kind="TRAIN", expected_request=request, policy=policy)
