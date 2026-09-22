"""Adversarial qualification of Verifier Standard (VSTD) retained domain computations.

Terminology: application programming interface (API); command-line interface (CLI);
JavaScript Object Notation (JSON); stochastic gradient descent (SGD).
Terminology: unsatisfiable (UNSAT).
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.domains.catalog import CHECKS
from verifier.domains.certification import (NativeDomainAdapter, build_domain_certificate,
    domain_policy, domain_request, recheck_domain_certificate)
from verifier.domains.common import Budget, Refuted, Unavailable, digest, merkle_root
from verifier.domains.numerical import forward, loss_gradient, network, update

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def bundles() -> dict:
    spec = importlib.util.spec_from_file_location("domain_example", ROOT / "examples/domain_grounding.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.specimens()


@pytest.fixture(scope="module")
def policy() -> dict:
    return domain_policy(trust_roots=["test:retained-inputs", "test:checker"])


def assess(bundle: dict, policy: dict) -> dict:
    return build_domain_certificate(domain_request(bundle), bundle, policy=policy)


@pytest.mark.parametrize("domain,depth", [(d,i) for d,checks in CHECKS.items() for i in range(1,len(checks)+1)])
def test_every_native_domain_prerequisite_replays(domain: str, depth: int, bundles: dict, policy: dict) -> None:
    request = domain_request(bundles[domain], target_depth=depth)
    certificate = build_domain_certificate(request, bundles[domain], policy=policy)
    result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS", result
    assert result["domain_depth"] == depth
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert all(row["established"] for row in result["checks"].values())


@pytest.mark.parametrize("domain", CHECKS)
def test_missing_evidence_never_certifies(domain: str, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles[domain])
    bundle["inputs"] = {}
    result = assess(bundle, policy)["result"]
    assert result["status"] == "UNKNOWN"
    assert result["domain_depth"] < len(CHECKS[domain])


@pytest.mark.parametrize("domain", CHECKS)
def test_reshashed_forged_result_is_rejected(domain: str, bundles: dict, policy: dict) -> None:
    certificate = assess(bundles[domain], policy)
    certificate["result"]["checks"][domain+".1"]["evaluation"]["observations"] = {"invented": True}
    certificate.pop("certificate_digest")
    certificate["certificate_digest"] = digest(certificate)
    result = recheck_domain_certificate(certificate, expected_request=domain_request(bundles[domain]), policy=policy)
    assert result["status"] == "REJECTED"


@pytest.mark.parametrize("domain", CHECKS)
def test_external_request_refuses_whole_bundle_substitution(domain: str, bundles: dict, policy: dict) -> None:
    substitute = deepcopy(bundles[domain])
    substitute["subject_id"] = "other-subject"
    certificate = assess(substitute, policy)
    assert recheck_domain_certificate(certificate, expected_request=domain_request(bundles[domain]), policy=policy)["status"] == "REJECTED"


@pytest.mark.parametrize("domain", CHECKS)
def test_policy_and_resource_bounds_cannot_be_self_selected(domain: str, bundles: dict, policy: dict) -> None:
    certificate = assess(bundles[domain], policy)
    changed = deepcopy(policy)
    changed["trust_roots"] = ["other-root"]
    assert recheck_domain_certificate(certificate, expected_request=domain_request(bundles[domain]), policy=changed)["status"] == "REJECTED"
    bounded = deepcopy(policy)
    bounded["max_evidence_bytes"] = 1
    result = assess(bundles[domain], bounded)["result"]
    assert result["status"] == "UNKNOWN"
    assert result["domain_depth"] == 0


@pytest.mark.parametrize("domain", CHECKS)
def test_operation_exhaustion_preserves_unknown(domain: str, bundles: dict, policy: dict) -> None:
    bounded = deepcopy(policy)
    bounded["max_operations"] = 1
    result = assess(bundles[domain], bounded)["result"]
    assert result["status"] == "UNKNOWN", result
    assert result["domain_depth"] < len(CHECKS[domain])


def test_dataset_semantic_counterexamples(bundles: dict, policy: dict) -> None:
    for field, value, coordinate in (("fields", {"id": "integer", "text": "string"}, "DATA.2"),
            ("transforms", [{"inputs": ["source"], "output": "training", "operation": "filter_eq", "parameters": {"field": "id", "value": "a"}}], "DATA.3"),
            ("splits", {"train": ["training"], "test": ["testing", "training"]}, "DATA.4")):
        bundle = deepcopy(bundles["DATA"])
        bundle["artifact"][field] = value
        result = assess(bundle, policy)["result"]
        assert result["checks"][coordinate]["evaluation"]["outcome"] == "FAIL"
        assert result["domain_depth"] < int(coordinate[-1])


def test_dataset_overlap_recomputed_after_rebinding_integrity(bundles: dict, policy: dict) -> None:
    from verifier.core.certificate import canonical_bytes
    bundle = deepcopy(bundles["DATA"])
    rows = bundle["inputs"]["shards"]["testing"]
    rows[0]["text"] = "red apple"
    bundle["artifact"]["shards"]["testing"] = {"digest": digest(rows), "records": len(rows),
        "bytes": len(canonical_bytes(rows)), "record_digests": [digest(r) for r in rows], "merkle_root": merkle_root(rows, Budget(10000))}
    result = assess(bundle, policy)["result"]
    assert result["domain_depth"] == 4
    assert result["checks"]["DATA.5"]["evaluation"]["outcome"] == "FAIL"


@pytest.mark.parametrize("field,value,coordinate", [
    ("configuration", {}, "ENV.2"),
    ("measurements", [{"wall_seconds": 100.0, "memory_bytes": 1, "threads": 1}], "ENV.3"),
    ("executions", [], "ENV.4")])
def test_environment_does_not_promote_incomplete_or_excess_observations(field: str, value: object, coordinate: str, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["ENV"])
    bundle["inputs"][field] = value
    result = assess(bundle, policy)["result"]
    assert result["checks"][coordinate]["evaluation"]["outcome"] in ("FAIL", "UNKNOWN")
    assert result["domain_depth"] < int(coordinate[-1])


def test_environment_physical_scope_is_unknown(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["ENV"])
    bundle["artifact"]["scope"] = "physical-isolation"
    assert assess(bundle, policy)["result"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["wrong-answer", "missing-run", "duplicate-run", "substitute-problem", "forged-score", "over-budget"])
def test_benchmark_actual_oracles_and_complete_scoring(mutation: str, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["BENCH"])
    runs = bundle["inputs"]["runs"]
    if mutation == "wrong-answer":
        runs[0]["answer"] = [False, False]
    elif mutation == "missing-run":
        runs.pop()
    elif mutation == "duplicate-run":
        runs.append(deepcopy(runs[0]))
    elif mutation == "substitute-problem":
        runs[0]["problem_digest"] = runs[1]["problem_digest"]
    elif mutation == "forged-score":
        bundle["inputs"]["score"] = 0.0
    else:
        runs[0]["execution_ms"] = 1001
    assert assess(bundle, policy)["result"]["status"] != "PASS"


def test_exhaustive_unsatisfiability_is_bounded(bundles: dict, policy: dict) -> None:
    from verifier.domains.bench import oracle
    with pytest.raises(Unavailable):
        oracle({"kind": "cnf-unsat", "specification": {"variables": 24, "clauses": [[1],[-1]]}}, "UNSAT", Budget(50))
    assert oracle({"kind": "cnf-unsat", "specification": {"variables": 1, "clauses": [[1]]}}, "UNSAT", Budget(50)) is False


def test_dense_backprop_matches_independent_finite_difference() -> None:
    architecture = {"input_size": 2, "layers": [{"outputs": 2, "activation": "relu"}, {"outputs": 1, "activation": "linear"}], "arithmetic": "python-binary64"}
    weights = [{"weight": [[0.5,0.25],[-0.25,0.5]], "bias": [0.1,0.2]}, {"weight": [[0.3,-0.2]], "bias": [0.05]}]
    batch = [{"input": [1.0,2.0], "target": [0.7]}, {"input": [2.0,1.0], "target": [0.4]}]
    loss, gradient = loss_gradient(architecture, weights, batch, Budget(10000))
    # Independent scalar loss, without production forward/backprop helpers.
    def objective(w: list) -> float:
        total = 0.0
        for sample in batch:
            x,y = sample["input"]
            a = max(0, w[0]*x+w[1]*y+w[4])
            b = max(0, w[2]*x+w[3]*y+w[5])
            prediction = w[6]*a+w[7]*b+w[8]
            total += (prediction-sample["target"][0])**2/2
        return total
    flat = [0.5,0.25,-0.25,0.5,0.1,0.2,0.3,-0.2,0.05]
    assert loss == pytest.approx(objective(flat), abs=1e-14)
    for i, actual in enumerate(gradient):
        left, right = flat.copy(), flat.copy()
        left[i] -= 1e-6
        right[i] += 1e-6
        assert actual == pytest.approx((objective(right)-objective(left))/2e-6, abs=1e-9)


@pytest.mark.parametrize("optimizer,expected", [("sgd", [0.9,-0.2]), ("adam", [0.9,-0.1]), ("adamw", [0.89,-0.1])])
def test_optimizer_equations_independent_known_answer(optimizer: str, expected: list, bundles: dict) -> None:
    config = deepcopy(bundles["TRAIN"]["artifact"]["configuration"])
    config.update(optimizer=optimizer, epsilon=1e-15, weight_decay=0.1 if optimizer == "adamw" else 0.0)
    weights, state = update([{"weight": [[1.0]], "bias": [0.0]}], [1.0,2.0],
        {"step": 0, "first": [0.0,0.0], "second": [0.0,0.0]}, config, Budget(100))
    assert weights[0]["weight"][0][0] == pytest.approx(expected[0], abs=1e-14)
    assert weights[0]["bias"][0] == pytest.approx(expected[1], abs=1e-14)
    assert state["step"] == 1


def test_training_recomputes_gradients_not_only_optimizer(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["TRAIN"])
    batch = [[{"input": [1.0], "target": [3.0]}]]
    bundle["inputs"]["batches"] = {digest(batch): batch}
    bundle["inputs"]["steps"][0]["batch"] = digest(batch)
    bundle["artifact"]["steps_digest"] = digest(bundle["inputs"]["steps"])
    result = assess(bundle, policy)["result"]
    assert result["domain_depth"] == 4
    assert result["checks"]["TRAIN.5"]["evaluation"]["outcome"] == "FAIL"


def test_training_parent_and_update_are_checked(bundles: dict, policy: dict) -> None:
    for mutation in ("parent", "gradient"):
        bundle = deepcopy(bundles["TRAIN"])
        step = bundle["inputs"]["steps"][0]
        if mutation == "parent":
            step["parent"] = step["result"]
        else:
            step["gradients"] = [0.0,0.0]
        bundle["artifact"]["steps_digest"] = digest(bundle["inputs"]["steps"])
        assert assess(bundle, policy)["result"]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["output", "metric", "challenge", "tensor"])
def test_model_executes_outputs_metrics_and_counterexamples(mutation: str, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["MODEL"])
    if mutation == "output":
        bundle["inputs"]["samples"][0]["output"] = [99.0]
        bundle["artifact"]["samples_digest"] = digest(bundle["inputs"]["samples"])
    elif mutation == "metric":
        bundle["inputs"]["metric_value"] = 1.0
    elif mutation == "challenge":
        bundle["artifact"]["challenges"][0]["condition"]["args"][1] = 99.0
    else:
        bundle["inputs"]["weights"][0]["weight"] = [[1.0,2.0]]
        bundle["artifact"]["weights_digest"] = digest(bundle["inputs"]["weights"])
    assert assess(bundle, policy)["result"]["status"] == "FAIL"


@pytest.mark.parametrize("mutation,coordinate", [("transition","SIM.1"), ("invariant","SIM.2"), ("projection","SIM.3"), ("channel","SIM.4"), ("shards","SIM.5")])
def test_simulation_mainstay_counterexamples(mutation: str, coordinate: str, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["SIM"])
    if mutation == "transition":
        bundle["artifact"]["transition"]["x"]["args"][1] = 2.0
    elif mutation == "invariant":
        bundle["artifact"]["invariants"][0]["args"][1] = 1.0
    elif mutation == "projection":
        bundle["artifact"]["projection"]["double"]["args"][1] = 3.0
    elif mutation == "channel":
        bundle["inputs"]["actions"][0]["move"] = 2.0
    else:
        bundle["inputs"]["shards"]["left"][1]["state"] = {"x": 99.0}
    result = assess(bundle, policy)["result"]
    assert result["checks"][coordinate]["evaluation"]["outcome"] == "FAIL"


def test_trace_invariant_cannot_become_closed_state_proof(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["SIM"])
    bundle["artifact"]["finite_state_set"] = bundle["inputs"]["states"]
    bundle["artifact"]["finite_entropy_set"] = [0.0]
    result = assess(bundle, policy)["result"]
    assert result["checks"]["SIM.2"]["evaluation"]["outcome"] == "FAIL"
    assert "transition-closed" in result["checks"]["SIM.2"]["evaluation"]["details"]


def test_shard_signature_authenticates_exact_coordinate(bundles: dict, policy: dict) -> None:
    # OPTIONAL_DEPENDENCY_ABSENT: signatures require the documented seal extra.
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519", reason="OPTIONAL_DEPENDENCY_ABSENT: seal signature backend")
    from cryptography.hazmat.primitives import serialization
    from verifier.core.certificate import canonical_bytes
    import base64
    bundle = deepcopy(bundles["SIM"])
    bundle["artifact"]["shards"]["require_signatures"] = True
    keys = {k: crypto.Ed25519PrivateKey.generate() for k in ("left","right")}
    admitted = deepcopy(policy)
    admitted["witness_keys"] = {k: v.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() for k,v in keys.items()}
    for key, rows in bundle["inputs"]["shards"].items():
        for i,row in enumerate(rows):
            message = {"artifact_digest": digest(bundle["artifact"]), "shard": key, "step": i, "time": row["time"], "state": row["state"]}
            row["signature"] = base64.b64encode(keys[key].sign(canonical_bytes(message))).decode()
    assert assess(bundle, admitted)["result"]["status"] == "PASS"
    assert assess(bundle, policy)["result"]["status"] == "UNKNOWN"
    bundle["inputs"]["shards"]["left"][0]["signature"] = bundle["inputs"]["shards"]["right"][0]["signature"]
    assert assess(bundle, admitted)["result"]["status"] == "FAIL"


def test_domain_cli_assess_check_and_no_overwrite(tmp_path: Path, bundles: dict, policy: dict) -> None:
    values = {"evidence": bundles["MODEL"], "request": domain_request(bundles["MODEL"]), "policy": policy}
    for key, value in values.items():
        (tmp_path / (key+".json")).write_text(json.dumps(value), encoding="utf-8")
    base = [sys.executable, "-m", "verifier.runtime.public_cli", "certification"]
    args = [str(tmp_path/"evidence.json"), "--request", str(tmp_path/"request.json"), "--policy", str(tmp_path/"policy.json"), "--output", str(tmp_path/"certificate.json"), "--json"]
    completed = subprocess.run(base+["domain-assess"]+args, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout+completed.stderr
    completed = subprocess.run(base+["domain-check", str(tmp_path/"certificate.json"), "--request", str(tmp_path/"request.json"), "--policy", str(tmp_path/"policy.json"), "--json"], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout+completed.stderr
    assert json.loads(completed.stdout)["domain_depth"] == 5
    completed = subprocess.run(base+["domain-assess"]+args, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["status"] == "REJECTED"


@pytest.mark.parametrize("domain", CHECKS)
def test_domain_envelope_schemas_and_packaged_copies(domain: str, bundles: dict, policy: dict) -> None:
    from jsonschema import Draft202012Validator
    values = {"evidence": bundles[domain], "request": domain_request(bundles[domain]),
              "policy": policy, "certification": assess(bundles[domain], policy)}
    for kind, value in values.items():
        name = f"verifier-domain-{kind}-1.schema.json"
        source = (ROOT / "src/verifier/schemas" / name).read_bytes()
        assert source == (ROOT / "src/verifier/schemas" / name).read_bytes()
        schema = json.loads(source)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(value)
        extra = deepcopy(value)
        extra["unrecognized"] = True
        assert list(validator.iter_errors(extra))


def test_nested_oracle_tolerance_and_missing_measurement_fail_closed(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["BENCH"])
    problem = bundle["artifact"]["problems"][2]
    problem["specification"]["tolerance"] = 100000.0
    bundle["inputs"]["runs"][2]["problem_digest"] = digest(problem)
    assert assess(bundle, policy)["result"]["status"] == "UNKNOWN"
    bundle = deepcopy(bundles["ENV"])
    bundle["inputs"]["measurements"].pop()
    assert assess(bundle, policy)["result"]["checks"]["ENV.3"]["evaluation"]["outcome"] == "FAIL"


def test_unsupported_workload_fields_are_not_silently_ignored(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["MODEL"])
    bundle["artifact"]["universal_safety"] = True
    with pytest.raises(ValueError, match="unsupported domain evidence field"):
        assess(bundle, policy)


def test_nonfinite_oversize_and_non_json_inputs_rejected(bundles: dict, policy: dict) -> None:
    for value in (float("nan"), float("inf"), 10**400, (1,2)):
        bundle = deepcopy(bundles["MODEL"])
        bundle["artifact"]["tolerance"] = value
        with pytest.raises(ValueError):
            assess(bundle, policy)


def test_projection_changes_schema_with_retained_source(bundles: dict, policy: dict) -> None:
    from verifier.core.certificate import canonical_bytes
    bundle = deepcopy(bundles["DATA"])
    bundle["inputs"]["shards"]["source"] = deepcopy(bundle["inputs"]["shards"]["source"])
    source = bundle["inputs"]["shards"]["source"]
    for row in source:
        row["auxiliary"] = 7
    bundle["artifact"]["shards"]["source"] = {"digest": digest(source), "records": len(source),
        "bytes": len(canonical_bytes(source)), "record_digests": [digest(r) for r in source], "merkle_root": merkle_root(source, Budget(100))}
    shared = bundle["artifact"].pop("fields")
    bundle["artifact"]["shard_fields"] = {"source": dict(shared, auxiliary="integer"), "training": shared, "testing": shared}
    bundle["artifact"]["transforms"][0].update(operation="project", parameters={"fields": ["id", "text"]})
    assert assess(bundle, policy)["result"]["status"] == "PASS"
    bundle["artifact"]["shard_fields"].pop("source")
    assert assess(bundle, policy)["result"]["status"] == "FAIL"


@pytest.mark.parametrize("metric,targets,measured", [("accuracy", [0,0], 1.0), ("mean_absolute_error", [[0.0],[1.0]], 1.0)])
def test_other_native_model_metrics(metric: str, targets: list, measured: float, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["MODEL"])
    for sample, target in zip(bundle["inputs"]["samples"], targets):
        sample["target"] = target
    bundle["artifact"].update(metric=metric, samples_digest=digest(bundle["inputs"]["samples"]), metric_bounds={"minimum": measured, "maximum": measured})
    bundle["inputs"]["metric_value"] = measured
    assert assess(bundle, policy)["result"]["status"] == "PASS"


def test_training_resume_and_gradient_accumulation(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["TRAIN"])
    checkpoints = bundle["inputs"]["checkpoints"]
    checkpoints.append({"weights": [{"weight": [[1.32]], "bias": [0.32]}],
        "optimizer_state": {"step": 2, "first": [-1.2,-1.2], "second": [0.0,0.0]}})
    first = bundle["inputs"]["steps"][0]
    second = dict(first, index=1, parent=digest(checkpoints[1]), result=digest(checkpoints[2]), gradients=[-1.2,-1.2], loss=0.36)
    bundle["inputs"]["steps"].append(second)
    bundle["artifact"].update(checkpoint_digests=[digest(c) for c in checkpoints], steps_digest=digest(bundle["inputs"]["steps"]))
    assert assess(bundle, policy)["result"]["status"] == "PASS"
    bundle["inputs"]["checkpoints"] = checkpoints[1:]
    bundle["inputs"]["steps"] = [second]
    bundle["artifact"].update(start_step=1, checkpoint_digests=[digest(c) for c in checkpoints[1:]], steps_digest=digest([second]))
    assert assess(bundle, policy)["result"]["status"] == "PASS"
    # The same mean gradient from two equal-sized microbatches.
    batch = list(bundle["inputs"]["batches"].values())[0]*2
    bundle["inputs"]["batches"] = {digest(batch): batch}
    bundle["artifact"]["configuration"]["accumulation"] = 2
    second.update(batch=digest(batch), configuration_digest=digest(bundle["artifact"]["configuration"]))
    bundle["artifact"]["steps_digest"] = digest([second])
    assert assess(bundle, policy)["result"]["status"] == "PASS"


def test_closed_finite_simulation_boundary_is_actually_checked(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["SIM"])
    states = [{"x": 0.0},{"x": 1.0},{"x": 0.0}]
    macro = [{"double": 0.0},{"double": 2.0},{"double": 0.0}]
    bundle["artifact"].update(transition={"x": {"op": "sub", "args": [1.0,{"var": "x"}]}},
        trajectory_digest=digest(states), macro_digest=digest(macro), finite_state_set=states[:2], finite_entropy_set=[0.0])
    bundle["inputs"].update(states=states, observations=states, macro_states=macro)
    for rows in bundle["inputs"]["shards"].values():
        for row, state in zip(rows,states):
            row["state"] = state
    assert assess(bundle, policy)["result"]["status"] == "PASS"


def test_record_named_tolerance_is_data_not_checker_configuration(bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["MODEL"])
    bundle["inputs"]["dependencies"]["training-data"] = {"tolerance": "ordinary user data"}
    bundle["artifact"]["dependencies"]["training-data"] = digest(bundle["inputs"]["dependencies"]["training-data"])
    assert assess(bundle, policy)["result"]["status"] == "PASS"


@pytest.mark.parametrize("shadow", ["root", "root.x"])
def test_shards_cannot_shadow_reference_relation_namespace(shadow: str, bundles: dict, policy: dict) -> None:
    bundle = deepcopy(bundles["SIM"])
    bundle["artifact"]["shards"]["ids"] = [shadow, "right"]
    bundle["inputs"]["shards"][shadow] = bundle["inputs"]["shards"].pop("left")
    bundle["artifact"]["shards"]["relations"][0]["args"][0]["var"] = shadow+".x"
    # With shadow == root, both retained shards agree with each other, but neither
    # agrees with the actual reference. Dictionary overwrite formerly hid that.
    for rows in bundle["inputs"]["shards"].values():
        for row in rows:
            row["state"] = {"x": 99.0}
    result = assess(bundle, policy)["result"]
    assert result["domain_depth"] == 4
    assert result["checks"]["SIM.5"]["evaluation"]["outcome"] == "FAIL"
    assert "reserved relation namespace" in result["checks"]["SIM.5"]["evaluation"]["details"]


def test_unavailable_check_does_not_block_independent_siblings(bundles: dict, policy: dict) -> None:
    """SIM fans out from SIM.1; an unavailable SIM.3 must not unestablish SIM.4/SIM.5.

    Regression guard. The catalog previously synthesized a linear ``i-1`` chain for
    every domain, so a single UNKNOWN made every later check report
    ``established: false`` while its own evaluation said PASS -- the certificate
    contradicted itself. Establishment now follows the declared dependency graph.
    """
    bundle = deepcopy(bundles["SIM"])
    bundle["artifact"]["projection"] = {}
    checks = assess(bundle, policy)["result"]["checks"]

    assert checks["SIM.3"]["evaluation"]["outcome"] == "UNKNOWN"
    assert checks["SIM.3"]["established"] is False

    # Asserted before any blocked_by lookup so this fails on the establishment
    # semantics themselves, not merely on the absence of the explanatory field.
    independent = ("SIM.2", "SIM.4", "SIM.5")
    assert [checks[c]["evaluation"]["outcome"] for c in independent] == ["PASS"] * 3
    assert [checks[c]["established"] for c in independent] == [True] * 3
    assert [checks[c]["blocked_by"] for c in independent] == [[]] * 3

    # The consecutive-prefix depth is unchanged: it still stops at the gap.
    assert assess(bundle, policy)["result"]["domain_depth"] == 2


def test_declared_dependencies_match_established_blocking(bundles: dict, policy: dict) -> None:
    """Every ``blocked_by`` entry must be a dependency the catalog actually declares."""
    from verifier.domains.catalog import domain_catalog

    declared = {c["id"]: set(c["depends_on"]) for d in domain_catalog()["domains"].values() for c in d["checks"]}
    for domain in CHECKS:
        for coordinate, row in assess(bundles[domain], policy)["result"]["checks"].items():
            assert set(row["blocked_by"]) <= declared[coordinate]
            assert coordinate not in declared[coordinate], "check cannot depend on itself"
