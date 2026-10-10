"""Refutable current SIM-2.5 finite perspective-shift examples."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import sim as native_sim
from verifier.domains.common import Budget, Refuted
from verifier.domains.contracts import sim_dynamics, sim_internal_state, sim_perspective
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.inventory import MECHANIZED_12_POINT_BINDINGS
from verifier.runtime.public_cli import main


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _raw_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _perspective():
    return importlib.import_module("verifier.domains.contracts.sim_perspective")


def _child(*, macro_states: list | None = None, projection: object = None,
           include_projection: bool = True, hidden_child: bool = False,
           steps: int = 1, tolerance: float = 0.1):
    states = [{"x": float(i)} for i in range(steps + 1)]
    entropy, times = [1.0] * steps, [float(i) for i in range(steps + 1)]
    macro = ([{"double": float(i * 2)} for i in range(steps + 1)]
             if macro_states is None else macro_states)
    mapping = {"double": {"op": "mul", "args": [{"var": "x"}, 2.0]}}
    if projection is not None:
        mapping = projection
    artifact = {
        "transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
        "initial_state": states[0], "trajectory_digest": _digest(states),
        "entropy_digest": _digest(entropy), "times_digest": _digest(times),
        "macro_digest": _digest(macro), "tolerance": tolerance,
        "macro_unit": "selected_model_length",
    }
    if include_projection:
        artifact["projection"] = mapping
    inputs = {"states": states, "entropy": entropy, "times": times,
              "macro_states": macro}
    objects = [NamespaceObject.create("data", "DATA", {}),
               NamespaceObject.create("checker", "VERIFIER", {}),
               NamespaceObject.create("world", "OBJECT", {}),
               NamespaceObject.create("env", "ENV", {})]
    subject = NamespaceObject.create("sim", "SIM", {
        "scope": "selected-retained-trajectory-replay",
        "artifact_digest": _digest(artifact), "inputs_digest": _digest(inputs),
    }, {"data": ["data"], "verifier": ["checker"],
        "objects": ["world"], "env": ["env"]})
    objects.append(subject)
    trajectory_evidence = canonical_bytes({
        "schema_version": sim_dynamics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "artifact": artifact, "inputs": inputs,
    })
    trajectory_policy = sim_dynamics.sim_dynamics_policy(
        trust_roots=["sim-perspective-trajectory-fixture"])
    trajectory_request = sim_dynamics.sim_dynamics_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        artifact_digest=_digest(artifact), inputs_digest=_digest(inputs),
        expected_counts={"states": steps + 1, "transitions": steps},
        evidence_ref=_digest(json.loads(trajectory_evidence)),
        policy=trajectory_policy)
    trajectory_certificate = sim_dynamics.build_sim_dynamics_certificate(
        trajectory_request, trajectory_evidence, policy=trajectory_policy)
    assert sim_dynamics.recheck_sim_dynamics_certificate(
        trajectory_certificate, expected_request=trajectory_request,
        policy=trajectory_policy)["status"] == "PASS"
    observation = {"declared_complete": True,
                   "channels": {"display": 0.0 if hidden_child else {"var": "x"}}}
    internal_evidence = canonical_bytes({
        "schema_version": sim_internal_state.EVIDENCE_VERSION,
        "trajectory_certificate": base64.b64encode(trajectory_certificate).decode("ascii"),
        "observation_artifact": observation, "declared_hidden_changes": [],
    })
    internal_policy = sim_internal_state.sim_internal_state_policy(
        trust_roots=["sim-perspective-internal-fixture"])
    internal_request = sim_internal_state.sim_internal_state_request(
        subject_id="sim", object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        trajectory_request=trajectory_request, trajectory_policy=trajectory_policy,
        trajectory_certificate_digest=_raw_digest(trajectory_certificate),
        observation_artifact_digest=_digest(observation),
        hidden_changes_digest=_digest([]),
        evidence_ref=_digest(json.loads(internal_evidence)), policy=internal_policy)
    internal_certificate = sim_internal_state.build_sim_internal_state_certificate(
        internal_request, internal_evidence, policy=internal_policy)
    expected = "FAIL" if hidden_child else "PASS"
    assert sim_internal_state.recheck_sim_internal_state_certificate(
        internal_certificate, expected_request=internal_request,
        policy=internal_policy)["status"] == expected
    return artifact, inputs, internal_request, internal_policy, internal_certificate


def _selected(**child_options):
    module = _perspective()
    artifact, inputs, internal_request, internal_policy, child = _child(**child_options)
    evidence = {"schema_version": module.EVIDENCE_VERSION,
                "internal_state_certificate": base64.b64encode(child).decode("ascii")}
    policy = module.sim_perspective_policy(trust_roots=["selected-perspective-fixture"])
    request = module.sim_perspective_request(
        subject_id=internal_request["subject_id"],
        object_digest=internal_request["object_digest"],
        collection_digest=internal_request["collection_digest"],
        internal_state_request=internal_request,
        internal_state_policy=internal_policy,
        internal_state_certificate_digest=_raw_digest(child),
        projection_digest=_digest(artifact["projection"]) if "projection" in artifact
                          else _digest({}),
        macro_states_digest=_digest(inputs["macro_states"]),
        tolerance=artifact["tolerance"], macro_unit="selected_model_length",
        evidence_ref=_digest(evidence), policy=policy)
    return module, request, policy, canonical_bytes(evidence)


def selected():
    _, request, policy, evidence = _selected()
    return request, policy, evidence


def _replay(module, request, policy, evidence):
    certificate = module.build_sim_perspective_certificate(request, evidence,
                                                           policy=policy)
    return module.recheck_sim_perspective_certificate(
        certificate, expected_request=request, policy=policy)


def test_existing_native_refinement_compares_every_aligned_state():
    artifact, inputs, *_ = _child()
    assert native_sim.evaluate("refinement", artifact, inputs,
                               Budget(100_000), witness_keys={}) == {
                                   "states": 2, "transitions": 1}
    changed = deepcopy(inputs)
    changed["macro_states"][1]["double"] = 2.5
    selected = {**artifact, "macro_digest": _digest(changed["macro_states"])}
    with pytest.raises(Refuted, match="macro projection differs"):
        native_sim.evaluate("refinement", selected, changed,
                            Budget(100_000), witness_keys={})


def test_selected_child_and_projection_replay_without_tier_promotion():
    module, request, policy, evidence = _selected()
    result = _replay(module, request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["sim_tier_2_conformance"] == "NOT_ESTABLISHED"
    assert result["physical_macro_truth"] == "NOT_ESTABLISHED"


def test_reselected_mismatching_macro_value_fails_native_comparison():
    module, request, policy, evidence = _selected(
        macro_states=[{"double": 0.0}, {"double": 2.5}])
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


def test_middle_macro_mismatch_cannot_hide_behind_correct_final_state():
    module, request, policy, evidence = _selected(steps=2,
        macro_states=[{"double": 0.0}, {"double": 2.5}, {"double": 4.0}])
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("scale", [1.0, 3.0, -2.0])
def test_projection_scaling_preserves_alignment_and_rejects_middle_error(scale):
    projection = {"scaled": {"op": "mul", "args": [{"var": "x"}, scale]}}
    aligned = [{"scaled": scale * float(i)} for i in range(3)]
    module, request, policy, evidence = _selected(
        steps=2, projection=projection, macro_states=aligned)
    assert _replay(module, request, policy, evidence)["status"] == "PASS"

    mismatched = deepcopy(aligned)
    mismatched[1]["scaled"] += 0.5
    module, request, policy, evidence = _selected(
        steps=2, projection=projection, macro_states=mismatched)
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


def test_selected_absolute_tolerance_has_a_refutable_boundary():
    module, request, policy, evidence = _selected(tolerance=0.25,
        macro_states=[{"double": 0.0}, {"double": 2.25}])
    assert _replay(module, request, policy, evidence)["status"] == "PASS"
    module, request, policy, evidence = _selected(tolerance=0.25,
        macro_states=[{"double": 0.0}, {"double": 2.251}])
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


def test_missing_projection_stays_unknown_after_passing_child():
    module, request, policy, evidence = _selected(include_projection=False)
    assert _replay(module, request, policy, evidence)["status"] == "UNKNOWN"


def test_unsupported_selected_projection_stays_unknown():
    module, request, policy, evidence = _selected(
        projection={"double": {"op": "future", "args": [1.0, 2.0]}})
    assert _replay(module, request, policy, evidence)["status"] == "UNKNOWN"


def test_failed_prerequisite_precedes_missing_projection():
    module, request, policy, evidence = _selected(
        include_projection=False, hidden_child=True)
    assert _replay(module, request, policy, evidence)["status"] == "FAIL"


def test_unknown_prerequisite_does_not_create_parent_pass():
    module, request, policy, evidence = _selected()
    unknown = sim_internal_state.build_sim_internal_state_certificate(
        request["internal_state_request"], None,
        policy=request["internal_state_policy"])
    assert json.loads(unknown)["result"]["status"] == "UNKNOWN"
    changed = json.loads(evidence)
    changed["internal_state_certificate"] = base64.b64encode(unknown).decode("ascii")
    request["internal_state_certificate_digest"] = _raw_digest(unknown)
    request["evidence_ref"] = _digest(changed)
    assert _replay(module, request, policy, canonical_bytes(changed))["status"] == "UNKNOWN"


def test_substituted_child_is_refused_even_when_rehashed():
    module, request, policy, _ = _selected()
    _, _, _, foreign = _selected(macro_states=[{"double": 0.0}, {"double": 4.0}])
    changed = json.loads(foreign)
    request["evidence_ref"] = _digest(changed)
    result = _replay(module, request, policy, canonical_bytes(changed))
    assert result["status"] == "FAIL"


def test_public_route_rechecks_selected_bytes_and_retains_unknown_tier():
    module, request, policy, evidence = _selected()
    certificate = module.build_sim_perspective_certificate(request, evidence,
                                                           policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=module.SEMANTIC_VERSION,
        objective=module.COORDINATE, represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["sim_tier_2_conformance"] == "NOT_ESTABLISHED"


def test_public_cli_replays_exact_immutable_files(tmp_path, capsys):
    module, request, policy, evidence = _selected()
    certificate = module.build_sim_perspective_certificate(request, evidence,
                                                           policy=policy)
    paths = [tmp_path / name for name in ("certificate.json", "request.json", "policy.json")]
    for path, data in zip(paths, (certificate, canonical_bytes(request), canonical_bytes(policy))):
        path.write_bytes(data)
    before = [path.read_bytes() for path in paths]
    exit_code = main(["current-object", "check", str(paths[0]),
        "--semantic-version", module.SEMANTIC_VERSION,
        "--objective", module.COORDINATE, "--represented-kind", "SIM",
        "--request", str(paths[1]), "--policy", str(paths[2]), "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert [path.read_bytes() for path in paths] == before


def test_rehashed_carried_verdict_cannot_replace_native_replay():
    module, request, policy, evidence = _selected()
    certificate = module.build_sim_perspective_certificate(request, evidence,
                                                           policy=policy)
    changed = json.loads(certificate)
    changed["result"]["status"] = "FAIL"
    changed["digest"] = _digest({k: v for k, v in changed.items() if k != "digest"})
    with pytest.raises(module.SimPerspectiveError):
        module.recheck_sim_perspective_certificate(canonical_bytes(changed),
            expected_request=request, policy=policy)


def test_public_inventory_binds_exact_selected_claim():
    module = _perspective()
    binding = MECHANIZED_12_POINT_BINDINGS["SIM-2.5"]
    assert binding["exact_claim"] == module.registration()["proposition"]
    assert binding["resulting_evidence"] == module.CERTIFICATE_VERSION


def test_selected_unit_or_tolerance_substitution_is_refused():
    module, request, policy, evidence = _selected()
    for field, value in (("macro_unit", "other_unit"), ("tolerance", 0.0)):
        changed = deepcopy(request)
        changed[field] = value
        assert _replay(module, changed, policy, evidence)["status"] == "FAIL"


def test_exact_tolerance_representation_is_bound_not_numerically_coerced():
    module, request, policy, evidence = _selected(tolerance=0.0)
    assert _replay(module, request, policy, evidence)["status"] == "PASS"
    changed = deepcopy(request)
    changed["tolerance"] = 0
    assert _replay(module, changed, policy, evidence)["status"] == "FAIL"
