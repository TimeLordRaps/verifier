"""Completion-audit regressions for Verifier Standard (VSTD) environments.

JavaScript Object Notation (JSON) types, model interaction identity, and portable
path boundaries must survive both inspection and explicit mechanism checking.
"""

from __future__ import annotations

from dataclasses import replace
import json

import pytest

from verifier.core.evidence import VerificationSession
from verifier.core.geometry import CoordinateStatus
from verifier.environments import ArtifactBinding, assess_environment, environment_surface, evaluate_environment_run
from verifier.environments.specimen_checks import MixedSuiteMechanism
from verifier.environments.specimens import build_specimen, specimen_bindings


def test_restoration_numeric_substitution_is_falsified():
    definition, instance, run, store = build_specimen("counter")
    trace = json.loads(store.resolve(run.trace.digest))
    trace["restoration"]["snapshot"]["steps"] = 2.0
    run = replace(run, trace=ArtifactBinding(run.trace.path, store.add(json.dumps(trace).encode())[7:]))
    store.add(run.canonical_json_bytes())
    session = VerificationSession(store)
    session.register(MixedSuiteMechanism())
    result = evaluate_environment_run(definition, instance, run, session, specimen_bindings(definition, instance, run))
    restored = next(row for row in result.evaluations if row.coordinate_id.endswith(":environment.state_restore"))
    assert restored.status is CoordinateStatus.FALSIFIED


def test_parent_directory_case_alias_is_rejected():
    definition, instance, _, store = build_specimen("reasoning")
    alias = replace(instance.inputs[0], path="Input/alternate.json")
    instance = replace(instance, inputs=(*instance.inputs, alias))
    assert not assess_environment(definition, store, instance).bindings_established


def test_recall_records_model_tokenizer_and_inference_bindings():
    _, _, run, store = build_specimen("recall")
    interaction = getattr(run, "model_interaction", None)
    assert interaction is not None
    assert interaction.model.digest in run.workload.model_commitments
    for ref in (interaction.model, interaction.tokenizer, interaction.parameters,
                interaction.request, interaction.response):
        assert store.resolve(ref.digest)


@pytest.mark.parametrize("field", ["tokenizer", "parameters", "request", "response"])
def test_rebound_model_interaction_substitution_is_falsified(field):
    definition, instance, run, store = build_specimen("recall")
    interaction = run.model_interaction
    prior = getattr(interaction, field)
    value = json.loads(store.resolve(prior.digest))
    value["unexpected"] = "substitution"
    changed = ArtifactBinding(prior.path, store.add(json.dumps(value).encode())[7:])
    run = replace(run, model_interaction=replace(interaction, **{field: changed}))
    store.add(run.canonical_json_bytes())
    session = VerificationSession(store)
    session.register(MixedSuiteMechanism())
    result = evaluate_environment_run(definition, instance, run, session, specimen_bindings(definition, instance, run))
    assert result.bindings_established
    assert result.evaluations[0].status is CoordinateStatus.FALSIFIED


def test_missing_model_interaction_is_unknown_and_wrong_model_binding_fails():
    definition, instance, run, store = build_specimen("recall")
    changed = replace(run, model_interaction=None)
    store.add(changed.canonical_json_bytes())
    session = VerificationSession(store)
    session.register(MixedSuiteMechanism())
    result = evaluate_environment_run(definition, instance, changed, session, specimen_bindings(definition, instance, changed))
    assert result.evaluations[0].status is CoordinateStatus.INDETERMINATE
    wrong = replace(run, workload=replace(run.workload, model_commitments=("a" * 64,)))
    assert not assess_environment(definition, store, instance, wrong).bindings_established


def test_full_geometry_retains_instance_run_and_model_without_judgments():
    definition, instance, run, _ = build_specimen("recall")
    geometry = environment_surface(definition, instance, run)
    assert geometry.validate() == []
    addresses = {item.address for item in geometry.loci}
    assert "sha256:" + instance.canonical_digest() in addresses
    assert "sha256:" + run.canonical_digest() in addresses
    assert "sha256:" + run.model_interaction.model.digest in addresses
    assert any(item.kind.value == "MODEL" for item in geometry.loci)
    assert not geometry.judgments


def test_model_wrapper_receives_only_tokenized_public_observations(monkeypatch):
    from verifier.environments.specimens import ReferenceRecallModel
    original = ReferenceRecallModel.predict
    captured = []
    def observe(self, request, parameters):
        captured.append(json.loads(json.dumps(request)))
        assert set(request) == {"input_ids", "query_positions"}
        assert "answers" not in request and "answer_key" not in request
        return original(self, request, parameters)
    monkeypatch.setattr(ReferenceRecallModel, "predict", observe)
    _, _, run, store = build_specimen("recall")
    assert captured == [json.loads(store.resolve(run.model_interaction.request.digest))]
