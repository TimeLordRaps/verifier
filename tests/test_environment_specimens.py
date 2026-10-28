"""Falsification cases for Verifier Standard (VSTD) environment specimens.

JavaScript Object Notation (JSON) traces are retained observations, not proof of
authenticated execution. No language-model inference is performed here.
"""

from __future__ import annotations

from dataclasses import replace
import json

import pytest

from verifier.core.evidence import VerificationSession
from verifier.core.geometry import CoordinateStatus
from verifier.environments import ArtifactBinding, evaluate_environment_run
from verifier.environments.specimen_checks import MixedSuiteMechanism
from verifier.environments.specimens import CounterEnvironment, build_specimen, specimen_bindings


def evaluate_mutation(family, mutate, field="trace"):
    definition, instance, run, store = build_specimen(family)
    old = getattr(run, field)
    value = json.loads(store.resolve(old.digest))
    mutate(value)
    reference = store.add(json.dumps(value, sort_keys=True).encode())
    run = replace(run, **{field: ArtifactBinding(old.path, reference[7:])})
    store.add(run.canonical_json_bytes())
    session = VerificationSession(store)
    session.register(MixedSuiteMechanism())
    return evaluate_environment_run(definition, instance, run, session, specimen_bindings(definition, instance, run))


@pytest.mark.parametrize("family,mutation", [
    ("recall", lambda trace: trace["actions"].__setitem__(0, "wrong-answer")),
    ("recall", lambda trace: trace["observation"].update(answer_key=trace["actions"])),
    ("reasoning", lambda trace: trace.update(actions=[False, False, False])),
    ("reasoning", lambda trace: trace.update(actions=[1, 0, 1])),
    ("counter", lambda trace: trace["states"].__setitem__(2, 20)),
    ("counter", lambda trace: trace["actions"].__setitem__(0, True)),
    ("counter", lambda trace: trace.update(terminated=False)),
    ("counter", lambda trace: trace["restoration"]["suffix_states"].__setitem__(1, 99)),
])
def test_bad_answers_leakage_transitions_and_restoration_are_falsified(family, mutation):
    result = evaluate_mutation(family, mutation)
    assert result.bindings_established  # New hashes alone do not make the new trace correct.
    assert any(row.status is CoordinateStatus.FALSIFIED for row in result.evaluations)
    assert result.to_dict()["conformance"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("field,mutation", [
    ("evaluation", lambda value: value.update(checked_items=999)),
    ("evaluation", lambda value: value.update(passed=False)),
    ("measurements", lambda value: value.update(accuracy="0.5")),
])
def test_evaluator_and_measurement_reports_are_recomputed(field, mutation):
    result = evaluate_mutation("reasoning", mutation, field)
    assert result.evaluations[0].status is CoordinateStatus.FALSIFIED


def test_reward_is_bound_but_not_relabelled_as_verification():
    result = evaluate_mutation("reasoning", lambda value: value.update(value="1000000"), "reward")
    assert result.evaluations[0].status is CoordinateStatus.VERIFIED
    assert result.to_dict()["conformance"] == "NOT_ESTABLISHED"


def test_counter_restore_reproduces_future_and_enforces_termination():
    environment = CounterEnvironment(3)
    assert environment.reset() == 0
    environment.step(1)
    snapshot = environment.save_state()
    expected = [environment.step(1), environment.step(1)]
    with pytest.raises(ValueError, match="ended"):
        environment.step(-1)
    environment.load_state(snapshot)
    assert [environment.step(1), environment.step(1)] == expected
    with pytest.raises(ValueError, match="snapshot"):
        environment.load_state(b'{"state":1,"goal":4,"steps":1}')
    assert environment.state == 3  # Invalid restore was atomic.


def test_counter_truncates_at_declared_step_budget():
    environment = CounterEnvironment(4)
    for _ in range(8):
        environment.step(1)
        observation, reward, terminated, truncated = environment.step(-1)
    assert (observation, reward, terminated, truncated) == (0, 0, False, True)
    with pytest.raises(ValueError, match="ended"):
        environment.step(1)


def test_longer_recall_fixture_keeps_distance_and_distribution_explicit():
    definition, instance, run, store = build_specimen("recall", symbols=16384)
    config = json.loads(store.resolve(instance.configuration.digest))
    assert config["token_distances"] == [16383, 8191, 0]
    assert config["token_unit"] == "fixture-symbol"
    session = VerificationSession(store)
    session.register(MixedSuiteMechanism())
    result = evaluate_environment_run(definition, instance, run, session, specimen_bindings(definition, instance, run))
    assert result.evaluations[0].status is CoordinateStatus.VERIFIED
