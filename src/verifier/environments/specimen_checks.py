"""Bounded, independently written fixture checkers for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) fixtures demonstrate environment contracts,
not model performance, physical simulation validity, or independent actors.
The checker never imports producer code or executes submitted implementation bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence

from verifier.core.evidence import BoundProposition, MechanismDecision, MechanismOutcome, implementation_file_digest

from .contracts import EnvironmentDefinition, EnvironmentInstance, EnvironmentRunBinding, load_environment_record


def _object(payload: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate fixture field")
            result[key] = value
        return result
    value = json.loads(payload, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("fixture must be an object")
    return value


def _same(left: Any, right: Any) -> bool:
    """Compare exact JSON types as well as values; booleans are not integers."""
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False)


class MixedSuiteMechanism:
    """Check retained recall, Boolean assignment, and finite-counter specimens."""

    mechanism_id = "environment.specimen.v0.1"

    @property
    def mechanism_digest(self) -> str:
        return implementation_file_digest(__file__)

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if sum(map(len, evidence)) > 16 * 1024 * 1024:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "Specimen evidence exceeds checker byte bound.")
        by_digest = {hashlib.sha256(payload).hexdigest(): payload for payload in evidence}
        try:
            run = load_environment_record(by_digest[binding.expected], expected_digest=binding.expected)
            if not isinstance(run, EnvironmentRunBinding) or run.run_id != binding.subject_id:
                raise ValueError("wrong run binding")
            instance = load_environment_record(by_digest[run.instance_digest], expected_digest=run.instance_digest)
            if not isinstance(instance, EnvironmentInstance):
                raise ValueError("wrong instance binding")
            definition = load_environment_record(by_digest[instance.definition_digest], expected_digest=instance.definition_digest)
            if not isinstance(definition, EnvironmentDefinition):
                raise ValueError("wrong definition binding")
            inputs = {ref.path: _object(by_digest[ref.digest]) for ref in instance.inputs}
            config = _object(by_digest[instance.configuration.digest])
            initial = _object(by_digest[instance.initialization.digest])
            if run.trace is None or run.evaluation is None:
                raise ValueError("missing trace or evaluation")
            trace = _object(by_digest[run.trace.digest])
            evaluation = _object(by_digest[run.evaluation.digest])
            task = inputs["input/task.json"]
            family = config["family"]
            expected_hidden = ("input/answers.json",) if family == "recall" else ()
            if (instance.model_visible_paths != ("input/task.json",)
                    or instance.evaluator_only_paths != expected_hidden):
                raise ValueError("specimen observation/evaluator partition differs from its contract")
            task_fields = {"recall": {"stream", "queries"}, "reasoning": {"variables", "clauses"}, "counter": {"goal"}}
            if family in task_fields and set(task) != task_fields[family]:
                raise ValueError("unexpected public task field or hidden-answer leakage")
            if not _same(trace.get("observation"), task) or set(trace) != {"observation", "actions", "states", "terminated", "restoration"}:
                raise ValueError("wrapper observation differs from its exact public input boundary")
            if family == "recall":
                if binding.predicate != "environment.evaluate":
                    raise ValueError("recall specimen has no stepping or replay mechanism")
                stream, queries = task["stream"], task["queries"]
                if (not isinstance(stream, list) or not 1 <= len(stream) <= 131072
                        or not all(isinstance(word, str) for word in stream)
                        or not isinstance(queries, list) or not 1 <= len(queries) <= 64
                        or any(type(index) is not int or not 0 <= index < len(stream) for index in queries)):
                    raise ValueError("recall task exceeds finite contract")
                answers = [stream[index] for index in queries]
                if (not _same(config, {"family": "recall", "token_unit": "fixture-symbol",
                               "token_distances": [len(stream) - 1 - index for index in queries],
                               "query_distribution": queries, "answer_rule": "exact-symbol"})
                        or not _same(inputs["input/answers.json"], {"answers": answers})
                        or not _same(trace["actions"], answers)):
                    raise ValueError("recall answer, distribution, distance, or evaluator key disagrees")
                interaction = run.model_interaction
                if interaction is None:
                    return MechanismDecision(MechanismOutcome.UNKNOWN, "Recall has no bound model interaction.")
                token_ids = []
                for word in stream:
                    identifier = int(word.removeprefix("symbol-"))
                    if not 0 <= identifier < 131072 or word != "symbol-" + str(identifier):
                        raise ValueError("input symbol does not inhabit the declared tokenizer")
                    token_ids.append(identifier)
                if (interaction.model.digest not in run.workload.model_commitments
                        or not _same(_object(by_digest[interaction.tokenizer.digest]),
                            {"algorithm": "indexed-fixture-symbols", "version": "1", "token_unit": "fixture-symbol"})
                        or not _same(_object(by_digest[interaction.parameters.digest]),
                            {"max_output_tokens": len(queries), "sampling": "greedy", "seed": 0})
                        or not _same(_object(by_digest[interaction.request.digest]),
                            {"input_ids": token_ids, "query_positions": queries})
                        or not _same(_object(by_digest[interaction.response.digest]),
                            {"output_ids": [token_ids[index] for index in queries]})):
                    raise ValueError("model identity, tokenization, parameters, request, or response disagrees with recall trace")
                count = len(queries)
            elif family == "reasoning":
                if binding.predicate != "environment.evaluate":
                    raise ValueError("reasoning specimen has no stepping or replay mechanism")
                assignment, clauses = trace["actions"], task["clauses"]
                if (not _same(config, {"family": "reasoning", "answer_rule": "all-clauses-satisfied"})
                        or type(task["variables"]) is not int or not 1 <= task["variables"] <= 64
                        or not isinstance(assignment, list) or len(assignment) != task["variables"]
                        or not all(type(item) is bool for item in assignment)
                        or not isinstance(clauses, list) or not 1 <= len(clauses) <= 256):
                    raise ValueError("invalid Boolean assignment or formula contract")
                for clause in clauses:
                    if (not isinstance(clause, list) or not 1 <= len(clause) <= 64
                            or any(type(lit) is not int or not 1 <= abs(lit) <= len(assignment) for lit in clause)
                            or not any(assignment[abs(lit) - 1] == (lit > 0) for lit in clause)):
                        raise ValueError("assignment fails a retained clause")
                count = len(clauses)
            elif family == "counter":
                if binding.predicate not in {"environment.evaluate", "environment.step", "environment.replay", "environment.state_restore"}:
                    raise ValueError("unsupported counter predicate")
                if not _same(config, {"family": "counter", "action_unit": "integer-increment", "state_unit": "integer-count", "max_steps": 16}):
                    raise ValueError("counter configuration differs from declared finite rules")
                actions, states = trace["actions"], trace["states"]
                start, goal = initial["state"], task["goal"]
                if (type(start) is not int or type(goal) is not int or not 0 <= start < goal <= 32
                        or not isinstance(actions, list) or not 1 <= len(actions) <= 16
                        or not isinstance(states, list) or not states or states[0] != start
                        or len(states) != len(actions) + 1 or not all(type(state) is int for state in states)):
                    raise ValueError("invalid counter state or action extent")
                expected_states = [start]
                for action in actions:
                    if type(action) is not int or action not in (-1, 1) or expected_states[-1] == goal:
                        raise ValueError("illegal action or action after termination")
                    following = expected_states[-1] + action
                    if not 0 <= following <= goal:
                        raise ValueError("counter escaped declared state bounds")
                    expected_states.append(following)
                if states != expected_states or states[-1] != goal or trace["terminated"] is not True:
                    raise ValueError("transition trace or termination disagrees with rules")
                if binding.predicate == "environment.state_restore":
                    restored = trace["restoration"]
                    if not isinstance(restored, dict) or set(restored) != {"at_step", "snapshot", "suffix_states"}:
                        raise ValueError("missing restoration observation")
                    step = restored["at_step"]
                    if (type(step) is not int or not 0 <= step < len(actions)
                            or not _same(restored["snapshot"], {"state": states[step], "goal": goal, "steps": step})
                            or not _same(restored["suffix_states"], states[step:])):
                        raise ValueError("restored suffix differs from retained transition trace")
                count = len(actions)
            else:
                return MechanismDecision(MechanismOutcome.UNKNOWN, "No checker for this specimen family.")
            if family != "counter" and (not _same(initial, {"state": "stateless"}) or trace["states"] != []
                    or trace["terminated"] is not True or trace["restoration"] is not None):
                raise ValueError("static fixture contains fabricated state or termination")
            if not _same(evaluation, {"passed": True, "checked_items": count}):
                raise ValueError("evaluator report disagrees with recomputed result")
            if run.measurements is None or not _same(_object(by_digest[run.measurements.digest]), {"accuracy": "1", "unit": "fraction"}):
                raise ValueError("measurement report disagrees with retained successful observations")
        except (KeyError, TypeError, ValueError, IndexError, RecursionError) as exc:
            return MechanismDecision(MechanismOutcome.FAIL, str(exc))
        return MechanismDecision(MechanismOutcome.PASS,
            "Retained fixture satisfies the selected finite predicate; actual execution and actor independence are not established.",
            {"family": family, "checked_items": count})
