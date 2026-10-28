"""Runnable, synthetic environment specimens for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) fixtures exercise record, package, and checker
contracts. They use a scripted reference model, not learned-model inference or a capability
benchmark. Counter states are integer counts; recall distances are fixture
symbols, not tokens from a model tokenizer. No independent witness is claimed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, VerificationSession
from verifier.hardware.models import WorkloadIdentity
from verifier.interoperability.catalog import ComponentKind, ComponentLifecycle, InteroperabilityComponentDescriptor, InteractionMode

from . import (
    ArtifactBinding, ComponentRole, EnvironmentCapability, EnvironmentComponent,
    EnvironmentConnection, EnvironmentDefinition, EnvironmentInstance, EnvironmentMechanism,
    EnvironmentRole, EnvironmentRunBinding, ModelInteractionBinding, bind_environment_workload,
    environment_evidence_refs, evaluate_environment_run, package_environment, unpack_environment,
)
from .specimen_checks import MixedSuiteMechanism


class CounterEnvironment:
    """Finite deterministic specimen; one action changes the count by one."""

    def __init__(self, goal: int = 4) -> None:
        if type(goal) is not int or not 1 <= goal <= 32:
            raise ValueError("goal must be an integer from 1 through 32")
        self.goal = goal
        self.state = 0
        self.steps = 0

    def reset(self) -> int:
        self.state, self.steps = 0, 0
        return self.state

    def step(self, action: int) -> tuple[int, int, bool, bool]:
        if self.state == self.goal or self.steps >= 16:
            raise ValueError("episode already ended")
        if type(action) is not int or action not in (-1, 1) or not 0 <= self.state + action <= self.goal:
            raise ValueError("action is outside the declared transition domain")
        self.state += action
        self.steps += 1
        terminal = self.state == self.goal
        return self.state, int(terminal), terminal, self.steps == 16 and not terminal

    def save_state(self) -> bytes:
        return _bytes({"state": self.state, "goal": self.goal, "steps": self.steps})

    def load_state(self, payload: bytes) -> None:
        saved = json.loads(payload)
        if (not isinstance(saved, dict) or set(saved) != {"state", "goal", "steps"}
                or not all(type(value) is int for value in saved.values())
                or saved["goal"] != self.goal or not 0 <= saved["state"] <= self.goal
                or not 0 <= saved["steps"] <= 16):
            raise ValueError("snapshot is outside this environment's contract")
        self.state, self.steps = saved["state"], saved["steps"]


class ReferenceRecallModel:
    """Scripted reference model of exact indexed recall, not a learned model."""

    def predict(self, request: dict[str, Any], parameters: dict[str, Any]) -> list[int]:
        if (set(request) != {"input_ids", "query_positions"}
                or parameters != {"max_output_tokens": len(request["query_positions"]), "sampling": "greedy", "seed": 0}):
            raise ValueError("reference model request differs from its finite contract")
        return [request["input_ids"][position] for position in request["query_positions"]]


def _bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def build_specimen(family: str, *, symbols: int = 128) -> tuple[
    EnvironmentDefinition, EnvironmentInstance, EnvironmentRunBinding, EvidenceStore
]:
    """Construct one disclosed fixture using a scripted solver or counter runner."""
    if family not in {"recall", "reasoning", "counter"}:
        raise ValueError("unknown specimen family")
    store = EvidenceStore()

    def retain(path: str, value: Any, *, raw: bool = False) -> ArtifactBinding:
        payload = value if raw else _bytes(value)
        return ArtifactBinding(path, store.add(payload).removeprefix("sha256:"))

    producer = retain("implementation/specimens.py", Path(__file__).read_bytes(), raw=True)
    checker = retain("implementation/specimen_checks.py", Path(__file__).with_name("specimen_checks.py").read_bytes(), raw=True)
    lineage = retain("lineage/specimen.json", {"origin": "project-local synthetic fixture",
                     "separation": "shared publisher and runner; actor independence not established"})
    mechanism = MixedSuiteMechanism()
    predicates = ("environment.evaluate",)
    capabilities: tuple[EnvironmentCapability, ...] = ()
    mode = InteractionMode.STATIC
    if family == "counter":
        mode = InteractionMode.SIMULATION
        capabilities = tuple(EnvironmentCapability)
        predicates += ("environment.step", "environment.replay", "environment.state_restore")

    def descriptor(identifier: str, kind: ComponentKind, implementation: str) -> InteroperabilityComponentDescriptor:
        evaluator = kind is ComponentKind.CHECKER
        return InteroperabilityComponentDescriptor(
            identifier, "Synthetic " + family + " " + identifier, kind, ComponentLifecycle.EXPERIMENTAL,
            implementation, (), planning_surface_schema_ids=("VSTD-2",),
            native_inputs=("environment-specimen-bundle",) if evaluator else ("specimen-family",),
            native_outputs=("bounded-mechanism-decision",) if evaluator else ("environment-specimen-bundle",),
            mechanism_ids=(mechanism.mechanism_id,) if evaluator else ("specimen-construction.v0.1",),
            supported_relations=predicates if evaluator else ("constructs-specimen",),
            interaction_modes=(mode,), domain_tags=("synthetic-environment-specimen",),
            claim_boundary="Disclosed synthetic fixture only; no model benchmark or actor independence.",
        )

    producer_roles = (ComponentRole.TASK, ComponentRole.WRAPPER, ComponentRole.RUNTIME)
    if family == "counter":
        producer_roles += (ComponentRole.DYNAMICS,)
    definition = EnvironmentDefinition(
        "specimen-" + family, "0.1.0", "Retained fixture answers or transitions satisfy the declared finite rules.",
        tuple(EnvironmentRole), (
            EnvironmentComponent(descriptor("producer", ComponentKind.WORKFLOW,
                "verifier.environments.specimens:build_specimen"), producer_roles, (producer,), (lineage,)),
            EnvironmentComponent(descriptor("evaluator", ComponentKind.CHECKER,
                "verifier.environments.specimen_checks:MixedSuiteMechanism.evaluate"),
                (ComponentRole.EVALUATOR,), (checker,), (lineage,),
                (EnvironmentMechanism(mechanism.mechanism_id, checker),)),
        ), mode, capabilities, (EnvironmentConnection("producer", "evaluator", "environment-specimen-bundle"),),
        assumptions=("Installed contract decoder and explicitly registered checker are trusted within their declared bounds.",),
        limitations=("Synthetic fixture with scripted reference responses; no learned-model benchmark, authenticated runtime, or independent witness.",),
    )
    hidden: tuple[ArtifactBinding, ...] = ()
    states: list[int] = []
    restoration = None
    model_interaction = None
    initial: dict[str, Any] = {"state": "stateless"}
    if family == "recall":
        if type(symbols) is not int or not 4 <= symbols <= 131072:
            raise ValueError("symbols must be an integer from 4 through 131072")
        stream = ["symbol-" + str(index) for index in range(symbols)]
        queries = [0, symbols // 2, symbols - 1]
        task = {"stream": stream, "queries": queries}
        config = {"family": family, "token_unit": "fixture-symbol",
                  "token_distances": [symbols - 1 - query for query in queries],
                  "query_distribution": queries, "answer_rule": "exact-symbol"}
        request = {"input_ids": [int(word[len("symbol-"):]) for word in stream], "query_positions": queries}
        parameters = {"max_output_tokens": len(queries), "sampling": "greedy", "seed": 0}
        request_ref = retain("model/request.json", request)
        response = ReferenceRecallModel().predict(json.loads(_bytes(request)), parameters.copy())
        model_interaction = ModelInteractionBinding(
            producer, retain("model/tokenizer.json", {"algorithm": "indexed-fixture-symbols", "version": "1", "token_unit": "fixture-symbol"}),
            retain("model/parameters.json", parameters), request_ref,
            retain("model/response.json", {"output_ids": response}))
        actions = ["symbol-" + str(token) for token in response]
        hidden = (retain("input/answers.json", {"answers": [stream[index] for index in queries]}),)
        count = len(actions)
    elif family == "reasoning":
        config = {"family": family, "answer_rule": "all-clauses-satisfied"}
        task = {"variables": 3, "clauses": [[1, -2], [2, 3], [-1, 3]]}
        actions = [True, False, True]
        count = len(task["clauses"])
    else:
        config = {"family": family, "action_unit": "integer-increment", "state_unit": "integer-count", "max_steps": 16}
        task, initial = {"goal": 4}, {"state": 0}
        environment = CounterEnvironment(task["goal"])
        states = [environment.reset()]
        actions = [1, 1, -1, 1, 1, 1]
        snapshot = b""
        for index, action in enumerate(actions):
            if index == 2:
                snapshot = environment.save_state()
            states.append(environment.step(action)[0])
        environment.load_state(snapshot)
        suffix = [environment.state]
        for action in actions[2:]:
            suffix.append(environment.step(action)[0])
        restoration = {"at_step": 2, "snapshot": json.loads(snapshot), "suffix_states": suffix}
        count = len(actions)
    public_input = retain("input/task.json", task)
    instance = EnvironmentInstance("instance-" + family, definition.canonical_digest(),
        retain("instance/configuration.json", config), retain("instance/initialization.json", initial),
        (public_input, *hidden), (public_input.path,), tuple(ref.path for ref in hidden))
    trace = retain("run/trace.json", {"observation": task, "actions": actions, "states": states,
                   "terminated": True, "restoration": restoration})
    run = EnvironmentRunBinding("run-" + family, instance.canonical_digest(),
        bind_environment_workload(instance, WorkloadIdentity("workload-" + family, executable_digest=producer.digest,
            model_commitments=(model_interaction.model.digest,) if model_interaction else ())),
        "evaluator", (retain("run/execution.json", {"source": "scripted-local-fixture", "authentication": "none"}),),
        trace, retain("run/evaluation.json", {"passed": True, "checked_items": count}),
        retain("run/reward.json", {"value": "1", "unit": "completion-point"}),
        retain("run/measurements.json", {"accuracy": "1", "unit": "fraction"}), model_interaction)
    for record in (definition, instance, run):
        store.add(record.canonical_json_bytes())
    return definition, instance, run, store


def specimen_bindings(definition: EnvironmentDefinition, instance: EnvironmentInstance,
                      run: EnvironmentRunBinding) -> tuple[BoundProposition, ...]:
    mechanism = MixedSuiteMechanism()
    evaluator = next(item for item in definition.components if item.descriptor.component_id == run.evaluator_component_id)
    return tuple(BoundProposition(run.run_id, predicate, run.canonical_digest(),
                 mechanism.mechanism_id, mechanism.mechanism_digest,
                 environment_evidence_refs(definition, instance, run),
                 ("installed-contract-decoder", "local-specimen-checker", "same-publisher-no-independent-witness"),
                 EvidenceBounds(64, 16 * 1024 * 1024)) for predicate in evaluator.descriptor.supported_relations)


def main() -> None:
    for family in ("recall", "reasoning", "counter"):
        definition, instance, run, store = build_specimen(family)
        package = package_environment(definition, store, publisher="local-specimen", license="Apache-2.0", instance=instance, run=run)
        definition, instance, run, transported = unpack_environment(package)
        assert instance is not None and run is not None
        session = VerificationSession(transported)
        session.register(MixedSuiteMechanism())
        result = evaluate_environment_run(definition, instance, run, session, specimen_bindings(definition, instance, run))
        print(json.dumps({"family": family, "bindings_established": result.bindings_established,
                          "checks": [item.status.value for item in result.evaluations],
                          "conformance": "NOT_ESTABLISHED", "package_digest": package.canonical_digest()}), flush=True)


if __name__ == "__main__":
    main()
