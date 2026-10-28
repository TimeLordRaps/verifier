"""Bounded environment assessment for Verifier Standard (VSTD).

Inspection never executes an environment. Explicit evaluation uses an existing
VerificationSession and its exact registered mechanisms. Neither operation
establishes numbered-profile conformance or authenticates execution occurrence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Sequence

from verifier.core.evidence import BoundProposition, EvaluatedProposition, EvidenceBindingError, EvidenceStore, VerificationSession
from verifier.core.geometry import CoordinateJudgment, CoordinateStatus
from verifier.interoperability.catalog import InteractionMode

from .contracts import (
    ComponentRole, EnvironmentCapability, EnvironmentDefinition, EnvironmentInstance,
    EnvironmentRunBinding, artifact_bindings,
)


CLAIM_BOUNDARY = (
    "Findings cover declared connections, exact byte bindings, and explicitly checked "
    "propositions only. Runtime occurrence, enforcement, real-world validity, actor "
    "independence, and numbered-profile conformance are NOT_ESTABLISHED."
)
CAPABILITY_PREDICATES = {
    "environment.step": EnvironmentCapability.STEP,
    "environment.state_restore": EnvironmentCapability.STATE_RESTORE,
    "environment.replay": EnvironmentCapability.REPLAY,
}


@dataclass(frozen=True)
class EnvironmentAssessment:
    definition_digest: str
    instance_digest: str | None
    run_digest: str | None
    judgments: tuple[CoordinateJudgment, ...]
    evaluations: tuple[CoordinateJudgment, ...] = ()
    mechanism_results: tuple[EvaluatedProposition, ...] = ()
    claim_boundary: str = CLAIM_BOUNDARY

    @property
    def bindings_established(self) -> bool:
        return bool(self.judgments) and all(item.status is CoordinateStatus.VERIFIED for item in self.judgments)

    def to_dict(self) -> dict[str, Any]:
        def row(item: CoordinateJudgment) -> dict[str, Any]:
            return {"coordinate_id": item.coordinate_id, "status": item.status.value,
                    "mechanism_ids": list(item.mechanism_ids), "evidence_ids": list(item.evidence_ids),
                    "assumptions": list(item.assumptions), "limitations": list(item.limitations)}
        return {"definition_digest": self.definition_digest, "instance_digest": self.instance_digest,
                "run_digest": self.run_digest, "bindings_established": self.bindings_established,
                "judgments": [row(item) for item in self.judgments],
                "evaluations": [row(item) for item in self.evaluations],
                "mechanism_results": [item.to_dict() for item in self.mechanism_results],
                "conformance": "NOT_ESTABLISHED", "claim_boundary": self.claim_boundary}


def environment_evidence_refs(definition: EnvironmentDefinition, instance: EnvironmentInstance,
                              run: EnvironmentRunBinding) -> tuple[str, ...]:
    """Exact evidence set required for evaluation; does not read or write a store."""
    digests = {item.canonical_digest() for item in (definition, instance, run)}
    digests.update(ref.digest for ref in artifact_bindings(definition, instance, run))
    return tuple("sha256:" + digest for digest in sorted(digests))


def assess_environment(definition: EnvironmentDefinition, evidence: EvidenceStore,
                       instance: EnvironmentInstance | None = None,
                       run: EnvironmentRunBinding | None = None) -> EnvironmentAssessment:
    """Check bindings and declared compatibility without importing submitted code.

Missing bytes remain indeterminate. Contradictory references are falsified on
that binding coordinate. A success covers neither component semantics nor the
completeness of the caller's modeled boundary.
"""
    judgments: list[CoordinateJudgment] = []
    prefix = "environment:" + definition.canonical_digest()

    def finding(name: str, status: CoordinateStatus, detail: str,
                refs: tuple[str, ...] = ()) -> None:
        judgments.append(CoordinateJudgment(prefix + ":" + name, status,
                         ("environment.bindings.v0.1",), refs,
                         definition.assumptions, (detail, CLAIM_BOUNDARY)))

    def check(name: str, okay: bool, detail: str) -> None:
        finding(name, CoordinateStatus.VERIFIED if okay else CoordinateStatus.FALSIFIED, detail)

    components = {item.descriptor.component_id: item for item in definition.components}
    for identifier, item in components.items():
        check("mode:" + identifier, definition.interaction_mode in item.descriptor.interaction_modes,
              "Selected component must declare support for this interaction mode; availability is separate.")
    for index, edge in enumerate(definition.connections):
        source, target = components.get(edge.source_component_id), components.get(edge.target_component_id)
        check(f"connection:{index}", bool(source and target
              and edge.contract in source.descriptor.native_outputs
              and edge.contract in target.descriptor.native_inputs),
              "Both endpoints must declare the exact contract; transformations require an explicit component.")
    interactive = definition.interaction_mode in (
        InteractionMode.SIMULATION, InteractionMode.LIVE_READ_ONLY, InteractionMode.LIVE_MUTATING,
    )
    check("capabilities", not definition.capabilities or (
          EnvironmentCapability.STEP not in definition.capabilities or interactive),
          "Static and replay-only definitions cannot declare live stepping.")
    check("restore-capability", EnvironmentCapability.STATE_RESTORE not in definition.capabilities
          or EnvironmentCapability.STEP in definition.capabilities,
          "State restoration requires a declared stepping interface.")

    references = artifact_bindings(definition, instance, run)
    paths: dict[str, tuple[str, str]] = {}
    prefixes: dict[str, str] = {}
    file_paths = {ref.path.casefold() for ref in references}
    for index, ref in enumerate(references):
        previous = paths.setdefault(ref.path.casefold(), (ref.path, ref.digest))
        parts = ref.path.split("/")
        prefix_collision = any("/".join(parts[:length]).casefold() in file_paths for length in range(1, len(parts)))
        case_collision = False
        for length in range(1, len(parts) + 1):
            current_prefix = "/".join(parts[:length])
            case_collision |= prefixes.setdefault(current_prefix.casefold(), current_prefix) != current_prefix
        check(f"path-binding:{index}", previous == (ref.path, ref.digest) and not prefix_collision and not case_collision,
              "Retained paths must not contain byte substitutions, case aliases, or file/directory collisions.")
        status, detail = CoordinateStatus.INDETERMINATE, "Bound artifact is unavailable."
        if ref.digest in evidence:
            try:
                evidence.resolve(ref.digest)
                status, detail = CoordinateStatus.VERIFIED, "Exact retained bytes match their declared digest."
            except EvidenceBindingError as exc:
                status, detail = CoordinateStatus.FALSIFIED, str(exc)
        finding(f"artifact:{index}:" + ref.path, status, detail, ("sha256:" + ref.digest,))

    if instance is not None:
        check("definition-binding", instance.definition_digest == definition.canonical_digest(),
              "Instance must bind this exact definition, including components and limitations.")
        visible, hidden = set(instance.model_visible_paths), set(instance.evaluator_only_paths)
        inputs = {ref.path for ref in instance.inputs}
        check("input-boundary", not visible.intersection(hidden) and visible.union(hidden) <= inputs,
              "Observation and evaluator-only declarations must be disjoint known inputs; this is not non-inferability.")
        visible_digests = {ref.digest for ref in instance.inputs if ref.path in visible}
        hidden_digests = {ref.digest for ref in instance.inputs if ref.path in hidden}
        check("input-alias", not visible_digests.intersection(hidden_digests),
              "An evaluator-only artifact cannot be exposed under a different input path.")
    if run is not None:
        check("instance-binding", instance is not None and run.instance_digest == instance.canonical_digest(),
              "Run must bind the exact supplied instance.")
        check("workload-binding", run.workload.environment_digest == run.instance_digest,
              "Workload environment commitment must identify the complete configured instance.")
        evaluator = components.get(run.evaluator_component_id)
        check("evaluator-binding", bool(evaluator and ComponentRole.EVALUATOR in evaluator.roles),
              "Run evaluator must be an evaluator component inside the bound definition.")
        if run.model_interaction is not None:
            check("model-binding", run.model_interaction.model.digest in run.workload.model_commitments,
                  "Recorded model interaction must identify a model committed by this workload.")
        if run.trace is None or run.evaluation is None:
            finding("run-evidence", CoordinateStatus.INDETERMINATE,
                    "Run checking requires a trace and evaluator output; reward and measurements are separate.")
    return EnvironmentAssessment(definition.canonical_digest(),
                                 instance.canonical_digest() if instance else None,
                                 run.canonical_digest() if run else None, tuple(judgments))


def evaluate_environment_run(definition: EnvironmentDefinition, instance: EnvironmentInstance,
                             run: EnvironmentRunBinding, session: VerificationSession,
                             checks: Sequence[BoundProposition]) -> EnvironmentAssessment:
    """Explicitly rerun selected checks after exact binding preflight.

The binding expected value must be the run digest. Every proposition must carry
the complete retained environment evidence set. A registered checker is a named
trust boundary, not an independent witness or an environment execution engine.
"""
    assessment = assess_environment(definition, session.evidence, instance, run)
    results: list[CoordinateJudgment] = []
    mechanism_results: list[EvaluatedProposition] = []
    evaluator = next((item.descriptor for item in definition.components
                      if item.descriptor.component_id == run.evaluator_component_id), None)
    mechanisms = {mechanism.mechanism_id: mechanism.implementation.digest
                  for item in definition.components if item.descriptor.component_id == run.evaluator_component_id
                  for mechanism in item.mechanisms}
    seen: set[str] = set()
    for binding in checks:
        detail: str | None = None
        if not assessment.bindings_established:
            detail = "Environment binding preflight is unresolved or contradicted; checker was not invoked."
        elif binding.subject_id != run.run_id or binding.expected != run.canonical_digest():
            detail = "Evaluation proposition does not bind this exact run."
        elif set(binding.evidence_refs) != set(environment_evidence_refs(definition, instance, run)):
            detail = "Evaluation proposition must retain the exact complete environment evidence set."
        elif evaluator is None or binding.mechanism_id not in evaluator.mechanism_ids or binding.predicate not in evaluator.supported_relations:
            detail = "Evaluation mechanism or predicate is outside the bound evaluator descriptor."
        elif mechanisms.get(binding.mechanism_id) != binding.mechanism_digest.removeprefix("sha256:"):
            detail = "Evaluation mechanism digest differs from the retained evaluator implementation."
        elif binding.predicate in CAPABILITY_PREDICATES and CAPABILITY_PREDICATES[binding.predicate] not in definition.capabilities:
            detail = "Requested capability was not declared by this environment."
        elif binding.predicate in seen:
            detail = "Duplicate predicates cannot create additional support."
        seen.add(binding.predicate)
        status = CoordinateStatus.INDETERMINATE
        if detail is None:
            evaluated = session.evaluate(binding)
            mechanism_results.append(evaluated)
            status = {"PASS": CoordinateStatus.VERIFIED, "FAIL": CoordinateStatus.FALSIFIED,
                      "UNKNOWN": CoordinateStatus.INDETERMINATE}[evaluated.outcome.value]
            detail = evaluated.details
        results.append(CoordinateJudgment("environment:" + run.canonical_digest() + ":" + binding.predicate,
                       status, (binding.mechanism_id,), binding.evidence_refs, binding.trust_roots,
                       (detail, "Expected run digest: " + run.canonical_digest(), CLAIM_BOUNDARY)))
    if not checks:
        results.append(CoordinateJudgment("environment:" + run.canonical_digest() + ":evaluation",
                       CoordinateStatus.INDETERMINATE, limitations=("No evaluation mechanism selected.", CLAIM_BOUNDARY)))
    return replace(assessment, evaluations=tuple(results), mechanism_results=tuple(mechanism_results))
