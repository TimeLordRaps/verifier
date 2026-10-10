# Acronyms: Boolean satisfiability problem (SAT); unsatisfiable (UNSAT);
# Verifier Standard (VSTD).
"""Non-normative VSTD and provenance hypergraph binding for experiment route observations."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from verifier.core.receipt import compute_canonical_digest
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    EvidenceClassification,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)

from .canonical import canonical_bytes, canonical_digest
from .contracts import NativeVerdict
from .external_verifiers import load_verifier
from .route import RouteError, compile_route
from .sat_backend import CadicalBackend, SatStatus


BINDING_VERSION = "vgsat-vstd-binding-0.1"
BASE_SHA = "598c545be3833d6d81bb7e252ca5837f3bb2a449"


def build_record(
    *,
    instance_id: str,
    domain: str,
    arm: str,
    instance: dict[str, Any],
    contract: dict[str, Any],
    lm_observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    formula: dict[str, Any] | None,
    solver_configuration: dict[str, Any],
    solver_observation: dict[str, Any] | None,
    candidate: dict[str, Any] | None,
    native_observation: dict[str, Any] | None,
    timings: dict[str, int | None],
    resource_bounds: dict[str, Any],
    failure_observation: dict[str, Any] | None,
    retry_index: int = 0,
) -> dict[str, Any]:
    """Bind exact route artifacts without creating a new VSTD wire receipt."""

    route_status = _route_status(solver_observation, native_observation)
    bounded_claim_status = (
        "PASS" if route_status in {"SAT_ACCEPTED", "CANDIDATE_ACCEPTED"} else "UNKNOWN"
    )
    stable_payload: dict[str, Any] = {
        "binding_version": BINDING_VERSION,
        "base_sha": BASE_SHA,
        "instance_id": instance_id,
        "domain": domain,
        "arm": arm,
        "instance": instance,
        "instance_digest": canonical_digest(instance),
        "verifier_contract": contract,
        "verifier_contract_digest": canonical_digest(contract),
        "lm_observation": lm_observation,
        "lm_observation_digest": (
            canonical_digest(lm_observation) if lm_observation is not None else None
        ),
        "proposal": proposal,
        "proposal_digest": canonical_digest(proposal) if proposal is not None else None,
        "formula": formula,
        "formula_digest": canonical_digest(formula) if formula is not None else None,
        "solver_configuration": solver_configuration,
        "solver_configuration_digest": canonical_digest(solver_configuration),
        "solver_observation": solver_observation,
        "candidate": candidate,
        "candidate_digest": canonical_digest(candidate) if candidate is not None else None,
        "native_observation": native_observation,
        "failure_observation": failure_observation,
        "timings_ns": dict(timings),
        "resource_bounds": resource_bounds,
        "retry_index": retry_index,
        "route_status": route_status,
        "bounded_claim_status": bounded_claim_status,
        "permitted_inference": (
            "the supplied candidate passed the pinned native verifier for this exact instance"
            if bounded_claim_status == "PASS"
            else "no positive domain conclusion; the bounded search outcome remains UNKNOWN"
        ),
        "prohibited_inferences": [
            "route-local UNSAT is global domain UNSAT",
            "exhausted routes establish nonexistence",
            "timeout or resource exhaustion means false",
            "the native verifier is sound",
            "a smaller formula means less total work",
            "missing identity establishes independence or trustworthiness",
        ],
    }
    graph, artifact_payloads = _build_graph(stable_payload)
    graph_payload = graph.to_dict()
    binding_payload = {"stable_payload": stable_payload, "graph": graph_payload}
    return {
        "experiment_record_version": BINDING_VERSION,
        "stable_payload": stable_payload,
        "graph": graph_payload,
        "artifact_payloads": artifact_payloads,
        "binding_digest": compute_canonical_digest(binding_payload),
    }


def validate_record(experiment_root: Any, record: Mapping[str, Any], *, reexecute: bool = True) -> list[str]:
    """Independently rehash, rebuild, and optionally reexecute a record."""

    errors: list[str] = []
    if record.get("experiment_record_version") != BINDING_VERSION:
        errors.append("unsupported experiment_record_version")
        return errors
    stable = record.get("stable_payload")
    graph_raw = record.get("graph")
    artifacts = record.get("artifact_payloads")
    if not isinstance(stable, Mapping) or not isinstance(graph_raw, Mapping) or not isinstance(artifacts, Mapping):
        return ["record sections must be objects"]
    expected_binding = compute_canonical_digest({"stable_payload": stable, "graph": graph_raw})
    if record.get("binding_digest") != expected_binding:
        errors.append("binding_digest mismatch")

    try:
        graph = ProvenanceHypergraph.from_dict(graph_raw)
        errors.extend(graph.validate_structure())
        if not graph.verify_acyclicity():
            errors.append("provenance hypergraph route history is cyclic")
        for artifact_id, artifact in graph.artifacts.items():
            if artifact_id not in artifacts:
                errors.append(f"missing payload for graph artifact {artifact_id}")
                continue
            digest = hashlib.sha256(canonical_bytes(artifacts[artifact_id])).hexdigest()
            if digest != artifact.content_digest:
                errors.append(f"content digest mismatch for {artifact_id}")
    except (TypeError, ValueError, KeyError) as exc:
        errors.append(f"invalid provenance hypergraph route history: {type(exc).__name__}")

    for field, value_field in (
        ("instance_digest", "instance"),
        ("verifier_contract_digest", "verifier_contract"),
        ("lm_observation_digest", "lm_observation"),
        ("proposal_digest", "proposal"),
        ("formula_digest", "formula"),
        ("solver_configuration_digest", "solver_configuration"),
        ("candidate_digest", "candidate"),
    ):
        value = stable.get(value_field)
        expected = canonical_digest(value) if value is not None else None
        if stable.get(field) != expected:
            errors.append(f"{field} mismatch")

    proposal = stable.get("proposal")
    formula = stable.get("formula")
    solver_raw = stable.get("solver_observation")
    if isinstance(proposal, Mapping) and formula is not None:
        try:
            compiled = compile_route(proposal)
            if compiled.formula_payload() != formula:
                errors.append("compiled formula does not match bound formula")
            if reexecute and isinstance(solver_raw, Mapping):
                solver_configuration = stable.get("solver_configuration")
                if not isinstance(solver_configuration, Mapping):
                    errors.append("solver configuration is missing")
                    solver_configuration = {}
                conflict_budget = solver_configuration.get("conflict_budget")
                if conflict_budget is not None and (
                    isinstance(conflict_budget, bool)
                    or not isinstance(conflict_budget, int)
                    or conflict_budget <= 0
                ):
                    errors.append("solver conflict budget is unsupported")
                    conflict_budget = None
                expected_configuration = CadicalBackend(
                    conflict_budget=conflict_budget
                ).configuration
                if dict(solver_configuration) != expected_configuration:
                    errors.append("solver configuration is unsupported")
                observed = CadicalBackend(
                    conflict_budget=conflict_budget
                ).solve(compiled)
                if observed.status.value != solver_raw.get("status"):
                    errors.append("reexecuted SAT status mismatch")
        except RouteError as exc:
            errors.append(f"bound route is malformed: {exc}")

    if reexecute and stable.get("candidate") is not None:
        try:
            verifier = load_verifier(experiment_root, str(stable.get("domain")))
            observed = verifier.verify(stable.get("instance"), stable.get("candidate"))
            native_raw = stable.get("native_observation")
            if not isinstance(native_raw, Mapping) or observed.verdict.value != native_raw.get("verdict"):
                errors.append("reexecuted native-verifier verdict mismatch")
        except Exception as exc:
            errors.append(f"native-verifier reexecution failed: {type(exc).__name__}")

    expected_status = _route_status(solver_raw, stable.get("native_observation"))
    if stable.get("route_status") != expected_status:
        errors.append("route_status is inconsistent")
    expected_claim = (
        "PASS" if expected_status in {"SAT_ACCEPTED", "CANDIDATE_ACCEPTED"} else "UNKNOWN"
    )
    if stable.get("bounded_claim_status") != expected_claim:
        errors.append("bounded_claim_status is inconsistent")
    return errors


def _route_status(solver: Any, native: Any) -> str:
    if isinstance(solver, Mapping):
        sat_status = solver.get("status")
        if sat_status == SatStatus.UNSAT.value:
            return "ROUTE_UNSAT"
        if sat_status == SatStatus.UNKNOWN.value:
            return "ROUTE_UNKNOWN"
        if sat_status == SatStatus.SAT.value:
            if isinstance(native, Mapping) and native.get("verdict") == NativeVerdict.ACCEPTED.value:
                return "SAT_ACCEPTED"
            if isinstance(native, Mapping) and native.get("verdict") == NativeVerdict.REJECTED.value:
                return "SAT_REJECTED"
            if isinstance(native, Mapping) and native.get("verdict") == NativeVerdict.ERROR.value:
                return "SAT_NATIVE_ERROR"
            if isinstance(native, Mapping) and native.get("verdict") == NativeVerdict.UNKNOWN.value:
                return "SAT_NATIVE_UNKNOWN"
            return "ROUTE_UNKNOWN"
    if isinstance(native, Mapping):
        if native.get("verdict") == NativeVerdict.ACCEPTED.value:
            return "CANDIDATE_ACCEPTED"
        if native.get("verdict") == NativeVerdict.REJECTED.value:
            return "CANDIDATE_REJECTED"
        if native.get("verdict") == NativeVerdict.ERROR.value:
            return "CANDIDATE_ERROR"
        return "CANDIDATE_UNKNOWN"
    return "MALFORMED"


def _build_graph(stable: Mapping[str, Any]) -> tuple[ProvenanceHypergraph, dict[str, Any]]:
    graph = ProvenanceHypergraph()
    payloads: dict[str, Any] = {}
    chain: list[str] = []

    def add(label: str, payload: Any, artifact_type: ArtifactType, evidence: EvidenceClassification) -> str:
        raw_digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        artifact_id = f"vgsat:{label}:{raw_digest[:16]}"
        payloads[artifact_id] = payload
        graph.add_artifact(
            ArtifactNode(
                artifact_id=artifact_id,
                label=label,
                artifact_type=artifact_type,
                content_digest=raw_digest,
                byte_size=len(canonical_bytes(payload)),
                mime_type="application/json",
                status=ArtifactStatus.VALID,
                evidence_class=evidence,
                attributes={"claim_status": stable.get("bounded_claim_status", "UNKNOWN")},
            )
        )
        return artifact_id

    instance_id = add("instance", stable["instance"], ArtifactType.RAW_SOURCE_FILE, EvidenceClassification.IMPORTED)
    chain.append(instance_id)
    stages = [
        (
            "lm-observation",
            stable.get("lm_observation"),
            ArtifactType.EXECUTION_EVIDENCE,
            EvidenceClassification.DIRECTLY_OBSERVED,
        ),
        ("proposal", stable.get("proposal"), ArtifactType.CONFIG, EvidenceClassification.DECLARED),
        ("formula", stable.get("formula"), ArtifactType.CONFIG, EvidenceClassification.REPRODUCED),
        (
            "solver-config",
            stable.get("solver_configuration") if stable.get("formula") is not None else None,
            ArtifactType.CONFIG,
            EvidenceClassification.DECLARED,
        ),
        ("solver", stable.get("solver_observation"), ArtifactType.EXECUTION_EVIDENCE, EvidenceClassification.DIRECTLY_OBSERVED),
        ("candidate", stable.get("candidate"), ArtifactType.SUBMISSION_ARTIFACT, EvidenceClassification.REPRODUCED),
        ("native", stable.get("native_observation"), ArtifactType.EVALUATION_REPORT, EvidenceClassification.DIRECTLY_OBSERVED),
        ("failure", stable.get("failure_observation"), ArtifactType.EVALUATION_REPORT, EvidenceClassification.DIRECTLY_OBSERVED),
    ]
    for label, payload, kind, evidence in stages:
        if payload is None:
            continue
        artifact_id = add(label, payload, kind, evidence)
        previous = chain[-1]
        graph.add_transformation(
            TransformationHyperedge(
                transformation_id=f"vgsat:edge:{len(chain)}:{artifact_id.rsplit(':', 1)[-1]}",
                label=f"{chain[-1].split(':')[1]}-to-{label}",
                transformation_type=(
                    TransformationType.EVALUATION if label == "native" else TransformationType.WORKLOAD_EXECUTION
                ),
                inputs=(HyperedgePort(previous, "INPUT"),),
                outputs=(HyperedgePort(artifact_id, "OUTPUT"),),
                software_provenance={"repo": "TimeLordRaps/verifier", "commit_sha": BASE_SHA},
                parameters={"arm": stable.get("arm"), "domain": stable.get("domain")},
                execution_environment={"public_environment": "see experiment result metadata"},
                evidence_class=evidence,
                status="COMPLETED",
            )
        )
        chain.append(artifact_id)
    return graph, payloads
