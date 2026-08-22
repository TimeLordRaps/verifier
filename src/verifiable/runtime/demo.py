"""Deterministic adversarial demonstration of VSTD's refutation boundaries.

The demo is intentionally self-contained and side-effect free unless a caller
explicitly asks to emit its JSON specimens.  It does not execute manifests,
reach the network, or manufacture a general truth claim.  Each scenario asks a
narrow question of the reference implementation and checks the observed result
against an explicit invariant.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
import json

from verifiable.core.certificate import (
    CertificateHeader,
    ClaimBinding,
    ClaimCoordinate,
    ClauseGrounding,
    CostTier,
    DecisionBlock,
    DecisionCertificate,
    EncodingRule,
    GroundedFact,
    Grounding,
    IndeterminacyReason,
    IndeterminacyTranscript,
    PropagationStep,
    ResolutionProof,
    ResourceBounds,
    UnitPropagationProof,
    VariableGrounding,
    Verdict,
    canonical_digest,
)
from verifiable.core.kernel import KernelOutcome, check, reference_descriptor
from verifiable.data.graph_level import GraphCollection, ObligationKind, graph_level
from verifiable.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)


TARGET = "artifact:target"
ANCESTOR = "artifact:ancestor-1"
OTHER_ARTIFACT = "artifact:somebody-else"
FORMULA = ((1,), (-1, 2), (-2,))
RULES = (
    EncodingRule("ASSERT_TARGET", ("target",), ((1, "target"),)),
    EncodingRule(
        "TARGET_REQUIRES",
        ("target", "member"),
        ((-1, "target"), (1, "member")),
    ),
    EncodingRule("MEMBER_VIOLATES", ("member",), ((-1, "member"),)),
)


@dataclass(frozen=True)
class DemoResult:
    """One scenario's expected and observed bounded outcome."""

    scenario: str
    title: str
    question: str
    expected: str
    observed: str
    ok: bool
    details: str
    specimen: dict[str, Any]

    def to_dict(self, *, include_specimen: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scenario": self.scenario,
            "title": self.title,
            "question": self.question,
            "expected": self.expected,
            "observed": self.observed,
            "ok": self.ok,
            "details": self.details,
        }
        if include_specimen:
            payload["specimen"] = self.specimen
        return payload


def _binding(claim: str = "no ancestor is revoked") -> ClaimBinding:
    return ClaimBinding(
        claim=claim,
        coordinate=ClaimCoordinate(TARGET, "no_revoked_ancestors"),
        policy_root=canonical_digest([list(clause) for clause in FORMULA]),
        evidence_root=canonical_digest([TARGET, ANCESTOR]),
        verifier=reference_descriptor(),
        bounds=ResourceBounds(1000, 1000, 10000),
    )


def _grounding(ancestor: str = ANCESTOR) -> Grounding:
    return Grounding(
        variables=(
            VariableGrounding(
                1, GroundedFact(TARGET, "policy_admissible", "ASSERTED")
            ),
            VariableGrounding(2, GroundedFact(ancestor, "clean", "REVOKED")),
        ),
        clauses=(
            ClauseGrounding(0, "ASSERT_TARGET", {"target": 1}, {"target": TARGET}),
            ClauseGrounding(
                1,
                "TARGET_REQUIRES",
                {"target": 1, "member": 2},
                {"target": TARGET, "member": ancestor},
            ),
            ClauseGrounding(
                2,
                "MEMBER_VIOLATES",
                {"member": 2},
                {"member": ancestor},
            ),
        ),
        rules=RULES,
    )


def _failure_certificate(
    *,
    binding: ClaimBinding | None = None,
    grounding: Grounding | None = None,
    tier: CostTier = CostTier.UP,
    decision: DecisionBlock | None = None,
) -> DecisionCertificate:
    actual_binding = binding or _binding()
    actual_grounding = grounding or _grounding()
    actual_decision = decision or DecisionBlock(
        propagation=UnitPropagationProof(
            (PropagationStep(0, 1), PropagationStep(1, 2)), 2
        )
    )
    header = CertificateHeader(
        Verdict.FAIL,
        tier,
        2,
        3,
        4,
        2 if actual_decision.propagation is not None else 1,
        actual_binding.digest(),
    )
    return DecisionCertificate(header, FORMULA, actual_grounding, actual_decision)


def _wrong_artifact() -> DemoResult:
    binding = _binding()
    base = _grounding()
    wrong_grounding = Grounding(
        variables=base.variables,
        clauses=(
            base.clauses[0],
            base.clauses[1],
            ClauseGrounding(
                2,
                "MEMBER_VIOLATES",
                {"member": 2},
                {"member": OTHER_ARTIFACT},
            ),
        ),
        rules=RULES,
    )
    certificate = _failure_certificate(binding=binding, grounding=wrong_grounding)
    result = check(certificate, budget=1000, binding=binding)
    ok = (
        result.outcome is KernelOutcome.REJECTED
        and ANCESTOR in result.details
        and OTHER_ARTIFACT in result.details
    )
    return DemoResult(
        scenario="wrong-artifact",
        title="Valid-looking proof, wrong artifact",
        question="Does the grounded proof refer to the same artifact as the claim?",
        expected="REJECTED",
        observed=result.outcome.value,
        ok=ok,
        details=result.details,
        specimen={
            "binding": binding.to_dict(),
            "certificate": certificate.to_dict(),
            "kernel_result": result.to_dict(),
        },
    )


def _honest_unknown() -> DemoResult:
    binding = _binding()
    transcript = IndeterminacyTranscript(
        IndeterminacyReason.PROOF_BOUND_EXCEEDED,
        canonical_digest([list(clause) for clause in FORMULA]),
        declared_bound=3,
        observed_cost=9,
        stopped_at_step=3,
        detail="deterministic demo exhaustion point",
    )
    header = CertificateHeader(
        Verdict.UNKNOWN,
        CostTier.UP,
        2,
        3,
        4,
        0,
        binding.digest(),
    )
    certificate = DecisionCertificate(
        header, FORMULA, _grounding(), DecisionBlock(transcript=transcript)
    )
    result = check(certificate, budget=1000, binding=binding)
    ok = (
        result.outcome is KernelOutcome.ACCEPTED
        and result.verdict is Verdict.UNKNOWN
        and result.reason is IndeterminacyReason.PROOF_BOUND_EXCEEDED
    )
    observed = f"{result.outcome.value}/{result.verdict.value if result.verdict else 'NONE'}"
    return DemoResult(
        scenario="honest-unknown",
        title="Bound exhausted without a false answer",
        question="Can bounded exhaustion remain explicit instead of becoming PASS or FAIL?",
        expected="ACCEPTED/UNKNOWN",
        observed=observed,
        ok=ok,
        details=result.details,
        specimen={
            "binding": binding.to_dict(),
            "certificate": certificate.to_dict(),
            "kernel_result": result.to_dict(),
        },
    )


def _inflated_tier() -> DemoResult:
    binding = _binding()
    certificate = _failure_certificate(
        binding=binding,
        tier=CostTier.RES,
        decision=DecisionBlock(resolution=ResolutionProof(steps=((),))),
    )
    result = check(certificate, budget=1000, binding=binding)
    ok = (
        result.outcome is KernelOutcome.REJECTED
        and "Horn" in result.details
        and "mandatory" in result.details
    )
    return DemoResult(
        scenario="inflated-tier",
        title="Inflated verification-cost claim",
        question="Can a linear Horn check be dressed up as general resolution?",
        expected="REJECTED",
        observed=result.outcome.value,
        ok=ok,
        details=result.details,
        specimen={
            "binding": binding.to_dict(),
            "certificate": certificate.to_dict(),
            "kernel_result": result.to_dict(),
        },
    )


def _artifact(artifact_id: str, status: ArtifactStatus) -> ArtifactNode:
    return ArtifactNode(
        artifact_id=artifact_id,
        label=artifact_id,
        artifact_type=ArtifactType.CORPUS,
        content_digest=canonical_digest({"artifact_id": artifact_id}),
        status=status,
    )


def _poisoned_ancestor() -> DemoResult:
    graph = ProvenanceHypergraph()
    for artifact_id, status in (
        ("artifact:source", ArtifactStatus.REVOKED),
        ("artifact:intermediate", ArtifactStatus.VALID),
        ("artifact:corpus", ArtifactStatus.VALID),
    ):
        graph.add_artifact(_artifact(artifact_id, status))

    for transformation_id, label, kind, source, target in (
        (
            "transform:extract",
            "extract source",
            TransformationType.EXTRACTION,
            "artifact:source",
            "artifact:intermediate",
        ),
        (
            "transform:collect",
            "collect corpus",
            TransformationType.COLLECTION,
            "artifact:intermediate",
            "artifact:corpus",
        ),
    ):
        graph.add_transformation(
            TransformationHyperedge(
                transformation_id=transformation_id,
                label=label,
                transformation_type=kind,
                inputs=(HyperedgePort(source, "INPUT"),),
                outputs=(HyperedgePort(target, "OUTPUT"),),
                software_provenance={},
                parameters={},
                execution_environment={},
            )
        )

    collection = GraphCollection(
        "collection:demo",
        ("artifact:corpus",),
        {
            "artifact:source": 5,
            "artifact:intermediate": 5,
            "artifact:corpus": 5,
        },
        {"transform:extract": 5, "transform:collect": 5},
    )
    binding = ClaimBinding(
        claim="compute the bounded graph level for collection:demo",
        coordinate=ClaimCoordinate("collection:demo", "vstd_graph_level"),
        policy_root=canonical_digest("flagship-demo-graph-policy"),
        evidence_root=canonical_digest(graph.to_dict()),
        verifier=reference_descriptor(),
        bounds=ResourceBounds(10000, 10000, 100000),
    )
    result = graph_level(graph, collection, binding=binding)
    refutation_check = (
        None
        if result.refutation is None
        else check(result.refutation, budget=10000, binding=binding)
    )
    blockers = result.blocking_obligations
    ok = (
        result.level == 0
        and len(blockers) == 1
        and blockers[0].kind is ObligationKind.STATUS_ADMISSIBILITY
        and blockers[0].subject == "artifact:source"
        and blockers[0].observed == ArtifactStatus.REVOKED.value
        and refutation_check is not None
        and refutation_check.outcome is KernelOutcome.ACCEPTED
        and refutation_check.verdict is Verdict.FAIL
    )
    observed = (
        f"GRAPH-LEVEL-{result.level}; "
        f"{blockers[0].observed if blockers else 'NO-BLOCKER'}"
    )
    return DemoResult(
        scenario="poisoned-ancestor",
        title="Revoked ancestor behind valid descendants",
        question="Does a poisoned transitive ancestor cap the collection's graph level?",
        expected="GRAPH-LEVEL-0; REVOKED blocker; checked refutation",
        observed=observed,
        ok=ok,
        details=result.explanation,
        specimen={
            "binding": binding.to_dict(),
            "collection": {
                "collection_id": collection.collection_id,
                "members": list(collection.members),
                "object_levels": dict(sorted(collection.object_levels.items())),
                "edge_levels": dict(sorted(collection.edge_levels.items())),
            },
            "fixture_boundary": (
                "Object and edge levels are declared scenario inputs. This graph-level "
                "refutation does not establish or upgrade their separate evidence."
            ),
            "hypergraph": graph.to_dict(),
            "graph_result": result.to_dict(),
            "refutation": (
                None if result.refutation is None else result.refutation.to_dict()
            ),
            "refutation_check": (
                None if refutation_check is None else refutation_check.to_dict()
            ),
        },
    )


SCENARIOS: dict[str, Callable[[], DemoResult]] = {
    "wrong-artifact": _wrong_artifact,
    "honest-unknown": _honest_unknown,
    "inflated-tier": _inflated_tier,
    "poisoned-ancestor": _poisoned_ancestor,
}


def run_demo(selected: str = "all") -> tuple[DemoResult, ...]:
    """Run one scenario or the complete deterministic flagship demonstration."""
    if selected != "all" and selected not in SCENARIOS:
        raise ValueError(f"unknown demo scenario: {selected}")
    names: Iterable[str] = SCENARIOS if selected == "all" else (selected,)
    return tuple(SCENARIOS[name]() for name in names)


def demo_report(
    results: Iterable[DemoResult], *, include_specimens: bool = True
) -> dict[str, Any]:
    """Return the stable machine-readable report used by the CLI and tests."""
    materialized = tuple(results)
    return {
        "demo": "VSTD-FLAGSHIP-1",
        "status": "OK" if all(item.ok for item in materialized) else "FAILED",
        "scenario_count": len(materialized),
        "successful_scenarios": sum(item.ok for item in materialized),
        "claim_boundary": (
            "These are bounded reference-implementation checks over the included "
            "specimens, not a claim of empirical truth, complete provenance, or adoption."
        ),
        "scenarios": [
            item.to_dict(include_specimen=include_specimens) for item in materialized
        ],
    }


def demo_index(results: Iterable[DemoResult]) -> dict[str, Any]:
    """Return the compact index written beside the full per-scenario specimens."""
    materialized = tuple(results)
    payload = demo_report(materialized, include_specimens=False)
    payload["scenario_files"] = {
        item.scenario: f"{item.scenario}.json" for item in materialized
    }
    return payload


def emit_specimens(results: Iterable[DemoResult], output_dir: Path) -> tuple[Path, ...]:
    """Write deterministic JSON without overwriting different existing content."""
    materialized = tuple(results)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def write_if_safe(path: Path, text: str) -> None:
        encoded = text.encode("utf-8")
        if path.exists() and path.read_bytes() != encoded:
            raise FileExistsError(
                f"refusing to overwrite a different existing demo specimen: {path}"
            )
        if not path.exists():
            path.write_bytes(encoded)

    for item in materialized:
        path = output_dir / f"{item.scenario}.json"
        write_if_safe(
            path,
            json.dumps(item.to_dict(), indent=2, sort_keys=True) + "\n",
        )
        written.append(path)
    index = output_dir / "index.json"
    write_if_safe(
        index,
        json.dumps(demo_index(materialized), indent=2, sort_keys=True) + "\n",
    )
    written.append(index)
    return tuple(written)
