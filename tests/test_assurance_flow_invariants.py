"""Terminology: Verifier Standard (VSTD).

Falsification probes for evidence-strength invariants shared by the five-As
human traversal and existing VSTD machinery.
"""

from __future__ import annotations

from verifier.core.reproducibility import (
    ReproducibilityLevel,
    compare_reproduction_level,
)
from verifier.data.models import (
    ArtifactNode,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)


def _artifact(artifact_id: str) -> ArtifactNode:
    return ArtifactNode(artifact_id, artifact_id, ArtifactType.MODEL, "a" * 64)


def _edge(edge_id: str, source: str, target: str) -> TransformationHyperedge:
    return TransformationHyperedge(
        edge_id,
        edge_id,
        TransformationType.EVALUATION,
        (HyperedgePort(source, "INPUT"),),
        (HyperedgePort(target, "OUTPUT"),),
        {},
        {},
        {},
    )


def test_matching_field_or_mismatching_verdict_earns_no_reproduction_level() -> None:
    assert compare_reproduction_level("a", "b", "PASS", "PASS") is None
    assert compare_reproduction_level("a", "b", "PASS", "FAIL") is None


def test_matching_bound_evidence_can_earn_only_its_checked_level() -> None:
    assert (
        compare_reproduction_level(
            "a",
            "b",
            "PASS",
            "PASS",
            original_evidence_hash="evidence",
            reproduced_evidence_hash="evidence",
        )
        is ReproducibilityLevel.EVIDENCE_EQUIVALENT
    )


def test_duplicate_paths_do_not_multiply_ancestral_support() -> None:
    graph = ProvenanceHypergraph()
    for artifact_id in ("source", "result"):
        graph.add_artifact(_artifact(artifact_id))
    graph.add_transformation(_edge("path:one", "source", "result"))
    graph.add_transformation(_edge("path:two", "source", "result"))

    assert graph.ancestors(["result"]) == {"source", "result"}
    assert graph.descendants(["source"]) == {"source", "result"}


def test_self_consumption_and_two_node_feedback_are_cycles() -> None:
    self_graph = ProvenanceHypergraph()
    self_graph.add_artifact(_artifact("a"))
    self_graph.add_transformation(_edge("self", "a", "a"))
    assert self_graph.verify_acyclicity() is False

    feedback = ProvenanceHypergraph()
    feedback.add_artifact(_artifact("a"))
    feedback.add_artifact(_artifact("b"))
    feedback.add_transformation(_edge("a-to-b", "a", "b"))
    feedback.add_transformation(_edge("b-to-a", "b", "a"))
    assert feedback.verify_acyclicity() is False
