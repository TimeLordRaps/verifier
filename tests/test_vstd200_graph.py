"""Terminology: directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Comprehensive adversarial test suite for VSTD-GRAPH directed acyclic graph provenance and causal proof lineages.
"""

from __future__ import annotations

import hashlib
import json
import pytest

from verifier.corrigibility.graph import (
    AcyclicityViolationError,
    CausalDirection,
    EpistemicStatus,
    GraphEdge,
    GraphNode,
    GraphNodeKind,
    GraphProvenanceError,
    LineageBrokenError,
    ProvenanceDAG,
)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def test_node_creation_and_validation() -> None:
    valid_digest = _digest("artifact-payload-1")
    node = GraphNode(
        node_id="artifact:001",
        kind=GraphNodeKind.INPUT_ARTIFACT,
        payload_digest=valid_digest,
        epistemic_status=EpistemicStatus.VERIFIED,
    )
    assert node.node_id == "artifact:001"
    assert node.kind == GraphNodeKind.INPUT_ARTIFACT
    assert node.payload_digest == valid_digest
    assert node.epistemic_status == EpistemicStatus.VERIFIED

    # Invalid empty ID
    with pytest.raises(GraphProvenanceError, match="node_id must be a non-empty string"):
        GraphNode(node_id="", kind=GraphNodeKind.INPUT_ARTIFACT, payload_digest=valid_digest)

    # Invalid digest format
    with pytest.raises(GraphProvenanceError, match="Invalid payload_digest"):
        GraphNode(node_id="node:1", kind=GraphNodeKind.INPUT_ARTIFACT, payload_digest="not-a-sha256")

    # Immediate self-dependency in parents
    with pytest.raises(AcyclicityViolationError, match="Immediate self-dependency"):
        GraphNode(
            node_id="node:cycle",
            kind=GraphNodeKind.TRANSFORMATION,
            payload_digest=valid_digest,
            parents=("node:cycle",),
        )


def test_edge_creation_and_validation() -> None:
    edge = GraphEdge(
        source_id="artifact:001",
        target_id="transform:001",
        causal_direction=CausalDirection.FORWARD_DERIVATION,
    )
    assert edge.source_id == "artifact:001"
    assert edge.target_id == "transform:001"

    # Self-loop edge rejection
    with pytest.raises(AcyclicityViolationError, match="Self-loop edge detected"):
        GraphEdge(source_id="node:same", target_id="node:same")

    # Invalid witness digest format
    with pytest.raises(GraphProvenanceError, match="Invalid witness_digest"):
        GraphEdge(source_id="a", target_id="b", witness_digest="invalid-digest")


def test_topological_sort_linear_and_branching() -> None:
    dag = ProvenanceDAG()
    d1 = _digest("node1")
    d2 = _digest("node2")
    d3 = _digest("node3")
    d4 = _digest("node4")

    n1 = GraphNode("n1", GraphNodeKind.INPUT_ARTIFACT, d1, epistemic_status=EpistemicStatus.VERIFIED)
    n2 = GraphNode("n2", GraphNodeKind.TRANSFORMATION, d2, parents=("n1",), epistemic_status=EpistemicStatus.VERIFIED)
    n3 = GraphNode("n3", GraphNodeKind.TRANSFORMATION, d3, parents=("n1",), epistemic_status=EpistemicStatus.VERIFIED)
    n4 = GraphNode("n4", GraphNodeKind.ASSERTION, d4, parents=("n2", "n3"), epistemic_status=EpistemicStatus.VERIFIED)

    dag.add_node(n1)
    dag.add_node(n2)
    dag.add_node(n3)
    dag.add_node(n4)

    order = dag.topological_sort()
    assert order.index("n1") < order.index("n2")
    assert order.index("n1") < order.index("n3")
    assert order.index("n2") < order.index("n4")
    assert order.index("n3") < order.index("n4")
    assert dag.validate_acyclicity() is True


def test_cycle_detection_direct_and_transitive() -> None:
    # Direct 2-cycle: n1 -> n2 -> n1
    dag = ProvenanceDAG()
    d = _digest("data")
    dag.add_node(GraphNode("n1", GraphNodeKind.INPUT_ARTIFACT, d))
    dag.add_node(GraphNode("n2", GraphNodeKind.TRANSFORMATION, d, parents=("n1",)))
    # Add cycle edge n2 -> n1
    dag.add_edge(GraphEdge(source_id="n2", target_id="n1"))

    with pytest.raises(AcyclicityViolationError, match="Cyclic dependency detected"):
        dag.validate_acyclicity()

    # Transitive 3-cycle: a -> b -> c -> a
    dag3 = ProvenanceDAG()
    dag3.add_node(GraphNode("a", GraphNodeKind.INPUT_ARTIFACT, d))
    dag3.add_node(GraphNode("b", GraphNodeKind.TRANSFORMATION, d, parents=("a",)))
    dag3.add_node(GraphNode("c", GraphNodeKind.TRANSFORMATION, d, parents=("b",)))
    dag3.add_edge(GraphEdge(source_id="c", target_id="a"))

    with pytest.raises(AcyclicityViolationError, match="Cyclic dependency detected"):
        dag3.topological_sort()


def test_causal_lineage_verification_success() -> None:
    dag = ProvenanceDAG()
    n1 = GraphNode("input:01", GraphNodeKind.INPUT_ARTIFACT, _digest("input"), epistemic_status=EpistemicStatus.VERIFIED)
    n2 = GraphNode("step:01", GraphNodeKind.PROOF_STEP, _digest("step1"), parents=("input:01",), epistemic_status=EpistemicStatus.VERIFIED)
    n3 = GraphNode("claim:01", GraphNodeKind.ASSERTION, _digest("claim1"), parents=("step:01",), epistemic_status=EpistemicStatus.VERIFIED)

    dag.add_node(n1)
    dag.add_node(n2)
    dag.add_node(n3)

    verified, reason, lineage = dag.verify_causal_lineage("claim:01")
    assert verified is True
    assert "Unbroken derivation lineage established" in reason
    assert set(lineage) == {"input:01", "step:01", "claim:01"}


def test_causal_lineage_fails_on_falsified_or_tainted_ancestor() -> None:
    dag = ProvenanceDAG()
    n1 = GraphNode("input:01", GraphNodeKind.INPUT_ARTIFACT, _digest("input"), epistemic_status=EpistemicStatus.FALSIFIED)
    n2 = GraphNode("step:01", GraphNodeKind.PROOF_STEP, _digest("step1"), parents=("input:01",), epistemic_status=EpistemicStatus.VERIFIED)
    n3 = GraphNode("claim:01", GraphNodeKind.ASSERTION, _digest("claim1"), parents=("step:01",), epistemic_status=EpistemicStatus.VERIFIED)

    dag.add_node(n1)
    dag.add_node(n2)
    dag.add_node(n3)

    verified, reason, _ = dag.verify_causal_lineage("claim:01")
    assert verified is False
    assert "Lineage contains FALSIFIED node 'input:01'" in reason


def test_causal_lineage_fails_on_ungrounded_root() -> None:
    dag = ProvenanceDAG()
    # n1 is a transformation without parents, but status is UNKNOWN
    n1 = GraphNode("step:orphan", GraphNodeKind.TRANSFORMATION, _digest("orphan"), epistemic_status=EpistemicStatus.UNKNOWN)
    n2 = GraphNode("claim:01", GraphNodeKind.ASSERTION, _digest("claim1"), parents=("step:orphan",), epistemic_status=EpistemicStatus.VERIFIED)

    dag.add_node(n1)
    dag.add_node(n2)

    verified, reason, _ = dag.verify_causal_lineage("claim:01")
    assert verified is False
    assert "Ungrounded root node 'step:orphan'" in reason


def test_revocation_blast_radius_propagation() -> None:
    dag = ProvenanceDAG()
    # Branch 1: root1 -> mid1 -> leaf1
    # Branch 2: root2 -> mid2 -> leaf2
    # Cross: mid1 -> leaf2
    d = _digest("test")
    dag.add_node(GraphNode("root1", GraphNodeKind.INPUT_ARTIFACT, d, epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("root2", GraphNodeKind.INPUT_ARTIFACT, d, epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("mid1", GraphNodeKind.TRANSFORMATION, d, parents=("root1",), epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("mid2", GraphNodeKind.TRANSFORMATION, d, parents=("root2",), epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("leaf1", GraphNodeKind.ASSERTION, d, parents=("mid1",), epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("leaf2", GraphNodeKind.ASSERTION, d, parents=("mid1", "mid2"), epistemic_status=EpistemicStatus.VERIFIED))

    # Revoke root1: affected should be mid1, leaf1, leaf2
    affected = dag.propagate_revocation("root1")
    assert affected == {"mid1", "leaf1", "leaf2"}
    assert dag.nodes["mid1"].epistemic_status == EpistemicStatus.TAINTED
    assert dag.nodes["leaf1"].epistemic_status == EpistemicStatus.TAINTED
    assert dag.nodes["leaf2"].epistemic_status == EpistemicStatus.TAINTED

    # root2 and mid2 must remain untouched
    assert dag.nodes["root2"].epistemic_status == EpistemicStatus.VERIFIED
    assert dag.nodes["mid2"].epistemic_status == EpistemicStatus.VERIFIED


def test_premise_satisfiability_consistency() -> None:
    dag = ProvenanceDAG()
    dag.add_node(
        GraphNode(
            "p1",
            GraphNodeKind.INPUT_ARTIFACT,
            _digest("p1"),
            metadata={"proposition_key": "x_positive", "proposition_value": True},
        )
    )
    dag.add_node(
        GraphNode(
            "p2",
            GraphNodeKind.INPUT_ARTIFACT,
            _digest("p2"),
            metadata={"proposition_key": "x_positive", "proposition_value": True},
        )
    )
    assert dag.assert_premise_satisfiability() is True

    # Inconsistent premise
    dag_bad = ProvenanceDAG()
    dag_bad.add_node(
        GraphNode(
            "bad1",
            GraphNodeKind.ASSERTION,
            _digest("bad1"),
            metadata={"proposition_key": "prime_bound", "proposition_value": 17},
        )
    )
    dag_bad.add_node(
        GraphNode(
            "bad2",
            GraphNodeKind.ASSERTION,
            _digest("bad2"),
            metadata={"proposition_key": "prime_bound", "proposition_value": 19},
        )
    )
    with pytest.raises(GraphProvenanceError, match="Premise inconsistency: contradictory values"):
        dag_bad.assert_premise_satisfiability()


def test_canonical_digest_determinism_and_serialization() -> None:
    dag1 = ProvenanceDAG()
    dag2 = ProvenanceDAG()

    n1 = GraphNode("a", GraphNodeKind.INPUT_ARTIFACT, _digest("a"))
    n2 = GraphNode("b", GraphNodeKind.TRANSFORMATION, _digest("b"), parents=("a",))

    # Add in different orders
    dag1.add_node(n1)
    dag1.add_node(n2)

    dag2.add_node(n2)
    dag2.add_node(n1)

    assert dag1.canonical_digest() == dag2.canonical_digest()

    serialized = dag1.to_dict()
    restored = ProvenanceDAG.from_dict(serialized)
    assert restored.canonical_digest() == dag1.canonical_digest()
    assert len(restored.nodes) == 2


def test_causal_lineage_rejects_unknown_and_unsupported_root_premise() -> None:
    dag = ProvenanceDAG()
    root_unknown = GraphNode(
        "input:unknown",
        GraphNodeKind.INPUT_ARTIFACT,
        _digest("input"),
        epistemic_status=EpistemicStatus.UNKNOWN,
    )
    step = GraphNode(
        "step:01",
        GraphNodeKind.PROOF_STEP,
        _digest("step"),
        parents=("input:unknown",),
        epistemic_status=EpistemicStatus.VERIFIED,
    )
    dag.add_node(root_unknown)
    dag.add_node(step)

    verified, reason, _ = dag.verify_causal_lineage("step:01")
    assert verified is False
    assert "Ungrounded root node 'input:unknown'" in reason


def test_causal_lineage_rejects_unverified_intermediate_step() -> None:
    dag = ProvenanceDAG()
    n1 = GraphNode("input:01", GraphNodeKind.INPUT_ARTIFACT, _digest("input"), epistemic_status=EpistemicStatus.VERIFIED)
    n2 = GraphNode("step:intermediate", GraphNodeKind.PROOF_STEP, _digest("step1"), parents=("input:01",), epistemic_status=EpistemicStatus.UNKNOWN)
    n3 = GraphNode("claim:01", GraphNodeKind.ASSERTION, _digest("claim1"), parents=("step:intermediate",), epistemic_status=EpistemicStatus.VERIFIED)

    dag.add_node(n1)
    dag.add_node(n2)
    dag.add_node(n3)

    verified, reason, _ = dag.verify_causal_lineage("claim:01")
    assert verified is False
    assert "Lineage node 'step:intermediate' is not VERIFIED" in reason


def test_topological_sort_rejects_dangling_edge_references() -> None:
    dag = ProvenanceDAG()
    dag.add_node(GraphNode("node:01", GraphNodeKind.INPUT_ARTIFACT, _digest("01")))
    # Manually add edge to a non-existent node
    dag.add_edge(GraphEdge(source_id="node:01", target_id="node:ghost"))

    with pytest.raises(GraphProvenanceError, match="Dangling edge reference: nodes.*node:ghost"):
        dag.topological_sort()


def test_add_edge_preserves_custom_witness_and_prevents_duplicates() -> None:
    dag = ProvenanceDAG()
    n1 = GraphNode("n1", GraphNodeKind.INPUT_ARTIFACT, _digest("n1"))
    n2 = GraphNode("n2", GraphNodeKind.PROOF_STEP, _digest("n2"), parents=("n1",))
    dag.add_node(n1)
    dag.add_node(n2)
    assert len(dag.edges) == 1
    assert dag.edges[0].witness_digest == ""

    # Add custom edge with witness
    w_digest = _digest("witness-payload")
    dag.add_edge(GraphEdge(source_id="n1", target_id="n2", witness_digest=w_digest))
    assert len(dag.edges) == 1
    assert dag.edges[0].witness_digest == w_digest
