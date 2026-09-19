"""Terminology: directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

VSTD-GRAPH: Directed acyclic graphs of computational provenance, dependencies, and causal proof lineages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class GraphNodeKind(str, Enum):
    """Classification of computational provenance graph nodes."""

    INPUT_ARTIFACT = "INPUT_ARTIFACT"
    TRANSFORMATION = "TRANSFORMATION"
    EVALUATION_STEP = "EVALUATION_STEP"
    ASSERTION = "ASSERTION"
    PROOF_STEP = "PROOF_STEP"
    CHECKPOINT = "CHECKPOINT"
    MODEL_STATE = "MODEL_STATE"
    ENVIRONMENT_CAPTURE = "ENVIRONMENT_CAPTURE"


class EpistemicStatus(str, Enum):
    """Bounded epistemic status of nodes and assertions."""

    VERIFIED = "VERIFIED"
    FALSIFIED = "FALSIFIED"
    UNKNOWN = "UNKNOWN"
    TAINTED = "TAINTED"
    UNSUPPORTED = "UNSUPPORTED"


class CausalDirection(str, Enum):
    """Directionality of causal and verification lineages."""

    FORWARD_DERIVATION = "FORWARD_DERIVATION"
    BACKWARD_REFUTATION = "BACKWARD_REFUTATION"
    WITNESS_FLOW = "WITNESS_FLOW"


class GraphProvenanceError(ValueError):
    """Base error for VSTD-GRAPH operations."""


class AcyclicityViolationError(GraphProvenanceError):
    """Raised when a cycle or self-justifying dependency is detected in the DAG."""


class LineageBrokenError(GraphProvenanceError):
    """Raised when an unbroken path to trusted premises cannot be established."""


@dataclass(frozen=True)
class GraphNode:
    """A discrete node in the computational provenance graph."""

    node_id: str
    kind: GraphNodeKind
    payload_digest: str
    parents: tuple[str, ...] = field(default_factory=tuple)
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.node_id or not isinstance(self.node_id, str):
            raise GraphProvenanceError("node_id must be a non-empty string")
        if not _DIGEST_PATTERN.match(self.payload_digest):
            raise GraphProvenanceError(
                f"Invalid payload_digest: '{self.payload_digest}' must be a sha256 hex digest"
            )
        if self.node_id in self.parents:
            raise AcyclicityViolationError(
                f"Immediate self-dependency detected on node '{self.node_id}'"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "payload_digest": self.payload_digest,
            "parents": list(self.parents),
            "epistemic_status": self.epistemic_status.value,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GraphNode:
        return cls(
            node_id=str(data["node_id"]),
            kind=GraphNodeKind(data["kind"]),
            payload_digest=str(data["payload_digest"]),
            parents=tuple(str(p) for p in data.get("parents", ())),
            epistemic_status=EpistemicStatus(data.get("epistemic_status", EpistemicStatus.UNKNOWN.value)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class GraphEdge:
    """A directed dependency or derivation edge in the provenance graph."""

    source_id: str
    target_id: str
    causal_direction: CausalDirection = CausalDirection.FORWARD_DERIVATION
    relation_kind: str = "DERIVED_FROM"
    witness_digest: str = ""

    def __post_init__(self) -> None:
        if not self.source_id or not self.target_id:
            raise GraphProvenanceError("Edge source and target must be non-empty strings")
        if self.source_id == self.target_id:
            raise AcyclicityViolationError(
                f"Self-loop edge detected on node '{self.source_id}'"
            )
        if self.witness_digest and not _DIGEST_PATTERN.match(self.witness_digest):
            raise GraphProvenanceError(
                f"Invalid witness_digest: '{self.witness_digest}' must be a sha256 hex digest"
            )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "causal_direction": self.causal_direction.value,
            "relation_kind": self.relation_kind,
        }
        if self.witness_digest:
            result["witness_digest"] = self.witness_digest
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GraphEdge:
        return cls(
            source_id=str(data["source_id"]),
            target_id=str(data["target_id"]),
            causal_direction=CausalDirection(
                data.get("causal_direction", CausalDirection.FORWARD_DERIVATION.value)
            ),
            relation_kind=str(data.get("relation_kind", "DERIVED_FROM")),
            witness_digest=str(data.get("witness_digest", "")),
        )


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


class ProvenanceDAG:
    """Directed acyclic graph of computational provenance and causal proof lineages."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adjacency: dict[str, set[str]] = {}  # parent -> children
        self._reverse_adjacency: dict[str, set[str]] = {}  # child -> parents

    @property
    def nodes(self) -> Mapping[str, GraphNode]:
        return dict(self._nodes)

    @property
    def edges(self) -> Sequence[GraphEdge]:
        return tuple(self._edges)

    def add_node(self, node: GraphNode) -> None:
        if node.node_id in self._nodes:
            raise GraphProvenanceError(f"Duplicate node_id: '{node.node_id}' already exists")
        self._nodes[node.node_id] = node
        self._adjacency.setdefault(node.node_id, set())
        self._reverse_adjacency.setdefault(node.node_id, set())
        for parent_id in node.parents:
            self.add_edge(GraphEdge(source_id=parent_id, target_id=node.node_id))

    def add_edge(self, edge: GraphEdge) -> None:
        existing_idx = next(
            (i for i, e in enumerate(self._edges) if e.source_id == edge.source_id and e.target_id == edge.target_id),
            None,
        )
        if existing_idx is not None:
            if edge.witness_digest and not self._edges[existing_idx].witness_digest:
                self._edges[existing_idx] = edge
        else:
            self._edges.append(edge)
        self._adjacency.setdefault(edge.source_id, set()).add(edge.target_id)
        self._reverse_adjacency.setdefault(edge.target_id, set()).add(edge.source_id)

    def validate_acyclicity(self) -> bool:
        """Enforce strict acyclicity. Raises AcyclicityViolationError if a cycle exists."""
        self.topological_sort()
        return True

    def topological_sort(self) -> list[str]:
        """Kahn's algorithm for deterministic topological ordering."""
        all_ids = set(self._nodes.keys()) | set(self._adjacency.keys()) | set(self._reverse_adjacency.keys())
        missing = all_ids - set(self._nodes.keys())
        if missing:
            raise GraphProvenanceError(
                f"Dangling edge reference: nodes {sorted(missing)} referenced in edges but not added to DAG"
            )
        in_degree: dict[str, int] = {node_id: 0 for node_id in all_ids}
        for parent, children in self._adjacency.items():
            for child in children:
                in_degree[child] = in_degree.get(child, 0) + 1

        queue = sorted([node_id for node_id, deg in in_degree.items() if deg == 0])
        ordered: list[str] = []

        while queue:
            curr = queue.pop(0)
            ordered.append(curr)
            for child in sorted(self._adjacency.get(curr, set())):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
                    queue.sort()

        if len(ordered) != len(all_ids):
            cycle_nodes = sorted(node_id for node_id, deg in in_degree.items() if deg > 0)
            raise AcyclicityViolationError(
                f"Cyclic dependency detected among nodes: {cycle_nodes}"
            )
        return ordered

    def verify_causal_lineage(self, target_node_id: str) -> tuple[bool, str, list[str]]:
        """Verify that target_node has an unbroken causal derivation path to verified premises.

        Returns (is_verified, reason, path_node_ids).
        """
        if target_node_id not in self._nodes:
            raise GraphProvenanceError(f"Target node '{target_node_id}' not found in DAG")

        self.validate_acyclicity()

        visited: set[str] = set()
        stack: list[str] = [target_node_id]
        lineage_nodes: list[str] = []

        while stack:
            curr_id = stack.pop()
            if curr_id in visited:
                continue
            visited.add(curr_id)
            lineage_nodes.append(curr_id)

            node = self._nodes.get(curr_id)
            if node is None:
                return (
                    False,
                    f"Lineage broken: referenced parent '{curr_id}' is missing from DAG nodes",
                    lineage_nodes,
                )

            if node.epistemic_status == EpistemicStatus.FALSIFIED:
                return (
                    False,
                    f"Lineage contains FALSIFIED node '{curr_id}'",
                    lineage_nodes,
                )

            if node.epistemic_status == EpistemicStatus.TAINTED:
                return (
                    False,
                    f"Lineage contains TAINTED node '{curr_id}'",
                    lineage_nodes,
                )

            parents = self._reverse_adjacency.get(curr_id, set())
            if not parents:
                if node.epistemic_status != EpistemicStatus.VERIFIED:
                    return (
                        False,
                        f"Ungrounded root node '{curr_id}' of kind {node.kind.value} is not VERIFIED",
                        lineage_nodes,
                    )
            else:
                if node.epistemic_status != EpistemicStatus.VERIFIED:
                    return (
                        False,
                        f"Lineage node '{curr_id}' is not VERIFIED (status: {node.epistemic_status.value})",
                        lineage_nodes,
                    )
                for parent_id in sorted(parents):
                    stack.append(parent_id)

        target = self._nodes[target_node_id]
        if target.epistemic_status != EpistemicStatus.VERIFIED:
            return (
                False,
                f"Target node '{target_node_id}' status is {target.epistemic_status.value}, not VERIFIED",
                lineage_nodes,
            )

        return True, "Unbroken derivation lineage established", sorted(lineage_nodes)

    def propagate_revocation(self, revoked_node_id: str) -> set[str]:
        """When an ancestor node is revoked or falsified, deterministically identify all downstream affected nodes."""
        if revoked_node_id not in self._nodes:
            raise GraphProvenanceError(f"Node '{revoked_node_id}' not found in DAG")

        affected: set[str] = set()
        queue: list[str] = [revoked_node_id]

        while queue:
            curr = queue.pop(0)
            for child in self._adjacency.get(curr, set()):
                if child not in affected:
                    affected.add(child)
                    queue.append(child)

        for node_id in affected:
            if node_id in self._nodes:
                old_node = self._nodes[node_id]
                self._nodes[node_id] = GraphNode(
                    node_id=old_node.node_id,
                    kind=old_node.kind,
                    payload_digest=old_node.payload_digest,
                    parents=old_node.parents,
                    epistemic_status=EpistemicStatus.TAINTED,
                    metadata=dict(old_node.metadata),
                )
        return affected

    def assert_premise_satisfiability(self) -> bool:
        """Verify that root premise nodes do not assert contradictory propositions (vacuity check)."""
        seen_assertions: dict[str, Any] = {}
        for node in self._nodes.values():
            if node.kind in (GraphNodeKind.INPUT_ARTIFACT, GraphNodeKind.ASSERTION):
                prop_key = node.metadata.get("proposition_key")
                prop_val = node.metadata.get("proposition_value")
                if prop_key is not None and prop_val is not None:
                    if prop_key in seen_assertions and seen_assertions[prop_key] != prop_val:
                        raise GraphProvenanceError(
                            f"Premise inconsistency: contradictory values for proposition '{prop_key}': "
                            f"{seen_assertions[prop_key]} vs {prop_val}"
                        )
                    seen_assertions[prop_key] = prop_val
        return True

    def canonical_digest(self) -> str:
        """Compute stable SHA-256 digest binding topological node order, digests, and edges."""
        topo_order = self.topological_sort()
        payload = {
            "topological_nodes": [
                self._nodes[nid].to_dict() for nid in topo_order if nid in self._nodes
            ],
            "edges": sorted(
                [edge.to_dict() for edge in self._edges],
                key=lambda e: (e["source_id"], e["target_id"]),
            ),
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {nid: node.to_dict() for nid, node in sorted(self._nodes.items())},
            "edges": [edge.to_dict() for edge in self._edges],
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProvenanceDAG:
        dag = cls()
        nodes_dict = data.get("nodes", {})
        for nid, ndata in nodes_dict.items():
            dag.add_node(GraphNode.from_dict(ndata))
        for edata in data.get("edges", []):
            dag.add_edge(GraphEdge.from_dict(edata))
        dag.validate_acyclicity()
        return dag
