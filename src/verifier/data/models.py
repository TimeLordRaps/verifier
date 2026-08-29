"""Terminology: Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

VSTD-Graph provenance models and algorithms.

Graph-1 receipts retain the frozen ``VSTD-DATA-0.1`` serialized receipt identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Iterable, Mapping, Optional, Sequence


class ArtifactType(str, Enum):
    RAW_SOURCE_FILE = "RAW_SOURCE_FILE"
    CORPUS = "CORPUS"
    SHARD = "SHARD"
    DATASET_SPLIT = "DATASET_SPLIT"
    TOKENIZED_CORPUS = "TOKENIZED_CORPUS"
    CHECKPOINT = "CHECKPOINT"
    ADAPTER = "ADAPTER"
    MODEL = "MODEL"
    EVALUATION_REPORT = "EVALUATION_REPORT"
    SUBMISSION_ARTIFACT = "SUBMISSION_ARTIFACT"
    CONFIG = "CONFIG"
    HARDWARE_EVIDENCE = "HARDWARE_EVIDENCE"
    DEVICE_IDENTITY = "DEVICE_IDENTITY"
    FIRMWARE_MEASUREMENT = "FIRMWARE_MEASUREMENT"
    RUNTIME_MEASUREMENT = "RUNTIME_MEASUREMENT"
    TOPOLOGY_SNAPSHOT = "TOPOLOGY_SNAPSHOT"
    EXECUTION_EVIDENCE = "EXECUTION_EVIDENCE"
    ACCOUNTING_EVIDENCE = "ACCOUNTING_EVIDENCE"
    CONTINUITY_EVIDENCE = "CONTINUITY_EVIDENCE"
    HARDWARE_RECEIPT = "HARDWARE_RECEIPT"
    PROVIDER_EVIDENCE = "PROVIDER_EVIDENCE"


class TransformationType(str, Enum):
    COLLECTION = "COLLECTION"
    EXTRACTION = "EXTRACTION"
    FILTERING = "FILTERING"
    DEDUPLICATION = "DEDUPLICATION"
    NORMALIZATION = "NORMALIZATION"
    AUGMENTATION = "AUGMENTATION"
    SYNTHETIC_GENERATION = "SYNTHETIC_GENERATION"
    TOKENIZATION = "TOKENIZATION"
    TRAINING = "TRAINING"
    FINE_TUNING = "FINE_TUNING"
    DISTILLATION = "DISTILLATION"
    QUANTIZATION = "QUANTIZATION"
    EVALUATION = "EVALUATION"
    HARDWARE_DISCOVERY = "HARDWARE_DISCOVERY"
    HARDWARE_ATTESTATION = "HARDWARE_ATTESTATION"
    WORKLOAD_EXECUTION = "WORKLOAD_EXECUTION"
    COMPUTE_ACCOUNTING = "COMPUTE_ACCOUNTING"
    CONTINUITY_ANCHORING = "CONTINUITY_ANCHORING"
    EVIDENCE_BINDING = "EVIDENCE_BINDING"


class ArtifactStatus(str, Enum):
    VALID = "VALID"
    CHALLENGED = "CHALLENGED"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class EvidenceClassification(str, Enum):
    CRYPTOGRAPHICALLY_BOUND = "CRYPTOGRAPHICALLY_BOUND"
    DIRECTLY_OBSERVED = "DIRECTLY_OBSERVED"
    REPRODUCED = "REPRODUCED"
    DECLARED = "DECLARED"
    IMPORTED = "IMPORTED"
    INFERRED = "INFERRED"
    MANUAL = "MANUAL"
    UNKNOWN = "UNKNOWN"


class RightsEvidenceLevel(str, Enum):
    RIGHTS_DECLARED = "RIGHTS_DECLARED"
    RIGHTS_SOURCE_REFERENCED = "RIGHTS_SOURCE_REFERENCED"
    RIGHTS_DOCUMENT_VERIFIED = "RIGHTS_DOCUMENT_VERIFIED"
    RIGHTS_CONTRACTUALLY_ATTESTED = "RIGHTS_CONTRACTUALLY_ATTESTED"
    RIGHTS_UNKNOWN = "RIGHTS_UNKNOWN"
    RIGHTS_CONFLICTED = "RIGHTS_CONFLICTED"


@dataclass(frozen=True)
class ContributorSpec:
    contributor_id: str
    name: str
    contributor_type: str  # INDIVIDUAL, ORGANIZATION, AUTOMATED_PIPELINE
    identifier_uri: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "contributor_id": self.contributor_id,
            "name": self.name,
            "contributor_type": self.contributor_type,
            "identifier_uri": self.identifier_uri,
        }


@dataclass(frozen=True)
class RightsSpec:
    rights_id: str
    license_spdx: str
    license_uri: str = ""
    commercial_allowed: bool = True
    attribution_required: bool = True
    usage_restrictions: tuple[str, ...] = ()
    rights_evidence_level: RightsEvidenceLevel = RightsEvidenceLevel.RIGHTS_DECLARED

    def to_dict(self) -> dict[str, Any]:
        return {
            "rights_id": self.rights_id,
            "license_spdx": self.license_spdx,
            "license_uri": self.license_uri,
            "commercial_allowed": self.commercial_allowed,
            "attribution_required": self.attribution_required,
            "usage_restrictions": list(self.usage_restrictions),
            "rights_evidence_level": self.rights_evidence_level.value,
        }


@dataclass(frozen=True)
class ArtifactNode:
    artifact_id: str
    label: str
    artifact_type: ArtifactType
    content_digest: str  # SHA-256 over raw file payload bytes
    byte_size: int = 0
    record_count: Optional[int] = None
    mime_type: str = "application/octet-stream"
    metadata_digest: str = ""
    provenance_digest: str = ""
    status: ArtifactStatus = ArtifactStatus.UNKNOWN
    evidence_class: EvidenceClassification = EvidenceClassification.DECLARED
    rights_id: Optional[str] = None
    contributor_id: Optional[str] = None
    storage_uris: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "label": self.label,
            "artifact_type": self.artifact_type.value,
            "content_digest": self.content_digest,
            "byte_size": self.byte_size,
            "record_count": self.record_count,
            "mime_type": self.mime_type,
            "metadata_digest": self.metadata_digest,
            "provenance_digest": self.provenance_digest,
            "status": self.status.value,
            "evidence_class": self.evidence_class.value,
            "rights_id": self.rights_id,
            "contributor_id": self.contributor_id,
            "storage_uris": list(self.storage_uris),
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class ConflictRecord:
    """Retained incompatible evidence about one artifact or transformation field."""

    conflict_id: str
    subject_id: str
    predicate: str
    competing_values: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "subject_id": self.subject_id,
            "predicate": self.predicate,
            "competing_values": list(self.competing_values),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class HyperedgePort:
    artifact_id: str
    role: str  # e.g., INPUT_SHARD, CONFIG, BASE_WEIGHTS, TRAINING_SPLIT, OUTPUT_CHECKPOINT


@dataclass
class TransformationHyperedge:
    transformation_id: str
    label: str
    transformation_type: TransformationType
    inputs: Sequence[HyperedgePort]
    outputs: Sequence[HyperedgePort]
    software_provenance: dict[str, Any]  # repo, commit, script, version, clean/dirty
    parameters: dict[str, Any]  # hyperparams, filter specs, seeds
    execution_environment: dict[str, Any]  # runtime, os, hardware, timestamp
    evidence_class: EvidenceClassification = EvidenceClassification.DECLARED
    status: str = "COMPLETED"

    def __post_init__(self) -> None:
        if isinstance(self.inputs, HyperedgePort):
            self.inputs = (self.inputs,)
        else:
            self.inputs = tuple(self.inputs)
        if isinstance(self.outputs, HyperedgePort):
            self.outputs = (self.outputs,)
        else:
            self.outputs = tuple(self.outputs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transformation_id": self.transformation_id,
            "label": self.label,
            "transformation_type": self.transformation_type.value,
            "inputs": [{"artifact_id": p.artifact_id, "role": p.role} for p in self.inputs],
            "outputs": [{"artifact_id": p.artifact_id, "role": p.role} for p in self.outputs],
            "software_provenance": dict(self.software_provenance),
            "parameters": dict(self.parameters),
            "execution_environment": dict(self.execution_environment),
            "evidence_class": self.evidence_class.value,
            "status": self.status,
        }


@dataclass(frozen=True)
class CompletenessMetrics:
    source_coverage: float
    transformation_coverage: float
    content_integrity: float
    license_coverage: float
    contributor_coverage: float
    lineage_depth: int
    overall_completeness: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_coverage": round(self.source_coverage, 4),
            "transformation_coverage": round(self.transformation_coverage, 4),
            "content_integrity": round(self.content_integrity, 4),
            "license_coverage": round(self.license_coverage, 4),
            "contributor_coverage": round(self.contributor_coverage, 4),
            "lineage_depth": self.lineage_depth,
            "overall_completeness": round(self.overall_completeness, 4),
        }


class ProvenanceHypergraph:
    """N-ary Hypergraph structure for dataset, training, and artifact lineage."""

    def __init__(self) -> None:
        self.artifacts: dict[str, ArtifactNode] = {}
        self.transformations: dict[str, TransformationHyperedge] = {}
        self.contributors: dict[str, ContributorSpec] = {}
        self.rights: dict[str, RightsSpec] = {}
        self.conflicts: dict[str, ConflictRecord] = {}

    @staticmethod
    def _add_unique(collection: dict[str, Any], identifier: str, value: Any) -> str:
        if identifier in collection:
            raise ValueError(f"duplicate graph identifier: {identifier}")
        collection[identifier] = value
        return identifier

    def add_artifact(self, artifact: ArtifactNode) -> str:
        if artifact.artifact_id in self.transformations:
            raise ValueError(
                "artifact and transformation identifiers must be disjoint: "
                f"{artifact.artifact_id}"
            )
        return self._add_unique(self.artifacts, artifact.artifact_id, artifact)

    def add_transformation(self, transform: TransformationHyperedge) -> str:
        if transform.transformation_id in self.artifacts:
            raise ValueError(
                "artifact and transformation identifiers must be disjoint: "
                f"{transform.transformation_id}"
            )
        return self._add_unique(
            self.transformations, transform.transformation_id, transform
        )

    def add_contributor(self, contributor: ContributorSpec) -> str:
        return self._add_unique(
            self.contributors, contributor.contributor_id, contributor
        )

    def add_rights(self, rights: RightsSpec) -> str:
        return self._add_unique(self.rights, rights.rights_id, rights)

    def add_conflict(self, conflict: ConflictRecord) -> str:
        return self._add_unique(self.conflicts, conflict.conflict_id, conflict)

    def has_conflict(self, subject_id: str) -> bool:
        return any(record.subject_id == subject_id for record in self.conflicts.values())

    def incoming_hyperedges(self, artifact_id: str) -> list[TransformationHyperedge]:
        """Hyperedges that produce artifact_id as an output."""
        return [
            t for t in self.transformations.values()
            if any(p.artifact_id == artifact_id for p in t.outputs)
        ]

    def outgoing_hyperedges(self, artifact_id: str) -> list[TransformationHyperedge]:
        """Hyperedges that consume artifact_id as an input."""
        return [
            t for t in self.transformations.values()
            if any(p.artifact_id == artifact_id for p in t.inputs)
        ]

    def ancestors(self, artifact_ids: Iterable[str]) -> set[str]:
        """Backward reachability closure across transformation hyperedges."""
        visited: set[str] = set(artifact_ids)
        queue = list(artifact_ids)

        while queue:
            curr = queue.pop(0)
            for t in self.incoming_hyperedges(curr):
                for inp in t.inputs:
                    if inp.artifact_id not in visited:
                        visited.add(inp.artifact_id)
                        queue.append(inp.artifact_id)
        return visited

    def descendants(self, artifact_ids: Iterable[str]) -> set[str]:
        """Forward reachability closure across transformation hyperedges."""
        visited: set[str] = set(artifact_ids)
        queue = list(artifact_ids)

        while queue:
            curr = queue.pop(0)
            for t in self.outgoing_hyperedges(curr):
                for out in t.outputs:
                    if out.artifact_id not in visited:
                        visited.add(out.artifact_id)
                        queue.append(out.artifact_id)
        return visited

    def blast_radius(self, revoked_artifact_id: str) -> list[str]:
        """Compute the forward blast radius of affected downstream artifacts when one node is revoked."""
        desc = self.descendants([revoked_artifact_id])
        desc.discard(revoked_artifact_id)
        return sorted(desc)

    def root_sources(self) -> set[str]:
        """Artifacts with zero incoming hyperedges (genesis roots)."""
        roots = set()
        for art_id in self.artifacts:
            if not self.incoming_hyperedges(art_id):
                roots.add(art_id)
        return roots

    def validate_structure(self) -> list[str]:
        """Return deterministic errors for the implemented graph surface.

        This validates the stored representation.  It does not prove that the graph
        captures every real-world input or transformation.
        """
        errors: list[str] = []
        for identifier in sorted(set(self.artifacts) & set(self.transformations)):
            errors.append(
                "artifact and transformation identifiers must be disjoint: "
                f"{identifier}"
            )
        digest_pattern = re.compile(r"^[0-9a-fA-F]{64}$")

        for artifact_id, artifact in sorted(self.artifacts.items()):
            if not artifact_id:
                errors.append("artifact_id must not be empty")
            if artifact.artifact_id != artifact_id:
                errors.append(f"artifact map key does not match artifact_id: {artifact_id}")
            if not digest_pattern.fullmatch(artifact.content_digest):
                errors.append(f"artifact {artifact_id} has an invalid content_digest")
            if artifact.rights_id is not None and artifact.rights_id not in self.rights:
                errors.append(f"artifact {artifact_id} references missing rights {artifact.rights_id}")
            if artifact.contributor_id is not None and artifact.contributor_id not in self.contributors:
                errors.append(
                    f"artifact {artifact_id} references missing contributor {artifact.contributor_id}"
                )

        for transformation_id, transform in sorted(self.transformations.items()):
            if not transformation_id:
                errors.append("transformation_id must not be empty")
            if transform.transformation_id != transformation_id:
                errors.append(
                    f"transformation map key does not match transformation_id: {transformation_id}"
                )
            if not transform.inputs:
                errors.append(f"transformation {transformation_id} has no inputs")
            if not transform.outputs:
                errors.append(f"transformation {transformation_id} has no outputs")
            for port in (*transform.inputs, *transform.outputs):
                if port.artifact_id not in self.artifacts:
                    errors.append(
                        f"transformation {transformation_id} references missing artifact {port.artifact_id}"
                    )
                if not port.role:
                    errors.append(
                        f"transformation {transformation_id} has an empty role for {port.artifact_id}"
                    )
        subjects = set(self.artifacts) | set(self.transformations)
        for conflict_id, conflict in sorted(self.conflicts.items()):
            if not conflict_id or conflict.conflict_id != conflict_id:
                errors.append(f"conflict map key does not match conflict_id: {conflict_id}")
            if conflict.subject_id not in subjects:
                errors.append(
                    f"conflict {conflict_id} references missing subject {conflict.subject_id}"
                )
            if not conflict.predicate:
                errors.append(f"conflict {conflict_id} has an empty predicate")
            if len(set(conflict.competing_values)) < 2:
                errors.append(f"conflict {conflict_id} must retain at least two competing values")
            if len(set(conflict.evidence_refs)) < 2:
                errors.append(f"conflict {conflict_id} must retain at least two evidence references")
        return errors

    def verify_acyclicity(self, artifact_ids: Optional[Iterable[str]] = None) -> bool:
        """Check whether all or a selected artifact-induced subgraph contains cycles.

        Structural reference validation remains the responsibility of
        :meth:`validate_structure`; missing referenced artifacts are retained as
        vertices here so the cycle check itself remains total.
        """
        if artifact_ids is None:
            selected = set(self.artifacts)
            for transform in self.transformations.values():
                selected.update(port.artifact_id for port in (*transform.inputs, *transform.outputs))
        else:
            selected = set(artifact_ids)
        adj: dict[str, set[str]] = {artifact_id: set() for artifact_id in selected}
        for t in self.transformations.values():
            for inp in t.inputs:
                for out in t.outputs:
                    if inp.artifact_id in selected and out.artifact_id in selected:
                        adj[inp.artifact_id].add(out.artifact_id)

        visited: set[str] = set()
        rec_stack: set[str] = set()

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            for nxt in adj.get(node, ()):
                if nxt not in visited:
                    if dfs(nxt):
                        return True
                elif nxt in rec_stack:
                    return True
            rec_stack.remove(node)
            return False

        for a in selected:
            if a not in visited:
                if dfs(a):
                    return False
        return True

    def compute_completeness(self) -> CompletenessMetrics:
        if not self.artifacts:
            return CompletenessMetrics(0.0, 0.0, 0.0, 0.0, 0.0, 0, 0.0)

        roots = self.root_sources()
        total_arts = len(self.artifacts)
        total_trans = len(self.transformations)

        # 1. Source Coverage: Roots with declared origin
        src_covered = sum(
            1 for r_id in roots
            if (art := self.artifacts.get(r_id)) is not None
            and bool(art.storage_uris or art.attributes.get("source_repository"))
        )
        src_cov = src_covered / max(len(roots), 1)

        # 2. Transformation Coverage: Edges with software provenance
        trans_covered = sum(
            1 for t in self.transformations.values()
            if bool(t.software_provenance.get("commit_sha") or t.software_provenance.get("script"))
        )
        trans_cov = trans_covered / max(total_trans, 1)

        # 3. Content-digest declaration coverage.  This is syntax coverage, not a
        # physical-byte rehash; see VSTD-Graph-1 section 3.
        digest_pattern = re.compile(r"^[0-9a-fA-F]{64}$")
        integ_covered = sum(
            1 for art in self.artifacts.values()
            if digest_pattern.fullmatch(art.content_digest)
        )
        integ_cov = integ_covered / total_arts

        # 4. License Coverage: Roots with explicit rights
        lic_covered = sum(
            1 for r_id in roots
            if (art := self.artifacts.get(r_id)) is not None and art.rights_id in self.rights
        )
        lic_cov = lic_covered / max(len(roots), 1)

        # 5. Contributor Coverage: Artifacts with attributed contributor
        contrib_covered = sum(
            1 for art in self.artifacts.values()
            if art.contributor_id in self.contributors
        )
        contrib_cov = contrib_covered / total_arts

        # 6. Lineage Depth: Longest path from roots
        depth = 0
        frontier = set(roots)
        seen = set(roots)
        while frontier:
            nxt = set()
            for f in frontier:
                for t in self.outgoing_hyperedges(f):
                    for out in t.outputs:
                        if out.artifact_id not in seen:
                            nxt.add(out.artifact_id)
                            seen.add(out.artifact_id)
            if not nxt:
                break
            frontier = nxt
            depth += 1

        overall = (src_cov * 0.25) + (trans_cov * 0.25) + (integ_cov * 0.25) + (lic_cov * 0.15) + (contrib_cov * 0.10)

        return CompletenessMetrics(
            source_coverage=src_cov,
            transformation_coverage=trans_cov,
            content_integrity=integ_cov,
            license_coverage=lic_cov,
            contributor_coverage=contrib_cov,
            lineage_depth=depth,
            overall_completeness=overall,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts.values()],
            "transformations": [t.to_dict() for t in self.transformations.values()],
            "contributors": [c.to_dict() for c in self.contributors.values()],
            "rights": [r.to_dict() for r in self.rights.values()],
            "conflicts": [c.to_dict() for c in self.conflicts.values()],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProvenanceHypergraph":
        g = cls()
        for c_data in data.get("contributors", []):
            g.add_contributor(ContributorSpec(**c_data))
        for r_data in data.get("rights", []):
            g.add_rights(
                RightsSpec(
                    rights_id=r_data["rights_id"],
                    license_spdx=r_data["license_spdx"],
                    license_uri=r_data.get("license_uri", ""),
                    commercial_allowed=r_data.get("commercial_allowed", True),
                    attribution_required=r_data.get("attribution_required", True),
                    usage_restrictions=tuple(r_data.get("usage_restrictions", ())),
                    rights_evidence_level=RightsEvidenceLevel(r_data.get("rights_evidence_level", "RIGHTS_DECLARED")),
                )
            )
        for conflict_data in data.get("conflicts", []):
            g.add_conflict(
                ConflictRecord(
                    conflict_id=conflict_data["conflict_id"],
                    subject_id=conflict_data["subject_id"],
                    predicate=conflict_data["predicate"],
                    competing_values=tuple(conflict_data.get("competing_values", ())),
                    evidence_refs=tuple(conflict_data.get("evidence_refs", ())),
                )
            )
        for a_data in data.get("artifacts", []):
            g.add_artifact(
                ArtifactNode(
                    artifact_id=a_data["artifact_id"],
                    label=a_data["label"],
                    artifact_type=ArtifactType(a_data["artifact_type"]),
                    content_digest=a_data["content_digest"],
                    byte_size=a_data.get("byte_size", 0),
                    record_count=a_data.get("record_count"),
                    mime_type=a_data.get("mime_type", "application/octet-stream"),
                    metadata_digest=a_data.get("metadata_digest", ""),
                    provenance_digest=a_data.get("provenance_digest", ""),
                    status=ArtifactStatus(a_data.get("status", "UNKNOWN")),
                    evidence_class=EvidenceClassification(a_data.get("evidence_class", "DECLARED")),
                    rights_id=a_data.get("rights_id"),
                    contributor_id=a_data.get("contributor_id"),
                    storage_uris=tuple(a_data.get("storage_uris", ())),
                    attributes=a_data.get("attributes", {}),
                )
            )
        for t_data in data.get("transformations", []):
            inputs = tuple(
                HyperedgePort(artifact_id=p["artifact_id"], role=p["role"])
                for p in t_data.get("inputs", [])
            )
            outputs = tuple(
                HyperedgePort(artifact_id=p["artifact_id"], role=p["role"])
                for p in t_data.get("outputs", [])
            )
            g.add_transformation(
                TransformationHyperedge(
                    transformation_id=t_data["transformation_id"],
                    label=t_data["label"],
                    transformation_type=TransformationType(t_data["transformation_type"]),
                    inputs=inputs,
                    outputs=outputs,
                    software_provenance=t_data.get("software_provenance", {}),
                    parameters=t_data.get("parameters", {}),
                    execution_environment=t_data.get("execution_environment", {}),
                    evidence_class=EvidenceClassification(t_data.get("evidence_class", "DECLARED")),
                    status=t_data.get("status", "COMPLETED"),
                )
            )
        return g
