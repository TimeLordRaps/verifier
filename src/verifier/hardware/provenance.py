"""Composition of VSTD 3 hardware evidence into the existing provenance hypergraph."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from typing import Iterable, Optional

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

from .canonical import canonical_digest
from .continuity import KeyResolver
from .models import (
    ClaimKind,
    ClaimStatus,
    EvidenceProducer,
    FirmwareMeasurement,
    RuntimeMeasurement,
    VerificationState,
    VSTD3Receipt,
)
from .provider_evidence import independently_verify_provider_evidence
from .validation import ReceiptValidation, validate_vstd3_receipt


class HardwareProvenanceError(ValueError):
    pass


@dataclass(frozen=True)
class HardwareProvenanceBinding:
    receipt_artifact_id: str
    added_artifact_ids: tuple[str, ...]
    added_transformation_ids: tuple[str, ...]
    validation: ReceiptValidation


def _classification(producer: EvidenceProducer) -> EvidenceClassification:
    if producer in {EvidenceProducer.HOST_RUNTIME, EvidenceProducer.SOFTWARE_COLLECTOR}:
        return EvidenceClassification.DIRECTLY_OBSERVED
    return EvidenceClassification.DECLARED


def attach_vstd3_receipt(
    graph: ProvenanceHypergraph,
    receipt: VSTD3Receipt,
    *,
    key_resolver: Optional[KeyResolver] = None,
    output_artifact_ids: Iterable[str] | None = None,
) -> HardwareProvenanceBinding:
    """Attach a validated receipt so evidence invalidation reaches derived artifacts.

    The function refuses receipts whose passing claims cannot be independently
    reproduced under the supplied key resolver. ``output_artifact_ids`` defaults to
    the receipt's declared provenance links and every target must already exist.
    """

    validation = validate_vstd3_receipt(receipt, key_resolver=key_resolver)
    if not validation.valid:
        raise HardwareProvenanceError(
            "VSTD 3 receipt failed validation: " + "; ".join(validation.errors)
        )
    targets = tuple(
        dict.fromkeys(
            output_artifact_ids
            if output_artifact_ids is not None
            else receipt.provenance_artifact_ids
        )
    )
    missing_targets = sorted(set(targets) - set(graph.artifacts))
    if missing_targets:
        raise HardwareProvenanceError(
            "hardware receipt references missing provenance artifacts: "
            + ", ".join(missing_targets)
        )

    target_graph = copy.deepcopy(graph)
    added_artifacts: list[str] = []
    added_transformations: list[str] = []

    def claim_passes(kind: ClaimKind, *, evidence_id: str | None = None) -> bool:
        return any(
            claim.claim_kind is kind
            and claim.status is ClaimStatus.PASS
            and (evidence_id is None or evidence_id in claim.evidence_ids)
            for claim in receipt.claim_evaluations
        )

    def add_artifact(artifact: ArtifactNode) -> None:
        existing = target_graph.artifacts.get(artifact.artifact_id)
        if existing is not None and existing != artifact:
            raise HardwareProvenanceError(
                f"provenance artifact id collision: {artifact.artifact_id}"
            )
        if existing is None:
            target_graph.add_artifact(artifact)
            added_artifacts.append(artifact.artifact_id)

    def add_transform(transform: TransformationHyperedge) -> None:
        existing = target_graph.transformations.get(transform.transformation_id)
        if existing is not None and existing.to_dict() != transform.to_dict():
            raise HardwareProvenanceError(
                f"provenance transformation id collision: {transform.transformation_id}"
            )
        if existing is None:
            target_graph.add_transformation(transform)
            added_transformations.append(transform.transformation_id)

    common_software = {
        "standard": "VSTD-3.0",
        "implementation": "vstd",
    }
    source_artifact_ids: list[str] = []
    for source in receipt.evidence_sources:
        source_artifact_id = f"hardware-source:{source.source_id}"
        raw = base64.b64decode(source.raw_evidence_b64, validate=True)
        add_artifact(
            ArtifactNode(
                artifact_id=source_artifact_id,
                label=f"Hardware evidence source {source.source_id}",
                artifact_type=ArtifactType.HARDWARE_EVIDENCE,
                content_digest=source.raw_evidence_digest,
                byte_size=len(raw),
                mime_type=source.media_type,
                status=ArtifactStatus.VALID,
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if any(
                        claim.status is ClaimStatus.PASS and source.source_id in claim.evidence_ids
                        for claim in receipt.claim_evaluations
                    )
                    else _classification(source.producer)
                ),
                attributes={
                    "producer": source.producer.value,
                    "mechanism": source.mechanism,
                    "verification_state": source.verification_state.value,
                    "capabilities": [item.value for item in source.capabilities],
                    "limitations": list(source.limitations),
                },
            )
        )
        source_artifact_ids.append(source_artifact_id)

    identity_artifact_ids: list[str] = []
    for identity in receipt.physical_identities:
        artifact_id = f"hardware-identity:{identity.identity_id}"
        add_artifact(
            ArtifactNode(
                artifact_id,
                f"Physical accelerator identity {identity.identity_id}",
                ArtifactType.DEVICE_IDENTITY,
                canonical_digest(identity),
                mime_type="application/vnd.vstd3.device-identity+json",
                status=ArtifactStatus.VALID,
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.DEVICE_IDENTITY, evidence_id=identity.evidence_source_id)
                    else EvidenceClassification.DECLARED
                ),
                attributes={"descriptor_id": identity.descriptor_id},
            )
        )
        source_input = f"hardware-source:{identity.evidence_source_id}"
        add_transform(
            TransformationHyperedge(
                f"hardware-discovery:{receipt.receipt_id}:{identity.identity_id}",
                f"Discover {identity.identity_id}",
                TransformationType.HARDWARE_DISCOVERY,
                inputs=(HyperedgePort(source_input, "RAW_HARDWARE_EVIDENCE"),),
                outputs=(HyperedgePort(artifact_id, "PHYSICAL_DEVICE_IDENTITY"),),
                software_provenance=common_software,
                parameters={},
                execution_environment={"observed_at": receipt.created_at},
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.DEVICE_IDENTITY, evidence_id=identity.evidence_source_id)
                    else EvidenceClassification.DECLARED
                ),
            )
        )
        identity_artifact_ids.append(artifact_id)

    measurement_artifact_ids: list[str] = []
    for attestation in receipt.attestation_evidence:
        source_input = f"hardware-source:{attestation.evidence_source_id}"
        measurement_sets: tuple[
            tuple[
                str,
                Iterable[FirmwareMeasurement | RuntimeMeasurement],
                ArtifactType,
            ],
            ...,
        ] = (
            ("firmware", attestation.firmware_measurements, ArtifactType.FIRMWARE_MEASUREMENT),
            ("runtime", attestation.runtime_measurements, ArtifactType.RUNTIME_MEASUREMENT),
        )
        for kind, measurements, artifact_type in measurement_sets:
            for index, measurement in enumerate(measurements):
                artifact_id = (
                    f"hardware-{kind}:{attestation.evidence_id}:{index}:{measurement.component}"
                )
                add_artifact(
                    ArtifactNode(
                        artifact_id,
                        f"{kind.title()} measurement {measurement.component}",
                        artifact_type,
                        canonical_digest(measurement),
                        mime_type=f"application/vnd.vstd3.{kind}-measurement+json",
                        status=ArtifactStatus.VALID,
                        evidence_class=(
                            EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                            if claim_passes(
                                ClaimKind.FIRMWARE_INTEGRITY
                                if kind == "firmware"
                                else ClaimKind.EXECUTION_ATTESTATION,
                                evidence_id=attestation.evidence_id,
                            )
                            else EvidenceClassification.DECLARED
                        ),
                        attributes={
                            "attestation_evidence_id": attestation.evidence_id,
                            "comparison": measurement.comparison.value,
                        },
                    )
                )
                add_transform(
                    TransformationHyperedge(
                        f"hardware-attestation:{receipt.receipt_id}:{kind}:{attestation.evidence_id}:{index}",
                        f"Bind {kind} measurement {measurement.component}",
                        TransformationType.HARDWARE_ATTESTATION,
                        inputs=(HyperedgePort(source_input, "SIGNED_ATTESTATION_EVIDENCE"),),
                        outputs=(HyperedgePort(artifact_id, "MEASUREMENT"),),
                        software_provenance=common_software,
                        parameters={"challenge_id": attestation.challenge_id},
                        execution_environment={"subject_identity_id": attestation.subject_identity_id},
                        evidence_class=(
                            EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                            if claim_passes(
                                ClaimKind.FIRMWARE_INTEGRITY
                                if kind == "firmware"
                                else ClaimKind.EXECUTION_ATTESTATION,
                                evidence_id=attestation.evidence_id,
                            )
                            else EvidenceClassification.DECLARED
                        ),
                    )
                )
                measurement_artifact_ids.append(artifact_id)

    topology_artifact_ids: dict[str, str] = {}
    for snapshot in receipt.topology_snapshots:
        artifact_id = f"hardware-topology:{snapshot.snapshot_id}"
        add_artifact(
            ArtifactNode(
                artifact_id,
                f"Accelerator topology {snapshot.snapshot_id}",
                ArtifactType.TOPOLOGY_SNAPSHOT,
                canonical_digest(snapshot),
                mime_type="application/vnd.vstd3.topology+json",
                status=ArtifactStatus.VALID,
                evidence_class=EvidenceClassification.DIRECTLY_OBSERVED,
                attributes={"boundary_id": snapshot.boundary_id},
            )
        )
        inputs = tuple(
            HyperedgePort(f"hardware-source:{source_id}", "TOPOLOGY_EVIDENCE")
            for source_id in snapshot.evidence_source_ids
        )
        add_transform(
            TransformationHyperedge(
                f"hardware-topology-binding:{receipt.receipt_id}:{snapshot.snapshot_id}",
                f"Bind topology {snapshot.snapshot_id}",
                TransformationType.HARDWARE_DISCOVERY,
                inputs=inputs,
                outputs=(HyperedgePort(artifact_id, "TOPOLOGY_SNAPSHOT"),),
                software_provenance=common_software,
                parameters={"completeness_claimed": snapshot.completeness_claimed},
                execution_environment={"observed_at": snapshot.observed_at},
                evidence_class=EvidenceClassification.DIRECTLY_OBSERVED,
            )
        )
        topology_artifact_ids[snapshot.snapshot_id] = artifact_id

    execution_artifact_ids: dict[str, str] = {}
    for execution in receipt.executions:
        artifact_id = f"hardware-execution:{execution.execution_id}"
        add_artifact(
            ArtifactNode(
                artifact_id,
                f"Accelerator execution {execution.execution_id}",
                ArtifactType.EXECUTION_EVIDENCE,
                canonical_digest(execution),
                mime_type="application/vnd.vstd3.execution+json",
                status=ArtifactStatus.VALID,
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.EXECUTION_ATTESTATION)
                    else EvidenceClassification.DIRECTLY_OBSERVED
                ),
                attributes={"workload_id": execution.workload.workload_id},
            )
        )
        execution_inputs = [
            HyperedgePort(topology_artifact_ids[execution.topology_snapshot_id], "BOUND_TOPOLOGY")
        ]
        execution_inputs.extend(
            HyperedgePort(source_id, "EXECUTION_EVIDENCE") for source_id in source_artifact_ids
        )
        add_transform(
            TransformationHyperedge(
                f"hardware-execution-binding:{receipt.receipt_id}:{execution.execution_id}",
                f"Bind execution {execution.execution_id}",
                TransformationType.WORKLOAD_EXECUTION,
                inputs=tuple(execution_inputs),
                outputs=(HyperedgePort(artifact_id, "EXECUTION"),),
                software_provenance=common_software,
                parameters={"workload": execution.workload.to_dict()},
                execution_environment={
                    "logical_device_ids": list(execution.logical_device_ids),
                    "submitted_at": execution.submitted_at,
                },
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.EXECUTION_ATTESTATION)
                    else EvidenceClassification.DIRECTLY_OBSERVED
                ),
            )
        )
        execution_artifact_ids[execution.execution_id] = artifact_id

    accounting_artifact_ids: list[str] = []
    for observation in receipt.accounting_observations:
        artifact_id = f"hardware-accounting:{observation.observation_id}"
        add_artifact(
            ArtifactNode(
                artifact_id,
                f"Compute accounting {observation.observation_id}",
                ArtifactType.ACCOUNTING_EVIDENCE,
                canonical_digest(observation),
                mime_type="application/vnd.vstd3.accounting+json",
                status=ArtifactStatus.VALID,
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.EXECUTION_ACCOUNTING)
                    else EvidenceClassification.DECLARED
                ),
                attributes={
                    "execution_id": observation.execution_id,
                    "quantities": [item.to_dict() for item in observation.quantities],
                },
            )
        )
        accounting_inputs = [
            HyperedgePort(execution_artifact_ids[observation.execution_id], "EXECUTION")
        ]
        accounting_inputs.extend(
            HyperedgePort(f"hardware-source:{source_id}", "COUNTER_EVIDENCE")
            for source_id in observation.evidence_source_ids
        )
        add_transform(
            TransformationHyperedge(
                f"hardware-accounting-binding:{receipt.receipt_id}:{observation.observation_id}",
                f"Bind accounting {observation.observation_id}",
                TransformationType.COMPUTE_ACCOUNTING,
                inputs=tuple(accounting_inputs),
                outputs=(HyperedgePort(artifact_id, "ACCOUNTING"),),
                software_provenance=common_software,
                parameters={},
                execution_environment={"observed_at": observation.observed_at},
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.EXECUTION_ACCOUNTING)
                    else EvidenceClassification.DECLARED
                ),
            )
        )
        accounting_artifact_ids.append(artifact_id)

    continuity_artifact_ids: list[str] = []
    for record in receipt.continuity_records:
        artifact_id = f"hardware-continuity:{receipt.receipt_id}:{record.device_identity_id}"
        add_artifact(
            ArtifactNode(
                artifact_id,
                f"Accounting continuity {record.device_identity_id}",
                ArtifactType.CONTINUITY_EVIDENCE,
                canonical_digest(record),
                mime_type="application/vnd.vstd3.continuity+json",
                status=ArtifactStatus.VALID,
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.ACCOUNTING_CONTINUITY)
                    else EvidenceClassification.DECLARED
                ),
                attributes={"event_count": len(record.events), "anchor_count": len(record.anchors)},
            )
        )
        add_transform(
            TransformationHyperedge(
                f"hardware-continuity-binding:{receipt.receipt_id}:{record.device_identity_id}",
                f"Bind continuity {record.device_identity_id}",
                TransformationType.CONTINUITY_ANCHORING,
                inputs=tuple(
                    HyperedgePort(source_id, "DEVICE_EVENT_SOURCE")
                    for source_id in source_artifact_ids
                ),
                outputs=(HyperedgePort(artifact_id, "CONTINUITY_RECORD"),),
                software_provenance=common_software,
                parameters={},
                execution_environment={},
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if claim_passes(ClaimKind.ACCOUNTING_CONTINUITY)
                    else EvidenceClassification.DECLARED
                ),
            )
        )
        continuity_artifact_ids.append(artifact_id)

    provider_artifact_ids: list[str] = []
    for provider_evidence in receipt.provider_evidence:
        checked_provider, _ = independently_verify_provider_evidence(
            provider_evidence, key_resolver=key_resolver
        )
        provider_class = (
            EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
            if checked_provider.verification_state is VerificationState.VERIFIED
            else EvidenceClassification.DECLARED
        )
        artifact_id = f"provider-evidence:{provider_evidence.evidence_id}"
        add_artifact(
            ArtifactNode(
                artifact_id,
                f"Provider evidence {provider_evidence.evidence_id}",
                ArtifactType.PROVIDER_EVIDENCE,
                canonical_digest(provider_evidence),
                mime_type="application/vnd.vstd3.provider-evidence+json",
                status=ArtifactStatus.VALID,
                evidence_class=provider_class,
                attributes={
                    "provider": provider_evidence.provider,
                    "resource_id": provider_evidence.resource_id,
                    "verification_state": checked_provider.verification_state.value,
                    "hardware_evidence_refs": list(provider_evidence.hardware_evidence_refs),
                },
            )
        )
        provider_inputs = [
            HyperedgePort(
                f"hardware-source:{provider_evidence.evidence_source_id}",
                "PROVIDER_CONTROL_PLANE_SOURCE",
            )
        ]
        for evidence_ref in provider_evidence.hardware_evidence_refs:
            if evidence_ref in {item.source_id for item in receipt.evidence_sources}:
                provider_inputs.append(
                    HyperedgePort(f"hardware-source:{evidence_ref}", "REFERENCED_HARDWARE_EVIDENCE")
                )
        add_transform(
            TransformationHyperedge(
                f"provider-evidence-binding:{receipt.receipt_id}:{provider_evidence.evidence_id}",
                f"Bind provider evidence {provider_evidence.evidence_id}",
                TransformationType.EVIDENCE_BINDING,
                inputs=tuple(provider_inputs),
                outputs=(HyperedgePort(artifact_id, "PROVIDER_EVIDENCE"),),
                software_provenance=common_software,
                parameters={},
                execution_environment={},
                evidence_class=provider_class,
            )
        )
        provider_artifact_ids.append(artifact_id)

    receipt_artifact_id = f"hardware-receipt:{receipt.receipt_id}"
    add_artifact(
        ArtifactNode(
            receipt_artifact_id,
            f"VSTD 3 receipt {receipt.receipt_id}",
            ArtifactType.HARDWARE_RECEIPT,
            receipt.canonical_digest,
            mime_type="application/vnd.vstd3.receipt+json",
            status=ArtifactStatus.VALID,
            evidence_class=(
                EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                if any(claim.status is ClaimStatus.PASS for claim in receipt.claim_evaluations)
                else EvidenceClassification.DECLARED
            ),
            attributes={
                "schema_version": receipt.schema_version,
                "claim_statuses": {
                    claim.claim_kind.value: claim.status.value for claim in receipt.claim_evaluations
                },
            },
        )
    )
    receipt_inputs = tuple(
        HyperedgePort(artifact_id, "RECEIPT_EVIDENCE")
        for artifact_id in (
            *identity_artifact_ids,
            *measurement_artifact_ids,
            *execution_artifact_ids.values(),
            *accounting_artifact_ids,
            *continuity_artifact_ids,
            *provider_artifact_ids,
        )
    )
    if not receipt_inputs:
        raise HardwareProvenanceError("cannot attach a hardware receipt with no derived evidence")
    add_transform(
        TransformationHyperedge(
            f"hardware-receipt-binding:{receipt.receipt_id}",
            f"Assemble VSTD 3 receipt {receipt.receipt_id}",
            TransformationType.EVIDENCE_BINDING,
            inputs=receipt_inputs,
            outputs=(HyperedgePort(receipt_artifact_id, "VSTD3_RECEIPT"),),
            software_provenance=common_software,
            parameters={},
            execution_environment={"created_at": receipt.created_at},
            evidence_class=(
                EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                if any(claim.status is ClaimStatus.PASS for claim in receipt.claim_evaluations)
                else EvidenceClassification.DECLARED
            ),
        )
    )
    if targets:
        add_transform(
            TransformationHyperedge(
                f"hardware-output-binding:{receipt.receipt_id}",
                f"Bind VSTD 3 receipt {receipt.receipt_id} to produced artifacts",
                TransformationType.EVIDENCE_BINDING,
                inputs=(HyperedgePort(receipt_artifact_id, "HARDWARE_RECEIPT"),),
                outputs=tuple(HyperedgePort(target, "EXECUTION_OUTPUT") for target in targets),
                software_provenance=common_software,
                parameters={},
                execution_environment={},
                evidence_class=(
                    EvidenceClassification.CRYPTOGRAPHICALLY_BOUND
                    if any(claim.status is ClaimStatus.PASS for claim in receipt.claim_evaluations)
                    else EvidenceClassification.DECLARED
                ),
            )
        )
    structure_errors = target_graph.validate_structure()
    if structure_errors:
        raise HardwareProvenanceError(
            "hardware provenance composition is structurally invalid: "
            + "; ".join(structure_errors)
        )
    if not target_graph.verify_acyclicity():
        raise HardwareProvenanceError("hardware provenance composition introduced a cycle")
    graph.artifacts = target_graph.artifacts
    graph.transformations = target_graph.transformations
    return HardwareProvenanceBinding(
        receipt_artifact_id=receipt_artifact_id,
        added_artifact_ids=tuple(added_artifacts),
        added_transformation_ids=tuple(added_transformations),
        validation=validation,
    )
