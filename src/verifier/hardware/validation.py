"""Terminology: International Organization for Standardization (ISO); Verifier Standard (VSTD).

Fail-closed structural and epistemic validation for VSTD 3 receipts."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
from typing import Iterable, Optional

from .attestation import independently_verify_attestation
from .canonical import canonical_digest
from .claims import ClaimContext, evaluate_claim
from .continuity import ContinuityVerification, KeyResolver, verify_continuity
from .fleet import verify_fleet_observation
from .models import (
    Capability,
    ClaimKind,
    ClaimStatus,
    EventType,
    EvidenceProducer,
    VerificationState,
    VSTD3Receipt,
)
from .provider_evidence import independently_verify_provider_evidence


@dataclass(frozen=True)
class ReceiptValidation:
    valid: bool
    status: ClaimStatus
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    continuity: tuple[ContinuityVerification, ...]


def _duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    duplicate: set[str] = set()
    for value in values:
        if value in seen:
            duplicate.add(value)
        seen.add(value)
    return duplicate


def _parse_time(value: str, *, label: str, errors: list[str]) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{label} is not an ISO-8601 timestamp")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{label} must include a timezone")
        return None
    return parsed


def validate_vstd3_receipt(
    receipt: VSTD3Receipt,
    *,
    key_resolver: Optional[KeyResolver] = None,
) -> ReceiptValidation:
    errors: list[str] = []
    warnings: list[str] = []
    if not receipt.verify_digest_integrity():
        errors.append("canonical digest mismatch")

    id_groups = {
        "descriptor": [item.descriptor_id for item in receipt.descriptors],
        "physical identity": [item.identity_id for item in receipt.physical_identities],
        "logical identity": [item.logical_id for item in receipt.logical_identities],
        "partition": [item.partition_id for item in receipt.partitions],
        "topology snapshot": [item.snapshot_id for item in receipt.topology_snapshots],
        "evidence source": [item.source_id for item in receipt.evidence_sources],
        "attestation challenge": [item.challenge_id for item in receipt.attestation_challenges],
        "attestation evidence": [item.evidence_id for item in receipt.attestation_evidence],
        "execution": [item.execution_id for item in receipt.executions],
        "accounting observation": [item.observation_id for item in receipt.accounting_observations],
        "provider evidence": [item.evidence_id for item in receipt.provider_evidence],
        "fleet manifest": [item.manifest_id for item in receipt.fleet_manifests],
        "fleet observation": [item.observation_id for item in receipt.fleet_observations],
        "gap": [item.gap_id for item in receipt.evidence_gaps],
        "claim": [item.claim_id for item in receipt.claim_evaluations],
    }
    for label, values in id_groups.items():
        for duplicate in sorted(_duplicates(values)):
            errors.append(f"duplicate {label} id {duplicate}")

    descriptor_ids = set(id_groups["descriptor"])
    source_ids = set(id_groups["evidence source"])
    physical_ids = set(id_groups["physical identity"])
    logical_ids = set(id_groups["logical identity"])
    partition_ids = set(id_groups["partition"])
    topology_ids = set(id_groups["topology snapshot"])
    execution_ids = set(id_groups["execution"])
    accounting_ids = set(id_groups["accounting observation"])
    gap_ids = set(id_groups["gap"])
    challenge_by_id = {item.challenge_id: item for item in receipt.attestation_challenges}
    source_by_id = {item.source_id: item for item in receipt.evidence_sources}
    attestation_by_id = {}
    physical_by_id = {item.identity_id: item for item in receipt.physical_identities}
    logical_by_id = {item.logical_id: item for item in receipt.logical_identities}
    partition_by_id = {item.partition_id: item for item in receipt.partitions}

    for physical_identity in receipt.physical_identities:
        if physical_identity.descriptor_id not in descriptor_ids:
            errors.append(f"physical identity {physical_identity.identity_id} references missing descriptor")
        if physical_identity.evidence_source_id not in source_ids:
            errors.append(f"physical identity {physical_identity.identity_id} references missing evidence source")
    for logical_identity in receipt.logical_identities:
        for parent in logical_identity.parent_physical_device_ids:
            if parent not in physical_ids:
                errors.append(f"logical identity {logical_identity.logical_id} references missing parent {parent}")
        if logical_identity.partition_id and logical_identity.partition_id not in partition_ids:
            errors.append(f"logical identity {logical_identity.logical_id} references missing partition")
        if logical_identity.evidence_source_id not in source_ids:
            errors.append(f"logical identity {logical_identity.logical_id} references missing evidence source")
        if logical_identity.partition_id:
            partition = partition_by_id.get(logical_identity.partition_id)
            if partition is not None:
                if logical_identity.logical_id not in partition.logical_device_ids:
                    errors.append(
                        f"logical identity {logical_identity.logical_id} is absent from its partition"
                    )
                if partition.parent_physical_device_id not in logical_identity.parent_physical_device_ids:
                    errors.append(
                        f"logical identity {logical_identity.logical_id} partition has inconsistent physical lineage"
                    )
                if partition.capacity_fraction_ppm != logical_identity.capacity_fraction_ppm:
                    errors.append(
                        f"logical identity {logical_identity.logical_id} disagrees with partition capacity"
                    )
    fraction_by_parent: dict[str, int] = {}
    for partition in receipt.partitions:
        if partition.parent_physical_device_id not in physical_ids:
            errors.append(f"partition {partition.partition_id} references missing physical device")
        missing_logical = set(partition.logical_device_ids) - logical_ids
        if missing_logical:
            errors.append(
                f"partition {partition.partition_id} references missing logical devices: {', '.join(sorted(missing_logical))}"
            )
        fraction_by_parent[partition.parent_physical_device_id] = (
            fraction_by_parent.get(partition.parent_physical_device_id, 0)
            + partition.capacity_fraction_ppm
        )
    for parent, fraction in sorted(fraction_by_parent.items()):
        if fraction > 1_000_000:
            errors.append(f"partitions exceed physical capacity for {parent}")

    for source in receipt.evidence_sources:
        try:
            raw = base64.b64decode(source.raw_evidence_b64, validate=True)
        except ValueError:
            errors.append(f"evidence source {source.source_id} has invalid base64")
            continue
        if hashlib.sha256(raw).hexdigest() != source.raw_evidence_digest:
            errors.append(f"evidence source {source.source_id} raw evidence digest mismatch")
        device_capabilities = {
            Capability.DEVICE_IDENTITY_ATTESTED,
            Capability.FIRMWARE_ATTESTED,
            Capability.EXECUTION_ATTESTED,
            Capability.CONTINUITY_ATTESTED,
            Capability.COMPLETE_MEDIATION_ATTESTED,
        }
        if source.producer in {EvidenceProducer.HOST_RUNTIME, EvidenceProducer.SOFTWARE_COLLECTOR}:
            forbidden = device_capabilities.intersection(source.capabilities)
            if forbidden:
                errors.append(
                    f"host/software evidence source {source.source_id} claims device-only capabilities: "
                    + ", ".join(sorted(item.value for item in forbidden))
                )
        if (
            Capability.COMPLETE_MEDIATION_ATTESTED in source.capabilities
            and source.producer
            not in {EvidenceProducer.DEVICE, EvidenceProducer.FIRMWARE, EvidenceProducer.TEST_EMULATOR}
        ):
            errors.append(f"evidence source {source.source_id} cannot substantiate complete mediation")

    created_at = _parse_time(receipt.created_at, label="receipt.created_at", errors=errors)
    consumed_challenges: set[str] = set()
    for challenge in receipt.attestation_challenges:
        try:
            nonce = base64.b64decode(challenge.nonce_b64, validate=True)
        except ValueError:
            errors.append(f"attestation challenge {challenge.challenge_id} has invalid base64 nonce")
            nonce = b""
        if len(nonce) < 8:
            errors.append(f"attestation challenge {challenge.challenge_id} nonce has less than 64 bits")
        issued = _parse_time(challenge.issued_at, label=f"{challenge.challenge_id}.issued_at", errors=errors)
        expires = _parse_time(challenge.expires_at, label=f"{challenge.challenge_id}.expires_at", errors=errors)
        if issued and expires and expires <= issued:
            errors.append(f"attestation challenge {challenge.challenge_id} expires before it is issued")

    for evidence in receipt.attestation_evidence:
        attestation_source = source_by_id.get(evidence.evidence_source_id)
        if attestation_source is None:
            errors.append(f"attestation evidence {evidence.evidence_id} references missing source")
        evidence_challenge = challenge_by_id.get(evidence.challenge_id)
        if evidence_challenge is None:
            errors.append(f"attestation evidence {evidence.evidence_id} references missing challenge")
        elif evidence.nonce_b64 != evidence_challenge.nonce_b64:
            errors.append(f"attestation evidence {evidence.evidence_id} nonce does not match its challenge")
        elif evidence.challenge_id in consumed_challenges:
            errors.append(f"attestation challenge {evidence.challenge_id} was consumed more than once")
        else:
            consumed_challenges.add(evidence.challenge_id)
        if evidence.subject_identity_id not in physical_ids and evidence.subject_identity_id not in logical_ids:
            errors.append(f"attestation evidence {evidence.evidence_id} references missing subject identity")
        if evidence.device_certificate is not None and evidence.subject_identity_id in physical_by_id:
            physical_identity = physical_by_id[evidence.subject_identity_id]
            if physical_identity.certificate_digest and physical_identity.certificate_digest not in {
                evidence.device_certificate.certificate_chain_digest,
                evidence.device_certificate.leaf_fingerprint,
            }:
                errors.append(
                    f"attestation evidence {evidence.evidence_id} certificate does not bind the declared device identity"
                )
        issued = _parse_time(evidence.issued_at, label=f"{evidence.evidence_id}.issued_at", errors=errors)
        expires = _parse_time(evidence.expires_at, label=f"{evidence.evidence_id}.expires_at", errors=errors)
        if issued and expires and expires <= issued:
            errors.append(f"attestation evidence {evidence.evidence_id} expires before it is issued")
        if expires and created_at and expires < created_at:
            errors.append(f"attestation evidence {evidence.evidence_id} was stale when the receipt was created")
        if evidence_challenge is not None:
            challenge_issued = _parse_time(
                evidence_challenge.issued_at,
                label=f"{evidence_challenge.challenge_id}.issued_at",
                errors=[],
            )
            challenge_expires = _parse_time(
                evidence_challenge.expires_at,
                label=f"{evidence_challenge.challenge_id}.expires_at",
                errors=[],
            )
            if issued and challenge_issued and issued < challenge_issued:
                errors.append(f"attestation evidence {evidence.evidence_id} predates its challenge")
            if expires and challenge_expires and expires > challenge_expires:
                errors.append(f"attestation evidence {evidence.evidence_id} outlives its challenge")
        if evidence.verification_state is VerificationState.VERIFIED and attestation_source is not None:
            undeclared = set(evidence.demonstrated_capabilities) - set(attestation_source.capabilities)
            if undeclared:
                errors.append(
                    f"attestation evidence {evidence.evidence_id} demonstrates undeclared capabilities"
                )
        checked_evidence, verification_detail = independently_verify_attestation(
            evidence, key_resolver=key_resolver
        )
        attestation_by_id[evidence.evidence_id] = checked_evidence
        if checked_evidence.verification_state is VerificationState.FAILED:
            errors.append(f"attestation evidence {evidence.evidence_id}: {verification_detail}")
        elif (
            evidence.verification_state is VerificationState.VERIFIED
            and checked_evidence.verification_state is not VerificationState.VERIFIED
        ):
            warnings.append(
                f"attestation evidence {evidence.evidence_id} could not be verified against configured trust material: {verification_detail}"
            )

    verified_source_ids = {
        evidence.evidence_source_id
        for evidence in attestation_by_id.values()
        if evidence.verification_state is VerificationState.VERIFIED
    }
    claim_source_by_id = {
        source_id: (
            source
            if source_id in verified_source_ids
            or source.verification_state is not VerificationState.VERIFIED
            else replace(source, verification_state=VerificationState.NOT_VERIFIED)
        )
        for source_id, source in source_by_id.items()
    }

    node_ids: set[str] = set()
    topology_logical_ids: dict[str, set[str]] = {}
    for snapshot in receipt.topology_snapshots:
        snapshot_node_ids = {node.node_id for node in snapshot.nodes}
        topology_logical_ids[snapshot.snapshot_id] = {
            node.logical_identity_id for node in snapshot.nodes if node.logical_identity_id
        }
        node_ids.update(snapshot_node_ids)
        if len(snapshot_node_ids) != len(snapshot.nodes):
            errors.append(f"topology snapshot {snapshot.snapshot_id} has duplicate nodes")
        for node in snapshot.nodes:
            if node.profile_id and node.profile_id not in {item.profile_id for item in receipt.descriptors}:
                errors.append(f"topology node {node.node_id} references missing profile")
            if node.physical_identity_id and node.physical_identity_id not in physical_ids:
                errors.append(f"topology node {node.node_id} references missing physical identity")
            if node.logical_identity_id and node.logical_identity_id not in logical_ids:
                errors.append(f"topology node {node.node_id} references missing logical identity")
            if set(node.parent_node_ids) - snapshot_node_ids:
                errors.append(f"topology node {node.node_id} references a missing parent node")
        for link in snapshot.links:
            if link.source_node_id not in snapshot_node_ids or link.target_node_id not in snapshot_node_ids:
                errors.append(f"topology snapshot {snapshot.snapshot_id} has a dangling link")
        if set(snapshot.evidence_source_ids) - source_ids:
            errors.append(f"topology snapshot {snapshot.snapshot_id} references missing evidence sources")
        if snapshot.completeness_claimed and not any(
            Capability.FLEET_BOUNDARY_ATTESTED in source_by_id[source_id].capabilities
            and source_by_id[source_id].verification_state is VerificationState.VERIFIED
            for source_id in snapshot.evidence_source_ids
            if source_id in source_by_id
        ):
            errors.append(f"topology snapshot {snapshot.snapshot_id} overclaims completeness")

    for execution in receipt.executions:
        if set(execution.logical_device_ids) - logical_ids:
            errors.append(f"execution {execution.execution_id} references missing logical devices")
        if execution.topology_snapshot_id not in topology_ids:
            errors.append(f"execution {execution.execution_id} references missing topology snapshot")
        elif set(execution.logical_device_ids) - topology_logical_ids[execution.topology_snapshot_id]:
            errors.append(
                f"execution {execution.execution_id} references logical devices absent from its topology snapshot"
            )
        workload = execution.workload
        if not any(
            (
                workload.executable_digest,
                workload.source_tree_digest,
                workload.container_image_digest,
                workload.model_commitments,
                workload.input_commitments,
                workload.dataset_commitments,
                workload.environment_digest,
                workload.kernel_commitments,
                workload.invocation_commitment,
                workload.orchestrator_job_id,
                workload.cloud_resource_id,
            )
        ):
            warnings.append(
                f"execution {execution.execution_id} has no workload commitment beyond its declared workload id"
            )
    event_by_id = {
        event.event_id: event
        for record in receipt.continuity_records
        for event in record.events
    }
    for duplicate in sorted(_duplicates(item.execution_id for item in receipt.execution_starts)):
        errors.append(f"duplicate execution start for {duplicate}")
    for duplicate in sorted(_duplicates(item.execution_id for item in receipt.execution_ends)):
        errors.append(f"duplicate execution end for {duplicate}")
    execution_by_id = {item.execution_id: item for item in receipt.executions}
    accounting_by_id = {item.observation_id: item for item in receipt.accounting_observations}
    for start in receipt.execution_starts:
        event = event_by_id.get(start.event_id)
        if start.execution_id not in execution_ids:
            errors.append(f"execution start references missing execution {start.execution_id}")
        if event is None or event.event_type is not EventType.EXEC_START or event.execution_id != start.execution_id:
            errors.append(f"execution start {start.event_id} is not bound to its continuity event")
        else:
            bound_execution = execution_by_id.get(start.execution_id)
            if bound_execution is not None and event.event_payload_digest != canonical_digest(bound_execution):
                errors.append(f"execution start {start.event_id} does not bind the workload identity")
            if event.timestamp != start.started_at:
                errors.append(f"execution start {start.event_id} timestamp disagrees with its event")
    for observation in receipt.execution_observations:
        event = event_by_id.get(observation.event_id)
        if observation.execution_id not in execution_ids:
            errors.append(f"execution observation references missing execution {observation.execution_id}")
        if observation.accounting_observation_id not in accounting_ids:
            errors.append("execution observation references missing accounting evidence")
        if (
            event is None
            or event.event_type is not EventType.EXEC_OBSERVATION
            or event.execution_id != observation.execution_id
        ):
            errors.append(f"execution observation {observation.event_id} is not bound to its continuity event")
        else:
            accounting = accounting_by_id.get(observation.accounting_observation_id)
            if accounting is not None and event.event_payload_digest != canonical_digest(accounting):
                errors.append(
                    f"execution observation {observation.event_id} does not bind its accounting payload"
                )
            if event.timestamp != observation.observed_at:
                errors.append(
                    f"execution observation {observation.event_id} timestamp disagrees with its event"
                )
    for end in receipt.execution_ends:
        event = event_by_id.get(end.event_id)
        if end.execution_id not in execution_ids:
            errors.append(f"execution end references missing execution {end.execution_id}")
        if event is None or event.event_type is not EventType.EXEC_END or event.execution_id != end.execution_id:
            errors.append(f"execution end {end.event_id} is not bound to its continuity event")
        else:
            expected_payload = {
                "execution_id": end.execution_id,
                "outcome": end.outcome.value,
                "output_commitments": list(end.output_commitments),
            }
            if event.event_payload_digest != canonical_digest(expected_payload):
                errors.append(f"execution end {end.event_id} does not bind its outcome payload")
            if event.timestamp != end.completed_at:
                errors.append(f"execution end {end.event_id} timestamp disagrees with its event")
    started = {item.execution_id for item in receipt.execution_starts}
    ended = {item.execution_id for item in receipt.execution_ends}
    for execution_id in sorted(execution_ids - started):
        warnings.append(f"execution {execution_id} has no authenticated start event")
    for execution_id in sorted(execution_ids - ended):
        warnings.append(f"execution {execution_id} has no authenticated end event")

    for accounting_observation in receipt.accounting_observations:
        if accounting_observation.execution_id not in execution_ids:
            errors.append(f"accounting observation {accounting_observation.observation_id} references missing execution")
        if set(accounting_observation.evidence_source_ids) - source_ids:
            errors.append(f"accounting observation {accounting_observation.observation_id} references missing sources")
        accounting_execution = execution_by_id.get(accounting_observation.execution_id)
        if accounting_execution is not None:
            allowed_scopes = set(accounting_execution.logical_device_ids)
            for logical_id in accounting_execution.logical_device_ids:
                identity = logical_by_id.get(logical_id)
                if identity is not None:
                    allowed_scopes.update(identity.parent_physical_device_ids)
            if set(accounting_observation.device_scope_ids) - allowed_scopes:
                errors.append(
                    f"accounting observation {accounting_observation.observation_id} has a device scope outside its execution topology"
                )
        for quantity in accounting_observation.quantities:
            if quantity.evidence_source_id not in source_ids:
                errors.append(
                    f"accounting quantity {accounting_observation.observation_id}/{quantity.name} references missing source"
                )
            elif quantity.evidence_source_id not in accounting_observation.evidence_source_ids:
                errors.append(
                    f"accounting quantity {accounting_observation.observation_id}/{quantity.name} source is absent from its observation"
                )

    provider_hardware_refs = source_ids | set(attestation_by_id)
    for provider_evidence in receipt.provider_evidence:
        if provider_evidence.evidence_source_id not in source_ids:
            errors.append(f"provider evidence {provider_evidence.evidence_id} references missing source")
        missing_refs = set(provider_evidence.hardware_evidence_refs) - provider_hardware_refs
        if missing_refs:
            errors.append(
                f"provider evidence {provider_evidence.evidence_id} references missing hardware evidence: "
                + ", ".join(sorted(missing_refs))
            )
        issued = _parse_time(
            provider_evidence.issued_at,
            label=f"{provider_evidence.evidence_id}.issued_at",
            errors=errors,
        )
        expires = _parse_time(
            provider_evidence.expires_at,
            label=f"{provider_evidence.evidence_id}.expires_at",
            errors=errors,
        )
        if issued and expires and expires <= issued:
            errors.append(
                f"provider evidence {provider_evidence.evidence_id} expires before it is issued"
            )
        if expires and created_at and expires < created_at:
            errors.append(
                f"provider evidence {provider_evidence.evidence_id} was stale when the receipt was created"
            )
        checked_provider, verification_detail = independently_verify_provider_evidence(
            provider_evidence, key_resolver=key_resolver
        )
        if checked_provider.verification_state is VerificationState.FAILED:
            errors.append(
                f"provider evidence {provider_evidence.evidence_id}: {verification_detail}"
            )
        elif (
            provider_evidence.verification_state is VerificationState.VERIFIED
            and checked_provider.verification_state is not VerificationState.VERIFIED
        ):
            warnings.append(
                f"provider evidence {provider_evidence.evidence_id} could not be verified against configured trust material: "
                f"{verification_detail}"
            )

    continuity_results = tuple(
        verify_continuity(record, key_resolver=key_resolver) for record in receipt.continuity_records
    )
    for record, result in zip(receipt.continuity_records, continuity_results):
        errors.extend(f"continuity {record.device_identity_id}: {error}" for error in result.errors)
        warnings.extend(
            f"continuity {record.device_identity_id}: {gap.explanation}" for gap in result.gaps
        )

    manifest_by_id = {item.manifest_id: item for item in receipt.fleet_manifests}
    fleet_valid_by_manifest: dict[str, bool] = {}
    profile_ids = {item.profile_id for item in receipt.descriptors}
    anchor_ids = {
        anchor.anchor_id for record in receipt.continuity_records for anchor in record.anchors
    }
    for manifest in receipt.fleet_manifests:
        if set(manifest.evidence_source_ids) - source_ids:
            errors.append(f"fleet manifest {manifest.manifest_id} references missing evidence sources")
        member_ids = {member.member_id for member in manifest.members}
        for member in manifest.members:
            if set(member.physical_device_ids) - physical_ids:
                errors.append(f"fleet member {member.member_id} references missing physical devices")
            if set(member.logical_device_ids) - logical_ids:
                errors.append(f"fleet member {member.member_id} references missing logical devices")
            if member.expected_profile_id not in profile_ids:
                errors.append(f"fleet member {member.member_id} references missing accelerator profile")
            if member.replacement_member_id and member.replacement_member_id not in member_ids:
                errors.append(f"fleet member {member.member_id} references missing replacement member")
        enrollment_ids = set(manifest.boundary.enrollment_completeness_evidence_ids)
        if enrollment_ids - source_ids:
            errors.append(
                f"fleet manifest {manifest.manifest_id} has missing enrollment-completeness evidence"
            )
    for fleet_observation in receipt.fleet_observations:
        observed_manifest = manifest_by_id.get(fleet_observation.manifest_id)
        if observed_manifest is None:
            errors.append(f"fleet observation {fleet_observation.observation_id} references missing manifest")
            continue
        fleet_result = verify_fleet_observation(observed_manifest, fleet_observation)
        if fleet_observation.topology_snapshot_id not in topology_ids:
            errors.append(
                f"fleet observation {fleet_observation.observation_id} references missing topology"
            )
        if set(fleet_observation.evidence_source_ids) - source_ids:
            errors.append(
                f"fleet observation {fleet_observation.observation_id} references missing evidence sources"
            )
        if set(fleet_observation.last_anchor_ids) - anchor_ids:
            errors.append(
                f"fleet observation {fleet_observation.observation_id} references missing continuity anchors"
            )
        interval_start = _parse_time(
            fleet_observation.interval_start,
            label=f"{fleet_observation.observation_id}.interval_start",
            errors=errors,
        )
        interval_end = _parse_time(
            fleet_observation.interval_end,
            label=f"{fleet_observation.observation_id}.interval_end",
            errors=errors,
        )
        if interval_start and interval_end and interval_end <= interval_start:
            errors.append(
                f"fleet observation {fleet_observation.observation_id} has an invalid interval"
            )
        observed_enrollment_ids = observed_manifest.boundary.enrollment_completeness_evidence_ids
        enrollment_verified = bool(observed_enrollment_ids) and all(
            evidence_id in claim_source_by_id
            and claim_source_by_id[evidence_id].verification_state is VerificationState.VERIFIED
            and Capability.FLEET_BOUNDARY_ATTESTED
            in claim_source_by_id[evidence_id].capabilities
            for evidence_id in observed_enrollment_ids
        )
        if fleet_result.valid and not enrollment_verified:
            warnings.append(
                f"fleet manifest {observed_manifest.manifest_id} matched its member set but enrollment completeness is not verified"
            )
        fleet_valid_by_manifest[observed_manifest.manifest_id] = (
            fleet_result.valid and enrollment_verified
        )
        errors.extend(
            f"fleet {observed_manifest.manifest_id}: {error}" for error in fleet_result.errors
        )

    continuity_by_device = {
        record.device_identity_id: result
        for record, result in zip(receipt.continuity_records, continuity_results)
    }
    for claim in receipt.claim_evaluations:
        if set(claim.gap_ids) - gap_ids:
            errors.append(f"claim {claim.claim_id} references missing evidence gaps")
        selected_sources = tuple(
            claim_source_by_id[evidence_id]
            for evidence_id in claim.evidence_ids
            if evidence_id in claim_source_by_id
        )
        selected_attestation = tuple(
            attestation_by_id[evidence_id]
            for evidence_id in claim.evidence_ids
            if evidence_id in attestation_by_id
        )
        context = ClaimContext(
            sources=selected_sources,
            attestation=selected_attestation,
            capability_declarations=receipt.capability_declarations,
            continuity=continuity_by_device.get(claim.subject_id),
            gap_ids=claim.gap_ids,
            fleet_boundary_verified=fleet_valid_by_manifest.get(claim.subject_id, False),
            violation=(
                "Complete mediation cannot pass when an execution lacks an authenticated start or end event."
                if claim.claim_kind is ClaimKind.COMPLETE_MEDIATION
                and (execution_ids - started or execution_ids - ended)
                else ""
            ),
        )
        recomputed = evaluate_claim(
            claim_id=claim.claim_id,
            claim_kind=claim.claim_kind,
            subject_id=claim.subject_id,
            context=context,
        )
        if claim.status is ClaimStatus.PASS and recomputed.status is not ClaimStatus.PASS:
            errors.append(
                f"claim {claim.claim_id} overclaims {claim.claim_kind.value}: "
                f"recomputed status is {recomputed.status.value}"
            )
        if claim.claim_kind is ClaimKind.PHYSICAL_WORLD_COMPLETENESS and claim.status is not ClaimStatus.UNSUPPORTED:
            errors.append("physical-world completeness must remain UNSUPPORTED")

    epistemic_key_warning = any(
        "could not be verified against configured trust material" in warning
        and ("key unavailable" in warning or "unsupported signature verifier" in warning)
        for warning in warnings
    )
    only_claim_overclaim_errors = bool(errors) and all(
        error.startswith("claim ") and " overclaims " in error for error in errors
    )
    if errors:
        status = (
            ClaimStatus.UNKNOWN
            if epistemic_key_warning and only_claim_overclaim_errors
            else ClaimStatus.FAIL
        )
    elif warnings or any(result.status is ClaimStatus.UNKNOWN for result in continuity_results):
        status = ClaimStatus.UNKNOWN
    else:
        status = ClaimStatus.PASS
    return ReceiptValidation(
        valid=not errors,
        status=status,
        errors=tuple(errors),
        warnings=tuple(warnings),
        continuity=continuity_results,
    )
