"""Terminology: artificial intelligence (AI); application-specific integrated circuit (ASIC);
hash-based message authentication code (HMAC); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).

Executable reference model for the VSTD 3 firmware-accountability contract."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
import hashlib
from typing import Iterable

from .adapters.base import evidence_source_from_bytes
from .anchors import AnchorProvider, LocalAnchorProvider
from .attestation import attestation_signed_digest
from .canonical import canonical_digest, canonical_json_bytes
from .claims import ClaimContext, evaluate_claim
from .continuity import build_accounting_event, genesis_root, hmac_sign_digest, verify_continuity
from .models import (
    AcceleratorDescriptor,
    AcceleratorPartition,
    AccountingEvent,
    AccountingQuantity,
    AttestationChallenge,
    AttestationEvidence,
    Capability,
    CapabilityDeclaration,
    CapabilitySupport,
    ClaimEvaluation,
    ClaimKind,
    ComponentKind,
    ComputeAccountingObservation,
    ContinuityAnchor,
    ContinuityRecord,
    DeviceCertificateEvidence,
    DeviceClass,
    EvidenceProducer,
    EventType,
    ExecutionEnd,
    ExecutionIdentity,
    ExecutionObservation,
    ExecutionOutcome,
    ExecutionStart,
    FirmwareMeasurement,
    LogicalDeviceIdentity,
    PhysicalDeviceIdentity,
    ResetEpoch,
    RuntimeMeasurement,
    TopologyLink,
    TopologyNode,
    TopologySnapshot,
    VerificationState,
    VSTD3Receipt,
)


class FirmwareContractError(RuntimeError):
    pass


EMULATOR_CAPABILITIES = (
    Capability.DEVICE_IDENTITY_ATTESTED,
    Capability.FIRMWARE_ATTESTED,
    Capability.EXECUTION_OBSERVED,
    Capability.EXECUTION_ATTESTED,
    Capability.EXECUTION_ACCOUNTING_EVIDENCED,
    Capability.CONTINUITY_ATTESTED,
    Capability.COMPLETE_MEDIATION_ATTESTED,
)


@dataclass
class VirtualVSTDAccelerator:
    """A deterministic governed accelerator boundary.

    This emulator accepts work only through methods that commit accounting events. Its
    test HMAC key models a protected firmware key, but it is not a claim about physical
    tamper resistance or any commodity accelerator.
    """

    device_id: str
    firmware_version: str
    signing_key: bytes
    key_id: str = "vstd3-virtual-device-key"
    profile_id: str = "vstd.virtual-firmware-1"
    _events: list[AccountingEvent] = field(default_factory=list, init=False)
    _resets: list[ResetEpoch] = field(default_factory=list, init=False)
    _anchors: list[ContinuityAnchor] = field(default_factory=list, init=False)
    _challenges: list[AttestationChallenge] = field(default_factory=list, init=False)
    _attestations: list[AttestationEvidence] = field(default_factory=list, init=False)
    _executions: list[ExecutionIdentity] = field(default_factory=list, init=False)
    _starts: list[ExecutionStart] = field(default_factory=list, init=False)
    _observations: list[ExecutionObservation] = field(default_factory=list, init=False)
    _ends: list[ExecutionEnd] = field(default_factory=list, init=False)
    _accounting: list[ComputeAccountingObservation] = field(default_factory=list, init=False)
    _active: set[str] = field(default_factory=set, init=False)
    _epoch: int = field(default=-1, init=False)
    _partitions: list[AcceleratorPartition] = field(default_factory=list, init=False)
    _logical: list[LogicalDeviceIdentity] = field(default_factory=list, init=False)
    _verification_keys: dict[str, bytes] = field(default_factory=dict, init=False)
    _topology_history: list[TopologySnapshot] = field(default_factory=list, init=False)
    _topology_revision: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if not self.signing_key:
            raise FirmwareContractError("virtual accelerator signing key must not be empty")
        self._verification_keys[self.key_id] = self.signing_key

    @property
    def physical_identity_id(self) -> str:
        return f"physical:{self.device_id}"

    @property
    def evidence_source_id(self) -> str:
        return f"evidence:virtual:{self.device_id}"

    @property
    def current_topology_snapshot_id(self) -> str:
        if self._epoch < 0:
            raise FirmwareContractError("device must boot before topology can identify an epoch")
        return f"topology:{self.device_id}:{self._epoch}:{self._topology_revision}"

    @property
    def descriptor(self) -> AcceleratorDescriptor:
        return AcceleratorDescriptor(
            descriptor_id=f"descriptor:{self.device_id}",
            profile_id=self.profile_id,
            vendor="EMULATED",
            family="VirtualVSTDAccelerator",
            architecture="reference-emulator",
            model="VirtualVSTDAccelerator",
            device_class=DeviceClass.AI_ASIC,
            deployment_class="emulator",
            discovery_method="constructed reference device",
            attributes={"root_of_trust": "TEST_HMAC_FIXTURE"},
        )

    @property
    def physical_identity(self) -> PhysicalDeviceIdentity:
        certificate_digest = hashlib.sha256(b"vstd3-test-certificate:" + self.signing_key).hexdigest()
        return PhysicalDeviceIdentity(
            identity_id=self.physical_identity_id,
            descriptor_id=self.descriptor.descriptor_id,
            serial_commitment=hashlib.sha256(self.device_id.encode()).hexdigest(),
            certificate_digest=certificate_digest,
            hardware_revision="virtual-1",
            evidence_source_id=self.evidence_source_id,
        )

    def configure_partitions(
        self,
        partitions: Iterable[tuple[str, str, int]],
        *,
        timestamp: str | None = None,
    ) -> None:
        if self._active:
            raise FirmwareContractError("partition configuration cannot change during active execution")
        configured = tuple(partitions)
        if not configured:
            configured = ((f"partition:{self.device_id}:whole", "whole-device", 1_000_000),)
        if sum(item[2] for item in configured) > 1_000_000:
            raise FirmwareContractError("partition capacity exceeds the physical device")
        self._partitions.clear()
        self._logical.clear()
        for partition_id, mode, fraction in configured:
            logical_id = f"logical:{partition_id}"
            self._logical.append(
                LogicalDeviceIdentity(
                    logical_id=logical_id,
                    parent_physical_device_ids=(self.physical_identity_id,),
                    partition_id=partition_id,
                    virtualization_mode=mode,
                    capacity_fraction_ppm=fraction,
                    evidence_source_id=self.evidence_source_id,
                )
            )
            self._partitions.append(
                AcceleratorPartition(
                    partition_id=partition_id,
                    parent_physical_device_id=self.physical_identity_id,
                    logical_device_ids=(logical_id,),
                    partition_mode=mode,
                    capacity_fraction_ppm=fraction,
                    configuration_digest=canonical_digest(
                        {"partition_id": partition_id, "mode": mode, "capacity_fraction_ppm": fraction}
                    ),
                )
            )
        if timestamp is not None and self._epoch >= 0:
            self._topology_revision += 1
            self._append_event(
                EventType.PARTITION_CHANGE,
                execution_id="",
                partition_id="",
                timestamp=timestamp,
                payload={"partitions": [partition.to_dict() for partition in self._partitions]},
            )
            self._remember_topology(timestamp)

    def boot(self, *, boot_id: str, timestamp: str) -> AccountingEvent:
        if self._epoch >= 0:
            raise FirmwareContractError("device is already booted; use reset()")
        if not self._partitions:
            self.configure_partitions(())
        self._epoch = 0
        self._topology_revision = 0
        reset = ResetEpoch(
            device_identity_id=self.physical_identity_id,
            epoch=0,
            boot_id=boot_id,
            reason="initial boot",
            prior_epoch=None,
            prior_rolling_root="",
            external_anchor_id="",
        )
        self._resets.append(reset)
        event = self._append_event(
            EventType.DEVICE_BOOT,
            execution_id="",
            partition_id="",
            timestamp=timestamp,
            payload={
                "boot_id": boot_id,
                "firmware_measurement": self.firmware_measurement().to_dict(),
                "capabilities": [item.value for item in EMULATOR_CAPABILITIES],
            },
        )
        self._remember_topology(timestamp)
        return event

    def firmware_measurement(self) -> FirmwareMeasurement:
        digest = hashlib.sha256(
            f"VSTD3-VIRTUAL-FIRMWARE:{self.firmware_version}".encode()
        ).hexdigest()
        return FirmwareMeasurement(
            component="virtual-vstd-firmware",
            digest=digest,
            algorithm="SHA-256",
            version=self.firmware_version,
            reference_value_digest=digest,
            comparison=VerificationState.VERIFIED,
        )

    def issue_challenge(
        self,
        *,
        challenge_id: str,
        nonce: bytes,
        issued_at: str,
        expires_at: str,
        verifier_id: str,
    ) -> AttestationChallenge:
        if len(nonce) < 8:
            raise FirmwareContractError("attestation nonce must contain at least 64 bits")
        challenge = AttestationChallenge(
            challenge_id=challenge_id,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            issued_at=issued_at,
            expires_at=expires_at,
            verifier_id=verifier_id,
        )
        if any(item.challenge_id == challenge_id for item in self._challenges):
            raise FirmwareContractError("attestation challenge replay")
        self._challenges.append(challenge)
        return challenge

    def attest(self, challenge: AttestationChallenge) -> AttestationEvidence:
        if challenge not in self._challenges:
            raise FirmwareContractError("challenge was not issued to this device")
        if any(item.challenge_id == challenge.challenge_id for item in self._attestations):
            raise FirmwareContractError("attestation challenge has already been consumed")
        evidence_id = f"attestation:{self.device_id}:{challenge.challenge_id}"
        certificate_digest = hashlib.sha256(b"vstd3-test-certificate:" + self.signing_key).hexdigest()
        evidence = AttestationEvidence(
            evidence_id=evidence_id,
            subject_identity_id=self.physical_identity_id,
            challenge_id=challenge.challenge_id,
            nonce_b64=challenge.nonce_b64,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
            evidence_source_id=self.evidence_source_id,
            firmware_measurements=(self.firmware_measurement(),),
            runtime_measurements=(
                RuntimeMeasurement(
                    component="virtual-runtime",
                    digest=hashlib.sha256(b"vstd3-virtual-runtime-1").hexdigest(),
                    algorithm="SHA-256",
                    version="1",
                    comparison=VerificationState.VERIFIED,
                ),
            ),
            device_certificate=DeviceCertificateEvidence(
                certificate_chain_digest=certificate_digest,
                leaf_fingerprint=certificate_digest,
                trust_anchor_id="vstd3-test-root",
                verification_state=VerificationState.VERIFIED,
                checked_at=challenge.issued_at,
            ),
            signature=None,
            verification_state=VerificationState.VERIFIED,
            demonstrated_capabilities=EMULATOR_CAPABILITIES,
        )
        evidence = replace(
            evidence,
            signature=hmac_sign_digest(
                attestation_signed_digest(evidence), key_id=self.key_id, key=self.signing_key
            ),
        )
        self._attestations.append(evidence)
        return evidence

    def submit_execution(self, execution: ExecutionIdentity, *, timestamp: str) -> ExecutionStart:
        if self._epoch < 0:
            raise FirmwareContractError("device must boot before execution")
        known_logical = {item.logical_id for item in self._logical}
        if not execution.logical_device_ids or set(execution.logical_device_ids) - known_logical:
            raise FirmwareContractError("execution references a logical device outside this boundary")
        if execution.topology_snapshot_id != self.current_topology_snapshot_id:
            raise FirmwareContractError("execution is not bound to the current topology snapshot")
        if execution.execution_id in {item.execution_id for item in self._executions}:
            raise FirmwareContractError("execution id replay")
        event = self._append_event(
            EventType.EXEC_START,
            execution_id=execution.execution_id,
            partition_id=self._logical_partition(execution.logical_device_ids[0]),
            timestamp=timestamp,
            payload=execution.to_dict(),
        )
        self._executions.append(execution)
        self._active.add(execution.execution_id)
        start = ExecutionStart(execution.execution_id, event.event_id, timestamp)
        self._starts.append(start)
        return start

    def observe_execution(
        self,
        execution_id: str,
        quantities: Iterable[AccountingQuantity],
        *,
        timestamp: str,
    ) -> ExecutionObservation:
        if execution_id not in self._active:
            raise FirmwareContractError("cannot account for an execution that is not active")
        execution = next(item for item in self._executions if item.execution_id == execution_id)
        quantity_tuple = tuple(quantities)
        if not quantity_tuple:
            raise FirmwareContractError("execution observation requires at least one quantity")
        if any(item.evidence_source_id != self.evidence_source_id for item in quantity_tuple):
            raise FirmwareContractError("emulator counters must reference the emulator evidence source")
        observation_id = f"accounting:{execution_id}:{len(self._accounting)}"
        accounting = ComputeAccountingObservation(
            observation_id=observation_id,
            execution_id=execution_id,
            device_scope_ids=execution.logical_device_ids,
            observed_at=timestamp,
            quantities=quantity_tuple,
            evidence_source_ids=(self.evidence_source_id,),
        )
        event = self._append_event(
            EventType.EXEC_OBSERVATION,
            execution_id=execution_id,
            partition_id=self._logical_partition(execution.logical_device_ids[0]),
            timestamp=timestamp,
            payload=accounting.to_dict(),
        )
        self._accounting.append(accounting)
        observation = ExecutionObservation(execution_id, event.event_id, observation_id, timestamp)
        self._observations.append(observation)
        return observation

    def complete_execution(
        self,
        execution_id: str,
        *,
        timestamp: str,
        outcome: ExecutionOutcome = ExecutionOutcome.COMPLETED,
        output_commitments: tuple[str, ...] = (),
    ) -> ExecutionEnd:
        if execution_id not in self._active:
            raise FirmwareContractError("cannot end an execution that is not active")
        execution = next(item for item in self._executions if item.execution_id == execution_id)
        payload: dict[str, object] = {
            "execution_id": execution_id,
            "outcome": outcome.value,
            "output_commitments": list(output_commitments),
        }
        event = self._append_event(
            EventType.EXEC_END,
            execution_id=execution_id,
            partition_id=self._logical_partition(execution.logical_device_ids[0]),
            timestamp=timestamp,
            payload=payload,
        )
        self._active.remove(execution_id)
        end = ExecutionEnd(execution_id, event.event_id, timestamp, outcome, output_commitments)
        self._ends.append(end)
        return end

    def anchor(self, provider: AnchorProvider, *, anchored_at: str) -> ContinuityAnchor:
        if not self._events:
            raise FirmwareContractError("cannot anchor an empty accounting state")
        anchor = provider.anchor(self._events[-1], anchored_at=anchored_at)
        if not provider.verify(anchor):
            raise FirmwareContractError("anchor provider could not verify its anchor")
        if isinstance(provider, LocalAnchorProvider):
            self._verification_keys[provider.key_id] = provider.signing_key
        self._anchors.append(anchor)
        return anchor

    def reset(
        self,
        *,
        boot_id: str,
        reason: str,
        timestamp: str,
        anchor_provider: AnchorProvider,
    ) -> AccountingEvent:
        for execution_id in tuple(sorted(self._active)):
            self.complete_execution(
                execution_id,
                timestamp=timestamp,
                outcome=ExecutionOutcome.INTERRUPTED,
            )
        anchor = self.anchor(anchor_provider, anchored_at=timestamp)
        prior_event = self._events[-1]
        prior_epoch = self._epoch
        self._epoch += 1
        self._topology_revision = 0
        reset = ResetEpoch(
            device_identity_id=self.physical_identity_id,
            epoch=self._epoch,
            boot_id=boot_id,
            reason=reason,
            prior_epoch=prior_epoch,
            prior_rolling_root=prior_event.rolling_root,
            external_anchor_id=anchor.anchor_id,
        )
        self._resets.append(reset)
        event = self._append_event(
            EventType.RESET,
            execution_id="",
            partition_id="",
            timestamp=timestamp,
            payload={"boot_id": boot_id, "reason": reason, "prior_anchor_id": anchor.anchor_id},
        )
        self._remember_topology(timestamp)
        return event

    def continuity_record(self) -> ContinuityRecord:
        return ContinuityRecord(
            device_identity_id=self.physical_identity_id,
            events=tuple(self._events),
            reset_epochs=tuple(self._resets),
            anchors=tuple(self._anchors),
        )

    def build_receipt(self, *, receipt_id: str, created_at: str) -> VSTD3Receipt:
        if self._active:
            raise FirmwareContractError("cannot finalize a receipt while executions are active")
        if not self._attestations:
            raise FirmwareContractError("receipt requires a nonce-bound attestation")
        source_payload = {
            "domain": "VSTD3-VIRTUAL-EVIDENCE-SOURCE-1",
            "device_identity_id": self.physical_identity_id,
            "firmware_version": self.firmware_version,
            "capabilities": [item.value for item in EMULATOR_CAPABILITIES],
            "root_of_trust": "TEST_HMAC_FIXTURE",
        }
        source = evidence_source_from_bytes(
            source_id=self.evidence_source_id,
            producer=EvidenceProducer.TEST_EMULATOR,
            mechanism="VirtualVSTDAccelerator firmware contract emulator",
            observed_at=created_at,
            capabilities=EMULATOR_CAPABILITIES,
            raw=canonical_json_bytes(source_payload),
            media_type="application/json",
            original_format="VSTD3-VIRTUAL-EVIDENCE-SOURCE-1",
            verification_state=VerificationState.VERIFIED,
            limitations=(
                "Test HMAC evidence demonstrates protocol semantics, not physical tamper resistance.",
                "Complete mediation is bounded to calls accepted by this emulator instance.",
            ),
        )
        continuity = self.continuity_record()
        continuity_result = verify_continuity(
            continuity,
            key_resolver=self._verification_keys.get,
        )
        context = ClaimContext(
            sources=(source,),
            attestation=tuple(self._attestations),
            capability_declarations=self.capability_declarations(),
            continuity=continuity_result,
        )
        claims: list[ClaimEvaluation] = []
        for claim_kind in ClaimKind:
            claims.append(
                evaluate_claim(
                    claim_id=f"claim:{receipt_id}:{claim_kind.value.lower()}",
                    claim_kind=claim_kind,
                    subject_id=self.physical_identity_id,
                    context=context,
                )
            )
        self._remember_topology(created_at)
        receipt = VSTD3Receipt(
            schema_version="VSTD-3.0",
            receipt_id=receipt_id,
            created_at=created_at,
            descriptors=(self.descriptor,),
            physical_identities=(self.physical_identity,),
            logical_identities=tuple(self._logical),
            partitions=tuple(self._partitions),
            topology_snapshots=tuple(self._topology_history),
            capability_declarations=self.capability_declarations(),
            evidence_sources=(source,),
            attestation_challenges=tuple(self._challenges),
            attestation_evidence=tuple(self._attestations),
            executions=tuple(self._executions),
            execution_starts=tuple(self._starts),
            execution_observations=tuple(self._observations),
            execution_ends=tuple(self._ends),
            accounting_observations=tuple(self._accounting),
            continuity_records=(continuity,),
            provider_evidence=(),
            fleet_manifests=(),
            fleet_observations=(),
            evidence_gaps=(),
            claim_evaluations=tuple(claims),
            provenance_artifact_ids=(),
        )
        receipt.compute_and_set_digest()
        return receipt

    def topology_snapshot(self, *, observed_at: str) -> TopologySnapshot:
        physical_node_id = f"node:{self.physical_identity_id}"
        nodes = [
            TopologyNode(
                node_id=physical_node_id,
                component_kind=ComponentKind.PHYSICAL_DEVICE,
                profile_id=self.profile_id,
                physical_identity_id=self.physical_identity_id,
            )
        ]
        links: list[TopologyLink] = []
        for partition, logical in zip(self._partitions, self._logical):
            partition_node = f"node:{partition.partition_id}"
            logical_node = f"node:{logical.logical_id}"
            nodes.extend(
                [
                    TopologyNode(
                        node_id=partition_node,
                        component_kind=ComponentKind.PARTITION,
                        parent_node_ids=(physical_node_id,),
                    ),
                    TopologyNode(
                        node_id=logical_node,
                        component_kind=ComponentKind.LOGICAL_DEVICE,
                        logical_identity_id=logical.logical_id,
                        parent_node_ids=(partition_node,),
                    ),
                ]
            )
            links.extend(
                [
                    TopologyLink(physical_node_id, partition_node, "CONTAINS"),
                    TopologyLink(partition_node, logical_node, "EXPOSES"),
                ]
            )
        return TopologySnapshot(
            snapshot_id=self.current_topology_snapshot_id,
            boundary_id=f"virtual-boundary:{self.device_id}",
            observed_at=observed_at,
            nodes=tuple(nodes),
            links=tuple(links),
            evidence_source_ids=(self.evidence_source_id,),
            completeness_claimed=False,
        )

    def _remember_topology(self, observed_at: str) -> TopologySnapshot:
        snapshot = self.topology_snapshot(observed_at=observed_at)
        if all(item.snapshot_id != snapshot.snapshot_id for item in self._topology_history):
            self._topology_history.append(snapshot)
        return snapshot

    def capability_declarations(self) -> tuple[CapabilityDeclaration, ...]:
        return tuple(
            CapabilityDeclaration(
                capability=capability,
                support=CapabilitySupport.SUPPORTED,
                evidence_method="VirtualVSTDAccelerator reference firmware state machine",
                limitations=("Reference emulator only; not commodity hardware.",),
            )
            for capability in EMULATOR_CAPABILITIES
        )

    def _append_event(
        self,
        event_type: EventType,
        *,
        execution_id: str,
        partition_id: str,
        timestamp: str,
        payload: dict[str, object],
    ) -> AccountingEvent:
        reset = next(item for item in self._resets if item.epoch == self._epoch)
        epoch_events = [event for event in self._events if event.epoch == self._epoch]
        sequence = len(epoch_events)
        previous_root = epoch_events[-1].rolling_root if epoch_events else genesis_root(reset)
        event = build_accounting_event(
            event_id=f"event:{self.device_id}:{self._epoch}:{sequence}",
            event_type=event_type,
            device_identity_id=self.physical_identity_id,
            partition_id=partition_id,
            execution_id=execution_id,
            epoch=self._epoch,
            sequence=sequence,
            timestamp=timestamp,
            payload=payload,
            previous_root=previous_root,
            key_id=self.key_id,
            signing_key=self.signing_key,
        )
        self._events.append(event)
        return event

    def _logical_partition(self, logical_id: str) -> str:
        for logical in self._logical:
            if logical.logical_id == logical_id:
                return logical.partition_id
        raise FirmwareContractError(f"unknown logical device {logical_id}")
