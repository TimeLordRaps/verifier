"""Accelerator-agnostic records for VSTD 3 hardware accountability."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Mapping, TypeVar

from .canonical import canonical_digest, canonical_json_bytes, require_sha256, strict_decode, to_jsonable


class Capability(str, Enum):
    SELF_REPORTED = "SELF_REPORTED"
    HOST_OBSERVED = "HOST_OBSERVED"
    EXECUTION_OBSERVED = "EXECUTION_OBSERVED"
    SOFTWARE_SIGNED = "SOFTWARE_SIGNED"
    PROVIDER_ATTESTED = "PROVIDER_ATTESTED"
    DEVICE_IDENTITY_ATTESTED = "DEVICE_IDENTITY_ATTESTED"
    FIRMWARE_ATTESTED = "FIRMWARE_ATTESTED"
    EXECUTION_ATTESTED = "EXECUTION_ATTESTED"
    EXECUTION_ACCOUNTING_EVIDENCED = "EXECUTION_ACCOUNTING_EVIDENCED"
    CONTINUITY_ATTESTED = "CONTINUITY_ATTESTED"
    COMPLETE_MEDIATION_ATTESTED = "COMPLETE_MEDIATION_ATTESTED"
    FLEET_BOUNDARY_ATTESTED = "FLEET_BOUNDARY_ATTESTED"


class CapabilitySupport(str, Enum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class ClaimStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class ClaimKind(str, Enum):
    DEVICE_IDENTITY = "DEVICE_IDENTITY"
    FIRMWARE_INTEGRITY = "FIRMWARE_INTEGRITY"
    EXECUTION_OBSERVED = "EXECUTION_OBSERVED"
    EXECUTION_ATTESTATION = "EXECUTION_ATTESTATION"
    EXECUTION_ACCOUNTING = "EXECUTION_ACCOUNTING"
    ACCOUNTING_CONTINUITY = "ACCOUNTING_CONTINUITY"
    COMPLETE_MEDIATION = "COMPLETE_MEDIATION"
    FLEET_COMPLETENESS = "FLEET_COMPLETENESS"
    PHYSICAL_WORLD_COMPLETENESS = "PHYSICAL_WORLD_COMPLETENESS"


class DeviceClass(str, Enum):
    GPU = "GPU"
    TPU = "TPU"
    AI_ASIC = "AI_ASIC"
    FPGA = "FPGA"
    ADAPTIVE_COMPUTE = "ADAPTIVE_COMPUTE"
    INTEGRATED_NPU = "INTEGRATED_NPU"
    ACCELERATOR_SWITCH = "ACCELERATOR_SWITCH"
    DPU = "DPU"
    SMARTNIC = "SMARTNIC"
    FABRIC_ADAPTER = "FABRIC_ADAPTER"
    MANAGEMENT_CONTROLLER = "MANAGEMENT_CONTROLLER"
    LOGICAL_ACCELERATOR = "LOGICAL_ACCELERATOR"
    OTHER = "OTHER"


class ComponentKind(str, Enum):
    PHYSICAL_DEVICE = "PHYSICAL_DEVICE"
    LOGICAL_DEVICE = "LOGICAL_DEVICE"
    PARTITION = "PARTITION"
    SWITCH = "SWITCH"
    DPU = "DPU"
    SMARTNIC = "SMARTNIC"
    PCIE_FUNCTION = "PCIE_FUNCTION"
    FABRIC_ADAPTER = "FABRIC_ADAPTER"
    MANAGEMENT_CONTROLLER = "MANAGEMENT_CONTROLLER"
    PACKAGE = "PACKAGE"
    CHIPLET = "CHIPLET"
    HOST = "HOST"
    RACK = "RACK"
    POD = "POD"
    CLUSTER = "CLUSTER"
    OTHER = "OTHER"


class EvidenceProducer(str, Enum):
    SOFTWARE_COLLECTOR = "SOFTWARE_COLLECTOR"
    HOST_RUNTIME = "HOST_RUNTIME"
    PROVIDER_CONTROL_PLANE = "PROVIDER_CONTROL_PLANE"
    DEVICE = "DEVICE"
    FIRMWARE = "FIRMWARE"
    EXTERNAL_VERIFIER = "EXTERNAL_VERIFIER"
    TEST_EMULATOR = "TEST_EMULATOR"


class VerificationState(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNKNOWN = "UNKNOWN"


class AccountingMethod(str, Enum):
    HARDWARE_COUNTER = "HARDWARE_COUNTER"
    FIRMWARE_COUNTER = "FIRMWARE_COUNTER"
    COMPILER_EXACT = "COMPILER_EXACT"
    COMPILER_ESTIMATE = "COMPILER_ESTIMATE"
    RUNTIME_ESTIMATE = "RUNTIME_ESTIMATE"
    MODEL_ESTIMATE = "MODEL_ESTIMATE"
    CAPACITY_TIME_UPPER_BOUND = "CAPACITY_TIME_UPPER_BOUND"
    PROVIDER_REPORT = "PROVIDER_REPORT"
    SELF_REPORT = "SELF_REPORT"
    VENDOR_SPECIFIC = "VENDOR_SPECIFIC"
    UNKNOWN = "UNKNOWN"


class AccountingExactness(str, Enum):
    EXACT_FOR_DECLARED_SCOPE = "EXACT_FOR_DECLARED_SCOPE"
    ESTIMATE = "ESTIMATE"
    UPPER_BOUND = "UPPER_BOUND"
    UNKNOWN = "UNKNOWN"


class EventType(str, Enum):
    DEVICE_BOOT = "DEVICE_BOOT"
    EPOCH_START = "EPOCH_START"
    EXEC_START = "EXEC_START"
    EXEC_OBSERVATION = "EXEC_OBSERVATION"
    EXEC_END = "EXEC_END"
    TOPOLOGY_CHANGE = "TOPOLOGY_CHANGE"
    PARTITION_CHANGE = "PARTITION_CHANGE"
    ANCHOR = "ANCHOR"
    RESET = "RESET"


class ExecutionOutcome(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    UNKNOWN = "UNKNOWN"


class FleetMemberStatus(str, Enum):
    ENROLLED = "ENROLLED"
    RETIRED = "RETIRED"
    REPLACED = "REPLACED"


class CanonicalModel:
    def to_dict(self) -> dict[str, Any]:
        result = to_jsonable(self)
        assert isinstance(result, dict)
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def canonical_hash(self) -> str:
        return canonical_digest(self)

    @classmethod
    def from_dict(cls: type[_ModelT], payload: Mapping[str, Any]) -> _ModelT:
        return strict_decode(cls, payload)


_ModelT = TypeVar("_ModelT", bound=CanonicalModel)


@dataclass(frozen=True)
class CapabilityDeclaration(CanonicalModel):
    capability: Capability
    support: CapabilitySupport
    evidence_method: str
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AcceleratorProfile(CanonicalModel):
    profile_id: str
    vendor: str
    family: str
    architecture: str
    models: tuple[str, ...]
    device_class: DeviceClass
    deployment_classes: tuple[str, ...]
    discovery_methods: tuple[str, ...]
    partition_modes: tuple[str, ...]
    evidence_methods: tuple[str, ...]
    attestation_protocols: tuple[str, ...]
    firmware_identity_support: CapabilitySupport
    hardware_identity_support: CapabilitySupport
    anti_replay_support: CapabilitySupport
    monotonic_state_support: CapabilitySupport
    execution_accounting_support: CapabilitySupport
    topology_attestation_support: CapabilitySupport
    trusted_reset_support: CapabilitySupport
    cloud_provider_evidence_support: CapabilitySupport
    native_complete_mediation_support: CapabilitySupport
    capability_declarations: tuple[CapabilityDeclaration, ...]
    documentation_refs: tuple[str, ...]
    confidence: str
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all((self.profile_id, self.vendor, self.family, self.architecture, self.models)):
            raise ValueError("accelerator profiles require identity, architecture, and models")
        if not self.deployment_classes or not self.discovery_methods:
            raise ValueError("accelerator profiles require deployment and discovery classes")
        sequences = {
            "models": self.models,
            "deployment_classes": self.deployment_classes,
            "discovery_methods": self.discovery_methods,
            "partition_modes": self.partition_modes,
            "evidence_methods": self.evidence_methods,
            "attestation_protocols": self.attestation_protocols,
            "documentation_refs": self.documentation_refs,
        }
        for label, values in sequences.items():
            if len(values) != len(set(values)):
                raise ValueError(f"accelerator profile {label} must not contain duplicates")
        declared = [item.capability for item in self.capability_declarations]
        if len(declared) != len(set(declared)):
            raise ValueError("accelerator profile capability declarations must be unique")


@dataclass(frozen=True)
class AcceleratorDescriptor(CanonicalModel):
    descriptor_id: str
    profile_id: str
    vendor: str
    family: str
    architecture: str
    model: str
    device_class: DeviceClass
    deployment_class: str
    discovery_method: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PhysicalDeviceIdentity(CanonicalModel):
    identity_id: str
    descriptor_id: str
    serial_commitment: str
    certificate_digest: str
    hardware_revision: str
    evidence_source_id: str

    def __post_init__(self) -> None:
        if self.serial_commitment:
            require_sha256(self.serial_commitment, field_name="serial_commitment")
        if self.certificate_digest:
            require_sha256(self.certificate_digest, field_name="certificate_digest")


@dataclass(frozen=True)
class LogicalDeviceIdentity(CanonicalModel):
    logical_id: str
    parent_physical_device_ids: tuple[str, ...]
    partition_id: str
    virtualization_mode: str
    capacity_fraction_ppm: int
    evidence_source_id: str

    def __post_init__(self) -> None:
        if not self.parent_physical_device_ids:
            raise ValueError("logical devices require physical-device lineage")
        if not 0 < self.capacity_fraction_ppm <= 1_000_000:
            raise ValueError("capacity_fraction_ppm must be in 1..1000000")


@dataclass(frozen=True)
class AcceleratorPartition(CanonicalModel):
    partition_id: str
    parent_physical_device_id: str
    logical_device_ids: tuple[str, ...]
    partition_mode: str
    capacity_fraction_ppm: int
    configuration_digest: str

    def __post_init__(self) -> None:
        if not 0 < self.capacity_fraction_ppm <= 1_000_000:
            raise ValueError("capacity_fraction_ppm must be in 1..1000000")
        require_sha256(self.configuration_digest, field_name="configuration_digest")


@dataclass(frozen=True)
class TopologyNode(CanonicalModel):
    node_id: str
    component_kind: ComponentKind
    profile_id: str = ""
    physical_identity_id: str = ""
    logical_identity_id: str = ""
    parent_node_ids: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TopologyLink(CanonicalModel):
    source_node_id: str
    target_node_id: str
    link_type: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TopologySnapshot(CanonicalModel):
    snapshot_id: str
    boundary_id: str
    observed_at: str
    nodes: tuple[TopologyNode, ...]
    links: tuple[TopologyLink, ...]
    evidence_source_ids: tuple[str, ...]
    completeness_claimed: bool = False


@dataclass(frozen=True)
class SignatureEnvelope(CanonicalModel):
    algorithm: str
    key_id: str
    signed_digest: str
    signature_b64: str

    def __post_init__(self) -> None:
        require_sha256(self.signed_digest, field_name="signed_digest")


@dataclass(frozen=True)
class EvidenceSource(CanonicalModel):
    source_id: str
    producer: EvidenceProducer
    mechanism: str
    observed_at: str
    capabilities: tuple[Capability, ...]
    raw_evidence_b64: str
    raw_evidence_digest: str
    media_type: str
    original_format: str
    verification_state: VerificationState = VerificationState.NOT_VERIFIED
    limitations: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_sha256(self.raw_evidence_digest, field_name="raw_evidence_digest")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("evidence source capabilities must be unique")


@dataclass(frozen=True)
class AttestationChallenge(CanonicalModel):
    challenge_id: str
    nonce_b64: str
    issued_at: str
    expires_at: str
    verifier_id: str


@dataclass(frozen=True)
class FirmwareMeasurement(CanonicalModel):
    component: str
    digest: str
    algorithm: str
    version: str
    reference_value_digest: str = ""
    comparison: VerificationState = VerificationState.NOT_VERIFIED

    def __post_init__(self) -> None:
        require_sha256(self.digest, field_name="firmware measurement digest")
        if self.reference_value_digest:
            require_sha256(self.reference_value_digest, field_name="reference_value_digest")


@dataclass(frozen=True)
class RuntimeMeasurement(CanonicalModel):
    component: str
    digest: str
    algorithm: str
    version: str
    comparison: VerificationState = VerificationState.NOT_VERIFIED

    def __post_init__(self) -> None:
        require_sha256(self.digest, field_name="runtime measurement digest")


@dataclass(frozen=True)
class DeviceCertificateEvidence(CanonicalModel):
    certificate_chain_digest: str
    leaf_fingerprint: str
    trust_anchor_id: str
    verification_state: VerificationState
    checked_at: str

    def __post_init__(self) -> None:
        require_sha256(self.certificate_chain_digest, field_name="certificate_chain_digest")
        require_sha256(self.leaf_fingerprint, field_name="leaf_fingerprint")


@dataclass(frozen=True)
class AttestationEvidence(CanonicalModel):
    evidence_id: str
    subject_identity_id: str
    challenge_id: str
    nonce_b64: str
    issued_at: str
    expires_at: str
    evidence_source_id: str
    firmware_measurements: tuple[FirmwareMeasurement, ...]
    runtime_measurements: tuple[RuntimeMeasurement, ...]
    device_certificate: DeviceCertificateEvidence | None
    signature: SignatureEnvelope | None
    verification_state: VerificationState
    demonstrated_capabilities: tuple[Capability, ...]


@dataclass(frozen=True)
class WorkloadIdentity(CanonicalModel):
    workload_id: str
    executable_digest: str = ""
    source_tree_digest: str = ""
    container_image_digest: str = ""
    model_commitments: tuple[str, ...] = ()
    input_commitments: tuple[str, ...] = ()
    dataset_commitments: tuple[str, ...] = ()
    environment_digest: str = ""
    compiler: str = ""
    accelerator_runtime: str = ""
    driver: str = ""
    libraries_digest: str = ""
    kernel_commitments: tuple[str, ...] = ()
    invocation_commitment: str = ""
    orchestrator_job_id: str = ""
    cloud_resource_id: str = ""
    tenant_commitment: str = ""
    parent_run_id: str = ""

    def __post_init__(self) -> None:
        digest_fields = {
            "executable_digest": self.executable_digest,
            "source_tree_digest": self.source_tree_digest,
            "environment_digest": self.environment_digest,
            "libraries_digest": self.libraries_digest,
            "invocation_commitment": self.invocation_commitment,
            "tenant_commitment": self.tenant_commitment,
        }
        if self.container_image_digest:
            container_digest = self.container_image_digest.removeprefix("sha256:")
            require_sha256(container_digest, field_name="container_image_digest")
        for label, value in digest_fields.items():
            if value:
                require_sha256(value, field_name=label)
        for label, values in {
            "model_commitments": self.model_commitments,
            "input_commitments": self.input_commitments,
            "dataset_commitments": self.dataset_commitments,
            "kernel_commitments": self.kernel_commitments,
        }.items():
            for value in values:
                require_sha256(value, field_name=label)


@dataclass(frozen=True)
class ExecutionIdentity(CanonicalModel):
    execution_id: str
    workload: WorkloadIdentity
    logical_device_ids: tuple[str, ...]
    topology_snapshot_id: str
    submitted_at: str


@dataclass(frozen=True)
class ExecutionStart(CanonicalModel):
    execution_id: str
    event_id: str
    started_at: str


@dataclass(frozen=True)
class ExecutionObservation(CanonicalModel):
    execution_id: str
    event_id: str
    accounting_observation_id: str
    observed_at: str


@dataclass(frozen=True)
class ExecutionEnd(CanonicalModel):
    execution_id: str
    event_id: str
    completed_at: str
    outcome: ExecutionOutcome
    output_commitments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for commitment in self.output_commitments:
            require_sha256(commitment, field_name="output_commitment")


_EXACT_METHODS = {
    AccountingMethod.HARDWARE_COUNTER,
    AccountingMethod.FIRMWARE_COUNTER,
    AccountingMethod.COMPILER_EXACT,
}


@dataclass(frozen=True)
class AccountingQuantity(CanonicalModel):
    name: str
    value: str
    unit: str
    method: AccountingMethod
    evidence_source_id: str
    scope: str
    exactness: AccountingExactness
    uncertainty: str = ""
    vendor_extension: str = ""

    def __post_init__(self) -> None:
        try:
            number = Decimal(self.value)
        except InvalidOperation as exc:
            raise ValueError("accounting value must be a finite decimal string") from exc
        if not number.is_finite() or number < 0:
            raise ValueError("accounting value must be finite and non-negative")
        if self.exactness is AccountingExactness.EXACT_FOR_DECLARED_SCOPE and self.method not in _EXACT_METHODS:
            raise ValueError(f"{self.method.value} cannot be represented as an exact counter")
        if self.method is AccountingMethod.CAPACITY_TIME_UPPER_BOUND and self.exactness is not AccountingExactness.UPPER_BOUND:
            raise ValueError("capacity-time accounting must be labeled as an upper bound")


@dataclass(frozen=True)
class ComputeAccountingObservation(CanonicalModel):
    observation_id: str
    execution_id: str
    device_scope_ids: tuple[str, ...]
    observed_at: str
    quantities: tuple[AccountingQuantity, ...]
    evidence_source_ids: tuple[str, ...]


@dataclass(frozen=True)
class AccountingEvent(CanonicalModel):
    event_id: str
    event_type: EventType
    device_identity_id: str
    partition_id: str
    execution_id: str
    epoch: int
    sequence: int
    timestamp: str
    event_payload_digest: str
    previous_root: str
    rolling_root: str
    signature: SignatureEnvelope | None = None

    def __post_init__(self) -> None:
        if self.epoch < 0 or not 0 <= self.sequence < 2**64:
            raise ValueError("epoch and sequence must be non-negative and sequence must fit uint64")
        require_sha256(self.event_payload_digest, field_name="event_payload_digest")
        require_sha256(self.previous_root, field_name="previous_root")
        require_sha256(self.rolling_root, field_name="rolling_root")


@dataclass(frozen=True)
class ContinuityAnchor(CanonicalModel):
    anchor_id: str
    device_identity_id: str
    epoch: int
    sequence: int
    rolling_root: str
    anchored_at: str
    provider_id: str
    signature: SignatureEnvelope

    def __post_init__(self) -> None:
        require_sha256(self.rolling_root, field_name="rolling_root")


@dataclass(frozen=True)
class ResetEpoch(CanonicalModel):
    device_identity_id: str
    epoch: int
    boot_id: str
    reason: str
    prior_epoch: int | None
    prior_rolling_root: str
    external_anchor_id: str

    def __post_init__(self) -> None:
        if self.epoch < 0:
            raise ValueError("epoch must be non-negative")
        if self.prior_rolling_root:
            require_sha256(self.prior_rolling_root, field_name="prior_rolling_root")


@dataclass(frozen=True)
class ContinuityRecord(CanonicalModel):
    device_identity_id: str
    events: tuple[AccountingEvent, ...]
    reset_epochs: tuple[ResetEpoch, ...]
    anchors: tuple[ContinuityAnchor, ...]


@dataclass(frozen=True)
class EvidenceGap(CanonicalModel):
    gap_id: str
    gap_type: str
    subject_id: str
    explanation: str
    first_sequence: int | None = None
    last_sequence: int | None = None


@dataclass(frozen=True)
class ProviderEvidence(CanonicalModel):
    evidence_id: str
    provider: str
    resource_id: str
    issued_at: str
    expires_at: str
    claims: dict[str, Any]
    evidence_source_id: str
    signature: SignatureEnvelope | None
    verification_state: VerificationState
    hardware_evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class FleetBoundary(CanonicalModel):
    boundary_id: str
    organization: str
    site: str
    cluster: str
    rack: str
    host: str
    accelerator_set: str
    enrollment_completeness_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class FleetMember(CanonicalModel):
    member_id: str
    physical_device_ids: tuple[str, ...]
    logical_device_ids: tuple[str, ...]
    expected_profile_id: str
    enrolled_at: str
    status: FleetMemberStatus = FleetMemberStatus.ENROLLED
    replacement_member_id: str = ""


@dataclass(frozen=True)
class FleetManifest(CanonicalModel):
    manifest_id: str
    boundary: FleetBoundary
    members: tuple[FleetMember, ...]
    effective_at: str
    evidence_source_ids: tuple[str, ...]


@dataclass(frozen=True)
class FleetObservation(CanonicalModel):
    observation_id: str
    manifest_id: str
    interval_start: str
    interval_end: str
    observed_member_ids: tuple[str, ...]
    missing_member_ids: tuple[str, ...]
    unexpected_device_ids: tuple[str, ...]
    last_anchor_ids: tuple[str, ...]
    topology_snapshot_id: str
    evidence_source_ids: tuple[str, ...]


@dataclass(frozen=True)
class ClaimEvaluation(CanonicalModel):
    claim_id: str
    claim_kind: ClaimKind
    subject_id: str
    status: ClaimStatus
    required_capabilities: tuple[Capability, ...]
    observed_capabilities: tuple[Capability, ...]
    evidence_ids: tuple[str, ...]
    gap_ids: tuple[str, ...]
    explanation: str
    prohibited_inference: str


@dataclass(frozen=True)
class AdapterResult(CanonicalModel):
    adapter_id: str
    profile_id: str
    descriptors: tuple[AcceleratorDescriptor, ...]
    physical_identities: tuple[PhysicalDeviceIdentity, ...]
    logical_identities: tuple[LogicalDeviceIdentity, ...]
    partitions: tuple[AcceleratorPartition, ...]
    topology_snapshots: tuple[TopologySnapshot, ...]
    evidence_sources: tuple[EvidenceSource, ...]
    attestation_challenges: tuple[AttestationChallenge, ...]
    attestation_evidence: tuple[AttestationEvidence, ...]
    capability_declarations: tuple[CapabilityDeclaration, ...]
    evidence_gaps: tuple[EvidenceGap, ...]


@dataclass
class VSTD3Receipt(CanonicalModel):
    schema_version: str
    receipt_id: str
    created_at: str
    descriptors: tuple[AcceleratorDescriptor, ...]
    physical_identities: tuple[PhysicalDeviceIdentity, ...]
    logical_identities: tuple[LogicalDeviceIdentity, ...]
    partitions: tuple[AcceleratorPartition, ...]
    topology_snapshots: tuple[TopologySnapshot, ...]
    capability_declarations: tuple[CapabilityDeclaration, ...]
    evidence_sources: tuple[EvidenceSource, ...]
    attestation_challenges: tuple[AttestationChallenge, ...]
    attestation_evidence: tuple[AttestationEvidence, ...]
    executions: tuple[ExecutionIdentity, ...]
    execution_starts: tuple[ExecutionStart, ...]
    execution_observations: tuple[ExecutionObservation, ...]
    execution_ends: tuple[ExecutionEnd, ...]
    accounting_observations: tuple[ComputeAccountingObservation, ...]
    continuity_records: tuple[ContinuityRecord, ...]
    provider_evidence: tuple[ProviderEvidence, ...]
    fleet_manifests: tuple[FleetManifest, ...]
    fleet_observations: tuple[FleetObservation, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    claim_evaluations: tuple[ClaimEvaluation, ...]
    provenance_artifact_ids: tuple[str, ...]
    canonical_digest: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != "VSTD-3.0":
            raise ValueError("VSTD3Receipt schema_version must be VSTD-3.0")

    def stable_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("canonical_digest")
        return payload

    def compute_and_set_digest(self) -> str:
        self.canonical_digest = canonical_digest(self.stable_payload())
        return self.canonical_digest

    def verify_digest_integrity(self) -> bool:
        return bool(self.canonical_digest) and self.canonical_digest == canonical_digest(
            self.stable_payload()
        )
