"""Experimental artifact tracing bound to Verifier Standard (VSTD)-3 coordinates.

Terminology: hash-based message authentication code (HMAC); Secure Hash
Algorithm 256-bit (SHA-256); identifier (ID).

This module authenticates a detached trace binding.  It does not identify an
actor, conceal an artifact, or establish information-theoretic security.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import secrets
from typing import Protocol

from .canonical import canonical_json_bytes, require_sha256
from .continuity import KeyResolver
from .models import CanonicalModel, VSTD3Receipt
from .validation import validate_vstd3_receipt


TRACE_FORMAT_ID = "VSTD3-ARTIFACT-TRACE-EXPERIMENTAL-0.1"
TRACE_MARKER_BYTES = 32
TRACE_MAC_DOMAIN = b"VSTD3-ARTIFACT-TRACE-BINDING\x00"
PROHIBITED_INFERENCE = (
    "Trace status does not identify a natural person, establish authorship, "
    "malicious intent, guilt, correctness, authorization, or the absence of "
    "untraced artifacts."
)
DEFAULT_LIMITATIONS = (
    "The carrier may be discoverable, removable, copied, or damaged.",
    "Hardware/runtime digests inherit the receipt evidence and trust boundaries.",
    "HMAC-SHA256 supplies computational authentication, not information-theoretic security.",
)


class TraceStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNKNOWN = "UNKNOWN"


class TraceAction(str, Enum):
    NONE = "NONE"
    QUARANTINE_FOR_REVIEW = "QUARANTINE_FOR_REVIEW"


class EntropyProvider(Protocol):
    provider_id: str

    def token_bytes(self, length: int) -> bytes: ...


class TraceCarrier(Protocol):
    carrier_id: str

    def embed(self, artifact: bytes, marker: bytes) -> bytes: ...

    def extract(self, artifact: bytes) -> bytes | None: ...


class TraceKeyResolver(Protocol):
    def __call__(self, key_id: str) -> bytes | None: ...


class SystemEntropyProvider:
    """Generate markers from Python's operating-system-backed secrets source."""

    provider_id = "python-secrets-system-random"

    def token_bytes(self, length: int) -> bytes:
        return secrets.token_bytes(length)


@dataclass(frozen=True)
class HardwareRuntimeCoordinate(CanonicalModel):
    receipt_digest: str
    execution_identity_digest: str
    topology_snapshot_digest: str
    logical_identity_digests: tuple[str, ...]
    physical_identity_digests: tuple[str, ...]
    runtime_measurement_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        require_sha256(self.receipt_digest, field_name="receipt_digest")
        require_sha256(
            self.execution_identity_digest,
            field_name="execution_identity_digest",
        )
        require_sha256(
            self.topology_snapshot_digest,
            field_name="topology_snapshot_digest",
        )
        for field_name, values in (
            ("logical_identity_digests", self.logical_identity_digests),
            ("physical_identity_digests", self.physical_identity_digests),
            ("runtime_measurement_digests", self.runtime_measurement_digests),
        ):
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be sorted and unique")
            for value in values:
                require_sha256(value, field_name=field_name)


@dataclass(frozen=True)
class ArtifactTraceBinding(CanonicalModel):
    format_id: str
    artifact_sha256: str
    artifact_size_bytes: int
    coordinate: HardwareRuntimeCoordinate
    carrier_id: str
    entropy_provider_id: str
    key_id: str
    binding_mac_b64: str
    limitations: tuple[str, ...] = DEFAULT_LIMITATIONS

    def __post_init__(self) -> None:
        if self.format_id != TRACE_FORMAT_ID:
            raise ValueError(f"format_id must be {TRACE_FORMAT_ID}")
        require_sha256(self.artifact_sha256, field_name="artifact_sha256")
        if self.artifact_size_bytes < 0:
            raise ValueError("artifact_size_bytes must be nonnegative")
        for field_name in ("carrier_id", "entropy_provider_id", "key_id"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} must not be empty")
        try:
            decoded_mac = base64.b64decode(self.binding_mac_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("binding_mac_b64 must be strict base64") from exc
        if len(decoded_mac) != hashlib.sha256().digest_size:
            raise ValueError("binding_mac_b64 must encode a 32-byte HMAC-SHA256 value")


@dataclass(frozen=True)
class TraceVerification(CanonicalModel):
    status: TraceStatus
    reason_codes: tuple[str, ...]
    recommended_action: TraceAction
    prohibited_inference: str = PROHIBITED_INFERENCE


def build_hardware_runtime_coordinate(
    receipt: VSTD3Receipt,
    execution_id: str,
    *,
    key_resolver: KeyResolver | None = None,
) -> HardwareRuntimeCoordinate:
    """Bind one validated receipt execution and its reachable hardware records."""

    validation = validate_vstd3_receipt(receipt, key_resolver=key_resolver)
    if not validation.valid:
        details = "; ".join(validation.errors) or validation.status.value
        raise ValueError(f"cannot trace an invalid VSTD-3 receipt: {details}")

    execution = next(
        (item for item in receipt.executions if item.execution_id == execution_id),
        None,
    )
    if execution is None:
        raise ValueError(f"receipt does not contain execution {execution_id!r}")
    topology = next(
        (
            item
            for item in receipt.topology_snapshots
            if item.snapshot_id == execution.topology_snapshot_id
        ),
        None,
    )
    if topology is None:
        raise ValueError("execution topology snapshot is unavailable")

    logical_by_id = {item.logical_id: item for item in receipt.logical_identities}
    logical = tuple(logical_by_id[item_id] for item_id in execution.logical_device_ids)
    physical_ids = sorted(
        {
            physical_id
            for identity in logical
            for physical_id in identity.parent_physical_device_ids
        }
    )
    physical_by_id = {item.identity_id: item for item in receipt.physical_identities}
    physical = tuple(physical_by_id[item_id] for item_id in physical_ids)
    relevant_subjects = set(execution.logical_device_ids) | set(physical_ids)
    runtime_measurements = tuple(
        measurement
        for evidence in receipt.attestation_evidence
        if evidence.subject_identity_id in relevant_subjects
        for measurement in evidence.runtime_measurements
    )

    return HardwareRuntimeCoordinate(
        receipt_digest=receipt.canonical_digest,
        execution_identity_digest=execution.canonical_hash(),
        topology_snapshot_digest=topology.canonical_hash(),
        logical_identity_digests=_sorted_hashes(logical),
        physical_identity_digests=_sorted_hashes(physical),
        runtime_measurement_digests=_sorted_hashes(runtime_measurements),
    )


def issue_artifact_trace(
    artifact: bytes,
    coordinate: HardwareRuntimeCoordinate,
    *,
    carrier: TraceCarrier,
    entropy_provider: EntropyProvider,
    key_id: str,
    key: bytes,
) -> tuple[bytes, ArtifactTraceBinding]:
    """Embed a fresh marker and authenticate a detached final-byte binding."""

    _require_key(key)
    if not key_id:
        raise ValueError("key_id must not be empty")
    if not carrier.carrier_id:
        raise ValueError("carrier_id must not be empty")
    if not entropy_provider.provider_id:
        raise ValueError("entropy provider_id must not be empty")

    marker = entropy_provider.token_bytes(TRACE_MARKER_BYTES)
    if not isinstance(marker, bytes) or len(marker) != TRACE_MARKER_BYTES:
        raise ValueError("entropy provider must return exactly 32 bytes")
    traced_artifact = carrier.embed(artifact, marker)
    if not isinstance(traced_artifact, bytes):
        raise TypeError("trace carrier embed must return bytes")
    try:
        extracted = carrier.extract(traced_artifact)
    except Exception as exc:
        raise ValueError("trace carrier could not re-extract its marker") from exc
    if extracted != marker:
        raise ValueError("trace carrier did not preserve the exact marker")

    artifact_digest = hashlib.sha256(traced_artifact).hexdigest()
    limitations = DEFAULT_LIMITATIONS
    mac = _binding_mac(
        marker=marker,
        artifact_sha256=artifact_digest,
        artifact_size_bytes=len(traced_artifact),
        coordinate=coordinate,
        carrier_id=carrier.carrier_id,
        entropy_provider_id=entropy_provider.provider_id,
        key_id=key_id,
        limitations=limitations,
        key=key,
    )
    binding = ArtifactTraceBinding(
        format_id=TRACE_FORMAT_ID,
        artifact_sha256=artifact_digest,
        artifact_size_bytes=len(traced_artifact),
        coordinate=coordinate,
        carrier_id=carrier.carrier_id,
        entropy_provider_id=entropy_provider.provider_id,
        key_id=key_id,
        binding_mac_b64=base64.b64encode(mac).decode("ascii"),
        limitations=limitations,
    )
    return traced_artifact, binding


def verify_artifact_trace(
    artifact: bytes,
    binding: ArtifactTraceBinding,
    expected_coordinate: HardwareRuntimeCoordinate,
    *,
    carrier: TraceCarrier,
    key_resolver: TraceKeyResolver | None,
) -> TraceVerification:
    """Verify a trace without converting absent evidence into a clean result."""

    try:
        marker = carrier.extract(artifact)
    except Exception:
        return _trace_result(TraceStatus.UNKNOWN, ["CARRIER_EXTRACTION_UNAVAILABLE"])
    if marker is None:
        return _trace_result(TraceStatus.UNKNOWN, ["MARKER_UNAVAILABLE"])
    if not isinstance(marker, bytes) or len(marker) != TRACE_MARKER_BYTES:
        return _trace_result(TraceStatus.UNKNOWN, ["MARKER_INVALID"])
    if key_resolver is None:
        return _trace_result(TraceStatus.UNKNOWN, ["KEY_RESOLVER_UNAVAILABLE"])
    try:
        key = key_resolver(binding.key_id)
    except Exception:
        return _trace_result(TraceStatus.UNKNOWN, ["KEY_RESOLVER_UNAVAILABLE"])
    if key is None:
        return _trace_result(TraceStatus.UNKNOWN, ["KEY_UNAVAILABLE"])
    if not isinstance(key, bytes) or len(key) < 32:
        return _trace_result(TraceStatus.UNKNOWN, ["KEY_MATERIAL_INVALID"])

    expected_mac = _binding_mac(
        marker=marker,
        artifact_sha256=binding.artifact_sha256,
        artifact_size_bytes=binding.artifact_size_bytes,
        coordinate=binding.coordinate,
        carrier_id=binding.carrier_id,
        entropy_provider_id=binding.entropy_provider_id,
        key_id=binding.key_id,
        limitations=binding.limitations,
        key=key,
    )
    actual_mac = base64.b64decode(binding.binding_mac_b64, validate=True)
    if not hmac.compare_digest(actual_mac, expected_mac):
        return _trace_result(
            TraceStatus.MISMATCH,
            ["BINDING_AUTHENTICATION_MISMATCH"],
        )

    reasons: list[str] = []
    if carrier.carrier_id != binding.carrier_id:
        reasons.append("CARRIER_ID_MISMATCH")
    if expected_coordinate != binding.coordinate:
        reasons.append("COORDINATE_MISMATCH")
    if len(artifact) != binding.artifact_size_bytes:
        reasons.append("ARTIFACT_SIZE_MISMATCH")
    if hashlib.sha256(artifact).hexdigest() != binding.artifact_sha256:
        reasons.append("ARTIFACT_DIGEST_MISMATCH")
    if reasons:
        return _trace_result(TraceStatus.MISMATCH, reasons)
    return _trace_result(TraceStatus.MATCH, [])


def _binding_mac(
    *,
    marker: bytes,
    artifact_sha256: str,
    artifact_size_bytes: int,
    coordinate: HardwareRuntimeCoordinate,
    carrier_id: str,
    entropy_provider_id: str,
    key_id: str,
    limitations: tuple[str, ...],
    key: bytes,
) -> bytes:
    payload = {
        "artifact_sha256": artifact_sha256,
        "artifact_size_bytes": artifact_size_bytes,
        "carrier_id": carrier_id,
        "coordinate": coordinate,
        "entropy_provider_id": entropy_provider_id,
        "format_id": TRACE_FORMAT_ID,
        "key_id": key_id,
        "limitations": limitations,
        "marker_b64": base64.b64encode(marker).decode("ascii"),
    }
    return hmac.new(
        key,
        TRACE_MAC_DOMAIN + canonical_json_bytes(payload),
        hashlib.sha256,
    ).digest()


def _require_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("trace authentication key must contain at least 32 bytes")


def _sorted_hashes(records: tuple[CanonicalModel, ...]) -> tuple[str, ...]:
    return tuple(sorted({record.canonical_hash() for record in records}))


def _trace_result(status: TraceStatus, reasons: list[str]) -> TraceVerification:
    action = TraceAction.NONE if status is TraceStatus.MATCH else TraceAction.QUARANTINE_FOR_REVIEW
    return TraceVerification(
        status=status,
        reason_codes=tuple(reasons),
        recommended_action=action,
    )
