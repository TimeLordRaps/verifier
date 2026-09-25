"""Terminology: central processing unit (CPU); identifier (ID); inter-process communication (IPC); JavaScript Object Notation (JSON); operating system (OS); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Software One-Way Data Diode Emulator for development, testing, and interface rehearsal.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
from typing import Any, Optional

class ZeroFalseConfidenceError(ValueError):
    """Raised when an emulated diode breaches zero-false-confidence invariants."""


DIODE_EMULATOR_DISCLAIMER_TEXT = (
    "SOFTWARE EMULATION ONLY: This software data diode emulator operates entirely on shared "
    "silicon, microarchitectural caches, memory buses, and operating-system kernel space. It "
    "DOES NOT provide physical unidirectional optical isolation, DOES NOT sever "
    "electromagnetic/timing side-channels, and CANNOT guarantee one-way containment against "
    "high-capability models, superintelligent systems, or kernel-level exploits. It is "
    "strictly for development, testing, and interface rehearsal."
)

DIODE_EMULATOR_DISCLAIMER_DIGEST = (
    f"sha256:{hashlib.sha256(DIODE_EMULATOR_DISCLAIMER_TEXT.encode('utf-8')).hexdigest()}"
)


class SeveredChannelReadViolationError(ValueError):
    """Raised when an attempt is made to read from a severed one-way diode channel."""


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class EmulatedDiodeAttestationReceipt:
    """Explicitly degraded attestation receipt emitted by the diode emulator.

    Carries machine-readable refusal markers preventing Tier 3 promotion.
    """

    emulator_id: str
    is_software_emulation: bool = True
    hardware_attestation_valid: bool = False
    maximum_admissible_tier: str = "TIER_1_LOCAL"
    disclaimer: str = DIODE_EMULATOR_DISCLAIMER_TEXT
    disclaimer_digest: str = DIODE_EMULATOR_DISCLAIMER_DIGEST
    bytes_transmitted: int = 0
    message_count: int = 0
    schema_version: str = "VSTD-DIODE-EMU-1.0.0"

    def __post_init__(self) -> None:
        if not self.emulator_id:
            raise ValueError("emulator_id cannot be empty")
        if not self.is_software_emulation:
            raise ZeroFalseConfidenceError("Emulated diode cannot claim is_software_emulation=False")
        if self.hardware_attestation_valid:
            raise ZeroFalseConfidenceError("Emulated diode cannot claim hardware_attestation_valid=True")
        if self.maximum_admissible_tier != "TIER_1_LOCAL":
            raise ZeroFalseConfidenceError("Emulated diode cannot claim higher tier than TIER_1_LOCAL")

    def canonical_digest(self) -> str:
        payload = {
            "bytes_transmitted": self.bytes_transmitted,
            "disclaimer_digest": self.disclaimer_digest,
            "emulator_id": self.emulator_id,
            "hardware_attestation_valid": self.hardware_attestation_valid,
            "is_software_emulation": self.is_software_emulation,
            "maximum_admissible_tier": self.maximum_admissible_tier,
            "message_count": self.message_count,
            "schema_version": self.schema_version,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "bytes_transmitted": self.bytes_transmitted,
            "canonical_digest": self.canonical_digest(),
            "disclaimer": self.disclaimer,
            "disclaimer_digest": self.disclaimer_digest,
            "emulator_id": self.emulator_id,
            "hardware_attestation_valid": self.hardware_attestation_valid,
            "is_software_emulation": self.is_software_emulation,
            "maximum_admissible_tier": self.maximum_admissible_tier,
            "message_count": self.message_count,
            "schema_version": self.schema_version,
        }


class SoftwareOneWayDataDiodeEmulator:
    """Executable unidirectional stream emulator with physical channel severance modeling.

    Provides strictly push-only semantics (write/flush) and unconditionally raises on read.
    """

    def __init__(self, emulator_id: str, sink: Optional[io.BytesIO] = None) -> None:
        if not emulator_id:
            raise ValueError("emulator_id cannot be empty")
        self.emulator_id = emulator_id
        self._sink: io.BytesIO = sink if sink is not None else io.BytesIO()
        self._bytes_written: int = 0
        self._message_count: int = 0
        self._closed: bool = False

    @property
    def disclaimer(self) -> str:
        return DIODE_EMULATOR_DISCLAIMER_TEXT

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def message_count(self) -> int:
        return self._message_count

    def push(self, data: bytes) -> int:
        """Push bytes across the diode boundary to the isolated receiver sink."""
        if self._closed:
            raise ValueError("Cannot push to closed diode emulator")
        n = self._sink.write(data)
        self._sink.flush()
        self._bytes_written += n
        self._message_count += 1
        return n

    def read(self, *args: Any, **kwargs: Any) -> bytes:
        """Severed reverse channel invariant: read operations are categorically prohibited."""
        raise SeveredChannelReadViolationError(
            "Unidirectional Diode Invariant Breach: reverse read channel is severed. "
            "Data diodes permit push-only communication; read back is categorically prohibited."
        )

    def recv(self, *args: Any, **kwargs: Any) -> bytes:
        return self.read(*args, **kwargs)

    def peek(self, *args: Any, **kwargs: Any) -> bytes:
        return self.read(*args, **kwargs)

    def close(self) -> None:
        self._closed = True

    def emit_attestation_receipt(self) -> EmulatedDiodeAttestationReceipt:
        return EmulatedDiodeAttestationReceipt(
            emulator_id=self.emulator_id,
            bytes_transmitted=self._bytes_written,
            message_count=self._message_count,
        )

    def to_hardware_diode_attestation_attempt(self) -> dict[str, Any]:
        """Attempting to convert software emulation into HardwareDiodeAttestation payload.

        This intentional marker MUST be rejected by TeslaCageSandbox under zero false confidence.
        """
        return {
            "device_id": f"SOFTWARE_EMULATOR:{self.emulator_id}",
            "optical_wavelength_nm": 0,
            "severed_reverse_channel": True,
            "firmware_measurement": DIODE_EMULATOR_DISCLAIMER_DIGEST,
        }
