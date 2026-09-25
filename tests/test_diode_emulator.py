"""Terminology: central processing unit (CPU); identifier (ID); inter-process communication (IPC); JavaScript Object Notation (JSON); operating system (OS); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Adversarial test suite for SoftwareOneWayDataDiodeEmulator and Zero False Confidence containment invariants.
"""
from __future__ import annotations

import io
import pytest

from verifier.corrigibility import (
    AnalogPowerRelayAttestation,
    ContainmentTier,
    ContainmentViolationError,
    HardwareDiodeAttestation,
    TeslaCageSandbox,
    ZeroFalseConfidenceError,
)
from verifier.hardware.diode_emulator import (
    DIODE_EMULATOR_DISCLAIMER_DIGEST,
    DIODE_EMULATOR_DISCLAIMER_TEXT,
    EmulatedDiodeAttestationReceipt,
    SeveredChannelReadViolationError,
    SoftwareOneWayDataDiodeEmulator,
)


def _sample_relay() -> AnalogPowerRelayAttestation:
    return AnalogPowerRelayAttestation(
        relay_id="relay:test-break-001",
        isolation_voltage_volts=250.0,
        mechanical_break_response_ms=10.0,
        out_of_band_control_channel="GPIO_PHYSICAL_PIN_18",
    )


def test_software_data_diode_push_and_severed_read() -> None:
    sink = io.BytesIO()
    diode = SoftwareOneWayDataDiodeEmulator(emulator_id="emu:diode-test-001", sink=sink)

    # 1. Human-readable and digest disclaimers
    assert diode.disclaimer == DIODE_EMULATOR_DISCLAIMER_TEXT
    assert "SOFTWARE EMULATION ONLY" in diode.disclaimer
    assert "DOES NOT provide physical unidirectional optical isolation" in diode.disclaimer

    # 2. Push stream semantics (write/flush succeeds)
    bytes_sent = diode.push(b"TELEMETRY_RECORD_001\n")
    assert bytes_sent == 21
    assert diode.bytes_written == 21
    assert diode.message_count == 1
    assert sink.getvalue() == b"TELEMETRY_RECORD_001\n"

    # Push second message
    diode.push(b"TELEMETRY_RECORD_002\n")
    assert diode.bytes_written == 42
    assert diode.message_count == 2

    # 3. Severed read channel: read, recv, and peek unconditionally raise
    with pytest.raises(SeveredChannelReadViolationError, match="reverse read channel is severed"):
        diode.read()

    with pytest.raises(SeveredChannelReadViolationError, match="reverse read channel is severed"):
        diode.recv(1024)

    with pytest.raises(SeveredChannelReadViolationError, match="reverse read channel is severed"):
        diode.peek()


def test_emulated_diode_attestation_receipt_metadata_and_integrity() -> None:
    sink = io.BytesIO()
    diode = SoftwareOneWayDataDiodeEmulator(emulator_id="emu:diode-test-002", sink=sink)
    diode.push(b"AUDIT_PACKET")

    receipt = diode.emit_attestation_receipt()
    assert receipt.emulator_id == "emu:diode-test-002"
    assert receipt.is_software_emulation is True
    assert receipt.hardware_attestation_valid is False
    assert receipt.maximum_admissible_tier == "TIER_1_LOCAL"
    assert receipt.disclaimer_digest == DIODE_EMULATOR_DISCLAIMER_DIGEST
    assert receipt.bytes_transmitted == 12
    assert receipt.message_count == 1
    assert receipt.canonical_digest().startswith("sha256:")

    # Dict serialization
    as_dict = receipt.to_dict()
    assert as_dict["is_software_emulation"] is True
    assert as_dict["hardware_attestation_valid"] is False
    assert as_dict["maximum_admissible_tier"] == "TIER_1_LOCAL"
    assert as_dict["canonical_digest"] == receipt.canonical_digest()


def test_emulated_diode_rejects_false_claims() -> None:
    # Attempting to claim it is NOT software emulation
    with pytest.raises(ZeroFalseConfidenceError, match="cannot claim is_software_emulation=False"):
        EmulatedDiodeAttestationReceipt(
            emulator_id="bad",
            is_software_emulation=False,
        )

    # Attempting to claim hardware attestation is valid
    with pytest.raises(ZeroFalseConfidenceError, match="cannot claim hardware_attestation_valid=True"):
        EmulatedDiodeAttestationReceipt(
            emulator_id="bad",
            hardware_attestation_valid=True,
        )

    # Attempting to claim higher containment tier than TIER_1_LOCAL
    with pytest.raises(ZeroFalseConfidenceError, match="cannot claim higher tier than TIER_1_LOCAL"):
        EmulatedDiodeAttestationReceipt(
            emulator_id="bad",
            maximum_admissible_tier="TIER_3_TESLA_CAGED",
        )


def test_zero_false_confidence_rejects_software_diode_in_tier_3_cage() -> None:
    diode = SoftwareOneWayDataDiodeEmulator(emulator_id="emu:dev-diode")
    attempt_payload = diode.to_hardware_diode_attestation_attempt()

    # HardwareDiodeAttestation rejects SOFTWARE_EMULATOR prefix
    with pytest.raises(ZeroFalseConfidenceError, match="Software data diode emulator cannot masquerade"):
        HardwareDiodeAttestation(
            device_id=attempt_payload["device_id"],
            optical_wavelength_nm=1310,
            severed_reverse_channel=True,
            firmware_measurement=attempt_payload["firmware_measurement"],
        )

    # Even if somehow passed into TeslaCageSandbox with TIER_3_TESLA_CAGED, cage rejects it
    fake_hardware_diode = HardwareDiodeAttestation(
        device_id="diode:valid-physical-001",
        optical_wavelength_nm=1310,
        severed_reverse_channel=True,
        firmware_measurement=DIODE_EMULATOR_DISCLAIMER_DIGEST,
    )

    # Legitimate physical diode passes
    valid_cage = TeslaCageSandbox(
        tier=ContainmentTier.TIER_3_TESLA_CAGED,
        is_software_only=False,
        diode_attestation=fake_hardware_diode,
        relay_attestation=_sample_relay(),
        dram_zeroization_verified=True,
    )
    assert valid_cage.tier == ContainmentTier.TIER_3_TESLA_CAGED
