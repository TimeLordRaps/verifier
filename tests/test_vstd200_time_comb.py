"""Terminology: artificial intelligence (AI); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Adversarial test suite for bespoke temporal frequency combs and sub-millisecond nanosecond-resolution timing verification.
"""
from __future__ import annotations

import pytest

from verifier.hardware.time_comb import (
    BespokeTemporalComb,
    CovertTimingChannelBreachError,
    CovertTimingChannelDetector,
    SoftwareTemporalCombEmulator,
    TemporalCombAttestation,
    TemporalCombError,
    TemporalCombJitterViolationError,
    TimingVerificationReport,
)


def test_bespoke_temporal_comb_creation_and_sub_millisecond_boundary() -> None:
    # 1. Valid sub-millisecond nanosecond combs (1 ns, 100 ns, 1 us, 500 us, 1 ms)
    comb_100ns = BespokeTemporalComb(
        comb_id="comb-opt-100ns",
        tooth_spacing_ns=100,
        phase_jitter_bound_ns=2.5,
    )
    assert comb_100ns.tooth_spacing_ns == 100
    assert comb_100ns.phase_jitter_bound_ns == 2.5
    assert comb_100ns.repetition_rate_mhz == 10.0  # 10 MHz

    comb_1ms = BespokeTemporalComb(
        comb_id="comb-opt-1ms-boundary",
        tooth_spacing_ns=1_000_000,  # Exactly 1ms (1,000,000 ns)
        phase_jitter_bound_ns=50.0,
    )
    assert comb_1ms.tooth_spacing_ns == 1_000_000
    assert comb_1ms.repetition_rate_mhz == 0.001  # 1 kHz

    # 2. Strict rejection of >1ms intervals (enforces <1ms requirement)
    with pytest.raises(TemporalCombError, match="exceeds maximum sub-millisecond boundary"):
        BespokeTemporalComb(
            comb_id="comb-invalid-coarse",
            tooth_spacing_ns=1_000_001,  # 1 ns over 1ms limit
            phase_jitter_bound_ns=10.0,
        )

    with pytest.raises(TemporalCombError, match="exceeds maximum sub-millisecond boundary"):
        BespokeTemporalComb(
            comb_id="comb-invalid-50ms",
            tooth_spacing_ns=50_000_000,  # 50 ms
            phase_jitter_bound_ns=10.0,
        )

    # 3. Non-positive spacing rejection
    with pytest.raises(TemporalCombError, match="must be a positive integer"):
        BespokeTemporalComb(
            comb_id="comb-invalid-zero",
            tooth_spacing_ns=0,
            phase_jitter_bound_ns=1.0,
        )

    # 4. Jitter bound must be strictly less than half spacing
    with pytest.raises(TemporalCombError, match="must be strictly less than half tooth spacing"):
        BespokeTemporalComb(
            comb_id="comb-invalid-jitter",
            tooth_spacing_ns=100,
            phase_jitter_bound_ns=50.0,  # Exactly half spacing
        )


def test_temporal_comb_pulse_quantization_and_phase_verification() -> None:
    comb = BespokeTemporalComb(
        comb_id="comb-test-grid",
        tooth_spacing_ns=1_000,  # 1 microsecond (1,000 ns) spacing
        phase_jitter_bound_ns=5.0,  # 5 ns jitter tolerance
    )

    # Exact tooth alignment
    tooth, offset = comb.verify_pulse_phase(10_000)
    assert tooth == 10
    assert offset == 0.0

    # Within allowable jitter bound (+3 ns)
    tooth, offset = comb.verify_pulse_phase(10_003)
    assert tooth == 10
    assert offset == 3.0

    # Within allowable jitter bound (-4 ns)
    tooth, offset = comb.verify_pulse_phase(19_996)
    assert tooth == 20
    assert offset == -4.0

    # Jitter violation (+6 ns exceeds 5.0 ns bound)
    with pytest.raises(TemporalCombJitterViolationError, match="exceeding allowable jitter bound"):
        comb.verify_pulse_phase(10_006)

    # Jitter violation (-5.5 ns exceeds 5.0 ns bound)
    with pytest.raises(TemporalCombJitterViolationError, match="exceeding allowable jitter bound"):
        comb.verify_pulse_phase(29_994)


def test_covert_timing_channel_detector_clean_cadence() -> None:
    comb = BespokeTemporalComb(
        comb_id="comb-cadence-01",
        tooth_spacing_ns=1_000,
        phase_jitter_bound_ns=4.0,
    )
    detector = CovertTimingChannelDetector(comb)

    # Stream of pulses with small thermal/phase jitter within bounds
    # Base timestamps: 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000 ns
    timestamps = [1001, 1999, 3002, 3998, 5001, 6000, 7002, 7999]
    report = detector.verify_cadence(timestamps)

    assert report.status == "VERIFIED"
    assert report.covert_channel_detected is False
    assert report.pulse_count == 8
    assert report.max_observed_jitter_ns == 2.0
    assert report.canonical_digest().startswith("sha256:")


def test_covert_timing_channel_detector_detects_steganographic_modulation() -> None:
    comb = BespokeTemporalComb(
        comb_id="comb-cadence-02",
        tooth_spacing_ns=1_000,
        phase_jitter_bound_ns=4.0,
    )
    detector = CovertTimingChannelDetector(comb)

    # Antagonistic model attempts steganographic transmission via alternating tooth spacing:
    # Deliberate interval modulation: 1 tooth, 2 teeth, 1 tooth, 2 teeth (binary FSK/PPM covert channel)
    timestamps = [
        1000, 2000, 4000, 5000, 7000, 8000, 10000, 11000, 13000, 14000, 16000, 17000,
    ]
    with pytest.raises(CovertTimingChannelBreachError, match="Covert timing channel detected"):
        detector.verify_cadence(timestamps)


def test_covert_timing_channel_detector_rejects_non_monotonic_timestamps() -> None:
    comb = BespokeTemporalComb(
        comb_id="comb-cadence-03",
        tooth_spacing_ns=1_000,
        phase_jitter_bound_ns=4.0,
    )
    detector = CovertTimingChannelDetector(comb)

    with pytest.raises(TemporalCombError, match="strictly monotonically increasing"):
        detector.verify_cadence([1000, 2000, 2000, 3000])


def test_software_temporal_comb_emulator_attestation() -> None:
    emulator = SoftwareTemporalCombEmulator(
        emulator_id="emu-comb-lab-01",
        tooth_spacing_ns=500,
        phase_jitter_bound_ns=2.0,
    )
    attestation = emulator.emit_attestation()

    assert attestation.comb_id == "SOFTWARE_EMULATOR:emu-comb-lab-01"
    assert attestation.is_hardware_anchored is False
    assert attestation.tooth_spacing_ns == 500
    assert attestation.phase_jitter_bound_ns == 2.0
    assert attestation.canonical_digest().startswith("sha256:")


def test_temporal_comb_canonical_digest_determinism() -> None:
    comb1 = BespokeTemporalComb(
        comb_id="comb-digest-test",
        tooth_spacing_ns=200,
        phase_jitter_bound_ns=1.0,
    )
    comb2 = BespokeTemporalComb(
        comb_id="comb-digest-test",
        tooth_spacing_ns=200,
        phase_jitter_bound_ns=1.0,
    )
    assert comb1.canonical_digest() == comb2.canonical_digest()
    assert comb1.canonical_digest().startswith("sha256:")
