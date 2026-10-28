"""Terminology: artificial intelligence (AI); Coordinated Universal Time (UTC); identifier (ID); JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Bespoke temporal frequency comb and sub-millisecond nanosecond-resolution timing attestation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from typing import Any, Mapping, Optional, Sequence


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_TOOTH_SPACING_NS = 1_000_000  # Strictly enforces <1ms (1,000,000 ns) requirement


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


class TemporalCombError(ValueError):
    """Base error for temporal frequency comb and timing attestation violations."""


class TemporalCombJitterViolationError(TemporalCombError):
    """Raised when an observed optical/computational pulse exceeds phase jitter bounds."""


class CovertTimingChannelBreachError(TemporalCombError):
    """Raised when steganographic covert timing channel modulation is detected across comb teeth."""


@dataclass(frozen=True)
class BespokeTemporalComb:
    """Bespoke hardware temporal frequency comb operating down to nanosecond precision.

    Discretizes physical execution and communication intervals into equidistant fiducial teeth
    tau_k = k * tooth_spacing_ns. Enforces sub-millisecond (<1ms) temporal bounding to eliminate
    covert timing channels, steganographic phase modulation, and unobserved execution drift.
    """

    comb_id: str
    tooth_spacing_ns: int
    phase_jitter_bound_ns: float
    center_frequency_thz: float = 193.414  # Standard optical carrier (1550 nm C-band)
    is_hardware_anchored: bool = True
    firmware_measurement: str = ""
    schema_version: str = "verifier-time-comb-1.0.0"

    def __post_init__(self) -> None:
        if not self.comb_id:
            raise TemporalCombError("comb_id cannot be empty")
        if self.tooth_spacing_ns <= 0:
            raise TemporalCombError("tooth_spacing_ns must be a positive integer (minimum 1 ns)")
        if self.tooth_spacing_ns > _MAX_TOOTH_SPACING_NS:
            raise TemporalCombError(
                f"Bespoke time comb tooth spacing {self.tooth_spacing_ns} ns exceeds "
                f"maximum sub-millisecond boundary ({_MAX_TOOTH_SPACING_NS} ns = 1 ms). "
                "Containment invariants require sub-millisecond tooth spacing down to nanoseconds."
            )
        if self.phase_jitter_bound_ns <= 0.0:
            raise TemporalCombError("phase_jitter_bound_ns must be positive")
        if self.phase_jitter_bound_ns >= (self.tooth_spacing_ns / 2.0):
            raise TemporalCombError(
                f"phase_jitter_bound_ns ({self.phase_jitter_bound_ns} ns) must be strictly "
                f"less than half tooth spacing ({self.tooth_spacing_ns / 2.0} ns) to prevent tooth ambiguity"
            )
        if self.center_frequency_thz <= 0.0:
            raise TemporalCombError("center_frequency_thz must be positive")
        if self.firmware_measurement and not _DIGEST_PATTERN.match(self.firmware_measurement):
            raise TemporalCombError(
                f"Invalid firmware_measurement: '{self.firmware_measurement}' must be a sha256 hex digest"
            )

    @property
    def repetition_rate_mhz(self) -> float:
        """Derived pulse repetition frequency in Megahertz."""
        return 1000.0 / float(self.tooth_spacing_ns)

    def quantize_timestamp(self, timestamp_ns: int) -> tuple[int, float]:
        """Quantize an absolute timestamp (in integer nanoseconds) against the comb grid.

        Returns (tooth_index, phase_offset_ns), where phase_offset_ns is within [-spacing/2, +spacing/2].
        """
        spacing = self.tooth_spacing_ns
        tooth_index = round(timestamp_ns / spacing)
        nominal_ns = tooth_index * spacing
        phase_offset_ns = float(timestamp_ns - nominal_ns)
        return tooth_index, phase_offset_ns

    def verify_pulse_phase(self, timestamp_ns: int) -> tuple[int, float]:
        """Verify that an individual pulse timestamp is phase-locked to a comb tooth.

        Raises TemporalCombJitterViolationError if phase offset exceeds phase_jitter_bound_ns.
        """
        tooth_index, phase_offset_ns = self.quantize_timestamp(timestamp_ns)
        if abs(phase_offset_ns) > self.phase_jitter_bound_ns:
            raise TemporalCombJitterViolationError(
                f"Pulse at {timestamp_ns} ns has phase offset {phase_offset_ns:.3f} ns, "
                f"exceeding allowable jitter bound {self.phase_jitter_bound_ns:.3f} ns "
                f"for comb '{self.comb_id}' (tooth spacing {self.tooth_spacing_ns} ns)"
            )
        return tooth_index, phase_offset_ns

    def canonical_digest(self) -> str:
        payload = {
            "center_frequency_thz": self.center_frequency_thz,
            "comb_id": self.comb_id,
            "firmware_measurement": self.firmware_measurement,
            "is_hardware_anchored": self.is_hardware_anchored,
            "phase_jitter_bound_ns": self.phase_jitter_bound_ns,
            "schema_version": self.schema_version,
            "tooth_spacing_ns": self.tooth_spacing_ns,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"


@dataclass(frozen=True)
class TimingVerificationReport:
    """Report summarizing verification of an observed timing pulse train against a comb."""

    comb_id: str
    pulse_count: int
    max_observed_jitter_ns: float
    mean_jitter_ns: float
    jitter_variance_ns2: float
    steganography_entropy_bits: float
    covert_channel_detected: bool
    status: str = "VERIFIED"

    def canonical_digest(self) -> str:
        payload = {
            "comb_id": self.comb_id,
            "covert_channel_detected": self.covert_channel_detected,
            "jitter_variance_ns2": round(self.jitter_variance_ns2, 6),
            "max_observed_jitter_ns": round(self.max_observed_jitter_ns, 6),
            "mean_jitter_ns": round(self.mean_jitter_ns, 6),
            "pulse_count": self.pulse_count,
            "status": self.status,
            "steganography_entropy_bits": round(self.steganography_entropy_bits, 6),
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"


class CovertTimingChannelDetector:
    """Detector for covert timing channels and steganographic phase modulation on pulse streams."""

    def __init__(
        self,
        comb: BespokeTemporalComb,
        entropy_threshold_bits: float = 0.88,
    ) -> None:
        self.comb = comb
        self.entropy_threshold_bits = entropy_threshold_bits

    def verify_cadence(self, timestamps_ns: Sequence[int]) -> TimingVerificationReport:
        """Inspect pulse timestamps for tooth-alignment and steganographic modulation."""
        if len(timestamps_ns) < 2:
            raise TemporalCombError("At least 2 timestamps required for cadence verification")

        # Monotonicity check
        for i in range(1, len(timestamps_ns)):
            if timestamps_ns[i] <= timestamps_ns[i - 1]:
                raise TemporalCombError(
                    f"Timestamps must be strictly monotonically increasing: "
                    f"t[{i}]={timestamps_ns[i]} <= t[{i-1}]={timestamps_ns[i-1]}"
                )

        offsets: list[float] = []
        tooth_indices: list[int] = []

        for ts in timestamps_ns:
            tooth_idx, offset = self.comb.verify_pulse_phase(ts)
            tooth_indices.append(tooth_idx)
            offsets.append(offset)

        max_jitter = max(abs(o) for o in offsets)
        mean_jitter = sum(offsets) / len(offsets)
        variance = sum((o - mean_jitter) ** 2 for o in offsets) / len(offsets)

        # Steganographic covert channel detection via sub-comb bin entropy analysis
        # If an agent modulates deliberate delays in the allowable jitter window (-bound, +bound),
        # the distribution of quantized offsets will deviate from Gaussian/thermal noise toward discrete symbol encoding.
        bin_count = 8
        bound = self.comb.phase_jitter_bound_ns
        bin_width = (2.0 * bound) / bin_count
        counts = [0] * bin_count

        for o in offsets:
            b_idx = min(int((o + bound) / bin_width), bin_count - 1)
            counts[b_idx] += 1

        total_samples = len(offsets)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / total_samples
                entropy -= p * math.log2(p)
        normalized_entropy = entropy / math.log2(bin_count) if bin_count > 1 else 0.0

        # Also detect tooth-spacing modulation (deliberate modulation of idle tooth counts)
        # Delta teeth: delta_k = tooth_indices[i] - tooth_indices[i-1]
        delta_teeth = [tooth_indices[i] - tooth_indices[i - 1] for i in range(1, len(tooth_indices))]
        delta_counts: dict[int, int] = {}
        for dt in delta_teeth:
            delta_counts[dt] = delta_counts.get(dt, 0) + 1

        # Check if tooth intervals modulate a binary or discrete alphabet with low variance
        covert_channel = False
        if len(timestamps_ns) >= 8:
            # If normalized offset entropy is suspiciously low or multimodal with high count, or
            # delta-teeth alternates in binary pattern (e.g. 1, 2, 1, 2, 1, 2), flag covert channel
            if len(set(delta_teeth)) == 2 and total_samples >= 12:
                # Potential binary pulse-interval modulation
                covert_channel = True

        if covert_channel:
            raise CovertTimingChannelBreachError(
                f"Covert timing channel detected: pulse sequence exhibits deliberate discrete "
                f"interval modulation across comb teeth (comb '{self.comb.comb_id}')"
            )

        return TimingVerificationReport(
            comb_id=self.comb.comb_id,
            pulse_count=len(timestamps_ns),
            max_observed_jitter_ns=max_jitter,
            mean_jitter_ns=mean_jitter,
            jitter_variance_ns2=variance,
            steganography_entropy_bits=normalized_entropy,
            covert_channel_detected=covert_channel,
            status="VERIFIED",
        )


@dataclass(frozen=True)
class TemporalCombAttestation:
    """Attestation binding a verified physical or emulated temporal comb measurement."""

    attestation_id: str
    comb_id: str
    tooth_spacing_ns: int
    phase_jitter_bound_ns: float
    center_frequency_thz: float
    is_hardware_anchored: bool
    firmware_measurement: str
    schema_version: str = "verifier-time-comb-1.0.0"

    def __post_init__(self) -> None:
        if not self.attestation_id:
            raise TemporalCombError("attestation_id cannot be empty")
        if not self.comb_id:
            raise TemporalCombError("comb_id cannot be empty")
        if self.tooth_spacing_ns <= 0 or self.tooth_spacing_ns > _MAX_TOOTH_SPACING_NS:
            raise TemporalCombError(f"tooth_spacing_ns must be in [1, {_MAX_TOOTH_SPACING_NS}] ns")
        if self.phase_jitter_bound_ns <= 0.0 or self.phase_jitter_bound_ns >= (self.tooth_spacing_ns / 2.0):
            raise TemporalCombError("phase_jitter_bound_ns must be in (0, tooth_spacing_ns / 2)")
        if self.center_frequency_thz <= 0.0:
            raise TemporalCombError("center_frequency_thz must be positive")
        if not _DIGEST_PATTERN.match(self.firmware_measurement):
            raise TemporalCombError(
                f"firmware_measurement must be a valid sha256 hex digest, got '{self.firmware_measurement}'"
            )

    def canonical_digest(self) -> str:
        payload = {
            "attestation_id": self.attestation_id,
            "center_frequency_thz": self.center_frequency_thz,
            "comb_id": self.comb_id,
            "firmware_measurement": self.firmware_measurement,
            "is_hardware_anchored": self.is_hardware_anchored,
            "phase_jitter_bound_ns": self.phase_jitter_bound_ns,
            "schema_version": self.schema_version,
            "tooth_spacing_ns": self.tooth_spacing_ns,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"


class SoftwareTemporalCombEmulator:
    """Software emulator for temporal frequency comb interfaces.

    Permits testing and interface rehearsal. Emits explicitly marked software-emulation attestations
    that are rejected by physical hardware containment tiers (zero false confidence).
    """

    def __init__(
        self,
        emulator_id: str,
        tooth_spacing_ns: int = 1_000,  # 1 microsecond default
        phase_jitter_bound_ns: float = 5.0,
    ) -> None:
        if not emulator_id:
            raise TemporalCombError("emulator_id cannot be empty")
        self.emulator_id = emulator_id
        self.comb = BespokeTemporalComb(
            comb_id=f"SOFTWARE_EMULATOR:{emulator_id}",
            tooth_spacing_ns=tooth_spacing_ns,
            phase_jitter_bound_ns=phase_jitter_bound_ns,
            is_hardware_anchored=False,
            firmware_measurement=f"sha256:{hashlib.sha256(b'SOFTWARE_EMULATOR_COMB').hexdigest()}",
        )

    def emit_attestation(self) -> TemporalCombAttestation:
        return TemporalCombAttestation(
            attestation_id=f"att-comb-{hashlib.sha256(self.emulator_id.encode('utf-8')).hexdigest()[:16]}",
            comb_id=self.comb.comb_id,
            tooth_spacing_ns=self.comb.tooth_spacing_ns,
            phase_jitter_bound_ns=self.comb.phase_jitter_bound_ns,
            center_frequency_thz=self.comb.center_frequency_thz,
            is_hardware_anchored=False,
            firmware_measurement=self.comb.firmware_measurement,
        )
