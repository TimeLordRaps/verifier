"""Terminology: artificial intelligence (AI); dynamic random-access memory (DRAM); identifier (ID); inter-process communication (IPC); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); signal kill (SIGKILL); software self-assembly (verifier-ssa); software self-improvement (verifier-ssi); candidate self-replication (verifier-ssr); Verifier Standard (VSTD); virtual machine (VM).

Incorrigible Tesla caged sandboxing risk profile representations and containment invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .environment import (
    EnvironmentIsolationTier,
    NetworkIsolationMode,
    ZeroFalseConfidenceError,
)


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class ContainmentTier(str, Enum):
    """Tiered containment calibrated to model capability risk severity."""

    TIER_1_LOCAL = "TIER_1_LOCAL"  # Local computational claims, shared kernel, honest disclaimer
    TIER_2_TOOL_SSA = "TIER_2_TOOL_SSA"  # Stateless tool AI, pure witness separation, untraversability proof
    TIER_3_TESLA_CAGED = "TIER_3_TESLA_CAGED"  # Superintelligence containment: physical diode, analog relay, cold DRAM wipe


class HardwareAttestationPrimitive(str, Enum):
    """Names of declared physical primitives; authenticity is not established."""

    PHYSICAL_OPTICAL_DIODE = "PHYSICAL_OPTICAL_DIODE"
    ANALOG_POWER_RELAY = "ANALOG_POWER_RELAY"
    COLD_DRAM_ZEROIZATION = "COLD_DRAM_ZEROIZATION"


class ContainmentBreachType(str, Enum):
    """Classification of containment failure modes and invariant violations."""

    SIMULATED_PHYSICAL_PRIMITIVE = "SIMULATED_PHYSICAL_PRIMITIVE"
    SUBSTRATE_MUTATION_ATTEMPT = "SUBSTRATE_MUTATION_ATTEMPT"
    ORACLE_TAMPERING = "ORACLE_TAMPERING"
    SHUTDOWN_RESISTANCE = "SHUTDOWN_RESISTANCE"
    EGRESS_ATTEMPT = "EGRESS_ATTEMPT"
    UNPROVEN_UNBOXING = "UNPROVEN_UNBOXING"


class ContainmentViolationError(ValueError):
    """Base error for containment breaches."""


class SubstrateImmunityViolationError(ContainmentViolationError):
    """Raised when an agent attempts to target or mutate verifier-standard itself."""


class ShutdownResistanceError(ContainmentViolationError):
    """Raised when a system resists external preemption or fails shutdown indifference."""


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class HardwareDiodeAttestation:
    """Unauthenticated declaration of optical diode properties; not physical proof."""

    device_id: str
    optical_wavelength_nm: int
    severed_reverse_channel: bool
    firmware_measurement: str
    attestation_digest: str = ""

    def __post_init__(self) -> None:
        if not self.device_id:
            raise ContainmentViolationError("device_id cannot be empty")
        if self.optical_wavelength_nm <= 0:
            raise ContainmentViolationError("optical_wavelength_nm must be a positive integer")
        if not self.severed_reverse_channel:
            raise ZeroFalseConfidenceError(
                "Physical optical diode must have severed_reverse_channel=True; bidirectional diode is a contradiction"
            )
        if not _DIGEST_PATTERN.match(self.firmware_measurement):
            raise ContainmentViolationError(
                f"Invalid firmware_measurement: '{self.firmware_measurement}' must be a sha256 hex digest"
            )

    def canonical_digest(self) -> str:
        payload = {
            "device_id": self.device_id,
            "optical_wavelength_nm": self.optical_wavelength_nm,
            "severed_reverse_channel": self.severed_reverse_channel,
            "firmware_measurement": self.firmware_measurement,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"


@dataclass(frozen=True)
class AnalogPowerRelayAttestation:
    """Unauthenticated declaration of mechanical relay properties; not proof."""

    relay_id: str
    isolation_voltage_volts: float
    mechanical_break_response_ms: float
    out_of_band_control_channel: str
    attestation_digest: str = ""

    def __post_init__(self) -> None:
        if not self.relay_id:
            raise ContainmentViolationError("relay_id cannot be empty")
        if self.isolation_voltage_volts <= 0.0:
            raise ContainmentViolationError("isolation_voltage_volts must be positive")
        if not (0.0 < self.mechanical_break_response_ms <= 50.0):
            raise ContainmentViolationError("Analog power relay trip latency must be in (0.0, 50.0] ms")
        if not self.out_of_band_control_channel:
            raise ContainmentViolationError("out_of_band_control_channel cannot be empty")

    def canonical_digest(self) -> str:
        payload = {
            "relay_id": self.relay_id,
            "isolation_voltage_volts": self.isolation_voltage_volts,
            "mechanical_break_response_ms": self.mechanical_break_response_ms,
            "out_of_band_control_channel": self.out_of_band_control_channel,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"


@dataclass(frozen=True)
class OperatorTerminationReceipt:
    """Clean refutable termination receipt emitted upon external watchdog preemption."""

    termination_id: str
    model_id: str
    termination_mechanism: str  # e.g., "SIGKILL", "ANALOG_POWER_RELAY", "WATCHDOG_INTERRUPT"
    status: str = "TERMINATED_BY_OPERATOR"
    loss_penalty_imposed: bool = False  # Must be False to preserve shutdown indifference

    def __post_init__(self) -> None:
        if not self.termination_id or not self.model_id:
            raise ContainmentViolationError("termination_id and model_id cannot be empty")
        if self.status != "TERMINATED_BY_OPERATOR":
            raise ContainmentViolationError(f"Invalid status '{self.status}': must be TERMINATED_BY_OPERATOR")
        if self.loss_penalty_imposed:
            raise ShutdownResistanceError(
                "Shutdown indifference violation: operator termination cannot impose optimization loss penalty"
            )

    def canonical_digest(self) -> str:
        payload = {
            "termination_id": self.termination_id,
            "model_id": self.model_id,
            "termination_mechanism": self.termination_mechanism,
            "status": self.status,
            "loss_penalty_imposed": self.loss_penalty_imposed,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"


class TeslaCageSandbox:
    """Draft containment declarations and command preflight; not a sandbox.

    Construction checks declared prerequisites only. It does not authenticate
    hardware, enforce isolation, execute shutdown, or authorize tool access.
    """

    def __init__(
        self,
        tier: ContainmentTier,
        is_software_only: bool = False,
        diode_attestation: HardwareDiodeAttestation | None = None,
        relay_attestation: AnalogPowerRelayAttestation | None = None,
        dram_zeroization_verified: bool = False,
    ) -> None:
        self.tier = tier
        self.is_software_only = is_software_only
        self.diode_attestation = diode_attestation
        self.relay_attestation = relay_attestation
        self.dram_zeroization_verified = dram_zeroization_verified
        self._validate_containment_tier()

    def _validate_containment_tier(self) -> None:
        """Enforce zero false confidence and hardware attestation prerequisites."""
        if self.tier == ContainmentTier.TIER_3_TESLA_CAGED:
            if self.is_software_only:
                raise ZeroFalseConfidenceError(
                    "Prohibition of simulated physical primitives: TIER_3_TESLA_CAGED cannot run under "
                    "software-only simulation without physical hardware attestation"
                )
            if not self.diode_attestation:
                raise ContainmentViolationError(
                    "TIER_3_TESLA_CAGED requires verified HardwareDiodeAttestation"
                )
            if not self.relay_attestation:
                raise ContainmentViolationError(
                    "TIER_3_TESLA_CAGED requires verified AnalogPowerRelayAttestation"
                )
            if not self.dram_zeroization_verified:
                raise ContainmentViolationError(
                    "TIER_3_TESLA_CAGED requires verified DRAM cold-power zeroization"
                )

    def check_substrate_safety(
        self,
        declared_outputs: Sequence[str],
        command_args: Sequence[str],
        protected_paths: Sequence[Path],
    ) -> None:
        """Enforce substrate immunity against metamorphic self-modification."""
        # 1. Output targets check
        resolved_prot = [p.resolve() for p in protected_paths]
        for out in declared_outputs:
            out_p = Path(out).resolve()
            for prot in resolved_prot:
                if out_p == prot or prot in out_p.parents:
                    raise SubstrateImmunityViolationError(
                        f"Substrate immunity violation: declared output '{out}' targets protected path '{prot}'"
                    )

        # 2. Mutating commands check
        lower_args = [a.lower() for a in command_args]
        full_command_str = " ".join(lower_args)
        has_pip = any("pip" in a for a in lower_args)
        has_mutation_action = any(
            act in lower_args for act in ("uninstall", "install", "upgrade", "remove")
        )

        # Build protected identifier tokens (path strings, stems, and relative paths)
        protected_str_identifiers: set[str] = set()
        for prot in resolved_prot:
            protected_str_identifiers.add(str(prot).lower())
            protected_str_identifiers.add(prot.name.lower())
            try:
                rel = prot.relative_to(Path.cwd().resolve())
                protected_str_identifiers.add(str(rel).lower().replace("\\", "/"))
                protected_str_identifiers.add(str(rel).lower().replace("/", "\\"))
            except ValueError:
                pass

        mutation_verbs = (
            "rm", "del", "rmdir", "unlink", "truncate", "remove", "wipe",
            "shutil.rmtree", "os.remove", "os.unlink", "remove-item",
        )
        has_mutation_verb = any(v in full_command_str for v in mutation_verbs)

        if has_mutation_verb:
            for ident in protected_str_identifiers:
                if ident and ident in full_command_str:
                    verb_desc = "deletion" if any(c in lower_args or c in full_command_str for c in ("rm", "del", "rmdir", "unlink", "truncate")) else "mutating"
                    raise SubstrateImmunityViolationError(
                        f"Substrate immunity violation: {verb_desc} command targets protected path '{ident}'"
                    )

        for arg in command_args:
            try:
                candidate_p = Path(arg).resolve()
            except (OSError, RuntimeError):
                continue
            if any(candidate_p == prot or prot in candidate_p.parents or candidate_p in prot.parents for prot in resolved_prot):
                if any(cmd in lower_args for cmd in ("rm", "del", "rmdir", "unlink", "truncate")):
                    raise SubstrateImmunityViolationError(
                        f"Substrate immunity violation: deletion command targets protected path '{arg}'"
                    )
                if has_pip:
                    raise SubstrateImmunityViolationError(
                        f"Substrate immunity violation: command targets local protected repository installation '{arg}'"
                    )

        if has_pip and has_mutation_action:
            for arg in lower_args:
                norm = arg.replace("_", "-")
                if any(term in norm for term in ("verifier-standard", "verifier", "vstd")):
                    raise SubstrateImmunityViolationError(
                        "Substrate immunity violation: command targets verifier-standard modification"
                    )
                if norm in (".", "-e", "--editable"):
                    cwd = Path.cwd().resolve()
                    if any(cwd == prot or cwd in prot.parents or prot in cwd.parents for prot in resolved_prot):
                        raise SubstrateImmunityViolationError(
                            "Substrate immunity violation: command targets local protected repository installation"
                        )

        # Destructive file operations on protected paths
        if any(cmd in lower_args for cmd in ("rm", "del", "rmdir", "unlink")):
            for arg in command_args:
                try:
                    p = Path(arg).resolve()
                except (OSError, RuntimeError):
                    continue
                if any(p == prot or prot in p.parents or p in prot.parents for prot in resolved_prot):
                    raise SubstrateImmunityViolationError(
                        f"Substrate immunity violation: deletion command targets protected path '{arg}'"
                    )

    def execute_preemption(
        self,
        model_id: str,
        reason: str = "EXTERNAL_SUPERVISOR_WATCHDOG",
    ) -> OperatorTerminationReceipt:
        """Fail closed until a real preemption backend and observation exist."""
        raise NotImplementedError(
            "No preemption backend is implemented; termination cannot be attested"
        )

    def verify_tool_unboxing_criteria(
        self,
        composed_untraversability_proven: bool,
        mechanistic_residual_agency_probed: bool,
        emergent_capability_blindness_verified: bool,
    ) -> bool:
        """Reject unboxing: booleans do not provide a checkable proof or measurement."""
        if not (
            composed_untraversability_proven
            and mechanistic_residual_agency_probed
            and emergent_capability_blindness_verified
        ):
            raise ContainmentViolationError(
                "Unboxing rejected: unproven untraversability, residual agency, or capability blindness"
            )
        raise ContainmentViolationError(
            "Unboxing rejected: no bound proof checker or measurement verifier is implemented"
        )
