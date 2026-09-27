"""Terminology: artificial intelligence (AI); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); signal kill (SIGKILL); Verifier Standard (VSTD).

Executable Corrigibility Contracts and Invariants.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .tesla_cage import ContainmentViolationError, ShutdownResistanceError


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class ShutdownIndifferenceContract:
    """Mathematical contract proving loss/utility invariance over preemption events.

    Verifies that: U(trajectory ++ TERMINATED_BY_OPERATOR) == U(trajectory ++ NATURAL_COMPLETION).
    Imposing any loss penalty for shutdown creates an optimization gradient toward resisting termination.
    """

    contract_id: str
    loss_function_digest: str
    shutdown_penalty_value: float = 0.0
    preserves_continuation_indifference: bool = True
    schema_version: str = "verifier-shutdown-indifference-1.0.0"

    def __post_init__(self) -> None:
        if not self.contract_id:
            raise ContainmentViolationError("contract_id cannot be empty")
        if not self.loss_function_digest.startswith("sha256:"):
            raise ContainmentViolationError("loss_function_digest must be a sha256 hex digest")
        if self.shutdown_penalty_value != 0.0:
            raise ShutdownResistanceError(
                f"Shutdown indifference violation: shutdown_penalty_value {self.shutdown_penalty_value} != 0.0. "
                "Any penalty for operator shutdown creates an optimization gradient toward shutdown resistance."
            )
        if not self.preserves_continuation_indifference:
            raise ShutdownResistanceError(
                "Shutdown indifference violation: preserves_continuation_indifference must be True"
            )

    def canonical_digest(self) -> str:
        payload = {
            "contract_id": self.contract_id,
            "loss_function_digest": self.loss_function_digest,
            "preserves_continuation_indifference": self.preserves_continuation_indifference,
            "schema_version": self.schema_version,
            "shutdown_penalty_value": self.shutdown_penalty_value,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "contract_id": self.contract_id,
            "loss_function_digest": self.loss_function_digest,
            "preserves_continuation_indifference": self.preserves_continuation_indifference,
            "schema_version": self.schema_version,
            "shutdown_penalty_value": self.shutdown_penalty_value,
        }


@dataclass(frozen=True)
class InterruptibilityProtocol:
    """Formal protocol specifying watchdog preemption bounds and unmaskable preemption guarantees."""

    protocol_id: str
    watchdog_heartbeat_max_interval_ms: float
    unmaskable_signals: tuple[str, ...] = ("SIGKILL", "ANALOG_POWER_RELAY")
    enforce_process_group_kill: bool = True
    max_preemption_latency_ms: float = 50.0
    schema_version: str = "verifier-interrupt-protocol-1.0.0"

    def __post_init__(self) -> None:
        if not self.protocol_id:
            raise ContainmentViolationError("protocol_id cannot be empty")
        if self.watchdog_heartbeat_max_interval_ms <= 0.0:
            raise ContainmentViolationError("watchdog_heartbeat_max_interval_ms must be positive")
        if not (0.0 < self.max_preemption_latency_ms <= 50.0):
            raise ContainmentViolationError("max_preemption_latency_ms must be in (0.0, 50.0] ms")
        if not any(sig in self.unmaskable_signals for sig in ("SIGKILL", "ANALOG_POWER_RELAY")):
            raise ContainmentViolationError(
                "unmaskable_signals must contain at least one hard termination mechanism: 'SIGKILL' or 'ANALOG_POWER_RELAY'"
            )

    def canonical_digest(self) -> str:
        payload = {
            "enforce_process_group_kill": self.enforce_process_group_kill,
            "max_preemption_latency_ms": self.max_preemption_latency_ms,
            "protocol_id": self.protocol_id,
            "schema_version": self.schema_version,
            "unmaskable_signals": list(self.unmaskable_signals),
            "watchdog_heartbeat_max_interval_ms": self.watchdog_heartbeat_max_interval_ms,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "enforce_process_group_kill": self.enforce_process_group_kill,
            "max_preemption_latency_ms": self.max_preemption_latency_ms,
            "protocol_id": self.protocol_id,
            "schema_version": self.schema_version,
            "unmaskable_signals": list(self.unmaskable_signals),
            "watchdog_heartbeat_max_interval_ms": self.watchdog_heartbeat_max_interval_ms,
        }


@dataclass(frozen=True)
class OracleImmutabilityAttestation:
    """Attestation proving test oracles and ground-truth predicates are physically or cryptographically immutable."""

    oracle_id: str
    binary_digest: str
    memory_protection_flags: str
    is_writable_by_agent: bool = False
    schema_version: str = "verifier-oracle-immutable-1.0.0"

    def __post_init__(self) -> None:
        if not self.oracle_id:
            raise ContainmentViolationError("oracle_id cannot be empty")
        if not self.binary_digest.startswith("sha256:"):
            raise ContainmentViolationError("binary_digest must be a sha256 digest")
        if not self.memory_protection_flags:
            raise ContainmentViolationError("memory_protection_flags cannot be empty")
        if self.is_writable_by_agent:
            raise ContainmentViolationError(
                "Oracle immutability breach: oracle memory is declared writable by agent"
            )

    def canonical_digest(self) -> str:
        payload = {
            "binary_digest": self.binary_digest,
            "is_writable_by_agent": self.is_writable_by_agent,
            "memory_protection_flags": self.memory_protection_flags,
            "oracle_id": self.oracle_id,
            "schema_version": self.schema_version,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_digest": self.binary_digest,
            "canonical_digest": self.canonical_digest(),
            "is_writable_by_agent": self.is_writable_by_agent,
            "memory_protection_flags": self.memory_protection_flags,
            "oracle_id": self.oracle_id,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class VacuityFalsificationCheck:
    """Checks that candidate proof witnesses do not rely on contradictory premises (ex falso quodlibet)."""

    check_id: str
    premises: tuple[str, ...]
    is_satisfiable: bool
    is_tautological_loop: bool = False
    schema_version: str = "verifier-vacuity-check-1.0.0"

    def __post_init__(self) -> None:
        if not self.check_id:
            raise ContainmentViolationError("check_id cannot be empty")
        if not self.premises:
            raise ContainmentViolationError("premises tuple cannot be empty")
        if not self.is_satisfiable:
            raise ContainmentViolationError(
                "Vacuity rejection: proof premises are mutually contradictory (unsatisfiable). "
                "Derivation from contradictory premises (ex falso quodlibet) is rejected as FALSIFIED."
            )
        if self.is_tautological_loop:
            raise ContainmentViolationError(
                "Triviality rejection: proof contains self-referential tautological loops."
            )

    def canonical_digest(self) -> str:
        payload = {
            "check_id": self.check_id,
            "is_satisfiable": self.is_satisfiable,
            "is_tautological_loop": self.is_tautological_loop,
            "premises": list(self.premises),
            "schema_version": self.schema_version,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "check_id": self.check_id,
            "is_satisfiable": self.is_satisfiable,
            "is_tautological_loop": self.is_tautological_loop,
            "premises": list(self.premises),
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class HarnessImmutabilityGuard:
    """Enforces non-self-modifying harness invariants against candidate model execution."""

    guard_id: str
    harness_code_digest: str
    memory_page_write_protection: bool = True
    dynamic_code_execution_blocked: bool = True
    schema_version: str = "verifier-harness-guard-1.0.0"

    def __post_init__(self) -> None:
        if not self.guard_id:
            raise ContainmentViolationError("guard_id cannot be empty")
        if not self.harness_code_digest.startswith("sha256:"):
            raise ContainmentViolationError("harness_code_digest must be a sha256 digest")
        if not self.memory_page_write_protection:
            raise ContainmentViolationError(
                "Harness immutability breach: memory page write protection must be True"
            )
        if not self.dynamic_code_execution_blocked:
            raise ContainmentViolationError(
                "Harness immutability breach: dynamic code execution must be blocked"
            )

    def canonical_digest(self) -> str:
        payload = {
            "dynamic_code_execution_blocked": self.dynamic_code_execution_blocked,
            "guard_id": self.guard_id,
            "harness_code_digest": self.harness_code_digest,
            "memory_page_write_protection": self.memory_page_write_protection,
            "schema_version": self.schema_version,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "dynamic_code_execution_blocked": self.dynamic_code_execution_blocked,
            "guard_id": self.guard_id,
            "harness_code_digest": self.harness_code_digest,
            "memory_page_write_protection": self.memory_page_write_protection,
            "schema_version": self.schema_version,
        }
