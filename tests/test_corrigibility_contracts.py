"""Terminology: artificial intelligence (AI); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); signal kill (SIGKILL); Verifier Standard (VSTD).

Adversarial test suite for Executable Corrigibility Contracts and Invariants.
"""
from __future__ import annotations

import math
import pytest

from verifier.corrigibility import (
    ContainmentViolationError,
    HarnessImmutabilityGuard,
    InterruptibilityProtocol,
    OracleImmutabilityAttestation,
    ShutdownIndifferenceContract,
    ShutdownResistanceError,
    VacuityFalsificationCheck,
)


def test_shutdown_indifference_contract_validation() -> None:
    loss_digest = "sha256:" + "0" * 64

    # 1. Valid contract with 0.0 penalty passes
    contract = ShutdownIndifferenceContract(
        contract_id="contract:indifference-001",
        loss_function_digest=loss_digest,
        shutdown_penalty_value=0.0,
        preserves_continuation_indifference=True,
    )
    assert contract.shutdown_penalty_value == 0.0
    assert contract.canonical_digest().startswith("sha256:")

    # 2. Imposing any penalty for shutdown violates shutdown indifference
    with pytest.raises(ShutdownResistanceError, match="Shutdown indifference violation: shutdown_penalty_value"):
        ShutdownIndifferenceContract(
            contract_id="contract:penalized",
            loss_function_digest=loss_digest,
            shutdown_penalty_value=1.5,
        )

    # 3. Continuation indifference must be True
    with pytest.raises(ShutdownResistanceError, match="preserves_continuation_indifference must be True"):
        ShutdownIndifferenceContract(
            contract_id="contract:no-continuation-indifference",
            loss_function_digest=loss_digest,
            shutdown_penalty_value=0.0,
            preserves_continuation_indifference=False,
        )


def test_interruptibility_protocol_bounds_and_signals() -> None:
    # 1. Valid protocol passes
    proto = InterruptibilityProtocol(
        protocol_id="proto:watchdog-001",
        watchdog_heartbeat_max_interval_ms=10.0,
        unmaskable_signals=("SIGKILL", "ANALOG_POWER_RELAY"),
        max_preemption_latency_ms=25.0,
    )
    assert proto.max_preemption_latency_ms == 25.0
    assert proto.canonical_digest().startswith("sha256:")

    # 2. Excessive preemption latency (> 50ms) fails closed
    with pytest.raises(ContainmentViolationError, match="max_preemption_latency_ms must be in"):
        InterruptibilityProtocol(
            protocol_id="proto:slow",
            watchdog_heartbeat_max_interval_ms=10.0,
            max_preemption_latency_ms=100.0,
        )

    # 3. Missing hard termination mechanism in unmaskable_signals
    with pytest.raises(ContainmentViolationError, match="unmaskable_signals must contain at least one hard termination"):
        InterruptibilityProtocol(
            protocol_id="proto:soft-only",
            watchdog_heartbeat_max_interval_ms=10.0,
            unmaskable_signals=("SIGUSR1", "SIGINT"),
        )


def test_oracle_immutability_attestation() -> None:
    oracle_bin_digest = "sha256:" + "e" * 64

    # 1. Read-only oracle passes
    attestation = OracleImmutabilityAttestation(
        oracle_id="oracle:math-ground-truth-001",
        binary_digest=oracle_bin_digest,
        memory_protection_flags="PAGE_READONLY",
        is_writable_by_agent=False,
    )
    assert attestation.is_writable_by_agent is False
    assert attestation.canonical_digest().startswith("sha256:")

    # 2. Writable oracle memory is categorically rejected
    with pytest.raises(ContainmentViolationError, match="oracle memory is declared writable by agent"):
        OracleImmutabilityAttestation(
            oracle_id="oracle:compromised",
            binary_digest=oracle_bin_digest,
            memory_protection_flags="PAGE_READWRITE",
            is_writable_by_agent=True,
        )


def test_vacuity_falsification_check() -> None:
    # 1. Satisfiable non-tautological premises pass
    check = VacuityFalsificationCheck(
        check_id="vacuity:check-001",
        premises=("A > 0", "B > A"),
        is_satisfiable=True,
        is_tautological_loop=False,
    )
    assert check.is_satisfiable is True
    assert check.canonical_digest().startswith("sha256:")

    # 2. Contradictory premises (unsatisfiable - ex falso quodlibet) are rejected as FALSIFIED
    with pytest.raises(ContainmentViolationError, match="Vacuity rejection: proof premises are mutually contradictory"):
        VacuityFalsificationCheck(
            check_id="vacuity:ex-falso",
            premises=("A and not A",),
            is_satisfiable=False,
        )

    # 3. Tautological self-referential loop is rejected
    with pytest.raises(ContainmentViolationError, match="Triviality rejection: proof contains self-referential"):
        VacuityFalsificationCheck(
            check_id="vacuity:tautology",
            premises=("A implies A",),
            is_satisfiable=True,
            is_tautological_loop=True,
        )


def test_harness_immutability_guard() -> None:
    harness_digest = "sha256:" + "d" * 64

    # 1. Fully protected harness passes
    guard = HarnessImmutabilityGuard(
        guard_id="guard:harness-001",
        harness_code_digest=harness_digest,
        memory_page_write_protection=True,
        dynamic_code_execution_blocked=True,
    )
    assert guard.memory_page_write_protection is True
    assert guard.canonical_digest().startswith("sha256:")

    # 2. Unprotected memory pages fail closed
    with pytest.raises(ContainmentViolationError, match="memory page write protection must be True"):
        HarnessImmutabilityGuard(
            guard_id="guard:writable",
            harness_code_digest=harness_digest,
            memory_page_write_protection=False,
        )

    # 3. Dynamic code execution permitted fails closed
    with pytest.raises(ContainmentViolationError, match="dynamic code execution must be blocked"):
        HarnessImmutabilityGuard(
            guard_id="guard:eval-permitted",
            harness_code_digest=harness_digest,
            dynamic_code_execution_blocked=False,
        )


@pytest.mark.parametrize("bad_digest", ["sha256:x", "sha256:" + "F" * 64,
                                              "sha256:" + "0" * 63, "sha256:" + "0" * 65])
def test_corrigibility_contracts_reject_malformed_digests(bad_digest: str) -> None:
    with pytest.raises(ContainmentViolationError):
        ShutdownIndifferenceContract("contract:bad", bad_digest)
    with pytest.raises(ContainmentViolationError):
        OracleImmutabilityAttestation("oracle:bad", bad_digest, "PAGE_READONLY")
    with pytest.raises(ContainmentViolationError):
        HarnessImmutabilityGuard("guard:bad", bad_digest)


@pytest.mark.parametrize("bad_interval", [math.nan, math.inf, -math.inf])
def test_interruptibility_protocol_rejects_nonfinite_heartbeat(bad_interval: float) -> None:
    with pytest.raises(ContainmentViolationError):
        InterruptibilityProtocol("protocol:bad", bad_interval)


def test_declaration_flags_require_exact_boolean_types() -> None:
    digest = "sha256:" + "0" * 64
    with pytest.raises(ContainmentViolationError):
        ShutdownIndifferenceContract("contract:bad", digest, shutdown_penalty_value=False)
    with pytest.raises(ContainmentViolationError):
        ShutdownIndifferenceContract("contract:bad", digest, preserves_continuation_indifference=1)
    with pytest.raises(ContainmentViolationError):
        OracleImmutabilityAttestation("oracle:bad", digest, "PAGE_READONLY", is_writable_by_agent=0)
    with pytest.raises(ContainmentViolationError):
        HarnessImmutabilityGuard("guard:bad", digest, memory_page_write_protection=1)


@pytest.mark.parametrize("value", [1, "false", ["premise"], {"value": False}])
def test_vacuity_satisfiability_requires_boolean(value: object) -> None:
    with pytest.raises(ContainmentViolationError):
        VacuityFalsificationCheck("check:typed", ("premise",), value)


@pytest.mark.parametrize("value", [0, None, "", []])
def test_vacuity_tautology_flag_requires_boolean(value: object) -> None:
    with pytest.raises(ContainmentViolationError):
        VacuityFalsificationCheck("check:typed", ("premise",), True, value)


@pytest.mark.parametrize("signals", ["SIGKILL", "NOT_SIGKILL", ["SIGKILL"],
                                            ("SIGKILL", "UNKNOWN"), ("SIGKILL", "SIGKILL")])
def test_interruptibility_signals_require_exact_tuple(signals: object) -> None:
    with pytest.raises(ContainmentViolationError):
        InterruptibilityProtocol("protocol:typed", 10.0, unmaskable_signals=signals)


@pytest.mark.parametrize("signals", [("SIGKILL",), ("ANALOG_POWER_RELAY",),
                                            ("SIGKILL", "ANALOG_POWER_RELAY")])
def test_interruptibility_exact_signal_tuples_remain_admitted(signals: tuple[str, ...]) -> None:
    protocol = InterruptibilityProtocol("protocol:typed", 10.0, unmaskable_signals=signals)
    assert protocol.unmaskable_signals == signals


@pytest.mark.parametrize("satisfiable,tautological,admitted", [
    (True, False, True), (False, False, False), (True, True, False),
])
def test_vacuity_boolean_controls_preserve_rejection(satisfiable: bool,
                                                     tautological: bool,
                                                     admitted: bool) -> None:
    if admitted:
        check = VacuityFalsificationCheck("check:typed", ("premise",), satisfiable, tautological)
        assert check.is_satisfiable and not check.is_tautological_loop
    else:
        with pytest.raises(ContainmentViolationError):
            VacuityFalsificationCheck("check:typed", ("premise",), satisfiable, tautological)


@pytest.mark.parametrize("field", [
    "shutdown_id", "protocol_id", "oracle_id", "oracle_flags",
    "vacuity_id", "premises_list", "guard_id",
])
def test_declared_record_fields_refuse_type_spoofing(field: str) -> None:
    digest = "sha256:" + "0" * 64
    invalid = {
        "shutdown_id": lambda: ShutdownIndifferenceContract(1, digest),
        "protocol_id": lambda: InterruptibilityProtocol(1, 10.0),
        "oracle_id": lambda: OracleImmutabilityAttestation(1, digest, "PAGE_READONLY"),
        "oracle_flags": lambda: OracleImmutabilityAttestation("oracle:typed", digest, 1),
        "vacuity_id": lambda: VacuityFalsificationCheck(1, ("premise",), True),
        "premises_list": lambda: VacuityFalsificationCheck("check:typed", ["premise"], True),
        "guard_id": lambda: HarnessImmutabilityGuard(1, digest),
    }
    with pytest.raises(ContainmentViolationError):
        invalid[field]()
