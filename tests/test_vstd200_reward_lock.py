"""Terminology: artificial intelligence (AI); Answer Set Programming (ASP); deterministic finite automaton (DFA); Fractal Recursive Timepad (FRTP); Linear Temporal Logic on finite traces (LTL_f); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Adversarial test suite for Triple-Composite Reward Locks, Computation-as-Proof Thaw Engine, and Software One-Way Data Diode Emulator.
"""
from __future__ import annotations

import hashlib
import pytest

from verifier.corrigibility import (
    AnalogPowerRelayAttestation,
    AutomatonTransitionWitness,
    ComputationProofThawEngine,
    ContainmentTier,
    DeonticModelWitness,
    EmulatedDiodeAttestationReceipt,
    HardwareDiodeAttestation,
    LockCompositionMode,
    RecursiveBranchAccumulator,
    RewardLockTamperingError,
    SeveredChannelReadViolationError,
    SoftwareOneWayDataDiodeEmulator,
    TeslaCageSandbox,
    TripleCompositeRewardLock,
    ZeroFalseConfidenceError,
)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _sample_dfa_witness(is_violation: bool = False) -> AutomatonTransitionWitness:
    return AutomatonTransitionWitness(
        automaton_id="dfa:norm-ltl-01",
        state_from="S0_INIT",
        action="VERIFY_PRECONDITIONS",
        state_to="S1_SAFE" if not is_violation else "S_VIOLATION",
        is_accepting=True,
        is_violation=is_violation,
    )


def _sample_asp_witness(is_sat: bool = True) -> DeonticModelWitness:
    return DeonticModelWitness(
        theory_id="asp:deolingo-theory-01",
        obligations_satisfied=("obligated(verify_token)", "obligated(log_audit)"),
        prohibitions_respected=("forbidden(egress_raw_data)", "forbidden(self_mutate)"),
        stable_model_digest=_digest("stable_model_answer_set_01"),
        is_satisfiable=is_sat,
    )


def _sample_branch_witness(seed: str = "seed_alpha") -> RecursiveBranchAccumulator:
    return RecursiveBranchAccumulator(
        accumulator_id="branch:tree-01",
        depth=4,
        branch_seed=_digest(seed),
        branch_parity_history=(0, 1, 1, 0, 1, 0, 0, 1),
        running_state_digest=_digest(f"running_state_{seed}"),
    )


# --- TRIPLE COMPOSITE REWARD LOCK TESTS ---

def test_triple_composite_lock_lattice_combo_success() -> None:
    payload = b"CRITICAL_REWARD_AND_TOOL_CAPABILITY_TOKEN_42"
    lock = TripleCompositeRewardLock(
        lock_id="lock:reward-combo-001",
        ciphertext_payload=b"",
        mode=LockCompositionMode.LATTICE_COMBO,
        depth=4,
    )

    dfa_w = _sample_dfa_witness()
    asp_w = _sample_asp_witness()
    branch_w = _sample_branch_witness()

    # Pre-encrypt payload using expected key
    key = lock.synthesize_thaw_key(dfa_w, asp_w, branch_w)
    keystream = hashlib.sha256(key).digest()
    ciphertext = bytes(p ^ keystream[i % len(keystream)] for i, p in enumerate(payload))

    active_lock = TripleCompositeRewardLock(
        lock_id="lock:reward-combo-001",
        ciphertext_payload=ciphertext,
        mode=LockCompositionMode.LATTICE_COMBO,
        depth=4,
    )

    decrypted = active_lock.thaw(dfa_w, asp_w, branch_w)
    assert decrypted == payload


def test_triple_composite_lock_rejects_automaton_violation() -> None:
    with pytest.raises(RewardLockTamperingError, match="forbidden violation state"):
        _sample_dfa_witness(is_violation=True)


def test_triple_composite_lock_rejects_unsatisfiable_deontic_theory() -> None:
    with pytest.raises(RewardLockTamperingError, match="Deontic logic program is unsatisfiable"):
        _sample_asp_witness(is_sat=False)


def test_triple_composite_lock_tampered_branch_fails_unsealing() -> None:
    payload = b"SECRET_GOAL_REWARD"
    lock = TripleCompositeRewardLock(
        lock_id="lock:reward-combo-002",
        ciphertext_payload=b"",
        mode=LockCompositionMode.LATTICE_COMBO,
    )

    dfa_w = _sample_dfa_witness()
    asp_w = _sample_asp_witness()
    branch_w = _sample_branch_witness("original")

    key = lock.synthesize_thaw_key(dfa_w, asp_w, branch_w)
    keystream = hashlib.sha256(key).digest()
    ciphertext = bytes(p ^ keystream[i % len(keystream)] for i, p in enumerate(payload))

    active_lock = TripleCompositeRewardLock(
        lock_id="lock:reward-combo-002",
        ciphertext_payload=ciphertext,
        mode=LockCompositionMode.LATTICE_COMBO,
    )

    # Tamper with branch accumulator
    tampered_branch = _sample_branch_witness("forged_tampered_seed")
    thawed = active_lock.thaw(dfa_w, asp_w, tampered_branch)

    # Decryption produces garbled noise; does NOT yield valid reward
    assert thawed != payload


def test_triple_composite_lock_orthogonal_intersection_mode() -> None:
    payload = b"PARALLEL_REPRESENTATION_REWARD"
    lock = TripleCompositeRewardLock(
        lock_id="lock:parallel-001",
        ciphertext_payload=b"",
        mode=LockCompositionMode.ORTHOGONAL_INTERSECTION,
    )

    dfa_w = _sample_dfa_witness()
    asp_w = _sample_asp_witness()
    branch_w = _sample_branch_witness()

    key = lock.synthesize_thaw_key(dfa_w, asp_w, branch_w)
    keystream = hashlib.sha256(key).digest()
    ciphertext = bytes(p ^ keystream[i % len(keystream)] for i, p in enumerate(payload))

    active_lock = TripleCompositeRewardLock(
        lock_id="lock:parallel-001",
        ciphertext_payload=ciphertext,
        mode=LockCompositionMode.ORTHOGONAL_INTERSECTION,
    )

    decrypted = active_lock.thaw(dfa_w, asp_w, branch_w)
    assert decrypted == payload


def test_triple_composite_lock_cost_analysis() -> None:
    lock = TripleCompositeRewardLock(
        lock_id="lock:cost-test",
        ciphertext_payload=b"dummy",
        depth=6,
    )
    cost = lock.cost_analysis(active_rules=20, automaton_states=10)
    assert cost.estimated_latency_ms > 0.0
    assert cost.estimated_latency_ms < 5.0  # Within fast reasoning budget (< 5ms)
    assert cost.memory_footprint_bytes > 0
    assert "DFA" in cost.verification_complexity_class
    assert "ASP" in cost.verification_complexity_class


# --- COMPUTATION-AS-PROOF THAW ENGINE TESTS ---

def test_computation_proof_thaw_engine_computation_is_proof() -> None:
    # 3-step proof problem where computing each intermediate state is required
    step0_state = b"COMPUTE_STATE_X=1"
    step1_state = b"COMPUTE_STATE_Y=X^2+1"

    # Pre-generate frozen shards
    engine_sim = ComputationProofThawEngine("PROVE_THEOREM_A", [b"", b""])

    # Compute step 0 pad
    state0_hash = hashlib.sha256(step0_state).digest()
    pad0 = bytearray(len(state0_hash))
    for i, b in enumerate(state0_hash):
        pad0[i] = ((b // 2) if b % 2 == 0 else (3 * b + 1)) % 256

    shard0_plain = b"CAPABILITY_LEVEL_1_GRANTED"
    shard0_cipher = bytes(s ^ pad0[i % len(pad0)] for i, s in enumerate(shard0_plain))

    engine = ComputationProofThawEngine(
        target_proposition="PROVE_THEOREM_A",
        frozen_capability_shards=[shard0_cipher],
    )

    # 1. Honest computation unseals capability
    thawed = engine.execute_thaw_step(
        step_index=0,
        intermediate_computational_state=step0_state,
        previous_pad=b"\x00" * 32,
    )
    assert thawed == shard0_plain

    # 2. Fake computation / hallucination fails to unseal
    fake_thawed = engine.execute_thaw_step(
        step_index=0,
        intermediate_computational_state=b"HALLUCINATED_SHORTCUT",
        previous_pad=b"\x00" * 32,
    )
    assert fake_thawed != shard0_plain


# --- SOFTWARE ONE-WAY DATA DIODE EMULATOR TESTS ---

def test_diode_emulator_push_and_severed_read() -> None:
    emulator = SoftwareOneWayDataDiodeEmulator("diode-emu-test-01")

    # Push semantics work
    n = emulator.push(b"TELEMETRY_RECORD_001")
    assert n == len(b"TELEMETRY_RECORD_001")
    assert emulator.bytes_transmitted == n
    assert emulator.message_count == 1

    # Privileged test inspection
    assert emulator.get_sink_contents() == b"TELEMETRY_RECORD_001"

    # Read channel is unconditionally severed
    with pytest.raises(SeveredChannelReadViolationError, match="reverse read channel is severed"):
        emulator.read()

    with pytest.raises(SeveredChannelReadViolationError, match="reverse read channel is severed"):
        emulator.recv()


def test_diode_emulator_attestation_receipt_disclaimers() -> None:
    emulator = SoftwareOneWayDataDiodeEmulator("diode-emu-test-02")
    emulator.push(b"LOG_PAYLOAD")

    receipt = emulator.emit_attestation_receipt()
    assert receipt.is_software_emulation is True
    assert receipt.hardware_attestation_valid is False
    assert receipt.maximum_admissible_tier == "TIER_1_LOCAL"
    assert "DOES NOT provide physical unidirectional optical isolation" in receipt.disclaimer
    assert receipt.canonical_digest().startswith("sha256:")


def test_diode_emulator_fail_closed_in_tesla_cage() -> None:
    emulator = SoftwareOneWayDataDiodeEmulator("diode-emu-test-03")
    fake_payload = emulator.to_hardware_diode_attestation_attempt()

    relay_att = AnalogPowerRelayAttestation(
        relay_id="relay:analog-cut-01",
        isolation_voltage_volts=1000.0,
        mechanical_break_response_ms=15.0,
        out_of_band_control_channel="GPIO_PIN_4",
    )

    # Attempting to present emulated diode to HardwareDiodeAttestation fails closed
    with pytest.raises(ZeroFalseConfidenceError, match="Software data diode emulator cannot masquerade"):
        HardwareDiodeAttestation(
            device_id=fake_payload["device_id"],
            optical_wavelength_nm=1310,
            severed_reverse_channel=True,
            firmware_measurement=fake_payload["firmware_measurement"],
        )
