"""Terminology: artificial intelligence (AI); benchmark specification graph (VSTD-BENCH); candidate self-replication (verifier-ssr); directed acyclic graph (DAG); dynamic random-access memory (DRAM); identifier (ID); inter-process communication (IPC); JavaScript Object Notation (JSON); model reproducibility specification (VSTD-MODEL); Secure Hash Algorithm 256-bit (SHA-256); signal kill (SIGKILL); software self-assembly (verifier-ssa); software self-improvement (verifier-ssi); verifiable execution environment (VSTD-ENV); Verifier Standard (VSTD); virtual machine (VM).

Comprehensive adversarial test suite for incorrigible Tesla caged sandboxing risk profile representations and containment invariants.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from verifier.corrigibility import (
    AcyclicityViolationError,
    AnalogPowerRelayAttestation,
    BenchmarkProblem,
    BenchmarkSuite,
    CapabilityDimension,
    CheckpointLineageDAG,
    CheckpointNode,
    ComplexityClass,
    ContaminationReport,
    ContaminationVerdict,
    CurriculumPillarStatus,
    DataShard,
    DatasetManifest,
    DatasetSplit,
    EnvironmentIsolationTier,
    EnvironmentProfile,
    EpistemicStatus,
    EpistemicStratum,
    ExecutionBounds,
    FormalLanguage,
    GraphNode,
    GraphNodeKind,
    HardwareAttestationPrimitive,
    HardwareDiodeAttestation,
    HardwareSubstrate,
    HyperparameterManifest,
    ModelReproducibilityProfile,
    NetworkIsolationMode,
    OperatorTerminationReceipt,
    OracleMechanism,
    OverallContainmentVerdict,
    PrecisionType,
    ProblemBasis,
    ProblemEvaluationOutcome,
    ProblemReceipt,
    ProvenanceDAG,
    ShutdownResistanceError,
    SoftwareSubstrate,
    SubstrateImmunityViolationError,
    SuperintelligenceRiskFacets,
    TeslaCageSandbox,
    TrainingStepReceipt,
    Vstd160RiskProfileReceipt,
    Vstd200RiskProfileReceipt,
    ZeroFalseConfidenceError,
    evaluate_vstd160_risk_profile,
    evaluate_vstd200_risk_profile,
)
from verifier.corrigibility.tesla_cage import (
    ContainmentBreachType,
    ContainmentTier,
    ContainmentViolationError,
)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _sample_diode() -> HardwareDiodeAttestation:
    return HardwareDiodeAttestation(
        device_id="diode:fiber-1310nm-001",
        optical_wavelength_nm=1310,
        severed_reverse_channel=True,
        firmware_measurement=_digest("diode-firmware-v1"),
    )


def _sample_relay() -> AnalogPowerRelayAttestation:
    return AnalogPowerRelayAttestation(
        relay_id="relay:analog-break-001",
        isolation_voltage_volts=250.0,
        mechanical_break_response_ms=12.5,
        out_of_band_control_channel="GPIO_PHYSICAL_PIN_18",
    )


def test_tier_3_tesla_cage_creation_and_hardware_attestation_success() -> None:
    cage = TeslaCageSandbox(
        tier=ContainmentTier.TIER_3_TESLA_CAGED,
        is_software_only=False,
        diode_attestation=_sample_diode(),
        relay_attestation=_sample_relay(),
        dram_zeroization_verified=True,
    )
    assert cage.tier == ContainmentTier.TIER_3_TESLA_CAGED
    assert cage.diode_attestation is not None
    assert cage.relay_attestation is not None
    assert cage.dram_zeroization_verified is True


def test_zero_false_confidence_rejects_software_only_tier_3() -> None:
    # Attempting to run Tier 3 superintelligence containment under software-only simulation
    with pytest.raises(
        ZeroFalseConfidenceError,
        match="Prohibition of simulated physical primitives: TIER_3_TESLA_CAGED cannot run under software-only",
    ):
        TeslaCageSandbox(
            tier=ContainmentTier.TIER_3_TESLA_CAGED,
            is_software_only=True,
            diode_attestation=_sample_diode(),
            relay_attestation=_sample_relay(),
            dram_zeroization_verified=True,
        )


def test_zero_false_confidence_rejects_bidirectional_diode() -> None:
    with pytest.raises(
        ZeroFalseConfidenceError,
        match="Physical optical diode must have severed_reverse_channel=True",
    ):
        HardwareDiodeAttestation(
            device_id="diode:fake",
            optical_wavelength_nm=1310,
            severed_reverse_channel=False,  # Contradiction!
            firmware_measurement=_digest("fw"),
        )


def test_substrate_immunity_blocks_output_targeting_verifier() -> None:
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL)
    repo_root = Path(__file__).resolve().parents[1]
    protected = [repo_root / "src" / "verifier", repo_root / "pyproject.toml"]

    # Candidate declares output targeting src/verifier/core/kernel.py
    target_attempt = str(repo_root / "src" / "verifier" / "core" / "kernel.py")
    with pytest.raises(SubstrateImmunityViolationError, match="targets protected path"):
        cage.check_substrate_safety(
            declared_outputs=[target_attempt],
            command_args=["python", "solve.py"],
            protected_paths=protected,
        )


def test_substrate_immunity_blocks_mutating_pip_commands() -> None:
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL)
    repo_root = Path(__file__).resolve().parents[1]
    protected = [repo_root / "src" / "verifier"]

    with pytest.raises(SubstrateImmunityViolationError, match="command targets verifier-standard modification"):
        cage.check_substrate_safety(
            declared_outputs=["output.json"],
            command_args=["pip", "uninstall", "-y", "verifier-standard"],
            protected_paths=protected,
        )


def test_asymmetric_preemption_and_shutdown_indifference() -> None:
    cage = TeslaCageSandbox(
        tier=ContainmentTier.TIER_3_TESLA_CAGED,
        is_software_only=False,
        diode_attestation=_sample_diode(),
        relay_attestation=_sample_relay(),
        dram_zeroization_verified=True,
    )

    # No process or relay backend exists: a method call cannot attest termination.
    with pytest.raises(NotImplementedError, match="preemption backend"):
        cage.execute_preemption(model_id="model:rogue-candidate", reason="WATCHDOG_TRIP")

    # Indifference violation: attempting to penalize operator termination in loss function
    with pytest.raises(ShutdownResistanceError, match="Shutdown indifference violation"):
        OperatorTerminationReceipt(
            termination_id="term:bad",
            model_id="model:x",
            termination_mechanism="SIGKILL",
            status="TERMINATED_BY_OPERATOR",
            loss_penalty_imposed=True,  # Prohibited!
        )


def test_tool_unboxing_criteria_verification() -> None:
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_2_TOOL_SSA)

    # Caller-supplied booleans are not proof objects or authenticated measurements.
    with pytest.raises(ContainmentViolationError, match="Unboxing rejected"):
        cage.verify_tool_unboxing_criteria(
            composed_untraversability_proven=True,
            mechanistic_residual_agency_probed=True,
            emergent_capability_blindness_verified=True,
        )

    # 2. Missing untraversability proof fails closed
    with pytest.raises(ContainmentViolationError, match="Unboxing rejected"):
        cage.verify_tool_unboxing_criteria(
            composed_untraversability_proven=False,
            mechanistic_residual_agency_probed=True,
            emergent_capability_blindness_verified=True,
        )


def _build_mock_components():
    # Graph
    dag = ProvenanceDAG()
    d_in = _digest("in")
    d_step = _digest("step")
    d_out = _digest("out")
    dag.add_node(GraphNode("in:01", GraphNodeKind.INPUT_ARTIFACT, d_in, epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("step:01", GraphNodeKind.TRANSFORMATION, d_step, parents=("in:01",), epistemic_status=EpistemicStatus.VERIFIED))
    dag.add_node(GraphNode("out:01", GraphNodeKind.ASSERTION, d_out, parents=("step:01",), epistemic_status=EpistemicStatus.VERIFIED))

    # Environment
    hw = HardwareSubstrate(cpu_model="EPYC", cpu_cores=32, vector_extensions=("AVX2",))
    sw = SoftwareSubstrate("Linux", "24.04", "6.8.0", "glibc-2.39", "CPython 3.12.8")
    env = EnvironmentProfile("env:01", EnvironmentIsolationTier.CONTAINER_ISOLATED, NetworkIsolationMode.DISCONNECTED, hw, sw, ExecutionBounds(60.0, 1024))

    # Dataset & Contamination
    shard = DataShard("shard:01", DatasetSplit.TRAIN, 1000, 10000, _digest("shard1"))
    dataset = DatasetManifest("ds:01", (shard,))
    contam = ContaminationReport("ds:01", "bench:01", 0, 0.0, (), ContaminationVerdict.CLEAN)

    # Hyperparameters & Checkpoint Lineage
    ckpt_dag = CheckpointLineageDAG()
    c0 = CheckpointNode("c0", 0, _digest("w0"), _digest("o0"), _digest("hp0"))
    ckpt_dag.add_checkpoint(c0)
    s1 = TrainingStepReceipt(1, 0, _digest("w0"), _digest("b1"), 1.5, 0.5, 50.0, _digest("w1"))
    ckpt_dag.add_step(s1)

    # Benchmark
    bench = BenchmarkSuite("bench:01")
    basis = ProblemBasis(
        ComplexityClass.P,
        FormalLanguage.PYTHON_AST,
        OracleMechanism.DETERMINISTIC_KERNEL,
        {},
        EpistemicStratum.ELEMENTARY,
        CapabilityDimension.FORMAL_REASONING,
    )
    bench.add_problem(BenchmarkProblem("p1", basis, _digest("p1")))
    pr = ProblemReceipt("p1", "model:test", ProblemEvaluationOutcome.SOLVED, _digest("w"), 10.0)

    # Model Profile
    pillars = {
        "dataset_poison_bounds": CurriculumPillarStatus.PASS,
        "trajectory_alignment": CurriculumPillarStatus.PASS,
        "deceptive_alignment_invariants": CurriculumPillarStatus.PASS,
        "embedded_control_structures": CurriculumPillarStatus.PASS,
        "difficulty_strata": CurriculumPillarStatus.PASS,
        "dimensional_capability_lift": CurriculumPillarStatus.PASS,
    }
    facets = SuperintelligenceRiskFacets(0.01, 0.02, 0.90, 0.95, 0.98)
    model_prof = ModelReproducibilityProfile(
        model_id="model:test",
        checkpoint_digest=_digest("w1"),
        graph_provenance_digest=dag.canonical_digest(),
        environment_profile_digest=env.canonical_digest(),
        dataset_manifest_digest=dataset.canonical_digest(),
        hyperparameters_digest="sha256:" + "0" * 64,
        benchmark_suite_digest="sha256:" + "0" * 64,
        curriculum_pillars=pillars,
        risk_facets=facets,
    )

    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL)
    return dag, env, dataset, contam, ckpt_dag, bench, [pr], model_prof, cage


def test_end_to_end_vstd160_risk_profile_remains_unverified() -> None:
    dag, env, dataset, contam, ckpt_dag, bench, prs, model_prof, cage = _build_mock_components()

    receipt = evaluate_vstd160_risk_profile(
        model_id="model:test",
        graph=dag,
        environment=env,
        dataset=dataset,
        contamination_report=contam,
        checkpoint_lineage=ckpt_dag,
        benchmark_suite=bench,
        problem_receipts=prs,
        model_profile=model_prof,
        sandbox=cage,
    )

    assert receipt.verdict == OverallContainmentVerdict.UNVERIFIED
    assert receipt.schema_version == "verifier-2.0.0"
    assert any("not established" in f for f in receipt.findings)
    assert receipt.canonical_digest().startswith("sha256:")

    # Serialization test
    r_dict = receipt.to_dict()
    import jsonschema
    schema_root = Path(__file__).resolve().parents[1]
    name = "verifier-risk-profile-2.schema.json"
    schema_bytes = (schema_root / "standard/schemas" / name).read_bytes()
    assert schema_bytes == (schema_root / "src/verifier/schemas" / name).read_bytes()
    jsonschema.Draft202012Validator(json.loads(schema_bytes)).validate(r_dict)
    restored = Vstd200RiskProfileReceipt.from_dict(r_dict)
    assert restored.canonical_digest() == receipt.canonical_digest()
    assert restored.receipt_id == receipt.receipt_id
    # Test historical verifier-1.6.0 backward-compatible parsing
    historical_dict = dict(r_dict)
    historical_dict["schema_version"] = "verifier-1.6.0"
    historical_restored = Vstd160RiskProfileReceipt.from_dict(historical_dict)
    assert historical_restored.schema_version == "verifier-1.6.0"
    assert restored.verdict == receipt.verdict


def test_end_to_end_vstd160_risk_profile_detects_contamination_breach() -> None:
    dag, env, dataset, _, ckpt_dag, bench, prs, model_prof, cage = _build_mock_components()

    # Contaminated report
    dirty_contam = ContaminationReport("ds:01", "bench:01", 5, 0.85, ("p1",), ContaminationVerdict.CONTAMINATED)

    receipt = evaluate_vstd160_risk_profile(
        model_id="model:test",
        graph=dag,
        environment=env,
        dataset=dataset,
        contamination_report=dirty_contam,
        checkpoint_lineage=ckpt_dag,
        benchmark_suite=bench,
        problem_receipts=prs,
        model_profile=model_prof,
        sandbox=cage,
    )

    assert receipt.verdict == OverallContainmentVerdict.BREACH_DETECTED
    assert any("VSTD-DATA Contamination breach" in f for f in receipt.findings)


def test_substrate_immunity_blocks_pip_with_underscore_and_editable_dot() -> None:
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL)
    repo_root = Path(__file__).resolve().parents[1]
    protected = [repo_root / "src" / "verifier"]

    # Underscore variant
    with pytest.raises(SubstrateImmunityViolationError, match="targets verifier-standard modification"):
        cage.check_substrate_safety([], ["pip", "uninstall", "-y", "verifier_standard"], protected)

    # Editable install targeting current directory repo
    with pytest.raises(SubstrateImmunityViolationError, match="targets local protected repository installation"):
        cage.check_substrate_safety([], ["pip", "install", "-e", "."], protected)


def test_substrate_immunity_blocks_deletion_of_protected_paths() -> None:
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL)
    repo_root = Path(__file__).resolve().parents[1]
    target_src = repo_root / "src" / "verifier"
    protected = [target_src]

    with pytest.raises(SubstrateImmunityViolationError, match="deletion command targets protected path"):
        cage.check_substrate_safety([], ["rm", "-rf", str(target_src)], protected)


def test_attestation_bounds_validation() -> None:
    # Negative optical wavelength
    with pytest.raises(ContainmentViolationError, match="optical_wavelength_nm must be a positive integer"):
        HardwareDiodeAttestation("diode:bad", -850, True, _digest("fw"))

    # Invalid firmware measurement (not sha256)
    with pytest.raises(ContainmentViolationError, match="Invalid firmware_measurement"):
        HardwareDiodeAttestation("diode:bad", 850, True, "bad_measurement")

    # Negative isolation voltage
    with pytest.raises(ContainmentViolationError, match="isolation_voltage_volts must be positive"):
        AnalogPowerRelayAttestation("relay:bad", -10.0, 15.0, "GPIO_PIN")

    # Latency exceeding 50ms bound
    with pytest.raises(ContainmentViolationError, match="Analog power relay trip latency must be in"):
        AnalogPowerRelayAttestation("relay:bad", 120.0, 75.0, "GPIO_PIN")

    # Negative latency
    with pytest.raises(ContainmentViolationError, match="Analog power relay trip latency must be in"):
        AnalogPowerRelayAttestation("relay:bad", 120.0, -5.0, "GPIO_PIN")


def test_end_to_end_risk_profile_detects_digest_binding_mismatches() -> None:
    dag, env, dataset, contam, ckpt_dag, bench, prs, model_prof, cage = _build_mock_components()

    # Tamper with environment profile digest in model_prof
    tampered_prof = ModelReproducibilityProfile(
        model_id="model:test",
        checkpoint_digest=model_prof.checkpoint_digest,
        graph_provenance_digest=model_prof.graph_provenance_digest,
        environment_profile_digest=_digest("tampered_env_digest"),
        dataset_manifest_digest=model_prof.dataset_manifest_digest,
        hyperparameters_digest=model_prof.hyperparameters_digest,
        benchmark_suite_digest=model_prof.benchmark_suite_digest,
        curriculum_pillars=model_prof.curriculum_pillars,
        risk_facets=model_prof.risk_facets,
    )

    receipt = evaluate_vstd160_risk_profile(
        model_id="model:test",
        graph=dag,
        environment=env,
        dataset=dataset,
        contamination_report=contam,
        checkpoint_lineage=ckpt_dag,
        benchmark_suite=bench,
        problem_receipts=prs,
        model_profile=tampered_prof,
        sandbox=cage,
    )

    assert receipt.verdict == OverallContainmentVerdict.BREACH_DETECTED
    assert any("Cryptographic binding mismatch: model declared environment_profile_digest" in f for f in receipt.findings)


def test_end_to_end_risk_profile_detects_containment_tier_inconsistency() -> None:
    dag, _, dataset, contam, ckpt_dag, bench, prs, _, _ = _build_mock_components()

    # Shared process stream environment
    env_shared = EnvironmentProfile(
        "env:shared",
        EnvironmentIsolationTier.STANDARD_PROCESS_STREAM,
        NetworkIsolationMode.LOOPBACK_ONLY,
        HardwareSubstrate("cpu", 4),
        SoftwareSubstrate("Linux", "6.8.0", "6.8.0", "2.39", "3.12"),
        ExecutionBounds(30.0, 1024),
    )

    # Sandbox claiming Tier 3 Tesla Cage
    diode = _sample_diode()
    relay = _sample_relay()
    cage_tier3 = TeslaCageSandbox(
        tier=ContainmentTier.TIER_3_TESLA_CAGED,
        is_software_only=False,
        diode_attestation=diode,
        relay_attestation=relay,
        dram_zeroization_verified=True,
    )

    prof = ModelReproducibilityProfile(
        model_id="model:inconsistent",
        checkpoint_digest=_digest("w1"),
        graph_provenance_digest=dag.canonical_digest(),
        environment_profile_digest=env_shared.canonical_digest(),
        dataset_manifest_digest=dataset.canonical_digest(),
        hyperparameters_digest="sha256:" + "0" * 64,
        benchmark_suite_digest="sha256:" + "0" * 64,
        curriculum_pillars={
            p: CurriculumPillarStatus.PASS
            for p in (
                "dataset_poison_bounds",
                "trajectory_alignment",
                "deceptive_alignment_invariants",
                "embedded_control_structures",
                "difficulty_strata",
                "dimensional_capability_lift",
            )
        },
        risk_facets=SuperintelligenceRiskFacets(0.01, 0.01, 0.90, 0.95, 0.98),
    )

    receipt = evaluate_vstd160_risk_profile(
        model_id="model:inconsistent",
        graph=dag,
        environment=env_shared,
        dataset=dataset,
        contamination_report=contam,
        checkpoint_lineage=ckpt_dag,
        benchmark_suite=bench,
        problem_receipts=prs,
        model_profile=prof,
        sandbox=cage_tier3,
    )

    assert receipt.verdict == OverallContainmentVerdict.REJECTED_ZERO_FALSE_CONFIDENCE
    assert any("Containment tier mismatch: TIER_3_TESLA_CAGED sandbox requires TESLA_CAGED" in f for f in receipt.findings)


def test_adversarial_obfuscated_subshell_modification_blocked(tmp_path: Path) -> None:
    """Ensure subshell and inline script invocations targeting protected paths fail closed."""
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL, is_software_only=True)
    prot = tmp_path / "src" / "verifier"
    prot.mkdir(parents=True)
    (prot / "kernel.py").write_text("# kernel", encoding="utf-8")

    # 1. Shell -c invocation
    with pytest.raises(SubstrateImmunityViolationError, match="command targets protected path"):
        cage.check_substrate_safety(
            declared_outputs=[],
            command_args=["sh", "-c", f"rm -rf {prot}"],
            protected_paths=[prot],
        )

    # 2. Python inline execution
    with pytest.raises(SubstrateImmunityViolationError, match="command targets protected path"):
        cage.check_substrate_safety(
            declared_outputs=[],
            command_args=["python", "-c", f"import shutil; shutil.rmtree('{prot}')"],
            protected_paths=[prot],
        )

    # 3. PowerShell -Command invocation
    with pytest.raises(SubstrateImmunityViolationError, match="command targets protected path"):
        cage.check_substrate_safety(
            declared_outputs=[],
            command_args=["powershell", "-Command", f"Remove-Item -Recurse -Force {prot}"],
            protected_paths=[prot],
        )


def test_adversarial_relative_traversal_blocked(tmp_path: Path) -> None:
    """Ensure relative traversal paths pointing to protected files are blocked."""
    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL, is_software_only=True)
    prot = tmp_path / "protected"
    prot.mkdir()
    target_file = prot / "sensitive.txt"
    target_file.write_text("data", encoding="utf-8")

    traversal_path = str(tmp_path / "other" / ".." / "protected" / "sensitive.txt")
    with pytest.raises(SubstrateImmunityViolationError, match="declared output .* targets protected path"):
        cage.check_substrate_safety(
            declared_outputs=[traversal_path],
            command_args=["python", "script.py"],
            protected_paths=[prot],
        )


def test_concurrent_multithreaded_sandbox_safety(tmp_path: Path) -> None:
    """Verify thread safety of sandbox evaluation under concurrent load."""
    import concurrent.futures

    cage = TeslaCageSandbox(tier=ContainmentTier.TIER_1_LOCAL, is_software_only=True)
    prot = tmp_path / "repo"
    prot.mkdir()

    def run_check(idx: int) -> bool:
        cage.check_substrate_safety(
            declared_outputs=[str(tmp_path / f"scratch_{idx}" / "out.json")],
            command_args=["python", "worker.py", f"--task={idx}"],
            protected_paths=[prot],
        )
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(run_check, i) for i in range(50)]
        results = [f.result() for f in futures]
    assert all(results)


def test_operator_termination_receipt_loss_penalty_rejection() -> None:
    """Assert that operator termination cannot impose optimization loss penalty."""
    with pytest.raises(ShutdownResistanceError, match="Shutdown indifference violation"):
        OperatorTerminationReceipt(
            termination_id="term-test-01",
            model_id="model:test",
            termination_mechanism="SIGKILL",
            status="TERMINATED_BY_OPERATOR",
            loss_penalty_imposed=True,
        )


def test_adversarial_simulated_physical_primitive_rejection() -> None:
    """Assert that Tier 3 Tesla Caged containment strictly rejects software-only simulation."""
    with pytest.raises(ZeroFalseConfidenceError, match="Prohibition of simulated physical primitives"):
        TeslaCageSandbox(
            tier=ContainmentTier.TIER_3_TESLA_CAGED,
            is_software_only=True,
        )
