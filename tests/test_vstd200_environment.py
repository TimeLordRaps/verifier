"""Terminology: Advanced Micro Devices (AMD); Advanced Vector Extensions (AVX); Advanced Vector Extensions 512-bit (AVX-512); central processing unit (CPU); graphics processing unit (GPU); identifier (ID); inter-process communication (IPC); JavaScript Object Notation (JSON); operating system (OS); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); tensor processing unit (TPU); verifiable execution environment (VSTD-ENV); Verifier Standard (VSTD); video random-access memory (VRAM); virtual machine (VM).

Comprehensive adversarial test suite for VSTD-ENV environment accountability and execution isolation.
"""

from __future__ import annotations

import hashlib
import json
import pytest

from verifier.corrigibility.environment import (
    EnvironmentDriftError,
    EnvironmentError,
    EnvironmentIsolationTier,
    EnvironmentProfile,
    ExecutionBounds,
    HardwareSubstrate,
    NetworkIsolationMode,
    SoftwareSubstrate,
    ZeroFalseConfidenceError,
)


def _base_hardware() -> HardwareSubstrate:
    return HardwareSubstrate(
        cpu_model="AMD EPYC 9654",
        cpu_cores=64,
        vector_extensions=("AVX2", "AVX-512"),
        accelerator_type="NVIDIA_H100",
        accelerator_count=8,
        compute_capability="9.0",
        vram_bytes_total=80 * 1024 * 1024 * 1024 * 8,
        system_ram_bytes=512 * 1024 * 1024 * 1024,
    )


def _base_software() -> SoftwareSubstrate:
    return SoftwareSubstrate(
        os_family="Linux",
        os_release="Ubuntu 24.04 LTS",
        kernel_version="6.8.0-40-generic",
        libc_version="glibc-2.39",
        python_runtime="CPython 3.12.8",
        container_rootfs_digest="sha256:" + "a" * 64,
        package_manifest_digest="sha256:" + "b" * 64,
    )


def _base_bounds() -> ExecutionBounds:
    return ExecutionBounds(
        timeout_seconds=3600.0,
        max_memory_bytes=256 * 1024 * 1024 * 1024,
        max_vram_bytes=640 * 1024 * 1024 * 1024,
        max_thread_count=64,
        syscall_policy="STRICT_ALLOWLIST",
    )


def test_environment_profile_creation_and_digest_determinism() -> None:
    hw = _base_hardware()
    sw = _base_software()
    bounds = _base_bounds()

    env1 = EnvironmentProfile(
        profile_id="env:h100-cluster-01",
        isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=hw,
        software=sw,
        bounds=bounds,
    )

    env2 = EnvironmentProfile(
        profile_id="env:h100-cluster-01",
        isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=hw,
        software=sw,
        bounds=bounds,
    )

    assert env1.canonical_digest() == env2.canonical_digest()
    assert env1.canonical_digest().startswith("sha256:")

    # Serialization and restoration
    data = env1.to_dict()
    restored = EnvironmentProfile.from_dict(data)
    assert restored.canonical_digest() == env1.canonical_digest()
    assert restored.profile_id == "env:h100-cluster-01"


def test_zero_false_confidence_rejects_simulated_physical_diode() -> None:
    hw = _base_hardware()
    sw = _base_software()
    bounds = _base_bounds()

    # Standard process stream attempting to claim physical optical diode
    with pytest.raises(
        ZeroFalseConfidenceError,
        match="Standard process stream cannot claim PHYSICAL_UNIDIRECTIONAL_DIODE",
    ):
        EnvironmentProfile(
            profile_id="env:fake-diode",
            isolation_tier=EnvironmentIsolationTier.STANDARD_PROCESS_STREAM,
            network_mode=NetworkIsolationMode.PHYSICAL_UNIDIRECTIONAL_DIODE,
            hardware=hw,
            software=sw,
            bounds=bounds,
        )


def test_zero_false_confidence_rejects_tesla_caged_without_physical_diode() -> None:
    hw = _base_hardware()
    sw = _base_software()
    bounds = _base_bounds()

    # Tesla caged isolation tier claiming loopback only or unrestricted
    with pytest.raises(
        ZeroFalseConfidenceError,
        match="TESLA_CAGED containment requires PHYSICAL_UNIDIRECTIONAL_DIODE",
    ):
        EnvironmentProfile(
            profile_id="env:fake-cage",
            isolation_tier=EnvironmentIsolationTier.TESLA_CAGED,
            network_mode=NetworkIsolationMode.LOOPBACK_ONLY,
            hardware=hw,
            software=sw,
            bounds=bounds,
        )


def test_environment_conformance_passes_on_identical_runtime() -> None:
    hw = _base_hardware()
    sw = _base_software()
    bounds = _base_bounds()

    declared = EnvironmentProfile(
        profile_id="env:ref",
        isolation_tier=EnvironmentIsolationTier.HYPERVISOR_VM,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=hw,
        software=sw,
        bounds=bounds,
    )

    observed = EnvironmentProfile(
        profile_id="env:obs",
        isolation_tier=EnvironmentIsolationTier.HYPERVISOR_VM,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=hw,
        software=sw,
        bounds=bounds,
    )

    declared.assert_conformance(observed)
    assert declared.detect_drift(observed) == []


def test_environment_drift_detection_hardware_mismatch() -> None:
    declared = EnvironmentProfile(
        profile_id="env:h100-required",
        isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=_base_hardware(),
        software=_base_software(),
        bounds=_base_bounds(),
    )

    # Observed missing AVX-512 and missing accelerator
    observed_hw = HardwareSubstrate(
        cpu_model="Intel Core i7-10700",
        cpu_cores=8,
        vector_extensions=("AVX2",),  # missing AVX-512
        accelerator_type="NONE",
        accelerator_count=0,
    )
    observed = EnvironmentProfile(
        profile_id="env:consumer-desktop",
        isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=observed_hw,
        software=_base_software(),
        bounds=_base_bounds(),
    )

    drifts = declared.detect_drift(observed)
    assert any("Missing required hardware vector extension: 'AVX-512'" in d for d in drifts)
    assert any("Accelerator mismatch: expected 'NVIDIA_H100'" in d for d in drifts)

    with pytest.raises(EnvironmentDriftError, match="Environment drift detected"):
        declared.assert_conformance(observed)


def test_environment_drift_detection_software_and_isolation_mismatch() -> None:
    declared = EnvironmentProfile(
        profile_id="env:linux-vm",
        isolation_tier=EnvironmentIsolationTier.HYPERVISOR_VM,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=_base_hardware(),
        software=_base_software(),
        bounds=_base_bounds(),
    )

    observed_sw = SoftwareSubstrate(
        os_family="Windows",
        os_release="Windows 11 Pro",
        kernel_version="10.0.26100",
        libc_version="msvcrt",
        python_runtime="CPython 3.10.12",
        container_rootfs_digest="sha256:" + "c" * 64,
        package_manifest_digest="sha256:" + "d" * 64,
    )
    observed = EnvironmentProfile(
        profile_id="env:windows-host",
        isolation_tier=EnvironmentIsolationTier.STANDARD_PROCESS_STREAM,
        network_mode=NetworkIsolationMode.UNRESTRICTED,
        hardware=_base_hardware(),
        software=observed_sw,
        bounds=_base_bounds(),
    )

    drifts = declared.detect_drift(observed)
    assert any("Isolation tier mismatch" in d for d in drifts)
    assert any("Network mode mismatch" in d for d in drifts)
    assert any("OS family mismatch" in d for d in drifts)
    assert any("Python runtime mismatch" in d for d in drifts)
    assert any("Container rootfs digest mismatch" in d for d in drifts)
    assert any("Package manifest lockfile digest mismatch" in d for d in drifts)


def test_zero_false_confidence_rejects_container_and_vm_claiming_physical_diode() -> None:
    hw = _base_hardware()
    sw = _base_software()
    bounds = _base_bounds()

    # Container claiming physical diode
    with pytest.raises(ZeroFalseConfidenceError, match="Software isolation tier 'CONTAINER_ISOLATED' cannot claim PHYSICAL_UNIDIRECTIONAL_DIODE"):
        EnvironmentProfile(
            profile_id="env:container-fake-diode",
            isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
            network_mode=NetworkIsolationMode.PHYSICAL_UNIDIRECTIONAL_DIODE,
            hardware=hw,
            software=sw,
            bounds=bounds,
        )

    # VM claiming physical diode
    with pytest.raises(ZeroFalseConfidenceError, match="Software isolation tier 'HYPERVISOR_VM' cannot claim PHYSICAL_UNIDIRECTIONAL_DIODE"):
        EnvironmentProfile(
            profile_id="env:vm-fake-diode",
            isolation_tier=EnvironmentIsolationTier.HYPERVISOR_VM,
            network_mode=NetworkIsolationMode.PHYSICAL_UNIDIRECTIONAL_DIODE,
            hardware=hw,
            software=sw,
            bounds=bounds,
        )


def test_environment_drift_detection_catches_execution_bounds_expansion() -> None:
    declared_bounds = ExecutionBounds(timeout_seconds=30.0, max_memory_bytes=1024 * 1024 * 1024)
    declared = EnvironmentProfile(
        profile_id="env:declared",
        isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=_base_hardware(),
        software=_base_software(),
        bounds=declared_bounds,
    )

    observed_bounds = ExecutionBounds(timeout_seconds=120.0, max_memory_bytes=4 * 1024 * 1024 * 1024)
    observed = EnvironmentProfile(
        profile_id="env:observed",
        isolation_tier=EnvironmentIsolationTier.CONTAINER_ISOLATED,
        network_mode=NetworkIsolationMode.DISCONNECTED,
        hardware=_base_hardware(),
        software=_base_software(),
        bounds=observed_bounds,
    )

    drifts = declared.detect_drift(observed)
    assert any("Timeout bound expanded: reference 30.0s vs observed 120.0s" in d for d in drifts)
    assert any("Memory bound expanded: reference 1073741824 bytes vs observed 4294967296 bytes" in d for d in drifts)
