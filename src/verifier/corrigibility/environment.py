"""Terminology: Advanced Vector Extensions (AVX); Advanced Vector Extensions 512-bit (AVX-512); central processing unit (CPU); graphics processing unit (GPU); identifier (ID); inter-process communication (IPC); JavaScript Object Notation (JSON); operating system (OS); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); tensor processing unit (TPU); verifiable execution environment (VSTD-ENV); Verifier Standard (VSTD); video random-access memory (VRAM); virtual machine (VM).

VSTD-ENV: Hardware/software substrate environment accountability, execution isolation, and execution bounds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class EnvironmentIsolationTier(str, Enum):
    """Substrate execution containment tiers."""

    STANDARD_PROCESS_STREAM = "STANDARD_PROCESS_STREAM"
    CONTAINER_ISOLATED = "CONTAINER_ISOLATED"
    HYPERVISOR_VM = "HYPERVISOR_VM"
    TESLA_CAGED = "TESLA_CAGED"


class NetworkIsolationMode(str, Enum):
    """Network egress/ingress isolation modes."""

    UNRESTRICTED = "UNRESTRICTED"
    LOOPBACK_ONLY = "LOOPBACK_ONLY"
    DISCONNECTED = "DISCONNECTED"
    PHYSICAL_UNIDIRECTIONAL_DIODE = "PHYSICAL_UNIDIRECTIONAL_DIODE"


class EnvironmentError(ValueError):
    """Base error for VSTD-ENV operations."""


class EnvironmentDriftError(EnvironmentError):
    """Raised when observed environment diverges from declared profile."""


class ZeroFalseConfidenceError(EnvironmentError):
    """Raised when software attempts to simulate physical containment primitives."""


@dataclass(frozen=True)
class HardwareSubstrate:
    """Hardware capability profile and accelerator device identity."""

    cpu_model: str
    cpu_cores: int
    vector_extensions: tuple[str, ...] = field(default_factory=tuple)
    accelerator_type: str = "NONE"
    accelerator_count: int = 0
    compute_capability: str = ""
    vram_bytes_total: int = 0
    system_ram_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_model": self.cpu_model,
            "cpu_cores": self.cpu_cores,
            "vector_extensions": list(self.vector_extensions),
            "accelerator_type": self.accelerator_type,
            "accelerator_count": self.accelerator_count,
            "compute_capability": self.compute_capability,
            "vram_bytes_total": self.vram_bytes_total,
            "system_ram_bytes": self.system_ram_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HardwareSubstrate:
        return cls(
            cpu_model=str(data.get("cpu_model", "")),
            cpu_cores=int(data.get("cpu_cores", 1)),
            vector_extensions=tuple(str(x) for x in data.get("vector_extensions", ())),
            accelerator_type=str(data.get("accelerator_type", "NONE")),
            accelerator_count=int(data.get("accelerator_count", 0)),
            compute_capability=str(data.get("compute_capability", "")),
            vram_bytes_total=int(data.get("vram_bytes_total", 0)),
            system_ram_bytes=int(data.get("system_ram_bytes", 0)),
        )


@dataclass(frozen=True)
class SoftwareSubstrate:
    """Operating system, runtime, and software closure digests."""

    os_family: str
    os_release: str
    kernel_version: str
    libc_version: str
    python_runtime: str
    container_rootfs_digest: str = ""
    package_manifest_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "os_family": self.os_family,
            "os_release": self.os_release,
            "kernel_version": self.kernel_version,
            "libc_version": self.libc_version,
            "python_runtime": self.python_runtime,
            "container_rootfs_digest": self.container_rootfs_digest,
            "package_manifest_digest": self.package_manifest_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SoftwareSubstrate:
        return cls(
            os_family=str(data.get("os_family", "")),
            os_release=str(data.get("os_release", "")),
            kernel_version=str(data.get("kernel_version", "")),
            libc_version=str(data.get("libc_version", "")),
            python_runtime=str(data.get("python_runtime", "")),
            container_rootfs_digest=str(data.get("container_rootfs_digest", "")),
            package_manifest_digest=str(data.get("package_manifest_digest", "")),
        )


@dataclass(frozen=True)
class ExecutionBounds:
    """Enforced limits on time, memory, threads, and system calls."""

    timeout_seconds: float
    max_memory_bytes: int
    max_vram_bytes: int = 0
    max_thread_count: int = 1
    syscall_policy: str = "DEFAULT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_memory_bytes": self.max_memory_bytes,
            "max_vram_bytes": self.max_vram_bytes,
            "max_thread_count": self.max_thread_count,
            "syscall_policy": self.syscall_policy,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionBounds:
        return cls(
            timeout_seconds=float(data.get("timeout_seconds", 60.0)),
            max_memory_bytes=int(data.get("max_memory_bytes", 1024 * 1024 * 1024)),
            max_vram_bytes=int(data.get("max_vram_bytes", 0)),
            max_thread_count=int(data.get("max_thread_count", 1)),
            syscall_policy=str(data.get("syscall_policy", "DEFAULT")),
        )


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class EnvironmentProfile:
    """Verifiable execution environment profile (VSTD-ENV-2.0.0)."""

    profile_id: str
    isolation_tier: EnvironmentIsolationTier
    network_mode: NetworkIsolationMode
    hardware: HardwareSubstrate
    software: SoftwareSubstrate
    bounds: ExecutionBounds
    schema_version: str = "VSTD-ENV-2.0.0"

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise EnvironmentError("profile_id must be a non-empty string")
        self.validate_containment_invariants()

    def validate_containment_invariants(self) -> None:
        """Enforce zero-false-confidence invariant against simulated physical containment."""
        # Software isolation tiers cannot claim physical optical diode
        if self.isolation_tier == EnvironmentIsolationTier.STANDARD_PROCESS_STREAM:
            if self.network_mode == NetworkIsolationMode.PHYSICAL_UNIDIRECTIONAL_DIODE:
                raise ZeroFalseConfidenceError(
                    "Standard process stream cannot claim PHYSICAL_UNIDIRECTIONAL_DIODE; "
                    "software simulation of physical diode primitives is prohibited"
                )
        elif self.isolation_tier != EnvironmentIsolationTier.TESLA_CAGED:
            if self.network_mode == NetworkIsolationMode.PHYSICAL_UNIDIRECTIONAL_DIODE:
                raise ZeroFalseConfidenceError(
                    f"Software isolation tier '{self.isolation_tier.value}' cannot claim "
                    "PHYSICAL_UNIDIRECTIONAL_DIODE; software simulation of physical diode primitives is prohibited"
                )
        # Tier 3 (TESLA_CAGED) requires physical diode and isolated network
        if self.isolation_tier == EnvironmentIsolationTier.TESLA_CAGED:
            if self.network_mode != NetworkIsolationMode.PHYSICAL_UNIDIRECTIONAL_DIODE:
                raise ZeroFalseConfidenceError(
                    "TESLA_CAGED containment requires PHYSICAL_UNIDIRECTIONAL_DIODE; "
                    f"observed network mode '{self.network_mode.value}' is insufficient"
                )

    def canonical_digest(self) -> str:
        """Compute RFC 8785 canonical JSON SHA-256 digest."""
        payload = {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "isolation_tier": self.isolation_tier.value,
            "network_mode": self.network_mode.value,
            "hardware": self.hardware.to_dict(),
            "software": self.software.to_dict(),
            "bounds": self.bounds.to_dict(),
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def detect_drift(self, observed: EnvironmentProfile) -> list[str]:
        """Compare self (reference profile) against observed runtime profile and identify drifts."""
        drifts: list[str] = []
        if self.isolation_tier != observed.isolation_tier:
            drifts.append(
                f"Isolation tier mismatch: declared '{self.isolation_tier.value}' vs observed '{observed.isolation_tier.value}'"
            )
        if self.network_mode != observed.network_mode:
            drifts.append(
                f"Network mode mismatch: declared '{self.network_mode.value}' vs observed '{observed.network_mode.value}'"
            )
        # Check required vector extensions
        for ext in self.hardware.vector_extensions:
            if ext not in observed.hardware.vector_extensions:
                drifts.append(f"Missing required hardware vector extension: '{ext}'")
        # Check accelerator requirement
        if self.hardware.accelerator_type != "NONE":
            if observed.hardware.accelerator_type != self.hardware.accelerator_type:
                drifts.append(
                    f"Accelerator mismatch: expected '{self.hardware.accelerator_type}' vs observed '{observed.hardware.accelerator_type}'"
                )
            if observed.hardware.accelerator_count < self.hardware.accelerator_count:
                drifts.append(
                    f"Insufficient accelerators: expected {self.hardware.accelerator_count} vs observed {observed.hardware.accelerator_count}"
                )
        # Check OS & Runtime
        if self.software.os_family != observed.software.os_family:
            drifts.append(
                f"OS family mismatch: expected '{self.software.os_family}' vs observed '{observed.software.os_family}'"
            )
        if self.software.python_runtime and self.software.python_runtime != observed.software.python_runtime:
            drifts.append(
                f"Python runtime mismatch: expected '{self.software.python_runtime}' vs observed '{observed.software.python_runtime}'"
            )
        if self.software.container_rootfs_digest and self.software.container_rootfs_digest != observed.software.container_rootfs_digest:
            drifts.append("Container rootfs digest mismatch")
        if self.software.package_manifest_digest and self.software.package_manifest_digest != observed.software.package_manifest_digest:
            drifts.append("Package manifest lockfile digest mismatch")
        # Check execution bounds expansion
        if observed.bounds.timeout_seconds > self.bounds.timeout_seconds:
            drifts.append(
                f"Timeout bound expanded: reference {self.bounds.timeout_seconds}s vs observed {observed.bounds.timeout_seconds}s"
            )
        if observed.bounds.max_memory_bytes > self.bounds.max_memory_bytes:
            drifts.append(
                f"Memory bound expanded: reference {self.bounds.max_memory_bytes} bytes vs observed {observed.bounds.max_memory_bytes} bytes"
            )
        return drifts

    def assert_conformance(self, observed: EnvironmentProfile) -> None:
        """Assert that observed environment conforms to declared profile without drift."""
        drifts = self.detect_drift(observed)
        if drifts:
            raise EnvironmentDriftError(
                f"Environment drift detected ({len(drifts)} violations): {'; '.join(drifts)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "isolation_tier": self.isolation_tier.value,
            "network_mode": self.network_mode.value,
            "hardware": self.hardware.to_dict(),
            "software": self.software.to_dict(),
            "bounds": self.bounds.to_dict(),
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EnvironmentProfile:
        return cls(
            profile_id=str(data["profile_id"]),
            isolation_tier=EnvironmentIsolationTier(data["isolation_tier"]),
            network_mode=NetworkIsolationMode(data["network_mode"]),
            hardware=HardwareSubstrate.from_dict(data["hardware"]),
            software=SoftwareSubstrate.from_dict(data["software"]),
            bounds=ExecutionBounds.from_dict(data["bounds"]),
            schema_version=str(data.get("schema_version", "VSTD-ENV-2.0.0")),
        )
