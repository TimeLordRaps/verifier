"""Terminology: Advanced Micro Devices (AMD); application-specific integrated circuit (ASIC);
Verifier Standard (VSTD)."""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from verifier.hardware.adapters.amd import AmdAdapter
from verifier.hardware.adapters.base import AdapterError, evidence_source_from_bytes
from verifier.hardware.adapters.generic import GenericFixtureAdapter
from verifier.hardware.adapters.intel import IntelGaudiAdapter
from verifier.hardware.adapters.nvidia import NvidiaAdapter
from verifier.hardware.adapters.provider import (
    AwsNeuronProviderAdapter,
    GoogleTpuProviderAdapter,
    MicrosoftMaiaProviderAdapter,
    normalize_provider_evidence,
    sign_provider_fixture,
)
from verifier.hardware.claims import ClaimContext, evaluate_claim
from verifier.hardware.fleet import aggregate_partition_accounting, verify_fleet_observation
from verifier.hardware.models import (
    AccountingExactness,
    AccountingMethod,
    AccountingQuantity,
    Capability,
    ClaimKind,
    ClaimStatus,
    ComputeAccountingObservation,
    EvidenceProducer,
    FleetBoundary,
    FleetManifest,
    FleetMember,
    FleetObservation,
    LogicalDeviceIdentity,
    VerificationState,
)
from verifier.hardware.registry import AcceleratorRegistry, RegistryError, load_builtin_registry


def _write_fixture(path: Path, *, schema_version: str, profile_id: str) -> bytes:
    payload = {
        "schema_version": schema_version,
        "profile_id": profile_id,
        "observed_at": "2026-08-21T17:00:00Z",
        "boundary_id": "fixture-host",
        "devices": [
            {
                "device_id": "device-0",
                "model": "fixture accelerator",
                "architecture": "fixture-architecture",
                "serial": "serial-0",
                "deployment_class": "datacenter",
                "partitions": [
                    {
                        "partition_id": "partition-0",
                        "logical_id": "logical-0",
                        "mode": "slice",
                        "capacity_fraction_ppm": 500_000,
                    },
                    {
                        "partition_id": "partition-1",
                        "logical_id": "logical-1",
                        "mode": "slice",
                        "capacity_fraction_ppm": 500_000,
                    },
                ],
                "attributes": {"driver": "fixture-only"},
            }
        ],
    }
    raw = json.dumps(payload, sort_keys=True).encode()
    path.write_bytes(raw)
    return raw


@pytest.mark.parametrize(
    ("adapter_type", "schema_version", "profile_id"),
    [
        (NvidiaAdapter, "VSTD3-NVIDIA-FIXTURE-1.0", "nvidia.hopper"),
        (AmdAdapter, "VSTD3-AMD-FIXTURE-1.0", "amd.instinct-mi300"),
    ],
)
def test_vendor_fixture_adapters_preserve_raw_bytes_without_inventing_attestation(
    tmp_path: Path,
    adapter_type: type[NvidiaAdapter] | type[AmdAdapter],
    schema_version: str,
    profile_id: str,
) -> None:
    path = tmp_path / "vendor.json"
    raw = _write_fixture(path, schema_version=schema_version, profile_id=profile_id)
    result = adapter_type(fixture_path=path).discover()
    source = result.evidence_sources[0]

    assert base64.b64decode(source.raw_evidence_b64) == raw
    assert source.raw_evidence_digest == hashlib.sha256(raw).hexdigest()
    assert source.capabilities == (Capability.HOST_OBSERVED,)
    assert source.verification_state is VerificationState.NOT_VERIFIED
    assert result.attestation_evidence == ()
    assert len(result.partitions) == 2


@pytest.mark.parametrize(
    ("adapter_type", "schema_version", "profile_id", "field", "vendor"),
    [
        (NvidiaAdapter, "VSTD3-NVIDIA-FIXTURE-1.0", "nvidia.hopper", "attestation_evidence", "nvidia"),
        (AmdAdapter, "VSTD3-AMD-FIXTURE-1.0", "amd.instinct-mi300", "dice_evidence", "amd"),
    ],
)
def test_opaque_vendor_attestation_is_preserved_but_never_promoted(
    tmp_path: Path,
    adapter_type: type[NvidiaAdapter] | type[AmdAdapter],
    schema_version: str,
    profile_id: str,
    field: str,
    vendor: str,
) -> None:
    path = tmp_path / "vendor-opaque.json"
    _write_fixture(path, schema_version=schema_version, profile_id=profile_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    opaque = b"opaque-vendor-signed-envelope"
    payload[field] = [
        {
            "evidence_id": "opaque-0",
            "format": "vendor-opaque-test-envelope",
            "raw_evidence_b64": base64.b64encode(opaque).decode(),
            "observed_at": "2026-08-21T17:00:01Z",
            "subject_hint": "device-0",
        }
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = adapter_type(fixture_path=path).discover()
    opaque_source = next(item for item in result.evidence_sources if "opaque" in item.source_id)
    assert opaque_source.source_id == f"evidence:{vendor}-opaque:opaque-0"
    assert base64.b64decode(opaque_source.raw_evidence_b64) == opaque
    assert opaque_source.capabilities == (Capability.HOST_OBSERVED,)
    assert opaque_source.verification_state is VerificationState.NOT_VERIFIED
    assert result.attestation_evidence == ()
    assert result.evidence_gaps[-1].gap_type == "UNVERIFIED_VENDOR_ATTESTATION"


def test_generic_registry_extension_requires_no_core_code_change(tmp_path: Path) -> None:
    builtin = load_builtin_registry()
    custom = replace(
        builtin.get("generic.ai-asic"),
        profile_id="example.future-accelerator",
        vendor="Example Vendor",
        family="Future Accelerator",
        models=("Example X1",),
        documentation_refs=("https://example.invalid/spec",),
    )
    registry = AcceleratorRegistry((custom,), registry_version="test-1")
    path = tmp_path / "generic.json"
    _write_fixture(
        path,
        schema_version="VSTD3-GENERIC-FIXTURE-1.0",
        profile_id=custom.profile_id,
    )

    result = GenericFixtureAdapter(path, registry=registry).discover()
    assert result.profile_id == custom.profile_id
    assert result.descriptors[0].vendor == "Example Vendor"

    malformed = registry.to_dict()
    malformed["unrecognized"] = True
    with pytest.raises(RegistryError, match="unknown fields"):
        AcceleratorRegistry.from_dict(malformed)


def test_generic_fixture_rejects_unrecognized_signed_surface(tmp_path: Path) -> None:
    path = tmp_path / "generic.json"
    _write_fixture(
        path,
        schema_version="VSTD3-GENERIC-FIXTURE-1.0",
        profile_id="generic.ai-asic",
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["unrecognized"] = "must not be silently discarded"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AdapterError, match="unknown fields"):
        GenericFixtureAdapter(path).discover()


def test_generic_adapter_represents_multiple_devices_in_one_topology(tmp_path: Path) -> None:
    path = tmp_path / "multi.json"
    payload = {
        "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
        "profile_id": "generic.ai-asic",
        "observed_at": "2026-08-21T17:00:00Z",
        "boundary_id": "two-device-host",
        "devices": [
            {
                "device_id": device_id,
                "model": "Unknown future ASIC",
                "architecture": "future",
                "serial": f"serial-{device_id}",
                "deployment_class": "datacenter",
                "partitions": [],
                "attributes": {},
            }
            for device_id in ("device-a", "device-b")
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = GenericFixtureAdapter(path).discover()
    assert len(result.physical_identities) == 2
    assert len(result.logical_identities) == 2
    assert len(result.partitions) == 2
    assert {item.parent_physical_device_ids[0] for item in result.logical_identities} == {
        "physical:device-a",
        "physical:device-b",
    }


def test_firmware_attestation_does_not_imply_execution_or_accounting() -> None:
    raw = b"firmware evidence"
    source = evidence_source_from_bytes(
        source_id="firmware-source",
        producer=EvidenceProducer.FIRMWARE,
        mechanism="fixture",
        observed_at="2026-08-21T17:00:00Z",
        capabilities=(Capability.FIRMWARE_ATTESTED,),
        raw=raw,
        media_type="application/octet-stream",
        original_format="fixture",
        verification_state=VerificationState.VERIFIED,
    )
    context = ClaimContext(sources=(source,))
    firmware = evaluate_claim(
        claim_id="firmware", claim_kind=ClaimKind.FIRMWARE_INTEGRITY, subject_id="device", context=context
    )
    execution = evaluate_claim(
        claim_id="execution", claim_kind=ClaimKind.EXECUTION_ATTESTATION, subject_id="device", context=context
    )
    accounting = evaluate_claim(
        claim_id="accounting", claim_kind=ClaimKind.EXECUTION_ACCOUNTING, subject_id="device", context=context
    )
    assert firmware.status is ClaimStatus.PASS
    assert execution.status is ClaimStatus.UNKNOWN
    assert accounting.status is ClaimStatus.UNKNOWN


def test_provider_control_plane_evidence_remains_separate_from_hardware() -> None:
    key = b"provider-test-key"
    payload = sign_provider_fixture(
        {
            "schema_version": "VSTD3-PROVIDER-EVIDENCE-1.0",
            "evidence_id": "provider-evidence-0",
            "provider": "example-cloud",
            "resource_id": "resource-0",
            "issued_at": "2026-08-21T17:00:00Z",
            "expires_at": "2026-08-21T18:00:00Z",
            "claims": {"allocation": "accelerator-0"},
            "key_id": "provider-key",
            "hardware_evidence_refs": [],
        },
        key,
    )
    evidence, source = normalize_provider_evidence(
        json.dumps(payload, sort_keys=True).encode(), verification_key=key
    )
    assert evidence.verification_state is VerificationState.VERIFIED
    assert source.capabilities == (Capability.PROVIDER_ATTESTED,)
    hardware_claim = evaluate_claim(
        claim_id="device",
        claim_kind=ClaimKind.DEVICE_IDENTITY,
        subject_id="resource-0",
        context=ClaimContext(sources=(source,)),
    )
    assert hardware_claim.status is ClaimStatus.UNKNOWN


@pytest.mark.parametrize(
    ("adapter_type", "provider"),
    [
        (GoogleTpuProviderAdapter, "google-cloud-tpu"),
        (AwsNeuronProviderAdapter, "aws-neuron"),
        (MicrosoftMaiaProviderAdapter, "microsoft-azure-maia"),
    ],
)
def test_named_cloud_provider_fixture_boundaries(
    tmp_path: Path, adapter_type: type, provider: str
) -> None:
    key = b"provider-adapter-key"
    payload = sign_provider_fixture(
        {
            "schema_version": "VSTD3-PROVIDER-EVIDENCE-1.0",
            "evidence_id": f"{provider}-evidence",
            "provider": provider,
            "resource_id": "resource-0",
            "issued_at": "2026-08-21T17:00:00Z",
            "expires_at": "2026-08-21T18:00:00Z",
            "claims": {"allocation": "accelerator-slice"},
            "key_id": "provider-key",
            "hardware_evidence_refs": [],
        },
        key,
    )
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = adapter_type(fixture_path=path, verification_key=key).collect()
    assert result.evidence.provider == provider
    assert result.evidence.verification_state is VerificationState.VERIFIED
    assert result.source.producer is EvidenceProducer.PROVIDER_CONTROL_PLANE

    payload.pop("hardware_evidence_refs")
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AdapterError, match="missing fields"):
        adapter_type(fixture_path=path, verification_key=key).collect()


def test_fleet_completeness_is_exactly_boundary_relative() -> None:
    manifest = FleetManifest(
        manifest_id="fleet-0",
        boundary=FleetBoundary("boundary-0", "org", "site", "cluster", "rack", "host", "set"),
        members=(
            FleetMember(
                member_id="member-0",
                physical_device_ids=("physical-0",),
                logical_device_ids=("logical-0",),
                expected_profile_id="generic.ai-asic",
                enrolled_at="2026-08-21T17:00:00Z",
            ),
        ),
        effective_at="2026-08-21T17:00:00Z",
        evidence_source_ids=("fleet-source",),
    )
    observation = FleetObservation(
        observation_id="observation-0",
        manifest_id=manifest.manifest_id,
        interval_start="2026-08-21T17:00:00Z",
        interval_end="2026-08-21T18:00:00Z",
        observed_member_ids=("member-0",),
        missing_member_ids=(),
        unexpected_device_ids=(),
        last_anchor_ids=("anchor-0",),
        topology_snapshot_id="topology-0",
        evidence_source_ids=("fleet-source",),
    )
    assert verify_fleet_observation(manifest, observation).valid
    fleet_claim = evaluate_claim(
        claim_id="fleet",
        claim_kind=ClaimKind.FLEET_COMPLETENESS,
        subject_id=manifest.manifest_id,
        context=ClaimContext(sources=(), fleet_boundary_verified=True),
    )
    world_claim = evaluate_claim(
        claim_id="world",
        claim_kind=ClaimKind.PHYSICAL_WORLD_COMPLETENESS,
        subject_id="world",
        context=ClaimContext(sources=(), fleet_boundary_verified=True),
    )
    assert fleet_claim.status is ClaimStatus.PASS
    assert world_claim.status is ClaimStatus.UNSUPPORTED

    missing = replace(observation, observed_member_ids=(), missing_member_ids=("member-0",))
    result = verify_fleet_observation(manifest, missing)
    assert not result.valid
    assert "missing enrolled fleet members" in result.errors[0]


def _observation(observation_id: str, scope_id: str, value: str) -> ComputeAccountingObservation:
    return ComputeAccountingObservation(
        observation_id=observation_id,
        execution_id="execution",
        device_scope_ids=(scope_id,),
        observed_at="2026-08-21T17:00:00Z",
        quantities=(
            AccountingQuantity(
                name="operations",
                value=value,
                unit="operations",
                method=AccountingMethod.FIRMWARE_COUNTER,
                evidence_source_id="source",
                scope="counter",
                exactness=AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
            ),
        ),
        evidence_source_ids=("source",),
    )


def test_partition_accounting_aggregates_repeated_intervals_but_not_mixed_geometry() -> None:
    logical = (
        LogicalDeviceIdentity("logical-a", ("physical-0",), "partition-a", "slice", 500_000, "source"),
        LogicalDeviceIdentity("logical-b", ("physical-0",), "partition-b", "slice", 500_000, "source"),
    )
    result = aggregate_partition_accounting(
        (
            _observation("a0", "logical-a", "10"),
            _observation("a1", "logical-a", "11"),
            _observation("b0", "logical-b", "20"),
        ),
        logical,
    )
    assert result.errors == ()
    assert result.totals[("physical-0", "operations", "operations")] == "41"

    mixed = aggregate_partition_accounting(
        (_observation("logical", "logical-a", "10"), _observation("physical", "physical-0", "20")),
        logical,
    )
    assert any("physical and logical scopes" in error for error in mixed.errors)

    oversubscribed = replace(logical[1], capacity_fraction_ppm=600_000)
    over = aggregate_partition_accounting((_observation("a", "logical-a", "1"),), (logical[0], oversubscribed))
    assert any("exceed physical capacity" in error for error in over.errors)


def test_unsupported_adapter_records_a_gap_instead_of_guessing() -> None:
    result = IntelGaudiAdapter().discover()
    assert result.descriptors == ()
    assert result.evidence_sources == ()
    assert len(result.evidence_gaps) == 1
    assert result.evidence_gaps[0].gap_type == "UNSUPPORTED_HARDWARE_OR_COLLECTOR"
