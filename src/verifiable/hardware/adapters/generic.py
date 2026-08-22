"""Registry-driven generic fixture adapter for unknown and future accelerators."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Mapping

from ..canonical import canonical_digest, canonical_json_bytes
from ..models import (
    AcceleratorDescriptor,
    AcceleratorPartition,
    AdapterResult,
    Capability,
    ComponentKind,
    EvidenceProducer,
    LogicalDeviceIdentity,
    PhysicalDeviceIdentity,
    TopologyLink,
    TopologyNode,
    TopologySnapshot,
)
from ..registry import AcceleratorRegistry, load_builtin_registry
from .base import AdapterError, evidence_source_from_bytes


@dataclass
class GenericFixtureAdapter:
    fixture_path: Path
    registry: AcceleratorRegistry | None = None
    adapter_id: str = "vstd3.generic-fixture"

    def discover(self) -> AdapterResult:
        registry = self.registry or load_builtin_registry()
        raw = self.fixture_path.read_bytes()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"malformed generic accelerator fixture: {exc}") from exc
        if not isinstance(payload, Mapping) or payload.get("schema_version") != "VSTD3-GENERIC-FIXTURE-1.0":
            raise AdapterError("generic fixture must use VSTD3-GENERIC-FIXTURE-1.0")
        allowed = {"schema_version", "profile_id", "observed_at", "boundary_id", "devices"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise AdapterError(f"generic fixture has unknown fields: {', '.join(unknown)}")
        profile_id = payload.get("profile_id")
        observed_at = payload.get("observed_at")
        devices = payload.get("devices")
        if not isinstance(profile_id, str) or not isinstance(observed_at, str) or not isinstance(devices, list):
            raise AdapterError("generic fixture profile_id/observed_at/devices are invalid")
        boundary_id = payload.get("boundary_id", "fixture-boundary")
        if not isinstance(boundary_id, str):
            raise AdapterError("generic fixture boundary_id must be a string")
        profile = registry.get(profile_id)
        source_id = f"evidence:{self.adapter_id}:{hashlib.sha256(raw).hexdigest()[:16]}"
        source = evidence_source_from_bytes(
            source_id=source_id,
            producer=EvidenceProducer.SOFTWARE_COLLECTOR,
            mechanism="generic fixture normalization",
            observed_at=observed_at,
            capabilities=(Capability.HOST_OBSERVED,),
            raw=raw,
            media_type="application/json",
            original_format="VSTD3-GENERIC-FIXTURE-1.0",
            limitations=(
                "Fixture content is host/software supplied and does not establish device attestation.",
            ),
        )
        descriptors: list[AcceleratorDescriptor] = []
        physical: list[PhysicalDeviceIdentity] = []
        logical: list[LogicalDeviceIdentity] = []
        partitions: list[AcceleratorPartition] = []
        nodes: list[TopologyNode] = []
        links: list[TopologyLink] = []
        seen_devices: set[str] = set()
        seen_partitions: set[str] = set()
        seen_logical: set[str] = set()
        for index, item in enumerate(devices):
            if not isinstance(item, Mapping):
                raise AdapterError(f"device {index} must be an object")
            allowed_device = {
                "device_id",
                "model",
                "architecture",
                "serial",
                "deployment_class",
                "partitions",
                "attributes",
            }
            unknown_device = sorted(set(item) - allowed_device)
            if unknown_device:
                raise AdapterError(f"device {index} has unknown fields: {', '.join(unknown_device)}")
            device_id = item.get("device_id")
            model = item.get("model")
            if not isinstance(device_id, str) or not device_id or not isinstance(model, str):
                raise AdapterError(f"device {index} requires string device_id and model")
            if device_id in seen_devices:
                raise AdapterError(f"duplicate device_id {device_id}")
            seen_devices.add(device_id)
            for string_field in ("architecture", "serial", "deployment_class"):
                if string_field in item and not isinstance(item[string_field], str):
                    raise AdapterError(f"device {index} {string_field} must be a string")
            attributes = item.get("attributes", {})
            if not isinstance(attributes, Mapping):
                raise AdapterError(f"device {index} attributes must be an object")
            try:
                canonical_json_bytes(dict(attributes))
            except (TypeError, ValueError) as exc:
                raise AdapterError(f"device {index} attributes are not canonical JSON: {exc}") from exc
            descriptor_id = f"descriptor:{device_id}"
            physical_id = f"physical:{device_id}"
            descriptors.append(
                AcceleratorDescriptor(
                    descriptor_id=descriptor_id,
                    profile_id=profile_id,
                    vendor=profile.vendor,
                    family=profile.family,
                    architecture=str(item.get("architecture", profile.architecture)),
                    model=model,
                    device_class=profile.device_class,
                    deployment_class=str(item.get("deployment_class", profile.deployment_classes[0])),
                    discovery_method="generic fixture",
                    attributes=dict(attributes),
                )
            )
            physical.append(
                PhysicalDeviceIdentity(
                    identity_id=physical_id,
                    descriptor_id=descriptor_id,
                    serial_commitment=hashlib.sha256(str(item.get("serial", "")).encode()).hexdigest(),
                    certificate_digest="",
                    hardware_revision="",
                    evidence_source_id=source_id,
                )
            )
            physical_node_id = f"node:{physical_id}"
            nodes.append(
                TopologyNode(
                    node_id=physical_node_id,
                    component_kind=ComponentKind.PHYSICAL_DEVICE,
                    profile_id=profile_id,
                    physical_identity_id=physical_id,
                )
            )
            partition_items = item.get("partitions", [])
            if not isinstance(partition_items, list):
                raise AdapterError(f"device {index} partitions must be an array")
            if not partition_items:
                partition_items = [
                    {
                        "partition_id": f"partition:{device_id}:whole",
                        "logical_id": f"logical:{device_id}:whole",
                        "mode": "whole-device",
                        "capacity_fraction_ppm": 1_000_000,
                    }
                ]
            device_fraction = 0
            for partition_item in partition_items:
                if not isinstance(partition_item, Mapping):
                    raise AdapterError("partition entries must be objects")
                required = {"partition_id", "logical_id", "mode", "capacity_fraction_ppm"}
                if set(partition_item) != required:
                    raise AdapterError("partition entries require exactly partition_id/logical_id/mode/capacity_fraction_ppm")
                logical_id = partition_item["logical_id"]
                partition_id_value = partition_item["partition_id"]
                mode = partition_item["mode"]
                if not all(isinstance(value, str) and value for value in (partition_id_value, logical_id, mode)):
                    raise AdapterError("partition identifiers and mode must be non-empty strings")
                partition_id = partition_id_value
                if partition_id in seen_partitions:
                    raise AdapterError(f"duplicate partition_id {partition_id}")
                if logical_id in seen_logical:
                    raise AdapterError(f"duplicate logical_id {logical_id}")
                seen_partitions.add(partition_id)
                seen_logical.add(logical_id)
                fraction = partition_item["capacity_fraction_ppm"]
                if type(fraction) is not int:
                    raise AdapterError("capacity_fraction_ppm must be an integer")
                device_fraction += fraction
                if device_fraction > 1_000_000:
                    raise AdapterError(f"device {device_id} partitions exceed physical capacity")
                logical.append(
                    LogicalDeviceIdentity(
                        logical_id=logical_id,
                        parent_physical_device_ids=(physical_id,),
                        partition_id=partition_id,
                        virtualization_mode=mode,
                        capacity_fraction_ppm=fraction,
                        evidence_source_id=source_id,
                    )
                )
                partitions.append(
                    AcceleratorPartition(
                        partition_id=partition_id,
                        parent_physical_device_id=physical_id,
                        logical_device_ids=(logical_id,),
                        partition_mode=mode,
                        capacity_fraction_ppm=fraction,
                        configuration_digest=canonical_digest(dict(partition_item)),
                    )
                )
                partition_node = f"node:{partition_id}"
                logical_node = f"node:{logical_id}"
                nodes.extend(
                    [
                        TopologyNode(
                            node_id=partition_node,
                            component_kind=ComponentKind.PARTITION,
                            parent_node_ids=(physical_node_id,),
                        ),
                        TopologyNode(
                            node_id=logical_node,
                            component_kind=ComponentKind.LOGICAL_DEVICE,
                            logical_identity_id=logical_id,
                            parent_node_ids=(partition_node,),
                        ),
                    ]
                )
                links.extend(
                    [
                        TopologyLink(physical_node_id, partition_node, "CONTAINS"),
                        TopologyLink(partition_node, logical_node, "EXPOSES"),
                    ]
                )
        snapshot = TopologySnapshot(
            snapshot_id=f"topology:{hashlib.sha256(raw).hexdigest()[:16]}",
            boundary_id=boundary_id,
            observed_at=observed_at,
            nodes=tuple(nodes),
            links=tuple(links),
            evidence_source_ids=(source_id,),
            completeness_claimed=False,
        )
        return AdapterResult(
            adapter_id=self.adapter_id,
            profile_id=profile_id,
            descriptors=tuple(descriptors),
            physical_identities=tuple(physical),
            logical_identities=tuple(logical),
            partitions=tuple(partitions),
            topology_snapshots=(snapshot,),
            evidence_sources=(source,),
            attestation_challenges=(),
            attestation_evidence=(),
            capability_declarations=profile.capability_declarations,
            evidence_gaps=(),
        )
