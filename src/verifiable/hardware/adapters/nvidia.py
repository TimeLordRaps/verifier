"""NVIDIA NVML/nvidia-smi discovery and offline evidence normalization."""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import subprocess

from ..models import AdapterResult
from ..registry import AcceleratorRegistry, load_builtin_registry
from .base import AdapterError, normalize_opaque_vendor_evidence, unsupported_result
from .generic import GenericFixtureAdapter


def _profile_for_model(model: str) -> str:
    upper = model.upper()
    if any(token in upper for token in ("B300", "GB300")):
        return "nvidia.blackwell-ultra"
    if any(token in upper for token in ("B100", "B200", "GB200")):
        return "nvidia.blackwell"
    if any(token in upper for token in ("H100", "H200", "GH200")):
        return "nvidia.hopper"
    return "nvidia.future"


@dataclass
class NvidiaAdapter:
    fixture_path: Path | None = None
    registry: AcceleratorRegistry | None = None
    adapter_id: str = "vstd3.nvidia"

    def discover(self) -> AdapterResult:
        registry = self.registry or load_builtin_registry()
        if self.fixture_path is not None:
            return self._from_fixture(self.fixture_path, registry)
        executable = shutil.which("nvidia-smi")
        if executable is None:
            return unsupported_result(
                adapter_id=self.adapter_id,
                profile_id="nvidia.future",
                registry=registry,
                reason="nvidia-smi was not found; no NVIDIA hardware evidence was collected",
            )
        result = subprocess.run(
            [
                executable,
                "--query-gpu=uuid,name,pci.bus_id,driver_version,vbios_version",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return unsupported_result(
                adapter_id=self.adapter_id,
                profile_id="nvidia.future",
                registry=registry,
                reason=f"nvidia-smi discovery failed with exit code {result.returncode}",
            )
        rows = list(csv.reader(io.StringIO(result.stdout.decode("utf-8", errors="strict"))))
        devices = []
        profile_ids: set[str] = set()
        for index, row in enumerate(rows):
            if len(row) != 5:
                raise AdapterError(f"nvidia-smi row {index} had {len(row)} fields, expected 5")
            uuid, model, pci_bus, driver, vbios = (item.strip() for item in row)
            profile_ids.add(_profile_for_model(model))
            devices.append(
                {
                    "device_id": uuid,
                    "model": model,
                    "architecture": registry.get(_profile_for_model(model)).architecture,
                    "serial": uuid,
                    "deployment_class": "datacenter",
                    "partitions": [],
                    "attributes": {
                        "pci_bus_id": pci_bus,
                        "driver_version": driver,
                        "vbios_version": vbios,
                    },
                }
            )
        if len(profile_ids) != 1:
            profile_id = "nvidia.future"
        else:
            profile_id = next(iter(profile_ids))
        payload = {
            "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
            "profile_id": profile_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "boundary_id": "host-visible-nvidia-devices",
            "devices": devices,
        }
        return self._normalize_payload(payload, result.stdout, registry)

    def _from_fixture(self, path: Path, registry: AcceleratorRegistry) -> AdapterResult:
        raw = path.read_bytes()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"malformed NVIDIA fixture: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != "VSTD3-NVIDIA-FIXTURE-1.0":
            raise AdapterError("NVIDIA fixture must use VSTD3-NVIDIA-FIXTURE-1.0")
        allowed = {"schema_version", "profile_id", "observed_at", "boundary_id", "devices", "attestation_evidence"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise AdapterError(f"NVIDIA fixture has unknown fields: {', '.join(unknown)}")
        missing = sorted({"profile_id", "observed_at", "devices"} - set(payload))
        if missing:
            raise AdapterError(f"NVIDIA fixture is missing fields: {', '.join(missing)}")
        generic_payload = {
            "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
            "profile_id": payload["profile_id"],
            "observed_at": payload["observed_at"],
            "boundary_id": payload.get("boundary_id", "fixture-nvidia-devices"),
            "devices": payload["devices"],
        }
        result = self._normalize_payload(generic_payload, raw, registry)
        opaque_sources, opaque_gaps = normalize_opaque_vendor_evidence(
            payload.get("attestation_evidence"),
            vendor="NVIDIA",
            default_observed_at=str(payload["observed_at"]),
        )
        return replace(
            result,
            evidence_sources=(*result.evidence_sources, *opaque_sources),
            evidence_gaps=(*result.evidence_gaps, *opaque_gaps),
        )

    def _normalize_payload(
        self,
        payload: dict,
        raw: bytes,
        registry: AcceleratorRegistry,
    ) -> AdapterResult:
        # GenericFixtureAdapter accepts a path so normalization remains one implementation.
        # The temporary is never used: construct the same payload through a private in-memory shim.
        adapter = _InMemoryGenericAdapter(payload=payload, raw=raw, registry=registry, adapter_id=self.adapter_id)
        return adapter.discover()


@dataclass
class _InMemoryGenericAdapter(GenericFixtureAdapter):
    payload: dict | None = None
    raw: bytes = b""

    def __init__(self, *, payload: dict, raw: bytes, registry: AcceleratorRegistry, adapter_id: str) -> None:
        self.payload = payload
        self.raw = raw
        self.registry = registry
        self.adapter_id = adapter_id
        self.fixture_path = Path("<in-memory>")

    def discover(self) -> AdapterResult:
        # Use a deterministic temporary file outside the repository's semantic surface.
        import tempfile

        with tempfile.TemporaryDirectory(prefix="vstd3-nvidia-") as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps(self.payload, sort_keys=True), encoding="utf-8")
            result = GenericFixtureAdapter(path, registry=self.registry, adapter_id=self.adapter_id).discover()
        # Preserve the exact original vendor bytes rather than the normalization JSON.
        from .base import evidence_source_from_bytes
        from ..models import Capability, EvidenceProducer

        original_source = evidence_source_from_bytes(
            source_id=result.evidence_sources[0].source_id,
            producer=EvidenceProducer.SOFTWARE_COLLECTOR,
            mechanism="NVIDIA NVML/nvidia-smi or offline fixture normalization",
            observed_at=result.evidence_sources[0].observed_at,
            capabilities=(Capability.HOST_OBSERVED,),
            raw=self.raw,
            media_type="application/json" if self.raw.lstrip().startswith(b"{") else "text/csv",
            original_format="NVIDIA evidence preserved verbatim",
            limitations=(
                "Normalization does not cryptographically verify SPDM, certificate, RIM, or nonce claims.",
                "Host discovery does not prove execution accounting or complete mediation.",
            ),
        )
        source_id = original_source.source_id
        physical = tuple(
            type(identity)(
                identity_id=identity.identity_id,
                descriptor_id=identity.descriptor_id,
                serial_commitment=identity.serial_commitment,
                certificate_digest=identity.certificate_digest,
                hardware_revision=identity.hardware_revision,
                evidence_source_id=source_id,
            )
            for identity in result.physical_identities
        )
        logical = tuple(
            type(identity)(
                logical_id=identity.logical_id,
                parent_physical_device_ids=identity.parent_physical_device_ids,
                partition_id=identity.partition_id,
                virtualization_mode=identity.virtualization_mode,
                capacity_fraction_ppm=identity.capacity_fraction_ppm,
                evidence_source_id=source_id,
            )
            for identity in result.logical_identities
        )
        topology = tuple(
            type(snapshot)(
                snapshot_id=snapshot.snapshot_id,
                boundary_id=snapshot.boundary_id,
                observed_at=snapshot.observed_at,
                nodes=snapshot.nodes,
                links=snapshot.links,
                evidence_source_ids=(source_id,),
                completeness_claimed=False,
            )
            for snapshot in result.topology_snapshots
        )
        return AdapterResult(
            adapter_id=result.adapter_id,
            profile_id=result.profile_id,
            descriptors=result.descriptors,
            physical_identities=physical,
            logical_identities=logical,
            partitions=result.partitions,
            topology_snapshots=topology,
            evidence_sources=(original_source,),
            attestation_challenges=(),
            attestation_evidence=(),
            capability_declarations=result.capability_declarations,
            evidence_gaps=result.evidence_gaps,
        )
