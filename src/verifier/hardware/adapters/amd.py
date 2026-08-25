"""Terminology: Advanced Micro Devices (AMD); application-specific integrated circuit (ASIC);
JavaScript Object Notation (JSON); system management interface (SMI); Verifier Standard (VSTD).

AMD SMI/ROCm discovery and offline evidence normalization."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess

from ..models import AdapterResult
from ..registry import AcceleratorRegistry, load_builtin_registry
from .base import AdapterError, normalize_opaque_vendor_evidence, unsupported_result
from .nvidia import _InMemoryGenericAdapter


def _profile_for_model(model: str) -> str:
    upper = model.upper()
    if "MI355" in upper or "MI350" in upper:
        return "amd.instinct-mi350"
    if "MI325" in upper:
        return "amd.instinct-mi325"
    if "MI300" in upper:
        return "amd.instinct-mi300"
    return "amd.cdna-future"


@dataclass
class AmdAdapter:
    fixture_path: Path | None = None
    registry: AcceleratorRegistry | None = None
    adapter_id: str = "vstd3.amd"

    def discover(self) -> AdapterResult:
        registry = self.registry or load_builtin_registry()
        if self.fixture_path is not None:
            raw = self.fixture_path.read_bytes()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AdapterError(f"malformed AMD fixture: {exc}") from exc
            if not isinstance(payload, dict) or payload.get("schema_version") != "VSTD3-AMD-FIXTURE-1.0":
                raise AdapterError("AMD fixture must use VSTD3-AMD-FIXTURE-1.0")
            allowed = {"schema_version", "profile_id", "observed_at", "boundary_id", "devices", "dice_evidence"}
            unknown = sorted(set(payload) - allowed)
            if unknown:
                raise AdapterError(f"AMD fixture has unknown fields: {', '.join(unknown)}")
            missing = sorted({"profile_id", "observed_at", "devices"} - set(payload))
            if missing:
                raise AdapterError(f"AMD fixture is missing fields: {', '.join(missing)}")
            generic = {
                "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
                "profile_id": payload["profile_id"],
                "observed_at": payload["observed_at"],
                "boundary_id": payload.get("boundary_id", "fixture-amd-devices"),
                "devices": payload["devices"],
            }
            fixture_result = _InMemoryGenericAdapter(
                payload=generic,
                raw=raw,
                registry=registry,
                adapter_id=self.adapter_id,
            ).discover()
            opaque_sources, opaque_gaps = normalize_opaque_vendor_evidence(
                payload.get("dice_evidence"),
                vendor="AMD",
                default_observed_at=str(payload["observed_at"]),
            )
            return replace(
                fixture_result,
                evidence_sources=(*fixture_result.evidence_sources, *opaque_sources),
                evidence_gaps=(*fixture_result.evidence_gaps, *opaque_gaps),
            )
        executable = shutil.which("amd-smi")
        if executable is None:
            return unsupported_result(
                adapter_id=self.adapter_id,
                profile_id="amd.cdna-future",
                registry=registry,
                reason="amd-smi was not found; no AMD hardware evidence was collected",
            )
        result = subprocess.run(
            [executable, "static", "--json"], capture_output=True, check=False
        )
        if result.returncode != 0:
            return unsupported_result(
                adapter_id=self.adapter_id,
                profile_id="amd.cdna-future",
                registry=registry,
                reason=f"amd-smi discovery failed with exit code {result.returncode}",
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"amd-smi returned malformed JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AdapterError("amd-smi JSON root must be an object")
        devices = []
        profile_ids: set[str] = set()
        for device_key, record in sorted(payload.items()):
            if not isinstance(record, dict):
                continue
            model = str(record.get("ASIC Market Name", record.get("name", "unknown AMD accelerator")))
            uuid = str(record.get("UUID", record.get("uuid", device_key)))
            profile_id = _profile_for_model(model)
            profile_ids.add(profile_id)
            devices.append(
                {
                    "device_id": uuid,
                    "model": model,
                    "architecture": registry.get(profile_id).architecture,
                    "serial": uuid,
                    "deployment_class": "datacenter",
                    "partitions": [],
                    "attributes": record,
                }
            )
        profile_id = next(iter(profile_ids)) if len(profile_ids) == 1 else "amd.cdna-future"
        generic = {
            "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
            "profile_id": profile_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "boundary_id": "host-visible-amd-devices",
            "devices": devices,
        }
        return _InMemoryGenericAdapter(
            payload=generic,
            raw=result.stdout,
            registry=registry,
            adapter_id=self.adapter_id,
        ).discover()
