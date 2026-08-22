"""Intel Gaudi discovery boundary with honest unsupported degradation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..models import AdapterResult
from ..registry import AcceleratorRegistry, load_builtin_registry
from .base import unsupported_result
from .generic import GenericFixtureAdapter


@dataclass
class IntelGaudiAdapter:
    fixture_path: Path | None = None
    registry: AcceleratorRegistry | None = None
    adapter_id: str = "vstd3.intel-gaudi"

    def discover(self) -> AdapterResult:
        registry = self.registry or load_builtin_registry()
        if self.fixture_path is not None:
            return GenericFixtureAdapter(
                self.fixture_path,
                registry=registry,
                adapter_id=self.adapter_id,
            ).discover()
        return unsupported_result(
            adapter_id=self.adapter_id,
            profile_id="intel.gaudi",
            registry=registry,
            reason="no stable vendor-independent Gaudi attestation collector is configured",
        )

