"""Terminology: Verifier Standard (VSTD).

VSTD 3 accelerator-accountability reference implementation."""

from .conformance import ConformanceProfile, evaluate_conformance
from .emulator import VirtualVSTDAccelerator
from .models import (
    AcceleratorDescriptor,
    AccountingEvent,
    AccountingExactness,
    AccountingMethod,
    AccountingQuantity,
    Capability,
    ClaimEvaluation,
    ClaimKind,
    ClaimStatus,
    ContinuityRecord,
    EvidenceGap,
    EvidenceSource,
    FleetManifest,
    FleetObservation,
    LogicalDeviceIdentity,
    PhysicalDeviceIdentity,
    TopologySnapshot,
    VSTD3Receipt,
)
from .registry import load_builtin_registry
from .validation import validate_vstd3_receipt

__all__ = [
    "AcceleratorDescriptor",
    "AccountingEvent",
    "AccountingExactness",
    "AccountingMethod",
    "AccountingQuantity",
    "Capability",
    "ConformanceProfile",
    "ClaimEvaluation",
    "ClaimKind",
    "ClaimStatus",
    "ContinuityRecord",
    "EvidenceGap",
    "EvidenceSource",
    "FleetManifest",
    "FleetObservation",
    "LogicalDeviceIdentity",
    "PhysicalDeviceIdentity",
    "TopologySnapshot",
    "VSTD3Receipt",
    "VirtualVSTDAccelerator",
    "evaluate_conformance",
    "load_builtin_registry",
    "validate_vstd3_receipt",
]
