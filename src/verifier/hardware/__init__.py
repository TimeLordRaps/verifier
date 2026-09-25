"""Terminology: Verifier Standard (VSTD).

VSTD 3 accelerator-accountability reference implementation."""

from .conformance import ConformanceProfile, evaluate_conformance
from .diode_emulator import (
    DIODE_EMULATOR_DISCLAIMER_DIGEST,
    DIODE_EMULATOR_DISCLAIMER_TEXT,
    EmulatedDiodeAttestationReceipt,
    SeveredChannelReadViolationError,
    SoftwareOneWayDataDiodeEmulator,
)
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
    "DIODE_EMULATOR_DISCLAIMER_DIGEST",
    "DIODE_EMULATOR_DISCLAIMER_TEXT",
    "EmulatedDiodeAttestationReceipt",
    "EvidenceGap",
    "EvidenceSource",
    "FleetManifest",
    "FleetObservation",
    "LogicalDeviceIdentity",
    "PhysicalDeviceIdentity",
    "SeveredChannelReadViolationError",
    "SoftwareOneWayDataDiodeEmulator",
    "TopologySnapshot",
    "VSTD3Receipt",
    "VirtualVSTDAccelerator",
    "evaluate_conformance",
    "load_builtin_registry",
    "validate_vstd3_receipt",
]
