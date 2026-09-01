"""Terminology: application programming interface (API); Verifier Standard (VSTD).

VSTD reference implementation public API."""

from __future__ import annotations

from importlib import import_module
import warnings
from typing import TYPE_CHECKING, Any

__version__ = "1.2.0"
# This names the highest project-specification coordinate exposed by the package;
# it is not a conformance claim. Keep the adjacent status when presenting it.
__standard__ = "VSTD-5"
__standard_status__ = "PROJECT SPECIFICATION; EVIDENCE-BOUND REFERENCE MECHANISM"

_LAZY_EXPORTS = {
    "ArtifactControlError": ("verifier.artifact_control", "ArtifactControlError"),
    "ArtifactVerification": ("verifier.artifact_control", "ArtifactVerification"),
    "freeze_artifact": ("verifier.artifact_control", "freeze_artifact"),
    "seal_artifact": ("verifier.artifact_control", "seal_artifact"),
    "thaw_artifact": ("verifier.artifact_control", "thaw_artifact"),
    "thawed_artifact_status": (
        "verifier.artifact_control",
        "thawed_artifact_status",
    ),
    "verify_frozen_artifact": (
        "verifier.artifact_control",
        "verify_frozen_artifact",
    ),
    "VerificationVerdict": ("verifier.core.checker", "VerificationVerdict"),
    "VstdReceipt": ("verifier.core.receipt", "VstdReceipt"),
    "compute_canonical_digest": ("verifier.core.receipt", "compute_canonical_digest"),
    "ReproducibilityLevel": ("verifier.core.reproducibility", "ReproducibilityLevel"),
    "capture_run": ("verifier.core.run", "capture_run"),
    "validate_run_receipt": ("verifier.core.run", "validate_run_receipt"),
    "VerificationGeometry": ("verifier.core.geometry", "VerificationGeometry"),
    "DecisionCertificate": ("verifier.core.certificate", "DecisionCertificate"),
    "certificate_from_canonical_bytes": (
        "verifier.core.certificate",
        "certificate_from_canonical_bytes",
    ),
    "vstd4_depth": ("verifier.core.depth", "vstd4_depth"),
    "establish_vstd4": ("verifier.core.depth", "establish_vstd4"),
    "build_evidence_bound_vstd4_receipt": (
        "verifier.core.depth",
        "build_evidence_bound_vstd4_receipt",
    ),
    "claim_binding_from_dict": ("verifier.core.depth", "claim_binding_from_dict"),
    "recheck_evidence_bound_vstd4_receipt": (
        "verifier.core.depth",
        "recheck_evidence_bound_vstd4_receipt",
    ),
    "require_vstd5_entry": ("verifier.core.depth", "require_vstd5_entry"),
    "BoundProposition": ("verifier.core.evidence", "BoundProposition"),
    "EvidenceBounds": ("verifier.core.evidence", "EvidenceBounds"),
    "EvidenceStore": ("verifier.core.evidence", "EvidenceStore"),
    "EvidenceBindingError": ("verifier.core.evidence", "EvidenceBindingError"),
    "MechanismDecision": ("verifier.core.evidence", "MechanismDecision"),
    "MechanismOutcome": ("verifier.core.evidence", "MechanismOutcome"),
    "VerificationSession": ("verifier.core.evidence", "VerificationSession"),
    "WitnessBundle": ("verifier.core.witness", "WitnessBundle"),
    "assess_witness_corroboration": (
        "verifier.core.witness",
        "assess_witness_corroboration",
    ),
    "build_vstd5_receipt": ("verifier.core.witness", "build_vstd5_receipt"),
    "recheck_vstd5_receipt": ("verifier.core.witness", "recheck_vstd5_receipt"),
    "AssuranceLedger": ("verifier.data.assurance", "AssuranceLedger"),
    "ObligationCoordinate": ("verifier.data.assurance", "ObligationCoordinate"),
    "recheck_assurance_log": (
        "verifier.data.assurance",
        "recheck_assurance_log",
    ),
    "ProvenanceHypergraph": ("verifier.data.models", "ProvenanceHypergraph"),
    "establish_graph_level": (
        "verifier.data.graph_level",
        "establish_graph_level",
    ),
    "build_evidence_bound_graph_level_record": (
        "verifier.data.graph_level",
        "build_evidence_bound_graph_level_record",
    ),
    "graph_collection_binding_digest": (
        "verifier.data.graph_level",
        "graph_collection_binding_digest",
    ),
    "recheck_evidence_bound_graph_level_record": (
        "verifier.data.graph_level",
        "recheck_evidence_bound_graph_level_record",
    ),
}

# Supported names remain in _LAZY_EXPORTS while deprecated. Each entry records the
# first release carrying the warning and the supported replacement.
_API_DEPRECATIONS: dict[str, tuple[str, str]] = {}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    deprecation = _API_DEPRECATIONS.get(name)
    if deprecation is not None:
        since, replacement = deprecation
        warnings.warn(
            f"verifier.{name} is deprecated since {since}; use {replacement}",
            DeprecationWarning,
            stacklevel=2,
        )
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


if TYPE_CHECKING:
    from verifier.artifact_control import (
        ArtifactControlError as ArtifactControlError,
        ArtifactVerification as ArtifactVerification,
        freeze_artifact as freeze_artifact,
        seal_artifact as seal_artifact,
        thaw_artifact as thaw_artifact,
        thawed_artifact_status as thawed_artifact_status,
        verify_frozen_artifact as verify_frozen_artifact,
    )
    from verifier.core.checker import VerificationVerdict as VerificationVerdict
    from verifier.core.geometry import VerificationGeometry as VerificationGeometry
    from verifier.core.certificate import (
        DecisionCertificate as DecisionCertificate,
        certificate_from_canonical_bytes as certificate_from_canonical_bytes,
    )
    from verifier.core.depth import (
        build_evidence_bound_vstd4_receipt as build_evidence_bound_vstd4_receipt,
        claim_binding_from_dict as claim_binding_from_dict,
        establish_vstd4 as establish_vstd4,
        recheck_evidence_bound_vstd4_receipt as recheck_evidence_bound_vstd4_receipt,
        require_vstd5_entry as require_vstd5_entry,
        vstd4_depth as vstd4_depth,
    )
    from verifier.core.evidence import (
        BoundProposition as BoundProposition,
        EvidenceBindingError as EvidenceBindingError,
        EvidenceBounds as EvidenceBounds,
        EvidenceStore as EvidenceStore,
        MechanismDecision as MechanismDecision,
        MechanismOutcome as MechanismOutcome,
        VerificationSession as VerificationSession,
    )
    from verifier.core.witness import (
        WitnessBundle as WitnessBundle,
        assess_witness_corroboration as assess_witness_corroboration,
        build_vstd5_receipt as build_vstd5_receipt,
        recheck_vstd5_receipt as recheck_vstd5_receipt,
    )
    from verifier.data.assurance import (
        AssuranceLedger as AssuranceLedger,
        ObligationCoordinate as ObligationCoordinate,
        recheck_assurance_log as recheck_assurance_log,
    )
    from verifier.data.graph_level import (
        build_evidence_bound_graph_level_record as build_evidence_bound_graph_level_record,
        establish_graph_level as establish_graph_level,
        graph_collection_binding_digest as graph_collection_binding_digest,
        recheck_evidence_bound_graph_level_record as recheck_evidence_bound_graph_level_record,
    )
    from verifier.data.models import ProvenanceHypergraph as ProvenanceHypergraph
    from verifier.core.receipt import (
        VstdReceipt as VstdReceipt,
        compute_canonical_digest as compute_canonical_digest,
    )
    from verifier.core.reproducibility import ReproducibilityLevel as ReproducibilityLevel
    from verifier.core.run import capture_run as capture_run, validate_run_receipt as validate_run_receipt
