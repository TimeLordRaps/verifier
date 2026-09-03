"""Experimental interoperability catalog and surface-planning facade.

This subpackage is outside the supported top-level :mod:`verifier` application
programming interface. Catalog membership and validation planning describe
nonexecuting candidates only; neither establishes a verifier result or closure.
"""

from .catalog import (
    CatalogError,
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from .control_surface import (
    CandidateStatus,
    ControlSurfaceContext,
    SurfaceAnalysis,
    SurfaceAnalysisError,
    SurfaceHole,
    SurfaceHoleKind,
    ValidationCandidate,
    ValidationPlan,
    analyze_verification_surface,
    plan_validation,
)


__all__ = [
    "CandidateStatus",
    "CatalogError",
    "ComponentAvailability",
    "ComponentKind",
    "ComponentLifecycle",
    "ControlSurfaceContext",
    "InteractionMode",
    "InteroperabilityComponentDescriptor",
    "InteroperabilityComponentRegistry",
    "SurfaceAnalysis",
    "SurfaceAnalysisError",
    "SurfaceHole",
    "SurfaceHoleKind",
    "ValidationCandidate",
    "ValidationPlan",
    "analyze_verification_surface",
    "plan_validation",
]
