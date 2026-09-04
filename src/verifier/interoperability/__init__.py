"""Interoperability surface-analysis and experimental planning facade.

The analyzer's supported names are exported separately by the top-level
:mod:`verifier` application programming interface. Catalog membership and
validation planning remain experimental, describe nonexecuting candidates only,
and establish neither a verifier result nor closure.
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
from .execution_readiness import (
    AuthorizationDecision,
    CandidateExecutionDeclaration,
    ExecutionReadinessError,
    ExecutionReadinessReport,
    ExecutionReadinessStatus,
    NativeInputBinding,
    PlannedEvidenceMapping,
    PostExecutionReassessmentContract,
    PrerequisiteResolution,
    SuppliedAuthorizationDecision,
    assess_execution_readiness,
)
from .geometry_conflicts import (
    AcyclicPropositionDependency,
    ConflictWitnessKind,
    GeometryConflictReport,
    GeometryConflictStatus,
    GeometryConflictWitness,
    JudgmentObservation,
    SharedPropositionIdentity,
    analyze_geometry_conflicts,
)
from .reference_catalog import reference_component_registry


__all__ = [
    "AcyclicPropositionDependency",
    "AuthorizationDecision",
    "CandidateStatus",
    "CandidateExecutionDeclaration",
    "CatalogError",
    "ComponentAvailability",
    "ComponentKind",
    "ComponentLifecycle",
    "ConflictWitnessKind",
    "ControlSurfaceContext",
    "ExecutionReadinessError",
    "ExecutionReadinessReport",
    "ExecutionReadinessStatus",
    "GeometryConflictReport",
    "GeometryConflictStatus",
    "GeometryConflictWitness",
    "InteractionMode",
    "InteroperabilityComponentDescriptor",
    "InteroperabilityComponentRegistry",
    "JudgmentObservation",
    "NativeInputBinding",
    "PlannedEvidenceMapping",
    "PostExecutionReassessmentContract",
    "PrerequisiteResolution",
    "SharedPropositionIdentity",
    "SurfaceAnalysis",
    "SurfaceAnalysisError",
    "SurfaceHole",
    "SurfaceHoleKind",
    "SuppliedAuthorizationDecision",
    "ValidationCandidate",
    "ValidationPlan",
    "analyze_geometry_conflicts",
    "analyze_verification_surface",
    "assess_execution_readiness",
    "plan_validation",
    "reference_component_registry",
]
