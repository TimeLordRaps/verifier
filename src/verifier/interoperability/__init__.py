"""Interoperability surface-analysis, experimental storage and planning facade.

The analyzer's supported names are exported separately by the top-level
:mod:`verifier` application programming interface. Catalog membership and
validation planning and component storage remain experimental. Retaining bytes
and describing nonexecuting candidates establish neither a verifier result nor
closure.
"""

from __future__ import annotations

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
from .storage import (
    COMPONENT_PACKAGE_SCHEMA_VERSION,
    ComponentPackageError,
    ImplementationBinding,
    PackageArtifact,
    PackageDependency,
    StoredComponentPackage,
    load_component_package,
    save_component_package,
)


__all__ = [
    "AcyclicPropositionDependency",
    "AuthorizationDecision",
    "CandidateStatus",
    "CandidateExecutionDeclaration",
    "CatalogError",
    "COMPONENT_PACKAGE_SCHEMA_VERSION",
    "ComponentAvailability",
    "ComponentKind",
    "ComponentLifecycle",
    "ComponentPackageError",
    "ConflictWitnessKind",
    "ControlSurfaceContext",
    "ExecutionReadinessError",
    "ExecutionReadinessReport",
    "ExecutionReadinessStatus",
    "GeometryConflictReport",
    "GeometryConflictStatus",
    "GeometryConflictWitness",
    "ImplementationBinding",
    "InteractionMode",
    "InteroperabilityComponentDescriptor",
    "InteroperabilityComponentRegistry",
    "JudgmentObservation",
    "NativeInputBinding",
    "PackageArtifact",
    "PackageDependency",
    "PlannedEvidenceMapping",
    "PostExecutionReassessmentContract",
    "PrerequisiteResolution",
    "SharedPropositionIdentity",
    "StoredComponentPackage",
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
    "load_component_package",
    "plan_validation",
    "reference_component_registry",
    "save_component_package",
]
