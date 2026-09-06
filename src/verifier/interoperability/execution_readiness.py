"""Terminology: JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Experimental, nonexecuting preflight for an exact validation plan.

This module checks only whether caller-supplied execution declarations are internally
complete and consistent with one surface analysis, validation plan, and component
registry.  It never imports or invokes a component, reads native inputs or other
external resources, grants authorization, or reassesses a verification geometry.
Package-bound plans also require the exact retained package to be revalidated;
an AUTHORIZED declaration must name that exact plan digest. Such a declaration
remains caller-supplied, not independently established authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional

from .catalog import (
    AWARENESS_CLAIM_BOUNDARY,
    ComponentAvailability,
    ComponentLifecycle,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from .control_surface import (
    ANALYSIS_SCHEMA_VERSION,
    CandidateStatus,
    SurfaceHole,
    SurfaceAnalysis,
    ValidationCandidate,
    ValidationPlan,
    _declared_plan_id,
    plan_validation,
)
from .storage import StoredComponentPackage


EXECUTION_READINESS_SCHEMA_VERSION = "VSTD-EXECUTION-READINESS-EXPERIMENTAL-0.1"
REASSESSMENT_PROCEDURE = "ANALYZE_UPDATED_VSTD2_GEOMETRY"
RUNTIME_AVAILABILITY_PREREQUISITE = "RUNTIME_AVAILABILITY"
EXECUTION_READINESS_CLAIM_BOUNDARY = (
    "READY means only that caller-supplied preflight declarations are internally "
    "complete and consistent with the exact analysis, plan, registry, and required "
    "stored package. It does not "
    "execute a component, validate native inputs or results, grant authorization, "
    "establish safety or closure, or perform post-execution reassessment. "
    + AWARENESS_CLAIM_BOUNDARY
)


class ExecutionReadinessError(ValueError):
    """Raised when a readiness record is structurally malformed."""


class ExecutionReadinessStatus(str, Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    INVALID = "INVALID"


class AuthorizationDecision(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"
    NOT_REQUIRED = "NOT_REQUIRED"


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ExecutionReadinessError(
            f"{label} must be a non-empty string without surrounding whitespace"
        )
    return value


def _optional_nonempty(value: Any, label: str) -> Optional[str]:
    if value is None:
        return None
    return _nonempty(value, label)


def _unique_strings(values: Any, label: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise ExecutionReadinessError(f"{label} must be an array of strings")
    normalized = tuple(_nonempty(value, f"{label} item") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ExecutionReadinessError(f"{label} must not contain duplicates")
    return tuple(sorted(normalized))


def _sha256(value: Any, label: str) -> str:
    value = _nonempty(value, label)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ExecutionReadinessError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class NativeInputBinding:
    """Digest-bound native input for one exact hole, candidate, and component."""

    binding_id: str
    candidate_id: str
    hole_id: str
    component_id: str
    native_input_contract: str
    input_sha256: str
    schema_id: Optional[str] = None
    media_type: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in (
            "binding_id",
            "candidate_id",
            "hole_id",
            "component_id",
            "native_input_contract",
        ):
            object.__setattr__(
                self, field_name, _nonempty(getattr(self, field_name), field_name)
            )
        object.__setattr__(self, "input_sha256", _sha256(self.input_sha256, "input_sha256"))
        object.__setattr__(self, "schema_id", _optional_nonempty(self.schema_id, "schema_id"))
        object.__setattr__(
            self, "media_type", _optional_nonempty(self.media_type, "media_type")
        )
        if (self.schema_id is None) is not (self.media_type is None):
            raise ExecutionReadinessError(
                "schema_id and media_type must either both be supplied or both be absent"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "candidate_id": self.candidate_id,
            "hole_id": self.hole_id,
            "component_id": self.component_id,
            "native_input_contract": self.native_input_contract,
            "input_sha256": self.input_sha256,
            "schema_id": self.schema_id,
            "media_type": self.media_type,
        }


@dataclass(frozen=True)
class PlannedEvidenceMapping:
    """Declared mapping from a native output into future geometry evidence."""

    mapping_id: str
    candidate_id: str
    hole_id: str
    component_id: str
    native_output_contract: str
    evidence_contract: str
    target_source_kind: str
    target_source_id: str

    def __post_init__(self) -> None:
        for field_name in (
            "mapping_id",
            "candidate_id",
            "hole_id",
            "component_id",
            "native_output_contract",
            "evidence_contract",
            "target_source_kind",
            "target_source_id",
        ):
            object.__setattr__(
                self, field_name, _nonempty(getattr(self, field_name), field_name)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "candidate_id": self.candidate_id,
            "hole_id": self.hole_id,
            "component_id": self.component_id,
            "native_output_contract": self.native_output_contract,
            "evidence_contract": self.evidence_contract,
            "target_source_kind": self.target_source_kind,
            "target_source_id": self.target_source_id,
        }


@dataclass(frozen=True)
class PrerequisiteResolution:
    """Caller assertion about one prerequisite, bound to supporting evidence when resolved."""

    candidate_id: str
    prerequisite: str
    resolved: bool
    evidence_sha256: Optional[str] = None
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", _nonempty(self.candidate_id, "candidate_id"))
        object.__setattr__(
            self, "prerequisite", _nonempty(self.prerequisite, "prerequisite")
        )
        if type(self.resolved) is not bool:
            raise ExecutionReadinessError("resolved must be a boolean")
        if self.evidence_sha256 is not None:
            object.__setattr__(
                self,
                "evidence_sha256",
                _sha256(self.evidence_sha256, "evidence_sha256"),
            )
        if not isinstance(self.reason, str) or self.reason != self.reason.strip():
            raise ExecutionReadinessError(
                "reason must be a string without surrounding whitespace"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "prerequisite": self.prerequisite,
            "resolved": self.resolved,
            "evidence_sha256": self.evidence_sha256,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CandidateExecutionDeclaration:
    """All caller-supplied preflight declarations for one selected plan candidate."""

    candidate_id: str
    hole_id: str
    component_id: str
    native_inputs: tuple[NativeInputBinding, ...]
    evidence_mappings: tuple[PlannedEvidenceMapping, ...]
    prerequisite_resolutions: tuple[PrerequisiteResolution, ...]

    def __post_init__(self) -> None:
        for field_name in ("candidate_id", "hole_id", "component_id"):
            object.__setattr__(
                self, field_name, _nonempty(getattr(self, field_name), field_name)
            )
        for field_name, expected_type, identifier in (
            ("native_inputs", NativeInputBinding, "binding_id"),
            ("evidence_mappings", PlannedEvidenceMapping, "mapping_id"),
            ("prerequisite_resolutions", PrerequisiteResolution, "prerequisite"),
        ):
            values = getattr(self, field_name)
            if not isinstance(values, (tuple, list)) or not all(
                isinstance(item, expected_type) for item in values
            ):
                raise ExecutionReadinessError(
                    f"{field_name} must be an array of {expected_type.__name__} records"
                )
            items = tuple(values)
            identifiers = [getattr(item, identifier) for item in items]
            if len(set(identifiers)) != len(identifiers):
                raise ExecutionReadinessError(
                    f"{field_name} must not contain duplicate {identifier} values"
                )
            object.__setattr__(
                self,
                field_name,
                tuple(sorted(items, key=lambda item: getattr(item, identifier))),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "hole_id": self.hole_id,
            "component_id": self.component_id,
            "native_inputs": [item.to_dict() for item in self.native_inputs],
            "evidence_mappings": [item.to_dict() for item in self.evidence_mappings],
            "prerequisite_resolutions": [
                item.to_dict() for item in self.prerequisite_resolutions
            ],
        }


@dataclass(frozen=True)
class SuppliedAuthorizationDecision:
    """An authorization decision supplied by the caller, never granted here."""

    decision: AuthorizationDecision
    authority_requirements: tuple[str, ...]
    decision_evidence_sha256: Optional[str] = None
    reason: str = ""
    plan_digest: Optional[str] = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "decision", AuthorizationDecision(self.decision))
        except (TypeError, ValueError) as exc:
            raise ExecutionReadinessError(str(exc)) from exc
        object.__setattr__(
            self,
            "authority_requirements",
            _unique_strings(self.authority_requirements, "authority_requirements"),
        )
        if self.decision_evidence_sha256 is not None:
            object.__setattr__(
                self,
                "decision_evidence_sha256",
                _sha256(self.decision_evidence_sha256, "decision_evidence_sha256"),
            )
        if self.plan_digest is not None:
            _sha256(self.plan_digest, "plan_digest")
        if not isinstance(self.reason, str) or self.reason != self.reason.strip():
            raise ExecutionReadinessError(
                "reason must be a string without surrounding whitespace"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "authority_requirements": list(self.authority_requirements),
            "decision_evidence_sha256": self.decision_evidence_sha256,
            "reason": self.reason,
            "decision_source": "CALLER_SUPPLIED",
            "plan_digest": self.plan_digest,
        }


@dataclass(frozen=True)
class PostExecutionReassessmentContract:
    """Caller commitment to reassess a future evidence-updated geometry."""

    geometry_id: str
    prior_geometry_digest: str
    evidence_mapping_ids: tuple[str, ...]
    procedure: str = REASSESSMENT_PROCEDURE
    analysis_schema_version: str = ANALYSIS_SCHEMA_VERSION
    requires_fresh_geometry_digest: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "geometry_id", _nonempty(self.geometry_id, "geometry_id"))
        object.__setattr__(
            self,
            "prior_geometry_digest",
            _nonempty(self.prior_geometry_digest, "prior_geometry_digest"),
        )
        object.__setattr__(
            self,
            "evidence_mapping_ids",
            _unique_strings(self.evidence_mapping_ids, "evidence_mapping_ids"),
        )
        if self.procedure != REASSESSMENT_PROCEDURE:
            raise ExecutionReadinessError(
                f"procedure must be {REASSESSMENT_PROCEDURE!r}"
            )
        if self.analysis_schema_version != ANALYSIS_SCHEMA_VERSION:
            raise ExecutionReadinessError(
                f"analysis_schema_version must be {ANALYSIS_SCHEMA_VERSION!r}"
            )
        if self.requires_fresh_geometry_digest is not True:
            raise ExecutionReadinessError(
                "requires_fresh_geometry_digest must remain true"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "geometry_id": self.geometry_id,
            "prior_geometry_digest": self.prior_geometry_digest,
            "evidence_mapping_ids": list(self.evidence_mapping_ids),
            "procedure": self.procedure,
            "analysis_schema_version": self.analysis_schema_version,
            "requires_fresh_geometry_digest": self.requires_fresh_geometry_digest,
        }


@dataclass(frozen=True)
class ExecutionReadinessReport:
    """Nonexecuting preflight result; package_digest names the plan's binding.

    A carried package digest does not by itself establish successful revalidation;
    missing or mismatched bytes are reported in status and findings.
    """

    status: ExecutionReadinessStatus
    geometry_id: str
    geometry_digest: str
    analysis_digest: str
    plan_id: str
    plan_digest: str
    registry_version: str
    registry_digest: str
    declarations: tuple[CandidateExecutionDeclaration, ...]
    authorization: SuppliedAuthorizationDecision
    reassessment: PostExecutionReassessmentContract
    findings: tuple[str, ...]
    schema_version: str = EXECUTION_READINESS_SCHEMA_VERSION
    execution_performed: bool = field(default=False, init=False)
    authorization_granted_by_module: bool = field(default=False, init=False)
    claim_boundary: str = EXECUTION_READINESS_CLAIM_BOUNDARY
    package_digest: Optional[str] = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "status", ExecutionReadinessStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise ExecutionReadinessError(str(exc)) from exc
        for field_name in ("geometry_id", "plan_id", "registry_version"):
            object.__setattr__(
                self, field_name, _nonempty(getattr(self, field_name), field_name)
            )
        for field_name in (
            "geometry_digest",
            "analysis_digest",
            "plan_digest",
            "registry_digest",
        ):
            object.__setattr__(
                self, field_name, _sha256(getattr(self, field_name), field_name)
            )
        if self.package_digest is not None:
            _sha256(self.package_digest, "package_digest")
        if not isinstance(self.declarations, (tuple, list)) or not all(
            isinstance(item, CandidateExecutionDeclaration) for item in self.declarations
        ):
            raise ExecutionReadinessError(
                "declarations must be an array of CandidateExecutionDeclaration records"
            )
        declarations = tuple(self.declarations)
        candidate_ids = [item.candidate_id for item in declarations]
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ExecutionReadinessError(
                "declarations must have unique candidate identifiers"
            )
        object.__setattr__(
            self,
            "declarations",
            tuple(sorted(declarations, key=lambda item: item.candidate_id)),
        )
        if not isinstance(self.authorization, SuppliedAuthorizationDecision):
            raise ExecutionReadinessError(
                "authorization must be a SuppliedAuthorizationDecision"
            )
        if not isinstance(self.reassessment, PostExecutionReassessmentContract):
            raise ExecutionReadinessError(
                "reassessment must be a PostExecutionReassessmentContract"
            )
        object.__setattr__(self, "findings", _unique_strings(self.findings, "findings"))
        if self.schema_version != EXECUTION_READINESS_SCHEMA_VERSION:
            raise ExecutionReadinessError(
                f"schema_version must be {EXECUTION_READINESS_SCHEMA_VERSION!r}"
            )
        if self.claim_boundary != EXECUTION_READINESS_CLAIM_BOUNDARY:
            raise ExecutionReadinessError(
                "claim_boundary is fixed and cannot be weakened or replaced"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "geometry_id": self.geometry_id,
            "geometry_digest": self.geometry_digest,
            "analysis_digest": self.analysis_digest,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "package_digest": self.package_digest,
            "binding_scope": "REGISTRY_ONLY" if self.package_digest is None else "STORED_PACKAGE",
            "declarations": [item.to_dict() for item in self.declarations],
            "authorization": self.authorization.to_dict(),
            "reassessment": self.reassessment.to_dict(),
            "findings": list(self.findings),
            "execution_performed": self.execution_performed,
            "authorization_granted_by_module": self.authorization_granted_by_module,
            "claim_boundary": self.claim_boundary,
        }

    def canonical_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_dict())

    def canonical_digest(self) -> str:
        return _digest_bytes(self.canonical_json_bytes())


def _add(finding_sets: dict[ExecutionReadinessStatus, set[str]], status: ExecutionReadinessStatus, message: str) -> None:
    finding_sets[status].add(message)


def _validate_binding_coordinates(
    declaration: CandidateExecutionDeclaration,
    candidate: ValidationCandidate,
    component: InteroperabilityComponentDescriptor,
    hole: SurfaceHole,
    finding_sets: dict[ExecutionReadinessStatus, set[str]],
) -> None:
    prefix = declaration.candidate_id
    if declaration.hole_id != candidate.hole_id:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: declaration hole_id does not match plan candidate")
    if declaration.component_id != candidate.component_id:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: declaration component_id does not match plan candidate")

    bound_contracts: set[str] = set()
    for binding in declaration.native_inputs:
        if (
            binding.candidate_id != candidate.candidate_id
            or binding.hole_id != candidate.hole_id
            or binding.component_id != component.component_id
        ):
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: native input binding coordinates were substituted")
            continue
        if binding.native_input_contract not in component.native_inputs:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: unknown native input contract {binding.native_input_contract!r}")
        if binding.native_input_contract in bound_contracts:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: native input contract {binding.native_input_contract!r} is bound more than once")
        bound_contracts.add(binding.native_input_contract)
        if binding.schema_id is not None:
            if not component.accepted_schema_ids:
                _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: component declares no versioned native input schema")
            elif binding.schema_id not in component.accepted_schema_ids:
                _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: native input schema {binding.schema_id!r} is not accepted by the exact component")
    missing_contracts = set(component.native_inputs) - bound_contracts
    if missing_contracts:
        _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"{prefix}: missing native input bindings for {', '.join(sorted(missing_contracts))}")
    if not component.native_inputs:
        _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"{prefix}: component declares no named native input contract")

    mapping_ids: set[str] = set()
    for mapping in declaration.evidence_mappings:
        mapping_ids.add(mapping.mapping_id)
        if (
            mapping.candidate_id != candidate.candidate_id
            or mapping.hole_id != candidate.hole_id
            or mapping.component_id != component.component_id
        ):
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: evidence mapping coordinates were substituted")
        if mapping.native_output_contract not in component.native_outputs:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{prefix}: unknown native output contract {mapping.native_output_contract!r}")
        if (
            mapping.target_source_kind != hole.source_kind
            or mapping.target_source_id != hole.source_id
        ):
            _add(
                finding_sets,
                ExecutionReadinessStatus.INVALID,
                f"{prefix}: evidence mapping target does not match the exact geometry hole",
            )
    if not mapping_ids:
        _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"{prefix}: no planned output/evidence mapping was supplied")


def assess_execution_readiness(
    analysis: SurfaceAnalysis,
    plan: ValidationPlan,
    registry: InteroperabilityComponentRegistry,
    declarations: tuple[CandidateExecutionDeclaration, ...],
    authorization: SuppliedAuthorizationDecision,
    reassessment: PostExecutionReassessmentContract,
    *,
    package: Optional[StoredComponentPackage] = None,
) -> ExecutionReadinessReport:
    """Check declared execution readiness without importing or invoking components."""

    if not isinstance(analysis, SurfaceAnalysis):
        raise ExecutionReadinessError("analysis must be a SurfaceAnalysis")
    if not isinstance(plan, ValidationPlan):
        raise ExecutionReadinessError("plan must be a ValidationPlan")
    if not isinstance(registry, InteroperabilityComponentRegistry):
        raise ExecutionReadinessError(
            "registry must be an InteroperabilityComponentRegistry"
        )
    if not isinstance(declarations, (tuple, list)) or not all(
        isinstance(item, CandidateExecutionDeclaration) for item in declarations
    ):
        raise ExecutionReadinessError(
            "declarations must be an array of CandidateExecutionDeclaration records"
        )
    if not isinstance(authorization, SuppliedAuthorizationDecision):
        raise ExecutionReadinessError(
            "authorization must be a SuppliedAuthorizationDecision"
        )
    if not isinstance(reassessment, PostExecutionReassessmentContract):
        raise ExecutionReadinessError(
            "reassessment must be a PostExecutionReassessmentContract"
        )

    declarations = tuple(declarations)
    finding_sets = {status: set() for status in ExecutionReadinessStatus}

    if plan.geometry_id != analysis.geometry_id or plan.geometry_digest != analysis.geometry_digest:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "plan geometry binding does not match the supplied analysis")
    if plan.context != analysis.context:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "plan context does not match the supplied analysis")
    if plan.registry_version != registry.registry_version or plan.registry_digest != registry.canonical_digest():
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "plan registry binding does not match the supplied registry")
    if plan.package_digest is not None and package is None:
        _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, "package-bound plan requires the exact stored package for revalidation")
    try:
        expected_plan = plan_validation(analysis, registry, package=package)
    except Exception as exc:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, f"analysis, plan, registry, and package binding cannot be recomposed: {type(exc).__name__}")
    else:
        if package is None and plan.package_digest is not None:
            # Check the identity implied by the declared digest without treating
            # that declaration as validated package bytes. Missing stays unknown.
            expected_plan = replace(
                expected_plan,
                package_digest=plan.package_digest,
                plan_id=_declared_plan_id(
                    analysis, registry, expected_plan.candidates, plan.package_digest,
                ),
            )
        elif plan.package_digest != expected_plan.package_digest:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, "plan package binding does not match the supplied stored package")
        if plan.canonical_json_bytes() != expected_plan.canonical_json_bytes():
            _add(finding_sets, ExecutionReadinessStatus.INVALID, "plan content is inconsistent with exact replanning")

    candidates = {candidate.candidate_id: candidate for candidate in plan.candidates}
    holes = {hole.hole_id: hole for hole in analysis.holes}
    components = {component.component_id: component for component in registry.components}
    seen_candidates: set[str] = set()
    selected_holes: set[str] = set()
    all_mapping_ids: set[str] = set()

    for declaration in declarations:
        if declaration.candidate_id in seen_candidates:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"duplicate declaration for candidate {declaration.candidate_id!r}")
            continue
        seen_candidates.add(declaration.candidate_id)
        candidate = candidates.get(declaration.candidate_id)
        if candidate is None:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"unknown or substituted candidate {declaration.candidate_id!r}")
            continue
        selected_holes.add(candidate.hole_id)
        if candidate.hole_id not in holes:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: candidate references a hole absent from the analysis")
            continue
        if candidate.status is CandidateStatus.UNMATCHED:
            _add(finding_sets, ExecutionReadinessStatus.BLOCKED, f"{candidate.candidate_id}: unmatched plan candidate cannot be execution-ready")
            continue
        if candidate.component_id is None:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: matched candidate has no component")
            continue
        component = components.get(candidate.component_id)
        if component is None:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: plan component is absent from the exact registry")
            continue
        if candidate.status is CandidateStatus.BLOCKED:
            _add(finding_sets, ExecutionReadinessStatus.BLOCKED, f"{candidate.candidate_id}: plan candidate is blocked")
        if component.availability is not ComponentAvailability.AVAILABLE:
            _add(finding_sets, ExecutionReadinessStatus.BLOCKED, f"{candidate.candidate_id}: component availability is {component.availability.value}")
        if component.lifecycle in {ComponentLifecycle.UNSUPPORTED, ComponentLifecycle.ABSENT}:
            _add(finding_sets, ExecutionReadinessStatus.BLOCKED, f"{candidate.candidate_id}: component lifecycle is {component.lifecycle.value}")

        _validate_binding_coordinates(
            declaration,
            candidate,
            component,
            holes[candidate.hole_id],
            finding_sets,
        )
        declaration_mapping_ids = {
            item.mapping_id for item in declaration.evidence_mappings
        }
        duplicate_mapping_ids = all_mapping_ids & declaration_mapping_ids
        if duplicate_mapping_ids:
            _add(
                finding_sets,
                ExecutionReadinessStatus.INVALID,
                "evidence mapping identifiers must be globally unique across selected "
                f"candidates: {', '.join(sorted(duplicate_mapping_ids))}",
            )
        all_mapping_ids.update(declaration_mapping_ids)

        required = {
            item
            for item in candidate.execution_prerequisites
            if not item.startswith("AUTHORITY:")
        }
        required.add(RUNTIME_AVAILABILITY_PREREQUISITE)
        resolutions = {
            item.prerequisite: item for item in declaration.prerequisite_resolutions
        }
        extras = set(resolutions) - required
        if extras:
            _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: undeclared prerequisite resolutions for {', '.join(sorted(extras))}")
        missing = required - set(resolutions)
        if missing:
            _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"{candidate.candidate_id}: missing prerequisite resolutions for {', '.join(sorted(missing))}")
        for prerequisite, resolution in resolutions.items():
            if resolution.candidate_id != candidate.candidate_id:
                _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: prerequisite resolution candidate was substituted")
            if resolution.resolved and resolution.evidence_sha256 is None:
                _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"{candidate.candidate_id}: resolved prerequisite {prerequisite!r} lacks an evidence digest")
            elif resolution.resolved and resolution.reason:
                _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: resolved prerequisite {prerequisite!r} carries an unresolved reason")
            elif not resolution.resolved and resolution.evidence_sha256 is not None:
                _add(finding_sets, ExecutionReadinessStatus.INVALID, f"{candidate.candidate_id}: unresolved prerequisite {prerequisite!r} carries resolution evidence")
            elif not resolution.resolved and not resolution.reason:
                _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"{candidate.candidate_id}: unresolved prerequisite {prerequisite!r} lacks a reason")
            elif not resolution.resolved:
                _add(finding_sets, ExecutionReadinessStatus.BLOCKED, f"{candidate.candidate_id}: prerequisite {prerequisite!r} is unresolved")

    missing_holes = set(holes) - selected_holes
    if missing_holes:
        _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, f"no selected candidate for holes {', '.join(sorted(missing_holes))}")
    duplicate_holes = {
        hole_id
        for hole_id in selected_holes
        if sum(
            1
            for declaration in declarations
            if candidates.get(declaration.candidate_id) is not None
            and candidates[declaration.candidate_id].hole_id == hole_id
        )
        > 1
    }
    if duplicate_holes:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, f"more than one candidate selected for holes {', '.join(sorted(duplicate_holes))}")

    required_authorities = set(analysis.context.authority_requirements)
    required_authorities.update(
        prerequisite.removeprefix("AUTHORITY:")
        for candidate in plan.candidates
        if candidate.candidate_id in seen_candidates
        for prerequisite in candidate.execution_prerequisites
        if prerequisite.startswith("AUTHORITY:")
    )
    if set(authorization.authority_requirements) != required_authorities:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "authorization requirements do not match the selected plan coordinates")
    if authorization.plan_digest is not None and authorization.plan_digest != _digest_bytes(plan.canonical_json_bytes()):
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "authorization plan binding does not match the exact supplied plan")
    if required_authorities and authorization.decision is AuthorizationDecision.NOT_REQUIRED:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "authorization cannot be NOT_REQUIRED when the plan declares authority requirements")
    elif not required_authorities and authorization.decision is not AuthorizationDecision.NOT_REQUIRED:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "authorization must be explicitly NOT_REQUIRED when the plan declares no authority requirements")
    elif authorization.decision is AuthorizationDecision.AUTHORIZED:
        if authorization.decision_evidence_sha256 is None:
            _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, "supplied authorization lacks a decision evidence digest")
        if plan.package_digest is not None and authorization.plan_digest is None:
            _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, "supplied authorization lacks the exact package-bound plan digest")
    elif authorization.decision is AuthorizationDecision.DENIED:
        _add(finding_sets, ExecutionReadinessStatus.BLOCKED, "supplied authorization decision is DENIED")
    elif authorization.decision is AuthorizationDecision.UNKNOWN:
        _add(finding_sets, ExecutionReadinessStatus.NOT_ESTABLISHED, "supplied authorization decision is UNKNOWN")

    if reassessment.geometry_id != analysis.geometry_id or reassessment.prior_geometry_digest != analysis.geometry_digest:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "post-execution reassessment geometry binding was substituted")
    if set(reassessment.evidence_mapping_ids) != all_mapping_ids:
        _add(finding_sets, ExecutionReadinessStatus.INVALID, "post-execution reassessment does not bind the exact planned evidence mappings")

    if finding_sets[ExecutionReadinessStatus.INVALID]:
        status = ExecutionReadinessStatus.INVALID
    elif finding_sets[ExecutionReadinessStatus.BLOCKED]:
        status = ExecutionReadinessStatus.BLOCKED
    elif finding_sets[ExecutionReadinessStatus.NOT_ESTABLISHED]:
        status = ExecutionReadinessStatus.NOT_ESTABLISHED
    else:
        status = ExecutionReadinessStatus.READY
    findings = tuple(
        sorted(
            message
            for finding_status, messages in finding_sets.items()
            if finding_status is not ExecutionReadinessStatus.READY
            for message in messages
        )
    )
    return ExecutionReadinessReport(
        status=status,
        geometry_id=analysis.geometry_id,
        geometry_digest=analysis.geometry_digest,
        analysis_digest=_digest_bytes(analysis.canonical_json_bytes()),
        plan_id=plan.plan_id,
        plan_digest=_digest_bytes(plan.canonical_json_bytes()),
        registry_version=registry.registry_version,
        registry_digest=registry.canonical_digest(),
        declarations=declarations,
        authorization=authorization,
        reassessment=reassessment,
        findings=findings,
        package_digest=plan.package_digest,
    )


__all__ = [
    "AuthorizationDecision",
    "CandidateExecutionDeclaration",
    "EXECUTION_READINESS_CLAIM_BOUNDARY",
    "EXECUTION_READINESS_SCHEMA_VERSION",
    "ExecutionReadinessError",
    "ExecutionReadinessReport",
    "ExecutionReadinessStatus",
    "NativeInputBinding",
    "PlannedEvidenceMapping",
    "PostExecutionReassessmentContract",
    "PrerequisiteResolution",
    "REASSESSMENT_PROCEDURE",
    "RUNTIME_AVAILABILITY_PREREQUISITE",
    "SuppliedAuthorizationDecision",
    "assess_execution_readiness",
]
