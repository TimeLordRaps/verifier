"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Stable analysis of the declared VSTD-2 control surface and experimental,
nonexecuting candidate planning.

The analyzer derives diagnostics only from geometry already represented by the
caller.  It does not infer an expected profile, omitted ontology, or real-world
completeness.  A catalog match is a candidate association, not a verification
result and not authority to execute a component.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from verifier.core.geometry import (
    CoordinateStatus,
    GEOMETRY_SCHEMA_VERSION,
    ResidualDisposition,
    ValenceStatus,
    VerificationGeometry,
)

from .catalog import (
    ComponentAvailability,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)


ANALYSIS_SCHEMA_VERSION = "VSTD-SURFACE-ANALYSIS-1.0"
PLAN_SCHEMA_VERSION = "VSTD-VALIDATION-PLAN-EXPERIMENTAL-0.1"
MODELED_SURFACE_SCOPE = "MODELED_SURFACE_ONLY"
ANALYSIS_INPUT_MODE = "TYPED_VERIFICATION_GEOMETRY_ONLY"
STRICT_WIRE_LOADING_STATUS = "UNSUPPORTED"

ANALYSIS_CLAIM_BOUNDARY = (
    "Derived only from the supplied VSTD-2 geometry. It does not establish that the "
    "declared surface, coordinates, ontology, or evidence are complete."
)
PLAN_CLAIM_BOUNDARY = (
    "Exact catalog matches are nonexecuting candidates. They do not establish "
    "availability, validity, assurance, authority, or closure."
)
EXECUTION_PREREQUISITES = (
    "BOUND_PROPOSITION",
    "MECHANISM_DIGEST",
    "EVIDENCE_BYTES",
    "TRUST_ROOTS",
    "RESOURCE_BOUNDS",
)


class SurfaceAnalysisError(ValueError):
    """Raised when an analysis or candidate-plan object is malformed."""


class SurfaceHoleKind(str, Enum):
    MISSING_JUDGMENT = "MISSING_JUDGMENT"
    COORDINATE_STATUS = "COORDINATE_STATUS"
    RESIDUAL = "RESIDUAL"
    VALENCE = "VALENCE"
    HORIZON = "HORIZON"
    MECHANISM = "MECHANISM"
    VERIFICATION_ORDER = "VERIFICATION_ORDER"
    SELF_CLOSURE_REQUIREMENT = "SELF_CLOSURE_REQUIREMENT"


class CandidateStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    BLOCKED = "BLOCKED"
    UNMATCHED = "UNMATCHED"


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SurfaceAnalysisError(
            f"{label} must be a non-empty string without surrounding whitespace"
        )
    return value


def _unique_strings(values: Any, label: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise SurfaceAnalysisError(f"{label} must be an array of strings")
    normalized = tuple(_nonempty(value, f"{label} item") for value in values)
    if len(set(normalized)) != len(normalized):
        raise SurfaceAnalysisError(f"{label} must not contain duplicates")
    return tuple(sorted(normalized))


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _stable_identifier(prefix: str, value: Any) -> str:
    return f"{prefix}:{hashlib.sha256(_canonical_json_bytes(value)).hexdigest()}"


@dataclass(frozen=True)
class ControlSurfaceContext:
    """External planning context; only schema and interaction mode affect matches."""

    schema_id: str = GEOMETRY_SCHEMA_VERSION
    interaction_mode: InteractionMode = InteractionMode.STATIC
    domain_tags: tuple[str, ...] = ()
    operating_regime: str = ""
    consequence_profiles: tuple[str, ...] = ()
    authority_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "schema_id", _nonempty(self.schema_id, "schema_id"))
        try:
            object.__setattr__(self, "interaction_mode", InteractionMode(self.interaction_mode))
        except (TypeError, ValueError) as exc:
            raise SurfaceAnalysisError(str(exc)) from exc
        for field_name in (
            "domain_tags",
            "consequence_profiles",
            "authority_requirements",
        ):
            object.__setattr__(
                self, field_name, _unique_strings(getattr(self, field_name), field_name)
            )
        if not isinstance(self.operating_regime, str):
            raise SurfaceAnalysisError("operating_regime must be a string")
        if self.operating_regime and self.operating_regime != self.operating_regime.strip():
            raise SurfaceAnalysisError(
                "operating_regime must not contain surrounding whitespace"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "interaction_mode": self.interaction_mode.value,
            "domain_tags": list(self.domain_tags),
            "operating_regime": self.operating_regime,
            "consequence_profiles": list(self.consequence_profiles),
            "authority_requirements": list(self.authority_requirements),
        }


@dataclass(frozen=True)
class SurfaceHole:
    """One structured diagnostic derived from an existing geometry blocker."""

    hole_id: str
    kind: SurfaceHoleKind
    source_kind: str
    source_id: str
    native_status: str
    description: str
    blocks_ordinary_closure: bool
    blocks_self_closure: bool
    schema_id: str
    interaction_mode: InteractionMode
    required_relations: tuple[str, ...] = ()
    mechanism_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "hole_id",
            "source_kind",
            "source_id",
            "native_status",
            "description",
            "schema_id",
        ):
            object.__setattr__(
                self, field_name, _nonempty(getattr(self, field_name), field_name)
            )
        try:
            object.__setattr__(self, "kind", SurfaceHoleKind(self.kind))
            object.__setattr__(self, "interaction_mode", InteractionMode(self.interaction_mode))
        except (TypeError, ValueError) as exc:
            raise SurfaceAnalysisError(str(exc)) from exc
        if type(self.blocks_ordinary_closure) is not bool:
            raise SurfaceAnalysisError("blocks_ordinary_closure must be a boolean")
        if type(self.blocks_self_closure) is not bool:
            raise SurfaceAnalysisError("blocks_self_closure must be a boolean")
        object.__setattr__(
            self,
            "required_relations",
            _unique_strings(self.required_relations, "required_relations"),
        )
        object.__setattr__(
            self, "mechanism_ids", _unique_strings(self.mechanism_ids, "mechanism_ids")
        )

    @property
    def native_state(self) -> str:
        """Compatibility spelling for callers that describe statuses as states."""

        return self.native_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "hole_id": self.hole_id,
            "kind": self.kind.value,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "native_status": self.native_status,
            "description": self.description,
            "blocks_ordinary_closure": self.blocks_ordinary_closure,
            "blocks_self_closure": self.blocks_self_closure,
            "schema_id": self.schema_id,
            "interaction_mode": self.interaction_mode.value,
            "required_relations": list(self.required_relations),
            "mechanism_ids": list(self.mechanism_ids),
        }


@dataclass(frozen=True)
class SurfaceAnalysis:
    """Deterministic report over only the supplied, declared geometry."""

    geometry_id: str
    geometry_digest: str
    context: ControlSurfaceContext
    validity_errors: tuple[str, ...]
    ordinary_closed: bool
    self_closed: bool
    ordinary_blockers: tuple[str, ...]
    self_closure_blockers: tuple[str, ...]
    holes: tuple[SurfaceHole, ...]
    scope: str = MODELED_SURFACE_SCOPE
    input_mode: str = ANALYSIS_INPUT_MODE
    strict_wire_loading_status: str = STRICT_WIRE_LOADING_STATUS
    claim_boundary: str = ANALYSIS_CLAIM_BOUNDARY
    schema_version: str = ANALYSIS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _nonempty(self.geometry_id, "geometry_id")
        _nonempty(self.geometry_digest, "geometry_digest")
        if not isinstance(self.context, ControlSurfaceContext):
            raise SurfaceAnalysisError("context must be a ControlSurfaceContext")
        if self.scope != MODELED_SURFACE_SCOPE:
            raise SurfaceAnalysisError(f"scope must be {MODELED_SURFACE_SCOPE!r}")
        if self.input_mode != ANALYSIS_INPUT_MODE:
            raise SurfaceAnalysisError(f"input_mode must be {ANALYSIS_INPUT_MODE!r}")
        if self.strict_wire_loading_status != STRICT_WIRE_LOADING_STATUS:
            raise SurfaceAnalysisError(
                "strict_wire_loading_status must remain "
                f"{STRICT_WIRE_LOADING_STATUS!r}"
            )
        if self.schema_version != ANALYSIS_SCHEMA_VERSION:
            raise SurfaceAnalysisError(
                f"schema_version must be {ANALYSIS_SCHEMA_VERSION!r}"
            )
        if self.claim_boundary != ANALYSIS_CLAIM_BOUNDARY:
            raise SurfaceAnalysisError(
                "claim_boundary is fixed and cannot be weakened or replaced"
            )
        if type(self.ordinary_closed) is not bool:
            raise SurfaceAnalysisError("ordinary_closed must be a boolean")
        if type(self.self_closed) is not bool:
            raise SurfaceAnalysisError("self_closed must be a boolean")
        for field_name in (
            "validity_errors",
            "ordinary_blockers",
            "self_closure_blockers",
        ):
            values = getattr(self, field_name)
            if not isinstance(values, (tuple, list)) or not all(
                isinstance(item, str) for item in values
            ):
                raise SurfaceAnalysisError(f"{field_name} must be an array of strings")
            object.__setattr__(self, field_name, tuple(values))
        if not isinstance(self.holes, (tuple, list)):
            raise SurfaceAnalysisError("holes must be an array of SurfaceHole records")
        holes = tuple(self.holes)
        if not all(isinstance(item, SurfaceHole) for item in holes):
            raise SurfaceAnalysisError("holes must contain SurfaceHole records")
        hole_ids = [item.hole_id for item in holes]
        if len(set(hole_ids)) != len(hole_ids):
            raise SurfaceAnalysisError("holes must have unique identifiers")
        object.__setattr__(
            self,
            "holes",
            tuple(
                sorted(
                    holes,
                    key=lambda item: (
                        item.kind.value,
                        item.source_kind,
                        item.source_id,
                        item.native_status,
                        item.hole_id,
                    ),
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "geometry_id": self.geometry_id,
            "geometry_digest": self.geometry_digest,
            "scope": self.scope,
            "input_mode": self.input_mode,
            "strict_wire_loading_status": self.strict_wire_loading_status,
            "context": self.context.to_dict(),
            "validity_errors": list(self.validity_errors),
            "ordinary_closed": self.ordinary_closed,
            "self_closed": self.self_closed,
            "ordinary_blockers": list(self.ordinary_blockers),
            "self_closure_blockers": list(self.self_closure_blockers),
            "holes": [hole.to_dict() for hole in self.holes],
            "claim_boundary": self.claim_boundary,
        }

    def canonical_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_dict())


def _make_hole(
    *,
    kind: SurfaceHoleKind,
    source_kind: str,
    source_id: str,
    native_status: str,
    description: str,
    ordinary: bool,
    self_closure: bool,
    context: ControlSurfaceContext,
    required_relations: tuple[str, ...] = (),
    mechanism_ids: tuple[str, ...] = (),
) -> SurfaceHole:
    relations = tuple(sorted(set(required_relations)))
    mechanisms = tuple(sorted(set(mechanism_ids)))
    identifier_material = {
        "kind": kind.value,
        "source_kind": source_kind,
        "source_id": source_id,
        "native_status": native_status,
        "schema_id": context.schema_id,
        "interaction_mode": context.interaction_mode.value,
        "required_relations": list(relations),
        "mechanism_ids": list(mechanisms),
    }
    return SurfaceHole(
        hole_id=_stable_identifier("surface-hole", identifier_material),
        kind=kind,
        source_kind=source_kind,
        source_id=source_id,
        native_status=native_status,
        description=description,
        blocks_ordinary_closure=ordinary,
        blocks_self_closure=self_closure,
        schema_id=context.schema_id,
        interaction_mode=context.interaction_mode,
        required_relations=relations,
        mechanism_ids=mechanisms,
    )


def analyze_verification_surface(
    geometry: VerificationGeometry,
    context: Optional[ControlSurfaceContext] = None,
) -> SurfaceAnalysis:
    """Derive structured holes from the supplied VSTD-2 geometry only."""

    if not isinstance(geometry, VerificationGeometry):
        raise SurfaceAnalysisError("geometry must be a VerificationGeometry")
    if context is None:
        context = ControlSurfaceContext(schema_id=geometry.schema_version)
    elif not isinstance(context, ControlSurfaceContext):
        raise SurfaceAnalysisError("context must be a ControlSurfaceContext")
    elif context.schema_id != geometry.schema_version:
        raise SurfaceAnalysisError(
            "context schema_id must exactly equal the typed geometry schema_version"
        )

    try:
        validity_errors = tuple(geometry.validate())
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise SurfaceAnalysisError(
            f"verification geometry validation failed: {exc}"
        ) from exc
    if validity_errors:
        raise SurfaceAnalysisError(
            "verification geometry is structurally invalid: "
            + "; ".join(validity_errors)
        )
    try:
        assessment = geometry.assess_closure()
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise SurfaceAnalysisError(
            f"verification geometry closure assessment failed: {exc}"
        ) from exc
    judgments: dict[str, Any] = {}
    for judgment in geometry.judgments:
        judgments.setdefault(judgment.coordinate_id, judgment)
    surface_coordinate_ids = set(geometry.surface.coordinate_ids)
    holes: dict[tuple[str, str, str, str], SurfaceHole] = {}

    def add(hole: SurfaceHole) -> None:
        key = (
            hole.kind.value,
            hole.source_kind,
            hole.source_id,
            hole.native_status,
        )
        existing = holes.get(key)
        if existing is None:
            holes[key] = hole
            return
        holes[key] = _make_hole(
            kind=hole.kind,
            source_kind=hole.source_kind,
            source_id=hole.source_id,
            native_status=hole.native_status,
            description=existing.description,
            ordinary=(
                existing.blocks_ordinary_closure or hole.blocks_ordinary_closure
            ),
            self_closure=(existing.blocks_self_closure or hole.blocks_self_closure),
            context=context,
            required_relations=tuple(
                set(existing.required_relations) | set(hole.required_relations)
            ),
            mechanism_ids=tuple(set(existing.mechanism_ids) | set(hole.mechanism_ids)),
        )

    def add_coordinate_hole(
        coordinate_id: str, *, ordinary: bool, layer_mechanisms: tuple[str, ...] = ()
    ) -> None:
        judgment = judgments.get(coordinate_id)
        if judgment is None:
            add(
                _make_hole(
                    kind=SurfaceHoleKind.MISSING_JUDGMENT,
                    source_kind="COORDINATE",
                    source_id=coordinate_id,
                    native_status="MISSING_JUDGMENT",
                    description=f"Coordinate {coordinate_id!r} has no current judgment.",
                    ordinary=ordinary,
                    self_closure=True,
                    context=context,
                    mechanism_ids=layer_mechanisms,
                )
            )
        elif judgment.status is not CoordinateStatus.VERIFIED:
            add(
                _make_hole(
                    kind=SurfaceHoleKind.COORDINATE_STATUS,
                    source_kind="COORDINATE",
                    source_id=coordinate_id,
                    native_status=judgment.status.value,
                    description=(
                        f"Coordinate {coordinate_id!r} retains native status "
                        f"{judgment.status.value}; it is not VERIFIED."
                    ),
                    ordinary=ordinary,
                    self_closure=True,
                    context=context,
                    mechanism_ids=tuple(judgment.mechanism_ids) or layer_mechanisms,
                )
            )

    for coordinate_id in geometry.surface.coordinate_ids:
        add_coordinate_hole(coordinate_id, ordinary=True)

    relations_by_horizon: dict[str, set[str]] = {}
    mechanisms_by_horizon: dict[str, set[str]] = {}
    relations_by_location: dict[tuple[str, str], set[str]] = {}
    for valence in geometry.valences:
        relations_by_location.setdefault(
            (valence.source_kind, valence.source_id), set()
        ).add(valence.required_relation)
        if valence.horizon_id:
            relations_by_horizon.setdefault(valence.horizon_id, set()).add(
                valence.required_relation
            )
    for mechanism in geometry.mechanisms:
        if mechanism.boundary_horizon_id:
            mechanisms_by_horizon.setdefault(mechanism.boundary_horizon_id, set()).add(
                mechanism.mechanism_id
            )
    for verification_order in geometry.verification_layers:
        if verification_order.horizon_id:
            mechanisms_by_horizon.setdefault(verification_order.horizon_id, set()).update(
                verification_order.mechanism_ids
            )

    for residual in geometry.residuals:
        if not residual.material or residual.disposition is ResidualDisposition.RESOLVED:
            continue
        relations: set[str] = set()
        mechanisms: set[str] = set()
        for source_kind, source_id in (
            ("LOCUS", residual.locus_id),
            ("COORDINATE", residual.coordinate_id),
            ("SEAM", residual.seam_id),
        ):
            if source_id:
                relations.update(relations_by_location.get((source_kind, source_id), set()))
        if residual.coordinate_id and residual.coordinate_id in judgments:
            mechanisms.update(judgments[residual.coordinate_id].mechanism_ids)
        if residual.horizon_id:
            relations.update(relations_by_horizon.get(residual.horizon_id, set()))
            mechanisms.update(mechanisms_by_horizon.get(residual.horizon_id, set()))
        add(
            _make_hole(
                kind=SurfaceHoleKind.RESIDUAL,
                source_kind="RESIDUAL",
                source_id=residual.residual_id,
                native_status=residual.disposition.value,
                description=residual.description,
                ordinary=residual.disposition
                not in {ResidualDisposition.RESOLVED, ResidualDisposition.HORIZON},
                self_closure=True,
                context=context,
                required_relations=tuple(relations),
                mechanism_ids=tuple(mechanisms),
            )
        )

    for valence in geometry.valences:
        if valence.status is ValenceStatus.DISCHARGED:
            continue
        add(
            _make_hole(
                kind=SurfaceHoleKind.VALENCE,
                source_kind="VALENCE",
                source_id=valence.valence_id,
                native_status=valence.status.value,
                description=valence.description,
                ordinary=False,
                self_closure=True,
                context=context,
                required_relations=(valence.required_relation,),
            )
        )

    for horizon in geometry.horizons:
        add(
            _make_hole(
                kind=SurfaceHoleKind.HORIZON,
                source_kind="HORIZON",
                source_id=horizon.horizon_id,
                native_status=horizon.kind.value,
                description=horizon.description,
                ordinary=False,
                self_closure=True,
                context=context,
                required_relations=tuple(
                    relations_by_horizon.get(horizon.horizon_id, set())
                ),
                mechanism_ids=tuple(
                    mechanisms_by_horizon.get(horizon.horizon_id, set())
                ),
            )
        )

    for mechanism in geometry.mechanisms:
        if mechanism.post_verified:
            continue
        add(
            _make_hole(
                kind=SurfaceHoleKind.MECHANISM,
                source_kind="MECHANISM",
                source_id=mechanism.mechanism_id,
                native_status="NOT_POST_VERIFIED",
                description=(
                    f"Mechanism {mechanism.mechanism_id!r} is not post-verified."
                ),
                ordinary=False,
                self_closure=True,
                context=context,
                mechanism_ids=(mechanism.mechanism_id,),
            )
        )

    for verification_order in geometry.verification_layers:
        for coordinate_id in verification_order.coordinate_ids:
            add_coordinate_hole(
                coordinate_id,
                ordinary=coordinate_id in surface_coordinate_ids,
                layer_mechanisms=tuple(verification_order.mechanism_ids),
            )
        if verification_order.order > 0 and not verification_order.evidence_ids:
            add(
                _make_hole(
                    kind=SurfaceHoleKind.VERIFICATION_ORDER,
                    source_kind="VERIFICATION_ORDER",
                    source_id=verification_order.layer_id,
                    native_status="MISSING_SUFFICIENCY_EVIDENCE",
                    description=(
                        f"Higher verification order {verification_order.layer_id!r} "
                        "has no sufficiency evidence."
                    ),
                    ordinary=False,
                    self_closure=True,
                    context=context,
                    mechanism_ids=tuple(verification_order.mechanism_ids),
                )
            )

    if geometry.secondary_subject_id is None:
        add(
            _make_hole(
                kind=SurfaceHoleKind.SELF_CLOSURE_REQUIREMENT,
                source_kind="GEOMETRY",
                source_id=geometry.geometry_id,
                native_status="MISSING_SECONDARY_SUBJECT",
                description="Self-closure requires a secondary verification subject.",
                ordinary=False,
                self_closure=True,
                context=context,
            )
        )
    if not geometry.meta_focus_coordinate_ids:
        add(
            _make_hole(
                kind=SurfaceHoleKind.SELF_CLOSURE_REQUIREMENT,
                source_kind="GEOMETRY",
                source_id=geometry.geometry_id,
                native_status="MISSING_META_FOCUS",
                description="Self-closure requires an explicit meta-focus.",
                ordinary=False,
                self_closure=True,
                context=context,
            )
        )
    orders = {item.order for item in geometry.verification_layers}
    if not {0, 1}.issubset(orders):
        add(
            _make_hole(
                kind=SurfaceHoleKind.SELF_CLOSURE_REQUIREMENT,
                source_kind="GEOMETRY",
                source_id=geometry.geometry_id,
                native_status="MISSING_ADJACENT_V0_V1_ORDERS",
                description="Self-closure requires adjacent V0 and V1 verification orders.",
                ordinary=False,
                self_closure=True,
                context=context,
            )
        )

    return SurfaceAnalysis(
        geometry_id=geometry.geometry_id,
        geometry_digest=geometry.canonical_digest(),
        context=context,
        validity_errors=validity_errors,
        ordinary_closed=assessment.ordinary_closed,
        self_closed=assessment.self_closed,
        ordinary_blockers=assessment.ordinary_blockers,
        self_closure_blockers=assessment.self_closure_blockers,
        holes=tuple(holes.values()),
    )


@dataclass(frozen=True)
class ValidationCandidate:
    """One exact, nonexecuting association between a hole and a component."""

    candidate_id: str
    hole_id: str
    status: CandidateStatus
    component_id: Optional[str]
    mechanism_id: Optional[str]
    relation_id: Optional[str]
    matching_basis: tuple[str, ...]
    execution_prerequisites: tuple[str, ...]
    blockers: tuple[str, ...] = ()
    plan_only: bool = field(default=True, init=False)
    execution_performed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _nonempty(self.candidate_id, "candidate_id")
        _nonempty(self.hole_id, "hole_id")
        try:
            object.__setattr__(self, "status", CandidateStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise SurfaceAnalysisError(str(exc)) from exc
        if self.component_id is not None:
            _nonempty(self.component_id, "component_id")
        if self.mechanism_id is not None:
            _nonempty(self.mechanism_id, "mechanism_id")
        if self.relation_id is not None:
            _nonempty(self.relation_id, "relation_id")
        for field_name in ("matching_basis", "execution_prerequisites", "blockers"):
            object.__setattr__(
                self, field_name, _unique_strings(getattr(self, field_name), field_name)
            )
        if self.status is CandidateStatus.UNMATCHED:
            if any(
                value is not None
                for value in (self.component_id, self.mechanism_id, self.relation_id)
            ):
                raise SurfaceAnalysisError(
                    "an unmatched candidate cannot identify a component or match coordinate"
                )
            if not self.blockers:
                raise SurfaceAnalysisError("an unmatched candidate must explain its blocker")
            return
        if self.component_id is None:
            raise SurfaceAnalysisError("a matched candidate must identify a component")
        if self.mechanism_id is None and self.relation_id is None:
            raise SurfaceAnalysisError(
                "a matched candidate must identify a relation or mechanism coordinate"
            )
        if self.status is CandidateStatus.CANDIDATE and self.blockers:
            raise SurfaceAnalysisError("an unblocked candidate cannot carry blockers")
        if self.status is CandidateStatus.BLOCKED and not self.blockers:
            raise SurfaceAnalysisError("a blocked candidate must explain its blockers")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "hole_id": self.hole_id,
            "status": self.status.value,
            "component_id": self.component_id,
            "mechanism_id": self.mechanism_id,
            "relation_id": self.relation_id,
            "matching_basis": list(self.matching_basis),
            "execution_prerequisites": list(self.execution_prerequisites),
            "blockers": list(self.blockers),
            "plan_only": self.plan_only,
            "execution_performed": self.execution_performed,
        }


@dataclass(frozen=True)
class ValidationPlan:
    """Deterministic experimental plan; it has no execution path."""

    plan_id: str
    geometry_id: str
    geometry_digest: str
    registry_version: str
    registry_digest: str
    context: ControlSurfaceContext
    candidates: tuple[ValidationCandidate, ...]
    scope: str = MODELED_SURFACE_SCOPE
    claim_boundary: str = PLAN_CLAIM_BOUNDARY
    schema_version: str = PLAN_SCHEMA_VERSION
    plan_only: bool = field(default=True, init=False)
    execution_performed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        for field_name in (
            "plan_id",
            "geometry_id",
            "geometry_digest",
            "registry_version",
            "registry_digest",
        ):
            _nonempty(getattr(self, field_name), field_name)
        if not isinstance(self.context, ControlSurfaceContext):
            raise SurfaceAnalysisError("context must be a ControlSurfaceContext")
        if self.scope != MODELED_SURFACE_SCOPE:
            raise SurfaceAnalysisError(f"scope must be {MODELED_SURFACE_SCOPE!r}")
        if self.schema_version != PLAN_SCHEMA_VERSION:
            raise SurfaceAnalysisError(f"schema_version must be {PLAN_SCHEMA_VERSION!r}")
        if self.claim_boundary != PLAN_CLAIM_BOUNDARY:
            raise SurfaceAnalysisError(
                "claim_boundary is fixed and cannot be weakened or replaced"
            )
        if not isinstance(self.candidates, (tuple, list)):
            raise SurfaceAnalysisError(
                "candidates must be an array of ValidationCandidate records"
            )
        candidates = tuple(self.candidates)
        if not all(isinstance(item, ValidationCandidate) for item in candidates):
            raise SurfaceAnalysisError("candidates must contain ValidationCandidate records")
        candidate_ids = [item.candidate_id for item in candidates]
        if len(set(candidate_ids)) != len(candidate_ids):
            raise SurfaceAnalysisError("candidates must have unique identifiers")
        object.__setattr__(
            self,
            "candidates",
            tuple(
                sorted(
                    candidates,
                    key=lambda item: (
                        item.hole_id,
                        item.component_id or "",
                        item.mechanism_id or "",
                        item.relation_id or "",
                        item.status.value,
                    ),
                )
            ),
        )

    @property
    def unmatched_hole_ids(self) -> tuple[str, ...]:
        return tuple(
            item.hole_id
            for item in self.candidates
            if item.status is CandidateStatus.UNMATCHED
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "geometry_id": self.geometry_id,
            "geometry_digest": self.geometry_digest,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "scope": self.scope,
            "context": self.context.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "plan_only": self.plan_only,
            "execution_performed": self.execution_performed,
            "claim_boundary": self.claim_boundary,
        }

    def canonical_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_dict())


def _candidate_status(
    component: InteroperabilityComponentDescriptor,
) -> tuple[CandidateStatus, tuple[str, ...]]:
    blockers: list[str] = []
    if component.availability is not ComponentAvailability.AVAILABLE:
        blockers.append(f"component availability is {component.availability.value}")
    if component.lifecycle in {
        ComponentLifecycle.UNSUPPORTED,
        ComponentLifecycle.ABSENT,
    }:
        blockers.append(f"component lifecycle is {component.lifecycle.value}")
    if blockers:
        return CandidateStatus.BLOCKED, tuple(blockers)
    return CandidateStatus.CANDIDATE, ()


def _candidate(
    *,
    hole: SurfaceHole,
    component: InteroperabilityComponentDescriptor,
    mechanism_id: Optional[str],
    relation_id: Optional[str],
    context: ControlSurfaceContext,
) -> ValidationCandidate:
    status, blockers = _candidate_status(component)
    basis = [
        f"schema_id={hole.schema_id}",
        f"interaction_mode={hole.interaction_mode.value}",
    ]
    if relation_id is not None:
        basis.append(f"relation_id={relation_id}")
    if mechanism_id is not None:
        basis.append(f"mechanism_id={mechanism_id}")
    identity = {
        "hole_id": hole.hole_id,
        "component_id": component.component_id,
        "mechanism_id": mechanism_id,
        "relation_id": relation_id,
        "matching_basis": sorted(basis),
        "status": status.value,
    }
    prerequisites = tuple(
        dict.fromkeys(
            (
                *EXECUTION_PREREQUISITES,
                *component.execution_prerequisites,
                *(f"TRUST_ROOT:{item}" for item in component.trust_roots),
                *(f"DEPENDENCY:{item}" for item in component.optional_dependencies),
                *(f"AUTHORITY:{item}" for item in context.authority_requirements),
            )
        )
    )
    return ValidationCandidate(
        candidate_id=_stable_identifier("validation-candidate", identity),
        hole_id=hole.hole_id,
        status=status,
        component_id=component.component_id,
        mechanism_id=mechanism_id,
        relation_id=relation_id,
        matching_basis=tuple(basis),
        execution_prerequisites=prerequisites,
        blockers=blockers,
    )


def _unmatched(
    hole: SurfaceHole, context: ControlSurfaceContext
) -> ValidationCandidate:
    sought = [
        f"schema_id={hole.schema_id}",
        f"interaction_mode={hole.interaction_mode.value}",
    ]
    sought.extend(f"relation_id={item}" for item in hole.required_relations)
    sought.extend(f"mechanism_id={item}" for item in hole.mechanism_ids)
    identity = {"hole_id": hole.hole_id, "matching_basis": sorted(sought)}
    return ValidationCandidate(
        candidate_id=_stable_identifier("validation-candidate", identity),
        hole_id=hole.hole_id,
        status=CandidateStatus.UNMATCHED,
        component_id=None,
        mechanism_id=None,
        relation_id=None,
        matching_basis=tuple(sought),
        execution_prerequisites=(
            *EXECUTION_PREREQUISITES,
            *(f"AUTHORITY:{item}" for item in context.authority_requirements),
        ),
        blockers=("no exact registered component match",),
    )


def plan_validation(
    analysis: SurfaceAnalysis,
    registry: InteroperabilityComponentRegistry,
) -> ValidationPlan:
    """Match modeled holes to exact capabilities without selecting or executing one.

    If a hole names relations and mechanisms, a candidate is emitted only for an
    exact pair matched by one descriptor. Separate partial matches cannot be
    combined into a candidate.
    """

    if not isinstance(analysis, SurfaceAnalysis):
        raise SurfaceAnalysisError("analysis must be a SurfaceAnalysis")
    if not isinstance(registry, InteroperabilityComponentRegistry):
        raise SurfaceAnalysisError(
            "registry must be an InteroperabilityComponentRegistry"
        )
    if analysis.validity_errors:
        raise SurfaceAnalysisError(
            "cannot plan validation for a structurally invalid verification geometry"
        )

    candidates: list[ValidationCandidate] = []
    for hole in analysis.holes:
        matched: dict[tuple[str, Optional[str], Optional[str]], ValidationCandidate] = {}
        if hole.required_relations and hole.mechanism_ids:
            for relation_id in hole.required_relations:
                for mechanism_id in hole.mechanism_ids:
                    for component in registry.match_exact(
                        schema_id=hole.schema_id,
                        interaction_mode=hole.interaction_mode,
                        relation_id=relation_id,
                        mechanism_id=mechanism_id,
                    ):
                        key = (component.component_id, mechanism_id, relation_id)
                        matched[key] = _candidate(
                            hole=hole,
                            component=component,
                            mechanism_id=mechanism_id,
                            relation_id=relation_id,
                            context=analysis.context,
                        )
        elif hole.required_relations:
            for relation_id in hole.required_relations:
                for component in registry.match_exact(
                    schema_id=hole.schema_id,
                    interaction_mode=hole.interaction_mode,
                    relation_id=relation_id,
                ):
                    for mechanism_id in component.mechanism_ids:
                        key = (component.component_id, mechanism_id, relation_id)
                        matched[key] = _candidate(
                            hole=hole,
                            component=component,
                            mechanism_id=mechanism_id,
                            relation_id=relation_id,
                            context=analysis.context,
                        )
        elif hole.mechanism_ids:
            for mechanism_id in hole.mechanism_ids:
                for component in registry.match_exact(
                    schema_id=hole.schema_id,
                    interaction_mode=hole.interaction_mode,
                    mechanism_id=mechanism_id,
                ):
                    key = (component.component_id, mechanism_id, None)
                    matched[key] = _candidate(
                        hole=hole,
                        component=component,
                        mechanism_id=mechanism_id,
                        relation_id=None,
                        context=analysis.context,
                    )
        if matched:
            candidates.extend(
                matched[key]
                for key in sorted(
                    matched,
                    key=lambda item: (item[0], item[1] or "", item[2] or ""),
                )
            )
        else:
            candidates.append(_unmatched(hole, analysis.context))

    registry_digest = registry.canonical_digest()
    plan_identity = {
        "geometry_id": analysis.geometry_id,
        "geometry_digest": analysis.geometry_digest,
        "registry_version": registry.registry_version,
        "registry_digest": registry_digest,
        "scope": analysis.scope,
        "schema_id": analysis.context.schema_id,
        "interaction_mode": analysis.context.interaction_mode.value,
        "operating_regime": analysis.context.operating_regime,
        "consequence_profiles": list(analysis.context.consequence_profiles),
        "authority_requirements": list(analysis.context.authority_requirements),
        "candidates": [
            candidate.to_dict()
            for candidate in sorted(candidates, key=lambda item: item.candidate_id)
        ],
    }
    return ValidationPlan(
        plan_id=_stable_identifier("validation-plan", plan_identity),
        geometry_id=analysis.geometry_id,
        geometry_digest=analysis.geometry_digest,
        registry_version=registry.registry_version,
        registry_digest=registry_digest,
        context=analysis.context,
        candidates=tuple(candidates),
    )


generate_validation_plan = plan_validation


__all__ = [
    "ANALYSIS_CLAIM_BOUNDARY",
    "ANALYSIS_INPUT_MODE",
    "ANALYSIS_SCHEMA_VERSION",
    "CandidateStatus",
    "ControlSurfaceContext",
    "EXECUTION_PREREQUISITES",
    "MODELED_SURFACE_SCOPE",
    "PLAN_CLAIM_BOUNDARY",
    "PLAN_SCHEMA_VERSION",
    "STRICT_WIRE_LOADING_STATUS",
    "SurfaceAnalysis",
    "SurfaceAnalysisError",
    "SurfaceHole",
    "SurfaceHoleKind",
    "ValidationCandidate",
    "ValidationPlan",
    "analyze_verification_surface",
    "generate_validation_plan",
    "plan_validation",
]
