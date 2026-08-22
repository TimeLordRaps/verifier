"""Typed verification geometry for the additive VSTD-0.2 vertical slice.

This module does not alter VSTD-0.1 or VSTD-DATA-0.1 receipts.  It supplies a
small common representation for describing *where* verification attaches,
*in what respect*, and why apparent closure must sometimes be refused.

The central epistemic rule is fail-closed: assumptions, declarations, and
trust boundaries are representable, but none of them count as evidence of a
passing verification judgment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional


GEOMETRY_SCHEMA_VERSION = "VSTD-0.2"


class LocusKind(str, Enum):
    PROJECT = "PROJECT"
    REPOSITORY = "REPOSITORY"
    PACKAGE = "PACKAGE"
    MODULE = "MODULE"
    FILE = "FILE"
    OBJECT = "OBJECT"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    EXPRESSION = "EXPRESSION"
    STATEMENT = "STATEMENT"
    AST_NODE = "AST_NODE"
    INSTRUCTION = "INSTRUCTION"
    DATASET = "DATASET"
    ROW = "ROW"
    MODEL = "MODEL"
    CHECKPOINT = "CHECKPOINT"
    VISUALIZATION = "VISUALIZATION"
    INTERFACE = "INTERFACE"
    PROCESS = "PROCESS"
    RELATION = "RELATION"
    VERIFICATION_GEOMETRY = "VERIFICATION_GEOMETRY"
    CUSTOM = "CUSTOM"


class Grain(str, Enum):
    SUBJECT = "SUBJECT"
    REPOSITORY = "REPOSITORY"
    PACKAGE = "PACKAGE"
    MODULE = "MODULE"
    FILE = "FILE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    STATEMENT = "STATEMENT"
    EXPRESSION = "EXPRESSION"
    INSTRUCTION = "INSTRUCTION"
    DATASET = "DATASET"
    ROW = "ROW"
    MODEL = "MODEL"
    CHECKPOINT = "CHECKPOINT"
    CUSTOM = "CUSTOM"


class Stratum(str, Enum):
    REQUIREMENT = "REQUIREMENT"
    SOURCE = "SOURCE"
    AST = "AST"
    IR = "IR"
    ASSEMBLY = "ASSEMBLY"
    EXECUTION = "EXECUTION"
    OUTPUT = "OUTPUT"
    VERIFICATION = "VERIFICATION"
    CUSTOM = "CUSTOM"


class CoordinateStatus(str, Enum):
    PRE_VERIFIED = "PRE_VERIFIED"
    VERIFIED = "VERIFIED"
    FALSIFIED = "FALSIFIED"
    INDETERMINATE = "INDETERMINATE"
    UNSUPPORTED = "UNSUPPORTED"
    STALE = "STALE"


class ResidualType(str, Enum):
    STRUCTURAL = "STRUCTURAL"
    BEHAVIORAL = "BEHAVIORAL"
    SEMANTIC = "SEMANTIC"
    ONTOLOGICAL = "ONTOLOGICAL"


class ResidualDisposition(str, Enum):
    OPEN = "OPEN"
    LOCALIZED = "LOCALIZED"
    RESOLVED = "RESOLVED"
    HORIZON = "HORIZON"


class HorizonKind(str, Enum):
    EVIDENCE = "EVIDENCE"
    REPRESENTATION = "REPRESENTATION"
    MECHANISM = "MECHANISM"
    GRAIN = "GRAIN"
    ONTOLOGY = "ONTOLOGY"
    TRUST_ROOT = "TRUST_ROOT"


class ValenceStatus(str, Enum):
    OPEN = "OPEN"
    DISCHARGED = "DISCHARGED"
    HORIZON = "HORIZON"


class NoveltyKind(str, Enum):
    GRAIN = "GRAIN"
    LOCUS = "LOCUS"
    FACET = "FACET"
    SEAM = "SEAM"
    STRATUM = "STRATUM"
    MECHANISM = "MECHANISM"
    ONTOLOGICAL = "ONTOLOGICAL"


@dataclass(frozen=True)
class Subject:
    subject_id: str
    label: str
    version: str
    parent_subject_id: Optional[str] = None


@dataclass(frozen=True)
class Facet:
    """An assurance dimension.  Facets remain extensible by stable id."""

    facet_id: str
    label: str
    description: str


@dataclass(frozen=True)
class Locus:
    """A scale-independent addressable entity to which verification attaches."""

    locus_id: str
    subject_id: str
    label: str
    kind: LocusKind
    grain: Grain
    stratum: Stratum
    address: str
    parent_locus_id: Optional[str] = None


@dataclass(frozen=True)
class Seam:
    """An interface, dependency, or translation boundary between loci."""

    seam_id: str
    label: str
    source_locus_id: str
    target_locus_id: str
    relation: str


@dataclass(frozen=True)
class Coordinate:
    """The locus x facet point at which a verification claim can attach."""

    coordinate_id: str
    locus_id: str
    facet_id: str


@dataclass(frozen=True)
class VerificationSurface:
    """A declared selection of coordinates and relevant relations."""

    surface_id: str
    subject_id: str
    coordinate_ids: tuple[str, ...]
    seam_ids: tuple[str, ...] = ()
    scope_statement: str = ""


@dataclass(frozen=True)
class VerificationMechanism:
    mechanism_id: str
    label: str
    version: str
    post_verified: bool = False
    post_verification_evidence_ids: tuple[str, ...] = ()
    boundary_horizon_id: Optional[str] = None


@dataclass(frozen=True)
class CoordinateJudgment:
    coordinate_id: str
    status: CoordinateStatus
    mechanism_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Horizon:
    """An explicit point beyond which the current derivation cannot proceed."""

    horizon_id: str
    kind: HorizonKind
    description: str
    locus_id: Optional[str] = None
    coordinate_id: Optional[str] = None
    seam_id: Optional[str] = None


@dataclass(frozen=True)
class Residual:
    residual_id: str
    residual_type: ResidualType
    description: str
    observed: str
    represented_or_reconstructed: str
    material: bool = True
    disposition: ResidualDisposition = ResidualDisposition.OPEN
    locus_id: Optional[str] = None
    coordinate_id: Optional[str] = None
    seam_id: Optional[str] = None
    horizon_id: Optional[str] = None


@dataclass(frozen=True)
class VerificationValence:
    """An open relational/evidentiary capacity licensed by existing geometry."""

    valence_id: str
    source_kind: str
    source_id: str
    required_relation: str
    description: str
    status: ValenceStatus = ValenceStatus.OPEN
    evidence_ids: tuple[str, ...] = ()
    horizon_id: Optional[str] = None


@dataclass(frozen=True)
class ReconstructionAttempt:
    reconstruction_id: str
    subject_id: str
    method: str
    observed_ref: str
    reconstructed_ref: str
    residual_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationLayer:
    """One bounded order of verification under the adjacent-layer invariant."""

    layer_id: str
    order: int
    subject_id: str
    verifies_layer_id: Optional[str] = None
    coordinate_ids: tuple[str, ...] = ()
    mechanism_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    horizon_id: Optional[str] = None


@dataclass(frozen=True)
class Novelty:
    novelty_id: str
    kind: NoveltyKind
    residual_id: str
    description: str


@dataclass(frozen=True)
class ClosureAssessment:
    ordinary_closed: bool
    self_closed: bool
    ordinary_blockers: tuple[str, ...]
    self_closure_blockers: tuple[str, ...]


def _duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


@dataclass
class VerificationGeometry:
    """A finite verification geometry and its higher-order audit surface."""

    geometry_id: str
    primary_subject_id: str
    subjects: list[Subject]
    loci: list[Locus]
    facets: list[Facet]
    coordinates: list[Coordinate]
    surface: VerificationSurface
    seams: list[Seam] = field(default_factory=list)
    mechanisms: list[VerificationMechanism] = field(default_factory=list)
    judgments: list[CoordinateJudgment] = field(default_factory=list)
    horizons: list[Horizon] = field(default_factory=list)
    residuals: list[Residual] = field(default_factory=list)
    valences: list[VerificationValence] = field(default_factory=list)
    reconstructions: list[ReconstructionAttempt] = field(default_factory=list)
    verification_layers: list[VerificationLayer] = field(default_factory=list)
    novelties: list[Novelty] = field(default_factory=list)
    secondary_subject_id: Optional[str] = None
    focus_coordinate_ids: tuple[str, ...] = ()
    meta_focus_coordinate_ids: tuple[str, ...] = ()
    schema_version: str = GEOMETRY_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))

    def canonical_digest(self) -> str:
        payload = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def validate(self) -> list[str]:
        """Return structural and epistemic errors; an empty list means valid."""

        errors: list[str] = []
        if self.schema_version != GEOMETRY_SCHEMA_VERSION:
            errors.append(
                f"schema_version must be {GEOMETRY_SCHEMA_VERSION!r}, got {self.schema_version!r}"
            )
        if not self.geometry_id:
            errors.append("geometry_id is empty")

        collections = {
            "subject": [item.subject_id for item in self.subjects],
            "locus": [item.locus_id for item in self.loci],
            "facet": [item.facet_id for item in self.facets],
            "coordinate": [item.coordinate_id for item in self.coordinates],
            "seam": [item.seam_id for item in self.seams],
            "mechanism": [item.mechanism_id for item in self.mechanisms],
            "horizon": [item.horizon_id for item in self.horizons],
            "residual": [item.residual_id for item in self.residuals],
            "valence": [item.valence_id for item in self.valences],
            "reconstruction": [item.reconstruction_id for item in self.reconstructions],
            "verification_layer": [item.layer_id for item in self.verification_layers],
            "novelty": [item.novelty_id for item in self.novelties],
        }
        for kind, ids in collections.items():
            for duplicate in sorted(_duplicates(ids)):
                errors.append(f"duplicate {kind} id {duplicate!r}")
            for index, value in enumerate(ids):
                if not value:
                    errors.append(f"{kind}[{index}] has an empty id")

        subject_ids = set(collections["subject"])
        locus_ids = set(collections["locus"])
        facet_ids = set(collections["facet"])
        coordinate_ids = set(collections["coordinate"])
        seam_ids = set(collections["seam"])
        mechanism_ids = set(collections["mechanism"])
        horizon_ids = set(collections["horizon"])
        residual_ids = set(collections["residual"])

        if self.primary_subject_id not in subject_ids:
            errors.append(f"primary_subject_id {self.primary_subject_id!r} is unknown")
        if self.secondary_subject_id and self.secondary_subject_id not in subject_ids:
            errors.append(f"secondary_subject_id {self.secondary_subject_id!r} is unknown")
        if self.surface.subject_id not in subject_ids:
            errors.append(f"surface subject_id {self.surface.subject_id!r} is unknown")

        for subject in self.subjects:
            if subject.parent_subject_id and subject.parent_subject_id not in subject_ids:
                errors.append(
                    f"subject {subject.subject_id!r} has unknown parent {subject.parent_subject_id!r}"
                )
            if subject.parent_subject_id == subject.subject_id:
                errors.append(f"subject {subject.subject_id!r} cannot contain itself")

        parents: dict[str, str] = {}
        for locus in self.loci:
            if locus.subject_id not in subject_ids:
                errors.append(f"locus {locus.locus_id!r} has unknown subject {locus.subject_id!r}")
            if not locus.address:
                errors.append(f"locus {locus.locus_id!r} has an empty address")
            if locus.parent_locus_id:
                if locus.parent_locus_id not in locus_ids:
                    errors.append(
                        f"locus {locus.locus_id!r} has unknown parent {locus.parent_locus_id!r}"
                    )
                elif locus.parent_locus_id == locus.locus_id:
                    errors.append(f"locus {locus.locus_id!r} cannot contain itself")
                else:
                    parents[locus.locus_id] = locus.parent_locus_id
        for start in parents:
            visited: set[str] = set()
            current = start
            while current in parents:
                if current in visited:
                    errors.append(f"locus containment cycle reaches {current!r}")
                    break
                visited.add(current)
                current = parents[current]

        coordinate_pairs: set[tuple[str, str]] = set()
        for coordinate in self.coordinates:
            if coordinate.locus_id not in locus_ids:
                errors.append(
                    f"coordinate {coordinate.coordinate_id!r} has unknown locus {coordinate.locus_id!r}"
                )
            if coordinate.facet_id not in facet_ids:
                errors.append(
                    f"coordinate {coordinate.coordinate_id!r} has unknown facet {coordinate.facet_id!r}"
                )
            pair = (coordinate.locus_id, coordinate.facet_id)
            if pair in coordinate_pairs:
                errors.append(f"duplicate locus-facet coordinate {pair!r}")
            coordinate_pairs.add(pair)

        for seam in self.seams:
            if seam.source_locus_id not in locus_ids:
                errors.append(f"seam {seam.seam_id!r} has unknown source locus")
            if seam.target_locus_id not in locus_ids:
                errors.append(f"seam {seam.seam_id!r} has unknown target locus")
            if not seam.relation:
                errors.append(f"seam {seam.seam_id!r} has an empty relation")

        for coordinate_id in self.surface.coordinate_ids:
            if coordinate_id not in coordinate_ids:
                errors.append(f"surface references unknown coordinate {coordinate_id!r}")
        if not self.surface.coordinate_ids:
            errors.append("surface must select at least one coordinate")
        for seam_id in self.surface.seam_ids:
            if seam_id not in seam_ids:
                errors.append(f"surface references unknown seam {seam_id!r}")
        if _duplicates(self.surface.coordinate_ids):
            errors.append("surface contains duplicate coordinate ids")
        if _duplicates(self.surface.seam_ids):
            errors.append("surface contains duplicate seam ids")

        for coordinate_id in (*self.focus_coordinate_ids, *self.meta_focus_coordinate_ids):
            if coordinate_id not in coordinate_ids:
                errors.append(f"focus references unknown coordinate {coordinate_id!r}")
        if not set(self.focus_coordinate_ids).issubset(set(self.surface.coordinate_ids)):
            errors.append("focus coordinates must be selected by the declared surface")

        for horizon in self.horizons:
            locations = [horizon.locus_id, horizon.coordinate_id, horizon.seam_id]
            if not any(locations):
                errors.append(f"horizon {horizon.horizon_id!r} has no location")
            if horizon.locus_id and horizon.locus_id not in locus_ids:
                errors.append(f"horizon {horizon.horizon_id!r} has unknown locus")
            if horizon.coordinate_id and horizon.coordinate_id not in coordinate_ids:
                errors.append(f"horizon {horizon.horizon_id!r} has unknown coordinate")
            if horizon.seam_id and horizon.seam_id not in seam_ids:
                errors.append(f"horizon {horizon.horizon_id!r} has unknown seam")

        for mechanism in self.mechanisms:
            if mechanism.post_verified and not mechanism.post_verification_evidence_ids:
                errors.append(
                    f"mechanism {mechanism.mechanism_id!r} is post-verified without evidence"
                )
            if mechanism.boundary_horizon_id:
                if mechanism.boundary_horizon_id not in horizon_ids:
                    errors.append(
                        f"mechanism {mechanism.mechanism_id!r} has unknown boundary horizon"
                    )
                if mechanism.post_verified:
                    errors.append(
                        f"mechanism {mechanism.mechanism_id!r} cannot be post-verified and terminate at an unresolved horizon"
                    )

        judgment_by_coordinate: dict[str, CoordinateJudgment] = {}
        for judgment in self.judgments:
            if judgment.coordinate_id not in coordinate_ids:
                errors.append(f"judgment references unknown coordinate {judgment.coordinate_id!r}")
            if judgment.coordinate_id in judgment_by_coordinate:
                errors.append(f"multiple current judgments for coordinate {judgment.coordinate_id!r}")
            judgment_by_coordinate[judgment.coordinate_id] = judgment
            for mechanism_id in judgment.mechanism_ids:
                if mechanism_id not in mechanism_ids:
                    errors.append(
                        f"judgment for {judgment.coordinate_id!r} references unknown mechanism {mechanism_id!r}"
                    )
            if judgment.status is CoordinateStatus.VERIFIED:
                if not judgment.mechanism_ids:
                    errors.append(
                        f"coordinate {judgment.coordinate_id!r} is VERIFIED without a mechanism"
                    )
                if not judgment.evidence_ids:
                    errors.append(
                        f"coordinate {judgment.coordinate_id!r} is VERIFIED without evidence; assumptions do not count"
                    )

        for residual in self.residuals:
            if not any((residual.locus_id, residual.coordinate_id, residual.seam_id)):
                errors.append(f"residual {residual.residual_id!r} is not localized")
            if residual.locus_id and residual.locus_id not in locus_ids:
                errors.append(f"residual {residual.residual_id!r} has unknown locus")
            if residual.coordinate_id and residual.coordinate_id not in coordinate_ids:
                errors.append(f"residual {residual.residual_id!r} has unknown coordinate")
            if residual.seam_id and residual.seam_id not in seam_ids:
                errors.append(f"residual {residual.residual_id!r} has unknown seam")
            if residual.disposition is ResidualDisposition.HORIZON:
                if not residual.horizon_id:
                    errors.append(
                        f"residual {residual.residual_id!r} has HORIZON disposition without a horizon"
                    )
                elif residual.horizon_id not in horizon_ids:
                    errors.append(f"residual {residual.residual_id!r} has unknown horizon")
            elif residual.horizon_id:
                errors.append(
                    f"residual {residual.residual_id!r} references a horizon but its disposition is not HORIZON"
                )

        for valence in self.valences:
            valid_sources = {
                "LOCUS": locus_ids,
                "COORDINATE": coordinate_ids,
                "SEAM": seam_ids,
                "SURFACE": {self.surface.surface_id},
                "GEOMETRY": {self.geometry_id},
            }
            if valence.source_kind not in valid_sources:
                errors.append(f"valence {valence.valence_id!r} has invalid source_kind")
            elif valence.source_id not in valid_sources[valence.source_kind]:
                errors.append(f"valence {valence.valence_id!r} has unknown source_id")
            if valence.status is ValenceStatus.DISCHARGED and not valence.evidence_ids:
                errors.append(f"valence {valence.valence_id!r} is discharged without evidence")
            if valence.status is ValenceStatus.HORIZON:
                if not valence.horizon_id or valence.horizon_id not in horizon_ids:
                    errors.append(f"valence {valence.valence_id!r} has no valid horizon")
            elif valence.horizon_id:
                errors.append(
                    f"valence {valence.valence_id!r} references a horizon without HORIZON status"
                )

        for reconstruction in self.reconstructions:
            if reconstruction.subject_id not in subject_ids:
                errors.append(
                    f"reconstruction {reconstruction.reconstruction_id!r} has unknown subject"
                )
            for residual_id in reconstruction.residual_ids:
                if residual_id not in residual_ids:
                    errors.append(
                        f"reconstruction {reconstruction.reconstruction_id!r} references unknown residual {residual_id!r}"
                    )

        layers_by_id = {layer.layer_id: layer for layer in self.verification_layers}
        orders = sorted(layer.order for layer in self.verification_layers)
        if orders and orders != list(range(orders[-1] + 1)):
            errors.append("verification layer orders must be contiguous and start at 0")
        for layer in self.verification_layers:
            if layer.order < 0:
                errors.append(f"verification layer {layer.layer_id!r} has negative order")
            if layer.subject_id not in subject_ids:
                errors.append(f"verification layer {layer.layer_id!r} has unknown subject")
            if layer.order == 0 and layer.verifies_layer_id is not None:
                errors.append("verification layer order 0 cannot verify another layer")
            if layer.order > 0:
                target = layers_by_id.get(layer.verifies_layer_id or "")
                if target is None:
                    errors.append(
                        f"verification layer {layer.layer_id!r} does not identify a previous layer"
                    )
                elif target.order != layer.order - 1:
                    errors.append(
                        f"verification layer {layer.layer_id!r} violates the adjacent-layer invariant"
                    )
            for coordinate_id in layer.coordinate_ids:
                if coordinate_id not in coordinate_ids:
                    errors.append(f"verification layer {layer.layer_id!r} has unknown coordinate")
            for mechanism_id in layer.mechanism_ids:
                if mechanism_id not in mechanism_ids:
                    errors.append(f"verification layer {layer.layer_id!r} has unknown mechanism")
            if layer.horizon_id and layer.horizon_id not in horizon_ids:
                errors.append(f"verification layer {layer.layer_id!r} has unknown horizon")

        for novelty in self.novelties:
            if novelty.residual_id not in residual_ids:
                errors.append(f"novelty {novelty.novelty_id!r} has unknown residual")

        return errors

    def assess_closure(self) -> ClosureAssessment:
        """Assess declared closure and higher-order self-closure separately.

        Ordinary closure is allowed up to an explicit horizon: the declared
        coordinates must pass, and every material residual must be resolved or
        honestly terminated at a horizon.  Self-closure is stronger and refuses
        all unresolved horizons, open valence, unverified mechanisms, and
        unaccounted verification layers.
        """

        ordinary: list[str] = list(self.validate())
        self_blockers: list[str] = []
        judgments = {judgment.coordinate_id: judgment for judgment in self.judgments}

        for coordinate_id in self.surface.coordinate_ids:
            judgment = judgments.get(coordinate_id)
            if judgment is None:
                ordinary.append(f"surface coordinate {coordinate_id!r} has no judgment")
            elif judgment.status is not CoordinateStatus.VERIFIED:
                ordinary.append(
                    f"surface coordinate {coordinate_id!r} is {judgment.status.value}, not VERIFIED"
                )

        for residual in self.residuals:
            if residual.material and residual.disposition not in {
                ResidualDisposition.RESOLVED,
                ResidualDisposition.HORIZON,
            }:
                ordinary.append(
                    f"material residual {residual.residual_id!r} remains {residual.disposition.value}"
                )

        ordinary_closed = not ordinary
        if not ordinary_closed:
            self_blockers.append("ordinary closure has not been established")

        for residual in self.residuals:
            if residual.material and residual.disposition is not ResidualDisposition.RESOLVED:
                self_blockers.append(
                    f"material residual {residual.residual_id!r} is not resolved"
                )
        for horizon in self.horizons:
            self_blockers.append(
                f"horizon {horizon.horizon_id!r} terminates derivation without proving what lies beyond it"
            )
        for valence in self.valences:
            if valence.status is not ValenceStatus.DISCHARGED:
                self_blockers.append(
                    f"verification valence {valence.valence_id!r} remains {valence.status.value}"
                )
        for mechanism in self.mechanisms:
            if not mechanism.post_verified:
                self_blockers.append(
                    f"mechanism {mechanism.mechanism_id!r} is not post-verified"
                )
        for layer in self.verification_layers:
            if layer.horizon_id:
                self_blockers.append(
                    f"verification layer {layer.layer_id!r} terminates at a horizon"
                )

        if self.secondary_subject_id is None:
            self_blockers.append("self-closure requires a secondary verification subject")
        if not self.meta_focus_coordinate_ids:
            self_blockers.append("self-closure requires an explicit meta-focus")
        layer_orders = {layer.order for layer in self.verification_layers}
        if not {0, 1}.issubset(layer_orders):
            self_blockers.append("self-closure requires adjacent V0 and V1 verification layers")
        for layer in self.verification_layers:
            for coordinate_id in layer.coordinate_ids:
                judgment = judgments.get(coordinate_id)
                if judgment is None or judgment.status is not CoordinateStatus.VERIFIED:
                    self_blockers.append(
                        f"verification layer {layer.layer_id!r} coordinate {coordinate_id!r} is not VERIFIED"
                    )
            if layer.order > 0 and not layer.evidence_ids:
                self_blockers.append(
                    f"higher verification layer {layer.layer_id!r} has no sufficiency evidence"
                )

        return ClosureAssessment(
            ordinary_closed=ordinary_closed,
            self_closed=ordinary_closed and not self_blockers,
            ordinary_blockers=tuple(dict.fromkeys(ordinary)),
            self_closure_blockers=tuple(dict.fromkeys(self_blockers)),
        )


def validate_geometry(geometry: VerificationGeometry) -> list[str]:
    """Functional validator entry point for callers that prefer one."""

    return geometry.validate()
