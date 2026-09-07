"""Experimental Verifier Standard (VSTD)-2 conflict diagnostics across explicitly
bound geometries.

This module compares only caller-declared proposition identities bound to exact
geometry digests.  It never infers that similarly named coordinates are equivalent,
never executes a verifier, and never treats graph consistency as physical truth.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from verifier.core.geometry import CoordinateStatus, VerificationGeometry


CONFLICT_REPORT_SCHEMA_VERSION = "VSTD-GEOMETRY-CONFLICTS-EXPERIMENTAL-0.1"
CONFLICT_REPORT_CLAIM_BOUNDARY = (
    "This diagnostic covers only the supplied geometry bytes, explicit shared-"
    "proposition bindings, and declared acyclic dependencies. It does not infer "
    "translation equivalence, omitted obligations, evidence validity, physical truth, "
    "safety, authority, conformance, or permission to execute a component."
)


class GeometryConflictStatus(str, Enum):
    """Fail-closed result states for a bounded multi-geometry diagnostic."""

    CONSISTENT = "CONSISTENT"
    CONFLICTED = "CONFLICTED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    INVALID = "INVALID"


class ConflictWitnessKind(str, Enum):
    """Contradictions that this bounded diagnostic can reproduce."""

    JUDGMENT_CONTRADICTION = "JUDGMENT_CONTRADICTION"
    DEPENDENCY_CYCLE = "DEPENDENCY_CYCLE"


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string without surrounding whitespace")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class SharedPropositionIdentity:
    """Explicitly bind one coordinate to one shared proposition identifier."""

    proposition_id: str
    geometry_digest: str
    coordinate_id: str

    def __post_init__(self) -> None:
        _nonempty(self.proposition_id, "proposition_id")
        _nonempty(self.coordinate_id, "coordinate_id")
        if (
            not isinstance(self.geometry_digest, str)
            or len(self.geometry_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.geometry_digest)
        ):
            raise ValueError("geometry_digest must be a lowercase 64-character hexadecimal digest")

    def to_dict(self) -> dict[str, str]:
        return {
            "proposition_id": self.proposition_id,
            "geometry_digest": self.geometry_digest,
            "coordinate_id": self.coordinate_id,
        }


@dataclass(frozen=True)
class AcyclicPropositionDependency:
    """Declare that one proposition must precede another without a cycle."""

    dependency_id: str
    prerequisite_proposition_id: str
    dependent_proposition_id: str

    def __post_init__(self) -> None:
        _nonempty(self.dependency_id, "dependency_id")
        _nonempty(self.prerequisite_proposition_id, "prerequisite_proposition_id")
        _nonempty(self.dependent_proposition_id, "dependent_proposition_id")

    def to_dict(self) -> dict[str, str]:
        return {
            "dependency_id": self.dependency_id,
            "prerequisite_proposition_id": self.prerequisite_proposition_id,
            "dependent_proposition_id": self.dependent_proposition_id,
        }


@dataclass(frozen=True)
class JudgmentObservation:
    """One exact geometry-coordinate status carried by a conflict witness."""

    geometry_digest: str
    coordinate_id: str
    status: CoordinateStatus

    def to_dict(self) -> dict[str, str]:
        return {
            "geometry_digest": self.geometry_digest,
            "coordinate_id": self.coordinate_id,
            "status": self.status.value,
        }


@dataclass(frozen=True)
class GeometryConflictWitness:
    """A deterministic witness derived entirely from declared input records."""

    witness_id: str
    kind: ConflictWitnessKind
    proposition_ids: tuple[str, ...]
    observations: tuple[JudgmentObservation, ...] = ()
    dependencies: tuple[AcyclicPropositionDependency, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "kind": self.kind.value,
            "proposition_ids": list(self.proposition_ids),
            "observations": [item.to_dict() for item in self.observations],
            "dependencies": [item.to_dict() for item in self.dependencies],
        }


@dataclass(frozen=True)
class GeometryConflictReport:
    """Bounded result of comparing an explicit set of geometry propositions."""

    status: GeometryConflictStatus
    geometry_digests: tuple[str, ...]
    identity_digest: str
    dependency_digest: str
    shared_proposition_ids: tuple[str, ...]
    witnesses: tuple[GeometryConflictWitness, ...] = ()
    missing_identity_coordinates: tuple[str, ...] = ()
    unshared_identity_coordinates: tuple[str, ...] = ()
    unresolved_propositions: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    schema_version: str = CONFLICT_REPORT_SCHEMA_VERSION
    claim_boundary: str = field(default=CONFLICT_REPORT_CLAIM_BOUNDARY, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "geometry_digests": list(self.geometry_digests),
            "identity_digest": self.identity_digest,
            "dependency_digest": self.dependency_digest,
            "shared_proposition_ids": list(self.shared_proposition_ids),
            "witnesses": [item.to_dict() for item in self.witnesses],
            "missing_identity_coordinates": list(self.missing_identity_coordinates),
            "unshared_identity_coordinates": list(self.unshared_identity_coordinates),
            "unresolved_propositions": list(self.unresolved_propositions),
            "errors": list(self.errors),
            "claim_boundary": self.claim_boundary,
        }

    def canonical_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.canonical_json_bytes()).hexdigest()


def _witness(
    kind: ConflictWitnessKind,
    proposition_ids: Iterable[str],
    *,
    observations: Iterable[JudgmentObservation] = (),
    dependencies: Iterable[AcyclicPropositionDependency] = (),
) -> GeometryConflictWitness:
    propositions = tuple(sorted(set(proposition_ids)))
    observed = tuple(
        sorted(
            observations,
            key=lambda item: (item.geometry_digest, item.coordinate_id, item.status.value),
        )
    )
    dependency_records = tuple(
        sorted(dependencies, key=lambda item: item.dependency_id)
    )
    material = {
        "kind": kind.value,
        "proposition_ids": list(propositions),
        "observations": [item.to_dict() for item in observed],
        "dependencies": [item.to_dict() for item in dependency_records],
    }
    return GeometryConflictWitness(
        witness_id=f"geometry-conflict:{_digest(material)}",
        kind=kind,
        proposition_ids=propositions,
        observations=observed,
        dependencies=dependency_records,
    )


def _dependency_cycles(
    dependencies: tuple[AcyclicPropositionDependency, ...],
) -> tuple[tuple[str, ...], ...]:
    """Return deterministic strongly connected components that violate acyclicity."""

    adjacency: dict[str, set[str]] = {}
    for dependency in dependencies:
        adjacency.setdefault(dependency.prerequisite_proposition_id, set()).add(
            dependency.dependent_proposition_id
        )
        adjacency.setdefault(dependency.dependent_proposition_id, set())

    reverse_adjacency = {node: set() for node in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse_adjacency[target].add(source)

    # Use an iterative Kosaraju traversal. Dependency graphs are supplied by
    # callers and may legitimately be deeper than Python's recursion limit.
    visited: set[str] = set()
    finishing_order: list[str] = []
    for root in sorted(adjacency):
        if root in visited:
            continue
        traversal: list[tuple[str, bool]] = [(root, False)]
        while traversal:
            node, expanded = traversal.pop()
            if expanded:
                finishing_order.append(node)
                continue
            if node in visited:
                continue
            # Mark on expansion, not when queued: a pending sibling must still
            # be traversable through this node to preserve depth-first finish order.
            visited.add(node)
            traversal.append((node, True))
            for target in reversed(sorted(adjacency[node])):
                if target not in visited:
                    traversal.append((target, False))

    assigned: set[str] = set()
    components: list[tuple[str, ...]] = []
    for root in reversed(finishing_order):
        if root in assigned:
            continue
        assigned.add(root)
        component: list[str] = []
        traversal = [root]
        while traversal:
            node = traversal.pop()
            component.append(node)
            for source in reversed(sorted(reverse_adjacency[node])):
                if source not in assigned:
                    assigned.add(source)
                    traversal.append(source)
        ordered = tuple(sorted(component))
        if len(ordered) > 1 or (
            len(ordered) == 1 and ordered[0] in adjacency[ordered[0]]
        ):
            components.append(ordered)
    return tuple(sorted(components))


def analyze_geometry_conflicts(
    geometries: Iterable[VerificationGeometry],
    identities: Iterable[SharedPropositionIdentity],
    dependencies: Iterable[AcyclicPropositionDependency] = (),
) -> GeometryConflictReport:
    """Compare explicitly identified propositions without executing a mechanism."""

    geometry_items = tuple(geometries)
    identity_items = tuple(identities)
    dependency_items = tuple(dependencies)
    identity_payload = [
        item.to_dict()
        for item in sorted(
            (item for item in identity_items if isinstance(item, SharedPropositionIdentity)),
            key=lambda item: (item.geometry_digest, item.coordinate_id, item.proposition_id),
        )
    ]
    dependency_payload = [
        item.to_dict()
        for item in sorted(
            (
                item
                for item in dependency_items
                if isinstance(item, AcyclicPropositionDependency)
            ),
            key=lambda item: item.dependency_id,
        )
    ]
    identity_digest = _digest(identity_payload)
    dependency_digest = _digest(dependency_payload)

    type_errors: list[str] = []
    if not all(isinstance(item, VerificationGeometry) for item in geometry_items):
        type_errors.append("geometries must contain only VerificationGeometry objects")
    if not all(isinstance(item, SharedPropositionIdentity) for item in identity_items):
        type_errors.append("identities must contain only SharedPropositionIdentity records")
    if not all(
        isinstance(item, AcyclicPropositionDependency) for item in dependency_items
    ):
        type_errors.append(
            "dependencies must contain only AcyclicPropositionDependency records"
        )
    if type_errors:
        return GeometryConflictReport(
            status=GeometryConflictStatus.INVALID,
            geometry_digests=(),
            identity_digest=identity_digest,
            dependency_digest=dependency_digest,
            shared_proposition_ids=(),
            errors=tuple(type_errors),
        )

    digest_to_geometry: dict[str, VerificationGeometry] = {}
    errors: list[str] = []
    for geometry in geometry_items:
        try:
            geometry_digest = geometry.canonical_digest()
            geometry_errors = geometry.validate()
        except (AttributeError, TypeError, ValueError) as exc:
            errors.append(f"geometry cannot be analyzed: {exc}")
            continue
        if geometry_digest in digest_to_geometry:
            errors.append(f"duplicate geometry digest {geometry_digest}")
        digest_to_geometry[geometry_digest] = geometry
        errors.extend(
            f"geometry {geometry_digest}: {error}" for error in geometry_errors
        )
    geometry_digests = tuple(sorted(digest_to_geometry))
    if errors:
        return GeometryConflictReport(
            status=GeometryConflictStatus.INVALID,
            geometry_digests=geometry_digests,
            identity_digest=identity_digest,
            dependency_digest=dependency_digest,
            shared_proposition_ids=(),
            errors=tuple(sorted(set(errors))),
        )

    binding_by_coordinate: dict[tuple[str, str], SharedPropositionIdentity] = {}
    proposition_bindings: dict[str, list[SharedPropositionIdentity]] = {}
    for identity in identity_items:
        geometry = digest_to_geometry.get(identity.geometry_digest)
        if geometry is None:
            errors.append(
                f"identity {identity.proposition_id!r} references an unknown geometry digest"
            )
            continue
        coordinate_ids = {item.coordinate_id for item in geometry.coordinates}
        if identity.coordinate_id not in coordinate_ids:
            errors.append(
                f"identity {identity.proposition_id!r} references unknown coordinate "
                f"{identity.coordinate_id!r}"
            )
            continue
        if identity.coordinate_id not in geometry.surface.coordinate_ids:
            errors.append(
                f"identity {identity.proposition_id!r} references coordinate "
                f"{identity.coordinate_id!r} outside the declared surface"
            )
            continue
        key = (identity.geometry_digest, identity.coordinate_id)
        if key in binding_by_coordinate:
            errors.append(
                f"coordinate {identity.geometry_digest}:{identity.coordinate_id} has multiple identities"
            )
            continue
        if any(
            item.geometry_digest == identity.geometry_digest
            for item in proposition_bindings.get(identity.proposition_id, [])
        ):
            errors.append(
                f"proposition {identity.proposition_id!r} maps to multiple coordinates in one geometry"
            )
            continue
        binding_by_coordinate[key] = identity
        proposition_bindings.setdefault(identity.proposition_id, []).append(identity)

    dependency_ids = [item.dependency_id for item in dependency_items]
    if len(set(dependency_ids)) != len(dependency_ids):
        errors.append("dependency identifiers must be unique")
    known_propositions = set(proposition_bindings)
    for dependency in dependency_items:
        for proposition_id in (
            dependency.prerequisite_proposition_id,
            dependency.dependent_proposition_id,
        ):
            if proposition_id not in known_propositions:
                errors.append(
                    f"dependency {dependency.dependency_id!r} references unknown proposition "
                    f"{proposition_id!r}"
                )
    if errors:
        return GeometryConflictReport(
            status=GeometryConflictStatus.INVALID,
            geometry_digests=geometry_digests,
            identity_digest=identity_digest,
            dependency_digest=dependency_digest,
            shared_proposition_ids=(),
            errors=tuple(sorted(set(errors))),
        )

    shared_propositions = tuple(
        sorted(
            proposition_id
            for proposition_id, bindings in proposition_bindings.items()
            if len({item.geometry_digest for item in bindings}) > 1
        )
    )
    shared_proposition_set = set(shared_propositions)
    missing_identities = tuple(
        sorted(
            f"{geometry_digest}:{coordinate_id}"
            for geometry_digest, geometry in digest_to_geometry.items()
            for coordinate_id in geometry.surface.coordinate_ids
            if (geometry_digest, coordinate_id) not in binding_by_coordinate
        )
    )
    unshared_identities = tuple(
        sorted(
            f"{geometry_digest}:{coordinate_id}"
            for (geometry_digest, coordinate_id), identity in binding_by_coordinate.items()
            if identity.proposition_id not in shared_proposition_set
        )
    )

    observations: dict[str, tuple[JudgmentObservation, ...]] = {}
    unresolved: set[str] = set()
    for proposition_id in shared_propositions:
        items: list[JudgmentObservation] = []
        for binding in proposition_bindings[proposition_id]:
            geometry = digest_to_geometry[binding.geometry_digest]
            judgment = next(
                (
                    item
                    for item in geometry.judgments
                    if item.coordinate_id == binding.coordinate_id
                ),
                None,
            )
            if judgment is None:
                unresolved.add(proposition_id)
                continue
            items.append(
                JudgmentObservation(
                    geometry_digest=binding.geometry_digest,
                    coordinate_id=binding.coordinate_id,
                    status=judgment.status,
                )
            )
            if judgment.status not in {
                CoordinateStatus.VERIFIED,
                CoordinateStatus.FALSIFIED,
            }:
                unresolved.add(proposition_id)
        observations[proposition_id] = tuple(items)

    witnesses: list[GeometryConflictWitness] = []
    for proposition_id in shared_propositions:
        statuses = {item.status for item in observations[proposition_id]}
        if {CoordinateStatus.VERIFIED, CoordinateStatus.FALSIFIED}.issubset(statuses):
            witnesses.append(
                _witness(
                    ConflictWitnessKind.JUDGMENT_CONTRADICTION,
                    (proposition_id,),
                    observations=observations[proposition_id],
                )
            )

    for component in _dependency_cycles(dependency_items):
        component_set = set(component)
        cycle_dependencies = tuple(
            item
            for item in dependency_items
            if item.prerequisite_proposition_id in component_set
            and item.dependent_proposition_id in component_set
        )
        witnesses.append(
            _witness(
                ConflictWitnessKind.DEPENDENCY_CYCLE,
                component,
                dependencies=cycle_dependencies,
            )
        )

    ordered_witnesses = tuple(sorted(witnesses, key=lambda item: item.witness_id))
    not_established_reasons: list[str] = []
    if len(geometry_digests) < 2:
        not_established_reasons.append("at least two distinct geometries are required")
    if missing_identities:
        not_established_reasons.append(
            "one or more surface coordinates lacks an explicit proposition identity"
        )
    if unshared_identities:
        not_established_reasons.append(
            "one or more proposition identities are not shared across geometries"
        )
    if not shared_propositions:
        not_established_reasons.append(
            "no proposition identity is shared by two distinct geometries"
        )
    if unresolved:
        not_established_reasons.append(
            "one or more shared propositions lacks a current VERIFIED or FALSIFIED judgment"
        )

    if ordered_witnesses:
        status = GeometryConflictStatus.CONFLICTED
    elif not_established_reasons:
        status = GeometryConflictStatus.NOT_ESTABLISHED
    else:
        status = GeometryConflictStatus.CONSISTENT
    return GeometryConflictReport(
        status=status,
        geometry_digests=geometry_digests,
        identity_digest=identity_digest,
        dependency_digest=dependency_digest,
        shared_proposition_ids=shared_propositions,
        witnesses=ordered_witnesses,
        missing_identity_coordinates=missing_identities,
        unshared_identity_coordinates=unshared_identities,
        unresolved_propositions=tuple(sorted(unresolved)),
        errors=tuple(not_established_reasons),
    )


__all__ = [
    "AcyclicPropositionDependency",
    "ConflictWitnessKind",
    "GeometryConflictReport",
    "GeometryConflictStatus",
    "GeometryConflictWitness",
    "JudgmentObservation",
    "SharedPropositionIdentity",
    "analyze_geometry_conflicts",
]
