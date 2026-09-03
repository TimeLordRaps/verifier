"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Domain-neutral component descriptors for VSTD interoperability planning.

Registry membership describes an exact declared capability.  It does not run a
component, establish availability, validate a native result, or grant assurance.
Domain tags are discovery metadata only and never participate in matching.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional


CATALOG_SCHEMA_VERSION = "VSTD-INTEROPERABILITY-CATALOG-1.0"


class CatalogError(ValueError):
    """Raised when a component descriptor or registry is malformed."""


class ComponentKind(str, Enum):
    ADAPTER = "ADAPTER"
    TRANSLATOR = "TRANSLATOR"
    COMPARATOR = "COMPARATOR"
    VERIFIER = "VERIFIER"
    CONSTRAINT = "CONSTRAINT"
    COLLECTOR = "COLLECTOR"
    POLICY = "POLICY"
    WORKFLOW = "WORKFLOW"


class ComponentLifecycle(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNSUPPORTED = "UNSUPPORTED"
    ABSENT = "ABSENT"


class ComponentAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"
    UNAVAILABLE = "UNAVAILABLE"


class InteractionMode(str, Enum):
    STATIC = "STATIC"
    OFFLINE_REPLAY = "OFFLINE_REPLAY"
    SIMULATION = "SIMULATION"
    LIVE_READ_ONLY = "LIVE_READ_ONLY"
    LIVE_MUTATING = "LIVE_MUTATING"


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CatalogError(
            f"{label} must be a non-empty string without surrounding whitespace"
        )
    return value


def _unique_strings(values: Any, label: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise CatalogError(f"{label} must be an array of strings")
    normalized = tuple(_nonempty(value, f"{label} item") for value in values)
    if len(set(normalized)) != len(normalized):
        raise CatalogError(f"{label} must not contain duplicates")
    return tuple(sorted(normalized))


def _interaction_modes(values: Any) -> tuple[InteractionMode, ...]:
    if not isinstance(values, (tuple, list)):
        raise CatalogError("interaction_modes must be an array")
    try:
        normalized = tuple(InteractionMode(value) for value in values)
    except (TypeError, ValueError) as exc:
        raise CatalogError(f"invalid interaction mode: {exc}") from exc
    if len(set(normalized)) != len(normalized):
        raise CatalogError("interaction_modes must not contain duplicates")
    return tuple(sorted(normalized, key=lambda item: item.value))


@dataclass(frozen=True)
class InteroperabilityComponentDescriptor:
    """One component's exact, declared interoperability capability.

    ``domain_tags`` help callers group and present components.  The exact-match
    operation deliberately does not read them. ``supported_relations`` and
    ``mechanism_ids`` declare a Cartesian product: every listed relation and
    mechanism pair is supported. A component with a narrower capability must
    use separate descriptors rather than rely on an implicit pairing.
    """

    component_id: str
    label: str
    kind: ComponentKind
    lifecycle: ComponentLifecycle
    implementation_ref: str
    accepted_schema_ids: tuple[str, ...]
    verifier_family_ids: tuple[str, ...] = ()
    native_system: str = ""
    native_objects: tuple[str, ...] = ()
    native_versions: tuple[str, ...] = ()
    native_inputs: tuple[str, ...] = ()
    native_outputs: tuple[str, ...] = ()
    native_result_vocabulary: tuple[str, ...] = ()
    emitted_schema_ids: tuple[str, ...] = ()
    supported_relations: tuple[str, ...] = ()
    mechanism_ids: tuple[str, ...] = ()
    interaction_modes: tuple[InteractionMode, ...] = (InteractionMode.STATIC,)
    domain_tags: tuple[str, ...] = ()
    optional_dependencies: tuple[str, ...] = ()
    execution_prerequisites: tuple[str, ...] = ()
    trust_roots: tuple[str, ...] = ()
    freshness_behavior: str = ""
    transformation_loss: str = ""
    failure_behavior: str = ""
    availability: ComponentAvailability = ComponentAvailability.NOT_CHECKED
    claim_boundary: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "component_id", _nonempty(self.component_id, "component_id"))
        object.__setattr__(self, "label", _nonempty(self.label, "label"))
        object.__setattr__(
            self, "implementation_ref", _nonempty(self.implementation_ref, "implementation_ref")
        )
        try:
            object.__setattr__(self, "kind", ComponentKind(self.kind))
            object.__setattr__(self, "lifecycle", ComponentLifecycle(self.lifecycle))
            object.__setattr__(self, "availability", ComponentAvailability(self.availability))
        except (TypeError, ValueError) as exc:
            raise CatalogError(str(exc)) from exc
        object.__setattr__(
            self,
            "accepted_schema_ids",
            _unique_strings(self.accepted_schema_ids, "accepted_schema_ids"),
        )
        if not self.accepted_schema_ids:
            raise CatalogError("accepted_schema_ids must not be empty")
        object.__setattr__(
            self,
            "emitted_schema_ids",
            _unique_strings(self.emitted_schema_ids, "emitted_schema_ids"),
        )
        object.__setattr__(
            self,
            "supported_relations",
            _unique_strings(self.supported_relations, "supported_relations"),
        )
        object.__setattr__(
            self, "mechanism_ids", _unique_strings(self.mechanism_ids, "mechanism_ids")
        )
        if not self.mechanism_ids:
            raise CatalogError("a component must declare at least one mechanism identifier")
        object.__setattr__(self, "interaction_modes", _interaction_modes(self.interaction_modes))
        if not self.interaction_modes:
            raise CatalogError("interaction_modes must not be empty")
        for field_name in (
            "verifier_family_ids",
            "native_objects",
            "native_versions",
            "native_inputs",
            "native_outputs",
            "native_result_vocabulary",
            "domain_tags",
            "optional_dependencies",
            "execution_prerequisites",
            "trust_roots",
        ):
            object.__setattr__(
                self, field_name, _unique_strings(getattr(self, field_name), field_name)
            )
        for field_name in (
            "native_system",
            "freshness_behavior",
            "transformation_loss",
            "failure_behavior",
            "claim_boundary",
        ):
            if not isinstance(getattr(self, field_name), str):
                raise CatalogError(f"{field_name} must be a string")

    def matches_exact(
        self,
        *,
        schema_id: str,
        interaction_mode: InteractionMode,
        relation_id: Optional[str] = None,
        mechanism_id: Optional[str] = None,
    ) -> bool:
        """Return whether every supplied semantic coordinate matches exactly.

        At least a relation or mechanism coordinate is required.  This prevents
        the registry from treating a shared schema and interaction mode as a
        sufficient capability match. When both are supplied, they name one
        exact coordinate in the descriptor's declared relation-by-mechanism
        Cartesian product; matching either coordinate alone is insufficient.
        """

        try:
            mode = InteractionMode(interaction_mode)
        except (TypeError, ValueError):
            return False
        if relation_id is None and mechanism_id is None:
            return False
        if schema_id not in self.accepted_schema_ids or mode not in self.interaction_modes:
            return False
        if relation_id is not None and relation_id not in self.supported_relations:
            return False
        if mechanism_id is not None and mechanism_id not in self.mechanism_ids:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "label": self.label,
            "kind": self.kind.value,
            "lifecycle": self.lifecycle.value,
            "implementation_ref": self.implementation_ref,
            "accepted_schema_ids": list(self.accepted_schema_ids),
            "verifier_family_ids": list(self.verifier_family_ids),
            "native_system": self.native_system,
            "native_objects": list(self.native_objects),
            "native_versions": list(self.native_versions),
            "native_inputs": list(self.native_inputs),
            "native_outputs": list(self.native_outputs),
            "native_result_vocabulary": list(self.native_result_vocabulary),
            "emitted_schema_ids": list(self.emitted_schema_ids),
            "supported_relations": list(self.supported_relations),
            "mechanism_ids": list(self.mechanism_ids),
            "interaction_modes": [item.value for item in self.interaction_modes],
            "domain_tags": list(self.domain_tags),
            "optional_dependencies": list(self.optional_dependencies),
            "execution_prerequisites": list(self.execution_prerequisites),
            "trust_roots": list(self.trust_roots),
            "freshness_behavior": self.freshness_behavior,
            "transformation_loss": self.transformation_loss,
            "failure_behavior": self.failure_behavior,
            "availability": self.availability.value,
            "claim_boundary": self.claim_boundary,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InteroperabilityComponentDescriptor":
        if not isinstance(value, Mapping):
            raise CatalogError("component descriptor must be an object")
        expected = {
            "component_id",
            "label",
            "kind",
            "lifecycle",
            "implementation_ref",
            "accepted_schema_ids",
            "verifier_family_ids",
            "native_system",
            "native_objects",
            "native_versions",
            "native_inputs",
            "native_outputs",
            "native_result_vocabulary",
            "emitted_schema_ids",
            "supported_relations",
            "mechanism_ids",
            "interaction_modes",
            "domain_tags",
            "optional_dependencies",
            "execution_prerequisites",
            "trust_roots",
            "freshness_behavior",
            "transformation_loss",
            "failure_behavior",
            "availability",
            "claim_boundary",
        }
        actual = set(value)
        if actual != expected:
            raise CatalogError(
                "component descriptor keys mismatch; "
                f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
            )
        return cls(
            component_id=value["component_id"],
            label=value["label"],
            kind=value["kind"],
            lifecycle=value["lifecycle"],
            implementation_ref=value["implementation_ref"],
            accepted_schema_ids=value["accepted_schema_ids"],
            verifier_family_ids=value["verifier_family_ids"],
            native_system=value["native_system"],
            native_objects=value["native_objects"],
            native_versions=value["native_versions"],
            native_inputs=value["native_inputs"],
            native_outputs=value["native_outputs"],
            native_result_vocabulary=value["native_result_vocabulary"],
            emitted_schema_ids=value["emitted_schema_ids"],
            supported_relations=value["supported_relations"],
            mechanism_ids=value["mechanism_ids"],
            interaction_modes=value["interaction_modes"],
            domain_tags=value["domain_tags"],
            optional_dependencies=value["optional_dependencies"],
            execution_prerequisites=value["execution_prerequisites"],
            trust_roots=value["trust_roots"],
            freshness_behavior=value["freshness_behavior"],
            transformation_loss=value["transformation_loss"],
            failure_behavior=value["failure_behavior"],
            availability=value["availability"],
            claim_boundary=value["claim_boundary"],
        )


@dataclass(frozen=True)
class InteroperabilityComponentRegistry:
    """Immutable, deterministically ordered component catalog."""

    registry_version: str
    components: tuple[InteroperabilityComponentDescriptor, ...]
    schema_version: str = CATALOG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "registry_version", _nonempty(self.registry_version, "registry_version")
        )
        if self.schema_version != CATALOG_SCHEMA_VERSION:
            raise CatalogError(f"schema_version must be {CATALOG_SCHEMA_VERSION!r}")
        if not isinstance(self.components, (tuple, list)):
            raise CatalogError("components must be an array of component descriptors")
        components = tuple(self.components)
        if not all(isinstance(item, InteroperabilityComponentDescriptor) for item in components):
            raise CatalogError("components must contain component descriptors")
        identifiers = [item.component_id for item in components]
        if len(set(identifiers)) != len(identifiers):
            duplicates = sorted(
                identifier for identifier in set(identifiers) if identifiers.count(identifier) > 1
            )
            raise CatalogError(f"duplicate component identifiers: {', '.join(duplicates)}")
        object.__setattr__(
            self, "components", tuple(sorted(components, key=lambda item: item.component_id))
        )

    def list(self) -> tuple[InteroperabilityComponentDescriptor, ...]:
        return self.components

    def get(self, component_id: str) -> InteroperabilityComponentDescriptor:
        component_id = _nonempty(component_id, "component_id")
        for component in self.components:
            if component.component_id == component_id:
                return component
        raise CatalogError(f"unknown interoperability component {component_id!r}")

    def match_exact(
        self,
        *,
        schema_id: str,
        interaction_mode: InteractionMode,
        relation_id: Optional[str] = None,
        mechanism_id: Optional[str] = None,
    ) -> tuple[InteroperabilityComponentDescriptor, ...]:
        """Return every exact match in stable component-identifier order."""

        return tuple(
            component
            for component in self.components
            if component.matches_exact(
                schema_id=schema_id,
                interaction_mode=interaction_mode,
                relation_id=relation_id,
                mechanism_id=mechanism_id,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "registry_version": self.registry_version,
            "components": [component.to_dict() for component in self.components],
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

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InteroperabilityComponentRegistry":
        if not isinstance(value, Mapping):
            raise CatalogError("component registry must be an object")
        expected = {"schema_version", "registry_version", "components"}
        actual = set(value)
        if actual != expected:
            raise CatalogError(
                "component registry keys mismatch; "
                f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
            )
        components = value["components"]
        if not isinstance(components, list) or not all(
            isinstance(item, Mapping) for item in components
        ):
            raise CatalogError("components must be an array of objects")
        return cls(
            schema_version=value["schema_version"],
            registry_version=value["registry_version"],
            components=tuple(
                InteroperabilityComponentDescriptor.from_dict(item) for item in components
            ),
        )


# ``InteroperabilityCatalog`` is the presentation name used by the release plan;
# both names identify the same immutable registry contract.
InteroperabilityCatalog = InteroperabilityComponentRegistry


__all__ = [
    "CATALOG_SCHEMA_VERSION",
    "CatalogError",
    "ComponentAvailability",
    "ComponentKind",
    "ComponentLifecycle",
    "InteractionMode",
    "InteroperabilityCatalog",
    "InteroperabilityComponentDescriptor",
    "InteroperabilityComponentRegistry",
]
