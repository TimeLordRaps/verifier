"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Strict loading for the VSTD-2 verification-geometry wire representation.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
from pathlib import Path
from typing import Any, Mapping

from verifier.core.geometry import (
    Coordinate,
    CoordinateJudgment,
    CoordinateStatus,
    Facet,
    GEOMETRY_SCHEMA_VERSION,
    Grain,
    Horizon,
    HorizonKind,
    Locus,
    LocusKind,
    Novelty,
    NoveltyKind,
    ReconstructionAttempt,
    Residual,
    ResidualDisposition,
    ResidualType,
    Seam,
    Stratum,
    Subject,
    ValenceStatus,
    VerificationGeometry,
    VerificationLayer,
    VerificationMechanism,
    VerificationSurface,
    VerificationValence,
)
from verifier.core.receipt import StrictJsonError, strict_json_loads


class GeometryLoadError(ValueError):
    """Raised when VSTD-2 wire bytes cannot produce one valid typed geometry."""


@dataclass(frozen=True)
class _RecordSpec:
    record_type: type[Any]
    nonempty: frozenset[str] = frozenset()
    optional_strings: frozenset[str] = frozenset()
    identifier_arrays: frozenset[str] = frozenset()
    string_arrays: frozenset[str] = frozenset()
    boolean_fields: frozenset[str] = frozenset()
    integer_fields: frozenset[str] = frozenset()
    enum_fields: tuple[tuple[str, type[Any]], ...] = ()
    literal_fields: tuple[tuple[str, frozenset[str]], ...] = ()


_RECORD_SPECS: dict[str, _RecordSpec] = {
    "subjects": _RecordSpec(
        Subject,
        frozenset(("subject_id", "label", "version")),
        optional_strings=frozenset(("parent_subject_id",)),
    ),
    "loci": _RecordSpec(
        Locus,
        frozenset(("locus_id", "subject_id", "label", "address")),
        optional_strings=frozenset(("parent_locus_id",)),
        enum_fields=(("kind", LocusKind), ("grain", Grain), ("stratum", Stratum)),
    ),
    "facets": _RecordSpec(Facet, frozenset(("facet_id", "label"))),
    "coordinates": _RecordSpec(
        Coordinate, frozenset(("coordinate_id", "locus_id", "facet_id"))
    ),
    "seams": _RecordSpec(
        Seam,
        frozenset(
            ("seam_id", "label", "source_locus_id", "target_locus_id", "relation")
        ),
    ),
    "mechanisms": _RecordSpec(
        VerificationMechanism,
        frozenset(("mechanism_id", "label", "version")),
        optional_strings=frozenset(("boundary_horizon_id",)),
        identifier_arrays=frozenset(("post_verification_evidence_ids",)),
        boolean_fields=frozenset(("post_verified",)),
    ),
    "judgments": _RecordSpec(
        CoordinateJudgment,
        frozenset(("coordinate_id",)),
        identifier_arrays=frozenset(("mechanism_ids", "evidence_ids")),
        string_arrays=frozenset(("assumptions", "limitations")),
        enum_fields=(("status", CoordinateStatus),),
    ),
    "horizons": _RecordSpec(
        Horizon,
        frozenset(("horizon_id", "description")),
        optional_strings=frozenset(("locus_id", "coordinate_id", "seam_id")),
        enum_fields=(("kind", HorizonKind),),
    ),
    "residuals": _RecordSpec(
        Residual,
        frozenset(("residual_id", "description")),
        optional_strings=frozenset(
            ("locus_id", "coordinate_id", "seam_id", "horizon_id")
        ),
        boolean_fields=frozenset(("material",)),
        enum_fields=(
            ("residual_type", ResidualType),
            ("disposition", ResidualDisposition),
        ),
    ),
    "valences": _RecordSpec(
        VerificationValence,
        frozenset(
            ("valence_id", "source_id", "required_relation", "description")
        ),
        optional_strings=frozenset(("horizon_id",)),
        identifier_arrays=frozenset(("evidence_ids",)),
        enum_fields=(("status", ValenceStatus),),
        literal_fields=(
            (
                "source_kind",
                frozenset(("LOCUS", "COORDINATE", "SEAM", "SURFACE", "GEOMETRY")),
            ),
        ),
    ),
    "reconstructions": _RecordSpec(
        ReconstructionAttempt,
        frozenset(
            (
                "reconstruction_id",
                "subject_id",
                "method",
                "observed_ref",
                "reconstructed_ref",
            )
        ),
        identifier_arrays=frozenset(("residual_ids",)),
    ),
    "verification_layers": _RecordSpec(
        VerificationLayer,
        frozenset(("layer_id", "subject_id")),
        optional_strings=frozenset(("verifies_layer_id", "horizon_id")),
        identifier_arrays=frozenset(
            ("coordinate_ids", "mechanism_ids", "evidence_ids")
        ),
        integer_fields=frozenset(("order",)),
    ),
    "novelties": _RecordSpec(
        Novelty,
        frozenset(("novelty_id", "residual_id", "description")),
        enum_fields=(("kind", NoveltyKind),),
    ),
}

_SURFACE_SPEC = _RecordSpec(
    VerificationSurface,
    frozenset(("surface_id", "subject_id")),
    identifier_arrays=frozenset(("coordinate_ids", "seam_ids")),
)

_ROOT_FIELDS = frozenset(
    (
        "schema_version",
        "geometry_id",
        "primary_subject_id",
        "secondary_subject_id",
        "subjects",
        "loci",
        "facets",
        "coordinates",
        "surface",
        "seams",
        "mechanisms",
        "judgments",
        "horizons",
        "residuals",
        "valences",
        "reconstructions",
        "verification_layers",
        "novelties",
        "focus_coordinate_ids",
        "meta_focus_coordinate_ids",
    )
)
_ROOT_REQUIRED = frozenset(
    (
        "schema_version",
        "geometry_id",
        "primary_subject_id",
        "subjects",
        "loci",
        "facets",
        "coordinates",
        "surface",
    )
)


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GeometryLoadError(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise GeometryLoadError(f"{label} object keys must be strings")
    return value


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise GeometryLoadError(f"{label} missing required fields: {', '.join(missing)}")
    if unexpected:
        raise GeometryLoadError(f"{label} has unexpected fields: {', '.join(unexpected)}")


def _string(value: object, label: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        raise GeometryLoadError(f"{label} must be a string")
    if nonempty and not value:
        raise GeometryLoadError(f"{label} must be a non-empty string")
    return value


def _string_array(
    value: object, label: str, *, identifiers: bool
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise GeometryLoadError(f"{label} must be an array")
    result = tuple(
        _string(item, f"{label}[{index}]", nonempty=identifiers)
        for index, item in enumerate(value)
    )
    if identifiers and len(set(result)) != len(result):
        raise GeometryLoadError(f"{label} must not contain duplicate identifiers")
    return result


def _record(value: object, label: str, spec: _RecordSpec) -> Any:
    raw = _object(value, label)
    expected = {item.name for item in fields(spec.record_type)}
    _exact_fields(raw, expected, label)
    enum_fields = dict(spec.enum_fields)
    literal_fields = dict(spec.literal_fields)
    kwargs: dict[str, Any] = {}
    for name in expected:
        item_label = f"{label}.{name}"
        item = raw[name]
        if name in enum_fields:
            try:
                kwargs[name] = enum_fields[name](item)
            except (TypeError, ValueError) as exc:
                raise GeometryLoadError(f"{item_label} has an unsupported value") from exc
        elif name in literal_fields:
            if not isinstance(item, str) or item not in literal_fields[name]:
                raise GeometryLoadError(f"{item_label} has an unsupported value")
            kwargs[name] = item
        elif name in spec.optional_strings:
            kwargs[name] = (
                None if item is None else _string(item, item_label)
            )
        elif name in spec.identifier_arrays:
            kwargs[name] = _string_array(item, item_label, identifiers=True)
        elif name in spec.string_arrays:
            kwargs[name] = _string_array(item, item_label, identifiers=False)
        elif name in spec.boolean_fields:
            if type(item) is not bool:
                raise GeometryLoadError(f"{item_label} must be a boolean")
            kwargs[name] = item
        elif name in spec.integer_fields:
            is_integer = type(item) is int or (
                type(item) is float and item.is_integer()
            )
            if not is_integer or item < 0:
                raise GeometryLoadError(f"{item_label} must be a non-negative integer")
            # JSON Schema treats integral numbers such as 0.0 as integers.
            kwargs[name] = int(item)
        else:
            kwargs[name] = _string(item, item_label, nonempty=name in spec.nonempty)
    return spec.record_type(**kwargs)


def _decode_geometry(payload: object) -> VerificationGeometry:
    raw = _object(payload, "geometry")
    missing = sorted(_ROOT_REQUIRED - set(raw))
    unexpected = sorted(set(raw) - _ROOT_FIELDS)
    if missing:
        raise GeometryLoadError(
            "geometry missing required fields: " + ", ".join(missing)
        )
    if unexpected:
        raise GeometryLoadError(
            "geometry has unexpected fields: " + ", ".join(unexpected)
        )
    if raw["schema_version"] != GEOMETRY_SCHEMA_VERSION:
        raise GeometryLoadError(
            f"schema_version must be {GEOMETRY_SCHEMA_VERSION!r}"
        )
    kwargs: dict[str, Any] = {
        "schema_version": GEOMETRY_SCHEMA_VERSION,
        "geometry_id": _string(raw["geometry_id"], "geometry.geometry_id", nonempty=True),
        "primary_subject_id": _string(
            raw["primary_subject_id"], "geometry.primary_subject_id", nonempty=True
        ),
        "secondary_subject_id": None,
        "surface": _record(raw["surface"], "geometry.surface", _SURFACE_SPEC),
        "focus_coordinate_ids": _string_array(
            raw.get("focus_coordinate_ids", []),
            "geometry.focus_coordinate_ids",
            identifiers=True,
        ),
        "meta_focus_coordinate_ids": _string_array(
            raw.get("meta_focus_coordinate_ids", []),
            "geometry.meta_focus_coordinate_ids",
            identifiers=True,
        ),
    }
    if "secondary_subject_id" in raw:
        secondary = raw["secondary_subject_id"]
        kwargs["secondary_subject_id"] = (
            None
            if secondary is None
            else _string(secondary, "geometry.secondary_subject_id")
        )
    for name, spec in _RECORD_SPECS.items():
        collection = raw.get(name, [])
        if not isinstance(collection, list):
            raise GeometryLoadError(f"geometry.{name} must be an array")
        kwargs[name] = [
            _record(item, f"geometry.{name}[{index}]", spec)
            for index, item in enumerate(collection)
        ]
    geometry = VerificationGeometry(**kwargs)
    errors = geometry.validate()
    if errors:
        raise GeometryLoadError(
            "verification geometry is structurally invalid: " + "; ".join(errors)
        )
    return geometry


def load_verification_geometry(
    source: str | Path | Mapping[str, Any],
) -> VerificationGeometry:
    """Strictly load one valid VSTD-2 geometry from a path or parsed mapping."""

    if isinstance(source, Mapping):
        return _decode_geometry(source)
    path = Path(source)
    try:
        payload = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJsonError) as exc:
        raise GeometryLoadError(f"geometry is not readable strict JSON: {exc}") from exc
    return _decode_geometry(payload)
