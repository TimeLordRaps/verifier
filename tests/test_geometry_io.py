"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Strict VSTD-2 verification-geometry loading tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier.core.geometry_io import GeometryLoadError, load_verification_geometry


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "verification_geometry_residual" / "geometry.json"


def _example_payload() -> dict[str, object]:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def test_loads_complete_example_without_wire_loss() -> None:
    payload = _example_payload()

    geometry = load_verification_geometry(EXAMPLE)

    assert geometry.to_dict() == payload
    assert geometry.validate() == []
    assert geometry.canonical_digest() == load_verification_geometry(payload).canonical_digest()


def test_optional_root_collections_default_only_when_omitted() -> None:
    payload = _example_payload()
    for field_name in (
        "secondary_subject_id",
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
    ):
        payload.pop(field_name, None)
    payload["surface"]["seam_ids"] = []  # type: ignore[index]

    geometry = load_verification_geometry(payload)

    assert geometry.secondary_subject_id is None
    assert geometry.seams == []
    assert geometry.focus_coordinate_ids == ()


def test_schema_integral_number_is_normalized_to_python_integer() -> None:
    payload = _example_payload()
    payload["verification_layers"][0]["order"] = 0.0  # type: ignore[index]

    geometry = load_verification_geometry(payload)

    assert geometry.verification_layers[0].order == 0
    assert type(geometry.verification_layers[0].order) is int


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda payload: payload.__setitem__("unexpected", True), "unexpected fields"),
        (lambda payload: payload.pop("surface"), "missing required fields"),
        (
            lambda payload: payload["coordinates"][0].__setitem__("unexpected", True),
            "unexpected fields",
        ),
        (
            lambda payload: payload["coordinates"][0].pop("facet_id"),
            "missing required fields",
        ),
        (
            lambda payload: payload.__setitem__("schema_version", "VSTD-1"),
            "schema_version",
        ),
        (
            lambda payload: payload["loci"][0].__setitem__("kind", "NOT_A_LOCUS"),
            "unsupported value",
        ),
        (
            lambda payload: payload["valences"][0].__setitem__("source_kind", []),
            "unsupported value",
        ),
        (
            lambda payload: payload["focus_coordinate_ids"].append(
                payload["focus_coordinate_ids"][0]
            ),
            "duplicate identifiers",
        ),
        (
            lambda payload: payload["mechanisms"][0].__setitem__("post_verified", 1),
            "must be a boolean",
        ),
        (
            lambda payload: payload["verification_layers"][0].__setitem__("order", True),
            "must be a non-negative integer",
        ),
        (
            lambda payload: payload["coordinates"][0].__setitem__(
                "locus_id", "locus:missing"
            ),
            "structurally invalid",
        ),
    ),
)
def test_rejects_wire_and_semantic_substitutions(mutation, message: str) -> None:
    payload = _example_payload()
    mutation(payload)

    with pytest.raises(GeometryLoadError, match=message):
        load_verification_geometry(payload)


def test_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    geometry_path = tmp_path / "geometry.json"
    geometry_path.write_text(
        '{"schema_version":"VSTD-2","schema_version":"VSTD-2"}',
        encoding="utf-8",
    )

    with pytest.raises(GeometryLoadError, match="duplicate object key"):
        load_verification_geometry(geometry_path)


def test_rejects_nonfinite_json_number(tmp_path: Path) -> None:
    geometry_path = tmp_path / "geometry.json"
    geometry_path.write_text('{"schema_version":"VSTD-2","x":NaN}', encoding="utf-8")

    with pytest.raises(GeometryLoadError, match="non-finite number"):
        load_verification_geometry(geometry_path)


def test_rejects_invalid_utf8(tmp_path: Path) -> None:
    geometry_path = tmp_path / "geometry.json"
    geometry_path.write_bytes(b"\xff")

    with pytest.raises(GeometryLoadError, match="not readable strict JSON"):
        load_verification_geometry(geometry_path)


def test_rejects_unreadable_non_file_path(tmp_path: Path) -> None:
    with pytest.raises(GeometryLoadError, match="not readable strict JSON"):
        load_verification_geometry(tmp_path)


def test_extreme_layer_order_fails_without_allocating_proportional_range() -> None:
    payload = _example_payload()
    payload["verification_layers"][0]["order"] = 10**100  # type: ignore[index]

    with pytest.raises(GeometryLoadError, match="contiguous and start at 0"):
        load_verification_geometry(payload)


def test_rejects_non_string_mapping_keys_as_geometry_errors() -> None:
    payload = _example_payload()
    payload[1] = "not a JSON object key"  # type: ignore[index]

    with pytest.raises(GeometryLoadError, match="object keys must be strings"):
        load_verification_geometry(payload)
