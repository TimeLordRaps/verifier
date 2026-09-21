"""Terminology: Verifier Standard (VSTD).

The Graph axis carries its own grounding coordinates, disjoint from the object axis.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verifier.core.profile_obligations import (
    BY_ID,
    GRAPH_BY_ID,
    GRAPH_OBLIGATIONS,
    GRAPH_PROFILE_NAMES,
    catalog_digest,
    graph_catalog_digest,
    graph_obligation_catalog,
    graph_specification_digest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_every_graph_profile_has_contiguous_obligations() -> None:
    assert {o.profile for o in GRAPH_OBLIGATIONS} == {1, 2, 3, 4, 5}
    for profile in range(1, 6):
        rows = [o for o in GRAPH_OBLIGATIONS if o.profile == profile]
        assert [o.index for o in rows] == list(range(1, len(rows) + 1))
        assert rows[0].depends_on == ()
    assert graph_obligation_catalog()["schema_version"] == "VSTD-GRAPH-OBLIGATIONS-1"
    assert graph_obligation_catalog()["axis"] == "GRAPH"
    assert set(GRAPH_BY_ID) == {o.id for o in GRAPH_OBLIGATIONS}


def test_dependencies_stay_inside_their_profile_and_cannot_cycle() -> None:
    for obligation in GRAPH_OBLIGATIONS:
        for dependency in obligation.depends_on:
            assert dependency in GRAPH_BY_ID, (obligation.id, dependency)
            earlier = GRAPH_BY_ID[dependency]
            assert earlier.profile == obligation.profile
            assert earlier.index < obligation.index, (obligation.id, dependency)


def test_graph_and_object_coordinates_never_alias() -> None:
    assert not set(GRAPH_BY_ID) & set(BY_ID)
    assert not {o.predicate for o in GRAPH_OBLIGATIONS} & {o.predicate for o in BY_ID.values()}
    for obligation in GRAPH_OBLIGATIONS:
        assert obligation.id.startswith("Graph-")
        assert obligation.predicate.startswith("vstd.graph.obligation.")


def test_extending_the_graph_axis_does_not_move_the_object_catalogue() -> None:
    assert catalog_digest() != graph_catalog_digest()
    assert graph_catalog_digest() == graph_catalog_digest()


def test_every_numbered_graph_layer_names_its_obligation_coordinates() -> None:
    for profile in range(1, 6):
        count = len([o for o in GRAPH_OBLIGATIONS if o.profile == profile])
        text = (REPO_ROOT / f"src/verifier/specifications/VSTD-Graph-{profile}.md").read_text(encoding="utf-8")
        assert "## Grounded certification obligation coordinates" in text, profile
        assert f"`Graph-{profile}.1` through `Graph-{profile}.{count}`" in text, profile


def test_normative_graph_catalogue_and_runtime_rows_agree() -> None:
    text = (REPO_ROOT / "src/verifier/specifications/GRAPH_GROUNDING.md").read_text(encoding="utf-8")
    for obligation in GRAPH_OBLIGATIONS:
        dependencies = ", ".join(obligation.depends_on) or "none"
        row = (f"| {obligation.id} | {obligation.name} | {obligation.requirement} "
               f"| {dependencies} | {obligation.source} |")
        assert row in text, obligation.id
    for profile, name in GRAPH_PROFILE_NAMES.items():
        assert f"### VSTD-Graph-{profile}: {name}" in text


def test_graph_specification_digest_pins_the_graph_bytes_only() -> None:
    first = graph_specification_digest()
    assert first == graph_specification_digest()
    assert len(first) == 64


@pytest.mark.parametrize("profile", range(1, 6))
def test_no_graph_profile_is_empty(profile: int) -> None:
    assert [o for o in GRAPH_OBLIGATIONS if o.profile == profile]
