"""Every numeral META_TIERS.md publishes about the grid must be measurable.

The grid's size, depth and reachability figures were typed into the specification.
This module re-derives each one from the catalogued dependencies, so a numeral that
stops being true turns the suite red instead of standing as prose.
"""

from __future__ import annotations

import re
from math import prod
from pathlib import Path

import pytest

from verifier.core.profile_obligations import (
    DOMAIN_OBJECTS,
    DOMAIN_OBLIGATIONS,
    GRAPH_OBLIGATIONS,
    OBLIGATIONS,
    UNGROUNDED_OBJECTS,
    tier_depth,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
META = (REPO_ROOT / "src/verifier/specifications/META_TIERS.md").read_text(encoding="utf-8")

# The two specification axes carry no catalogued dependencies of their own, so their
# depths are read back out of the published ladder strip rather than computed.
_STRIP = re.compile(r"\[(\d)\.1[–-](\d)\.(\d+)\]")


def _strip_depths(stem: str) -> tuple[int, ...]:
    line = next(line for line in META.splitlines() if line.startswith(f"| `{stem}` "))
    return tuple(int(end) for _, _, end in _STRIP.findall(line))


SPEC_AXES = {"VSTD": _strip_depths("VSTD-"), "GRAPH": _strip_depths("VSTD-Graph-")}
DOMAIN_DEPTHS = {o: tuple(tier_depth(o, t) for t in range(1, 6)) for o in DOMAIN_OBJECTS}
ALL_DEPTHS = {**SPEC_AXES, **DOMAIN_DEPTHS}


def _published(pattern: str) -> int:
    found = re.search(pattern, META)
    assert found, pattern
    return int(found.group(1).replace(",", ""))


@pytest.mark.parametrize("object_name", sorted(DOMAIN_OBJECTS))
def test_the_ladder_strip_depth_matches_tier_depth(object_name: str) -> None:
    """The published climb of each domain object is its measured topological depth."""
    assert _strip_depths(f"VSTD-{object_name}-") == DOMAIN_DEPTHS[object_name]


def test_every_object_carries_five_profiles() -> None:
    assert all(len(d) == 5 for d in ALL_DEPTHS.values())
    assert len(ALL_DEPTHS) == 13
    assert len(ALL_DEPTHS) * 5 == 65


def test_the_published_rung_total_is_the_sum_of_the_depths() -> None:
    rungs = sum(sum(d) for d in ALL_DEPTHS.values())
    assert rungs == _published(r"([\d,]+) rungs over sixty-five profiles")
    assert rungs == _published(r"([\d,]+) rungs across the thirteen ladders")


def test_the_published_obligation_total_is_the_sum_of_the_catalogues() -> None:
    total = len(DOMAIN_OBLIGATIONS) + len(GRAPH_OBLIGATIONS) + len(OBLIGATIONS)
    assert total == _published(r"([\d,]+) obligations across the three")


def test_unreachable_coordinates_are_the_total_less_the_rungs() -> None:
    total = len(DOMAIN_OBLIGATIONS) + len(GRAPH_OBLIGATIONS) + len(OBLIGATIONS)
    rungs = sum(sum(d) for d in ALL_DEPTHS.values())
    published = _published(r"The remaining ([\d,]+) of [\d,]+ catalogued")
    assert published == total - rungs


def test_the_free_product_is_the_product_of_every_depth() -> None:
    """`prod(i, 13 x 5)` is a product of depths, never of obligation counts."""
    free = prod(d for depths in ALL_DEPTHS.values() for d in depths)
    assert free == _published(r"prod\(i, 13 x 5\) = ([\d,]+)")
    assert free == _published(r"free product over 65 cells\s+([\d,]+)")
    counts = prod(len([o for o in DOMAIN_OBLIGATIONS
                       if o.object_name == name and o.profile == tier])
                  for name in DOMAIN_OBJECTS for tier in range(1, 6))
    assert free != counts, "a depth is not a count"


def test_the_cumulative_product_is_one_plus_each_ladder() -> None:
    """An object's reachable positions are `1 + sum(i)`: one scalar, not five."""
    cumulative = prod(1 + sum(d) for d in ALL_DEPTHS.values())
    assert cumulative == _published(r"cumulative profiles, per object\s+([\d,]+)")


def test_an_unconstrained_ladder_multiplies_the_reachable_counts() -> None:
    """OWNER composes nothing, so it scales the two lattice figures by its own ladder."""
    positive = _published(r"\+ composition, operands positive\s+([\d,]+)")
    complete = _published(r"\+ composition, operands complete\s+([\d,]+)")
    factor = 1 + sum(DOMAIN_DEPTHS["OWNER"])
    assert _published(r"by its own (\d+)\nreachable positions") == factor
    assert _published(r"the free product by prod\(i\) = (\d+)") == prod(DOMAIN_DEPTHS["OWNER"])
    assert positive % factor == 0 and complete % factor == 0
    assert complete < positive, "the tighter gate must admit fewer states"
    free = prod(d for depths in ALL_DEPTHS.values() for d in depths)
    assert free // complete == _published(r"around one in\n([\d,]+) of the free product")


def test_the_ungrounded_object_is_marked_in_every_published_table() -> None:
    """A row with no adapter anywhere must be visibly distinguished from one with."""
    for name in UNGROUNDED_OBJECTS:
        rows = [line for line in META.splitlines()
                if line.startswith(f"| {name} ") or line.startswith(f"| `VSTD-{name}-` ")]
        assert len(rows) == 3, (name, len(rows))
        assert all("‡" in row for row in rows), name
