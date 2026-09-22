"""Every numeral the Verifier Standard (VSTD) meta-tier grid publishes must be measurable.

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
    CORROBORATION_TIERS,
    DISCLOSURE_TIER,
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


SPEC_AXES = {"VSTD": _strip_depths("VSTD-"), "GRAPH": _strip_depths("GRAPH-")}
DOMAIN_DEPTHS = {o: tuple(tier_depth(o, t) for t in range(1, 6)) for o in DOMAIN_OBJECTS}
ALL_DEPTHS = {**SPEC_AXES, **DOMAIN_DEPTHS}


def _published(pattern: str) -> int:
    found = re.search(pattern, META)
    assert found, pattern
    return int(found.group(1).replace(",", ""))


def _corroboration_total() -> int:
    """Tiers 1-5 across all three namespaces: the obligations the ladders are built from."""
    domain = [o for o in DOMAIN_OBLIGATIONS if o.profile in CORROBORATION_TIERS]
    return len(domain) + len(GRAPH_OBLIGATIONS) + len(OBLIGATIONS)


def test_the_disclosure_level_is_excluded_from_every_lattice_figure() -> None:
    """Level 6 cannot move a verdict, so counting it as a rung would inflate every figure.

    This is the arithmetic half of `<object>-6.6`. The grand total the file publishes is
    the corroboration total plus the disclosure rows, and no lattice figure sees the
    second term.
    """
    disclosure = [o for o in DOMAIN_OBLIGATIONS if o.profile == DISCLOSURE_TIER]
    assert disclosure, "the level is meant to be inhabited"
    assert len(disclosure) == 6 * len(DOMAIN_OBJECTS)

    grand = len(DOMAIN_OBLIGATIONS) + len(GRAPH_OBLIGATIONS) + len(OBLIGATIONS)
    assert _corroboration_total() + len(disclosure) == grand
    assert grand == _published(r"([\d,]+) obligations across the three")

    # Every depth the lattice is built from is a corroboration depth.
    assert all(len(d) == len(CORROBORATION_TIERS) for d in ALL_DEPTHS.values())
    rungs = sum(sum(d) for d in ALL_DEPTHS.values())
    assert rungs == sum(tier_depth(o, t)
                        for o in DOMAIN_OBJECTS for t in CORROBORATION_TIERS) + sum(
        sum(d) for d in SPEC_AXES.values())


@pytest.mark.parametrize("object_name", sorted(DOMAIN_OBJECTS))
def test_the_ladder_strip_depth_matches_tier_depth(object_name: str) -> None:
    """The published climb of each domain object is its measured topological depth."""
    assert _strip_depths(f"{object_name}-") == DOMAIN_DEPTHS[object_name]


def test_every_object_carries_five_corroboration_profiles() -> None:
    assert all(len(d) == 5 for d in ALL_DEPTHS.values())
    assert len(ALL_DEPTHS) == 18
    assert len(ALL_DEPTHS) * 5 == 90


def test_the_published_rung_total_is_the_sum_of_the_depths() -> None:
    rungs = sum(sum(d) for d in ALL_DEPTHS.values())
    assert rungs == _published(r"([\d,]+) rungs over ninety profiles")
    assert rungs == _published(r"([\d,]+) rungs across the eighteen ladders")


def test_the_published_obligation_total_is_the_sum_of_the_catalogues() -> None:
    total = len(DOMAIN_OBLIGATIONS) + len(GRAPH_OBLIGATIONS) + len(OBLIGATIONS)
    assert total == _published(r"([\d,]+) obligations across the three")


def test_unreachable_coordinates_are_the_total_less_the_rungs() -> None:
    """Unreachable-as-an-`m` is a statement about rungs, so it is scoped to tiers 1-5.

    Level 6 carries no rungs at all, by construction rather than by shortfall, so folding
    it into this figure would silently restate "not a rung" as "not yet reached".
    """
    corroboration = _corroboration_total()
    rungs = sum(sum(d) for d in ALL_DEPTHS.values())
    published = _published(r"The remaining ([\d,]+) of ([\d,]+) catalogued")
    assert published == corroboration - rungs
    assert _published(r"The remaining [\d,]+ of ([\d,]+) catalogued") == corroboration


def test_the_free_product_is_the_product_of_every_depth() -> None:
    """`prod(i, 18 x 5)` is a product of depths, never of obligation counts."""
    free = prod(d for depths in ALL_DEPTHS.values() for d in depths)
    assert free == _published(r"prod\(i, 18 x 5\) = ([\d,]+)")
    assert free == _published(r"free product over 90 cells\s+([\d,]+)")
    counts = prod(len([o for o in DOMAIN_OBLIGATIONS
                       if o.object_name == name and o.profile == tier])
                  for name in DOMAIN_OBJECTS for tier in range(1, 6))
    assert free != counts, "a depth is not a count"


def test_the_cumulative_product_is_one_plus_each_ladder() -> None:
    """An object's reachable positions are `1 + sum(i)`: one scalar, not five."""
    cumulative = prod(1 + sum(d) for d in ALL_DEPTHS.values())
    assert cumulative == _published(r"cumulative profiles, per object\s+([\d,]+)")


def test_only_the_composition_operator_escapes_the_lattice() -> None:
    """HYPER is the last unconstrained ladder; OWNER stopped being one.

    OWNER-1.1 binds a ACTOR certificate, so OWNER sits on a composition edge and its
    own reachable positions no longer multiply through. The previous version of this guard
    asserted that they did, which is why it is inverted here rather than deleted: a ladder
    that escapes the lattice INFLATES a reachable count, so a passing divisibility check
    would have been evidence of the defect, not of correctness.
    """
    positive = _published(r"\+ composition, operands positive\s+([\d,]+)")
    complete = _published(r"\+ composition, operands complete\s+([\d,]+)")
    factor = 1 + sum(DOMAIN_DEPTHS["OWNER"])
    assert not (positive % factor == 0 and complete % factor == 0), (
        "OWNER still factors out of both gated figures, so its edge is not being applied"
    )
    assert complete < positive, "the tighter gate must admit fewer states"
    free = prod(d for depths in ALL_DEPTHS.values() for d in depths)
    assert free // complete == _published(r"around one in\n([\d,]+) of the free product")
    # The prose must name the one escape and must no longer claim OWNER is another.
    assert "`HYPER` is the only ladder the lattice leaves unconstrained" in META
    assert "`OWNER` composes nothing and is composed of nothing" not in META


def test_the_ungrounded_object_is_marked_in_every_published_table() -> None:
    """A row with no adapter anywhere must be visibly distinguished from one with."""
    for name in UNGROUNDED_OBJECTS:
        rows = [line for line in META.splitlines()
                if line.startswith(f"| {name} ") or line.startswith(f"| `{name}-` ")]
        assert len(rows) == 3, (name, len(rows))
        assert all("‡" in row for row in rows), name
