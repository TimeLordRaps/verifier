"""Every numeral the Verifier Standard (VSTD) meta-tier grid publishes must be measurable.

The grid's size, depth and reachability figures were typed into the specification.
This module re-derives each one from the catalogued dependencies, so a numeral that
stops being true turns the suite red instead of standing as prose.
"""

from __future__ import annotations

import importlib.util
import re
from collections import Counter
from math import prod
from pathlib import Path

import pytest

from verifier.core.profile_obligations import (
    CERTIFIABLE_OBJECTS,
    CORROBORATION_TIERS,
    DISCLOSURE_TIER,
    DOMAIN_OBJECTS,
    DOMAIN_OBLIGATIONS,
    GRAPH_OBLIGATIONS,
    GROUNDED_OBJECTS,
    OBLIGATIONS,
    OPERATOR_OBJECTS,
    UNGROUNDED_OBJECTS,
    tier_depth,
)
from verifier.domains.catalog import CHECKS
from verifier.domains.mainstays import PREFIX as MAINSTAY_PREFIX
from verifier.domains.statics import PREFIX as STATICS_PREFIX

REPO_ROOT = Path(__file__).resolve().parents[1]
META = (REPO_ROOT / "src/verifier/standard/META_TIERS.md").read_text(encoding="utf-8")
# Prose wraps wherever the line runs out, so sentences are matched with whitespace folded.
FLAT = " ".join(META.split())


def _number_words() -> dict[str, int]:
    """The pull-request gate's vocabulary, so the spec and the description read numbers alike."""
    spec = importlib.util.spec_from_file_location(
        "check_pr_description", REPO_ROOT / "scripts" / "check_pr_description.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return {word: value for value, word in module.NUMBER_WORDS.items()}


NUMBER_WORDS = _number_words()

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
    assert len(ALL_DEPTHS) == 19
    assert len(ALL_DEPTHS) * 5 == 95


def test_the_published_rung_total_is_the_sum_of_the_depths() -> None:
    rungs = sum(sum(d) for d in ALL_DEPTHS.values())
    assert rungs == _published(r"([\d,]+) rungs over ninety-five profiles")
    assert rungs == _published(r"([\d,]+) rungs across the nineteen ladders")


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
    """`prod(i, 19 x 5)` is a product of depths, never of obligation counts."""
    free = prod(d for depths in ALL_DEPTHS.values() for d in depths)
    ladders = len(ALL_DEPTHS)
    assert free == _published(rf"prod\(i, {ladders} x 5\) = ([\d,]+)")
    assert free == _published(rf"free product over {ladders * 5} cells\s+([\d,]+)")
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


def _count(token: str) -> int:
    return int(token.replace(",", "")) if token[0].isdigit() else NUMBER_WORDS[token.lower()]


def _stated(pattern: str) -> tuple[int, ...]:
    found = re.search(pattern, FLAT)
    assert found, pattern
    return tuple(_count(group) for group in found.groups())


def _family(obligation) -> str:
    if obligation.mechanism.startswith(STATICS_PREFIX):
        return "statics"
    if obligation.mechanism.startswith(MAINSTAY_PREFIX):
        return "adaptation"
    return "behavioural"


def _profile(name: str, tier: int) -> list:
    if name == "VSTD":
        return [o for o in OBLIGATIONS if o.profile == tier]
    if name == "GRAPH":
        return [o for o in GRAPH_OBLIGATIONS if o.profile == tier]
    return [o for o in DOMAIN_OBLIGATIONS if o.object_name == name and o.profile == tier]


def _complete(tier: int) -> set[str]:
    return {name for name in GROUNDED_OBJECTS if all(o.mechanized for o in _profile(name, tier))}


def _mark(name: str) -> str:
    return "§" if name in OPERATOR_OBJECTS else "‡" if name in UNGROUNDED_OBJECTS else ""


def _rows(first_cell: str) -> dict[str, tuple[str, list[str]]]:
    """Rows of the one table whose second column opens with `first_cell`, keyed by object."""
    shape = re.compile(rf"^\| (?P<name>[A-Z]+)(?P<marks>(?: [^\s|]+)*) \| (?P<cells>{first_cell}.*)\|$")
    rows: dict[str, tuple[str, list[str]]] = {}
    for line in META.splitlines():
        found = shape.match(line.rstrip())
        if found:
            assert found["name"] not in rows, f"{found['name']} appears twice in one table"
            rows[found["name"]] = (found["marks"].strip(),
                                   [cell.strip() for cell in found["cells"].split("|")])
    assert set(rows) == set(ALL_DEPTHS), sorted(set(rows) ^ set(ALL_DEPTHS))
    return rows


_GRID_CELL = re.compile(r"^\*\*(\d+)\*\*(?: of (\d+))?(?: \((\d+)\))?$")


@pytest.mark.parametrize("name", sorted(ALL_DEPTHS))
def test_every_depth_grid_cell_is_measured(name: str) -> None:
    """Each cell's depth, module count and mechanized count; each row's totals and mark.

    A module count is shown exactly where it differs from the depth, and a mechanized
    count only on a domain object, because the two specification axes carry no domain
    adapter by construction.
    """
    marks, cells = _rows(r"\*\*")[name]
    assert marks == _mark(name), (name, marks)
    domain = name in DOMAIN_OBJECTS
    assert len(cells) == len(CORROBORATION_TIERS) + 4, (name, cells)
    tiers = [*CORROBORATION_TIERS, DISCLOSURE_TIER] if domain else list(CORROBORATION_TIERS)
    for tier, cell in zip(tiers, cells):
        found = _GRID_CELL.match(cell)
        assert found, (name, tier, cell)
        depth, modules, mechanized = found.groups()
        rows = _profile(name, tier)
        expected = tier_depth(name, tier) if domain else SPEC_AXES[name][tier - 1]
        assert int(depth) == expected, (name, tier, cell)
        assert modules == (str(len(rows)) if expected < len(rows) else None), (name, tier, cell)
        assert mechanized == (str(sum(o.mechanized for o in rows)) if domain else None), (name, tier, cell)
    if not domain:
        assert cells[len(CORROBORATION_TIERS)] == "—", name
    rungs = sum(ALL_DEPTHS[name])
    assert cells[-3:-1] == [str(rungs), str(rungs + 1)], name
    catalogued = [o for o in DOMAIN_OBLIGATIONS if o.object_name == name]
    assert cells[-1] == (f"{sum(o.mechanized for o in catalogued)}/{len(catalogued)}"
                         if domain else "n/a"), name


@pytest.mark.parametrize("name", sorted(ALL_DEPTHS))
def test_every_coordinate_range_ends_at_its_profile_size(name: str) -> None:
    marks, cells = _rows("`")[name]
    assert marks == _mark(name), (name, marks)
    prefix = "" if name == "VSTD" else f"{name}-"
    domain = name in DOMAIN_OBJECTS
    tiers = [*CORROBORATION_TIERS, DISCLOSURE_TIER] if domain else list(CORROBORATION_TIERS)
    expected = [f"`{prefix}{tier}.1`-`{tier}.{len(_profile(name, tier))}`" for tier in tiers]
    if not domain:
        expected.append("—")
    assert cells == expected, name


def test_the_published_mechanization_figures_are_measured() -> None:
    mechanized = [o for o in DOMAIN_OBLIGATIONS if o.mechanized]
    families = Counter(_family(o) for o in mechanized)
    assert {o.profile for o in mechanized if _family(o) == "statics"} == {3}
    assert {o.profile for o in mechanized if _family(o) == "adaptation"} == {5}
    assert {o.object_name for o in mechanized} == set(GROUNDED_OBJECTS)
    assert _stated(r"Only (\w+) of the (\w+) domain objects have an adapter in any family, "
                   r"and only (\w+) have a behavioural adapter") == (
        len(GROUNDED_OBJECTS), len(DOMAIN_OBJECTS), len(CHECKS))
    assert _stated(r"Of the (\d+) domain obligations, (\d+) are mechanized, across (\w+) disjoint "
                   r"families: (\d+) behavioural adapter checks, (\d+) tier-3 statics checks and "
                   r"(\d+) tier-5 adaptation checks\.") == (
        len(DOMAIN_OBLIGATIONS), len(mechanized), len(families),
        families["behavioural"], families["statics"], families["adaptation"])

    assert _complete(5) == set(GROUNDED_OBJECTS)
    assert not any(o.profile == DISCLOSURE_TIER for o in mechanized)
    assert not any(o.object_name in UNGROUNDED_OBJECTS for o in mechanized)
    assert _stated(r"Tier 5 is fully mechanized on the (\w+) grounded objects and tier 3 on (\w+) "
                   r"of them; on the (\w+) ungrounded objects no tier is mechanized at all, and "
                   r"level 6 is mechanized nowhere\.") == (
        len(GROUNDED_OBJECTS), len(_complete(3)), len(UNGROUNDED_OBJECTS))

    bare = Counter(o.profile for o in DOMAIN_OBLIGATIONS if not o.mechanized)
    assert _stated(r"What remains bare is (\d+) at tier 1, (\d+) at tier 2, (\d+) at tier 3, "
                   r"(\d+) at tier 4, (\d+) at tier 5, and the whole of level 6") == tuple(
        bare[tier] for tier in CORROBORATION_TIERS)


def test_the_tier_three_and_five_claims_hold() -> None:
    """The shapes items 1 and 2 state in place of the counts they used to carry."""
    statics = {o.object_name for o in DOMAIN_OBLIGATIONS if o.mechanized and _family(o) == "statics"}
    assert "Tier 5 is mechanized on every grounded object" in FLAT
    assert _complete(5) == set(GROUNDED_OBJECTS)
    assert "Tier 3 is complete on every object with a statics check" in FLAT
    assert statics == _complete(3)
    found = re.search(r"The bare tier-3 coordinates that remain on grounded objects are all on "
                      r"((?:[A-Z]+, )*[A-Z]+ and [A-Z]+), whose", FLAT)
    assert found
    named = set(re.findall(r"[A-Z]{2,}", found.group(1)))
    bare = {o.object_name for o in DOMAIN_OBLIGATIONS
            if o.profile == 3 and o.object_name in GROUNDED_OBJECTS and not o.mechanized}
    assert named == bare == set(GROUNDED_OBJECTS) - statics


def test_both_remainder_partitions_are_measured() -> None:
    """The unmechanized obligations split three ways, and both sentences state the split."""
    assert OPERATOR_OBJECTS == ("HYPER",), "both sentences name the operator"
    bare = [o for o in DOMAIN_OBLIGATIONS if not o.mechanized]
    ungrounded = [o for o in DOMAIN_OBLIGATIONS if o.object_name in UNGROUNDED_OBJECTS]
    operator = [o for o in bare if o.object_name in OPERATOR_OBJECTS]
    certifiable = [o for o in bare if o.object_name in CERTIFIABLE_OBJECTS]
    assert len(bare) == len(ungrounded) + len(operator) + len(certifiable), "the split is exact"
    mechanized = len(DOMAIN_OBLIGATIONS) - len(bare)

    assert _stated(r"What remains provisional is mechanization: (\d+) of (\d+) domain obligations "
                   r"have a check behind them, and every one of the remaining (\d+) is a coordinate "
                   r"a certificate can name but not yet clear\. (\d+) of those (\d+) are the whole "
                   r"of the (\w+) ungrounded objects, which have no adapter at all, and (\d+) are "
                   r"the unmechanized obligations of HYPER") == (
        mechanized, len(DOMAIN_OBLIGATIONS), len(bare), len(ungrounded), len(bare),
        len(UNGROUNDED_OBJECTS), len(operator))
    assert _stated(r"Of the (\w+) domain objects, (\d+) of (\d+) obligations name a check in one "
                   r"of the (\w+) families") == (
        len(DOMAIN_OBJECTS), mechanized, len(DOMAIN_OBLIGATIONS),
        len({_family(o) for o in DOMAIN_OBLIGATIONS if o.mechanized}))
    assert _stated(r"The remaining (\d+) are specified without a mechanism [^;]*; (\d+) of them are "
                   r"the whole of the (\w+) objects with no adapter at all, (\d+) more are the "
                   r"unmechanized obligations of `HYPER`, which has no behavioural adapter, and the "
                   r"remaining (\d+) are the bare tiers of the (\w+) certifiable objects\.") == (
        len(bare), len(ungrounded), len(UNGROUNDED_OBJECTS), len(operator), len(certifiable),
        len(CERTIFIABLE_OBJECTS))
