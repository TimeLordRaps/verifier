"""Terminology: Verifier Standard (VSTD).

The ten domain objects carry grounding coordinates of their own, in a third
namespace disjoint from both the object axis and the Graph axis.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verifier.core.profile_obligations import (
    BY_ID,
    DOMAIN_BY_ID,
    DOMAIN_OBJECTS,
    GROUNDED_OBJECTS,
    RELATIONAL_OBJECTS,
    UNGROUNDED_OBJECTS,
    DOMAIN_OBLIGATIONS,
    GRAPH_BY_ID,
    TIER_NAMES,
    catalog_digest,
    domain_catalog_digest,
    domain_obligation_catalog,
    domain_obligation_digest,
    graph_catalog_digest,
    tier_depth,
)
from verifier.domains.catalog import CHECKS
from verifier.domains.mainstays import CHECKS as ADAPTATION_CHECKS
from verifier.domains.mainstays import PREFIX as MAINSTAY_PREFIX
from verifier.domains.statics import BY_NAME as STATICS_BY_NAME
from verifier.domains.statics import PREFIX as STATICS_PREFIX

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_every_domain_profile_has_contiguous_obligations() -> None:
    assert set(DOMAIN_OBJECTS) == {o.object_name for o in DOMAIN_OBLIGATIONS}
    for object_name in DOMAIN_OBJECTS:
        for profile in range(1, 6):
            rows = [o for o in DOMAIN_OBLIGATIONS
                    if o.object_name == object_name and o.profile == profile]
            assert rows, (object_name, profile)
            assert [o.index for o in rows] == list(range(1, len(rows) + 1))
            assert rows[0].depends_on == ()
    assert domain_obligation_catalog()["schema_version"] == "VSTD-DOMAIN-OBLIGATIONS-1"
    assert domain_obligation_catalog()["axis"] == "DOMAIN"
    assert set(DOMAIN_BY_ID) == {o.id for o in DOMAIN_OBLIGATIONS}


def test_dependencies_stay_inside_their_profile_and_cannot_cycle() -> None:
    for obligation in DOMAIN_OBLIGATIONS:
        for dependency in obligation.depends_on:
            assert dependency in DOMAIN_BY_ID, (obligation.id, dependency)
            earlier = DOMAIN_BY_ID[dependency]
            assert earlier.object_name == obligation.object_name
            assert earlier.profile == obligation.profile
            assert earlier.index < obligation.index, (obligation.id, dependency)


def test_the_three_namespaces_never_alias() -> None:
    assert not set(DOMAIN_BY_ID) & set(BY_ID)
    assert not set(DOMAIN_BY_ID) & set(GRAPH_BY_ID)
    predicates = {o.predicate for o in DOMAIN_OBLIGATIONS}
    assert not predicates & {o.predicate for o in BY_ID.values()}
    assert not predicates & {o.predicate for o in GRAPH_BY_ID.values()}
    assert len(predicates) == len(DOMAIN_OBLIGATIONS)
    for obligation in DOMAIN_OBLIGATIONS:
        assert obligation.id.startswith(f"{obligation.object_name}-")
        assert obligation.predicate.startswith(
            f"vstd.{obligation.object_name.lower()}.obligation.")


def test_extending_one_catalogue_does_not_move_another() -> None:
    digests = {catalog_digest(), graph_catalog_digest(), domain_catalog_digest()}
    assert len(digests) == 3
    assert domain_catalog_digest() == domain_catalog_digest()


def test_every_mechanism_names_a_real_check_in_its_own_family() -> None:
    """Three families, routed by prefix; a bare name is a behavioural adapter check."""
    for obligation in DOMAIN_OBLIGATIONS:
        if not obligation.mechanized:
            continue
        name = obligation.mechanism
        if name.startswith(STATICS_PREFIX):
            assert obligation.profile == 3, obligation.id
            family = STATICS_BY_NAME[obligation.object_name]
            assert name[len(STATICS_PREFIX):] in family, obligation.id
        elif name.startswith(MAINSTAY_PREFIX):
            assert obligation.profile == 5, obligation.id
            assert name[len(MAINSTAY_PREFIX):] in ADAPTATION_CHECKS, obligation.id
        else:
            # HARNESS, AGENT and BOT behavioural adapters ship on the release branch.
            if obligation.object_name not in CHECKS:
                continue
            assert name in {check[0] for check in CHECKS[obligation.object_name]}, obligation.id


def test_the_three_mechanism_families_never_share_a_name() -> None:
    behavioural = {c[0] for rows in CHECKS.values() for c in rows}
    statics = {STATICS_PREFIX + n for rows in STATICS_BY_NAME.values() for n in rows}
    adaptation = {MAINSTAY_PREFIX + n for n in ADAPTATION_CHECKS}
    assert not behavioural & statics and not behavioural & adaptation
    assert not statics & adaptation


def test_an_absent_mechanism_is_unknown_and_never_passed() -> None:
    bare = [o for o in DOMAIN_OBLIGATIONS if not o.mechanized]
    assert bare, "the catalogue is meant to outrun the adapters"
    for obligation in bare:
        assert obligation.mechanism == ""
        assert obligation.to_dict()["mechanized"] is False
    grounded = {o.profile for o in bare if o.object_name in GROUNDED_OBJECTS}
    assert grounded == {1, 2, 3, 4}, "tier 5 of a grounded object is fully mechanized"


def test_every_tier_three_and_five_profile_is_mechanized_somewhere() -> None:
    for object_name in GROUNDED_OBJECTS:
        for profile in (3, 5):
            rows = [o for o in DOMAIN_OBLIGATIONS
                    if o.object_name == object_name and o.profile == profile]
            assert any(o.mechanized for o in rows), (object_name, profile)


def test_an_ungrounded_object_mechanizes_nothing_at_any_tier() -> None:
    """A relational object with no adapter must not claim a single mechanism."""
    assert UNGROUNDED_OBJECTS, "the partition is meant to be inhabited"
    for object_name in UNGROUNDED_OBJECTS:
        rows = [o for o in DOMAIN_OBLIGATIONS if o.object_name == object_name]
        assert rows, object_name
        assert not any(o.mechanized for o in rows), object_name
        for profile in range(1, 6):
            assert [o for o in rows if o.profile == profile], (object_name, profile)


def test_the_relational_partition_is_exact() -> None:
    """GRAPH carries its own axis; HYPER and OWNER sit on the domain axis."""
    assert set(UNGROUNDED_OBJECTS) <= set(RELATIONAL_OBJECTS)
    assert set(UNGROUNDED_OBJECTS) <= set(DOMAIN_OBJECTS)
    assert set(GROUNDED_OBJECTS) | set(UNGROUNDED_OBJECTS) == set(DOMAIN_OBJECTS)
    assert not set(GROUNDED_OBJECTS) & set(UNGROUNDED_OBJECTS)
    assert "GRAPH" in RELATIONAL_OBJECTS and "GRAPH" not in DOMAIN_OBJECTS
    assert "HYPER" in RELATIONAL_OBJECTS and "HYPER" in GROUNDED_OBJECTS
    catalog = domain_obligation_catalog()
    assert catalog["relational"] == list(RELATIONAL_OBJECTS)
    assert catalog["ungrounded"] == list(UNGROUNDED_OBJECTS)


def test_tier_depth_is_a_depth_not_a_count() -> None:
    for object_name in DOMAIN_OBJECTS:
        for profile in range(1, 6):
            count = len([o for o in DOMAIN_OBLIGATIONS
                         if o.object_name == object_name and o.profile == profile])
            depth = tier_depth(object_name, profile)
            assert 1 <= depth <= count, (object_name, profile)
    with pytest.raises(ValueError):
        tier_depth("NOPE", 1)


def test_normative_domain_catalogue_and_runtime_rows_agree() -> None:
    text = (REPO_ROOT / "src/verifier/specifications/DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    for obligation in DOMAIN_OBLIGATIONS:
        dependencies = ", ".join(obligation.depends_on) or "none"
        row = (f"| {obligation.id} | {obligation.name} | {obligation.requirement} "
               f"| {dependencies} | {obligation.mechanism or 'none'} |")
        assert row in text, obligation.id
    for object_name in DOMAIN_OBJECTS:
        for profile, name in TIER_NAMES.items():
            assert f"### VSTD-{object_name}-{profile}: {name}" in text


def test_domain_obligation_digest_pins_the_domain_bytes_only() -> None:
    first = domain_obligation_digest()
    assert first == domain_obligation_digest()
    assert len(first) == 64


@pytest.mark.parametrize("object_name", DOMAIN_OBJECTS)
def test_no_domain_profile_is_empty(object_name: str) -> None:
    for profile in range(1, 6):
        assert [o for o in DOMAIN_OBLIGATIONS
                if o.object_name == object_name and o.profile == profile]
