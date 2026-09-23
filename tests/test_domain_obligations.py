"""Terminology: Verifier Standard (VSTD).

The domain objects carry grounding coordinates of their own, in a third
namespace disjoint from both the object axis and the Graph axis.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from verifier.core.profile_obligations import (
    BY_ID,
    CERTIFIABLE_OBJECTS,
    DISCLOSURE_TIER,
    DOMAIN_BY_ID,
    DOMAIN_OBJECTS,
    GROUNDED_OBJECTS,
    RELATIONAL_OBJECTS,
    UNGROUNDED_OBJECTS,
    DOMAIN_OBLIGATIONS,
    GRAPH_BY_ID,
    TIER_NAMES,
    ADAPTER_PENDING_OBJECTS,
    OPERATOR_OBJECTS,
    UNCERTIFIABLE_OBJECTS,
    catalog_digest,
    domain_catalog_digest,
    domain_obligation_catalog,
    domain_obligation_digest,
    graph_catalog_digest,
    tier_depth,
)
from verifier.domains.catalog import CHECKS, SCOPES
from verifier.domains.mainstays import CHECKS as ADAPTATION_CHECKS
from verifier.domains.mainstays import PREFIX as MAINSTAY_PREFIX
from verifier.domains.statics import BY_NAME as STATICS_BY_NAME
from verifier.domains.statics import PREFIX as STATICS_PREFIX

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = (REPO_ROOT / "src/verifier/standard/DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
# Prose wraps wherever the line runs out, so sentences are matched with whitespace folded.
FLAT = " ".join(SPEC.split())


def _number_words() -> dict[str, int]:
    """The pull-request gate's vocabulary, so the spec and the description read numbers alike."""
    spec = importlib.util.spec_from_file_location(
        "check_pr_description", REPO_ROOT / "scripts" / "check_pr_description.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return {word: value for value, word in module.NUMBER_WORDS.items()}


NUMBER_WORDS = _number_words()


def _count(token: str) -> int:
    return int(token) if token[0].isdigit() else NUMBER_WORDS[token.lower()]


def _stated(pattern: str) -> re.Match:
    found = re.search(pattern, FLAT)
    assert found, pattern
    return found


def test_every_domain_profile_has_contiguous_obligations() -> None:
    assert set(DOMAIN_OBJECTS) == {o.object_name for o in DOMAIN_OBLIGATIONS}
    for object_name in DOMAIN_OBJECTS:
        for profile in range(1, 7):
            rows = [o for o in DOMAIN_OBLIGATIONS
                    if o.object_name == object_name and o.profile == profile]
            assert rows, (object_name, profile)
            assert [o.index for o in rows] == list(range(1, len(rows) + 1))
            assert rows[0].depends_on == ()
    assert domain_obligation_catalog()["schema_version"] == "verifier-domain-obligations-1"
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
            # A behavioural name needs a behavioural adapter on its own object.
            assert obligation.object_name in CHECKS, obligation.id
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
    assert grounded == {1, 2, 3, 4, 6}, (
        "tier 5 of a grounded object is fully mechanized, and level 6 is mechanized "
        "nowhere -- no adapter runs at emission time")


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
        for profile in range(1, 7):
            assert [o for o in rows if o.profile == profile], (object_name, profile)


def test_the_relational_partition_is_exact() -> None:
    """GRAPH carries its own axis; HYPER, OWNER and IDENTITY sit on the domain axis.

    Relational and ungrounded are independent. Until the identity family was
    catalogued OWNER was the only ungrounded object and it was relational too, so
    the containment held by coincidence of there being one. A person is not a
    relation between certified objects, and asserting the containment again would
    force HUMAN, ROLE and COLLECTIVE to be mislabelled as relations to keep it.
    """
    assert set(UNGROUNDED_OBJECTS) <= set(DOMAIN_OBJECTS)
    assert set(UNGROUNDED_OBJECTS) - set(RELATIONAL_OBJECTS), (
        "ungrounded must not collapse back into a subset of relational")
    assert set(RELATIONAL_OBJECTS) - set(UNGROUNDED_OBJECTS) - {"GRAPH"}, (
        "a relational object may be grounded")
    assert set(GROUNDED_OBJECTS) | set(UNGROUNDED_OBJECTS) == set(DOMAIN_OBJECTS)
    assert not set(GROUNDED_OBJECTS) & set(UNGROUNDED_OBJECTS)
    assert "GRAPH" in RELATIONAL_OBJECTS and "GRAPH" not in DOMAIN_OBJECTS
    assert "HYPER" in RELATIONAL_OBJECTS and "HYPER" in GROUNDED_OBJECTS
    catalog = domain_obligation_catalog()
    assert catalog["relational"] == list(RELATIONAL_OBJECTS)
    assert catalog["ungrounded"] == list(UNGROUNDED_OBJECTS)


def test_tier_depth_is_a_depth_not_a_count() -> None:
    for object_name in DOMAIN_OBJECTS:
        for profile in range(1, 7):
            count = len([o for o in DOMAIN_OBLIGATIONS
                         if o.object_name == object_name and o.profile == profile])
            depth = tier_depth(object_name, profile)
            assert 1 <= depth <= count, (object_name, profile)
    with pytest.raises(ValueError):
        tier_depth("NOPE", 1)


def test_normative_domain_catalogue_and_runtime_rows_agree() -> None:
    text = (REPO_ROOT / "src/verifier/standard/DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    for obligation in DOMAIN_OBLIGATIONS:
        dependencies = ", ".join(obligation.depends_on) or "none"
        row = (f"| {obligation.id} | {obligation.name} | {obligation.requirement} "
               f"| {dependencies} | {obligation.mechanism or 'none'} |")
        assert row in text, obligation.id
    for object_name in DOMAIN_OBJECTS:
        for profile, name in TIER_NAMES.items():
            assert f"### {object_name}-{profile}: {name}" in text


def test_domain_obligation_digest_pins_the_domain_bytes_only() -> None:
    first = domain_obligation_digest()
    assert first == domain_obligation_digest()
    assert len(first) == 64


@pytest.mark.parametrize("object_name", DOMAIN_OBJECTS)
def test_no_domain_profile_is_empty(object_name: str) -> None:
    for profile in range(1, 7):
        assert [o for o in DOMAIN_OBLIGATIONS
                if o.object_name == object_name and o.profile == profile]


def test_the_disclosure_level_is_a_level_and_not_an_object() -> None:
    """Level 6 is the same six rows everywhere; an object would contribute rows that differ.

    Four of the six are the same proposition at every object, which is the whole argument
    that disclosure is a level rather than an object of its own. Only 6.1 (what this
    object emits) and 6.5 (what composing it reveals) are object-specific.
    """
    shapes = set()
    uniform: dict[int, set[str]] = {}
    for object_name in DOMAIN_OBJECTS:
        rows = [o for o in DOMAIN_OBLIGATIONS
                if o.object_name == object_name and o.profile == DISCLOSURE_TIER]
        assert len(rows) == 6, object_name
        # The prefix is the object; the shape is what is left when it is removed.
        shapes.add(tuple((o.index, o.name,
                          tuple(d.split("-", 1)[1] for d in o.depends_on))
                         for o in rows))
        for o in rows:
            uniform.setdefault(o.index, set()).add(o.requirement)
    assert len(shapes) == 1, "level 6 must have one shape on every object"
    assert {i for i, texts in uniform.items() if len(texts) == 1} == {2, 3, 4, 6}
    assert {i for i, texts in uniform.items() if len(texts) > 1} == {1, 5}


def test_the_disclosure_level_is_mechanized_nowhere() -> None:
    """A PASS here would claim an observer model the implementation does not establish."""
    six = [o for o in DOMAIN_OBLIGATIONS if o.profile == DISCLOSURE_TIER]
    assert len(six) == 6 * len(DOMAIN_OBJECTS)
    assert not any(o.mechanized for o in six)
    assert all(o.to_dict()["mechanized"] is False for o in six)


def test_the_disclosure_level_adds_no_adapter_module() -> None:
    """Level 6 must not move implementation_digest(): it names no check in any family."""
    behavioural = {c[0] for rows in CHECKS.values() for c in rows}
    statics = {STATICS_PREFIX + n for rows in STATICS_BY_NAME.values() for n in rows}
    adaptation = {MAINSTAY_PREFIX + n for n in ADAPTATION_CHECKS}
    for obligation in DOMAIN_OBLIGATIONS:
        if obligation.profile == DISCLOSURE_TIER:
            assert obligation.mechanism not in behavioural | statics | adaptation


def test_every_mechanism_name_resolves_to_a_registered_check() -> None:
    """A mechanism is a promise that something executes it. An unresolvable name is not.

    The four OWNER defects found on landing day were all unmechanized prose, where
    adversarial reading was the only possible gate. This class is the opposite: it was
    always mechanically checkable, and nothing checked it, so a mechanism could name a
    check belonging to a different object -- or to none -- and the suite stayed green.
    Resolution is scoped to the obligation's OWN object for the two object-keyed families,
    because a name that resolves under another object resolves to the wrong check.
    """
    adaptation = {MAINSTAY_PREFIX + n for n in ADAPTATION_CHECKS}
    unresolved = []
    for obligation in DOMAIN_OBLIGATIONS:
        if not obligation.mechanized:
            continue
        behavioural = {c[0] for c in CHECKS.get(obligation.object_name, ())}
        statics = {STATICS_PREFIX + n
                   for n in STATICS_BY_NAME.get(obligation.object_name, ())}
        if obligation.mechanism not in behavioural | statics | adaptation:
            unresolved.append((obligation.id, obligation.mechanism))
    assert unresolved == [], unresolved


def test_certifiable_is_not_the_same_property_as_grounded() -> None:
    """Conflating the two published a false claim about HYPER for this catalogue's life.

    `build_domain_certificate` rejects any domain absent from CHECKS, so CERTIFIABLE_OBJECTS
    is the set of objects a domain certificate can be built for at all. It is asserted
    against both registries here rather than imported into the catalogue -- which
    verifier.domains depends on -- and that assertion is what keeps the published partition
    and the executable one the same.
    """
    assert set(CERTIFIABLE_OBJECTS) == set(CHECKS) == set(SCOPES)
    assert set(CERTIFIABLE_OBJECTS).isdisjoint(UNCERTIFIABLE_OBJECTS)
    assert set(CERTIFIABLE_OBJECTS) | set(UNCERTIFIABLE_OBJECTS) == set(DOMAIN_OBJECTS)

    # HYPER is the case a two-part partition could not express: grounded, because
    # statics and adaptation checks do execute over it, and certifiable not at all.
    # There are two possible reasons, which is why the residue is named by two constants
    # rather than by a literal. HYPER is the composition *operator*: it holds between
    # certified objects and carries no substrate of its own for an adapter to bind, so
    # its residue is permanent -- the shape every relational entry would have. The other
    # reason is an object with a substrate whose behavioural adapter is not written yet:
    # a pending wiring decision with a price attached, not a property of the object.
    # Enumerating them separately is the point: collapsing them would hide that one kind
    # can be discharged and the other never can.
    #
    # TOKEN held the pending position until 2026-09-22, when verifier.domains.token
    # discharged it. The constant is kept and asserted empty, so an object that loses or
    # awaits its adapter has to be named in it -- and this test edited -- rather than
    # dropping out of the certifiable set unremarked.
    #
    # TRAIN sat in HYPER's slot here until 2026-09-22, and that was the false claim. A
    # training run has a substrate -- the checkpoint inventory and the step trace -- and
    # verifier.domains.train replays it. The adapter was never missing; it was filed
    # under the operator's name.
    residue = set(UNCERTIFIABLE_OBJECTS) - set(UNGROUNDED_OBJECTS)
    assert residue == set(OPERATOR_OBJECTS) | set(ADAPTER_PENDING_OBJECTS)
    assert set(OPERATOR_OBJECTS) == {"HYPER"}
    assert ADAPTER_PENDING_OBJECTS == ()
    assert residue == {"HYPER"}
    assert not set(OPERATOR_OBJECTS) & set(ADAPTER_PENDING_OBJECTS), "the reasons are distinct"
    assert "HYPER" in GROUNDED_OBJECTS and "HYPER" not in CERTIFIABLE_OBJECTS
    assert "TRAIN" in CERTIFIABLE_OBJECTS, "the object that owns the adapter is certifiable"
    assert "TOKEN" in CERTIFIABLE_OBJECTS, "its pending adapter was written"
    hyper = [o for o in DOMAIN_OBLIGATIONS if o.object_name == "HYPER"]
    assert any(o.mechanized for o in hyper), "its statics and adaptation rows do resolve"
    assert not any(o.mechanized for o in hyper if o.profile in (1, 2, 4)), (
        "with no behavioural adapter, no facets, dynamics or closure row may name a check")

    # An ungrounded object carries no mechanism in any family, which is the stronger claim.
    for name in UNGROUNDED_OBJECTS:
        rows = [o for o in DOMAIN_OBLIGATIONS if o.object_name == name]
        assert rows and not any(o.mechanized for o in rows), name


def test_every_profile_header_states_its_measured_depth_and_mechanization() -> None:
    """One header per profile, and each figure in it recomputed from the catalogue."""
    headers = re.findall(r"^`[A-Z]+-\d\.1` through `[A-Z]+-\d\.\d+`; topological depth \d+; "
                         r"\d+ of \d+ mechanized\.$", SPEC, re.MULTILINE)
    assert len(headers) == len(set(headers)) == 6 * len(DOMAIN_OBJECTS)
    for object_name in DOMAIN_OBJECTS:
        for profile in range(1, 7):
            rows = [o for o in DOMAIN_OBLIGATIONS
                    if o.object_name == object_name and o.profile == profile]
            header = (f"`{object_name}-{profile}.1` through `{object_name}-{profile}.{len(rows)}`; "
                      f"topological depth {tier_depth(object_name, profile)}; "
                      f"{sum(o.mechanized for o in rows)} of {len(rows)} mechanized.")
            assert header in headers, (object_name, profile)


def test_the_families_table_states_each_measured_bound() -> None:
    mechanized = [o for o in DOMAIN_OBLIGATIONS if o.mechanized]
    statics = sum(o.mechanism.startswith(STATICS_PREFIX) for o in mechanized)
    adaptation = sum(o.mechanism.startswith(MAINSTAY_PREFIX) for o in mechanized)
    bounds = dict(re.findall(r"^\| (Behavioural|Statics|Adaptation) \|.*\| (\d+) \|$", SPEC, re.MULTILINE))
    assert bounds == {"Behavioural": str(len(mechanized) - statics - adaptation),
                      "Statics": str(statics), "Adaptation": str(adaptation)}


def test_the_published_partition_is_measured() -> None:
    """The certifiable, operator and ungrounded sentences, each against the constants."""
    for pattern in (r"^# Grounded certification obligations of the (\w+) domain objects$",
                    r"\(normative for the (\w+) domain objects' obligations\)"):
        found = re.search(pattern, SPEC, re.MULTILINE)
        assert found and _count(found.group(1)) == len(DOMAIN_OBJECTS), pattern
    found = _stated(r"the (\w+) domain objects, coordinate `<object>-<tier>\.<index>`, (\d+) obligations")
    assert (_count(found.group(1)), _count(found.group(2))) == (len(DOMAIN_OBJECTS), len(DOMAIN_OBLIGATIONS))

    found = _stated(r"\*\*(\w+) of the (\w+) are certifiable")
    assert (_count(found.group(1)), _count(found.group(2))) == (len(CERTIFIABLE_OBJECTS), len(DOMAIN_OBJECTS))
    found = _stated(r"so those (\w+) -- (.+?) -- are the objects a domain certificate can be built for")
    assert _count(found.group(1)) == len(CERTIFIABLE_OBJECTS)
    assert re.findall(r"`([A-Z]+)`", found.group(2)) == list(CERTIFIABLE_OBJECTS)

    assert OPERATOR_OBJECTS == ("HYPER",), "the operator sentence names HYPER"
    hyper = [o for o in DOMAIN_OBLIGATIONS if o.object_name == "HYPER"]
    found = _stated(r"`HYPER` is \*\*catalogued but not certifiable\*\*\. Its statics and adaptation "
                    r"mechanisms resolve and execute, so (\d+) of its (\d+) obligations are mechanized")
    assert (int(found.group(1)), int(found.group(2))) == (sum(o.mechanized for o in hyper), len(hyper))

    found = _stated(r"The other (\w+) -- `OWNER` and the (\w+) identity objects (.+?) -- are "
                    r"\*\*ungrounded\*\*: no adapter executes them in any family, so all (\d+) of "
                    r"their obligations report `UNKNOWN`")
    named = ["OWNER", *re.findall(r"`([A-Z]+)`", found.group(3))]
    assert _count(found.group(1)) == len(UNGROUNDED_OBJECTS)
    assert _count(found.group(2)) == len(UNGROUNDED_OBJECTS) - 1
    assert sorted(named) == sorted(UNGROUNDED_OBJECTS)
    assert int(found.group(4)) == len([o for o in DOMAIN_OBLIGATIONS if o.object_name in UNGROUNDED_OBJECTS])


# The two vocabularies the training-run section was read against when it said neither can
# name a layer or an operator. That is a reading, not a computation, so what is pinned is the
# event that could falsify it: widening either vocabulary turns this red until the section is
# read again and the pin is moved with it.
READ_ARTIFACT_TYPES = {
    "ACCOUNTING_EVIDENCE", "ADAPTER", "CHECKPOINT", "CONFIG", "CONTINUITY_EVIDENCE", "CORPUS",
    "DATASET_SPLIT", "DEVICE_IDENTITY", "EVALUATION_REPORT", "EXECUTION_EVIDENCE",
    "FIRMWARE_MEASUREMENT", "HARDWARE_EVIDENCE", "HARDWARE_RECEIPT", "MODEL", "PROVIDER_EVIDENCE",
    "RAW_SOURCE_FILE", "RUNTIME_MEASUREMENT", "SHARD", "SUBMISSION_ARTIFACT", "TOKENIZED_CORPUS",
    "TOPOLOGY_SNAPSHOT",
}
READ_TRANSFORMATION_TYPES = {
    "AUGMENTATION", "COLLECTION", "COMPUTE_ACCOUNTING", "CONTINUITY_ANCHORING", "DEDUPLICATION",
    "DISTILLATION", "EVALUATION", "EVIDENCE_BINDING", "EXTRACTION", "FILTERING", "FINE_TUNING",
    "HARDWARE_ATTESTATION", "HARDWARE_DISCOVERY", "NORMALIZATION", "QUANTIZATION",
    "SYNTHETIC_GENERATION", "TOKENIZATION", "TRAINING", "WORKLOAD_EXECUTION",
}


def test_the_architecture_operand_is_stated_against_the_vocabulary_it_was_read_against() -> None:
    from verifier.data.models import ArtifactType, TransformationType

    assert ("The Graph axis has no vocabulary for the second role yet: the artifact and "
            "transformation types of `GRAPH-1` are provenance kinds, and none of them names a "
            "layer or an operator.") in FLAT
    assert {member.value for member in ArtifactType} == READ_ARTIFACT_TYPES
    assert {member.value for member in TransformationType} == READ_TRANSFORMATION_TYPES


def test_every_relational_enumeration_is_the_constant() -> None:
    """A count or a list of the relational objects is read back from the catalogue.

    The count was stated as three after the identity family made it four, and nothing
    noticed, because no test read the prose.
    """
    relational = list(RELATIONAL_OBJECTS)
    both = [name for name in relational if name in UNGROUNDED_OBJECTS]
    meta = " ".join((REPO_ROOT / "src/verifier/standard/META_TIERS.md").read_text(encoding="utf-8").split())
    counted = listed = 0
    for prose in (FLAT, meta):
        for found in re.finditer(r"\b(\w+) relational objects\b", prose):
            if found.group(1).lower() in NUMBER_WORDS:
                assert _count(found.group(1)) == len(relational), found.group(0)
                counted += 1
        for found in re.finditer(r"relational objects (?:are|--) ((?:`[A-Z]+`,? )+and `[A-Z]+`)", prose):
            assert re.findall(r"`([A-Z]+)`", found.group(1)) == relational, found.group(0)
            listed += 1
    assert (counted, listed) == (1, 2), "the enumerations moved; re-point this guard"

    found = _stated(r"-- the last (\w+) are \*\*ungrounded\*\*")
    assert relational[-_count(found.group(1)):] == both, "the ungrounded relational objects end the list"
    found = re.search(r"((?:`[A-Z]+` relates [^,.]+, )+and `[A-Z]+` relates [^.]+)\. None of the (\w+) "
                      r"certifies a substrate of its own", meta)
    assert found, "the relational paragraph of META_TIERS.md"
    assert re.findall(r"`([A-Z]+)` relates", found.group(1)) == relational
    assert _count(found.group(2)) == len(relational)


def test_every_coordinate_the_prose_says_binds_is_a_binding_row() -> None:
    """A sentence saying an obligation binds something names a row that binds by certificate.

    The collective's facet row declares the collective to be a graph and binds nothing, while
    two summaries and the lattice section said it bound a `GRAPH`. The check is general:
    every coordinate a summary says binds must be a row whose requirement is "bound by".
    """
    meta = " ".join((REPO_ROOT / "src/verifier/standard/META_TIERS.md").read_text(encoding="utf-8").split())
    named = []
    for prose in (FLAT, meta):
        for found in re.finditer(r"((?:`[A-Z]+-\d\.\d+`(?:,? and |, ))*`[A-Z]+-\d\.\d+`) binds?\b", prose):
            named += re.findall(r"`([A-Z]+-\d\.\d+)`", found.group(1))
    assert len(set(named)) >= 4, named
    for coordinate in named:
        assert re.search(r"\bbound by\b", DOMAIN_BY_ID[coordinate].requirement), coordinate
