"""Terminology: Verifier Standard (VSTD).

The VSTD-NAMESPACE is closed, and this is what closes it.

`scripts/check_namespace_closure.py` is the gate; these tests keep the gate
honest.  A gate that passes but cannot fail would have admitted all 59 invented
heads just as silently as no gate at all, so the rejection path is asserted here
rather than checked once by hand.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_namespace_closure.py"


def named(tail: str) -> str:
    """Build a VSTD- token without spelling one.

    This file is scanned by the very gate it tests, and by scripts/
    check_presentation.py besides.  A reject-path fixture written as a plain
    literal would be found by both -- correctly, since finding exactly those
    strings is their job -- so the fixtures name only the tail and the prefix is
    joined on at runtime.  The scanner's token regex requires an alphanumeric
    after the hyphen, so `VSTD-{tail}` in this source matches nothing.

    The assertion is identical at runtime.  Inlining these back into literals
    turns the suite red and gains nothing.
    """

    return f"VSTD-{tail}"


def _gate():
    spec = importlib.util.spec_from_file_location("check_namespace_closure", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_catalogue_carries_no_object_outside_the_eighteen() -> None:
    """The load-bearing check: the object set, not prose about it."""

    found = _gate().catalogue_offenders()
    assert not found, "objects outside the closed VSTD-NAMESPACE: " + ", ".join(found)


def test_no_object_still_carries_the_prefix() -> None:
    found = _gate().residue_offenders()
    assert not found, "VSTD- prefixes that should be bare:\n" + "\n".join(
        f"  {relative}:{number}: {token}" for relative, number, token in found
    )


def test_the_namespace_is_the_base_abstract_and_eighteen_objects() -> None:
    """Enumerated by Tyler on 2026-09-22: VSTD and these eighteen, nineteen names.

    TRAIN is the eighteenth. It was held out while being composed was treated as
    disqualifying; it is in because composition is a property an object has, not a
    reason it is not one.
    """
    gate = _gate()
    assert len(gate.OBJECTS) == 18
    assert gate.OBJECTS == {
        "GRAPH", "ENV", "DATA", "BENCH", "HYPER", "MODEL", "SIM", "HARNESS",
        "AGENT", "BOT", "ACTOR", "ROLE", "COLLECTIVE", "IDENTITY", "HUMAN", "OWNER",
        "TRAIN", "TOKEN",
    }
    assert len({"VSTD"} | gate.OBJECTS) == 19, "the namespace is nineteen names"


def test_the_gate_reads_the_live_catalogue_not_a_copy_of_it() -> None:
    """The object set is checked against the catalogue that actually ships.

    A gate holding its own second copy of the object set would agree with itself
    while the catalogue drifted, which is the failure mode this whole exercise
    exists to prevent.
    """

    sys.path.insert(0, str(ROOT / "src"))
    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    gate = _gate()
    assert set(DOMAIN_OBJECTS) - gate.OBJECTS == set(gate.COMPOSITIONS)


@pytest.mark.parametrize(
    "tail",
    ["1", "5", "6", "3.2", "N", "1..5", "1..VSTD-6"],
)
def test_admits_the_base_abstract_tiers_and_ranges(tail: str) -> None:
    """The prefix survives exactly here: a bare `3` would name nothing."""

    assert _gate().admissible(named(tail))


def test_admits_the_base_abstract_bare() -> None:
    assert _gate().admissible("VSTD")


@pytest.mark.parametrize(
    "tail",
    ["DATA", "GRAPH", "OWNER", "SIM", "DATA-1", "OWNER-6", "GRAPH-2.3"],
)
def test_an_object_may_no_longer_carry_the_prefix(tail: str) -> None:
    """ALL-CAPS is the marker, so the prefixed spelling of an object is retired."""

    assert not _gate().admissible(named(tail))


@pytest.mark.parametrize(
    "tail",
    [
        # the heads that actually squatted the namespace before the gate existed
        "SILO-TRANSFER-1", "OBJECT-1", "PUBLISHER-1",
        "PROPOSITION-TRANSFER-RULE-1", "RUNTIME-AUTHORITY-1",
        "UNTRAVERSABLE-1", "ARTIFACT-1", "ZK-1",
        # a plausible future invention
        "REGISTRY-1",
    ],
)
def test_rejects_a_head_the_namespace_never_admitted(tail: str) -> None:
    """The fail path is the whole point: assert it, do not assume it."""

    assert not _gate().admissible(named(tail))


def test_no_zero_is_admissible_in_either_position() -> None:
    """The namespace is 1-indexed in both positions of `<tier>.<module>`.

    The zero tier and the squatting were one defect -- a name that was never an
    object had no real tier available to it -- so repairing the head must not
    leave a route back to the zero, in either position.
    """

    gate = _gate()
    for tail in ("0.1", "0.3", "3.0", "1.0", "2.0", "4.0"):
        assert not gate.admissible(named(tail)), tail


def test_the_one_composition_is_declared_the_same_way_in_all_three_places() -> None:
    """A name carried in one place and not the others is exactly how TRAIN drifted.

    TRAIN is composed *and* a namespace object, admitted 2026-09-22. The composition
    still has to be stated identically everywhere it is stated at all: the gate's
    object set, the runtime partition, and the normative document. Every operand must
    itself be a namespace object, or the composition would be written over something
    that does not exist.

    ``COMPOSITIONS`` is the table of names expressible in the namespace *without*
    being members of it. It is empty, and the emptiness is asserted rather than
    assumed: a head may only be added there with a definition, so a future entry
    cannot slip in by being written down.
    """

    sys.path.insert(0, str(ROOT / "src"))
    from verifier.core.profile_obligations import (
        COMPOSITION_OF,
        DOMAIN_OBJECTS,
    )

    gate = _gate()
    assert gate.COMPOSITIONS == {}, "no name is catalogued outside the namespace"
    assert set(COMPOSITION_OF) <= set(gate.OBJECTS), "a composition is still an object"
    assert set(COMPOSITION_OF) <= set(DOMAIN_OBJECTS), "and it is still catalogued"

    for name in COMPOSITION_OF:
        operands, index = COMPOSITION_OF[name]
        assert len(set(operands)) == len(operands), name
        assert set(operands) - {"VSTD"} <= gate.OBJECTS, "an operand must be an object"
        assert index.split("-")[0] in gate.OBJECTS, "and so must the axis it is indexed by"

        published = " ".join(
            (ROOT / "src/verifier/standard/DOMAIN_OBLIGATIONS.md")
            .read_text(encoding="utf-8").split()
        )
        assert (
            f"`HYPER({', '.join(operands)})` indexed by a `{index}` recorded lineage"
            in published
        ), f"{name} is declared in the runtime but not in the document"


def test_every_exception_and_composition_head_carries_its_reason() -> None:
    """A name is admitted by an argument, never by an empty slot."""

    gate = _gate()
    for table in (gate.EXCEPTIONS, gate.COMPOSITIONS):
        for name, reason in table.items():
            assert reason.strip(), f"{name} was admitted without a reason"
            assert len(reason) > 20, f"{name} carries no real reason: {reason!r}"


def test_the_acceptance_keyword_left_the_namespace() -> None:
    """Ruled 2026-09-22: the keyword is `acceptance-clearance`, and is not a VSTD name.

    It was minted by an agent in 7ad211a (merged from codex/pr-lifecycle-hardening),
    never declared, and it rode a *legitimate* head -- HUMAN is one of the sixteen --
    so every head-shaped sweep went straight past it, exactly as they went past
    the two zero-module names the tightened tier regex later caught.  It had also
    never once been used on a pull request.

    The mechanism stayed and only the spelling moved, because it is the sole thing
    binding a human's approval to the promotion record digest: GitHub stamps a review
    with a commit but knows nothing of the record, and a comment carries neither.
    An earlier version of this test asserted the opposite -- that the keyword must
    survive because renaming it would change what Tyler types.  That was circular;
    the cost existed only because an agent had wired the name into four files.
    """

    gate = _gate()
    stale = named("HUMAN-ACCEPTANCE")
    assert not gate.admissible(stale), "the minted spelling is refused like any other"
    assert stale not in gate.EXCEPTIONS, "and it is not excused by an exception either"

    policy = (ROOT / "scripts" / "check_pr_policy.py").read_text(encoding="utf-8")
    assert "acceptance-clearance:" in policy, "the parser still has a keyword to parse"
    assert stale not in policy

def test_the_gate_runs_as_a_script() -> None:
    finished = subprocess.run(
        [sys.executable, str(GATE)], capture_output=True, text=True
    )
    assert finished.returncode == 0, finished.stdout + finished.stderr
    assert "PASS" in finished.stdout
