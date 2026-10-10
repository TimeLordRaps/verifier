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


def test_the_legacy_catalogue_carries_no_object_outside_the_nineteen() -> None:
    """Retained numbered profiles cannot silently add a current namespace kind."""

    found = _gate().catalogue_offenders()
    assert not found, "objects outside the closed VSTD-NAMESPACE: " + ", ".join(found)


def test_no_object_still_carries_the_prefix() -> None:
    found = _gate().residue_offenders()
    assert not found, "VSTD- prefixes that should be bare:\n" + "\n".join(
        f"  {relative}:{number}: {token}" for relative, number, token in found
    )


def test_historical_source_manifest_is_not_an_active_namespace_surface(tmp_path: Path, monkeypatch) -> None:
    """The exact generated manifest may quote retired names; ordinary files may not."""
    docs = tmp_path / "docs"
    source = tmp_path / "src"
    docs.mkdir()
    source.mkdir()
    retired = named("DATA-0.1")
    (docs / "PR_SOURCE_FEATURES.json").write_text(
        '{"files":[{"path":"src/old/' + retired + '.md",'
        '"summary":"formerly ' + retired + '"}]}', encoding="utf-8"
    )
    (docs / "ordinary.json").write_text('{"new":"' + retired + '"}', encoding="utf-8")
    (source / "ordinary.py").write_text('name = "' + retired + '"\n', encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "--", "docs", "src"], check=True)
    gate = _gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert [(path, token) for path, _, token in gate.residue_offenders()] == [
        ("docs/ordinary.json", retired), ("src/ordinary.py", retired),
    ]


def test_the_current_namespace_has_twenty_six_objects_and_no_vstd_object() -> None:
    """The standard name is retained, while RECEIPT is the admitted object kind."""
    gate = _gate()
    assert len(gate.OBJECTS) == 26
    assert gate.OBJECTS == {
        "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
        "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
        "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
        "AGENT", "SIM", "BOT", "TOKEN",
    }
    assert "VSTD" not in gate.OBJECTS
    assert len(gate.LEGACY_DOMAIN_OBJECTS) == 19
    assert gate.LEGACY_DOMAIN_OBJECTS <= gate.OBJECTS


def test_the_gate_reads_the_live_legacy_catalogue_not_a_copy_of_it() -> None:
    """The old numbered-profile object set is checked against what ships.

    A gate holding its own second copy of the object set would agree with itself
    while the catalogue drifted, which is the failure mode this whole exercise
    exists to prevent.
    """

    sys.path.insert(0, str(ROOT / "src"))
    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    gate = _gate()
    assert set(DOMAIN_OBJECTS) == gate.LEGACY_DOMAIN_OBJECTS
    assert set(DOMAIN_OBJECTS) - gate.OBJECTS == set(gate.COMPOSITIONS)


@pytest.mark.parametrize(
    "tail",
    ["1", "5", "6", "3.2", "N", "1..5", "1..VSTD-6"],
)
def test_preserves_historical_vstd_tiers_and_ranges(tail: str) -> None:
    """The standard's historical numbered profiles keep their exact spellings."""

    assert _gate().admissible(named(tail))


def test_admits_the_standard_name_bare_without_making_it_an_object() -> None:
    assert _gate().admissible("VSTD")
    assert "VSTD" not in _gate().OBJECTS


@pytest.mark.parametrize(
    "tail",
    ["DATA", "GRAPH", "OWNER", "SIM", "OBJECT-1", "RECEIPT-3.2",
     "DATA-1", "OWNER-6", "GRAPH-2.3"],
)
def test_an_object_may_no_longer_carry_the_prefix(tail: str) -> None:
    """ALL-CAPS is the marker, so the prefixed spelling of an object is retired."""

    assert not _gate().admissible(named(tail))


@pytest.mark.parametrize(
    "tail",
    [
        # the heads that actually squatted the namespace before the gate existed
        "SILO-TRANSFER-1", "PUBLISHER-1",
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


def test_legacy_catalogue_requires_every_retained_domain_object(monkeypatch) -> None:
    from verifier.core import profile_obligations

    gate = _gate()
    assert gate.catalogue_missing() == []
    monkeypatch.setattr(profile_obligations, "DOMAIN_OBJECTS", tuple(
        name for name in profile_obligations.DOMAIN_OBJECTS if name != "VERIFIER"
    ))
    assert gate.catalogue_missing() == ["VERIFIER"]


@pytest.mark.parametrize("kind", ["DEFINITION", "INSTANCE", "RUN"])
def test_exact_experimental_wire_references_do_not_admit_namespace_objects(kind: str) -> None:
    from verifier.domains.certification import domain_request
    gate = _gate()
    token = named("ENVIRONMENT-" + kind + "-0.1")
    assert gate.admissible(token), "exact migration reference preserves existing external bytes"
    assert "ENVIRONMENT" not in gate.OBJECTS
    assert not gate.admissible(named("ENVIRONMENT-" + kind + "-0.2"))
    assert not gate.admissible(named("ENVIRONMENT"))
    with pytest.raises(ValueError, match="unknown domain"):
        domain_request({"schema_version": "verifier-domain-evidence-1", "domain": "ENVIRONMENT",
                        "subject_id": "example:boundary", "artifact": {}, "inputs": {}})
