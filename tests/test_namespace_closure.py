"""Terminology: identifier (ID); Verifier Standard (VSTD).

The VSTD-NAMESPACE is closed, and this is what closes it.

`scripts/check_namespace_closure.py` is the gate; these tests keep the gate
honest.  A gate that passes but cannot fail would have admitted all 59 invented
heads just as silently as no gate at all, so the rejection path is asserted here
rather than checked once by hand.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from scripts import check_namespace_closure as namespace_gate

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_namespace_closure.py"


def named(tail: str) -> str:
    """Build an explicit namespace-adversary fixture.

    The gate recognizes this named constructor only as explicit test-fixture
    provenance.  It does not exempt this module, and bytes emitted into the
    temporary product trees below are scanned normally.
    """

    return namespace_gate.namespace_fixture_identifier(tail)


def _gate():
    return namespace_gate


def test_the_legacy_catalogue_carries_no_object_outside_the_nineteen() -> None:
    """Retained numbered profiles cannot silently add a current namespace kind."""

    found = _gate().catalogue_offenders()
    assert not found, "objects outside the closed VSTD-NAMESPACE: " + ", ".join(found)


def test_no_object_still_carries_the_prefix() -> None:
    found = _gate().residue_offenders()
    assert not found, "VSTD- prefixes that should be bare:\n" + "\n".join(
        f"  {relative}:{number}: {token}" for relative, number, token in found
    )


def test_historical_source_manifest_remains_part_of_the_product_surface(
    tmp_path: Path, monkeypatch
) -> None:
    """Generated text is scanned unless it has an explicitly excluded format."""
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
        ("docs/PR_SOURCE_FEATURES.json", retired),
        ("docs/PR_SOURCE_FEATURES.json", retired),
        ("docs/ordinary.json", retired),
        ("src/ordinary.py", retired),
    ]


def test_the_current_namespace_has_thirty_eight_objects_and_no_vstd_object() -> None:
    """The standard name is retained, while RECEIPT is the admitted object kind."""
    gate = _gate()
    assert len(gate.OBJECTS) == 38
    assert gate.OBJECTS == {
        "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
        "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
        "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
        "AGENT", "SIM", "BOT", "TOKEN",
        "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
        "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
    }
    assert "VSTD" not in gate.OBJECTS
    assert len(gate.LEGACY_WIRE_OBJECTS) == 26
    assert gate.LEGACY_WIRE_OBJECTS < gate.OBJECTS
    assert len(gate.LEGACY_DOMAIN_OBJECTS) == 19
    assert gate.LEGACY_DOMAIN_OBJECTS <= gate.LEGACY_WIRE_OBJECTS


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


@pytest.mark.parametrize(
    "tail",
    ["Graph-N", "Graph-1", "Graph-3", "Graph-5", "Graph-1..5", "Graph-1..VSTD-Graph-5"],
)
def test_preserves_the_separate_historical_graph_profile_axis(tail: str) -> None:
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


@pytest.mark.parametrize("tail", ["SOMETHING-1", "2-near-miss", "5-DRAFT"])
def test_reject_fixtures_do_not_lexically_authorize_their_pseudo_identifiers(
    tail: str,
) -> None:
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


def test_installed_non_object_identifiers_come_from_narrow_runtime_authorities() -> None:
    gate = _gate()
    installed = gate.installed_non_object_identifiers()
    assert named("T0.2-object-denominator-closure") in installed
    assert named("ENVIRONMENT-DEFINITION-0.1") in installed
    assert named("ENVIRONMENT-INSTANCE-0.1") in installed
    assert named("ENVIRONMENT-RUN-0.1") in installed
    assert named("SOMETHING-1") not in installed


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


TIER_ZERO_TAILS = (
    "T0.1-canonical-manifest-admission",
    "T0.2-object-denominator-closure",
    "T0.3-typed-relation-closure",
    "T0.4-exposed-surface-closure",
    "T0.5-obligation-denominator-closure",
    "T0.6-reason-and-realization-closure",
    "T0.7-source-and-mechanism-freshness",
    "T0.8-independent-implementation-agreement",
    "T0.9-conservative-verdict-and-authority-boundary",
)

# These once appeared in a hand-copied table, but they are not the names of the
# installed Tier-0 obligations.  Keep only tails here: this test module is itself
# part of the product surface scanned below, so rejected full tokens would be
# real residue rather than harmless fixtures.
WRONG_HAND_COPIED_TIER_ZERO_TAILS = (
    "T0.2-object-classification-and-applicability",
    "T0.3-typed-base-and-consequence-composition",
    "T0.4-exact-discovered-surface-coverage",
    "T0.5-extensible-obligation-denominator",
    "T0.6-reasons-and-source-bound-declarations",
    "T0.8-independent-declaration-reconciliation",
    "T0.9-conservative-assurance-boundary",
)


@pytest.mark.parametrize("tail", TIER_ZERO_TAILS)
def test_admits_each_canonical_tier_zero_obligation_identifier(tail: str) -> None:
    """Readable obligation identifiers are the registered public spelling of Tier 0."""

    assert _gate().admissible(named(tail))


@pytest.mark.parametrize("index", range(1, 10))
def test_admits_each_tier_zero_coordinate_bare(index: int) -> None:
    assert _gate().admissible(named(f"T0.{index}"))


def test_bare_tier_zero_family_prefix_does_not_admit_a_pseudo_identifier() -> None:
    gate = _gate()
    assert gate.admissible(named("T0"))
    assert not gate.admissible(named("T0.N-namespace-admission"))
    assert not gate.admissible(named("T0-harness-launch-denominator"))


def test_tier_zero_inventory_is_the_runtime_profile() -> None:
    """Runtime names and the normative document jointly define the readable IDs."""

    sys.path.insert(0, str(ROOT / "src"))
    from verifier.runtime.tier_zero_profile import installed_tier_zero_profile

    profile = installed_tier_zero_profile()
    runtime = {
        row["coordinate"] + "-" + re.sub(r"[^a-z0-9]+", "-", row["name"].lower()).strip("-")
        for row in profile["obligations"]
    }
    assert runtime == _gate().TIER_ZERO_OBLIGATIONS
    assert {named(f"T0.{index}") for index in range(1, 10)} == _gate().TIER_ZERO_COORDINATES

    specification = (ROOT / "src" / "verifier" / "standard" / "TIER_ZERO.md").read_text(
        encoding="utf-8"
    )
    for row in profile["obligations"]:
        assert f"`{row['coordinate']}` {row['name'].lower()}:" in specification


@pytest.mark.parametrize(
    "tail",
    [
        # missing slug: a dangling separator, or a truncated readable identifier
        "T0.7-", "T0.7-source", "T0.7-source-and-mechanism",
        # bad case
        "T0.7-Source-and-mechanism-freshness", "T0.7-SOURCE-AND-MECHANISM-FRESHNESS",
        "t0.7-source-and-mechanism-freshness",
        # whitespace and trailing punctuation
        "T0.7 -source-and-mechanism-freshness", "T0.7-source-and-mechanism-freshness ",
        " T0.7-source-and-mechanism-freshness", "T0.7-source-and-mechanism-freshness.",
        # extra separators
        "T0.7--source-and-mechanism-freshness", "T0.7-source--and-mechanism-freshness",
        "T0..7-source-and-mechanism-freshness", "T0.7.-source-and-mechanism-freshness",
        # wrong tiers, and a real slug paired with the wrong index
        "T0.0-source-and-mechanism-freshness", "T0.10-source-and-mechanism-freshness",
        "T1.7-source-and-mechanism-freshness", "T4.7-source-and-mechanism-freshness",
        "T4.1-canonical-manifest-admission", "T0.1-source-and-mechanism-freshness",
        "T0.7-canonical-manifest-admission",
        # unknown prefixes, index-less and forged slugs
        "X0.7-source-and-mechanism-freshness", "T-0.7-source-and-mechanism-freshness",
        "T0-harness-launch-denominator", "T0.N-namespace-admission",
        "T0.2-namespace-admission",
        "T0.7-made-up-admission",
        # an extension of a canonical identifier is a different identifier
        "T0.7-source-and-mechanism-freshness-v2", "T0.7-source-and-mechanism-freshness2",
    ],
)
def test_rejects_near_miss_tier_zero_identifiers(tail: str) -> None:
    assert not _gate().admissible(named(tail)), tail


@pytest.mark.parametrize("tail", WRONG_HAND_COPIED_TIER_ZERO_TAILS)
def test_rejects_hand_copied_tier_zero_slugs(tail: str) -> None:
    assert not _gate().admissible(named(tail)), tail


def test_residue_scan_flags_near_misses_and_embedded_identifiers_in_context(
    tmp_path: Path, monkeypatch
) -> None:
    """A canonical identifier in prose passes; the same text in a larger token does not."""

    canonical = named("T0.7-source-and-mechanism-freshness")
    docs = tmp_path / "docs"
    docs.mkdir()
    lines = [
        f"Run the focused gate for {canonical}.",
        f"{canonical}-extra",
        named("T0.7--source-and-mechanism-freshness"),
        "x" + canonical,
        named("T0.7-"),
    ]
    (docs / "ordinary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "--", "docs"], check=True)
    gate = _gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert gate.residue_offenders() == [
        ("docs/ordinary.md", 2, canonical + "-extra"),
        ("docs/ordinary.md", 3, named("T0.7--source-and-mechanism-freshness")),
        ("docs/ordinary.md", 4, "x" + canonical),
        ("docs/ordinary.md", 5, named("T0.7-")),
    ]


def test_residue_scan_covers_tracked_and_ordinary_nonignored_untracked_product_files(
    tmp_path: Path, monkeypatch
) -> None:
    """An untracked source, test, or document is product surface, not an exemption."""

    tracked = named("T0.2-namespace-admission")
    untracked_doc = named("T0-harness-launch-denominator")
    untracked_source = named("T0.4-namespace-admission")
    untracked_test = named("T0.N-namespace-admission")

    for directory in (
        "docs", "src", "tests", "ignored", "tmp", "scratch", "cache",
        ".pytest_cache", "assets", "schemas",
    ):
        (tmp_path / directory).mkdir()
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (tmp_path / "docs" / "tracked.md").write_text(tracked + "\n", encoding="utf-8")
    (tmp_path / "docs" / "untracked.md").write_text(untracked_doc + "\n", encoding="utf-8")
    (tmp_path / "src" / "untracked.py").write_text(untracked_source + "\n", encoding="utf-8")
    (tmp_path / "tests" / "untracked.txt").write_text(untracked_test + "\n", encoding="utf-8")

    excluded = named("T0.9-made-up-admission")
    (tmp_path / "ignored" / "ignored.md").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / "tmp" / "temporary.md").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / "scratch" / "fixture.md").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / "cache" / "cached.md").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / ".pytest_cache" / "state.md").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / "objects.vstd").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / "schemas" / "nested.vstd").write_text(excluded + "\n", encoding="utf-8")
    (tmp_path / "assets" / "image.png").write_bytes(excluded.encode("ascii"))
    (tmp_path / "assets" / "opaque.bin").write_bytes(b"\x00" + excluded.encode("ascii"))
    (tmp_path / "run.log").write_text(excluded + "\n", encoding="utf-8")

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "--", ".gitignore", "docs/tracked.md"],
        check=True,
    )
    gate = _gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert gate.residue_offenders() == [
        ("docs/tracked.md", 1, tracked),
        ("docs/untracked.md", 1, untracked_doc),
        ("src/untracked.py", 1, untracked_source),
        ("tests/untracked.txt", 1, untracked_test),
    ]


def test_historical_migration_ledger_does_not_authorize_ordinary_prose_or_tests(
    tmp_path: Path, monkeypatch
) -> None:
    """Only exact base-bound ledger context retains an old non-object identifier."""

    old_wire = named("OLD-WIRE-0.1")
    old_changelog = named("OLD-CHANGELOG-1")
    arbitrary = named("SOMETHING-1")
    (tmp_path / "src").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "legacy.py").write_text(
        f'SCHEMA_VERSION = "{old_wire}"\n', encoding="utf-8"
    )
    (tmp_path / "CHANGELOG.md").write_text(old_changelog + "\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "--", "src/legacy.py", "CHANGELOG.md"],
        check=True,
    )
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Verifier Test",
            "-c", "user.email=verifier" "@example.invalid", "commit", "--quiet",
            "-m", "historical base",
        ],
        check=True,
    )
    base = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    (tmp_path / "src" / "legacy.py").write_text(
        'SCHEMA_VERSION = "verifier-old-wire-1"\n', encoding="utf-8"
    )
    manifest = {
        "base": base,
        "files": [{
            "path": "src/legacy.py",
            "sha256": "0" * 64,
            "symbols": ["SCHEMA_VERSION"],
            "summary": f"Respells the old schema from {old_wire} to verifier-old-wire-1.",
            "limits": "Historical bytes only.",
        }],
    }
    (tmp_path / "docs" / "PR_SOURCE_FEATURES.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (tmp_path / "docs" / "ordinary.md").write_text(
        f'Claimed schema_version: {old_wire}\nForged: {arbitrary}\n', encoding="utf-8"
    )
    (tmp_path / "tests" / "ordinary.py").write_text(
        f'SCHEMA_VERSION = "{old_wire}"\n', encoding="utf-8"
    )

    gate = _gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert gate.residue_offenders() == [
        ("docs/ordinary.md", 1, old_wire),
        ("docs/ordinary.md", 2, arbitrary),
        ("tests/ordinary.py", 1, old_wire),
    ]


def test_no_tier_four_spelling_is_admitted_under_any_slug() -> None:
    """Only Tier 0 has readable obligation identifiers in this gate; Tier 4 is excluded."""

    gate = _gate()
    for tail in TIER_ZERO_TAILS:
        assert not gate.admissible(named("T4" + tail[2:])), tail
    for index in range(1, 10):
        assert not gate.admissible(named(f"T4.{index}")), index


SELECTOR_TAIL = "T0.2-namespace-admission"
SELECTOR_SLOT_CONTEXTS = {
    "positional assess_gate": 'assess_gate("accounts.py", "SELECTOR", root)\n',
    "positional assess_object_gate": 'manifest_gate.assess_object_gate(graph_id, "SELECTOR", root)\n',
    "obligation_id keyword": 'finding = _finding(code, object_id="accounts.py", obligation_id="SELECTOR")\n',
    "rerun_argv expected selector": 'argv = ["vstd", "gate", "--object", "accounts.py", "--obligation", "SELECTOR"]\n',
    "mapping with obligation_id key": 'row = {"obligation_id": "SELECTOR", "status": "PASS"}\n',
    "comparison with obligation_id subscript": 'assert finding["obligation_id"] == "SELECTOR"\n',
    "single-name parametrize": (
        '@pytest.mark.parametrize("obligation_id", ["SELECTOR"])\n'
        'def test_row(obligation_id):\n    pass\n'
    ),
    "row parametrize": (
        '@pytest.mark.parametrize("object_id, obligation_id", [("accounts.py", "SELECTOR")])\n'
        'def test_row(object_id, obligation_id):\n    pass\n'
    ),
    "iterated obligation list": 'ids = ["SELECTOR"]\nfindings = [_finding(code, obligation_id=item) for item in ids]\n',
    "concatenated obligation argument": 'assess_gate("accounts.py", "' + named("T0.2") + '" + "-namespace-admission", root)\n',
}
OBJECT_IDENTITY_CONTEXTS = {
    "object_id keyword": 'finding = _finding(code, object_id="SELECTOR")\n',
    "positional object argument": 'assess_gate("SELECTOR", "accounts.py", root)\n',
    "selected object keyword": 'report = build(selected_object="SELECTOR")\n',
    "graph node identity": 'node = {"node_id": "SELECTOR", "kind": "OBJECT"}\n',
    "manifest object identifier": 'manifest = {"objects": [{"object_id": "SELECTOR"}]}\n',
    "unrelated gate call": 'other_gate("accounts.py", "SELECTOR")\n',
    "object key in iterated list": 'ids = ["SELECTOR"]\nrows = [build(object_id=item) for item in ids]\n',
    "concatenated object identifier": 'row = {"object_id": "' + named("T0.2") + '" + "-namespace-admission"}\n',
    "escaped object identifier": 'row = {"object_id": "VSTD\x2d' + SELECTOR_TAIL + '"}\n',
    "comment": '# the SELECTOR gate\n',
    "docstring": '"""Runs the SELECTOR gate."""\n',
    "unparseable source": 'def broken(:\n    assess_gate("accounts.py", "SELECTOR", root)\n',
}


def _residue_in(tmp_path: Path, monkeypatch, relative: str, text: str):
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    gate = _gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    return gate.residue_offenders()


def test_registered_obligation_selectors_are_the_runtime_namespace_admission_family() -> None:
    """Selectors come from the runtime registry and are never prose-admissible tokens."""

    from verifier.runtime.manifest_gate import _admission_identities

    gate = _gate()
    runtime = {key for key in _admission_identities() if key.endswith("-namespace-admission")}
    assert gate.registered_obligation_selectors() == runtime
    assert len(runtime) == 9, "one selector per Tier-0 coordinate T0.1 through T0.9"
    assert not any(gate.admissible(selector) for selector in runtime)


@pytest.mark.parametrize("context", sorted(SELECTOR_SLOT_CONTEXTS))
def test_a_registered_selector_is_admitted_in_an_obligation_slot(
    context: str, tmp_path: Path, monkeypatch
) -> None:
    text = SELECTOR_SLOT_CONTEXTS[context].replace("SELECTOR", named(SELECTOR_TAIL))
    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", text) == [], context


@pytest.mark.parametrize("context", sorted(OBJECT_IDENTITY_CONTEXTS))
def test_the_same_selector_is_refused_as_an_object_identity(
    context: str, tmp_path: Path, monkeypatch
) -> None:
    text = OBJECT_IDENTITY_CONTEXTS[context].replace("SELECTOR", named(SELECTOR_TAIL))
    found = _residue_in(tmp_path, monkeypatch, "src/subject.py", text)
    assert found, context
    assert {token for _, _, token in found} <= {named(SELECTOR_TAIL)}, context


def test_a_selector_in_prose_or_markdown_is_refused_fail_closed(tmp_path: Path, monkeypatch) -> None:
    text = "Rerun with --obligation " + named(SELECTOR_TAIL) + " after the gate.\n"
    assert _residue_in(tmp_path, monkeypatch, "docs/rerun.md", text) == [
        ("docs/rerun.md", 1, named(SELECTOR_TAIL)),
    ]


@pytest.mark.parametrize("coordinate", range(1, 10))
def test_every_registered_coordinate_is_slot_admitted_and_object_refused(
    coordinate: int, tmp_path: Path, monkeypatch
) -> None:
    selector = named(f"T0.{coordinate}-namespace-admission")
    slot = 'assess_gate("accounts.py", "' + selector + '", root)\n'
    identity = 'row = {"object_id": "' + selector + '"}\n'
    assert _residue_in(tmp_path, monkeypatch, "src/slot.py", slot) == []
    assert _residue_in(tmp_path, monkeypatch, "src/identity.py", identity) == [
        ("src/identity.py", 1, selector),
    ]


def test_count_preserving_substitution_moves_the_offender_to_its_true_location(
    tmp_path: Path, monkeypatch
) -> None:
    """Same number of selectors: a swapped argument is still found, at its own line."""

    selector = named(SELECTOR_TAIL)
    lawful = (
        'assess_gate("accounts.py", "' + selector + '", root)\n'
        'assess_gate("accounts.py", "' + selector + '", root)\n'
    )
    swapped = (
        'assess_gate("accounts.py", "' + selector + '", root)\n'
        'assess_gate("' + selector + '", "accounts.py", root)\n'
    )
    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", lawful) == []
    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", swapped) == [
        ("src/subject.py", 2, selector),
    ]


def test_same_line_substitution_is_located_per_occurrence(tmp_path: Path, monkeypatch) -> None:
    selector = named(SELECTOR_TAIL)
    text = (
        'assess_gate("accounts.py", "' + selector + '", root); '
        'assess_gate("' + selector + '", "accounts.py", root)\n'
    )
    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", text) == [
        ("src/subject.py", 1, selector),
    ]


def test_constant_helper_dataflow_cannot_hide_a_tier_zero_identity(
    tmp_path: Path, monkeypatch
) -> None:
    """A pure helper call must be scanned as the exact string it returns."""

    token = named("T0.2-namespace-admisson")
    prefix, tail = token[:5], token[5:]
    source = (
        "def _unregistered(tail: str) -> str:\n"
        f'    return "{prefix}" + tail\n'
        f'row = {{"object_id": _unregistered("{tail}")}}\n'
    )

    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", source) == [
        ("src/subject.py", 3, token),
    ]


def test_constant_helper_dataflow_keeps_slot_and_identity_semantics(
    tmp_path: Path, monkeypatch
) -> None:
    selector = named(SELECTOR_TAIL)
    prefix, tail = selector[:5], selector[5:]
    helper = (
        "def selector(tail: str) -> str:\n"
        f'    prefix = "{prefix}"\n'
        "    return prefix + tail\n"
    )
    lawful = helper + f'assess_gate("accounts.py", selector("{tail}"), root)\n'
    object_use = helper + f'row = {{"object_id": selector("{tail}")}}\n'

    assert _residue_in(tmp_path, monkeypatch, "src/lawful.py", lawful) == []
    assert _residue_in(tmp_path, monkeypatch, "src/object_use.py", object_use) == [
        ("src/object_use.py", 4, selector),
    ]


@pytest.mark.parametrize(
    "tail",
    [
        "T0.N-namespace-admission",
        "T0.2-namespace-admisson",
        "T0.2-namespace-admission-extra",
    ],
)
def test_token_splicing_does_not_admit_unknown_tier_zero_names(
    tail: str, tmp_path: Path, monkeypatch
) -> None:
    token = named(tail)
    prefix, remainder = token[:5], token[5:]
    source = (
        'parts = ["' + prefix[:-1] + '", "' + prefix[-1] + '", "' + remainder + '"]\n'
        'row = {"object_id": "".join(parts)}\n'
    )
    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", source) == [
        ("src/subject.py", 2, token),
    ]


def test_fixture_constructor_is_not_an_escape_outside_tests(
    tmp_path: Path, monkeypatch
) -> None:
    token = named("T0.2-namespace-admisson")
    source = (
        "from scripts.check_namespace_closure import namespace_fixture_identifier\n"
        'row = {"object_id": namespace_fixture_identifier("T0.2-namespace-admisson")}\n'
    )
    assert _residue_in(tmp_path, monkeypatch, "src/subject.py", source) == [
        ("src/subject.py", 2, token),
    ]


def test_residue_finding_reports_token_and_reason(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    token = named("T0.2-namespace-admisson")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "subject.py").write_text(
        'row = {"object_id": namespace_fixture_identifier("T0.2-namespace-admisson")}\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    gate = _gate()
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert gate.residue_findings() == [
        (
            "src/subject.py",
            1,
            token,
            "unregistered Tier-0 obligation-shaped identifier",
        ),
    ]
    assert gate.main() == 1
    printed = capsys.readouterr().out
    assert (
        f"src/subject.py:1: {token} -- "
        "unregistered Tier-0 obligation-shaped identifier"
    ) in printed
