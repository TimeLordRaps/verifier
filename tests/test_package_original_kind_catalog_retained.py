"""Boundaries for the retained 27-row, 25-kind source-bound applicability audit.

Pinned totals describe the reviewed working-tree bytes recorded in the module.
Any changed cell, owned-file digest, or owned path must be re-audited and the
pins updated in the same change; a drifted digest fails closed.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from verifier.runtime import namespace_manifest
from verifier.runtime.package_original_kind_catalog_retained import (
    RETAINED_ORIGINAL_KIND_AUDITS,
    RETAINED_PARTIAL_PROFILE,
    UNRESOLVED,
    _cell,
    _record,
    refutation_line_is_substantive,
    review_document,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    owned_path_set_digest,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS


ROOT = Path(__file__).parents[1]
PINNED_APPLIES = 657
PINNED_DOES_NOT_APPLY = 18
PINNED_UNRESOLVED = 0
# A cited line that is only a label, comment or import carries no semantics of the kind.
REFERENT_ONLY_LINE = re.compile(
    r"""^\s*(?:[A-Z][A-Z0-9_]*\s*(?::[^=]+)?=\s*["']|#|import\s|from\s+\S+\s+import\s)"""
)
# Manifest operands are namespace data, not owned source: a refutation whose
# text requires an operand is rejected, because it cannot be grounded in code.
OPERAND_REFUTATION = re.compile(r"\b(requires?|needs?)\b[^.;]*\boperands?\b", re.I)


def _rows_by_id():
    return {row.object_id: row for row in RETAINED_ORIGINAL_KIND_AUDITS}


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _stale_paths(row, root: Path = ROOT) -> list[str]:
    stale = []
    for path, recorded in zip(row.expected_owned_paths, row.source_sha256):
        target = root / path
        if not target.is_file() or _sha256(target) != recorded:
            stale.append(path)
    return stale


def test_audit_has_exact_27_rows_each_with_25_ordered_cells():
    rows = _rows_by_id()
    assert len(rows) == len(RETAINED_ORIGINAL_KIND_AUDITS) == 27
    assert not set(rows).intersection(spec.object_id for spec in SEMANTIC_OWNERSHIP_SPECS)
    for row in rows.values():
        assert tuple(question.kind for question in row.questions) == ORIGINAL_NON_OBJECT_KINDS
        assert len(row.questions) == 25
        assert len(row.source_sha256) == len(row.expected_owned_paths)


def test_status_totals_are_pinned_to_the_reviewed_audit():
    statuses = [
        question.status
        for row in RETAINED_ORIGINAL_KIND_AUDITS
        for question in row.questions
    ]
    assert len(statuses) == 27 * 25
    assert statuses.count(APPLIES) == PINNED_APPLIES
    assert statuses.count(DOES_NOT_APPLY) == PINNED_DOES_NOT_APPLY
    assert statuses.count(UNRESOLVED) == PINNED_UNRESOLVED


def test_primary_kind_is_never_refuted_and_event_primary_is_conservatively_retained():
    rows = _rows_by_id()
    for row in rows.values():
        primary = [q for q in row.questions if q.kind == row.expected_primary]
        if primary:
            assert primary[0].status != DOES_NOT_APPLY, row.object_id
    event = [q for q in rows["vstd-event"].questions if q.kind == "EVENT"][0]
    assert event.status == APPLIES
    assert "reasons.vstd retains EVENT" in event.reason


@pytest.mark.parametrize(("kind", "boundary"), [
    ("EVENT", "no real-world event occurrence is claimed"),
    ("MODEL", "no model inference or execution is claimed"),
    ("SIM", "no simulation execution is claimed"),
])
def test_architecture_retains_obligations_for_unclosed_evaluation(kind, boundary):
    event = next(
        question
        for question in _rows_by_id()["vstd-architecture"].questions
        if question.kind == kind
    )

    assert event.status == APPLIES
    assert event.path == "src/verifier/domains/contracts/arch_resolution.py"
    assert event.line == 624
    assert "VerificationSession.evaluate" in event.reason
    assert boundary in event.reason


@pytest.mark.parametrize("kind", ["ACTOR", "OWNER"])
def test_hypergraph_retains_obligations_for_unclosed_evaluation(kind):
    question = next(q for q in _rows_by_id()["vstd-hypergraph"].questions if q.kind == kind)
    assert question.status == APPLIES
    assert question.path == "src/verifier/domains/contracts/hyper_closure.py"
    assert question.line == 387
    assert "VerificationSession.evaluate" in question.reason


def test_every_source_bound_cell_cites_an_owned_nonblank_line():
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.status == UNRESOLVED:
                assert question.path is None and question.line is None
                continue
            if question.path is None:
                assert row.object_id == "vstd-package-object"
                assert question.line is None
                assert "sole reasons.vstd conservatively retains" in question.reason
                continue
            assert question.path in row.expected_owned_paths, row.object_id
            assert question.line is not None, (row.object_id, question.kind)
            lines = (ROOT / question.path).read_text(encoding="utf-8").splitlines()
            assert 1 <= question.line <= len(lines), (row.object_id, question.kind)
            assert lines[question.line - 1].strip(), (row.object_id, question.kind)


def test_every_reason_is_nonblank_bounded_and_unique_within_its_row():
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        reasons = [question.reason for question in row.questions]
        assert all(reason.strip() and len(reason) <= 260 for reason in reasons)
        assert len(set(reasons)) == len(reasons), row.object_id


def test_refutations_do_not_rest_on_manifest_operands():
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.status == DOES_NOT_APPLY:
                assert OPERAND_REFUTATION.search(question.reason) is None, (
                    row.object_id,
                    question.kind,
                )


def test_owned_path_sets_match_current_manifest_and_digests():
    _raw, manifest = namespace_manifest.read_manifest(ROOT / "objects.vstd")
    manifest_rows = {row["object_id"]: row for row in manifest["namespace"]["objects"]}
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        paths = tuple(
            sorted(
                surface.removeprefix("file:")
                for surface in manifest_rows[row.object_id]["surfaces"]
                if surface.startswith("file:")
            )
        )
        assert paths == row.expected_owned_paths
        assert owned_path_set_digest(paths) == row.expected_owned_path_set_digest


def test_source_drift_makes_recorded_decisions_stale():
    stale = {row.object_id: _stale_paths(row) for row in RETAINED_ORIGINAL_KIND_AUDITS}
    assert {key: value for key, value in stale.items() if value} == {}


def test_drift_checker_detects_one_changed_byte(tmp_path):
    row = _rows_by_id()["vstd-time"]
    for path in row.expected_owned_paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / path).read_bytes())
    assert _stale_paths(row, tmp_path) == []
    victim = tmp_path / row.expected_owned_paths[0]
    victim.write_bytes(victim.read_bytes() + b" ")
    assert _stale_paths(row, tmp_path) == [row.expected_owned_paths[0]]


def test_atomicity_rejects_short_misordered_or_unsupported_rows():
    base = RETAINED_ORIGINAL_KIND_AUDITS[1]
    ordered = [
        _cell(question.kind, question.status, None, None, question.reason)
        if question.status == UNRESOLVED
        else _cell(question.kind, question.status, 0, 2, question.reason)
        for question in base.questions
    ]
    with pytest.raises(AssertionError, match="order or denominator differs"):
        _record("bad-short", "ACTOR", ("a.py",), ("sha256:00",), "scope", tuple(ordered[:24]))
    with pytest.raises(AssertionError, match="order or denominator differs"):
        _record("bad-order", "ACTOR", ("a.py",), ("sha256:00",), "scope", tuple(reversed(ordered)))
    with pytest.raises(AssertionError, match="cell cites a path it does not own"):
        bad = list(ordered)
        bad[0] = _cell("ACTOR", APPLIES, 3, 1, "reason")
        _record("bad-path", "ACTOR", ("a.py",), ("sha256:00",), "scope", tuple(bad))
    with pytest.raises(AssertionError, match="UNRESOLVED cell cites evidence"):
        bad = list(ordered)
        bad[1] = _cell("AGENT", UNRESOLVED, 0, 1, "reason")
        _record("bad-open", "ACTOR", ("a.py",), ("sha256:00",), "scope", tuple(bad))
    with pytest.raises(AssertionError, match="refutes its own primary kind"):
        bad = list(ordered)
        bad[0] = _cell("ACTOR", DOES_NOT_APPLY, 0, 2, "reason")
        _record("bad-primary", "ACTOR", ("a.py",), ("sha256:00",), "scope", tuple(bad))
    with pytest.raises(AssertionError, match="source digest count"):
        _record("bad-digest", "ACTOR", ("a.py", "b.py"), ("sha256:00",), "scope", tuple(ordered))


def test_partial_profile_is_sealed_and_carries_exactly_the_decided_cells():
    assert validate_profile(RETAINED_PARTIAL_PROFILE) is RETAINED_PARTIAL_PROFILE
    assert len(RETAINED_PARTIAL_PROFILE.assignments) == 27
    decided = sum(len(assignment.decisions) for assignment in RETAINED_PARTIAL_PROFILE.assignments)
    assert decided == PINNED_APPLIES + PINNED_DOES_NOT_APPLY
    assert all(
        decision.status in {APPLIES, DOES_NOT_APPLY}
        for assignment in RETAINED_PARTIAL_PROFILE.assignments
        for decision in assignment.decisions
    )


def test_full_closure_accepts_the_complete_explicit_matrix():
    ids = tuple(row.object_id for row in RETAINED_ORIGINAL_KIND_AUDITS)
    assert validate_full_closure(
        RETAINED_PARTIAL_PROFILE,
        ids,
        expected_object_count=27,
    ) is RETAINED_PARTIAL_PROFILE


def test_review_document_exposes_every_cell_with_its_evidence_binding():
    document = review_document()
    assert len(document) == 27
    statuses = [
        decision["status"]
        for row in document.values()
        for decision in row["questions"].values()
    ]
    assert statuses.count(APPLIES) == PINNED_APPLIES
    assert statuses.count(DOES_NOT_APPLY) == PINNED_DOES_NOT_APPLY
    assert statuses.count(UNRESOLVED) == PINNED_UNRESOLVED
    for row in document.values():
        assert len(row["source_sha256"]) == len(row["expected_owned_paths"])
        for decision in row["questions"].values():
            if decision["status"] == UNRESOLVED:
                assert decision["path"] is None and decision["line"] is None
            elif decision["path"] is None:
                assert "sole reasons.vstd conservatively retains" in decision["reason"]
                assert decision["line"] is None
            else:
                assert decision["path"] in row["expected_owned_paths"]
                assert decision["line"] >= 1


def _line_text(question) -> str:
    """Return the exact owned line a decided cell cites."""
    assert question.path is not None and question.line is not None, question.kind
    return (ROOT / question.path).read_text(encoding="utf-8").splitlines()[question.line - 1]


def _cited_line(row_id: str, kind: str) -> tuple[str, str]:
    """Return (status, exact cited text) for one decided cell."""
    question = next(q for q in _rows_by_id()[row_id].questions if q.kind == kind)
    if question.path is None:
        return question.status, ""
    return question.status, _line_text(question)


def _status(row_id: str, kind: str) -> str:
    return next(q for q in _rows_by_id()[row_id].questions if q.kind == kind).status


def test_referent_only_lines_are_detected_and_never_cited_as_evidence():
    """Bad fixtures: label, comment and import lines are referents, not semantics."""
    assert REFERENT_ONLY_LINE.match('MECHANISM_ID = "verifier.current-role.finite.1"')
    assert REFERENT_ONLY_LINE.match("# Conversely, absent inventory cannot erase a FAIL.")
    assert REFERENT_ONLY_LINE.match("import hashlib")
    assert REFERENT_ONLY_LINE.match("from verifier.domains import common")
    # Good fixture: a real decision line is not a referent.
    assert REFERENT_ONLY_LINE.match("    covered = {(case) for case in cases}") is None
    assert REFERENT_ONLY_LINE.match("def _evaluate(data: bytes) -> MechanismDecision:") is None
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.status == UNRESOLVED or question.path is None:
                continue
            text = _line_text(question)
            assert REFERENT_ONLY_LINE.match(text) is None, (row.object_id, question.kind, text)


def test_flagged_classes_distinguish_source_and_reason_only_retention():
    """Both retention routes keep obligations without inventing a refutation."""
    assert all(
        question.status != UNRESOLVED
        for row in RETAINED_ORIGINAL_KIND_AUDITS
        for question in row.questions
    )
    keeps = [
        ("vstd-event", "EVENT"),
        ("vstd-collective", "ACTOR"),
        ("vstd-human", "IDENTITY"),
        ("vstd-receipt", "HARDWARE"),
        ("vstd-harness", "HYPER"),
        ("vstd-model", "TIME"),
        ("vstd-training", "TIME"),
        ("vstd-hypergraph", "SPACE"),
        ("vstd-model", "GRAPH"),
        ("vstd-model", "HYPER"),
        ("vstd-model", "RECEIPT"),
        ("vstd-token", "GRAPH"),
        ("vstd-token", "HYPER"),
        ("vstd-token", "RECEIPT"),
        ("vstd-package-object", "TIME"),
        ("vstd-package-object", "SPACE"),
        ("vstd-package-object", "IDENTITY"),
        ("vstd-package-object", "EVENT"),
        ("vstd-package-object", "DATA"),
    ]
    for row_id, kind in keeps:
        assert _status(row_id, kind) == APPLIES, (row_id, kind)
    assert _status("vstd-human", "GRAPH") == APPLIES


def test_recited_and_flipped_cells_bind_to_the_structure_they_claim():
    """Each re-cited or flipped citation must still show the claimed structure."""
    for row_id, kind, needle in (
        ("vstd-role", "GRAPH", "unselected state"),
        ("vstd-training", "GRAPH", '"parent"'),
        ("vstd-time", "HYPER", "_child(value, request)"),
        ("vstd-simulation", "VERIFIER", "def evaluate"),
    ):
        status, line = _cited_line(row_id, kind)
        assert needle in line, (row_id, kind, line)
        assert status in {APPLIES, DOES_NOT_APPLY}, (row_id, kind)


def test_env_applies_never_rest_on_a_checkers_own_pin():
    """Failure class: a checker's module-digest pin is not the subject's execution environment."""
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.kind != "ENV" or question.status != APPLIES:
                continue
            text = _line_text(question)
            assert "mechanism_digest" not in text, (row.object_id, text)


def test_package_object_retention_binds_the_owned_actuator_execution_boundary():
    """Open duties bind the owned backend run without claiming the effects occur."""
    row = _rows_by_id()["vstd-package-object"]
    for kind in ("TIME", "SPACE", "IDENTITY", "EVENT", "GRAPH"):
        question = next(question for question in row.questions if question.kind == kind)
        assert question.status == APPLIES
        assert question.path == "src/verifier/domains/contracts/actuator_physical.py"
        assert question.line == 622
        assert "injected ActuatorBackend run" in question.reason
        assert "no such effect, authority or checker PASS is claimed" in question.reason


def test_flip_targets_are_owned_by_their_rows():
    """Flipped APPLIES cells must cite a path the row actually owns."""
    for row_id, kind in (("vstd-role", "GRAPH"), ("vstd-training", "GRAPH")):
        question = next(q for q in _rows_by_id()[row_id].questions if q.kind == kind)
        assert question.path in _rows_by_id()[row_id].expected_owned_paths, (row_id, kind)


# Adversarial fixture: a named subject in a line-1 docstring, a primary-kind declaration,
# imports, a callback, a synonym, and an empty marker. None of these may refute a kind.
FIXTURE = '''"""Subject is an AGENT trajectory with a bot callback and a person alias."""
import verifier.domains.bot as bot_loop
from verifier.domains import human as person
# callback and person are synonyms here, not evidence
SUBJECT_KIND = "AGENT"
PAYLOAD = {
    "subject_kind": "AGENT",
}


def callback_step(value):
    pass
    if value is None:
        raise ValueError("absent")
'''


def test_every_live_refutation_cites_a_substantive_non_docstring_line():
    for row in RETAINED_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.status != DOES_NOT_APPLY:
                continue
            assert question.line != 1, (row.object_id, question.kind)
            assert question.path is not None and question.line is not None, (row.object_id, question.kind)
            assert refutation_line_is_substantive(ROOT, question.path, question.line), (
                row.object_id,
                question.kind,
                question.path,
                question.line,
            )


def test_named_module_docstring_cannot_refute_an_unrelated_role():
    """A line-1 docstring naming AGENT is a primary label; it cannot refute BOT."""
    cells = tuple(
        _cell(kind, DOES_NOT_APPLY, 0, 1, "Subject is an AGENT trajectory (subject.py:1).")
        if kind == "BOT"
        else _cell(kind, UNRESOLVED, None, None, "UNRESOLVED: " + kind + " remains open.")
        for kind in ORIGINAL_NON_OBJECT_KINDS
    )
    with pytest.raises(AssertionError, match="cites line 1"):
        _record("fixture-docstring", "AGENT", ("subject.py",), ("sha256:00",), "scope", cells)


def test_primary_declaration_and_empty_marker_lines_are_not_substantive(tmp_path):
    """Named module, primary-kind declaration, pass and comment lines are referents only."""
    (tmp_path / "subject.py").write_text(FIXTURE, encoding="utf-8")
    for line in (1, 2, 3, 4, 5, 7, 12):
        assert not refutation_line_is_substantive(tmp_path, "subject.py", line), line
    for line in (13, 14):
        assert refutation_line_is_substantive(tmp_path, "subject.py", line), line
    assert not refutation_line_is_substantive(tmp_path, "subject.py", 99)


def test_callback_and_synonym_counterexamples_cannot_be_cited_as_evidence(tmp_path):
    """An import of another kind's module, a docstring callback, or a comment synonym is not evidence."""
    (tmp_path / "subject.py").write_text(FIXTURE, encoding="utf-8")
    assert not refutation_line_is_substantive(tmp_path, "subject.py", 2)
    assert not refutation_line_is_substantive(tmp_path, "subject.py", 3)
    assert not refutation_line_is_substantive(tmp_path, "subject.py", 4)
    assert not refutation_line_is_substantive(tmp_path, "subject.py", 1)
