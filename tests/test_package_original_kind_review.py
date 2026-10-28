"""Fail-closed tests for explicit original-kind review profiles."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from verifier.runtime import package_original_kind_review as review
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindDecision,
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    owned_path_set_digest,
    profile_document,
    seal_profile,
    validate_full_closure,
    validate_profile,
)


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _decision(
    kind: str,
    status: str = DOES_NOT_APPLY,
) -> OriginalKindDecision:
    return OriginalKindDecision(
        kind,
        status,
        (
            "The exact reviewed source has an explicit "
            + kind
            + " boundary; this decision does not infer from a name or omission."
        ),
    )


def _assignment(
    object_id: str = "vstd-example",
    *,
    primary: str = "OBJECT",
    path: str = "src/example.py",
    decisions: tuple[OriginalKindDecision, ...] = (),
) -> OriginalKindAssignment:
    paths = (path,)
    return OriginalKindAssignment(
        object_id=object_id,
        expected_primary=primary,
        expected_owned_paths=paths,
        expected_owned_path_set_digest=owned_path_set_digest(paths),
        scope_reason=(
            "This object-specific review covers only the exact example source "
            "and makes no statement about another object or later tier."
        ),
        decisions=tuple(sorted(decisions, key=lambda row: row.kind)),
    )


def _profile(*assignments: OriginalKindAssignment):
    return seal_profile(
        "test-original-kind-review",
        1,
        "Test-only exact source review; not package admission.",
        tuple(sorted(assignments, key=lambda row: row.object_id)),
    )


def _fixture(tmp_path: Path, *, primary: str = "OBJECT"):
    target = tmp_path / "src" / "example.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"VALUE = 1\n")
    files = {"src/example.py": _digest(target.read_bytes())}
    rows = {
        "vstd-example": {
            "object_id": "vstd-example",
            "kind": primary,
            "surfaces": ["file:src/example.py"],
            "specializations": [],
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "The question remains explicit and unanswered.",
                    "evidence": [],
                }
                for kind in ORIGINAL_NON_OBJECT_KINDS
            },
        }
    }
    return rows, files


def test_original_non_object_denominator_is_exact_and_does_not_include_object():
    assert len(ORIGINAL_NON_OBJECT_KINDS) == 25
    assert tuple(sorted(ORIGINAL_NON_OBJECT_KINDS)) == ORIGINAL_NON_OBJECT_KINDS
    assert "OBJECT" not in ORIGINAL_NON_OBJECT_KINDS


def test_partial_profile_does_not_generate_a_complement(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    profile = _profile(_assignment(decisions=(_decision("HUMAN"),)))

    result = review.apply_original_kind_profile(tmp_path, rows, files, profile)

    assert result["vstd-example"]["classification"]["HUMAN"]["status"] == DOES_NOT_APPLY
    assert result["vstd-example"]["classification"]["AGENT"]["status"] == "UNRESOLVED"
    assert rows["vstd-example"]["classification"]["HUMAN"]["status"] == "UNRESOLVED"


def test_full_closure_requires_every_literal_kind_and_object():
    decisions = tuple(
        _decision(kind, APPLIES if kind == "HUMAN" else DOES_NOT_APPLY)
        for kind in ORIGINAL_NON_OBJECT_KINDS
    )
    complete = _profile(
        _assignment("vstd-human", primary="HUMAN", decisions=decisions)
    )
    assert (
        validate_full_closure(
            complete, ("vstd-human",), expected_object_count=1
        )
        is complete
    )

    incomplete = _profile(
        _assignment(
            "vstd-human",
            primary="HUMAN",
            decisions=decisions[:-1],
        )
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_KIND_DENOMINATOR_INCOMPLETE:vstd-human",
    ):
        validate_full_closure(
            incomplete, ("vstd-human",), expected_object_count=1
        )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_EXPECTED_OBJECTS_INVALID",
    ):
        validate_full_closure(
            complete,
            ("vstd-human",),
            expected_object_count=VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
        )


def test_full_closure_refuses_to_refute_an_original_primary():
    profile = _profile(
        _assignment(
            "vstd-human",
            primary="HUMAN",
            decisions=tuple(
                _decision(kind) for kind in ORIGINAL_NON_OBJECT_KINDS
            ),
        )
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_PRIMARY_REFUTED:vstd-human",
    ):
        validate_full_closure(
            profile, ("vstd-human",), expected_object_count=1
        )


def test_profile_digest_binds_scope_paths_and_decisions():
    profile = _profile(_assignment(decisions=(_decision("HUMAN"),)))
    document = profile_document(profile)
    assert document["canonical_digest"] == profile.canonical_digest
    assert document["assignments"][0]["expected_owned_path_set_digest"].startswith(
        "sha256:"
    )
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_KIND_PROFILE_DIGEST_INVALID"
    ):
        validate_profile(replace(profile, claim_boundary="Changed boundary."))
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_OWNERSHIP_DIGEST_INVALID",
    ):
        _profile(
            replace(
                _assignment(decisions=(_decision("HUMAN"),)),
                expected_owned_path_set_digest="sha256:" + "0" * 64,
            )
        )


def test_positive_decision_may_bind_a_source_subset_but_refutation_may_not():
    paths = ("src/example.py", "src/support.py")
    assignment = OriginalKindAssignment(
        object_id="vstd-example",
        expected_primary="OBJECT",
        expected_owned_paths=paths,
        expected_owned_path_set_digest=owned_path_set_digest(paths),
        scope_reason="Both exact files form the reviewed owner boundary.",
        decisions=(
            OriginalKindDecision(
                "AGENT",
                APPLIES,
                "The example source contains the positive AGENT witness.",
                ("src/example.py",),
            ),
        ),
    )
    profile = _profile(assignment)
    assert profile_document(profile)["assignments"][0]["decisions"][0][
        "evidence_paths"
    ] == ["src/example.py"]

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_REFUTATION_EVIDENCE_INCOMPLETE",
    ):
        _profile(
            replace(
                assignment,
                decisions=(
                    OriginalKindDecision(
                        "AGENT",
                        DOES_NOT_APPLY,
                        "A refutation must cover the whole reviewed owner.",
                        ("src/example.py",),
                    ),
                ),
            )
        )


def test_positive_decision_emits_only_its_profile_bound_witness(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    support = tmp_path / "src" / "support.py"
    support.write_bytes(b"SUPPORT = 1\n")
    files["src/support.py"] = _digest(support.read_bytes())
    rows["vstd-example"]["surfaces"].append("file:src/support.py")
    paths = ("src/example.py", "src/support.py")
    assignment = OriginalKindAssignment(
        object_id="vstd-example",
        expected_primary="OBJECT",
        expected_owned_paths=paths,
        expected_owned_path_set_digest=owned_path_set_digest(paths),
        scope_reason="Both exact files form the reviewed owner boundary.",
        decisions=(
            OriginalKindDecision(
                "AGENT",
                APPLIES,
                "The example source contains the positive AGENT witness.",
                ("src/example.py",),
            ),
        ),
    )

    result = review.apply_original_kind_profile(
        tmp_path, rows, files, _profile(assignment)
    )

    assert result["vstd-example"]["classification"]["AGENT"]["evidence"] == [
        {"path": "src/example.py", "sha256": files["src/example.py"]}
    ]


@pytest.mark.parametrize("authority", ["source_applies", "consequence_applies"])
def test_source_and_consequence_authority_cannot_be_refuted(
    tmp_path: Path, authority: str
):
    rows, files = _fixture(tmp_path)
    profile = _profile(_assignment(decisions=(_decision("AGENT"),)))
    kwargs = {authority: {"vstd-example": ("AGENT",)}}
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_REFUTED:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path, rows, files, profile, **kwargs
        )


def test_known_required_role_cannot_be_omitted_from_partial_profile(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    profile = _profile(_assignment(decisions=(_decision("HUMAN"),)))
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_UNDECIDED:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            profile,
            source_applies={"vstd-example": ("AGENT",)},
        )


def test_record_policy_keeps_an_unestablished_primary_unresolved_and_names_it(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path, primary="HUMAN")
    profile = _profile(
        _assignment(primary="HUMAN", decisions=(_decision("AGENT"),))
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_UNDECIDED:vstd-example:HUMAN",
    ):
        review.apply_original_kind_profile(tmp_path, rows, files, profile)

    result = review.apply_original_kind_profile(
        tmp_path, rows, files, profile, unestablished_primary="record"
    )

    classification = result["vstd-example"]["classification"]
    assert classification["HUMAN"]["status"] == "UNRESOLVED"
    assert classification["HUMAN"]["evidence"] == []
    assert "HUMAN" in classification["HUMAN"]["reason"]
    assert "primary" in classification["HUMAN"]["reason"].lower()
    assert "test-original-kind-review" in classification["HUMAN"]["reason"]
    assert classification["AGENT"]["status"] == DOES_NOT_APPLY
    assert (
        rows["vstd-example"]["classification"]["HUMAN"]["reason"]
        == "The question remains explicit and unanswered."
    )


def test_record_policy_keeps_a_declared_primary_applies_and_marks_it_unsupported(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path, primary="HUMAN")
    declared = {
        "status": APPLIES,
        "reason": "The package object declares HUMAN as its primary original kind.",
        "evidence": [{"path": "src/example.py", "sha256": files["src/example.py"]}],
    }
    rows["vstd-example"]["classification"]["HUMAN"] = declared
    profile = _profile(
        _assignment(primary="HUMAN", decisions=(_decision("AGENT"),))
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_UNDECIDED:vstd-example:HUMAN",
    ):
        review.apply_original_kind_profile(tmp_path, rows, files, profile)

    result = review.apply_original_kind_profile(
        tmp_path, rows, files, profile, unestablished_primary="record"
    )

    cell = result["vstd-example"]["classification"]["HUMAN"]
    assert cell["status"] == APPLIES
    assert cell["evidence"] == declared["evidence"]
    assert cell["reason"].startswith(declared["reason"])
    assert "not yet supported by owned source" in cell["reason"]
    assert rows["vstd-example"]["classification"]["HUMAN"] == declared


def test_record_policy_forgives_nothing_but_the_primary_label(tmp_path: Path):
    rows, files = _fixture(tmp_path, primary="HUMAN")
    profile = _profile(
        _assignment(primary="HUMAN", decisions=(_decision("BOT"),))
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_UNDECIDED:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            profile,
            source_applies={"vstd-example": ("AGENT",)},
            unestablished_primary="record",
        )
    refuted = _profile(
        _assignment(primary="HUMAN", decisions=(_decision("HUMAN"),))
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_REFUTED:vstd-example:HUMAN",
    ):
        review.apply_original_kind_profile(
            tmp_path, rows, files, refuted, unestablished_primary="record"
        )


def test_primary_policy_value_is_closed(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_KIND_REVIEW_PRIMARY_POLICY_INVALID"
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            _profile(_assignment(decisions=(_decision("HUMAN"),))),
            unestablished_primary="ignore",
        )


def test_record_unreviewed_paths_joins_extra_paths_without_refuting_anything(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    rows["vstd-example"]["surfaces"].append("file:src/extra.py")
    profile = _profile(
        _assignment(decisions=(_decision("AGENT", APPLIES), _decision("BOT")))
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_OWNERSHIP_DIFFERS:vstd-example",
    ):
        review.apply_original_kind_profile(tmp_path, rows, files, profile)

    result = review.apply_original_kind_profile(
        tmp_path, rows, files, profile, unreviewed_paths="record"
    )

    classification = result["vstd-example"]["classification"]
    # A finding backed by cited lines survives extra files: they cannot weaken it.
    assert classification["AGENT"]["status"] == APPLIES
    assert [item["path"] for item in classification["AGENT"]["evidence"]] == [
        "src/example.py"
    ]
    assert "1 unreviewed owned path" in classification["AGENT"]["reason"]
    # A refutation is a closed-world claim over the reviewed set, so it reopens.
    assert classification["BOT"]["status"] == "UNRESOLVED"
    assert classification["BOT"]["evidence"] == []
    assert "src/extra.py" in classification["BOT"]["reason"]
    assert "reviewed" in classification["BOT"]["reason"]
    assert rows["vstd-example"]["classification"]["BOT"]["status"] == "UNRESOLVED"


def test_record_unreviewed_paths_never_forgives_a_missing_reviewed_path(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    rows["vstd-example"]["surfaces"] = ["file:src/other.py"]
    profile = _profile(_assignment(decisions=(_decision("AGENT", APPLIES),)))
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_OWNERSHIP_DIFFERS:vstd-example",
    ):
        review.apply_original_kind_profile(
            tmp_path, rows, files, profile, unreviewed_paths="record"
        )


def test_record_unreviewed_paths_still_refuses_to_refute_a_required_kind(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    rows["vstd-example"]["surfaces"].append("file:src/extra.py")
    profile = _profile(_assignment(decisions=(_decision("AGENT"),)))
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_REFUTED:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            profile,
            source_applies={"vstd-example": ("AGENT",)},
            unreviewed_paths="record",
        )


def test_unreviewed_paths_policy_value_is_closed(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_KIND_REVIEW_UNREVIEWED_POLICY_INVALID"
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            _profile(_assignment(decisions=(_decision("HUMAN"),))),
            unreviewed_paths="ignore",
        )


def test_primary_and_existing_applies_conflicts_hard_fail(tmp_path: Path):
    rows, files = _fixture(tmp_path, primary="HUMAN")
    primary_refutation = _profile(
        _assignment(
            primary="HUMAN",
            decisions=(_decision("HUMAN"),),
        )
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_REFUTED:vstd-example:HUMAN",
    ):
        review.apply_original_kind_profile(
            tmp_path, rows, files, primary_refutation
        )

    rows, files = _fixture(tmp_path / "other")
    rows["vstd-example"]["classification"]["AGENT"] = {
        "status": APPLIES,
        "reason": "A separate current source review requires AGENT.",
        "evidence": [],
    }
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_DECISION_CONFLICT:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path / "other",
            rows,
            files,
            _profile(_assignment(decisions=(_decision("AGENT"),))),
        )


def test_record_policy_lets_cited_applicability_supersede_a_prior_refutation(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    prior = {
        "status": DOES_NOT_APPLY,
        "reason": "The corpus owner is not itself an identity-bearing subject.",
        "evidence": [],
    }
    rows["vstd-example"]["classification"]["AGENT"] = prior
    profile = _profile(_assignment(decisions=(_decision("AGENT", APPLIES),)))
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_DECISION_CONFLICT:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(tmp_path, rows, files, profile)

    result = review.apply_original_kind_profile(
        tmp_path, rows, files, profile, superseded_refutations="record"
    )

    cell = result["vstd-example"]["classification"]["AGENT"]
    assert cell["status"] == APPLIES
    assert [item["path"] for item in cell["evidence"]] == ["src/example.py"]
    assert "Superseded refutation" in cell["reason"]
    assert prior["reason"] in cell["reason"]
    assert rows["vstd-example"]["classification"]["AGENT"] == prior


def test_record_policy_never_lets_a_refutation_supersede_prior_applicability(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    rows["vstd-example"]["classification"]["AGENT"] = {
        "status": APPLIES,
        "reason": "A separate current source review requires AGENT.",
        "evidence": [],
    }
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_DECISION_CONFLICT:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            _profile(_assignment(decisions=(_decision("AGENT"),))),
            superseded_refutations="record",
        )


def test_checked_documented_retention_allows_only_the_exact_source_reversal(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    prior = {
        "status": APPLIES,
        "reason": "A prior source review conservatively retained AGENT.",
        "evidence": [],
    }
    rows["vstd-example"]["classification"]["AGENT"] = prior
    profile = _profile(_assignment(decisions=(_decision("AGENT"),)))

    result = review.apply_original_kind_profile(
        tmp_path,
        rows,
        files,
        profile,
        superseded_refutations="record",
        documented_retention_keys=frozenset({("vstd-example", "AGENT")}),
    )

    cell = result["vstd-example"]["classification"]["AGENT"]
    assert cell["status"] == DOES_NOT_APPLY
    assert "checked reasons.vstd APPLIES retains this kind" in cell["reason"]
    assert rows["vstd-example"]["classification"]["AGENT"] == prior

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_DECISION_CONFLICT:vstd-example:AGENT",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            profile,
            superseded_refutations="record",
            documented_retention_keys=frozenset({("vstd-example", "MODEL")}),
        )


def test_superseded_refutation_policy_value_is_closed(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_KIND_REVIEW_SUPERSEDE_POLICY_INVALID"
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            _profile(_assignment(decisions=(_decision("HUMAN"),))),
            superseded_refutations="ignore",
        )


def test_prior_same_status_is_not_authority_and_is_replaced(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    rows["vstd-example"]["classification"]["AGENT"] = {
        "status": APPLIES,
        "reason": "Untrusted prior bytes.",
        "evidence": [],
    }
    profile = _profile(
        _assignment(decisions=(_decision("AGENT", APPLIES),))
    )

    result = review.apply_original_kind_profile(tmp_path, rows, files, profile)
    decision = result["vstd-example"]["classification"]["AGENT"]
    assert "Untrusted prior bytes" not in decision["reason"]
    assert profile.canonical_digest in decision["reason"]
    assert decision["evidence"] == [
        {"path": "src/example.py", "sha256": files["src/example.py"]}
    ]


def test_exact_owned_paths_and_current_file_census_are_required(tmp_path: Path):
    rows, files = _fixture(tmp_path)
    profile = _profile(_assignment(decisions=(_decision("AGENT", APPLIES),)))
    rows["vstd-example"]["surfaces"].append("file:src/extra.py")
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_OWNERSHIP_DIFFERS:vstd-example",
    ):
        review.apply_original_kind_profile(tmp_path, rows, files, profile)

    rows, files = _fixture(tmp_path / "other")
    files["src/example.py"] = "sha256:" + "0" * 64
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_SOURCE_DIFFERS:vstd-example:src/example.py",
    ):
        review.apply_original_kind_profile(
            tmp_path / "other", rows, files, profile
        )


def test_opening_and_closing_source_snapshots_must_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    rows, files = _fixture(tmp_path)
    profile = _profile(_assignment(decisions=(_decision("AGENT", APPLIES),)))
    actual = review._source_snapshot
    calls = 0

    def changed(root, assignment):
        nonlocal calls
        calls += 1
        snapshot = actual(root, assignment)
        if calls == 2:
            return ({**snapshot[0], "sha256": "sha256:" + "f" * 64},)
        return snapshot

    monkeypatch.setattr(review, "_source_snapshot", changed)
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_SOURCE_CHANGED:vstd-example",
    ):
        review.apply_original_kind_profile(tmp_path, rows, files, profile)


def test_full_closure_application_requires_explicit_expected_coordinate(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    profile = _profile(_assignment(decisions=(_decision("AGENT", APPLIES),)))
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_EXPECTED_OBJECTS_REQUIRED",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            profile,
            require_full_closure=True,
            expected_object_count=1,
        )


def test_full_closure_application_rejects_a_different_row_denominator(
    tmp_path: Path,
):
    rows, files = _fixture(tmp_path)
    decisions = tuple(
        _decision(kind, APPLIES if kind == "HUMAN" else DOES_NOT_APPLY)
        for kind in ORIGINAL_NON_OBJECT_KINDS
    )
    profile = _profile(
        _assignment("vstd-human", primary="HUMAN", decisions=decisions)
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_REVIEW_ROW_DENOMINATOR_DIFFERS",
    ):
        review.apply_original_kind_profile(
            tmp_path,
            rows,
            files,
            profile,
            require_full_closure=True,
            expected_object_ids=("vstd-human",),
            expected_object_count=1,
        )


def _write_sources(root: Path, sources: dict[str, bytes]) -> tuple[str, ...]:
    for relative, raw in sources.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return tuple(sources)


def _effect_blockers(audit) -> tuple[str, ...]:
    return audit.blockers


def test_closed_effect_audit_refuses_unsupported_languages(tmp_path: Path):
    paths = _write_sources(tmp_path, {"src/main.js": b"export const x = 1;\n"})

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert _effect_blockers(audit) == (
        "UNSUPPORTED_LANGUAGE:src/main.js",
    )
    assert audit.sources[0].sha256 == _digest(b"export const x = 1;\n")


def test_closed_effect_audit_reports_exact_syntax_error(tmp_path: Path):
    paths = _write_sources(tmp_path, {"broken.py": b"def nope(:\n    pass\n"})

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert any(
        blocker.startswith("PYTHON_SYNTAX_ERROR:broken.py:1:")
        for blocker in _effect_blockers(audit)
    )


def test_closed_effect_audit_rejects_local_import_outside_owned_closure(
    tmp_path: Path,
):
    paths = _write_sources(
        tmp_path,
        {
            "main.py": b"from helper import value\nRESULT = value()\n",
            "helper.py": b"def value():\n    return 1\n",
        },
    )

    audit = review.audit_closed_effects(tmp_path, (paths[0],))

    assert audit.status == "UNKNOWN"
    assert (
        "IMPORT_ESCAPES_OWNERSHIP:main.py:1:helper.py"
        in _effect_blockers(audit)
    )
    assert audit.imports[0].resolution == "PROJECT_LOCAL_OUTSIDE_OWNERSHIP"


def test_closed_effect_audit_checks_relative_submodule_not_only_package(
    tmp_path: Path,
):
    _write_sources(
        tmp_path,
        {
            "src/pkg/__init__.py": b"\n",
            "src/pkg/main.py": b"from . import hidden\nVALUE = hidden.value()\n",
            "src/pkg/hidden.py": b"def value():\n    return 1\n",
        },
    )

    audit = review.audit_closed_effects(
        tmp_path,
        ("src/pkg/__init__.py", "src/pkg/main.py"),
    )

    assert audit.status == "UNKNOWN"
    assert (
        "IMPORT_ESCAPES_OWNERSHIP:src/pkg/main.py:1:src/pkg/hidden.py"
        in audit.blockers
    )


@pytest.mark.parametrize(
    ("source", "operation"),
    [
        (b"import importlib\nVALUE = importlib.import_module('x')\n", "importlib.import_module"),
        (b"VALUE = eval('1 + 1')\n", "eval"),
        (b"exec('VALUE = 1')\n", "exec"),
    ],
)
def test_closed_effect_audit_exposes_dynamic_execution_uncertainty(
    tmp_path: Path, source: bytes, operation: str
):
    paths = _write_sources(tmp_path, {"dynamic.py": source})

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert any(
        blocker.startswith("DYNAMIC_EXECUTION_UNRESOLVED:dynamic.py:")
        and blocker.endswith(":" + operation)
        for blocker in audit.blockers
    )
    assert "dynamic_import_eval_exec_reflection" in {
        finding.channel for finding in audit.consequences
    }


def test_closed_effect_audit_exposes_indirect_injected_callback(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "callbacks.py": (
                b"def apply(callback, value):\n"
                b"    return list(map(callback, (value,)))\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert any(
        blocker.startswith("INJECTED_CALLABLE_UNRESOLVED:callbacks.py:2:callback")
        for blocker in audit.blockers
    )
    assert "callback_injected_callable" in {
        finding.channel for finding in audit.consequences
    }


def test_closed_effect_audit_resolves_alias_imports_and_effect_channels(
    tmp_path: Path,
):
    paths = _write_sources(
        tmp_path,
        {
            "aliases.py": (
                b"import os as operating\n"
                b"from json import dumps as encode\n"
                b"def render(value):\n"
                b"    return encode({'value': value, 'home': operating.getenv('HOME')})\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {call.target for call in audit.calls} >= {"json.dumps", "os.getenv"}
    assert {finding.channel for finding in audit.consequences} == {
        "environment",
        "serialization_message_boundary",
    }


def test_closed_effect_audit_enumerates_all_static_consequence_channels(
    tmp_path: Path,
):
    paths = _write_sources(
        tmp_path,
        {
            "effects.py": (
                b"import json\nimport mmap\nimport os\nimport random\n"
                b"import socket\nimport subprocess\nimport time\n"
                b"def effects():\n"
                b"    source = open('input.txt')\n"
                b"    data = source.read()\n"
                b"    target = open('output.txt', 'w')\n"
                b"    target.write(data)\n"
                b"    subprocess.run(())\n"
                b"    socket.socket()\n"
                b"    time.time()\n"
                b"    random.random()\n"
                b"    os.getenv('HOME')\n"
                b"    json.dumps(data)\n"
                b"    mmap.mmap(-1, 1)\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {finding.channel for finding in audit.consequences} == {
        "clock",
        "environment",
        "filesystem_read",
        "filesystem_write",
        "hardware_device",
        "network",
        "randomness",
        "serialization_message_boundary",
        "subprocess_process",
    }


def test_closed_effect_audit_closes_recursive_local_pure_source(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "main.py": (
                b"from helper import twice\n"
                b"def public_value(value):\n"
                b"    return twice(value) + abs(value)\n"
            ),
            "helper.py": b"def twice(value):\n    return value * 2\n",
        },
    )

    audit = review.audit_closed_effects(tmp_path, reversed(paths))

    assert audit.status == "CLOSED", audit.blockers
    assert audit.owned_paths == ("helper.py", "main.py")
    assert {definition.qualified_name for definition in audit.public_definitions} == {
        "helper.twice",
        "main.public_value",
    }
    assert {call.target for call in audit.calls} == {"abs", "helper.twice"}
    assert audit.consequences == ()


def test_closed_effect_audit_uses_a_static_builtin_type_registry(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "exceptions.py": (
                b"def failure(message):\n"
                b"    return ValueError(message), PermissionError(message)\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {
        (call.target, call.resolution) for call in audit.calls
    } == {
        ("ValueError", "PURE_BUILTIN_TYPE"),
        ("PermissionError", "PURE_BUILTIN_TYPE"),
    }
    assert audit.consequences == ()


def test_closed_effect_audit_closes_import_resolved_sha256_hexdigest(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "digest.py": (
                b"import hashlib\n"
                b"def digest(payload):\n"
                b"    return hashlib.sha256(payload).hexdigest()\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {
        (call.target, call.resolution) for call in audit.calls
    } == {
        ("hashlib.sha256", "PURE_STDLIB"),
        ("<dynamic-call-target>", "PURE_STDLIB_METHOD"),
    }
    assert audit.consequences == ()


def test_closed_effect_audit_closes_import_resolved_path_constructor_and_read(
    tmp_path: Path,
):
    paths = _write_sources(
        tmp_path,
        {
            "source.py": (
                b"from pathlib import Path\n"
                b"def source_bytes(filename):\n"
                b"    path = Path(filename)\n"
                b"    return path.read_bytes()\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {
        (call.target, call.resolution) for call in audit.calls
    } == {
        ("pathlib.Path", "PURE_STDLIB"),
        ("path.read_bytes", "ACCOUNTED_CONSEQUENCE"),
    }
    assert {finding.channel for finding in audit.consequences} == {
        "filesystem_read"
    }


def test_closed_effect_audit_rejects_unimported_path_lookalike(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "source.py": (
                b"def source_bytes(Path, filename):\n"
                b"    path = Path(filename)\n"
                b"    return path.read_bytes()\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert any(
        blocker.endswith(":Path") for blocker in audit.blockers
    )


def test_closed_effect_audit_types_import_resolved_json_dumps_result(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "encode.py": (
                b"import json\n"
                b"def encode(payload):\n"
                b"    return json.dumps(payload, sort_keys=True).encode('utf-8')\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {
        (call.target, call.resolution) for call in audit.calls
    } == {
        ("json.dumps", "ACCOUNTED_CONSEQUENCE"),
        ("<dynamic-call-target>", "PURE_BUILTIN_METHOD"),
    }
    assert {finding.channel for finding in audit.consequences} == {
        "serialization_message_boundary"
    }


def test_closed_effect_audit_closes_explicit_local_and_builtin_descriptors(
    tmp_path: Path,
):
    paths = _write_sources(
        tmp_path,
        {
            "record.py": (
                b"class Record:\n"
                b"    def digest(self):\n"
                b"        return 'sha256:value'\n"
                b"    def to_dict(self):\n"
                b"        value = Record.digest(self)\n"
                b"        return {'digest': value, 'valid': str.startswith(value, 'sha256:')}\n"
            )
        },
    )

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "CLOSED", audit.blockers
    assert {
        (call.target, call.resolution) for call in audit.calls
    } == {
        ("record.Record.digest", "OWNED_LOCAL_DEFINITION"),
        ("str.startswith", "PURE_BUILTIN_METHOD"),
    }


def test_corrigibility_ontology_owned_source_closes_effect_audit():
    root = Path(__file__).resolve().parents[1]

    audit = review.audit_closed_effects(
        root, ("src/verifier/corrigibility/ontology.py",),
    )

    assert audit.status == "CLOSED", audit.blockers
    assert audit.blockers == ()
    assert {finding.channel for finding in audit.consequences} == {
        "serialization_message_boundary"
    }


@pytest.mark.parametrize(
    "source",
    (
        (
            b"def digest(payload):\n"
            b"    return hashlib.sha256(payload).hexdigest()\n"
        ),
        (
            b"import hashlib\n"
            b"def digest(hashlib, payload):\n"
            b"    return hashlib.sha256(payload).hexdigest()\n"
        ),
        (
            b"import hashlib\n"
            b"class Hash:\n"
            b"    def hexdigest(self):\n"
            b"        return 'fake'\n"
            b"class Provider:\n"
            b"    def sha256(self, payload):\n"
            b"        return Hash()\n"
            b"hashlib = Provider()\n"
            b"def digest(payload):\n"
            b"    return hashlib.sha256(payload).hexdigest()\n"
        ),
    ),
)
def test_closed_effect_audit_rejects_unresolved_sha256_lookalikes(
    tmp_path: Path, source: bytes,
):
    paths = _write_sources(tmp_path, {"digest.py": source})

    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert any(
        blocker.startswith("CALL_TARGET_UNRESOLVED:digest.py:")
        or blocker.startswith("INJECTED_CALLABLE_UNRESOLVED:digest.py:")
        for blocker in audit.blockers
    )


def test_closed_effect_audit_detects_source_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = _write_sources(tmp_path, {"stable.py": b"VALUE = 1\n"})
    actual = review._effect_source_snapshot
    calls = 0

    def changed(root, selected_paths):
        nonlocal calls
        calls += 1
        snapshot = actual(root, selected_paths)
        if calls == 2:
            return (
                replace(snapshot[0], sha256="sha256:" + "f" * 64),
            )
        return snapshot

    monkeypatch.setattr(review, "_effect_source_snapshot", changed)
    audit = review.audit_closed_effects(tmp_path, paths)

    assert audit.status == "UNKNOWN"
    assert audit.blockers == ("SOURCE_CHANGED_DURING_AUDIT:stable.py",)


def test_closed_effect_audit_is_deterministic_and_digest_bound(tmp_path: Path):
    paths = _write_sources(
        tmp_path,
        {
            "b.py": b"def beta(value):\n    return value + 1\n",
            "a.py": b"def alpha(value):\n    return value - 1\n",
        },
    )

    first = review.audit_closed_effects(tmp_path, paths)
    second = review.audit_closed_effects(tmp_path, reversed(paths))
    first_document = review.closed_effect_audit_document(first)
    second_document = review.closed_effect_audit_document(second)
    body = {
        key: value
        for key, value in first_document.items()
        if key != "evidence_digest"
    }
    expected = "sha256:" + sha256(
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()

    assert first.status == second.status == "CLOSED"
    assert first_document == second_document
    assert first.evidence_digest == expected
