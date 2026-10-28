"""Adversarial tests for the imported test and normative-asset original-kind audit.

Terminology: JavaScript Object Notation (JSON).

Each rejection path has its own case built from the live source, so a drifted
digest, a substituted path, a role conflict, or an OBJECT bypass fails for the
precise reason named in the validator.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import shutil
from pathlib import Path

import pytest

from verifier.runtime import package_original_kind_catalog_tests_normative as audit
from verifier.runtime import package_semantic_ownership as ownership
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindDecision,
    owned_path_set_digest,
    profile_digest,
    seal_profile,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    root_role_decision,
)
from verifier.runtime.package_semantic_ownership_normative_assets import (
    AGENCY_CROSSWALK_APPLIES,
    AGENCY_CROSSWALK_ROOT_APPLIES,
    NORMATIVE_ASSET_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_tests_fixtures import (
    TEST_FIXTURE_OWNERSHIP_SPECS,
)

UNRESOLVED = audit.UNRESOLVED
RECEIPT_REASON = (
    "These files define simulation-risk and receipt wire grammars; schema documents "
    "are not receipt instances with bound subject and hardware operands."
)
BOT_SIM_QUOTE = "These test definitions are not SIMs, BOTs, ROBOTs, FINBOTs, trained MODEL artifacts"


def _specs() -> tuple[SemanticOwnershipSpec, ...]:
    return audit.current_source_partition()


def _spec(object_id: str) -> SemanticOwnershipSpec:
    return next(spec for spec in _specs() if spec.object_id == object_id)


def _row(object_id: str) -> audit.PartitionRow:
    return next(row for row in audit.REVIEW_ROWS if row.object_id == object_id)


def _audit(object_id: str) -> audit.PartitionAudit:
    return next(item for item in audit.AUDITS if item.object_id == object_id)


def _with_row(replacement: audit.PartitionRow) -> tuple[audit.PartitionRow, ...]:
    return tuple(
        replacement if row.object_id == replacement.object_id else row
        for row in audit.REVIEW_ROWS
    )


def _pinned(
    spec: SemanticOwnershipSpec,
    *,
    applies: tuple[str, ...] = (),
    refutes: tuple[tuple[str, str], ...] = (),
) -> audit.PartitionRow:
    """Pin digests to a deliberately modified spec so only the targeted check fires."""

    return audit.PartitionRow(
        object_id=spec.object_id,
        primary=spec.primary_kind,
        path_count=len(spec.owned_paths),
        path_set_digest=owned_path_set_digest(spec.owned_paths),
        coordinate_digest=audit._source_coordinate_digest(spec),
        applies=applies,
        refutes=refutes,
    )


def _decided() -> dict[tuple[str, str], str]:
    return {
        (item.object_id, question.kind): question.status
        for item in audit.AUDITS
        for question in item.questions
        if question.status != UNRESOLVED
    }


def test_denominator_is_exact_83_objects_949_paths_2075_questions() -> None:
    assert len(TEST_FIXTURE_OWNERSHIP_SPECS) == 16
    assert len(NORMATIVE_ASSET_OWNERSHIP_SPECS) == 67
    assert len(audit.AUDITS) == 83
    assert sum(item.path_count for item in audit.AUDITS) == 949
    assert sum(len(item.questions) for item in audit.AUDITS) == 83 * 25 == 2075
    assert tuple(item.object_id for item in audit.AUDITS) == tuple(
        sorted(spec.object_id for spec in _specs())
    )
    assert {spec.object_id for spec in _specs()} == {
        row.object_id for row in audit.REVIEW_ROWS
    }


def test_each_object_answers_all_25_original_kinds_in_source_order() -> None:
    for item in audit.AUDITS:
        assert tuple(question.kind for question in item.questions) == (
            ORIGINAL_NON_OBJECT_KINDS
        ), item.object_id
        assert all(question.status in {APPLIES, DOES_NOT_APPLY, UNRESOLVED} for question in item.questions)
        assert all(question.reason.strip() for question in item.questions)


def test_exact_decided_matrix_matches_source_declared_roles_and_text_denials() -> None:
    applies = {key for key, status in _decided().items() if status == APPLIES}
    denied = {key for key, status in _decided().items() if status == DOES_NOT_APPLY}
    expected = {
        (row.object_id, row.primary)
        for row in audit.REVIEW_ROWS
        if row.primary in ORIGINAL_NON_OBJECT_KINDS
    }
    expected.update((AGENCY, kind) for kind in ORIGINAL_NON_OBJECT_KINDS)
    assert applies == expected
    assert len(applies) == 52
    # No denial survives.  The ARCH denial's object has an open reference
    # closure (external $ref and unowned Markdown targets), and the RECEIPT
    # denial is narrowed by its trailing "with bound subject ..." clause.  Every
    # quoted denial is recorded but gated to UNRESOLVED
    # (see test_screen_gated_cells and test_qualified_denial_is_downgraded).
    assert denied == set()


def test_status_totals_are_52_applies_0_does_not_apply_2023_unresolved() -> None:
    statuses = [question.status for item in audit.AUDITS for question in item.questions]
    assert statuses.count(APPLIES) == 52
    assert statuses.count(DOES_NOT_APPLY) == 0
    assert statuses.count(UNRESOLVED) == 2023


def test_primary_original_kind_is_applies_and_never_refuted() -> None:
    for row in audit.REVIEW_ROWS:
        if row.primary in ORIGINAL_NON_OBJECT_KINDS:
            assert _audit(row.object_id).questions[
                ORIGINAL_NON_OBJECT_KINDS.index(row.primary)
            ].status == APPLIES, row.object_id


def test_receipt_denial_is_the_source_root_decision_not_inference() -> None:
    # The root decision is source-declared and recorded, but its denial is
    # narrowed by "with bound subject and hardware operands", so the RECEIPT
    # question is downgraded rather than decided.
    spec = _spec("vstd-simulation-risk-receipt-assets")
    assert spec.root_role_decisions == (
        root_role_decision("RECEIPT", DOES_NOT_APPLY, RECEIPT_REASON),
    )
    question = _audit("vstd-simulation-risk-receipt-assets").questions[
        ORIGINAL_NON_OBJECT_KINDS.index("RECEIPT")
    ]
    assert question.status == UNRESOLVED
    assert (
        "schema documents are not receipt instances with bound subject and hardware operands"
        in question.reason
    )
    assert 'narrows RECEIPT by the qualifier "with"' in question.reason


def test_claim_status_and_transfer_phrasing_never_decides_a_kind() -> None:
    def status(object_id: str, kind: str) -> str:
        return _audit(object_id).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)].status

    # "establishes no ... safety" and "executes no SIM" are claim or activity
    # disclaimers, not identity refutations.
    assert status("vstd-current-model-policy-assets", "MODEL") == UNRESOLVED
    assert status("vstd-current-sim-policy-assets", "SIM") == UNRESOLVED
    # "The policy instantiates no BOT or SIM" is an instantiation denial, so the
    # BOT and SIM cells of the current BOT policy stay UNRESOLVED.
    assert status("vstd-current-bot-policy-assets", "BOT") == UNRESOLVED
    assert status("vstd-current-bot-policy-assets", "SIM") == UNRESOLVED
    assert status("vstd-current-arch-policy-assets", "ARCH") == UNRESOLVED
    assert status("vstd-corrigibility-control-assets", "MODEL") == UNRESOLVED
    assert status("vstd-corrigibility-control-assets", "AGENT") == UNRESOLVED
    # "Testing a HUMAN ... does not turn the test suite into that subject" names
    # an identity boundary for exactly these five kinds.  The quote is recorded,
    # but the suite's closure is UNKNOWN, so the cells stay UNRESOLVED.
    for kind in ("HUMAN", "MODEL", "SIM", "BOT", "HARDWARE"):
        question = _audit("vstd-test-current-object-regressions").questions[
            ORIGINAL_NON_OBJECT_KINDS.index(kind)
        ]
        assert question.status == UNRESOLVED, kind
        assert "counterexample screen is UNKNOWN" in question.reason, kind
    for kind in ("ACTOR", "AGENT", "ARCH", "COLLECTIVE", "TOKEN", "OWNER"):
        assert status("vstd-test-current-object-regressions", kind) == UNRESOLVED
    assert status("vstd-test-artifact-evidence-regressions", "BOT") == UNRESOLVED
    # "It is not a production HARNESS" refutes a different scope and cannot
    # refute the declared primary HARNESS.
    assert status("vstd-test-fixture-harness", "HARNESS") == APPLIES
    assert status("vstd-test-fixture-harness", "BOT") == UNRESOLVED


def test_partial_profile_lists_only_decided_rows_and_is_self_consistent() -> None:
    decided_ids = {object_id for object_id, _kind in _decided()}
    profiled = {assignment.object_id for assignment in audit.PARTIAL_PROFILE.assignments}
    assert profiled == decided_ids
    assert len(profiled) == 28
    assert audit.PARTIAL_PROFILE.profile_id == audit.PROFILE_ID
    assert validate_profile(audit.PARTIAL_PROFILE) is audit.PARTIAL_PROFILE
    assert profile_digest(audit.PARTIAL_PROFILE) == audit.PARTIAL_PROFILE.canonical_digest
    for assignment in audit.PARTIAL_PROFILE.assignments:
        assert assignment.decisions
        assert all(decision.status in {APPLIES, DOES_NOT_APPLY} for decision in assignment.decisions)


def test_partial_profile_cannot_claim_full_package_closure() -> None:
    expected = tuple(sorted(spec.object_id for spec in _specs()))
    with pytest.raises(ValueError, match="OBJECT_DENOMINATOR_INCOMPLETE"):
        validate_full_closure(audit.PARTIAL_PROFILE, expected, expected_object_count=83)


def test_profile_rejects_unresolved_status_and_tampered_digest() -> None:
    assignment = audit.PARTIAL_PROFILE.assignments[0]
    unresolved = dataclasses.replace(
        assignment,
        decisions=(OriginalKindDecision("ACTOR", UNRESOLVED, "not a decision"),),
    )
    with pytest.raises(ValueError, match="STATUS_INVALID"):
        seal_profile(audit.PROFILE_ID, 1, audit.CLAIM_BOUNDARY, (unresolved,))
    tampered = dataclasses.replace(audit.PARTIAL_PROFILE, claim_boundary="changed")
    with pytest.raises(ValueError, match="DIGEST_INVALID"):
        validate_profile(tampered)


def test_row_level_bypass_and_conflict_rules_fail_closed() -> None:
    harness = _row("vstd-test-fixture-harness")
    with pytest.raises(ValueError, match="OBJECT_BYPASS"):
        audit.audit_row(dataclasses.replace(harness, primary="OBJECT"))
    with pytest.raises(ValueError, match="OBJECT_BYPASS"):
        audit.audit_row(dataclasses.replace(harness, applies=("HARNESS", "OBJECT")))
    with pytest.raises(ValueError, match="ROLE_CONFLICT"):
        audit.audit_row(
            dataclasses.replace(
                harness,
                refutes=(("HARNESS", "It is not a production HARNESS"),),
            )
        )
    with pytest.raises(ValueError, match="PRIMARY_UNANSWERED"):
        audit.audit_row(dataclasses.replace(harness, applies=()))
    with pytest.raises(ValueError, match="APPLIES_INVALID"):
        audit.audit_row(dataclasses.replace(harness, applies=("HARNESS", "PROTOCOL")))
    with pytest.raises(ValueError, match="REFUTES_INVALID"):
        audit.audit_row(dataclasses.replace(harness, refutes=(("POLICY", "x"),)))
    with pytest.raises(ValueError, match="REFUTES_INVALID"):
        audit.audit_row(
            dataclasses.replace(harness, refutes=(("BOT", "a"), ("BOT", "b")))
        )
    with pytest.raises(ValueError, match="DENIAL_TEXT_INVALID"):
        audit.audit_row(dataclasses.replace(harness, refutes=(("BOT", "   "),)))
    with pytest.raises(ValueError, match="DIGEST_INVALID"):
        audit.audit_row(dataclasses.replace(harness, path_set_digest="sha256:xyz"))
    with pytest.raises(ValueError, match="PATH_COUNT_INVALID"):
        audit.audit_row(dataclasses.replace(harness, path_count=0))


def test_quoted_denial_must_be_verbatim_source_text_and_name_its_kind() -> None:
    profile = _row("vstd-profile-architecture-assets")
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND"):
        audit.validate_source_partition(
            _specs(),
            _with_row(
                dataclasses.replace(
                    profile,
                    refutes=(("ARCH", "not a computational-model ARCHITECTURE"),),
                )
            ),
        )
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND"):
        audit.validate_source_partition(
            _specs(),
            _with_row(
                dataclasses.replace(
                    profile,
                    refutes=(("SIM", "not a computational-model ARCH"),),
                )
            ),
        )


def test_text_substitution_changes_the_pinned_coordinate() -> None:
    profile = _spec("vstd-profile-architecture-assets")
    drifted = dataclasses.replace(
        profile,
        consequence_boundary=profile.consequence_boundary.replace(
            "not a computational-model ARCH", "a computational-model ARCH"
        ),
    )
    specs = tuple(drifted if spec.object_id == drifted.object_id else spec for spec in _specs())
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        audit.validate_source_partition(specs)


def test_path_substitution_is_rejected() -> None:
    harness = _spec("vstd-test-fixture-harness")
    substituted = dataclasses.replace(harness, owned_paths=harness.owned_paths[:-1])
    specs = tuple(substituted if spec.object_id == harness.object_id else spec for spec in _specs())
    with pytest.raises(ValueError, match="SOURCE_PATH_DRIFT"):
        audit.validate_source_partition(specs)


def test_primary_kind_substitution_is_rejected() -> None:
    harness = _spec("vstd-test-fixture-harness")
    substituted = dataclasses.replace(harness, primary_kind="POLICY")
    specs = tuple(substituted if spec.object_id == harness.object_id else spec for spec in _specs())
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT"):
        audit.validate_source_partition(specs)


def test_unrecorded_specialization_role_is_accumulated_role_drift() -> None:
    harness = _spec("vstd-test-fixture-harness")
    accumulated = dataclasses.replace(harness, specializations=("DATA",))
    specs = tuple(accumulated if spec.object_id == harness.object_id else spec for spec in _specs())
    rows = _with_row(_pinned(accumulated, applies=("HARNESS",)))
    with pytest.raises(ValueError, match="ACCUMULATED_ROLE_DRIFT"):
        audit.validate_source_partition(specs, rows)


def test_root_applies_against_row_denial_is_a_role_conflict() -> None:
    profile = _spec("vstd-profile-architecture-assets")
    conflicting = dataclasses.replace(
        profile,
        root_role_decisions=(root_role_decision("ARCH", APPLIES, "source-declared root"),),
    )
    specs = tuple(conflicting if spec.object_id == profile.object_id else spec for spec in _specs())
    rows = _with_row(
        _pinned(
            conflicting,
            applies=("ARCH",),
            refutes=(("ARCH", "not a computational-model ARCH"),),
        )
    )
    with pytest.raises(ValueError, match="ROLE_CONFLICT"):
        audit.validate_source_partition(specs, rows)


def test_source_declared_root_applies_and_denies_is_rejected() -> None:
    profile = _spec("vstd-profile-architecture-assets")
    both = dataclasses.replace(
        profile,
        root_role_decisions=(
            root_role_decision("ARCH", APPLIES, "a"),
            root_role_decision("ARCH", DOES_NOT_APPLY, "b"),
        ),
    )
    specs = tuple(both if spec.object_id == profile.object_id else spec for spec in _specs())
    rows = _with_row(_pinned(both, refutes=(("ARCH", "not a computational-model ARCH"),)))
    with pytest.raises(ValueError, match="SOURCE_ROLE_CONFLICT"):
        audit.validate_source_partition(specs, rows)


def test_source_root_denial_missing_from_the_row_is_rejected() -> None:
    risk = _spec("vstd-simulation-risk-receipt-assets")
    extra = dataclasses.replace(
        risk,
        root_role_decisions=(
            root_role_decision("RECEIPT", DOES_NOT_APPLY, RECEIPT_REASON),
            root_role_decision("SIM", DOES_NOT_APPLY, "receipt-only denial"),
        ),
    )
    specs = tuple(extra if spec.object_id == risk.object_id else spec for spec in _specs())
    rows = _with_row(
        _pinned(extra, refutes=(("RECEIPT", "schema documents are not receipt instances"),))
    )
    with pytest.raises(ValueError, match="ROOT_DENIAL_UNRECORDED"):
        audit.validate_source_partition(specs, rows)


def test_root_denial_quote_that_drifts_from_the_root_reason_is_rejected() -> None:
    risk = _spec("vstd-simulation-risk-receipt-assets")
    specs = _specs()
    rows = _with_row(
        _pinned(risk, refutes=(("RECEIPT", "schema documents are not receipt instances with hardware substitutes"),))
    )
    with pytest.raises(ValueError, match="ROOT_DENIAL_DRIFT"):
        audit.validate_source_partition(specs, rows)


def test_missing_or_extra_objects_are_denominator_drift() -> None:
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        audit.validate_source_partition(_specs()[1:])
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        audit.validate_source_partition(_specs(), audit.REVIEW_ROWS[:-1])


def test_duplicate_source_object_identifier_is_rejected() -> None:
    specs = (*_specs(), _specs()[0])
    with pytest.raises(ValueError, match="SOURCE_PARTITION_INVALID"):
        audit.validate_source_partition(specs)


def test_non_aggregate_partition_member_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    trimmed = tuple(
        spec
        for spec in ownership.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id != "vstd-test-fixture-harness"
    )
    monkeypatch.setattr(ownership, "SEMANTIC_OWNERSHIP_SPECS", trimmed)
    with pytest.raises(ValueError, match="NOT_AGGREGATE_MEMBER"):
        audit.current_source_partition()


def test_current_source_validates_and_review_document_is_complete() -> None:
    assert len(audit.validate_source_partition(_specs())) == 83
    document = audit.review_document()
    assert len(document) == 83
    assert all(len(item["questions"]) == 25 for item in document.values())
    profiled = {object_id for object_id, item in document.items() if item["partial_profile_digest"]}
    assert len(profiled) == 28
    assert all(item["claim_boundary"] == audit.CLAIM_BOUNDARY for item in document.values())


def test_review_rows_carry_the_exact_owned_paths_the_aggregate_binds() -> None:
    """The aggregate re-hashes each row's owned files, so the row must name them."""
    specs = {spec.object_id: spec for spec in _specs()}
    document = audit.review_document()
    for object_id, item in document.items():
        paths = item["expected_owned_paths"]
        assert paths == sorted(specs[object_id].owned_paths)
        assert len(paths) == item["expected_owned_path_count"]
        assert owned_path_set_digest(paths) == item["expected_owned_path_set_digest"]


def test_omitted_and_complement_kinds_stay_unresolved_never_denied() -> None:
    # Complement is not identity: a kind that no declared role or verbatim
    # quote names remains UNRESOLVED, and every DOES_NOT_APPLY traces to a
    # row-recorded quote.
    for row in audit.REVIEW_ROWS:
        named = {row.primary, *row.applies, *(kind for kind, _quote in row.refutes)}
        for question in _audit(row.object_id).questions:
            if question.kind not in named:
                assert question.status == UNRESOLVED, (row.object_id, question.kind)
    decided = _decided()
    denied_pairs = {key for key, status in decided.items() if status == DOES_NOT_APPLY}
    quoted_pairs = {
        (row.object_id, kind) for row in audit.REVIEW_ROWS for kind, _quote in row.refutes
    }
    # Every decided denial is quoted, but a quote is not a decision by itself:
    # the quoted-but-gated cells must remain UNRESOLVED.
    assert denied_pairs < quoted_pairs
    for object_id, kind in quoted_pairs - denied_pairs:
        assert _audit(object_id).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)].status == (
            UNRESOLVED
        ), (object_id, kind)


def test_transfer_sentence_decides_only_through_its_identity_clause() -> None:
    # The evidence-transfer clause of the current-object boundary carries no
    # identity predicate, so no row may quote it as a denial.
    assert "does not turn the test suite into that subject" in (
        audit.CURRENT_OBJECT_TRANSFER_DENIAL
    )
    assert "transfer" not in audit.CURRENT_OBJECT_TRANSFER_DENIAL
    row = _row("vstd-test-current-object-regressions")
    assert {quote for _kind, quote in row.refutes} == {
        audit.CURRENT_OBJECT_TRANSFER_DENIAL
    }


def test_identity_clause_drift_in_source_is_rejected() -> None:
    current = _spec("vstd-test-current-object-regressions")
    drifted = dataclasses.replace(
        current,
        consequence_boundary=current.consequence_boundary.replace(
            "does not turn the test suite into that subject",
            "is not limited to the test suite",
        ),
    )
    specs = tuple(drifted if spec.object_id == current.object_id else spec for spec in _specs())
    rows = _with_row(
        _pinned(
            drifted,
            applies=("VERIFIER",),
            refutes=tuple(
                (kind, audit.CURRENT_OBJECT_TRANSFER_DENIAL)
                for kind in ("HUMAN", "MODEL", "SIM", "BOT", "HARDWARE")
            ),
        )
    )
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND"):
        audit.validate_source_partition(specs, rows)


def test_quote_from_a_neighboring_owner_does_not_refute_this_row() -> None:
    # The identical boundary text is not copied into neighboring test objects,
    # so reusing it there must fail the verbatim source-binding check.
    neighbor = _row("vstd-test-artifact-evidence-regressions")
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND"):
        audit.validate_source_partition(
            _specs(),
            _with_row(
                dataclasses.replace(
                    neighbor,
                    refutes=(("HUMAN", audit.CURRENT_OBJECT_TRANSFER_DENIAL),),
                )
            ),
        )


HIGH_RISK_KINDS = frozenset(
    ("AGENT", "BOT", "FINBOT", "HARDWARE", "HUMAN", "MODEL", "OWNER", "ROBOT", "SIM", "TOKEN")
)
ARTIFACT_SUFFIXES = frozenset(
    (
        ".bin", ".ckpt", ".dll", ".dts", ".dtsi", ".exe", ".gguf", ".h5", ".onnx",
        ".pkl", ".pt", ".pth", ".pyc", ".safetensors", ".so", ".wasm",
    )
)


def test_high_risk_denials_have_no_artifact_counterexample_in_owned_paths() -> None:
    # Counterexample guard: a DOES_NOT_APPLY for a high-risk kind must not sit
    # over an owned path that is a weight, binary, or hardware-description
    # artifact. Suffix screening is a bounded guard, not an identity proof.
    checked = 0
    for row in audit.REVIEW_ROWS:
        if not any(kind in HIGH_RISK_KINDS for kind, _quote in row.refutes):
            continue
        checked += 1
        spec = _spec(row.object_id)
        suffixes = {Path(path).suffix for path in spec.owned_paths}
        assert suffixes.isdisjoint(ARTIFACT_SUFFIXES), row.object_id
    assert checked == 2


def test_module_imports_only_stdlib_and_verifier_namespace() -> None:
    source = Path(audit.__file__).read_text(encoding="utf-8")
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= {
        "__future__",
        "collections",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "re",
        "typing",
        "verifier",
    }


ROOT = Path(__file__).resolve().parents[1]


def test_identity_screen_rejects_activity_and_instantiation_quotes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "instantiates no BOT" and "executes no SIM" are activity phrasing; the
    # identity screen refuses them before any cell can become DOES_NOT_APPLY.
    bot = _row("vstd-current-bot-policy-assets")
    with pytest.raises(ValueError, match="DENIAL_NOT_IDENTITY"):
        audit.audit_row(
            dataclasses.replace(bot, refutes=(("BOT", "The policy instantiates no BOT or SIM"),))
        )
    with pytest.raises(ValueError, match="DENIAL_NOT_IDENTITY"):
        audit.audit_row(dataclasses.replace(bot, refutes=(("SIM", "The policy executes no SIM"),)))
    # An identity quote passes the screen but is gated: with no closed screen
    # record for this object, the cell stays UNRESOLVED.
    gated = audit.audit_row(
        dataclasses.replace(bot, refutes=(("BOT", "The policy is not a BOT"),))
    )
    assert gated.questions[ORIGINAL_NON_OBJECT_KINDS.index("BOT")].status == UNRESOLVED
    # With a closed record for the same object, the identical quote decides.
    closed = audit.ScreenRecord(
        object_id=bot.object_id,
        status="CLOSED",
        path_count=bot.path_count,
        bytes_digest="sha256:" + "0" * 64,
        effect_digest="",
        blocker_counts=(),
    )
    monkeypatch.setitem(audit._SCREEN_BY_OBJECT, bot.object_id, closed)
    accepted = audit.audit_row(
        dataclasses.replace(bot, refutes=(("BOT", "The policy is not a BOT"),))
    )
    assert accepted.questions[ORIGINAL_NON_OBJECT_KINDS.index("BOT")].status == DOES_NOT_APPLY


def test_stale_instantiation_decision_is_rejected_even_when_verbatim() -> None:
    # The pre-downgrade BOT and SIM denials quote real source text, so only the
    # identity screen can reject their reintroduction.
    bot = _row("vstd-current-bot-policy-assets")
    stale = _with_row(
        dataclasses.replace(bot, refutes=(("BOT", "The policy instantiates no BOT or SIM"),))
    )
    with pytest.raises(ValueError, match="DENIAL_NOT_IDENTITY:vstd-current-bot-policy-assets"):
        audit.validate_source_partition(_specs(), stale)


def test_drifted_row_aborts_the_whole_partition_without_partial_state() -> None:
    # The drifted object sorts last, so every earlier row validates before the
    # failure. No partial audit or profile may escape, and module state must not change.
    drifted_id = "vstd-zero-identity-token-assets"
    before_profile = audit.PARTIAL_PROFILE
    before_audits = audit.AUDITS
    spec = _spec(drifted_id)
    drifted = dataclasses.replace(spec, consequence_boundary=spec.consequence_boundary + " ")
    specs = tuple(drifted if item.object_id == drifted_id else item for item in _specs())
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT:" + drifted_id):
        audit.validate_source_partition(specs)
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT:" + drifted_id):
        audit.build_partial_profile(specs)
    assert audit.PARTIAL_PROFILE is before_profile
    assert audit.AUDITS is before_audits
    assert len(audit.PARTIAL_PROFILE.assignments) == 28


def test_every_owned_path_exists_in_the_checkout() -> None:
    missing = [
        (spec.object_id, path)
        for spec in _specs()
        for path in spec.owned_paths
        if not (ROOT / path).is_file()
    ]
    assert missing == []
    assert sum(len(spec.owned_paths) for spec in _specs()) == 949


def test_denial_rows_have_no_instance_or_artifact_counterexample() -> None:
    # ARCH and RECEIPT denials: every owned JSON document is a schema, not an
    # instance, so no model architecture or receipt instance is owned here.
    for object_id in ("vstd-profile-architecture-assets", "vstd-simulation-risk-receipt-assets"):
        for path in _spec(object_id).owned_paths:
            if path.endswith(".json"):
                document = json.loads((ROOT / path).read_text(encoding="utf-8"))
                assert "$schema" in document and "$id" in document, path
            else:
                assert path.endswith(".md") or path.endswith(".json"), path
    # Current-object and simulation-model denials: every owned asset is a pytest
    # module with at least one test function, so the test object is not the subject.
    for object_id in (
        "vstd-test-current-object-regressions",
        "vstd-test-simulation-model-regressions",
    ):
        for path in _spec(object_id).owned_paths:
            assert path.startswith("tests/test_") and path.endswith(".py"), path
            tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
            assert any(
                isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
                for node in tree.body
            ), path


def test_every_denial_cell_is_verbatim_source_text_in_its_row() -> None:
    for item in audit.AUDITS:
        row = _row(item.object_id)
        spec = _spec(item.object_id)
        quotes = dict(row.refutes)
        fields = (
            spec.representation_role,
            spec.necessity_reason,
            spec.consequence_boundary,
            *(decision.reason for decision in spec.root_role_decisions),
        )
        for question in item.questions:
            if question.kind not in quotes:
                continue
            quote = quotes[question.kind]
            assert quote in question.reason, (item.object_id, question.kind)
            assert any(quote in field for field in fields), (item.object_id, question.kind)
            # A quoted cell that is not decided must never read as a refutation.
            if question.status == UNRESOLVED:
                assert "refutes only this row" not in question.reason, (
                    item.object_id,
                    question.kind,
                )


def _screen_blockers(record: audit.ScreenRecord) -> set[str]:
    return {name for name, _count in record.blocker_counts}


def _write_tree(root: Path, files: dict[str, bytes]) -> tuple[str, ...]:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return tuple(sorted(files))


def test_screen_gated_cells_are_exactly_the_unclosed_denials() -> None:
    gated = {
        (row.object_id, kind)
        for row in audit.REVIEW_ROWS
        for kind, _quote in row.refutes
        if audit._SCREEN_BY_OBJECT[row.object_id].status != "CLOSED"
    }
    assert gated == {
        ("vstd-profile-architecture-assets", "ARCH"),
        ("vstd-test-simulation-model-regressions", "BOT"),
        ("vstd-test-simulation-model-regressions", "MODEL"),
        ("vstd-test-simulation-model-regressions", "SIM"),
        ("vstd-test-current-object-regressions", "HUMAN"),
        ("vstd-test-current-object-regressions", "MODEL"),
        ("vstd-test-current-object-regressions", "SIM"),
        ("vstd-test-current-object-regressions", "BOT"),
        ("vstd-test-current-object-regressions", "HARDWARE"),
    }
    for object_id, kind in gated:
        question = _audit(object_id).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)]
        assert question.status == UNRESOLVED, (object_id, kind)
        assert "counterexample screen is UNKNOWN" in question.reason
    arch = _audit("vstd-profile-architecture-assets").questions[
        ORIGINAL_NON_OBJECT_KINDS.index("ARCH")
    ]
    assert "REFERENCE_EXTERNAL_URL x40" in arch.reason
    assert "REFERENCE_UNOWNED_TARGET x113" in arch.reason
    for object_id, kind in gated:
        if object_id == "vstd-profile-architecture-assets":
            continue
        question = _audit(object_id).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)]
        assert "EFFECT_BLOCKER_CALL_TARGET_UNRESOLVED x" in question.reason, (object_id, kind)


def test_missing_screen_record_gates_a_quoted_denial_without_deciding_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(audit._SCREEN_BY_OBJECT, "vstd-profile-architecture-assets")
    row_audit = audit.audit_row(_row("vstd-profile-architecture-assets"))
    question = row_audit.questions[ORIGINAL_NON_OBJECT_KINDS.index("ARCH")]
    assert question.status == UNRESOLVED
    assert "is MISSING" in question.reason


def test_qualified_denials_are_downgraded_not_decided(monkeypatch: pytest.MonkeyPatch) -> None:
    # "production HARNESS" and "current RECEIPT" deny a narrower class than the
    # kind itself, so a qualified quote cannot refute the kind it names, even
    # when its screen is CLOSED.
    closed = audit.ScreenRecord(
        object_id="vstd-test-fixture-harness",
        status="CLOSED",
        path_count=4,
        bytes_digest="sha256:" + "0" * 64,
        effect_digest="",
        blocker_counts=(),
    )
    monkeypatch.setitem(audit._SCREEN_BY_OBJECT, "vstd-test-fixture-harness", closed)
    harness = _row("vstd-test-fixture-harness")
    cases = (
        ("RECEIPT", "It is not a current RECEIPT", "current"),
        ("RECEIPT", "A retained or passing polish test is not a package-wide polish receipt", "package-wide"),
        ("RECEIPT", "Checked-in fixture bytes are not independently authoritative RECEIPTs", "independently"),
    )
    for kind, quote, qualifier in cases:
        assert audit._denial_qualifier(kind, quote) == qualifier
        row = dataclasses.replace(harness, refutes=((kind, quote),))
        question = audit.audit_row(row).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)]
        assert question.status == UNRESOLVED, quote
        assert 'by the qualifier "' + qualifier + '"' in question.reason
    # The fixture-harness boundary's own "production HARNESS" phrase is a
    # qualified denial; the existing role-conflict rule rejects it first.
    assert audit._denial_qualifier("HARNESS", "It is not a production HARNESS") == "production"
    with pytest.raises(ValueError, match="ROLE_CONFLICT"):
        audit.audit_row(
            dataclasses.replace(harness, refutes=(("HARNESS", "It is not a production HARNESS"),))
        )
    # Unqualified identity quotes keep their kind, e.g. the architecture denial.
    assert audit._denial_qualifier("ARCH", "not a computational-model ARCH") is None


def test_qualified_denial_is_downgraded(monkeypatch: pytest.MonkeyPatch) -> None:
    # Trailing qualifier: the RECEIPT denial reads "receipt instances with bound
    # subject", a narrower class.  Even with a closed screen it must not decide.
    quote = "schema documents are not receipt instances with bound subject and hardware operands"
    assert audit._denial_qualifier("RECEIPT", quote) == "with"
    closed = audit.ScreenRecord(
        object_id="vstd-simulation-risk-receipt-assets",
        status="CLOSED",
        path_count=2,
        bytes_digest="sha256:" + "0" * 64,
        effect_digest="",
        blocker_counts=(),
    )
    monkeypatch.setitem(audit._SCREEN_BY_OBJECT, "vstd-simulation-risk-receipt-assets", closed)
    receipt = _row("vstd-simulation-risk-receipt-assets")
    question = audit.audit_row(receipt).questions[ORIGINAL_NON_OBJECT_KINDS.index("RECEIPT")]
    assert question.status == UNRESOLVED
    assert "narrows RECEIPT" in question.reason
    # The identical clause without the trailing qualifier decides.
    unqualified = "schema documents are not receipt instances"
    assert audit._denial_qualifier("RECEIPT", unqualified) is None
    decided = audit.audit_row(
        dataclasses.replace(receipt, refutes=(("RECEIPT", unqualified),))
    ).questions[ORIGINAL_NON_OBJECT_KINDS.index("RECEIPT")]
    assert decided.status == DOES_NOT_APPLY


def test_neither_nor_denial_in_formation_corpus_is_qualified_and_undecided() -> None:
    corpus = _row("vstd-test-formation-fixture-corpus")
    assert corpus.refutes == ()
    spec = _spec("vstd-test-formation-fixture-corpus")
    assert "neither fresh executions nor independently authoritative RECEIPTs" in (
        spec.consequence_boundary
    )
    assert audit._denial_qualifier(
        "RECEIPT",
        "Checked-in fixture bytes are neither fresh executions nor independently authoritative RECEIPTs",
    ) == "independently"
    question = _audit("vstd-test-formation-fixture-corpus").questions[
        ORIGINAL_NON_OBJECT_KINDS.index("RECEIPT")
    ]
    assert question.status == UNRESOLVED


def test_referent_denials_bind_only_to_the_object_that_states_them() -> None:
    # The test definitions' SIM quote is a statement about the tested suite. It
    # cannot refute the SIM policy object, whose declaration never states it.
    policy = _row("vstd-current-sim-policy-assets")
    quote = "These test definitions are not SIMs, BOTs, ROBOTs, FINBOTs, trained MODEL artifacts"
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND"):
        audit.validate_source_partition(
            _specs(),
            _with_row(dataclasses.replace(policy, refutes=(("SIM", quote),))),
        )
    # A receipt-type denial about schema documents cannot refute a regression
    # suite that merely exercises receipts.
    artifact = _row("vstd-test-artifact-evidence-regressions")
    receipt_quote = "schema documents are not receipt instances with bound subject and hardware operands"
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND"):
        audit.validate_source_partition(
            _specs(),
            _with_row(dataclasses.replace(artifact, refutes=(("RECEIPT", receipt_quote),))),
        )


def test_transitive_project_import_escape_blocks_the_screen(tmp_path: Path) -> None:
    owned = _write_tree(
        tmp_path,
        {"owned/a.py": b"from verifier.runtime import package_semantic_ownership\n"},
    )
    record = audit.counterexample_screen("probe", owned, tmp_path)
    assert record.status == "UNKNOWN"
    assert "EFFECT_BLOCKER_EXTERNAL_IMPORT_UNACCOUNTED" in _screen_blockers(record)


def test_transitive_import_inside_the_closure_is_accounted_but_escape_behind_it_is_not(
    tmp_path: Path,
) -> None:
    closed = _write_tree(
        tmp_path / "closed",
        {"owned/a.py": b"from . import b\n", "owned/b.py": b"VALUE = 1\n"},
    )
    assert audit.counterexample_screen("probe", closed, tmp_path / "closed").status == "CLOSED"
    escaped = _write_tree(
        tmp_path / "escaped",
        {
            "owned/a.py": b"from . import b\n",
            "owned/b.py": b"from verifier.runtime import package_semantic_ownership\n",
        },
    )
    record = audit.counterexample_screen("probe", escaped, tmp_path / "escaped")
    assert record.status == "UNKNOWN"
    assert "EFFECT_BLOCKER_EXTERNAL_IMPORT_UNACCOUNTED" in _screen_blockers(record)


def test_callback_injection_blocks_the_screen(tmp_path: Path) -> None:
    owned = _write_tree(
        tmp_path,
        {"owned/cb.py": b"def run(cb):\n    return cb()\n\nrun(lambda: 1)\n"},
    )
    record = audit.counterexample_screen("probe", owned, tmp_path)
    assert record.status == "UNKNOWN"
    assert "EFFECT_callback_injected_callable" in _screen_blockers(record)


def test_dynamic_and_reflective_escape_blocks_the_screen(tmp_path: Path) -> None:
    owned = _write_tree(
        tmp_path,
        {"owned/dyn.py": b'import importlib\nmod = importlib.import_module("json")\n'},
    )
    record = audit.counterexample_screen("probe", owned, tmp_path)
    assert record.status == "UNKNOWN"
    assert "EFFECT_dynamic_import_eval_exec_reflection" in _screen_blockers(record)


def test_subprocess_effect_blocks_the_screen(tmp_path: Path) -> None:
    owned = _write_tree(
        tmp_path,
        {"owned/proc.py": b'import subprocess\nsubprocess.run(["echo", "x"])\n'},
    )
    record = audit.counterexample_screen("probe", owned, tmp_path)
    assert record.status == "UNKNOWN"
    assert "EFFECT_subprocess_process" in _screen_blockers(record)


def test_binary_asset_and_instance_json_block_while_schema_and_prose_close(
    tmp_path: Path,
) -> None:
    binary = _write_tree(tmp_path / "binary", {"owned/w.safetensors": b"weights\x00\x01"})
    assert "BINARY_ASSET" in _screen_blockers(
        audit.counterexample_screen("probe", binary, tmp_path / "binary")
    )
    instance = _write_tree(tmp_path / "instance", {"owned/data.json": b'{"layers": [1]}'})
    assert "JSON_INSTANCE" in _screen_blockers(
        audit.counterexample_screen("probe", instance, tmp_path / "instance")
    )
    schema_and_prose = _write_tree(
        tmp_path / "docs",
        {"owned/s.json": b'{"$schema": "x", "$id": "y"}', "owned/d.md": b"# prose\n"},
    )
    record = audit.counterexample_screen("probe", schema_and_prose, tmp_path / "docs")
    assert record.status == "CLOSED"
    assert record.effect_digest == ""


def test_missing_owned_path_is_a_blocker_not_an_omission(tmp_path: Path) -> None:
    record = audit.counterexample_screen("probe", ("owned/absent.md",), tmp_path)
    assert record.status == "UNKNOWN"
    assert _screen_blockers(record) == {"MISSING_PATH"}


def test_live_closure_screens_match_the_pinned_records() -> None:
    assert audit.recheck_closure_screens() == audit.SCREEN_RECORDS


ROOT_INDEPENDENT_OBJECT = "vstd-profile-architecture-assets"


def test_stale_bytes_fail_the_pinned_screen(tmp_path: Path) -> None:
    # The ARCH object has no executable owned source, so its screen depends only
    # on its own bytes and can be validated from a copied tree.
    specs = {spec.object_id: spec for spec in _specs()}
    owned = specs[ROOT_INDEPENDENT_OBJECT].owned_paths
    for path in owned:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    pinned = (ROOT_INDEPENDENT_OBJECT,)
    assert audit.recheck_closure_screens(tmp_path, pinned) == (
        audit.SCREEN_RECORDS[0],
    )
    with (tmp_path / owned[0]).open("ab") as handle:
        handle.write(b"\n")
    with pytest.raises(ValueError, match="SCREEN_STALE:" + ROOT_INDEPENDENT_OBJECT):
        audit.recheck_closure_screens(tmp_path, pinned)


def test_effect_screen_is_bound_to_the_repository_root_that_resolved_it(tmp_path: Path) -> None:
    # Identical owned bytes copied without the rest of src/ resolve project-local
    # imports differently, so the effect-bearing record is not portable.
    specs = {spec.object_id: spec for spec in _specs()}
    object_id = "vstd-test-current-object-regressions"
    owned = specs[object_id].owned_paths
    for path in owned:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    copied = audit.counterexample_screen(object_id, owned, tmp_path)
    assert copied.bytes_digest == audit._SCREEN_BY_OBJECT[object_id].bytes_digest
    assert copied.effect_digest != audit._SCREEN_BY_OBJECT[object_id].effect_digest
    with pytest.raises(ValueError, match="SCREEN_DRIFT:" + object_id):
        audit.recheck_closure_screens(tmp_path, (object_id,))


def test_cell_evidence_is_pinned_and_every_quoted_cell_is_downgraded() -> None:
    assert audit.cell_evidence_digest() == audit.CELL_EVIDENCE_DIGEST
    records = audit.cell_evidence_records()
    assert len(records) == 83 * 25
    denied = [record for record in records if record.status == DOES_NOT_APPLY]
    assert denied == []
    qualified = [record for record in records if record.basis == "IDENTITY_DENIAL_QUALIFIED"]
    assert [(record.object_id, record.kind) for record in qualified] == [
        ("vstd-simulation-risk-receipt-assets", "RECEIPT")
    ]
    assert qualified[0].status == UNRESOLVED
    gated = [record for record in records if record.basis == "IDENTITY_DENIAL_SCREEN_UNCLOSED"]
    assert len(gated) == 9
    assert all(
        record.status == UNRESOLVED and record.screen_status == "UNKNOWN" for record in gated
    )
    assert all(
        record.basis == "SOURCE_DECLARED_ROLE"
        for record in records
        if record.status == APPLIES
    )


# Adversarial regressions: closed-effect escapes, reference edges, aliases,
# referent-versus-object confusion, reason substitution, and primary labels.


def _closed(object_id: str, path_count: int) -> audit.ScreenRecord:
    return audit.ScreenRecord(
        object_id=object_id,
        status="CLOSED",
        path_count=path_count,
        bytes_digest="sha256:" + "0" * 64,
        effect_digest="",
        blocker_counts=(),
    )


def _question(row: audit.PartitionRow, kind: str) -> audit.PartitionQuestion:
    return audit.audit_row(row).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)]


@pytest.mark.parametrize(
    ("body", "blocker"),
    (
        (
            b"import importlib\nmod = importlib.import_module('json')\n",
            "EFFECT_dynamic_import_eval_exec_reflection",
        ),
        (b"def f(o):\n    return getattr(o, 'x')\n", "EFFECT_dynamic_import_eval_exec_reflection"),
        (b"x = eval('1')\n", "EFFECT_dynamic_import_eval_exec_reflection"),
        (b"def run(cb):\n    return cb()\n\nrun(lambda: 1)\n", "EFFECT_callback_injected_callable"),
        (b"import subprocess\nsubprocess.run(['echo'])\n", "EFFECT_subprocess_process"),
    ),
)
def test_dynamic_reflective_callback_and_process_effects_downgrade_a_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes, blocker: str
) -> None:
    # A closed-looking denial row is downgraded as soon as its owned closure
    # admits any effect, even when the quoted identity is exact.
    owned = _write_tree(tmp_path, {"owned/effect.py": body})
    record = audit.counterexample_screen("vstd-profile-architecture-assets", owned, tmp_path)
    assert record.status == "UNKNOWN"
    assert blocker in _screen_blockers(record)
    monkeypatch.setitem(audit._SCREEN_BY_OBJECT, "vstd-profile-architecture-assets", record)
    question = _question(_row("vstd-profile-architecture-assets"), "ARCH")
    assert question.status == UNRESOLVED
    assert blocker in question.reason


def test_imported_effect_behind_a_closed_importer_downgrades_the_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The importer is clean and the effect lives in an owned module it imports.
    owned = _write_tree(
        tmp_path,
        {
            "owned/a.py": b"from . import b\n",
            "owned/b.py": b"import subprocess\nsubprocess.run(['echo'])\n",
        },
    )
    record = audit.counterexample_screen("vstd-profile-architecture-assets", owned, tmp_path)
    assert record.status == "UNKNOWN"
    assert "EFFECT_subprocess_process" in _screen_blockers(record)
    monkeypatch.setitem(audit._SCREEN_BY_OBJECT, "vstd-profile-architecture-assets", record)
    question = _question(_row("vstd-profile-architecture-assets"), "ARCH")
    assert question.status == UNRESOLVED
    assert "EFFECT_subprocess_process" in question.reason


@pytest.mark.parametrize(
    ("text", "blocker"),
    (
        (b"[self](#top) [same](b.md) [frag](b.md#sec) [query](b.md?x=1)\n", None),
        (b"[up](../../docs/X.md)\n", "REFERENCE_UNOWNED_TARGET"),
        (b"[abs](/etc/passwd)\n", "REFERENCE_UNOWNED_TARGET"),
        (b"[web](https://example.com/x)\n", "REFERENCE_EXTERNAL_URL"),
        (b"<https://example.com/y>\n", "REFERENCE_EXTERNAL_URL"),
        (b"[ref][r]\n\n[r]: https://example.com/z\n", "REFERENCE_EXTERNAL_URL"),
        (b'<img src="other.png" />\n', "REFERENCE_UNOWNED_TARGET"),
        (b"[missing](never-written.md)\n", "REFERENCE_UNOWNED_TARGET"),
    ),
)
def test_markdown_reference_edges_close_only_inside_the_owned_set(
    tmp_path: Path, text: bytes, blocker: str | None
) -> None:
    owned = _write_tree(tmp_path, {"owned/a.md": text, "owned/b.md": b"# B\n"})
    record = audit.counterexample_screen("probe", owned, tmp_path)
    if blocker is None:
        assert record.status == "CLOSED", text
    else:
        assert record.status == "UNKNOWN", text
        assert blocker in _screen_blockers(record), text


@pytest.mark.parametrize(
    ("document", "blocker"),
    (
        (
            {"$schema": "s", "$id": "x", "properties": {"p": {"$ref": "#/$defs/d"}}, "$defs": {"d": {}}},
            None,
        ),
        ({"$schema": "s", "$id": "x", "properties": {"p": {"$ref": "b.json"}}}, None),
        ({"$schema": "s", "$id": "x", "properties": {"p": {"$ref": "other.json#/d"}}}, "REFERENCE_UNOWNED_TARGET"),
        ({"$schema": "s", "$id": "x", "properties": {"p": {"$ref": "../../escape.json"}}}, "REFERENCE_UNOWNED_TARGET"),
        ({"$schema": "s", "$id": "x", "properties": {"p": {"$ref": "https://example.com/s.json#/a"}}}, "REFERENCE_EXTERNAL_URL"),
        # An absolute $id rebases every relative reference onto an external base.
        ({"$schema": "s", "$id": "https://example.com/root.json", "properties": {"p": {"$ref": "b.json"}}}, "REFERENCE_EXTERNAL_URL"),
        ({"$schema": "s", "$id": "x", "properties": {"p": {"$ref": 7}}}, "REFERENCE_UNREADABLE"),
    ),
)
def test_json_ref_edges_block_unless_they_close_inside_the_owned_set(
    tmp_path: Path, document: dict, blocker: str | None
) -> None:
    owned = _write_tree(
        tmp_path,
        {
            "owned/a.json": json.dumps(document).encode("utf-8"),
            "owned/b.json": b'{"$schema": "s", "$id": "y"}',
        },
    )
    record = audit.counterexample_screen("probe", owned, tmp_path)
    if blocker is None:
        assert record.status == "CLOSED", document
    else:
        assert record.status == "UNKNOWN", document
        assert blocker in _screen_blockers(record), document


def test_architecture_closure_is_open_through_its_external_schema_ref() -> None:
    graph = "src/verifier/schemas/verifier-graph-assurance-1.schema.json"
    record = audit.counterexample_screen("probe", (graph,), ROOT)
    assert record.status == "UNKNOWN"
    assert "REFERENCE_EXTERNAL_URL" in _screen_blockers(record)


def test_synonym_and_substring_denials_never_name_an_original_kind() -> None:
    # "computational architecture" is a synonym, "ARCHITECTURE" contains ARCH as a
    # substring, and "SIM-like" is a compound token; none names the kind itself.
    profile = _row("vstd-profile-architecture-assets")
    for kind, quote in (
        ("ARCH", "not a computational architecture"),
        ("ARCH", "not a computational-model ARCHITECTURE"),
        ("SIM", "not a simulation"),
        ("SIM", "not a SIM-like process"),
    ):
        assert not audit._names_kind(kind, quote), quote
        with pytest.raises(ValueError, match="DENIAL_KIND_ABSENT"):
            audit.audit_row(dataclasses.replace(profile, refutes=((kind, quote),)))
    assert audit._names_kind("SIM", "These test definitions are not SIMs, BOTs")


def test_source_denial_naming_a_longer_word_cannot_refute_a_shorter_kind() -> None:
    # Before the token check, "ARCH" matched inside a source "ARCHITECTURE" by
    # substring, so an altered source sentence could refute the wrong kind.
    profile = _spec("vstd-profile-architecture-assets")
    drifted = dataclasses.replace(
        profile,
        consequence_boundary=profile.consequence_boundary.replace(
            "not a computational-model ARCH", "not a computational-model ARCHITECTURE"
        ),
    )
    specs = tuple(drifted if spec.object_id == drifted.object_id else spec for spec in _specs())
    rows = _with_row(
        _pinned(drifted, refutes=(("ARCH", "not a computational-model ARCHITECTURE"),))
    )
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND:vstd-profile-architecture-assets"):
        audit.validate_source_partition(specs, rows)


def test_identity_clause_decides_only_the_kinds_it_names(monkeypatch: pytest.MonkeyPatch) -> None:
    # Referent versus object: the transfer identity clause describes the test
    # suite as not being a represented subject.  It decides exactly the five kinds
    # it names, and never ARCH or ACTOR for the suite.
    current = _row("vstd-test-current-object-regressions")
    monkeypatch.setitem(
        audit._SCREEN_BY_OBJECT,
        current.object_id,
        _closed(current.object_id, current.path_count),
    )
    decided = audit.audit_row(current)
    for kind in ("HUMAN", "MODEL", "SIM", "BOT", "HARDWARE"):
        question = decided.questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)]
        assert question.status == DOES_NOT_APPLY, kind
        assert "refutes only this row" in question.reason
    for kind in ("ARCH", "ACTOR", "AGENT"):
        assert _question(current, kind).status == UNRESOLVED, kind
    with pytest.raises(ValueError, match="DENIAL_KIND_ABSENT"):
        audit.audit_row(
            dataclasses.replace(current, refutes=(("ARCH", audit.CURRENT_OBJECT_TRANSFER_DENIAL),))
        )


def test_referent_denial_from_another_object_is_not_source_bound() -> None:
    # The fixture-corpus RECEIPT sentence describes checked-in bytes, not the
    # architecture object, so it cannot refute the architecture row.
    corpus_quote = (
        "Checked-in fixture bytes are neither fresh executions nor independently "
        "authoritative RECEIPTs"
    )
    profile = _row("vstd-profile-architecture-assets")
    with pytest.raises(ValueError, match="DENIAL_NOT_SOURCE_BOUND:vstd-profile-architecture-assets"):
        audit.validate_source_partition(
            _specs(),
            _with_row(dataclasses.replace(profile, refutes=(("RECEIPT", corpus_quote),))),
        )


def test_root_reason_substitution_breaks_the_coordinate_pin() -> None:
    # A weakened root reason keeps the same denial verb but changes the declaration
    # text, so the pinned source coordinate must reject it.
    receipt = _spec("vstd-simulation-risk-receipt-assets")
    weakened = dataclasses.replace(
        receipt,
        root_role_decisions=(
            root_role_decision("RECEIPT", DOES_NOT_APPLY, "schema documents are not receipt instances."),
        ),
    )
    specs = tuple(weakened if spec.object_id == weakened.object_id else spec for spec in _specs())
    with pytest.raises(
        ValueError, match="SOURCE_COORDINATE_DRIFT:vstd-simulation-risk-receipt-assets"
    ):
        audit.validate_source_partition(specs)


def test_disclaimer_phrasing_cannot_be_recorded_as_an_identity_denial() -> None:
    # "establishes no ARCH" and "does not establish an ARCH" disclaim a claim;
    # they are not identity predicates and are rejected before any screen.
    profile = _row("vstd-profile-architecture-assets")
    for quote in (
        "These texts establish no computational-model ARCH.",
        "The texts do not establish an ARCH.",
    ):
        with pytest.raises(ValueError, match="DENIAL_NOT_IDENTITY"):
            audit.audit_row(dataclasses.replace(profile, refutes=(("ARCH", quote),)))


def test_primary_label_neither_refutes_nor_exempts_another_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # POLICY is not an original kind, so the primary label grants no APPLIES, and
    # PROTOCOL cannot be used as a denial kind either.
    profile = _row("vstd-profile-architecture-assets")
    row_audit = audit.audit_row(profile)
    assert all(question.status != APPLIES for question in row_audit.questions)
    with pytest.raises(ValueError, match="REFUTES_INVALID"):
        audit.audit_row(
            dataclasses.replace(profile, refutes=(("PROTOCOL", "It is not a PROTOCOL"),))
        )
    # An original primary cannot be refuted, even by an exact identity quote over
    # a closed screen.
    harness = _row("vstd-test-fixture-harness")
    monkeypatch.setitem(
        audit._SCREEN_BY_OBJECT,
        harness.object_id,
        _closed(harness.object_id, harness.path_count),
    )
    with pytest.raises(ValueError, match="ROLE_CONFLICT"):
        audit.audit_row(dataclasses.replace(harness, refutes=(("HARNESS", "It is not a HARNESS"),)))


def test_every_applies_cell_is_a_primary_or_explicit_root_decision() -> None:
    # Stale or foreign citation guard: every APPLIES cell is either the source
    # primary or an exact source-bound root APPLIES decision.
    specs = {spec.object_id: spec for spec in _specs()}
    applies = 0
    for item in audit.AUDITS:
        spec = specs[item.object_id]
        for question in item.questions:
            if question.status != APPLIES:
                continue
            applies += 1
            root_applies = {
                decision.kind
                for decision in spec.root_role_decisions
                if decision.status == APPLIES
            }
            assert (
                question.kind == spec.primary_kind == item.primary
                or question.kind in root_applies
            ), item.object_id
            assert item.object_id in question.reason, item.object_id
    assert applies == 52


def test_owned_paths_are_disjoint_so_no_citation_is_foreign() -> None:
    seen: dict[str, str] = {}
    for spec in _specs():
        for path in spec.owned_paths:
            assert path not in seen, (path, seen.get(path), spec.object_id)
            seen[path] = spec.object_id
    assert len(seen) == 949


FIXTURE_OBJECT_IDS = tuple(sorted(spec.object_id for spec in TEST_FIXTURE_OWNERSHIP_SPECS))
# Structural reconciliation: exact live path counts for the eight test-fixture rows
# that gained 24 paths.  Every other fixture row keeps its prior count.
RECONCILED_FIXTURE_COUNTS = {
    "vstd-test-current-object-regressions": 124,
    "vstd-test-governance-authority-regressions": 40,
    "vstd-test-graph-composition-regressions": 56,
    "vstd-test-hardware-environment-regressions": 23,
    "vstd-test-namespace-admission-regressions": 91,
    "vstd-test-packaging-compatibility-regressions": 22,
    "vstd-test-polish-regressions": 70,
    "vstd-test-runtime-execution-regressions": 60,
}


def test_reconciled_fixture_rows_have_their_exact_live_counts() -> None:
    for object_id, count in RECONCILED_FIXTURE_COUNTS.items():
        assert _row(object_id).path_count == count == len(_spec(object_id).owned_paths), object_id
    assert len(FIXTURE_OBJECT_IDS) == 16
    assert sum(len(spec.owned_paths) for spec in TEST_FIXTURE_OWNERSHIP_SPECS) == 658
    assert sum(_row(object_id).path_count for object_id in FIXTURE_OBJECT_IDS) == 658


def test_every_fixture_row_pins_its_exact_sorted_unique_live_path_set() -> None:
    for object_id in FIXTURE_OBJECT_IDS:
        spec = _spec(object_id)
        row = _row(object_id)
        assert spec.owned_paths == tuple(sorted(set(spec.owned_paths))), object_id
        assert row.path_count == len(spec.owned_paths), object_id
        assert row.path_set_digest == owned_path_set_digest(spec.owned_paths), object_id
        assert row.coordinate_digest == audit._source_coordinate_digest(spec), object_id


def _path_set_substitutions(
    spec: SemanticOwnershipSpec,
) -> tuple[tuple[str, tuple[str, ...], str], ...]:
    paths = spec.owned_paths
    foreign = next(
        other.owned_paths[0]
        for other in TEST_FIXTURE_OWNERSHIP_SPECS
        if other.object_id != spec.object_id
    )
    cases = [
        ("dropped", paths[:-1], "SOURCE_PATH_DRIFT"),
        ("duplicated", paths + (paths[0],), "SOURCE_PATH_DRIFT"),
        ("unowned_appended", paths + ("tests/zz_unowned_adversarial.py",), "SOURCE_PATH_DRIFT"),
        ("unowned_same_count", paths[:-1] + ("tests/zz_unowned_adversarial.py",), "SOURCE_PATH_DRIFT"),
        ("foreign_owner", paths[:-1] + (foreign,), "DUPLICATE_OWNERSHIP"),
    ]
    if len(paths) >= 2:
        swapped = (paths[1], paths[0]) + paths[2:]
        cases.append(("permuted", swapped, "PACKAGE_ORIGINAL_KIND_PROFILE_PATHS_INVALID"))
    return tuple(cases)


def test_every_fixture_row_rejects_each_path_set_substitution_for_its_precise_reason() -> None:
    # Each object is substituted alone against its pinned row, so only the path check
    # for that object can fire, and an order-only permutation fails the sorted-set check.
    for spec in TEST_FIXTURE_OWNERSHIP_SPECS:
        for label, paths, expected in _path_set_substitutions(spec):
            substituted = dataclasses.replace(spec, owned_paths=paths)
            specs = tuple(
                substituted if other.object_id == spec.object_id else other for other in _specs()
            )
            with pytest.raises(ValueError) as caught:
                audit.validate_source_partition(specs)
            assert expected in str(caught.value), (spec.object_id, label, str(caught.value))


AGENCY = "vstd-agency-surface-crosswalk-assets"
AGENCY_OBJECT_CLAUSE = (
    "an OBJECT label or unknown applicability cannot exempt a conditional route"
)


def test_agency_crosswalk_retains_every_original_kind_obligation() -> None:
    row = _row(AGENCY)
    expected = tuple(
        kind for kind in AGENCY_CROSSWALK_APPLIES if kind in ORIGINAL_NON_OBJECT_KINDS
    )
    assert (row.primary, row.path_count, row.applies, row.refutes) == (
        "POLICY",
        1,
        expected,
        (),
    )
    spec = _spec(AGENCY)
    assert spec.primary_kind == "POLICY"
    assert spec.specializations == ("PROTOCOL",)
    assert tuple(decision.kind for decision in spec.root_role_decisions) == (
        AGENCY_CROSSWALK_ROOT_APPLIES
    )
    assert {decision.status for decision in spec.root_role_decisions} == {APPLIES}
    assert spec.owned_paths == ("src/verifier/standard/AGENCY_SURFACE.md",)
    statuses = {question.kind: question.status for question in _audit(AGENCY).questions}
    assert len(statuses) == 25
    assert set(statuses.values()) == {APPLIES}
    assert {(AGENCY, kind) for kind in ORIGINAL_NON_OBJECT_KINDS} <= set(_decided())
    assert AGENCY in {assignment.object_id for assignment in audit.PARTIAL_PROFILE.assignments}


def test_agency_crosswalk_roles_are_conservative_not_semantic_promotion() -> None:
    statuses = {question.kind: question.status for question in _audit(AGENCY).questions}
    for kind in ("AGENT", "BOT", "VERIFIER", "SIM", "HARDWARE", "ENV", "HUMAN"):
        assert statuses[kind] == APPLIES, kind
    spec = _spec(AGENCY)
    assert all(
        "obligations remain required" in decision.reason
        and "neither subject instantiation nor external effect" in decision.reason
        for decision in spec.root_role_decisions
    )
    assert "NOT_ESTABLISHED" in spec.consequence_boundary


def test_agency_crosswalk_omission_is_denominator_drift() -> None:
    kept = tuple(spec for spec in _specs() if spec.object_id != AGENCY)
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        audit.validate_source_partition(kept)
    dropped = tuple(row for row in audit.REVIEW_ROWS if row.object_id != AGENCY)
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        audit.validate_source_partition(_specs(), dropped)


def test_agency_crosswalk_wrong_primary_is_rejected() -> None:
    row = dataclasses.replace(_row(AGENCY), primary="PROTOCOL")
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT:" + AGENCY):
        audit.validate_source_partition(_specs(), _with_row(row))


def test_agency_crosswalk_wrong_specialization_changes_its_pinned_coordinate() -> None:
    spec = _spec(AGENCY)
    accumulated = dataclasses.replace(spec, specializations=("BOT",))
    specs = tuple(accumulated if item.object_id == AGENCY else item for item in _specs())
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT:" + AGENCY):
        audit.validate_source_partition(specs)


def test_agency_crosswalk_cannot_drop_or_refute_a_required_role() -> None:
    row = _row(AGENCY)
    for kind in ("AGENT", "BOT"):
        dropped = dataclasses.replace(
            row, applies=tuple(item for item in row.applies if item != kind)
        )
        with pytest.raises(ValueError, match="ACCUMULATED_ROLE_DRIFT:" + AGENCY):
            audit.validate_source_partition(_specs(), _with_row(dropped))
    contradicted = dataclasses.replace(row, refutes=(("BOT", "is not a BOT"),))
    with pytest.raises(ValueError, match="ROLE_CONFLICT:" + AGENCY):
        audit.validate_source_partition(_specs(), _with_row(contradicted))


def test_agency_crosswalk_object_label_cannot_exempt_its_routes() -> None:
    row = _row(AGENCY)
    with pytest.raises(ValueError, match="OBJECT_BYPASS:" + AGENCY):
        audit.audit_row(dataclasses.replace(row, primary="OBJECT"))
    with pytest.raises(ValueError, match="OBJECT_BYPASS:" + AGENCY):
        audit.audit_row(dataclasses.replace(row, refutes=(("OBJECT", AGENCY_OBJECT_CLAUSE),)))
    # The clause is verbatim source text, so only the bypass rule rejects it.
    assert AGENCY_OBJECT_CLAUSE in _spec(AGENCY).necessity_reason


def test_agency_crosswalk_path_claimed_by_a_second_owner_is_duplicate_ownership() -> None:
    duplicate = dataclasses.replace(
        _spec(AGENCY), object_id="vstd-agency-surface-duplicate-assets"
    )
    specs = (*_specs(), duplicate)
    rows = (*audit.REVIEW_ROWS, _pinned(duplicate))
    with pytest.raises(ValueError, match="DUPLICATE_OWNERSHIP:src/verifier/standard/AGENCY_SURFACE.md"):
        audit.validate_source_partition(specs, rows)


def test_duplicated_row_is_rejected_before_any_question_is_answered() -> None:
    rows = (*audit.REVIEW_ROWS, _row(AGENCY))
    with pytest.raises(ValueError, match="ROWS_INVALID"):
        audit.validate_source_partition(_specs(), rows)
