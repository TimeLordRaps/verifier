from __future__ import annotations

import ast
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import sys

import pytest

from verifier.runtime import package_original_kind_catalog_scripts_examples as catalog
from verifier.runtime.package_original_kind_catalog_scripts_examples import (
    BEHAVIORAL_PREFIX,
    CLAIM_BOUNDARY,
    CLOSED_PREFIX,
    REVIEWED_SOURCE_BINDING_DIGEST,
    REVIEWED_SOURCE_PINS,
    SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS,
    SCRIPT_EXAMPLE_PARTIAL_PROFILE,
    UNRESOLVED,
    _NON_EXECUTION_BASIS,
    _closed_blocker,
    _question_reason,
    _scan_effects,
    behavioral_evidence,
    closed_evidence,
    current_source_partition,
    review_document,
    validate_source_partition,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    profile_digest,
    profile_document,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_semantic_ownership_model import RootRoleDecision


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_SOURCE = (
    REPO_ROOT
    / "src"
    / "verifier"
    / "runtime"
    / "package_original_kind_catalog_scripts_examples.py"
)

# Literal oracle copied from the source declarations, not from the catalog.
EXPECTED_ROOT_APPLIES = {
    ("vstd-artifact-network-fixture-ledger", "DATA"),
    ("vstd-documentation-site-assembly", "ENV"),
    ("vstd-documentation-site-assembly", "HARNESS"),
    ("vstd-domain-grounding-specimen", "AGENT"),
    ("vstd-domain-grounding-specimen", "BENCH"),
    ("vstd-domain-grounding-specimen", "BOT"),
    ("vstd-domain-grounding-specimen", "DATA"),
    ("vstd-domain-grounding-specimen", "ENV"),
    ("vstd-domain-grounding-specimen", "HARDWARE"),
    ("vstd-domain-grounding-specimen", "HARNESS"),
    ("vstd-domain-grounding-specimen", "MODEL"),
    ("vstd-domain-grounding-specimen", "SIM"),
    ("vstd-domain-grounding-specimen", "TOKEN"),
    ("vstd-domain-grounding-specimen", "TRAIN"),
    ("vstd-example-dataset-gate-verifier", "DATA"),
    ("vstd-example-gate-pipeline", "DATA"),
    ("vstd-experiment-index-materialization", "VERIFIER"),
    ("vstd-first-software-workflow-declarations", "DATA"),
    ("vstd-graph-topology-specimen", "GRAPH"),
    ("vstd-graph-topology-specimen", "HYPER"),
    ("vstd-interoperability-composition-harness", "VERIFIER"),
    ("vstd-local-preflight-controller", "ENV"),
    ("vstd-local-preflight-controller", "HARNESS"),
    ("vstd-local-preflight-controller", "VERIFIER"),
    ("vstd-logits-constraint-harness", "DATA"),
    ("vstd-logits-constraint-harness", "VERIFIER"),
    ("vstd-monograph-build-transaction", "HARNESS"),
    ("vstd-package-manifest-migration-controller", "ENV"),
    ("vstd-package-manifest-migration-controller", "RECEIPT"),
    ("vstd-package-manifest-migration-controller", "VERIFIER"),
    ("vstd-platform-evidence-recording", "ENV"),
    ("vstd-prdel-self-polish-declarations", "DATA"),
    ("vstd-prdel-source-selection-checks", "HARNESS"),
    ("vstd-public-reference-generation", "ENV"),
    ("vstd-public-reference-generation", "HARNESS"),
    ("vstd-public-reference-generation", "VERIFIER"),
    ("vstd-public-source-policy-gates", "HARNESS"),
    ("vstd-publication-state-observers", "VERIFIER"),
    ("vstd-pull-request-promotion-policy", "HARNESS"),
    ("vstd-release-artifact-controller", "ENV"),
    ("vstd-release-artifact-controller", "HARNESS"),
    ("vstd-release-artifact-controller", "VERIFIER"),
    ("vstd-risc0-proof-environment", "DATA"),
    ("vstd-risc0-proof-host-controller", "HARNESS"),
    ("vstd-risc0-proof-host-controller", "RECEIPT"),
    ("vstd-risc0-proof-host-controller", "VERIFIER"),
    ("vstd-risc0-recorded-proof", "RECEIPT"),
    ("vstd-scitt-distribution-fetch-controller", "ENV"),
    ("vstd-scitt-distribution-fetch-controller", "HARNESS"),
    ("vstd-scitt-distribution-fetch-controller", "VERIFIER"),
    ("vstd-scitt-local-log-specimen", "DATA"),
    ("vstd-scitt-native-comparison-plan", "DATA"),
    ("vstd-scitt-native-execution-harness", "ENV"),
    ("vstd-scitt-native-execution-harness", "HARNESS"),
    ("vstd-scitt-requirement-consistency-verifier", "ENV"),
    ("vstd-scitt-source-freeze-transaction", "VERIFIER"),
    ("vstd-stored-component-export", "HARNESS"),
    ("vstd-verification-geometry-residual", "GRAPH"),
    ("vstd-workflow-verdict-neutrality-specimen", "DATA"),
    ("vstd-workflow-verdict-neutrality-specimen", "EVENT"),
    ("vstd-zero-identity-status-model", "DATA"),
}
EXPECTED_DOES_NOT_APPLY = {
    ("vstd-artifact-network-fixture-ledger", "RECEIPT"),
    ("vstd-example-catalog-guide", "HARNESS"),
    ("vstd-flagship-adversarial-receipts", "RECEIPT"),
    ("vstd-logits-constraint-harness", "MODEL"),
    ("vstd-platform-evidence-recording", "RECEIPT"),
    ("vstd-prdel-self-polish-declarations", "HARNESS"),
    ("vstd-scitt-comparison-catalog-entry", "RECEIPT"),
    ("vstd-scitt-local-log-specimen", "RECEIPT"),
    ("vstd-scitt-native-package-marker", "HARNESS"),
    ("vstd-scitt-native-package-marker", "RECEIPT"),
    ("vstd-scitt-native-package-marker", "VERIFIER"),
    ("vstd-selected-validation-guide", "HARNESS"),
    ("vstd-selected-validation-guide", "VERIFIER"),
    ("vstd-zero-identity-policy", "IDENTITY"),
    ("vstd-zero-identity-policy", "RECEIPT"),
    ("vstd-zero-identity-status-model", "IDENTITY"),
    ("vstd-zero-identity-status-model", "MODEL"),
    ("vstd-zero-identity-status-model", "RECEIPT"),
    ("vstd-zizk-reference-guide", "IDENTITY"),
    ("vstd-zizk-reference-guide", "RECEIPT"),
}
# Behavioral source citations (see _BEHAVIORAL_OVERRIDES in the catalog source).
EXPECTED_BEHAVIORAL_APPLIES = {
    ("vstd-publication-state-observers", "ENV"),
    ("vstd-zero-identity-fixture-corpus", "IDENTITY"),
    ("vstd-zero-identity-reference-verifier", "IDENTITY"),
}
# Closed-surface DNE cells: each needs a verbatim source-owned non-execution basis and a
# clean live scan. The 18 candidates of the four owners below have no such basis and
# carry executable owned code, so they stay UNRESOLVED with their exact blocker.
EXPECTED_CLOSED_DNE_CELLS = 86
EXPECTED_DOWNGRADED_CLOSED_CELLS = {
    ("vstd-first-software-workflow-declarations", kind)
    for kind in ("BENCH", "ENV", "HARDWARE", "MODEL", "TRAIN")
} | {
    ("vstd-generic-run-specimen", kind)
    for kind in ("BENCH", "ENV", "HARDWARE", "MODEL", "TRAIN")
} | {
    ("vstd-monograph-build-transaction", kind)
    for kind in ("BENCH", "HARDWARE", "MODEL", "TRAIN")
} | {
    ("vstd-prdel-source-selection-checks", kind)
    for kind in ("BENCH", "HARDWARE", "MODEL", "TRAIN")
}


def _rows_by_id():
    return {row.object_id: row for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS}


def _with_question(row, index, **changes):
    questions = list(row.questions)
    questions[index] = replace(questions[index], **changes)
    return replace(row, questions=tuple(questions))


def _audits_with(object_id, transform):
    return tuple(
        transform(row) if row.object_id == object_id else row
        for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS
    )


def test_audit_has_exact_55_rows_175_paths_and_25_literal_questions_each() -> None:
    rows = SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS
    assert len(rows) == 55
    ids = [row.object_id for row in rows]
    assert len(set(ids)) == 55
    assert ids == sorted(ids)
    paths = [path for row in rows for path in row.expected_owned_paths]
    assert len(paths) == 175
    assert len(set(paths)) == 175
    for row in rows:
        assert tuple(question.kind for question in row.questions) == (
            ORIGINAL_NON_OBJECT_KINDS
        )
        assert all(
            question.reason.startswith(row.scope_reason)
            for question in row.questions
        )
        assert all(question.kind in question.reason for question in row.questions)


def test_source_lists_every_question_literally_without_complement() -> None:
    source = CATALOG_SOURCE.read_text(encoding="utf-8")
    literal = source.split("_RAW_AUDITS = (", 1)[1].split(
        "@dataclass(frozen=True)\nclass _EffectScan", 1
    )[0]
    assert literal.count('_question("') == 55 * 25
    assert "for kind in" not in literal
    assert "set(ORIGINAL_NON_OBJECT_KINDS)" not in literal
    assert "difference(" not in literal
    assert literal.count('_question("') == literal.count("_question(")


def test_current_source_partition_is_exact_and_every_owned_path_exists() -> None:
    selected = current_source_partition()
    assert validate_source_partition(selected) == selected
    assert tuple(spec.object_id for spec in selected) == tuple(
        row.object_id for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS
    )
    assert sum(len(spec.owned_paths) for spec in selected) == 175
    assert [
        path
        for spec in selected
        for path in spec.owned_paths
        if not (REPO_ROOT / path).is_file()
    ] == []


def test_only_source_declared_roles_apply_and_counts_are_exact() -> None:
    applies = set()
    behavioral = set()
    dne = set()
    closed = set()
    unresolved = 0
    for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            pair = (row.object_id, question.kind)
            if question.status == APPLIES:
                applies.add(pair)
                if question.evidence.startswith(BEHAVIORAL_PREFIX):
                    behavioral.add(pair)
            elif question.status == DOES_NOT_APPLY:
                dne.add(pair)
                if question.evidence.startswith(CLOSED_PREFIX):
                    closed.add(pair)
            else:
                assert question.status == UNRESOLVED
                unresolved += 1
    root_applies = {
        pair for pair in applies if pair in EXPECTED_ROOT_APPLIES
    }
    primary_applies = applies - root_applies - behavioral
    assert root_applies == EXPECTED_ROOT_APPLIES
    assert behavioral == EXPECTED_BEHAVIORAL_APPLIES
    assert dne - closed == EXPECTED_DOES_NOT_APPLY
    assert len(closed) == EXPECTED_CLOSED_DNE_CELLS
    assert len(primary_applies) == 36
    assert all(kind == _rows_by_id()[object_id].expected_primary for object_id, kind in primary_applies)
    assert len(applies) == 100
    assert len(dne) == 106
    assert unresolved == 1169


def test_closed_candidates_without_a_source_basis_are_downgraded_with_exact_blockers() -> None:
    # Absence insufficient: a clean scan alone never keeps a closed-surface DNE.
    downgraded = set()
    for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if (row.object_id, question.kind) in EXPECTED_DOWNGRADED_CLOSED_CELLS:
                downgraded.add((row.object_id, question.kind))
                assert question.status == UNRESOLVED
                assert question.evidence == ""
                assert "Closed-surface downgrade: no verbatim source-owned non-execution basis" in question.reason
                assert "owned executable code:" in question.reason
    assert downgraded == EXPECTED_DOWNGRADED_CLOSED_CELLS
    assert set(_NON_EXECUTION_BASIS).isdisjoint(
        {object_id for object_id, _kind in EXPECTED_DOWNGRADED_CLOSED_CELLS}
    )


def test_every_closed_dne_quotes_its_own_owners_verbatim_basis() -> None:
    selected = {spec.object_id: spec for spec in current_source_partition()}
    for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS:
        closed = [q for q in row.questions if q.evidence.startswith(CLOSED_PREFIX)]
        if not closed:
            continue
        basis = _NON_EXECUTION_BASIS[row.object_id]
        spec = selected[row.object_id]
        assert basis in "\n".join(
            (spec.representation_role, spec.necessity_reason, spec.consequence_boundary)
        ), row.object_id
        for question in closed:
            assert '"' + basis + '"' in question.reason, (row.object_id, question.kind)


def test_partial_profile_is_digest_bound_and_contains_only_decided_rows() -> None:
    profile = SCRIPT_EXAMPLE_PARTIAL_PROFILE
    assert validate_profile(profile) is profile
    assert profile_digest(profile) == profile.canonical_digest
    assert len(profile.assignments) == 54
    assert sum(len(assignment.decisions) for assignment in profile.assignments) == 206
    assert all(
        decision.status in {APPLIES, DOES_NOT_APPLY}
        for assignment in profile.assignments
        for decision in assignment.decisions
    )
    decided_ids = {
        row.object_id
        for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS
        if any(question.status != UNRESOLVED for question in row.questions)
    }
    assert {assignment.object_id for assignment in profile.assignments} == decided_ids
    document = profile_document(profile)
    assert document["canonical_digest"] == profile.canonical_digest
    assert all(
        decision["status"] != UNRESOLVED
        for assignment in document["assignments"]
        for decision in assignment["decisions"]
    )


def test_partial_profile_cannot_claim_package_or_script_closure() -> None:
    profile = SCRIPT_EXAMPLE_PARTIAL_PROFILE
    profile_ids = tuple(
        sorted(assignment.object_id for assignment in profile.assignments)
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_OBJECT_DENOMINATOR_INCOMPLETE",
    ):
        validate_full_closure(
            profile,
            tuple(sorted(row.object_id for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS)),
            expected_object_count=55,
        )
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_KIND_PROFILE_KIND_DENOMINATOR_INCOMPLETE",
    ):
        validate_full_closure(
            profile,
            profile_ids,
            expected_object_count=len(profile_ids),
        )
    assert "no full package" in CLAIM_BOUNDARY
    assert "UNRESOLVED" in CLAIM_BOUNDARY


def test_source_drift_and_denominator_substitution_fail_closed() -> None:
    selected = list(current_source_partition())
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        validate_source_partition(selected[:-1])
    substituted = list(selected)
    substituted[0] = replace(substituted[0], object_id="vstd-not-a-declared-row")
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        validate_source_partition(substituted)
    duplicated = [*selected, selected[0]]
    with pytest.raises(ValueError, match="SOURCE_PARTITION_INVALID"):
        validate_source_partition(duplicated)


def test_object_label_cannot_bypass_the_25_question_matrix() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.primary_kind == "VERIFIER"
    )
    selected[index] = replace(selected[index], primary_kind="OBJECT")
    with pytest.raises(ValueError, match="OBJECT_BYPASS"):
        validate_source_partition(selected)

    selected = list(current_source_partition())
    index = selected.index(
        next(spec for spec in selected if spec.object_id == "vstd-graph-topology-specimen")
    )
    selected[index] = replace(
        selected[index],
        root_role_decisions=(
            RootRoleDecision("OBJECT", APPLIES, "label, not an original kind"),
        ),
    )
    with pytest.raises(ValueError, match="OBJECT_BYPASS"):
        validate_source_partition(selected)

    rows = _audits_with(
        "vstd-graph-topology-specimen",
        lambda row: replace(
            row,
            questions=tuple(
                replace(question, kind="OBJECT") if question.kind == "ACTOR" else question
                for question in row.questions
            ),
        ),
    )
    with pytest.raises(ValueError, match="REVIEW_DENOMINATOR_DRIFT"):
        validate_source_partition(current_source_partition(), rows)


def test_path_primary_reason_and_coordinate_drift_fail_closed() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-example-catalog-guide"
    )
    target = selected[index]

    selected[index] = replace(
        target, owned_paths=("examples/not-the-audited-path.md",)
    )
    with pytest.raises(ValueError, match="PATH_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, primary_kind="ARCH_SUBSTITUTE")
    with pytest.raises(ValueError, match="PRIMARY_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, necessity_reason="substituted necessity")
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, consequence_boundary="substituted boundary")
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)


def test_manifest_controller_accumulates_env_receipt_and_verifier_but_not_ledger() -> None:
    """The journal's three mechanisms apply; accounting LEDGER is explicitly refuted."""

    object_id = "vstd-package-manifest-migration-controller"
    spec = next(item for item in current_source_partition() if item.object_id == object_id)
    row = _rows_by_id()[object_id]
    decisions = {
        decision.kind: (decision.status, decision.reason)
        for decision in spec.root_role_decisions
    }
    assert set(decisions) == {"ENV", "RECEIPT", "VERIFIER"}
    assert all(status == APPLIES and reason.strip() for status, reason in decisions.values())
    questions = {question.kind: question for question in row.questions}
    for kind in ("ENV", "RECEIPT", "VERIFIER"):
        assert questions[kind].status == APPLIES
        assert questions[kind].evidence == decisions[kind][1]
        assert decisions[kind][1] in questions[kind].reason
    assert "not an accounting LEDGER" in spec.consequence_boundary
    assert "no units, balances, issuance, or sources and sinks" in spec.consequence_boundary
    assert "LEDGER" not in {spec.primary_kind, *spec.specializations, *decisions}


def test_manifest_transition_text_does_not_infer_a_harness_role() -> None:
    """Recorded launch coordinates are referents, not this controller's executions."""

    object_id = "vstd-package-manifest-migration-controller"
    source = (
        REPO_ROOT / "src/verifier/runtime/package_manifest_migration.py"
    ).read_text(encoding="utf-8")
    assert "callee=subprocess.run" in source
    spec = next(item for item in current_source_partition() if item.object_id == object_id)
    assert "HARNESS" not in {
        spec.primary_kind,
        *spec.specializations,
        *(decision.kind for decision in spec.root_role_decisions),
    }
    harness = next(
        question
        for question in _rows_by_id()[object_id].questions
        if question.kind == "HARNESS"
    )
    assert harness.status == UNRESOLVED
    assert harness.evidence == ""


@pytest.mark.parametrize("omitted", ("ENV", "RECEIPT"))
def test_manifest_controller_cannot_omit_new_source_declared_roles(omitted: str) -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-package-manifest-migration-controller"
    )
    target = selected[index]
    selected[index] = replace(
        target,
        root_role_decisions=tuple(
            decision for decision in target.root_role_decisions if decision.kind != omitted
        ),
    )
    with pytest.raises(
        ValueError,
        match="SOURCE_COORDINATE_DRIFT:vstd-package-manifest-migration-controller",
    ):
        validate_source_partition(selected)


def test_manifest_controller_cannot_be_falsely_reclassified_as_ledger() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-package-manifest-migration-controller"
    )
    target = selected[index]
    selected[index] = replace(
        target,
        specializations=tuple(sorted((*target.specializations, "LEDGER"))),
    )
    with pytest.raises(
        ValueError,
        match="SOURCE_COORDINATE_DRIFT:vstd-package-manifest-migration-controller",
    ):
        validate_source_partition(selected)


def test_five_reviewed_sources_have_exact_per_path_current_byte_pins() -> None:
    expected = (
        (
            "vstd-public-source-policy-gates",
            "scripts/check_namespace_closure.py",
            "sha256:88a88d91befb87e45848569360e3ebc526489e0abb49e0d879714d427650f0e2",
        ),
        (
            "vstd-local-preflight-controller",
            "scripts/preflight.py",
            "sha256:04631ee735248af418f758f281f165394d5996eec6f1815c3426fd8e9cf5235b",
        ),
        (
            "vstd-release-artifact-controller",
            "scripts/release_artifacts.py",
            "sha256:804a8d7b98402678b620ecb3b54159585de561ae5398be18607f55eff489715e",
        ),
        (
            "vstd-package-manifest-migration-controller",
            "src/verifier/runtime/package_manifest_migration.py",
            "sha256:06f56ce5b04d5b93e42cf7c6f77df37ebb41cc239c0c290887521fb7fc6bdcfb",
        ),
        (
            "vstd-package-manifest-migration-controller",
            "src/verifier/runtime/package_manifest_refresh.py",
            "sha256:d26fc242bbdf012c179a665f1aaa03f7eb55dbc255d2ae18f21c970796cff78a",
        ),
    )
    assert REVIEWED_SOURCE_PINS == expected
    assert REVIEWED_SOURCE_BINDING_DIGEST == "sha256:" + sha256(
        "\n".join("\t".join(pin) for pin in expected).encode("ascii")
    ).hexdigest()
    for _object_id, path, expected_digest in expected:
        assert "sha256:" + sha256((REPO_ROOT / path).read_bytes()).hexdigest() == expected_digest


@pytest.mark.parametrize(
    ("object_id", "path", "_expected_digest"), REVIEWED_SOURCE_PINS
)
def test_each_reviewed_source_rejects_same_size_byte_drift(
    tmp_path: Path, object_id: str, path: str, _expected_digest: str
) -> None:
    root = _owned_copy(tmp_path)
    target = root / path
    changed = bytearray(target.read_bytes())
    changed[-1] ^= 1
    target.write_bytes(changed)
    with pytest.raises(ValueError) as raised:
        validate_source_partition(current_source_partition(), root=root)
    assert str(raised.value) == (
        "SCRIPT_EXAMPLE_ORIGINAL_KIND_REVIEWED_SOURCE_PIN_DIFFERS:"
        + object_id
        + ":"
        + path
    )


def test_reviewed_source_path_substitution_fails_at_the_exact_path(tmp_path: Path) -> None:
    # Same-set aggregate rebinding must not permit one path to carry another path's bytes.
    root = _owned_copy(tmp_path)
    object_id, target_path, _digest = REVIEWED_SOURCE_PINS[0]
    _other_object, other_path, _other_digest = REVIEWED_SOURCE_PINS[1]
    (root / target_path).write_bytes((root / other_path).read_bytes())
    with pytest.raises(ValueError) as raised:
        validate_source_partition(current_source_partition(), root=root)
    assert str(raised.value) == (
        "SCRIPT_EXAMPLE_ORIGINAL_KIND_REVIEWED_SOURCE_PIN_DIFFERS:"
        + object_id
        + ":"
        + target_path
    )


def test_reviewed_source_missing_path_is_typed_and_exact(tmp_path: Path) -> None:
    root = _owned_copy(tmp_path)
    object_id, path, _digest = REVIEWED_SOURCE_PINS[0]
    (root / path).unlink()
    with pytest.raises(ValueError) as raised:
        validate_source_partition(current_source_partition(), root=root)
    assert str(raised.value) == (
        "SCRIPT_EXAMPLE_ORIGINAL_KIND_REVIEWED_SOURCE_UNAVAILABLE:"
        + object_id
        + ":"
        + path
    )


def test_reviewed_source_alias_is_not_a_regular_owned_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _owned_copy(tmp_path)
    object_id, path, _digest = REVIEWED_SOURCE_PINS[0]
    target = root / path
    original_is_symlink = Path.is_symlink

    def report_selected_alias(candidate: Path) -> bool:
        return candidate == target or original_is_symlink(candidate)

    # The rejection is based on the standard-library alias observation rather
    # than OS-specific symlink creation privileges, so this regression is
    # deterministic on Windows and POSIX.
    monkeypatch.setattr(Path, "is_symlink", report_selected_alias)
    with pytest.raises(ValueError) as raised:
        validate_source_partition(current_source_partition(), root=root)
    assert str(raised.value) == (
        "SCRIPT_EXAMPLE_ORIGINAL_KIND_REVIEWED_SOURCE_ALIAS:"
        + object_id
        + ":"
        + path
    )


def test_closing_snapshot_rejects_concurrent_reviewed_source_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _owned_copy(tmp_path)
    _object_id, path, _digest = REVIEWED_SOURCE_PINS[1]
    target = root / path
    original = catalog._reviewed_source_snapshot
    calls = 0

    def mutate_after_opening(selected_root: Path):
        nonlocal calls
        result = original(selected_root)
        if calls == 0:
            target.write_bytes(target.read_bytes() + b"\n# concurrent drift\n")
        calls += 1
        return result

    monkeypatch.setattr(catalog, "_reviewed_source_snapshot", mutate_after_opening)
    with pytest.raises(
        ValueError,
        match="SCRIPT_EXAMPLE_ORIGINAL_KIND_REVIEWED_SOURCE_PIN_DIFFERS",
    ):
        validate_source_partition(current_source_partition(), root=root)
    assert calls == 1


def test_removing_a_source_refutation_cannot_keep_the_exclusion() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-zero-identity-policy"
    )
    selected[index] = replace(selected[index], root_role_decisions=())
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)


def test_primary_original_kind_cannot_be_refuted() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-zero-identity-reference-verifier"
    )
    selected[index] = replace(
        selected[index],
        root_role_decisions=(
            *selected[index].root_role_decisions,
            RootRoleDecision("VERIFIER", DOES_NOT_APPLY, "attempted primary refutation"),
        ),
    )
    with pytest.raises(ValueError, match="PRIMARY_REFUTED"):
        validate_source_partition(selected)


def test_conflicting_accumulated_roles_hard_fail() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-graph-topology-specimen"
    )
    selected[index] = replace(
        selected[index],
        root_role_decisions=(
            RootRoleDecision("HYPER", APPLIES, "explicit applicability"),
            RootRoleDecision("HYPER", DOES_NOT_APPLY, "explicit incompatible exclusion"),
        ),
    )
    with pytest.raises(ValueError, match="SOURCE_ROLE_CONFLICT"):
        validate_source_partition(selected)


def test_promoting_an_unresolved_question_to_applies_fails_closed() -> None:
    rows = _audits_with(
        "vstd-artifact-network-fixture-ledger",
        lambda row: _with_question(
            row, 0, status=APPLIES, evidence="primary_kind"
        ),
    )
    with pytest.raises(ValueError, match="ACCUMULATED_ROLE_DRIFT"):
        validate_source_partition(current_source_partition(), rows)


def test_substituting_a_refutation_reason_or_evidence_fails_closed() -> None:
    rows = _audits_with(
        "vstd-zero-identity-policy",
        lambda row: _with_question(
            row,
            list(row.questions).index(
                next(q for q in row.questions if q.kind == "IDENTITY")
            ),
            evidence="a substituted exclusion",
        ),
    )
    with pytest.raises(ValueError, match="ACCUMULATED_ROLE_DRIFT"):
        validate_source_partition(current_source_partition(), rows)

    rows = _audits_with(
        "vstd-zero-identity-policy",
        lambda row: _with_question(
            row,
            list(row.questions).index(
                next(q for q in row.questions if q.kind == "IDENTITY")
            ),
            reason="a substituted reason with the same status",
        ),
    )
    with pytest.raises(ValueError, match="REASON_DRIFT"):
        validate_source_partition(current_source_partition(), rows)


def test_dropped_or_duplicated_questions_and_rows_fail_closed() -> None:
    rows = _audits_with(
        "vstd-graph-topology-specimen",
        lambda row: replace(row, questions=row.questions[:-1]),
    )
    with pytest.raises(ValueError, match="REVIEW_DENOMINATOR_DRIFT"):
        validate_source_partition(current_source_partition(), rows)

    rows = tuple(
        row for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS
        if row.object_id != "vstd-graph-topology-specimen"
    )
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        validate_source_partition(current_source_partition(), rows)

    rows = (*SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS[0])
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        validate_source_partition(current_source_partition(), rows)


def test_review_document_exposes_every_unknown_reason_and_profile_binding() -> None:
    document = review_document()
    assert len(document) == 55
    assert all(
        tuple(entry["questions"]) == ORIGINAL_NON_OBJECT_KINDS
        for entry in document.values()
    )
    statuses = [
        question["status"]
        for entry in document.values()
        for question in entry["questions"].values()
    ]
    assert statuses.count(APPLIES) == 100
    assert statuses.count(DOES_NOT_APPLY) == 106
    assert statuses.count(UNRESOLVED) == 1169
    profile_ids = {
        assignment.object_id for assignment in SCRIPT_EXAMPLE_PARTIAL_PROFILE.assignments
    }
    documented_pins = {
        (object_id, path, digest)
        for object_id, entry in document.items()
        for path, digest in entry["expected_reviewed_source_sha256"].items()
    }
    assert documented_pins == set(REVIEWED_SOURCE_PINS)
    for object_id, entry in document.items():
        assert entry["expected_source_coordinate_digest"].startswith("sha256:")
        assert entry["expected_owned_path_set_digest"].startswith("sha256:")
        assert entry["reviewed_source_binding_digest"] == REVIEWED_SOURCE_BINDING_DIGEST
        assert all(question["reason"].strip() for question in entry["questions"].values())
        assert (entry["partial_profile_digest"] is not None) == (object_id in profile_ids)
        assert entry["partial_profile_digest"] in {
            None,
            SCRIPT_EXAMPLE_PARTIAL_PROFILE.canonical_digest,
        }
        for kind, question in entry["questions"].items():
            if question["status"] == UNRESOLVED:
                if "Closed-surface downgrade:" in question["reason"]:
                    assert question["reason"].endswith(".")
                else:
                    assert question["reason"].endswith(
                        kind + " remains UNRESOLVED."
                    )
            if question["status"] == DOES_NOT_APPLY:
                if "Closed effect surface" in question["reason"]:
                    assert "no effect of this owner declares " + kind in question["reason"]
                else:
                    assert "DOES_NOT_APPLY" in question["reason"]


def test_module_uses_only_standard_library_and_verifier_imports() -> None:
    tree = ast.parse(CATALOG_SOURCE.read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules.add((node.module or "").split(".")[0])
    allowed = set(sys.stdlib_module_names) | {"__future__", "verifier"}
    assert modules <= allowed
    assert "verifier" in modules


def test_every_exclusion_is_a_source_declared_root_decision_or_a_closed_surface() -> None:
    # Anti-complement: a DOES_NOT_APPLY cell is either source-declared or a live closed-surface scan.
    selected = {spec.object_id: spec for spec in current_source_partition()}
    for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS:
        declared = {
            decision.kind
            for decision in selected[row.object_id].root_role_decisions
            if decision.status == DOES_NOT_APPLY
            and decision.kind in ORIGINAL_NON_OBJECT_KINDS
        }
        catalog_dne = {
            question.kind
            for question in row.questions
            if question.status == DOES_NOT_APPLY
            and not question.evidence.startswith(CLOSED_PREFIX)
        }
        closed_dne = {
            question.kind
            for question in row.questions
            if question.evidence.startswith(CLOSED_PREFIX)
        }
        assert catalog_dne == declared, row.object_id
        assert closed_dne.isdisjoint(declared), row.object_id


def test_unresolved_cells_are_never_source_declared_and_carry_no_evidence() -> None:
    # Anti-complement: omitted, filename, label, and neighboring-owner cells stay UNRESOLVED.
    selected = {spec.object_id: spec for spec in current_source_partition()}
    for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS:
        spec = selected[row.object_id]
        declared = {decision.kind for decision in spec.root_role_decisions}
        declared |= {spec.primary_kind, *spec.specializations}
        for question in row.questions:
            if question.status != UNRESOLVED:
                continue
            assert question.kind not in declared, (row.object_id, question.kind)
            assert question.evidence == ""


def test_every_new_exclusion_quotes_a_literal_owned_negation() -> None:
    # Explicit-text: a DOES_NOT_APPLY that cites the consequence boundary needs a literal negation there.
    negations = (" no ", " not ", "execute no")
    selected = current_source_partition()
    checked = 0
    for spec in selected:
        for decision in spec.root_role_decisions:
            if decision.status != DOES_NOT_APPLY:
                continue
            if "consequence boundary states" not in decision.reason:
                continue
            checked += 1
            assert any(token in spec.consequence_boundary for token in negations), (
                spec.object_id,
                decision.kind,
            )
    assert checked == 12


def test_synthetic_boundary_does_not_exempt_directly_constructed_high_risk_roles() -> None:
    # High-risk counterexample: "establish no real ..." limits evidence truth, not the constructed role.
    spec = next(
        item
        for item in current_source_partition()
        if item.object_id == "vstd-domain-grounding-specimen"
    )
    assert "establish no real actor, hardware, MODEL, SIM, BOT" in spec.consequence_boundary
    statuses = {
        question.kind: question.status
        for question in _rows_by_id()["vstd-domain-grounding-specimen"].questions
    }
    for kind in ("AGENT", "BENCH", "BOT", "DATA", "ENV", "HARDWARE", "HARNESS", "MODEL", "SIM", "TOKEN", "TRAIN"):
        assert statuses[kind] == APPLIES, kind
    assert statuses["ACTOR"] == UNRESOLVED
    assert statuses["HUMAN"] == UNRESOLVED


def test_dropping_or_substituting_a_constructed_high_risk_role_fails_closed() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-domain-grounding-specimen"
    )
    target = selected[index]
    selected[index] = replace(
        target,
        root_role_decisions=tuple(
            decision for decision in target.root_role_decisions if decision.kind != "MODEL"
        ),
    )
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(
        target,
        root_role_decisions=tuple(
            RootRoleDecision("ACTOR", decision.status, decision.reason)
            if decision.kind == "MODEL"
            else decision
            for decision in target.root_role_decisions
        ),
    )
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)


def test_catalog_substitution_of_a_constructed_role_to_exclusion_fails_closed() -> None:
    model_index = ORIGINAL_NON_OBJECT_KINDS.index("MODEL")
    rows = _audits_with(
        "vstd-domain-grounding-specimen",
        lambda row: _with_question(
            row,
            model_index,
            status=DOES_NOT_APPLY,
            evidence="a substituted exclusion for a constructed role",
        ),
    )
    with pytest.raises(ValueError, match="ACCUMULATED_ROLE_DRIFT"):
        validate_source_partition(current_source_partition(), rows)


def test_new_exclusion_cannot_refute_a_primary_kind() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-selected-validation-guide"
    )
    selected[index] = replace(
        selected[index],
        root_role_decisions=(
            *selected[index].root_role_decisions,
            RootRoleDecision("ARCH", DOES_NOT_APPLY, "attempted primary refutation"),
        ),
    )
    with pytest.raises(ValueError, match="PRIMARY_REFUTED"):
        validate_source_partition(selected)


def _owned_copy(tmp_path: Path) -> Path:
    """Copy every owned path so a mutation can be validated without touching the repo."""

    for spec in current_source_partition():
        for path in spec.owned_paths:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO_ROOT / path).read_bytes())
    return tmp_path


def _closed_owner(kinds: tuple[str, ...], suffix: str) -> tuple[str, str]:
    """Pick an owner with a closed-surface DNE in ``kinds`` and an owned file ending in ``suffix``."""

    for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS:
        closed_kinds = {
            question.kind
            for question in row.questions
            if question.evidence.startswith(CLOSED_PREFIX)
        }
        if not closed_kinds.intersection(kinds):
            continue
        for path in row.expected_owned_paths:
            if path.endswith(suffix):
                return row.object_id, path
    raise AssertionError("no closed-surface owner matches " + repr((kinds, suffix)))


def _mutated_owner(
    tmp_path: Path, kinds: tuple[str, ...], suffix: str, mutate
) -> tuple[str, Path]:
    object_id, path = _closed_owner(kinds, suffix)
    root = _owned_copy(tmp_path)
    target = root / path
    target.write_bytes(mutate(target.read_bytes()))
    return object_id, root


def test_dynamic_import_in_a_closed_owner_breaks_its_closed_surface(tmp_path: Path) -> None:
    # Dynamic escape: importlib can bind any module, so no closed DNE may survive.
    object_id, root = _mutated_owner(
        tmp_path,
        ("BENCH", "ENV", "HARDWARE", "HARNESS", "MODEL", "TRAIN"),
        ".py",
        lambda data: data + b'\nimport importlib\nimportlib.import_module("json")\n',
    )
    with pytest.raises(ValueError, match="CLOSED_SURFACE_NOT_CLOSED:" + object_id):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)


def test_subprocess_in_a_closed_owner_breaks_env_and_harness_closure(tmp_path: Path) -> None:
    # Subprocess inherits the environment, so proc is an ENV channel and a HARNESS effect.
    object_id, root = _mutated_owner(
        tmp_path,
        ("ENV", "HARNESS"),
        ".py",
        lambda data: data + b'\nimport subprocess\nsubprocess.run(["true"], check=False)\n',
    )
    with pytest.raises(ValueError, match="CLOSED_SURFACE_NOT_CLOSED:" + object_id):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)


def test_environment_callback_reference_breaks_env_closure(tmp_path: Path) -> None:
    # Callback: a bound reader is still an environment read, so the ENV DNE must not survive.
    object_id, root = _mutated_owner(
        tmp_path,
        ("ENV",),
        ".py",
        lambda data: data + b"\nimport os\n_reader = os.getenv\n",
    )
    with pytest.raises(ValueError, match="CLOSED_SURFACE_NOT_CLOSED:" + object_id):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)


def test_unresolved_import_leaving_the_owner_breaks_closure(tmp_path: Path) -> None:
    # Unbound import: the target is not an owned file, so the closed surface is open.
    object_id, root = _mutated_owner(
        tmp_path,
        ("BENCH", "ENV", "HARDWARE", "HARNESS", "MODEL", "TRAIN"),
        ".py",
        lambda data: data + b"\nfrom verifier.runtime import namespace_contracts\n",
    )
    with pytest.raises(ValueError, match="CLOSED_SURFACE_NOT_CLOSED:" + object_id):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)


def test_opaque_generated_artifact_breaks_closure(tmp_path: Path) -> None:
    # Opaque bytes cannot be shown effect-free, so a NUL-bearing owned file blocks closure.
    object_id, root = _mutated_owner(
        tmp_path,
        ("BENCH", "ENV", "HARDWARE", "HARNESS", "MODEL", "TRAIN"),
        ".json",
        lambda data: b"\x00" + data,
    )
    with pytest.raises(ValueError, match="CLOSED_SURFACE_NOT_CLOSED:" + object_id):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)


def test_stale_behavioral_needle_fails_closed(tmp_path: Path) -> None:
    # Stale citation: the cited line no longer carries the quoted needle.
    root = _owned_copy(tmp_path)
    target = root / "scripts/check_public_estate_sync.py"
    target.write_bytes(
        target.read_bytes().replace(b"os.environ.get(env_var)", b"os.environ.get(name)", 1)
    )
    with pytest.raises(ValueError, match="BEHAVIORAL_CITATION_DRIFT:vstd-publication-state-observers:ENV"):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)


def test_behavioral_citation_to_a_foreign_owner_fails_closed() -> None:
    # Wrong-source substitution: a real needle in another owner's file is not this object's evidence.
    index = ORIGINAL_NON_OBJECT_KINDS.index("ENV")
    foreign = behavioral_evidence(
        ("examples/zizk_artifact_first/zero_identity/evaluate.py", 85, "def _evaluate_civil_identity(")
    )

    def substitute(row):
        return _with_question(
            row,
            index,
            evidence=foreign,
            reason=_question_reason(row.scope_reason, "ENV", APPLIES, foreign),
        )

    audits = _audits_with("vstd-publication-state-observers", substitute)
    with pytest.raises(ValueError, match="BEHAVIORAL_CITATION_DRIFT:vstd-publication-state-observers:ENV"):
        validate_source_partition(current_source_partition(), audits, root=REPO_ROOT)


def test_closed_exclusion_cannot_be_relabeled_to_another_kind() -> None:
    # Substituted evidence: a closed scan for HARDWARE cannot justify an ENV exclusion.
    object_id = next(
        row.object_id
        for row in SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS
        if any(question.kind == "ENV" and question.evidence.startswith(CLOSED_PREFIX) for question in row.questions)
    )
    index = ORIGINAL_NON_OBJECT_KINDS.index("ENV")
    wrong = closed_evidence("HARDWARE")

    def relabel(row):
        return _with_question(
            row,
            index,
            evidence=wrong,
            reason=_question_reason(row.scope_reason, "ENV", DOES_NOT_APPLY, wrong),
        )

    audits = _audits_with(object_id, relabel)
    with pytest.raises(ValueError, match="CLOSED_CATEGORY_DRIFT:" + object_id + ":ENV"):
        validate_source_partition(current_source_partition(), audits, root=REPO_ROOT)


def test_unmodified_owned_bytes_still_validate_every_new_citation_and_closure() -> None:
    # Positive control: the unmutated tree satisfies every adversarial precondition above.
    validated = validate_source_partition(
        current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=REPO_ROOT
    )
    assert len(validated) == 55


def _scan_one(root: Path, name: str, text: str | bytes):
    """Scan a single owned file written under a fresh root."""

    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return _scan_effects(root, (name,))


def _forced_closed(row, kind: str):
    """Force one closed-surface DNE onto a row, with the reason the catalog would write."""

    index = ORIGINAL_NON_OBJECT_KINDS.index(kind)
    evidence = closed_evidence(kind)
    return _with_question(
        row,
        index,
        status=DOES_NOT_APPLY,
        evidence=evidence,
        reason=_question_reason(row.scope_reason, kind, DOES_NOT_APPLY, evidence),
    )


@pytest.mark.parametrize(
    ("source", "category"),
    [
        ("import time\nt = time.perf_counter_ns()\n", "clock"),
        ("from time import process_time\nprocess_time()\n", "clock"),
        ("import timeit as tm\ntm.default_timer()\n", "clock"),
        ("from os import system\nsystem('true')\n", "proc"),
        ("import os as o\no.popen('true')\n", "proc"),
        ("import os as o\nprint(o.environb)\n", "env"),
        ("from os import getenv as read\nread('HOME')\n", "env"),
        ("import platform as p\np.machine()\n", "platform"),
    ],
)
def test_lexical_synonyms_of_an_effect_break_its_closed_surface(tmp_path, source, category):
    # Lexical synonym: an alias or an unmatched spelling still reaches the same effect.
    scan = _scan_one(tmp_path, "owned/probe.py", source)
    assert any(hit[0] == category for hit in scan.hits)
    assert _closed_blocker(scan, (category,)) == "executable owned code"
    # Isolate the effect vocabulary from the executable-code check.
    effect_only = replace(scan, code=())
    assert _closed_blocker(effect_only, (category,)) == "mapped effect construct"


@pytest.mark.parametrize(
    ("source", "category", "blocker"),
    [
        ("import os\nlist(map(os.system, ['true']))\n", "proc", "mapped effect construct"),
        ("import os\nread = getattr(os, 'environ')\n", "dynamic", "dynamic escape"),
        ("g = globals()\n", "dynamic", "dynamic escape"),
        ("__import__('subprocess')\n", "dynamic", "dynamic escape"),
        ("import importlib\nimportlib.import_module('json')\n", "dynamic", "dynamic escape"),
        ("import sys\nsys.modules['os'].getenv('HOME')\n", "dynamic", "dynamic escape"),
    ],
)
def test_callbacks_and_reflection_break_closure(tmp_path, source, category, blocker):
    # Callback and reflection: a bound function reference or indirect lookup is still an effect.
    scan = _scan_one(tmp_path, "owned/probe.py", source)
    assert any(hit[0] == category for hit in scan.hits)
    assert _closed_blocker(scan, ("env", "proc")) == "executable owned code"
    effect_only = replace(scan, code=())
    assert _closed_blocker(effect_only, ("env", "proc")) == blocker


def test_unparsed_or_unparsable_owned_code_blocks_closure(tmp_path):
    # Unparsed code cannot be shown effect-free, so a shell or syntax-broken owner is open.
    shell = _scan_one(tmp_path / "shell", "owned/run.sh", "echo ok\n")
    broken = _scan_one(tmp_path / "broken", "owned/broken.py", "def (:\n")
    assert _closed_blocker(shell, ("clock",)) == "unparsed executable code"
    assert _closed_blocker(broken, ("clock",)) == "unparsable python"


def test_empty_and_docstring_only_scripts_are_inert_and_support_only(tmp_path):
    # Empty or inert script: no effect and no executable code, which is support, never a basis.
    empty = _scan_one(tmp_path / "empty", "owned/empty.py", "")
    marker = _scan_one(tmp_path / "marker", "owned/__init__.py", '"""Namespace marker."""\n')
    executable = _scan_one(tmp_path / "exec", "owned/exec.py", "VALUE = 1\n")
    assert _closed_blocker(empty, ("clock",)) == ""
    assert _closed_blocker(marker, ("clock",)) == ""
    assert _closed_blocker(executable, ("clock",)) == "executable owned code"


def test_empty_script_cannot_establish_a_closed_dne_without_a_source_basis(tmp_path):
    # Absence insufficient: an emptied executable owner with no source basis still gets no DNE.
    object_id = "vstd-generic-run-specimen"
    root = _owned_copy(tmp_path)
    (root / "examples/generic_run/compute.py").write_bytes(b"")
    rows = _audits_with(object_id, lambda row: _forced_closed(row, "BENCH"))
    with pytest.raises(ValueError, match="CLOSED_BASIS_MISSING:" + object_id + ":BENCH"):
        validate_source_partition(current_source_partition(), rows, root=root)


def test_promoting_a_downgraded_candidate_fails_closed_on_untouched_bytes():
    # Promotion: the unmodified owner still has no basis, so the exclusion cannot land.
    object_id = "vstd-monograph-build-transaction"
    rows = _audits_with(object_id, lambda row: _forced_closed(row, "MODEL"))
    with pytest.raises(ValueError, match="CLOSED_BASIS_MISSING:" + object_id + ":MODEL"):
        validate_source_partition(current_source_partition(), rows, root=REPO_ROOT)


def test_dropping_a_supported_closed_dne_fails_closed():
    # Silent under-claim: a supported closed-surface DNE cannot be dropped to UNRESOLVED.
    object_id = "vstd-example-catalog-guide"
    index = ORIGINAL_NON_OBJECT_KINDS.index("BENCH")
    rows = _audits_with(
        object_id,
        lambda row: _with_question(
            row,
            index,
            status=UNRESOLVED,
            evidence="",
            reason=_question_reason(row.scope_reason, "BENCH", UNRESOLVED, ""),
        ),
    )
    with pytest.raises(ValueError, match="CLOSED_DECISION_DRIFT:" + object_id + ":BENCH"):
        validate_source_partition(current_source_partition(), rows, root=REPO_ROOT)


def test_a_basis_borrowed_from_another_owner_cannot_close_this_owner(monkeypatch):
    # Referent-vs-object: another object's declaration describes a different identity.
    object_id = "vstd-artifact-network-fixture-ledger"
    monkeypatch.setitem(
        _NON_EXECUTION_BASIS,
        object_id,
        _NON_EXECUTION_BASIS["vstd-example-catalog-guide"],
    )
    with pytest.raises(ValueError, match="CLOSED_BASIS_DRIFT:" + object_id):
        validate_source_partition(
            current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=REPO_ROOT
        )


def test_reason_substitution_for_a_closed_basis_fails_closed():
    # Reason substitution: a valid evidence code with another owner's basis text is drift.
    object_id = "vstd-artifact-network-fixture-ledger"
    index = ORIGINAL_NON_OBJECT_KINDS.index("ENV")
    evidence = closed_evidence("ENV")
    borrowed = _question_reason(
        _rows_by_id()[object_id].scope_reason,
        "ENV",
        DOES_NOT_APPLY,
        evidence,
        basis=_NON_EXECUTION_BASIS["vstd-example-catalog-guide"],
    )
    rows = _audits_with(
        object_id,
        lambda row: _with_question(
            row, index, status=DOES_NOT_APPLY, evidence=evidence, reason=borrowed
        ),
    )
    with pytest.raises(ValueError, match="REASON_DRIFT:" + object_id):
        validate_source_partition(current_source_partition(), rows, root=REPO_ROOT)


def test_a_data_referent_naming_an_effect_is_a_hit_never_a_basis(tmp_path):
    # Referent text in owned data is fail-closed: it blocks the exclusion and grants none.
    scan = _scan_one(
        tmp_path,
        "owned/fixture.json",
        '{"note": "reads os.getenv(\\"HOME\\") in the original run"}\n',
    )
    assert any(hit[0] == "env" for hit in scan.hits)
    assert _closed_blocker(scan, ("env",)) == "mapped effect construct"


def test_an_owned_sibling_carrying_an_effect_is_scanned_transitively(tmp_path):
    # Transitive import: a bound sibling's effect belongs to the owner's closed surface.
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text('"""Package."""\n', encoding="utf-8")
    (tmp_path / "pkg/a.py").write_text("from . import b\n", encoding="utf-8")
    (tmp_path / "pkg/b.py").write_text("import os\nVALUE = os.getenv('HOME')\n", encoding="utf-8")
    scan = _scan_effects(tmp_path, ("pkg/__init__.py", "pkg/a.py", "pkg/b.py"))
    assert scan.opens == ()
    assert any(hit[0] == "env" and hit[1] == "pkg/b.py" for hit in scan.hits)
    assert _closed_blocker(scan, ("env",)) == "executable owned code"


def test_an_executable_marker_breaks_its_inert_basis(tmp_path):
    # Inert identity is checked against bytes: adding an executable statement voids it.
    object_id, root = _mutated_owner(
        tmp_path,
        ("BENCH", "ENV", "HARDWARE", "HARNESS", "MODEL", "TRAIN"),
        ".py",
        lambda data: data + b"\nVALUE = 1\n",
    )
    with pytest.raises(ValueError, match="CLOSED_SURFACE_NOT_CLOSED:" + object_id):
        validate_source_partition(current_source_partition(), SCRIPT_EXAMPLE_ORIGINAL_KIND_AUDITS, root=root)
