"""Terminology: application programming interface (API); command-line interface (CLI); Verifier Standard (VSTD).

Adversarial tests for the imported Python-application and public-CLI original-kind
audit: exact denominators, literal decisions, owned-source binding, and fail-closed
substitutions of declarations, quotations, bytes, and sealed profiles.
"""

from __future__ import annotations

import ast
from dataclasses import replace
from hashlib import sha256
import inspect
from pathlib import Path
import re

import pytest

from verifier.runtime import package_semantic_ownership as ownership
from verifier.runtime.package_original_kind_catalog_python_apps_public_cli import (
    PARTIAL_PROFILE,
    PYTHON_APPS_PUBLIC_CLI_AUDITS,
    UNRESOLVED,
    audit_row,
    current_source_partition,
    does_not_apply_closure_blockers,
    review_document,
    validate_audit_row,
    validate_owned_source_bytes,
    validate_source_partition,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindDecision,
    OriginalKindProfile,
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    profile_digest,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_original_kind_review import audit_closed_effects
from verifier.runtime.package_semantic_ownership_model import RootRoleDecision


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_SOURCE = (
    REPO_ROOT
    / "src"
    / "verifier"
    / "runtime"
    / "package_original_kind_catalog_python_apps_public_cli.py"
)
# Rows with at least one decision beyond their primary role. Every other row
# with an original primary is decided only by that primary APPLIES.
EXPECTED_DECIDED_ROWS = {
    "vstd-agent-bot-ontology-architecture": {
        "ACTOR": DOES_NOT_APPLY,
        "AGENT": APPLIES,
        "ARCH": APPLIES,
        "BENCH": DOES_NOT_APPLY,
        "BOT": APPLIES,
        "COLLECTIVE": DOES_NOT_APPLY,
        "DATA": DOES_NOT_APPLY,
        "ENV": DOES_NOT_APPLY,
        "EVENT": APPLIES,
        "GRAPH": DOES_NOT_APPLY,
        "HARDWARE": DOES_NOT_APPLY,
        "HARNESS": DOES_NOT_APPLY,
        "HUMAN": DOES_NOT_APPLY,
        "HYPER": DOES_NOT_APPLY,
        "IDENTITY": DOES_NOT_APPLY,
        "MODEL": DOES_NOT_APPLY,
        "OWNER": DOES_NOT_APPLY,
        "RECEIPT": DOES_NOT_APPLY,
        "ROLE": DOES_NOT_APPLY,
        "SIM": APPLIES,
        "SPACE": APPLIES,
        "TIME": APPLIES,
        "TOKEN": DOES_NOT_APPLY,
        "TRAIN": DOES_NOT_APPLY,
        "VERIFIER": DOES_NOT_APPLY,
    },
    "vstd-corrigibility-environment-profile": {"ENV": APPLIES, "HARDWARE": APPLIES},
    "vstd-tesla-cage-contract": {"HARDWARE": APPLIES, "HARNESS": APPLIES},
    "vstd-graph-level-verifier": {"GRAPH": APPLIES, "VERIFIER": APPLIES},
    "vstd-benchmark-suite-verifier": {"BENCH": APPLIES, "VERIFIER": APPLIES},
    "vstd-model-reproducibility-profile": {"DATA": APPLIES},
    "vstd-training-data-contamination-assessor": {"DATA": APPLIES, "VERIFIER": APPLIES},
    "vstd-corrigibility-provenance-ledger": {"GRAPH": APPLIES},
    "vstd-provenance-hypergraph-ledger": {"GRAPH": APPLIES},
    "vstd-training-checkpoint-ledger": {"TRAIN": APPLIES},
    "vstd-sim-trace-assessor": {"SIM": APPLIES, "VERIFIER": APPLIES},
    "vstd-environment-synthetic-specimens": {"ENV": APPLIES, "HARNESS": APPLIES},
}
# Rows whose primary is not an original kind and that carry no decision at all.
EXCLUDED_ROWS = {
    "vstd-module-cli-entrypoint",
    "vstd-operator-stop-authentication",
    "vstd-public-cli-dispatch",
    "vstd-refutation-surface-policy",
    "vstd-training-control-profile",
}
# No refutation survives: the ownership declarations pin no DOES_NOT_APPLY root
# decision for any row, and no owned closure is CLOSED. A DOES_NOT_APPLY may
# return only with a matching declaration and a CLOSED owned closure.
# Decisions withdrawn from APPLIES or DOES_NOT_APPLY to UNRESOLVED on this audit.
WITHDRAWN_TO_UNRESOLVED = (
    ("vstd-model-reproducibility-profile", "MODEL"),
    ("vstd-environment-synthetic-specimens", "BENCH"),
    ("vstd-environment-synthetic-specimens", "MODEL"),
    ("vstd-operator-stop-authentication", "HUMAN"),
    ("vstd-consent-stage-verifier", "HUMAN"),
    ("vstd-training-control-profile", "MODEL"),
    ("vstd-training-control-profile", "TRAIN"),
)
# Literal digests recomputed from the reconciled matrix. Stale re-pinning of a
# coordinate or of the sealed profile changes these and fails the pin.
PINNED_COORDINATE_DIGESTS = {
    "vstd-consent-stage-verifier": "sha256:7ce92bf5933c0f316e67e8e4801548eece9b82a299f6195c41a05d991b563f3b",
    "vstd-training-control-profile": "sha256:edb74fa8d3fe624dbc757cb54de4a6d7db61c5f43d46502879bd8fba61185c38",
}
PINNED_PROFILE_DIGEST = "sha256:0e5581e9eb8168098b428d21e92e36e2f30e06f85471466d47b3dbba38d1ef69"
_CLOSURE_MARKER = "PYTHON_APPS_PUBLIC_CLI_ORIGINAL_KIND_DOES_NOT_APPLY_CLOSURE_NOT_CLOSED:"
_EFFECT_MARKER = "PYTHON_APPS_PUBLIC_CLI_ORIGINAL_KIND_DOES_NOT_APPLY_EFFECT_DEFEATED:"


def _rows_by_id():
    return {row.object_id: row for row in PYTHON_APPS_PUBLIC_CLI_AUDITS}


def _specs_by_id():
    return {spec.object_id: spec for spec in current_source_partition()}


def _rebuild(row, selections, root_role_decisions=None):
    """Re-run the literal constructor on a row's own coordinate with new selections."""

    return audit_row(
        row.group,
        row.object_id,
        row.expected_primary,
        row.expected_owned_paths,
        row.expected_owned_file_digests,
        row.expected_representation_role,
        row.expected_necessity_reason,
        row.expected_consequence_boundary,
        row.expected_specializations,
        row.expected_operands,
        selections,
        row.expected_root_role_decisions
        if root_role_decisions is None
        else root_role_decisions,
    )


def _selections(row, overrides=None):
    overrides = overrides or {}
    return tuple(
        overrides.get(
            question.kind,
            (
                question.kind,
                question.status,
                "" if question.source is None else question.source.path,
                "" if question.source is None else question.source.quote,
            ),
        )
        for question in row.questions
    )


def _digest_of(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def test_exact_denominators_and_literal_matrix_are_declared() -> None:
    assert len(PYTHON_APPS_PUBLIC_CLI_AUDITS) == 41
    assert len({row.object_id for row in PYTHON_APPS_PUBLIC_CLI_AUDITS}) == 41
    assert sum(len(row.expected_owned_paths) for row in PYTHON_APPS_PUBLIC_CLI_AUDITS) == 43
    assert {
        group: sum(row.group == group for row in PYTHON_APPS_PUBLIC_CLI_AUDITS)
        for group in {row.group for row in PYTHON_APPS_PUBLIC_CLI_AUDITS}
    } == {"imported-python-apps": 40, "imported-public-cli": 1}
    assert all(
        tuple(question.kind for question in row.questions) == ORIGINAL_NON_OBJECT_KINDS
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
    )
    assert sum(len(row.questions) for row in PYTHON_APPS_PUBLIC_CLI_AUDITS) == 1025

    source = MODULE_SOURCE.read_text(encoding="utf-8")
    literal_calls = re.findall(r"^\s+_question\(", source, flags=re.MULTILINE)
    ontology_refutations = re.findall(
        r"^\s+_ontology_refutation_question\(", source, flags=re.MULTILINE
    )
    assert len(literal_calls) + len(ontology_refutations) == 1025
    literal_matrix = source.split("PYTHON_APPS_PUBLIC_CLI_AUDITS = (", 1)[1].split(
        "PARTIAL_PROFILE = seal_profile(", 1
    )[0]
    assert "for kind in" not in literal_matrix
    assert "set(ORIGINAL_NON_OBJECT_KINDS)" not in literal_matrix
    assert "difference(" not in literal_matrix


def test_module_has_no_third_party_import_surface() -> None:
    tree = ast.parse(MODULE_SOURCE.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "typing",
        "verifier",
    }


def test_current_partition_is_exact_imported_declarations_and_paths_exist() -> None:
    selected = current_source_partition()
    assert validate_source_partition(selected) == selected
    assert tuple(spec.object_id for spec in selected) == tuple(
        row.object_id for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
    )
    assert all(spec in ownership.SEMANTIC_OWNERSHIP_SPECS for spec in selected)
    assert all(
        (REPO_ROOT / path).is_file() for spec in selected for path in spec.owned_paths
    )


def test_owned_source_bytes_and_quotations_bind_current_checkout() -> None:
    assert does_not_apply_closure_blockers(REPO_ROOT) == ()
    validate_owned_source_bytes(REPO_ROOT)
    for row in PYTHON_APPS_PUBLIC_CLI_AUDITS:
        validate_owned_source_bytes(REPO_ROOT, rows=(row,))


def test_decided_rows_are_exact_and_zero_decision_rows_are_explicit() -> None:
    specs = _specs_by_id()
    decided = {
        row.object_id: {
            question.kind: question.status
            for question in row.questions
            if question.status != UNRESOLVED
        }
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
    }
    decided = {object_id: values for object_id, values in decided.items() if values}
    expected = {
        object_id: dict(
            EXPECTED_DECIDED_ROWS.get(
                object_id, {specs[object_id].primary_kind: APPLIES}
            )
        )
        for object_id in specs
        if object_id not in EXCLUDED_ROWS
    }
    assert decided == expected
    assert len(decided) == 36
    for object_id in EXCLUDED_ROWS:
        assert all(
            question.status == UNRESOLVED
            for question in _rows_by_id()[object_id].questions
        )


def test_status_totals_match_the_literal_decision_rule() -> None:
    statuses = [
        question.status
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
        for question in row.questions
    ]
    assert statuses.count(APPLIES) == 49
    assert statuses.count(DOES_NOT_APPLY) == 18
    assert statuses.count(UNRESOLVED) == 958
    assert len(statuses) == 1025


def test_applies_only_from_declared_primary_or_exact_owned_quotation() -> None:
    specs = _specs_by_id()
    for row in PYTHON_APPS_PUBLIC_CLI_AUDITS:
        spec = specs[row.object_id]
        for question in row.questions:
            if question.status != APPLIES:
                continue
            if question.source is None:
                assert question.kind == spec.primary_kind
                continue
            assert question.source.path in spec.owned_paths
            text = (REPO_ROOT / question.source.path).read_text(encoding="utf-8")
            assert question.source.quote in text


def test_does_not_apply_only_from_exact_owned_refutation_and_never_primary() -> None:
    specs = _specs_by_id()
    exclusions = []
    for row in PYTHON_APPS_PUBLIC_CLI_AUDITS:
        spec = specs[row.object_id]
        for question in row.questions:
            if question.status != DOES_NOT_APPLY:
                continue
            exclusions.append((row.object_id, question.kind))
            assert question.kind != spec.primary_kind
            assert question.kind not in spec.specializations
            assert question.source is not None
            assert question.source.path in spec.owned_paths
            text = (REPO_ROOT / question.source.path).read_text(encoding="utf-8")
            assert question.source.quote in text
    assert sorted(exclusions) == sorted(
        (object_id, kind)
        for object_id, values in EXPECTED_DECIDED_ROWS.items()
        for kind, status in values.items()
        if status == DOES_NOT_APPLY
    )


def test_partial_profile_is_digest_bound_and_cannot_claim_closure() -> None:
    assert validate_profile(PARTIAL_PROFILE) is PARTIAL_PROFILE
    assert profile_digest(PARTIAL_PROFILE) == PARTIAL_PROFILE.canonical_digest
    assert PARTIAL_PROFILE.canonical_digest == PINNED_PROFILE_DIGEST
    assert len(PARTIAL_PROFILE.assignments) == 36
    assert all(
        decision.status in {APPLIES, DOES_NOT_APPLY}
        for assignment in PARTIAL_PROFILE.assignments
        for decision in assignment.decisions
    )
    assert {assignment.object_id for assignment in PARTIAL_PROFILE.assignments} == (
        {row.object_id for row in PYTHON_APPS_PUBLIC_CLI_AUDITS} - EXCLUDED_ROWS
    )
    # The sealed profile carries exactly the audit's APPLIES and DOES_NOT_APPLY
    # decisions and nothing withdrawn; a re-sealed profile must match this set.
    sealed = {
        (assignment.object_id, decision.kind, decision.status, decision.reason)
        for assignment in PARTIAL_PROFILE.assignments
        for decision in assignment.decisions
    }
    audited = {
        (row.object_id, question.kind, question.status, question.reason)
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
        for question in row.questions
        if question.status in {APPLIES, DOES_NOT_APPLY}
    }
    assert sealed == audited
    assert sum(
        status == DOES_NOT_APPLY
        for _object, _kind, status, _reason in sealed
    ) == 18
    expected_ids = tuple(
        sorted(
            {row.object_id for row in PYTHON_APPS_PUBLIC_CLI_AUDITS}
            | {
                f"filler-object-{index:03d}"
                for index in range(
                    VERIFIER_PACKAGE_OBJECT_DENOMINATOR
                    - len(PYTHON_APPS_PUBLIC_CLI_AUDITS)
                )
            }
        )
    )
    assert len(expected_ids) == VERIFIER_PACKAGE_OBJECT_DENOMINATOR
    with pytest.raises(ValueError, match="OBJECT_DENOMINATOR_INCOMPLETE"):
        validate_full_closure(PARTIAL_PROFILE, expected_ids)


def test_review_document_exposes_every_unknown_reason_and_profile_binding() -> None:
    document = review_document()
    assert len(document) == 41
    assert sum(
        question["status"] == UNRESOLVED
        for entry in document.values()
        for question in entry["questions"].values()
    ) == 958
    profile_ids = {assignment.object_id for assignment in PARTIAL_PROFILE.assignments}
    for object_id, entry in document.items():
        assert tuple(entry["questions"]) == ORIGINAL_NON_OBJECT_KINDS
        assert entry["expected_source_coordinate_digest"].startswith("sha256:")
        assert entry["expected_owned_path_set_digest"].startswith("sha256:")
        assert entry["scope_reason"].strip()
        assert all(
            question["reason"].strip() for question in entry["questions"].values()
        )
        assert (entry["partial_profile_digest"] is not None) == (object_id in profile_ids)


def test_omitted_or_reordered_selections_fail_closed() -> None:
    row = _rows_by_id()["vstd-operator-stop-authentication"]
    selections = _selections(row)
    with pytest.raises(AssertionError, match="question order differs"):
        _rebuild(row, selections[:-1])
    swapped = (selections[1], selections[0], *selections[2:])
    with pytest.raises(AssertionError, match="question order differs"):
        _rebuild(row, swapped)


def test_exclusion_without_owned_source_and_unresolved_evidence_fail_closed() -> None:
    row = _rows_by_id()["vstd-operator-stop-authentication"]
    with pytest.raises(AssertionError, match="lacks an owned-source quotation"):
        _rebuild(row, _selections(row, {"HUMAN": ("HUMAN", DOES_NOT_APPLY, "", "")}))
    with pytest.raises(AssertionError, match="unresolved item carries evidence"):
        _rebuild(
            row,
            _selections(
                row,
                {
                    "ACTOR": (
                        "ACTOR",
                        UNRESOLVED,
                        "src/verifier/corrigibility/operator_stop.py",
                        "Configured-key authentication",
                    )
                },
            ),
        )
    with pytest.raises(AssertionError, match="invalid status"):
        _rebuild(row, _selections(row, {"ACTOR": ("ACTOR", "ASSUMED", "", "")}))


def test_quotation_outside_the_row_owned_paths_fails_closed() -> None:
    row = _rows_by_id()["vstd-operator-stop-authentication"]
    with pytest.raises(AssertionError, match="lacks an owned-source quotation"):
        _rebuild(
            row,
            _selections(
                row,
                {
                    "HUMAN": (
                        "HUMAN",
                        DOES_NOT_APPLY,
                        "src/verifier/runtime/public_cli.py",
                        "Public, target-neutral CLI",
                    )
                },
            ),
        )


def test_primary_kind_cannot_be_refuted_or_downgraded() -> None:
    row = _rows_by_id()["vstd-python-public-api"]
    spec = _specs_by_id()[row.object_id]
    refuted = _rebuild(
        row,
        _selections(
            row,
            {
                "ARCH": (
                    "ARCH",
                    DOES_NOT_APPLY,
                    "src/verifier/__init__.py",
                    "VSTD reference implementation public API.",
                )
            },
        ),
    )
    with pytest.raises(ValueError, match="SOURCE_ROLE_CONFLICT"):
        validate_audit_row(refuted, spec)
    downgraded = _rebuild(row, _selections(row, {"ARCH": ("ARCH", UNRESOLVED, "", "")}))
    with pytest.raises(ValueError, match="PRIMARY_REFUTED"):
        validate_audit_row(downgraded, spec)


def test_quotation_substitution_is_rejected_by_owned_source_bytes() -> None:
    row = _rows_by_id()["vstd-sim-trace-assessor"]
    spec = _specs_by_id()[row.object_id]
    exact = _rebuild(
        row,
        _selections(
            row,
            {
                "SIM": (
                    "SIM",
                    APPLIES,
                    "src/verifier/corrigibility/simulation.py",
                    "Abstract, substrate-neutral generative simulation specification",
                )
            },
        ),
    )
    validate_audit_row(exact, spec)
    validate_owned_source_bytes(REPO_ROOT, rows=(exact,))
    invented = _rebuild(
        row,
        _selections(
            row,
            {
                "SIM": (
                    "SIM",
                    APPLIES,
                    "src/verifier/corrigibility/simulation.py",
                    "generative simulation specification (SIM-9..9)",
                )
            },
        ),
    )
    validate_audit_row(invented, spec)
    with pytest.raises(ValueError, match="EVIDENCE_QUOTE_MISSING:vstd-sim-trace-assessor:SIM"):
        validate_owned_source_bytes(REPO_ROOT, rows=(invented,))


def test_source_partition_substitutions_fail_closed() -> None:
    selected = list(current_source_partition())
    with pytest.raises(ValueError, match="SOURCE_DENOMINATOR_DRIFT"):
        validate_source_partition(selected[:-1])
    duplicated = list(selected)
    duplicated[0] = replace(duplicated[0], object_id=duplicated[1].object_id)
    with pytest.raises(ValueError, match="SOURCE_PARTITION_INVALID"):
        validate_source_partition(duplicated)

    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-python-public-api"
    )
    target = selected[index]
    cases = [
        (replace(target, primary_kind="OBJECT"), "SOURCE_PRIMARY_DRIFT"),
        (
            replace(target, owned_paths=("src/verifier/runtime/not-audited.py",)),
            "SOURCE_PATH_DRIFT",
        ),
        (replace(target, representation_role="substituted role"), "SOURCE_COORDINATE_DRIFT"),
        (replace(target, necessity_reason="substituted reason"), "SOURCE_COORDINATE_DRIFT"),
        (replace(target, specializations=("TRAIN",)), "SOURCE_COORDINATE_DRIFT"),
        (
            replace(
                target,
                root_role_decisions=(
                    RootRoleDecision("ACTOR", APPLIES, "explicit applicability"),
                ),
            ),
            "ROOT_ROLE_DECISION_UNAUDITED",
        ),
    ]
    for substitute, code in cases:
        mutated = list(selected)
        mutated[index] = substitute
        with pytest.raises(ValueError, match=code):
            validate_source_partition(mutated)


def test_operand_substitution_changes_the_bound_coordinate() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-data-receipt-lifecycle"
    )
    target = selected[index]
    assert target.operands
    selected[index] = replace(
        target,
        operands=(("subject", ("vstd-hardware",)), ("hardware", ("vstd-data",))),
    )
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)


def test_object_label_cannot_bypass_the_matrix() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.primary_kind == "VERIFIER"
    )
    selected[index] = replace(selected[index], primary_kind="OBJECT")
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT"):
        validate_source_partition(selected)


def test_owned_file_digest_drift_and_missing_quotation_fail_closed(tmp_path: Path) -> None:
    row = _rows_by_id()["vstd-sim-trace-assessor"]
    root = tmp_path / "root"
    source = root / "src" / "verifier" / "corrigibility"
    source.mkdir(parents=True)
    original = (REPO_ROOT / "src/verifier/corrigibility/simulation.py").read_bytes()
    (source / "simulation.py").write_bytes(original + b"\n# drift\n")
    with pytest.raises(ValueError, match="OWNED_SOURCE_DIGEST_DRIFT"):
        validate_owned_source_bytes(root, rows=(row,))

    altered = original.replace(
        b"Abstract, substrate-neutral generative simulation specification",
        b"Abstract, substrate-bound generative simulation registry",
    )
    assert altered != original
    (source / "simulation.py").write_bytes(altered)
    rebuilt_row = replace(
        row,
        expected_owned_file_digests=(
            ("src/verifier/corrigibility/simulation.py", _digest_of(altered)),
        ),
    )
    with pytest.raises(
        ValueError, match="EVIDENCE_QUOTE_MISSING:vstd-sim-trace-assessor:SIM"
    ):
        validate_owned_source_bytes(root, rows=(rebuilt_row,))

    (source / "simulation.py").unlink()
    with pytest.raises(ValueError, match="OWNED_SOURCE_MISSING"):
        validate_owned_source_bytes(root, rows=(row,))


def test_root_role_decisions_are_feature_near_audited_and_quote_bound() -> None:
    specs = _specs_by_id()
    rows = _rows_by_id()
    declared = {
        object_id: spec.root_role_decisions
        for object_id, spec in specs.items()
        if spec.root_role_decisions
    }
    # Every root decision is feature-near, quote-bound, and closure-gated.
    assert {
        object_id: tuple(decision.kind for decision in decisions)
        for object_id, decisions in declared.items()
    } == {
        "vstd-agent-bot-ontology-architecture": (
            "ACTOR", "BENCH", "COLLECTIVE", "DATA", "ENV", "GRAPH",
            "HARDWARE", "HARNESS", "HUMAN", "HYPER", "IDENTITY", "MODEL",
            "OWNER", "RECEIPT", "ROLE", "SIM", "TOKEN", "TRAIN", "VERIFIER",
        ),
        "vstd-corrigibility-environment-profile": ("HARDWARE",),
        "vstd-environment-synthetic-specimens": ("ENV",),
        "vstd-graph-level-verifier": ("GRAPH",),
        "vstd-tesla-cage-contract": ("HARDWARE",),
    }
    assert sum(
        decision.status == DOES_NOT_APPLY
        for decisions in declared.values()
        for decision in decisions
    ) == 18
    for object_id, decisions in declared.items():
        row = rows[object_id]
        assert row.expected_root_role_decisions == tuple(
            (decision.kind, decision.status, decision.reason) for decision in decisions
        )
        for kind, status, _reason in row.expected_root_role_decisions:
            question = next(item for item in row.questions if item.kind == kind)
            assert question.status == status
            assert question.source is not None
            assert question.source.path in row.expected_owned_paths
            text = (REPO_ROOT / question.source.path).read_text(encoding="utf-8")
            assert question.source.quote in text


def test_root_role_decisions_cannot_complement_or_escape_the_matrix() -> None:
    row = _rows_by_id()["vstd-corrigibility-environment-profile"]
    # An unaudited kind (ACTOR is UNRESOLVED on this row) is not made applicable by a root record.
    with pytest.raises(AssertionError, match="ACTOR root role decision is not audited"):
        _rebuild(row, _selections(row), (("ACTOR", APPLIES, "unaudited"),))
    # Converting an audited APPLIES root into a bare DOES_NOT_APPLY without a quotation fails.
    with pytest.raises(AssertionError, match="HARDWARE root role decision is not audited"):
        _rebuild(
            row,
            _selections(row, {"HARDWARE": ("HARDWARE", DOES_NOT_APPLY, "", "")}),
        )
    # Object labels and non-original kinds cannot carry a root decision.
    with pytest.raises(AssertionError, match="OBJECT root role decision is not audited"):
        _rebuild(row, _selections(row), (("OBJECT", APPLIES, "label"),))
    # Omitting the root record while keeping the audited quotation is also rejected by the spec binding.
    spec = _specs_by_id()[row.object_id]
    with pytest.raises(ValueError, match="ROOT_ROLE_DECISION_UNAUDITED"):
        validate_audit_row(_rebuild(row, _selections(row), ()), spec)


def test_root_role_decision_reason_drift_fails_closed() -> None:
    row = _rows_by_id()["vstd-tesla-cage-contract"]
    spec = _specs_by_id()[row.object_id]
    validate_audit_row(row, spec)
    drifted = replace(
        spec,
        root_role_decisions=(
            RootRoleDecision("HARDWARE", APPLIES, "substituted root reason"),
        ),
    )
    with pytest.raises(ValueError, match="ROOT_ROLE_DECISION_UNAUDITED:vstd-tesla-cage-contract"):
        validate_audit_row(row, drifted)
    dropped = replace(spec, root_role_decisions=())
    with pytest.raises(ValueError, match="ROOT_ROLE_DECISION_UNAUDITED:vstd-tesla-cage-contract"):
        validate_audit_row(row, dropped)


def test_profile_tampering_and_unresolved_profile_entries_fail_closed() -> None:
    assignment = PARTIAL_PROFILE.assignments[0]
    decision = assignment.decisions[0]
    tampered_assignment = OriginalKindAssignment(
        object_id=assignment.object_id,
        expected_primary=assignment.expected_primary,
        expected_owned_paths=assignment.expected_owned_paths,
        expected_owned_path_set_digest=assignment.expected_owned_path_set_digest,
        scope_reason=assignment.scope_reason,
        decisions=(
            OriginalKindDecision(decision.kind, decision.status, "substituted reason"),
            *assignment.decisions[1:],
        ),
    )
    tampered = OriginalKindProfile(
        profile_id=PARTIAL_PROFILE.profile_id,
        revision=PARTIAL_PROFILE.revision,
        claim_boundary=PARTIAL_PROFILE.claim_boundary,
        assignments=(tampered_assignment, *PARTIAL_PROFILE.assignments[1:]),
        canonical_digest=PARTIAL_PROFILE.canonical_digest,
    )
    with pytest.raises(ValueError, match="DIGEST_INVALID"):
        validate_profile(tampered)

    unresolved_assignment = OriginalKindAssignment(
        object_id=assignment.object_id,
        expected_primary=assignment.expected_primary,
        expected_owned_paths=assignment.expected_owned_paths,
        expected_owned_path_set_digest=assignment.expected_owned_path_set_digest,
        scope_reason=assignment.scope_reason,
        decisions=(OriginalKindDecision(decision.kind, UNRESOLVED, decision.reason),),
    )
    with pytest.raises(ValueError, match="STATUS_INVALID"):
        validate_profile(
            OriginalKindProfile(
                profile_id=PARTIAL_PROFILE.profile_id,
                revision=PARTIAL_PROFILE.revision,
                claim_boundary=PARTIAL_PROFILE.claim_boundary,
                assignments=(unresolved_assignment, *PARTIAL_PROFILE.assignments[1:]),
                canonical_digest=PARTIAL_PROFILE.canonical_digest,
            )
        )


def test_only_the_closed_ontology_boundary_is_refuted() -> None:
    refuted = sorted(
        (row.object_id, question.kind)
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
        for question in row.questions
        if question.status == DOES_NOT_APPLY
    )
    expected = sorted(
        ("vstd-agent-bot-ontology-architecture", kind)
        for kind, status in EXPECTED_DECIDED_ROWS[
            "vstd-agent-bot-ontology-architecture"
        ].items()
        if status == DOES_NOT_APPLY
    )
    assert refuted == expected
    specs = _specs_by_id()
    assert sorted(
        (spec.object_id, decision.kind)
        for spec in specs.values()
        for decision in spec.root_role_decisions
        if decision.status == DOES_NOT_APPLY
    ) == expected
    assert does_not_apply_closure_blockers(REPO_ROOT) == ()


def test_recomputed_coordinate_digests_are_pinned_for_withdrawn_rows() -> None:
    rows = _rows_by_id()
    for object_id, digest in PINNED_COORDINATE_DIGESTS.items():
        assert rows[object_id].expected_source_coordinate_digest == digest
        assert rows[object_id].expected_root_role_decisions == ()


@pytest.mark.parametrize(("object_id", "kind"), WITHDRAWN_TO_UNRESOLVED)
def test_withdrawn_decisions_are_unresolved_with_exact_blocker_and_undeclared(
    object_id, kind
) -> None:
    row = _rows_by_id()[object_id]
    question = next(item for item in row.questions if item.kind == kind)
    spec = _specs_by_id()[object_id]
    assert question.status == UNRESOLVED
    assert question.source is None
    assert "Exact blocker: " in question.reason
    # Withdrawal must never hide a role the ownership declaration establishes.
    assert kind != spec.primary_kind
    assert kind not in spec.specializations
    assert all(decision.kind != kind for decision in spec.root_role_decisions)


def test_reasons_embed_their_exact_quotation_and_unresolved_reasons_embed_none() -> None:
    for row in PYTHON_APPS_PUBLIC_CLI_AUDITS:
        for question in row.questions:
            if question.source is None:
                continue
            assert "'" + question.source.quote + "'" in question.reason
            assert question.source.quote in (
                (REPO_ROOT / question.source.path).read_text(encoding="utf-8")
            )
    assert "reason" not in inspect.signature(audit_row).parameters


def test_closure_gate_refuses_a_refutation_whose_closure_is_not_closed(
    tmp_path: Path,
) -> None:
    row, root = _refutation_fixture(
        tmp_path,
        "def read(obj, name):\n    return getattr(obj, name)\n",
    )
    audit = audit_closed_effects(root, row.expected_owned_paths)
    assert audit.status == "UNKNOWN"
    assert does_not_apply_closure_blockers(root, (row,)) == (
        _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
    )


def _refutation_fixture(tmp_path: Path, body: str, digest_text: str | None = None):
    """One synthetic owned file whose refutation quotes its own first line."""

    source = "# Synthetic owned surface.\n" + body
    package = tmp_path / "pkg"
    package.mkdir(exist_ok=True)
    # Exact bytes: text mode would translate newlines and stale every digest.
    (package / "surface.py").write_bytes(source.encode("utf-8"))
    selections = tuple(
        (kind, DOES_NOT_APPLY, "pkg/surface.py", "Synthetic owned surface.")
        if kind == "HUMAN"
        else (kind, UNRESOLVED, "", "")
        for kind in ORIGINAL_NON_OBJECT_KINDS
    )
    row = audit_row(
        "imported-python-apps",
        "synthetic-closure-row",
        "VERIFIER",
        ("pkg/surface.py",),
        (("pkg/surface.py", _digest_of((digest_text or source).encode("utf-8"))),),
        "Synthetic fixture surface.",
        "Synthetic necessity.",
        "Synthetic consequence boundary.",
        (),
        (),
        selections,
    )
    return row, tmp_path


def test_closed_pure_refutation_is_the_only_admissible_shape(tmp_path: Path) -> None:
    row, root = _refutation_fixture(tmp_path, "def value(x):\n    return x + 1\n")
    assert audit_closed_effects(root, row.expected_owned_paths).status == "CLOSED"
    assert does_not_apply_closure_blockers(root, (row,)) == ()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(
            "import os as host\n\ndef run():\n    host.system('true')\n",
            _EFFECT_MARKER + "synthetic-closure-row:HUMAN:subprocess_process",
            id="module-alias-process",
        ),
        pytest.param(
            "from subprocess import run as go\n\ndef run():\n    return go(['true'])\n",
            _EFFECT_MARKER + "synthetic-closure-row:HUMAN:subprocess_process",
            id="from-import-alias-process",
        ),
        pytest.param(
            "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n",
            _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
            id="dynamic-import",
        ),
        pytest.param(
            "def read(obj, name):\n    return getattr(obj, name)\n",
            _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
            id="reflection-getattr",
        ),
        pytest.param(
            "def evaluate(source):\n    return eval(source)\n",
            _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
            id="dynamic-execution",
        ),
        pytest.param(
            "def apply(callback):\n    return callback()\n",
            _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
            id="injected-callback",
        ),
        pytest.param(
            "from verifier.core.certificate import canonical_bytes\n\n"
            "def encode(value):\n    return canonical_bytes(value)\n",
            _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
            id="imported-effect-escapes-ownership",
        ),
    ],
)
def test_adversarial_closures_cannot_support_a_refutation(
    tmp_path: Path, body: str, expected: str
) -> None:
    row, root = _refutation_fixture(tmp_path, body)
    assert does_not_apply_closure_blockers(root, (row,)) == (expected,)


def test_stale_digest_cannot_support_a_refutation(tmp_path: Path) -> None:
    body = "def value(x):\n    return x + 1\n"
    row, root = _refutation_fixture(
        tmp_path, body, digest_text=body + "# stale bytes\n"
    )
    assert does_not_apply_closure_blockers(root, (row,)) == (
        _CLOSURE_MARKER + "synthetic-closure-row:HUMAN",
    )
    with pytest.raises(ValueError, match="OWNED_SOURCE_DIGEST_DRIFT"):
        validate_owned_source_bytes(root, rows=(row,))


_WITHDRAWN_REFUTATIONS = (
    pytest.param(
        "vstd-consent-stage-verifier",
        "HUMAN",
        "src/verifier/consent/stages.py",
        "authenticate clocks, or establish voluntary human consent.",
        id="consent-disclaimer-human",
    ),
    pytest.param(
        "vstd-training-control-profile",
        "MODEL",
        "src/verifier/corrigibility/train_profile.py",
        "TRAIN means an optimization procedure; MODEL means an optimized artifact.",
        id="training-type-distinction-model",
    ),
)


@pytest.mark.parametrize(("object_id", "kind", "path", "quote"), _WITHDRAWN_REFUTATIONS)
def test_withdrawn_refutation_cannot_return_by_quotation_or_declaration_alone(
    object_id, kind, path, quote
) -> None:
    row = _rows_by_id()[object_id]
    spec = _specs_by_id()[object_id]
    selections = _selections(row, {kind: (kind, DOES_NOT_APPLY, path, quote)})
    # Quotation without a matching declaration is an undeclared exclusion.
    unpinned = _rebuild(row, selections, ())
    with pytest.raises(
        ValueError, match="EXCLUSION_WITHOUT_ROOT_DECLARATION:" + object_id + ":" + kind
    ):
        validate_audit_row(unpinned, spec)
    # A row-side declaration the ownership source does not carry is unaudited.
    pinned = _rebuild(row, selections, ((kind, DOES_NOT_APPLY, quote),))
    with pytest.raises(ValueError, match="ROOT_ROLE_DECISION_UNAUDITED:" + object_id):
        validate_audit_row(pinned, spec)
    # Even a fully quoted, pinned row cannot pass: its closure is not CLOSED.
    with pytest.raises(
        ValueError,
        match=re.escape(
            "PYTHON_APPS_PUBLIC_CLI_ORIGINAL_KIND_DOES_NOT_APPLY_CLOSURE_NOT_CLOSED:"
            + object_id
            + ":"
            + kind
        ),
    ):
        validate_owned_source_bytes(REPO_ROOT, rows=(pinned,))


@pytest.mark.parametrize(("object_id", "kind", "path", "quote"), _WITHDRAWN_REFUTATIONS)
def test_stale_quote_repin_of_withdrawn_refutation_fails_atomically(
    tmp_path: Path, object_id, kind, path, quote
) -> None:
    row = _rows_by_id()[object_id]
    original = (REPO_ROOT / path).read_bytes()
    assert quote.encode("utf-8") in original
    # Rewrite the quoted clause, then re-pin the digest to the new bytes: the
    # stale quotation must still be refused before any closure is considered.
    altered = original.replace(quote.encode("utf-8"), quote[:-1].encode("utf-8") + b";")
    assert altered != original
    root = tmp_path / "root"
    (root / path).parent.mkdir(parents=True)
    (root / path).write_bytes(altered)
    stale_row = replace(
        row,
        expected_owned_file_digests=((path, _digest_of(altered)),),
    )
    stale = _rebuild(
        stale_row,
        _selections(stale_row, {kind: (kind, DOES_NOT_APPLY, path, quote)}),
        ((kind, DOES_NOT_APPLY, quote),),
    )
    with pytest.raises(ValueError, match="EVIDENCE_QUOTE_MISSING:" + object_id + ":" + kind):
        validate_owned_source_bytes(root, rows=(stale,))
    # The unmodified digest pin no longer matches the drifted bytes.
    with pytest.raises(ValueError, match="OWNED_SOURCE_DIGEST_DRIFT"):
        validate_owned_source_bytes(root, rows=(row,))


@pytest.mark.parametrize(("object_id", "kind", "path", "quote"), _WITHDRAWN_REFUTATIONS)
def test_source_and_operand_substitution_fail_closed_for_withdrawn_rows(
    object_id, kind, path, quote
) -> None:
    selected = list(current_source_partition())
    index = next(
        position for position, spec in enumerate(selected) if spec.object_id == object_id
    )
    target = selected[index]
    cases = [
        (replace(target, primary_kind="OBJECT"), "SOURCE_PRIMARY_DRIFT"),
        (
            replace(target, owned_paths=("src/verifier/runtime/not-audited.py",)),
            "SOURCE_PATH_DRIFT",
        ),
        (
            replace(target, operands=(("subject", ("vstd-data",)),)),
            "SOURCE_COORDINATE_DRIFT",
        ),
        (replace(target, specializations=("TRAIN",)), "SOURCE_COORDINATE_DRIFT"),
        (
            replace(target, consequence_boundary="substituted consequence boundary"),
            "SOURCE_COORDINATE_DRIFT",
        ),
        (
            replace(target, root_role_decisions=(RootRoleDecision(kind, DOES_NOT_APPLY, quote),)),
            "ROOT_ROLE_DECISION_UNAUDITED",
        ),
    ]
    for substitute, code in cases:
        mutated = list(selected)
        mutated[index] = substitute
        with pytest.raises(ValueError, match=code):
            validate_source_partition(mutated)
    assert validate_source_partition(selected) == tuple(selected)


@pytest.mark.parametrize("mutation", ["reinstate-withdrawn-refutation", "drop-consent-row"])
def test_partial_profile_mutation_fails_atomically_on_stale_digest(mutation) -> None:
    assignments = list(PARTIAL_PROFILE.assignments)
    if mutation == "reinstate-withdrawn-refutation":
        row = _rows_by_id()["vstd-training-control-profile"]
        assignments.append(
            OriginalKindAssignment(
                object_id=row.object_id,
                expected_primary=row.expected_primary,
                expected_owned_paths=row.expected_owned_paths,
                expected_owned_path_set_digest=row.expected_owned_path_set_digest,
                scope_reason=row.scope_reason,
                decisions=(
                    OriginalKindDecision(
                        "MODEL",
                        DOES_NOT_APPLY,
                        "TRAIN means an optimization procedure; MODEL means an optimized artifact.",
                    ),
                ),
            )
        )
        assignments.sort(key=lambda assignment: assignment.object_id)
    else:
        assignments = [
            assignment
            for assignment in assignments
            if assignment.object_id != "vstd-consent-stage-verifier"
        ]
    tampered = OriginalKindProfile(
        profile_id=PARTIAL_PROFILE.profile_id,
        revision=PARTIAL_PROFILE.revision,
        claim_boundary=PARTIAL_PROFILE.claim_boundary,
        assignments=tuple(assignments),
        canonical_digest=PARTIAL_PROFILE.canonical_digest,
    )
    with pytest.raises(ValueError, match="DIGEST_INVALID"):
        validate_profile(tampered)
    assert PARTIAL_PROFILE.canonical_digest == PINNED_PROFILE_DIGEST
