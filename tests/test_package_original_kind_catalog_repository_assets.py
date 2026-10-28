"""Adversarial tests for the repository-asset original-kind catalog partition.

The tests bind the literal audit to the live imported ownership rows, then
mutate copies of the audit and source rows to show that every substitution,
omission, unestablished APPLIES, unquoted DOES_NOT_APPLY, and OBJECT bypass
fails closed.  Verifier Standard (VSTD) and JavaScript Object Notation (JSON)
are expanded in the module that owns these claims.
"""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from verifier.runtime import package_original_kind_catalog_repository_assets as audit_module
from verifier.runtime import package_semantic_ownership as ownership
from verifier.runtime.package_original_kind_catalog_repository_assets import (
    CLAIM_BOUNDARY,
    REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS,
    REPOSITORY_ASSET_PARTIAL_PROFILE,
    RepositoryAssetOriginalKindAudit,
    RepositoryAssetOriginalKindQuestion,
    UNRESOLVED,
    current_source_partition,
    review_document,
    validate_source_partition,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindProfile,
    profile_digest,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_semantic_ownership_model import SemanticOwnershipSpec, root_role_decision
from verifier.runtime.package_semantic_ownership_repository_assets import (
    REPOSITORY_ASSET_OWNERSHIP_SPECS,
)

# Pinned refutation table after the second adversarial pass: no DOES_NOT_APPLY survives.
# The former object-facet request denial is UNRESOLVED behind an effect-boundary
# blocker: its request schema is consumed by a checking procedure outside the
# name-based owned-source closure, so a clean screen cannot exhaust the boundary.
EXPECTED_DNE_KINDS: dict[str, tuple[str, ...]] = {}
UNCLOSED_ROW = "vstd-retained-object-facet-requests"
UNCLOSED_CONSUMER = "src/verifier/domains/contracts/object_facets.py"
UNCLOSED_SCHEMA = "verifier-current-object-facets-request-1"
# The prior 54 DOES_NOT_APPLY cells, reconciled against the demotion ledger.
PRIOR_DNE_KINDS = {
    "vstd-accelerator-profile-wire-schema": ("IDENTITY",),
    "vstd-documentation-claim-boundary-policy": ("ACTOR", "VERIFIER"),
    "vstd-documentation-core-architecture": ("VERIFIER",),
    "vstd-documentation-hosting-protocol": ("ACTOR", "RECEIPT"),
    "vstd-documentation-reader-reference": ("RECEIPT", "VERIFIER"),
    "vstd-documentation-remote-submission-protocols": ("ACTOR", "IDENTITY", "ROLE"),
    "vstd-documentation-environment-graph-architecture": ("ENV",),
    "vstd-github-contribution-form-policy": ("VERIFIER",),
    "vstd-github-documentation-deployment-protocol": ("ACTOR", "ROLE"),
    "vstd-github-external-link-policy": ("ACTOR", "IDENTITY"),
    "vstd-github-promotion-policy-protocols": ("ACTOR", "EVENT", "HUMAN", "RECEIPT", "ROLE", "VERIFIER"),
    "vstd-github-release-workflow-protocol": ("ACTOR", "RECEIPT", "VERIFIER"),
    "vstd-github-source-description-workflow-protocol": ("ACTOR", "VERIFIER"),
    "vstd-github-verification-workflow-protocols": ("RECEIPT", "VERIFIER"),
    "vstd-receipt-wire-schema-catalog": ("IDENTITY", "VERIFIER"),
    "vstd-repository-agent-operating-policy": ("ACTOR", "ROLE", "VERIFIER"),
    "vstd-repository-community-governance-policy": ("ACTOR", "IDENTITY", "ROLE"),
    "vstd-repository-legal-notices": ("IDENTITY", "RECEIPT"),
    "vstd-repository-release-procedure-policy": ("ACTOR", "RECEIPT"),
    "vstd-repository-source-admission-designs": ("RECEIPT", "VERIFIER"),
    "vstd-retained-graph-statics-certificate": ("VERIFIER",),
    "vstd-retained-graph-statics-policy-input": ("ACTOR", "VERIFIER"),
    "vstd-retained-graph-statics-request": ("VERIFIER",),
    "vstd-retained-object-facet-certificates": ("ACTOR", "VERIFIER"),
    "vstd-retained-object-facet-requests": ("VERIFIER",),
    "vstd-retained-typed-facet-certificates": ("ACTOR", "ROLE", "VERIFIER"),
}
PROMOTED_PRIOR_DNE = {
    ("vstd-accelerator-profile-wire-schema", "IDENTITY"),
}
# Rows whose declarations contain only proof boundaries; no kind is refuted.
PROOF_ONLY_ROWS = (
    "vstd-documentation-adjacent-standards-crosswalks",
    "vstd-documentation-artifact-interoperability-architecture",
    "vstd-documentation-control-domain-candidates",
    "vstd-documentation-derived-metadata",
    "vstd-documentation-local-tool-protocols",
    "vstd-documentation-user-navigation",
    "vstd-generated-distribution-metadata",
    "vstd-repository-citation-metadata",
    "vstd-repository-file-and-package-policy",
    "vstd-repository-history-and-roadmap",
    "vstd-repository-overview",
    "vstd-retained-facet-policy-inputs",
    "vstd-retained-typed-facet-requests",
    "vstd-root-uv-dependency-resolution",
)
# Kinds whose misidentification has operational consequence; a refutation or
# applicability here needs counterexample review (see the accelerator test).
HIGH_RISK_KINDS = ("AGENT", "BOT", "HARDWARE", "MODEL", "OWNER", "SIM", "TOKEN")
RECEIPT_ROOT_ROWS = (
    "vstd-retained-object-facet-certificates",
    "vstd-retained-typed-facet-certificates",
    "vstd-retained-graph-statics-certificate",
)
ARCH_ROWS = (
    "vstd-documentation-core-architecture",
    "vstd-documentation-artifact-interoperability-architecture",
    "vstd-documentation-environment-graph-architecture",
    "vstd-documentation-adjacent-standards-crosswalks",
    "vstd-repository-source-admission-designs",
)

# These six paths are the only byte changes behind the three reviewed aggregate
# content-coordinate updates.  Keep their bytes and semantic markers independent
# of the aggregate: rebinding an aggregate alone must not conceal a role change.
REVIEWED_CONTENT_REFRESH = {
    "vstd-documentation-claim-boundary-policy": {
        "digest": "sha256:e6f33e93a20c836c1e9d5030e696d511cec3a31678828c0a6dc9c79bd4a7bfc0",
        "applies": (),
        "files": {
            "docs/ACCOUNTABILITY_RELEASE_SCOPE.md": (
                5920,
                "d9a8f6ee00f123815359333f1223972c27e4d4336eeaeff960cfc6e0e50b3734",
                ("38-kind extensible namespace",),
            ),
            "docs/API_STABILITY.md": (
                38164,
                "598b7c8a5cb5f31ea9cc9813b9b9961a9138bd31ccfaf437212151f7b6a02207",
                ("not all 38 kinds in the extensible namespace",),
            ),
        },
    },
    "vstd-generated-distribution-metadata": {
        "digest": "sha256:ebe9410b2153ea617dfcfbb4a7b8a55dab0b7ec23c3471d36775044054ca0409",
        "applies": (("DATA", "primary"),),
        "files": {
            "src/verifier_standard.egg-info/PKG-INFO": (
                79637,
                "935a25523923764ed90f3dcadb6cef4952988839557a308b13ecee133bb56334",
                ("Metadata-Version: 2.4", "Name: verifier-standard", 'Requires-Dist: cryptography==50.0.0; extra == "test"'),
            ),
            "src/verifier_standard.egg-info/SOURCES.txt": (
                68161,
                "70deb793a336024be5ab2603877727ed649cd6e121ea9f324c1bf75eee1dd9af",
                ("src/verifier/runtime/package_semantic_ownership_repository_assets.py",),
            ),
            "src/verifier_standard.egg-info/requires.txt": (
                686,
                "7b2d1431734bbbb76a92bfa3e930fe5ebb206b748d5b83d42332bb25fb370eae",
                (
                    "[discovery-javascript]",
                    "[discovery-rust]",
                    "[discovery-shell]",
                    "[discovery-workflows]",
                ),
            ),
        },
    },
    "vstd-github-verification-workflow-protocols": {
        "digest": "sha256:f18b06663888bf5353cdc879fde4af09103ab88733e8f85b16278bb96af3783d",
        "applies": (),
        "files": {
            ".github/workflows/ci.yml": (
                40420,
                "4de94dd7e3ee1268ec065a5eb60be96ad3c186dfc4db18707032139fe4e9d360",
                ("  optional-discovery:", "tests/test_namespace_javascript.py"),
            ),
        },
    },
}


def _audit(object_id: str) -> RepositoryAssetOriginalKindAudit:
    return next(row for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS if row.object_id == object_id)


def _spec(object_id: str) -> SemanticOwnershipSpec:
    return next(spec for spec in current_source_partition() if spec.object_id == object_id)


def _with_question(
    row: RepositoryAssetOriginalKindAudit, kind: str, status: str, evidence: str
) -> RepositoryAssetOriginalKindAudit:
    questions = tuple(
        RepositoryAssetOriginalKindQuestion(kind, status, evidence, "mutated")
        if question.kind == kind
        else question
        for question in row.questions
    )
    return replace(row, questions=questions)


def _replaced_source(object_id: str, **changes: object) -> tuple[SemanticOwnershipSpec, ...]:
    return tuple(
        replace(spec, **changes) if spec.object_id == object_id else spec
        for spec in current_source_partition()
    )


def _audits_with(row: RepositoryAssetOriginalKindAudit) -> tuple[RepositoryAssetOriginalKindAudit, ...]:
    return tuple(
        row if existing.object_id == row.object_id else existing
        for existing in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
    )


def _counts() -> tuple[int, int, int]:
    statuses = [q.status for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS for q in row.questions]
    return statuses.count(APPLIES), statuses.count(DOES_NOT_APPLY), statuses.count(UNRESOLVED)


def test_denominator_is_the_imported_repository_asset_partition() -> None:
    assert len(REPOSITORY_ASSET_OWNERSHIP_SPECS) == 40
    assert len(REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS) == 40
    paths = [path for spec in REPOSITORY_ASSET_OWNERSHIP_SPECS for path in spec.owned_paths]
    assert len(paths) == len(set(paths)) == 234
    assert {row.object_id for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS} == {
        spec.object_id for spec in REPOSITORY_ASSET_OWNERSHIP_SPECS
    }


def test_partition_rows_are_the_aggregate_rows_by_identity() -> None:
    aggregate = {id(spec) for spec in ownership.SEMANTIC_OWNERSHIP_SPECS}
    assert all(id(spec) in aggregate for spec in REPOSITORY_ASSET_OWNERSHIP_SPECS)


def test_repository_paths_are_disjoint_from_other_imported_partitions() -> None:
    own = {path for spec in REPOSITORY_ASSET_OWNERSHIP_SPECS for path in spec.owned_paths}
    other_names = (
        "DOMAIN_OWNERSHIP_SPECS",
        "EXPERIMENT_OWNERSHIP_SPECS",
        "HARDWARE_INTEROP_OWNERSHIP_SPECS",
        "PYTHON_APPS_OWNERSHIP_SPECS",
        "PUBLIC_CLI_OWNERSHIP_SPECS",
        "SCRIPT_EXAMPLE_OWNERSHIP_SPECS",
        "TEST_FIXTURE_OWNERSHIP_SPECS",
        "NORMATIVE_ASSET_OWNERSHIP_SPECS",
    )
    for name in other_names:
        for spec in getattr(ownership, name):
            assert not own & set(spec.owned_paths), (name, spec.object_id)


def test_every_row_answers_all_25_original_kinds_in_order() -> None:
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        assert tuple(question.kind for question in row.questions) == ORIGINAL_NON_OBJECT_KINDS
        assert len(row.questions) == 25
        assert "OBJECT" not in {question.kind for question in row.questions}


def test_decision_counts_are_exact() -> None:
    # 44 primary or root-role APPLIES, no surviving DOES_NOT_APPLY, 956 UNRESOLVED.
    assert _counts() == (44, 0, 956)
    assert sum(_counts()) == 40 * 25


def test_applies_table_is_exactly_primary_and_root_receipt_roles() -> None:
    applies = {
        (row.object_id, question.kind, question.evidence)
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
        for question in row.questions
        if question.status == APPLIES
    }
    expected = {
        (row.object_id, row.expected_primary, "primary")
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
        if row.expected_primary in ORIGINAL_NON_OBJECT_KINDS
    }
    expected |= {(object_id, "RECEIPT", "root_role_decision") for object_id in RECEIPT_ROOT_ROWS}
    expected |= {
        ("vstd-accelerator-profile-wire-schema", kind, "root_role_decision")
        for kind in ORIGINAL_NON_OBJECT_KINDS
    }
    assert applies == expected
    assert len(applies) == 44
    assert {object_id for object_id, _kind, _basis in applies} >= set(ARCH_ROWS)


def test_does_not_apply_table_is_pinned_to_direct_quotes() -> None:
    dne = {
        row.object_id: tuple(
            sorted(
                question.kind
                for question in row.questions
                if question.status == DOES_NOT_APPLY
            )
        )
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
    }
    assert {object_id: kinds for object_id, kinds in dne.items() if kinds} == {
        object_id: tuple(sorted(kinds)) for object_id, kinds in EXPECTED_DNE_KINDS.items()
    }


def _declared_text(object_id: str) -> str:
    spec = _spec(object_id)
    return "\n".join(
        (spec.representation_role, spec.necessity_reason, spec.consequence_boundary)
    )


def test_each_quote_occurs_verbatim_in_its_owned_declaration() -> None:
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        text = _declared_text(row.object_id)
        for question in row.questions:
            if question.status == DOES_NOT_APPLY:
                assert question.evidence in text, (row.object_id, question.kind)


def test_every_quote_is_a_whole_negated_declaration_sentence() -> None:
    # A quote must start and end at sentence boundaries and carry its own negation,
    # so a bare noun such as a receipt type or a substring of another clause cannot refute.
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        text = _declared_text(row.object_id)
        for question in row.questions:
            if question.status != DOES_NOT_APPLY:
                continue
            start = text.index(question.evidence)
            assert start == 0 or text[start - 1] in " \n", (row.object_id, question.kind)
            assert question.evidence.endswith(".")
            assert audit_module._is_negated(question.evidence), (row.object_id, question.kind)


def test_negation_detection_rejects_bare_noun_quotes() -> None:
    assert audit_module._is_negated("Stored certificate bytes are not fresh replay.")
    assert audit_module._is_negated("does not host an environment")
    assert not audit_module._is_negated("trusted platform receipt")
    assert not audit_module._is_negated("The files do notice receipts")


def test_no_derived_exclusion_for_kinds_without_a_quote() -> None:
    # Omission, complement, primary difference and OBJECT labeling never refute.
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.status == DOES_NOT_APPLY:
                assert question.evidence
                assert question.reason.endswith(
                    question.evidence + "\", which directly denies that this exact row is "
                    + audit_module._KIND_CRITERIA[question.kind] + "."
                )


def test_live_source_validates_exactly() -> None:
    assert validate_source_partition() == current_source_partition()
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        assert row.expected_owned_content_digest == audit_module.owned_content_digest(
            row.expected_owned_paths
        )
    assert audit_module._EXPECTED_IDENTITY_SCREEN_DIGESTS == {}


def test_reviewed_content_refresh_is_byte_bound_and_preserves_decisions() -> None:
    for object_id, review in REVIEWED_CONTENT_REFRESH.items():
        row = _audit(object_id)
        assert row.expected_owned_content_digest == review["digest"]
        assert audit_module.owned_content_digest(row.expected_owned_paths) == review["digest"]

        decisions = tuple(
            (question.kind, question.evidence)
            for question in row.questions
            if question.status == APPLIES
        )
        assert decisions == review["applies"]
        assert not any(question.status == DOES_NOT_APPLY for question in row.questions)
        for question in row.questions:
            assert question.reason == audit_module._reason(
                question.kind,
                question.status,
                question.evidence,
                row.scope,
            )

        for relative_path, (size, digest, markers) in review["files"].items():
            payload = (audit_module.REPOSITORY_ROOT / relative_path).read_bytes()
            assert len(payload) == size
            assert hashlib.sha256(payload).hexdigest() == digest
            text = payload.decode("utf-8")
            assert all(marker in text for marker in markers)


def test_primary_kind_is_never_refuted() -> None:
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        if row.expected_primary in ORIGINAL_NON_OBJECT_KINDS:
            status = next(q.status for q in row.questions if q.kind == row.expected_primary)
            assert status == APPLIES


def test_partial_profile_contains_only_decided_rows_and_no_unresolved_decisions() -> None:
    decided_rows = {
        row.object_id
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
        if any(question.status != UNRESOLVED for question in row.questions)
    }
    profile_rows = {assignment.object_id for assignment in REPOSITORY_ASSET_PARTIAL_PROFILE.assignments}
    assert profile_rows == decided_rows
    assert len(profile_rows) == 17
    assert UNCLOSED_ROW not in profile_rows
    decisions = [
        decision
        for assignment in REPOSITORY_ASSET_PARTIAL_PROFILE.assignments
        for decision in assignment.decisions
    ]
    assert len(decisions) == 44
    assert {decision.status for decision in decisions} == {APPLIES}


def test_partial_profile_is_sealed_and_recomputes() -> None:
    profile = validate_profile(REPOSITORY_ASSET_PARTIAL_PROFILE)
    assert profile_digest(profile) == profile.canonical_digest
    assert profile.claim_boundary == CLAIM_BOUNDARY
    assert "proves no full package closure" in CLAIM_BOUNDARY


def test_partial_profile_cannot_close_a_package_denominator() -> None:
    object_ids = tuple(sorted(spec.object_id for spec in REPOSITORY_ASSET_OWNERSHIP_SPECS))
    with pytest.raises(ValueError, match="DENOMINATOR_INCOMPLETE"):
        validate_full_closure(
            REPOSITORY_ASSET_PARTIAL_PROFILE, object_ids, expected_object_count=40
        )


def test_profile_digest_tamper_is_rejected() -> None:
    tampered = OriginalKindProfile(
        profile_id=REPOSITORY_ASSET_PARTIAL_PROFILE.profile_id,
        revision=REPOSITORY_ASSET_PARTIAL_PROFILE.revision,
        claim_boundary=REPOSITORY_ASSET_PARTIAL_PROFILE.claim_boundary,
        assignments=REPOSITORY_ASSET_PARTIAL_PROFILE.assignments[1:],
        canonical_digest=REPOSITORY_ASSET_PARTIAL_PROFILE.canonical_digest,
    )
    with pytest.raises(ValueError, match="DIGEST_INVALID"):
        validate_profile(tampered)


def test_profile_path_digest_tamper_is_rejected() -> None:
    first = REPOSITORY_ASSET_PARTIAL_PROFILE.assignments[0]
    bad_first = replace(first, expected_owned_path_set_digest="sha256:" + "0" * 64)
    tampered = OriginalKindProfile(
        profile_id=REPOSITORY_ASSET_PARTIAL_PROFILE.profile_id,
        revision=REPOSITORY_ASSET_PARTIAL_PROFILE.revision,
        claim_boundary=REPOSITORY_ASSET_PARTIAL_PROFILE.claim_boundary,
        assignments=(bad_first,) + REPOSITORY_ASSET_PARTIAL_PROFILE.assignments[1:],
        canonical_digest=REPOSITORY_ASSET_PARTIAL_PROFILE.canonical_digest,
    )
    with pytest.raises(ValueError):
        validate_profile(tampered)


def test_path_drift_is_rejected() -> None:
    spec = _spec("vstd-repository-overview")
    drifted = _replaced_source("vstd-repository-overview", owned_paths=("README.rst",))
    assert spec.owned_paths == ("README.md",)
    with pytest.raises(ValueError, match="PATH_DRIFT:vstd-repository-overview"):
        validate_source_partition(drifted)


def test_boundary_text_drift_changes_the_coordinate_digest() -> None:
    drifted = _replaced_source(
        "vstd-documentation-hosting-protocol",
        consequence_boundary="Altered boundary text that no longer quotes the refutation.",
    )
    with pytest.raises(ValueError, match="COORDINATE_DRIFT:vstd-documentation-hosting-protocol"):
        validate_source_partition(drifted)


def test_primary_drift_is_rejected() -> None:
    drifted = _replaced_source("vstd-repository-overview", primary_kind="PROTOCOL")
    with pytest.raises(ValueError, match="PRIMARY_DRIFT:vstd-repository-overview"):
        validate_source_partition(drifted)


def test_missing_source_row_is_rejected() -> None:
    specs = tuple(
        spec for spec in current_source_partition() if spec.object_id != "vstd-repository-overview"
    )
    with pytest.raises(ValueError, match="DENOMINATOR_DRIFT"):
        validate_source_partition(specs)


def test_extra_source_row_is_rejected() -> None:
    extra = replace(_spec("vstd-repository-overview"), object_id="vstd-extra-unaudited-row")
    with pytest.raises(ValueError, match="DENOMINATOR_DRIFT"):
        validate_source_partition(current_source_partition() + (extra,))


def test_duplicate_source_row_is_rejected() -> None:
    with pytest.raises(ValueError, match="SOURCE_PARTITION_INVALID"):
        validate_source_partition(current_source_partition() + (_spec("vstd-repository-overview"),))


def test_object_primary_bypass_is_rejected() -> None:
    drifted = _replaced_source("vstd-repository-overview", primary_kind="OBJECT")
    row = replace(_audit("vstd-repository-overview"), expected_primary="OBJECT")
    audits = _audits_with(row)
    with pytest.raises(ValueError, match="OBJECT_BYPASS:vstd-repository-overview"):
        validate_source_partition(drifted, audits)


def test_unestablished_applies_is_rejected() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "TIME", APPLIES, "primary")
    with pytest.raises(ValueError, match="UNESTABLISHED_APPLIES:vstd-repository-overview:TIME"):
        validate_source_partition(None, _audits_with(row))


def test_applies_with_wrong_basis_is_rejected() -> None:
    row = _with_question(_audit(RECEIPT_ROOT_ROWS[0]), "RECEIPT", APPLIES, "primary")
    with pytest.raises(ValueError, match="UNESTABLISHED_APPLIES"):
        validate_source_partition(None, _audits_with(row))


def test_primary_applies_cannot_be_downgraded_to_unresolved() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "DATA", UNRESOLVED, "")
    with pytest.raises(ValueError, match="ESTABLISHED_ROLE_OMITTED:vstd-repository-overview"):
        validate_source_partition(None, _audits_with(row))


def test_primary_cannot_be_refuted() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "DATA", DOES_NOT_APPLY, "README")
    with pytest.raises(ValueError, match="ESTABLISHED_ROLE_REFUTED:vstd-repository-overview:DATA"):
        validate_source_partition(None, _audits_with(row))


def test_root_receipt_role_cannot_be_refuted() -> None:
    row = _with_question(
        _audit(RECEIPT_ROOT_ROWS[0]), "RECEIPT", DOES_NOT_APPLY, "certificate result records"
    )
    with pytest.raises(ValueError, match="ESTABLISHED_ROLE_REFUTED"):
        validate_source_partition(None, _audits_with(row))


def test_fabricated_exclusion_quote_is_rejected() -> None:
    row = _with_question(
        _audit("vstd-repository-overview"), "RECEIPT", DOES_NOT_APPLY, "not a receipt at all"
    )
    with pytest.raises(ValueError, match="EXCLUSION_NOT_SOURCE_BOUND:vstd-repository-overview:RECEIPT"):
        validate_source_partition(None, _audits_with(row))


def test_exclusion_without_a_quote_is_rejected() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "RECEIPT", DOES_NOT_APPLY, "")
    with pytest.raises(ValueError, match="EXCLUSION_NOT_SOURCE_BOUND"):
        validate_source_partition(None, _audits_with(row))


def test_unresolved_carrying_evidence_is_rejected() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "RECEIPT", UNRESOLVED, "artifact receipt")
    with pytest.raises(ValueError, match="UNRESOLVED_CARRIES_EVIDENCE"):
        validate_source_partition(None, _audits_with(row))


def test_unknown_status_is_rejected() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "RECEIPT", "MAYBE", "")
    with pytest.raises(ValueError, match="STATUS_INVALID"):
        validate_source_partition(None, _audits_with(row))


def test_omitted_question_is_rejected_at_construction() -> None:
    row = _audit("vstd-repository-overview")
    with pytest.raises(AssertionError):
        audit_module._record(
            "vstd-repository-overview",
            "DATA",
            row.expected_owned_paths,
            row.expected_source_coordinate_digest,
            row.scope,
            tuple(
                audit_module._question(question.kind, question.status)
                for question in row.questions[:-1]
            ),
        )


def test_reordered_questions_are_rejected_at_construction() -> None:
    row = _audit("vstd-repository-overview")
    selections = tuple((q.kind, q.status, q.evidence) for q in row.questions)
    with pytest.raises(AssertionError, match="order differs"):
        audit_module._record(
            "vstd-repository-overview",
            "DATA",
            row.expected_owned_paths,
            row.expected_source_coordinate_digest,
            row.scope,
            tuple(reversed(selections)),
        )


def test_invalid_status_is_rejected_at_construction() -> None:
    row = _audit("vstd-repository-overview")
    selections = tuple((q.kind, q.status, q.evidence) for q in row.questions)
    selections = ((selections[0][0], "MAYBE", ""),) + selections[1:]
    with pytest.raises(AssertionError, match="status invalid"):
        audit_module._record(
            "vstd-repository-overview",
            "DATA",
            row.expected_owned_paths,
            row.expected_source_coordinate_digest,
            row.scope,
            selections,
        )


def test_review_document_is_complete_and_never_upgrades_unresolved() -> None:
    document = review_document()
    assert len(document) == 40
    for object_id, entry in document.items():
        assert len(entry["questions"]) == 25
        assert entry["expected_owned_content_digest"] == _audit(
            object_id
        ).expected_owned_content_digest
        for kind, answer in entry["questions"].items():
            if answer["status"] == UNRESOLVED:
                assert answer["evidence"] == ""
            assert kind in ORIGINAL_NON_OBJECT_KINDS
        assert (entry["partial_profile_digest"] is not None) == any(
            answer["status"] != UNRESOLVED for answer in entry["questions"].values()
        ), object_id


def test_module_uses_only_standard_library_and_verifier_modules() -> None:
    source = Path(audit_module.__file__).read_text(encoding="utf-8")
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= {"__future__", "dataclasses", "hashlib", "json", "typing", "verifier", "pathlib", "re"}


def test_module_source_is_ascii_and_has_no_local_paths() -> None:
    raw = Path(audit_module.__file__).read_bytes()
    raw.decode("ascii")
    assert b"C:\\" not in raw and b"/Users/" not in raw


def test_refutation_quote_borrowed_from_another_row_is_rejected() -> None:
    # Substitution: a true negated sentence from a different owned row cannot refute this row.
    borrowed = _spec("vstd-repository-release-procedure-policy").consequence_boundary
    row = _with_question(_audit("vstd-documentation-hosting-protocol"), "ACTOR", DOES_NOT_APPLY, borrowed)
    with pytest.raises(ValueError, match="EXCLUSION_NOT_SOURCE_BOUND:vstd-documentation-hosting-protocol:ACTOR"):
        validate_source_partition(None, _audits_with(row))


def test_refutation_quote_without_negation_is_rejected() -> None:
    # A noun phrase that occurs in a negated sentence is not itself a refutation.
    row = _with_question(
        _audit("vstd-github-verification-workflow-protocols"),
        "RECEIPT",
        DOES_NOT_APPLY,
        "trusted platform receipt",
    )
    with pytest.raises(ValueError, match="EXCLUSION_NOT_NEGATED:vstd-github-verification-workflow-protocols:RECEIPT"):
        validate_source_partition(None, _audits_with(row))


def test_unresolved_cannot_be_upgraded_without_a_declared_quote() -> None:
    row = _with_question(_audit("vstd-repository-overview"), "ACTOR", DOES_NOT_APPLY, "")
    with pytest.raises(ValueError, match="EXCLUSION_NOT_SOURCE_BOUND:vstd-repository-overview:ACTOR"):
        validate_source_partition(None, _audits_with(row))


def test_proof_only_rows_refute_nothing() -> None:
    # "does not prove", "does not establish" and "do not show" are proof boundaries.
    # Every row whose declaration holds only such boundaries keeps all non-primary kinds UNRESOLVED.
    assert set(PROOF_ONLY_ROWS) <= {row.object_id for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS}
    assert not set(PROOF_ONLY_ROWS) & set(EXPECTED_DNE_KINDS)
    for object_id in PROOF_ONLY_ROWS:
        row = _audit(object_id)
        for question in row.questions:
            if question.kind != row.expected_primary:
                assert question.status == UNRESOLVED, (object_id, question.kind)


def test_high_risk_kinds_are_retained_only_for_the_unclosed_accelerator_schema() -> None:
    # Counterexample review: the accelerator row's "does not detect hardware, measure a
    # device" sentence does not refute HARDWARE, because its declared profile schema
    # describes device-class, architecture and capability fields, a device-inventory shape.
    schema = Path(__file__).resolve().parents[1] / "receipts" / "schema"
    assert '"device_class"' in (schema / "vstd3_accelerator_profile.json").read_text(encoding="utf-8")
    for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.kind in HIGH_RISK_KINDS:
                expected = (
                    APPLIES
                    if row.object_id == "vstd-accelerator-profile-wire-schema"
                    else UNRESOLVED
                )
                assert question.status == expected, (row.object_id, question.kind)


def test_declared_refutation_sentence_drift_is_rejected() -> None:
    drifted = _replaced_source(
        "vstd-retained-graph-statics-policy-input",
        consequence_boundary="The stored policy is a retained decision rule with altered text.",
    )
    with pytest.raises(ValueError, match="COORDINATE_DRIFT:vstd-retained-graph-statics-policy-input"):
        validate_source_partition(drifted)


def test_negated_quote_alone_cannot_bypass_the_identity_ledger() -> None:
    # A verbatim, negated sentence from the row's own declaration is not enough:
    # this one denies only proof and reachability, so it must not refute ACTOR.
    text = _spec("vstd-repository-overview").consequence_boundary
    assert "does not establish" in text and text in _declared_text("vstd-repository-overview")
    row = _with_question(_audit("vstd-repository-overview"), "ACTOR", DOES_NOT_APPLY, text)
    with pytest.raises(ValueError, match="DENIAL_NOT_IDENTITY_BASED:vstd-repository-overview:ACTOR"):
        validate_source_partition(None, _audits_with(row))


def test_contradicting_owned_source_blocks_an_identity_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    # The EVENT sentence is a whole-kind denial on paper, but the invoked policy scripts
    # build "action" and "event_name" records.  Even a ledgered denial must not survive.
    object_id = "vstd-github-promotion-policy-protocols"
    quote = (
        "Static workflow bytes are not a dispatched event, trusted run, human acceptance, "
        "queue state, approval, merge authority or integration proof."
    )
    monkeypatch.setitem(audit_module.IDENTITY_DENIALS, (object_id, "EVENT"), (quote, "not a dispatched event"))
    row = _with_question(_audit(object_id), "EVENT", DOES_NOT_APPLY, quote)
    with pytest.raises(ValueError, match="SOURCE_COUNTEREXAMPLE:vstd-github-promotion-policy-protocols:EVENT"):
        validate_source_partition(None, _audits_with(row))


def test_identity_denial_ledger_matches_the_surviving_denials() -> None:
    survivors = {
        (row.object_id, question.kind)
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
        for question in row.questions
        if question.status == DOES_NOT_APPLY
    }
    assert set(audit_module.IDENTITY_DENIALS) == survivors
    for (object_id, kind), (quote, clause) in audit_module.IDENTITY_DENIALS.items():
        assert quote in _declared_text(object_id), (object_id, kind)
        assert clause in quote, (object_id, kind)


def test_demotion_ledger_reconciles_the_prior_table_exactly() -> None:
    prior = {(object_id, kind) for object_id, kinds in PRIOR_DNE_KINDS.items() for kind in kinds}
    ledger = [(object_id, kind) for object_id, kind, _basis in audit_module.DEMOTED_EXCLUSIONS]
    survivors = {(object_id, kind) for object_id, kinds in EXPECTED_DNE_KINDS.items() for kind in kinds}
    assert len(ledger) == len(set(ledger)) == 53
    assert set(ledger) | survivors | PROMOTED_PRIOR_DNE == prior
    assert not set(ledger) & survivors
    assert not set(ledger) & PROMOTED_PRIOR_DNE
    for object_id, kind, basis in audit_module.DEMOTED_EXCLUSIONS:
        assert basis in audit_module._DEMOTION_BASES, (object_id, kind)
        assert _audit(object_id).questions[ORIGINAL_NON_OBJECT_KINDS.index(kind)].status == UNRESOLVED
    assert (UNCLOSED_ROW, "VERIFIER", audit_module.UNCLOSED_EFFECT_BOUNDARY) in audit_module.DEMOTED_EXCLUSIONS


def test_source_counterexample_demotion_reproduces_its_hit() -> None:
    object_id = "vstd-github-promotion-policy-protocols"
    spec = _spec(object_id)
    hits = audit_module.owned_source_hits(spec.owned_paths, "EVENT", object_id)
    assert any(hit.startswith("scripts/check_policy_notification.py:") for hit in hits)
    assert any(hit.startswith("scripts/check_pr_policy.py:") for hit in hits)
    assert (object_id, "EVENT", audit_module.SOURCE_COUNTEREXAMPLE) in audit_module.DEMOTED_EXCLUSIONS


def test_owned_closure_follows_invoked_scripts_and_excludes_declarations() -> None:
    object_id = "vstd-github-promotion-policy-protocols"
    closure = audit_module.owned_source_closure(_spec(object_id).owned_paths, object_id)
    assert {"scripts/check_pr_policy.py", "scripts/check_policy_notification.py"} <= set(closure)
    assert not [path for path in closure if path.startswith(audit_module._DECLARATION_PREFIXES)]


def test_every_screen_kind_has_a_closed_marker_table() -> None:
    assert set(audit_module._OWNED_SOURCE_SCREEN) == set(ORIGINAL_NON_OBJECT_KINDS)
    assert all(markers for markers in audit_module._OWNED_SOURCE_SCREEN.values())


def test_unavailable_owned_bytes_fail_closed(tmp_path: Path) -> None:
    # An identity denial without readable owned bytes cannot be screened, so it fails.
    with pytest.raises(ValueError, match="OWNED_SOURCE_UNAVAILABLE"):
        validate_source_partition(None, REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS, source_root=tmp_path)


def _write(root: Path, relpath: str, text: str) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_closure_resolves_named_submodules_and_transitive_imports(tmp_path: Path) -> None:
    # A package named in "from pkg import name" adds only the submodule files that exist,
    # a multi-line import is read in full, and a name without a file is tolerated.
    _write(tmp_path, "docs/owned.md", "Run `python scripts/driver.py` to check.\n")
    _write(tmp_path, "scripts/driver.py", "from verifier.pkg import a\nfrom verifier.pkg import (\n    b,\n    missing,\n)\n")
    _write(tmp_path, "src/verifier/pkg/__init__.py", "")
    _write(tmp_path, "src/verifier/pkg/a.py", "VALUE = 1\n")
    _write(tmp_path, "src/verifier/pkg/b.py", "from verifier.pkg.c import thing\n")
    _write(tmp_path, "src/verifier/pkg/c.py", "thing = 2\n")
    _write(tmp_path, "src/verifier/pkg/unrelated.py", "OTHER = 3\n")
    closure = audit_module.owned_source_closure(("docs/owned.md",), "", tmp_path)
    assert closure == (
        "scripts/driver.py",
        "src/verifier/pkg/__init__.py",
        "src/verifier/pkg/a.py",
        "src/verifier/pkg/b.py",
        "src/verifier/pkg/c.py",
    )


def test_closure_fails_closed_on_unresolved_or_oversized_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "docs/owned.md", "Run `python scripts/driver.py` to check.\n")
    _write(tmp_path, "scripts/driver.py", "import verifier.nope\n")
    with pytest.raises(ValueError, match="IMPORT_UNRESOLVED:verifier.nope"):
        audit_module.owned_source_closure(("docs/owned.md",), "", tmp_path)
    _write(tmp_path, "scripts/driver.py", "from verifier.pkg import a\n")
    _write(tmp_path, "src/verifier/pkg/__init__.py", "")
    _write(tmp_path, "src/verifier/pkg/a.py", "VALUE = 1\n")
    monkeypatch.setattr(audit_module, "SOURCE_CLOSURE_LIMIT", 1)
    with pytest.raises(ValueError, match="CLOSURE_LIMIT"):
        audit_module.owned_source_closure(("docs/owned.md",), "", tmp_path)


def test_verifier_screen_separates_retry_fields_from_checker_identity() -> None:
    # Good: a retry or recovery field is not a checker.  Bad: a replay procedure, a
    # verdict record, or a decision procedure is checker identity.
    screen = dict(audit_module._OWNED_SOURCE_SCREEN["VERIFIER"])
    for benign in ('"replay": profile.retry,', '"recovery": policy.limit,'):
        assert not [name for name, pattern in screen.items() if pattern.search(benign)], benign
    assert "procedure-definition" in [name for name, pattern in screen.items() if pattern.search("def replay_check(request):")]
    assert "verdict-or-checker-key" in [name for name, pattern in screen.items() if pattern.search('"verdict": "PASS",')]
    assert "decision-procedure" in [name for name, pattern in screen.items() if pattern.search("decision_procedure = None")]


def test_binary_owned_asset_is_opaque_to_kind_screening(tmp_path: Path) -> None:
    path = tmp_path / "assets" / "opaque.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xff\xfe\x00{\"verdict\":\"PASS\"}")
    with pytest.raises(ValueError, match="OWNED_SOURCE_NOT_UTF8:assets/opaque.bin"):
        audit_module.owned_source_hits(("assets/opaque.bin",), "VERIFIER", root=tmp_path)


def test_json_schema_consumer_closure_retains_roles_without_effect_claims() -> None:
    schema = _audit("vstd-accelerator-profile-wire-schema")
    schema_text = (audit_module.REPOSITORY_ROOT / schema.expected_owned_paths[0]).read_text(
        encoding="utf-8"
    )
    assert '"device_class"' in schema_text and '"architecture"' in schema_text
    assert next(q for q in schema.questions if q.kind == "HARDWARE").status == APPLIES
    assert next(q for q in schema.questions if q.kind == "ARCH").status == APPLIES

    request = _audit("vstd-retained-graph-statics-request")
    request_text = (audit_module.REPOSITORY_ROOT / request.expected_owned_paths[0]).read_text(
        encoding="utf-8"
    )
    assert '"object_kind":"GRAPH"' in request_text
    assert next(q for q in request.questions if q.kind == "GRAPH").status == UNRESOLVED


def test_owned_content_digest_detects_stale_bytes(tmp_path: Path) -> None:
    _write(tmp_path, "docs/asset.json", '{"kind":"DATA"}\n')
    before = audit_module.owned_content_digest(("docs/asset.json",), tmp_path)
    _write(tmp_path, "docs/asset.json", '{"kind":"OBJECT"}\n')
    after = audit_module.owned_content_digest(("docs/asset.json",), tmp_path)
    assert before != after


def test_owned_content_digest_substitution_is_rejected() -> None:
    row = _audit("vstd-repository-overview")
    forged = replace(row, expected_owned_content_digest="sha256:" + "0" * 64)
    with pytest.raises(
        ValueError,
        match="CONTENT_DIGEST_SUBSTITUTION:vstd-repository-overview",
    ):
        validate_source_partition(None, _audits_with(forged))


def test_path_alias_and_symlink_cannot_substitute_owned_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "docs/asset.json", "{}\n")
    with pytest.raises(ValueError, match="OWNED_SOURCE_PATH_ALIAS"):
        audit_module.owned_content_digest(("docs/../docs/asset.json",), tmp_path)

    link = tmp_path / "docs" / "alias.json"
    try:
        link.symlink_to(tmp_path / "docs" / "asset.json")
    except OSError:
        # Windows may deny symlink creation without Developer Mode.  Exercise the
        # same branch deterministically instead of turning the safety gate UNKNOWN.
        _write(tmp_path, "docs/alias.json", "{}\n")
        real_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda selected: selected == link or real_is_symlink(selected),
        )
    with pytest.raises(ValueError, match="OWNED_SOURCE_SYMLINK"):
        audit_module.owned_content_digest(("docs/alias.json",), tmp_path)


def test_same_status_reason_forgery_is_rejected() -> None:
    row = _audit("vstd-repository-overview")
    forged = replace(
        row,
        questions=tuple(
            replace(question, reason="forged same-status rationale")
            if question.kind == "DATA"
            else question
            for question in row.questions
        ),
    )
    with pytest.raises(ValueError, match="REASON_DRIFT:vstd-repository-overview:DATA"):
        validate_source_partition(None, _audits_with(forged))


def test_validation_rejects_a_mixed_pre_and_post_source_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = audit_module.owned_content_digest
    calls = 0

    def changing_digest(paths: object, root: Path = audit_module.REPOSITORY_ROOT) -> str:
        nonlocal calls
        calls += 1
        digest = original(paths, root)
        return digest if calls <= len(REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS) else digest + "-changed"

    monkeypatch.setattr(audit_module, "owned_content_digest", changing_digest)
    with pytest.raises(ValueError, match="SOURCE_CHANGED:vstd-accelerator-profile-wire-schema"):
        validate_source_partition()


def test_denial_screen_rejects_a_mixed_source_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No denial survives, so reinstate the former one with its effect-boundary blocker
    # lifted: only then does validation reach the screen snapshot.
    original = audit_module.owned_screen_digest
    calls = 0

    def changing_screen(paths: object, object_id: str, root: Path) -> str:
        nonlocal calls
        calls += 1
        digest = original(paths, object_id, root)  # type: ignore[arg-type]
        return digest if calls == 1 else digest + "-changed"

    quote = _spec(UNCLOSED_ROW).necessity_reason
    monkeypatch.delitem(audit_module.UNCLOSED_EFFECT_BLOCKERS, (UNCLOSED_ROW, "VERIFIER"))
    monkeypatch.setitem(
        audit_module.IDENTITY_DENIALS, (UNCLOSED_ROW, "VERIFIER"), (quote, "without being mechanisms themselves")
    )
    monkeypatch.setattr(audit_module, "owned_screen_digest", changing_screen)
    reinstated = _with_question(_audit(UNCLOSED_ROW), "VERIFIER", DOES_NOT_APPLY, quote)
    with pytest.raises(
        ValueError,
        match="SCREEN_SOURCE_CHANGED:vstd-retained-object-facet-requests:VERIFIER",
    ):
        validate_source_partition(None, _audits_with(reinstated))


def test_former_denial_is_unresolved_behind_an_exact_effect_boundary_blocker() -> None:
    # The request messages are read by a checking procedure outside the name-based closure,
    # so the clean VERIFIER screen cannot exhaust the effect boundary.
    row = _audit(UNCLOSED_ROW)
    question = next(q for q in row.questions if q.kind == "VERIFIER")
    assert (question.status, question.evidence) == (UNRESOLVED, "")
    assert audit_module.UNCLOSED_EFFECT_BLOCKERS == {(UNCLOSED_ROW, "VERIFIER"): (UNCLOSED_CONSUMER, UNCLOSED_SCHEMA)}
    assert (UNCLOSED_ROW, "VERIFIER", audit_module.UNCLOSED_EFFECT_BOUNDARY) in audit_module.DEMOTED_EXCLUSIONS
    closure = audit_module.owned_source_closure(_spec(UNCLOSED_ROW).owned_paths, UNCLOSED_ROW)
    assert UNCLOSED_CONSUMER not in closure
    root = audit_module.REPOSITORY_ROOT
    consumer = (root / UNCLOSED_CONSUMER).read_text(encoding="utf-8")
    assert "def recheck_object_facets_certificate(" in consumer
    for relpath in row.expected_owned_paths:
        assert UNCLOSED_SCHEMA in (root / relpath).read_text(encoding="utf-8"), relpath


def test_excluded_consumer_contains_a_verifier_counterexample_the_closure_misses() -> None:
    # Counterexample evidence: the screen's own VERIFIER markers match the consumer's
    # checker identity key, but only if the consumer is in the closure, which it is not.
    consumer = (audit_module.REPOSITORY_ROOT / UNCLOSED_CONSUMER).read_text(encoding="utf-8")
    matched = [
        (number, name)
        for number, line in enumerate(consumer.splitlines(), 1)
        for name, pattern in audit_module._OWNED_SOURCE_SCREEN["VERIFIER"]
        if pattern.search(line)
    ]
    assert ("verdict-or-checker-key" in {name for _number, name in matched})
    assert UNCLOSED_CONSUMER not in audit_module.owned_source_closure(
        _spec(UNCLOSED_ROW).owned_paths, UNCLOSED_ROW
    )


def test_reinstating_the_denial_is_blocked_by_the_effect_boundary() -> None:
    quote = _spec(UNCLOSED_ROW).necessity_reason
    reinstated = _with_question(_audit(UNCLOSED_ROW), "VERIFIER", DOES_NOT_APPLY, quote)
    with pytest.raises(ValueError, match="EFFECT_BOUNDARY_BLOCKED:vstd-retained-object-facet-requests:VERIFIER"):
        validate_source_partition(None, _audits_with(reinstated))


def test_effect_boundary_blocker_must_reproduce_outside_the_closure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        audit_module.UNCLOSED_EFFECT_BLOCKERS,
        (UNCLOSED_ROW, "VERIFIER"),
        (UNCLOSED_CONSUMER, "verifier-current-object-facets-request-0"),
    )
    with pytest.raises(ValueError, match="EFFECT_BOUNDARY_NOT_REPRODUCED:vstd-retained-object-facet-requests:VERIFIER"):
        validate_source_partition()


def test_effect_boundary_blocker_cannot_name_a_missing_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        audit_module.UNCLOSED_EFFECT_BLOCKERS,
        (UNCLOSED_ROW, "VERIFIER"),
        ("src/verifier/domains/contracts/absent_consumer.py", UNCLOSED_SCHEMA),
    )
    with pytest.raises(ValueError, match="EFFECT_BOUNDARY_NOT_REPRODUCED"):
        validate_source_partition()


def test_unclosed_basis_without_a_blocker_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(audit_module.UNCLOSED_EFFECT_BLOCKERS, (UNCLOSED_ROW, "VERIFIER"))
    with pytest.raises(ValueError, match="EFFECT_BOUNDARY_NOT_REPRODUCED"):
        validate_source_partition()


def test_demotion_basis_outside_the_closed_vocabulary_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    demotions = tuple(
        (object_id, kind, "FREE_TEXT_BASIS" if (object_id, kind) == (UNCLOSED_ROW, "VERIFIER") else basis)
        for object_id, kind, basis in audit_module.DEMOTED_EXCLUSIONS
    )
    monkeypatch.setattr(audit_module, "DEMOTED_EXCLUSIONS", demotions)
    with pytest.raises(ValueError, match="DEMOTION_INVALID:" + UNCLOSED_ROW):
        validate_source_partition()


def test_closed_screen_cannot_see_dynamic_reflective_or_relative_consumers(tmp_path: Path) -> None:
    # Dynamic import, reflection and a relative import in a consumer that never names the
    # owned path or object id are outside the closure.  A clean screen is therefore not
    # exhaustive proof that no VERIFIER effect exists, so no DOES_NOT_APPLY may rest on it.
    _write(tmp_path, "docs/req.json", '{"schema_version":"verifier-x-request-1"}\n')
    _write(
        tmp_path,
        "scripts/dispatch.py",
        'import importlib\nmodule = importlib.import_module("verifier.checker")\n'
        'result = getattr(module, "check" + "_request")({"verdict": "PASS"})\n',
    )
    _write(tmp_path, "src/verifier/pkg/relay.py", "from .checker import run\n")
    _write(tmp_path, "src/verifier/pkg/checker.py", 'RESULT = {"verdict": "PASS"}\n')
    assert audit_module.owned_source_closure(("docs/req.json",), "", tmp_path) == ()
    assert audit_module.owned_source_hits(("docs/req.json",), "VERIFIER", "", tmp_path) == ()


def test_imported_checker_is_screened_when_the_owned_bytes_name_its_driver(tmp_path: Path) -> None:
    _write(tmp_path, "docs/req.json", "Run `python scripts/driver.py` to check.\n")
    _write(tmp_path, "scripts/driver.py", "from verifier.pkg import checker as ck\n")
    _write(tmp_path, "src/verifier/pkg/__init__.py", "")
    _write(tmp_path, "src/verifier/pkg/checker.py", 'RESULT = {"verdict": "PASS"}\n')
    assert audit_module.owned_source_hits(("docs/req.json",), "VERIFIER", "", tmp_path) == (
        "src/verifier/pkg/checker.py:1:verdict-or-checker-key",
    )


@pytest.mark.parametrize(
    "statement",
    [
        "import verifier.pkg.checker as ck\n",
        "from verifier.pkg import checker as ck\n",
        "from verifier.pkg import (\n    other as o,\n    checker as ck,\n)\n",
    ],
)
def test_aliased_imports_resolve_to_the_aliased_module(tmp_path: Path, statement: str) -> None:
    _write(tmp_path, "docs/req.json", "Run `python scripts/driver.py`.\n")
    _write(tmp_path, "scripts/driver.py", statement)
    _write(tmp_path, "src/verifier/pkg/__init__.py", "")
    _write(tmp_path, "src/verifier/pkg/checker.py", "VALUE = 1\n")
    _write(tmp_path, "src/verifier/pkg/other.py", "VALUE = 2\n")
    closure = audit_module.owned_source_closure(("docs/req.json",), "", tmp_path)
    assert "src/verifier/pkg/checker.py" in closure


@pytest.mark.parametrize(
    "relpath",
    ["./docs/req.json", "docs//req.json", "docs\\req.json", "/docs/req.json", "docs/req.json/"],
)
def test_path_spelling_aliases_cannot_select_other_owned_bytes(tmp_path: Path, relpath: str) -> None:
    _write(tmp_path, "docs/req.json", "{}\n")
    with pytest.raises(ValueError, match="OWNED_SOURCE_PATH_ALIAS"):
        audit_module.owned_content_digest((relpath,), tmp_path)


def test_referent_fields_do_not_establish_object_identity(tmp_path: Path) -> None:
    # A mechanism digest and an object kind are references to other things; only an
    # identity key such as mechanism_id is checker identity for the VERIFIER screen.
    _write(tmp_path, "docs/request.json", '{"object_kind":"OBJECT","mechanism_digest":"sha256:00"}\n')
    assert audit_module.owned_source_hits(("docs/request.json",), "VERIFIER", "", tmp_path) == ()
    _write(tmp_path, "docs/identity.json", '{"mechanism_id":"verifier.x"}\n')
    assert audit_module.owned_source_hits(("docs/identity.json",), "VERIFIER", "", tmp_path) == (
        "docs/identity.json:1:verdict-or-checker-key",
    )


def test_synonym_denial_absent_from_declared_text_is_rejected() -> None:
    # "validators" is a synonym for a checker, not the declared sentence.
    row = _with_question(
        _audit("vstd-repository-overview"),
        "ACTOR",
        DOES_NOT_APPLY,
        "The overview is not a decider or approver.",
    )
    with pytest.raises(ValueError, match="EXCLUSION_NOT_SOURCE_BOUND:vstd-repository-overview:ACTOR"):
        validate_source_partition(None, _audits_with(row))


def test_reason_text_borrowed_from_another_kind_is_rejected() -> None:
    row = _audit("vstd-repository-overview")
    borrowed = audit_module._reason("ACTOR", UNRESOLVED, "", row.scope)
    forged = replace(
        row,
        questions=tuple(
            replace(question, reason=borrowed) if question.kind == "DATA" else question
            for question in row.questions
        ),
    )
    with pytest.raises(ValueError, match="REASON_DRIFT:vstd-repository-overview:DATA"):
        validate_source_partition(None, _audits_with(forged))


def test_accumulated_root_role_must_be_answered_and_cannot_be_refuted() -> None:
    # A source root decision accumulates a second kind onto the primary role.  The audit
    # must answer it with the matching basis and reason; omission or refutation fails.
    object_id = "vstd-repository-overview"
    spec = _spec(object_id)
    extended = replace(
        spec,
        root_role_decisions=spec.root_role_decisions
        + (root_role_decision("ROLE", "APPLIES", "Synthetic accumulated root role for this test."),),
    )
    base = _audit(object_id)
    rebound = replace(
        base, expected_source_coordinate_digest=audit_module._source_coordinate_digest(extended)
    )
    with pytest.raises(ValueError, match="ESTABLISHED_ROLE_OMITTED:" + object_id):
        validate_source_partition(_replaced_source(object_id, root_role_decisions=extended.root_role_decisions), _audits_with(rebound))
    answered = _with_question(
        rebound,
        "ROLE",
        APPLIES,
        "root_role_decision",
    )
    answered = replace(
        answered,
        questions=tuple(
            replace(q, reason=audit_module._reason("ROLE", APPLIES, "root_role_decision", rebound.scope))
            if q.kind == "ROLE" else q
            for q in answered.questions
        ),
    )
    assert validate_source_partition(
        _replaced_source(object_id, root_role_decisions=extended.root_role_decisions), _audits_with(answered)
    )
    refuted = _with_question(rebound, "ROLE", DOES_NOT_APPLY, "The overview is not a role.")
    with pytest.raises(ValueError, match="ESTABLISHED_ROLE_REFUTED:" + object_id + ":ROLE"):
        validate_source_partition(
            _replaced_source(object_id, root_role_decisions=extended.root_role_decisions), _audits_with(refuted)
        )
