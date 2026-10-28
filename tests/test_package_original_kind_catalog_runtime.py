# Terminology: Advanced Micro Devices (AMD); conjunctive normal form (CNF).
from __future__ import annotations

import random
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.core.certificate import Verdict
from verifier.core.checker import VerificationVerdict
from verifier.data import policy as provenance_policy
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    RightsSpec,
    TransformationHyperedge,
    TransformationType,
)
from verifier.runtime import package_original_kind_catalog_runtime as catalog
from verifier.runtime import package_protocol_dependency_relation as relation
from verifier.runtime.package_original_kind_catalog_runtime import (
    RUNTIME_ORIGINAL_KIND_AUDITS,
    RUNTIME_PARTIAL_PROFILE,
    UNRESOLVED,
    current_source_partition,
    review_document,
    validate_behavioral_evidence,
    validate_runtime_review,
    validate_source_partition,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    profile_digest,
    validate_profile,
)
from verifier.runtime.package_semantic_ownership_model import RootRoleDecision


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_SOURCE = (
    REPO_ROOT
    / "src"
    / "verifier"
    / "runtime"
    / "package_original_kind_catalog_runtime.py"
)

# The only boundary exclusions accepted after the counterexample review.  The
# first audit's ACTOR and application-authority HUMAN exclusions were retired:
# their boundary sentences limit output authority rather than deny an operation.
EXPECTED_EXCLUSIONS = {
    ("vstd-finite-record-issuance", "HUMAN"),
    ("vstd-self-polish-native-case-registry", "VERIFIER"),
}
# Cells retired on adversarial re-audit; each must stay UNRESOLVED.
RETIRED_CELLS = {
    ("vstd-invocation-ledger", "ACTOR"),
    ("vstd-application-authority-protocol", "HUMAN"),
    ("vstd-hardware-receipt-assessor", "RECEIPT"),
    ("vstd-graph-topology-reader", "GRAPH"),
    ("vstd-dataset-provenance-policy", "GRAPH"),
    ("vstd-namespace-rule-engine", "VERIFIER"),
    ("vstd-self-polish-native-case-registry", "BENCH"),
}
# Kinds whose identity or authority is high-risk; no runtime row may exclude them.
HIGH_RISK_KINDS = {
    "SIM",
    "MODEL",
    "AGENT",
    "BOT",
    "HARDWARE",
    "TOKEN",
    "OWNER",
}


def _source_map():
    return {spec.object_id: spec for spec in current_source_partition()}


def _cell(object_id: str, kind: str):
    row = next(
        row for row in RUNTIME_ORIGINAL_KIND_AUDITS if row.object_id == object_id
    )
    return next(question for question in row.questions if question.kind == kind)


@pytest.mark.parametrize(
    "object_id",
    (
        "vstd-invocation-ledger",
        "vstd-package-worker-exchange",
        "vstd-sim-resource-measurement",
    ),
)
def test_executed_package_obligation_owner_is_a_verifier(object_id: str) -> None:
    assert _cell(object_id, "VERIFIER").status == APPLIES
    evidence = catalog._BEHAVIORAL_BY_CELL[(object_id, "VERIFIER")]
    assert evidence.path in _source_map()[object_id].owned_paths
    assert evidence.anchor.startswith("def evaluate(")


def test_runtime_audit_has_exact_local_denominator_and_literal_questions() -> None:
    assert len(RUNTIME_ORIGINAL_KIND_AUDITS) == 122
    assert len({row.object_id for row in RUNTIME_ORIGINAL_KIND_AUDITS}) == 122
    assert {
        row.group for row in RUNTIME_ORIGINAL_KIND_AUDITS
    } == {
        "runtime-admission",
        "runtime-command",
        "runtime-polish",
        "runtime-self-polish",
        "runtime-hardware-cli",
        "added-kind-behavioral",
        "additional-explicit",
    }
    counts = {
        group: sum(row.group == group for row in RUNTIME_ORIGINAL_KIND_AUDITS)
        for group in {row.group for row in RUNTIME_ORIGINAL_KIND_AUDITS}
    }
    assert counts == {
        "runtime-admission": 14,
        "runtime-command": 13,
        "runtime-polish": 18,
        "runtime-self-polish": 14,
        "runtime-hardware-cli": 5,
        "added-kind-behavioral": 1,
        "additional-explicit": 57,
    }
    assert all(
        tuple(question.kind for question in row.questions)
        == ORIGINAL_NON_OBJECT_KINDS
        for row in RUNTIME_ORIGINAL_KIND_AUDITS
    )

    source = CATALOG_SOURCE.read_text(encoding="utf-8")
    literal_catalog = source.split("RUNTIME_ORIGINAL_KIND_AUDITS = (", 1)[1].split(
        "RUNTIME_PARTIAL_PROFILE =", 1
    )[0]
    assert literal_catalog.count('_question("') == 122 * 25
    assert "for kind in" not in literal_catalog
    assert "set(ORIGINAL_NON_OBJECT_KINDS)" not in literal_catalog
    assert "difference(" not in literal_catalog


def test_current_aggregate_local_source_is_exact_and_paths_exist() -> None:
    selected = current_source_partition()
    assert validate_source_partition(selected) == selected
    assert len(selected) == 122
    assert tuple(spec.object_id for spec in selected) == tuple(
        row.object_id for row in RUNTIME_ORIGINAL_KIND_AUDITS
    )
    assert sum(len(spec.owned_paths) for spec in selected) == 294
    missing = [
        path
        for spec in selected
        for path in spec.owned_paths
        if not (REPO_ROOT / path).is_file()
    ]
    assert missing == []


def test_runtime_pins_equal_every_current_central_spec_coordinate() -> None:
    source = _source_map()
    assert len(source) == len(RUNTIME_ORIGINAL_KIND_AUDITS) == 122
    mismatches = []
    for row in RUNTIME_ORIGINAL_KIND_AUDITS:
        spec = source[row.object_id]
        pairs = {
            "primary": (spec.primary_kind, row.expected_primary),
            "owned_paths": (tuple(spec.owned_paths), row.expected_owned_paths),
            "representation_role": (
                spec.representation_role,
                row.expected_representation_role,
            ),
            "necessity_reason": (
                spec.necessity_reason,
                row.expected_necessity_reason,
            ),
            "consequence_boundary": (
                spec.consequence_boundary,
                row.expected_consequence_boundary,
            ),
            "specializations": (
                tuple(spec.specializations),
                row.expected_specializations,
            ),
            "root_role_decisions": (
                tuple(
                    (decision.kind, decision.status, decision.reason)
                    for decision in spec.root_role_decisions
                ),
                row.expected_root_role_decisions,
            ),
            "source_coordinate_digest": (
                catalog._spec_source_coordinate_digest(spec),
                row.expected_source_coordinate_digest,
            ),
        }
        mismatches.extend(
            (row.object_id, name)
            for name, (actual, pinned) in pairs.items()
            if actual != pinned
        )
    assert mismatches == []


def test_every_coordinate_field_changes_the_pinned_source_digest() -> None:
    for spec in current_source_partition():
        digest = catalog._spec_source_coordinate_digest(spec)
        representation_drift = replace(
            spec, representation_role=spec.representation_role + " drift"
        )
        necessity_drift = replace(
            spec, necessity_reason=spec.necessity_reason + " drift"
        )
        specialization_drift = replace(
            spec, specializations=(*spec.specializations, "TRANSACTION")
        )
        assert catalog._spec_source_coordinate_digest(representation_drift) != digest
        assert catalog._spec_source_coordinate_digest(necessity_drift) != digest
        assert catalog._spec_source_coordinate_digest(specialization_drift) != digest


def test_unexpected_drift_in_any_other_row_fails_closed() -> None:
    selected = list(current_source_partition())
    audits = {row.object_id: row for row in RUNTIME_ORIGINAL_KIND_AUDITS}
    # Rows whose pins already disagree with the central source are named by the
    # validator first; the oracle accepts only those rows or the mutated row.
    pre_drifted = {
        spec.object_id
        for spec in selected
        if catalog._spec_source_coordinate_digest(spec)
        != audits[spec.object_id].expected_source_coordinate_digest
    }
    target = next(spec for spec in selected if spec.object_id not in pre_drifted)
    index = selected.index(target)
    selected[index] = replace(
        target, necessity_reason=target.necessity_reason + " unexpected drift"
    )
    with pytest.raises(ValueError) as error:
        validate_source_partition(selected)
    prefix = "RUNTIME_ORIGINAL_KIND_SOURCE_COORDINATE_DRIFT:"
    assert str(error.value).startswith(prefix)
    named = str(error.value)[len(prefix) :]
    assert named in pre_drifted | {target.object_id}
    if not pre_drifted:
        assert named == target.object_id


def test_only_source_declared_roles_apply_and_only_reviewed_exclusions_exist() -> None:
    source = _source_map()
    applies = []
    unresolved = []
    exclusions = []
    for row in RUNTIME_ORIGINAL_KIND_AUDITS:
        spec = source[row.object_id]
        expected = set()
        if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS:
            expected.add(spec.primary_kind)
        expected.update(
            kind
            for kind in spec.specializations
            if kind in ORIGINAL_NON_OBJECT_KINDS
        )
        expected.update(
            decision.kind
            for decision in spec.root_role_decisions
            if decision.kind in ORIGINAL_NON_OBJECT_KINDS
            and decision.status == APPLIES
        )
        expected.update(
            kind
            for owner, kind in catalog._BEHAVIORAL_BY_CELL
            if owner == row.object_id
        )
        actual = {
            question.kind
            for question in row.questions
            if question.status == APPLIES
        }
        assert actual == expected
        applies.extend(
            (row.object_id, question.kind)
            for question in row.questions
            if question.status == APPLIES
        )
        unresolved.extend(
            (row.object_id, question.kind)
            for question in row.questions
            if question.status == UNRESOLVED
        )
        exclusions.extend(
            (row.object_id, question.kind)
            for question in row.questions
            if question.status == DOES_NOT_APPLY
        )
    assert len(applies) == 176
    assert len(exclusions) == 2
    assert set(exclusions) == EXPECTED_EXCLUSIONS
    assert len(unresolved) == 2872
    assert len(applies) + len(exclusions) + len(unresolved) == 122 * 25


def test_partial_profile_is_digest_bound_and_does_not_claim_unknown_rows() -> None:
    assert validate_profile(RUNTIME_PARTIAL_PROFILE) is RUNTIME_PARTIAL_PROFILE
    assert profile_digest(RUNTIME_PARTIAL_PROFILE) == (
        RUNTIME_PARTIAL_PROFILE.canonical_digest
    )
    # 74 before re-audit; invocation-ledger and namespace-rule-engine lost their
    # only decisions (retired cells with no declared primary or specialization).
    # 73 after the HYPER primary of the package worker dependency relation.
    # 74 after the ASSET Tier-0 VERIFIER record gains its declared VERIFIER APPLIES.
    # 76 after the ledger and resource-measurement obligation owners gain their
    # source-bound VERIFIER decisions; the worker exchange was already present.
    assert len(RUNTIME_PARTIAL_PROFILE.assignments) == 76
    source = _source_map()
    for assignment in RUNTIME_PARTIAL_PROFILE.assignments:
        spec = source[assignment.object_id]
        assert assignment.expected_primary == spec.primary_kind
        assert assignment.expected_owned_paths == spec.owned_paths
        assert assignment.decisions
        assert all(
            decision.status in {APPLIES, DOES_NOT_APPLY}
            for decision in assignment.decisions
        )
    profile_ids = {
        assignment.object_id for assignment in RUNTIME_PARTIAL_PROFILE.assignments
    }
    assert all(
        (row.object_id in profile_ids)
        == any(
            question.status in {APPLIES, DOES_NOT_APPLY}
            for question in row.questions
        )
        for row in RUNTIME_ORIGINAL_KIND_AUDITS
    )
    profile_exclusions = {
        (assignment.object_id, decision.kind)
        for assignment in RUNTIME_PARTIAL_PROFILE.assignments
        for decision in assignment.decisions
        if decision.status == DOES_NOT_APPLY
    }
    assert profile_exclusions == EXPECTED_EXCLUSIONS


def test_source_denominator_and_object_substitution_fail_closed() -> None:
    selected = current_source_partition()
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_DENOMINATOR_DRIFT"
    ):
        validate_source_partition(selected[:-1])
    substituted = list(selected)
    substituted[0] = replace(
        substituted[0], object_id=substituted[1].object_id
    )
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_PARTITION_INVALID"
    ):
        validate_source_partition(substituted)


def test_path_role_reason_and_primary_source_drift_fail_closed() -> None:
    selected = list(current_source_partition())
    target = selected[0]
    index = selected.index(target)

    selected[index] = replace(
        target, owned_paths=("src/verifier/runtime/not-the-audited-path.py",)
    )
    with pytest.raises(ValueError, match="SOURCE_PATH_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, representation_role="substituted role")
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, necessity_reason="substituted reason")
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, primary_kind="OBJECT")
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT"):
        validate_source_partition(selected)


def test_conflicting_accumulated_role_decisions_hard_fail() -> None:
    selected = list(current_source_partition())
    target = selected[0]
    selected[0] = replace(
        target,
        root_role_decisions=(
            RootRoleDecision("ACTOR", APPLIES, "explicit applicability"),
            RootRoleDecision(
                "ACTOR", DOES_NOT_APPLY, "explicit incompatible exclusion"
            ),
        ),
    )
    with pytest.raises(ValueError, match="SOURCE_ROLE_CONFLICT"):
        validate_source_partition(selected)


def test_object_label_cannot_bypass_the_25_question_matrix() -> None:
    document = review_document()
    assert len(document) == 122
    assert all(
        tuple(entry["questions"]) == ORIGINAL_NON_OBJECT_KINDS
        for entry in document.values()
    )

    selected = list(current_source_partition())
    target = next(spec for spec in selected if spec.primary_kind == "VERIFIER")
    index = selected.index(target)
    selected[index] = replace(target, primary_kind="OBJECT")
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT"):
        validate_source_partition(selected)


def test_review_document_exposes_unknowns_reasons_and_profile_binding() -> None:
    document = review_document()
    profile_ids = {
        assignment.object_id for assignment in RUNTIME_PARTIAL_PROFILE.assignments
    }
    assert sum(
        question["status"] == UNRESOLVED
        for entry in document.values()
        for question in entry["questions"].values()
    ) == 2872
    for object_id, entry in document.items():
        assert entry["expected_source_coordinate_digest"].startswith("sha256:")
        assert entry["expected_owned_path_set_digest"].startswith("sha256:")
        assert entry["scope_reason"].strip()
        assert all(
            question["reason"].strip()
            for question in entry["questions"].values()
        )
        assert (entry["partial_profile_digest"] is not None) == (
            object_id in profile_ids
        )


def test_every_exclusion_is_a_verbatim_boundary_sentence_of_its_own_row() -> None:
    source = _source_map()
    for object_id, kind in EXPECTED_EXCLUSIONS:
        question = _cell(object_id, kind)
        assert question.status == DOES_NOT_APPLY
        assert question.source_quote
        assert question.source_quote in source[object_id].consequence_boundary
        assert question.reason.endswith(
            catalog._EXCLUSION_REVIEWS[(object_id, kind)]
        )
        other_hits = [
            spec.object_id
            for spec in source.values()
            if spec.object_id != object_id
            and question.source_quote in spec.consequence_boundary
        ]
        assert other_hits == []
    assert set(catalog._EXCLUSION_REVIEWS) == EXPECTED_EXCLUSIONS
    assert all(
        question.source_quote == ""
        for row in RUNTIME_ORIGINAL_KIND_AUDITS
        for question in row.questions
        if question.status != DOES_NOT_APPLY
    )


def test_exclusion_quote_drift_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    drifted = []
    for row in RUNTIME_ORIGINAL_KIND_AUDITS:
        if row.object_id == "vstd-finite-record-issuance":
            questions = tuple(
                replace(question, source_quote="no actor attestation")
                if question.kind == "HUMAN"
                else question
                for question in row.questions
            )
            row = replace(row, questions=questions)
        drifted.append(row)
    monkeypatch.setattr(
        catalog, "RUNTIME_ORIGINAL_KIND_AUDITS", tuple(drifted)
    )
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_BOUNDARY_QUOTE_DRIFT"
    ):
        validate_source_partition(current_source_partition())


def test_exclusion_without_counterexample_review_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviews = dict(catalog._EXCLUSION_REVIEWS)
    reviews.pop(("vstd-finite-record-issuance", "HUMAN"))
    monkeypatch.setattr(catalog, "_EXCLUSION_REVIEWS", reviews)
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EXCLUSION_REVIEW_DRIFT"
    ):
        validate_source_partition(current_source_partition())


def test_epistemic_limits_and_output_scope_are_never_exclusions() -> None:
    # Each sentence limits what an output or statement establishes; none denies
    # that the row itself is, or performs, the kind's identity or operation.
    for object_id, kind in (
        ("vstd-hardware-receipt-assessor", "ACTOR"),
        ("vstd-challenge-record-ledger", "OWNER"),
        ("vstd-accelerator-discovery-command", "OWNER"),
        ("vstd-governance-policy", "HUMAN"),
        ("vstd-consent-policy", "HUMAN"),
        ("vstd-polish-public-authority", "HUMAN"),
        ("vstd-package-owner-decision", "HUMAN"),
        ("vstd-hardware-cli-protocol", "IDENTITY"),
        ("vstd-invocation-ledger", "IDENTITY"),
        ("vstd-invocation-ledger", "ACTOR"),
        ("vstd-application-authority-protocol", "HUMAN"),
    ):
        assert _cell(object_id, kind).status != DOES_NOT_APPLY, (object_id, kind)


def test_high_risk_kinds_are_never_excluded_by_runtime_rows() -> None:
    for row in RUNTIME_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.kind in HIGH_RISK_KINDS:
                assert question.status != DOES_NOT_APPLY, (
                    row.object_id,
                    question.kind,
                )


def test_counterexamples_keep_device_and_verifier_identities_unresolved() -> None:
    # A software device model whose counters or capacity still match HARDWARE's
    # criteria is a counterexample to "not a physical device" as an exclusion.
    assert _cell("vstd-software-diode-effect", "HARDWARE").status == UNRESOLVED
    assert _cell("vstd-firmware-emulator-accounting", "HARDWARE").status == (
        UNRESOLVED
    )
    # The observer's owned projections include validators and checks, so
    # "does not execute a checker" is not an exclusion of VERIFIER identity.
    assert _cell("vstd-source-provenance-observer", "VERIFIER").status == (
        UNRESOLVED
    )


def test_unresolved_reasons_name_the_exact_source_annotation_needed() -> None:
    for row in RUNTIME_ORIGINAL_KIND_AUDITS:
        for question in row.questions:
            if question.status != UNRESOLVED:
                continue
            assert f"RootRoleDecision('{question.kind}'" in question.reason
            assert "Exact blocker:" in question.reason


def _evidence(object_id: str, kind: str):
    return next(
        record
        for record in catalog._BEHAVIORAL_EVIDENCE
        if record.object_id == object_id and record.kind == kind
    )


def _copy_owned(tmp_path: Path, rel: str) -> None:
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((REPO_ROOT / rel).read_bytes())


def test_behavioral_evidence_binds_current_source_bytes() -> None:
    records = validate_behavioral_evidence(REPO_ROOT)
    assert len(records) == 121
    assert {(record.object_id, record.kind) for record in records} == set(
        catalog._BEHAVIORAL_BY_CELL
    )
    source = _source_map()
    for record in records:
        question = _cell(record.object_id, record.kind)
        assert question.status == APPLIES
        assert record.path in source[record.object_id].owned_paths
        assert record.path in question.reason
        assert record.sha256 in question.reason
        assert record.anchor in question.reason
        assert question.source_quote == ""


def test_behavioral_profile_normalizes_scope_and_exact_positive_witnesses() -> None:
    assignments = {
        assignment.object_id: assignment
        for assignment in RUNTIME_PARTIAL_PROFILE.assignments
    }
    for record in catalog._BEHAVIORAL_EVIDENCE:
        assignment = assignments[record.object_id]
        decision = next(
            item for item in assignment.decisions if item.kind == record.kind
        )
        assert assignment.scope_reason == (
            "Full review scope is bound by source coordinate "
            + next(
                row.expected_source_coordinate_digest
                for row in RUNTIME_ORIGINAL_KIND_AUDITS
                if row.object_id == record.object_id
            )
            + "."
        )
        assert decision.reason == record.mechanism
        assert decision.evidence_paths == (record.path,)


def test_behavioral_evidence_is_disjoint_from_declared_roles() -> None:
    source = _source_map()
    for record in catalog._BEHAVIORAL_EVIDENCE:
        spec = source[record.object_id]
        declared = (
            {spec.primary_kind}
            | set(spec.specializations)
            | {decision.kind for decision in spec.root_role_decisions}
        )
        assert record.kind not in declared, (record.object_id, record.kind)


def test_behavioral_evidence_accepts_unchanged_bytes_and_rejects_stale_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, record.path)
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (record,))
    assert validate_behavioral_evidence(tmp_path) == (record,)

    (tmp_path / record.path).write_bytes(
        (REPO_ROOT / record.path).read_bytes() + b"\n# edited after audit\n"
    )
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_STALE:vstd-amd-live-sensor:HARDWARE"
    ):
        validate_behavioral_evidence(tmp_path)


def test_behavioral_anchor_drift_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, record.path)
    drifted = replace(record, anchor="ROCm host discovery was removed")
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (drifted,))
    with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_ANCHOR_DRIFT"):
        validate_behavioral_evidence(tmp_path)


def test_wrong_source_and_object_substitution_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    cases = {
        "path of another row": replace(
            record, path="src/verifier/hardware/adapters/nvidia.py"
        ),
        "object of another row": replace(record, object_id="vstd-nvidia-live-sensor"),
        "cell not APPLIES": replace(record, kind="DATA"),
    }
    for substituted in cases.values():
        monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (substituted,))
        with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_"):
            validate_behavioral_evidence(REPO_ROOT)


def test_behavioral_validation_is_atomic_across_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = _evidence("vstd-amd-live-sensor", "HARDWARE")
    stale = _evidence("vstd-nvidia-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, good.path)
    _copy_owned(tmp_path, stale.path)
    (tmp_path / stale.path).write_bytes(b"not the audited bytes")
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (good, stale))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_STALE:vstd-nvidia-live-sensor"
    ):
        validate_behavioral_evidence(tmp_path)


def test_duplicate_behavioral_cell_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, record.path)
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (record, record))
    with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_DUPLICATE"):
        validate_behavioral_evidence(tmp_path)


def test_same_cell_with_a_second_digest_is_a_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, record.path)
    second = replace(record, sha256="sha256:" + "0" * 64)
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (record, second))
    with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_DUPLICATE"):
        validate_behavioral_evidence(tmp_path)


@pytest.mark.parametrize("anchor", ["", "   "])
def test_blank_anchor_cannot_bypass_the_containment_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, anchor: str
) -> None:
    # "" is a substring of every text, so the containment check alone accepted it.
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, record.path)
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (replace(record, anchor=anchor),))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_BLANK:vstd-amd-live-sensor:HARDWARE"
    ):
        validate_behavioral_evidence(tmp_path)


@pytest.mark.parametrize(
    "anchor",
    [
        # Quote from the pre-change AMD source, before the bounded file-backed capture.
        '[executable, "static", "--json"], capture_output=True',
        # Fabricated calibration or measurement claims must never pass as source quotes.
        "calibrated physical measurement",
        "calibration_offset",
    ],
)
def test_stale_or_fabricated_anchor_quotes_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, anchor: str
) -> None:
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    _copy_owned(tmp_path, record.path)
    assert anchor not in (REPO_ROOT / record.path).read_text(encoding="utf-8")
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (replace(record, anchor=anchor),))
    with pytest.raises(
        ValueError,
        match="RUNTIME_ORIGINAL_KIND_EVIDENCE_ANCHOR_DRIFT:vstd-amd-live-sensor:HARDWARE",
    ):
        validate_behavioral_evidence(tmp_path)


@pytest.mark.parametrize("kind", ["SENSOR", "MEASUREMENT"])
def test_sensor_or_measurement_is_not_an_original_kind_cell(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    # The 25-kind matrix has no SENSOR or MEASUREMENT cell; the row's live-sensor
    # name must not promote a device-observation mechanism to a measurement kind.
    assert kind not in ORIGINAL_NON_OBJECT_KINDS
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (replace(record, kind=kind),))
    with pytest.raises(
        ValueError,
        match=f"RUNTIME_ORIGINAL_KIND_EVIDENCE_CELL_INVALID:vstd-amd-live-sensor:{kind}",
    ):
        validate_behavioral_evidence(REPO_ROOT)


def test_timeout_weakening_edit_keeps_anchor_but_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The anchor survives this edit, so only the byte binding can reject it.
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    data = (REPO_ROOT / record.path).read_bytes()
    weakened = data.replace(
        b"_DISCOVERY_TIMEOUT_SECONDS = 30.0", b"_DISCOVERY_TIMEOUT_SECONDS = 3000.0"
    )
    assert weakened != data
    assert record.anchor.encode("utf-8") in weakened
    target = tmp_path / record.path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(weakened)
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (record,))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_STALE:vstd-amd-live-sensor:HARDWARE"
    ):
        validate_behavioral_evidence(tmp_path)


def test_amd_mechanism_disclaims_calibration_and_physical_truth() -> None:
    # Vendor subprocess output is observed state; the row must not claim it is
    # calibrated or a physical measurement.
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    assert record.kind == "HARDWARE"
    assert "not calibrated or physical measurement" in record.mechanism


def test_nvidia_mechanism_disclaims_calibration_and_physical_truth() -> None:
    record = _evidence("vstd-nvidia-live-sensor", "HARDWARE")
    assert record.kind == "HARDWARE"
    assert "not calibrated or physical measurement" in record.mechanism


def test_retired_cell_cannot_be_reintroduced_as_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = "src/verifier/runtime/namespace_classification.py"
    _copy_owned(tmp_path, path)
    reintroduced = catalog.BehavioralEvidence(
        "vstd-namespace-rule-engine",
        "VERIFIER",
        path,
        "def assess_classification",
        "sha256:" + sha256((REPO_ROOT / path).read_bytes()).hexdigest(),
        "re-added without owner review",
    )
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", (reintroduced,))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_CELL_NOT_APPLIES:vstd-namespace-rule-engine"
    ):
        validate_behavioral_evidence(tmp_path)


def test_retired_cells_are_unresolved_with_no_evidence_or_exclusion() -> None:
    for object_id, kind in RETIRED_CELLS:
        question = _cell(object_id, kind)
        assert question.status == UNRESOLVED, (object_id, kind)
        assert question.source_quote == ""
        assert (object_id, kind) not in catalog._BEHAVIORAL_BY_CELL
        assert "Exact blocker:" in question.reason
    assert not (RETIRED_CELLS & EXPECTED_EXCLUSIONS)


def test_partial_profile_decisions_equal_the_reviewed_non_unresolved_cells() -> None:
    profile_decisions = {
        (assignment.object_id, decision.kind): decision.status
        for assignment in RUNTIME_PARTIAL_PROFILE.assignments
        for decision in assignment.decisions
    }
    reviewed = {
        (row.object_id, question.kind): question.status
        for row in RUNTIME_ORIGINAL_KIND_AUDITS
        for question in row.questions
        if question.status != UNRESOLVED
    }
    assert profile_decisions == reviewed


def _drifted_first_path() -> list:
    selected = list(current_source_partition())
    selected[0] = replace(
        selected[0], owned_paths=("src/verifier/runtime/not-the-audited-path.py",)
    )
    return selected


def test_default_review_path_fails_closed_on_source_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drifted = tuple(_drifted_first_path())
    monkeypatch.setattr(catalog, "current_source_partition", lambda: drifted)
    with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_"):
        review_document()


def test_composed_entry_fails_closed_on_source_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _copy_owned(tmp_path, _evidence("vstd-amd-live-sensor", "HARDWARE").path)
    drifted = tuple(_drifted_first_path())
    monkeypatch.setattr(catalog, "current_source_partition", lambda: drifted)
    with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_"):
        validate_runtime_review(tmp_path)


def test_composed_entry_rejects_evidence_set_drift_and_stale_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Source binding is isolated here; its drift is covered by the tests above.
    monkeypatch.setattr(catalog, "validate_source_partition", lambda specs: tuple(specs))
    original = tuple(catalog._BEHAVIORAL_EVIDENCE)
    for record in original:
        _copy_owned(tmp_path, record.path)
    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", original[:-1])
    with pytest.raises(ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_SET_DRIFT"):
        validate_runtime_review(tmp_path)

    monkeypatch.setattr(catalog, "_BEHAVIORAL_EVIDENCE", original)
    record = _evidence("vstd-amd-live-sensor", "HARDWARE")
    (tmp_path / record.path).write_bytes(
        (REPO_ROOT / record.path).read_bytes() + b"\n# edited after audit\n"
    )
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_EVIDENCE_STALE:vstd-amd-live-sensor:HARDWARE"
    ):
        validate_runtime_review(tmp_path)


def test_composed_entry_binds_current_repository_evidence() -> None:
    # Gated on current source coordinates; fails until the drifted ownership
    # source is re-audited, which is intentional fail-closed behavior.
    document = validate_runtime_review(REPO_ROOT)
    assert len(document) == 122


RELATION_ID = "vstd-package-worker-dependency-relation"
RELATION_PATH = "src/verifier/runtime/package_protocol_dependency_relation.py"


def _relation_row():
    return next(
        row for row in RUNTIME_ORIGINAL_KIND_AUDITS if row.object_id == RELATION_ID
    )


def test_relation_row_is_source_bound_hyper_applies_without_any_dne() -> None:
    row = _relation_row()
    assert row.group == "runtime-admission"
    assert row.expected_primary == relation.PRIMARY_KIND == "HYPER"
    assert row.expected_owned_paths == relation.OWNED_PATHS == (RELATION_PATH,)
    assert row.expected_operands == relation.OPERANDS
    assert row.expected_representation_role == relation.REPRESENTATION_ROLE
    assert row.expected_necessity_reason == relation.NECESSITY_REASON
    assert row.expected_consequence_boundary == relation.CONSEQUENCE_BOUNDARY
    statuses = {question.kind: question.status for question in row.questions}
    assert tuple(statuses) == ORIGINAL_NON_OBJECT_KINDS
    assert {kind for kind, status in statuses.items() if status == APPLIES} == {
        "HYPER"
    }
    assert DOES_NOT_APPLY not in statuses.values()
    hyper = _cell(RELATION_ID, "HYPER")
    assert "explicitly establishes HYPER as this row's original primary" in hyper.reason
    assert "not mechanism truth or higher-tier conformance" in hyper.reason
    assert (RELATION_ID, "HYPER") not in catalog._BEHAVIORAL_BY_CELL
    for question in row.questions:
        if question.status == UNRESOLVED:
            assert "Exact blocker:" in question.reason
            assert f"RootRoleDecision('{question.kind}'" in question.reason


def test_relation_missing_extra_and_duplicate_specs_fail_atomically() -> None:
    selected = list(current_source_partition())
    relation_spec = next(spec for spec in selected if spec.object_id == RELATION_ID)
    removed = [spec for spec in selected if spec.object_id != RELATION_ID]
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_DENOMINATOR_DRIFT"
    ):
        validate_source_partition(removed)
    extra = replace(
        relation_spec,
        object_id="vstd-package-worker-dependency-relation-copy",
        owned_paths=("src/verifier/runtime/package_protocol_dependency_relation_copy.py",),
    )
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_DENOMINATOR_DRIFT"
    ):
        validate_source_partition([*selected, extra])
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_PARTITION_INVALID"
    ):
        validate_source_partition([*selected, relation_spec])


def test_relation_endpoint_substitution_fails_closed() -> None:
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == RELATION_ID
    )
    relation_spec = selected[index]
    substitutions = (
        # dependent endpoint substituted by another real object
        (
            ("dependents", ("vstd-invocation-ledger", "vstd-hardware")),
            ("protocol_exchange", ("vstd-package-worker-exchange",)),
        ),
        # protocol exchange substituted by a different worker object
        (
            ("dependents", ("vstd-invocation-ledger", "vstd-manifest-write")),
            ("protocol_exchange", ("vstd-package-worker-recorder",)),
        ),
        # one of the three literal edges dropped
        (
            ("dependents", ("vstd-invocation-ledger",)),
            ("protocol_exchange", ("vstd-package-worker-exchange",)),
        ),
        # operand name changed
        (
            ("dependencies", ("vstd-invocation-ledger", "vstd-manifest-write")),
            ("protocol_exchange", ("vstd-package-worker-exchange",)),
        ),
        # all operands removed
        (),
    )
    for operands in substitutions:
        mutated = list(selected)
        mutated[index] = replace(relation_spec, operands=operands)
        with pytest.raises(
            ValueError,
            match="RUNTIME_ORIGINAL_KIND_SOURCE_OPERAND_DRIFT:" + RELATION_ID,
        ):
            validate_source_partition(mutated)


def test_operand_drift_is_bound_for_every_operand_bearing_row() -> None:
    # The hardware receipt publication row also carries operands; the pin is
    # generic, so a substituted endpoint there fails closed as well.
    selected = list(current_source_partition())
    index = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id == "vstd-hardware-receipt-publication"
    )
    mutated = list(selected)
    mutated[index] = replace(
        selected[index],
        operands=(("hardware", ("vstd-hardware",)), ("subject", ("vstd-accelerator",))),
    )
    with pytest.raises(
        ValueError,
        match="RUNTIME_ORIGINAL_KIND_SOURCE_OPERAND_DRIFT:vstd-hardware-receipt-publication",
    ):
        validate_source_partition(mutated)


def test_operands_are_bound_into_the_source_coordinate_digest() -> None:
    spec = _source_map()[RELATION_ID]
    digest = catalog._spec_source_coordinate_digest(spec)
    assert catalog._spec_source_coordinate_digest(replace(spec, operands=())) != digest
    assert catalog._spec_source_coordinate_digest(
        replace(spec, operands=(("dependents", ("vstd-invocation-ledger",)),))
    ) != digest


def test_literal_relation_row_text_equals_the_relation_module_constants() -> None:
    row = _relation_row()
    assert row.expected_source_coordinate_digest == catalog._spec_source_coordinate_digest(
        _source_map()[RELATION_ID]
    )
    assert row.scope_reason == (
        relation.REPRESENTATION_ROLE
        + " Necessity: "
        + relation.NECESSITY_REASON
        + " Consequence boundary: "
        + relation.CONSEQUENCE_BOUNDARY
    )


def test_relation_module_bytes_are_pinned_and_stale_bytes_fail_closed(
    tmp_path: Path,
) -> None:
    _copy_owned(tmp_path, RELATION_PATH)
    assert catalog.validate_declared_source_bytes(tmp_path) == (
        catalog._DECLARED_SOURCE_BINDINGS
    )
    (tmp_path / RELATION_PATH).write_bytes(
        (REPO_ROOT / RELATION_PATH).read_bytes() + b"\n# edited after audit\n"
    )
    with pytest.raises(
        ValueError,
        match="RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_STALE:" + RELATION_ID,
    ):
        catalog.validate_declared_source_bytes(tmp_path)


def test_relation_module_bytes_unavailable_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError,
        match="RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_UNAVAILABLE:" + RELATION_ID,
    ):
        catalog.validate_declared_source_bytes(tmp_path / "absent")


def test_declared_source_binding_rejects_wrong_owner_and_duplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _copy_owned(tmp_path, RELATION_PATH)
    pinned = catalog._DECLARED_SOURCE_BINDINGS[0]
    wrong_owner = replace(pinned, path="src/verifier/runtime/package_owner_decision.py")
    monkeypatch.setattr(catalog, "_DECLARED_SOURCE_BINDINGS", (wrong_owner,))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_WRONG_OWNER"
    ):
        catalog.validate_declared_source_bytes(tmp_path)
    monkeypatch.setattr(catalog, "_DECLARED_SOURCE_BINDINGS", (pinned, pinned))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_DUPLICATE"
    ):
        catalog.validate_declared_source_bytes(tmp_path)


def test_shared_owned_path_across_rows_fails_closed() -> None:
    selected = list(current_source_partition())
    other = next(
        position
        for position, spec in enumerate(selected)
        if spec.object_id != RELATION_ID
    )
    selected[other] = replace(selected[other], owned_paths=(RELATION_PATH,))
    with pytest.raises(
        ValueError, match="RUNTIME_ORIGINAL_KIND_SOURCE_OWNERSHIP_OVERLAP"
    ):
        validate_source_partition(selected)


def test_composed_entry_gates_the_relation_module_bytes(tmp_path: Path) -> None:
    for record in catalog._BEHAVIORAL_EVIDENCE:
        _copy_owned(tmp_path, record.path)
    _copy_owned(tmp_path, RELATION_PATH)
    assert len(validate_runtime_review(tmp_path)) == 122
    (tmp_path / RELATION_PATH).write_bytes(
        (REPO_ROOT / RELATION_PATH).read_bytes() + b"\n# edited after audit\n"
    )
    with pytest.raises(
        ValueError,
        match="RUNTIME_ORIGINAL_KIND_DECLARED_SOURCE_STALE:" + RELATION_ID,
    ):
        validate_runtime_review(tmp_path)


# Semantic acceptance for the provenance-policy repin.  The prior pin was the HEAD
# bytes 51e2cc...; the current bytes add evidence retention, a recheck and stricter
# refusal of malformed encodings.  Verifier-reachable verdicts were compared with the
# HEAD module on 3000 seeded graphs with zero mismatches; these predicates bind that
# acceptance to the exact current bytes.
PROVENANCE_POLICY_SOURCE = REPO_ROOT / "src" / "verifier" / "data" / "policy.py"
PROVENANCE_POLICY_SHA256 = "49b7249262b44f1f8375e4ca15e40b138a9b1bf85eb8d676edf6816645e4e8a3"
_POLICY_TARGET = "artifact:target"
_POLICY_APPROVED = ("CC-BY-4.0", "CC-BY-NC-4.0", "MIT", "Apache-2.0")
_POLICY_METHODS = (
    "verify_no_revoked_ancestors",
    "verify_all_ancestors_valid",
    "verify_approved_licenses",
)
_POLICY_RESULT_KEYS = {
    "policy_id",
    "policy_name",
    "target_artifact_id",
    "passed",
    "verdict",
    "clauses",
    "variable_map",
    "explanation",
}


def _policy_graph(
    artifacts: dict[str, tuple[ArtifactStatus, str | None]],
    edges: list[tuple[str, str]],
) -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    for index, (artifact_id, (status, license_spdx)) in enumerate(artifacts.items()):
        rights_id = None
        if license_spdx is not None:
            rights_id = f"rights:{index}"
            graph.add_rights(RightsSpec(rights_id, license_spdx))
        graph.add_artifact(
            ArtifactNode(
                artifact_id=artifact_id,
                label=artifact_id,
                artifact_type=ArtifactType.RAW_SOURCE_FILE,
                content_digest=f"{index:064x}",
                status=status,
                rights_id=rights_id,
            )
        )
    for number, (source, target) in enumerate(edges):
        graph.add_transformation(
            TransformationHyperedge(
                transformation_id=f"transform:t{number}",
                label=f"t{number}",
                transformation_type=TransformationType.EVALUATION,
                inputs=(HyperedgePort(source, "INPUT"),),
                outputs=(HyperedgePort(target, "OUTPUT"),),
                software_provenance={},
                parameters={},
                execution_environment={},
            )
        )
    return graph


def _random_policy_graph(rng: random.Random) -> tuple[ProvenanceHypergraph, str]:
    count = rng.randint(1, 6)
    ids = [f"artifact:a{index}" for index in range(count)]
    licenses = ("MIT", "CC-BY-4.0", "GPL-3.0", "PROPRIETARY", "Apache-2.0", None)
    artifacts = {
        artifact_id: (rng.choice(list(ArtifactStatus)), rng.choice(licenses))
        for artifact_id in ids
    }
    edges: list[tuple[str, str]] = []
    for _ in range(rng.randint(0, count) if count > 1 else 0):
        source, target = rng.sample(ids, 2)
        edges.append((source, target))
    return _policy_graph(artifacts, edges), rng.choice(ids + ["artifact:absent"])


def _policy_oracle(
    graph: ProvenanceHypergraph, target: str, method: str
) -> tuple[bool, bool | None]:
    """Direct predicate over the graph, independent of the CNF path: (indeterminate, passed)."""
    if target not in graph.artifacts:
        return True, None
    ancestors = graph.ancestors([target])
    if method == "verify_no_revoked_ancestors":
        return False, not any(
            graph.artifacts[a].status == ArtifactStatus.REVOKED for a in ancestors
        )
    if method == "verify_all_ancestors_valid":
        return False, all(
            a in graph.artifacts and graph.artifacts[a].status == ArtifactStatus.VALID
            for a in ancestors
        )
    roots = [a for a in ancestors if a in graph.root_sources()]
    if not roots:
        return True, None
    for root in roots:
        node = graph.artifacts[root]
        rights = graph.rights.get(node.rights_id) if node.rights_id else None
        if not rights or rights.license_spdx not in _POLICY_APPROVED:
            return False, False
    return False, True


def test_provenance_policy_repin_binds_exact_current_bytes() -> None:
    record = _evidence("vstd-dataset-provenance-policy", "VERIFIER")
    raw = PROVENANCE_POLICY_SOURCE.read_bytes()
    assert sha256(raw).hexdigest() == PROVENANCE_POLICY_SHA256
    assert record.sha256 == f"sha256:{PROVENANCE_POLICY_SHA256}"
    assert record.anchor in raw.decode("utf-8")


def test_provenance_policy_verdicts_equal_direct_predicates_and_retain_evidence() -> None:
    rng = random.Random(20261016)
    seen: set[tuple[str, str]] = set()
    for _ in range(120):
        graph, target = _random_policy_graph(rng)
        for method in _POLICY_METHODS:
            indeterminate, expected = _policy_oracle(graph, target, method)
            try:
                result = getattr(provenance_policy.ProvenancePolicyVerifier, method)(
                    graph, target
                )
            except provenance_policy.PolicyEncodingError:
                assert graph.validate_structure(), (method, target)
                continue
            assert set(result.to_dict()) == _POLICY_RESULT_KEYS
            if indeterminate:
                assert result.verdict is VerificationVerdict.INDETERMINATE, (method, target)
                assert result.certificate is None
                assert result.decision_evidence() is None
                seen.add((method, "INDETERMINATE"))
                continue
            assert result.passed is expected, (method, target, result.explanation)
            assert result.verdict is (
                VerificationVerdict.VERIFIED if expected else VerificationVerdict.FALSIFIED
            )
            assert result.certificate is not None, (method, "certificate dropped")
            assert result.certificate.header.verdict is (Verdict.PASS if expected else Verdict.FAIL)
            evidence = result.decision_evidence()
            assert evidence is not None
            assert provenance_policy.check_policy_decision(evidence) is True, method
            seen.add((method, "PASS" if expected else "FAIL"))
    assert len(seen) == 9, sorted(seen)


def test_provenance_policy_boundaries_and_forged_evidence_are_refused() -> None:
    valid = provenance_policy.ProvenancePolicyVerifier.verify_all_ancestors_valid(
        _policy_graph({_POLICY_TARGET: (ArtifactStatus.VALID, None)}, []), _POLICY_TARGET
    )
    revoked = provenance_policy.ProvenancePolicyVerifier.verify_no_revoked_ancestors(
        _policy_graph({_POLICY_TARGET: (ArtifactStatus.REVOKED, None)}, []), _POLICY_TARGET
    )
    licensed = provenance_policy.ProvenancePolicyVerifier.verify_approved_licenses(
        _policy_graph({_POLICY_TARGET: (ArtifactStatus.VALID, "MIT")}, []), _POLICY_TARGET
    )
    assert valid.passed and revoked.passed is False and licensed.passed
    # Explicit NOT_ESTABLISHED boundaries travel with the passing explanations.
    no_revoked_pass = provenance_policy.ProvenancePolicyVerifier.verify_no_revoked_ancestors(
        _policy_graph({_POLICY_TARGET: (ArtifactStatus.VALID, None)}, []), _POLICY_TARGET
    )
    assert "does not establish that every ancestor is VALID" in no_revoked_pass.explanation
    assert "does not establish legal ownership or license validity" in licensed.explanation

    evidence = valid.decision_evidence()
    revoked_evidence = revoked.decision_evidence()
    assert evidence is not None and revoked_evidence is not None
    assert provenance_policy.check_policy_decision(evidence) is True
    forged = [
        replace(evidence, policy_id="POL-NO-REVOKED-ANCESTORS"),
        replace(evidence, passed=False),
        replace(evidence, target_artifact_id="artifact:other"),
        replace(evidence, certificate=revoked_evidence.certificate),
        replace(evidence, clauses=tuple(reversed(evidence.clauses))),
        replace(evidence, member_values=((_POLICY_TARGET, "NOT_VALID"),)),
    ]
    for candidate in forged:
        assert provenance_policy.check_policy_decision(candidate) is False, candidate.policy_id
    with pytest.raises(ValueError):
        provenance_policy.PolicyDecisionEvidence.from_dict({**evidence.to_dict(), "unexpected": True})


def test_provenance_policy_refuses_malformed_encodings_instead_of_silent_acceptance() -> None:
    """Each case is accepted silently or fails with an unrelated error at HEAD."""
    cases = [
        ([[-1, 2], [2], [1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2, "CLEAN_b": 2}, None),
        ([[-1, 2], [2], [1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2}, {"artifact:zzz": "REVOKED"}),
        ([[-1, 2], [2], [1], [3]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2}, None),
        ([[-1, 3], [2], [1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2}, None),
        ([[-1, 2], [2], [1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 0}, None),
        ([[-1, 2], [2], [1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": True}, None),
        ([[1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2}, None),
    ]
    for clauses, variable_map, member_values in cases:
        with pytest.raises(provenance_policy.PolicyEncodingError):
            provenance_policy.ground_policy_cnf(
                clauses, variable_map, _POLICY_TARGET, member_value=member_values
            )
    with pytest.raises(provenance_policy.PolicyEncodingError):
        provenance_policy.certify_policy_cnf(
            satisfiable=True,
            direct_result=False,
            policy_id="POL-CONTROL",
            target_artifact_id=_POLICY_TARGET,
            clauses=[[-1, 2], [2], [1]],
            var_map={"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2},
        )


def test_provenance_policy_binding_commits_the_policy_claim() -> None:
    first = provenance_policy._policy_binding("POL-A", _POLICY_TARGET, [[1]])
    second = provenance_policy._policy_binding("POL-B", _POLICY_TARGET, [[1]])
    assert first.claim == "POL-A" and second.claim == "POL-B"
    assert first != second and first.coordinate != second.coordinate


CONTROLLER_OBJECT_ID = "vstd-controlled-emission-controller"
CONTROLLER_DRIFT = "RUNTIME_ORIGINAL_KIND_SOURCE_COORDINATE_DRIFT:" + CONTROLLER_OBJECT_ID


def _controller_live_spec():
    return _source_map()[CONTROLLER_OBJECT_ID]


def _validate_controller_only(monkeypatch, spec):
    # Other pre-existing drift must not mask this object's own coordinate check,
    # so the audit denominator is narrowed to the controller row for this call.
    row = next(row for row in RUNTIME_ORIGINAL_KIND_AUDITS if row.object_id == CONTROLLER_OBJECT_ID)
    monkeypatch.setattr(catalog, "RUNTIME_ORIGINAL_KIND_AUDITS", (row,))
    return validate_source_partition([spec])


def test_controller_runtime_pin_equals_the_live_declaration_coordinate() -> None:
    spec = _controller_live_spec()
    row = next(row for row in RUNTIME_ORIGINAL_KIND_AUDITS if row.object_id == CONTROLLER_OBJECT_ID)
    assert row.expected_necessity_reason == spec.necessity_reason
    assert "transaction boundaries" in row.expected_necessity_reason
    assert row.expected_specializations == tuple(spec.specializations) == ("POLICY", "TRANSACTION")
    assert row.expected_source_coordinate_digest == catalog._spec_source_coordinate_digest(spec)


def test_controller_live_declaration_verifies_in_isolation(monkeypatch) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)


def test_controller_stale_actuator_declaration_does_not_verify(monkeypatch) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)
    stale = replace(
        spec,
        specializations=("ACTUATOR", "POLICY", "TRANSACTION"),
        necessity_reason=spec.necessity_reason.replace(
            "transaction boundaries", "effect boundaries"
        ),
    )
    with pytest.raises(ValueError) as error:
        _validate_controller_only(monkeypatch, stale)
    assert str(error.value) == CONTROLLER_DRIFT


@pytest.mark.parametrize(
    "specializations",
    [
        ("ACTUATOR", "TRANSACTION"),
        ("POLICY", "ROBOT"),
        ("PROTOCOL", "TRANSACTION"),
    ],
)
def test_controller_count_preserving_obligation_substitution_fails_closed(
    monkeypatch, specializations
) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)
    assert len(specializations) == len(spec.specializations)
    with pytest.raises(ValueError) as error:
        _validate_controller_only(monkeypatch, replace(spec, specializations=specializations))
    assert str(error.value) == CONTROLLER_DRIFT


def test_controller_owned_path_substitution_fails_closed(monkeypatch) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)
    moved = replace(spec, owned_paths=("src/verifier/corrigibility/operator_stop.py",))
    with pytest.raises(ValueError) as error:
        _validate_controller_only(monkeypatch, moved)
    assert str(error.value) == "RUNTIME_ORIGINAL_KIND_SOURCE_PATH_DRIFT:" + CONTROLLER_OBJECT_ID


def test_controller_representation_role_substitution_fails_closed(monkeypatch) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)
    reframed = replace(
        spec, representation_role=spec.representation_role.replace("controller", "gate")
    )
    assert reframed.representation_role != spec.representation_role
    with pytest.raises(ValueError) as error:
        _validate_controller_only(monkeypatch, reframed)
    assert str(error.value) == CONTROLLER_DRIFT


def test_controller_evidence_semantics_substitution_fails_closed(monkeypatch) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)
    inverted = replace(
        spec,
        consequence_boundary=spec.consequence_boundary.replace(
            "is not proof of downstream effect", "is proof of downstream effect"
        ),
    )
    assert inverted.consequence_boundary != spec.consequence_boundary
    with pytest.raises(ValueError) as error:
        _validate_controller_only(monkeypatch, inverted)
    assert str(error.value) == CONTROLLER_DRIFT


def test_controller_refutation_decision_substitution_fails_closed(monkeypatch) -> None:
    spec = _controller_live_spec()
    assert _validate_controller_only(monkeypatch, spec) == (spec,)
    refuted = replace(
        spec,
        root_role_decisions=(
            RootRoleDecision(
                kind="ACTOR",
                status="DOES_NOT_APPLY",
                reason="Synthetic refutation used only to test digest binding.",
            ),
        ),
    )
    with pytest.raises(ValueError) as error:
        _validate_controller_only(monkeypatch, refuted)
    assert str(error.value) == CONTROLLER_DRIFT


# The thirteen reviewed rows.  Each must equal its live declaration in every
# coordinate field, and each adversary must fail on its exact drift token rather
# than on an unrelated check.
REVIEWED_COORDINATE_IDS = (
    CONTROLLER_OBJECT_ID,
    "vstd-core-mechanism-executor",
    "vstd-core-provenance-sensor",
    "vstd-gate-pipeline-controller",
    "vstd-javascript-parser-protocol",
    "vstd-native-gate-suite",
    "vstd-permission-slot-controller",
    "vstd-repository-admission-reconciler",
    "vstd-source-provenance-observer",
    "vstd-systems-parser-protocol",
    "vstd-train-control-session",
    "vstd-verifier-run-constraint-controller",
    "vstd-workflow-parser-protocol",
)
COORDINATE_DRIFT = "RUNTIME_ORIGINAL_KIND_SOURCE_COORDINATE_DRIFT:"
PATH_DRIFT = "RUNTIME_ORIGINAL_KIND_SOURCE_PATH_DRIFT:"
_ABSENT_SPECIALIZATIONS = ("ROBOT", "FINBOT", "ACTUATOR")
COORDINATE_ADVERSARIES = (
    "added_specialization",
    "removed_specialization",
    "count_preserving_specialization",
    "duplicate_specialization",
    "reason_boundary_swap",
    "path_substitution",
    "role_substitution",
    "refutation_inversion",
    "evidence_inversion",
)


def _reviewed_row(object_id: str):
    return next(row for row in RUNTIME_ORIGINAL_KIND_AUDITS if row.object_id == object_id)


def _validate_reviewed_row_only(monkeypatch, object_id: str, spec):
    # Narrow the denominator to one row so other pre-existing drift cannot mask it.
    row = _reviewed_row(object_id)
    monkeypatch.setattr(catalog, "RUNTIME_ORIGINAL_KIND_AUDITS", (row,))
    return validate_source_partition([spec])


def _mutate_coordinate(spec, name: str):
    """Return ``(mutated_spec, expected_token_prefix)``, or None when inapplicable."""

    specs = tuple(spec.specializations)
    absent = next(kind for kind in _ABSENT_SPECIALIZATIONS if kind not in specs)
    if name == "added_specialization":
        return replace(spec, specializations=specs + (absent,)), COORDINATE_DRIFT
    if name == "removed_specialization":
        if not specs:
            return None
        return replace(spec, specializations=specs[1:]), COORDINATE_DRIFT
    if name == "count_preserving_specialization":
        if not specs:
            return None
        return replace(spec, specializations=(absent,) + specs[1:]), COORDINATE_DRIFT
    if name == "duplicate_specialization":
        if len(specs) < 2:
            return None
        return replace(spec, specializations=(specs[0],) * len(specs)), COORDINATE_DRIFT
    if name == "reason_boundary_swap":
        swapped = replace(
            spec,
            necessity_reason=spec.consequence_boundary,
            consequence_boundary=spec.necessity_reason,
        )
        return swapped, COORDINATE_DRIFT
    if name == "path_substitution":
        moved = tuple(path + ".substitute" for path in spec.owned_paths)
        return replace(spec, owned_paths=moved), PATH_DRIFT
    if name == "role_substitution":
        reframed = "Substituted role: " + spec.representation_role
        return replace(spec, representation_role=reframed), COORDINATE_DRIFT
    if name == "refutation_inversion":
        refuted = RootRoleDecision(
            kind="ACTOR",
            status="DOES_NOT_APPLY",
            reason="Synthetic refutation used only to test digest binding.",
        )
        return replace(spec, root_role_decisions=(refuted,)), COORDINATE_DRIFT
    if name == "evidence_inversion":
        applied = RootRoleDecision(
            kind="ACTOR",
            status="APPLIES",
            reason="Synthetic applicability used only to test digest binding.",
        )
        return replace(spec, root_role_decisions=(applied,)), COORDINATE_DRIFT
    raise AssertionError(name)


COORDINATE_ADVERSARY_CASES = [
    pytest.param(object_id, name, id=object_id + "-" + name)
    for object_id in REVIEWED_COORDINATE_IDS
    for name in COORDINATE_ADVERSARIES
    if _mutate_coordinate(_source_map()[object_id], name) is not None
]


@pytest.mark.parametrize("object_id", REVIEWED_COORDINATE_IDS)
def test_reviewed_row_equals_live_declaration_in_every_coordinate_field(
    monkeypatch, object_id
) -> None:
    spec = _source_map()[object_id]
    row = _reviewed_row(object_id)
    assert row.expected_primary == spec.primary_kind
    assert row.expected_owned_paths == tuple(spec.owned_paths)
    assert row.expected_representation_role == spec.representation_role
    assert row.expected_necessity_reason == spec.necessity_reason
    assert row.expected_consequence_boundary == spec.consequence_boundary
    assert row.expected_specializations == tuple(spec.specializations)
    assert row.expected_root_role_decisions == tuple(
        (decision.kind, decision.status, decision.reason)
        for decision in spec.root_role_decisions
    )
    assert row.expected_operands == tuple(
        (name, tuple(targets)) for name, targets in spec.operands
    )
    assert row.expected_source_coordinate_digest == catalog._spec_source_coordinate_digest(spec)
    assert _validate_reviewed_row_only(monkeypatch, object_id, spec) == (spec,)


@pytest.mark.parametrize(("object_id", "name"), COORDINATE_ADVERSARY_CASES)
def test_reviewed_row_adversaries_fail_closed_on_their_exact_token(
    monkeypatch, object_id, name
) -> None:
    spec = _source_map()[object_id]
    # The live baseline must verify first, so the adversary is the only cause.
    assert _validate_reviewed_row_only(monkeypatch, object_id, spec) == (spec,)
    mutated, prefix = _mutate_coordinate(spec, name)
    assert mutated != spec
    with pytest.raises(ValueError) as error:
        _validate_reviewed_row_only(monkeypatch, object_id, mutated)
    assert str(error.value) == prefix + object_id


OBSERVER_ID = "vstd-source-provenance-observer"
OBSERVER_NARROW_CLAIM = (
    "Only the mutable worktree-state capture in self_polish_estate.py runs Git "
    "with repository-configured fsmonitor disabled"
)
OBSERVER_BROAD_CLAIM = "The observer disables repository-configured fsmonitor execution"


def test_observer_catalog_row_pins_the_narrow_boundary_and_no_actuator() -> None:
    row = _reviewed_row(OBSERVER_ID)
    assert OBSERVER_NARROW_CLAIM in row.expected_consequence_boundary
    assert OBSERVER_BROAD_CLAIM not in row.expected_consequence_boundary
    assert row.expected_specializations == ("MEASUREMENT", "PROTOCOL", "TRANSACTION")
    assert "ACTUATOR" not in row.expected_specializations


def test_observer_rebroadened_fsmonitor_claim_fails_on_its_exact_token(monkeypatch) -> None:
    spec = _source_map()[OBSERVER_ID]
    assert _validate_reviewed_row_only(monkeypatch, OBSERVER_ID, spec) == (spec,)
    broadened = replace(
        spec,
        consequence_boundary=spec.consequence_boundary.replace(
            OBSERVER_NARROW_CLAIM, "Every observer Git query runs with fsmonitor disabled"
        ),
    )
    assert broadened.consequence_boundary != spec.consequence_boundary
    with pytest.raises(ValueError) as error:
        _validate_reviewed_row_only(monkeypatch, OBSERVER_ID, broadened)
    assert str(error.value) == COORDINATE_DRIFT + OBSERVER_ID


def test_observer_capture_site_substitution_fails_on_its_exact_token(monkeypatch) -> None:
    spec = _source_map()[OBSERVER_ID]
    assert _validate_reviewed_row_only(monkeypatch, OBSERVER_ID, spec) == (spec,)
    substituted = replace(
        spec,
        consequence_boundary=spec.consequence_boundary.replace(
            "in self_polish_estate.py runs Git", "in prdel.py runs Git"
        ),
    )
    assert substituted.consequence_boundary != spec.consequence_boundary
    with pytest.raises(ValueError) as error:
        _validate_reviewed_row_only(monkeypatch, OBSERVER_ID, substituted)
    assert str(error.value) == COORDINATE_DRIFT + OBSERVER_ID


def test_observer_actuator_reintroduction_fails_on_its_exact_token(monkeypatch) -> None:
    spec = _source_map()[OBSERVER_ID]
    assert _validate_reviewed_row_only(monkeypatch, OBSERVER_ID, spec) == (spec,)
    reintroduced = replace(spec, specializations=(*spec.specializations, "ACTUATOR"))
    with pytest.raises(ValueError) as error:
        _validate_reviewed_row_only(monkeypatch, OBSERVER_ID, reintroduced)
    assert str(error.value) == COORDINATE_DRIFT + OBSERVER_ID
