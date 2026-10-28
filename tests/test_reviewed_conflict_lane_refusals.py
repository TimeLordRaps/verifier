from __future__ import annotations

import copy

import pytest

from verifier.domains.contracts import reviewed_conflict_lane_refusals as refusals


EXPECTED_MEMBERS = (
    "HYPER-2.3", "HYPER-3.1", "HYPER-4.1", "OWNER-3.1", "AGENT-3.1",
    "BOT-3.1", "VERIFIER-2.1", "VERIFIER-3.1", "VERIFIER-4.1", "EVENT-1.1",
    "AGENT-1.1", "AGENT-1.8", "AGENT-2.1", "AGENT-2.3", "AGENT-4.1",
    "AGENT-4.3", "BOT-1.1", "BOT-1.6", "BOT-2.1", "BOT-2.2", "BOT-2.3",
    "BOT-4.1", "HYPER-1.1", "OWNER-1.1", "SPACE-1.1", "VERIFIER-1.1",
)
EXPECTED_INHERITED_INDEPENDENCE_REFUSALS = (
    "AGENT-5.1", "BOT-5.1", "EVENT-5.1", "HYPER-5.1", "OWNER-5.1", "SPACE-5.1", "VERIFIER-5.1",
)
EXPECTED_INHERITED_BATCH04_06_REFUSALS = (
    "OBJECT-1.1", "SIM-5.1", "EVENT-2.1", "EVENT-3.1", "EVENT-4.1",
    "OWNER-2.6", "OWNER-4.3", "SPACE-2.1", "SPACE-3.1", "SPACE-4.1",
)


def test_exact_twenty_six_reviewed_refusals_are_fail_closed() -> None:
    assert refusals.REFUSED_MEMBERS == EXPECTED_MEMBERS
    assert len(refusals.REFUSAL_ROWS) == len(set(refusals.REFUSED_MEMBERS)) == 26
    for member_id in EXPECTED_MEMBERS:
        row = refusals.reviewed_refusal(member_id)
        result = refusals.classify_exact_refusal(member_id, row)
        assert row["direction"] is None
        assert row["unavailable_selector"] is None
        assert row["dependency_binding_status"] == "UNKNOWN"
        assert row["requirements"]
        assert row["requirements_preserved"] is True
        assert row["requirements_discharged"] is False
        assert row["credit"] == 0
        assert row["refusal_reason"]
        assert result["status"] == "EXPLICIT_REVIEWED_REFUSAL"
        assert result["release_admissible"] is False


def test_final_conflict_lane_denominator_is_exact_and_zero_credit() -> None:
    assert refusals.INHERITED_INDEPENDENCE_REFUSALS == EXPECTED_INHERITED_INDEPENDENCE_REFUSALS
    assert refusals.INHERITED_BATCH04_06_REFUSALS == EXPECTED_INHERITED_BATCH04_06_REFUSALS
    assert refusals.INHERITED_EXPLICIT_REFUSALS == (
        EXPECTED_INHERITED_INDEPENDENCE_REFUSALS + EXPECTED_INHERITED_BATCH04_06_REFUSALS
    )
    assert refusals.FOREIGN_REJECTED_KINDS_OUTSIDE_R12_DENOMINATOR == ("MODEL-5.1", "TRAIN-5.1")
    assert refusals.conflict_lane_accounting() == {
        "denominator": 140,
        "accepted_one_way_mappings": 97,
        "inherited_explicit_refusals": 17,
        "new_explicit_refusals": 26,
        "explicit_refusals": 43,
        "uninspected": 0,
        "source_inspection_closed": True,
        "r12_member_id_set_sha256":
            "566030c39bd6768d3c39c86402fdc166ad2635513849090086d8d2f27d702fc2",
        "runtime_qualified": False,
        "full_suite_qualified": False,
        "package_qualified": False,
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def test_accounting_refuses_wrong_same_count_duplicate_foreign_and_missing_partitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = refusals.REGISTRY_ACCEPTED_MEMBER_IDS
    inherited = refusals.INHERITED_EXPLICIT_REFUSALS
    final = refusals.REFUSED_MEMBERS

    monkeypatch.setattr(refusals, "REGISTRY_ACCEPTED_MEMBER_IDS", accepted[:-1] + ("MODEL-5.1",))
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="accepted R12 identity mismatch") as wrong_set:
        refusals.conflict_lane_accounting()
    assert "missing=SIM-4.2" in str(wrong_set.value)
    assert "foreign=MODEL-5.1" in str(wrong_set.value)

    monkeypatch.setattr(refusals, "REGISTRY_ACCEPTED_MEMBER_IDS", accepted[:-1] + (accepted[0],))
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="duplicate accepted"):
        refusals.conflict_lane_accounting()

    monkeypatch.setattr(refusals, "REGISTRY_ACCEPTED_MEMBER_IDS", accepted[:-1] + (inherited[0],))
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="overlapping R12 partition identities"):
        refusals.conflict_lane_accounting()

    monkeypatch.setattr(refusals, "REGISTRY_ACCEPTED_MEMBER_IDS", accepted)
    monkeypatch.setattr(refusals, "REFUSED_MEMBERS", final[:-1] + (final[0],))
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="duplicate refusal"):
        refusals.conflict_lane_accounting()

    monkeypatch.setattr(refusals, "REFUSED_MEMBERS", final[:-1])
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="refused R12 identity mismatch"):
        refusals.conflict_lane_accounting()

    monkeypatch.setattr(refusals, "REFUSED_MEMBERS", final)
    removed_inherited_identity = inherited[-1]
    monkeypatch.setattr(refusals, "INHERITED_EXPLICIT_REFUSALS", inherited[:-1] + ("TRAIN-5.1",))
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="refused R12 identity mismatch") as refused_wrong_set:
        refusals.conflict_lane_accounting()
    assert f"missing={removed_inherited_identity}" in str(refused_wrong_set.value)
    assert "foreign=TRAIN-5.1" in str(refused_wrong_set.value)


def test_exact_r12_identity_partition_and_foreign_missing_substitutions() -> None:
    accepted = refusals.REGISTRY_ACCEPTED_MEMBER_IDS
    refused = refusals.INHERITED_EXPLICIT_REFUSALS + refusals.REFUSED_MEMBERS
    assert accepted == refusals.EXPECTED_R12_ACCEPTED_MEMBER_IDS
    assert set(refused) == set(refusals.EXPECTED_R12_REFUSED_MEMBER_IDS)
    assert set(refusals.EXPECTED_R12_MEMBER_IDS) == set(accepted + refused)
    assert refusals.validate_exact_r12_partition(accepted, refused) == {
        "denominator": 140,
        "accepted_member_ids": 97,
        "refused_member_ids": 43,
        "overlap": 0,
        "foreign": 0,
        "missing": 0,
        "r12_member_id_set_sha256":
            "566030c39bd6768d3c39c86402fdc166ad2635513849090086d8d2f27d702fc2",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="accepted R12 identity mismatch"):
        refusals.validate_exact_r12_partition(accepted[:-1], refused)
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="accepted R12 identity mismatch"):
        refusals.validate_exact_r12_partition(accepted[:-1] + ("MODEL-5.1",), refused)
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="refused R12 identity mismatch"):
        refusals.validate_exact_r12_partition(accepted, refused[:-1])
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="refused R12 identity mismatch"):
        refusals.validate_exact_r12_partition(accepted, refused[:-1] + ("TRAIN-5.1",))


def test_duplicate_identity_plus_compensating_omission_is_refused_at_same_count() -> None:
    accepted = refusals.REGISTRY_ACCEPTED_MEMBER_IDS
    refused = refusals.INHERITED_EXPLICIT_REFUSALS + refusals.REFUSED_MEMBERS
    duplicate_accepted = accepted[:-1] + (accepted[0],)
    assert len(duplicate_accepted) == len(accepted) == 97
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="duplicate accepted"):
        refusals.validate_exact_r12_partition(duplicate_accepted, refused)
    duplicate_refused = refused[:-1] + (refused[0],)
    assert len(duplicate_refused) == len(refused) == 43
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="duplicate refusal"):
        refusals.validate_exact_r12_partition(accepted, duplicate_refused)


def test_substitution_alias_and_generic_fallback_are_refused() -> None:
    row = refusals.reviewed_refusal("HYPER-2.3")
    substituted = copy.deepcopy(row)
    substituted["refusal_reason"] = "generic alias"
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", substituted)
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="outside"):
        refusals.reviewed_refusal("hyper-2.3")
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="outside"):
        refusals.reviewed_refusal("UNREVIEWED-99.99")
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased refusal coordinate"):
        refusals.classify_exact_refusal("HYPER-2.3", {"family": "HYPER"})


@pytest.mark.parametrize("field", [
    "member_id", "object_kind", "tier", "module_path", "module_binding", "module_sha256", "module_bytes",
    "mechanism", "certificate_schema", "scope", "route_instance_id",
    "route_registration_digest", "native_proposition_text", "native_proposition_text_sha256",
    "union_ref", "union_claim_text", "union_claim_digest", "union_source_uri",
    "union_source_sha256", "producer_source_coordinate_digest",
    "ancestor_consumer_source_coordinate_digest", "candidate_input_digest", "source_map_digest",
    "union_contribution_index_zero_based", "union_row_index_zero_based", "direction",
    "unavailable_selector", "dependency_binding_status", "disposition", "refusal_reason", "credit",
    "requirements", "requirements_preserved", "requirements_discharged", "batch",
])
def test_every_bound_refusal_field_rejects_substitution(field: str) -> None:
    row = refusals.reviewed_refusal("HYPER-2.3")
    substituted = copy.deepcopy(row)
    value = substituted[field]
    if value is None:
        substituted[field] = "missing-source-alias"
    elif isinstance(value, bool):
        substituted[field] = not value
    elif isinstance(value, int):
        substituted[field] = value + 1
    elif isinstance(value, tuple):
        substituted[field] = value + ("alias",)
    else:
        substituted[field] = str(value) + " "
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", substituted)


@pytest.mark.parametrize("alias", ["HYPER-2.3 ", "hyper-2.3", "HYPER-2.03", "HYPER-2.4"])
def test_whitespace_case_and_family_adjacent_aliases_are_refused(alias: str) -> None:
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="outside"):
        refusals.reviewed_refusal(alias)


@pytest.mark.parametrize("field,value", [
    ("tier", True),
    ("tier", 2.0),
    ("credit", False),
    ("module_bytes", 25514.0),
])
def test_bool_int_and_integral_float_equivalence_is_refused(field: str, value: object) -> None:
    candidate = refusals.reviewed_refusal("HYPER-2.3")
    candidate[field] = value
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", candidate)


def test_list_tuple_and_nested_type_substitution_is_refused() -> None:
    candidate = refusals.reviewed_refusal("HYPER-2.3")
    candidate["requirements"] = list(candidate["requirements"])
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", candidate)
    candidate = refusals.reviewed_refusal("HYPER-2.3")
    candidate["requirements"] = ([candidate["requirements"][0]],) + candidate["requirements"][1:]
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", candidate)


def test_extra_and_missing_keys_are_refused_but_mapping_order_is_irrelevant() -> None:
    row = refusals.reviewed_refusal("HYPER-2.3")
    reordered = dict(reversed(tuple(row.items())))
    assert refusals.classify_exact_refusal("HYPER-2.3", reordered)["status"] == "EXPLICIT_REVIEWED_REFUSAL"
    extra = dict(row)
    extra["alias"] = None
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", extra)
    missing = dict(row)
    del missing["route_registration_digest"]
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", missing)


def test_foreign_custom_and_non_string_keys_are_refused_without_foreign_equality() -> None:
    class ForeignKey:
        equality_invocations = 0

        def __hash__(self) -> int:
            return hash("__foreign_custom_key__")

        def __eq__(self, other: object) -> bool:
            type(self).equality_invocations += 1
            raise AssertionError("foreign key equality must not be invoked")

    custom = refusals.reviewed_refusal("HYPER-2.3")
    custom[ForeignKey()] = "foreign"
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", custom)
    assert ForeignKey.equality_invocations == 0

    non_string = refusals.reviewed_refusal("HYPER-2.3")
    non_string[7] = "foreign"
    with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
        refusals.classify_exact_refusal("HYPER-2.3", non_string)


def test_batch08_common_union_binding_is_nonnull_exact_and_fail_closed() -> None:
    expected = {
        "producer_source_coordinate_digest":
            "sha256:362d1b38573221b9cc21e0dafba1069f360fc04ba73ae63866cb858ac009bd95",
        "ancestor_consumer_source_coordinate_digest":
            "sha256:88f3fb09e1818ecfc8c5757c8fbb859a8b7a4956451b403c1927de1022bab763",
        "candidate_input_digest":
            "sha256:d807a812b0dcb4d609d61cfca901e1b032fd40ffcd1e4055a1b12dc16bc59de5",
    }
    for member_id in EXPECTED_MEMBERS[10:]:
        row = refusals.reviewed_refusal(member_id)
        for field, value in expected.items():
            assert row[field] == value
            substituted = copy.deepcopy(row)
            substituted[field] = None
            with pytest.raises(refusals.ReviewedConflictLaneRefusal, match="substituted or aliased"):
                refusals.classify_exact_refusal(member_id, substituted)


def test_normative_note_keeps_qualification_boundary() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_REVIEWED_CONFLICT_LANE_REFUSALS.md")
        .read_text(encoding="utf-8").split()
    )
    for phrase in (
        "97 exact accepted one-way mappings plus 43 explicit refusals plus zero uninspected rows",
        "source-inspection closure only",
        "all active requirements remain preserved and undischarged",
        "runtime, full-suite, package, profile, semantic-completeness, or release qualification",
        "no generic fallback",
        "27 exact relation triples and 25 distinct endpoint pairs",
        "opaque coordinate fields are source-review-bound",
        "recursive type-sensitive equality",
        "seven inherited independence refusals",
        "10 inherited batch-04–06 refusals",
        "all 16 batch-08 rows retain the same three non-null common union bindings",
        "exact R12 identity partition",
        "AGENT-5.1 and BOT-5.1",
        "`MODEL-5.1` and `TRAIN-5.1` remain source-rejected kinds outside this R12 denominator",
        "Cardinality 140 alone is insufficient",
        "batch-04–06 source packets contribute the R19 subset of 27 exact relation triples and 25 distinct endpoint pairs",
        "Four inherited disjoint relations raise the receiver total to 31 relation entries and 29 distinct endpoint pairs",
        "all 31 remain `UNKNOWN` and undischarged",
    ):
        assert phrase in note
