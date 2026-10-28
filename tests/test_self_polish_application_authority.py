"""Application-authority evidence boundaries for Verifier Standard (VSTD)."""
from __future__ import annotations

import pytest
from copy import deepcopy

from verifier.runtime import core_application_authority as authority
from verifier.runtime import core_obligation_union as union
from verifier.runtime import self_polish_tiers as tiers


def _carried_assessment(status: str = "PASS") -> dict:
    value = {
        "schema_version": authority.ASSESSMENT_SCHEMA,
        "status": status,
        "binding_status": "PASS",
        "authority_status": status,
        "child_status": "PASS",
        "interaction_status": "PASS",
        "semantic_completeness": status,
        "expected_instances": 2,
        "union_validation": {"report_digest": "sha256:" + "6" * 64},
        "full_application_status": "UNKNOWN",
        "polished": False,
        "release_authorized": False,
        "blockers": [],
    }
    value["assessment_digest"] = union.value_digest(value)
    return value


@pytest.mark.parametrize("declared_status", ["PASS", "UNKNOWN"])
def test_self_hashed_authority_assessment_is_not_independent_replay(
        declared_status: str) -> None:
    value = _carried_assessment(declared_status)
    result = tiers._authority_summary(
        union.canonical_bytes(value), expected_digest=value["assessment_digest"],
        union_summary={"status": "PASS", "report_digest": "sha256:" + "6" * 64},
        expected_instances=2,
    )
    assert result["status"] == "UNKNOWN", result
    assert result["authority_status"] == "NOT_ESTABLISHED", result
    assert result["semantic_completeness"] == "NOT_ESTABLISHED", result
    assert result["declared_status"] == declared_status
    assert result["replay_status"] == "NOT_ESTABLISHED"
    assert result["obligation"]["classification"] == "CONDITIONAL"
    assert result["obligation"]["condition_status"] == "TRIGGERED"
    assert "APPLICATION_AUTHORITY_REPLAY_NOT_ESTABLISHED" in result["blockers"]


def test_self_hashed_authority_failure_is_never_softened() -> None:
    value = _carried_assessment("FAIL")
    result = tiers._authority_summary(
        union.canonical_bytes(value), expected_digest=value["assessment_digest"],
        union_summary={"status": "PASS", "report_digest": "sha256:" + "6" * 64},
        expected_instances=2,
    )
    assert result["status"] == "FAIL"
    assert result["authority_status"] == "FAIL"


@pytest.mark.parametrize("tier,condition", [(1, "NOT_TRIGGERED"), (2, "NOT_TRIGGERED")])
def test_native_authority_has_reasoned_conditional_necessity(
        tier: int, condition: str) -> None:
    denominators = tiers._denominators("verifier-core-self")
    source = {"source_head": "a" * 40, "source_manifest_digest": "sha256:" + "b" * 64}
    route_union = tiers._derived_route_union_summary(
        source_coordinate=source, tier=tier, denominators=denominators,
        expected_members=denominators["complete_tiers"][str(tier)][
            "registered_route_membership_count"],
    )
    result = tiers._derived_application_authority_summary(
        union_summary=route_union, expected_instances=2,
        source_coordinate=source, tier=tier, denominators=denominators,
    )
    obligation = result.get("obligation", {})
    assert obligation.get("classification") == "CONDITIONAL", result
    assert obligation["condition_status"] == condition
    assert obligation["necessity_reason"] and obligation["assessment_reason"]
    assert result["status"] == "UNKNOWN"
    assert result["authority_status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mutation", [
    "optional", "missing-reason", "unknown-condition", "full-application",
    "authority-pass", "union-substitution", "tier2",
])
def test_authority_non_trigger_must_reproduce_exact_source_reason(
        mutation: str) -> None:
    denominators = tiers._denominators("verifier-core-self")
    source = {"source_head": "a" * 40, "source_manifest_digest": "sha256:" + "b" * 64}
    route_union = tiers._derived_route_union_summary(
        source_coordinate=source, tier=1, denominators=denominators,
        expected_members=45,
    )
    result = tiers._derived_application_authority_summary(
        union_summary=route_union, expected_instances=2,
        source_coordinate=source, tier=1, denominators=denominators,
    )
    def qualifies(value: dict, tier: int = 1) -> bool:
        return tiers._native_authority_condition_not_triggered(
            value, union_summary=route_union, source_coordinate=source,
            tier=tier, denominators=denominators,
        )
    assert qualifies(result)
    result = deepcopy(result)
    if mutation == "optional":
        result["obligation"]["classification"] = "OPTIONAL"
    elif mutation == "missing-reason":
        result["obligation"].pop("assessment_reason")
    elif mutation == "unknown-condition":
        result["obligation"]["condition_status"] = "UNKNOWN"
    elif mutation == "full-application":
        result["full_application_status"] = "PASS"
    elif mutation == "authority-pass":
        result["authority_status"] = "PASS"
    elif mutation == "union-substitution":
        route_union["authority_binding"] = "MATCHED"
        route_union.pop("report_digest")
        route_union["report_digest"] = union.value_digest(route_union)
        result["union_report_digest"] = route_union["report_digest"]
    result.pop("assessment_digest")
    result["assessment_digest"] = union.value_digest(result)
    assert not qualifies(result, 2 if mutation == "tier2" else 1)


@pytest.mark.parametrize("mutation", [None, "reason", "scope", "membership", "authority"])
def test_tier2_non_trigger_requires_its_own_exact_scope_and_reason(mutation):
    denominators = tiers._denominators("verifier-core-self")
    source = {"source_head": "a" * 40, "source_manifest_digest": "sha256:" + "b" * 64}
    selected = tiers._derived_route_union_summary(
        source_coordinate=source, tier=2, denominators=denominators, expected_members=37,
    )
    value = tiers._derived_application_authority_summary(
        union_summary=selected,
        expected_instances=(denominators["facets"]["instantiated_obligation_count"]
                            + denominators["dynamics"]["registered_route_membership_count"]),
        source_coordinate=source, tier=2, denominators=denominators,
    )
    if mutation == "reason":
        value["obligation"]["assessment_reason"] = "Tier 1 passed so inherit it."
    elif mutation == "scope":
        value["obligation"]["claim_scope"] = "SOURCE_BOUND_TIER1_FACETS"
    elif mutation == "membership":
        value["expected_instances"] = 2
    elif mutation == "authority":
        value["authority_status"] = "PASS"
    value.pop("assessment_digest")
    value["assessment_digest"] = union.value_digest(value)
    assert tiers._native_authority_condition_not_triggered(
        value, union_summary=selected, source_coordinate=source,
        tier=2, denominators=denominators,
    ) is (mutation is None)
