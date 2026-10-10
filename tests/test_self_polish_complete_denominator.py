"""Independent complete-denominator oracles for numeric self-polish tiers.

These tests deliberately distinguish the retained two-obligation core replay
from whole-tier conformance. They exercise the public assessment and command-line
interface (CLI) surfaces
while replacing only upstream evidence producers with deterministic records.
"""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_tiers as tiers


_SHA = "sha256:" + "a" * 64


def _source_coordinate(seed: str = "a") -> dict[str, str]:
    return {
        "source_head": seed * 40,
        "source_tree": chr(ord(seed) + 1) * 40,
        "source_worktree_status_digest": (
            "sha256:" + chr(ord(seed) + 2) * 64
        ),
        "source_manifest_digest": "sha256:" + chr(ord(seed) + 3) * 64,
    }


def _attempt(coordinate: dict[str, str] | None = None) -> dict:
    selected = coordinate or _source_coordinate()
    return {
        "status": "PASS",
        "gate_status": "PASS",
        "receipt_status": "ISSUED",
        "assessment_digest": "sha256:" + "1" * 64,
        "receipt_digest": "sha256:" + "2" * 64,
        "selection_digest": "sha256:" + "3" * 64,
        "external_selection_pin": "MATCHED",
        "source_coordinate": selected,
        "source_coordinate_digest": core_obligation_union.value_digest(
            selected
        ),
        "root_id": "verifier-core-self",
        "installed_definition_count": 27,
        "installed_membership_count": 52,
        "instantiated_obligation_count": 2,
        "full_application_status": "UNKNOWN",
        "polished": False,
        "reason": None,
    }


def _union_pass() -> dict:
    return {
        "status": "PASS",
        "authority_binding": "MATCHED",
        "source_coordinate_binding": "MATCHED",
        "dependency_binding": "MATCHED",
        "candidate_coverage": "MATCHED",
        "structural_union": "PASS",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
        "issue_codes": [],
        "report_digest": "sha256:" + "4" * 64,
    }


def _authority_pass() -> dict:
    return {
        "status": "PASS",
        "binding_status": "PASS",
        "authority_status": "PASS",
        "child_status": "PASS",
        "interaction_status": "PASS",
        "semantic_completeness": "PASS",
        "expected_instances": 2,
        "assessment_digest": "sha256:" + "5" * 64,
        "blockers": [],
    }


def _redigest(document: dict, digest_field: str) -> dict:
    document.pop(digest_field, None)
    document[digest_field] = core_obligation_union.value_digest(document)
    return document


def _complete_ledger(
    denominators: dict,
    coordinate: dict[str, str],
    *,
    tier: int = 1,
) -> dict:
    expected = denominators["complete_tiers"][str(tier)]
    entries = []
    for index, membership in enumerate(expected["membership_identities"]):
        assessment_digest = "sha256:" + f"{index + 1:064x}"
        mechanism = membership["checking_mechanism"]
        entries.append({
            "membership": deepcopy(membership),
            "applicability_status": "PASS",
            "authority_status": "PASS",
            "observation_status": "PASS",
            "native_assessment_status": "PASS",
            "provider_review_status": "PASS",
            "native_assessment_digest": assessment_digest,
            "obligation_id": (
                f"{membership['object_kind']}:{membership['coordinate']}"
            ),
            "definition_source": {
                "proposition_digest": membership["proposition_digest"],
                "scope": membership["scope"],
            },
            "definition_version": membership["semantic_version"],
            "implementation": {
                "checking_mechanism": mechanism,
                "files": [
                    mechanism.rsplit(".", 1)[0].replace(".", "/") + ".py"
                ],
                "symbols": [mechanism.rsplit(".", 1)[-1]],
            },
            "evidence": {
                "native_assessment_digest": assessment_digest,
                "source_coordinate_digest": (
                    core_obligation_union.value_digest(coordinate)
                ),
                "freshness": "CURRENT",
                "sources": [membership["coordinate"]],
            },
            "dependencies": [],
            "prerequisites": [],
            "applicability": {
                "platform_status": "PASS",
                "binding_status": "PASS",
            },
            "expected_behavior": {
                "positive": "admit exact valid evidence",
                "negative": "refuse contradictory evidence",
                "unknown": "preserve unavailable evidence as UNKNOWN",
            },
            "ownership": {
                "supervisor": "INDEPENDENT_QUALIFICATION_SUPERVISOR_C",
                "owner": "AGENT_6",
            },
            "provider_records": {
                "claude": {
                    "state": "PASS",
                    "receipt_digest": "sha256:" + "9" * 64,
                },
                "antigravity": {
                    "state": "PASS",
                    "receipt_digest": "sha256:" + "a" * 64,
                },
            },
            "implementation_status": "PASS",
            "focused_validation": {
                "status": "PASS",
                "receipt_digest": "sha256:" + "b" * 64,
            },
            "independent_replay": {
                "status": "PASS",
                "receipt_digest": "sha256:" + "c" * 64,
            },
            "final_disposition": "PASS",
            "justified_exclusion": None,
        })
    body = {
        "schema_version": tiers.TIER_LEDGER_SCHEMA,
        "tier": tier,
        "tier_name": expected["tier_name"],
        "source_coordinate": deepcopy(coordinate),
        "source_coordinate_digest": core_obligation_union.value_digest(
            coordinate
        ),
        "installed_inventory_digest": denominators[
            "installed_route_inventory_digest"
        ],
        "installed_family_cell_count_total": denominators[
            "installed_route_family_cell_count"
        ],
        "installed_membership_count_total": denominators[
            "installed_route_membership_count"
        ],
        "tier_family_cell_count": expected["family_cell_count"],
        "tier_membership_count": expected[
            "registered_route_membership_count"
        ],
        "entries": entries,
    }
    return _redigest(body, "ledger_digest")


def _complete_representation(
    denominators: dict,
    coordinate: dict[str, str],
    ledger: dict,
    *,
    tier: int = 1,
    prior_report_digest: str | None = None,
    representation_status: str = "PASS",
    provider_review_status: str = "PASS",
    unobserved_fields: list[str] | None = None,
) -> dict:
    reasons = tiers._validated_facet_reason_assessment(denominators)
    partition = reasons["consumer_route_partition"]
    body = {
        "schema_version": tiers.SELF_REPRESENTATION_SCHEMA,
        "subject": {
            "object_id": "verifier-core-self",
            "object_kind": "VERIFIER",
        },
        "source_coordinate": deepcopy(coordinate),
        "source_coordinate_digest": core_obligation_union.value_digest(
            coordinate
        ),
        "installed_inventory_digest": denominators[
            "installed_route_inventory_digest"
        ],
        "installed_family_cell_count_total": denominators[
            "installed_route_family_cell_count"
        ],
        "installed_membership_count_total": denominators[
            "installed_route_membership_count"
        ],
        "represented_tiers": list(range(1, tier + 1)),
        "tier_ledger_digest": ledger["ledger_digest"],
        "prior_whole_tier_report_digest": prior_report_digest,
        "representation_status": representation_status,
        "provider_review_status": provider_review_status,
        "unobserved_fields": unobserved_fields or [],
        "representation_evidence_digest": (
            _SHA if representation_status == "PASS" else None
        ),
        "tier1_facet_reason_assessment_digest": reasons[
            "assessment_digest"
        ],
        "tier1_facet_reason_ledger_digest": reasons["ledger_digest"],
        "tier1_facet_choice_identity_digest": reasons[
            "choice_identity_digest"
        ],
        "tier1_reasoned_structural_membership_digest": reasons[
            "reasoned_structural_membership_digest"
        ],
        "tier1_reasoned_route_membership_digest": reasons[
            "reasoned_route_membership_digest"
        ],
        "tier1_reasoned_slot_digest": reasons["reasoned_slot_digest"],
        "tier1_domain_route_reason_status": reasons[
            "domain_route_reason_status"
        ],
        "tier1_domain_route_reason_identity_digest": reasons[
            "domain_route_reason_identity_digest"
        ],
        "tier1_domain_route_reasons_digest": partition[
            "domain_route_reasons_digest"
        ],
        "tier1_facet_direct_route_membership_count": partition[
            "facet_direct_route_membership_count"
        ],
        "tier1_facet_direct_route_membership_digest": partition[
            "facet_direct_route_membership_digest"
        ],
        "tier1_domain_route_membership_count": partition[
            "domain_route_membership_count"
        ],
        "tier1_domain_route_membership_digest": partition[
            "domain_route_membership_digest"
        ],
        "tier1_reason_route_union_membership_count": partition[
            "route_union_membership_count"
        ],
        "tier1_reason_route_union_membership_digest": partition[
            "route_union_membership_digest"
        ],
        "tier1_reason_route_partition_digest": reasons[
            "consumer_route_partition_digest"
        ],
    }
    return _redigest(body, "representation_digest")


def _install_passed_upstream_evidence(
    monkeypatch: pytest.MonkeyPatch,
    coordinate: dict[str, str],
) -> None:
    monkeypatch.setattr(
        tiers,
        "_attempt_tier1",
        lambda *_args, **_kwargs: _attempt(coordinate),
    )
    monkeypatch.setattr(
        tiers, "_union_summary", lambda *_args, **_kwargs: _union_pass()
    )
    monkeypatch.setattr(
        tiers,
        "_authority_summary",
        lambda *_args, **_kwargs: _authority_pass(),
    )


def _assess_tier1(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ledger: dict | None = None,
    representation: dict | None = None,
    coordinate: dict[str, str] | None = None,
) -> dict:
    selected = coordinate or _source_coordinate()
    _install_passed_upstream_evidence(monkeypatch, selected)
    kwargs = {}
    if ledger is not None:
        kwargs.update(
            complete_tier_ledger_bytes=(
                core_obligation_union.canonical_bytes(ledger)
            ),
            expected_complete_tier_ledger_digest=ledger["ledger_digest"],
        )
    if representation is not None:
        kwargs.update(
            complete_self_representation_bytes=(
                core_obligation_union.canonical_bytes(representation)
            ),
            expected_complete_self_representation_digest=representation[
                "representation_digest"
            ],
        )
    return tiers.assess_self_polish_tier(
        1, source_root="selected-source", **kwargs
    )


def _synthetic_complete_tier1_report(
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    """Make an otherwise admissible retained report for Tier-2 fencing tests."""
    report = _assess_tier1(monkeypatch)
    expected = report["installed_denominators"]["complete_tiers"]["1"]
    ledger_digest = "sha256:" + "6" * 64
    report.update(
        status="PASS",
        selected_tier_status="PASS",
        source_binding_status="PASS",
        applicability_status="PASS",
        authority_status="PASS",
        dependency_status="PASS",
        interaction_status="PASS",
        whole_tier_conformance="PASS",
        blockers=[],
        complete_tier_ledger={
            "status": "PASS",
            "ledger_digest": ledger_digest,
            "tier_family_cell_count": expected["family_cell_count"],
            "tier_membership_count": expected[
                "registered_route_membership_count"
            ],
        },
        complete_self_representation={
            "status": "PASS",
            "represented_tiers": [1],
            "tier_ledger_digest": ledger_digest,
        },
    )
    return _redigest(report, "report_digest")


def test_complete_denominator_counts_are_visible_and_bound() -> None:
    report = tiers.assess_self_polish_tier(1)
    denominator = report["installed_denominators"]

    assert denominator["installed_route_family_cell_count"] == 234
    assert denominator["installed_route_membership_count"] == 408
    assert denominator["installed_object_kind_count"] == 26
    assert denominator["installed_tier_count"] == 9
    complete = denominator["complete_tiers"]
    assert complete["1"]["family_cell_count"] == 26
    assert complete["1"]["registered_route_membership_count"] == 45
    assert len(complete["1"]["membership_identities"]) == 45
    assert complete["2"]["family_cell_count"] == 26
    assert complete["2"]["registered_route_membership_count"] == 37
    assert len(complete["2"]["membership_identities"]) == 37
    assert denominator["installed_route_inventory_digest"].startswith("sha256:")
    assert complete["1"]["membership_identity_digest"].startswith("sha256:")
    assert complete["2"]["membership_identity_digest"].startswith("sha256:")


def test_two_retained_obligations_are_explicitly_only_a_narrow_subset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _assess_tier1(monkeypatch)

    assert report["installed_denominators"]["facets"][
        "instantiated_obligation_count"
    ] == 2
    assert report["retained_core_subset"] == {
        "relationship_to_complete_tier": "NARROW_EVIDENCE_SUBSET",
        "retained_concrete_instance_count": 2,
        "complete_tier_family_cell_count": 26,
        "complete_tier_membership_count": 45,
        "establishes_complete_tier": False,
    }
    assert report["status"] != "PASS"
    assert report["selected_tier_status"] != "PASS"
    assert report["whole_tier_conformance"] != "PASS"


def test_cli_returns_unknown_for_retained_subset_without_complete_evidence(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _assess_tier1(monkeypatch)
    assert report["whole_tier_conformance"] != "PASS"
    monkeypatch.setattr(
        tiers, "assess_self_polish_tier", lambda *_args, **_kwargs: report
    )

    code = tiers.handle_self_polish_tier_argv(["1", "--json"])
    emitted = json.loads(capsys.readouterr().out)

    assert code == 2
    assert emitted["status"] == "UNKNOWN"
    assert emitted["whole_tier_conformance"] != "PASS"


def test_complete_ledger_contract_carries_minimum_user_audit_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ledger row must name every audit dimension required by the goal."""
    coordinate = _source_coordinate()
    denominators = tiers._denominators("verifier-core-self")
    ledger = _complete_ledger(denominators, coordinate)
    required_audit_fields = {
        "obligation_id", "definition_source", "definition_version",
        "implementation", "evidence", "dependencies", "prerequisites",
        "applicability", "expected_behavior", "ownership",
        "provider_records", "implementation_status", "focused_validation",
        "independent_replay", "final_disposition", "justified_exclusion",
    }
    for entry in ledger["entries"]:
        assert required_audit_fields <= set(entry)
    _redigest(ledger, "ledger_digest")
    representation = _complete_representation(
        denominators, coordinate, ledger
    )

    report = _assess_tier1(
        monkeypatch,
        ledger=ledger,
        representation=representation,
        coordinate=coordinate,
    )

    assert "COMPLETE_TIER_LEDGER_ENTRY_INVALID" not in report["blockers"]
    assert report["complete_tier_ledger"] is not None


@pytest.mark.parametrize(
    "mutation",
    [
        "absent-obligation",
        "unknown-status",
        "stale-evidence",
        "unobserved-evidence",
        "source-mismatch",
        "provider-review-missing",
        "denominator-mismatch",
    ],
)
def test_incomplete_or_unobserved_ledger_never_closes_whole_tier(
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinate = _source_coordinate()
    denominators = tiers._denominators("verifier-core-self")
    ledger = _complete_ledger(denominators, coordinate)
    if mutation == "absent-obligation":
        ledger["entries"].pop()
    elif mutation == "unknown-status":
        ledger["entries"][0]["native_assessment_status"] = "UNKNOWN"
        ledger["entries"][0]["native_assessment_digest"] = None
    elif mutation == "stale-evidence":
        ledger["entries"][0]["observation_status"] = "UNKNOWN"
    elif mutation == "unobserved-evidence":
        ledger["entries"][0]["observation_status"] = "NOT_ESTABLISHED"
    elif mutation == "source-mismatch":
        ledger["source_coordinate"] = _source_coordinate("e")
        ledger["source_coordinate_digest"] = core_obligation_union.value_digest(
            ledger["source_coordinate"]
        )
    elif mutation == "provider-review-missing":
        ledger["entries"][0]["provider_review_status"] = "UNKNOWN"
    else:
        ledger["tier_membership_count"] -= 1
    _redigest(ledger, "ledger_digest")
    representation = _complete_representation(
        denominators, coordinate, ledger
    )

    report = _assess_tier1(
        monkeypatch,
        ledger=ledger,
        representation=representation,
        coordinate=coordinate,
    )

    assert report["status"] != "PASS"
    assert report["selected_tier_status"] != "PASS"
    assert report["whole_tier_conformance"] != "PASS"


def test_recorded_provider_exception_does_not_silently_complete_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinate = _source_coordinate()
    denominators = tiers._denominators("verifier-core-self")
    ledger = _complete_ledger(denominators, coordinate)
    ledger["entries"][0]["provider_review_status"] = "NOT_ESTABLISHED"
    _redigest(ledger, "ledger_digest")
    representation = _complete_representation(
        denominators,
        coordinate,
        ledger,
        provider_review_status="NOT_ESTABLISHED",
        unobserved_fields=["provider-review-exception:recorded"],
    )

    report = _assess_tier1(
        monkeypatch,
        ledger=ledger,
        representation=representation,
        coordinate=coordinate,
    )

    assert report["status"] != "PASS"
    assert report["whole_tier_conformance"] != "PASS"
    assert report["complete_tier_ledger"]["declared_status"] == "PASS"
    assert report["complete_tier_ledger"][
        "provider_coverage_exception_membership_count"
    ] == 1
    assert report["complete_tier_ledger"][
        "provider_review_status_counts"
    ] == {"NOT_ESTABLISHED": 1, "PASS": 44}
    assert report["complete_self_representation"][
        "provider_declared_status"
    ] == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    "mutation", ["whole-tier-not-pass", "source-mismatch", "denominator-mismatch"]
)
def test_tier2_is_fenced_by_exact_complete_retained_tier1(
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained = _synthetic_complete_tier1_report(monkeypatch)
    if mutation == "whole-tier-not-pass":
        retained["whole_tier_conformance"] = "NOT_ESTABLISHED"
    elif mutation == "source-mismatch":
        retained["source_coordinate"] = _source_coordinate("e")
        retained["source_coordinate_digest"] = (
            core_obligation_union.value_digest(retained["source_coordinate"])
        )
    else:
        retained["installed_denominators"][
            "installed_route_membership_count"
        ] -= 1
    _redigest(retained, "report_digest")
    calls: list[str] = []

    def progression(*_args, **_kwargs):
        calls.append("progression")
        return {
            "status": "PASS",
            "selected_target_status": "PASS",
            "subject": {"object_id": "verifier-core-self"},
            "tiers": [
                {"direct_status": "PASS", "cumulative_status": "PASS"},
                {"direct_status": "PASS", "cumulative_status": "PASS"},
            ],
        }

    monkeypatch.setattr(
        tiers.core_tier_progression, "assess_tier_progression", progression
    )
    selection = {
        "ranks": [
            {"node_id": "facets", "tier": 1},
            {"node_id": "dynamics", "tier": 2},
        ]
    }
    bundle = {
        "edges": [
            {
                "node_id": "dynamics",
                "prerequisite_id": "facets",
                "operand_role": "verifier",
            }
        ]
    }

    report = tiers.assess_self_polish_tier(
        2,
        tier1_report_bytes=core_obligation_union.canonical_bytes(retained),
        expected_tier1_report_digest=retained["report_digest"],
        progression_selection_bytes=core_obligation_union.canonical_bytes(
            selection
        ),
        progression_bundle_bytes=core_obligation_union.canonical_bytes(bundle),
        progression_policy_bytes=b"{}",
        progression_artifact_files={},
        expected_progression_selection_digest="sha256:" + "7" * 64,
        expected_progression_mechanism_digest="sha256:" + "8" * 64,
    )

    assert calls == []
    assert report["status"] != "PASS"
    assert report["selected_tier_status"] != "PASS"
    assert report["whole_tier_conformance"] != "PASS"
