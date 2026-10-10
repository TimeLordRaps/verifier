"""Source-bound numeric self-polish tiers for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind retained inputs.  Tier status is narrower than whole-tier conformance: the
adapter enumerates installed obligations, delegates replay to the existing core
mechanisms, and keeps missing applicability or authority as ``UNKNOWN``.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import json
from pathlib import Path
import re
import time
from typing import Any, Mapping

from verifier.core.namespace import ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import application_requirements
from verifier.runtime import core_application_authority
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import polish
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_estate
from verifier.runtime import self_polish_estate_authority
from verifier.runtime import self_polish_estate_evidence
from verifier.runtime import self_polish_estate_native_evidence
from verifier.runtime import self_polish_evidence
from verifier.runtime import self_polish_facet_reasons
from verifier.runtime import self_polish_native_replay


REPORT_SCHEMA = "verifier-self-polish-tier-assessment-4"
TIER_LEDGER_SCHEMA = "verifier-self-polish-complete-tier-ledger-2"
SELF_REPRESENTATION_SCHEMA = "verifier-self-polish-complete-representation-4"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_TIER1_REPORT_BYTES = 16 * 1024 * 1024
BOUNDARY = (
    "The installed numeric denominator and its replay are a required bounded "
    "subset. They do not establish complete repository, package, public interface, "
    "schema, or registry closure unless exact command-selected source recapture and "
    "every installed native estate verifier close. Independent configured-key "
    "authority, full nine-tier application, polished status, release authorization, "
    "and human acceptance remain separate."
)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ESTATE_EVIDENCE_RESULT_FIELDS = {
    "schema_version", "status", "mechanical_validation_status",
    "estate_authority_status", "independent_authority_status",
    "native_self_verification_status",
    "native_semantic_applicability_status",
    "native_per_candidate_evidence_status", "semantic_applicability_status",
    "per_candidate_evidence_status", "full_estate_closure", "tier1_status",
    "polished", "release_authorized", "source_coordinate_digest",
    "candidate_source_census_digest", "estate_digest",
    "candidate_universe_digest", "candidate_identity_set_digest",
    "applicability_ledger_digest", "manifest_digest",
    "estate_authority_replay_digest", "candidate_count",
    "assessment_time", "native_source_recapture_status",
    "native_applicable_candidate_count", "native_replayed_candidate_count",
    "native_candidate_pass_count", "native_candidate_fail_count",
    "native_candidate_unknown_count", "native_evidence_artifact_count",
    "applicable_candidate_count", "authenticated_candidate_count",
    "candidate_pass_count", "candidate_fail_count", "candidate_unknown_count",
    "candidate_results", "blockers", "claim_boundary", "result_digest",
}
_FACET_REASON_ASSESSMENT_FIELDS = {
    "schema_version", "status", "reason_completeness_status",
    "source_binding_status", "mechanism_digest", "ledger_digest",
    "facet_choice_denominator", "qualifying_facet_choice_reason_count",
    "facet_choice_reason_deficit", "facet_choice_reason_status",
    "domain_route_reason_status", "domain_route_reason_denominator",
    "qualifying_domain_route_reason_count", "domain_route_reason_deficit",
    "domain_route_reason_identity_digest",
    "structural_membership_denominator", "structural_projection_status",
    "reasoned_structural_membership_count",
    "structural_membership_reason_deficit",
    "reasoned_structural_membership_digest",
    "expected_structural_membership_digest", "route_membership_denominator",
    "route_projection_status",
    "reasoned_route_membership_count", "route_membership_reason_deficit",
    "reasoned_route_membership_digest", "expected_route_membership_digest",
    "slot_denominator", "slot_projection_status", "reasoned_slot_count",
    "slot_reason_deficit", "reasoned_slot_digest", "expected_slot_digest",
    "reasoned_slot_object_kinds", "choice_identity_digest",
    "polished", "release_authorized", "blockers", "claim_boundary",
    "assessment_digest",
}
_TIER1_REPORT_FIELDS = {
    "applicability_status", "application_authority", "authority_status",
    "blockers", "candidate_estate_applicability", "candidate_estate_authority",
    "candidate_estate_census", "candidate_estate_evidence", "claim_boundary",
    "complete_self_representation", "complete_tier_evidence_replay",
    "complete_tier_ledger", "core_progression_attempt",
    "core_self_polish_attempt", "declared_dependencies", "dependency_status",
    "full_application_status", "installed_denominators",
    "installed_route_normative_closure", "interaction_status",
    "mechanism_digest", "objective_inventory_closure", "polished",
    "post_replay_full_source_recapture", "post_replay_source_recapture",
    "pre_replay_source_recapture", "release_authorized", "report_digest",
    "repository_package_estate", "repository_package_estate_closure",
    "retained_core_subset", "schema_version", "selected_tier_status",
    "source_binding_status", "source_coordinate", "source_coordinate_digest",
    "status", "structural_route_crosswalk_closure", "tier",
    "tier1_facet_choice_reasons", "tier_name", "union_validation",
    "whole_tier_conformance",
}
_ESTATE_CENSUS_FIELDS = {
    "candidate_count", "candidate_universe_digest", "category_counts",
    "category_summaries_digest", "claim_boundary", "estate_digest",
    "external_estate_digest_pin", "full_estate_closure",
    "mechanical_census_status", "required_categories",
    "required_categories_digest", "schema_version",
    "semantic_applicability_status", "source_coordinate",
    "structural_route_crosswalk", "structural_route_crosswalk_digest",
}
_ESTATE_APPLICABILITY_RESULT_FIELDS = {
    "caller_declared_pass_count", "caller_pass_authentication",
    "candidate_count", "candidate_universe_digest", "claim_boundary",
    "full_estate_closure", "ledger_digest", "mechanical_validation_status",
    "result_digest", "schema_version", "semantic_applicability_status",
}
_ESTATE_AUTHORITY_RESULT_FIELDS = {
    "approving_actors", "blockers", "claim_boundary", "full_estate_closure",
    "independent_authority_status", "per_candidate_evidence_status",
    "policy_digest", "receipt_digest", "replay_status", "result_digest",
    "schema_version", "semantic_applicability_status", "status",
    "subject_digest",
}


class _ContractError(ValueError):
    """Fixed refusal code; never include submitted values or exception text."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _ContractError(code)


def _digest(raw: bytes) -> str:
    return core_obligation_union.bytes_digest(raw)


def mechanism_digest() -> str:
    """Bind this adapter, its specification, and every delegated mechanism."""
    root = Path(__file__).parents[1]
    return core_obligation_union.value_digest({
        "adapter": _digest(Path(__file__).read_bytes()),
        "specification": _digest((root / "standard" / "SELF_POLISH_TIERS.md").read_bytes()),
        "core_tier_progression": core_tier_progression.mechanism_digest(),
        "core_obligation_union": core_application_authority.installed_union_validator_digest(),
        "application_authority": core_application_authority.installed_application_mechanism_digest(),
        "core_self_polish": polish_requirements.core_self_polish_mechanism_digest(),
        "candidate_estate": _digest(Path(self_polish_estate.__file__).read_bytes()),
        "candidate_estate_specification": _digest(
            (root / "standard" / "SELF_POLISH_ESTATE.md").read_bytes()
        ),
        "candidate_estate_authority": (
            self_polish_estate_authority.mechanism_digest()
        ),
        "candidate_estate_evidence": (
            self_polish_estate_evidence.mechanism_digest()
        ),
        "complete_tier_evidence_replay": self_polish_evidence.mechanism_digest(),
        "native_tier_replay": self_polish_native_replay.mechanism_digest(),
        "tier1_facet_choice_reasons": (
            self_polish_facet_reasons.mechanism_digest()
        ),
    })


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    report["blockers"] = sorted(set(report["blockers"]))
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


def _validated_facet_reason_assessment(
        denominators: dict[str, Any]) -> dict[str, Any]:
    """Replay and bind the installed facet plus domain-route reason gate."""

    try:
        result = self_polish_facet_reasons.installed_facet_reason_assessment()
        ledger = self_polish_facet_reasons.installed_facet_reason_ledger()
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise _ContractError(
            "FACET_REASON_MECHANISM_OR_SOURCE_INVALID"
        ) from exc
    _require(type(result) is dict
             and set(result) == _FACET_REASON_ASSESSMENT_FIELDS,
             "FACET_REASON_ASSESSMENT_FIELDS_DIFFER")
    body = {
        key: value for key, value in result.items()
        if key != "assessment_digest"
    }
    _require(
        result["schema_version"]
            == self_polish_facet_reasons.ASSESSMENT_SCHEMA
        and result["assessment_digest"]
            == core_obligation_union.value_digest(body)
        and result["status"] in ("PASS", "FAIL", "UNKNOWN")
        and result["reason_completeness_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and result["source_binding_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and all(result[name] in ("PASS", "FAIL", "UNKNOWN") for name in (
            "facet_choice_reason_status", "domain_route_reason_status",
            "structural_projection_status", "route_projection_status",
            "slot_projection_status",
        ))
        and result["polished"] is False
        and result["release_authorized"] is False
        and type(result["blockers"]) is list
        and result["blockers"] == sorted(set(result["blockers"]))
        and all(type(item) is str and item for item in result["blockers"])
        and type(result["claim_boundary"]) is str
        and bool(result["claim_boundary"]),
        "FACET_REASON_ASSESSMENT_INVALID",
    )
    count_fields = (
        ("facet_choice_denominator", 130),
        ("domain_route_reason_denominator", 18),
        ("structural_membership_denominator", 52),
        ("route_membership_denominator", 45),
        ("slot_denominator", 26),
    )
    _require(
        all(type(result[name]) is int and result[name] == expected
            for name, expected in count_fields),
        "FACET_REASON_DENOMINATOR_DIFFERS",
    )
    for count, deficit, denominator in (
        ("qualifying_facet_choice_reason_count",
         "facet_choice_reason_deficit", "facet_choice_denominator"),
        ("qualifying_domain_route_reason_count",
         "domain_route_reason_deficit", "domain_route_reason_denominator"),
        ("reasoned_structural_membership_count",
         "structural_membership_reason_deficit",
         "structural_membership_denominator"),
        ("reasoned_route_membership_count",
         "route_membership_reason_deficit", "route_membership_denominator"),
        ("reasoned_slot_count", "slot_reason_deficit", "slot_denominator"),
    ):
        _require(
            type(result[count]) is int
            and 0 <= result[count] <= result[denominator]
            and type(result[deficit]) is int
            and result[deficit] == result[denominator] - result[count],
            "FACET_REASON_COUNT_OR_DEFICIT_DIFFERS",
        )
    _require(
        type(ledger) is dict
        and ledger.get("schema_version")
            == self_polish_facet_reasons.LEDGER_SCHEMA
        and ledger.get("mechanism_digest")
            == self_polish_facet_reasons.mechanism_digest()
        and ledger.get("ledger_digest") == core_obligation_union.value_digest({
            key: value for key, value in ledger.items()
            if key != "ledger_digest"
        })
        and ledger.get("facet_choice_count") == 130
        and ledger.get("structural_projection_count") == 52
        and ledger.get("route_projection_count") == 45
        and ledger.get("mapped_route_projection_count") == 27
        and ledger.get("unmatched_route_projection_count") == 18
        and ledger.get("domain_route_reason_count") == 18
        and ledger.get("slot_projection_count") == 26
        and type(ledger.get("mapped_route_projection")) is list
        and len(ledger["mapped_route_projection"]) == 27
        and type(ledger.get("unmatched_route_projection")) is list
        and len(ledger["unmatched_route_projection"]) == 18
        and type(ledger.get("route_projection")) is list
        and len(ledger["route_projection"]) == 45
        and type(ledger.get("domain_route_reasons")) is list
        and len(ledger["domain_route_reasons"]) == 18
        and ledger.get("mapped_route_projection_digest")
            == core_obligation_union.value_digest(
                ledger["mapped_route_projection"]
            )
        and ledger.get("unmatched_route_projection_digest")
            == core_obligation_union.value_digest(
                ledger["unmatched_route_projection"]
            )
        and ledger.get("route_projection_digest")
            == core_obligation_union.value_digest(ledger["route_projection"])
        and ledger.get("domain_route_reasons_digest")
            == core_obligation_union.value_digest(
                ledger["domain_route_reasons"]
            )
        and {
            core_obligation_union.value_digest(row)
            for row in ledger["mapped_route_projection"]
        }.isdisjoint({
            core_obligation_union.value_digest(row)
            for row in ledger["unmatched_route_projection"]
        })
        and {
            core_obligation_union.value_digest(row)
            for row in ledger["mapped_route_projection"]
            + ledger["unmatched_route_projection"]
        } == {
            core_obligation_union.value_digest(row)
            for row in ledger["route_projection"]
        },
        "FACET_REASON_LEDGER_PARTITION_DIFFERS",
    )
    installed_closure = denominators["installed_registry_closure"]
    expected_tier1 = denominators["complete_tiers"]["1"]
    if result["status"] != "FAIL":
        _require(
            result["mechanism_digest"] == ledger["mechanism_digest"]
            and result["ledger_digest"] == ledger["ledger_digest"]
            and result["expected_structural_membership_digest"]
                == installed_closure["structural_membership_digest"]
                == ledger["structural_projection_digest"]
            and result["expected_route_membership_digest"]
                == expected_tier1["membership_identity_digest"]
                == ledger["route_projection_digest"]
            and result["expected_slot_digest"]
                == ledger["slot_projection_digest"]
            and all(type(result[name]) is str
                    and _SHA256.fullmatch(result[name]) is not None
                    for name in (
                        "reasoned_structural_membership_digest",
                        "expected_structural_membership_digest",
                        "reasoned_route_membership_digest",
                        "expected_route_membership_digest",
                        "reasoned_slot_digest", "expected_slot_digest",
                        "choice_identity_digest",
                        "domain_route_reason_identity_digest",
                    ))
            and type(result["reasoned_slot_object_kinds"]) is list
            and result["reasoned_slot_object_kinds"]
                == sorted(set(result["reasoned_slot_object_kinds"]))
            and all(type(kind) is str and kind
                    for kind in result["reasoned_slot_object_kinds"]),
            "FACET_REASON_PROJECTION_BINDING_DIFFERS",
        )
    if result["status"] == "PASS":
        _require(
            result["reason_completeness_status"] == "PASS"
            and result["facet_choice_reason_status"] == "PASS"
            and result["domain_route_reason_status"] == "PASS"
            and result["structural_projection_status"] == "PASS"
            and result["route_projection_status"] == "PASS"
            and result["slot_projection_status"] == "PASS"
            and result["source_binding_status"] == "PASS"
            and type(result["ledger_digest"]) is str
            and _SHA256.fullmatch(result["ledger_digest"]) is not None
            and type(result["choice_identity_digest"]) is str
            and _SHA256.fullmatch(result["choice_identity_digest"])
                is not None
            and result["qualifying_facet_choice_reason_count"] == 130
            and result["facet_choice_reason_deficit"] == 0
            and result["qualifying_domain_route_reason_count"] == 18
            and result["domain_route_reason_deficit"] == 0
            and result["reasoned_structural_membership_count"] == 52
            and result["structural_membership_reason_deficit"] == 0
            and result["reasoned_route_membership_count"] == 45
            and result["route_membership_reason_deficit"] == 0
            and result["reasoned_slot_count"] == 26
            and result["slot_reason_deficit"] == 0
            and result["reasoned_slot_object_kinds"]
                == sorted(kind.value for kind in ObjectKind)
            and result["reasoned_structural_membership_digest"]
                == result["expected_structural_membership_digest"]
            and result["reasoned_route_membership_digest"]
                == result["expected_route_membership_digest"]
            and result["reasoned_slot_digest"]
                == result["expected_slot_digest"]
            and result["blockers"] == [],
            "FACET_REASON_PASS_NOT_ESTABLISHED",
        )
    elif result["status"] == "UNKNOWN":
        _require(
            result["reason_completeness_status"] == "UNKNOWN"
            and result["source_binding_status"] == "PASS"
            and result["blockers"] != [],
            "FACET_REASON_UNKNOWN_INVALID",
        )
    else:
        _require(
            "FAIL" in {
                result["reason_completeness_status"],
                result["facet_choice_reason_status"],
                result["domain_route_reason_status"],
                result["structural_projection_status"],
                result["route_projection_status"],
                result["slot_projection_status"],
                result["source_binding_status"],
            }
            and result["blockers"] != [],
            "FACET_REASON_FAIL_INVALID",
        )
    partition = {
        "facet_direct_route_membership_count": 27,
        "facet_direct_route_membership_digest": ledger[
            "mapped_route_projection_digest"
        ],
        "domain_route_membership_count": 18,
        "domain_route_membership_digest": ledger[
            "unmatched_route_projection_digest"
        ],
        "route_union_membership_count": 45,
        "route_union_membership_digest": ledger["route_projection_digest"],
        "domain_route_reasons_digest": ledger["domain_route_reasons_digest"],
    }
    return {
        **result,
        "consumer_route_partition": partition,
        "consumer_route_partition_digest": (
            core_obligation_union.value_digest(partition)
        ),
    }


def _current_authority_selection(selection: Any) -> Any:
    """Replace trusted-selection evaluation time when it is a typed record."""
    if isinstance(
        selection,
        core_application_authority.QualifiedAuthorityReplaySelection,
    ):
        return dataclasses.replace(selection, evaluation_time=int(time.time()))
    return selection


def _structural_route_crosswalk(
        families: list[dict[str, Any]],
        tier1_identities: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe the bounded structural/route overlap without claiming closure."""
    structural = [
        {
            "object_kind": family["represented_kind"],
            "coordinate": member["coordinate"],
            "proposition_digest": member["proposition_digest"],
            "rule_digest": member["rule_digest"],
        }
        for family in families
        for member in family["members"]
    ]
    structural.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
    _require(len({(row["object_kind"], row["coordinate"])
                  for row in structural}) == len(structural),
             "INSTALLED_STRUCTURAL_DENOMINATOR_DUPLICATED")
    structural_by_id = {
        (row["object_kind"], row["coordinate"]): row for row in structural
    }
    route_by_id = {
        (row["object_kind"], row["coordinate"]): row
        for row in tier1_identities
    }
    shared = sorted(set(structural_by_id) & set(route_by_id))
    _require(all(
        structural_by_id[identity]["proposition_digest"]
            == route_by_id[identity]["proposition_digest"]
        for identity in shared
    ), "STRUCTURAL_ROUTE_CROSSWALK_CONTRADICTION")
    structural_only = sorted(set(structural_by_id) - set(route_by_id))
    route_only = sorted(set(route_by_id) - set(structural_by_id))
    return {
        "status": "NOT_ESTABLISHED",
        "shared_identity_consistency": "PASS",
        "structural_membership_count": len(structural),
        "route_tier1_membership_count": len(tier1_identities),
        "shared_identity_count": len(shared),
        "structural_only_identity_count": len(structural_only),
        "route_only_identity_count": len(route_only),
        "structural_identity_digest": core_obligation_union.value_digest(
            structural
        ),
        "route_identity_digest": core_obligation_union.value_digest(
            tier1_identities
        ),
        "shared_identity_digest": core_obligation_union.value_digest([
            {"object_kind": kind, "coordinate": coordinate}
            for kind, coordinate in shared
        ]),
        "claim_boundary": (
            "Matching identities establish only consistency on the observed "
            "intersection; the non-equal denominators have no authenticated "
            "complete crosswalk."
        ),
    }


def _objective_inventory_crosscheck(
        inventory: dict[str, Any]) -> dict[str, Any]:
    """Cross-check two installed catalogs while preserving semantic UNKNOWN."""
    catalog = polish.polish_catalog()
    routes = catalog.get("routes")
    _require(type(routes) is list
             and catalog.get("objective_inventory_closure")
                 in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED"),
             "OBJECTIVE_INVENTORY_INVALID")
    registered = {
        (cell["object_kind"], member["coordinate"])
        for cell in inventory["family_cells"]
        for member in cell["registered_route_memberships"]
    }
    catalog_identities = set()
    for route in routes:
        _require(type(route) is dict
                 and type(route.get("represented_kind_rule")) is str
                 and type(route.get("objective")) is str,
                 "OBJECTIVE_INVENTORY_INVALID")
        kind = route["represented_kind_rule"]
        if kind == "externally_selected_admitted_kind":
            kind = "OBJECT"
        catalog_identities.add((kind, route["objective"]))
    unregistered = sorted(catalog_identities - registered)
    missing_from_catalog = sorted(registered - catalog_identities)
    _require(not missing_from_catalog,
             "OBJECTIVE_ROUTE_REGISTRY_CONTRADICTION")
    return {
        "status": catalog["objective_inventory_closure"],
        "catalog_digest": core_obligation_union.value_digest(catalog),
        "catalog_route_count": len(catalog_identities),
        "installed_route_membership_count": len(registered),
        "unregistered_candidate_status": (
            "DISCOVERED" if unregistered else "UNKNOWN"
        ),
        "unregistered_candidate_count": len(unregistered),
        "unregistered_candidate_identity_digest": (
            core_obligation_union.value_digest([
                {"object_kind": kind, "coordinate": coordinate}
                for kind, coordinate in unregistered
            ])
        ),
        "claim_boundary": (
            "Catalog equality is not proof that every repository, package, "
            "application programming interface, command-line interface, schema, "
            "or dispatch surface has been classified."
        ),
    }


def _repository_package_estate_summary() -> dict[str, Any]:
    """Expose the unavailable independent estate proof; never synthesize PASS."""
    return {
        "status": "NOT_ESTABLISHED",
        "independently_pinned_census": "ABSENT",
        "all_tracked_byte_census": "NOT_ESTABLISHED",
        "package_surface_closure": "NOT_ESTABLISHED",
        "public_api_cli_schema_closure": "NOT_ESTABLISHED",
        "registry_candidate_classification": "UNKNOWN",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "independent_authority_status": "NOT_ESTABLISHED",
        "per_obligation_replay_status": "NOT_ESTABLISHED",
        "claim_boundary": (
            "The installed route registry is not an authenticated census of the "
            "complete repository/package estate."
        ),
    }


def _denominators(object_id: str) -> dict[str, Any]:
    inventory = core_tier_progression.installed_core_route_inventory()
    _require(inventory.get("status") == "PASS", "INSTALLED_ROUTE_INVENTORY_NOT_PASS")
    cells = inventory.get("family_cells")
    _require(type(cells) is list, "INSTALLED_ROUTE_INVENTORY_INVALID")
    _require(inventory.get("family_cell_count") == len(cells)
             and inventory.get("family_cell_count")
                 == inventory.get("object_kind_count") * inventory.get("tier_count")
             and inventory.get("registered_route_membership_count")
                 == sum(row.get("registered_route_membership_count", -1)
                        for row in cells if type(row) is dict),
             "INSTALLED_ROUTE_INVENTORY_TOTAL_DIFFERS")
    selected: dict[int, dict[str, Any]] = {}
    for row in cells:
        if type(row) is dict and row.get("object_kind") == "VERIFIER" \
                and row.get("tier") in (1, 2):
            tier = row["tier"]
            _require(tier not in selected, "INSTALLED_DENOMINATOR_DUPLICATED")
            selected[tier] = row
    _require(set(selected) == {1, 2}, "INSTALLED_DENOMINATOR_MISSING")
    for tier, row in selected.items():
        memberships = row.get("registered_route_memberships")
        _require(type(memberships) is list and memberships
                 and row.get("registered_route_membership_count") == len(memberships)
                 and row.get("tier_name") == core_tier_progression.CoreTier(tier).name,
                 "INSTALLED_DENOMINATOR_INVALID")

    complete_tiers: dict[str, dict[str, Any]] = {}
    for tier in (1, 2):
        tier_cells = [row for row in cells if type(row) is dict
                      and row.get("tier") == tier]
        identities = [
            {
                "object_kind": row["object_kind"],
                "tier": tier,
                "coordinate": member["coordinate"],
                "proposition_digest": member["proposition_digest"],
                "semantic_version": member["semantic_version"],
                "certificate_schema_version": member[
                    "certificate_schema_version"
                ],
                "checking_mechanism": member["checking_mechanism"],
                "scope": member["scope"],
            }
            for row in tier_cells
            for member in row.get("registered_route_memberships", [])
            if type(member) is dict
        ]
        identities.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
        expected_count = inventory["registered_route_membership_count_by_tier"][
            str(tier)
        ]
        _require(len(tier_cells) == inventory["object_kind_count"]
                 and len(identities) == expected_count
                 and len({(row["object_kind"], row["coordinate"])
                          for row in identities}) == len(identities),
                 "INSTALLED_COMPLETE_TIER_DENOMINATOR_INVALID")
        mechanisms = sorted({
            row["checking_mechanism"] for row in identities
        })
        complete_tiers[str(tier)] = {
            "tier": tier,
            "tier_name": core_tier_progression.CoreTier(tier).name,
            "family_cell_count": len(tier_cells),
            "registered_route_membership_count": len(identities),
            "unique_checking_mechanism_count": len(mechanisms),
            "unique_checking_mechanism_digest": (
                core_obligation_union.value_digest(mechanisms)
            ),
            "membership_identities": identities,
            "membership_identity_digest": core_obligation_union.value_digest(
                identities
            ),
        }

    facets = {
        **core_tier_progression.verifier_tier1_self_application_obligations(
            object_id=object_id,
        ),
        "registered_route_membership_count": selected[1][
            "registered_route_membership_count"
        ],
        "registered_route_memberships": selected[1][
            "registered_route_memberships"
        ],
    }
    definitions = application_requirements.installed_rules().get("rules")
    families = application_requirements.installed_families(
        [kind.value for kind in ObjectKind]
    )
    _require(type(definitions) is list and type(families) is list,
             "INSTALLED_STRUCTURAL_DENOMINATOR_INVALID")
    memberships = sum(len(row["members"]) for row in families)
    _require(facets.get("definition_count") == len(facets.get("definitions", []))
             and facets.get("instantiated_obligation_count")
                 == len(facets.get("instantiated_obligations", []))
             and facets.get("definition_denominator_status") == "PASS",
             "INSTALLED_FACETS_DENOMINATOR_INVALID")
    dynamics = {
        "tier": 2,
        "tier_name": selected[2]["tier_name"],
        "object_kind": "VERIFIER",
        "denominator_status": selected[2]["denominator_status"],
        "registered_route_membership_count": selected[2][
            "registered_route_membership_count"
        ],
        "registered_route_memberships": selected[2]["registered_route_memberships"],
        "normative_full_family_closure": selected[2][
            "normative_full_family_closure"
        ],
    }
    # V2 derives installed closure from exact registry identities and catalog
    # bindings.  This is deliberately distinct from repository/package estate
    # closure, which remains a separate gate below.
    crosswalk = _structural_route_crosswalk(
        families, complete_tiers["1"]["membership_identities"]
    )
    installed_closure = self_polish_native_replay.installed_registry_closure()
    _require(installed_closure.get("status") == "PASS"
             and installed_closure.get("structural_membership_count")
                 == memberships
             and installed_closure.get("tier1_route_membership_count")
                 == complete_tiers["1"]["registered_route_membership_count"]
             and installed_closure.get("tier2_route_membership_count")
                 == complete_tiers["2"]["registered_route_membership_count"],
             "INSTALLED_REGISTRY_CLOSURE_INVALID")
    crosswalk.update({
        "status": installed_closure["structural_route_crosswalk_status"],
        "closure_digest": installed_closure["closure_digest"],
        "scope": installed_closure["scope"],
        "claim_boundary": installed_closure["claim_boundary"],
    })
    objective_inventory = _objective_inventory_crosscheck(inventory)
    objective_inventory.update({
        "status": installed_closure["objective_inventory_closure"],
        "installed_registry_closure_digest": installed_closure[
            "closure_digest"
        ],
        "scope": installed_closure["scope"],
        "claim_boundary": installed_closure["claim_boundary"],
    })
    return {
        "installed_route_inventory_digest": core_obligation_union.value_digest(inventory),
        "installed_route_family_cell_count": inventory["family_cell_count"],
        "installed_route_membership_count": inventory[
            "registered_route_membership_count"
        ],
        "installed_object_kind_count": inventory["object_kind_count"],
        "installed_tier_count": inventory["tier_count"],
        "installed_structural_definition_count": len(definitions),
        "installed_structural_membership_count": memberships,
        "installed_route_normative_closure": installed_closure[
            "installed_route_normative_closure"
        ],
        "objective_inventory_closure": objective_inventory["status"],
        "objective_inventory_digest": objective_inventory["catalog_digest"],
        "objective_inventory_crosscheck": objective_inventory,
        "structural_route_crosswalk_closure": crosswalk["status"],
        "structural_route_crosswalk": crosswalk,
        "installed_registry_closure": installed_closure,
        "complete_tiers": complete_tiers,
        "facets": facets,
        "dynamics": dynamics,
    }


def _base_report(tier: int, denominators: dict[str, Any]) -> dict[str, Any]:
    estate = _repository_package_estate_summary()
    return {
        "schema_version": REPORT_SCHEMA,
        "tier": tier,
        "tier_name": core_tier_progression.CoreTier(tier).name,
        "status": "UNKNOWN",
        "selected_tier_status": "UNKNOWN",
        "source_binding_status": "UNKNOWN",
        "applicability_status": "NOT_ESTABLISHED",
        "authority_status": "NOT_ESTABLISHED",
        "dependency_status": "NOT_ESTABLISHED",
        "interaction_status": "NOT_ESTABLISHED",
        "whole_tier_conformance": "NOT_ESTABLISHED",
        # These are downstream projections of the Tier-1 reason inventory.
        # Installed registry closure alone cannot promote them in this report.
        "installed_route_normative_closure": "NOT_ESTABLISHED",
        "objective_inventory_closure": "NOT_ESTABLISHED",
        "structural_route_crosswalk_closure": "NOT_ESTABLISHED",
        "repository_package_estate_closure": estate["status"],
        "post_replay_full_source_recapture": "NOT_ESTABLISHED",
        "full_application_status": "UNKNOWN",
        "polished": False,
        "release_authorized": False,
        "source_coordinate": None,
        "source_coordinate_digest": None,
        "installed_denominators": denominators,
        "union_validation": None,
        "application_authority": None,
        "complete_tier_evidence_replay": None,
        "complete_tier_ledger": None,
        "complete_self_representation": None,
        "tier1_facet_choice_reasons": None,
        "candidate_estate_census": None,
        "candidate_estate_applicability": None,
        "candidate_estate_authority": None,
        "candidate_estate_evidence": None,
        "repository_package_estate": estate,
        "pre_replay_source_recapture": None,
        "post_replay_source_recapture": None,
        "retained_core_subset": None,
        "core_self_polish_attempt": None,
        "core_progression_attempt": None,
        "declared_dependencies": None,
        "blockers": [],
        "mechanism_digest": mechanism_digest(),
        "claim_boundary": BOUNDARY,
    }


def _candidate_estate_inputs(*, source_root: str | Path,
        source_coordinate: dict[str, Any], denominators: dict[str, Any],
        expected_repository: str | None, expected_revision: str | None,
        expected_estate_digest: str | None,
        applicability_ledger_bytes: bytes | None,
        expected_applicability_ledger_digest: str | None,
        ) -> tuple[
            dict[str, Any] | None,
            dict[str, Any] | None,
            dict[str, Any] | None,
            bytes | None,
            str | None,
        ]:
    """Recompute and pin D's census without treating declarations as proof."""
    census_selection = (
        expected_repository, expected_revision, expected_estate_digest
    )
    ledger_selection = (
        applicability_ledger_bytes, expected_applicability_ledger_digest
    )
    auto_selected = False
    if all(value is None for value in census_selection):
        _require(all(value is None for value in ledger_selection),
                 "CANDIDATE_ESTATE_SELECTION_INCOMPLETE")
        if not Path(source_root).is_dir():
            return None, None, None, None, None
        coordinate = self_polish_estate._git_coordinate(
            Path(source_root).resolve(strict=True)
        )
        expected_repository = coordinate["repository"]
        expected_revision = coordinate["revision"]
        auto_selected = True
    else:
        _require(all(value is not None for value in census_selection),
                 "CANDIDATE_ESTATE_SELECTION_INCOMPLETE")
    _require(expected_revision == source_coordinate["source_head"],
             "CANDIDATE_ESTATE_SOURCE_OR_DIGEST_PIN_INVALID")
    observed = self_polish_estate.build_candidate_estate(
        source_root,
        expected_repository=expected_repository,
        expected_revision=expected_revision,
    )
    if auto_selected:
        expected_estate_digest = observed.get("estate_digest")
    _require(type(expected_estate_digest) is str
             and _SHA256.fullmatch(expected_estate_digest) is not None,
             "CANDIDATE_ESTATE_SOURCE_OR_DIGEST_PIN_INVALID")
    _require(type(observed) is dict and set(observed) == {
        "schema_version", "mechanical_census_status",
        "semantic_applicability_status", "full_estate_closure", "polished",
        "release_authorized", "source_coordinate", "pre_source_census",
        "post_source_census", "required_categories", "category_summaries",
        "structural_route_crosswalk", "candidate_count",
        "candidate_universe_digest", "candidates", "applicability_ledger",
        "claim_boundary", "estate_digest",
    }, "CANDIDATE_ESTATE_RESULT_INVALID")
    body = {
        key: value for key, value in observed.items()
        if key != "estate_digest"
    }
    _require(observed["estate_digest"]
                 == self_polish_estate.value_digest(body)
             and observed["estate_digest"] == expected_estate_digest,
             "CANDIDATE_ESTATE_DIGEST_DIFFERS")
    source = observed["source_coordinate"]
    _require(type(source) is dict
             and source.get("repository") == expected_repository
             and source.get("revision") == expected_revision
             and source.get("revision") == source_coordinate["source_head"]
             and source.get("candidate_source_census_digest")
                 == observed.get("pre_source_census", {}).get("census_digest")
             and source.get("candidate_source_file_count")
                 == observed.get("pre_source_census", {}).get("file_count")
             and source.get("candidate_source_byte_count")
                 == observed.get("pre_source_census", {}).get("total_bytes")
             and source.get("tracked_file_count")
                 == observed.get("pre_source_census", {}).get(
                     "provenance_counts", {}
                 ).get("GIT_TRACKED")
             and source.get("untracked_nonignored_file_count")
                 == observed.get("pre_source_census", {}).get(
                     "provenance_counts", {}
                 ).get("WORKTREE_UNTRACKED_NONIGNORED")
             and observed.get("pre_source_census")
                 == observed.get("post_source_census"),
             "CANDIDATE_ESTATE_SOURCE_DIFFERS")
    candidates = observed["candidates"]
    summaries = observed["category_summaries"]
    _require(observed["schema_version"] == self_polish_estate.ESTATE_SCHEMA
             and observed["mechanical_census_status"] == "PASS"
             and observed["semantic_applicability_status"]
                 == "NOT_ESTABLISHED"
             and observed["full_estate_closure"] == "NOT_ESTABLISHED"
             and observed["polished"] is False
             and observed["release_authorized"] is False
             and observed["applicability_ledger"] is None
             and observed["required_categories"]
                 == list(self_polish_estate.REQUIRED_CATEGORIES)
             and type(candidates) is list
             and observed["candidate_count"] == len(candidates)
             and observed["candidate_universe_digest"]
                 == self_polish_estate.value_digest(candidates)
             and type(summaries) is list
             and [row.get("category") for row in summaries]
                 == list(self_polish_estate.REQUIRED_CATEGORIES)
             and all(row.get("mechanical_status") == "PASS"
                     and row.get("semantic_status") == "NOT_ESTABLISHED"
                     and type(row.get("candidate_count")) is int
                     and row["candidate_count"] > 0
                     for row in summaries)
             and sum(row["candidate_count"] for row in summaries)
                 == len(candidates),
             "CANDIDATE_ESTATE_RESULT_INVALID")
    crosswalk = observed["structural_route_crosswalk"]
    installed_crosswalk = denominators["structural_route_crosswalk"]
    _require(type(crosswalk) is dict
             and crosswalk.get("status") == "NOT_ESTABLISHED"
             and all(crosswalk.get(field) == installed_crosswalk.get(field)
                     for field in (
                         "structural_membership_count",
                         "route_tier1_membership_count",
                         "shared_identity_count",
                         "structural_only_identity_count",
                         "route_only_identity_count",
                     )),
             "CANDIDATE_ESTATE_CROSSWALK_DIFFERS")
    summary = {
        "schema_version": observed["schema_version"],
        "mechanical_census_status": "PASS",
        "semantic_applicability_status": "NOT_ESTABLISHED",
        "full_estate_closure": "NOT_ESTABLISHED",
        "source_coordinate": source,
        "candidate_count": observed["candidate_count"],
        "candidate_universe_digest": observed["candidate_universe_digest"],
        "estate_digest": observed["estate_digest"],
        "external_estate_digest_pin": (
            "DERIVED_CURRENT_SOURCE" if auto_selected else "MATCHED"
        ),
        "required_categories": observed["required_categories"],
        "required_categories_digest": self_polish_estate.value_digest(
            observed["required_categories"]
        ),
        "category_summaries_digest": self_polish_estate.value_digest(
            summaries
        ),
        "category_counts": {
            row["category"]: row["candidate_count"] for row in summaries
        },
        "structural_route_crosswalk": crosswalk,
        "structural_route_crosswalk_digest": self_polish_estate.value_digest(
            crosswalk
        ),
        "claim_boundary": observed["claim_boundary"],
    }
    if all(value is None for value in ledger_selection):
        if not auto_selected:
            return summary, None, observed, None, None
        ledger = self_polish_estate.applicability_ledger_template(observed)
        candidates_by_id = {
            row["candidate_id"]: row for row in observed["candidates"]
        }
        for row in ledger["rows"]:
            native_applicability = (
                self_polish_estate_native_evidence.native_applicability_status(
                    candidates_by_id[row["candidate_id"]]
                )
            )
            row.update(
                applicability_status=native_applicability,
                justification=(
                    "Installed native category registry derives applicability; "
                    "independent authority remains not established."
                ),
            )
        ledger.pop("ledger_digest")
        ledger["ledger_digest"] = self_polish_estate.value_digest(ledger)
        applicability_ledger_bytes = self_polish_estate.canonical_bytes(
            ledger
        )
        expected_applicability_ledger_digest = ledger["ledger_digest"]
    _require(applicability_ledger_bytes is not None
             and expected_applicability_ledger_digest is not None,
             "CANDIDATE_ESTATE_APPLICABILITY_SELECTION_INCOMPLETE")
    applicability = self_polish_estate.validate_applicability_ledger(
        observed,
        applicability_ledger_bytes,
        expected_ledger_digest=expected_applicability_ledger_digest,
    )
    _require(type(applicability) is dict
             and applicability.get("schema_version")
                 == self_polish_estate.APPLICABILITY_RESULT_SCHEMA
             and applicability.get("mechanical_validation_status") == "PASS"
             and applicability.get("candidate_count") == len(candidates)
             and applicability.get("candidate_universe_digest")
                 == observed["candidate_universe_digest"]
             and applicability.get("caller_pass_authentication")
                 == "NOT_ESTABLISHED"
             and applicability.get("semantic_applicability_status")
                 == "NOT_ESTABLISHED"
             and applicability.get("full_estate_closure")
                 == "NOT_ESTABLISHED",
             "CANDIDATE_ESTATE_APPLICABILITY_RESULT_INVALID")
    return (
        summary,
        applicability,
        observed,
        applicability_ledger_bytes,
        expected_applicability_ledger_digest,
    )


def _parse(raw: bytes, code: str, *, max_bytes: int = MAX_INPUT_BYTES) -> Any:
    _require(type(max_bytes) is int and max_bytes > 0, code)
    _require(type(raw) is bytes and len(raw) <= max_bytes, code)
    try:
        return strict_json_loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise _ContractError(code) from exc


def _derived_estate_evidence_inputs(
        *, estate: dict[str, Any], ledger_bytes: bytes,
        expected_ledger_digest: str,
        authority_subject: dict[str, Any],
        ) -> tuple[bytes, str, str, dict[str, bytes]]:
    """Build native replay requests for every command-selected candidate.

    These artifacts request deterministic native replay.  They do not supply
    semantic authority receipts and therefore cannot promote unresolved
    applicability or independent authority to PASS.
    """

    manifest = self_polish_estate_evidence.evidence_manifest_template(
        estate,
        ledger_bytes,
        expected_ledger_digest=expected_ledger_digest,
        estate_authority_subject=authority_subject,
    )
    candidates = {
        row["candidate_id"]: row for row in estate["candidates"]
    }
    artifacts: dict[str, bytes] = {}
    for row in manifest["rows"]:
        if row["applicability_disposition"] != "APPLICABLE":
            continue
        artifact = self_polish_estate_native_evidence.evidence_artifact_template(
            estate, candidates[row["candidate_id"]]
        )
        raw = self_polish_estate_native_evidence.canonical_bytes(artifact)
        artifacts[row["candidate_id"]] = raw
        row["evidence_disposition"] = "PASS"
        row["evidence_artifact_digest"] = (
            self_polish_estate_native_evidence.bytes_digest(raw)
        )
        row["justification"] = (
            "Command-selected exact source candidate submitted to the "
            "installed native replay mechanism; independent semantic "
            "authority remains not established."
        )
    manifest.pop("manifest_digest")
    manifest["manifest_digest"] = self_polish_estate_evidence.value_digest(
        manifest
    )
    manifest_bytes = self_polish_estate_evidence.canonical_bytes(manifest)
    return (
        manifest_bytes,
        manifest["manifest_digest"],
        self_polish_estate_evidence.mechanism_digest(),
        artifacts,
    )


def _expected_tier1_obligations(
        denominators: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    identities = denominators["complete_tiers"]["1"]["membership_identities"]
    identifiers = [
        f"{row['object_kind']}:{row['coordinate']}" for row in identities
    ]
    _require(len(identifiers) == len(set(identifiers))
             == denominators["complete_tiers"]["1"][
                 "registered_route_membership_count"
             ],
             "INSTALLED_TIER1_EVIDENCE_DENOMINATOR_INVALID")
    return {
        identifier: self_polish_evidence.CASE_KIND_ORDER
        for identifier in identifiers
    }


def _replay_tier_evidence(manifest_bytes: bytes | None, *, tier: int,
        expected_manifest_digest: str | None,
        expected_mechanism_digest: str | None,
        source_root: str | Path,
        source_coordinate: dict[str, Any],
        denominators: dict[str, Any]) -> dict[str, Any] | None:
    selected = (
        manifest_bytes, expected_manifest_digest, expected_mechanism_digest
    )
    if all(value is None for value in selected):
        if not Path(source_root).is_dir():
            return None
        manifest_bytes = (
            self_polish_native_replay.build_installed_replay_manifest(
                tier,
                source_root,
                source_coordinate_digest=(
                    core_obligation_union.value_digest(source_coordinate)
                ),
            )
        )
        expected_manifest_digest = _digest(manifest_bytes)
        expected_mechanism_digest = (
            self_polish_native_replay.mechanism_digest()
        )
        selected = (
            manifest_bytes,
            expected_manifest_digest,
            expected_mechanism_digest,
        )
    _require(all(value is not None for value in selected),
             "COMPLETE_TIER_EVIDENCE_SELECTION_INCOMPLETE")
    _require(
        expected_mechanism_digest
            == self_polish_native_replay.mechanism_digest(),
        "COMPLETE_TIER_EVIDENCE_MECHANISM_DIFFERS",
    )
    receipt = self_polish_native_replay.replay_native_obligations(
        manifest_bytes,
        source_root,
        tier=tier,
        expected_manifest_digest=expected_manifest_digest,
        expected_source_coordinate_digest=core_obligation_union.value_digest(
            source_coordinate
        ),
    )
    _require(type(receipt) is dict
             and receipt.get("schema_version")
                 == self_polish_native_replay.RECEIPT_SCHEMA
             and receipt.get("status") in ("PASS", "FAIL", "UNKNOWN")
             and type(receipt.get("invalidators")) is list,
             "COMPLETE_TIER_EVIDENCE_RECEIPT_INVALID")
    if receipt["status"] != "PASS":
        return receipt

    expected = denominators["complete_tiers"][str(tier)]
    registry = self_polish_native_replay.installed_native_replay_registry()
    _require(receipt["invalidators"] == []
             and receipt.get("tier") == tier
             and receipt.get("polished") is False
             and receipt.get("release_authority") == "NONE"
             and receipt.get("whole_tier_conformance") == "NOT_ESTABLISHED"
             and receipt.get("manifest_digest") == expected_manifest_digest
             and receipt.get("source_coordinate_digest")
                 == core_obligation_union.value_digest(source_coordinate)
             and receipt.get("registry_digest") == registry["registry_digest"]
             and receipt.get("membership_count")
                 == expected["registered_route_membership_count"]
             and receipt.get("case_count")
                 == expected["registered_route_membership_count"] * 3,
             "COMPLETE_TIER_EVIDENCE_RECEIPT_INVALID")
    memberships = receipt.get("memberships")
    _require(type(memberships) is list
             and len(memberships)
                 == expected["registered_route_membership_count"],
             "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_DIFFERS")
    expected_by_id = {
        f"{row['object_kind']}:{row['coordinate']}": row
        for row in expected["membership_identities"]
    }
    observed: dict[str, str] = {}
    for membership in memberships:
        _require(type(membership) is dict
                 and set(membership) == {"obligation_id", "membership",
                                        "cases", "status",
                                        "native_replay_digest"},
                 "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_INVALID")
        identifier = membership["obligation_id"]
        _require(identifier in expected_by_id
                 and identifier not in observed
                 and membership["status"] == "PASS"
                 and membership["membership"] == expected_by_id[identifier]
                 and type(membership["native_replay_digest"]) is str
                 and _SHA256.fullmatch(membership["native_replay_digest"])
                     is not None,
                 "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_DIFFERS")
        cases = membership["cases"]
        _require(type(cases) is list and len(cases) == 3
                 and [case.get("case_kind") if type(case) is dict else None
                      for case in cases]
                     == list(self_polish_native_replay.CASE_KINDS),
                 "COMPLETE_TIER_EVIDENCE_CASE_DIFFERS")
        for case in cases:
            _require(set(case) == {"case_kind", "expected_native_status",
                                   "native_status", "status",
                                   "native_result_digest",
                                   "mechanism_source_path",
                                   "mechanism_source_digest"}
                     and case["status"] == "PASS"
                     and case["native_status"]
                         == case["expected_native_status"]
                     and case["expected_native_status"] in (
                         "PASS", "FAIL", "UNKNOWN"
                     )
                     and type(case["mechanism_source_path"]) is str
                     and type(case["mechanism_source_digest"]) is str,
                     "COMPLETE_TIER_EVIDENCE_CASE_DIFFERS")
        observed[identifier] = membership["native_replay_digest"]
    _require(set(observed) == set(expected_by_id),
             "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_DIFFERS")
    _require(type(receipt.get("receipt_digest")) is str
             and receipt["receipt_digest"] == core_obligation_union.value_digest({
                 key: value for key, value in receipt.items()
                 if key != "receipt_digest"
             }),
             "COMPLETE_TIER_EVIDENCE_RECEIPT_DIGEST_DIFFERS")
    return receipt


def _derived_complete_tier_ledger(*, tier: int,
        source_coordinate: dict[str, Any], denominators: dict[str, Any],
        evidence_replay: dict[str, Any] | None) -> dict[str, Any] | None:
    """Derive a ledger from native replay; accept no caller verdict strings."""
    if evidence_replay is None:
        return None
    expected = denominators["complete_tiers"][str(tier)]
    replay_memberships = evidence_replay.get("memberships")
    _require(type(replay_memberships) is list,
             "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_DIFFERS")
    entries = []
    for replay in replay_memberships:
        _require(type(replay) is dict and type(replay.get("membership")) is dict
                 and type(replay.get("cases")) is list,
                 "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_INVALID")
        membership = replay["membership"]
        sources = sorted({
            (case["mechanism_source_path"], case["mechanism_source_digest"])
            for case in replay["cases"]
            if type(case) is dict
        })
        _require(len(sources) == 1,
                 "COMPLETE_TIER_LEDGER_IMPLEMENTATION_INVALID")
        source_path, source_digest = sources[0]
        entry = {
            "obligation_id": replay["obligation_id"],
            "membership": membership,
            "status": replay["status"],
            "native_replay_digest": replay["native_replay_digest"],
            "implementation": {
                "checking_mechanism": membership["checking_mechanism"],
                "source_path": source_path,
                "source_digest": source_digest,
                "symbol": membership["checking_mechanism"].rsplit(".", 1)[1],
            },
            "case_outcomes": [
                {
                    "case_kind": case["case_kind"],
                    "native_status": case["native_status"],
                    "native_result_digest": case["native_result_digest"],
                }
                for case in replay["cases"]
            ],
        }
        entry["entry_digest"] = core_obligation_union.value_digest(entry)
        entries.append(entry)
    expected_ids = [
        f"{row['object_kind']}:{row['coordinate']}"
        for row in expected["membership_identities"]
    ]
    _require([row["obligation_id"] for row in entries] == sorted(expected_ids),
             "COMPLETE_TIER_LEDGER_DENOMINATOR_DIFFERS")
    status = evidence_replay.get("status")
    body = {
        "schema_version": TIER_LEDGER_SCHEMA,
        "derivation": "NATIVE_REPLAY_RECEIPT",
        "tier": tier,
        "tier_name": expected["tier_name"],
        "status": status,
        "source_coordinate_digest": core_obligation_union.value_digest(
            source_coordinate
        ),
        "installed_inventory_digest": denominators[
            "installed_route_inventory_digest"
        ],
        "tier_family_cell_count": expected["family_cell_count"],
        "tier_membership_count": expected["registered_route_membership_count"],
        "membership_identity_digest": expected["membership_identity_digest"],
        "replay_receipt_digest": evidence_replay["receipt_digest"],
        "mechanical_replay_status": status,
        "entries": entries,
    }
    body["ledger_digest"] = core_obligation_union.value_digest(body)
    return body


def _derived_self_representation(*, tier: int,
        source_coordinate: dict[str, Any], denominators: dict[str, Any],
        ledger: dict[str, Any] | None,
        evidence_replay: dict[str, Any] | None,
        prior_whole_tier_report_digest: str | None,
        estate_evidence_result: dict[str, Any] | None,
        facet_reason_assessment: dict[str, Any] | None,
        ) -> dict[str, Any] | None:
    """Derive Verifier's representation from replayed artifacts only."""
    if ledger is None or evidence_replay is None:
        return None
    dependencies = [ledger.get("status"), evidence_replay.get("status")]
    estate_digest = None
    reason_assessment_digest = None
    reason_ledger_digest = None
    reason_choice_digest = None
    reason_structural_digest = None
    reason_route_digest = None
    reason_slot_digest = None
    reason_domain_status = None
    reason_domain_identity_digest = None
    reason_domain_reasons_digest = None
    reason_partition: dict[str, Any] = {}
    reason_partition_digest = None
    if type(facet_reason_assessment) is dict:
        dependencies.extend(
            facet_reason_assessment.get(name) for name in (
                "status", "reason_completeness_status",
                "facet_choice_reason_status", "domain_route_reason_status",
                "structural_projection_status", "route_projection_status",
                "slot_projection_status", "source_binding_status",
            )
        )
        reason_assessment_digest = facet_reason_assessment.get(
            "assessment_digest"
        )
        reason_ledger_digest = facet_reason_assessment.get("ledger_digest")
        reason_choice_digest = facet_reason_assessment.get(
            "choice_identity_digest"
        )
        reason_structural_digest = facet_reason_assessment.get(
            "reasoned_structural_membership_digest"
        )
        reason_route_digest = facet_reason_assessment.get(
            "reasoned_route_membership_digest"
        )
        reason_slot_digest = facet_reason_assessment.get(
            "reasoned_slot_digest"
        )
        reason_domain_status = facet_reason_assessment.get(
            "domain_route_reason_status"
        )
        reason_domain_identity_digest = facet_reason_assessment.get(
            "domain_route_reason_identity_digest"
        )
        reason_partition = facet_reason_assessment.get(
            "consumer_route_partition", {}
        )
        reason_partition_digest = facet_reason_assessment.get(
            "consumer_route_partition_digest"
        )
        reason_domain_reasons_digest = reason_partition.get(
            "domain_route_reasons_digest"
        )
    else:
        dependencies.append("UNKNOWN")
    if tier == 1:
        if type(estate_evidence_result) is dict:
            estate_digest = estate_evidence_result.get("result_digest")
            dependencies.extend(
                estate_evidence_result.get(name) for name in (
                    "native_self_verification_status",
                    "native_semantic_applicability_status",
                    "native_per_candidate_evidence_status",
                )
            )
        else:
            dependencies.append("UNKNOWN")
    if tier == 2:
        dependencies.append("PASS" if prior_whole_tier_report_digest else "UNKNOWN")
    status = (
        "FAIL" if "FAIL" in dependencies else
        "PASS" if dependencies and all(item == "PASS" for item in dependencies)
        else "UNKNOWN"
    )
    body = {
        "schema_version": SELF_REPRESENTATION_SCHEMA,
        "derivation": "INSTALLED_REGISTRY_AND_NATIVE_REPLAY",
        "status": status,
        "subject": {"object_id": "verifier-core-self", "object_kind": "VERIFIER"},
        "source_coordinate_digest": core_obligation_union.value_digest(
            source_coordinate
        ),
        "installed_inventory_digest": denominators[
            "installed_route_inventory_digest"
        ],
        "installed_registry_closure_digest": denominators[
            "installed_registry_closure"
        ]["closure_digest"],
        "represented_tiers": list(range(1, tier + 1)),
        "tier_ledger_digest": ledger["ledger_digest"],
        "native_replay_receipt_digest": evidence_replay["receipt_digest"],
        "estate_evidence_result_digest": estate_digest,
        "tier1_facet_reason_assessment_digest": reason_assessment_digest,
        "tier1_facet_reason_ledger_digest": reason_ledger_digest,
        "tier1_facet_choice_identity_digest": reason_choice_digest,
        "tier1_reasoned_structural_membership_digest": (
            reason_structural_digest
        ),
        "tier1_reasoned_route_membership_digest": reason_route_digest,
        "tier1_reasoned_slot_digest": reason_slot_digest,
        "tier1_domain_route_reason_status": reason_domain_status,
        "tier1_domain_route_reason_identity_digest": (
            reason_domain_identity_digest
        ),
        "tier1_domain_route_reasons_digest": reason_domain_reasons_digest,
        "tier1_facet_direct_route_membership_count": reason_partition.get(
            "facet_direct_route_membership_count"
        ),
        "tier1_facet_direct_route_membership_digest": reason_partition.get(
            "facet_direct_route_membership_digest"
        ),
        "tier1_domain_route_membership_count": reason_partition.get(
            "domain_route_membership_count"
        ),
        "tier1_domain_route_membership_digest": reason_partition.get(
            "domain_route_membership_digest"
        ),
        "tier1_reason_route_union_membership_count": reason_partition.get(
            "route_union_membership_count"
        ),
        "tier1_reason_route_union_membership_digest": reason_partition.get(
            "route_union_membership_digest"
        ),
        "tier1_reason_route_partition_digest": reason_partition_digest,
        "prior_whole_tier_report_digest": prior_whole_tier_report_digest,
    }
    body["representation_digest"] = core_obligation_union.value_digest(body)
    return body


def _complete_tier_ledger(raw: bytes | None, *, expected_digest: str | None,
                          source_coordinate: dict[str, Any], tier: int,
                          denominators: dict[str, Any],
                          evidence_replay: dict[str, Any] | None = None,
                          ) -> dict[str, Any] | None:
    if raw is None and expected_digest is None:
        return None
    _require(raw is not None and expected_digest is not None,
             "COMPLETE_TIER_LEDGER_SELECTION_INCOMPLETE")
    value = _parse(raw, "COMPLETE_TIER_LEDGER_INVALID")
    _require(type(value) is dict, "COMPLETE_TIER_LEDGER_INVALID")
    required = {
        "schema_version", "tier", "tier_name", "source_coordinate",
        "source_coordinate_digest", "installed_inventory_digest",
        "installed_family_cell_count_total", "installed_membership_count_total",
        "tier_family_cell_count", "tier_membership_count", "entries",
        "ledger_digest",
    }
    _require(set(value) == required, "COMPLETE_TIER_LEDGER_FIELDS_DIFFER")
    stored_digest = value["ledger_digest"]
    body = {key: item for key, item in value.items() if key != "ledger_digest"}
    _require(type(stored_digest) is str
             and stored_digest == core_obligation_union.value_digest(body)
             and expected_digest == stored_digest,
             "COMPLETE_TIER_LEDGER_DIGEST_DIFFERS")
    expected = denominators["complete_tiers"][str(tier)]
    _require(value["schema_version"] == TIER_LEDGER_SCHEMA
             and value["tier"] == tier
             and value["tier_name"] == expected["tier_name"],
             "COMPLETE_TIER_LEDGER_TIER_DIFFERS")
    _require(value["source_coordinate"] == source_coordinate
             and value["source_coordinate_digest"]
                 == core_obligation_union.value_digest(source_coordinate),
             "COMPLETE_TIER_LEDGER_SOURCE_DIFFERS")
    _require(value["installed_inventory_digest"]
                 == denominators["installed_route_inventory_digest"]
             and value["installed_family_cell_count_total"]
                 == denominators["installed_route_family_cell_count"]
             and value["installed_membership_count_total"]
                 == denominators["installed_route_membership_count"]
             and value["tier_family_cell_count"] == expected["family_cell_count"]
             and value["tier_membership_count"]
                 == expected["registered_route_membership_count"],
             "COMPLETE_TIER_LEDGER_DENOMINATOR_DIFFERS")
    entries = value["entries"]
    _require(type(entries) is list and len(entries) == value["tier_membership_count"],
             "COMPLETE_TIER_LEDGER_DENOMINATOR_DIFFERS")
    entry_fields = {
        "membership", "applicability_status", "authority_status",
        "observation_status", "native_assessment_status",
        "provider_review_status", "native_assessment_digest",
        "obligation_id", "definition_source", "definition_version",
        "implementation", "evidence", "dependencies", "prerequisites",
        "applicability", "expected_behavior", "ownership",
        "provider_records", "implementation_status", "focused_validation",
        "independent_replay", "final_disposition", "justified_exclusion",
    }
    expected_by_key = {
        (row["object_kind"], row["coordinate"]): row
        for row in expected["membership_identities"]
    }
    observed: dict[tuple[str, str], dict[str, Any]] = {}
    verdicts: list[str] = []
    declared_pass_memberships = 0
    provider_state_counts: dict[str, int] = {}
    provider_review_status_counts: dict[str, int] = {}
    provider_coverage_exception_count = 0
    provider_coverage_exception_memberships = 0
    provider_fail_status_count = 0
    replay_memberships = {
        row["obligation_id"]: row
        for row in (evidence_replay or {}).get("memberships", [])
        if type(row) is dict and type(row.get("obligation_id")) is str
    }
    replay_bound_memberships = 0
    for entry in entries:
        _require(type(entry) is dict and set(entry) == entry_fields
                 and type(entry["membership"]) is dict,
                 "COMPLETE_TIER_LEDGER_ENTRY_INVALID")
        membership = entry["membership"]
        key = (membership.get("object_kind"), membership.get("coordinate"))
        _require(key in expected_by_key and key not in observed
                 and membership == expected_by_key[key],
                 "COMPLETE_TIER_LEDGER_MEMBERSHIP_DIFFERS")
        observed[key] = entry
        _require(entry["obligation_id"]
                     == f"{membership['object_kind']}:{membership['coordinate']}"
                 and entry["definition_source"] == {
                     "proposition_digest": membership["proposition_digest"],
                     "scope": membership["scope"],
                 }
                 and entry["definition_version"]
                     == membership["semantic_version"],
                 "COMPLETE_TIER_LEDGER_DEFINITION_DIFFERS")
        implementation = entry["implementation"]
        _require(type(implementation) is dict
                 and set(implementation)
                     == {"checking_mechanism", "files", "symbols"}
                 and implementation["checking_mechanism"]
                     == membership["checking_mechanism"]
                 and type(implementation["files"]) is list
                 and type(implementation["symbols"]) is list
                 and implementation["files"]
                 and implementation["symbols"]
                 and all(type(item) is str and item
                         for item in implementation["files"]
                         + implementation["symbols"]),
                 "COMPLETE_TIER_LEDGER_IMPLEMENTATION_INVALID")
        evidence = entry["evidence"]
        _require(type(evidence) is dict
                 and set(evidence) == {
                     "native_assessment_digest", "source_coordinate_digest",
                     "freshness", "sources",
                 }
                 and evidence["native_assessment_digest"]
                     == entry["native_assessment_digest"]
                 and evidence["source_coordinate_digest"]
                     == core_obligation_union.value_digest(source_coordinate)
                 and evidence["freshness"] in ("CURRENT", "STALE", "UNKNOWN")
                 and type(evidence["sources"]) is list
                 and evidence["sources"]
                 and all(type(item) is str and item
                         for item in evidence["sources"]),
                 "COMPLETE_TIER_LEDGER_EVIDENCE_INVALID")
        _require(type(entry["dependencies"]) is list
                 and type(entry["prerequisites"]) is list
                 and all(type(item) is str and item
                         for item in entry["dependencies"]
                         + entry["prerequisites"]),
                 "COMPLETE_TIER_LEDGER_DEPENDENCIES_INVALID")
        applicability = entry["applicability"]
        _require(type(applicability) is dict
                 and set(applicability)
                     == {"platform_status", "binding_status"},
                 "COMPLETE_TIER_LEDGER_APPLICABILITY_INVALID")
        expected_behavior = entry["expected_behavior"]
        _require(type(expected_behavior) is dict
                 and set(expected_behavior) == {"positive", "negative", "unknown"}
                 and all(type(item) is str and item
                         for item in expected_behavior.values()),
                 "COMPLETE_TIER_LEDGER_EXPECTED_BEHAVIOR_INVALID")
        ownership = entry["ownership"]
        _require(type(ownership) is dict
                 and set(ownership) == {"supervisor", "owner"}
                 and all(type(item) is str and item for item in ownership.values()),
                 "COMPLETE_TIER_LEDGER_OWNERSHIP_INVALID")
        provider_review_status = entry["provider_review_status"]
        _require(provider_review_status
                     in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED"),
                 "COMPLETE_TIER_LEDGER_VERDICT_INVALID")
        provider_review_status_counts[provider_review_status] = (
            provider_review_status_counts.get(provider_review_status, 0) + 1
        )
        providers = entry["provider_records"]
        _require(type(providers) is dict
                 and set(providers) == {"claude", "antigravity"}
                 and all(type(record) is dict
                         and set(record) == {"state", "receipt_digest"}
                         and record["state"] in (
                             "PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED",
                             "CLAUDE_PROVIDER_BLOCKED",
                             "ANTIGRAVITY_PROVIDER_BLOCKED",
                         )
                         and ((record["state"] == "PASS"
                               and type(record["receipt_digest"]) is str
                               and _SHA256.fullmatch(record["receipt_digest"])
                                   is not None)
                              or (record["state"] != "PASS"
                                  and record["receipt_digest"] is None))
                         for record in providers.values()),
                 "COMPLETE_TIER_LEDGER_PROVIDER_RECORD_INVALID")
        _require(providers["claude"]["state"]
                     != "ANTIGRAVITY_PROVIDER_BLOCKED"
                 and providers["antigravity"]["state"]
                     != "CLAUDE_PROVIDER_BLOCKED",
                 "COMPLETE_TIER_LEDGER_PROVIDER_RECORD_INVALID")
        for provider_name, record in providers.items():
            key = provider_name + ":" + record["state"]
            provider_state_counts[key] = provider_state_counts.get(key, 0) + 1
        provider_exception_states = {
            "UNKNOWN", "NOT_ESTABLISHED", "CLAUDE_PROVIDER_BLOCKED",
            "ANTIGRAVITY_PROVIDER_BLOCKED",
        }
        entry_provider_exceptions = sum(
            record["state"] in provider_exception_states
            for record in providers.values()
        )
        provider_coverage_exception_count += entry_provider_exceptions
        if (provider_review_status in ("UNKNOWN", "NOT_ESTABLISHED")
                or entry_provider_exceptions):
            provider_coverage_exception_memberships += 1
        entry_provider_failures = (
            (1 if provider_review_status == "FAIL" else 0)
            + sum(record["state"] == "FAIL" for record in providers.values())
        )
        provider_fail_status_count += entry_provider_failures
        _require(entry["implementation_status"]
                     in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED"),
                 "COMPLETE_TIER_LEDGER_IMPLEMENTATION_STATUS_INVALID")
        validation_records = (
            entry["focused_validation"], entry["independent_replay"]
        )
        _require(all(type(record) is dict
                     and set(record) == {"status", "receipt_digest"}
                     and record["status"]
                         in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
                     and ((record["status"] == "PASS"
                           and type(record["receipt_digest"]) is str
                           and _SHA256.fullmatch(record["receipt_digest"])
                               is not None)
                          or (record["status"] != "PASS"
                              and record["receipt_digest"] is None))
                     for record in validation_records),
                 "COMPLETE_TIER_LEDGER_VALIDATION_RECORD_INVALID")
        replay_membership = replay_memberships.get(entry["obligation_id"])
        if evidence_replay is not None \
                and evidence_replay.get("status") == "PASS" \
                and entry["independent_replay"]["status"] == "PASS":
            _require(type(replay_membership) is dict
                     and replay_membership.get("status") == "PASS"
                     and entry["independent_replay"]["receipt_digest"]
                         == (replay_membership.get("native_replay_digest")
                             or replay_membership.get("stable_replay_digest")),
                     "COMPLETE_TIER_LEDGER_REPLAY_DIGEST_DIFFERS")
            replay_bound_memberships += 1
        _require(entry["final_disposition"]
                     in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
                 and (entry["justified_exclusion"] is None
                      or (type(entry["justified_exclusion"]) is dict
                          and set(entry["justified_exclusion"])
                              == {"reason", "authority_digest"}
                          and type(entry["justified_exclusion"]["reason"])
                              is str
                          and entry["justified_exclusion"]["reason"]
                          and type(entry["justified_exclusion"][
                              "authority_digest"
                          ]) is str
                          and _SHA256.fullmatch(entry["justified_exclusion"][
                              "authority_digest"
                          ]) is not None)),
                 "COMPLETE_TIER_LEDGER_DISPOSITION_INVALID")
        statuses = [entry[name] for name in (
            "applicability_status", "authority_status", "observation_status",
            "native_assessment_status",
        )]
        statuses.extend((
            applicability["platform_status"],
            applicability["binding_status"],
            entry["implementation_status"],
            entry["focused_validation"]["status"],
            entry["independent_replay"]["status"],
            entry["final_disposition"],
        ))
        if entry_provider_failures:
            statuses.append("FAIL")
        statuses.append(
            "PASS" if evidence["freshness"] == "CURRENT" else
            "FAIL" if evidence["freshness"] == "STALE" else "UNKNOWN"
        )
        if entry["justified_exclusion"] is not None:
            statuses.append("UNKNOWN")
        _require(all(status in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
                     for status in statuses),
                 "COMPLETE_TIER_LEDGER_VERDICT_INVALID")
        assessment_digest = entry["native_assessment_digest"]
        _require((entry["native_assessment_status"] != "PASS"
                  and assessment_digest is None)
                 or (entry["native_assessment_status"] == "PASS"
                     and type(assessment_digest) is str
                     and _SHA256.fullmatch(assessment_digest) is not None),
                 "COMPLETE_TIER_LEDGER_ASSESSMENT_DIGEST_INVALID")
        declared_pass_memberships += all(status == "PASS" for status in statuses)
        verdicts.extend(statuses)
    _require(set(observed) == set(expected_by_key),
             "COMPLETE_TIER_LEDGER_DENOMINATOR_DIFFERS")
    declared_status = ("FAIL" if "FAIL" in verdicts else
                       "PASS" if all(item == "PASS" for item in verdicts)
                       else "UNKNOWN")
    mechanical_replay_status = (
        "PASS" if evidence_replay is not None
        and evidence_replay.get("status") == "PASS"
        and replay_bound_memberships == len(expected_by_key)
        else "NOT_ESTABLISHED"
    )
    status = (
        "FAIL" if declared_status == "FAIL" else
        "PASS" if declared_status == "PASS"
        and mechanical_replay_status == "PASS" else "UNKNOWN"
    )
    return {
        "status": status,
        "declared_status": declared_status,
        "mechanical_replay_status": mechanical_replay_status,
        "replay_receipt_digest": (
            evidence_replay.get("receipt_digest")
            if mechanical_replay_status == "PASS" else None
        ),
        "replay_bound_membership_count": replay_bound_memberships,
        "ledger_digest": stored_digest,
        "tier": tier,
        "tier_name": expected["tier_name"],
        "installed_family_cell_count_total": value[
            "installed_family_cell_count_total"
        ],
        "installed_membership_count_total": value[
            "installed_membership_count_total"
        ],
        "tier_family_cell_count": value["tier_family_cell_count"],
        "tier_membership_count": value["tier_membership_count"],
        "declared_pass_membership_count": declared_pass_memberships,
        "fail_status_count": verdicts.count("FAIL"),
        "unresolved_status_count": sum(
            item in ("UNKNOWN", "NOT_ESTABLISHED") for item in verdicts
        ),
        "provider_fail_status_count": provider_fail_status_count,
        "provider_coverage_exception_count": provider_coverage_exception_count,
        "provider_coverage_exception_membership_count": (
            provider_coverage_exception_memberships
        ),
        "provider_review_status_counts": dict(sorted(
            provider_review_status_counts.items()
        )),
        "provider_state_counts": dict(sorted(provider_state_counts.items())),
        "membership_identity_digest": expected["membership_identity_digest"],
    }


def _complete_self_representation(raw: bytes | None, *,
        expected_digest: str | None, source_coordinate: dict[str, Any],
        tier: int, denominators: dict[str, Any], ledger_digest: str | None,
        prior_whole_tier_report_digest: str | None,
        evidence_replay: dict[str, Any] | None = None,
        estate_evidence_result: dict[str, Any] | None = None,
        facet_reason_assessment: dict[str, Any] | None = None,
        ledger_mechanical_replay_status: str = "NOT_ESTABLISHED",
        ) -> dict[str, Any] | None:
    if raw is None and expected_digest is None:
        return None
    _require(raw is not None and expected_digest is not None,
             "COMPLETE_SELF_REPRESENTATION_SELECTION_INCOMPLETE")
    value = _parse(raw, "COMPLETE_SELF_REPRESENTATION_INVALID")
    _require(type(value) is dict, "COMPLETE_SELF_REPRESENTATION_INVALID")
    required = {
        "schema_version", "subject", "source_coordinate",
        "source_coordinate_digest", "installed_inventory_digest",
        "installed_family_cell_count_total", "installed_membership_count_total",
        "represented_tiers", "tier_ledger_digest",
        "prior_whole_tier_report_digest", "representation_status",
        "provider_review_status", "unobserved_fields",
        "representation_evidence_digest", "representation_digest",
        "tier1_facet_reason_assessment_digest",
        "tier1_facet_reason_ledger_digest",
        "tier1_facet_choice_identity_digest",
        "tier1_reasoned_structural_membership_digest",
        "tier1_reasoned_route_membership_digest",
        "tier1_reasoned_slot_digest",
        "tier1_domain_route_reason_status",
        "tier1_domain_route_reason_identity_digest",
        "tier1_domain_route_reasons_digest",
        "tier1_facet_direct_route_membership_count",
        "tier1_facet_direct_route_membership_digest",
        "tier1_domain_route_membership_count",
        "tier1_domain_route_membership_digest",
        "tier1_reason_route_union_membership_count",
        "tier1_reason_route_union_membership_digest",
        "tier1_reason_route_partition_digest",
    }
    allowed = required | {"estate_evidence_result_digest"}
    _require(
        set(value) == allowed
        or (estate_evidence_result is None and set(value) == required),
        "COMPLETE_SELF_REPRESENTATION_FIELDS_DIFFER",
    )
    stored_digest = value["representation_digest"]
    body = {
        key: item for key, item in value.items()
        if key != "representation_digest"
    }
    _require(type(stored_digest) is str
             and stored_digest == core_obligation_union.value_digest(body)
             and expected_digest == stored_digest,
             "COMPLETE_SELF_REPRESENTATION_DIGEST_DIFFERS")
    _require(value["schema_version"] == SELF_REPRESENTATION_SCHEMA
             and value["subject"] == {
                 "object_id": "verifier-core-self", "object_kind": "VERIFIER"
             },
             "COMPLETE_SELF_REPRESENTATION_SUBJECT_DIFFERS")
    _require(value["source_coordinate"] == source_coordinate
             and value["source_coordinate_digest"]
                 == core_obligation_union.value_digest(source_coordinate),
             "COMPLETE_SELF_REPRESENTATION_SOURCE_DIFFERS")
    _require(value["installed_inventory_digest"]
                 == denominators["installed_route_inventory_digest"]
             and value["installed_family_cell_count_total"]
                 == denominators["installed_route_family_cell_count"]
             and value["installed_membership_count_total"]
                 == denominators["installed_route_membership_count"],
             "COMPLETE_SELF_REPRESENTATION_DENOMINATOR_DIFFERS")
    _require(value["represented_tiers"] == list(range(1, tier + 1))
             and ledger_digest is not None
             and value["tier_ledger_digest"] == ledger_digest
             and value["prior_whole_tier_report_digest"]
                 == prior_whole_tier_report_digest,
             "COMPLETE_SELF_REPRESENTATION_LEDGER_DIFFERS")
    estate_evidence_digest = (
        estate_evidence_result.get("result_digest")
        if type(estate_evidence_result) is dict else None
    )
    _require(
        value.get("estate_evidence_result_digest") == estate_evidence_digest
        and (estate_evidence_digest is None
             or (type(estate_evidence_digest) is str
                 and _SHA256.fullmatch(estate_evidence_digest) is not None)),
        "COMPLETE_SELF_REPRESENTATION_ESTATE_EVIDENCE_DIFFERS",
    )
    reason_bindings = {
        "tier1_facet_reason_assessment_digest": (
            facet_reason_assessment.get("assessment_digest")
            if type(facet_reason_assessment) is dict else None
        ),
        "tier1_facet_reason_ledger_digest": (
            facet_reason_assessment.get("ledger_digest")
            if type(facet_reason_assessment) is dict else None
        ),
        "tier1_facet_choice_identity_digest": (
            facet_reason_assessment.get("choice_identity_digest")
            if type(facet_reason_assessment) is dict else None
        ),
        "tier1_reasoned_structural_membership_digest": (
            facet_reason_assessment.get(
                "reasoned_structural_membership_digest"
            ) if type(facet_reason_assessment) is dict else None
        ),
        "tier1_reasoned_route_membership_digest": (
            facet_reason_assessment.get("reasoned_route_membership_digest")
            if type(facet_reason_assessment) is dict else None
        ),
        "tier1_reasoned_slot_digest": (
            facet_reason_assessment.get("reasoned_slot_digest")
            if type(facet_reason_assessment) is dict else None
        ),
        "tier1_domain_route_reason_identity_digest": (
            facet_reason_assessment.get("domain_route_reason_identity_digest")
            if type(facet_reason_assessment) is dict else None
        ),
        "tier1_domain_route_reasons_digest": (
            facet_reason_assessment.get("consumer_route_partition", {}).get(
                "domain_route_reasons_digest"
            ) if type(facet_reason_assessment) is dict else None
        ),
        "tier1_facet_direct_route_membership_digest": (
            facet_reason_assessment.get("consumer_route_partition", {}).get(
                "facet_direct_route_membership_digest"
            ) if type(facet_reason_assessment) is dict else None
        ),
        "tier1_domain_route_membership_digest": (
            facet_reason_assessment.get("consumer_route_partition", {}).get(
                "domain_route_membership_digest"
            ) if type(facet_reason_assessment) is dict else None
        ),
        "tier1_reason_route_union_membership_digest": (
            facet_reason_assessment.get("consumer_route_partition", {}).get(
                "route_union_membership_digest"
            ) if type(facet_reason_assessment) is dict else None
        ),
        "tier1_reason_route_partition_digest": (
            facet_reason_assessment.get("consumer_route_partition_digest")
            if type(facet_reason_assessment) is dict else None
        ),
    }
    _require(
        type(facet_reason_assessment) is dict
        and facet_reason_assessment.get("status") == "PASS"
        and all(value.get(name) == digest
                and type(digest) is str
                and _SHA256.fullmatch(digest) is not None
                for name, digest in reason_bindings.items()),
        "COMPLETE_SELF_REPRESENTATION_FACET_REASONS_DIFFER",
    )
    reason_partition = facet_reason_assessment["consumer_route_partition"]
    _require(
        value["tier1_domain_route_reason_status"] == "PASS"
        and value["tier1_facet_direct_route_membership_count"]
            == reason_partition["facet_direct_route_membership_count"] == 27
        and value["tier1_domain_route_membership_count"]
            == reason_partition["domain_route_membership_count"] == 18
        and value["tier1_reason_route_union_membership_count"]
            == reason_partition["route_union_membership_count"] == 45,
        "COMPLETE_SELF_REPRESENTATION_REASON_PARTITION_DIFFERS",
    )
    _require(value["representation_status"]
                 in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
             and value["provider_review_status"]
                 in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
             and type(value["unobserved_fields"]) is list
             and all(type(item) is str and item for item in value["unobserved_fields"]),
             "COMPLETE_SELF_REPRESENTATION_VERDICT_INVALID")
    evidence_digest = value["representation_evidence_digest"]
    _require((value["representation_status"] != "PASS"
              and evidence_digest is None)
             or (value["representation_status"] == "PASS"
                 and type(evidence_digest) is str
                 and _SHA256.fullmatch(evidence_digest) is not None),
             "COMPLETE_SELF_REPRESENTATION_EVIDENCE_DIGEST_INVALID")
    provider_failed = value["provider_review_status"] == "FAIL"
    provider_coverage_exception = value["provider_review_status"] in (
        "UNKNOWN", "NOT_ESTABLISHED"
    )
    declared_status = (
        "FAIL" if value["representation_status"] == "FAIL" or provider_failed
        else "PASS" if value["representation_status"] == "PASS"
        and not value["unobserved_fields"] else "UNKNOWN"
    )
    stable_replay_set_digest = (
        (evidence_replay.get("stable_replay_set_digest")
         or evidence_replay.get("receipt_digest"))
        if evidence_replay is not None
        and evidence_replay.get("status") == "PASS" else None
    )
    if stable_replay_set_digest is not None \
            and value["representation_status"] == "PASS":
        _require(evidence_digest == stable_replay_set_digest,
                 "COMPLETE_SELF_REPRESENTATION_REPLAY_DIGEST_DIFFERS")
    independent_evidence_status = (
        "PASS" if declared_status == "PASS"
        and ledger_mechanical_replay_status == "PASS"
        and stable_replay_set_digest is not None
        and evidence_digest == stable_replay_set_digest
        and estate_evidence_result is not None
        and all(estate_evidence_result.get(name) == "PASS" for name in (
            "native_self_verification_status",
            "native_semantic_applicability_status",
            "native_per_candidate_evidence_status",
        ))
        and estate_evidence_digest is not None
        else "NOT_ESTABLISHED"
    )
    status = (
        "FAIL" if declared_status == "FAIL" else
        "PASS" if independent_evidence_status == "PASS" else "UNKNOWN"
    )
    return {
        "status": status,
        "declared_status": declared_status,
        "independent_evidence_status": independent_evidence_status,
        "replay_receipt_digest": (
            evidence_replay.get("receipt_digest")
            if independent_evidence_status == "PASS" else None
        ),
        "stable_replay_set_digest": (
            stable_replay_set_digest
            if independent_evidence_status == "PASS" else None
        ),
        "representation_digest": stored_digest,
        "representation_evidence_digest": evidence_digest,
        "estate_evidence_result_digest": estate_evidence_digest,
        "provider_declared_status": value["provider_review_status"],
        "provider_coverage_exception": provider_coverage_exception,
        "represented_tiers": value["represented_tiers"],
        "tier_ledger_digest": value["tier_ledger_digest"],
        "prior_whole_tier_report_digest": value[
            "prior_whole_tier_report_digest"
        ],
        "unobserved_fields": value["unobserved_fields"],
    }


def _validated_estate_evidence_result(value: Any, *,
        candidate_estate: dict[str, Any],
        estate_applicability: dict[str, Any],
        estate_authority: dict[str, Any],
        expected_manifest_digest: str) -> dict[str, Any]:
    """Validate the in-process replay result before promoting estate state."""
    _require(
        type(value) is dict and set(value) == _ESTATE_EVIDENCE_RESULT_FIELDS,
        "CANDIDATE_ESTATE_EVIDENCE_RESULT_INVALID",
    )
    result_digest = value["result_digest"]
    body = {
        key: item for key, item in value.items() if key != "result_digest"
    }
    _require(
        type(result_digest) is str
        and _SHA256.fullmatch(result_digest) is not None
        and result_digest == self_polish_estate_evidence.value_digest(body),
        "CANDIDATE_ESTATE_EVIDENCE_RESULT_DIGEST_DIFFERS",
    )
    status = value["status"]
    semantic = (
        value["semantic_applicability_status"],
        value["per_candidate_evidence_status"],
        value["full_estate_closure"],
    )
    _require(
        status in ("PASS", "FAIL", "UNKNOWN")
        and value["mechanical_validation_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and value["estate_authority_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and value["independent_authority_status"]
            in ("PASS", "FAIL", "NOT_ESTABLISHED")
        and value["native_self_verification_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and value["native_semantic_applicability_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and value["native_per_candidate_evidence_status"]
            in ("PASS", "FAIL", "UNKNOWN")
        and value["tier1_status"] == "NOT_ESTABLISHED"
        and value["polished"] is False
        and value["release_authorized"] is False
        and type(value["candidate_results"]) is list
        and type(value["blockers"]) is list
        and type(value["assessment_time"]) is int
        and value["assessment_time"] >= 0
        and value["native_source_recapture_status"]
            in ("PASS", "FAIL", "NOT_ESTABLISHED")
        and all(type(item) is str and item for item in value["blockers"])
        and all(type(value[name]) is int and value[name] >= 0 for name in (
            "candidate_count", "applicable_candidate_count",
            "authenticated_candidate_count", "candidate_pass_count",
            "candidate_fail_count", "candidate_unknown_count",
            "native_applicable_candidate_count",
            "native_replayed_candidate_count",
            "native_candidate_pass_count", "native_candidate_fail_count",
            "native_candidate_unknown_count",
            "native_evidence_artifact_count",
        )),
        "CANDIDATE_ESTATE_EVIDENCE_RESULT_INVALID",
    )
    expected_by_id = {
        row["candidate_id"]: row for row in candidate_estate["candidates"]
    }
    expected_candidates = {
        (row["candidate_id"], row["candidate_digest"])
        for row in candidate_estate["candidates"]
    }
    expected_identity_digest = self_polish_estate_evidence.value_digest([{
        "candidate_id": row["candidate_id"],
        "candidate_digest": row["candidate_digest"],
        "category": row["category"],
    } for row in candidate_estate["candidates"]])
    candidate_result_fields = {
        "candidate_id", "candidate_digest", "category",
        "declared_applicability", "declared_evidence_disposition",
        "subject_digest", "replay_status", "independent_authority_status",
        "native_applicability_status", "native_replay_status",
        "native_replay_digest", "native_semantic_status",
        "receipt_digest", "policy_digest",
        "approving_actors", "applicability_status", "evidence_status",
        "semantic_status", "blockers",
    }
    for row in value["candidate_results"]:
        _require(type(row) is dict and set(row) == candidate_result_fields,
                 "CANDIDATE_ESTATE_EVIDENCE_CANDIDATE_RESULT_INVALID")
        expected_candidate = expected_by_id.get(row["candidate_id"])
        _require(expected_candidate is not None
                 and row["candidate_digest"]
                     == expected_candidate["candidate_digest"]
                 and row["category"] == expected_candidate["category"]
                 and row["declared_applicability"]
                     in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN")
                 and row["declared_evidence_disposition"]
                     in ("PASS", "FAIL", "UNKNOWN")
                 and type(row["subject_digest"]) is str
                 and _SHA256.fullmatch(row["subject_digest"]) is not None
                 and row["replay_status"]
                     in ("REPRODUCED", "REJECTED", "NOT_ESTABLISHED")
                  and row["independent_authority_status"]
                      in ("PASS", "FAIL", "NOT_ESTABLISHED")
                  and row["native_applicability_status"]
                      in ("APPLICABLE", "NOT_APPLICABLE")
                 and row["native_replay_status"]
                     in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE",
                         "NOT_ESTABLISHED")
                  and (
                      row["native_replay_digest"] is None
                      or (
                          type(row["native_replay_digest"]) is str
                          and _SHA256.fullmatch(row["native_replay_digest"])
                              is not None
                      )
                  )
                  and (
                      row["native_replay_status"] != "PASS"
                      or row["native_replay_digest"] is not None
                  )
                  and (
                      row["native_replay_status"]
                          not in {"NOT_APPLICABLE", "NOT_ESTABLISHED"}
                      or row["native_replay_digest"] is None
                  )
                  and row["native_semantic_status"]
                      in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")
                 and (row["receipt_digest"] is None
                      or (type(row["receipt_digest"]) is str
                          and _SHA256.fullmatch(row["receipt_digest"])
                              is not None))
                 and (row["policy_digest"] is None
                      or (type(row["policy_digest"]) is str
                          and _SHA256.fullmatch(row["policy_digest"])
                              is not None))
                 and type(row["approving_actors"]) is list
                 and all(type(actor) is str and actor
                         for actor in row["approving_actors"])
                 and row["applicability_status"]
                     in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "FAIL")
                 and row["evidence_status"]
                     in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")
                 and row["semantic_status"]
                     in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")
                 and type(row["blockers"]) is list
                 and all(type(item) is str and item for item in row["blockers"]),
                 "CANDIDATE_ESTATE_EVIDENCE_CANDIDATE_RESULT_INVALID")
    observed_candidates = [
        (row.get("candidate_id"), row.get("candidate_digest"))
        for row in value["candidate_results"]
        if type(row) is dict
    ]
    _require(
        len(observed_candidates) == value["candidate_count"]
        and len(set(observed_candidates)) == len(observed_candidates)
        and set(observed_candidates) == expected_candidates
        and value["candidate_identity_set_digest"]
            == expected_identity_digest
        and value["candidate_pass_count"]
            + value["candidate_fail_count"]
            + value["candidate_unknown_count"] == value["candidate_count"]
        and value["native_candidate_pass_count"]
            + value["native_candidate_fail_count"]
            + value["native_candidate_unknown_count"]
                == value["candidate_count"]
        and value["applicable_candidate_count"] <= value["candidate_count"]
        and value["native_applicable_candidate_count"]
            <= value["candidate_count"]
        and value["authenticated_candidate_count"] <= value["candidate_count"]
        and value["native_replayed_candidate_count"] <= value["candidate_count"]
        and value["native_evidence_artifact_count"] <= value["candidate_count"],
        "CANDIDATE_ESTATE_EVIDENCE_CANDIDATE_SET_DIFFERS",
    )
    expected_semantic = (
        ("PASS", "PASS", "PASS") if status == "PASS" else
        ("FAIL", "FAIL", "FAIL") if status == "FAIL" else
        ("NOT_ESTABLISHED", "NOT_ESTABLISHED", "NOT_ESTABLISHED")
    )
    _require(
        semantic == expected_semantic,
        "CANDIDATE_ESTATE_EVIDENCE_VERDICT_DIFFERS",
    )
    if value["mechanical_validation_status"] == "PASS":
        _require(
            value["source_coordinate_digest"]
                == self_polish_estate.value_digest(
                    candidate_estate["source_coordinate"]
                )
            and value["candidate_source_census_digest"]
                == candidate_estate["source_coordinate"][
                    "candidate_source_census_digest"
                ]
            and value["estate_digest"] == candidate_estate["estate_digest"]
            and value["candidate_universe_digest"]
                == candidate_estate["candidate_universe_digest"]
            and value["applicability_ledger_digest"]
                == estate_applicability["ledger_digest"]
            and value["manifest_digest"] == expected_manifest_digest
            and value["candidate_count"] == candidate_estate["candidate_count"],
            "CANDIDATE_ESTATE_EVIDENCE_BINDING_DIFFERS",
        )
    if value["native_self_verification_status"] == "PASS":
        _require(
            value["mechanical_validation_status"] == "PASS"
            and value["native_source_recapture_status"] == "PASS"
            and value["native_semantic_applicability_status"] == "PASS"
            and value["native_per_candidate_evidence_status"] == "PASS"
            and value["native_candidate_fail_count"] == 0
            and value["native_candidate_unknown_count"] == 0
            and value["native_candidate_pass_count"]
                == value["candidate_count"]
            and value["native_replayed_candidate_count"]
                == value["candidate_count"]
            and value["native_evidence_artifact_count"]
                == value["native_applicable_candidate_count"]
            and all(
                (
                    row["native_applicability_status"] == "APPLICABLE"
                    and row["native_replay_status"] == "PASS"
                    and row["native_semantic_status"] == "PASS"
                    and row["declared_applicability"] == "APPLICABLE"
                    and row["declared_evidence_disposition"] == "PASS"
                ) or (
                    row["native_applicability_status"] == "NOT_APPLICABLE"
                    and row["native_replay_status"] == "NOT_APPLICABLE"
                    and row["native_semantic_status"] == "NOT_APPLICABLE"
                    and row["declared_applicability"] == "NOT_APPLICABLE"
                    and row["declared_evidence_disposition"] == "UNKNOWN"
                )
                for row in value["candidate_results"]
            ),
            "CANDIDATE_ESTATE_NATIVE_SELF_VERIFICATION_DIFFERS",
        )
    if status == "PASS":
        _require(
            value["mechanical_validation_status"] == "PASS"
            and value["estate_authority_status"] == "PASS"
            and candidate_estate["mechanical_census_status"] == "PASS"
            and estate_applicability["mechanical_validation_status"] == "PASS"
            and estate_authority["status"] == "PASS"
            and estate_authority["independent_authority_status"] == "PASS"
            and value["native_source_recapture_status"] == "PASS"
            and value["authenticated_candidate_count"]
                == candidate_estate["candidate_count"]
            and value["native_replayed_candidate_count"]
                == candidate_estate["candidate_count"]
            and value["native_evidence_artifact_count"]
                == value["applicable_candidate_count"]
            and value["candidate_fail_count"] == 0
            and value["candidate_unknown_count"] == 0,
            "CANDIDATE_ESTATE_EVIDENCE_PREREQUISITE_NOT_ESTABLISHED",
        )
        _require(all(
            row["replay_status"] == "REPRODUCED"
            and row["native_replay_status"] in {"PASS", "NOT_APPLICABLE"}
            and row["applicability_status"]
                in {"APPLICABLE", "NOT_APPLICABLE"}
            and row["semantic_status"] in {"PASS", "NOT_APPLICABLE"}
            for row in value["candidate_results"]
        ), "CANDIDATE_ESTATE_EVIDENCE_PREREQUISITE_NOT_ESTABLISHED")
    return value


def _attempt_tier1(source_root: str | Path,
                   expected_selection_digest: str | None) -> dict[str, Any]:
    prepared = polish_requirements.prepare_core_self_polish_inputs(source_root)
    selected_digest = prepared["selection_digest"]
    external_pin = expected_selection_digest is not None
    assessment = polish_requirements.assess_core_self_polish(
        selection_bytes=prepared["selection_bytes"],
        expected_selection_digest=(expected_selection_digest or selected_digest),
        source_manifest_bytes=prepared["source_manifest_bytes"],
        source_root=source_root,
        source_scope_bytes=prepared["source_scope_bytes"],
        collection_bytes=prepared["collection_bytes"],
        application_selection_bytes=prepared["application_selection_bytes"],
        compiler_policy_bytes=prepared["compiler_policy_bytes"],
        compiler_manifest_bytes=prepared["compiler_manifest_bytes"],
        polish_bundle_bytes=prepared["polish_bundle_bytes"],
        polish_request_bytes=prepared["polish_request_bytes"],
        polish_inventory_bytes=prepared["polish_inventory_bytes"],
        expected_polish_inventory_digest=prepared[
            "expected_polish_inventory_digest"
        ],
        contract_version=prepared["contract_version"],
    )
    selection = _parse(prepared["selection_bytes"], "SELF_POLISH_SELECTION_INVALID")
    _require(type(selection) is dict, "SELF_POLISH_SELECTION_INVALID")
    coordinate = {
        "source_head": selection["source_head"],
        "source_tree": selection["source_tree"],
        "source_worktree_status_digest": selection[
            "source_worktree_status_digest"
        ],
        "source_manifest_digest": selection["source_manifest_digest"],
    }
    receipt = assessment.get("receipt")
    return {
        "status": assessment.get("status", "UNKNOWN"),
        "gate_status": assessment.get("gate_status", "UNKNOWN"),
        "receipt_status": assessment.get("receipt_status", "NOT_ISSUED"),
        "assessment_digest": assessment.get("assessment_digest"),
        "receipt_digest": (
            receipt.get("receipt_digest") if type(receipt) is dict else None
        ),
        "selection_digest": selected_digest,
        "external_selection_pin": "MATCHED" if external_pin
            and expected_selection_digest == selected_digest else (
                "MISMATCH" if external_pin else "DERIVED_CURRENT_SOURCE"
            ),
        "selection_mode": (
            "EXTERNAL_DIGEST_PIN" if external_pin
            else "COMMAND_SELECTED_EXACT_SOURCE_ROOT"
        ),
        "independent_selection_authority": (
            "MATCHED" if external_pin
            and expected_selection_digest == selected_digest
            else "NOT_ESTABLISHED"
        ),
        "source_coordinate": coordinate,
        "source_coordinate_digest": core_obligation_union.value_digest(coordinate),
        "root_id": selection["root_id"],
        "installed_definition_count": assessment.get("installed_definition_count"),
        "installed_membership_count": assessment.get("installed_membership_count"),
        "instantiated_obligation_count": assessment.get(
            "instantiated_obligation_count"
        ),
        "full_application_status": assessment.get(
            "full_application_status", "UNKNOWN"
        ),
        "polished": assessment.get("polished", False),
        "reason": assessment.get("reason"),
    }


def _post_replay_source_recapture(
        source_root: str | Path,
        selected_coordinate: dict[str, Any]) -> dict[str, Any]:
    """Recapture all tracked working bytes after replay and compare exactly."""
    try:
        observed = polish_requirements.capture_core_self_polish_source(
            source_root
        )
    except polish_requirements.MechanismBindingUnavailable:
        return {
            "status": "NOT_ESTABLISHED",
            "matches_selected_source": "UNKNOWN",
            "source_coordinate": None,
            "source_coordinate_digest": None,
            "claim_boundary": "Post-replay source recapture was unavailable.",
        }
    except polish_requirements.RequirementRefusal:
        return {
            "status": "FAIL",
            "matches_selected_source": False,
            "source_coordinate": None,
            "source_coordinate_digest": None,
            "claim_boundary": (
                "The post-replay source no longer satisfies the selected "
                "whole-source capture contract."
            ),
        }
    observed_coordinate = {
        "source_head": observed["git_head"],
        "source_tree": observed["git_tree"],
        "source_worktree_status_digest": observed["worktree_status_digest"],
        "source_manifest_digest": _digest(
            core_obligation_union.canonical_bytes(observed)
        ),
    }
    matches = observed_coordinate == selected_coordinate
    return {
        "status": "PASS" if matches else "FAIL",
        "matches_selected_source": matches,
        "source_coordinate": observed_coordinate,
        "source_coordinate_digest": core_obligation_union.value_digest(
            observed_coordinate
        ),
        "candidate_source_file_count": observed[
            "candidate_source_file_count"
        ],
        "candidate_source_bytes": observed["candidate_source_bytes"],
        "tracked_file_count": observed["tracked_file_count"],
        "untracked_nonignored_file_count": observed[
            "untracked_nonignored_file_count"
        ],
        "candidate_source_census_digest": observed[
            "candidate_source_census_digest"
        ],
        "candidate_source_census": observed["candidate_source_census"],
        "worktree_clean": observed["worktree_clean"],
        "claim_boundary": (
            "PASS establishes only exact equality to the pre-replay candidate-"
            "source byte "
            "capture; it does not establish estate completeness."
        ),
    }


def _union_summary(authority: dict[str, Any] | None,
                   contributions: list[dict[str, Any]] | None, *,
                   expected_authority_digest: str | None,
                   source_coordinate: dict[str, Any] | None,
                   tier: int, expected_members: int) -> dict[str, Any] | None:
    supplied = (authority, contributions, expected_authority_digest)
    if all(value is None for value in supplied):
        return None
    _require(authority is not None and contributions is not None
             and source_coordinate is not None,
             "UNION_SELECTION_INCOMPLETE")
    report = core_obligation_union.validate_union(
        authority,
        contributions,
        expected_authority_digest=expected_authority_digest,
        expected_source_coordinate=source_coordinate,
    )
    family_members = [
        item
        for family in authority.get("families", [])
        if type(family) is dict
        for item in family.get("requirements", [])
        if type(item) is dict
        and item.get("object_kind") == "VERIFIER"
        and item.get("tier") == tier
    ]
    fields = {
        key: report.get(key)
        for key in (
            "authority_binding", "source_coordinate_binding", "dependency_binding",
            "candidate_coverage", "structural_union", "semantic_completeness",
            "release_admissible", "report_digest",
        )
    }
    fields.update(
        issue_codes=sorted({row.get("code", "INVALID_UNION_ISSUE")
                            for row in report.get("issues", [])}),
        selected_verifier_tier_member_count=len(family_members),
    )
    clean = (
        fields["authority_binding"] == "MATCHED"
        and fields["source_coordinate_binding"] == "MATCHED"
        and fields["dependency_binding"] == "MATCHED"
        and fields["candidate_coverage"] == "MATCHED"
        and fields["structural_union"] == "PASS"
        and fields["semantic_completeness"] == "UNKNOWN"
        and fields["release_admissible"] is False
        and not fields["issue_codes"]
        and len(family_members) == expected_members
    )
    fields["status"] = "PASS" if clean else "FAIL"
    return fields


def _derived_route_union_summary(*, source_coordinate: dict[str, Any],
        tier: int, expected_members: int,
        denominators: dict[str, Any]) -> dict[str, Any]:
    """Derive exact route-union closure from the installed registries."""

    closure = self_polish_native_replay.installed_registry_closure()
    expected = denominators["complete_tiers"][str(tier)]
    _require(
        closure.get("status") == "PASS"
        and closure == denominators["installed_registry_closure"]
        and closure.get(f"tier{tier}_route_membership_count")
            == expected_members
        and expected["registered_route_membership_count"] == expected_members,
        "INSTALLED_ROUTE_UNION_NOT_ESTABLISHED",
    )
    body = {
        "status": "PASS",
        "derivation": "INSTALLED_REGISTRY_CLOSURE",
        "authority_binding": "SELF_DERIVED_INSTALLED_REGISTRY",
        "source_coordinate_binding": "MATCHED",
        "source_coordinate_digest": core_obligation_union.value_digest(
            source_coordinate
        ),
        "dependency_binding": "MATCHED",
        "candidate_coverage": "MATCHED",
        "structural_union": "PASS",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
        "issue_codes": [],
        "selected_verifier_tier_member_count": expected_members,
        "membership_identity_digest": expected["membership_identity_digest"],
        "installed_registry_closure_digest": closure["closure_digest"],
    }
    body["report_digest"] = core_obligation_union.value_digest(body)
    return body


def _authority_summary(raw: bytes | None, *, expected_digest: str | None,
                       union_summary: dict[str, Any] | None,
                       expected_instances: int) -> dict[str, Any] | None:
    if raw is None and expected_digest is None:
        return None
    _require(raw is not None and expected_digest is not None,
             "APPLICATION_AUTHORITY_SELECTION_INCOMPLETE")
    value = _parse(raw, "APPLICATION_AUTHORITY_ASSESSMENT_INVALID")
    _require(type(value) is dict
             and value.get("schema_version")
                 == core_application_authority.ASSESSMENT_SCHEMA,
             "APPLICATION_AUTHORITY_ASSESSMENT_INVALID")
    stored_digest = value.get("assessment_digest")
    body = {key: item for key, item in value.items() if key != "assessment_digest"}
    _require(stored_digest == core_obligation_union.value_digest(body)
             and expected_digest == stored_digest,
             "APPLICATION_AUTHORITY_ASSESSMENT_DIGEST_DIFFERS")
    _require(value.get("polished") is False
             and value.get("release_authorized") is False
             and value.get("full_application_status") == "UNKNOWN",
             "APPLICATION_AUTHORITY_BOUNDARY_DIFFERS")
    nested = value.get("union_validation")
    _require(union_summary is not None and type(nested) is dict
             and nested.get("report_digest") == union_summary.get("report_digest"),
             "APPLICATION_AUTHORITY_UNION_DIFFERS")
    statuses = {
        key: value.get(key)
        for key in (
            "binding_status", "authority_status", "child_status",
            "interaction_status", "semantic_completeness",
        )
    }
    failed = value.get("status") == "FAIL" or "FAIL" in statuses.values()
    complete = (
        value.get("status") == "PASS"
        and not failed
        and all(statuses[key] == "PASS" for key in statuses)
        and value.get("expected_instances") == expected_instances
        and union_summary.get("status") == "PASS"
    )
    return {
        "status": "FAIL" if failed else "PASS" if complete else "UNKNOWN",
        **statuses,
        "expected_instances": value.get("expected_instances"),
        "assessment_digest": stored_digest,
        "blockers": sorted(set(value.get("blockers", []))),
    }


def _derived_application_authority_summary(*,
        union_summary: dict[str, Any], expected_instances: int,
        source_coordinate: dict[str, Any], tier: int,
        denominators: dict[str, Any]) -> dict[str, Any]:
    """Bind installed Tier mechanics without inventing external authority."""

    expected = denominators["complete_tiers"][str(tier)]
    _require(
        union_summary.get("status") == "PASS"
        and union_summary.get("selected_verifier_tier_member_count")
            == expected["registered_route_membership_count"]
        and expected_instances > 0,
        "INSTALLED_APPLICATION_AUTHORITY_NOT_ESTABLISHED",
    )
    body = {
        "status": "PASS",
        "derivation": "COMMAND_SELECTED_INSTALLED_SELF_REPRESENTATION",
        "binding_status": "PASS",
        "authority_status": "PASS",
        "child_status": "PASS",
        "interaction_status": "PASS",
        "semantic_completeness": "PASS",
        "expected_instances": expected_instances,
        "source_coordinate_digest": core_obligation_union.value_digest(
            source_coordinate
        ),
        "union_report_digest": union_summary["report_digest"],
        "membership_identity_digest": expected["membership_identity_digest"],
        "independent_authority_status": "NOT_ESTABLISHED",
        "full_application_status": "UNKNOWN",
        "polished": False,
        "release_authorized": False,
        "blockers": [],
    }
    body["assessment_digest"] = core_obligation_union.value_digest(body)
    return body


def _representation_binds_facet_reasons(
        representation: Any, facet_reasons: Any) -> bool:
    if type(representation) is not dict or type(facet_reasons) is not dict:
        return False
    partition = facet_reasons.get("consumer_route_partition")
    if type(partition) is not dict:
        return False
    expected = {
        "tier1_facet_reason_assessment_digest": facet_reasons.get(
            "assessment_digest"
        ),
        "tier1_facet_reason_ledger_digest": facet_reasons.get(
            "ledger_digest"
        ),
        "tier1_facet_choice_identity_digest": facet_reasons.get(
            "choice_identity_digest"
        ),
        "tier1_reasoned_structural_membership_digest": facet_reasons.get(
            "reasoned_structural_membership_digest"
        ),
        "tier1_reasoned_route_membership_digest": facet_reasons.get(
            "reasoned_route_membership_digest"
        ),
        "tier1_reasoned_slot_digest": facet_reasons.get(
            "reasoned_slot_digest"
        ),
        "tier1_domain_route_reason_status": facet_reasons.get(
            "domain_route_reason_status"
        ),
        "tier1_domain_route_reason_identity_digest": facet_reasons.get(
            "domain_route_reason_identity_digest"
        ),
        "tier1_domain_route_reasons_digest": partition.get(
            "domain_route_reasons_digest"
        ),
        "tier1_facet_direct_route_membership_count": partition.get(
            "facet_direct_route_membership_count"
        ),
        "tier1_facet_direct_route_membership_digest": partition.get(
            "facet_direct_route_membership_digest"
        ),
        "tier1_domain_route_membership_count": partition.get(
            "domain_route_membership_count"
        ),
        "tier1_domain_route_membership_digest": partition.get(
            "domain_route_membership_digest"
        ),
        "tier1_reason_route_union_membership_count": partition.get(
            "route_union_membership_count"
        ),
        "tier1_reason_route_union_membership_digest": partition.get(
            "route_union_membership_digest"
        ),
        "tier1_reason_route_partition_digest": facet_reasons.get(
            "consumer_route_partition_digest"
        ),
    }
    return all(representation.get(name) == value
               for name, value in expected.items())


def _validated_retained_estate_census(value: Any, *,
        source_root: str | Path, source_coordinate: dict[str, Any],
        installed_denominators: dict[str, Any]) -> dict[str, Any]:
    """Recapture the full estate selected by a retained Tier 1 report."""

    _require(type(value) is dict and set(value) == _ESTATE_CENSUS_FIELDS,
             "TIER1_CANDIDATE_ESTATE_CENSUS_INVALID")
    coordinate = value.get("source_coordinate")
    _require(type(coordinate) is dict
             and type(coordinate.get("repository")) is str
             and coordinate["repository"]
             and type(coordinate.get("revision")) is str
             and coordinate["revision"],
             "TIER1_CANDIDATE_ESTATE_CENSUS_INVALID")
    summary, applicability, candidate_estate, ledger_bytes, ledger_digest = (
        _candidate_estate_inputs(
            source_root=source_root,
            source_coordinate=source_coordinate,
            denominators=installed_denominators,
            expected_repository=coordinate["repository"],
            expected_revision=coordinate["revision"],
            expected_estate_digest=value.get("estate_digest"),
            applicability_ledger_bytes=None,
            expected_applicability_ledger_digest=None,
        )
    )
    _require(applicability is None and ledger_bytes is None
             and ledger_digest is None and type(summary) is dict
             and type(candidate_estate) is dict,
             "TIER1_CANDIDATE_ESTATE_CENSUS_INVALID")
    _require(value["external_estate_digest_pin"] in {
        "MATCHED", "DERIVED_CURRENT_SOURCE",
    }, "TIER1_CANDIDATE_ESTATE_CENSUS_INVALID")
    summary["external_estate_digest_pin"] = value[
        "external_estate_digest_pin"
    ]
    _require(summary == value,
             "TIER1_CANDIDATE_ESTATE_CENSUS_DIFFERS")
    return candidate_estate


def _validated_retained_estate_applicability(
        value: Any, *, candidate_estate: dict[str, Any]) -> dict[str, Any]:
    """Validate the exact retained applicability-result envelope and binding."""

    _require(type(value) is dict
             and set(value) == _ESTATE_APPLICABILITY_RESULT_FIELDS,
             "TIER1_CANDIDATE_ESTATE_APPLICABILITY_INVALID")
    result_digest = value["result_digest"]
    body = {key: item for key, item in value.items() if key != "result_digest"}
    _require(type(result_digest) is str
             and _SHA256.fullmatch(result_digest) is not None
             and result_digest == self_polish_estate.value_digest(body)
             and value["schema_version"]
                 == self_polish_estate.APPLICABILITY_RESULT_SCHEMA
             and value["mechanical_validation_status"] == "PASS"
             and value["candidate_count"] == candidate_estate["candidate_count"]
             and value["candidate_universe_digest"]
                 == candidate_estate["candidate_universe_digest"]
             and type(value["ledger_digest"]) is str
             and _SHA256.fullmatch(value["ledger_digest"]) is not None
             and type(value["caller_declared_pass_count"]) is int
             and 0 <= value["caller_declared_pass_count"]
                 <= value["candidate_count"]
             and value["caller_pass_authentication"] == "NOT_ESTABLISHED"
             and value["semantic_applicability_status"] == "NOT_ESTABLISHED"
             and value["full_estate_closure"] == "NOT_ESTABLISHED",
             "TIER1_CANDIDATE_ESTATE_APPLICABILITY_INVALID")
    return value


def _validated_retained_estate_authority(value: Any, *,
        candidate_estate: dict[str, Any], estate_census: dict[str, Any],
        estate_applicability: dict[str, Any],
        source_coordinate_digest: str,
        installed_denominators: dict[str, Any]) -> dict[str, Any]:
    """Validate the retained configured-key authority result and subject."""

    _require(type(value) is dict
             and set(value) == _ESTATE_AUTHORITY_RESULT_FIELDS,
             "TIER1_CANDIDATE_ESTATE_AUTHORITY_INVALID")
    result_digest = value["result_digest"]
    body = {key: item for key, item in value.items() if key != "result_digest"}
    crosswalk = candidate_estate["structural_route_crosswalk"]
    subject = self_polish_estate_authority.estate_authority_subject(
        source_coordinate_digest=source_coordinate_digest,
        estate_source_coordinate_digest=self_polish_estate.value_digest(
            candidate_estate["source_coordinate"]
        ),
        candidate_source_census_digest=candidate_estate[
            "source_coordinate"
        ]["candidate_source_census_digest"],
        estate_digest=candidate_estate["estate_digest"],
        candidate_universe_digest=candidate_estate["candidate_universe_digest"],
        required_categories_digest=estate_census[
            "required_categories_digest"
        ],
        category_summaries_digest=estate_census["category_summaries_digest"],
        applicability_ledger_digest=estate_applicability["ledger_digest"],
        installed_inventory_digest=installed_denominators[
            "installed_route_inventory_digest"
        ],
        objective_catalog_digest=installed_denominators[
            "objective_inventory_digest"
        ],
        structural_route_crosswalk_digest=estate_census[
            "structural_route_crosswalk_digest"
        ],
        structural_identity_digest=crosswalk["structural_identity_digest"],
        route_identity_digest=crosswalk["route_identity_digest"],
        shared_identity_digest=crosswalk["shared_identity_digest"],
    )
    subject_digest = self_polish_estate.value_digest(subject)
    absent_receipt = self_polish_estate_authority.replay_estate_authority(
        subject, authority_replay=None
    )
    common_valid = (
        type(result_digest) is str
        and _SHA256.fullmatch(result_digest) is not None
        and result_digest == self_polish_estate.value_digest(body)
        and value["schema_version"]
            == self_polish_estate_authority.RESULT_SCHEMA
        and value["subject_digest"] == subject_digest
        and value["claim_boundary"] == absent_receipt["claim_boundary"]
        and value["semantic_applicability_status"] == "NOT_ESTABLISHED"
        and value["per_candidate_evidence_status"] == "NOT_ESTABLISHED"
        and value["full_estate_closure"] == "NOT_ESTABLISHED"
    )
    configured_key_pass = (
        value["status"] == "PASS"
        and value["independent_authority_status"] == "PASS"
        and value["replay_status"] == "REPRODUCED"
        and all(type(value[name]) is str
                and _SHA256.fullmatch(value[name]) is not None
                for name in ("policy_digest", "receipt_digest"))
        and type(value["approving_actors"]) is list
        and bool(value["approving_actors"])
        and all(type(actor) is str and actor
                for actor in value["approving_actors"])
        and value["blockers"] == []
    )
    absent_receipt_unknown = value == absent_receipt
    _require(
        common_valid and (configured_key_pass or absent_receipt_unknown),
        "TIER1_CANDIDATE_ESTATE_AUTHORITY_INVALID",
    )
    return value


def _retained_tier1(raw: bytes | None, expected_digest: str | None, *,
                    installed_denominators: dict[str, Any],
                    source_root: str | Path | None) -> dict[str, Any] | None:
    if raw is None and expected_digest is None:
        return None
    _require(raw is not None and expected_digest is not None,
             "TIER1_SELECTION_INCOMPLETE")
    value = _parse(
        raw, "TIER1_REPORT_INVALID", max_bytes=MAX_TIER1_REPORT_BYTES
    )
    _require(type(value) is dict and set(value) == _TIER1_REPORT_FIELDS
             and value.get("schema_version") == REPORT_SCHEMA,
             "TIER1_REPORT_INVALID")
    body = {key: item for key, item in value.items() if key != "report_digest"}
    _require(value.get("report_digest") == core_obligation_union.value_digest(body)
             and expected_digest == value["report_digest"],
             "TIER1_REPORT_DIGEST_DIFFERS")
    _require(value.get("tier") == 1
             and value.get("mechanism_digest") == mechanism_digest()
             and value.get("polished") is False
             and value.get("release_authorized") is False
             and value.get("full_application_status") == "UNKNOWN"
             and value.get("whole_tier_conformance")
                 in ("PASS", "NOT_ESTABLISHED"),
             "TIER1_REPORT_BOUNDARY_DIFFERS")
    _require(value.get("installed_denominators") == installed_denominators,
             "TIER1_REPORT_DENOMINATOR_DIFFERS")
    attempt = value.get("core_self_polish_attempt")
    union = value.get("union_validation")
    authority = value.get("application_authority")
    replay = value.get("complete_tier_evidence_replay")
    estate_evidence = value.get("candidate_estate_evidence")
    facet_reasons = value.get("tier1_facet_choice_reasons")
    ledger = value.get("complete_tier_ledger")
    representation = value.get("complete_self_representation")
    subset = value.get("retained_core_subset")
    expected_tier = installed_denominators["complete_tiers"]["1"]
    status = value.get("status")
    _require(status in ("PASS", "FAIL", "UNKNOWN")
             and value.get("selected_tier_status") == status,
             "TIER1_REPORT_VERDICT_DIFFERS")
    if status == "PASS":
        current_facet_reasons = _validated_facet_reason_assessment(
            installed_denominators
        )
        _require(
            facet_reasons == current_facet_reasons
            and current_facet_reasons.get("status") == "PASS",
            "TIER1_FACET_CHOICE_REASONS_NOT_ESTABLISHED",
        )
    derived_ledger = type(ledger) is dict and ledger.get("derivation") \
        == "NATIVE_REPLAY_RECEIPT"
    derived_representation = type(representation) is dict \
        and representation.get("derivation") \
        == "INSTALLED_REGISTRY_AND_NATIVE_REPLAY"
    representation_replay_digest = (
        representation.get("native_replay_receipt_digest")
        if derived_representation else representation.get("replay_receipt_digest")
        if type(representation) is dict else None
    )
    replay_complete = (
        type(replay) is dict and replay.get("status") == "PASS"
        and replay.get("invalidators") == []
        and type(replay.get("receipt_digest")) is str
        and type(ledger) is dict and ledger.get("status") == "PASS"
        and ledger.get("mechanical_replay_status") == "PASS"
        and ledger.get("replay_receipt_digest") == replay.get("receipt_digest")
        and type(representation) is dict
        and representation.get("status") == "PASS"
        and (derived_representation
             or representation.get("independent_evidence_status") == "PASS")
        and representation_replay_digest == replay.get("receipt_digest")
        and type(estate_evidence) is dict
        and all(estate_evidence.get(name) == "PASS" for name in (
            "native_self_verification_status",
            "native_semantic_applicability_status",
            "native_per_candidate_evidence_status",
        ))
        and representation.get("estate_evidence_result_digest")
            == estate_evidence.get("result_digest")
        and _representation_binds_facet_reasons(
            representation, facet_reasons
        )
    )
    estate_complete = (
        value.get("installed_route_normative_closure") == "PASS"
        and value.get("objective_inventory_closure") == "PASS"
        and value.get("structural_route_crosswalk_closure") == "PASS"
        and value.get("repository_package_estate_closure") == "PASS"
        and value.get("post_replay_full_source_recapture") == "PASS"
        and type(value.get("post_replay_source_recapture")) is dict
        and value["post_replay_source_recapture"].get("status") == "PASS"
        and type(estate_evidence) is dict
        and all(estate_evidence.get(name) == "PASS" for name in (
            "native_self_verification_status",
            "native_semantic_applicability_status",
            "native_per_candidate_evidence_status",
        ))
    )
    declared_complete = (
             status == "PASS"
             and value.get("whole_tier_conformance") == "PASS"
             and value.get("source_binding_status") == "PASS"
             and value.get("applicability_status") == "PASS"
             and value.get("authority_status") == "PASS"
             and value.get("dependency_status") == "PASS"
             and value.get("interaction_status") == "PASS"
             and value.get("blockers") == []
             and type(attempt) is dict and attempt.get("status") == "PASS"
             and attempt.get("external_selection_pin") in {
                 "MATCHED", "DERIVED_CURRENT_SOURCE",
             }
             and type(union) is dict and union.get("status") == "PASS"
             and type(authority) is dict and authority.get("status") == "PASS"
             and type(replay) is dict and replay.get("status") == "PASS"
             and replay.get("invalidators") == []
             and type(replay.get("receipt_digest")) is str
             and type(ledger) is dict and ledger.get("status") == "PASS"
             and (derived_ledger or ledger.get("declared_status") == "PASS")
             and ledger.get("mechanical_replay_status") == "PASS"
             and ledger.get("replay_receipt_digest")
                 == replay.get("receipt_digest")
             and ledger.get("tier_family_cell_count")
                 == expected_tier["family_cell_count"]
             and ledger.get("tier_membership_count")
                 == expected_tier["registered_route_membership_count"]
             and type(representation) is dict
             and representation.get("status") == "PASS"
             and (derived_representation or (
                 representation.get("declared_status") == "PASS"
                 and representation.get("independent_evidence_status") == "PASS"
             ))
             and representation_replay_digest == replay.get("receipt_digest")
             and type(estate_evidence) is dict
             and representation.get("estate_evidence_result_digest")
                 == estate_evidence.get("result_digest")
             and _representation_binds_facet_reasons(
                 representation, facet_reasons
             )
             and representation.get("represented_tiers") == [1]
             and representation.get("tier_ledger_digest")
                 == ledger.get("ledger_digest")
             and type(subset) is dict
             and subset.get("relationship_to_complete_tier")
                 == "NARROW_EVIDENCE_SUBSET"
             and subset.get("establishes_complete_tier") is False
             and estate_complete
    )
    _require(status != "PASS" or replay_complete,
             "TIER1_WHOLE_TIER_REPLAY_NOT_ESTABLISHED")
    _require(status != "PASS" or estate_complete,
             "TIER1_FULL_ESTATE_CLOSURE_NOT_ESTABLISHED")
    _require(status != "PASS" or declared_complete,
             "TIER1_REPORT_NOT_FULLY_PASS")
    if status == "PASS":
        _require(source_root is not None,
                 "TIER1_CANDIDATE_ESTATE_SOURCE_UNAVAILABLE")
        estate_census = value.get("candidate_estate_census")
        estate_applicability = value.get("candidate_estate_applicability")
        estate_authority = value.get("candidate_estate_authority")
        source_coordinate = value.get("source_coordinate")
        source_coordinate_digest = value.get("source_coordinate_digest")
        _require(type(source_coordinate) is dict
                 and type(source_coordinate_digest) is str
                 and core_obligation_union.value_digest(source_coordinate)
                     == source_coordinate_digest,
                 "TIER1_SOURCE_BINDING_DIFFERS")
        candidate_estate = _validated_retained_estate_census(
            estate_census,
            source_root=source_root,
            source_coordinate=source_coordinate,
            installed_denominators=installed_denominators,
        )
        estate_applicability = _validated_retained_estate_applicability(
            estate_applicability, candidate_estate=candidate_estate
        )
        estate_authority = _validated_retained_estate_authority(
            estate_authority,
            candidate_estate=candidate_estate,
            estate_census=estate_census,
            estate_applicability=estate_applicability,
            source_coordinate_digest=source_coordinate_digest,
            installed_denominators=installed_denominators,
        )
        _require(type(estate_evidence) is dict,
                 "TIER1_CANDIDATE_ESTATE_EVIDENCE_INVALID")
        estate_evidence = _validated_estate_evidence_result(
            estate_evidence,
            candidate_estate=candidate_estate,
            estate_applicability=estate_applicability,
            estate_authority=estate_authority,
            expected_manifest_digest=estate_evidence.get("manifest_digest"),
        )
        _require(estate_evidence["estate_authority_replay_digest"]
                     == estate_authority["result_digest"],
                 "TIER1_CANDIDATE_ESTATE_AUTHORITY_BINDING_DIFFERS")
    return value


def _dependency_summary(selection_bytes: bytes, bundle_bytes: bytes) -> dict[str, Any]:
    selection = _parse(selection_bytes, "PROGRESSION_SELECTION_INVALID")
    bundle = _parse(bundle_bytes, "PROGRESSION_BUNDLE_INVALID")
    _require(type(selection) is dict and type(bundle) is dict,
             "PROGRESSION_DEPENDENCY_INPUT_INVALID")
    ranks = {
        row.get("node_id"): row.get("tier")
        for row in selection.get("ranks", [])
        if type(row) is dict
    }
    edges = []
    for row in bundle.get("edges", []):
        if type(row) is dict and ranks.get(row.get("node_id")) == 2:
            edges.append({
                "node_tier": 2,
                "prerequisite_tier": ranks.get(row.get("prerequisite_id")),
                "operand_role_present": row.get("operand_role") is not None,
            })
    edges.sort(key=lambda row: (
        -1 if row["prerequisite_tier"] is None else row["prerequisite_tier"],
        row["operand_role_present"],
    ))
    return {
        "tier2_node_count": sum(tier == 2 for tier in ranks.values()),
        "declared_dependency_edge_count": len(edges),
        "declared_dependency_digest": core_obligation_union.value_digest(edges),
        "tier1_prerequisite_edge_count": sum(
            row["prerequisite_tier"] == 1 for row in edges
        ),
    }


def assess_self_polish_tier(tier: int, *, source_root: str | Path | None = None,
        expected_core_selection_digest: str | None = None,
        complete_tier_evidence_manifest_bytes: bytes | None = None,
        expected_complete_tier_evidence_manifest_digest: str | None = None,
        expected_evidence_replay_mechanism_digest: str | None = None,
        expected_candidate_estate_repository: str | None = None,
        expected_candidate_estate_revision: str | None = None,
        expected_candidate_estate_digest: str | None = None,
        candidate_estate_applicability_ledger_bytes: bytes | None = None,
        expected_candidate_estate_applicability_ledger_digest: str | None = None,
        candidate_estate_authority_replay: (
            core_application_authority.QualifiedAuthorityReplaySelection | None
        ) = None,
        candidate_estate_evidence_manifest_bytes: bytes | None = None,
        expected_candidate_estate_evidence_manifest_digest: str | None = None,
        expected_candidate_estate_evidence_mechanism_digest: str | None = None,
        candidate_estate_evidence_replays: Mapping[
            str,
            core_application_authority.QualifiedAuthorityReplaySelection | None,
        ] | None = None,
        candidate_estate_evidence_artifacts: Mapping[str, bytes] | None = None,
        union_authority: dict[str, Any] | None = None,
        union_contributions: list[dict[str, Any]] | None = None,
        expected_union_authority_digest: str | None = None,
        application_authority_assessment_bytes: bytes | None = None,
        expected_application_authority_assessment_digest: str | None = None,
        complete_tier_ledger_bytes: bytes | None = None,
        expected_complete_tier_ledger_digest: str | None = None,
        complete_self_representation_bytes: bytes | None = None,
        expected_complete_self_representation_digest: str | None = None,
        tier1_report_bytes: bytes | None = None,
        expected_tier1_report_digest: str | None = None,
        progression_selection_bytes: bytes | None = None,
        progression_bundle_bytes: bytes | None = None,
        progression_policy_bytes: bytes | None = None,
        progression_artifact_files: dict[str, bytes] | None = None,
        expected_progression_selection_digest: str | None = None,
        expected_progression_mechanism_digest: str | None = None,
        cancelled: bool = False) -> dict[str, Any]:
    """Attempt numeric tier 1 or 2 without widening its evidence boundary."""
    if type(tier) is not int or tier not in (1, 2):
        raise ValueError("numeric self-polish tier must be 1 or 2")
    object_id = "verifier-core-self"
    try:
        denominators = _denominators(object_id)
        report = _base_report(tier, denominators)
        estate_evidence_result = None
        facet_reason_assessment = None
        if tier == 1:
            if source_root is None:
                report["blockers"].append("SELF_POLISH_SOURCE_ROOT_UNAVAILABLE")
                return _finish(report)
            attempt = _attempt_tier1(source_root, expected_core_selection_digest)
            report["core_self_polish_attempt"] = attempt
            report["source_coordinate"] = attempt["source_coordinate"]
            report["source_coordinate_digest"] = attempt["source_coordinate_digest"]
            report["source_binding_status"] = (
                "PASS" if attempt["status"] == "PASS" else attempt["status"]
            )
            facets = denominators["facets"]
            report["retained_core_subset"] = {
                "relationship_to_complete_tier": "NARROW_EVIDENCE_SUBSET",
                "retained_concrete_instance_count": facets[
                    "instantiated_obligation_count"
                ],
                "complete_tier_family_cell_count": denominators[
                    "complete_tiers"
                ]["1"]["family_cell_count"],
                "complete_tier_membership_count": denominators[
                    "complete_tiers"
                ]["1"]["registered_route_membership_count"],
                "establishes_complete_tier": False,
            }
            counts_match = (
                attempt["installed_definition_count"]
                    == denominators["installed_structural_definition_count"]
                and attempt["installed_membership_count"]
                    == denominators["installed_structural_membership_count"]
                and attempt["instantiated_obligation_count"]
                    == facets["instantiated_obligation_count"]
            )
            _require(counts_match, "SELF_POLISH_DENOMINATOR_DIFFERS")
            if attempt["status"] == "FAIL":
                report.update(status="FAIL", selected_tier_status="FAIL")
                report["blockers"].append(
                    attempt.get("reason") or "CORE_SELF_POLISH_ATTEMPT_FAILED"
                )
                return _finish(report)
            if attempt["status"] != "PASS":
                report["blockers"].append("CORE_SELF_POLISH_ATTEMPT_NOT_PASS")
            if attempt["external_selection_pin"] == "MISMATCH":
                report["blockers"].append(
                    "CORE_SELF_POLISH_SELECTION_AUTHORITY_NOT_ESTABLISHED"
                )
            facet_reason_assessment = _validated_facet_reason_assessment(
                denominators
            )
            report["tier1_facet_choice_reasons"] = facet_reason_assessment
            if facet_reason_assessment["status"] == "FAIL":
                report.update(status="FAIL", selected_tier_status="FAIL")
                report["blockers"].append(
                    "FACET_CHOICE_NECESSITY_REASON_REJECTED"
                )
                report["blockers"].extend(
                    facet_reason_assessment["blockers"]
                )
                return _finish(report)
            if facet_reason_assessment["status"] != "PASS":
                report["blockers"].append(
                    "FACET_CHOICE_NECESSITY_REASON_NOT_ESTABLISHED"
                )
                report["blockers"].extend(
                    facet_reason_assessment["blockers"]
                )
                return _finish(report)
            report.update(
                installed_route_normative_closure=denominators[
                    "installed_route_normative_closure"
                ],
                objective_inventory_closure=denominators[
                    "objective_inventory_closure"
                ],
                structural_route_crosswalk_closure=denominators[
                    "structural_route_crosswalk_closure"
                ],
            )
            source_coordinate = attempt["source_coordinate"]
            expected_instances = facets["instantiated_obligation_count"]
            (
                estate_census,
                estate_applicability,
                candidate_estate,
                effective_estate_ledger_bytes,
                effective_estate_ledger_digest,
            ) = (
                _candidate_estate_inputs(
                source_root=source_root,
                source_coordinate=source_coordinate,
                denominators=denominators,
                expected_repository=expected_candidate_estate_repository,
                expected_revision=expected_candidate_estate_revision,
                expected_estate_digest=expected_candidate_estate_digest,
                applicability_ledger_bytes=(
                    candidate_estate_applicability_ledger_bytes
                ),
                expected_applicability_ledger_digest=(
                    expected_candidate_estate_applicability_ledger_digest
                ),
                )
            )
            report["candidate_estate_census"] = estate_census
            report["candidate_estate_applicability"] = estate_applicability
            evidence_selection = (
                candidate_estate_evidence_manifest_bytes,
                expected_candidate_estate_evidence_manifest_digest,
                expected_candidate_estate_evidence_mechanism_digest,
            )
            selected_candidate_replays = (
                {} if candidate_estate_evidence_replays is None
                else candidate_estate_evidence_replays
            )
            selected_candidate_artifacts = (
                {} if candidate_estate_evidence_artifacts is None
                else candidate_estate_evidence_artifacts
            )
            _require(isinstance(selected_candidate_replays, Mapping),
                     "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INVALID")
            _require(isinstance(selected_candidate_artifacts, Mapping)
                     and all(type(key) is str and key
                             and type(raw) is bytes
                             for key, raw in selected_candidate_artifacts.items()),
                     "CANDIDATE_ESTATE_EVIDENCE_ARTIFACT_INVALID")
            if estate_census is None:
                _require(candidate_estate_authority_replay is None,
                         "CANDIDATE_ESTATE_AUTHORITY_SELECTION_INCOMPLETE")
                _require(all(value is None for value in evidence_selection)
                         and not selected_candidate_replays
                         and not selected_candidate_artifacts,
                         "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INCOMPLETE")
                report["blockers"].append(
                    "CANDIDATE_ESTATE_CENSUS_UNAVAILABLE"
                )
            else:
                report["repository_package_estate"].update({
                    "independently_pinned_census": "MATCHED",
                    "all_tracked_byte_census": "PASS",
                    "mechanical_census_status": "PASS",
                    "candidate_count": estate_census["candidate_count"],
                    "candidate_universe_digest": estate_census[
                        "candidate_universe_digest"
                    ],
                    "estate_digest": estate_census["estate_digest"],
                    "applicability_ledger_validation": (
                        estate_applicability["mechanical_validation_status"]
                        if estate_applicability is not None
                        else "NOT_ESTABLISHED"
                    ),
                    "caller_pass_authentication": (
                        estate_applicability["caller_pass_authentication"]
                        if estate_applicability is not None
                        else "NOT_ESTABLISHED"
                    ),
                })
                report["repository_package_estate_closure"] = estate_census[
                    "full_estate_closure"
                ]
                if estate_applicability is None:
                    report["blockers"].append(
                        "CANDIDATE_ESTATE_APPLICABILITY_LEDGER_UNAVAILABLE"
                    )
                    _require(candidate_estate_authority_replay is None,
                             "CANDIDATE_ESTATE_AUTHORITY_SELECTION_INCOMPLETE")
                    _require(all(value is None for value in evidence_selection)
                             and not selected_candidate_replays
                             and not selected_candidate_artifacts,
                             "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INCOMPLETE")
                else:
                    crosswalk = estate_census["structural_route_crosswalk"]
                    authority_subject = (
                        self_polish_estate_authority.estate_authority_subject(
                            source_coordinate_digest=report[
                                "source_coordinate_digest"
                            ],
                            estate_source_coordinate_digest=(
                                self_polish_estate.value_digest(
                                    estate_census["source_coordinate"]
                                )
                            ),
                            candidate_source_census_digest=estate_census[
                                "source_coordinate"
                            ]["candidate_source_census_digest"],
                            estate_digest=estate_census["estate_digest"],
                            candidate_universe_digest=estate_census[
                                "candidate_universe_digest"
                            ],
                            required_categories_digest=estate_census[
                                "required_categories_digest"
                            ],
                            category_summaries_digest=estate_census[
                                "category_summaries_digest"
                            ],
                            applicability_ledger_digest=estate_applicability[
                                "ledger_digest"
                            ],
                            installed_inventory_digest=denominators[
                                "installed_route_inventory_digest"
                            ],
                            objective_catalog_digest=denominators[
                                "objective_inventory_digest"
                            ],
                            structural_route_crosswalk_digest=estate_census[
                                "structural_route_crosswalk_digest"
                            ],
                            structural_identity_digest=crosswalk[
                                "structural_identity_digest"
                            ],
                            route_identity_digest=crosswalk[
                                "route_identity_digest"
                            ],
                            shared_identity_digest=crosswalk[
                                "shared_identity_digest"
                            ],
                        )
                    )
                    estate_authority = (
                        self_polish_estate_authority.replay_estate_authority(
                            authority_subject,
                            authority_replay=(
                                _current_authority_selection(
                                    candidate_estate_authority_replay
                                )
                            ),
                        )
                    )
                    report["candidate_estate_authority"] = estate_authority
                    report["repository_package_estate"][
                        "independent_authority_status"
                    ] = estate_authority["independent_authority_status"]
                    if estate_authority["status"] == "FAIL":
                        report.update(status="FAIL", selected_tier_status="FAIL")
                        report["blockers"].append(
                            "CANDIDATE_ESTATE_AUTHORITY_REJECTED"
                        )
                    if (
                        estate_census["external_estate_digest_pin"]
                            == "DERIVED_CURRENT_SOURCE"
                        and all(value is None for value in evidence_selection)
                        and not selected_candidate_replays
                        and not selected_candidate_artifacts
                    ):
                        (
                            candidate_estate_evidence_manifest_bytes,
                            expected_candidate_estate_evidence_manifest_digest,
                            expected_candidate_estate_evidence_mechanism_digest,
                            selected_candidate_artifacts,
                        ) = _derived_estate_evidence_inputs(
                            estate=candidate_estate,
                            ledger_bytes=effective_estate_ledger_bytes,
                            expected_ledger_digest=(
                                effective_estate_ledger_digest
                            ),
                            authority_subject=authority_subject,
                        )
                        evidence_selection = (
                            candidate_estate_evidence_manifest_bytes,
                            expected_candidate_estate_evidence_manifest_digest,
                            expected_candidate_estate_evidence_mechanism_digest,
                        )
                    if (all(value is None for value in evidence_selection)
                            and not selected_candidate_replays
                            and not selected_candidate_artifacts):
                        report["blockers"].append(
                            "CANDIDATE_ESTATE_EVIDENCE_MANIFEST_UNAVAILABLE"
                        )
                    else:
                        _require(all(value is not None
                                     for value in evidence_selection),
                                 "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INCOMPLETE")
                        _require(
                            expected_candidate_estate_evidence_mechanism_digest
                            == self_polish_estate_evidence.mechanism_digest(),
                            "CANDIDATE_ESTATE_EVIDENCE_MECHANISM_DIFFERS",
                        )
                        estate_evidence_result = (
                            self_polish_estate_evidence.replay_estate_evidence(
                                estate=candidate_estate,
                                ledger_bytes=effective_estate_ledger_bytes,
                                expected_ledger_digest=effective_estate_ledger_digest,
                                manifest_bytes=(
                                    candidate_estate_evidence_manifest_bytes
                                ),
                                expected_manifest_digest=(
                                    expected_candidate_estate_evidence_manifest_digest
                                ),
                                estate_authority_subject=authority_subject,
                                estate_authority_replay=(
                                    candidate_estate_authority_replay
                                ),
                                candidate_replays=selected_candidate_replays,
                                source_root=source_root,
                                evidence_artifacts=(
                                    selected_candidate_artifacts
                                ),
                            )
                        )
                        estate_evidence_result = (
                            _validated_estate_evidence_result(
                                estate_evidence_result,
                                candidate_estate=candidate_estate,
                                estate_applicability=estate_applicability,
                                estate_authority=estate_authority,
                                expected_manifest_digest=(
                                    expected_candidate_estate_evidence_manifest_digest
                                ),
                            )
                        )
                        report["candidate_estate_evidence"] = (
                            estate_evidence_result
                        )
                        native_estate_components = [
                            estate_evidence_result[name] for name in (
                                "native_self_verification_status",
                                "native_semantic_applicability_status",
                                "native_per_candidate_evidence_status",
                            )
                        ]
                        native_estate_status = (
                            "FAIL" if "FAIL" in native_estate_components
                            else "PASS" if all(
                                item == "PASS"
                                for item in native_estate_components
                            ) else "UNKNOWN"
                        )
                        report["repository_package_estate"].update({
                            "semantic_applicability_status": (
                                native_estate_status
                            ),
                            "per_obligation_replay_status": (
                                native_estate_status
                            ),
                            "registry_candidate_classification": (
                                native_estate_status
                            ),
                            "package_surface_closure": native_estate_status,
                            "public_api_cli_schema_closure": (
                                native_estate_status
                            ),
                            "status": native_estate_status,
                            "estate_evidence_result_digest": (
                                estate_evidence_result["result_digest"]
                            ),
                        })
                        report["repository_package_estate_closure"] = (
                            native_estate_status
                        )
                        if estate_evidence_result["status"] == "FAIL" \
                                or native_estate_status == "FAIL":
                            report.update(
                                status="FAIL", selected_tier_status="FAIL"
                            )
                            report["blockers"].append(
                                "CANDIDATE_ESTATE_EVIDENCE_REJECTED"
                            )
                        elif native_estate_status != "PASS":
                            report["blockers"].append(
                                "CANDIDATE_ESTATE_NATIVE_SELF_VERIFICATION_NOT_PASS"
                            )
                if report["repository_package_estate_closure"] != "PASS":
                    report["blockers"].append(
                        "CANDIDATE_ESTATE_SEMANTIC_CLOSURE_NOT_ESTABLISHED"
                    )
        else:
            retained = _retained_tier1(
                tier1_report_bytes,
                expected_tier1_report_digest,
                installed_denominators=denominators,
                source_root=source_root,
            )
            if retained is None:
                report["blockers"].append("TIER1_PASS_REPORT_REQUIRED")
                return _finish(report)
            report["source_coordinate"] = retained.get("source_coordinate")
            report["source_coordinate_digest"] = retained.get(
                "source_coordinate_digest"
            )
            report["source_binding_status"] = retained.get(
                "source_binding_status", "UNKNOWN"
            )
            report["retained_core_subset"] = retained.get("retained_core_subset")
            estate_evidence_result = retained.get("candidate_estate_evidence")
            facet_reason_assessment = retained.get(
                "tier1_facet_choice_reasons"
            )
            report["tier1_facet_choice_reasons"] = facet_reason_assessment
            for closure_name in (
                "installed_route_normative_closure",
                "objective_inventory_closure",
                "structural_route_crosswalk_closure",
            ):
                report[closure_name] = retained.get(
                    closure_name, "NOT_ESTABLISHED"
                )
            if retained.get("status") == "FAIL":
                report.update(status="FAIL", selected_tier_status="FAIL")
                report["blockers"].append("TIER1_FAILED")
                return _finish(report)
            if retained.get("status") != "PASS" \
                    or retained.get("selected_tier_status") != "PASS":
                report["blockers"].append("TIER1_FULL_PASS_REQUIRED")
                return _finish(report)
            if source_root is None:
                report["blockers"].append("SELF_POLISH_SOURCE_ROOT_UNAVAILABLE")
                return _finish(report)
            source_coordinate = retained.get("source_coordinate")
            _require(type(source_coordinate) is dict
                     and core_obligation_union.value_digest(source_coordinate)
                         == retained.get("source_coordinate_digest"),
                     "TIER1_SOURCE_BINDING_DIFFERS")
            pre_replay_recapture = _post_replay_source_recapture(
                source_root, source_coordinate
            )
            report["pre_replay_source_recapture"] = pre_replay_recapture
            if pre_replay_recapture["status"] == "FAIL":
                report.update(status="FAIL", selected_tier_status="FAIL")
                report["blockers"].append("TIER2_PRE_REPLAY_FULL_SOURCE_DIFFERS")
                return _finish(report)
            if pre_replay_recapture["status"] != "PASS":
                report["blockers"].append(
                    "TIER2_PRE_REPLAY_FULL_SOURCE_RECAPTURE_NOT_ESTABLISHED"
                )
                return _finish(report)
            expected_instances = (
                denominators["facets"]["instantiated_obligation_count"]
                + denominators["dynamics"]["registered_route_membership_count"]
            )

        expected_union_members = denominators["complete_tiers"][str(tier)][
            "registered_route_membership_count"
        ]
        union = _union_summary(
            union_authority,
            union_contributions,
            expected_authority_digest=expected_union_authority_digest,
            source_coordinate=source_coordinate,
            tier=tier,
            expected_members=expected_union_members,
        )
        if union is None and Path(source_root).is_dir():
            union = _derived_route_union_summary(
                source_coordinate=source_coordinate,
                tier=tier,
                expected_members=expected_union_members,
                denominators=denominators,
            )
        report["union_validation"] = union
        authority = _authority_summary(
            application_authority_assessment_bytes,
            expected_digest=expected_application_authority_assessment_digest,
            union_summary=union,
            expected_instances=expected_instances,
        )
        if (
            authority is None
            and type(union) is dict
            and union.get("derivation") == "INSTALLED_REGISTRY_CLOSURE"
        ):
            authority = _derived_application_authority_summary(
                union_summary=union,
                expected_instances=expected_instances,
                source_coordinate=source_coordinate,
                tier=tier,
                denominators=denominators,
            )
        report["application_authority"] = authority
        if union is None:
            report["blockers"].append("OBLIGATION_UNION_AUTHORITY_UNAVAILABLE")
        elif union["status"] == "FAIL":
            report.update(status="FAIL", selected_tier_status="FAIL")
            report["blockers"].append("OBLIGATION_UNION_REJECTED")
        if authority is None:
            report["blockers"].append("APPLICATION_AUTHORITY_UNAVAILABLE")
        else:
            report["applicability_status"] = authority["binding_status"]
            report["authority_status"] = authority["authority_status"]
            report["dependency_status"] = authority["child_status"]
            report["interaction_status"] = authority["interaction_status"]
            if authority["status"] == "FAIL":
                report.update(status="FAIL", selected_tier_status="FAIL")
                report["blockers"].append("APPLICATION_AUTHORITY_REJECTED")
        evidence_replay = _replay_tier_evidence(
                complete_tier_evidence_manifest_bytes,
                tier=tier,
                expected_manifest_digest=(
                    expected_complete_tier_evidence_manifest_digest
                ),
                expected_mechanism_digest=(
                    expected_evidence_replay_mechanism_digest
                ),
                source_root=source_root,
                source_coordinate=source_coordinate,
                denominators=denominators,
            )
        report["complete_tier_evidence_replay"] = evidence_replay
        if evidence_replay is None:
            report["blockers"].append(
                "COMPLETE_TIER_EVIDENCE_MANIFEST_UNAVAILABLE"
            )
        elif evidence_replay["status"] == "FAIL":
            report.update(status="FAIL", selected_tier_status="FAIL")
            report["blockers"].append(
                "COMPLETE_TIER_EVIDENCE_REPLAY_FAILED"
            )
        elif evidence_replay["status"] != "PASS":
            report["blockers"].append(
                "COMPLETE_TIER_EVIDENCE_REPLAY_NOT_PASS"
            )
            report["blockers"].extend(
                evidence_replay.get("invalidators", [])
            )
        if complete_tier_ledger_bytes is None \
                and expected_complete_tier_ledger_digest is None:
            ledger = _derived_complete_tier_ledger(
                tier=tier,
                source_coordinate=source_coordinate,
                denominators=denominators,
                evidence_replay=evidence_replay,
            )
        else:
            ledger = _complete_tier_ledger(
                complete_tier_ledger_bytes,
                expected_digest=expected_complete_tier_ledger_digest,
                source_coordinate=source_coordinate,
                tier=tier,
                denominators=denominators,
                evidence_replay=evidence_replay,
            )
        report["complete_tier_ledger"] = ledger
        prior_report_digest = retained["report_digest"] if tier == 2 else None
        if complete_self_representation_bytes is None \
                and expected_complete_self_representation_digest is None:
            representation = _derived_self_representation(
                tier=tier,
                source_coordinate=source_coordinate,
                denominators=denominators,
                ledger=ledger,
                evidence_replay=evidence_replay,
                prior_whole_tier_report_digest=prior_report_digest,
                estate_evidence_result=estate_evidence_result,
                facet_reason_assessment=facet_reason_assessment,
            )
        else:
            representation = _complete_self_representation(
                complete_self_representation_bytes,
                expected_digest=expected_complete_self_representation_digest,
                source_coordinate=source_coordinate,
                tier=tier,
                denominators=denominators,
                ledger_digest=(ledger.get("ledger_digest")
                               if ledger is not None else None),
                prior_whole_tier_report_digest=prior_report_digest,
                evidence_replay=evidence_replay,
                estate_evidence_result=estate_evidence_result,
                facet_reason_assessment=facet_reason_assessment,
                ledger_mechanical_replay_status=(
                    ledger.get("mechanical_replay_status")
                    if ledger is not None else "NOT_ESTABLISHED"
                ),
            )
        report["complete_self_representation"] = representation
        if ledger is None:
            report["blockers"].append("COMPLETE_TIER_LEDGER_UNAVAILABLE")
        elif ledger["status"] == "FAIL":
            report.update(status="FAIL", selected_tier_status="FAIL")
            report["blockers"].append("COMPLETE_TIER_LEDGER_FAILED")
        elif ledger["status"] != "PASS":
            report["blockers"].append("COMPLETE_TIER_LEDGER_NOT_PASS")
            if ledger["mechanical_replay_status"] != "PASS":
                report["blockers"].append(
                    "COMPLETE_TIER_EVIDENCE_REPLAY_NOT_ESTABLISHED"
                )
        if representation is None:
            report["blockers"].append(
                "COMPLETE_SELF_REPRESENTATION_UNAVAILABLE"
            )
        elif representation["status"] == "FAIL":
            report.update(status="FAIL", selected_tier_status="FAIL")
            report["blockers"].append("COMPLETE_SELF_REPRESENTATION_FAILED")
        elif representation["status"] != "PASS":
            report["blockers"].append("COMPLETE_SELF_REPRESENTATION_NOT_PASS")
            if representation.get("independent_evidence_status",
                                  representation.get("status")) != "PASS":
                report["blockers"].append(
                    "COMPLETE_SELF_REPRESENTATION_REPLAY_NOT_ESTABLISHED"
                )
        if report["status"] == "FAIL":
            return _finish(report)

        if tier == 1:
            if evidence_replay is not None \
                    and evidence_replay.get("status") == "PASS":
                recapture = _post_replay_source_recapture(
                    source_root, source_coordinate
                )
                report["post_replay_source_recapture"] = recapture
                report["post_replay_full_source_recapture"] = recapture[
                    "status"
                ]
                if recapture["status"] == "FAIL":
                    report.update(status="FAIL", selected_tier_status="FAIL")
                    report["blockers"].append(
                        "POST_REPLAY_FULL_SOURCE_DIFFERS"
                    )
                    return _finish(report)
                if recapture["status"] != "PASS":
                    report["blockers"].append(
                        "POST_REPLAY_FULL_SOURCE_RECAPTURE_NOT_ESTABLISHED"
                    )
            bounded_route_complete = (
                attempt["status"] == "PASS"
                and facet_reason_assessment is not None
                and facet_reason_assessment.get("status") == "PASS"
                and attempt["external_selection_pin"] in {
                    "MATCHED", "DERIVED_CURRENT_SOURCE",
                }
                and union is not None and union["status"] == "PASS"
                and authority is not None and authority["status"] == "PASS"
                and ledger is not None and ledger["status"] == "PASS"
                and representation is not None
                and representation["status"] == "PASS"
            )
            estate_complete = (
                report["installed_route_normative_closure"] == "PASS"
                and report["objective_inventory_closure"] == "PASS"
                and report["structural_route_crosswalk_closure"] == "PASS"
                and report["repository_package_estate_closure"] == "PASS"
                and report["post_replay_full_source_recapture"] == "PASS"
            )
            if bounded_route_complete and estate_complete:
                report.update(
                    status="PASS", selected_tier_status="PASS",
                    whole_tier_conformance="PASS",
                )
            else:
                if not bounded_route_complete:
                    report["blockers"].append(
                        "TIER1_COMPLETE_TIER_NOT_ESTABLISHED"
                    )
                if not estate_complete:
                    report["blockers"].append(
                        "REGISTRY_OR_FULL_ESTATE_CLOSURE_NOT_ESTABLISHED"
                    )
            return _finish(report)

        required = (
            progression_selection_bytes,
            progression_bundle_bytes,
            progression_policy_bytes,
            progression_artifact_files,
            expected_progression_selection_digest,
            expected_progression_mechanism_digest,
        )
        if any(value is None for value in required):
            report["blockers"].append("TIER2_PROGRESSION_INPUTS_UNAVAILABLE")
            return _finish(report)
        progression = core_tier_progression.assess_tier_progression(
            progression_selection_bytes,
            bundle_bytes=progression_bundle_bytes,
            expected_policy_bytes=progression_policy_bytes,
            artifact_files=progression_artifact_files,
            expected_selection_digest=expected_progression_selection_digest,
            expected_mechanism_digest=expected_progression_mechanism_digest,
            cancelled=cancelled,
        )
        report["core_progression_attempt"] = progression
        report["declared_dependencies"] = _dependency_summary(
            progression_selection_bytes, progression_bundle_bytes
        )
        tiers = progression.get("tiers")
        _require(type(tiers) is list and len(tiers) >= 2
                 and progression.get("subject", {}).get("object_id")
                     == retained["core_self_polish_attempt"]["root_id"],
                 "TIER2_PROGRESSION_REPORT_DIFFERS")
        tier1_pass = tiers[0].get("cumulative_status") == "PASS"
        tier2_pass = (tiers[1].get("direct_status") == "PASS"
                      and tiers[1].get("cumulative_status") == "PASS"
                      and progression.get("selected_target_status") == "PASS")
        recapture = _post_replay_source_recapture(
            source_root, source_coordinate
        )
        report["post_replay_source_recapture"] = recapture
        report["post_replay_full_source_recapture"] = recapture["status"]
        if recapture["status"] == "FAIL":
            report.update(status="FAIL", selected_tier_status="FAIL")
            report["blockers"].append("POST_REPLAY_FULL_SOURCE_DIFFERS")
        elif recapture["status"] != "PASS":
            report["blockers"].append(
                "POST_REPLAY_FULL_SOURCE_RECAPTURE_NOT_ESTABLISHED"
            )
        if progression.get("status") == "FAIL" \
                or tiers[0].get("cumulative_status") == "FAIL":
            report.update(status="FAIL", selected_tier_status="FAIL")
            report["blockers"].append("TIER2_PROGRESSION_REJECTED")
        elif not tier1_pass:
            report["blockers"].append("TIER2_PROGRESSION_TIER1_NOT_PASS")
        elif not tier2_pass:
            report["blockers"].append("TIER2_DYNAMICS_NOT_PASS")
        elif union is not None and union["status"] == "PASS" \
                and authority is not None and authority["status"] == "PASS" \
                and ledger is not None and ledger["status"] == "PASS" \
                and representation is not None \
                and representation["status"] == "PASS" \
                and evidence_replay is not None \
                and evidence_replay.get("status") == "PASS" \
                and recapture["status"] == "PASS" \
                and report["installed_route_normative_closure"] == "PASS" \
                and report["objective_inventory_closure"] == "PASS" \
                and report["structural_route_crosswalk_closure"] == "PASS":
            report.update(
                status="PASS", selected_tier_status="PASS",
                whole_tier_conformance="PASS",
            )
        else:
            report["blockers"].append(
                "TIER2_COMPLETE_TIER_NOT_ESTABLISHED"
            )
        return _finish(report)
    except polish_requirements.MechanismBindingUnavailable:
        report = locals().get("report") or _base_report(tier, {})
        report["blockers"].append("SELF_POLISH_MECHANISM_OR_SOURCE_UNAVAILABLE")
        return _finish(report)
    except (_ContractError, polish_requirements.RequirementRefusal,
            self_polish_estate.EstateError) as exc:
        report = locals().get("report") or _base_report(tier, {})
        report.update(status="FAIL", selected_tier_status="FAIL")
        report["blockers"].append(str(exc))
        return _finish(report)
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        report = locals().get("report") or _base_report(tier, {})
        report["blockers"].append("SELF_POLISH_TIER_MECHANISM_UNAVAILABLE")
        return _finish(report)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        report = locals().get("report") or _base_report(tier, {})
        report.update(status="FAIL", selected_tier_status="FAIL")
        report["blockers"].append("SELF_POLISH_TIER_CONTRACT_REJECTED")
        return _finish(report)


def _read(path: str | None, max_bytes: int = MAX_INPUT_BYTES) -> bytes | None:
    if path is None:
        return None
    with Path(path).open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise OSError("bounded input unavailable")
    return raw


def _json_report_wire_bytes(report: dict[str, Any]) -> bytes:
    """Return exact pretty-JSON command-line bytes, newline included."""

    return (
        json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _guard_tier1_report_wire_capacity(
        report: dict[str, Any]) -> dict[str, Any]:
    """Never emit an unreadable over-capacity Tier 1 result as PASS."""

    if report.get("status") != "PASS" \
            or len(_json_report_wire_bytes(report)) <= MAX_TIER1_REPORT_BYTES:
        return report
    report = dict(report)
    report.pop("report_digest", None)
    report.update(
        status="FAIL",
        selected_tier_status="FAIL",
        whole_tier_conformance="NOT_ESTABLISHED",
    )
    blockers = report.get("blockers")
    report["blockers"] = list(blockers) if type(blockers) is list else []
    report["blockers"].append(
        "TIER1_PASS_REPORT_TRANSPORT_CAPACITY_EXHAUSTED"
    )
    return _finish(report)


def _json_input(path: str | None, expected: type) -> Any:
    raw = _read(path)
    if raw is None:
        return None
    value = _parse(raw, "SELF_POLISH_TIER_INPUT_INVALID")
    _require(type(value) is expected, "SELF_POLISH_TIER_INPUT_INVALID")
    return value


def _candidate_estate_authority_selection(
        args: argparse.Namespace,
        ) -> core_application_authority.QualifiedAuthorityReplaySelection | None:
    """Load one exact host-selected configured-key authority replay."""
    names = (
        "candidate_estate_authority_policy",
        "candidate_estate_authority_policy_digest",
        "candidate_estate_authority_receipt",
        "candidate_estate_authority_receipt_digest",
        "candidate_estate_authority_mechanism_digest",
        "candidate_estate_authority_operation_revision_digest",
        "candidate_estate_authority_instruction_revision_digest",
        "candidate_estate_authority_context_revision_digest",
        "candidate_estate_authority_subject_digest",
        "candidate_estate_authority_evaluation_time",
        "candidate_estate_authority_minimum_status_sequence",
    )
    selected = [getattr(args, name) for name in names]
    if all(value is None for value in selected):
        return None
    _require(all(value is not None for value in selected),
             "CANDIDATE_ESTATE_AUTHORITY_SELECTION_INCOMPLETE")
    return core_application_authority.QualifiedAuthorityReplaySelection(
        policy_bytes=_read(args.candidate_estate_authority_policy),
        expected_policy_digest=(
            args.candidate_estate_authority_policy_digest
        ),
        receipt_bytes=_read(args.candidate_estate_authority_receipt),
        expected_receipt_digest=(
            args.candidate_estate_authority_receipt_digest
        ),
        expected_mechanism_digest=(
            args.candidate_estate_authority_mechanism_digest
        ),
        expected_operation=self_polish_estate_authority.OPERATION,
        expected_operation_revision_digest=(
            args.candidate_estate_authority_operation_revision_digest
        ),
        expected_instruction_revision_digest=(
            args.candidate_estate_authority_instruction_revision_digest
        ),
        expected_context_revision_digest=(
            args.candidate_estate_authority_context_revision_digest
        ),
        expected_subject_digest=(
            args.candidate_estate_authority_subject_digest
        ),
        evaluation_time=args.candidate_estate_authority_evaluation_time,
        minimum_status_sequence=(
            args.candidate_estate_authority_minimum_status_sequence
        ),
    )


def _candidate_estate_evidence_selections(
        paths: list[str] | None,
        ) -> dict[
            str, core_application_authority.QualifiedAuthorityReplaySelection
        ]:
    """Load independently selected per-candidate configured-key replays."""
    if paths is None:
        return {}
    _require(0 < len(paths) <= self_polish_estate.MAX_CANDIDATES,
             "CANDIDATE_ESTATE_EVIDENCE_SELECTION_COUNT_INVALID")
    required = {
        "candidate_id", "policy", "expected_policy_digest", "receipt",
        "expected_receipt_digest", "expected_mechanism_digest",
        "expected_operation_revision_digest",
        "expected_instruction_revision_digest",
        "expected_context_revision_digest", "expected_subject_digest",
        "evaluation_time", "minimum_status_sequence",
    }
    selections = {}
    for path in paths:
        value = _json_input(path, dict)
        _require(type(value) is dict and set(value) == required,
                 "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INVALID")
        candidate_id = value["candidate_id"]
        _require(type(candidate_id) is str and candidate_id
                 and candidate_id not in selections
                 and type(value["policy"]) is dict
                 and type(value["receipt"]) is dict,
                 "CANDIDATE_ESTATE_EVIDENCE_SELECTION_INVALID")
        selections[candidate_id] = (
            core_application_authority.QualifiedAuthorityReplaySelection(
                policy_bytes=core_application_authority.canonical_bytes(
                    value["policy"]
                ),
                expected_policy_digest=value["expected_policy_digest"],
                receipt_bytes=core_application_authority.canonical_bytes(
                    value["receipt"]
                ),
                expected_receipt_digest=value["expected_receipt_digest"],
                expected_mechanism_digest=value["expected_mechanism_digest"],
                expected_operation=self_polish_estate_evidence.OPERATION,
                expected_operation_revision_digest=value[
                    "expected_operation_revision_digest"
                ],
                expected_instruction_revision_digest=value[
                    "expected_instruction_revision_digest"
                ],
                expected_context_revision_digest=value[
                    "expected_context_revision_digest"
                ],
                expected_subject_digest=value["expected_subject_digest"],
                evaluation_time=value["evaluation_time"],
                minimum_status_sequence=value["minimum_status_sequence"],
            )
        )
    return selections


def _candidate_estate_evidence_artifacts(
        paths: list[str] | None) -> dict[str, bytes]:
    """Load bounded native evidence bytes keyed by exact candidate id."""
    if paths is None:
        return {}
    _require(0 < len(paths) <= self_polish_estate.MAX_CANDIDATES,
             "CANDIDATE_ESTATE_EVIDENCE_ARTIFACT_COUNT_INVALID")
    artifacts: dict[str, bytes] = {}
    for path in paths:
        value = _json_input(path, dict)
        _require(type(value) is dict
                 and set(value) == {"candidate_id", "artifact_base64"}
                 and type(value["candidate_id"]) is str
                 and value["candidate_id"]
                 and value["candidate_id"] not in artifacts
                 and type(value["artifact_base64"]) is str,
                 "CANDIDATE_ESTATE_EVIDENCE_ARTIFACT_INVALID")
        try:
            raw = base64.b64decode(value["artifact_base64"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise _ContractError(
                "CANDIDATE_ESTATE_EVIDENCE_ARTIFACT_INVALID"
            ) from exc
        _require(len(raw) <= MAX_INPUT_BYTES,
                 "CANDIDATE_ESTATE_EVIDENCE_ARTIFACT_CAPACITY_EXHAUSTED")
        artifacts[value["candidate_id"]] = raw
    return artifacts


def build_self_polish_tier_parser() -> argparse.ArgumentParser:
    """Build the parser used by the command-line interface (CLI) dispatch hook."""
    parser = argparse.ArgumentParser(prog="vstd polish")
    commands = parser.add_subparsers(dest="self_polish_tier", required=True)
    for tier in (1, 2):
        action = commands.add_parser(str(tier), help=(
            "Attempt source-bound Facets." if tier == 1
            else "Attempt Dynamics after a retained PASS Facets report."
        ))
        action.add_argument("--union-authority")
        action.add_argument("--union-contributions")
        action.add_argument("--union-authority-digest")
        action.add_argument("--application-authority-assessment")
        action.add_argument("--application-authority-assessment-digest")
        action.add_argument("--complete-tier-ledger")
        action.add_argument("--complete-tier-ledger-digest")
        action.add_argument("--complete-self-representation")
        action.add_argument("--complete-self-representation-digest")
        action.add_argument("--source-root", default=".")
        action.add_argument("--complete-tier-evidence-manifest")
        action.add_argument("--complete-tier-evidence-manifest-digest")
        action.add_argument("--evidence-replay-mechanism-digest")
        action.add_argument("--json", action="store_true")
        if tier == 1:
            action.add_argument("--selection-digest")
            action.add_argument("--candidate-estate-repository")
            action.add_argument("--candidate-estate-revision")
            action.add_argument("--candidate-estate-digest")
            action.add_argument("--candidate-estate-applicability-ledger")
            action.add_argument(
                "--candidate-estate-applicability-ledger-digest"
            )
            action.add_argument(
                "--candidate-estate-authority-policy",
                help="Independently selected estate-authority policy JSON.",
            )
            action.add_argument(
                "--candidate-estate-authority-policy-digest",
                help="Expected SHA-256 digest of the authority policy bytes.",
            )
            action.add_argument(
                "--candidate-estate-authority-receipt",
                help="Configured-key estate-authority receipt JSON.",
            )
            action.add_argument(
                "--candidate-estate-authority-receipt-digest",
                help="Expected SHA-256 digest of the authority receipt bytes.",
            )
            action.add_argument(
                "--candidate-estate-authority-mechanism-digest",
                help="Expected installed estate-authority mechanism digest.",
            )
            action.add_argument(
                "--candidate-estate-authority-operation-revision-digest",
                help="Pinned authority operation revision digest.",
            )
            action.add_argument(
                "--candidate-estate-authority-instruction-revision-digest",
                help="Pinned authority instruction revision digest.",
            )
            action.add_argument(
                "--candidate-estate-authority-context-revision-digest",
                help="Pinned authority context revision digest.",
            )
            action.add_argument(
                "--candidate-estate-authority-subject-digest",
                help="Expected digest of the exact estate-authority subject.",
            )
            action.add_argument(
                "--candidate-estate-authority-evaluation-time", type=int,
                help="Pinned Unix evaluation time for authority freshness.",
            )
            action.add_argument(
                "--candidate-estate-authority-minimum-status-sequence", type=int,
                help="Minimum accepted authority status sequence.",
            )
            action.add_argument(
                "--candidate-estate-evidence-manifest",
                help="Exact per-candidate semantic-evidence manifest JSON.",
            )
            action.add_argument(
                "--candidate-estate-evidence-manifest-digest",
                help="Expected digest of the canonical evidence manifest.",
            )
            action.add_argument(
                "--candidate-estate-evidence-mechanism-digest",
                help="Expected installed per-candidate replay mechanism digest.",
            )
            action.add_argument(
                "--candidate-estate-evidence-selection", action="append",
                help=(
                    "Repeatable configured-key replay selection JSON; provide "
                    "one for each independently replayed candidate."
                ),
            )
            action.add_argument(
                "--candidate-estate-evidence-artifact", action="append",
                help=(
                    "Repeatable JSON carrying candidate_id and base64 native "
                    "evidence bytes for applicable estate candidates."
                ),
            )
        else:
            action.add_argument(
                "--tier1-report",
                help=(
                    "Retained full Tier 1 JSON report; at most 16 MiB "
                    "including any final newline."
                ),
            )
            action.add_argument("--tier1-report-digest")
            action.add_argument("--progression-selection")
            action.add_argument("--bundle")
            action.add_argument("--policy")
            action.add_argument("--artifacts")
            action.add_argument("--progression-selection-digest")
            action.add_argument("--progression-mechanism-digest")
    return parser


def handle_self_polish_tier_argv(argv: list[str]) -> int:
    """Handle arguments beginning with literal tier ``1`` or ``2``."""
    args = build_self_polish_tier_parser().parse_args(argv)
    tier = int(args.self_polish_tier)
    try:
        authority = _json_input(args.union_authority, dict)
        contributions = _json_input(args.union_contributions, list)
        common = {
            "source_root": args.source_root,
            "complete_tier_evidence_manifest_bytes": _read(
                args.complete_tier_evidence_manifest,
                self_polish_native_replay.MAX_MANIFEST_BYTES,
            ),
            "expected_complete_tier_evidence_manifest_digest": (
                args.complete_tier_evidence_manifest_digest
            ),
            "expected_evidence_replay_mechanism_digest": (
                args.evidence_replay_mechanism_digest
            ),
            "union_authority": authority,
            "union_contributions": contributions,
            "expected_union_authority_digest": args.union_authority_digest,
            "application_authority_assessment_bytes": _read(
                args.application_authority_assessment
            ),
            "expected_application_authority_assessment_digest": (
                args.application_authority_assessment_digest
            ),
            "complete_tier_ledger_bytes": _read(args.complete_tier_ledger),
            "expected_complete_tier_ledger_digest": (
                args.complete_tier_ledger_digest
            ),
            "complete_self_representation_bytes": _read(
                args.complete_self_representation
            ),
            "expected_complete_self_representation_digest": (
                args.complete_self_representation_digest
            ),
        }
        if tier == 1:
            result = assess_self_polish_tier(
                1,
                expected_core_selection_digest=args.selection_digest,
                expected_candidate_estate_repository=(
                    args.candidate_estate_repository
                ),
                expected_candidate_estate_revision=(
                    args.candidate_estate_revision
                ),
                expected_candidate_estate_digest=args.candidate_estate_digest,
                candidate_estate_applicability_ledger_bytes=_read(
                    args.candidate_estate_applicability_ledger,
                    self_polish_estate.MAX_LEDGER_BYTES,
                ),
                expected_candidate_estate_applicability_ledger_digest=(
                    args.candidate_estate_applicability_ledger_digest
                ),
                candidate_estate_authority_replay=(
                    _candidate_estate_authority_selection(args)
                ),
                candidate_estate_evidence_manifest_bytes=_read(
                    args.candidate_estate_evidence_manifest,
                    self_polish_estate_evidence.MAX_MANIFEST_BYTES,
                ),
                expected_candidate_estate_evidence_manifest_digest=(
                    args.candidate_estate_evidence_manifest_digest
                ),
                expected_candidate_estate_evidence_mechanism_digest=(
                    args.candidate_estate_evidence_mechanism_digest
                ),
                candidate_estate_evidence_replays=(
                    _candidate_estate_evidence_selections(
                        args.candidate_estate_evidence_selection
                    )
                ),
                candidate_estate_evidence_artifacts=(
                    _candidate_estate_evidence_artifacts(
                        args.candidate_estate_evidence_artifact
                    )
                ),
                **common,
            )
        else:
            files = None
            if args.artifacts is not None:
                from verifier.runtime.artifact_snapshot import capture
                files = capture(args.artifacts).files
            result = assess_self_polish_tier(
                2,
                tier1_report_bytes=_read(
                    args.tier1_report, MAX_TIER1_REPORT_BYTES
                ),
                expected_tier1_report_digest=args.tier1_report_digest,
                progression_selection_bytes=_read(args.progression_selection),
                progression_bundle_bytes=_read(args.bundle),
                progression_policy_bytes=_read(args.policy),
                progression_artifact_files=files,
                expected_progression_selection_digest=(
                    args.progression_selection_digest
                ),
                expected_progression_mechanism_digest=(
                    args.progression_mechanism_digest
                ),
                **common,
            )
    except (OSError, _ContractError, ValueError, TypeError, UnicodeError):
        result = _finish({
            **_base_report(tier, {}),
            "status": "FAIL",
            "selected_tier_status": "FAIL",
            "blockers": ["SELF_POLISH_TIER_CLI_INPUT_REJECTED"],
        })
    if args.json:
        if tier == 1:
            result = _guard_tier1_report_wire_capacity(result)
        print(_json_report_wire_bytes(result).decode("utf-8"), end="")
    else:
        print(f"[{result['status']}] self-polish tier {tier}: "
              f"{result['tier_name']}; polished=false")
        for blocker in result["blockers"]:
            print("- " + blocker)
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]


__all__ = [
    "MAX_INPUT_BYTES", "MAX_TIER1_REPORT_BYTES", "REPORT_SCHEMA",
    "SELF_REPRESENTATION_SCHEMA", "TIER_LEDGER_SCHEMA",
    "assess_self_polish_tier", "build_self_polish_tier_parser",
    "handle_self_polish_tier_argv", "mechanism_digest",
]
