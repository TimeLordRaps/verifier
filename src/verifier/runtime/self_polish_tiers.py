"""Source-bound numeric self-polish tiers for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind retained inputs.  Tier status is narrower than whole-tier conformance: the
adapter enumerates installed obligations, delegates replay to the existing core
mechanisms, and keeps missing applicability or authority as ``UNKNOWN``. A
conditional authority obligation blocks only when triggered or unresolved;
its exact source-bound native non-trigger does not establish authority.
Unicode Transformation Format, 8-bit (UTF-8) output is preferred; deterministic
American Standard Code for Information Interchange (ASCII) escapes are the fallback.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path
import re
import sys
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
from verifier.runtime import self_polish_dynamics


REPORT_SCHEMA = "verifier-self-polish-tier-assessment-7"
TIER_LEDGER_SCHEMA = "verifier-self-polish-complete-tier-ledger-2"
SELF_REPRESENTATION_SCHEMA = "verifier-self-polish-complete-representation-4"
POLISH_REFRESH_BLOCKED_SCHEMA = "verifier-polish-manifest-refresh-blocked-1"
# Estate refusals that mean the active source moved or was re-pinned while it
# was being read. Currency is then unknown and retryable, not a contract FAIL.
LIVE_SOURCE_DRIFT_CODES = frozenset({
    "CANDIDATE_SOURCE_MUTATED",
    "SOURCE_COORDINATE_MUTATED",
    "SOURCE_COORDINATE_DIFFERS",
})
# A broken or unimportable artifact is an outage of the mechanism, not a
# verdict about the selected repository. Only these import-time failures map to
# the command envelope; runtime errors keep their existing classification.
_MECHANISM_IMPORT_ERRORS = (ImportError, AssertionError, SyntaxError)
_NATIVE_TIER_NAMES = {0: "ADMISSION", 1: "FACETS", 2: "DYNAMICS", 3: "STATICS"}
LIVE_SOURCE_DRIFT_EXPLANATION = (
    "The active source changed or moved while this command read it, so "
    "currency for the selected source is not established. This is retryable "
    "and does not refute the source contract."
)
LIVE_SOURCE_DRIFT_ACTION = (
    "Keep the selected source tree and root objects.vstd unchanged until this "
    "command finishes, then rerun: vstd polish {tier} --json"
)
_MECHANISM_UNAVAILABLE_ACTIONS = {
    **{
        code: (LIVE_SOURCE_DRIFT_EXPLANATION, LIVE_SOURCE_DRIFT_ACTION)
        for code in LIVE_SOURCE_DRIFT_CODES
    },
    "MANIFEST_REFRESH_MECHANISM_UNAVAILABLE": (
        "The root manifest refresh mechanism could not be imported, so no "
        "refresh outcome exists and no assessment ran.",
        "Restore the installed refresh mechanism from reviewed source without "
        "editing objects.vstd, then rerun: vstd polish {tier} --json",
    ),
    "PACKAGE_POLISH_MECHANISM_UNAVAILABLE": (
        "The package polish mechanism could not be imported after manifest "
        "refresh, so no package assessment ran.",
        "Restore the installed package polish mechanism from reviewed source, "
        "then rerun: vstd polish {tier} --json",
    ),
    "MANIFEST_REFRESH_BLOCKED_ENVELOPE_INVALID": (
        "The manifest refresh outcome failed the blocked-report contract, so "
        "the command rebuilt the envelope without trusting that outcome.",
        "Repair the manifest refresh outcome producer, then rerun: "
        "vstd polish {tier} --json",
    ),
}
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
_FOCUS_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}\Z")
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
        "native_dynamics_progression": self_polish_dynamics.mechanism_digest(),
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
    """Preserve the caller-selected evaluation coordinate exactly."""
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
        # Numeric self-polish selects an explicitly versioned fresh SIM variant;
        # the historical signed-record route remains in the general inventory.
        if tier == 2:
            identities = [
                {key: value for key, value in row.items()
                 if key not in {"obligation_id", "required_case_kinds"}}
                for row in self_polish_native_replay.installed_native_replay_registry(
                    fresh_execution=True)["tiers"]["2"]
            ]
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
    installed_closure = self_polish_native_replay.installed_registry_closure(fresh_execution=True)
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
                fresh_execution=True,
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
        fresh_execution=True,
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
    registry = self_polish_native_replay.installed_native_replay_registry(fresh_execution=True)
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
    expected_reviews = self_polish_native_replay._source_review_binding(
        tier, fresh_execution=True
    )["entries"]
    _require(set(expected_reviews) == set(expected_by_id),
             "COMPLETE_TIER_EVIDENCE_SOURCE_REVIEW_DIFFERS")
    observed: dict[str, str] = {}
    for membership in memberships:
        _require(type(membership) is dict
                 and set(membership) == {"obligation_id", "membership",
                                         "cases", "status", "source_review",
                                         "conformance_status",
                                        "native_replay_digest"},
                 "COMPLETE_TIER_EVIDENCE_MEMBERSHIP_INVALID")
        identifier = membership["obligation_id"]
        _require(identifier in expected_by_id
                 and identifier not in observed
                 and membership["status"] == "PASS"
                  and membership["conformance_status"] == "PASS"
                  and membership["source_review"] == expected_reviews[identifier]
                  and membership["source_review"]["accepted"] is True
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
            _require(set(case) == ({"case_kind", "coordinate",
                                   "expected_native_status",
                                   "intended_refusal_codes", "policy_digest",
                                   "request_digest", "evidence_digest",
                                   "native_status", "refusal_detail", "reason",
                                   "status", "native_result_digest",
                                   "mechanism_source_path",
                                   "mechanism_source_digest"} | (
                                       {"fresh_execution_result"}
                                       if membership["membership"]["checking_mechanism"]
                                       == self_polish_native_replay.sim_resource_fresh.CHECKING_MECHANISM else set()))
                     and case["status"] == "PASS"
                      and case["coordinate"] == membership["membership"]["coordinate"]
                     and case["native_status"]
                         == case["expected_native_status"]
                     and case["expected_native_status"] in (
                         "PASS", "FAIL", "UNKNOWN"
                     )
                      and case["intended_refusal_codes"] == (
                          [self_polish_native_replay.self_polish_native_cases
                           .NEGATIVE_REFUSAL_CODES[identifier]]
                          if case["case_kind"] == "NEGATIVE" else []
                      )
                      and case["reason"] is None
                      and all(
                          type(case[field]) is str
                          and _SHA256.fullmatch(case[field]) is not None
                          for field in ("policy_digest", "request_digest",
                                        "evidence_digest", "native_result_digest",
                                        "mechanism_source_digest")
                      )
                     and type(case["mechanism_source_path"]) is str
                      and (
                          "fresh_execution_result" not in case
                          or core_obligation_union.value_digest(
                              case["fresh_execution_result"]
                          ) == case["native_result_digest"]
                      ),
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
        observed_coordinate = {
            "source_head": observed["git_head"],
            "source_tree": observed["git_tree"],
            "source_worktree_status_digest": observed[
                "worktree_status_digest"
            ],
            "source_manifest_digest": (
                polish_requirements.source_manifest_digest(observed)
            ),
        }
    except (polish_requirements.MechanismBindingUnavailable, OSError,
            ImportError, MemoryError, RecursionError, OverflowError):
        return {
            "status": "NOT_ESTABLISHED",
            "matches_selected_source": "UNKNOWN",
            "source_coordinate": None,
            "source_coordinate_digest": None,
            "claim_boundary": "Post-replay source recapture was unavailable.",
        }
    except (polish_requirements.RequirementRefusal, RuntimeError, TypeError,
            ValueError, UnicodeError, KeyError, AttributeError):
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

    closure = self_polish_native_replay.installed_registry_closure(fresh_execution=True)
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


def _application_authority_obligation(*, condition_status: str,
        claim_scope: str, assessment_reason: str) -> dict[str, str]:
    """Reason the obligation and its application separately; never offer a waiver."""
    return {
        "obligation_id": "INDEPENDENT_APPLICATION_AUTHORITY",
        "classification": "CONDITIONAL",
        "condition": "EXTERNAL_APPLICATION_SCOPE_OR_SEMANTIC_COMPLETENESS_CLAIM",
        "necessity_reason": (
            "A claim that an independently selected application scope is admitted "
            "or semantically complete depends on evidence from that authority. "
            "Source self-observation cannot establish another authority's adoption "
            "of requirements, exclusions, or completeness."
        ),
        "condition_status": condition_status,
        "claim_scope": claim_scope,
        "assessment_reason": assessment_reason,
    }


def _authority_summary(raw: bytes | None, *, expected_digest: str | None,
                       union_summary: dict[str, Any] | None,
                       expected_instances: int) -> dict[str, Any] | None:
    """Retain a selected assessment without authenticating its carried claims."""
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
    _require(value.get("status") in ("PASS", "FAIL", "UNKNOWN")
             and all(status in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
                     for status in statuses.values())
             and type(value.get("expected_instances")) is int
             and value["expected_instances"] == expected_instances
             and type(value.get("blockers")) is list
             and all(type(code) is str and code for code in value["blockers"]),
             "APPLICATION_AUTHORITY_ASSESSMENT_INVALID")
    failed = value.get("status") == "FAIL" or "FAIL" in statuses.values()
    return {
        "status": "FAIL" if failed else "UNKNOWN",
        **{key: "FAIL" if status == "FAIL" else "NOT_ESTABLISHED"
           for key, status in statuses.items()},
        "declared_status": value["status"],
        "declared_statuses": statuses,
        "selection_binding_status": "PASS",
        "replay_status": "NOT_ESTABLISHED",
        "obligation": _application_authority_obligation(
            condition_status="TRIGGERED",
            claim_scope="EXTERNALLY_SELECTED_APPLICATION_ASSESSMENT",
            assessment_reason=(
                "The caller selected an application-authority assessment. Its "
                "claimed scope admission and semantic completeness require fresh "
                "authority replay; neither a digest nor a carried verdict supplies it."
            ),
        ),
        "expected_instances": value.get("expected_instances"),
        "assessment_digest": stored_digest,
        "blockers": sorted(set(value["blockers"]) | {
            "APPLICATION_AUTHORITY_REPLAY_NOT_ESTABLISHED",
        }),
        "claim_boundary": (
            "The supplied digest selects this exact assessment and union binding "
            "only. Carried claims, receipt labels, and self-hashes do not replay "
            "application authority, semantic completeness, children, or interactions."
        ),
    }


def _derived_application_authority_summary(*,
        union_summary: dict[str, Any], expected_instances: int,
        source_coordinate: dict[str, Any], tier: int,
        denominators: dict[str, Any]) -> dict[str, Any]:
    """Bind installed Tier mechanics without inventing external authority."""

    expected = denominators["complete_tiers"][str(tier)]
    _require(
        union_summary == _derived_route_union_summary(
            source_coordinate=source_coordinate, tier=tier,
            expected_members=expected["registered_route_membership_count"],
            denominators=denominators,
        ) and type(expected_instances) is int and expected_instances > 0,
        "INSTALLED_APPLICATION_AUTHORITY_NOT_ESTABLISHED",
    )
    body = {
        "status": "UNKNOWN",
        "derivation": "COMMAND_SELECTED_INSTALLED_SELF_REPRESENTATION",
        "binding_status": "PASS",
        "authority_status": "NOT_ESTABLISHED",
        "child_status": "PASS",
        "interaction_status": "PASS",
        "semantic_completeness": "NOT_ESTABLISHED",
        "expected_instances": expected_instances,
        "source_coordinate_digest": core_obligation_union.value_digest(
            source_coordinate
        ),
        "union_report_digest": union_summary["report_digest"],
        "membership_identity_digest": expected["membership_identity_digest"],
        "independent_authority_status": "NOT_ESTABLISHED",
        "obligation": _application_authority_obligation(
            condition_status="NOT_TRIGGERED" if tier in (1, 2) else "UNKNOWN",
            claim_scope=("SOURCE_BOUND_TIER1_FACETS" if tier == 1
                         else "SOURCE_BOUND_TIER2_NATIVE_DYNAMICS" if tier == 2
                         else "AUTHORITY_APPLICABILITY_NOT_DERIVED"),
            assessment_reason=(
                "Tier 1 checks the exact installed Facets route union and the "
                "mechanically enumerated source estate. It asserts neither "
                "external adoption of application requirements or exclusions nor "
                "full-application semantic completeness. Native reasons, replay, "
                "estate closure, and source stability remain necessary; they do "
                "not establish independent authority."
                if tier == 1 else
                "Tier 2 selects the exact installed Dynamics route union and "
                "requires fresh cumulative Facets and Dynamics native replay at "
                "the retained source coordinate. This claim is about installed "
                "checker behavior, not adoption of an external application's "
                "scope or semantic completeness. SIM-2.4 selects the versioned "
                "fresh-execution resource variant with direct source loading, "
                "complete selected-step measurements, and explicit trusted-host "
                "assumptions. Historical correspondence remains NOT_ESTABLISHED; "
                "authority non-applicability does not exempt resource evidence."
                if tier == 2 else
                "This tier has no source-derived evaluation of the authority "
                "condition. The Tier-1 non-trigger cannot be inherited."
            ),
        ),
        "full_application_status": "UNKNOWN",
        "polished": False,
        "release_authorized": False,
        "blockers": ["INDEPENDENT_APPLICATION_AUTHORITY_NOT_ESTABLISHED"],
    }
    body["assessment_digest"] = core_obligation_union.value_digest(body)
    return body


def _native_authority_condition_not_triggered(authority: Any, *,
        union_summary: Any, source_coordinate: Any, tier: int,
        denominators: dict[str, Any]) -> bool:
    """Reconstruct the tier-specific native non-trigger, not a caller label."""
    if tier not in (1, 2) or type(authority) is not dict \
            or type(union_summary) is not dict or type(source_coordinate) is not dict:
        return False
    try:
        expected = _derived_application_authority_summary(
            union_summary=union_summary,
            expected_instances=(denominators["facets"]["instantiated_obligation_count"]
                + (denominators["dynamics"]["registered_route_membership_count"]
                   if tier == 2 else 0)),
            source_coordinate=source_coordinate, tier=tier, denominators=denominators,
        )
    except _ContractError:
        return False
    return authority == expected


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
    authority_condition_not_triggered = _native_authority_condition_not_triggered(
        authority, union_summary=union, source_coordinate=value.get("source_coordinate"),
        tier=1, denominators=installed_denominators,
    )
    declared_complete = (
             status == "PASS"
             and value.get("whole_tier_conformance") == "PASS"
             and value.get("source_binding_status") == "PASS"
             and value.get("applicability_status") == "PASS"
             and value.get("authority_status") == "NOT_ESTABLISHED"
             and value.get("dependency_status") == "PASS"
             and value.get("interaction_status") == "PASS"
             and value.get("blockers") == []
             and type(attempt) is dict and attempt.get("status") == "PASS"
             and attempt.get("external_selection_pin") in {
                 "MATCHED", "DERIVED_CURRENT_SOURCE",
             }
             and type(union) is dict and union.get("status") == "PASS"
             and authority_condition_not_triggered
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
    _require(status != "PASS" or authority_condition_not_triggered,
             "TIER1_APPLICATION_AUTHORITY_CONDITION_NOT_ESTABLISHED")
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
    """Attempt numeric tiers without widening their distinct evidence boundaries."""
    if type(tier) is int and tier == 3:
        # Tier 3 is a fresh source-only check. Keep its rejected input set
        # explicit so a newly added argument cannot disappear into reflection.
        tier3_incompatible_inputs = (
            expected_core_selection_digest,
            complete_tier_evidence_manifest_bytes,
            expected_complete_tier_evidence_manifest_digest,
            expected_evidence_replay_mechanism_digest,
            expected_candidate_estate_repository,
            expected_candidate_estate_revision,
            expected_candidate_estate_digest,
            candidate_estate_applicability_ledger_bytes,
            expected_candidate_estate_applicability_ledger_digest,
            candidate_estate_authority_replay,
            candidate_estate_evidence_manifest_bytes,
            expected_candidate_estate_evidence_manifest_digest,
            expected_candidate_estate_evidence_mechanism_digest,
            candidate_estate_evidence_replays,
            candidate_estate_evidence_artifacts,
            union_authority,
            union_contributions,
            expected_union_authority_digest,
            application_authority_assessment_bytes,
            expected_application_authority_assessment_digest,
            complete_tier_ledger_bytes,
            expected_complete_tier_ledger_digest,
            complete_self_representation_bytes,
            expected_complete_self_representation_digest,
            tier1_report_bytes,
            expected_tier1_report_digest,
            progression_selection_bytes,
            progression_bundle_bytes,
            progression_policy_bytes,
            progression_artifact_files,
            expected_progression_selection_digest,
            expected_progression_mechanism_digest,
        )
        if any(value is not None for value in tier3_incompatible_inputs):
            raise ValueError("Tier 3 accepts only source_root and cancelled; all prerequisites are fresh")
        from verifier.runtime.self_polish_statics import assess_self_polish_statics
        return assess_self_polish_statics(source_root, cancelled=cancelled)
    if type(tier) is not int or tier not in (1, 2):
        raise ValueError("numeric self-polish tier must be 1, 2 or 3")
    object_id = "verifier-core-self"
    report: dict[str, Any] | None = None
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
            count_values = (
                attempt["installed_definition_count"],
                attempt["installed_membership_count"],
                attempt["instantiated_obligation_count"],
            )
            if any(value is not None for value in count_values):
                counts_match = (
                    all(type(value) is int for value in count_values)
                    and count_values[0]
                        == denominators[
                            "installed_structural_definition_count"
                        ]
                    and count_values[1]
                        == denominators[
                            "installed_structural_membership_count"
                        ]
                    and count_values[2]
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
            # Retained closure is bounded to the identical, freshly recaptured
            # source. It is not a new independent-authority observation.
            report["repository_package_estate"] = dict(retained["repository_package_estate"])
            report["repository_package_estate_closure"] = retained["repository_package_estate_closure"]
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
        progression_inputs = (
            progression_selection_bytes, progression_bundle_bytes,
            progression_policy_bytes, progression_artifact_files,
            expected_progression_selection_digest,
            expected_progression_mechanism_digest,
        )
        native_progression_selected = all(value is None for value in progression_inputs)
        if tier == 2 and not native_progression_selected and authority is not None \
                and authority.get("derivation") == "COMMAND_SELECTED_INSTALLED_SELF_REPRESENTATION":
            authority["obligation"] = _application_authority_obligation(
                condition_status="UNKNOWN",
                claim_scope="EXTERNALLY_SELECTED_DYNAMICS_PROGRESSION",
                assessment_reason=(
                    "The caller selected progression inputs outside the fixed "
                    "source-native path. Their authority applicability has not "
                    "been derived; the native non-trigger cannot be inherited."
                ),
            )
            authority.pop("assessment_digest")
            authority["assessment_digest"] = core_obligation_union.value_digest(authority)
        authority_condition_not_triggered = _native_authority_condition_not_triggered(
            authority, union_summary=union, source_coordinate=source_coordinate,
            tier=tier, denominators=denominators,
        )
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
            elif not authority_condition_not_triggered:
                report["blockers"].append("APPLICATION_AUTHORITY_NOT_PASS")
            if not authority_condition_not_triggered:
                report["blockers"].extend(authority.get("blockers", []))
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
                and authority_condition_not_triggered
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

        if native_progression_selected:
            progression = self_polish_dynamics.assess_native_dynamics(
                source_root,
                source_coordinate_digest=report["source_coordinate_digest"],
                subject_id=retained["core_self_polish_attempt"]["root_id"],
                prior_report_digest=retained["report_digest"],
                cancelled=cancelled,
            )
            native_replayed_tier2 = progression["native_assessments"].get("2")
            if native_replayed_tier2 is not None:
                _require(self_polish_native_replay.same_execution_selection(
                             native_replayed_tier2, evidence_replay),
                         "DYNAMICS_NATIVE_REPLAY_BINDING_DIFFERS")
            report["tier2_dynamics_reasons"] = progression["dynamics_reasons"]
            report["declared_dependencies"] = {
                "derivation": "FIXED_CUMULATIVE_NATIVE_ROUTE_SELECTION",
                "prerequisite_tier": 1,
                "dependent_tier": 2,
                "prior_report_digest": retained["report_digest"],
                "progression_assessment_digest": progression["assessment_digest"],
                "claim_boundary": (
                    "Every installed Dynamics route requires retained full Facets "
                    "closure plus fresh native Facets replay. This is a tier "
                    "prerequisite, not an inferred application certificate graph."
                ),
            }
        elif any(value is None for value in progression_inputs):
            report["blockers"].append("TIER2_PROGRESSION_INPUTS_UNAVAILABLE")
            return _finish(report)
        else:
            progression = core_tier_progression.assess_tier_progression(
                progression_selection_bytes,
                bundle_bytes=progression_bundle_bytes,
                expected_policy_bytes=progression_policy_bytes,
                artifact_files=progression_artifact_files,
                expected_selection_digest=expected_progression_selection_digest,
                expected_mechanism_digest=expected_progression_mechanism_digest,
                cancelled=cancelled,
            )
            report["declared_dependencies"] = _dependency_summary(
                progression_selection_bytes, progression_bundle_bytes
            )
        report["core_progression_attempt"] = progression
        report["blockers"].extend(progression.get("blockers", []))
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
                and authority_condition_not_triggered \
                and ledger is not None and ledger["status"] == "PASS" \
                and representation is not None \
                and representation["status"] == "PASS" \
                and evidence_replay is not None \
                and evidence_replay.get("status") == "PASS" \
                and recapture["status"] == "PASS" \
                and report["installed_route_normative_closure"] == "PASS" \
                and report["objective_inventory_closure"] == "PASS" \
                and report["structural_route_crosswalk_closure"] == "PASS" \
                and report["repository_package_estate_closure"] == "PASS" \
                and report.get("tier2_dynamics_reasons", {}).get("status") == "PASS" \
                and not report["blockers"]:
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
        report = report or _base_report(tier, {})
        report["blockers"].append("SELF_POLISH_MECHANISM_OR_SOURCE_UNAVAILABLE")
        return _finish(report)
    except self_polish_estate.EstateError as exc:
        report = report or _base_report(tier, {})
        status = "UNKNOWN" if str(exc) in LIVE_SOURCE_DRIFT_CODES else "FAIL"
        report.update(status=status, selected_tier_status=status)
        report["blockers"].append(str(exc))
        return _finish(report)
    except (_ContractError, polish_requirements.RequirementRefusal,
            self_polish_native_replay.NativeReplayError) as exc:
        report = report or _base_report(tier, {})
        report.update(status="FAIL", selected_tier_status="FAIL")
        report["blockers"].append(str(exc))
        return _finish(report)
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        report = report or _base_report(tier, {})
        report["blockers"].append("SELF_POLISH_TIER_MECHANISM_UNAVAILABLE")
        return _finish(report)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        report = report or _base_report(tier, {})
        report.update(status="FAIL", selected_tier_status="FAIL")
        report["blockers"].append("SELF_POLISH_TIER_CONTRACT_REJECTED")
        refusal = _bounded_domain_refusal_blocker(exc)
        if refusal is not None:
            report["blockers"].append(refusal)
        return _finish(report)


_DOMAIN_CONTRACT_MODULE_PREFIX = "verifier.domains.contracts."
_DOMAIN_REFUSAL_MAX_CHARS = 160
_DOMAIN_REFUSAL_PHRASE = re.compile(r"[A-Za-z]+(?: [A-Za-z]+)*")


def _bounded_domain_refusal_blocker(exc: BaseException) -> str | None:
    """Return one exact code for a fixed domain-contract refusal, else None.

    Only exception classes defined under ``verifier.domains.contracts`` qualify,
    and only when their single argument is a short phrase of letters and single
    spaces, such as ``policy differs from installed mechanism``. Builtin and
    punctuated messages can carry subject text, so they keep the generic stage
    code alone. ``args`` is read directly so no ``__str__`` override can run.
    """

    if not isinstance(exc, ValueError):
        return None
    if not type(exc).__module__.startswith(_DOMAIN_CONTRACT_MODULE_PREFIX):
        return None
    if len(exc.args) != 1 or type(exc.args[0]) is not str:
        return None
    message = exc.args[0]
    if (
        len(message) > _DOMAIN_REFUSAL_MAX_CHARS
        or _DOMAIN_REFUSAL_PHRASE.fullmatch(message) is None
    ):
        return None
    return (
        "SELF_POLISH_TIER_CONTRACT_REJECTED:"
        + "_".join(message.upper().split())
    )


def _read(path: str | None, max_bytes: int = MAX_INPUT_BYTES) -> bytes | None:
    if path is None:
        return None
    with Path(path).open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise OSError("bounded input unavailable")
    return raw


def _json_report_wire_bytes(report: Any) -> bytes:
    """Return exact pretty-JSON command-line bytes, newline included."""

    return (
        json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _package_polish_schema_rejection_report(
    report: Any,
    requested_tier: int,
    source_raw: bytes | None,
    *,
    schema_supported: bool,
    validation_errors: tuple[str, ...],
    selected_schema_digest: str | None,
    validator_mechanism_digest: str | None,
    validation_errors_at_limit: bool,
) -> dict[str, Any]:
    """Replace a schema-invalid final projection with a bounded non-PASS receipt."""
    source_schema = None
    source_status = None
    if isinstance(report, dict):
        candidate_schema = report.get("schema_version")
        if isinstance(candidate_schema, str):
            try:
                encoded_schema = candidate_schema.encode("utf-8")
            except UnicodeError:
                pass
            else:
                if len(encoded_schema) <= 512:
                    source_schema = candidate_schema
        candidate_status = report.get("status")
        if (
            isinstance(candidate_status, str)
            and candidate_status in {"PASS", "FAIL", "UNKNOWN"}
        ):
            source_status = candidate_status
    source_encoding_available = source_raw is not None
    if source_encoding_available:
        blocker = (
            "PACKAGE_POLISH_REPORT_SCHEMA_INVALID"
            if schema_supported
            else "PACKAGE_POLISH_REPORT_SCHEMA_UNSUPPORTED"
        )
    else:
        blocker = "PACKAGE_POLISH_REPORT_ENCODING_UNAVAILABLE"
    bounded_errors: list[str] = []
    if not source_encoding_available:
        bounded_errors.append(
            "/: encoding: final report is not representable as strict JSON"
        )
    for value in validation_errors:
        safe_encoded = value.encode("utf-8", errors="backslashreplace")
        if len(safe_encoded) <= 512:
            bounded = safe_encoded.decode("utf-8")
        else:
            bounded = safe_encoded[:509].decode(
                "utf-8", errors="ignore"
            ) + "..."
        if bounded not in bounded_errors:
            bounded_errors.append(bounded)
        if len(bounded_errors) == 32:
            break
    if not bounded_errors:
        bounded_errors = [
            "/: validation: final report did not satisfy publication validation"
        ]
    rejected = {
        "schema_version": (
            "verifier-manifest-package-polish-publication-rejected-1"
        ),
        "status": "UNKNOWN",
        "blockers": [blocker],
        "source_report_schema": source_schema,
        "selected_schema_digest": selected_schema_digest,
        "validator_mechanism_digest": validator_mechanism_digest,
        "source_report_status": source_status,
        "requested_tier": requested_tier,
        "source_report_encoding_status": (
            "AVAILABLE" if source_encoding_available else "UNAVAILABLE"
        ),
        "source_report_digest": (
            _digest(source_raw) if source_raw is not None else None
        ),
        "source_report_bytes": (
            len(source_raw) if source_raw is not None else None
        ),
        "validation_error_count": len(bounded_errors),
        "validation_errors": bounded_errors,
        "validation_errors_at_limit": validation_errors_at_limit,
        "whole_package_conformance": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": (
            "The final package-polish projection contradicted or did not name "
            "a supported bundled schema, or could not be represented as strict "
            "JSON. The source report was not published; this receipt establishes "
            "only fail-closed publication rejection."
        ),
    }
    rejected["report_digest"] = core_obligation_union.value_digest(rejected)
    return rejected


def _human_json(value: Any) -> str:
    """Render a retained value without losing argument or field boundaries."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )


def _safe_focus_identifier(value: Any, *, maximum: int = 512) -> str | None:
    """Return an identifier safe to place in a displayed fixed argv."""

    if (
        type(value) is str
        and len(value) <= maximum
        and _FOCUS_IDENTIFIER.fullmatch(value) is not None
    ):
        return value
    return None


def _exact_gate_action(
    object_id: Any, obligation_id: Any,
) -> tuple[list[str], str] | None:
    """Build the only focused command emitted from rejected diagnostics."""

    selected_object = _safe_focus_identifier(object_id, maximum=256)
    selected_obligation = _safe_focus_identifier(obligation_id)
    if selected_object is None or selected_obligation is None:
        return None
    argv = [
        "vstd", "gate", "--object", selected_object,
        "--obligation", selected_obligation,
    ]
    return argv, " ".join(argv)


def _bounded_human_text(value: Any, *, maximum: int = 2048) -> str | None:
    """Bound and escape an unvalidated source string for one terminal line."""

    if type(value) is not str or not value:
        return None
    encoded = value.encode("utf-8", errors="backslashreplace")
    if len(encoded) > maximum:
        encoded = encoded[:maximum]
        value = encoded.decode("utf-8", errors="ignore") + "..."
    # JSON escaping removes terminal controls and lone surrogates. Strip only
    # the wrapper quotes; this is display data, never a shell command.
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _bounded_human_strings(value: Any, *, maximum: int = 32) -> list[str]:
    selected: list[str] = []
    if type(value) is not list:
        return selected
    for item in value:
        bounded = _bounded_human_text(item, maximum=512)
        if bounded is not None and bounded not in selected:
            selected.append(bounded)
        if len(selected) == maximum:
            break
    return selected


def _bounded_count_map(value: Any) -> dict[str, int]:
    selected: dict[str, int] = {}
    if type(value) is not dict:
        return selected
    for key, count in value.items():
        safe_key = _safe_focus_identifier(key, maximum=64)
        if (
            safe_key is not None
            and type(count) is int
            and 0 <= count <= 10**9
        ):
            selected[safe_key] = count
        if len(selected) == 16:
            break
    return selected


def _bounded_native_record(value: Any, *, tier: int) -> dict[str, Any] | None:
    """Project one rejected-source diagnostic without trusting its command."""

    if type(value) is not dict:
        return None
    status = value.get("status")
    if status not in {"FAIL", "UNKNOWN", "NOT_ESTABLISHED", "NOT_RUN"}:
        status = "UNKNOWN"
    selected: dict[str, Any] = {
        "status": status,
        "blockers": _bounded_human_strings(value.get("blockers")),
        "rerun_argv": (
            ["vstd", "polish", str(tier)]
            + (["--native-specimens"] if tier else [])
            + ["--json"]
        ),
    }
    for field in (
        "object_id", "obligation_id", "gate_id", "coordinate", "object_kind",
        "classification_kind", "kind", "tier_name", "scope", "case_kind",
        "candidate_id",
    ):
        maximum = 256 if field == "object_id" else 512
        safe = _safe_focus_identifier(value.get(field), maximum=maximum)
        if safe is not None:
            selected[field] = safe
    for field in ("tier",):
        if type(value.get(field)) is int:
            selected[field] = value[field]
    path = _bounded_human_text(value.get("path"), maximum=1024)
    if path is not None:
        selected["path"] = path
    for field in ("reason", "assessment_reason", "explanation"):
        reason = _bounded_human_text(value.get(field))
        if reason is not None:
            selected[field] = reason
            break
    action = _exact_gate_action(
        selected.get("object_id"), selected.get("obligation_id"),
    )
    if action is not None:
        selected["rerun_argv"], selected["next_action"] = action
    return selected


def _bounded_rejected_finding(value: Any) -> dict[str, Any] | None:
    """Retain exact focus but regenerate action from validated identifiers."""

    if type(value) is not dict:
        return None
    action = _exact_gate_action(
        value.get("object_id"), value.get("obligation_id"),
    )
    if action is None:
        return None
    argv, next_action = action
    status = value.get("status")
    if status not in {"FAIL", "UNKNOWN"}:
        status = "UNKNOWN"
    gate = _safe_focus_identifier(value.get("gate_id"))
    if gate is None:
        gate = "package-assessment"
    explanation = _bounded_human_text(value.get("explanation"))
    if explanation is None:
        explanation = (
            "The rejected source report retained this exact non-PASS focus."
        )
    return {
        "status": status,
        "object_id": argv[3],
        "obligation_id": argv[5],
        "gate_id": gate,
        "reason": explanation,
        "explanation": explanation,
        "next_action": next_action,
        "rerun_argv": argv,
    }


def _publication_rejection_diagnostic_projection(
    report: Any, requested_tier: int,
) -> dict[str, Any]:
    """Keep useful human diagnostics separate from the rejected publication."""

    if type(report) is not dict:
        report = {}
    graph = report.get("package_graph")
    graph_reference = report.get("package_graph_reference")
    object_count = None
    for candidate in (graph, graph_reference):
        if (
            type(candidate) is dict
            and type(candidate.get("object_count")) is int
            and 0 <= candidate["object_count"] <= 10**9
        ):
            object_count = candidate["object_count"]
            break
    tiers: list[dict[str, Any]] = []
    source_tiers = report.get("tier_results")
    if type(source_tiers) is list:
        for depth in range(1, requested_tier + 1):
            row = next((
                item for item in source_tiers
                if type(item) is dict and item.get("tier") == depth
            ), None)
            if row is None:
                continue
            status = row.get("status")
            if status not in {"PASS", "FAIL", "UNKNOWN"}:
                status = "UNKNOWN"
            execution_status = row.get("execution_status", "EXECUTED")
            if execution_status not in {"EXECUTED", "NOT_RUN", "UNKNOWN"}:
                execution_status = "UNKNOWN"
            count = row.get("instance_count")
            if type(count) is not int or not 0 <= count <= 10**9:
                count = 0
            selected_tier = {
                "tier": depth,
                "status": status,
                "execution_status": execution_status,
                "instance_count": count,
                "status_counts": _bounded_count_map(row.get("status_counts")),
                "checker_status_counts": _bounded_count_map(
                    row.get("checker_status_counts")
                ),
            }
            reason = _bounded_human_text(row.get("reason"))
            if reason is not None:
                selected_tier["reason"] = reason
            tiers.append(selected_tier)

    native_source = report.get("native_diagnostics")
    native = None
    if type(native_source) is dict:
        execution_source = native_source.get("tier_execution")
        prerequisite_source = native_source.get("prerequisites")
        execution: dict[str, Any] = {}
        prerequisites: dict[str, Any] = {}
        for depth in range(requested_tier + 1):
            key = str(depth)
            row = execution_source.get(key) if type(execution_source) is dict else None
            if type(row) is dict:
                status = row.get("status")
                if status not in {"PASS", "FAIL", "UNKNOWN"}:
                    status = "UNKNOWN"
                execution_status = row.get("execution_status")
                if execution_status not in {"EXECUTED", "NOT_RUN", "UNKNOWN"}:
                    execution_status = "UNKNOWN"
                selected_execution: dict[str, Any] = {
                    "tier": depth,
                    "status": status,
                    "execution_status": execution_status,
                }
                tier_name = _safe_focus_identifier(row.get("tier_name"))
                if tier_name is not None:
                    selected_execution["tier_name"] = tier_name
                reason = _bounded_human_text(
                    row.get("reason", row.get("assessment_reason"))
                )
                if reason is not None:
                    selected_execution["reason"] = reason
                blockers = _bounded_human_strings(row.get("blockers"))
                if blockers:
                    selected_execution["blockers"] = blockers
                blocking = row.get("blocking_prerequisite")
                if type(blocking) is dict:
                    blocking_tier = blocking.get("tier")
                    blocking_status = blocking.get("status")
                    if (
                        type(blocking_tier) is int
                        and blocking_status in {"PASS", "FAIL", "UNKNOWN"}
                    ):
                        selected_execution["blocking_prerequisite"] = {
                            "tier": blocking_tier, "status": blocking_status,
                        }
                execution[key] = selected_execution
            prerequisite = (
                prerequisite_source.get(key)
                if type(prerequisite_source) is dict else None
            )
            if type(prerequisite) is dict:
                prerequisite_status = prerequisite.get("status")
                if prerequisite_status not in {"PASS", "FAIL", "UNKNOWN"}:
                    prerequisite_status = "UNKNOWN"
                selected_prerequisite: dict[str, Any] = {
                    "status": prerequisite_status,
                    "blockers": _bounded_human_strings(
                        prerequisite.get("blockers")
                    ),
                }
                records = prerequisite.get("nonpass_records")
                if type(records) is list:
                    selected_records = [
                        selected
                        for selected in (
                            _bounded_native_record(item, tier=depth)
                            for item in records[:32]
                        )
                        if selected is not None
                    ]
                    if selected_records:
                        selected_prerequisite["nonpass_records"] = (
                            selected_records
                        )
                prerequisites[key] = selected_prerequisite
        native = {
            "status": (
                native_source.get("status")
                if native_source.get("status") in {"PASS", "FAIL", "UNKNOWN"}
                else "UNKNOWN"
            ),
            "tier_execution": execution,
            "prerequisites": prerequisites,
        }

    findings: list[dict[str, Any]] = []
    source_findings = report.get("findings")
    if type(source_findings) is list:
        for value in source_findings[:32]:
            selected = _bounded_rejected_finding(value)
            if selected is not None:
                findings.append(selected)
    denominator = report.get("denominator_status")
    if denominator not in {"COMPLETE", "NOT_RETAINED"}:
        denominator = None
    index = report.get("obligation_index")
    instance_count = 0
    if (
        type(index) is dict
        and type(index.get("instance_count")) is int
        and 0 <= index["instance_count"] <= 10**9
    ):
        instance_count = index["instance_count"]
    return {
        "schema_version": report.get("schema_version"),
        "status": "UNKNOWN",
        "blockers": _bounded_human_strings(report.get("blockers")),
        "package_graph": (
            {"object_count": object_count} if object_count is not None else {}
        ),
        "obligation_instances": [],
        "obligation_index": {"instance_count": instance_count},
        "tier_results": tiers,
        "denominator_status": denominator,
        "native_diagnostics": native,
        "findings": findings,
        "polished": False,
    }


def _print_native_nonpass_record(record: Mapping[str, Any], *, tier: int) -> None:
    """Print one native failure with its exact focus and reproducible argv."""

    status = record.get("status")
    if type(status) is not str:
        status = "UNKNOWN"
    fields = (
        ("object", record.get("object_id")),
        ("object_kind", record.get("object_kind")),
        ("classification_kind", record.get("classification_kind")),
        ("obligation", record.get("obligation_id")),
        ("gate", record.get("gate_id")),
        ("coordinate", record.get("coordinate")),
        ("path", record.get("path")),
    )
    focus = " ".join(
        f"{name}={value}" for name, value in fields
        if type(value) in {str, int}
    )
    print(f"[{status}] native tier {tier} nonpass" + (f" {focus}" if focus else ""))
    for field in ("reason", "assessment_reason", "explanation"):
        value = record.get(field)
        if type(value) is str and value:
            print(f"  reason={value}")
            break
    blockers = record.get("blockers")
    if type(blockers) is list and blockers:
        print("  blockers=" + _human_json(blockers))
    rerun = record.get("rerun_argv")
    if type(rerun) is list and all(type(argument) is str for argument in rerun):
        print("  rerun_argv=" + _human_json(rerun))
    next_action = record.get("next_action")
    if type(next_action) is str and next_action:
        print("  Next: " + next_action)


def _print_native_nonpass_records(
        records: list[tuple[int, Mapping[str, Any]]]) -> None:
    """Print a short native list record by record, a long one as counted groups."""

    from verifier.runtime import manifest_gate

    if len(records) <= manifest_gate.FINDING_DETAIL_LIMIT:
        for depth, record in records:
            _print_native_nonpass_record(record, tier=depth)
        return
    pseudo = []
    for depth, record in records:
        status = record.get("status")
        reason = next((
            record[field] for field in ("reason", "assessment_reason", "explanation")
            if type(record.get(field)) is str and record[field]
        ), "A native diagnostic record did not pass.")
        rerun = record.get("rerun_argv")
        next_action = record.get("next_action")
        pseudo.append({
            "scope": "object",
            "status": status if status in {"FAIL", "UNKNOWN"} else "UNKNOWN",
            "code": f"native tier {depth} {record.get('coordinate') or 'nonpass'}",
            "gate_id": record.get("gate_id") if type(record.get("gate_id")) is str
            else "native",
            "object_id": record.get("object_id")
            if type(record.get("object_id")) is str else None,
            "obligation_id": record.get("obligation_id")
            if type(record.get("obligation_id")) is str else None,
            "reason": reason,
            "next_action": next_action if type(next_action) is str and next_action
            else "Inspect the retained native record; rerun the command shown.",
            "rerun_argv": rerun
            if type(rerun) is list and all(type(part) is str for part in rerun)
            else None,
        })
    manifest_gate.print_finding_groups(pseudo, title="Native next actions")


_BLOCKER_DETAIL_LIMIT = 12
_BLOCKER_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_REFRESH_CAUSE = re.compile(r"[A-Za-z0-9_.@-][A-Za-z0-9_.@/-]{0,199}")
_REFRESH_CAUSE_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,127}")


def _print_tier_zero_summary(result: dict[str, Any]) -> None:
    """Print where Tier-0 admission stands, then what to do next.

    One line per obligation says which closures hold; the findings follow as the
    grouped next-action view (refutations first), never one block per open cell.
    """
    from verifier.runtime.manifest_gate import print_finding_groups

    print(f"[{result['status']}] self-polish tier 0: "
          "repository admission; polished=false")
    obligations = [row for row in result.get("obligations") or [] if type(row) is dict]
    for row in obligations:
        blockers = row.get("blockers") or []
        print(f"  {row.get('coordinate')} {row.get('status')} {row.get('name') or ''}".rstrip()
              + (": " + _human_blockers(blockers) if blockers else ""))
    if not obligations and result["blockers"]:
        print("blockers=" + _human_blockers(result["blockers"]))
    if result["findings"]:
        print_finding_groups(result["findings"])


def _refresh_cause_name(value: Any) -> str | None:
    """Name a refresh cause by its innermost refusal code and that code's arguments.

    Catalog validators wrap a refusal as ``OUTER:...:INNER:argument``.  The outer
    codes say where it was raised; the innermost says what to fix.  A bare type
    name such as ``OSError`` names itself.  Anything else is not named at all.
    """
    if type(value) is not str or len(value) > 1024 or ".." in value:
        return None
    segments = value.split(":")
    if not all(_REFRESH_CAUSE.fullmatch(segment) for segment in segments):
        return None
    codes = [index for index, segment in enumerate(segments)
             if _REFRESH_CAUSE_CODE.fullmatch(segment)]
    if codes:
        return ":".join(segments[codes[-1]:])
    return value if len(segments) == 1 else None


def _human_blockers(blockers: list[Any]) -> str:
    """Render a blocker list: a short one in full, a long one as counted groups.

    A blocker is ``CODE`` or ``CODE:subject[:detail]``.  Past the limit the codes are
    grouped with their counts and a few subjects, so the developer sees which review
    to open rather than hundreds of near-identical names; ``--json`` keeps them all.
    """

    if len(blockers) <= _BLOCKER_DETAIL_LIMIT:
        return _human_json(blockers)
    def name(value: str) -> str:
        # A plain identifier reads best; anything else keeps JSON's escaping.
        return value if _BLOCKER_NAME.fullmatch(value) else _human_json(value)

    groups: dict[str, list[str]] = {}
    for blocker in blockers:
        code, _, rest = (blocker if type(blocker) is str else "").partition(":")
        subject = rest.partition(":")[0]
        groups.setdefault(code or "UNNAMED", []).append(subject)
    parts = []
    for code, subjects in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        named = sorted({subject for subject in subjects if subject})
        part = (f"{len(subjects)}x " if len(subjects) > 1 else "") + name(code)
        if named:
            shown = ", ".join(name(subject) for subject in named[:2])
            part += (
                f" ({len(named)} object{'s' if len(named) != 1 else ''}"
                f"; e.g. {shown}{', ...' if len(named) > 2 else ''})"
            )
        parts.append(part)
    return (
        f"{len(blockers)} blockers in {len(groups)} groups: " + "; ".join(parts)
        + " (all of them: rerun with --json)"
    )


def _print_package_polish_summary(
        report: Mapping[str, Any], requested_tier: int) -> None:
    """Print the cumulative package and native result without hiding lower tiers.

    Human output is explanatory only. The bounded JSON report remains the
    authoritative machine-readable artifact, including when report capacity
    permits only fail-closed telemetry.
    """

    graph = report.get("package_graph")
    if type(graph) is not dict:
        graph = report.get("package_graph_reference")
    if type(graph) is not dict:
        graph = {}
    rows = report.get("obligation_instances")
    if type(rows) is list and rows:
        instance_count = len(rows)
    else:
        index = report.get("obligation_index")
        instance_count = (
            index.get("instance_count", 0) if type(index) is dict else 0
        )
    print(
        f"[{report.get('status', 'UNKNOWN')}] package GRAPH polish "
        f"{requested_tier}: objects.vstd; "
        f"objects={graph.get('object_count', 0)}; "
        f"obligation_instances={instance_count}; polished="
        f"{'true' if report.get('polished') is True else 'false'}"
    )

    tier_results = report.get("tier_results")
    if type(tier_results) is not list:
        tier_results = []
    package_tiers = {
        item.get("tier"): item for item in tier_results if type(item) is dict
    }
    for depth in range(1, requested_tier + 1):
        selected = package_tiers.get(depth)
        if type(selected) is not dict:
            print(
                f"[UNKNOWN] package tier {depth}: execution=MISSING; "
                "result=UNKNOWN; reason=package tier aggregation was not retained"
            )
            continue
        status = selected.get("status")
        if type(status) is not str:
            status = "UNKNOWN"
        execution_status = selected.get("execution_status", "EXECUTED")
        print(
            f"[{status}] package tier {depth}: execution={execution_status}; "
            f"result={status}; instances={selected.get('instance_count', 0)}; "
            f"status_counts={_human_json(selected.get('status_counts', {}))}; "
            "checker_status_counts="
            + _human_json(selected.get("checker_status_counts", {}))
        )
        reason = selected.get("reason")
        if type(reason) is str and reason:
            print(f"  reason={reason}")

    denominator = report.get("denominator_status")
    if type(denominator) is str:
        print(f"package denominator={denominator}")
        if denominator != "COMPLETE":
            print(
                "[UNKNOWN] cumulative report not complete: complete package-plus-"
                "native accounting was not retained; omitted rows or evidence "
                "are not PASS or inapplicable"
            )

    native = report.get("native_diagnostics")
    native_retained = type(native) is dict
    execution = native.get("tier_execution") if native_retained else None
    prerequisites = native.get("prerequisites") if native_retained else None
    if type(execution) is not dict:
        execution = {}
    if type(prerequisites) is not dict:
        prerequisites = {}

    listed: dict[str, int] = {}

    def blocker_text(blockers: list[Any], depth: int) -> str:
        # The tiers above a failed prerequisite all name the same blockers; list a
        # long set once and let the later tiers point back at it.
        first = listed.setdefault(_human_json(blockers), depth)
        if first != depth and len(blockers) > _BLOCKER_DETAIL_LIMIT:
            return f"same blockers as native tier {first}"
        return _human_blockers(blockers)

    for depth in range(requested_tier + 1):
        selected = execution.get(str(depth))
        prerequisite = prerequisites.get(str(depth))
        if type(selected) is not dict:
            missing_status = "NOT_RETAINED" if not native_retained else "MISSING"
            print(
                f"[UNKNOWN] native tier {depth}: execution={missing_status}; "
                "result=UNKNOWN; reason=native diagnostic execution evidence "
                "was not retained; cumulative report not complete"
            )
            if type(prerequisite) is dict:
                print(
                    "  prerequisite_result="
                    + str(prerequisite.get("status", "UNKNOWN"))
                )
                prerequisite_blockers = prerequisite.get("blockers")
                if type(prerequisite_blockers) is list \
                        and prerequisite_blockers:
                    print(
                        "  prerequisite_blockers="
                        + blocker_text(prerequisite_blockers, depth)
                    )
            continue
        execution_status = selected.get("execution_status")
        if type(execution_status) is not str:
            execution_status = "UNKNOWN"
        result_status = selected.get("status")
        if type(result_status) is not str and type(prerequisite) is dict:
            result_status = prerequisite.get("status")
        if type(result_status) is not str:
            result_status = "UNKNOWN"
        name = selected.get("tier_name")
        name_suffix = f" {name}" if type(name) is str and name else ""
        reason = selected.get("reason")
        if type(reason) is not str:
            reason = selected.get("assessment_reason")
        reason_suffix = f"; reason={reason}" if type(reason) is str and reason else ""
        print(
            f"[{result_status}] native tier {depth}{name_suffix}: "
            f"execution={execution_status}; result={result_status}"
            f"{reason_suffix}"
        )
        blocking = selected.get("blocking_prerequisite")
        if type(blocking) is dict and type(blocking.get("blockers")) is list \
                and len(blocking["blockers"]) > _BLOCKER_DETAIL_LIMIT:
            print(
                f"  blocking_prerequisite=tier {blocking.get('tier')} "
                f"{blocking.get('tier_name')} observed={blocking.get('observed_status')} "
                f"required={blocking.get('required_status')}; "
                + blocker_text(blocking["blockers"], depth)
            )
        elif blocking is not None:
            print("  blocking_prerequisite=" + _human_json(blocking))
        blockers = selected.get("blockers")
        if type(blockers) is list and blockers:
            print("  blockers=" + blocker_text(blockers, depth))
        prerequisite_blockers = (
            prerequisite.get("blockers")
            if type(prerequisite) is dict else None
        )
        if type(prerequisite_blockers) is list and prerequisite_blockers:
            print(
                "  prerequisite_blockers="
                + blocker_text(prerequisite_blockers, depth)
            )

    seen_records: set[str] = set()
    native_records: list[tuple[int, Mapping[str, Any]]] = []
    for depth_text, prerequisite in sorted(prerequisites.items()):
        if type(prerequisite) is not dict:
            continue
        try:
            depth = int(depth_text)
        except (TypeError, ValueError):
            depth = requested_tier
        records = prerequisite.get("nonpass_records")
        if type(records) is not list:
            continue
        for record in records:
            if type(record) is not dict:
                continue
            identity = _human_json(record)
            if identity in seen_records:
                continue
            seen_records.add(identity)
            native_records.append((depth, record))
    detail = native.get("nonpass_detail") if native_retained else None
    records = detail.get("nonpass_records") if type(detail) is dict else None
    if type(records) is list:
        for record in records:
            if type(record) is not dict:
                continue
            identity = _human_json(record)
            if identity in seen_records:
                continue
            seen_records.add(identity)
            selected_tier = record.get("tier")
            native_records.append((
                selected_tier if type(selected_tier) is int else requested_tier,
                record,
            ))
    _print_native_nonpass_records(native_records)

    for blocker in report.get("blockers", []):
        if type(blocker) is str:
            print("- " + blocker)
    findings = report.get("findings")
    if type(findings) is list and findings:
        from verifier.runtime.manifest_gate import print_finding_groups
        print_finding_groups(findings)


def _normalized_manifest_refresh_blockers(
        refresh: Mapping[str, Any]) -> list[str]:
    """Keep refresh blockers iterable, unique and fail-closed."""

    raw = refresh.get("blockers")
    selected: list[str] = []
    malformed = type(raw) is not list
    if type(raw) is list:
        for blocker in raw:
            if type(blocker) is not str or not blocker:
                malformed = True
                continue
            if blocker not in selected:
                selected.append(blocker)
    if (
        not selected
        or malformed
        or not _manifest_refresh_blocked_input_valid(refresh)
    ) and "MANIFEST_REFRESH_OUTCOME_INVALID" not in selected:
        selected.append("MANIFEST_REFRESH_OUTCOME_INVALID")
    return selected


def _manifest_refresh_blocked_input_valid(refresh: Any) -> bool:
    """Validate the bounded producer outcome used to build a blocked command."""

    from verifier.runtime import package_manifest_refresh

    if type(refresh) is not dict:
        return False
    allowed = {
        "schema_version", "status", "blockers", "review_required",
        "before_digest", "after_digest", "backup_digest",
        "source_census_digest", "migration_mechanism_digest",
        "refresh_is_admission", "refresh_is_polish", "source_refusal",
    }
    if (
        not set(refresh).issubset(allowed)
        or refresh.get("schema_version")
            != package_manifest_refresh.OUTCOME_SCHEMA
        or refresh.get("status") not in {"REFRESH_REQUIRED", "FAIL", "UNKNOWN"}
        or refresh.get("refresh_is_admission") is not False
        or refresh.get("refresh_is_polish") is not False
        or type(refresh.get("blockers")) is not list
        or not refresh["blockers"]
        or any(type(code) is not str or not code for code in refresh["blockers"])
    ):
        return False
    # Classified estate refusals travel as details from ensure_current_manifest;
    # accept only the producer's own closed vocabulary (or UNCLASSIFIED).
    if "source_refusal" in refresh and (
        type(refresh["source_refusal"]) is not str
        or refresh["source_refusal"] not in (
            package_manifest_refresh._SOURCE_REFUSAL_CODES | {"UNCLASSIFIED"}
        )
    ):
        return False
    for key in (
        "before_digest", "after_digest", "source_census_digest",
        "migration_mechanism_digest",
    ):
        if key in refresh and (
            type(refresh[key]) is not str
            or _SHA256.fullmatch(refresh[key]) is None
        ):
            return False
    if "backup_digest" in refresh and refresh["backup_digest"] is not None \
            and (
                type(refresh["backup_digest"]) is not str
                or _SHA256.fullmatch(refresh["backup_digest"]) is None
            ):
        return False
    if refresh["status"] == "REFRESH_REQUIRED":
        required = {
            "before_digest", "after_digest", "backup_digest",
            "source_census_digest", "migration_mechanism_digest",
        }
        if not required.issubset(refresh) or refresh["backup_digest"] is not None:
            return False
    return True


def _manifest_refresh_allows_assessment(refresh: Any) -> bool:
    """Accept only a complete refresh receipt before calling an assessor.

    A status label alone is not a freshness proof.  These are the exact public
    receipt shapes emitted by ``package_manifest_refresh`` for the three
    outcomes that permit assessment.  Unknown keys are rejected so a future
    producer version cannot silently widen this trust boundary.
    """

    from verifier.runtime import package_manifest_refresh

    if type(refresh) is not dict:
        return False
    status = refresh.get("status")
    common = {
        "schema_version", "status", "before_digest", "after_digest",
        "backup_digest", "source_census_digest",
        "migration_mechanism_digest", "refresh_is_admission",
        "refresh_is_polish",
    }
    if status in {"CURRENT", "NOT_APPLICABLE"}:
        if set(refresh) != common:
            return False
    elif status == "REMIGRATED":
        if set(refresh) != common | {
            "backup_locator", "prepared_receipt_digest",
            "directory_durability",
        }:
            return False
    else:
        return False
    if (
        refresh.get("schema_version")
        != package_manifest_refresh.RECEIPT_SCHEMA
        or refresh.get("refresh_is_admission") is not False
        or refresh.get("refresh_is_polish") is not False
        or not all(
            type(refresh.get(key)) is str
            and _SHA256.fullmatch(refresh[key]) is not None
            for key in (
                "before_digest", "after_digest",
                "migration_mechanism_digest",
            )
        )
    ):
        return False
    if status == "CURRENT":
        return (
            refresh["before_digest"] == refresh["after_digest"]
            and refresh.get("backup_digest") is None
            and type(refresh.get("source_census_digest")) is str
            and _SHA256.fullmatch(refresh["source_census_digest"]) is not None
        )
    if status == "NOT_APPLICABLE":
        return (
            refresh["before_digest"] == refresh["after_digest"]
            and refresh.get("backup_digest") is None
            and refresh.get("source_census_digest") is None
        )
    return (
        refresh["before_digest"] != refresh["after_digest"]
        and refresh.get("backup_digest") == refresh["before_digest"]
        and type(refresh.get("source_census_digest")) is str
        and _SHA256.fullmatch(refresh["source_census_digest"]) is not None
        and type(refresh.get("backup_locator")) is str
        and bool(refresh["backup_locator"])
        and type(refresh.get("prepared_receipt_digest")) is str
        and _SHA256.fullmatch(refresh["prepared_receipt_digest"]) is not None
        and refresh.get("directory_durability") == "NOT_ESTABLISHED"
    )


def _manifest_refresh_findings(
        refresh: Mapping[str, Any], blockers: list[str]) -> list[dict[str, Any]]:
    """Locate each refresh review at its object and obligation coordinate."""

    from verifier.runtime import manifest_gate

    findings: list[dict[str, Any]] = []
    review_required = refresh.get("review_required")
    malformed_review = review_required is not None and type(review_required) is not list
    seen: set[tuple[str, str, str, str, str | None]] = set()
    if type(review_required) is list:
        for row in review_required:
            if type(row) is not dict:
                malformed_review = True
                continue
            object_id = row.get("object_id")
            if type(object_id) is not str or not object_id:
                malformed_review = True
                continue
            path = row.get("path")
            if type(path) is not str or not path:
                malformed_review = True
                continue
            reason = row.get("reason")
            if type(reason) is not str or not reason:
                malformed_review = True
                continue
            classifications = row.get("classifications")
            if type(classifications) is not list:
                malformed_review = True
                classifications = []
            selected_classifications = []
            for classification_kind in classifications:
                if type(classification_kind) is not str or not classification_kind:
                    malformed_review = True
                    continue
                if classification_kind not in selected_classifications:
                    selected_classifications.append(classification_kind)
            obligations = row.get("obligations")
            if type(obligations) is not list:
                malformed_review = True
                obligations = []
            selected = []
            for obligation_id in obligations:
                if type(obligation_id) is not str or not obligation_id:
                    malformed_review = True
                    continue
                if obligation_id not in selected:
                    selected.append(obligation_id)
            if not selected and not selected_classifications:
                malformed_review = True
                continue
            # Applicability answers are review coordinates in their own right.
            # They need not share a completed kind obligation, so project each
            # one through the ubiquitous source-freshness obligation instead of
            # mislabelling a valid classification-only row as malformed.
            for classification_kind in selected_classifications:
                located = manifest_gate.repository_finding(
                    reason, "UNKNOWN", object_id=object_id,
                )
                obligation_id = located.get("obligation_id")
                if type(obligation_id) is not str or not obligation_id:
                    malformed_review = True
                    continue
                identity = (
                    object_id, obligation_id, path, reason, classification_kind,
                )
                if identity in seen:
                    continue
                seen.add(identity)
                rerun = [
                    "vstd", "gate", "--object", object_id,
                    "--obligation", obligation_id,
                ]
                explanation = (
                    f"{reason} requires renewed semantic review of "
                    f"classification {classification_kind} before root "
                    "objects.vstd can be refreshed."
                )
                located.update(
                    object_kind=classification_kind,
                    coordinate=f"file:{path}",
                    gate_id="manifest-refresh",
                    reason=explanation,
                    explanation=explanation,
                    next_action=(
                        "Review the changed source semantics for this exact "
                        "object and classification, then rerun the focused "
                        "source-freshness obligation."
                    ),
                    rerun_argv=rerun,
                )
                findings.append(located)
            for obligation_id in selected:
                identity = (object_id, obligation_id, path, reason, None)
                if identity in seen:
                    continue
                seen.add(identity)
                located = manifest_gate.repository_finding(
                    reason,
                    "UNKNOWN",
                    object_id=object_id,
                    obligation_id=obligation_id,
                )
                rerun = (
                    [
                        "vstd", "gate", "--object", object_id,
                        "--obligation", obligation_id,
                    ]
                    if object_id is not None and obligation_id is not None
                    else None
                )
                explanation = (
                    f"{reason} requires renewed semantic review before "
                    "root objects.vstd can be refreshed."
                )
                located.update(
                    coordinate=f"file:{path}",
                    gate_id="manifest-refresh",
                    reason=explanation,
                    explanation=explanation,
                    next_action=(
                        "Review the changed source semantics for this exact "
                        "object and obligation, then rerun the focused gate."
                    ),
                    rerun_argv=rerun,
                )
                findings.append(located)
    if malformed_review:
        invalid = manifest_gate.repository_finding(
            "MANIFEST_REFRESH_OUTCOME_INVALID", "UNKNOWN",
        )
        explanation = (
            "The manifest-refresh mechanism returned malformed review "
            "accounting; no omitted row is treated as reviewed."
        )
        invalid.update(
            gate_id="manifest-refresh",
            reason=explanation,
            explanation=explanation,
            next_action=(
                "Repair the refresh outcome producer and rerun package polish."
            ),
        )
        findings.append(invalid)
    if findings:
        return findings
    fallback = []
    for code in blockers:
        located = manifest_gate.repository_finding(code, "UNKNOWN")
        located["gate_id"] = "manifest-refresh"
        fallback.append(located)
    return fallback


def _manifest_refresh_not_run_accounting(
        tier: int, blockers: list[str]) -> dict[str, Any]:
    """Retain cumulative NOT_RUN ledgers when freshness blocks assessment.

    Manifest refresh is a prerequisite, not polish. The stale assessor remains
    uncalled, while every requested package and native tier is explicitly
    unexecuted instead of disappearing from the command result.
    """

    if tier not in {1, 2, 3}:
        return {}
    native = not_run_native_diagnostic_reference(
        stage="ROOT_MANIFEST_REFRESH", blockers=blockers, requested_tier=tier,
    )
    names = {1: "FACETS", 2: "DYNAMICS", 3: "STATICS"}
    return {
        "assessment_execution_status": "NOT_RUN",
        "package_graph": None,
        "obligation_instances": [],
        "tier_results": [
            {
                "tier": depth,
                "tier_name": names[depth],
                "instance_count": 0,
                "status_counts": {},
                "status": "UNKNOWN",
                "checker_status_counts": {},
                "prerequisite_tiers": list(range(depth)),
                "execution_status": "NOT_RUN",
                "reason": (
                    f"Package Tier {depth} {names[depth]} was not executed "
                    "because root objects.vstd refresh did not complete."
                ),
            }
            for depth in range(1, tier + 1)
        ],
        "denominator_status": "NOT_RETAINED",
        "native_diagnostics": native,
    }


_REFRESH_FINDING_FIELDS = {
    "scope", "object_id", "object_kind", "coordinate", "obligation_id",
    "obligation_name", "semantic_version", "gate_id", "status", "code",
    "reason", "explanation", "next_action", "rerun_argv",
}


def not_run_native_diagnostic_reference(
        *, stage: str, blockers: list[str], requested_tier: int = 3,
) -> dict[str, Any]:
    """Close the requested native prefix when package work stops first."""

    _require(requested_tier in {1, 2, 3}, "PACKAGE_NATIVE_TIER_INVALID")
    selected_blockers = sorted({
        blocker for blocker in blockers if type(blocker) is str and blocker
    }) or ["PACKAGE_ASSESSMENT_INCOMPLETE"]
    blocking = {
        "tier": 0,
        "tier_name": "ADMISSION",
        "required_status": "PASS",
        "observed_status": "UNKNOWN",
        "report_digest": None,
        "blockers": selected_blockers,
        "failure_stage": stage,
        "exception_type": "PACKAGE_ASSESSMENT_INCOMPLETE",
    }
    execution = {
        str(depth): _not_run_tier_execution_record(
            depth,
            reason=(
                f"Native Tier {depth} {_NATIVE_TIER_NAMES[depth]} did not "
                "complete because "
                f"package assessment stopped at {stage}; no native evidence "
                "digest is claimed."
            ),
            blocking_prerequisite=blocking,
        )
        for depth in range(requested_tier + 1)
    }
    body = {
        "schema_version": "verifier-native-diagnostic-reference-1",
        "status": "UNKNOWN",
        "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
        "transport": "NOT_RUN_LEDGER",
        "prerequisites": {},
        "tier_execution": execution,
        "claim_boundary": (
            "Package assessment stopped before an admissible native diagnostic "
            "report completed. Every requested native tier remains UNKNOWN and "
            "NOT_RUN."
        ),
    }
    return {**body, "report_digest": core_obligation_union.value_digest(body)}


def _not_run_tier_execution_record(
        tier: int, *, reason: str,
        blocking_prerequisite: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema_version": "verifier-self-polish-tier-execution-1",
        "tier": tier,
        "tier_name": _NATIVE_TIER_NAMES[tier],
        "execution_status": "NOT_RUN",
        "status": "UNKNOWN",
        "reason": reason,
        "evidence_digest": None,
        "blocking_prerequisite": blocking_prerequisite,
    }
    return {
        **body,
        "execution_record_digest": core_obligation_union.value_digest(body),
    }


def _sealed_blocked_report(
        tier: int, *, default_package: bool, blockers: list[str],
        findings: list[dict[str, Any]], refresh_schema: Any,
        refresh_status: Any) -> dict[str, Any]:
    """Seal the one command envelope used whenever assessment is not run."""

    body = {
        "schema_version": POLISH_REFRESH_BLOCKED_SCHEMA,
        "refresh_outcome_schema_version": (
            refresh_schema if type(refresh_schema) is str else None
        ),
        "refresh_outcome_status": (
            refresh_status if type(refresh_status) is str else None
        ),
        "status": "FAIL" if refresh_status == "FAIL" else "UNKNOWN",
        "blockers": blockers,
        "requested_tier": tier,
        "assessment_execution_status": "NOT_RUN",
        **(
            _manifest_refresh_not_run_accounting(tier, blockers)
            if default_package else {}
        ),
        "findings": findings,
        "refresh_is_admission": False,
        "refresh_is_polish": False,
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": (
            "The root manifest refresh did not complete, so no stale "
            "admission or package-polish assessor was run. The command envelope "
            "records NOT_RUN execution, not a polish assessment."
        ),
    }
    return {**body, "report_digest": core_obligation_union.value_digest(body)}


def _mechanism_unavailable_finding(code: str, tier: int) -> dict[str, Any]:
    """Name one unavailable prerequisite with its exact safe rerun route.

    Ordinary refresh blockers keep the producer's uniform repository finding so
    the same validator that reconstructs them continues to accept them.
    """

    if code not in _MECHANISM_UNAVAILABLE_ACTIONS:
        from verifier.runtime import manifest_gate

        finding = manifest_gate.repository_finding(code, "UNKNOWN", tier=tier)
        finding["gate_id"] = "manifest-refresh"
        return finding
    from verifier.runtime import manifest_gate

    explanation, action = _MECHANISM_UNAVAILABLE_ACTIONS[code]
    finding = manifest_gate.repository_finding(code, "UNKNOWN", tier=tier)
    finding.update(
        coordinate="VSTD-T0.7",
        obligation_id="VSTD-T0.7-source-and-mechanism-freshness",
        obligation_name="Source and mechanism freshness",
        gate_id="manifest-refresh",
        reason=explanation,
        explanation=explanation,
        next_action=action.format(tier=tier),
        rerun_argv=["vstd", "polish", str(tier), "--json"],
    )
    return finding


def _mechanism_unavailable_report(
        tier: int, *, default_package: bool,
        blockers: list[str]) -> dict[str, Any]:
    """Self-contained UNKNOWN envelope when a verifier mechanism is unusable.

    This builder imports nothing: the mechanism it reports may be the very
    module that failed to import. Its output still passes the same blocked-report
    contract that tests validate.
    """

    selected = sorted(set(blockers))
    return _sealed_blocked_report(
        tier,
        default_package=default_package,
        blockers=selected,
        findings=[_mechanism_unavailable_finding(code, tier) for code in selected],
        refresh_schema=None,
        refresh_status=None,
    )


def _refresh_source_drift_code(exc: BaseException) -> str | None:
    """Recover live source drift that the refresh wrapper reported as outage.

    Refresh converts estate failures into a generic UNKNOWN code and keeps the
    original refusal as its cause. Only the retryable drift codes are lifted.
    """

    cause = exc.__cause__
    if (
        isinstance(cause, self_polish_estate.EstateError)
        and str(cause) in LIVE_SOURCE_DRIFT_CODES
    ):
        return str(cause)
    return None


def _refresh_blockers_untrusted(refresh: Any) -> list[str]:
    return _normalized_manifest_refresh_blockers(
        refresh if type(refresh) is dict else {}
    )


def _manifest_refresh_blocked_report(
        refresh: Any, tier: int, *, default_package: bool) -> dict[str, Any]:
    """Normalize an untrusted refresh outcome into one command-owned schema."""

    selected = refresh if type(refresh) is dict else {}
    blockers = _normalized_manifest_refresh_blockers(selected)
    findings = _manifest_refresh_findings(selected, blockers)
    if (
        any(
            finding.get("code") == "MANIFEST_REFRESH_OUTCOME_INVALID"
            for finding in findings if type(finding) is dict
        )
        and "MANIFEST_REFRESH_OUTCOME_INVALID" not in blockers
    ):
        blockers.append("MANIFEST_REFRESH_OUTCOME_INVALID")
    blockers.sort()
    result = _sealed_blocked_report(
        tier,
        default_package=default_package,
        blockers=blockers,
        findings=findings,
        refresh_schema=selected.get("schema_version"),
        refresh_status=selected.get("status"),
    )
    _require(
        _valid_manifest_refresh_blocked_report(result),
        "MANIFEST_REFRESH_BLOCKED_ENVELOPE_INVALID",
    )
    return result


def _valid_manifest_refresh_finding(value: Any, *, tier: int) -> bool:
    if type(value) is not dict or set(value) != _REFRESH_FINDING_FIELDS:
        return False
    nullable_strings = {
        "object_id", "object_kind", "coordinate", "obligation_id",
        "obligation_name", "semantic_version",
    }
    if any(
        value[key] is not None and type(value[key]) is not str
        for key in nullable_strings
    ):
        return False
    if value.get("code") in _MECHANISM_UNAVAILABLE_ACTIONS:
        # These findings are produced without importing the mechanism they
        # describe, so their exact content is reconstructed from the table.
        return (
            type(value.get("code")) is str
            and value == _mechanism_unavailable_finding(value["code"], tier)
        )
    if any(
        type(value[key]) is not str or not value[key].strip()
        for key in (
            "scope", "gate_id", "status", "code", "reason", "explanation",
            "next_action",
        )
    ) or (
        # Refresh findings publish ``reason`` as the stable human-facing alias
        # for the backwards-compatible ``explanation`` field.  Presence alone
        # is insufficient: a recomputed outer digest must not let the two
        # accounts disagree about why assessment was blocked.
        value["reason"] != value["explanation"]
    ) or value["status"] != "UNKNOWN" or value["gate_id"] != "manifest-refresh":
        return False
    rerun = value["rerun_argv"]
    focused_rerun = (
        type(rerun) is list
        and all(type(item) is str and item for item in rerun)
        and len(rerun) == 6
        and rerun[:3] == ["vstd", "gate", "--object"]
        and rerun[4] == "--obligation"
        and rerun[3] == value["object_id"]
        and rerun[5] == value["obligation_id"]
    )
    root_rerun = (
        type(rerun) is list
        and len(rerun) == 4
        and rerun[:2] == ["vstd", "polish"]
        and rerun[2] in {"0", "1", "2", "3"}
        and rerun[3] == "--json"
    )
    rerun_valid = focused_rerun or root_rerun
    if not rerun_valid:
        return False

    # A fresh digest authenticates only the mutated envelope. Reconstruct the
    # deterministic producer row so changing both prose aliases cannot replace
    # the source-refresh reason while leaving the wire shape internally valid.
    from verifier.runtime import manifest_gate
    coordinate = value["coordinate"]
    if type(coordinate) is str and coordinate.startswith("file:"):
        if type(value["object_id"]) is not str \
                or type(value["obligation_id"]) is not str:
            return False
        classification_kind = value["object_kind"]
        if classification_kind is None:
            expected = manifest_gate.repository_finding(
                value["code"], "UNKNOWN", object_id=value["object_id"],
                obligation_id=value["obligation_id"],
            )
            explanation = (
                f"{value['code']} requires renewed semantic review before "
                "root objects.vstd can be refreshed."
            )
            next_action = (
                "Review the changed source semantics for this exact object "
                "and obligation, then rerun the focused gate."
            )
        else:
            if type(classification_kind) is not str or not classification_kind:
                return False
            expected = manifest_gate.repository_finding(
                value["code"], "UNKNOWN", object_id=value["object_id"],
            )
            if expected.get("obligation_id") != value["obligation_id"]:
                return False
            explanation = (
                f"{value['code']} requires renewed semantic review of "
                f"classification {classification_kind} before root "
                "objects.vstd can be refreshed."
            )
            next_action = (
                "Review the changed source semantics for this exact object and "
                "classification, then rerun the focused source-freshness obligation."
            )
        expected.update(
            object_kind=classification_kind,
            coordinate=coordinate,
            gate_id="manifest-refresh",
            reason=explanation,
            explanation=explanation,
            next_action=next_action,
            rerun_argv=[
                "vstd", "gate", "--object", value["object_id"],
                "--obligation", value["obligation_id"],
            ],
        )
        return value == expected

    if value["code"] == "MANIFEST_REFRESH_OUTCOME_INVALID" and value[
            "explanation"] == (
                "The manifest-refresh mechanism returned malformed review "
                "accounting; no omitted row is treated as reviewed."
            ):
        expected = manifest_gate.repository_finding(
            "MANIFEST_REFRESH_OUTCOME_INVALID", "UNKNOWN",
        )
        expected.update(
            gate_id="manifest-refresh",
            reason=value["explanation"],
            explanation=value["explanation"],
            next_action=(
                "Repair the refresh outcome producer and rerun package polish."
            ),
        )
        return value == expected

    expected = manifest_gate.repository_finding(value["code"], "UNKNOWN")
    expected["gate_id"] = "manifest-refresh"
    return value == expected


def _valid_manifest_refresh_native_execution(
        value: Any, *, tier: int, blockers: list[str]) -> bool:
    names = {0: "ADMISSION", 1: "FACETS", 2: "DYNAMICS", 3: "STATICS"}
    fields = {
        "schema_version", "tier", "tier_name", "execution_status", "status",
        "evidence_digest", "reason", "blocking_prerequisite",
        "execution_record_digest",
    }
    if type(value) is not dict or set(value) != fields:
        return False
    prerequisite = value.get("blocking_prerequisite")
    prerequisite_fields = {
        "tier", "tier_name", "required_status", "observed_status",
        "failure_stage", "exception_type", "blockers", "report_digest",
    }
    if (
        value.get("schema_version") != "verifier-self-polish-tier-execution-1"
        or value.get("tier") != tier
        or value.get("tier_name") != names[tier]
        or value.get("execution_status") != "NOT_RUN"
        or value.get("status") != "UNKNOWN"
        or value.get("evidence_digest") is not None
        or type(value.get("reason")) is not str
        or not value["reason"]
        or type(prerequisite) is not dict
        or set(prerequisite) != prerequisite_fields
        or prerequisite != {
            "tier": 0,
            "tier_name": "ADMISSION",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "failure_stage": "ROOT_MANIFEST_REFRESH",
            "exception_type": "PACKAGE_ASSESSMENT_INCOMPLETE",
            "blockers": blockers,
            "report_digest": None,
        }
    ):
        return False
    body = {key: item for key, item in value.items()
            if key != "execution_record_digest"}
    return value["execution_record_digest"] == core_obligation_union.value_digest(
        body
    )


def _valid_manifest_refresh_blocked_report(value: Any) -> bool:
    """Validate exact command accounting and every self-sealing digest."""

    base_fields = {
        "schema_version", "refresh_outcome_schema_version",
        "refresh_outcome_status", "status", "blockers", "requested_tier",
        "assessment_execution_status", "findings", "refresh_is_admission",
        "refresh_is_polish", "polished", "release_authorized",
        "deployment_authorized", "claim_boundary", "report_digest",
    }
    package_fields = {
        "package_graph", "obligation_instances", "tier_results",
        "denominator_status", "native_diagnostics",
    }
    if type(value) is not dict or value.get("requested_tier") not in {0, 1, 2, 3}:
        return False
    tier = value["requested_tier"]
    if set(value) != base_fields | (package_fields if tier else set()):
        return False
    blockers = value.get("blockers")
    findings = value.get("findings")
    refresh_status = value.get("refresh_outcome_status")
    if (
        value.get("schema_version") != POLISH_REFRESH_BLOCKED_SCHEMA
        or value.get("status") != (
            "FAIL" if refresh_status == "FAIL" else "UNKNOWN"
        )
        or type(blockers) is not list
        or not blockers
        or len(blockers) != len(set(blockers))
        or any(type(code) is not str or not code for code in blockers)
        or value.get("assessment_execution_status") != "NOT_RUN"
        or type(findings) is not list
        or not findings
        or not all(
            _valid_manifest_refresh_finding(row, tier=tier)
            for row in findings
        )
        or value.get("refresh_is_admission") is not False
        or value.get("refresh_is_polish") is not False
        or value.get("polished") is not False
        or value.get("release_authorized") is not False
        or value.get("deployment_authorized") is not False
        or type(value.get("claim_boundary")) is not str
        or not value["claim_boundary"]
        or value.get("refresh_outcome_schema_version") is not None
            and type(value["refresh_outcome_schema_version"]) is not str
        or refresh_status is not None and type(refresh_status) is not str
    ):
        return False
    body = {key: item for key, item in value.items() if key != "report_digest"}
    if value.get("report_digest") != core_obligation_union.value_digest(body):
        return False
    if tier == 0:
        return True
    names = {1: "FACETS", 2: "DYNAMICS", 3: "STATICS"}
    tiers = value.get("tier_results")
    if (
        value.get("package_graph") is not None
        or value.get("obligation_instances") != []
        or value.get("denominator_status") != "NOT_RETAINED"
        or type(tiers) is not list
        or len(tiers) != tier
    ):
        return False
    tier_fields = {
        "tier", "tier_name", "instance_count", "status_counts", "status",
        "checker_status_counts", "prerequisite_tiers", "execution_status",
        "reason",
    }
    for depth, row in enumerate(tiers, 1):
        if (
            type(row) is not dict
            or set(row) != tier_fields
            or row.get("tier") != depth
            or row.get("tier_name") != names[depth]
            or row.get("instance_count") != 0
            or row.get("status_counts") != {}
            or row.get("status") != "UNKNOWN"
            or row.get("checker_status_counts") != {}
            or row.get("prerequisite_tiers") != list(range(depth))
            or row.get("execution_status") != "NOT_RUN"
            or type(row.get("reason")) is not str
            or not row["reason"]
        ):
            return False
    native = value.get("native_diagnostics")
    native_fields = {
        "schema_version", "claim_scope", "transport", "status",
        "tier_execution", "prerequisites", "claim_boundary", "report_digest",
    }
    if (
        type(native) is not dict
        or set(native) != native_fields
        or native.get("schema_version") != "verifier-native-diagnostic-reference-1"
        or native.get("claim_scope")
            != "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES"
        or native.get("transport") != "NOT_RUN_LEDGER"
        or native.get("status") != "UNKNOWN"
        or native.get("prerequisites") != {}
        or type(native.get("claim_boundary")) is not str
        or not native["claim_boundary"]
        or type(native.get("tier_execution")) is not dict
        or set(native["tier_execution"]) != {
            str(depth) for depth in range(tier + 1)
        }
    ):
        return False
    if not all(
        _valid_manifest_refresh_native_execution(
            native["tier_execution"][str(depth)],
            tier=depth,
            blockers=blockers,
        )
        for depth in range(tier + 1)
    ):
        return False
    native_body = {key: item for key, item in native.items()
                   if key != "report_digest"}
    return native["report_digest"] == core_obligation_union.value_digest(
        native_body
    )


def _package_numeric_blockers(value: Mapping[str, Any]) -> tuple[str, ...]:
    """Namespace numeric blockers retained by a package fallback."""
    selected = value.get("blockers")
    if type(selected) is not list:
        return ()
    return tuple(
        f"NUMERIC_TIER1_BLOCKER:{blocker}"
        for blocker in selected if type(blocker) is str
    )


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

    def add_manifest_refresh_options(action: argparse.ArgumentParser) -> None:
        action.add_argument(
            "--manifest-refresh",
            choices=("auto", "check"),
            default="auto",
            help=(
                "Refresh Verifier's root objects.vstd from current exact source "
                "before assessment, or use check to refuse drift without writing."
            ),
        )
        action.add_argument(
            "--manifest-refresh-journal",
            help=(
                "External recovery-journal directory for an automatic refresh; "
                "locations inside the selected repository are refused."
            ),
        )
        action.add_argument(
            "--manifest-review-policy",
            choices=("record", "refuse"),
            default="record",
            help=(
                "How a refresh treats reviewed answers whose source changed: "
                "record reopens them and keeps every unanswered question in the "
                "regenerated manifest (the default), refuse stops for a person."
            ),
        )

    zero = commands.add_parser(
        "0", help="Assess repository admission before numbered self-polish tiers."
    )
    zero.add_argument("--source-root", default=".")
    zero.add_argument("--manifest")
    zero.add_argument("--json", action="store_true")
    add_manifest_refresh_options(zero)
    statics = commands.add_parser(
        "3", help="Run Statics with fresh Tier 0, 1 and 2 prerequisites.",
        description="Evaluate the package GRAPH from root objects.vstd through Statics with fresh Tier 0, 1 and 2 diagnostics; no retained caller verdicts.",
    )
    statics.add_argument("--source-root", default=".")
    statics.add_argument("--cancelled", action="store_true")
    statics.add_argument("--json", action="store_true")
    statics.add_argument("--native-specimens", action="store_true",
                         help="Run source-native diagnostic controls only, not package GRAPH polish.")
    add_manifest_refresh_options(statics)
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
        action.add_argument("--native-specimens", action="store_true",
                            help="Select the historical source-native diagnostic contract, not package polish.")
        action.add_argument("--cancelled", action="store_true",
                            help="Return a cancelled package assessment without executing checks.")
        action.add_argument("--complete-tier-evidence-manifest")
        action.add_argument("--complete-tier-evidence-manifest-digest")
        action.add_argument("--evidence-replay-mechanism-digest")
        action.add_argument("--json", action="store_true")
        add_manifest_refresh_options(action)
        if tier == 1:
            action.add_argument(
                "--package-graph",
                action="store_true",
                help=(
                    "Wrap the exact numeric Tier-1 result in the fail-closed "
                    "38-kind whole-package VSTD package GRAPH project gate "
                    "rooted in objects.vstd."
                ),
            )
            action.add_argument(
                "--package-obligation-cards",
                help=(
                    "Directory containing a candidate JSON card for every "
                    "admitted package object kind."
                ),
            )
            action.add_argument(
                "--package-obligation-manifest",
                help=(
                    "Hash manifest binding every selected candidate card's "
                    "bytes."
                ),
            )
            action.add_argument(
                "--package-obligation-manifest-digest",
                help="Required expected SHA-256 digest of the manifest bytes.",
            )
            action.add_argument(
                "--package-obligation-reasons",
                help=(
                    "Optional candidate reason ledger binding all installed "
                    "obligations and kind-tier slots to current semantics."
                ),
            )
            action.add_argument(
                "--package-obligation-reasons-digest",
                help=(
                    "Required expected SHA-256 digest when a candidate reason "
                    "ledger is selected."
                ),
            )
            action.add_argument(
                "--package-owner-policy",
                help=(
                    "Separately selected configured-key package owner policy "
                    "JSON."
                ),
            )
            action.add_argument(
                "--package-owner-policy-digest",
                help="Required expected SHA-256 digest of owner policy bytes.",
            )
            action.add_argument(
                "--package-owner-decisions",
                help=(
                    "Signed exact adoption statement for every applicable "
                    "package owner decision."
                ),
            )
            action.add_argument(
                "--package-owner-decisions-digest",
                help=(
                    "Required expected SHA-256 digest of owner decision "
                    "envelope bytes."
                ),
            )
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


def _selected_legacy_package_options(
        args: argparse.Namespace, tier: int,
        ) -> list[str]:
    """Return explicitly enumerated non-package inputs for numeric dispatch."""

    if tier == 3:
        return []
    common = (
        ("union_authority", args.union_authority),
        ("union_contributions", args.union_contributions),
        ("union_authority_digest", args.union_authority_digest),
        ("application_authority_assessment", args.application_authority_assessment),
        ("application_authority_assessment_digest", args.application_authority_assessment_digest),
        ("complete_tier_ledger", args.complete_tier_ledger),
        ("complete_tier_ledger_digest", args.complete_tier_ledger_digest),
        ("complete_self_representation", args.complete_self_representation),
        ("complete_self_representation_digest", args.complete_self_representation_digest),
        ("complete_tier_evidence_manifest", args.complete_tier_evidence_manifest),
        ("complete_tier_evidence_manifest_digest", args.complete_tier_evidence_manifest_digest),
        ("evidence_replay_mechanism_digest", args.evidence_replay_mechanism_digest),
    )
    if tier == 1:
        specific = (
            ("package_obligation_cards", args.package_obligation_cards),
            ("package_obligation_manifest", args.package_obligation_manifest),
            ("package_obligation_manifest_digest", args.package_obligation_manifest_digest),
            ("package_obligation_reasons", args.package_obligation_reasons),
            ("package_obligation_reasons_digest", args.package_obligation_reasons_digest),
            ("package_owner_policy", args.package_owner_policy),
            ("package_owner_policy_digest", args.package_owner_policy_digest),
            ("package_owner_decisions", args.package_owner_decisions),
            ("package_owner_decisions_digest", args.package_owner_decisions_digest),
            ("selection_digest", args.selection_digest),
            ("candidate_estate_repository", args.candidate_estate_repository),
            ("candidate_estate_revision", args.candidate_estate_revision),
            ("candidate_estate_digest", args.candidate_estate_digest),
            ("candidate_estate_applicability_ledger", args.candidate_estate_applicability_ledger),
            ("candidate_estate_applicability_ledger_digest", args.candidate_estate_applicability_ledger_digest),
            ("candidate_estate_authority_policy", args.candidate_estate_authority_policy),
            ("candidate_estate_authority_policy_digest", args.candidate_estate_authority_policy_digest),
            ("candidate_estate_authority_receipt", args.candidate_estate_authority_receipt),
            ("candidate_estate_authority_receipt_digest", args.candidate_estate_authority_receipt_digest),
            ("candidate_estate_authority_mechanism_digest", args.candidate_estate_authority_mechanism_digest),
            ("candidate_estate_authority_operation_revision_digest", args.candidate_estate_authority_operation_revision_digest),
            ("candidate_estate_authority_instruction_revision_digest", args.candidate_estate_authority_instruction_revision_digest),
            ("candidate_estate_authority_context_revision_digest", args.candidate_estate_authority_context_revision_digest),
            ("candidate_estate_authority_subject_digest", args.candidate_estate_authority_subject_digest),
            ("candidate_estate_authority_evaluation_time", args.candidate_estate_authority_evaluation_time),
            ("candidate_estate_authority_minimum_status_sequence", args.candidate_estate_authority_minimum_status_sequence),
            ("candidate_estate_evidence_manifest", args.candidate_estate_evidence_manifest),
            ("candidate_estate_evidence_manifest_digest", args.candidate_estate_evidence_manifest_digest),
            ("candidate_estate_evidence_mechanism_digest", args.candidate_estate_evidence_mechanism_digest),
            ("candidate_estate_evidence_selection", args.candidate_estate_evidence_selection),
            ("candidate_estate_evidence_artifact", args.candidate_estate_evidence_artifact),
        )
    else:
        specific = (
            ("tier1_report", args.tier1_report),
            ("tier1_report_digest", args.tier1_report_digest),
            ("progression_selection", args.progression_selection),
            ("bundle", args.bundle),
            ("policy", args.policy),
            ("artifacts", args.artifacts),
            ("progression_selection_digest", args.progression_selection_digest),
            ("progression_mechanism_digest", args.progression_mechanism_digest),
        )
    return [name for name, value in (*common, *specific)
            if value is not None and value is not False]


def _tier_zero_manifest_selection(
        args: argparse.Namespace, tier: int,
        ) -> tuple[Path | None, bool]:
    """Resolve Tier-zero input and identify the canonical root manifest.

    An explicit spelling of the root ``objects.vstd`` still selects automatic
    refresh. Returning the canonical path matters for aliases because atomic
    replacement changes the root directory entry, not an alias's old inode.
    """

    if tier != 0 or args.manifest is None:
        return None, tier == 0
    root = Path(args.source_root).resolve(strict=False)
    selected = Path(args.manifest)
    if not selected.is_absolute():
        selected = root / selected
    target = root / "objects.vstd"
    try:
        selects_root = selected.samefile(target)
    except OSError:
        selects_root = selected.resolve(strict=False) == target.resolve(strict=False)
    return (target if selects_root else selected), selects_root


def _emit_blocked_result(
        args: Any, result: dict[str, Any], tier: int, *,
        default_package: bool) -> int:
    """Write one bounded blocked envelope in the selected output mode."""

    raw = _json_report_wire_bytes(result)
    if args.json:
        output = getattr(sys.stdout, "buffer", None)
        if output is None:
            sys.stdout.write(raw.decode("utf-8"))
        else:
            sys.stdout.flush()
            output.write(raw)
    else:
        if default_package:
            _print_package_polish_summary(result, tier)
        else:
            _print_root_refresh_blocked_summary(result)
    return 1 if result["status"] == "FAIL" else 2


def _print_root_refresh_blocked_summary(result: Mapping[str, Any]) -> None:
    """Print a tier-zero refresh block with the focus that package output keeps.

    Refresh is a prerequisite, not assessment. The line states NOT_RUN and that
    conformance is NOT_ESTABLISHED so a blocked run cannot read as a pass.
    """

    print(
        f"[{result['status']}] root objects.vstd refresh; "
        "assessment=NOT_RUN; polished=false; "
        "whole_package_conformance=NOT_ESTABLISHED"
    )
    for blocker in result.get("blockers", []):
        print("- " + (_bounded_human_text(blocker, maximum=512) or ""))
    _print_refresh_blocked_findings(result.get("findings", []))


# A review of a few files reads best as full per-finding blocks.  Past this many
# findings the same instruction repeats once per classified kind and buries the
# next step, so the human view groups them by changed file instead.
_REFRESH_FULL_DETAIL_LIMIT = 12
_REFRESH_FILE_LINE_LIMIT = 25


def _print_refresh_blocked_findings(findings: Any) -> None:
    """Print refresh blockers; group by changed file once there are many.

    Human output only: ``--json`` keeps every finding, and the digest-bound wire
    shape is unchanged.  Findings that do not name a changed file keep their full
    block, and the bounded-text escaping applies to every displayed string.
    """

    rows = [row for row in findings if type(row) is dict] \
        if type(findings) is list else []
    if len(rows) <= _REFRESH_FULL_DETAIL_LIMIT:
        for row in rows:
            _print_refresh_blocked_finding(row)
        return

    by_file: dict[str, dict[str, Any]] = {}
    for row in rows:
        coordinate = row.get("coordinate")
        if row.get("gate_id") == "manifest-refresh" \
                and type(coordinate) is str and coordinate.startswith("file:"):
            entry = by_file.setdefault(coordinate, {
                "objects": set(), "kinds": set(), "count": 0, "rerun": None,
            })
            entry["count"] += 1
            if type(row.get("object_id")) is str:
                entry["objects"].add(row["object_id"])
            if type(row.get("object_kind")) is str:
                entry["kinds"].add(row["object_kind"])
            rerun = row.get("rerun_argv")
            if entry["rerun"] is None and type(rerun) is list and rerun \
                    and all(type(argument) is str for argument in rerun):
                entry["rerun"] = rerun
        else:
            _print_refresh_blocked_finding(row)

    if not by_file:
        return
    ordered = sorted(by_file)
    total = sum(entry["count"] for entry in by_file.values())
    print(
        f"{len(ordered)} changed source files need review "
        f"({total} findings; --json lists each one):"
    )
    for coordinate in ordered[:_REFRESH_FILE_LINE_LIMIT]:
        entry = by_file[coordinate]
        kinds = ",".join(sorted(entry["kinds"]))
        print(
            f"  {_bounded_human_text(coordinate, maximum=512)}"
            f"  objects={len(entry['objects'])}"
            + (f"  kinds={_bounded_human_text(kinds, maximum=512)}" if kinds else "")
        )
    hidden = len(ordered) - _REFRESH_FILE_LINE_LIMIT
    if hidden > 0:
        print(f"  ... and {hidden} more files")
    first = next(
        (coordinate for coordinate in ordered if by_file[coordinate]["rerun"]),
        None,
    )
    if first is not None:
        print(
            "Next: review the changed semantics of "
            f"{_bounded_human_text(first.removeprefix('file:'), maximum=512)}, "
            "then rerun the focused gate: "
            + _human_json(by_file[first]["rerun"])
        )


def _print_refresh_blocked_finding(finding: Mapping[str, Any]) -> None:
    """Print one bounded refresh finding at its exact object and obligation.

    The refresh outcome is an untrusted producer envelope, so every displayed
    string is escaped and bounded before it reaches the terminal.
    """

    status = finding.get("status")
    if status not in {"FAIL", "UNKNOWN"}:
        status = "UNKNOWN"
    target = _bounded_human_text(finding.get("object_id"), maximum=256)
    obligation = _bounded_human_text(finding.get("obligation_id"), maximum=512)
    gate = _bounded_human_text(finding.get("gate_id"), maximum=256)
    focus = ""
    for name in ("coordinate", "object_kind"):
        value = _bounded_human_text(finding.get(name), maximum=512)
        if value is not None:
            focus += f" {name}={value}"
    print(
        f"[{status}] object={target or '<repository>'} "
        f"obligation={obligation or '<package-wide prerequisite>'} "
        f"gate={gate or 'manifest-refresh'}" + focus
    )
    name = _bounded_human_text(finding.get("obligation_name"), maximum=512)
    if name is not None:
        print("  obligation_name=" + name)
    reason = _bounded_human_text(finding.get("reason"))
    if reason is not None:
        print("  reason=" + reason)
    rerun = finding.get("rerun_argv")
    if type(rerun) is list and rerun \
            and all(type(argument) is str for argument in rerun):
        print("  rerun_argv=" + _human_json(rerun))
    next_action = _bounded_human_text(finding.get("next_action"))
    if next_action is not None:
        print("  Next: " + next_action)


def handle_self_polish_tier_argv(argv: list[str]) -> int:
    """Handle arguments beginning with literal tier ``0``, ``1``, ``2`` or ``3``.

    The installed profile document, each distinct source census and each reviewed file's
    admission analysis are pure functions of bytes that cannot change under one command,
    so they are built once for the whole run (refresh, assessment and capacity replay)
    instead of once per consumer.
    """
    try:
        from verifier.runtime import (
            namespace_discovery,
            package_contract_profiles,
            package_semantic_review_admission,
        )
    except _MECHANISM_IMPORT_ERRORS:
        # The handler reports an unavailable mechanism itself; run it unscoped.
        return _handle_self_polish_tier_argv(argv)
    with (
        namespace_discovery.discovery_scope(),
        package_contract_profiles.document_scope(),
        package_semantic_review_admission.analysis_scope(),
    ):
        return _handle_self_polish_tier_argv(argv)


def _manifest_refresh_module():
    """Resolve the refresh mechanism at its bounded late-import seam."""

    from verifier.runtime import package_manifest_refresh
    return package_manifest_refresh


def _package_polish_modules():
    """Resolve the package assessor and its validator at one late-import seam."""

    from verifier.runtime import package_polish
    from verifier.runtime import package_polish_schema_validation
    return package_polish, package_polish_schema_validation


def _handle_self_polish_tier_argv(argv: list[str]) -> int:
    parser = build_self_polish_tier_parser()
    args = parser.parse_args(argv)
    tier = int(args.self_polish_tier)
    if tier in (1, 2) and args.cancelled and args.native_specimens:
        parser.error(
            "--cancelled applies to default package polish, not retained native "
            "or legacy package inputs"
        )
    if (
        tier in (1, 2)
        and args.native_specimens
        and getattr(args, "package_graph", False)
    ):
        parser.error("--native-specimens and --package-graph select distinct contracts")

    default_package = (
        tier in (1, 2, 3)
        and not args.native_specimens
        and not getattr(args, "package_graph", False)
    )
    if default_package:
        extras = _selected_legacy_package_options(args, tier)
        if extras:
            parser.error(
                "Default package polish reads root objects.vstd; native evidence "
                "options require --native-specimens, and legacy package owner/card "
                "inputs require --package-graph."
            )

    tier_zero_manifest_path, tier_zero_selects_root = (
        _tier_zero_manifest_selection(args, tier)
    )
    refresh_selected = (
        not getattr(args, "cancelled", False)
        and not getattr(args, "package_graph", False)
        and not getattr(args, "native_specimens", False)
        and not (
            tier == 0
            and args.manifest is not None
            and not tier_zero_selects_root
        )
    )
    refresh = None
    if refresh_selected:
        try:
            package_manifest_refresh = _manifest_refresh_module()
        except _MECHANISM_IMPORT_ERRORS:
            return _emit_blocked_result(
                args,
                _mechanism_unavailable_report(
                    tier,
                    default_package=default_package,
                    blockers=["MANIFEST_REFRESH_MECHANISM_UNAVAILABLE"],
                ),
                tier,
                default_package=default_package,
            )

        try:
            refresh = package_manifest_refresh.ensure_current_manifest(
                args.source_root,
                mode=args.manifest_refresh,
                journal_root=args.manifest_refresh_journal,
                review_policy=args.manifest_review_policy,
            )
        except package_manifest_refresh.ManifestRefreshError as exc:
            drift = _refresh_source_drift_code(exc)
            if drift is not None:
                return _emit_blocked_result(
                    args,
                    _mechanism_unavailable_report(
                        tier, default_package=default_package, blockers=[drift],
                    ),
                    tier,
                    default_package=default_package,
                )
            # The outcome has a closed key set.  A preview failure's cause is therefore
            # named as a second blocker instead of riding along as an unknown key
            # (which only made the whole outcome look invalid and hid the cause).
            details = dict(exc.details)
            cause = details.pop("cause", None)
            cause_type = details.pop("cause_type", None)
            named = next(
                (name for name in map(_refresh_cause_name, (cause, cause_type)) if name),
                None,
            )
            refresh = {
                "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
                "status": exc.status,
                "blockers": [exc.code, *([f"{exc.code}:{named}"] if named else [])],
                **details,
                "refresh_is_admission": False,
                "refresh_is_polish": False,
            }
        if not _manifest_refresh_allows_assessment(refresh):
            try:
                result = _manifest_refresh_blocked_report(
                    refresh, tier, default_package=default_package,
                )
            except (_ContractError, *_MECHANISM_IMPORT_ERRORS):
                # The producer outcome or a helper module broke the envelope
                # contract. Keep the refresh blockers, but do not trust the
                # rejected envelope or let its failure escape as a traceback.
                result = _mechanism_unavailable_report(
                    tier,
                    default_package=default_package,
                    blockers=[
                        *_refresh_blockers_untrusted(refresh),
                        "MANIFEST_REFRESH_BLOCKED_ENVELOPE_INVALID",
                    ],
                )
            return _emit_blocked_result(
                args, result, tier, default_package=default_package,
            )
        if refresh["status"] == "REMIGRATED":
            summary = {
                key: refresh[key]
                for key in (
                    "schema_version",
                    "status",
                    "before_digest",
                    "after_digest",
                    "source_census_digest",
                    "migration_mechanism_digest",
                )
            }
            print(
                "vstd manifest refresh: "
                + json.dumps(summary, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
    if default_package:
        try:
            package_polish, package_polish_schema_validation = (
                _package_polish_modules()
            )
        except _MECHANISM_IMPORT_ERRORS:
            return _emit_blocked_result(
                args,
                _mechanism_unavailable_report(
                    tier,
                    default_package=True,
                    blockers=["PACKAGE_POLISH_MECHANISM_UNAVAILABLE"],
                ),
                tier,
                default_package=True,
            )

        publication_rejection_diagnostics = None
        result = package_polish.assess_package_polish(
            tier, args.source_root, cancelled=args.cancelled
        )
        if refresh is not None:
            result = package_polish.bind_manifest_refresh_report(
                result, args.source_root, refresh
            )
        validation = (
            package_polish_schema_validation.validate_package_polish_report(
                result
            )
        )
        try:
            raw = _json_report_wire_bytes(result)
        except (TypeError, ValueError, UnicodeError, RecursionError,
                OverflowError):
            raw = None
        compact_encoding_available = True
        if raw is not None and len(raw) > package_polish.MAX_REPORT_BYTES:
            # Whitespace must not erase a complete assessment that fits the same
            # bound compactly. Retain every field and its existing report digest;
            # keep escaped text portable to terminals with limited encodings.
            try:
                raw = (
                    json.dumps(
                        result, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False,
                    ) + "\n"
                ).encode("utf-8")
            except (TypeError, ValueError, UnicodeError, RecursionError,
                    OverflowError):
                # A lone surrogate can be escaped by strict JSON while still
                # being impossible to emit through the preferred UTF-8 compact
                # projection. Retry compactly with deterministic ASCII escapes
                # so an oversized normal report still reaches the fail-closed
                # capacity path instead of bypassing its configured envelope.
                try:
                    raw = (
                        json.dumps(
                            result, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False,
                        ) + "\n"
                    ).encode("utf-8")
                except (TypeError, ValueError, UnicodeError, RecursionError,
                        OverflowError):
                    compact_encoding_available = False
        if (
            isinstance(result, dict)
            and isinstance(result.get("schema_version"), str)
            and result.get("schema_version") in {
                package_polish.REPORT_SCHEMA,
                package_polish.EXTENSIBLE_REPORT_SCHEMA,
            }
            and validation.valid
            and compact_encoding_available
            and raw is not None
            and len(raw) > package_polish.MAX_REPORT_BYTES
        ):
            # Do not discard an already completed assessment by executing a
            # cancelled replacement. The capacity receipt is derived from the
            # evaluated report and retains its denominator and every non-PASS
            # action. Compact UTF-8 avoids ASCII-escape expansion.
            result = package_polish._capacity_receipt(
                result, source_root=args.source_root,
            )
            try:
                raw = (
                    json.dumps(
                        result, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False,
                    ) + "\n"
                ).encode("utf-8")
            except (TypeError, ValueError, UnicodeError, RecursionError,
                    OverflowError):
                raw = None
            validation = (
                package_polish_schema_validation
                .validate_package_polish_report(result)
            )
        # Publication is a separate gate from assessment and capacity
        # projection.  Validate the exact final artifact kind here so neither a
        # normal nor a compact capacity report can pair schema-invalid PASS
        # JSON with a successful command exit.
        if raw is None or not validation.valid:
            # The strict rejection receipt intentionally cannot publish fields
            # from a schema-invalid producer. Human mode still needs a bounded,
            # explicitly unvalidated projection so an already-known exact
            # object/obligation failure is not replaced by only a generic code.
            publication_rejection_diagnostics = (
                _publication_rejection_diagnostic_projection(result, tier)
            )
            result = _package_polish_schema_rejection_report(
                result,
                tier,
                raw,
                schema_supported=validation.schema_supported,
                validation_errors=validation.errors,
                selected_schema_digest=validation.selected_schema_digest,
                validator_mechanism_digest=(
                    validation.validator_mechanism_digest
                ),
                validation_errors_at_limit=validation.errors_at_limit,
            )
            package_polish_schema_validation.validate_publication_rejection_receipt(
                result
            )
            # Validation is deliberately attempted before publication. If the
            # validation mechanism itself reports non-PASS, retain this already
            # non-PASS receipt rather than ever restoring the rejected source
            # report; the receipt validator exposes that failure to direct tests.
            raw = _json_report_wire_bytes(result)
        if args.json:
            # Emit the bytes we bounded: text-mode newline translation can make
            # redirected output larger on Windows. Text-only captures still work.
            output = getattr(sys.stdout, "buffer", None)
            if output is None:
                sys.stdout.write(raw.decode("utf-8"))
            else:
                sys.stdout.flush()
                output.write(raw)
        else:
            if publication_rejection_diagnostics is not None:
                print(
                    "[UNKNOWN] package polish publication rejected; bounded "
                    "source diagnostics below are unvalidated and cannot "
                    "establish conformance"
                )
                _print_package_polish_summary(
                    publication_rejection_diagnostics, tier,
                )
                print(
                    "[UNKNOWN] publication rejection receipt: "
                    + ",".join(result.get("blockers", []))
                )
            else:
                _print_package_polish_summary(result, tier)
        return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
    if tier == 3:
        from verifier.runtime import self_polish_statics

        result = assess_self_polish_tier(3, source_root=args.source_root, cancelled=args.cancelled)
        raw = _json_report_wire_bytes(result)
        if len(raw) > self_polish_statics.MAX_REPORT_BYTES:
            bounded_status = "FAIL" if result["status"] == "FAIL" else "UNKNOWN"
            result = {
                "schema_version": self_polish_statics.REPORT_SCHEMA,
                "tier": 3, "tier_name": "STATICS", "status": bounded_status,
                "selected_tier_status": bounded_status, "selected_depth": 0,
                "blockers": ["STATICS_REPORT_CAPACITY_EXHAUSTED"],
                "whole_tier_conformance": "NOT_ESTABLISHED",
                "full_application_status": "UNKNOWN", "polished": False,
                "release_authorized": False, "deployment_authorized": False,
            }
            result["report_digest"] = core_obligation_union.value_digest(result)
            raw = _json_report_wire_bytes(result)
        if args.json:
            print(raw.decode("utf-8"), end="")
        else:
            print(f"[{result['status']}] self-polish tier 3: STATICS; polished=false")
            for blocker in result["blockers"]:
                print("- " + blocker)
        return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
    if tier == 0:
        from verifier.runtime import tier_zero

        try:
            root = Path(args.source_root).resolve(strict=True)
            selected_manifest = tier_zero_manifest_path
            result = tier_zero.assess_tier_zero(
                root, manifest_path=selected_manifest,
            )
        except (OSError, ImportError, MemoryError, RecursionError,
                OverflowError) as exc:
            body = {
                "schema_version": tier_zero.REPORT_SCHEMA,
                "status": "UNKNOWN",
                "obligation_count": 9,
                "obligations": [],
                "blockers": ["TIER_ZERO_ASSESSMENT_UNAVAILABLE"],
                "error_type": type(exc).__name__,
                "tier_1_plus_status": "NOT_ESTABLISHED",
                "polished": False,
                "release_authorized": False,
                "deployment_authorized": False,
            }
            result = {
                **body, "report_digest": core_obligation_union.value_digest(body)
            }
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError,
                UnicodeError) as exc:
            body = {
                "schema_version": tier_zero.REPORT_SCHEMA,
                "status": "FAIL",
                "obligation_count": 9,
                "obligations": [],
                "blockers": [str(exc) or "TIER_ZERO_CONTRACT_VIOLATION"],
                "tier_1_plus_status": "NOT_ESTABLISHED",
                "polished": False,
                "release_authorized": False,
                "deployment_authorized": False,
            }
            result = {
                **body, "report_digest": core_obligation_union.value_digest(body)
            }
        try:
            from verifier.runtime.manifest_gate import admission_findings
            result["findings"] = admission_findings(result)
        except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
            if result["status"] != "FAIL":
                result["status"] = "UNKNOWN"
            result["findings"] = []
            result["blockers"] = sorted(set(result["blockers"] + ["TIER_ZERO_FINDINGS_UNAVAILABLE"]))
        try:
            result.pop("report_digest", None)
            result["report_digest"] = core_obligation_union.value_digest(result)
            raw = (
                json.dumps(
                    result,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ) + "\n"
            ).encode("utf-8")
        except (MemoryError, OverflowError, RecursionError):
            raw = b""
        if len(raw) > tier_zero.MAX_REPORT_BYTES or not raw:
            observed_status = result.get("status")
            body = {
                "schema_version": tier_zero.CAPACITY_REPORT_SCHEMA,
                "source_report_schema": result.get("schema_version"),
                "status": "FAIL" if observed_status == "FAIL" else "UNKNOWN",
                "obligation_count": 9,
                "obligations": [],
                "blockers": ["TIER_ZERO_REPORT_CAPACITY_EXHAUSTED"],
                "source_report_digest": result.get("report_digest"),
                "tier_1_plus_status": "NOT_ESTABLISHED",
                "polished": False,
                "release_authorized": False,
                "deployment_authorized": False,
            }
            result = {
                **body,
                "report_digest": core_obligation_union.value_digest(body),
            }
            raw = (
                json.dumps(
                    result,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ) + "\n"
            ).encode("utf-8")
        if args.json:
            output = getattr(sys.stdout, "buffer", None)
            if output is None:
                sys.stdout.write(raw.decode("utf-8"))
            else:
                sys.stdout.flush()
                output.write(raw)
        else:
            _print_tier_zero_summary(result)
        return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
    if tier == 1 and not args.package_graph and any(
            value is not None for value in (
                args.package_obligation_cards,
                args.package_obligation_manifest,
                args.package_obligation_manifest_digest,
                args.package_obligation_reasons,
                args.package_obligation_reasons_digest,
                args.package_owner_policy,
                args.package_owner_policy_digest,
                args.package_owner_decisions,
                args.package_owner_decisions_digest,
            )):
        parser.error(
            "package obligation and owner-decision inputs require "
            "--package-graph"
        )
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
            if args.package_graph:
                from verifier.runtime import package_self_polish

                coordinate = result.get("source_coordinate")
                if type(coordinate) is not dict:
                    result = package_self_polish.unavailable_package_report(
                        numeric_tier1_report=result,
                        prior_blockers=_package_numeric_blockers(result),
                    )
                else:
                    numeric_result = result
                    try:
                        result = package_self_polish.assess_package_self_polish(
                            coordinate,
                            self_verifier_tier1_report=numeric_result,
                            source_root=args.source_root,
                            candidate_obligation_cards_root=(
                                args.package_obligation_cards
                            ),
                            candidate_obligation_manifest_path=(
                                args.package_obligation_manifest
                            ),
                            expected_candidate_obligation_manifest_digest=(
                                args.package_obligation_manifest_digest
                            ),
                            candidate_obligation_reason_ledger_path=(
                                args.package_obligation_reasons
                            ),
                            expected_candidate_obligation_reason_ledger_digest=(
                                args.package_obligation_reasons_digest
                            ),
                            owner_decision_policy_path=(
                                args.package_owner_policy
                            ),
                            expected_owner_decision_policy_digest=(
                                args.package_owner_policy_digest
                            ),
                            owner_decision_path=(
                                args.package_owner_decisions
                            ),
                            expected_owner_decision_digest=(
                                args.package_owner_decisions_digest
                            ),
                        )
                    except (OSError, ImportError, MemoryError,
                            RecursionError, OverflowError):
                        result = (
                            package_self_polish.package_assessment_unavailable_report(
                                numeric_tier1_report=numeric_result,
                                prior_blockers=_package_numeric_blockers(
                                    numeric_result
                                ),
                            )
                        )
                    except (AttributeError, KeyError, RuntimeError, TypeError,
                            ValueError, UnicodeError):
                        result = (
                            package_self_polish.package_assessment_contradiction_report(
                                numeric_tier1_report=numeric_result,
                                source_coordinate=coordinate,
                                blocker="PACKAGE_SELF_POLISH_CONTRACT_VIOLATION",
                                prior_blockers=_package_numeric_blockers(
                                    numeric_result
                                ),
                            )
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
    except (OSError, _ContractError, RuntimeError, ValueError, TypeError,
            UnicodeError, RecursionError, OverflowError):
        numeric_failure = _finish({
            **_base_report(tier, {}),
            "status": "FAIL",
            "selected_tier_status": "FAIL",
            "blockers": ["SELF_POLISH_TIER_CLI_INPUT_REJECTED"],
        })
        if tier == 1 and args.package_graph:
            from verifier.runtime import package_self_polish
            result = package_self_polish.package_assessment_unavailable_report(
                numeric_tier1_report=numeric_failure,
                prior_blockers=_package_numeric_blockers(numeric_failure),
            )
        else:
            result = numeric_failure
    if args.json:
        if tier == 1 and not args.package_graph:
            result = _guard_tier1_report_wire_capacity(result)
        elif (tier == 1 and args.package_graph
                and len(_json_report_wire_bytes(result))
                    > package_self_polish.MAX_PACKAGE_REPORT_BYTES):
            result = (
                package_self_polish.package_report_capacity_exhausted_report(
                    result
                )
            )
        print(_json_report_wire_bytes(result).decode("utf-8"), end="")
    else:
        if tier == 1 and args.package_graph:
            print(f"[{result['status']}] VSTD package GRAPH self-polish; "
                  "polished=false")
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
