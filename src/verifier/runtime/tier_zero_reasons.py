"""Source-derived two-layer reasons for the installed Tier-zero denominator.

The provider emits one standard reason and one repository-realization annotation
for every installed route and kind-tier slot.  The annotations bind current
mechanism bytes but deliberately leave semantic truth and normative closure
``UNKNOWN``; Tier zero checks completeness and identity, not route satisfaction.
The installed route registry belongs to Verifier Standard (VSTD).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from verifier.core.namespace import ObjectKind
from verifier.domains import inventory as domain_inventory
from verifier.runtime import (
    core_obligation_union, core_tier_progression,
    package_obligation_candidate,
)


PROVIDER_SCHEMA = "verifier-tier-zero-reason-provider-1"
LEDGER_SCHEMA = package_obligation_candidate.REASON_LEDGER_SCHEMA


def _route_rows(inventory: dict[str, Any], root: Path) -> dict[str, Any]:
    routes = package_obligation_candidate._installed_routes(inventory)
    slots = {(slot.object_kind.value, slot.tier.value): slot
             for slot in domain_inventory.build_234_inventory()}
    rows: dict[str, Any] = {}
    for (kind, coordinate), route in sorted(routes.items()):
        slot = slots[(kind, route["tier"])]
        binding = domain_inventory.MECHANIZED_12_POINT_BINDINGS[coordinate]
        mechanism = package_obligation_candidate._checking_mechanism_binding(
            coordinate, source_root=root,
        )
        semantic_digest = (
            package_obligation_candidate._obligation_semantic_identity(
                coordinate, route, source_root=root,
            )
        )
        exact_claim = binding["exact_claim"]
        reason = (
            f"{coordinate} is retained because it makes the {kind} "
            f"{slot.tier.name.lower()} question refutable within the installed "
            f"scope {route['scope']}: {exact_claim} Without this route, that "
            "bounded proposition could be asserted without its registered "
            "certificate replay and falsifiers."
        )
        assumptions = binding.get("assumptions_and_exclusions")
        residuals = [
            "Whole-slot and normative full-family closure remain NOT_ESTABLISHED.",
            "Application authority and the truth of any submitted instance remain independently required.",
        ]
        rows[coordinate] = {
            "reason": reason,
            "reason_source": (
                "verifier.domains.inventory.MECHANIZED_12_POINT_BINDINGS["
                f"{coordinate}] plus the installed {kind}-{route['tier']} slot rationale"
            ),
            "disposition": "INFERRED",
            "author": "Verifier source-derived Tier-zero reason provider",
            "bound_digest": semantic_digest,
            "proposed_reason": (
                "Source-derived and mechanically bound; normative adoption is not implied."
            ),
            "repository_realization": {
                "class": "DIRECT",
                "explanation": (
                    f"{mechanism['checking_mechanism']} is the installed rechecker "
                    f"for {coordinate}; its current source bytes are bound and it "
                    f"replays the registered {route['certificate_schema_version']} "
                    f"proposition under scope {route['scope']}."
                ),
                "adaptation_necessity": None,
                "obligation_semantic_digest": semantic_digest,
                "discovered_surface_ids": [
                    f"installed-route:{kind}:{coordinate}",
                    "installed-mechanism:" + mechanism["checking_mechanism"],
                    "candidate-source-file:" + mechanism["source_path"],
                ],
                "mechanism_bindings": [mechanism],
                "evidence_requirements": [
                    f"A schema-valid {route['certificate_schema_version']} instance.",
                    f"A proposition binding equal to {route['proposition_digest']}.",
                    binding["reproduction_instructions"],
                ],
                "preserved_semantics": [
                    exact_claim,
                    f"Installed finite scope: {route['scope']}.",
                    f"Registered semantic version: {route['semantic_version']}.",
                ],
                "unpreserved_semantics": (
                    [assumptions] if isinstance(assumptions, str) and assumptions else []
                ),
                "residual_obligations": residuals,
                "falsifiers": [
                    binding["invalidating_dependencies"],
                    "The selected checking-mechanism path, symbol, or source digest differs.",
                    "The route disappears from or changes within the installed 408-route denominator.",
                ],
                "decision_authority": (
                    "The installed VSTD route registry selects this checking route. "
                    "It does not grant owner adoption, application authority, or a PASS instance."
                ),
            },
        }
    return rows


def _slot_rows(inventory: dict[str, Any]) -> dict[str, Any]:
    cells = {
        (row["object_kind"], row["tier"]): row
        for row in inventory["family_cells"]
    }
    rows: dict[str, Any] = {}
    for slot in domain_inventory.build_234_inventory():
        coordinate = f"{slot.object_kind.value}-{slot.tier.value}"
        cell = cells[(slot.object_kind.value, slot.tier.value)]
        route_ids = [
            f"installed-route:{slot.object_kind.value}:{route['coordinate']}"
            for route in cell["registered_route_memberships"]
        ]
        semantic_digest = package_obligation_candidate._slot_record_semantic_identity(slot)
        rows[coordinate] = {
            "reason": slot.rationale,
            "reason_source": (
                "verifier.domains.inventory._SLOT_RATIONALES and "
                "verifier.domains.inventory.GOVERNING_QUESTIONS"
            ),
            "disposition": "INFERRED",
            "author": "Verifier source-derived Tier-zero reason provider",
            "bound_digest": semantic_digest,
            "proposed_reason": (
                "Installed slot planning rationale; it is not a numbered-route "
                "proof or normative full-family closure claim."
            ),
            "repository_realization": {
                "class": "CONDITIONAL",
                "explanation": (
                    f"The installed {coordinate} cell preserves this abstract "
                    f"kind-tier question through exactly {len(route_ids)} registered "
                    "finite route membership(s); the slot itself remains unclosed."
                ),
                "adaptation_necessity": (
                    "A kind-tier slot is an abstract denominator and can contain "
                    "multiple independently replayable propositions, so the repository "
                    "represents it by an exact finite route set rather than one synthetic checker."
                ),
                "obligation_semantic_digest": semantic_digest,
                "discovered_surface_ids": [
                    f"installed-cell:{slot.object_kind.value}:{slot.tier.value}",
                    *route_ids,
                ],
                "mechanism_bindings": [],
                "evidence_requirements": [
                    "The installed cell identity, governing question, applicability, and rationale are unchanged.",
                    "Every registered route membership is present with a current reason and realization annotation.",
                ],
                "preserved_semantics": [
                    slot.governing_question,
                    slot.rationale,
                    "Exact current registered-route membership denominator.",
                ],
                "unpreserved_semantics": [
                    "The finite installed route set does not establish normative full-family closure."
                ],
                "residual_obligations": [
                    "Objective inventory closure remains NOT_ESTABLISHED.",
                    "Whole-slot conformance must be established by its numbered-tier gate, not Tier zero.",
                ],
                "falsifiers": [
                    "The installed cell, governing question, applicability, rationale, or route membership set changes.",
                    "Any referenced route lacks its own source-bound reason and realization annotation.",
                ],
                "decision_authority": (
                    "The installed VSTD inventory defines this current slot denominator. "
                    "Normative completeness and application authority remain NOT_ESTABLISHED."
                ),
            },
        }
    return rows


def installed_reason_ledger(source_root: str | Path) -> dict[str, Any]:
    """Derive the exact 408-route and 234-slot two-layer reason ledger."""
    root = Path(source_root).resolve(strict=True)
    inventory = core_tier_progression.installed_core_route_inventory()
    objectives = _route_rows(inventory, root)
    slots = _slot_rows(inventory)
    if len(objectives) != 408 or len(slots) != 234:
        raise RuntimeError("TIER_ZERO_REASON_DENOMINATOR_DIFFERS")
    return {
        "schema_version": LEDGER_SCHEMA,
        "authored": "Source-derived from the selected Verifier repository bytes.",
        "rule": (
            "Each installed route and kind-tier slot has a standard reason and "
            "a repository realization annotation. Binding PASS does not promote "
            "the annotation's semantic claim, route status, slot closure, owner "
            "adoption, application authority, polish, or release authority."
        ),
        "objectives": objectives,
        "slots": slots,
    }


def provider_receipt(source_root: str | Path) -> dict[str, Any]:
    ledger = installed_reason_ledger(source_root)
    provider_path = Path(__file__)
    body = {
        "schema_version": PROVIDER_SCHEMA,
        "status": "PASS",
        "objective_count": len(ledger["objectives"]),
        "slot_count": len(ledger["slots"]),
        "ledger_digest": core_obligation_union.value_digest(ledger),
        "provider_source_digest": core_obligation_union.bytes_digest(
            provider_path.read_bytes()
        ),
        "claim_status": "UNKNOWN",
        "claim_boundary": (
            "PASS establishes complete, source-derived reason and realization "
            "bindings for the installed denominator. Every realization claim and "
            "all route, slot, polish, release, and deployment claims remain UNKNOWN."
        ),
    }
    return {**body, "receipt_digest": core_obligation_union.value_digest(body)}


__all__ = [
    "LEDGER_SCHEMA", "PROVIDER_SCHEMA", "installed_reason_ledger",
    "provider_receipt",
]
