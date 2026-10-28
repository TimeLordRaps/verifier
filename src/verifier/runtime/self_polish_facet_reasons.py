"""Installed, source-bound reasons for Verifier's Tier-1 reason denominators.

The v3 ledger keeps 130 five-facet choices separate from 18 domain-route
necessity choices. Their reasoned route union covers exactly the current 45
registered Tier-1 routes and 26 slots. It does not establish route certificate
outcomes, polished status, release authority, or normative completeness outside
the installed source-bound denominators.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from verifier.core.certificate import canonical_bytes
from verifier.core import namespace as namespace_module
from verifier.core.namespace import ObjectKind
from verifier.domains import inventory as slot_inventory_module
from verifier.domains.contracts import (
    application_requirements,
    current_object_routes,
    facet_coverage,
    object_facets,
    typed_facets,
)
from verifier.runtime import core_tier_progression


LEDGER_SCHEMA = "verifier-self-polish-facet-reason-ledger-3"
ASSESSMENT_SCHEMA = "verifier-self-polish-facet-reason-assessment-3"
MECHANISM_SCHEMA = "verifier-self-polish-facet-reason-mechanism-3"
TIER = 1
FACETS = (
    "identifier",
    "admitted_kind",
    "canonical_payload",
    "named_ordered_operand_map",
    "declared_typed_composition",
)
CHOICES = frozenset({"NECESSARY", "NOT_NECESSARY", "UNKNOWN"})
PRIMITIVE_KINDS = frozenset(
    "HUMAN ROLE HARDWARE OBJECT SPACE TIME ENV DATA VERIFIER ARCH HARNESS TOKEN".split()
)
_AUTHORING_SOURCE = "runtime/self_polish_facet_reasons.py"
_CLAIM_BOUNDARY = (
    "PASS establishes that every installed Tier-1 semantic facet choice and every "
    "separate installed Tier-1 domain-route choice has an exact source-authored "
    "reason. The 130 facet reasons project onto 52 structural memberships and 27 "
    "direct generic/typed routes; the 18 domain-route reasons cover only their exact "
    "registered domain propositions. Their union reasons all 45 current Tier-1 "
    "routes and all 26 Tier-1 slots. This does not establish native certificate "
    "outcomes, exhaustive normative meaning, polished status, release authority, "
    "or deployment."
)
_SOURCE_PATHS = (
    "core/namespace.py",
    "domains/inventory.py",
    "domains/contracts/application_requirements.py",
    "domains/contracts/agent_checks.py",
    "domains/contracts/bench_checks.py",
    "domains/contracts/bot_checks.py",
    "domains/contracts/current_object_routes.py",
    "domains/contracts/data_checks.py",
    "domains/contracts/env_checks.py",
    "domains/contracts/env_configuration_surface.py",
    "domains/contracts/env_executable.py",
    "domains/contracts/facet_coverage.py",
    "domains/contracts/hardware_inventory.py",
    "domains/contracts/hardware_topology.py",
    "domains/contracts/harness_checks.py",
    "domains/contracts/model_checks.py",
    "domains/contracts/object_facets.py",
    "domains/contracts/train_checks.py",
    "domains/contracts/train_data_bridge.py",
    "domains/contracts/typed_facets.py",
    "runtime/core_tier_progression.py",
    _AUTHORING_SOURCE,
    "standard/CURRENT_OBJECT_FACETS.md",
    "standard/CURRENT_TYPED_FACETS.md",
    "standard/FACET_OBLIGATION_DERIVATION.md",
    "standard/NAMESPACE_OBJECTS.md",
    "standard/SELF_POLISH_FACET_REASONS.md",
)
_DOMAIN_ROUTE_REASON_SPECS: dict[str, dict[str, str]] = {
    "AGENT-1.8": {
        "object_kind": "AGENT",
        "category": "agent_harness_binding_surface",
        "checker_source": "domains/contracts/agent_checks.py",
        "reason": (
            "Tier 1 needs AGENT-1.8 because a structurally valid AGENT can name a "
            "HARNESS operand without establishing that the selected retained harness "
            "certificate reproduces or that every required channel lies inside its "
            "instrumented observation surface."
        ),
        "counterfactual": (
            "Without AGENT-1.8, an AGENT could satisfy namespace composition while its "
            "decisions refer to uninstrumented or unreplayed harness channels."
        ),
    },
    "BENCH-1.2": {
        "object_kind": "BENCH",
        "category": "bench_problem_inventory",
        "checker_source": "domains/contracts/bench_checks.py",
        "reason": (
            "Tier 1 needs BENCH-1.2 because a structurally valid BENCH can bind DATA and "
            "VERIFIER operands without enumerating a nonempty finite problem set, exact "
            "specifications, one retained answer per problem, and positive weights."
        ),
        "counterfactual": (
            "Without BENCH-1.2, a BENCH could omit problems or substitute answers and "
            "weights while retaining a valid namespace shape."
        ),
    },
    "BENCH-1.4": {
        "object_kind": "BENCH",
        "category": "bench_oracle_execution",
        "checker_source": "domains/contracts/bench_checks.py",
        "reason": (
            "Tier 1 needs BENCH-1.4 because a structurally valid BENCH does not prove "
            "that each named built-in oracle executed or that the exact weighted solved "
            "fraction was recomputed against the selected minimum score."
        ),
        "counterfactual": (
            "Without BENCH-1.4, a BENCH could accept caller-supplied solved flags or a "
            "substituted score without executing the registered oracle."
        ),
    },
    "BOT-1.6": {
        "object_kind": "BOT",
        "category": "bot_child_binding",
        "checker_source": "domains/contracts/bot_checks.py",
        "reason": (
            "Tier 1 needs BOT-1.6 because a structurally valid BOT can name AGENT, SIM, "
            "and ENV operands without replaying the exact selected child certificates "
            "and proving that each child binds the same retained namespace objects."
        ),
        "counterfactual": (
            "Without BOT-1.6, a BOT could combine validly typed but substituted AGENT, "
            "SIM, or ENV children from different selections."
        ),
    },
    "DATA-1.2": {
        "object_kind": "DATA",
        "category": "selected_retained_data_inventory",
        "checker_source": "domains/contracts/data_checks.py",
        "reason": (
            "Tier 1 needs DATA-1.2 because a structurally valid DATA record does not "
            "establish that every selected retained shard and record was enumerated, "
            "rehashed, ordered, counted, and committed into the selected digest-tree root."
        ),
        "counterfactual": (
            "Without DATA-1.2, a DATA object could omit or substitute shard and record "
            "bytes while preserving its generic and typed namespace structure."
        ),
    },
    "DATA-1.4": {
        "object_kind": "DATA",
        "category": "data_record_schema",
        "checker_source": "domains/contracts/data_checks.py",
        "reason": (
            "Tier 1 needs DATA-1.4 because a structurally valid DATA record does not bind "
            "the exact shared or per-shard field names and supported plain value types "
            "against every retained record in the selected inventory."
        ),
        "counterfactual": (
            "Without DATA-1.4, retained records could change fields or value types while "
            "their enclosing DATA object remains structurally valid."
        ),
    },
    "ENV-1.2": {
        "object_kind": "ENV",
        "category": "env_software_inventory_closure",
        "checker_source": "domains/contracts/env_checks.py",
        "reason": (
            "Tier 1 needs ENV-1.2 because a structurally valid ENV does not establish a "
            "nonempty closed retained software inventory in which every file is present, "
            "rehashes to its selected byte commitment, and has no retained extras."
        ),
        "counterfactual": (
            "Without ENV-1.2, an ENV could omit, add, or substitute executable software "
            "bytes while preserving its namespace composition."
        ),
    },
    "ENV-1.3": {
        "object_kind": "ENV",
        "category": "env_entrypoint_interpreter_binding",
        "checker_source": "domains/contracts/env_executable.py",
        "reason": (
            "Tier 1 needs ENV-1.3 because a structurally valid ENV does not bind the exact "
            "entrypoint and interpreter logical paths, selected version labels, byte "
            "commitments, and replayed ENV-1.2 inventory to one execution coordinate."
        ),
        "counterfactual": (
            "Without ENV-1.3, an ENV could retain valid software bytes yet execute a "
            "different entrypoint, interpreter, or version than the selected coordinate."
        ),
    },
    "ENV-1.4": {
        "object_kind": "ENV",
        "category": "env_required_configuration_surface",
        "checker_source": "domains/contracts/env_configuration_surface.py",
        "reason": (
            "Tier 1 needs ENV-1.4 because a structurally valid ENV does not enumerate the "
            "complete selected required configuration names and their exact admitted value "
            "domains under the registered configuration-surface proposition."
        ),
        "counterfactual": (
            "Without ENV-1.4, an ENV could leave a required variable undeclared or widen "
            "its admitted values while retaining a valid namespace record."
        ),
    },
    "ENV-1.5": {
        "object_kind": "ENV",
        "category": "env_retained_configuration",
        "checker_source": "domains/contracts/env_checks.py",
        "reason": (
            "Tier 1 needs ENV-1.5 because a structurally valid ENV does not show that every "
            "retained configuration name and value equals the complete selected nonempty "
            "configuration together with the retained software inventory."
        ),
        "counterfactual": (
            "Without ENV-1.5, retained execution configuration could omit or substitute a "
            "selected name or value even though the ENV remains structurally valid."
        ),
    },
    "HARDWARE-1.2": {
        "object_kind": "HARDWARE",
        "category": "hardware_containment_topology",
        "checker_source": "domains/contracts/hardware_topology.py",
        "reason": (
            "Tier 1 needs HARDWARE-1.2 because a structurally valid HARDWARE record does "
            "not establish that every retained containment edge resolves within the bound "
            "inventory or that the finite declared topology is acyclic."
        ),
        "counterfactual": (
            "Without HARDWARE-1.2, retained hardware could contain unresolved endpoints or "
            "a containment cycle while its namespace structure remains valid."
        ),
    },
    "HARDWARE-1.3": {
        "object_kind": "HARDWARE",
        "category": "hardware_device_inventory",
        "checker_source": "domains/contracts/hardware_inventory.py",
        "reason": (
            "Tier 1 needs HARDWARE-1.3 because a structurally valid HARDWARE record does "
            "not establish a consistent finite retained device inventory with exact device "
            "identities, typed capacities, declared clocks, and selected commitments."
        ),
        "counterfactual": (
            "Without HARDWARE-1.3, device records or their retained capacities and clocks "
            "could be missing or substituted behind a valid HARDWARE identifier."
        ),
    },
    "HARNESS-1.6": {
        "object_kind": "HARNESS",
        "category": "harness_observation_surface",
        "checker_source": "domains/contracts/harness_checks.py",
        "reason": (
            "Tier 1 needs HARNESS-1.6 because a structurally valid HARNESS does not prove "
            "that its declared observation channels partition exactly into instrumented "
            "channels and named gaps with at least one instrumented channel."
        ),
        "counterfactual": (
            "Without HARNESS-1.6, a HARNESS could silently treat an uninstrumented channel "
            "as observed or omit a known observation gap."
        ),
    },
    "MODEL-1.2": {
        "object_kind": "MODEL",
        "category": "model_dense_tensor_shape_contract",
        "checker_source": "domains/contracts/model_checks.py",
        "reason": (
            "Tier 1 needs MODEL-1.2 because a structurally valid MODEL does not establish "
            "that all retained dense tensor shapes are complete and compatible with the "
            "exact selected architecture and declared Python binary64 operations."
        ),
        "counterfactual": (
            "Without MODEL-1.2, incompatible layer dimensions or omitted tensors could "
            "remain hidden behind validly typed MODEL operands."
        ),
    },
    "MODEL-1.5": {
        "object_kind": "MODEL",
        "category": "model_artifact_dependency_binding",
        "checker_source": "domains/contracts/model_checks.py",
        "reason": (
            "Tier 1 needs MODEL-1.5 because a structurally valid MODEL does not rehash its "
            "selected architecture, weights, and dependency payloads or bind the weights "
            "to the final declared checkpoint of the selected TRAIN record."
        ),
        "counterfactual": (
            "Without MODEL-1.5, MODEL weights or dependency artifacts could be substituted "
            "or detached from the declared training checkpoint."
        ),
    },
    "TRAIN-1.2": {
        "object_kind": "TRAIN",
        "category": "train_configuration_contract",
        "checker_source": "domains/contracts/train_checks.py",
        "reason": (
            "Tier 1 needs TRAIN-1.2 because a structurally valid TRAIN does not admit and "
            "bind the exact optimizer, constant schedule, accumulation order, and ordered "
            "Python binary64 numerical contract used by the retained composition."
        ),
        "counterfactual": (
            "Without TRAIN-1.2, a TRAIN could change optimizer or numerical accumulation "
            "semantics while keeping the same valid operand structure."
        ),
    },
    "TRAIN-1.3": {
        "object_kind": "TRAIN",
        "category": "train_checkpoint_inventory_shape",
        "checker_source": "domains/contracts/train_checks.py",
        "reason": (
            "Tier 1 needs TRAIN-1.3 because a structurally valid TRAIN does not rehash "
            "every retained weight and optimizer-state record or check each dense tensor "
            "shape against the exact selected architecture."
        ),
        "counterfactual": (
            "Without TRAIN-1.3, a checkpoint could omit or substitute state or contain "
            "architecture-incompatible tensors while TRAIN composition remains valid."
        ),
    },
    "TRAIN-1.5": {
        "object_kind": "TRAIN",
        "category": "train_data_shard_batch_bridge",
        "checker_source": "domains/contracts/train_data_bridge.py",
        "reason": (
            "Tier 1 needs TRAIN-1.5 because a structurally valid TRAIN does not prove that "
            "each retained batch-view record bridges to exactly one record in the selected "
            "DATA shards under replayed TRAIN-4.1 and DATA-1.2 children."
        ),
        "counterfactual": (
            "Without TRAIN-1.5, training steps could consume batches that do not correspond "
            "to the selected retained DATA shards despite valid TRAIN operands."
        ),
    },
}
_CHOICE_FIELDS = {
    "choice_id",
    "object_kind",
    "tier",
    "facet",
    "choice",
    "reason",
    "reason_digest",
    "counterfactual_consequence",
    "provenance",
    "provenance_digest",
    "basis",
    "basis_digest",
    "source_binding_digest",
    "mapped_structural_identities",
    "mapped_route_identities",
    "route_mapping_rationales",
    "mapped_slot_identity",
    "choice_digest",
}
_DOMAIN_ROUTE_REASON_FIELDS = {
    "route_reason_id",
    "object_kind",
    "tier",
    "coordinate",
    "category",
    "choice",
    "reason",
    "reason_digest",
    "counterfactual_consequence",
    "provenance",
    "provenance_digest",
    "basis",
    "basis_digest",
    "source_binding_digest",
    "mapped_route_identity",
    "route_reason_digest",
}
_LEDGER_FIELDS = {
    "schema_version",
    "mechanism_digest",
    "source_bindings",
    "source_binding_digest",
    "semantic_facets",
    "object_kind_count",
    "tier",
    "facet_choice_count",
    "choices",
    "choices_digest",
    "domain_route_reason_count",
    "domain_route_reasons",
    "domain_route_reasons_digest",
    "structural_projection_count",
    "structural_projection",
    "structural_projection_digest",
    "route_projection_count",
    "route_projection",
    "route_projection_digest",
    "mapped_route_projection_count",
    "mapped_route_projection",
    "mapped_route_projection_digest",
    "unmatched_route_projection_count",
    "unmatched_route_projection",
    "unmatched_route_projection_digest",
    "slot_projection_count",
    "slot_projection",
    "slot_projection_digest",
    "polished",
    "release_authorized",
    "claim_boundary",
    "ledger_digest",
}


def _value_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _byte_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def installed_source_bindings() -> dict[str, str]:
    """Return exact current source-byte commitments for this installed gate."""
    root = Path(__file__).parents[1]
    bindings: dict[str, str] = {}
    for relative in _SOURCE_PATHS:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("FACET_REASON_SOURCE_UNAVAILABLE")
        bindings[relative] = _byte_digest(path.read_bytes())
    return bindings


def mechanism_digest() -> str:
    """Bind the producer, its specification, and every denominator source."""
    bindings = installed_source_bindings()
    return _value_digest(
        {
            "schema_version": MECHANISM_SCHEMA,
            "source_bindings": bindings,
            "source_binding_digest": _value_digest(bindings),
        }
    )


def _installed_denominators() -> dict[str, Any]:
    kinds = sorted(kind.value for kind in ObjectKind)
    if len(kinds) != 26:
        raise RuntimeError("FACET_REASON_OBJECT_KIND_DENOMINATOR_DIFFERS")

    families = application_requirements.installed_families(kinds)
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
    if len(structural) != 52 or len(
        {(row["object_kind"], row["coordinate"]) for row in structural}
    ) != len(structural):
        raise RuntimeError("FACET_REASON_STRUCTURAL_DENOMINATOR_DIFFERS")

    route_inventory = core_tier_progression.installed_core_route_inventory()
    if route_inventory.get("status") != "PASS":
        raise RuntimeError("FACET_REASON_ROUTE_INVENTORY_NOT_PASS")
    routes = [
        {
            "object_kind": cell["object_kind"],
            "tier": TIER,
            "coordinate": member["coordinate"],
            "proposition_digest": member["proposition_digest"],
            "semantic_version": member["semantic_version"],
            "certificate_schema_version": member["certificate_schema_version"],
            "checking_mechanism": member["checking_mechanism"],
            "scope": member["scope"],
        }
        for cell in route_inventory["family_cells"]
        if cell["tier"] == TIER
        for member in cell["registered_route_memberships"]
    ]
    routes.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
    if len(routes) != 45 or len(
        {(row["object_kind"], row["coordinate"]) for row in routes}
    ) != len(routes):
        raise RuntimeError("FACET_REASON_ROUTE_DENOMINATOR_DIFFERS")

    slots = [
        {
            "object_kind": row["object_kind"],
            "tier": row["tier"],
            "coordinate": row["coordinate"],
            "applicability": row["applicability"],
            "rationale_status": row["rationale_status"],
        }
        for row in slot_inventory_module.slot_inventory()
        if row["tier"] == TIER
    ]
    slots.sort(key=lambda row: row["object_kind"])
    if (
        len(slots) != 26
        or {row["object_kind"] for row in slots} != set(kinds)
        or any(row["applicability"] != "REQUIRED" for row in slots)
        or any(
            row["rationale_status"]
            != "PLANNING_CONTEXT_NOT_NUMBERED_REQUIREMENTS"
            for row in slots
        )
    ):
        raise RuntimeError("FACET_REASON_SLOT_DENOMINATOR_DIFFERS")
    return {
        "object_kinds": kinds,
        "structural": structural,
        "routes": routes,
        "slots": slots,
    }


def _role_contract(kind: str, registration: Mapping[str, Any]) -> dict[str, Any]:
    all_kinds = sorted(item.value for item in ObjectKind)
    common_invariants = [
        "role names are bounded nonempty strings, unique, and lexically sorted",
        "target identifiers are bounded, ordered, and unique within each role",
        "every target resolves in the exact selected collection",
        "the composition dependency graph is acyclic",
        "the record has at most 4,096 total direct targets",
    ]
    if kind in PRIMITIVE_KINDS:
        text = (
            f"{kind} has an exact empty role set: minimum 0 and maximum 0 roles, "
            "minimum 0 and maximum 0 direct targets per record, with a 4,096 global "
            "implementation ceiling that is vacuous because any role is rejected."
        )
        return {
            "contract_kind": "PRIMITIVE_EXPLICIT_EMPTY",
            "role_name_mode": "EXACT",
            "role_count_min": 0,
            "role_count_max": 0,
            "total_target_count_min": 0,
            "total_target_count_max": 0,
            "roles": [],
            "dynamic_target_kinds": [],
            "invariants": common_invariants,
            "contract_text": text,
        }
    if kind == "GRAPH":
        text = (
            "GRAPH has the exact role 'members', with minimum 1 and maximum 4,096 "
            "direct targets and minimum 1 and maximum 4,096 total direct targets. "
            "The payload.element_kind is admitted explicitly; every expanded leaf "
            "must have that kind unless element_kind is OBJECT, which admits any of "
            f"the 26 kinds ({', '.join(all_kinds)}). A nested GRAPH must preserve "
            "the selected element_kind, and references must resolve without a cycle."
        )
        return {
            "contract_kind": "GRAPH_SELECTED_ELEMENT_KIND",
            "role_name_mode": "EXACT",
            "role_count_min": 1,
            "role_count_max": 1,
            "total_target_count_min": 1,
            "total_target_count_max": 4096,
            "roles": [
                {
                    "name": "members",
                    "minimum_direct_targets": 1,
                    "maximum_direct_targets": 4096,
                    "target_kinds": all_kinds,
                    "target_kind_rule": (
                        "expanded leaves equal payload.element_kind; OBJECT admits any kind"
                    ),
                }
            ],
            "dynamic_target_kinds": [],
            "invariants": [
                *common_invariants,
                "nested graphs preserve the selected non-OBJECT element kind",
                "every expanded leaf satisfies the selected element kind",
            ],
            "contract_text": text,
        }
    if kind == "HYPER":
        text = (
            "HYPER has caller-declared named roles: minimum 1 and maximum 4,096 "
            "distinct sorted role names. Every declared role has minimum 1 and "
            "maximum 4,096 direct targets, every target may be any admitted kind "
            f"({', '.join(all_kinds)}), and the record has minimum 1 and maximum "
            "4,096 total direct targets. Empty roles, duplicate targets, unresolved "
            "targets, and composition cycles are rejected."
        )
        return {
            "contract_kind": "HYPER_DECLARED_NONEMPTY_RELATIONS",
            "role_name_mode": "DECLARED_NONEMPTY",
            "role_count_min": 1,
            "role_count_max": 4096,
            "total_target_count_min": 1,
            "total_target_count_max": 4096,
            "roles": [],
            "dynamic_role_minimum_direct_targets": 1,
            "dynamic_role_maximum_direct_targets": 4096,
            "dynamic_target_kinds": all_kinds,
            "invariants": common_invariants,
            "contract_text": text,
        }
    installed_slots = getattr(namespace_module, "_SLOTS", None)
    if type(installed_slots) is not dict or kind not in installed_slots:
        raise RuntimeError("FACET_REASON_ROLE_CONTRACT_UNAVAILABLE")
    installed_roles = installed_slots[kind]
    roles: list[dict[str, Any]] = []
    role_text: list[str] = []
    for name, admitted in sorted(installed_roles.items()):
        target_kinds = all_kinds if "OBJECT" in admitted else sorted(admitted)
        roles.append(
            {
                "name": name,
                "minimum_direct_targets": 1,
                "maximum_direct_targets": 4096,
                "target_kinds": target_kinds,
                "target_kind_rule": (
                    "any admitted expanded leaf kind"
                    if "OBJECT" in admitted
                    else "expanded leaves belong to the enumerated kinds"
                ),
            }
        )
        role_text.append(
            f"'{name}' has minimum 1 and maximum 4,096 direct targets of kinds "
            + ", ".join(target_kinds)
        )
    extra_invariants: list[str] = []
    if kind == "ACTOR":
        extra_invariants = [
            "expanded representation leaves contain exactly one decision maker",
            "expanded root_human leaves contain exactly one HUMAN",
            "a represented HUMAN is identical to its root_human",
        ]
    text = (
        f"{kind} has exactly {len(roles)} named roles (minimum {len(roles)} and "
        f"maximum {len(roles)}): "
        + "; ".join(role_text)
        + f". The record has minimum {len(roles)} and maximum 4,096 total direct "
        "targets. Unknown or empty roles, duplicate targets, unresolved targets, "
        "wrong-kind expanded leaves, and composition cycles are rejected."
    )
    if kind == "ACTOR":
        text += (
            " After typed GRAPH expansion there is exactly one representation and "
            "exactly one root HUMAN; a HUMAN representation must be that same root."
        )
    if registration.get("coordinate") != typed_facets.coordinate(kind):
        raise RuntimeError("FACET_REASON_TYPED_REGISTRATION_DIFFERS")
    return {
        "contract_kind": "FIXED_NAMED_TYPED_ROLES",
        "role_name_mode": "EXACT",
        "role_count_min": len(roles),
        "role_count_max": len(roles),
        "total_target_count_min": len(roles),
        "total_target_count_max": 4096,
        "roles": roles,
        "dynamic_target_kinds": [],
        "invariants": [*common_invariants, *extra_invariants],
        "contract_text": text,
    }


def _source_coordinate_bindings(
    kind: str,
    facet: str,
    registration: Mapping[str, Any],
    bindings: Mapping[str, str],
) -> list[dict[str, Any]]:
    generic = {
        "authority_role": "generic_object",
        "coordinate": object_facets.COORDINATE,
        "proposition_digest": object_facets.PROPOSITION_DIGEST,
        "checker_source": "domains/contracts/object_facets.py",
        "checker_source_digest": bindings["domains/contracts/object_facets.py"],
        "specification_source": "standard/CURRENT_OBJECT_FACETS.md",
        "specification_source_digest": bindings[
            "standard/CURRENT_OBJECT_FACETS.md"
        ],
    }
    typed = {
        "authority_role": "typed_composition",
        "coordinate": registration["coordinate"],
        "proposition_digest": _value_digest(registration),
        "checker_source": "domains/contracts/typed_facets.py",
        "checker_source_digest": bindings["domains/contracts/typed_facets.py"],
        "specification_source": "standard/CURRENT_TYPED_FACETS.md",
        "specification_source_digest": bindings[
            "standard/CURRENT_TYPED_FACETS.md"
        ],
    }
    if registration["subject_kind"] != kind:
        raise RuntimeError("FACET_REASON_TYPED_REGISTRATION_DIFFERS")
    roles = {
        "identifier": (generic,),
        "canonical_payload": (generic,),
        "admitted_kind": (generic, typed),
        "named_ordered_operand_map": (generic, typed),
        "declared_typed_composition": (typed,),
    }
    return [dict(row) for row in roles[facet]]


def _reason(
    kind: str,
    facet: str,
    registration: Mapping[str, Any],
    role_contract: Mapping[str, Any],
) -> tuple[str, str]:
    coordinate = registration["coordinate"]
    if facet == "identifier":
        return (
            f"The {kind} identifier facet is NECESSARY because {coordinate} must bind one "
            "bounded exact subject identifier before a retained record, reference target, "
            "or replay result can be attributed to that specific object.",
            f"Without the {kind} identifier choice, two records could be indistinguishable "
            "to selection or an operand could resolve to a different subject.",
        )
    if facet == "admitted_kind":
        return (
            f"The {kind} admitted-kind facet is NECESSARY because the exact {kind} tag "
            f"selects the installed {coordinate} proposition and its kind-specific operand "
            "contract while OBJECT-1.1 separately commits the recoverable kind field. "
            + role_contract["contract_text"],
            f"Without the admitted {kind} tag, replay could apply another object's rule or "
            f"treat an unadmitted kind as if it had the {kind} contract.",
        )
    if facet == "canonical_payload":
        return (
            f"The {kind} canonical-payload facet is NECESSARY because exact reconstruction "
            "and record addressing bind the complete declared payload bytes for the selected "
            f"{coordinate} subject, even though payload truth and domain completeness remain excluded.",
            f"Without the exact {kind} payload bytes, a changed declaration could retain the "
            "same kind and identifier while escaping the record commitment.",
        )
    if facet == "named_ordered_operand_map":
        if kind in PRIMITIVE_KINDS:
            return (
                f"The {kind} named-ordered-operand-map facet is NECESSARY because this primitive "
                "has an explicit empty-role constraint: the checker must establish that the exact "
                "operand map has no roles, rather than infer not-applicable structure from omission. "
                + role_contract["contract_text"],
                f"Without checking the explicit empty-role constraint, a {kind} record could add "
                "undeclared relationships while still being treated as a primitive.",
            )
        return (
            f"The {kind} named-ordered-operand-map facet is NECESSARY because OBJECT-1.1 "
            f"commits the exact map while {coordinate} interprets its role names, target "
            "order, multiplicity, and target kinds. " + role_contract["contract_text"],
            f"Without the exact {kind} role map, required roles could disappear, targets could "
            "change or reorder, and incompatible kinds could enter the composition.",
        )
    if facet == "declared_typed_composition":
        if kind in PRIMITIVE_KINDS:
            return (
                f"The {kind} declared-typed-composition facet is NECESSARY even though {kind} is "
                "primitive: its installed composition rule is the explicit empty-role constraint, "
                "which must be checked as a positive condition and cannot be inferred as N/A. "
                + role_contract["contract_text"],
                f"Without replaying the {kind} empty-role composition rule, unexpected operands "
                "could be present while an omitted reason silently converted the obligation to N/A.",
            )
        return (
            f"The {kind} declared-typed-composition facet is NECESSARY because {coordinate} "
            "requires an exact finite collection, resolved references, acyclicity, and this "
            "explicit role contract rather than an untyped bag of objects. "
            + role_contract["contract_text"],
            f"Without the {kind} typed-composition choice, cycles, unresolved references, or "
            "wrong-kind role targets could satisfy the other four record facets.",
        )
    raise RuntimeError("FACET_REASON_UNKNOWN_FACET")


def _choice_rows(bindings: Mapping[str, str], source_binding_digest: str) -> list[dict[str, Any]]:
    denominators = _installed_denominators()
    structural_by_kind = {
        kind: [row for row in denominators["structural"] if row["object_kind"] == kind]
        for kind in denominators["object_kinds"]
    }
    routes_by_kind = {
        kind: [row for row in denominators["routes"] if row["object_kind"] == kind]
        for kind in denominators["object_kinds"]
    }
    generic_routes = [
        row
        for row in denominators["routes"]
        if row["object_kind"] == "OBJECT" and row["coordinate"] == "OBJECT-1.1"
    ]
    if len(generic_routes) != 1:
        raise RuntimeError("FACET_REASON_GENERIC_ROUTE_MAPPING_DIFFERS")
    typed_route_by_kind: dict[str, dict[str, Any]] = {}
    for kind in denominators["object_kinds"]:
        matches = [
            row
            for row in routes_by_kind[kind]
            if row["coordinate"] == typed_facets.coordinate(kind)
        ]
        if len(matches) != 1:
            raise RuntimeError("FACET_REASON_TYPED_ROUTE_MAPPING_DIFFERS")
        typed_route_by_kind[kind] = matches[0]
    slots_by_kind = {row["object_kind"]: row for row in denominators["slots"]}
    provenance = {
        "kind": "INSTALLED_SOURCE_AUTHORED",
        "authoring_source": _AUTHORING_SOURCE,
        "reason_model": "FIXED_KIND_AND_FACET_REASON_TABLE_1",
        "authority_boundary": "NATIVE_SOURCE_ONLY_NO_RELEASE_AUTHORITY",
    }
    provenance_digest = _value_digest(provenance)
    rows: list[dict[str, Any]] = []
    for kind in denominators["object_kinds"]:
        registration = typed_facets.registration(kind)
        role_contract = _role_contract(kind, registration)
        structural = structural_by_kind[kind]
        generic = [row for row in structural if row["coordinate"] == "OBJECT-1.1"]
        typed = [row for row in structural if row["coordinate"] != "OBJECT-1.1"]
        if len(generic) != 1 or len(typed) != 1:
            raise RuntimeError("FACET_REASON_STRUCTURAL_MAPPING_DIFFERS")
        for facet in FACETS:
            source_coordinates = _source_coordinate_bindings(
                kind, facet, registration, bindings
            )
            reason, consequence = _reason(
                kind, facet, registration, role_contract
            )
            mapped_structural = []
            if facet in {
                "identifier",
                "admitted_kind",
                "canonical_payload",
                "named_ordered_operand_map",
            }:
                mapped_structural.extend(generic)
            if facet == "declared_typed_composition":
                mapped_structural.extend(typed)
            mapped_structural.sort(key=lambda row: row["coordinate"])
            if facet in {
                "identifier",
                "admitted_kind",
                "canonical_payload",
                "named_ordered_operand_map",
            }:
                mapped_routes = [generic_routes[0]]
                mapping_kind = "GENERIC_OBJECT_FACET_TO_OBJECT_1_1"
            else:
                mapped_routes = [typed_route_by_kind[kind]]
                mapping_kind = "DECLARED_COMPOSITION_TO_TYPED_COORDINATE"
            route_rationales = []
            for route in mapped_routes:
                authority_role = (
                    "generic_object"
                    if route["coordinate"] == "OBJECT-1.1"
                    else "typed_composition"
                )
                authority_coordinate = next(
                    row
                    for row in source_coordinates
                    if row["authority_role"] == authority_role
                )
                authority_basis = {
                    "mapping_kind": mapping_kind,
                    "mapping_specification_source": (
                        "standard/FACET_OBLIGATION_DERIVATION.md"
                    ),
                    "mapping_specification_source_digest": bindings[
                        "standard/FACET_OBLIGATION_DERIVATION.md"
                    ],
                    "mapping_implementation_source": (
                        "domains/contracts/facet_coverage.py"
                    ),
                    "mapping_implementation_source_digest": bindings[
                        "domains/contracts/facet_coverage.py"
                    ],
                    "source_coordinate_binding_digest": _value_digest(
                        authority_coordinate
                    ),
                    "route_inventory_source": "runtime/core_tier_progression.py",
                    "route_inventory_source_digest": bindings[
                        "runtime/core_tier_progression.py"
                    ],
                }
                route_rationale = {
                    "route_identity_digest": _value_digest(route),
                    "mapping_rationale": (
                        f"The authored {kind}/{facet} mapping selects exact predicate "
                        f"{route['coordinate']} under {mapping_kind}; this is not "
                        "attribution to any other Tier-1 route."
                    ),
                    "authority_basis": authority_basis,
                    "authority_basis_digest": _value_digest(authority_basis),
                }
                route_rationale["mapping_digest"] = _value_digest(route_rationale)
                route_rationales.append(route_rationale)
            basis = {
                "semantic_version": registration["semantic_version"],
                "typed_coordinate": registration["coordinate"],
                "typed_registration_digest": _value_digest(registration),
                "typed_registration": registration,
                "role_contract": role_contract,
                "source_coordinate_bindings": source_coordinates,
                "namespace_source_digest": bindings["core/namespace.py"],
                "namespace_specification_digest": bindings[
                    "standard/NAMESPACE_OBJECTS.md"
                ],
                "facet_mapping_specification_digest": bindings[
                    "standard/FACET_OBLIGATION_DERIVATION.md"
                ],
                "facet_mapping_implementation_digest": bindings[
                    "domains/contracts/facet_coverage.py"
                ],
                "structural_mapping_digest": _value_digest(mapped_structural),
                "route_mapping_digest": _value_digest(mapped_routes),
                "route_rationale_digest": _value_digest(route_rationales),
                "slot_mapping_digest": _value_digest(slots_by_kind[kind]),
                "facet_definition": facet,
            }
            identity = {"object_kind": kind, "tier": TIER, "facet": facet}
            row: dict[str, Any] = {
                "choice_id": _value_digest(identity),
                **identity,
                "choice": "NECESSARY",
                "reason": reason,
                "reason_digest": _value_digest(reason),
                "counterfactual_consequence": consequence,
                "provenance": dict(provenance),
                "provenance_digest": provenance_digest,
                "basis": basis,
                "basis_digest": _value_digest(basis),
                "source_binding_digest": source_binding_digest,
                "mapped_structural_identities": mapped_structural,
                "mapped_route_identities": mapped_routes,
                "route_mapping_rationales": route_rationales,
                "mapped_slot_identity": slots_by_kind[kind],
            }
            row["choice_digest"] = _value_digest(row)
            rows.append(row)
    rows.sort(key=lambda row: (row["object_kind"], FACETS.index(row["facet"])))
    if len(rows) != 130 or len({row["choice_id"] for row in rows}) != 130:
        raise RuntimeError("FACET_REASON_CHOICE_DENOMINATOR_DIFFERS")
    return rows


def _selected_data_inventory_property() -> dict[str, Any]:
    rules = facet_coverage.installed_facet_derivation_rules()
    matches = [
        row
        for row in rules.get("rules", [])
        if row.get("property_id") == "selected_retained_data_inventory"
        and row.get("object_kind") == "DATA"
    ]
    if len(matches) != 1:
        raise RuntimeError("FACET_REASON_DATA_PROPERTY_REGISTRATION_DIFFERS")
    outputs = matches[0].get("outputs")
    if (
        type(outputs) is not list
        or len(outputs) != 1
        or outputs[0].get("objective") != "DATA-1.2"
    ):
        raise RuntimeError("FACET_REASON_DATA_PROPERTY_REGISTRATION_DIFFERS")
    return matches[0]


def _domain_route_reason_rows(
    bindings: Mapping[str, str],
    source_binding_digest: str,
    domain_routes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    route_by_coordinate = {row["coordinate"]: dict(row) for row in domain_routes}
    catalog = {
        row["objective"]: row
        for row in current_object_routes.current_object_route_catalog()
    }
    if set(route_by_coordinate) != set(_DOMAIN_ROUTE_REASON_SPECS):
        raise RuntimeError("FACET_REASON_DOMAIN_ROUTE_DENOMINATOR_DIFFERS")
    data_property = _selected_data_inventory_property()
    provenance_base = {
        "authoring_source": _AUTHORING_SOURCE,
        "authoring_source_digest": bindings[_AUTHORING_SOURCE],
        "reason_model": "INSTALLED_SOURCE_AUTHORED_DOMAIN_ROUTE_NECESSITY",
        "route_registry_source": "domains/contracts/current_object_routes.py",
        "route_registry_source_digest": bindings[
            "domains/contracts/current_object_routes.py"
        ],
    }
    rows: list[dict[str, Any]] = []
    for coordinate, spec in sorted(_DOMAIN_ROUTE_REASON_SPECS.items()):
        route = route_by_coordinate[coordinate]
        registration = catalog.get(coordinate)
        if type(registration) is not dict:
            raise RuntimeError("FACET_REASON_DOMAIN_ROUTE_REGISTRATION_DIFFERS")
        if (
            route["object_kind"] != spec["object_kind"]
            or route["tier"] != TIER
            or registration["objective"] != coordinate
            or registration["represented_kind_rule"] != spec["object_kind"]
            or registration["semantic_version"] != route["semantic_version"]
            or registration["certificate_schema_version"]
            != route["certificate_schema_version"]
            or registration["proposition_digest"] != route["proposition_digest"]
            or registration["scope"] != route["scope"]
        ):
            raise RuntimeError("FACET_REASON_DOMAIN_ROUTE_REGISTRATION_DIFFERS")
        checker_module = (
            "verifier."
            + spec["checker_source"].removesuffix(".py").replace("/", ".")
        )
        if not route["checking_mechanism"].startswith(checker_module + "."):
            raise RuntimeError("FACET_REASON_DOMAIN_ROUTE_CHECKER_DIFFERS")
        property_id: str | None = None
        property_registration: dict[str, Any] | None = None
        property_source: str | None = None
        property_source_digest: str | None = None
        if coordinate == "DATA-1.2":
            property_id = "selected_retained_data_inventory"
            property_registration = data_property
            property_source = "domains/contracts/facet_coverage.py"
            property_source_digest = bindings[property_source]
        basis = {
            "necessity_model": "TIER1_DOMAIN_SEMANTIC_ESCAPE_PREVENTION",
            "route_registration": registration,
            "route_registration_digest": _value_digest(registration),
            "route_registry_source": "domains/contracts/current_object_routes.py",
            "route_registry_source_digest": bindings[
                "domains/contracts/current_object_routes.py"
            ],
            "checker_source": spec["checker_source"],
            "checker_source_digest": bindings[spec["checker_source"]],
            "checking_mechanism": route["checking_mechanism"],
            "domain_property_id": property_id,
            "domain_property_registration": property_registration,
            "domain_property_registration_digest": (
                _value_digest(property_registration)
                if property_registration is not None
                else None
            ),
            "domain_property_source": property_source,
            "domain_property_source_digest": property_source_digest,
            "direct_five_facet_derivation": False,
        }
        provenance = {
            **provenance_base,
            "checker_source": spec["checker_source"],
            "checker_source_digest": bindings[spec["checker_source"]],
        }
        identity = {
            "object_kind": spec["object_kind"],
            "tier": TIER,
            "coordinate": coordinate,
            "category": spec["category"],
        }
        row: dict[str, Any] = {
            "route_reason_id": _value_digest(identity),
            **identity,
            "choice": "NECESSARY",
            "reason": spec["reason"],
            "reason_digest": _value_digest(spec["reason"]),
            "counterfactual_consequence": spec["counterfactual"],
            "provenance": provenance,
            "provenance_digest": _value_digest(provenance),
            "basis": basis,
            "basis_digest": _value_digest(basis),
            "source_binding_digest": source_binding_digest,
            "mapped_route_identity": route,
        }
        row["route_reason_digest"] = _value_digest(row)
        rows.append(row)
    if len(rows) != 18 or len({row["route_reason_id"] for row in rows}) != 18:
        raise RuntimeError("FACET_REASON_DOMAIN_ROUTE_DENOMINATOR_DIFFERS")
    return rows


def installed_facet_reason_ledger() -> dict[str, Any]:
    """Build the exact current native reason ledger from installed source bytes."""
    bindings = installed_source_bindings()
    source_binding_digest = _value_digest(bindings)
    denominators = _installed_denominators()
    choices = _choice_rows(bindings, source_binding_digest)
    mapped_route_by_digest = {
        _value_digest(identity): identity
        for row in choices
        for identity in row["mapped_route_identities"]
    }
    mapped_routes = sorted(
        mapped_route_by_digest.values(),
        key=lambda row: (row["object_kind"], row["coordinate"]),
    )
    mapped_digests = set(mapped_route_by_digest)
    unmatched_routes = [
        row
        for row in denominators["routes"]
        if _value_digest(row) not in mapped_digests
    ]
    if len(mapped_routes) != 27 or len(unmatched_routes) != 18:
        raise RuntimeError("FACET_REASON_ROUTE_MAPPING_DENOMINATOR_DIFFERS")
    domain_route_reasons = _domain_route_reason_rows(
        bindings, source_binding_digest, unmatched_routes
    )
    ledger: dict[str, Any] = {
        "schema_version": LEDGER_SCHEMA,
        "mechanism_digest": mechanism_digest(),
        "source_bindings": bindings,
        "source_binding_digest": source_binding_digest,
        "semantic_facets": list(FACETS),
        "object_kind_count": len(denominators["object_kinds"]),
        "tier": TIER,
        "facet_choice_count": len(choices),
        "choices": choices,
        "choices_digest": _value_digest(choices),
        "domain_route_reason_count": len(domain_route_reasons),
        "domain_route_reasons": domain_route_reasons,
        "domain_route_reasons_digest": _value_digest(domain_route_reasons),
        "structural_projection_count": len(denominators["structural"]),
        "structural_projection": denominators["structural"],
        "structural_projection_digest": _value_digest(denominators["structural"]),
        "route_projection_count": len(denominators["routes"]),
        "route_projection": denominators["routes"],
        "route_projection_digest": _value_digest(denominators["routes"]),
        "mapped_route_projection_count": len(mapped_routes),
        "mapped_route_projection": mapped_routes,
        "mapped_route_projection_digest": _value_digest(mapped_routes),
        "unmatched_route_projection_count": len(unmatched_routes),
        "unmatched_route_projection": unmatched_routes,
        "unmatched_route_projection_digest": _value_digest(unmatched_routes),
        "slot_projection_count": len(denominators["slots"]),
        "slot_projection": denominators["slots"],
        "slot_projection_digest": _value_digest(denominators["slots"]),
        "polished": False,
        "release_authorized": False,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    ledger["ledger_digest"] = _value_digest(ledger)
    return ledger


def _projection_support(
    expected: Sequence[Mapping[str, Any]], field: str
) -> dict[str, tuple[dict[str, Any], set[str]]]:
    support: dict[str, tuple[dict[str, Any], set[str]]] = {}
    for row in expected:
        mapped = row[field]
        values = [mapped] if field == "mapped_slot_identity" else mapped
        for identity in values:
            digest = _value_digest(identity)
            if digest not in support:
                support[digest] = (dict(identity), set())
            support[digest][1].add(row["choice_id"])
    return support


def _finish_assessment(report: dict[str, Any]) -> dict[str, Any]:
    report["blockers"] = sorted(set(report["blockers"]))
    report["assessment_digest"] = _value_digest(report)
    return report


def _failed_assessment(code: str) -> dict[str, Any]:
    return _finish_assessment(
        {
            "schema_version": ASSESSMENT_SCHEMA,
            "status": "FAIL",
            "reason_completeness_status": "FAIL",
            "facet_choice_reason_status": "FAIL",
            "domain_route_reason_status": "FAIL",
            "structural_projection_status": "FAIL",
            "route_projection_status": "FAIL",
            "slot_projection_status": "FAIL",
            "source_binding_status": "FAIL",
            "mechanism_digest": None,
            "ledger_digest": None,
            "facet_choice_denominator": 130,
            "qualifying_facet_choice_reason_count": 0,
            "facet_choice_reason_deficit": 130,
            "domain_route_reason_denominator": 18,
            "qualifying_domain_route_reason_count": 0,
            "domain_route_reason_deficit": 18,
            "structural_membership_denominator": 52,
            "reasoned_structural_membership_count": 0,
            "structural_membership_reason_deficit": 52,
            "reasoned_structural_membership_digest": _value_digest([]),
            "expected_structural_membership_digest": None,
            "route_membership_denominator": 45,
            "reasoned_route_membership_count": 0,
            "route_membership_reason_deficit": 45,
            "reasoned_route_membership_digest": _value_digest([]),
            "expected_route_membership_digest": None,
            "slot_denominator": 26,
            "reasoned_slot_count": 0,
            "slot_reason_deficit": 26,
            "reasoned_slot_digest": _value_digest([]),
            "expected_slot_digest": None,
            "reasoned_slot_object_kinds": [],
            "choice_identity_digest": None,
            "domain_route_reason_identity_digest": None,
            "polished": False,
            "release_authorized": False,
            "blockers": [code],
            "claim_boundary": _CLAIM_BOUNDARY,
        }
    )


def assess_facet_reason_choices(
    choices: Any, domain_route_reasons: Any = None
) -> dict[str, Any]:
    """Assess installed facet and domain-route reasons fail closed.

    Omitted or otherwise-valid blank reasons are UNKNOWN. Malformed, substituted,
    cross-coordinate, or digest-invalid rows are FAIL. Omitting the optional
    domain-route argument means that none of the separate 18 route reasons were
    supplied; it never silently selects the installed rows.
    """
    try:
        installed = installed_facet_reason_ledger()
        expected_rows = installed["choices"]
        expected = {row["choice_id"]: row for row in expected_rows}
        if type(choices) is not list or len(choices) > len(expected_rows):
            return _failed_assessment("FACET_REASON_CHOICES_MALFORMED")
        observed: dict[str, Mapping[str, Any]] = {}
        qualifying: set[str] = set()
        missing_reason_ids: set[str] = set()
        for row in choices:
            if type(row) is not dict:
                return _failed_assessment("FACET_REASON_CHOICE_MALFORMED")
            choice_id = row.get("choice_id")
            if type(choice_id) is not str or choice_id not in expected:
                return _failed_assessment("FACET_REASON_CHOICE_CROSS_KIND_OR_UNKNOWN")
            if choice_id in observed:
                return _failed_assessment("FACET_REASON_CHOICE_DUPLICATED")
            target = expected[choice_id]
            if any(row.get(key) != target[key] for key in ("object_kind", "tier", "facet")):
                return _failed_assessment("FACET_REASON_CHOICE_CROSS_KIND_OR_UNKNOWN")
            if set(row) != _CHOICE_FIELDS:
                return _failed_assessment("FACET_REASON_CHOICE_MALFORMED")
            observed[choice_id] = row
            reason = row.get("reason")
            if row.get("choice") not in CHOICES:
                return _failed_assessment("FACET_REASON_CHOICE_MALFORMED")
            non_reason_fields = _CHOICE_FIELDS - {
                "reason", "reason_digest", "choice_digest"
            }
            if any(row[field] != target[field] for field in non_reason_fields):
                return _failed_assessment("FACET_REASON_CHOICE_SUBSTITUTED")
            if (
                row["reason_digest"] != _value_digest(reason)
                or row["provenance_digest"] != _value_digest(row["provenance"])
                or row["basis_digest"] != _value_digest(row["basis"])
                or row["choice_digest"]
                != _value_digest(
                    {
                        key: value
                        for key, value in row.items()
                        if key != "choice_digest"
                    }
                )
                or row["source_binding_digest"]
                != installed["source_binding_digest"]
            ):
                return _failed_assessment("FACET_REASON_DIGEST_OR_CHOICE_INVALID")
            if reason is None or (type(reason) is str and not reason.strip()):
                missing_reason_ids.add(choice_id)
                continue
            if type(reason) is not str or len(reason) < 80 or len(reason) > 4096:
                return _failed_assessment("FACET_REASON_CHOICE_MALFORMED")
            if row != target:
                return _failed_assessment("FACET_REASON_CHOICE_SUBSTITUTED")
            qualifying.add(choice_id)

        missing_ids = set(expected) - set(observed)
        incomplete_ids = missing_ids | missing_reason_ids
        if domain_route_reasons is None:
            domain_route_reasons = []
        expected_domain_rows = installed["domain_route_reasons"]
        expected_domain = {
            row["route_reason_id"]: row for row in expected_domain_rows
        }
        if (
            type(domain_route_reasons) is not list
            or len(domain_route_reasons) > len(expected_domain_rows)
        ):
            return _failed_assessment("DOMAIN_ROUTE_REASONS_MALFORMED")
        observed_domain: dict[str, Mapping[str, Any]] = {}
        qualifying_domain: set[str] = set()
        missing_domain_text: set[str] = set()
        for row in domain_route_reasons:
            if type(row) is not dict:
                return _failed_assessment("DOMAIN_ROUTE_REASON_MALFORMED")
            route_reason_id = row.get("route_reason_id")
            if type(route_reason_id) is not str or route_reason_id not in expected_domain:
                return _failed_assessment("DOMAIN_ROUTE_REASON_CROSS_ROUTE_OR_UNKNOWN")
            if route_reason_id in observed_domain:
                return _failed_assessment("DOMAIN_ROUTE_REASON_DUPLICATED")
            target = expected_domain[route_reason_id]
            if any(
                row.get(key) != target[key]
                for key in ("object_kind", "tier", "coordinate", "category")
            ):
                return _failed_assessment("DOMAIN_ROUTE_REASON_CROSS_ROUTE_OR_UNKNOWN")
            if set(row) != _DOMAIN_ROUTE_REASON_FIELDS:
                return _failed_assessment("DOMAIN_ROUTE_REASON_MALFORMED")
            observed_domain[route_reason_id] = row
            reason = row.get("reason")
            if row.get("choice") not in CHOICES:
                return _failed_assessment("DOMAIN_ROUTE_REASON_MALFORMED")
            non_reason_fields = _DOMAIN_ROUTE_REASON_FIELDS - {
                "reason",
                "reason_digest",
                "route_reason_digest",
            }
            if any(row[field] != target[field] for field in non_reason_fields):
                return _failed_assessment("DOMAIN_ROUTE_REASON_SUBSTITUTED")
            if (
                row["reason_digest"] != _value_digest(reason)
                or row["provenance_digest"] != _value_digest(row["provenance"])
                or row["basis_digest"] != _value_digest(row["basis"])
                or row["route_reason_digest"]
                != _value_digest(
                    {
                        key: value
                        for key, value in row.items()
                        if key != "route_reason_digest"
                    }
                )
                or row["source_binding_digest"]
                != installed["source_binding_digest"]
            ):
                return _failed_assessment("DOMAIN_ROUTE_REASON_DIGEST_OR_CHOICE_INVALID")
            if reason is None or (type(reason) is str and not reason.strip()):
                missing_domain_text.add(route_reason_id)
                continue
            if type(reason) is not str or len(reason) < 80 or len(reason) > 4096:
                return _failed_assessment("DOMAIN_ROUTE_REASON_MALFORMED")
            if row != target:
                return _failed_assessment("DOMAIN_ROUTE_REASON_SUBSTITUTED")
            qualifying_domain.add(route_reason_id)

        missing_domain_ids = set(expected_domain) - set(observed_domain)
        projections: dict[str, tuple[list[dict[str, Any]], int, str]] = {}
        for name, field, expected_count in (
            ("structural", "mapped_structural_identities", 52),
            ("route", "mapped_route_identities", 27),
        ):
            support = _projection_support(expected_rows, field)
            reasoned = sorted(
                (
                    identity
                    for identity, choice_ids in support.values()
                    if choice_ids <= qualifying
                ),
                key=lambda row: (row["object_kind"], row["coordinate"]),
            )
            if len(support) != expected_count:
                return _failed_assessment("FACET_REASON_PROJECTION_DENOMINATOR_DIFFERS")
            projections[name] = (reasoned, expected_count, _value_digest(reasoned))

        direct_routes = projections["route"][0]
        domain_routes = [
            row["mapped_route_identity"]
            for row in expected_domain_rows
            if row["route_reason_id"] in qualifying_domain
        ]
        reasoned_route_by_digest = {
            _value_digest(identity): identity
            for identity in [*direct_routes, *domain_routes]
        }
        reasoned_routes = sorted(
            reasoned_route_by_digest.values(),
            key=lambda row: (row["object_kind"], row["coordinate"]),
        )
        projections["route"] = (
            reasoned_routes,
            45,
            _value_digest(reasoned_routes),
        )

        slot_support = _projection_support(expected_rows, "mapped_slot_identity")
        if len(slot_support) != 26:
            return _failed_assessment("FACET_REASON_PROJECTION_DENOMINATOR_DIFFERS")
        reasoned_route_ids = {
            _value_digest(identity) for identity in projections["route"][0]
        }
        full_routes_by_kind = {
            kind.value: [
                row
                for row in installed["route_projection"]
                if row["object_kind"] == kind.value
            ]
            for kind in ObjectKind
        }
        reasoned_slots = sorted(
            (
                identity
                for identity, choice_ids in slot_support.values()
                if choice_ids <= qualifying
                and all(
                    _value_digest(route) in reasoned_route_ids
                    for route in full_routes_by_kind[identity["object_kind"]]
                )
            ),
            key=lambda row: (row["object_kind"], row["coordinate"]),
        )
        projections["slot"] = (
            reasoned_slots,
            26,
            _value_digest(reasoned_slots),
        )

        facet_choice_complete = (
            not incomplete_ids and len(qualifying) == len(expected)
        )
        domain_route_complete = (
            not missing_domain_ids
            and not missing_domain_text
            and len(qualifying_domain) == len(expected_domain)
        )
        structural_complete = len(projections["structural"][0]) == 52
        route_complete = len(projections["route"][0]) == 45
        slot_complete = len(projections["slot"][0]) == 26
        complete = (
            facet_choice_complete
            and domain_route_complete
            and structural_complete
            and route_complete
            and slot_complete
        )
        blockers = [] if complete else ["FACET_REASONS_INCOMPLETE"]
        if not domain_route_complete:
            blockers.append("DOMAIN_ROUTE_REASONS_MISSING")
        if missing_domain_text:
            blockers.append("DOMAIN_ROUTE_REASON_TEXT_MISSING")
        if missing_ids:
            blockers.append("FACET_REASON_CHOICES_MISSING")
        if missing_reason_ids:
            blockers.append("FACET_REASON_TEXT_MISSING")
        report = {
            "schema_version": ASSESSMENT_SCHEMA,
            "status": "PASS" if complete else "UNKNOWN",
            "reason_completeness_status": "PASS" if complete else "UNKNOWN",
            "facet_choice_reason_status": (
                "PASS" if facet_choice_complete else "UNKNOWN"
            ),
            "domain_route_reason_status": (
                "PASS" if domain_route_complete else "UNKNOWN"
            ),
            "structural_projection_status": (
                "PASS" if structural_complete else "UNKNOWN"
            ),
            "route_projection_status": "PASS" if route_complete else "UNKNOWN",
            "slot_projection_status": "PASS" if slot_complete else "UNKNOWN",
            "source_binding_status": "PASS",
            "mechanism_digest": installed["mechanism_digest"],
            "ledger_digest": installed["ledger_digest"],
            "facet_choice_denominator": len(expected),
            "qualifying_facet_choice_reason_count": len(qualifying),
            "facet_choice_reason_deficit": len(expected) - len(qualifying),
            "domain_route_reason_denominator": len(expected_domain),
            "qualifying_domain_route_reason_count": len(qualifying_domain),
            "domain_route_reason_deficit": len(expected_domain)
            - len(qualifying_domain),
            "structural_membership_denominator": 52,
            "reasoned_structural_membership_count": len(projections["structural"][0]),
            "structural_membership_reason_deficit": 52
            - len(projections["structural"][0]),
            "reasoned_structural_membership_digest": projections["structural"][2],
            "expected_structural_membership_digest": installed[
                "structural_projection_digest"
            ],
            "route_membership_denominator": 45,
            "reasoned_route_membership_count": len(projections["route"][0]),
            "route_membership_reason_deficit": 45 - len(projections["route"][0]),
            "reasoned_route_membership_digest": projections["route"][2],
            "expected_route_membership_digest": installed["route_projection_digest"],
            "slot_denominator": 26,
            "reasoned_slot_count": len(projections["slot"][0]),
            "slot_reason_deficit": 26 - len(projections["slot"][0]),
            "reasoned_slot_digest": projections["slot"][2],
            "expected_slot_digest": installed["slot_projection_digest"],
            "reasoned_slot_object_kinds": [
                row["object_kind"] for row in projections["slot"][0]
            ],
            "choice_identity_digest": _value_digest(sorted(qualifying)),
            "domain_route_reason_identity_digest": _value_digest(
                sorted(qualifying_domain)
            ),
            "polished": False,
            "release_authorized": False,
            "blockers": blockers,
            "claim_boundary": _CLAIM_BOUNDARY,
        }
        return _finish_assessment(report)
    except (KeyError, TypeError, ValueError, RuntimeError, OSError):
        return _failed_assessment("FACET_REASON_MECHANISM_OR_SOURCE_INVALID")


def replay_facet_reason_ledger(ledger: Any) -> dict[str, Any]:
    """Replay an exact ledger against current installed sources and reasons."""
    try:
        if type(ledger) is not dict or set(ledger) != _LEDGER_FIELDS:
            return _failed_assessment("FACET_REASON_LEDGER_MALFORMED")
        current = installed_facet_reason_ledger()
        if ledger["ledger_digest"] != _value_digest(
            {key: value for key, value in ledger.items() if key != "ledger_digest"}
        ):
            return _failed_assessment("FACET_REASON_LEDGER_DIGEST_MISMATCH")
        for field in (
            "schema_version",
            "mechanism_digest",
            "source_bindings",
            "source_binding_digest",
            "semantic_facets",
            "object_kind_count",
            "tier",
            "facet_choice_count",
            "choices_digest",
            "domain_route_reason_count",
            "domain_route_reasons_digest",
            "structural_projection_count",
            "structural_projection",
            "structural_projection_digest",
            "route_projection_count",
            "route_projection",
            "route_projection_digest",
            "mapped_route_projection_count",
            "mapped_route_projection",
            "mapped_route_projection_digest",
            "unmatched_route_projection_count",
            "unmatched_route_projection",
            "unmatched_route_projection_digest",
            "slot_projection_count",
            "slot_projection",
            "slot_projection_digest",
            "polished",
            "release_authorized",
            "claim_boundary",
        ):
            if ledger[field] != current[field]:
                return _failed_assessment("FACET_REASON_LEDGER_SUBSTITUTED")
        if ledger["choices_digest"] != _value_digest(ledger["choices"]):
            return _failed_assessment("FACET_REASON_LEDGER_DIGEST_MISMATCH")
        if ledger["domain_route_reasons_digest"] != _value_digest(
            ledger["domain_route_reasons"]
        ):
            return _failed_assessment("FACET_REASON_LEDGER_DIGEST_MISMATCH")
        result = assess_facet_reason_choices(
            ledger["choices"], ledger["domain_route_reasons"]
        )
        if result["status"] != "FAIL" and result["ledger_digest"] != ledger["ledger_digest"]:
            return _failed_assessment("FACET_REASON_LEDGER_DIGEST_MISMATCH")
        return result
    except (KeyError, TypeError, ValueError, RuntimeError, OSError):
        return _failed_assessment("FACET_REASON_LEDGER_MALFORMED")


def installed_facet_reason_assessment() -> dict[str, Any]:
    """Replay the exact installed ledger without an external authority prerequisite."""
    return replay_facet_reason_ledger(installed_facet_reason_ledger())


__all__ = [
    "ASSESSMENT_SCHEMA",
    "CHOICES",
    "FACETS",
    "LEDGER_SCHEMA",
    "MECHANISM_SCHEMA",
    "PRIMITIVE_KINDS",
    "assess_facet_reason_choices",
    "installed_facet_reason_assessment",
    "installed_facet_reason_ledger",
    "installed_source_bindings",
    "mechanism_digest",
    "replay_facet_reason_ledger",
]
