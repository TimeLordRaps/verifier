"""Assess the package contract denominator for Verifier Standard (VSTD).

Terminology: identifier (ID).

This is the aggregation checker, not a subject executor or a receipt importer.
It rebuilds expected clauses from installed contracts and source-derived kinds,
then checks the current invocation's results. A complete finite route join is
not a complete kind contract: the semantic questions remain separately visible.
No caller-authored list, applicability prose or PASS string closes that gap.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, TYPE_CHECKING

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.inventory import build_234_inventory
from verifier.runtime.namespace_contracts import registry_document
from verifier.runtime.tier_zero_profile import (
    validate_applicability_binding,
    value_digest,
)
from verifier.runtime import (
    added_kind_behavioral_routes,
    package_contract_profiles,
    package_execution,
    package_source_contracts,
)
from verifier.runtime.package_kind_requirements import accepts_subject

if TYPE_CHECKING:
    from verifier.runtime.package_kind_requirements import KindRequirements


SCHEMA = "verifier-package-contract-coverage-2"
_CONSEQUENCE_FAMILIES = {
    "MARKET": "REAL_MARKET",
    "ROBOT": "REAL_PHYSICAL",
    "FINBOT": "REAL_FINANCIAL",
}
_APPLICABILITY_ASSESSMENT_KEYS = {
    "kind", "status", "reason", "effect_domain", "object_denominator",
    "reviewed_object_count", "applies_count", "does_not_apply_count",
    "unresolved_count", "invalid_count", "carrier_count", "carriers",
    "next_unresolved", "missing_object_ids", "extra_object_ids",
    "checker_or_specimen_execution_is_carrier_evidence",
    "source_binding_digest", "source_bound_refutation_count",
    "evidence_digest",
}


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _promoted_applicability_status(
    family: str,
    assessment: Any,
) -> str:
    """Accept only the exact internally generated promotion receipt.

    UNKNOWN needs no promotion validation because it always remains a
    residual.  NECESSARY and source-bound CONDITION_NOT_MET can change the
    route denominator, so their compact receipt is validated before either is
    allowed to do so.  This validates a digest over the receipt; it does not
    re-hash the package GRAPH outside the promotion computation.
    """
    if not isinstance(assessment, dict) or assessment.get("status") == "UNKNOWN":
        return "UNKNOWN"
    if set(assessment) != _APPLICABILITY_ASSESSMENT_KEYS:
        return "UNKNOWN"
    if (
        assessment.get("kind") != family
        or assessment.get("effect_domain") != _CONSEQUENCE_FAMILIES[family]
        or type(assessment.get("reason")) is not str
        or not assessment["reason"].strip()
        or assessment.get("checker_or_specimen_execution_is_carrier_evidence")
            is not False
        or not _is_digest(assessment.get("source_binding_digest"))
        or not _is_digest(assessment.get("evidence_digest"))
        or assessment["evidence_digest"] != value_digest({
            key: value for key, value in assessment.items()
            if key != "evidence_digest"
        })
    ):
        return "UNKNOWN"
    count_names = (
        "object_denominator", "reviewed_object_count", "applies_count",
        "does_not_apply_count", "unresolved_count", "invalid_count",
        "carrier_count", "source_bound_refutation_count",
    )
    if any(
        type(assessment.get(name)) is not int or assessment[name] < 0
        for name in count_names
    ):
        return "UNKNOWN"
    denominator = assessment["object_denominator"]
    if (
        denominator <= 0
        or assessment["reviewed_object_count"]
            != assessment["applies_count"]
                + assessment["does_not_apply_count"]
                + assessment["unresolved_count"]
        or denominator
            != assessment["reviewed_object_count"] + assessment["invalid_count"]
        or assessment.get("missing_object_ids") != []
        or assessment.get("extra_object_ids") != []
        or type(assessment.get("carriers")) is not list
        or assessment["carrier_count"] != len(assessment["carriers"])
    ):
        return "UNKNOWN"
    carriers = assessment["carriers"]
    if any(
        type(row) is not dict
        or set(row) != {"object_id", "basis"}
        or type(row["object_id"]) is not str
        or not row["object_id"]
        or row["basis"] not in {
            "SOURCE_CLASSIFICATION_APPLIES",
            "DECLARED_" + _CONSEQUENCE_FAMILIES[family] + "_EFFECT",
        }
        for row in carriers
    ) or len({row["object_id"] for row in carriers}) != len(carriers):
        return "UNKNOWN"
    status = assessment.get("status")
    if status == "NECESSARY":
        return status if carriers else "UNKNOWN"
    if status == "SOURCE_BOUND_CONDITION_NOT_MET" and (
        assessment["applies_count"] == 0
        and assessment["does_not_apply_count"] == denominator
        and assessment["unresolved_count"] == 0
        and assessment["invalid_count"] == 0
        and assessment["carrier_count"] == 0
        and assessment["source_bound_refutation_count"] == denominator
        and assessment.get("next_unresolved") is None
    ):
        return status
    return "UNKNOWN"


def _family_profile_obligations(
    matrix_kinds: dict[str, Any],
    family: str,
) -> list[dict[str, Any]]:
    """Return the exact installed family IDs even if matrix output is damaged."""
    rows = matrix_kinds.get(family, {}).get("profile_obligations", [])
    if type(rows) is list and rows and all(
        type(row) is dict
        and type(row.get("obligation_id")) is str
        and row.get("earliest_executable_tier") in (1, 2, 3)
        for row in rows
    ):
        return rows
    installed = package_contract_profiles.profile(family)
    if installed is None:
        return []
    return [
        {
            "obligation_id": obligation_id,
            "earliest_executable_tier": min(
                int(coordinate.split("-", 1)[1].split(".", 1)[0])
                for coordinate in coordinates
            ),
        }
        for obligation_id, coordinates
        in installed["family_obligation_route_mapping"].items()
    ]


def _package_global_applicability_residuals(
    matrix: dict[str, Any],
    subjects: dict[str, NamespaceObject],
    kinds: KindRequirements,
    *,
    verifier_id: str,
) -> list[dict[str, Any]]:
    """Carry package-wide consequence UNKNOWN into one verifier-bound ledger.

    A family with zero effective objects still has an applicability question;
    otherwise omission of every MARKET/ROBOT/FINBOT label could erase the very
    obligations that detect mislabeling. Exact all-object source-bound
    CONDITION_NOT_MET closes the family only when the manifest also contains no
    effective carrier. A source-bound NECESSARY result must have an effective
    role so its installed routes remain in the ordinary instance denominator.
    """
    assessments = matrix.get("package_instance_applicability_assessments")
    matrix_kinds = matrix.get("kinds")
    if type(assessments) is not dict:
        assessments = {}
    if type(matrix_kinds) is not dict:
        matrix_kinds = {}
    effective_by_kind = {
        family: sorted(
            object_id
            for object_id in subjects
            if family in set(kinds.kinds(object_id))
        )
        for family in _CONSEQUENCE_FAMILIES
    }
    residuals: list[dict[str, Any]] = []
    for family in sorted(_CONSEQUENCE_FAMILIES):
        assessment = assessments.get(family)
        status = _promoted_applicability_status(family, assessment)
        effective = effective_by_kind.get(family, [])
        if status == "UNKNOWN":
            reason = (
                assessment.get("reason")
                if isinstance(assessment, dict) else None
            )
            question = (
                "Resolve every exact source-owned package object for " + family
                + "; UNKNOWN applicability is not an exemption even when no "
                "effective object currently carries the role."
            )
        elif status == "NECESSARY" and not effective:
            reason = (
                "Source-bound package evidence selects at least one " + family
                + " carrier, but the admitted package GRAPH has no effective "
                + family + " object; its routes cannot disappear by mislabeling."
            )
            question = (
                "Reconcile the source carrier with an effective package role and "
                "execute every installed family route."
            )
        elif status == "SOURCE_BOUND_CONDITION_NOT_MET" and effective:
            reason = (
                "The source review refutes " + family + " over its exact object "
                "denominator, but the admitted package GRAPH still assigns that "
                "effective role."
            )
            question = (
                "Reconcile the manifest role with current source before treating "
                "the family condition as not met."
            )
        else:
            continue
        if type(reason) is not str or not reason.strip():
            reason = "Package-wide consequence applicability remains unresolved."
        obligations = _family_profile_obligations(matrix_kinds, family)
        for obligation in obligations:
            if type(obligation) is not dict:
                continue
            obligation_id = obligation.get("obligation_id")
            earliest = obligation.get("earliest_executable_tier")
            if type(obligation_id) is not str or earliest not in (1, 2, 3):
                continue
            residuals.append({
                "source": "admission-contract-semantic-remainder",
                "source_id": obligation_id,
                "reason": reason,
                "status": "UNKNOWN",
                "question": question,
                "mechanism": (
                    "verifier.runtime.package_contract_profiles."
                    "reconcile_package_instance_applicability"
                ),
                "boundary": (
                    "Package-global applicability is bound to verifier "
                    + verifier_id
                    + ". Only exact all-object source-bound CONDITION_NOT_MET "
                    "with no effective manifest carrier closes this obligation; "
                    "checker/specimen PASS, zero objects, or an OBJECT label does not."
                ),
                "tier": earliest,
                "next_action": [
                    "vstd", "gate", "--object", verifier_id,
                    "--obligation", obligation_id,
                ],
            })
    return residuals


def _gate_action(coordinate: str, clause: dict[str, Any] | None,
                 route_obligations: dict[str, str] | None, route_tier: int) -> list[str]:
    """Return the exact gate action for one route, never a coordinate as obligation.

    A present clause names its own obligation. A missing clause is bound through
    the installed route catalog; an unbound coordinate falls back to its tier's
    polish action rather than inventing an obligation identifier.
    """
    if clause is not None:
        obligation_id = clause["obligation_id"]
    else:
        if route_obligations is None:
            # Direct callers do not own a catalog snapshot. Assessment passes
            # its already-selected mapping, so package-wide cost stays bounded.
            from verifier.runtime.manifest_gate import obligation_catalog
            route_obligations = {
                row["coordinate"]: row["obligation_id"] for row in obligation_catalog()
            }
        obligation_id = route_obligations.get(coordinate)
    if obligation_id is None:
        return ["vstd", "polish", str(route_tier)]
    return ["vstd", "gate", "--object", "{object_id}", "--obligation", obligation_id]


def _residuals(kind: str, tier: int, kinds: KindRequirements,
               slots: dict[tuple[str, int], Any],
               clauses: list[dict[str, Any]],
               matrix_obligations: dict[str, dict[str, Any]] | None = None,
               *, route_obligations: dict[str, str] | None = None,
               ) -> list[dict[str, Any]]:
    """Expose unclosed package-variant routes without source-only erasure.

The installed profile is an independently pinned current-package denominator.
Passing source-adaptation routes are necessary, but a behavioral route closes
only through a necessary finite check or an exact evidenced non-trigger. A
profiled kind without a KIND-1.90 clause still keeps every installed coordinate
that lacks its own PASS as an UNKNOWN residual. Unprofiled local extensions keep
the earlier explicit semantic questions.
"""
    contract = kinds.registry[kind]
    installed_profile = package_contract_profiles.profile(kind)
    rows: list[dict[str, Any]] = []
    if installed_profile is not None:
        # Every installed coordinate stays open until its own PASS clause exists,
        # whether or not a KIND-1.90 source clause was selected for this object.
        # A missing clause is an absence of evidence, never an erased route.
        required = package_contract_profiles.required_coordinates(kind, tier)
        by_coordinate = {row["coordinate"]: row for row in clauses}
        for coordinate in required or ():
            clause = by_coordinate.get(coordinate)
            if clause is not None and clause.get("closure_status") == "PASS":
                continue
            route_tier = int(coordinate.split("-", 1)[1].split(".", 1)[0])
            rows.append({
                "source": "installed-package-variant-profile",
                "source_id": coordinate,
                "reason": installed_profile["reason"],
                "status": "UNKNOWN",
                "question": (
                    "Run or explicitly refute the exact installed package-variant "
                    f"route {coordinate}; generic source adaptation is not behavioral closure."
                ),
                "mechanism": None if clause is None else clause["checking_mechanism"],
                "boundary": installed_profile["claim_boundary"],
                "tier": route_tier,
                "next_action": _gate_action(coordinate, clause, route_obligations, route_tier),
            })
    selected_profile = (
        installed_profile
        if installed_profile is not None and any(
            row.get("coordinate") in set(installed_profile["source_routes"].values())
            for row in clauses
        ) else None
    )
    if selected_profile is not None:
        by_coordinate = {row["coordinate"]: row for row in clauses}
        # Added-kind Tier-0 obligations name semantic families. Their mapped
        # tier-matched .90 route executes the exact current source, interfaces,
        # and omission controls, so it can discharge the source-representation
        # variant. Domain routes retain runtime claims and consequences.
        # Proving one installed implementation condition false closes only that
        # route; without a NECESSARY executable mapping the family stays open.
        obligations = {obligation.id: obligation for obligation in contract.obligations}
        for obligation_id, coordinates in selected_profile[
                "family_obligation_route_mapping"].items():
            obligation = obligations.get(obligation_id)
            if obligation is None:
                # Legacy profiles use one adapter-owned SOURCE-0.1 mapping for
                # their complete route set. Their native route denominator is
                # already represented by the coordinate residuals above.
                continue
            route_tiers = {
                coordinate: int(coordinate.split("-", 1)[1].split(".", 1)[0])
                for coordinate in coordinates
            }
            required_tier = min(route_tiers.values())
            in_scope = [coordinate for coordinate in coordinates
                        if route_tiers[coordinate] <= tier]
            if not in_scope:
                rows.append({
                    "source": "admission-contract-semantic-remainder",
                    "source_id": obligation_id,
                    "reason": obligation.reason,
                    "status": "UNKNOWN",
                    "question": (
                        f"Retain {obligation_id} in the cumulative denominator and "
                        f"execute its mapped Tier {required_tier} source and behavioral "
                        "routes; a lower selected tier is not an exemption."
                    ),
                    "mechanism": None,
                    "boundary": (
                        "Every applicable added-kind Tier-0 declaration remains visible "
                        "at Polish 1, 2, and 3. A route first available at a later tier "
                        "stays UNKNOWN rather than disappearing from the denominator."
                    ),
                    "tier": required_tier,
                    "next_action": ["vstd", "polish", str(required_tier)],
                })
                continue
            selected = [by_coordinate[coordinate] for coordinate in in_scope
                        if coordinate in by_coordinate]
            matrix_obligation = (
                matrix_obligations.get(obligation_id)
                if matrix_obligations is not None else None
            )
            semantic_blocker = (
                matrix_obligation.get("semantic_mapping_blocker")
                if type(matrix_obligation) is dict else
                package_contract_profiles.semantic_mapping_blocker(obligation_id)
            )
            unmapped_fields = (
                matrix_obligation.get("unmapped_declaration_fields", [])
                if type(matrix_obligation) is dict else []
            )
            if semantic_blocker is not None:
                field_summary = ", ".join(
                    str(row.get("field")) + "=" + str(row.get("status"))
                    for row in unmapped_fields if type(row) is dict
                )
                rows.append({
                    "source": "admission-contract-semantic-remainder",
                    "source_id": obligation_id,
                    "reason": obligation.reason,
                    "status": "UNKNOWN",
                    "question": (
                        "Add and source-bind an executable package-instance mechanism "
                        f"that covers the unmechanized semantics of {obligation_id}"
                        + (": " + field_summary if field_summary else ".")
                    ),
                    "mechanism": None,
                    "boundary": (
                        semantic_blocker
                        + " Catalog, source-adapter, schema, or retained specimen PASS "
                          "does not close this declaration family."
                    ),
                    "tier": required_tier,
                    "next_action": ["vstd", "polish", str(max(tier, required_tier))],
                })
                continue
            # Missing/failed/unknown routes already have exact coordinate
            # residuals above. Add the family residual only for the dangerous
            # false-closure case: every route looks closed solely through one
            # or more non-trigger refutations.
            if (len(selected) != len(in_scope)
                    or any(clause.get("closure_status") != "PASS"
                           for clause in selected)):
                continue
            discharged = any(
                clause.get("closure_status") == "PASS"
                and clause.get("checker_status") == "PASS"
                and clause.get("applicability", {}).get("classification") == "NECESSARY"
                and clause.get("fulfillment_required") is not False
                for clause in selected
            )
            if discharged:
                continue
            family_tier = max(
                int(coordinate.split("-", 1)[1].split(".", 1)[0])
                for coordinate in in_scope
            )
            rerun_obligation = next(
                (by_coordinate[coordinate]["obligation_id"]
                 for coordinate in in_scope if coordinate in by_coordinate),
                None,
            )
            rows.append({
                "source": "installed-package-variant-profile",
                "source_id": obligation_id,
                "reason": obligation.reason,
                "status": "UNKNOWN",
                "question": (
                    "Implement or register and source-bind an executable behavioral "
                    f"adapter for this object's variant of obligation family "
                    f"{obligation_id}, then run its exact mapped route. An installed "
                    "implementation non-trigger is not family conformance."
                ),
                "mechanism": None,
                "boundary": (
                    "Each implementation-specific CONDITION_NOT_MET result refutes "
                    "only its named route. Source declarations, catalog membership, "
                    "and adaptation PASS do not establish this behavioral family."
                ),
                "tier": family_tier,
                "next_action": (
                    ["vstd", "gate", "--object", "{object_id}",
                     "--obligation", rerun_obligation]
                    if rerun_obligation is not None else
                    ["vstd", "polish", str(tier)]
                ),
            })
        return rows
    rows.append({"source": "installed-kind-contract", "source_id": kind,
             "reason": contract.reason, "status": "UNKNOWN",
             "question": "Establish that the necessary clauses, applicability predicates and cross-object consequences are complete for this actual kind variant through the requested tier.",
             "mechanism": None, "boundary": "Kind registration and finite route coverage cannot establish this proposition.",
             "tier": tier, "next_action": ["vstd", "polish", str(tier)]})
    for depth in range(1, tier + 1):
        slot = slots.get((kind, depth))
        if slot is not None:
            rows.append({"source": "native-slot-planning-context", "source_id": f"{kind}-{depth}",
                "reason": slot.rationale, "status": "UNKNOWN", "question": slot.governing_question,
                "mechanism": None, "boundary": "This slot rationale is not a numbered obligation or a whole-slot proof.",
                "tier": depth, "next_action": ["vstd", "polish", str(depth)]})
    for index, obligation in enumerate(contract.obligations, start=1):
        if index > tier and installed_profile is None:
            continue
        rows.append({"source": "admission-contract-semantic-remainder", "source_id": obligation.id,
            "reason": obligation.reason, "status": "UNKNOWN",
            "question": "Mechanize the applicable behavioral meaning of: " + ", ".join(obligation.declaration_fields) + ".",
            "mechanism": None, "boundary": "The admission declaration has its own Tier-0 gate; filling its fields does not establish higher-tier behavior.",
            "tier": index, "next_action": ["vstd", "polish", str(index)]})
    return rows


def _selected_check_binds_route(
    route: dict[str, Any], selected: dict[str, Any], *, object_id: str,
    object_digest: str, collection_digest: str,
) -> bool:
    """Reject a PASS copied from another proposition, object, or snapshot."""
    if any((
        selected.get("object_id") != object_id,
        selected.get("object_digest") != object_digest,
        selected.get("collection_digest") != collection_digest,
    )):
        return False
    if package_source_contracts.is_route(route):
        body = {key: value for key, value in selected.items()
                if key != "result_digest"}
        return (
            selected.get("adapter") == package_source_contracts.ADAPTER
            and selected.get("coordinate") == route["coordinate"]
            and selected.get("result_digest") == value_digest(body)
        )
    if package_execution.route_mechanism(route) is not None:
        fields = ("coordinate", "obligation_id", "semantic_version",
                  "proposition_digest", "checking_mechanism")
    else:
        fields = ("coordinate", "semantic_version", "proposition_digest",
                  "checking_mechanism")
    return all(selected.get(field) == route[field] for field in fields)


def _clause_metadata(
    route: dict[str, Any], row: dict[str, Any], *, object_id: str,
    object_digest: str, collection_digest: str,
    accepted_status: str | None = None,
    installed_route: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Retain the applicability proof that decides finite profile closure."""
    applicability = row.get("applicability")
    selected = row.get("selected_package_check")
    if type(applicability) is not dict:
        applicability = {}
    if type(selected) is not dict:
        selected = {}
    classification = applicability.get("classification")
    accepted = row.get("status") if accepted_status is None else accepted_status
    necessary = (
        accepted == "PASS"
        and row.get("checker_status") == "PASS"
        and applicability.get("status") == "PASS"
        and applicability.get("assessment_required") is True
        and classification == "NECESSARY"
        and selected.get("status") == "PASS"
        and selected.get("fulfillment_required") is not False
        and _selected_check_binds_route(
            route, selected, object_id=object_id,
            object_digest=object_digest,
            collection_digest=collection_digest,
        )
    )
    if installed_route is None:
        # Focused callers do not own a catalog snapshot. Package assessment
        # passes its already-selected canonical row so the full 281-route
        # catalog is not rebuilt once for every object/obligation clause.
        from verifier.runtime import manifest_gate
        installed = [
            candidate for candidate in manifest_gate.obligation_catalog()
            if candidate == route
        ]
        installed_route = installed[0] if len(installed) == 1 else None
    try:
        declaration = (
            validate_applicability_binding(installed_route)
            if installed_route == route else None
        )
    except (TypeError, ValueError):
        declaration = None
    source_adaptation = package_source_contracts.source_route_for_obligation(
        selected.get("adaptation_obligation_id")
    )
    refuted = (
        type(declaration) is dict
        and declaration.get("mode") == "CONDITIONAL"
        and not package_source_contracts.is_route(route)
        and accepted == "PASS"
        and row.get("checker_status") == "NOT_REQUIRED"
        and applicability.get("status") == "PASS"
        and applicability.get("assessment_required") is True
        and classification == "CONDITION_NOT_MET"
        and selected.get("status") == "PASS"
        and selected.get("evidence_origin")
            == "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
        and selected.get("applicability_established") is True
        and selected.get("applicability_classification") == "CONDITION_NOT_MET"
        and selected.get("fulfillment_required") is False
        and selected.get("condition") == declaration.get("condition")
        and selected.get("applicability_digest")
            == route.get("applicability_digest")
        and selected.get("condition_status") == "NOT_TRIGGERED"
        and selected.get("object_id") == object_id
        and selected.get("object_digest") == object_digest
        and selected.get("collection_digest") == collection_digest
        and selected.get("native_coordinate") == route["coordinate"]
        and selected.get("conditional_coordinate") == route["coordinate"]
        and type(source_adaptation) is dict
        and source_adaptation.get("tier") == route.get("tier")
        and source_adaptation.get("obligation_id")
            == selected.get("adaptation_obligation_id")
        and type(selected.get("adaptation_result_digest")) is str
        and selected["adaptation_result_digest"].startswith("sha256:")
        and selected.get("result_digest") == value_digest({
            key: value for key, value in selected.items()
            if key != "result_digest"
        })
    )
    closure = "PASS" if necessary or refuted else (
        "FAIL" if accepted == "FAIL" else "UNKNOWN"
    )
    return {
        "checker_status": row.get("checker_status"),
        "applicability": {
            "status": applicability.get("status"),
            "classification": classification,
            "assessment_required": applicability.get("assessment_required"),
            "reason": applicability.get("reason"),
        },
        "fulfillment_required": selected.get("fulfillment_required"),
        "condition": selected.get("condition"),
        "condition_status": selected.get("condition_status"),
        "evidence_origin": selected.get("evidence_origin"),
        "selected_check_digest": value_digest(selected) if selected else None,
        "closure_status": closure,
    }


def assess(tier: int, objects: tuple[NamespaceObject, ...], kinds: KindRequirements,
           instances: list[dict[str, Any]], *, verifier_id: str) -> dict[str, Any]:
    """Check a fresh internal result set against the entire required denominator.

This accepts only in-process outputs from the package evaluator, not portable
evidence. The surrounding evaluator owns source/manifest recapture and actual
checker execution. Missing rows refute the aggregation contract; a present row
with missing evidence remains UNKNOWN. No optional-obligation disposition exists.
"""
    from verifier.runtime.manifest_gate import obligation_catalog

    if type(tier) is not int or tier not in (1, 2, 3):
        raise ValueError("PACKAGE_CONTRACT_TIER_INVALID")
    subjects = {item.object_id: item for item in objects}
    selected_collection_digest = composition_digest(objects)
    if (len(subjects) != len(objects) or set(subjects) != set(kinds.objects)
            or verifier_id not in subjects or subjects[verifier_id].kind.value != "VERIFIER"):
        raise ValueError("PACKAGE_CONTRACT_OBJECT_SET_DIFFERS")
    routes = [row for row in obligation_catalog() if row["tier"] <= tier]
    if len({row["coordinate"] for row in routes}) != len(routes):
        raise ValueError("PACKAGE_CONTRACT_CATALOG_DUPLICATED")
    route_by_coordinate = {row["coordinate"]: row for row in routes}
    route_obligations = {
        coordinate: row["obligation_id"] for coordinate, row in route_by_coordinate.items()
    }
    profile_document = package_contract_profiles.document()
    matrix_document = package_contract_profiles.contract_coverage_matrix()
    matrix_kinds = matrix_document.get("kinds", {})
    slots = {(slot.object_kind.value, slot.tier.value): slot for slot in build_234_inventory()}
    def applies(identifier: str, route: dict[str, Any]) -> bool:
        if route["object_kind"] not in kinds.kinds(identifier):
            return False
        item = subjects[identifier]
        if package_source_contracts.is_route(route):
            return package_source_contracts.applies_to(
                item, kinds.declarations[identifier], route, kinds
            )
        if package_execution.route_mechanism(route) is not None:
            return package_execution.requires_route_assessment(
                kinds.declarations[identifier], route,
                selected_mechanisms=kinds.execution_mechanisms[identifier],
            )
        if added_kind_behavioral_routes.is_route(route):
            return True
        # ``route["object_kind"]`` is already present in the independently
        # derived effective-kind set above.  Use that required role to rebuild
        # the denominator, while the package-instance evaluator separately
        # refuses to cast a differently declared record into that role.
        return accepts_subject(route, route["object_kind"])

    expected = {
        (identifier, route["coordinate"]): route
        for identifier in subjects
        for route in routes
        if applies(identifier, route)
    }
    received: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in instances:
        received.setdefault((row["object_id"], row["coordinate"]), []).append(row)
    findings: list[dict[str, Any]] = []

    def reject(code: str, identifier: str, coordinate: str, explanation: str) -> None:
        route = expected.get((identifier, coordinate))
        findings.append({"code": code, "status": "FAIL", "object_id": identifier,
            "coordinate": coordinate, "obligation_id": route["obligation_id"] if route else None,
            # A focused checker can pass while package assembly still loses its
            # result. Re-run this whole denominator; clauses retain focused gates.
            "explanation": explanation, "rerun_argv": ["vstd", "polish", str(tier)]})

    # Static catalog/profile/schema presence is only the route plan. Surface a
    # broken plan in the same object-focused package report before considering
    # any instance result, rather than letting a specimen or smaller catalog
    # silently redefine the denominator.
    for matrix_finding in matrix_document.get("findings", []):
        kind = matrix_finding.get("kind")
        targets = [
            identifier for identifier in sorted(subjects)
            if type(kind) is str and kind in kinds.kinds(identifier)
        ] or [verifier_id]
        coordinate = matrix_finding.get("coordinate") or (
            (kind or "PACKAGE") + "-CONTRACT-MATRIX"
        )
        for identifier in targets:
            reject(
                matrix_finding["code"],
                identifier,
                coordinate,
                matrix_finding["reason"],
            )
            findings[-1]["obligation_id"] = matrix_finding.get("obligation_id")

    # Effective roles are additive. Independently close each inheritance chain
    # so a corrupted or substituted KindRequirements provider cannot erase the
    # OBJECT/POLICY/etc. base contract while retaining only a specialization.
    for identifier in sorted(subjects):
        effective = set(kinds.kinds(identifier))
        for kind in sorted(effective):
            try:
                required_roles = set(
                    package_contract_profiles.accumulated_roles(kinds.registry, kind)
                )
            except ValueError as error:
                reject(
                    "PACKAGE_CONTRACT_ACCUMULATED_ROLE_INVALID",
                    identifier,
                    kind + "-ROLE-ACCUMULATION",
                    str(error),
                )
                findings[-1]["obligation_id"] = kind + "-ROLE-ACCUMULATION"
                continue
            missing_roles = sorted(required_roles - effective)
            if missing_roles:
                reject(
                    "PACKAGE_CONTRACT_ACCUMULATED_ROLE_MISSING",
                    identifier,
                    kind + "-ROLE-ACCUMULATION",
                    (
                        kind + " requires accumulated base role(s) "
                        + ", ".join(missing_roles)
                        + "; a specialization never replaces inherited obligations."
                    ),
                )
                findings[-1]["obligation_id"] = kind + "-ROLE-ACCUMULATION"

    for identifier, coordinate in sorted(set(received) - set(expected)):
        reject("PACKAGE_CONTRACT_INSTANCE_UNEXPECTED", identifier, coordinate,
               "This result is outside the source-derived object/kind/tier denominator.")
    clauses: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for (identifier, coordinate), route in sorted(expected.items()):
        item = subjects[identifier]
        rows = received.get((identifier, coordinate), [])
        identity = {"object_id": identifier, "object_digest": item.digest, "coordinate": coordinate,
                    "tier": route["tier"], "proposition_digest": route["proposition_digest"]}
        binding = {**identity, "instance_digest": value_digest(identity),
                   "object_kind": route["object_kind"], "verifier_id": verifier_id,
                   "checking_mechanism": route["checking_mechanism"], "scope": route["scope"],
                   "native_specimen_is_instance_evidence": False}
        status, digest, source_row = "FAIL", None, {}
        if len(rows) != 1:
            reject("PACKAGE_CONTRACT_INSTANCE_MISSING" if not rows else "PACKAGE_CONTRACT_INSTANCE_DUPLICATED",
                   identifier, coordinate, "Exactly one current result is required for this object and installed proposition.")
        else:
            row = rows[0]
            source_row = row
            digest = value_digest(row)
            contradiction = True
            if value_digest({key: row.get(key) for key in binding}) != value_digest(binding):
                reject("PACKAGE_CONTRACT_INSTANCE_BINDING_DIFFERS", identifier, coordinate,
                       "The selected object, proposition, tier, checker or assigned VERIFIER differs from the expected clause.")
            else:
                applicability = row.get("applicability", {})
                selected_check = row.get("selected_package_check")
                necessary_pass = (
                    applicability.get("classification") == "NECESSARY"
                    and row.get("checker_status") == "PASS"
                )
                refuted_condition_pass = (
                    applicability.get("classification") == "CONDITION_NOT_MET"
                    and row.get("checker_status") == "NOT_REQUIRED"
                    and type(selected_check) is dict
                    and selected_check.get("fulfillment_required") is False
                    and selected_check.get("condition_status") == "NOT_TRIGGERED"
                )
                candidate = _clause_metadata(
                    route, row, object_id=identifier,
                    object_digest=item.digest,
                    collection_digest=selected_collection_digest,
                    accepted_status=row.get("status"),
                    installed_route=route,
                )
                contradiction = (
                    row.get("status") not in {"PASS", "FAIL", "UNKNOWN"}
                    or (row["status"] == "PASS" and (
                        row.get("blockers") != []
                        or applicability.get("status") != "PASS"
                        or not (necessary_pass or refuted_condition_pass)
                        or candidate["closure_status"] != "PASS"
                        or applicability.get("assessment_required") is not True
                        or not applicability.get("reason", "").strip()
                        or type(selected_check) is not dict
                        or selected_check.get("status") != "PASS"))
                )
            if contradiction:
                reject("PACKAGE_CONTRACT_VERDICT_CONTRADICTION", identifier, coordinate,
                       "A finite PASS requires the actual selected checker, established applicability and no unresolved blockers.")
            else:
                status = row["status"]
        reason = route.get("reason") or slots[(route["object_kind"], route["tier"])].rationale
        if not reason.strip() or not route["exact_claim"].strip():
            raise ValueError("PACKAGE_CONTRACT_REASON_OR_CLAIM_MISSING")
        clauses.setdefault((identifier, route["object_kind"]), []).append({
            "obligation_id": route["obligation_id"], "coordinate": coordinate, "tier": route["tier"],
            "semantic_version": route["semantic_version"], "proposition_digest": route["proposition_digest"],
            "reason": reason, "exact_claim": route["exact_claim"],
            "checking_mechanism": route["checking_mechanism"], "status": status,
            "result_digest": digest, "rerun_argv": ["vstd", "gate", "--object", identifier,
                "--obligation", route["obligation_id"]],
            **_clause_metadata(
                route, source_row, object_id=identifier,
                object_digest=item.digest,
                collection_digest=selected_collection_digest,
                accepted_status=status,
                installed_route=route,
            )})
    contracts = []
    for identifier in sorted(subjects):
        for kind in sorted(kinds.kinds(identifier)):
            selected = clauses.get((identifier, kind), [])
            statuses = Counter(row["closure_status"] for row in selected)
            installed_profile = package_contract_profiles.profile(kind)
            profile = (
                installed_profile
                if installed_profile is not None and any(
                    row["coordinate"] in set(installed_profile["source_routes"].values())
                    for row in selected
                ) else None
            )
            required = (
                {
                    row["coordinate"]
                    for row in matrix_kinds.get(kind, {}).get("routes", [])
                    if row.get("tier") in range(1, tier + 1)
                }
                if profile is not None else set()
            )
            observed = {row["coordinate"] for row in selected}
            missing = sorted(required - observed)
            unexpected = sorted(observed - required) if profile is not None else []
            for coordinate in missing:
                route = route_by_coordinate.get(coordinate)
                reject("PACKAGE_CONTRACT_PROFILE_INSTANCE_MISSING", identifier,
                       coordinate,
                       "The installed package-variant profile requires this source or behavioral route, but no current instance was assessed.")
                if route is None:
                    findings[-1]["obligation_id"] = coordinate
            for coordinate in unexpected:
                reject("PACKAGE_CONTRACT_PROFILE_ROUTE_UNEXPECTED", identifier,
                       coordinate,
                       "A current route is outside the independently pinned package-variant profile; update the profile rather than silently widening closure.")
            finite = (
                "FAIL" if statuses["FAIL"] or missing or unexpected else
                "PASS" if selected and statuses["PASS"] == len(selected) else
                "UNKNOWN"
            )
            matrix_obligations = {
                row["obligation_id"]: row
                for row in matrix_kinds.get(kind, {}).get(
                    "profile_obligations", []
                )
                if type(row) is dict
                and type(row.get("obligation_id")) is str
            }
            residuals = _residuals(
                kind,
                tier,
                kinds,
                slots,
                selected,
                matrix_obligations,
                route_obligations=route_obligations,
            )
            for residual in residuals:
                action = residual.get("next_action")
                if type(action) is list:
                    residual["next_action"] = [identifier if value == "{object_id}" else value
                                               for value in action]
            profile_status = (
                "NOT_PROFILED" if profile is None else
                "PASS" if finite == "PASS" and not residuals else
                "FAIL" if finite == "FAIL" else "UNKNOWN"
            )
            contracts.append({"object_id": identifier, "object_digest": subjects[identifier].digest,
                "kind": kind, "kind_requirement": kinds.basis(identifier, kind),
                "profile_version": None if profile is None else profile["profile_version"],
                "profile_digest": None if profile is None else profile["profile_digest"],
                "profile_status": profile_status,
                "bounded_exclusions": (
                    [] if installed_profile is None
                    else installed_profile["bounded_exclusions"]
                ),
                "finite_check_status": finite, "clauses": selected,
                "residual_requirements": residuals,
                "status": ("FAIL" if finite == "FAIL" else "PASS"
                           if profile_status == "PASS" and not residuals else "UNKNOWN")})
    package_global_residuals = _package_global_applicability_residuals(
        matrix_document,
        subjects,
        kinds,
        verifier_id=verifier_id,
    )
    if package_global_residuals:
        verifier_contract = next(
            (
                row for row in contracts
                if row["object_id"] == verifier_id and row["kind"] == "VERIFIER"
            ),
            None,
        )
        if verifier_contract is None:
            reject(
                "PACKAGE_CONTRACT_GLOBAL_APPLICABILITY_TARGET_MISSING",
                verifier_id,
                "PACKAGE-INSTANCE-APPLICABILITY",
                "Package-global consequence residuals require the admitted VERIFIER contract.",
            )
        else:
            verifier_contract["residual_requirements"].extend(
                package_global_residuals
            )
            if verifier_contract["profile_status"] != "FAIL":
                verifier_contract["profile_status"] = "UNKNOWN"
            if verifier_contract["status"] != "FAIL":
                verifier_contract["status"] = "UNKNOWN"
    aggregate_status = ("FAIL" if findings or any(row["status"] == "FAIL" for row in contracts)
                        else "PASS" if contracts and all(row["status"] == "PASS" for row in contracts)
                        else "UNKNOWN")
    report = {"schema_version": SCHEMA, "through_tier": tier,
        "registry_digest": registry_document(kinds.registry)["digest"],
        "profile_registry_digest": profile_document["document_digest"],
        "collection_digest": selected_collection_digest,
        "source_census_digest": kinds.report["source_census_digest"], "verifier_id": verifier_id,
        "expected_instance_count": len(expected), "observed_instance_count": len(instances),
        "denominator_status": "FAIL" if findings else "PASS",
        "finite_check_status": ("FAIL" if findings or any(row["finite_check_status"] == "FAIL" for row in contracts)
                                else "PASS" if contracts and all(row["finite_check_status"] == "PASS" for row in contracts) else "UNKNOWN"),
        "status": aggregate_status,
        "normative_coverage": "PASS" if aggregate_status == "PASS" else "NOT_ESTABLISHED",
        "contracts": contracts, "findings": findings,
        "claim_boundary": "Internal current-result aggregation for exact installed source-representation and native-route applicability contracts. Package-global MARKET, ROBOT and FINBOT applicability remains verifier-bound even when zero effective objects carry a family. PASS is bounded to the selected source GRAPH; it is not runtime-domain truth, external authority, confinement, release or deployment. An empty finite route set is not PASS."}
    return {**report, "assessment_digest": value_digest(report)}
