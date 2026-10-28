"""Readable manifest-object gates for Verifier Standard (VSTD).

An identifier (ID) selects a registered proposition, not a caller-authored verdict.
JavaScript Object Notation (JSON) reports preserve source and selection binding.
American Standard Code for Information Interchange (ASCII) spelling rules keep
identifiers portable across the supported command surfaces.
Missing package-instance evidence never selects a native specimen instead.
"""
from __future__ import annotations

import argparse
import functools
import json
from pathlib import Path
import re
import shlex
from typing import Any

from verifier.domains import inventory as domain_inventory
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import core_tier_progression
from verifier.runtime.tier_zero_profile import (
    applicability_digest,
    validate_applicability_binding,
)


REPORT_SCHEMA = "verifier-manifest-object-gate-1"
_NAMES = {
    "generic_canonical_representation_and_address": (
        "canonical-representation-and-address", "Canonical representation and address"),
    "finite_kind_specific_declared_operand_facets": (
        "declared-operand-facets", "Declared operand facets"),
}
_COORDINATE_NAMES = {
    "SIM-2.4": ("signed-transition-resource-records", "Signed transition resource records"),
}
_ADMISSION_GATES = (
    "manifest-admission", "object-inventory", "typed-composition", "exposed-surface-coverage",
    "obligation-inventory", "reason-binding", "source-freshness", "independent-reconciliation",
    "verdict-boundary",
)
_GAPS = {
    "PACKAGE_INSTANCE_TYPED_REPRESENTATION_UNRESOLVED": (
        "typed-representation", "UNKNOWN",
        "Source, classification or consequence evidence adds this kind's obligation, but the selected record has a different base kind.",
        "Bind the actual typed subject and its required operands in objects.vstd; do not cast the generic record or reuse another role's certificate."),
    "PACKAGE_INSTANCE_SELECTION_REFUTED": (
        "instance-evidence", "FAIL", "The selected instance inputs or their native replay contradict the exact binding.",
        "Inspect the selected evidence paths and native result; preserve the exact subject, graph, request and policy."),
    "PACKAGE_INSTANCE_SELECTION_UNAVAILABLE": (
        "instance-evidence", "UNKNOWN", "Selected instance evidence or its supported binding is unavailable.",
        "Restore the named selected evidence or supported subject-binding adapter; no specimen fallback is used."),
    "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED": (
        "applicability", "UNKNOWN",
        "No object-specific necessity reason or evidenced refutation of a conditional trigger is established.",
        "Supply source-bound applicability evidence for this exact object and proposition; it is not an optional obligation."),
    "PACKAGE_INSTANCE_EVIDENCE_MISSING": (
        "instance-evidence", "UNKNOWN",
        "No package-instance input is connected to this registered checker. No process execution or certificate replay was performed for this instance.",
        "Bind the exact object's selected request, policy, retained evidence and supported runner. A native specimen is not this object's evidence."),
    "PACKAGE_INSTANCE_SEMANTIC_FULFILLMENT_NOT_ESTABLISHED": (
        "semantic-fulfillment", "UNKNOWN",
        "The bounded structural checker passed, but that does not establish semantic fulfillment for this repository object.",
        "Discharge the recorded applicability and residual semantic obligations using evidence for this object."),
    "PACKAGE_INSTANCE_CHECK_REFUTED": (
        "native-check", "FAIL", "The selected package-instance checker was refuted.",
        "Inspect the selected package check and its positive/negative/missing-evidence outcomes; repair the contradicted proposition."),
    "PACKAGE_INSTANCE_CHECK_UNAVAILABLE": (
        "native-check", "UNKNOWN", "The selected package-instance checker did not establish its result.",
        "Restore the required evidence or bounded checking resources and rerun this selection."),
}


def obligation_catalog() -> list[dict[str, Any]]:
    """Return names bound to the current registered semantics, never inferred variants."""
    rows = []
    declarations = core_tier_progression.installed_core_route_declarations()
    for cell in core_tier_progression.installed_core_route_inventory()["family_cells"]:
        for route in cell["registered_route_memberships"]:
            coordinate = route["coordinate"]
            declaration = declarations[
                cell["object_kind"], cell["tier"], coordinate
            ]
            scope = route["scope"]
            label = re.sub(r"^finite_(?:retained_|kind_specific_)?", "", scope)
            slug, name = _COORDINATE_NAMES.get(coordinate, _NAMES.get(
                scope, (label.replace("_", "-"), label.replace("_", " ").capitalize())))
            rows.append({**route, **declaration,
                         "object_kind": cell["object_kind"], "tier": cell["tier"],
                         "obligation_id": coordinate + "-" + slug, "obligation_name": name,
                         "exact_claim": domain_inventory.MECHANIZED_12_POINT_BINDINGS[coordinate]["exact_claim"]})
    from verifier.runtime.package_execution import catalog
    from verifier.runtime.added_kind_behavioral_routes import (
        catalog as added_kind_catalog,
    )
    from verifier.runtime.package_source_contracts import catalog as source_catalog
    combined = rows + catalog() + added_kind_catalog() + source_catalog()
    bound = []
    for route in combined:
        selected = dict(route)
        # The retained added-kind producer predates the dedicated digest; the
        # readable package-gate projection binds its already-canonical
        # declaration without rewriting that route's native proposition digest.
        if "applicability" in selected and "applicability_digest" not in selected:
            selected["applicability_digest"] = applicability_digest(
                selected["applicability"]
            )
        validate_applicability_binding(selected)
        bound.append(selected)
    return bound


def _rerun(object_id: str, obligation_id: str) -> list[str]:
    return ["vstd", "gate", "--object", object_id, "--obligation", obligation_id]


_FOCUS_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_INVOCATION_OBLIGATION = "CLI-PREREQUISITE-complete-gate-selectors"
_VALID_SELECTOR_OBLIGATION = "CLI-PREREQUISITE-valid-gate-selectors"


def _valid_focus_identifier(value: Any, *, maximum: int) -> bool:
    return bool(
        type(value) is str
        and 0 < len(value) <= maximum
        and _FOCUS_IDENTIFIER.fullmatch(value)
    )


def _invocation_report(
    code: str,
    status: str,
    explanation: str,
    *,
    object_id: Any = None,
    obligation_id: Any = None,
) -> dict[str, Any]:
    """Return a bounded actionable error without echoing malformed selectors."""

    selected_object = (
        object_id if _valid_focus_identifier(object_id, maximum=256) else None
    )
    selected_obligation = (
        obligation_id
        if _valid_focus_identifier(obligation_id, maximum=512)
        else _INVOCATION_OBLIGATION
        if code == "PACKAGE_GATE_SELECTORS_REQUIRED"
        else _VALID_SELECTOR_OBLIGATION
    )
    if code == "PACKAGE_GATE_SELECTORS_REQUIRED":
        selected_obligation = _INVOCATION_OBLIGATION
        obligation_name = "Complete focused gate selectors"
        next_action = (
            "Use vstd gate --help, then provide one valid manifest object ID and "
            "one valid registered obligation ID."
        )
    else:
        selected_obligation = _VALID_SELECTOR_OBLIGATION
        obligation_name = "Valid focused gate selectors"
        next_action = (
            "Use vstd gate --help, then provide identifiers beginning with an "
            "ASCII letter or digit and containing only letters, digits, dot, "
            "underscore, colon, slash, or hyphen within the documented lengths."
        )
    rerun = ["vstd", "gate", "--help"]
    finding = {
        "scope": "object" if selected_object is not None else "repository",
        "object_id": selected_object,
        "object_kind": None,
        "coordinate": None,
        "obligation_id": selected_obligation,
        "obligation_name": obligation_name,
        "semantic_version": None,
        "gate_id": "target-selection",
        "status": status,
        "code": code,
        "reason": explanation,
        "explanation": explanation,
        "next_action": next_action,
        "rerun_argv": rerun,
    }
    body = {
        "schema_version": "verifier-manifest-object-gate-invocation-1",
        "status": status,
        "error": code,
        "scope": finding["scope"],
        "object_id": selected_object,
        "obligation_id": selected_obligation,
        "obligation_name": obligation_name,
        "gate_id": "target-selection",
        "reason": explanation,
        "explanation": explanation,
        "next_action": next_action,
        "rerun_argv": rerun,
        "findings": [finding],
        "polished": False,
        "release_authorized": False,
        "claim_boundary": (
            "Invocation validation only; no manifest, object, obligation, or "
            "package conformance assessment was executed."
        ),
    }
    return {**body, "report_digest": binding.value_digest(body)}


_ORIGINAL_KIND_CLOSURE_OBLIGATION_ID = (
    "VSTD-T0.2-object-denominator-closure"
)


_CATALOG_CONTRADICTION_PREFIX = "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:"
_SOURCE_BINDING_PREFIX = "PACKAGE_ORIGINAL_KIND_SOURCE_"
# Decision-level blockers emitted by package_original_kind_catalog._decision_binding_blocker.
_DECISION_BINDING_CLAUSES = {
    "DECISION_UNRESOLVED": (
        "has no APPLIES or DOES_NOT_APPLY decision with a nonempty reason and evidence list",
        "Audit this exact object and kind against its owned current source, then record the decision with its reason and evidence.",
    ),
    "EVIDENCE_MALFORMED": (
        "has an evidence reference that is not exactly {path, sha256} with a nonempty path",
        "Rewrite each evidence reference as exactly {path, sha256} naming a file declared by this object.",
    ),
    "EVIDENCE_DIGEST_MALFORMED": (
        "has an evidence digest that is not canonical sha256:<64 lowercase hex>",
        "Recompute the evidence digest from the current file bytes in canonical form.",
    ),
    "SOURCE_INVENTORY_ABSENT": (
        "has no current source inventory against which its evidence can be bound",
        "Restore the current source census for this root, then rerun this gate.",
    ),
    "EVIDENCE_PATH_UNOWNED": (
        "cites evidence outside this object's current manifest-declared file surfaces",
        "Cite only files declared in this object's surfaces, or re-audit those surfaces against source.",
    ),
    "EVIDENCE_PATH_NOT_IN_INVENTORY": (
        "cites evidence absent from the current source inventory",
        "Restore the cited file within the source census, or re-audit this cell against current source.",
    ),
    "EVIDENCE_DIGEST_STALE": (
        "cites evidence whose recorded sha256 differs from the current file bytes",
        "Re-audit the cited current bytes, record their digest, and rerun; do not reuse the stale digest.",
    ),
}
# Denominator-level refusals emitted by package_original_kind_catalog.  These
# are more specific than DECISION_UNRESOLVED and therefore take precedence in
# the focused diagnostic when both are present.
_DOES_NOT_APPLY_DENOMINATOR_CLAUSES = {
    "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE": (
        "does not cite every file of the object's validated owned-file denominator",
        "Cite every owned file of this object, each once with its current "
        "sha256, in one DOES_NOT_APPLY refutation; until then the cell stays "
        "UNRESOLVED.",
    ),
    "DOES_NOT_APPLY_EVIDENCE_PATH_DUPLICATED": (
        "cites an owned file more than once",
        "List each owned file of this object exactly once in the refutation's "
        "evidence.",
    ),
    "DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN": (
        "the owned-file denominator or its source census is unavailable",
        "Restore this object's validated owned-file set and its current source "
        "census, then rerun this gate.",
    ),
    "DOES_NOT_APPLY_SOURCE_DRIFT": (
        "cites owned files that changed since their refutation was effect-audited",
        "Re-audit the owned files at their current bytes, record their fresh "
        "digests, and rerun from a quiescent tree.",
    ),
    "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED": (
        "has an unclosed effect boundary such as dynamic execution, unsupported language, callbacks, or unresolved imports",
        "Close the named effect boundary (dynamic execution, unsupported "
        "language, callbacks, or unresolved imports) in the owned source, or "
        "keep this cell UNRESOLVED.",
    ),
}
# Whole-snapshot failures from tier_zero; they bind no decision, so they never refute one.
_SOURCE_BINDING_CLAUSES = {
    "MUTATED": (
        "the source snapshot changed between the opening and closing census, so no decided cell is bound to a stable snapshot",
        "Rerun from a quiescent tree; the opening and closing censuses must agree.",
    ),
    "CLOSING_UNAVAILABLE": (
        "the closing source census was unavailable",
        "Restore the closing source census for this root, then rerun this gate.",
    ),
    "INVENTORY_UNAVAILABLE": (
        "the opening source census was unavailable",
        "Resolve the named census refusal, restore the source census for this root, then rerun this gate.",
    ),
}


def _binding_clauses(
    code: str,
    binding_blocker: str | None,
    denominator_blocker: str | None,
) -> tuple[list[str], list[str]]:
    """Return the cause clauses and next actions for a non-refutation closure cell."""
    clauses: list[str] = []
    actions: list[str] = []
    if code.startswith(_SOURCE_BINDING_PREFIX):
        key, _, detail = code[len(_SOURCE_BINDING_PREFIX):].partition(":")
        clause, action = _SOURCE_BINDING_CLAUSES.get(key, (
            "the source binding could not be established",
            "Restore the current source binding for this root, then rerun this gate.",
        ))
        if detail:
            clause += " (refusal " + detail + ")"
        clauses.append(clause)
        actions.append(action)
    if denominator_blocker is not None:
        if denominator_blocker not in _DOES_NOT_APPLY_DENOMINATOR_CLAUSES:
            raise ValueError(
                "ORIGINAL_KIND_DENOMINATOR_BLOCKER_UNKNOWN:"
                + denominator_blocker
            )
        clause, action = _DOES_NOT_APPLY_DENOMINATOR_CLAUSES[denominator_blocker]
        clauses.append(clause)
        actions.append(action)
    elif binding_blocker is not None:
        if binding_blocker not in _DECISION_BINDING_CLAUSES:
            raise ValueError("ORIGINAL_KIND_BINDING_BLOCKER_UNKNOWN:" + binding_blocker)
        clause, action = _DECISION_BINDING_CLAUSES[binding_blocker]
        clauses.append(clause)
        actions.append(action)
    return clauses, actions


def original_kind_closure_finding(
    *,
    object_id: str,
    object_kind: str | None,
    classification_kind: str,
    status: str,
    code: str,
    binding_blocker: str | None = None,
    denominator_blocker: str | None = None,
) -> dict[str, Any]:
    """Locate one fail-closed original-kind cell at the existing T0.2 gate.

    Only a genuine catalog contradiction is a FAIL.  Missing, stale, unowned,
    malformed, or unbindable evidence and any source-snapshot failure are UNKNOWN
    whatever ``status`` the caller reports: they show that the cell is not
    established, not that the source-audited decision is wrong.  ``binding_blocker``
    names the exact decision-level cause so the reason is specific.
    """
    contradiction = code.startswith(_CATALOG_CONTRADICTION_PREFIX)
    status = "FAIL" if contradiction else "UNKNOWN"
    clauses, actions = _binding_clauses(
        code, binding_blocker, denominator_blocker
    )
    if contradiction:
        reason = (
            "The declared original-kind cell for object "
            + object_id
            + " and kind "
            + classification_kind
            + " contradicts the explicit source-audited catalog decision."
        )
        next_action = (
            "Restore the source-audited status, reason, and exact current-source "
            "evidence for this cell; do not replace it with an inferred label."
        )
    elif clauses:
        reason = (
            "The original-kind applicability cell for object "
            + object_id
            + " and kind "
            + classification_kind
            + " is not bound to current source: "
            + "; ".join(clauses)
            + ". The exact 11,650-cell package classification denominator is not closed."
        )
        next_action = " ".join(actions)
    else:
        reason = (
            "The original-kind applicability cell for object "
            + object_id
            + " and kind "
            + classification_kind
            + " is missing, malformed, UNRESOLVED, reasonless, or evidence-free. "
            "The exact 11,650-cell package classification denominator is not closed."
        )
        next_action = (
            "Audit this exact object/kind against its owned current source, then "
            "bind APPLIES with required obligations or DOES_NOT_APPLY with an "
            "explicit source-grounded refutation."
        )
    return _reasoned_finding(
        {
            "scope": "object",
            "object_id": object_id,
            "object_kind": object_kind,
            "classification_kind": classification_kind,
            "coordinate": "VSTD-T0.2",
            "obligation_id": _ORIGINAL_KIND_CLOSURE_OBLIGATION_ID,
            "obligation_name": "Object denominator closure",
            "semantic_version": None,
            "gate_id": "object-inventory",
            "status": status,
            "code": code,
            "reason": reason,
            "explanation": reason,
            "next_action": next_action,
            "rerun_argv": _rerun(
                object_id, _ORIGINAL_KIND_CLOSURE_OBLIGATION_ID
            ),
        }
    )


def _reasoned_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Expose one normalized failure reason without discarding detailed prose.

    ``explanation`` remains the backwards-compatible diagnostic field.  The
    explicit ``reason`` alias is the stable, human-facing contract used by
    focused remediation tooling and by the package-polish failure summary.
    """
    selected = dict(finding)
    reason = selected.get("reason")
    if type(reason) is not str or not reason.strip():
        reason = selected.get("explanation")
    if type(reason) is not str or not reason.strip():
        reason = selected.get("assessment_reason")
    if type(reason) is not str or not reason.strip():
        reason = selected.get("code")
    if type(reason) is not str or not reason.strip():
        reason = "Unspecified verification failure."
    selected["reason"] = reason
    return selected


def _admission_catalog() -> list[dict[str, Any]]:
    from verifier.runtime.tier_zero_profile import installed_tier_zero_profile
    rows = [{**row, "obligation_id": row["coordinate"] + "-" + row["name"].lower().replace(" ", "-"),
             "obligation_name": row["name"], "gate_id": _ADMISSION_GATES[index],
             "tier": 0, "exact_claim": row["question"]}
            for index, row in enumerate(installed_tier_zero_profile()["obligations"])]
    for row in rows:
        validate_applicability_binding(row)
    return rows


def admission_findings(report: dict[str, Any], object_id: str | None = None) -> list[dict[str, Any]]:
    if report.get("schema_version") == "verifier-tier-zero-package-admission-report-4":
        return [_reasoned_finding(item) for item in report["findings"]]
    if report.get("schema_version") == "verifier-tier-zero-package-admission-report-3":
        return admission_findings(report["retained_admission"], object_id) + [
            _reasoned_finding(item)
            for item in report["namespace_admission"]["findings"]
        ]
    if report.get("schema_version") == "verifier-tier-zero-repository-admission-report-2":
        # Version 2 already carries per-object, evidence-near findings. Rebuilding
        # them through the legacy fixed-kind catalog would erase that context.
        return [_reasoned_finding(item) for item in report["findings"]]
    named = {row["coordinate"]: row for row in _admission_catalog()}
    findings = []
    for row in report["obligations"]:
        if row["status"] == "PASS":
            continue
        name = named[row["coordinate"]]
        for code in row["blockers"]:
            finding = repository_finding(code, row["status"], object_id=object_id,
                                         obligation_id=name["obligation_id"])
            finding.update(coordinate=row["coordinate"], obligation_name=name["name"],
                           gate_id=name["gate_id"], explanation=row["assessment_reason"])
            findings.append(finding)
    if not report["obligations"]:
        findings.extend(repository_finding(code, report["status"], object_id=object_id)
                        for code in report["blockers"])
    return [_reasoned_finding(item) for item in findings]


def instance_findings(row: dict[str, Any], named: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for code in row["blockers"]:
        gate, status, explanation, next_action = _GAPS[code]
        if code.startswith("PACKAGE_INSTANCE_SELECTION_"):
            explanation += " " + row["selected_package_check"]["reason"]
        findings.append(_reasoned_finding({
            "scope": "object", "object_id": row["object_id"], "object_kind": row["object_kind"],
            "coordinate": row["coordinate"], "obligation_id": named["obligation_id"],
            "obligation_name": named["obligation_name"], "semantic_version": named["semantic_version"],
            "gate_id": gate, "status": status, "code": code,
            "explanation": explanation, "next_action": next_action,
            "rerun_argv": _rerun(row["object_id"], named["obligation_id"]),
        }))
    return findings


_UNRESOLVED_OBLIGATION_NAME = "Unresolved obligation identity"
_UNRESOLVED_GATE = "obligation-resolution"
_INSTANCE_GATE = "obligation-instance"
_NAMESPACE_ADMISSION_GATE = "namespace-admission"


@functools.lru_cache(maxsize=1)
def _admission_identities() -> dict[str, dict[str, Any]]:
    """Return tier-zero and namespace-admission identities, which register gates."""
    rows: dict[str, dict[str, Any]] = {}
    for row in _admission_catalog():
        coordinate = row["coordinate"]
        rows[row["obligation_id"]] = {
            "coordinate": coordinate, "obligation_name": row["obligation_name"],
            "gate_id": row["gate_id"], "tier": 0, "object_kind": None,
        }
        # The namespace route registers this suffix under the same coordinate. Its
        # dimension names differ from the tier-zero profile (for example VSTD-T0.2),
        # so this identity names the coordinate rather than choosing either name.
        rows[coordinate + "-namespace-admission"] = {
            "coordinate": coordinate,
            "obligation_name": "Namespace admission (" + coordinate + ")",
            "gate_id": _NAMESPACE_ADMISSION_GATE, "tier": 0, "object_kind": None,
        }
    return rows


@functools.lru_cache(maxsize=1)
def _route_identities() -> dict[str, dict[str, Any]]:
    """Return tier-one-plus route identities; route rows register no gate."""
    return {
        row["obligation_id"]: {
            "coordinate": row["coordinate"], "obligation_name": row["obligation_name"],
            "gate_id": None, "tier": row["tier"], "object_kind": row["object_kind"],
        }
        for row in obligation_catalog()
    }


def _registered_identity(obligation_id: Any) -> dict[str, Any] | None:
    """Return the identity registered for one exact ID, or ``None`` if unresolved."""
    if type(obligation_id) is not str:
        return None
    found = _admission_identities().get(obligation_id)
    if found is None:
        found = _route_identities().get(obligation_id)
    return None if found is None else dict(found)


def _producer_identity(obligation_id: Any, *, coordinate: Any, gate: Any,
                       object_kind: Any) -> dict[str, Any]:
    """Return the producer's identity fields only where the registry defines none.

    An unresolved ID keeps the producer's coordinate, gate, and kind beside its
    visibly unresolved name. A tier-one-plus route registers a coordinate and kind
    but no gate, so the producer's gate applies. Tier-zero and namespace
    registrations control every field.
    """
    registered = _registered_identity(obligation_id)
    if registered is None:
        return {"coordinate": coordinate, "gate_id": gate, "object_kind": object_kind}
    if registered["gate_id"] is None:
        return {"gate_id": gate}
    return {}


def _code_identity(code: str) -> tuple[str, str | None]:
    """Return the default gate and coordinate that a blocker code's tokens name."""
    if "MANIFEST" in code:
        return "manifest-admission", "VSTD-T0.1"
    if "OBJECT_GRAPH" in code or "COMPOSITION" in code:
        return "typed-composition", "VSTD-T0.3"
    if "ORIGINAL_KIND_CATALOG" in code or "OBJECT_DENOMINATOR" in code:
        return "object-inventory", "VSTD-T0.2"
    if "SOURCE" in code or "RECAPTURE" in code or "MECHANISM_CHANGED" in code:
        return "source-freshness", "VSTD-T0.7"
    if "REASON" in code:
        return "reason-binding", "VSTD-T0.6"
    if code.startswith("PACKAGE_GATE_"):
        return "target-selection", None
    if "NORMATIVE_COVERAGE" in code:
        return "package-obligation-coverage", None
    if "NATIVE_DIAGNOSTICS" in code:
        return "source-native-diagnostics", None
    return "package-assessment", None


def repository_finding(code: str, status: str, *, object_id: str | None = None,
                       obligation_id: str | None = None, tier: int = 0) -> dict[str, Any]:
    """Name every prerequisite and retain one executable remediation route.

    An explicit ``obligation_id`` owns the identity: its registered coordinate,
    name, and gate are reported, or a visibly unresolved marker is when it is not
    registered. ``code`` never infers those fields for an explicit ID. Without an
    explicit ID, ``code`` selects the default identity. The supplied ID is never
    rewritten.
    """

    selected_tier = tier if type(tier) is int and 0 <= tier <= 9 else 0
    explicit = bool(obligation_id)
    registered = _registered_identity(obligation_id) if explicit else None
    unresolved = explicit and registered is None
    object_kind = None
    if registered is not None:
        selected_id = obligation_id
        coordinate = registered["coordinate"]
        selected_name = registered["obligation_name"]
        gate = registered["gate_id"] or _INSTANCE_GATE
        object_kind = registered["object_kind"]
        selected_tier = registered["tier"]
    elif explicit:
        selected_id = obligation_id
        coordinate, gate = None, _UNRESOLVED_GATE
        selected_name = _UNRESOLVED_OBLIGATION_NAME
    else:
        gate, coordinate = _code_identity(code)
        profile_name = None
        if coordinate:
            from verifier.runtime.tier_zero_profile import installed_tier_zero_profile
            profile_name = next(row["name"] for row in installed_tier_zero_profile()["obligations"]
                                if row["coordinate"] == coordinate)
        package_slug = re.sub(r"[^a-z0-9]+", "-", code.lower()).strip("-")
        package_slug = package_slug[:460] or "unspecified-package-prerequisite"
        package_id = "PACKAGE-PREREQUISITE-" + package_slug
        selected_id = (
            coordinate + "-" + profile_name.lower().replace(" ", "-")
            if coordinate else package_id
        )
        selected_name = profile_name or code.replace("_", " ").title()
    focusable = bool(object_id and (explicit or coordinate))
    explanations = {
        "PACKAGE_MANIFEST_MISSING": "The selected root has no objects.vstd. No object or obligation assessment can start.",
        "PACKAGE_GATE_OBJECT_NOT_DECLARED": "The selected object ID does not occur in this root's objects.vstd.",
        "PACKAGE_GATE_OBJECT_KIND_DIFFERS": "The registered obligation belongs to a different kind than the selected object.",
        "PACKAGE_GATE_OBLIGATION_NOT_REGISTERED": "The exact readable obligation ID is not registered. No similarly named route or variant was substituted.",
        "PACKAGE_NORMATIVE_COVERAGE_NOT_ESTABLISHED": "The installed route inventory does not establish that all necessary concrete-package obligations have been identified.",
        "PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS": "A source-native diagnostic or prerequisite did not pass. This is distinct from a package-instance verdict; inspect native_diagnostics.",
    }
    explanation = explanations.get(code, code.replace("_", " ").capitalize() + ".")
    next_action = (
        "Resolve this reported prerequisite without substituting objects, "
        "evidence or a passing specimen, then run the retained rerun_argv."
    )
    if unresolved:
        explanation += (
            ' Explicit obligation ID "' + str(obligation_id) + '" is not resolved by the '
            "installed package-gate catalog; its coordinate, name, and gate were not "
            "inferred from " + code + "."
        )
        next_action = (
            "Restore the registration of this exact obligation ID, or cite a registered "
            "ID, then run the retained rerun_argv. No coordinate, name, or gate was "
            "inferred from the blocker code."
        )
    rerun = (
        _rerun(object_id, selected_id)
        if focusable else ["vstd", "polish", str(selected_tier), "--json"]
    )
    return _reasoned_finding({"scope": "object" if object_id else "repository", "object_id": object_id,
            "object_kind": object_kind, "coordinate": coordinate, "obligation_id": selected_id,
            "obligation_name": selected_name, "semantic_version": None,
            "gate_id": gate, "status": status, "code": code,
            "explanation": explanation,
            "next_action": next_action,
            "rerun_argv": rerun})


_NATIVE_NONPASS_FINDING_LIMIT = 64


def _native_nonpass_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Promote bounded exact native loci without replacing the aggregate gate."""

    native = report.get("native_diagnostics")
    if type(native) is not dict:
        return []
    record_groups: list[Any] = []
    prerequisites = native.get("prerequisites")
    if type(prerequisites) is dict:
        for depth in sorted(prerequisites):
            prerequisite = prerequisites[depth]
            if type(prerequisite) is dict:
                record_groups.append(prerequisite.get("nonpass_records"))
    detail = native.get("nonpass_detail")
    if type(detail) is dict:
        record_groups.append(detail.get("nonpass_records"))

    findings: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for records in record_groups:
        if type(records) is not list:
            continue
        for record in records:
            if len(findings) >= _NATIVE_NONPASS_FINDING_LIMIT:
                return findings
            if type(record) is not dict:
                continue
            path = record.get("path")
            object_id = record.get("object_id")
            obligation_id = record.get("obligation_id")
            if not (
                type(path) is str and 0 < len(path) <= 4096
                and type(object_id) is str and 0 < len(object_id) <= 256
                and type(obligation_id) is str
                and 0 < len(obligation_id) <= 512
            ):
                continue
            blockers = record.get("blockers")
            selected_blockers = (
                [item for item in blockers if type(item) is str and item]
                if type(blockers) is list else []
            )
            code = (
                selected_blockers[0]
                if selected_blockers
                else "PACKAGE_NATIVE_DIAGNOSTIC_NONPASS"
            )
            status = "FAIL" if record.get("status") == "FAIL" else "UNKNOWN"
            gate = record.get("gate_id")
            if type(gate) is not str or not gate:
                gate = "source-native-diagnostics"
            coordinate = record.get("coordinate")
            if type(coordinate) is not str or not coordinate:
                coordinate = None
            object_kind = record.get("object_kind", record.get("kind"))
            if type(object_kind) is not str or not object_kind:
                object_kind = None
            reason = next((
                record[field]
                for field in ("reason", "assessment_reason", "explanation")
                if type(record.get(field)) is str and record[field].strip()
            ), code.replace("_", " ").capitalize() + ".")
            identity = (
                path, object_id, obligation_id, gate, coordinate, code, status,
            )
            if identity in seen:
                continue
            seen.add(identity)
            rerun = record.get("rerun_argv")
            if not (
                type(rerun) is list
                and rerun == [
                    "vstd", "gate", "--object", object_id,
                    "--obligation", obligation_id,
                ]
            ):
                rerun = _rerun(object_id, obligation_id)
            explanation = f"{reason} Native diagnostic path: {path}."
            located = repository_finding(
                code, status, object_id=object_id,
                obligation_id=obligation_id,
            )
            located.update(
                **_producer_identity(
                    obligation_id, coordinate=coordinate, gate=gate,
                    object_kind=object_kind,
                ),
                reason=explanation,
                explanation=explanation,
                diagnostic_path=path,
                next_action=(
                    f"Inspect the exact native diagnostic at {path}, then rerun "
                    "the focused object obligation."
                ),
                rerun_argv=rerun,
            )
            findings.append(located)
    return findings


def package_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Locate instance gaps without pretending package-wide failures have an object."""
    findings = []
    rows = report["obligation_instances"]
    if rows:
        named = {row["coordinate"]: row for row in obligation_catalog()}
        for row in rows:
            # The independent coverage checker can expose an unregistered result.
            # Do not crash while trying to name the very substitution it rejected.
            if row["coordinate"] in named:
                findings.extend(instance_findings(row, named[row["coordinate"]]))
    for item in report.get("kind_requirements", {}).get("findings", []):
        located = repository_finding(item["code"], item["status"], object_id=item["object_id"],
                                     obligation_id=item["obligation_id"])
        located.update(_producer_identity(
            item["obligation_id"], coordinate=item["coordinate"], gate=item["gate_id"],
            object_kind=located["object_kind"],
        ))
        located.update(explanation=item["explanation"], next_action=item["next_action"],
                       rerun_argv=item["rerun_argv"])
        findings.append(located)
    for item in report.get("kind_requirements", {}).get("contract_coverage", {}).get("findings", []):
        located = repository_finding(item["code"], "FAIL", object_id=item["object_id"],
                                     obligation_id=item["obligation_id"])
        located.update(_producer_identity(
            item["obligation_id"], coordinate=item["coordinate"], gate="contract-denominator",
            object_kind=located["object_kind"],
        ))
        located.update(explanation=item["explanation"], rerun_argv=item["rerun_argv"],
                       next_action="Repair the omitted, duplicate or mismatched package result; do not remove the required obligation.")
        findings.append(located)
    findings.extend(_native_nonpass_findings(report))
    for code in report["blockers"]:
        if rows and code in {"PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED",
                             "PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE"}:
            continue
        # Aggregate FAIL must not convert unrelated missing evidence into FAIL.
        status = "UNKNOWN" if ("NOT_ESTABLISHED" in code or "UNAVAILABLE" in code
                  or "MISSING" in code or "CANCELLED" in code or "CAPACITY" in code) else report["status"]
        findings.append(repository_finding(
            code, status, tier=report.get("requested_tier", 0),
        ))
    return [_reasoned_finding(item) for item in findings]


def print_findings(findings: list[dict[str, Any]]) -> None:
    """Commands are relative to the selected repository root; argv is authoritative."""
    for finding in findings:
        target = finding["object_id"] or "<repository>"
        obligation = finding["obligation_id"] or "<package-wide prerequisite>"
        print(f"[{finding['status']}] object={target} obligation={obligation} gate={finding['gate_id']}")
        print("  Reason: " + finding["reason"])
        print("  Next: " + finding["next_action"])
        if finding["rerun_argv"]:
            print("  From the selected repository root: " + shlex.join(finding["rerun_argv"]))


# A long finding list is read as groups, not rows: one block per (status, code, gate)
# with its count, a few exact examples and one next step.  Short lists print in full.
FINDING_DETAIL_LIMIT = 24
_GROUP_EXAMPLES = 3
_STATUS_ORDER = {"FAIL": 0, "UNKNOWN": 1}


def _finding_order(finding: dict[str, Any]) -> tuple[str, str, str]:
    return (
        finding.get("object_id") or "",
        finding.get("obligation_id") or "",
        finding.get("reason") or "",
    )


def _group_example(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_id": finding.get("object_id"),
        "obligation_id": finding.get("obligation_id"),
        "rerun_argv": finding.get("rerun_argv"),
    }


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse findings into counted groups keyed by (status, code, gate).

    A finding already carrying ``scope == "group"`` contributes its own counts and
    examples, so grouping is idempotent.  Refutations sort first, then the larger
    groups; a group of one keeps the original finding so no detail is lost.  The
    result never merges a FAIL into an UNKNOWN: status is part of the key.
    """
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        key = (finding["status"], finding["code"], finding["gate_id"])
        buckets.setdefault(key, []).append(finding)
    groups = []
    for (status, code, gate), members in buckets.items():
        singles = sorted(
            (item for item in members if item.get("scope") != "group"),
            key=_finding_order,
        )
        merged = [item for item in members if item.get("scope") == "group"]
        count = len(singles) + sum(
            item["instance_count"] if type(item.get("instance_count")) is int else 1
            for item in merged
        )
        object_count = len({
            item["object_id"] for item in singles if type(item.get("object_id")) is str
        }) + sum(
            item["object_count"] if type(item.get("object_count")) is int else 0
            for item in merged
        )
        if count == 1 and not merged:
            groups.append({
                **singles[0],
                "instance_count": 1,
                "object_count": object_count,
                "examples": [],
            })
            continue
        representative = singles[0] if singles else merged[0]
        examples = sorted(
            [_group_example(item) for item in singles]
            + [example for item in merged for example in item.get("examples", [])],
            key=lambda example: (
                example.get("object_id") or "", example.get("obligation_id") or "",
            ),
        )
        chosen: list[dict[str, Any]] = []
        for example in examples:
            if example not in chosen:
                chosen.append(example)
            if len(chosen) == _GROUP_EXAMPLES:
                break
        obligations = {item.get("obligation_id") for item in members}
        groups.append({
            **representative,
            "scope": "group",
            "object_id": None,
            "object_kind": None,
            "coordinate": None,
            "obligation_id": obligations.pop() if len(obligations) == 1 else None,
            "rerun_argv": chosen[0]["rerun_argv"] if chosen else None,
            "instance_count": count,
            "object_count": object_count,
            "examples": chosen,
        })
    groups.sort(key=lambda item: (
        _STATUS_ORDER.get(item["status"], len(_STATUS_ORDER)),
        -item["instance_count"], item["code"], item["gate_id"],
    ))
    return groups


def print_finding_groups(
        findings: list[dict[str, Any]], *, title: str = "Next actions") -> None:
    """Print every finding of a short list, else the grouped next-action view."""
    if len(findings) <= FINDING_DETAIL_LIMIT and all(
        item.get("scope") != "group" for item in findings
    ):
        print_findings(findings)
        return
    groups = group_findings(findings)
    total = sum(item["instance_count"] for item in groups)
    refuted = sum(
        item["instance_count"] for item in groups if item["status"] == "FAIL"
    )
    print(
        f"{title}: {len(groups)} kind(s) of finding covering {total} item(s) "
        f"({refuted} FAIL, {total - refuted} UNKNOWN); refutations first."
    )
    for group in groups:
        # A group of one is the original finding, and Tier-0 namespace findings carry no scope.
        if group.get("scope") != "group":
            print_findings([group])
            continue
        print(
            f"[{group['status']}] {group['instance_count']}x {group['code']} "
            f"gate={group['gate_id']} objects={group['object_count']}"
        )
        print("  Reason: " + group["reason"])
        print("  Next: " + group["next_action"])
        for example in group["examples"]:
            command = example["rerun_argv"]
            print(
                "  e.g. " + " ".join(
                    str(part) for part in (example["object_id"], example["obligation_id"])
                    if part
                ) + (": " + shlex.join(command) if command else "")
            )
    print(
        "Complete list: rerun with --json. Rows the report could not retain are "
        "never PASS or inapplicable."
    )


def assess_object_gate(object_id: str, obligation_id: str, source_root: str | Path = ".") -> dict[str, Any]:
    """Rerun one registered instance on the manifest's actual declared object.

    Package manifests carry structural, selected execution, and installed source-review
    adaptations. Unselected routes remain UNKNOWN; no caller command or specimen
    substitution is permitted.
"""
    if not (
        _valid_focus_identifier(object_id, maximum=256)
        and _valid_focus_identifier(obligation_id, maximum=512)
    ):
        return _invocation_report(
            "PACKAGE_GATE_SELECTION_INVALID",
            "FAIL",
            "The object or obligation selector is malformed or exceeds its finite length bound.",
            object_id=object_id,
            obligation_id=obligation_id,
        )
    from verifier.runtime.namespace_manifest import read_manifest, SCHEMA
    from verifier.runtime import package_manifest as package_manifest_contract
    selected_manifest = Path(source_root) / "objects.vstd"
    if selected_manifest.is_file():
        try:
            _, selected = read_manifest(selected_manifest)
        except (OSError, ValueError):
            selected = {}
        if selected.get("schema_version") == SCHEMA or (
                selected.get("schema_version") in package_manifest_contract.SCHEMAS
                and (obligation_id.startswith("VSTD-T0.")
                     or "-namespace-admission" in obligation_id
                     or "-0." in obligation_id)):
            from verifier.runtime.namespace_admission import assess_gate
            return assess_gate(object_id, obligation_id, source_root)
    from verifier.runtime import package_polish as package
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA, "status": "UNKNOWN", "object_id": object_id,
        "obligation_id": obligation_id, "obligation_name": None, "selection": None,
        "manifest_digest": None, "source_coordinate": None, "mechanism_digest": None,
        "runtime_source_binding": None,
        "instance": None, "facet_replay": None, "findings": [],
        "execution_observations": [],
        "rerun_argv": _rerun(object_id, obligation_id), "rerun_working_directory": "selected repository root",
        "post_replay_source_recapture": "NOT_ESTABLISHED", "post_replay_manifest_recapture": "NOT_ESTABLISHED",
        "polished": False, "release_authorized": False,
        "claim_boundary": "One manifest-bound obligation selection, not whole-tier or package polish. Missing applicability or evidence stays UNKNOWN. No native specimen or arbitrary repository command is executed.",
    }
    root = None
    raw = None
    instance_evidence = None
    kind_requirements = None
    source_assessment = None
    stage = "target-selection"
    try:
        package._require(type(object_id) is str and 0 < len(object_id) <= 256
                         and type(obligation_id) is str and 0 < len(obligation_id) <= 512,
                         "PACKAGE_GATE_SELECTION_INVALID")
        stage = "manifest-admission"
        root = Path(source_root).resolve(strict=True)
        raw = package._read_manifest(root)
        report["manifest_digest"] = binding.bytes_digest(raw)
        document = package.tier_zero_manifest._strict_json_document(raw)
        coordinate = package.self_polish_estate._git_coordinate(root)
        manifest, _, objects = package.package_manifest.select(document,
            repository=coordinate["repository"], revision=coordinate["revision"])
        stage = "target-selection"
        item = next((item for item in objects if item.object_id == object_id), None)
        package._require(item is not None, "PACKAGE_GATE_OBJECT_NOT_DECLARED")
        catalog = _admission_catalog() if obligation_id.startswith("VSTD-T0.") else obligation_catalog()
        selected = next((row for row in catalog if row["obligation_id"] == obligation_id), None)
        package._require(selected is not None, "PACKAGE_GATE_OBLIGATION_NOT_REGISTERED")
        if document.get("schema_version") in package.package_manifest.SCHEMAS and selected["tier"] != 0:
            # Version 6 stores repeated evidence behind digest selectors; every reader
            # must see the expanded declaration, exactly as whole-package Polish does.
            semantic_namespace = package._semantic_namespace(document)
            kind_requirements = package.KindRequirements(root, semantic_namespace)
            report["kind_requirements"] = kind_requirements.report
        kinds = kind_requirements.kinds(object_id) if kind_requirements is not None else {item.kind.value}
        package._require(selected["tier"] == 0 or selected["object_kind"] in kinds,
                         "PACKAGE_GATE_OBJECT_KIND_DIFFERS")
        report.update(selection=selected, obligation_name=selected["obligation_name"])
        stage = "source-binding"
        report["source_coordinate"] = package.self_polish_statics._capture_coordinate(root)
        report["runtime_source_binding"] = package.self_polish_statics._package_source_binding(root)
        report["mechanism_digest"] = package.mechanism_digest()
        verifier = package._verifier_selection(manifest, objects)
        reason_selection = package.reason_integration.select_root_reasons(root)
        if selected["tier"] == 0:
            stage = selected["gate_id"]
            admission = package.tier_zero.assess_tier_zero(root)
            package._require(admission["manifest_digest"] == report["manifest_digest"],
                             "PACKAGE_GATE_ADMISSION_MANIFEST_DIFFERS")
            selected_result = next(row for row in admission["obligations"]
                                   if row["coordinate"] == selected["coordinate"])
            report["admission_context"] = {
                "report_digest": admission["report_digest"], "status": admission["status"],
                "scope": "Shared repository-admission prerequisites were evaluated; this result selects only the named obligation.",
            }
            report.update(instance={**selected_result, "object_id": object_id,
                                    "checker_status": selected_result["status"]},
                          status=selected_result["status"],
                          findings=admission_findings({"obligations": [selected_result]}, object_id))
        else:
            stage = "native-check"
            if kind_requirements is not None:
                source_assessment = (
                    package.package_source_contracts.SourceContractAssessment(
                        root, objects, kind_requirements
                    )
                )
            facets = {"results": []}
            if selected["scope"] in _NAMES and package.accepts_subject(selected, item.kind.value):
                facets = package.package_self_polish._native_facets_replay(objects,
                    binding.value_digest(report["source_coordinate"]), selected_object_id=object_id)
                report["facet_replay"] = facets
            if document.get("schema_version") in package.package_manifest.SCHEMAS:
                root_graph_id = next(row["object_id"] for row in manifest["objects"] if row["object_kind"] == "GRAPH")
                instance_evidence = package.InstanceEvidence(root, objects, package._semantic_namespace(document), package_graph_id=root_graph_id,
                    representation_updates=document.get("representation_updates"))
            rows = package._instance_obligations(selected["tier"], (item,), root, verifier, facets,
                evidence=instance_evidence, kinds=kind_requirements,
                source_contracts=source_assessment,
                coordinates={selected["coordinate"]},
                reason_selection=reason_selection)
            instance = next(row for row in rows if row["coordinate"] == selected["coordinate"])
            report.update(instance=instance, status=instance["status"], findings=instance_findings(instance, selected))
    except package.PackagePolishUnknown as exc:
        report["findings"].append(repository_finding(str(exc), "UNKNOWN", object_id=object_id, obligation_id=obligation_id))
    except package._RESOURCE_ERRORS as exc:
        code = "PACKAGE_MANIFEST_MISSING" if str(exc) == "PACKAGE_MANIFEST_MISSING" else "PACKAGE_GATE_RESOURCE_UNAVAILABLE"
        report["findings"].append(repository_finding(code, "UNKNOWN", object_id=object_id, obligation_id=obligation_id))
    except (ValueError, KeyError, TypeError, RuntimeError, AttributeError, StopIteration) as exc:
        report["status"] = "FAIL"
        report["findings"].append(repository_finding(str(exc) or "PACKAGE_GATE_CONTRACT_REJECTED", "FAIL", object_id=object_id, obligation_id=obligation_id))
    if report["findings"] and report["instance"] is None:
        report["findings"][-1]["gate_id"] = stage
    if root is not None and raw is not None:
        try:
            if instance_evidence is not None:
                instance_evidence.recapture()
            if kind_requirements is not None:
                kind_requirements.recapture()
            unchanged = package._read_manifest(root) == raw
            report["post_replay_manifest_recapture"] = "PASS" if unchanged else "FAIL"
            package._require(unchanged, "PACKAGE_MANIFEST_CHANGED_DURING_REPLAY")
            if report["source_coordinate"] is not None:
                recapture = package.self_polish_tiers._post_replay_source_recapture(root, report["source_coordinate"])
                report["post_replay_source_recapture"] = recapture["status"]
                package._require(recapture["status"] != "FAIL", "PACKAGE_GATE_SOURCE_CHANGED")
                if recapture["status"] != "PASS":
                    raise OSError("source recapture unavailable")
                package._require(package.mechanism_digest() == report["mechanism_digest"], "PACKAGE_MECHANISM_CHANGED")
                package._require(package.self_polish_statics._package_source_binding(root)
                                 == report["runtime_source_binding"], "PACKAGE_GATE_RUNTIME_SOURCE_CHANGED")
        except package._RESOURCE_ERRORS:
            if report["status"] != "FAIL":
                report["status"] = "UNKNOWN"
            report["findings"].append(repository_finding("PACKAGE_CLOSING_RECAPTURE_UNAVAILABLE", "UNKNOWN", object_id=object_id, obligation_id=obligation_id))
        except (ValueError, KeyError, TypeError) as exc:
            report["status"] = "FAIL"
            report["findings"].append(repository_finding(str(exc), "FAIL", object_id=object_id, obligation_id=obligation_id))
    if instance_evidence is not None:
        report["execution_observations"] = package.package_execution.observation.retained(instance_evidence)
    report["findings"] = [_reasoned_finding(item) for item in report["findings"]]
    report["report_digest"] = binding.value_digest(report)
    return report


def handle_manifest_gate(args: argparse.Namespace) -> int:
    if not args.object or not args.obligation:
        # Missing selectors are invocation errors, not successful empty selections.
        explanation = "vstd gate requires both --object MANIFEST_ID and --obligation READABLE_ID (or a gate subcommand)."
        report = _invocation_report(
            "PACKAGE_GATE_SELECTORS_REQUIRED",
            "UNKNOWN",
            explanation,
            object_id=args.object,
            obligation_id=args.obligation,
        )
        if args.json:
            print(json.dumps(report, sort_keys=True, ensure_ascii=False, allow_nan=False))
        else:
            print("[UNKNOWN] " + explanation)
            print("  Next: " + report["next_action"])
            print("  Rerun: " + shlex.join(report["rerun_argv"]))
        return 2
    report = assess_object_gate(args.object, args.obligation, args.source_root or ".")
    if args.json:
        print(json.dumps(report, sort_keys=True, ensure_ascii=False, allow_nan=False))
    else:
        print(f"[{report['status']}] object={report['object_id']} obligation={report['obligation_id']}")
        if report["selection"]:
            print("  Claim: " + report["selection"]["exact_claim"])
        if report["instance"]:
            print("  Bounded checker: " + report["instance"]["checker_status"] + "; polished=false")
        print_findings(report["findings"])
        if report.get("prerequisite_findings"):
            print(f"  Other blocking prerequisites: {len(report['prerequisite_findings'])}; run vstd polish 0 to inspect them.")
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[report["status"]]
