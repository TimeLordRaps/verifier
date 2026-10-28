"""Current admission entry point and retained version-1 assessment.

This orchestrator composes the fixed profile, ``objects.vstd`` declaration,
source estate, installed obligation denominator, two-layer reasons, and the
independent Node structural receipt.  It never promotes structural admission to
numbered-tier conformance, whole-package polish, release, or deployment.
The fixed implementation is explicitly named assess_legacy_tier_zero; the public
assess_tier_zero entry point requires extensible, reasoned namespace admission.

JavaScript Object Notation (JSON); Verifier Standard (VSTD).
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from verifier.runtime import (
    core_obligation_union, core_tier_progression,
    package_obligation_candidate, self_polish_estate, tier_zero_manifest,
    tier_zero_profile,
)
from verifier.runtime import self_polish_estate_native_evidence
from verifier.runtime.tier_zero_reasoning import integration as reason_integration
from verifier.runtime.tier_zero_reasoning import reasons_dsl


REPORT_SCHEMA = "verifier-tier-zero-repository-admission-report-1"
CAPACITY_REPORT_SCHEMA = "verifier-tier-zero-report-capacity-1"
MAX_REPORT_BYTES = 64 * 1024 * 1024


def mechanism_digest() -> str:
    """Bind the installed Tier-zero assessment and every selected interpreter."""
    runtime_root = Path(__file__).parent
    # The orchestrator owns the packaged profile reads; the profile owner only
    # digests the exact bytes it receives.
    profile_specification = (
        Path(tier_zero_profile.__file__).resolve().parents[1]
        / "standard" / "TIER_ZERO.md"
    )
    return core_obligation_union.value_digest({
        "orchestrator": core_obligation_union.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "profile": tier_zero_profile.mechanism_digest(
            Path(tier_zero_profile.__file__).read_bytes(),
            profile_specification.read_bytes(),
        ),
        "manifest_interpreter": core_obligation_union.bytes_digest(
            Path(tier_zero_manifest.__file__).read_bytes()
        ),
        "manifest_schema": core_obligation_union.bytes_digest(
            runtime_root.parent.joinpath(
                "schemas", "verifier-objects-manifest-1.schema.json"
            ).read_bytes()
        ),
        "reason_interpreter": {
            "integration": core_obligation_union.bytes_digest(
                Path(reason_integration.__file__).read_bytes()
            ),
            "dsl": core_obligation_union.bytes_digest(
                Path(reasons_dsl.__file__).read_bytes()
            ),
        },
        "node_reconciler": core_obligation_union.bytes_digest(
            runtime_root.joinpath("tier_zero_reconcile.mjs").read_bytes()
        ),
        "source_estate": core_obligation_union.bytes_digest(
            Path(self_polish_estate.__file__).read_bytes()
        ),
        "source_estate_native_applicability": (
            self_polish_estate_native_evidence.mechanism_digest()
        ),
        "installed_inventory": core_tier_progression.mechanism_digest(),
        "semantic_binding": core_obligation_union.bytes_digest(
            Path(package_obligation_candidate.__file__).read_bytes()
        ),
    })


def _outcome(profile_row: dict[str, Any], status: str, *,
             evidence: dict[str, Any], blockers: list[str],
             pass_reason: str) -> dict[str, Any]:
    if status not in {"PASS", "FAIL", "UNKNOWN"}:
        raise ValueError("TIER_ZERO_OUTCOME_STATUS_INVALID")
    unique_blockers = sorted(set(blockers))
    if status == "PASS":
        assessment_reason = pass_reason
    elif status == "FAIL":
        assessment_reason = (
            "The installed obligation is refuted at this source coordinate by: "
            + ", ".join(unique_blockers)
        )
    else:
        assessment_reason = (
            "The installed obligation is not established at this source coordinate "
            "because: " + ", ".join(unique_blockers)
        )
    return {
        "coordinate": profile_row["coordinate"],
        "name": profile_row["name"],
        "rationale": profile_row["rationale"],
        "status": status,
        "assessment_reason": assessment_reason,
        "evidence": evidence,
        "blockers": unique_blockers,
        "claim_boundary": profile_row["claim_boundary"],
    }


def _selected_file(root: Path, selection: dict[str, Any], *,
                   exact_relative: str, code: str) -> Path:
    if selection.get("selection_status") != "SELECTED" \
            or selection.get("path") != exact_relative:
        raise ValueError(code + "_SELECTION_DIFFERS")
    candidate = root / exact_relative
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(code + "_INVALID")
    selected = candidate.resolve(strict=True)
    try:
        selected.relative_to(root)
    except ValueError as exc:
        raise ValueError(code + "_ESCAPES_SOURCE_ROOT") from exc
    observed = core_obligation_union.bytes_digest(selected.read_bytes())
    if observed != selection.get("sha256"):
        raise ValueError(code + "_DIGEST_DIFFERS")
    return selected


def _surface_closure(estate: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    rules = {row["category"]: row for row in manifest["surface_rules"]}
    counts: Counter[str] = Counter()
    excluded: list[str] = []
    unresolved: list[str] = []
    for candidate in estate["candidates"]:
        rule = rules[candidate["category"]]
        counts[rule["disposition"]] += 1
        if rule["disposition"] == "EXCLUDED":
            excluded.append(candidate["candidate_id"])
        elif rule["disposition"] == "UNRESOLVED":
            unresolved.append(candidate["candidate_id"])
    invalid_exclusions = [
        identifier for identifier in excluded
        if not identifier.startswith("unresolved-surface:")
    ]
    excluded_ids = set(excluded)
    missing_exclusion_reasons = [
        candidate["candidate_id"] for candidate in estate["candidates"]
        if candidate["candidate_id"] in excluded_ids
        and not (
            isinstance(candidate["metadata"].get("reason"), str)
            and candidate["metadata"]["reason"].strip()
        )
    ]
    native_not_applicable: list[str] = []
    unresolved_excluded: list[str] = []
    for candidate in estate["candidates"]:
        if candidate["candidate_id"] not in excluded_ids:
            continue
        try:
            native_applicability = (
                self_polish_estate_native_evidence.native_applicability_status(
                    candidate
                )
            )
        except self_polish_estate_native_evidence.NativeEvidenceError:
            native_applicability = "UNKNOWN"
        if native_applicability == "NOT_APPLICABLE":
            native_not_applicable.append(candidate["candidate_id"])
        else:
            unresolved_excluded.append(candidate["candidate_id"])
    status = "PASS"
    blockers: list[str] = []
    if invalid_exclusions:
        status = "FAIL"
        blockers.append("TIER_ZERO_FALSE_SOURCE_SURFACE_EXCLUSION")
    if missing_exclusion_reasons:
        status = "FAIL"
        blockers.append("TIER_ZERO_EXCLUDED_SURFACE_REASON_MISSING")
    # A reason preserves why a surface was set aside; it is not evidence that
    # the surface is inapplicable.  Only the installed native registry's exact,
    # digest-bound NOT_APPLICABLE replay closes an excluded boundary sentinel.
    # Arbitrary, malformed, or merely reasoned exclusions remain UNKNOWN.
    if unresolved_excluded and status != "FAIL":
        status = "UNKNOWN"
        blockers.append(
            "TIER_ZERO_EXCLUDED_SURFACE_APPLICABILITY_UNRESOLVED"
        )
    if unresolved and status != "FAIL":
        status = "UNKNOWN"
        blockers.append("TIER_ZERO_SURFACE_OWNERSHIP_UNRESOLVED")
    return {
        "status": status,
        "blockers": blockers,
        "candidate_count": estate["candidate_count"],
        "candidate_universe_digest": estate["candidate_universe_digest"],
        "estate_digest": estate["estate_digest"],
        "category_count": len(estate["required_categories"]),
        "disposition_counts": dict(sorted(counts.items())),
        "excluded_surface_ids": excluded,
        "native_not_applicable_surface_ids": native_not_applicable,
        "unresolved_excluded_surface_ids": unresolved_excluded,
        "native_applicability_mechanism_digest": (
            self_polish_estate_native_evidence.mechanism_digest()
        ),
        "excluded_surface_reason_preservation": (
            "FAIL" if missing_exclusion_reasons else "PASS"
        ),
    }


def _denominator_closure(estate: dict[str, Any]) -> dict[str, Any]:
    inventory = core_tier_progression.installed_core_route_inventory()
    cells = inventory["family_cells"]
    route_ids = {
        f"installed-route:{cell['object_kind']}:{route['coordinate']}"
        for cell in cells for route in cell["registered_route_memberships"]
    }
    cell_ids = {
        f"installed-cell:{cell['object_kind']}:{cell['tier']}" for cell in cells
    }
    candidate_ids = {row["candidate_id"] for row in estate["candidates"]}
    status = "PASS"
    blockers: list[str] = []
    if len(cells) != 234 or inventory["registered_route_membership_count"] != 408:
        status = "FAIL"
        blockers.append("TIER_ZERO_OBLIGATION_DENOMINATOR_COUNT_DIFFERS")
    if not route_ids | cell_ids <= candidate_ids:
        status = "FAIL"
        blockers.append("TIER_ZERO_OBLIGATION_DENOMINATOR_NOT_IN_ESTATE")
    return {
        "status": status,
        "blockers": blockers,
        "slot_count": len(cells),
        "route_count": len(route_ids),
        "slot_digest": core_obligation_union.value_digest(cells),
        "route_identity_digest": core_obligation_union.value_digest(
            sorted(route_ids)
        ),
        "inventory_semantic_version": inventory["semantic_version"],
    }


def _reason_closure(root: Path, estate: dict[str, Any],
                    manifest: dict[str, Any]) -> dict[str, Any]:
    """Bind the sole root reason authority to current compiled open cells."""

    _selected_file(
        root, manifest["obligation_reason_provider"],
        exact_relative="reasons.vstd",
        code="TIER_ZERO_REASON_PROVIDER",
    )
    selection = reason_integration.select_root_reasons(root)
    from verifier.runtime import namespace_manifest, package_manifest

    _raw, document = namespace_manifest.read_manifest(root / "objects.vstd")
    if document.get("schema_version") not in package_manifest.SCHEMAS:
        raise ValueError("TIER_ZERO_ROOT_REASON_NAMESPACE_REQUIRED")
    namespace = document["namespace"]
    if namespace.get("schema_version") == namespace_manifest.COMPACT_SCHEMA:
        namespace = namespace_manifest.normalize_manifest(namespace)
    open_keys = {
        (row["object_id"], kind)
        for row in namespace["objects"]
        for kind, cell in row.get("classification", {}).items()
        if cell.get("status") == "UNRESOLVED"
    }
    denial_keys = {
        (row["object_id"], kind)
        for row in namespace["objects"]
        for kind, cell in row.get("classification", {}).items()
        if cell.get("status") == "DOES_NOT_APPLY"
    }
    decisions = {
        (row["object_id"], row["object_kind"]): row
        for row in selection.classification_decisions
    }
    answerable_keys = open_keys | denial_keys
    missing = sorted(open_keys - decisions.keys())
    orphaned = sorted(decisions.keys() - answerable_keys)
    conservative_overrides = sorted(decisions.keys() & denial_keys)
    status = "PASS" if not missing and not orphaned else "UNKNOWN"
    return {
        "status": status,
        "blockers": ([] if status == "PASS" else [
            "TIER_ZERO_ROOT_REASON_RECONCILIATION_INCOMPLETE"
        ]),
        "reason_authority": selection.authority,
        "reason_ir_digest": selection.ir_digest,
        "reason_count": len(selection.ir.get("reasons", [])),
        "open_classification_count": len(open_keys),
        "denial_override_eligible_count": len(denial_keys),
        "conservative_override_count": len(conservative_overrides),
        "conservative_overrides_digest": core_obligation_union.value_digest(
            conservative_overrides
        ),
        "classification_reason_count": len(decisions),
        "reconciled_classification_count": len(open_keys & decisions.keys()),
        "reconciled_total_classification_count": len(
            answerable_keys & decisions.keys()
        ),
        "missing_classification_count": len(missing),
        "missing_classifications": [
            {"object_id": object_id, "kind": kind}
            for object_id, kind in missing
        ],
        "missing_classifications_digest": core_obligation_union.value_digest(
            missing
        ),
        "orphaned_classification_count": len(orphaned),
        "orphaned_classifications": [
            {"object_id": object_id, "kind": kind}
            for object_id, kind in orphaned
        ],
        "orphaned_classifications_digest": core_obligation_union.value_digest(
            orphaned
        ),
        "decision_authority": (
            "The sole root reasons.vstd answers every current compiled open "
            "object-kind cell and may conservatively supersede a compiled denial "
            "only by retaining obligations. A DOCUMENTED reason does not edit "
            "objects.vstd, establish source truth, supply a route checker result, "
            "or authorize release or deployment."
        ),
    }


def _node_structural_reconciliation(
        root: Path, manifest_path: Path, manifest: dict[str, Any],
        coordinate: dict[str, str], python_result: dict[str, Any],
        ) -> dict[str, Any]:
    node_path = _selected_file(
        root, manifest["node_reconciler"],
        exact_relative="src/verifier/runtime/tier_zero_reconcile.mjs",
        code="TIER_ZERO_NODE_RECONCILER",
    )
    try:
        completed = subprocess.run([
            "node", str(node_path), "--manifest", str(manifest_path),
            "--repository", coordinate["repository"],
            "--revision", coordinate["revision"],
            "--source-root", str(root),
        ], cwd=root, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "UNKNOWN",
            "blockers": ["TIER_ZERO_NODE_RECONCILER_UNAVAILABLE"],
            "detail": type(exc).__name__,
        }
    try:
        node_result = json.loads(completed.stdout)
    except (json.JSONDecodeError, RecursionError):
        return {
            "status": "FAIL",
            "blockers": ["TIER_ZERO_NODE_RECEIPT_INVALID"],
        }
    if completed.returncode != 0 or node_result.get("status") != "PASS":
        return {
            "status": "FAIL" if completed.returncode == 1 else "UNKNOWN",
            "blockers": [node_result.get(
                "error", "TIER_ZERO_NODE_RECONCILIATION_NOT_PASS"
            )],
            "node_receipt": node_result,
        }
    compared = (
        "status", "profile_digest", "object_count", "object_kind_digest",
        "graph_digest", "surface_rule_count", "surface_rule_digest",
        "semantic_version", "slot_count", "route_count", "slot_digest",
        "route_identity_digest", "attachment_selection_digest",
        "adversarial_corpus_status", "adversarial_corpus_digest",
        "reason_provider_selection_status", "node_reconciler_selection_status",
        "manifest_digest", "manifest_value_digest",
    )
    disagreements = [
        field for field in compared
        if node_result.get(field) != python_result.get(field)
    ]
    if node_result.get("attachment_source_binding_status") != "PASS":
        disagreements.append("attachment_source_binding_status")
    return {
        "status": "FAIL" if disagreements else "PASS",
        "blockers": (
            ["TIER_ZERO_NODE_STRUCTURAL_DISAGREEMENT"] if disagreements else []
        ),
        "structural_agreement_status": "FAIL" if disagreements else "PASS",
        "compared_fields": list(compared),
        "disagreements": disagreements,
        "node_receipt": node_result,
    }


def assess_legacy_tier_zero(source_root: str | Path = ".", *,
                            manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Replay the retained version-1 contract, not current namespace admission."""
    root = Path(source_root).resolve(strict=True)
    coordinate = self_polish_estate._git_coordinate(root)
    selected_manifest = (
        (root / "objects.vstd") if manifest_path is None
        else Path(manifest_path).resolve(strict=True)
    )
    manifest, manifest_result = tier_zero_manifest.load_manifest(
        selected_manifest,
        expected_repository=coordinate["repository"],
        expected_revision=coordinate["revision"],
    )
    estate = self_polish_estate.build_candidate_estate(
        root, expected_repository=coordinate["repository"],
        expected_revision=coordinate["revision"],
    )
    surface = _surface_closure(estate, manifest)
    denominator = _denominator_closure(estate)
    reasons = _reason_closure(root, estate, manifest)
    node = _node_structural_reconciliation(
        root, selected_manifest, manifest, coordinate, manifest_result,
    )
    closing_coordinate = self_polish_estate._git_coordinate(root)
    closing_census = self_polish_estate.capture_candidate_source_census(root)
    freshness_pass = (
        closing_coordinate == coordinate
        and closing_census == estate["post_source_census"]
    )
    profile = tier_zero_profile.installed_tier_zero_profile()
    rows = {row["coordinate"]: row for row in profile["obligations"]}
    outcomes = [
        _outcome(rows["VSTD-T0.1"], "PASS", evidence={
            "manifest_digest": manifest_result["manifest_digest"],
            "manifest_value_digest": manifest_result["manifest_value_digest"],
            "profile_digest": manifest_result["profile_digest"],
            "python_validation_status": manifest_result["status"],
        }, blockers=[], pass_reason=(
            "The selected objects.vstd bytes decoded as strict canonical JSON, "
            "validated against the installed schema, and reproduced the selected "
            "Tier-0 profile and manifest digests exactly."
        )),
        _outcome(rows["VSTD-T0.2"], "PASS", evidence={
            "object_count": manifest_result["object_count"],
            "object_kind_digest": manifest_result["object_kind_digest"],
        }, blockers=[], pass_reason=(
            "The manifest declares exactly the 26 installed VSTD object kinds once "
            "each, with a stable aggregate object-kind digest."
        )),
        _outcome(rows["VSTD-T0.3"], "PASS", evidence={
            "graph_digest": manifest_result["graph_digest"],
        }, blockers=[], pass_reason=(
            "Every declared typed edge resolves and the resulting package graph "
            "reproduces the installed relation template and canonical graph digest."
        )),
        _outcome(rows["VSTD-T0.4"], surface["status"], evidence=surface,
                 blockers=surface["blockers"], pass_reason=(
                     f"Independent discovery accounted for all "
                     f"{surface['candidate_count']} candidates across "
                     f"{surface['category_count']} installed surface categories; "
                     "each candidate has one owned disposition and no unresolved "
                     "or excluded surface remains."
                 )),
        _outcome(rows["VSTD-T0.5"], denominator["status"],
                 evidence=denominator, blockers=denominator["blockers"],
                 pass_reason=(
                     f"The declaration and discovered estate contain exactly all "
                     f"{denominator['slot_count']} installed kind-tier slots and "
                     f"{denominator['route_count']} installed route memberships "
                     "under the current inventory semantic version and identity "
                     "digests."
                 )),
        _outcome(rows["VSTD-T0.6"], reasons["status"], evidence=reasons,
                 blockers=reasons["blockers"], pass_reason=(
                     f"The sole root reasons.vstd contains exactly one checked "
                     f"classification decision for all "
                     f"{reasons.get('open_classification_count', reasons.get('objective_reason_count', 0))} compiled open "
                     "object-kind cells, plus "
                     f"{reasons.get('conservative_override_count', 0)} conservative "
                     "APPLIES overrides of compiled denials, with no missing or "
                     "orphaned decision."
                 )),
        _outcome(
            rows["VSTD-T0.7"], "PASS" if freshness_pass else "FAIL",
            evidence={
                "source_coordinate": coordinate,
                "opening_census_digest": estate["post_source_census"]["census_digest"],
                "closing_census_digest": closing_census["census_digest"],
                "unchanged": freshness_pass,
            },
            blockers=[] if freshness_pass else ["TIER_ZERO_SOURCE_MUTATED"],
            pass_reason=(
                "The closing source coordinate and complete candidate-source census "
                "are identical to the opening capture, so the declaration, reasons, "
                "mechanisms, and receipts describe one unchanged bounded source state."
            ),
        ),
        _outcome(rows["VSTD-T0.8"], node["status"], evidence=node,
                 blockers=node["blockers"], pass_reason=(
                     f"The source-bound Python and Node implementations agree on all "
                     f"{len(node.get('compared_fields', []))} compared canonical "
                     "manifest, graph, denominator, attachment, and adversarial-corpus "
                     "fields with no disagreement."
                 )),
        _outcome(rows["VSTD-T0.9"], "PASS", evidence={
            "tier_1_plus_status": "NOT_ESTABLISHED",
            "polished": False,
            "release_authorized": False,
            "deployment_authorized": False,
            "unknown_preserved": True,
        }, blockers=[], pass_reason=(
            "The assessment preserves all higher-tier, polish, release, and deployment "
            "claims as unestablished and grants no authority beyond Tier-0 repository "
            "admission."
        )),
    ]
    statuses = Counter(row["status"] for row in outcomes)
    overall = "FAIL" if statuses["FAIL"] else (
        "UNKNOWN" if statuses["UNKNOWN"] else "PASS"
    )
    unclosed_coordinates = [
        row["coordinate"] for row in outcomes if row["status"] != "PASS"
    ]
    if overall == "PASS":
        finalization_reason = (
            "All nine fixed Tier-0 repository-admission obligations pass at one "
            "unchanged source coordinate with explicit assessment reasons, no "
            "blockers, and independent Python/Node agreement. The versioned profile "
            "digest closes this denominator; changing it requires a new profile "
            "version and digest."
        )
    else:
        finalization_reason = (
            "Tier-0 repository admission is not finalized because these installed "
            "coordinates remain unclosed: " + ", ".join(unclosed_coordinates)
        )
    finalization = {
        "status": overall,
        "complete": overall == "PASS",
        "finalized": overall == "PASS",
        "scope": "TIER_ZERO_REPOSITORY_ADMISSION_ONLY",
        "reason": finalization_reason,
        "profile_digest": profile["profile_digest"],
        "mechanism_digest": mechanism_digest(),
        "source_coordinate": coordinate,
        "source_census_digest": closing_census["census_digest"],
        "closed_coordinates": [
            row["coordinate"] for row in outcomes if row["status"] == "PASS"
        ],
        "unclosed_coordinates": unclosed_coordinates,
        "profile_change_rule": profile["finalization_rule"],
        "claim_boundary": profile["claim_boundary"],
    }
    body = {
        "schema_version": REPORT_SCHEMA,
        "status": overall,
        "source_coordinate": coordinate,
        "profile_id": profile["profile_id"],
        "profile_digest": profile["profile_digest"],
        "manifest_digest": manifest_result["manifest_digest"],
        "mechanism_digest": finalization["mechanism_digest"],
        "obligation_count": len(outcomes),
        "obligation_status_counts": {
            key: statuses[key] for key in ("PASS", "FAIL", "UNKNOWN")
        },
        "obligations": outcomes,
        "finalization": finalization,
        "blockers": sorted({
            blocker for row in outcomes for blocker in row["blockers"]
        }),
        "tier_1_plus_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": profile["claim_boundary"],
    }
    return {**body, "report_digest": core_obligation_union.value_digest(body)}


def _source_inventory(root: Path) -> dict[str, Any]:
    """Capture the current candidate bytes as the owned-path inventory.

    A refused or unreadable census yields no inventory and a fixed refusal
    code; it never becomes an empty inventory that would bind nothing.
    """
    try:
        census = self_polish_estate.capture_candidate_source_census(root)
    except (OSError, ValueError) as exc:
        code = (
            str(exc)
            if isinstance(exc, self_polish_estate.EstateError)
            else type(exc).__name__
        )
        return {
            "inventory": None,
            "census_digest": None,
            "unavailable": "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_UNAVAILABLE:"
            + code,
        }
    return {
        "inventory": {row["path"]: row["sha256"] for row in census["files"]},
        "census_digest": census["census_digest"],
        "unavailable": None,
    }


def _package_original_kind_closure(
    document: dict[str, Any],
    root: str | Path,
    source_inventory: Mapping[str, str] | None,
    documented_retention_keys: frozenset[tuple[str, str]] = frozenset(),
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, str] | None]:
    """Assess the package matrix through the source-validated aggregate."""
    from verifier.runtime import (
        namespace_manifest,
        package_original_kind_catalog,
    )

    namespace = namespace_manifest.normalize_manifest(document["namespace"])
    rows = {row["object_id"]: row for row in namespace["objects"]}
    try:
        closure = package_original_kind_catalog.admission_closure_report(
            rows,
            root=root,
            source_inventory=source_inventory,
            documented_retention_keys=documented_retention_keys,
        )
    except (OSError, ValueError) as exc:
        first_object = min(rows) if rows else "verifier-package"
        focus = {
            "object_id": first_object,
            "kind": package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS[0],
        }
        diagnostic = "PACKAGE_ORIGINAL_KIND_CATALOG_REFUSED:" + (
            str(exc) or type(exc).__name__
        )
        closure = {
            "status": "UNKNOWN",
            "question_count": (
                package_original_kind_catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
            ),
            "decided_count": 0,
            "unresolved_count": (
                package_original_kind_catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
            ),
            "unresolved": [],
            "next_unresolved": focus,
            "conflict_count": 0,
            "conflicts": [],
            "next_conflict": None,
            "diagnostic": diagnostic,
            "denominator_first": focus,
            "source_inventory_bound": False,
            "unresolved_digest": core_obligation_union.value_digest(
                {"diagnostic": diagnostic, "focus": focus}
            ),
            "unresolved_reason_counts": {
                diagnostic: (
                    package_original_kind_catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
                )
            },
            # Catalog-level refusal is already carried by ``diagnostic``.  It
            # is not a per-cell decision-binding blocker and must not be fed
            # into the narrower manifest-gate blocker vocabulary.
            "unresolved_sample": [],
            "unresolved_sample_limit": (
                package_original_kind_catalog.UNRESOLVED_SAMPLE_LIMIT
            ),
            "unresolved_truncated": True,
            # No cell was refused by a denominator rule; the refusal is the diagnostic.
            "blocker_counts": {},
        }
    conflict = closure.get("next_conflict")
    return closure, rows, conflict if type(conflict) is dict else None


def _documented_original_kind_retention_keys(
    report: Mapping[str, Any], document: dict[str, Any], root: str | Path
) -> frozenset[tuple[str, str]]:
    """Select checked reasons that retain obligations without claiming source roles."""

    selected_root = Path(root)
    if report.get("status") != "PASS" or not (selected_root / "reasons.vstd").is_file():
        return frozenset()
    from verifier.runtime import namespace_manifest, package_original_kind_catalog

    namespace = namespace_manifest.normalize_manifest(document["namespace"])
    selection = reason_integration.select_root_reasons(selected_root)
    answers = reason_integration.documented_applicability_answers(
        selection, namespace["objects"]
    )
    return frozenset(
        (answer["object_id"], answer["object_kind"])
        for answer in answers
        if answer["object_kind"]
        in package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS
    )


def _bind_package_original_kind_closure(
    report: dict[str, Any], document: dict[str, Any], root: str | Path
) -> dict[str, Any]:
    """Conjoin original-kind completeness with existing VSTD-T0.2 admission.

    Decided cells pass only against one source snapshot that stays unchanged
    from before the closure to after it.  A changed or unreadable snapshot is
    UNKNOWN and retried from the exact first cell; a catalog contradiction is
    FAIL regardless of the snapshot.
    """
    from verifier.runtime.manifest_gate import original_kind_closure_finding

    selected = deepcopy(report)
    opening = _source_inventory(Path(root))
    documented_retention_keys = _documented_original_kind_retention_keys(
        report, document, root
    )
    closure, rows, conflict = _package_original_kind_closure(
        document,
        root,
        opening["inventory"],
        documented_retention_keys,
    )
    if opening["unavailable"] is not None:
        source_status = "UNAVAILABLE"
        closing_digest = None
    else:
        closing = _source_inventory(Path(root))
        closing_digest = closing["census_digest"]
        if closing["unavailable"] is not None:
            source_status = "CLOSING_UNAVAILABLE"
        elif closing_digest != opening["census_digest"]:
            source_status = "MUTATED"
        else:
            source_status = "BOUND"
    summary = {
        key: closure.get(key)
        for key in (
            "status",
            "question_count",
            "decided_count",
            "unresolved_count",
            "unresolved_digest",
            "unresolved_reason_counts",
            "blocker_counts",
            "documented_retention_selected_count",
            "documented_retention_applied_count",
            "documented_retention_digest",
            "unresolved_sample_limit",
            "unresolved_truncated",
            "unresolved_sample",
            "next_unresolved",
            "diagnostic",
        )
    }
    summary["source_binding"] = {
        "status": source_status,
        "opening_census_digest": opening["census_digest"],
        "closing_census_digest": closing_digest,
    }
    selected["original_kind_closure"] = summary
    source_code = opening["unavailable"] or (
        None
        if source_status == "BOUND"
        else "PACKAGE_ORIGINAL_KIND_SOURCE_" + source_status
    )
    if conflict is not None:
        status = "FAIL"
        focus = {"object_id": conflict["object_id"], "kind": conflict["kind"]}
        code = (
            "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:"
            + focus["object_id"]
            + ":"
            + focus["kind"]
        )
        summary.update(status="FAIL", conflict=conflict, diagnostic=code)
    elif source_code is not None or closure.get("status") != "PASS":
        status = "UNKNOWN"
        focus = closure.get("next_unresolved") or closure.get("denominator_first")
        if not (
            type(focus) is dict
            and type(focus.get("object_id")) is str
            and type(focus.get("kind")) is str
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED_FOCUS_MISSING"
            )
        if source_code is not None:
            code = source_code
        else:
            code = closure.get("diagnostic")
            if type(code) is not str or not code.strip():
                code = (
                    "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
                    + focus["object_id"]
                    + ":"
                    + focus["kind"]
                )
    else:
        selected.pop("report_digest", None)
        selected["report_digest"] = core_obligation_union.value_digest(selected)
        return selected

    object_row = rows.get(focus["object_id"], {})
    object_kind = object_row.get("kind") if type(object_row) is dict else None
    binding_blocker = None
    denominator_blocker = None
    if conflict is None and source_code is None:
        unresolved_sample = closure.get("unresolved_sample")
        if (
            type(unresolved_sample) is list
            and unresolved_sample
            and type(unresolved_sample[0]) is dict
            and type(unresolved_sample[0].get("reason")) is str
            and unresolved_sample[0].get("object_id") == focus["object_id"]
            and unresolved_sample[0].get("kind") == focus["kind"]
        ):
            head = unresolved_sample[0]
            # A refused DOES_NOT_APPLY keeps the generic DECISION_UNRESOLVED reason,
            # whose clause ("no APPLIES or DOES_NOT_APPLY decision") is false for it;
            # the exact denominator cause replaces that clause.
            if type(head.get("denominator_blocker")) is str:
                denominator_blocker = head["denominator_blocker"]
            else:
                binding_blocker = head["reason"]
    finding = original_kind_closure_finding(
        object_id=focus["object_id"],
        object_kind=object_kind if type(object_kind) is str else None,
        classification_kind=focus["kind"],
        status=status,
        code=code,
        binding_blocker=binding_blocker,
        denominator_blocker=denominator_blocker,
    )
    outcome = next(
        row
        for row in selected["obligations"]
        if row["coordinate"] == "VSTD-T0.2"
    )
    combined_statuses = {outcome["status"], status}
    outcome["status"] = (
        "FAIL"
        if "FAIL" in combined_statuses
        else "UNKNOWN"
        if "UNKNOWN" in combined_statuses
        else "PASS"
    )
    outcome["blockers"] = sorted(set([*outcome.get("blockers", []), code]))
    evidence = outcome.get("evidence")
    if type(evidence) is not dict:
        evidence = {}
        outcome["evidence"] = evidence
    evidence["original_kind_closure"] = summary
    outcome["assessment_reason"] = (
        outcome.get("assessment_reason", "").rstrip()
        + " "
        + finding["reason"]
    ).strip()
    selected.setdefault("findings", []).append(finding)

    counts = Counter(row["status"] for row in selected["obligations"])
    overall = (
        "FAIL" if counts["FAIL"] else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
    )
    selected["status"] = overall
    selected["obligation_count"] = len(selected["obligations"])
    selected["obligation_status_counts"] = {
        key: counts[key] for key in ("PASS", "FAIL", "UNKNOWN")
    }
    selected["blockers"] = sorted(
        {
            blocker
            for row in selected["obligations"]
            for blocker in row.get("blockers", [])
        }
    )
    closed = [
        row["coordinate"] for row in selected["obligations"] if row["status"] == "PASS"
    ]
    unclosed = [
        row["coordinate"] for row in selected["obligations"] if row["status"] != "PASS"
    ]
    finalization = selected.setdefault("finalization", {})
    finalization.update(
        status=overall,
        complete=overall == "PASS",
        finalized=overall == "PASS",
        closed_coordinates=closed,
        unclosed_coordinates=unclosed,
        reason=(
            "Tier-0 repository admission is not finalized because original-kind "
            "classification closure is "
            + status
            + " at "
            + focus["object_id"]
            + ":"
            + focus["kind"]
            + "."
        ),
    )
    selected.pop("report_digest", None)
    selected["report_digest"] = core_obligation_union.value_digest(selected)
    return selected


def assess_tier_zero(source_root: str | Path = ".", *,
                     manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Explicit version dispatch; full package admission is always additive."""
    from verifier.runtime.namespace_manifest import read_manifest
    from verifier.runtime import package_admission, package_manifest
    selected = Path(source_root) / "objects.vstd" if manifest_path is None else Path(manifest_path)
    try:
        _, document = read_manifest(selected)
    except (OSError, ValueError):
        document = {}  # The namespace assessor returns the precise input refusal.
    if document.get("schema_version") in package_manifest.SCHEMAS:
        report = package_admission.assess(
            source_root, manifest_path=manifest_path
        )
        return _bind_package_original_kind_closure(report, document, source_root)
    from verifier.runtime.namespace_admission import assess
    return assess(source_root, manifest_path=manifest_path)


__all__ = ["REPORT_SCHEMA", "assess_tier_zero", "assess_legacy_tier_zero", "mechanism_digest"]
