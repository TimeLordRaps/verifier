"""Manifest-driven Verifier Standard (VSTD) package GRAPH polish.

Terminology: application programming interface (API); identifier (ID).

The root objects.vstd is the subject declaration, never a hint to substitute
native specimens. Package-instance obligations, declared VERIFIER execution,
and source-native diagnostics are separate evidence classes. Missing instance
evidence remains UNKNOWN. JavaScript Object Notation (JSON) is used on the wire.

Before any whole-report JSON encoding, a report is measured by a bounded
lower-bound walk. A source that cannot fit its raw-source envelope goes straight
to the capacity receipt without being materialized, and that receipt names its
source as UNAVAILABLE instead of digesting a summary.
"""
from __future__ import annotations

from collections import Counter
import json
import math
from pathlib import Path
import re
import stat
from typing import Any, Iterator, Mapping, NamedTuple

from verifier.core import namespace
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import core_tier_progression, package_self_polish
from verifier.runtime import package_verifier_graph
from verifier.runtime import self_polish_estate, self_polish_statics, self_polish_tiers
from verifier.runtime import (
    tier_zero,
    tier_zero_manifest,
    tier_zero_reasons,  # compatibility surface only; never a reason authority
    package_manifest,
)
from verifier.runtime.tier_zero_reasoning import integration as reason_integration
from verifier.runtime.package_instance_evidence import InstanceEvidence, STRUCTURAL
from verifier.runtime.package_kind_requirements import KindRequirements, accepts_subject
from verifier.runtime.tier_zero_profile import validate_applicability_binding
from verifier.runtime import (
    added_kind_behavioral_routes,
    namespace_contracts,
    package_contract_coverage,
    package_execution,
    package_source_contracts,
)


REPORT_SCHEMA = "verifier-manifest-package-polish-1"
EXTENSIBLE_REPORT_SCHEMA = "verifier-manifest-package-polish-2"
CAPACITY_REPORT_SCHEMA = "verifier-manifest-package-polish-capacity-2"
REFRESH_BINDING_SCHEMA = "verifier-package-polish-refresh-binding-1"
REFRESH_REFERENCE_SCHEMA = "verifier-package-manifest-refresh-reference-1"
MAX_REPORT_BYTES = 32 * 1024 * 1024
# Keep a finite fail-closed ceiling while retaining the complete current
# Tier-0-through-3 package denominator.  The selected 26-object registry has
# 86,740 cumulative Tier-3 instances (32,330 Tier 1 + 28,608 Tier 2 + 25,802
# Tier 3); the previous 32,768 ceiling therefore stopped Tier 2 before any
# obligation ran.  The selector is linear and the report byte budgets below
# remain independent bounds on publication size.
MAX_OBLIGATION_INSTANCES = 131_072
# Blocking instances named verbatim in a skipped row's reason; beyond this the
# reason counts and digests the set so thousands of skipped rows stay small.
_BLOCKED_GATE_NAMED_INSTANCES = 8
MAX_INLINE_SELECTED_CHECK_BYTES = 1024
MAX_INLINE_REPOSITORY_REALIZATION_BYTES = 1024
MAX_INLINE_CONTRACT_COVERAGE_BYTES = 4 * 1024 * 1024
MAX_INLINE_INSTANCE_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_INLINE_OBLIGATION_ROWS_BYTES = 24 * 1024 * 1024
# Expanded capacity-index dictionaries carry enough repeated field names that
# the pre-encoding lower bound can stay below 24 MiB while canonical JSON still
# pushes the complete receipt past 32 MiB.  Factor large PASS denominators by
# explicit count as well as by the byte precheck; small diagnostic receipts keep
# their established directly inspectable v1 index.
MAX_INLINE_CAPACITY_INDEX_ENTRIES = 8_192
TARGET_REPORT_BYTES = 24 * 1024 * 1024
# Pre-encoding envelope.  The lower-bound walk visits each unique container once
# (shared containers are memoized by identity) and refuses depth, visit, cycle
# and unencodable inputs without recursion.  A raw source may exceed
# MAX_REPORT_BYTES by this factor because lossless PASS-row projection can still
# shrink it after encoding; beyond that factor it is refused before encoding.
# The current cumulative Tier-3 v3 projection is 275,004,439 canonical bytes,
# just over eight report envelopes, while its public capacity receipt remains
# independently capped at MAX_REPORT_BYTES.
RAW_SOURCE_ENVELOPE_FACTOR = 9
# Keep traversal work linear in the independently bounded obligation census.
# The v3 projection currently visits about 62 nodes per selected obligation;
# 80 retains bounded headroom without turning the visit guard into an open cap.
MAX_PREENCODING_VISITS = 80 * MAX_OBLIGATION_INSTANCES
MAX_PREENCODING_DEPTH = 128
_PREENCODING_BYTES = "PACKAGE_REPORT_PREENCODING_BYTES_EXCEEDED"
_PREENCODING_VISITS = "PACKAGE_REPORT_PREENCODING_VISITS_EXCEEDED"
_PREENCODING_DEPTH = "PACKAGE_REPORT_PREENCODING_DEPTH_EXCEEDED"
_PREENCODING_CYCLIC = "PACKAGE_REPORT_PREENCODING_CYCLIC"
_PREENCODING_UNENCODABLE = "PACKAGE_REPORT_PREENCODING_UNENCODABLE"
_PREENCODING_DONE = object()
_RESOURCE_ERRORS = (OSError, ImportError, MemoryError, RecursionError, OverflowError)
_EXPANDED_DENOMINATOR_COMMITMENT_SCHEMA = (
    "verifier-package-obligation-denominator-commitment-1"
)
_PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA = (
    "verifier-package-obligation-denominator-commitment-2"
)
_CAPACITY_DENOMINATOR_COMMITMENT_SCHEMA = (
    "verifier-package-obligation-denominator-commitment-3"
)
_PROJECTED_CONDITIONAL_TRANSPORT = "RECONSTRUCT_FROM_PROJECTED_ROWS"
_CAPACITY_CONDITIONAL_TRANSPORT = "REPLAY_FROM_DIGEST_BOUND_SOURCE_REPORT"
_PASS_TABLE_PROJECTION_SCHEMA = "verifier-pass-instance-projection-3"
_PASS_TABLE_TRANSPORT = "DIGEST_BOUND_PASS_TABLE_REFERENCES"
_PASS_TABLE_OBJECT_FIELDS = (
    "object_id", "object_digest", "object_kind", "declared_kind",
    "specializations",
)
_PASS_TABLE_ROUTE_FIELDS = (
    "coordinate", "tier", "proposition_digest", "checking_mechanism", "scope",
)
_PASS_TABLE_ENTRY_FIELDS = (
    "source_index", "object_index", "route_index", "instance_digest",
    "semantic_definition_index", "kind_requirement_definition_index",
    "complete_instance_digest", "native_specimen_is_instance_evidence",
    "package_graph_replay_is_instance_evidence", "check_definition_index",
    "full_check_digest", "adaptation_result_digest", "result_digest",
)
_PASS_CHECK_IDENTITY_FIELDS = (
    "object_id", "object_digest", "coordinate", "proposition_digest",
    "checking_mechanism", "native_coordinate", "conditional_coordinate",
)
_PASS_CHECK_IDENTITY_MARKER = "projection_identity_fields"
_PASS_CHECK_RESULT_MARKER = "projection_recompute_result_digest"
_FOCUS_IDENTIFIER_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)


class PackagePolishUnknown(Exception):
    """A missing selection is unresolved evidence, not a contradiction."""


class PackagePolishCapacity(Exception):
    """Finite package report work exceeded its declared API envelope."""


class PackageGraphCompositionRefusal(Exception):
    """A non-PASS typed composition verdict for the selected package graph.

    This is deliberately not a ``ValueError``: generic contract handlers would
    fold its ``UNKNOWN`` or ``FAIL`` into one rejection and drop the assessment
    reason that names the exact refuted or unestablished proposition.
    """

    def __init__(self, verdict: str, reason: str) -> None:
        super().__init__(f"PACKAGE_GRAPH_COMPOSITION_{verdict}")
        self.verdict = verdict
        self.reason = reason


_GRAPH_COMPOSITION_CODES = frozenset({
    "PACKAGE_GRAPH_COMPOSITION_NOT_PASS",
    "PACKAGE_GRAPH_COMPOSITION_FAILED",
})
_GRAPH_COMPOSITION_REASON_LIMIT = 512
_UNRETAINED_COMPOSITION_REASON = (
    "The typed composition assessment retained no reason text."
)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _cumulative_gate_depths(tier: int) -> tuple[int, ...]:
    """Return the one admitted numeric prefix; never select a direct tier.

    Gate zero is repository admission over the root ``objects.vstd`` package
    graph.  Numeric Polish 1, 2, and 3 can only extend that prefix.  Keeping
    this selector beside the package evaluator prevents a command path from
    silently replacing cumulative package work with one native specimen tier.
    """

    _require(type(tier) is int and tier in {1, 2, 3}, "PACKAGE_TIER_UNSUPPORTED")
    return tuple(range(tier + 1))


def _is_digest(value: Any) -> bool:
    """Recognize the one digest wire form used by package-polish receipts."""

    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _catalog_route_index(
    catalog: Any,
) -> dict[tuple[Any, Any, Any], dict[str, Any]] | None:
    """Index an installed catalog only when every route key is unambiguous."""

    if type(catalog) is not list:
        return None
    indexed = {}
    for route in catalog:
        if type(route) is not dict:
            return None
        key = (
            route.get("object_kind"), route.get("tier"), route.get("coordinate"),
        )
        if key in indexed:
            return None
        indexed[key] = route
    return indexed


def _conditional_refutation_matches_route(
    route: dict[str, Any], check: Any,
) -> bool:
    """Accept a non-trigger only for its exact installed conditional route."""

    try:
        declaration = validate_applicability_binding(route)
    except (TypeError, ValueError):
        return False
    return bool(
        declaration["mode"] == "CONDITIONAL"
        and type(check) is dict
        and check.get("status") == "PASS"
        and check.get("evidence_origin")
        == "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
        and check.get("applicability_established") is True
        and check.get("applicability_classification")
        == "CONDITION_NOT_MET"
        and check.get("fulfillment_required") is False
        and check.get("native_coordinate") == route.get("coordinate")
        and check.get("conditional_coordinate") == route.get("coordinate")
        and check.get("condition") == declaration["condition"]
        and check.get("applicability_digest")
        == route.get("applicability_digest")
        and check.get("condition_status") == "NOT_TRIGGERED"
        and check.get("result_digest") == binding.value_digest({
            key: value for key, value in check.items()
            if key != "result_digest"
        })
    )


def _manifest_refresh_binding(
    *,
    status: str,
    disposition: str,
    receipt_reference: dict[str, Any] | None,
    assessed_manifest_digest: str | None,
    assessed_source_census_digest: str | None,
    assessed_source_coordinate_digest: str | None,
    failure_code: str | None,
) -> dict[str, Any]:
    """Retain one explicit, bounded refresh disposition beside the assessment."""

    return {
        "schema_version": REFRESH_BINDING_SCHEMA,
        "status": status,
        "disposition": disposition,
        "receipt_reference": receipt_reference,
        "assessed_manifest_digest": assessed_manifest_digest,
        "assessed_source_census_digest": assessed_source_census_digest,
        "assessed_source_coordinate_digest": (
            assessed_source_coordinate_digest
        ),
        "failure_code": failure_code,
        "claim_boundary": (
            "The path-free refresh reference is matched to this package "
            "assessment snapshot. Refresh is neither repository admission "
            "nor a polish verdict."
            if receipt_reference is not None
            else
            "No refresh receipt was supplied; this binds the assessed manifest "
            "and source coordinate without claiming refresh execution."
        ),
    }


def _initial_manifest_refresh_binding(
    manifest_digest: str | None,
) -> dict[str, Any]:
    """Represent a direct assessment before its source coordinate is captured."""

    return _manifest_refresh_binding(
        status="UNKNOWN",
        disposition="NOT_REQUESTED",
        receipt_reference=None,
        assessed_manifest_digest=manifest_digest,
        assessed_source_census_digest=None,
        assessed_source_coordinate_digest=None,
        failure_code=None,
    )


def _no_refresh_binding(
    manifest_digest: str,
    source_coordinate_digest: str,
) -> dict[str, Any]:
    """Bind a direct API assessment without inventing a refresh receipt."""

    _require(
        _is_digest(manifest_digest) and _is_digest(source_coordinate_digest),
        "PACKAGE_REFRESH_DIRECT_COORDINATE_INVALID",
    )
    return _manifest_refresh_binding(
        status="PASS",
        disposition="NOT_REQUESTED",
        receipt_reference=None,
        assessed_manifest_digest=manifest_digest,
        assessed_source_census_digest=None,
        assessed_source_coordinate_digest=source_coordinate_digest,
        failure_code=None,
    )


def _manifest_refresh_reference(refresh: Any) -> dict[str, Any]:
    """Project an accepted receipt to a sealed reference without local paths."""

    _require(
        self_polish_tiers._manifest_refresh_allows_assessment(refresh),
        "PACKAGE_REFRESH_RECEIPT_INVALID",
    )
    body = {
        "schema_version": REFRESH_REFERENCE_SCHEMA,
        "receipt_schema_version": refresh["schema_version"],
        "status": refresh["status"],
        "before_digest": refresh["before_digest"],
        "after_digest": refresh["after_digest"],
        "backup_digest": refresh["backup_digest"],
        "source_census_digest": refresh["source_census_digest"],
        "migration_mechanism_digest": refresh["migration_mechanism_digest"],
        "prepared_receipt_digest": refresh.get("prepared_receipt_digest"),
        "directory_durability": refresh.get("directory_durability"),
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    return {**body, "reference_digest": binding.value_digest(body)}


def bind_manifest_refresh_report(
    report: dict[str, Any],
    source_root: str | Path,
    refresh: Any,
) -> dict[str, Any]:
    """Bind a command refresh receipt to the exact completed assessment.

    Legacy and malformed producer outputs are left for the publication schema
    gate. A version-2 report with the required assessment coordinates is
    independently recaptured here, after assessment, so a receipt accepted
    before execution cannot be replayed onto different manifest or source bytes.
    """

    if (
        type(report) is not dict
        or report.get("schema_version") != EXTENSIBLE_REPORT_SCHEMA
    ):
        return report
    manifest = report.get("manifest")
    if (
        type(manifest) is not dict
        or not _is_digest(manifest.get("digest"))
        or not _is_digest(report.get("source_coordinate_digest"))
        or type(report.get("source_coordinate")) is not dict
        or not _is_digest(report.get("report_digest"))
    ):
        return report
    retained_report_digest = report["report_digest"]
    report_body = dict(report)
    report_body.pop("report_digest", None)
    try:
        if retained_report_digest != binding.value_digest(report_body):
            return report
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        return report

    root: Path | None = None
    reference: dict[str, Any] | None = None
    actual_manifest_digest: str | None = None
    actual_source_census_digest: str | None = None
    actual_source_coordinate_digest: str | None = None
    failure_code: str | None = None
    disposition = "NOT_ESTABLISHED"
    try:
        reference = _manifest_refresh_reference(refresh)
        disposition = reference["status"]
        root = Path(source_root).resolve(strict=True)
        actual_manifest_digest = binding.bytes_digest(_read_manifest(root))
        coordinate = self_polish_statics._capture_coordinate(root)
        actual_source_coordinate_digest = binding.value_digest(coordinate)
        if reference["source_census_digest"] is not None:
            from verifier.runtime import package_manifest_migration

            actual_source_census_digest = (
                package_manifest_migration.source_refresh_coordinate(root)[0]
            )
        if actual_manifest_digest != manifest["digest"]:
            failure_code = "PACKAGE_REFRESH_MANIFEST_DIGEST_DIFFERS"
        elif reference["after_digest"] != manifest["digest"]:
            failure_code = "PACKAGE_REFRESH_AFTER_DIGEST_DIFFERS"
        elif (
            actual_source_coordinate_digest
            != report["source_coordinate_digest"]
        ):
            failure_code = "PACKAGE_REFRESH_SOURCE_COORDINATE_DIFFERS"
        elif (
            reference["source_census_digest"] is not None
            and actual_source_census_digest
            != reference["source_census_digest"]
        ):
            failure_code = "PACKAGE_REFRESH_SOURCE_CENSUS_DIFFERS"
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        failure_code = "PACKAGE_REFRESH_BINDING_UNAVAILABLE"
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        failure_code = str(exc) or "PACKAGE_REFRESH_BINDING_REJECTED"

    report.pop("report_digest", None)
    report["manifest_refresh"] = _manifest_refresh_binding(
        status="FAIL" if failure_code is not None else "PASS",
        disposition=disposition,
        receipt_reference=reference,
        assessed_manifest_digest=actual_manifest_digest,
        assessed_source_census_digest=actual_source_census_digest,
        assessed_source_coordinate_digest=actual_source_coordinate_digest,
        failure_code=failure_code,
    )
    if failure_code is not None:
        report["status"] = "FAIL"
        report["whole_package_conformance"] = "NOT_ESTABLISHED"
        report["polished"] = False
        blockers = report.get("blockers")
        if type(blockers) is not list:
            blockers = []
            report["blockers"] = blockers
        blockers.append(failure_code)
    return _seal(report, source_root=root)


_SELECTED_MANIFEST_FIELDS = frozenset({"path", "status", "digest"})
_MANIFEST_VALIDATION_FIELDS = frozenset({
    "schema_version", "status", "profile_digest", "object_count",
    "object_kind_digest", "graph_digest", "semantic_version", "slot_count",
    "route_count", "slot_digest", "route_identity_digest",
    "surface_rule_count", "surface_rule_digest",
    "reason_provider_selection_status", "node_reconciler_selection_status",
    "attachment_selection_digest", "adversarial_corpus_status",
    "adversarial_corpus_digest", "claim_boundary",
})


def _capacity_source_route_outcome(
    source_assessment: Any,
    instance_evidence: InstanceEvidence,
    item: namespace.NamespaceObject,
    route: dict[str, Any],
    *,
    object_kind: str,
    tier: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Replay the producer's positive-before-refutation decision order.

    Source review can refute a retained native-runtime variant even when the
    selected package subject has stronger, freshly reconstructed evidence for
    the same route.  Package evaluation consumes that positive evidence first;
    a capacity replay must do the same or it will misclassify a necessary PASS
    (notably the package-root ``GRAPH-3.1`` replay) as conditionally inapplicable.

    The returned pair is ``(positive_replay, conditional_refutation)``.  At
    most one member is populated.  This is source-derived authority, not a
    report-local preference between two mutually consistent hashes.
    """

    execution_mechanism = package_execution.route_mechanism(route)
    source_route = package_source_contracts.is_route(route)
    replayed = None
    if source_route:
        replayed = source_assessment.evaluate(item, route)
    elif execution_mechanism is not None:
        replayed = package_execution.evaluate(instance_evidence, item, route)
    else:
        replayed = instance_evidence.evaluate(item, route)
    if replayed is not None or source_route:
        return replayed, None
    return None, source_assessment.refute_native_runtime_variant(
        item,
        route,
        object_kind=object_kind,
        tier=tier,
    )


def _graph_composition_outcome(
    composition: Any,
    *,
    graph_digest: str,
    object_count: int,
) -> tuple[str, str]:
    """Return the selected graph's own verdict and its bounded assessment reason.

    Only a PASS that binds the selected collection continues: the assessment
    must carry the same collection digest and the same object count. FAIL stays
    a refutation. Every other shape, including an unbound PASS, is UNKNOWN, so a
    replacement assessment can never widen the graph verdict.
    """

    verdict = getattr(composition.verdict, "value", composition.verdict)
    reason = composition.reason
    if type(reason) is not str or not reason.strip():
        reason = _UNRETAINED_COMPOSITION_REASON
    reason = reason[:_GRAPH_COMPOSITION_REASON_LIMIT]
    if verdict == "PASS":
        if (composition.collection_digest == graph_digest
                and composition.objects_checked == object_count):
            return "PASS", reason
        return "UNKNOWN", (
            "The PASS assessment does not bind the selected collection digest "
            "and object count, so the package graph composition is not established."
        )
    if verdict == "FAIL":
        return "FAIL", reason
    return "UNKNOWN", reason


def _source_capacity_binding(
    source_root: str | Path | None,
    requested_tier: int,
) -> dict[str, Any]:
    """Replay the capacity denominator from the caller-selected source root.

    A capacity report is a projection of a larger in-memory assessment, so its
    own mutually consistent digests cannot establish what the selected source
    contained. This replay re-reads the canonical ``objects.vstd`` bytes,
    re-runs the package selector, and reconstructs the exact graph identities
    that a compact receipt is allowed to retain. The source coordinate is
    recaptured independently as part of the same replay; callers compare it to
    the coordinate captured before package evaluation.

    ``source_root`` is deliberately supplied by ``assess_package_polish`` and
    never recovered from report data or the process current directory.
    """

    if source_root is None:
        raise ValueError("PACKAGE_CAPACITY_SOURCE_ROOT_REQUIRED")
    _require(
        type(requested_tier) is int and requested_tier in {1, 2, 3},
        "PACKAGE_CAPACITY_REQUESTED_TIER_INVALID",
    )
    root = Path(source_root).resolve(strict=True)
    # Pin the whole source before any selector or role-classification work.
    # The matching recapture below closes changes to non-manifest inputs too;
    # rereading objects.vstd alone cannot establish a stable source replay.
    captured_source = self_polish_statics._capture_coordinate(root)
    raw = _read_manifest(root)
    document = tier_zero_manifest._strict_json_document(raw)
    coordinate = self_polish_estate._git_coordinate(root)
    manifest, validation, objects = package_manifest.select(
        document,
        repository=coordinate["repository"],
        revision=coordinate["revision"],
    )
    semantic_namespace = _semantic_namespace(document)
    root_id = next(
        row["object_id"]
        for row in manifest["objects"]
        if row["object_kind"] == "GRAPH"
    )
    graph = next(item for item in objects if item.object_id == root_id)
    collection_digest = namespace.composition_digest(objects)
    composition = namespace.assess_composition(
        objects,
        expected_digest=collection_digest,
    )
    outcome, composition_reason = _graph_composition_outcome(
        composition,
        graph_digest=collection_digest,
        object_count=len(objects),
    )
    if outcome != "PASS":
        raise PackageGraphCompositionRefusal(outcome, composition_reason)
    declarations = semantic_namespace.get("objects")
    if type(declarations) is not list:
        declarations = manifest["objects"]
    declaration_by_id = {
        row.get("object_id"): row
        for row in declarations
        if type(row) is dict and type(row.get("object_id")) is str
    }
    _require(
        len(declaration_by_id) == len(objects),
        "PACKAGE_CAPACITY_SOURCE_GRAPH_DENOMINATOR_DIFFERS",
    )
    graph_objects = []
    declaration_profiles = {}
    for item in objects:
        declaration = declaration_by_id.get(item.object_id)
        specializations = (
            declaration.get("specializations", [])
            if type(declaration) is dict else None
        )
        _require(
            type(specializations) is list
            and len(specializations) == len(set(specializations))
            and all(type(kind) is str and bool(kind) for kind in specializations),
            "PACKAGE_CAPACITY_SOURCE_SPECIALIZATIONS_INVALID",
        )
        graph_objects.append({
            "object_id": item.object_id,
            "kind": item.kind.value,
            "object_digest": item.digest,
            "specializations": list(specializations),
        })
        declared_kind = declaration.get("kind") if type(declaration) is dict else None
        _require(
            type(declared_kind) is str and bool(declared_kind),
            "PACKAGE_CAPACITY_SOURCE_DECLARED_KIND_INVALID",
        )
        declaration_profiles[item.object_id] = {
            "declared_kind": declared_kind,
            "specializations": list(specializations),
        }
    # Reconstruct the producer's exact effective-role selection from this
    # caller-selected source snapshot.  Declared kind plus specializations is
    # not the selection denominator: classification also supplies inherited
    # base roles (notably ubiquitous OBJECT) and source-derived consequential
    # roles.  The compact receipt must compare against the same preflight that
    # ran before instance evaluation, rather than guessing those roles from
    # projected report rows.
    kind_requirements = KindRequirements(root, semantic_namespace)
    _, selected_instance_index = _obligation_selection_preflight(
        requested_tier, objects, kind_requirements, None,
    )
    # Capacity publication is an authority-bearing local issuance step, not
    # merely a portable digest check. Re-run the installed source assessment
    # for every selected source-owned native family so a report-local rewrite
    # cannot turn NOT_REQUIRED into PASS or substitute its reason/digest.
    from verifier.runtime import manifest_gate

    route_by_key = _catalog_route_index(manifest_gate.obligation_catalog())
    _require(
        route_by_key is not None,
        "PACKAGE_CAPACITY_SOURCE_ROUTE_CATALOG_AMBIGUOUS",
    )
    object_by_id = {item.object_id: item for item in objects}
    conditional_source_authority = {}
    if selected_instance_index:
        source_assessment = package_source_contracts.SourceContractAssessment(
            root, objects, kind_requirements
        )
        instance_evidence = InstanceEvidence(
            root,
            objects,
            semantic_namespace,
            package_graph_id=root_id,
            representation_updates=document.get("representation_updates"),
        )
        for selected in selected_instance_index:
            route = route_by_key.get((
                selected["object_kind"], selected["tier"],
                selected["coordinate"],
            ))
            item = object_by_id.get(selected["object_id"])
            _require(
                type(route) is dict and item is not None,
                "PACKAGE_CAPACITY_SOURCE_ROUTE_MISSING",
            )
            # This replay retains only conditional refutations.  Source routes,
            # necessary routes, and the generic representation route can never
            # contribute one; evaluating their positive evidence here repeated
            # expensive work without changing the authority map.
            if not package_source_contracts.can_refute_native_runtime_variant(route):
                continue
            _, refutation = _capacity_source_route_outcome(
                source_assessment,
                instance_evidence,
                item,
                route,
                object_kind=selected["object_kind"],
                tier=selected["tier"],
            )
            if refutation is not None:
                conditional_source_authority[
                    (selected["object_id"], selected["coordinate"])
                ] = refutation
    kind_requirements.recapture()
    declaration_profile = _graph_declaration_profile(
        document, manifest, semantic_namespace=semantic_namespace,
    )
    retained_declaration_profile = {
        key: declaration_profile[key]
        for key in (
            "declaration_count",
            "declaration_digest",
            "object_payloads_transport",
        )
        if key in declaration_profile
    }
    _require(
        _read_manifest(root) == raw,
        "PACKAGE_CAPACITY_SOURCE_MANIFEST_CHANGED_DURING_REPLAY",
    )
    _require(
        self_polish_statics._capture_coordinate(root) == captured_source,
        "PACKAGE_CAPACITY_SOURCE_CHANGED_DURING_REPLAY",
    )
    return {
        "source_coordinate": captured_source,
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": binding.bytes_digest(raw),
            "validation": validation,
        },
        "selected_instance_index": selected_instance_index,
        "conditional_source_authority": conditional_source_authority,
        "declaration_profiles": declaration_profiles,
        "package_graph": {
            "status": "PASS",
            "root_id": graph.object_id,
            "root_kind": "GRAPH",
            "manifest_digest": binding.bytes_digest(raw),
            "collection_digest": collection_digest,
            "object_count": len(objects),
            "objects": graph_objects,
            **retained_declaration_profile,
        },
    }


def _selected_source_manifest_complete(
    manifest: Any,
    graph_reference: dict[str, Any],
    source_binding: dict[str, Any],
) -> bool:
    """Validate the producer-shaped selected-manifest source contract.

    Normal package reports retain the Tier-0 validation receipt beside the
    three-field manifest identity.  Capacity reports project that receipt away,
    but must distinguish this one producer-owned extension from arbitrary
    source fields before calling the remaining denominator complete.
    """

    if type(manifest) is not dict:
        return False
    fields = frozenset(manifest)
    if fields != _SELECTED_MANIFEST_FIELDS | {"validation"}:
        return False
    if not (
        manifest.get("path") == "objects.vstd"
        and manifest.get("status") == "SELECTED"
        and _is_digest(manifest.get("digest"))
        and manifest["digest"] == graph_reference.get("manifest_digest")
    ):
        return False
    validation = manifest["validation"]
    selected = source_binding.get("manifest")
    return bool(
        type(selected) is dict
        and type(validation) is dict
        and frozenset(validation) == _MANIFEST_VALIDATION_FIELDS
        and frozenset(selected.get("validation", {}))
        == _MANIFEST_VALIDATION_FIELDS
        and manifest == selected
        # Admission validates the retained 26-object Tier-0 graph; package
        # polish evaluates the separately composed package GRAPH. Reusing the
        # admission digest would collapse those two evidence scopes.
        and validation["graph_digest"]
        != graph_reference.get("collection_digest")
    )


class PreencodingEnvelope(NamedTuple):
    """Pre-encoding size verdict; a refusal is never a package verdict."""

    within_envelope: bool
    reason: str | None
    visits: int
    lower_bound_bytes: int


class _PreencodingFrame:
    """One unfinished JSON container in the iterative pre-encoding walk."""

    __slots__ = ("identity", "entries", "depth", "is_dict", "count", "subtotal")

    def __init__(
        self,
        identity: int,
        entries: Iterator[tuple[Any, Any]],
        depth: int,
        is_dict: bool,
    ) -> None:
        self.identity = identity
        self.entries = entries
        self.depth = depth
        self.is_dict = is_dict
        self.count = 0
        self.subtotal = 0


def _preencoding_scalar_bytes(item: Any) -> int | None:
    """Lower-bound one JSON scalar's canonical bytes; None means unencodable."""

    if item is None or item is True:
        return 4
    if item is False:
        return 5
    if isinstance(item, str):
        return str.__len__(item) + 2
    if isinstance(item, int):
        return 1
    if isinstance(item, float):
        return 1 if math.isfinite(item) else None
    return None


def _preencoding_entries(container: Any) -> Iterator[tuple[Any, Any]]:
    if isinstance(container, dict):
        return iter(container.items())
    return ((None, child) for child in container)


def _assess_preencoding_envelope(
    value: Any,
    *,
    byte_limit: int | None = None,
) -> PreencodingEnvelope:
    """Refuse an over-envelope value before its canonical encoding exists.

    The lower bound follows the exact canonical grammar: an object costs its
    braces, separators, quoted keys and colons, and an array its brackets and
    commas.  Each unique container is measured once by identity; a shared
    container referenced many times contributes its memoized size per reference,
    so the byte estimate expands as canonical JSON would while the visits stay
    linear in unique structure.  Traversal is iterative, so input depth cannot
    recurse.  Cycles, unencodable leaves, excessive depth and the visit budget
    are refused with reasons instead of estimated.
    """

    limit = (
        RAW_SOURCE_ENVELOPE_FACTOR * MAX_REPORT_BYTES
        if byte_limit is None else byte_limit
    )
    if not isinstance(value, (dict, list, tuple)):
        scalar = _preencoding_scalar_bytes(value)
        if scalar is None:
            return PreencodingEnvelope(False, _PREENCODING_UNENCODABLE, 1, 0)
        within = scalar <= limit
        return PreencodingEnvelope(
            within, None if within else _PREENCODING_BYTES, 1, scalar,
        )
    measured: dict[int, int] = {}
    active: set[int] = set()
    stack: list[_PreencodingFrame] = []
    visits = 1
    root = id(value)
    active.add(root)
    stack.append(_PreencodingFrame(
        root, _preencoding_entries(value), 0, isinstance(value, dict),
    ))
    while stack:
        frame = stack[-1]
        entry = next(frame.entries, _PREENCODING_DONE)
        if entry is _PREENCODING_DONE:
            stack.pop()
            active.discard(frame.identity)
            size = 2 + max(frame.count - 1, 0) + frame.subtotal
            measured[frame.identity] = size
            if size > limit:
                return PreencodingEnvelope(False, _PREENCODING_BYTES, visits, size)
            if not stack:
                return PreencodingEnvelope(True, None, visits, size)
            parent = stack[-1]
            parent.subtotal += size
            if parent.subtotal > limit:
                return PreencodingEnvelope(
                    False, _PREENCODING_BYTES, visits, parent.subtotal,
                )
            continue
        key, child = entry
        visits += 1
        if visits > MAX_PREENCODING_VISITS:
            return PreencodingEnvelope(
                False, _PREENCODING_VISITS, visits, frame.subtotal,
            )
        frame.count += 1
        if frame.is_dict:
            key_bytes = _preencoding_scalar_bytes(key)
            if key_bytes is None:
                return PreencodingEnvelope(
                    False, _PREENCODING_UNENCODABLE, visits, frame.subtotal,
                )
            frame.subtotal += key_bytes + 1
        if isinstance(child, (dict, list, tuple)):
            identity = id(child)
            if identity in measured:
                frame.subtotal += measured[identity]
            elif identity in active:
                return PreencodingEnvelope(
                    False, _PREENCODING_CYCLIC, visits, frame.subtotal,
                )
            elif frame.depth >= MAX_PREENCODING_DEPTH:
                return PreencodingEnvelope(
                    False, _PREENCODING_DEPTH, visits, frame.subtotal,
                )
            else:
                active.add(identity)
                stack.append(_PreencodingFrame(
                    identity,
                    _preencoding_entries(child),
                    frame.depth + 1,
                    isinstance(child, dict),
                ))
                continue
        else:
            scalar = _preencoding_scalar_bytes(child)
            if scalar is None:
                return PreencodingEnvelope(
                    False, _PREENCODING_UNENCODABLE, visits, frame.subtotal,
                )
            frame.subtotal += scalar
        if frame.subtotal > limit:
            return PreencodingEnvelope(
                False, _PREENCODING_BYTES, visits, frame.subtotal,
            )
    raise AssertionError("PREENCODING_WALK_EXHAUSTED_WITHOUT_ROOT")


def _preencoding_refusal(value: Any, *, byte_limit: int | None = None) -> str | None:
    """Return the reason a value must not be encoded whole, or None."""

    verdict = _assess_preencoding_envelope(value, byte_limit=byte_limit)
    return None if verdict.within_envelope else verdict.reason


def _source_report_identity(
    report: dict[str, Any],
    *,
    refused: bool,
) -> tuple[str, str | None, int | None]:
    """Name the complete source only when it was actually encoded.

    A refused source is never encoded, so no digest or byte count is claimed
    for it. Any encoding failure is also UNAVAILABLE rather than a substitute
    summary digest.
    """

    if refused:
        return "UNAVAILABLE", None, None
    try:
        source_body = {
            key: value for key, value in report.items()
            if key != "report_digest"
        }
        source_encoded = binding.canonical_bytes(source_body)
        return "AVAILABLE", binding.bytes_digest(source_encoded), len(source_encoded)
    except (
        TypeError, ValueError, UnicodeError,
        MemoryError, RecursionError, OverflowError,
    ):
        return "UNAVAILABLE", None, None


def _minimal_capacity_receipt(
    report: dict[str, Any],
    *,
    source_identity: tuple[str, str | None, int | None] | None = None,
) -> dict[str, Any]:
    from verifier.runtime import manifest_gate

    source_schema = report.get("schema_version")
    if source_schema == EXTENSIBLE_REPORT_SCHEMA:
        kind_denominators = namespace_contracts.validate_kind_denominators(
            report.get("kind_denominators")
        )
    else:
        kind_denominators = namespace_contracts.kind_denominators()

    manifest = report.get("manifest")
    manifest_summary = (
        {key: manifest.get(key) for key in ("path", "status", "digest")}
        if isinstance(manifest, dict)
        else None
    )
    source_blockers = report.get("blockers")
    retained_blockers = (
        [item for item in source_blockers if type(item) is str]
        if type(source_blockers) is list else []
    )
    source_rows = report.get("obligation_instances")
    source_instance_count = len(source_rows) if type(source_rows) is list else 0
    source_findings = report.get("findings")
    omitted_finding_count = (
        len(source_findings) if type(source_findings) is list else 0
    )
    requested_tier = report.get("requested_tier")
    selected_tier = (
        requested_tier
        if type(requested_tier) is int and requested_tier in {0, 1, 2, 3}
        else 0
    )
    capacity_finding = manifest_gate.repository_finding(
        "PACKAGE_REPORT_CAPACITY_EXHAUSTED", "UNKNOWN", tier=selected_tier,
    )
    projection = report.get("obligation_instance_projection")
    if (
        type(projection) is dict
        and projection.get("schema_version") == _PASS_TABLE_PROJECTION_SCHEMA
        and type(projection.get("source_instance_count")) is int
        and projection["source_instance_count"] >= source_instance_count
    ):
        source_instance_count = projection["source_instance_count"]
    # Never put a digest of fallback metadata in a field that claims to
    # identify the complete source report, and never encode a source that the
    # pre-encoding envelope already refused.
    if source_identity is None:
        source_identity = _source_report_identity(
            report, refused=_preencoding_refusal(report) is not None,
        )
    (
        source_report_encoding_status,
        source_report_digest,
        source_report_bytes,
    ) = source_identity
    empty_index_body = {
        "schema_version": "verifier-package-obligation-index-1",
        "instance_count": 0,
        "status_counts": {},
        "entries": [],
    }
    body = {
        "schema_version": CAPACITY_REPORT_SCHEMA,
        "source_report_schema": source_schema,
        "claim_scope": "MANIFEST_PACKAGE_GRAPH",
        "kind_denominators": kind_denominators,
        "requested_tier": report.get("requested_tier"),
        "status": "FAIL" if report.get("status") == "FAIL" else "UNKNOWN",
        "blockers": sorted(set(
            retained_blockers + ["PACKAGE_REPORT_CAPACITY_EXHAUSTED"]
        )),
        "manifest": manifest_summary,
        "reason_authority": report.get("reason_authority"),
        "reason_reconciliation": report.get("reason_reconciliation"),
        "package_graph": None,
        "obligation_instances": [],
        "tier_results": [],
        "source_coordinate_digest": report.get("source_coordinate_digest"),
        "mechanism_digest": report.get("mechanism_digest"),
        "package_graph_reference": None,
        "native_diagnostics": None,
        "source_instance_count": source_instance_count,
        # A minimal receipt never proves that an empty list was the evaluated
        # denominator.  It is emitted precisely because the complete index or
        # its supporting cumulative evidence could not be retained.
        "denominator_status": "NOT_RETAINED",
        "obligation_index": {
            **empty_index_body,
            "index_digest": binding.value_digest(empty_index_body),
        },
        "finding_count": 1,
        "findings": [capacity_finding],
        "next_target": None,
        "omitted_finding_count": omitted_finding_count,
        "source_report_encoding_status": source_report_encoding_status,
        "source_report_digest": source_report_digest,
        "source_report_bytes": source_report_bytes,
        "omitted_sections": ["capacity_receipt_detail_unavailable"],
        "whole_package_conformance": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": (
            "The package assessment exceeded its finite report/work envelope. "
            "No omitted row is interpreted as passing or inapplicable."
        ),
    }
    return {**body, "report_digest": binding.value_digest(body)}


def _capacity_source_applicability(
    report: dict[str, Any], row: dict[str, Any]
) -> dict[str, Any] | None:
    """Recover the committed applicability body for trusted source replay."""

    applicability = row.get("applicability")
    realization = row.get("repository_realization")
    if not (
        type(realization) is dict
        and realization.get("schema_version")
        == "verifier-pass-instance-definition-reference-2"
    ):
        return applicability if type(applicability) is dict else None
    definition_digest = realization.get("semantic_definition_digest")
    definitions = report.get("pass_instance_definitions")
    if not (_is_digest(definition_digest) and type(definitions) is list):
        return None
    matching = [
        definition for definition in definitions
        if type(definition) is dict
        and definition.get("definition_digest") == definition_digest
    ]
    reference_reason = (
        "See pass_instance_definitions semantic definition "
        + definition_digest + "."
    )
    retained_applicability = (
        matching[0].get("applicability") if len(matching) == 1 else None
    )
    if not (
        len(matching) == 1
        and type(applicability) is dict
        and type(retained_applicability) is dict
        and applicability.get("status") == retained_applicability.get("status")
        and applicability.get("classification")
        == retained_applicability.get("classification")
        and applicability.get("assessment_required") is True
        and applicability.get("reason") == reference_reason
        and row.get("reason") == reference_reason
        and matching[0].get("definition_kind") == "SEMANTIC"
        and matching[0].get("definition_digest") == binding.value_digest({
            key: value for key, value in matching[0].items()
            if key != "definition_digest"
        })
    ):
        return None
    return retained_applicability


def _capacity_denominator_complete(
    report: dict[str, Any],
    entries: list[dict[str, Any]],
    graph_reference: dict[str, Any] | None,
    source_root: str | Path | None,
    rows: list[dict[str, Any]] | None = None,
    refusals: list[PackageGraphCompositionRefusal] | None = None,
    source_report_digest: str | None = None,
) -> bool:
    """Return whether a capacity receipt accounts for the requested polish.

    ``COMPLETE`` means complete accounting, not PASS.  Non-passing and unsafe
    native tiers may remain FAIL, UNKNOWN or NOT_RUN, but Tier 3 must retain one
    explicit execution record for every native tier 0--3.  Earlier executed
    tiers must also retain their digest-bound prerequisite references.
    """

    requested = report.get("requested_tier")
    if rows is None:
        rows = _capacity_source_rows(report)
    tier_results = report.get("tier_results")
    source_coordinate_digest = report.get("source_coordinate_digest")
    mechanism_digest = report.get("mechanism_digest")
    source_coordinate = report.get("source_coordinate")
    try:
        kind_denominators = namespace_contracts.validate_kind_denominators(
            report.get("kind_denominators")
        )
    except ValueError:
        return False
    if (
        type(requested) is not int
        or requested not in {1, 2, 3}
        or report.get("schema_version") not in {REPORT_SCHEMA, EXTENSIBLE_REPORT_SCHEMA}
        or type(rows) is not list
        or len(entries) != len(rows)
        or type(graph_reference) is not dict
        or type(tier_results) is not list
        or not _is_digest(source_coordinate_digest)
        or not _is_digest(mechanism_digest)
        or type(source_coordinate) is not dict
        or binding.value_digest(source_coordinate) != source_coordinate_digest
        or kind_denominators != namespace_contracts.kind_denominators()
    ):
        return False
    retained_by_tier = {
        item.get("tier"): item for item in tier_results if type(item) is dict
    }
    if (
        len(retained_by_tier) != len(tier_results)
        or set(retained_by_tier) != set(range(1, requested + 1))
        or not entries
    ):
        return False
    try:
        source_binding = _source_capacity_binding(source_root, requested)
    except PackageGraphCompositionRefusal as refusal:
        # The replayed source no longer composes as PASS. The denominator is
        # not retained, and the caller keeps this verdict and reason visible.
        if refusals is not None:
            refusals.append(refusal)
        return False
    except (
        AttributeError, KeyError, StopIteration, TypeError, ValueError,
        PackagePolishCapacity, *_RESOURCE_ERRORS,
    ):
        return False
    if source_binding.get("source_coordinate") != source_coordinate:
        return False
    source_graph = source_binding.get("package_graph")
    conditional_source_authority = source_binding.get(
        "conditional_source_authority"
    )
    manifest = report.get("manifest")
    if not (
        type(source_graph) is dict
        and type(conditional_source_authority) is dict
        and _selected_source_manifest_complete(
            manifest,
            graph_reference,
            source_binding,
        )
        and graph_reference.get("status") == "PASS"
        and type(graph_reference.get("root_id")) is str
        and bool(graph_reference["root_id"])
        and graph_reference.get("root_kind") == "GRAPH"
        and type(graph_reference.get("object_count")) is int
        and 26 <= graph_reference["object_count"] <= 4096
        and all(_is_digest(graph_reference.get(field))
                for field in ("manifest_digest", "collection_digest"))
    ):
        return False
    graph_objects = graph_reference.get("objects")
    if type(graph_objects) is not list or len(graph_objects) != graph_reference["object_count"]:
        return False
    source_graph_fields = (
        "status", "root_id", "root_kind", "manifest_digest",
        "collection_digest", "object_count", "declaration_count",
        "declaration_digest", "object_payloads_transport", "objects",
    )
    if any(
        graph_reference.get(field) != source_graph.get(field)
        for field in source_graph_fields
        if field in source_graph or field in graph_reference
    ):
        return False
    graph_by_id = {
        item.get("object_id"): item
        for item in graph_objects
        if type(item) is dict and type(item.get("object_id")) is str
    }
    if len(graph_by_id) != len(graph_objects) or not all(
        type(item.get("kind")) is str
        and _is_digest(item.get("object_digest"))
        and type(item.get("specializations")) is list
        and len(item["specializations"]) == len(set(item["specializations"]))
        and all(type(kind) is str and bool(kind) for kind in item["specializations"])
        for item in graph_objects
    ):
        return False
    root_object = graph_by_id.get(graph_reference["root_id"])
    if type(root_object) is not dict or root_object.get("kind") != "GRAPH":
        return False
    declaration_profiles = source_binding.get("declaration_profiles")
    if not (
        type(declaration_profiles) is dict
        and set(declaration_profiles) == set(graph_by_id)
        and all(
            type(profile) is dict
            and set(profile) == {"declared_kind", "specializations"}
            and type(profile.get("declared_kind")) is str
            and bool(profile["declared_kind"])
            and type(profile.get("specializations")) is list
            and profile["specializations"]
            == graph_by_id[object_id]["specializations"]
            for object_id, profile in declaration_profiles.items()
        )
    ):
        return False
    try:
        from verifier.runtime import manifest_gate

        catalog = manifest_gate.obligation_catalog()
    except (ImportError, AttributeError, TypeError, ValueError, *_RESOURCE_ERRORS):
        return False
    # Resolve each installed route once.  A local index avoids rescanning the
    # entire catalog for every object-bound instance, while explicit duplicate
    # rejection preserves the former ``len(routes) == 1`` fail-closed rule.
    route_by_key = _catalog_route_index(catalog)
    if route_by_key is None:
        return False
    source_selection = source_binding.get("selected_instance_index")
    if type(source_selection) is not list:
        return False
    selected_fields = {
        "object_id", "object_kind", "coordinate", "tier", "instance_digest",
    }
    if not all(
        type(item) is dict
        and set(item) == selected_fields
        and type(item.get("object_id")) is str
        and item["object_id"] in graph_by_id
        and type(item.get("object_kind")) is str
        and bool(item["object_kind"])
        and type(item.get("coordinate")) is str
        and bool(item["coordinate"])
        and type(item.get("tier")) is int
        and 1 <= item["tier"] <= requested
        and _is_digest(item.get("instance_digest"))
        for item in source_selection
    ):
        return False
    if source_selection != sorted(source_selection, key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    )):
        return False
    selected_by_key = {
        (item["object_id"], item["coordinate"]): item
        for item in source_selection
    }
    if (
        not selected_by_key
        or len(selected_by_key) != len(source_selection)
    ):
        return False

    verifier_execution = report.get("verifier_execution")
    if not (
        type(verifier_execution) is dict
        and verifier_execution.get("subject_id")
        == verifier_execution.get("object_id")
        and verifier_execution.get("verified_graph_id")
        == graph_reference.get("root_id")
        and verifier_execution.get("subject_collection_digest")
        == graph_reference.get("collection_digest")
        and verifier_execution.get("manifest_digest") == manifest.get("digest")
        and verifier_execution.get("mechanism_digest") == mechanism_digest
        and verifier_execution.get("requested_tier") == requested
    ):
        return False
    commitment = verifier_execution.get("obligation_denominator_commitment")
    commitment_schema = (
        commitment.get("schema_version") if type(commitment) is dict else None
    )
    common_commitment_fields = {
        "schema_version", "status", "selected_instance_count",
        "selected_instance_index_digest", "conditional_refutation_count",
        "conditional_refutations_digest", "claim_boundary",
        "commitment_digest",
    }
    expanded_commitment = (
        type(commitment) is dict
        and commitment_schema == _EXPANDED_DENOMINATOR_COMMITMENT_SCHEMA
        and set(commitment) == common_commitment_fields | {
            "conditional_refutations"
        }
        and type(commitment.get("conditional_refutations")) is list
        and len(commitment["conditional_refutations"])
        == commitment.get("conditional_refutation_count")
        and commitment.get("conditional_refutations_digest")
        == binding.value_digest(commitment["conditional_refutations"])
    )
    projected_commitment = (
        type(commitment) is dict
        and commitment_schema == _PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA
        and type(report.get("obligation_instance_projection")) is dict
        and report["obligation_instance_projection"].get("schema_version")
        in {
            "verifier-pass-instance-projection-2",
            _PASS_TABLE_PROJECTION_SCHEMA,
        }
        and type(report.get("pass_instance_definitions")) is list
        and set(commitment) == common_commitment_fields | {
            "conditional_refutations_transport"
        }
        and commitment.get("conditional_refutations_transport")
        == _PROJECTED_CONDITIONAL_TRANSPORT
    )
    if not (
        type(commitment) is dict
        and (expanded_commitment or projected_commitment)
        and commitment.get("status") == "COMMITTED"
        and type(commitment.get("selected_instance_count")) is int
        and commitment["selected_instance_count"] > 0
        and _is_digest(commitment.get("selected_instance_index_digest"))
        and type(commitment.get("conditional_refutation_count")) is int
        and commitment["conditional_refutation_count"] >= 0
        and _is_digest(commitment.get("conditional_refutations_digest"))
        and type(commitment.get("claim_boundary")) is str
        and bool(commitment["claim_boundary"].strip())
        and _is_digest(commitment.get("commitment_digest"))
        and commitment["commitment_digest"] == binding.value_digest({
            key: value for key, value in commitment.items()
            if key != "commitment_digest"
        })
    ):
        return False
    source_by_digest = {
        row.get("instance_digest"): row
        for row in rows
        if type(row) is dict and type(row.get("instance_digest")) is str
    }
    if len(source_by_digest) != len(rows):
        return False
    source_keys: set[tuple[str, str]] = set()
    compact_index = []
    conditional_refutations = []
    for entry in entries:
        if not (
            type(entry.get("object_id")) is str
            and type(entry.get("object_kind")) is str
            and type(entry.get("coordinate")) is str
            and type(entry.get("obligation_id")) is str
            and type(entry.get("tier")) is int
            and 1 <= entry["tier"] <= requested
            and entry.get("status") in {"PASS", "FAIL", "UNKNOWN"}
            and type(entry.get("checker_status")) is str
            and type(entry.get("instance_digest")) is str
            and type(entry.get("blockers")) is list
            and type(entry.get("actions")) is list
        ):
            return False
        row = source_by_digest.get(entry["instance_digest"])
        graph_object = graph_by_id.get(entry["object_id"])
        declaration_profile = declaration_profiles.get(entry["object_id"])
        instance_key = entry["object_id"], entry["coordinate"]
        source_selected = selected_by_key.get(instance_key)
        if instance_key in source_keys:
            return False
        source_keys.add(instance_key)
        route = route_by_key.get((
            entry["object_kind"], entry["tier"], entry["coordinate"],
        ))
        if not (
            type(row) is dict
            and type(graph_object) is dict
            and type(declaration_profile) is dict
            and row.get("object_id") == entry["object_id"]
            and row.get("object_kind") == entry["object_kind"]
            and row.get("coordinate") == entry["coordinate"]
            and row.get("tier") == entry["tier"]
            and 1 <= row["tier"] <= requested
            and row.get("status") == entry["status"]
            and row.get("checker_status") == entry["checker_status"]
            and row.get("object_digest") == graph_object.get("object_digest")
            and row.get("declared_kind")
            == declaration_profile.get("declared_kind")
            and row.get("specializations")
            == declaration_profile.get("specializations")
            and source_selected == {
                "object_id": entry["object_id"],
                "object_kind": entry["object_kind"],
                "coordinate": entry["coordinate"],
                "tier": entry["tier"],
                "instance_digest": entry["instance_digest"],
            }
            and type(route) is dict
            and entry.get("obligation_id") == route.get("obligation_id")
            and row.get("proposition_digest") == route.get("proposition_digest")
            and row.get("checking_mechanism") == route.get("checking_mechanism")
            and row.get("scope") == route.get("scope")
        ):
            return False
        identity = {
            "object_id": row.get("object_id"),
            "object_digest": row.get("object_digest"),
            "coordinate": row.get("coordinate"),
            "tier": row.get("tier"),
            "proposition_digest": row.get("proposition_digest"),
        }
        expected_instance_digest = binding.value_digest(identity)
        if not (
            _is_digest(entry["instance_digest"])
            and row.get("instance_digest") == expected_instance_digest
            and entry["instance_digest"] == expected_instance_digest
        ):
            return False
        compact_index.append({
            "object_id": entry["object_id"],
            "object_kind": entry["object_kind"],
            "coordinate": entry["coordinate"],
            "tier": entry["tier"],
            "instance_digest": entry["instance_digest"],
        })
        if (
            entry["status"] == "PASS"
            and entry["checker_status"] not in {"PASS", "NOT_REQUIRED"}
        ):
            return False
        expected_refutation = conditional_source_authority.get(instance_key)
        if expected_refutation is not None:
            applicability = _capacity_source_applicability(report, row)
            if not (
                entry["status"] == "PASS"
                and entry["checker_status"] == "NOT_REQUIRED"
                and entry["blockers"] == []
                and row.get("selected_package_check") == expected_refutation
                and type(applicability) is dict
                and applicability.get("status") == "PASS"
                and applicability.get("classification") == "CONDITION_NOT_MET"
                and applicability.get("assessment_required") is True
                and applicability.get("reason") == expected_refutation["reason"]
                and row.get("package_graph_replay_is_instance_evidence") is False
            ):
                return False
        elif entry["checker_status"] == "NOT_REQUIRED":
            # A portable self-digest is not authority for a conditional waiver.
            # Only the fresh caller-selected source replay may establish it.
            return False
        if entry["checker_status"] == "FAIL" and entry["status"] != "FAIL":
            return False
        if entry["checker_status"] == "NOT_REQUIRED":
            check = row.get("selected_package_check")
            applicability = row.get("applicability")
            if not (
                entry["status"] == "PASS"
                and entry["blockers"] == []
                and type(applicability) is dict
                and applicability.get("status") == "PASS"
                and applicability.get("classification") == "CONDITION_NOT_MET"
                and applicability.get("assessment_required") is True
                and type(applicability.get("reason")) is str
                and bool(applicability["reason"].strip())
                and row.get("package_graph_replay_is_instance_evidence") is False
                and type(check) is dict
                and check.get("status") == "PASS"
                and check.get("evidence_origin")
                == "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
                and check.get("applicability_established") is True
                and check.get("applicability_classification") == "CONDITION_NOT_MET"
                and check.get("fulfillment_required") is False
                and check.get("native_coordinate") == entry["coordinate"]
                and check.get("conditional_coordinate") == entry["coordinate"]
                and type(check.get("adaptation_obligation_id")) is str
                and bool(check["adaptation_obligation_id"].strip())
                and _is_digest(check.get("adaptation_result_digest"))
                and type(check.get("condition")) is str
                and bool(check["condition"].strip())
                and check.get("condition_status") == "NOT_TRIGGERED"
                and type(check.get("reason")) is str
                and bool(check["reason"].strip())
                and _conditional_refutation_matches_route(route, check)
            ):
                return False
            if (
                commitment_schema == _PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA
                and "result_digest" not in check
            ):
                return False
            if "result_digest" in check:
                if check["result_digest"] != binding.value_digest({
                    key: value for key, value in check.items()
                    if key != "result_digest"
                }):
                    return False
                conditional_evidence_digest = binding.value_digest(check)
            elif not (
                check.get("schema_version") == "verifier-package-check-reference-1"
                and check.get("transport") == "DIGEST_BOUND_REFERENCE"
                and _is_digest(check.get("full_check_digest"))
                and type(check.get("full_check_bytes")) is int
                and check["full_check_bytes"] > 0
            ):
                return False
            else:
                conditional_evidence_digest = check["full_check_digest"]
            conditional_refutations.append({
                "object_id": entry["object_id"],
                "object_kind": entry["object_kind"],
                "coordinate": entry["coordinate"],
                "tier": entry["tier"],
                "instance_digest": entry["instance_digest"],
                "status": "PASS",
                "checker_status": "NOT_REQUIRED",
                "reason": check["reason"],
                "evidence_digest": conditional_evidence_digest,
            })
        if entry["status"] != "PASS" and not (
            type(entry.get("reason")) is str
            and bool(entry["reason"].strip())
            and bool(entry["actions"])
            and type(entry.get("rerun_argv")) is list
            and bool(entry["rerun_argv"])
            and all(type(argument) is str for argument in entry["rerun_argv"])
        ):
            return False
    if (
        {entry["object_id"] for entry in entries} != set(graph_by_id)
        or source_keys != set(selected_by_key)
    ):
        return False
    compact_index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    conditional_refutations.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["instance_digest"],
    ))
    reconstructed_conditional_matches = (
        commitment["conditional_refutation_count"]
        == len(conditional_refutations)
        and commitment["conditional_refutations_digest"]
        == binding.value_digest(conditional_refutations)
        and (
            commitment_schema == _PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA
            or commitment["conditional_refutations"] == conditional_refutations
        )
    )
    retained_commitment = graph_reference.get(
        "obligation_denominator_commitment"
    )
    expected_retained_commitment = _capacity_denominator_commitment(
        report, rows, source_report_digest=source_report_digest,
    )
    if not (
        compact_index == source_selection
        and
        commitment["selected_instance_count"] == len(compact_index)
        and commitment["selected_instance_index_digest"]
        == binding.value_digest(compact_index)
        and reconstructed_conditional_matches
        and retained_commitment == expected_retained_commitment
    ):
        return False
    for depth, tier_result in retained_by_tier.items():
        # The producer summarizes the complete prefix through each depth.  The
        # capacity receipt must validate that same cumulative denominator.
        selected = [entry for entry in entries if entry["tier"] <= depth]
        if not selected:
            return False
        expected_statuses = dict(Counter(entry["status"] for entry in selected))
        expected_checkers = dict(Counter(
            entry["checker_status"] for entry in selected
        ))
        expected_status = (
            "FAIL" if expected_statuses.get("FAIL", 0) else
            "PASS" if selected and expected_statuses.get("PASS", 0) == len(selected)
            else "UNKNOWN"
        )
        if not (
            tier_result.get("instance_count") == len(selected)
            and tier_result.get("status_counts") == expected_statuses
            and tier_result.get("status") == expected_status
            and tier_result.get("checker_status_counts") == expected_checkers
            and tier_result.get("prerequisite_tiers") == list(range(depth))
        ):
            return False
    if requested != 3:
        return _native_execution_prefix_complete(
            report.get("native_diagnostics"),
            requested_tier=requested,
            source_coordinate_digest=source_coordinate_digest,
            manifest_digest=manifest["digest"],
        )
    native = report.get("native_diagnostics")
    if not (
        type(native) is dict
        and _is_digest(native.get("report_digest"))
        and verifier_execution.get("native_diagnostic_report_digest")
        == native["report_digest"]
    ):
        return False
    execution = native.get("tier_execution")
    prerequisites = native.get("prerequisites")
    if type(execution) is not dict or type(prerequisites) is not dict:
        return False
    if (
        set(execution) != {"0", "1", "2", "3"}
        or not set(prerequisites).issubset({"0", "1", "2"})
    ):
        return False
    replay_reference = native.get("complete_tier_evidence_replay")
    tier_names = {0: "ADMISSION", 1: "FACETS", 2: "DYNAMICS", 3: "STATICS"}
    prior_not_run = False
    for depth in range(4):
        record = execution.get(str(depth))
        if not (
            type(record) is dict
            and record.get("schema_version")
            == "verifier-self-polish-tier-execution-1"
            and record.get("tier") == depth
            and record.get("tier_name") == tier_names[depth]
            and record.get("execution_status") in {"EXECUTED", "NOT_RUN"}
            and record.get("status") in {"PASS", "FAIL", "UNKNOWN"}
            and type(record.get("reason")) is str
            and bool(record["reason"].strip())
            and type(record.get("execution_record_digest")) is str
            and record["execution_record_digest"] == binding.value_digest({
                key: value for key, value in record.items()
                if key != "execution_record_digest"
            })
        ):
            return False
        if prior_not_run and record["execution_status"] == "EXECUTED":
            return False
        if record["execution_status"] == "EXECUTED":
            if not (
                type(record.get("evidence_digest")) is str
                and len(record["evidence_digest"]) == 71
                and record["evidence_digest"].startswith("sha256:")
                and record.get("blocking_prerequisite") is None
            ):
                return False
            if depth == 3 and not (
                type(replay_reference) is dict
                and replay_reference.get("status") == record["status"]
                and replay_reference.get("evidence_digest")
                == record["evidence_digest"]
                and replay_reference.get("transport")
                == "DIGEST_BOUND_REFERENCE"
                and (
                    ("receipt_digest" in replay_reference)
                    != ("value_digest" in replay_reference)
                )
                and replay_reference.get(
                    "receipt_digest"
                    if "receipt_digest" in replay_reference
                    else "value_digest"
                ) == record["evidence_digest"]
            ):
                return False
        else:
            prior_not_run = True
            blocking = record.get("blocking_prerequisite")
            if not (
                record["status"] == "UNKNOWN"
                and record.get("evidence_digest") is None
                and type(blocking) is dict
                and type(blocking.get("tier")) is int
                and 0 <= blocking["tier"] <= depth
                and blocking.get("tier_name") == tier_names[blocking["tier"]]
                and blocking.get("required_status") == "PASS"
                and blocking.get("observed_status")
                in {"FAIL", "UNKNOWN"}
                and (
                    blocking.get("report_digest") is None
                    or _is_digest(blocking.get("report_digest"))
                )
                and type(blocking.get("blockers")) is list
                and bool(blocking["blockers"])
                and all(type(item) is str and bool(item)
                        for item in blocking["blockers"])
            ):
                return False
            if depth == 3 and replay_reference is not None:
                return False
        if (
            depth < 3
            and record["execution_status"] == "EXECUTED"
            and (
                type(prerequisites.get(str(depth))) is not dict
                or record["evidence_digest"]
                != prerequisites[str(depth)].get("report_digest")
                or prerequisites[str(depth)].get("status")
                not in {"PASS", "FAIL", "UNKNOWN"}
                or record["status"] != prerequisites[str(depth)]["status"]
            )
        ):
            return False
        if (
            depth in {1, 2}
            and record["execution_status"] == "EXECUTED"
            and (
                prerequisites[str(depth)].get("schema_version")
                != self_polish_tiers.REPORT_SCHEMA
                or prerequisites[str(depth)].get("tier") != depth
                or prerequisites[str(depth)].get("source_coordinate_digest")
                != report.get("source_coordinate_digest")
                or (
                    record["status"] == "PASS"
                    and prerequisites[str(depth)].get(
                        "post_replay_full_source_recapture"
                    ) != "PASS"
                )
            )
        ):
            return False
    expected_prerequisites = {
        str(depth) for depth in range(3)
        if execution[str(depth)]["execution_status"] == "EXECUTED"
    }
    if set(prerequisites) != expected_prerequisites:
        return False
    executed_nonpass: tuple[int, str, str] | None = None
    retained_blocking_anchor: dict[str, Any] | None = None
    for depth in range(4):
        record = execution[str(depth)]
        if record["execution_status"] == "EXECUTED":
            if executed_nonpass is not None or retained_blocking_anchor is not None:
                return False
            if record["status"] != "PASS":
                executed_nonpass = (
                    depth, record["status"], record["evidence_digest"]
                )
            continue
        blocking = record["blocking_prerequisite"]
        if retained_blocking_anchor is None:
            if executed_nonpass is not None:
                blocked_tier, blocked_status, blocked_digest = executed_nonpass
                prerequisite_blockers = prerequisites[
                    str(blocked_tier)
                ].get("blockers")
                if not (
                    blocking["tier"] == blocked_tier
                    and blocking["tier_name"] == tier_names[blocked_tier]
                    and blocking["observed_status"] == blocked_status
                    and blocking["report_digest"] == blocked_digest
                    and type(prerequisite_blockers) is list
                    and blocking["blockers"] == prerequisite_blockers
                ):
                    return False
            elif not (
                blocking["tier"] == depth
                and blocking["tier_name"] == tier_names[depth]
                and blocking["observed_status"] == "UNKNOWN"
                and blocking["report_digest"] is None
            ):
                return False
            retained_blocking_anchor = blocking
        elif blocking != retained_blocking_anchor:
            return False
    if executed_nonpass is not None and native.get("status") != executed_nonpass[1]:
        return False
    if execution["0"]["execution_status"] == "EXECUTED":
        zero = prerequisites["0"]
        obligations = zero.get("obligations")
        if not (
            zero.get("obligation_count") == 9
            and type(obligations) is list
            and len(obligations) == 9
            and [
                item.get("coordinate")
                for item in obligations if type(item) is dict
            ] == [f"VSTD-T0.{index}" for index in range(1, 10)]
            and all(
                type(item.get("assessment_reason")) is str
                and bool(item["assessment_reason"].strip())
                for item in obligations if type(item) is dict
            )
            and zero.get("manifest_digest")
            == graph_reference.get("manifest_digest")
            == manifest.get("digest")
        ):
            return False
        statuses = Counter(
            item.get("status") for item in obligations
            if type(item) is dict
            and item.get("status") in {"PASS", "FAIL", "UNKNOWN"}
        )
        derived = (
            "FAIL" if statuses["FAIL"] else
            "PASS" if statuses["PASS"] == 9 else "UNKNOWN"
        )
        exact_status_counts = {
            status: statuses[status] for status in ("PASS", "FAIL", "UNKNOWN")
        }
        if not (
            sum(statuses.values()) == 9
            and zero.get("obligation_status_counts") == exact_status_counts
            and zero.get("status") == derived
        ):
            return False
    if native.get("status") == "PASS":
        if not all(
            type(prerequisites.get(str(depth))) is dict
            and prerequisites[str(depth)].get("status") == "PASS"
            for depth in range(3)
        ):
            return False
        if not all(
            execution[str(depth)].get("execution_status") == "EXECUTED"
            and execution[str(depth)].get("status") == "PASS"
            for depth in range(4)
        ):
            return False
    return True


def _selected_instance_commitment_index(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return the one canonical identity index sealed by the denominator."""

    selected = []
    keys: set[tuple[str, str]] = set()
    for row in rows:
        _require(type(row) is dict, "PACKAGE_OBLIGATION_ROW_INVALID")
        item = {
            "object_id": row.get("object_id"),
            "object_kind": row.get("object_kind"),
            "coordinate": row.get("coordinate"),
            "tier": row.get("tier"),
            "instance_digest": row.get("instance_digest"),
        }
        _require(
            type(item["object_id"]) is str and bool(item["object_id"])
            and type(item["object_kind"]) is str and bool(item["object_kind"])
            and type(item["coordinate"]) is str and bool(item["coordinate"])
            and type(item["tier"]) is int
            and _is_digest(item["instance_digest"]),
            "PACKAGE_OBLIGATION_DENOMINATOR_IDENTITY_INVALID",
        )
        key = item["object_id"], item["coordinate"]
        _require(
            key not in keys,
            "PACKAGE_OBLIGATION_DENOMINATOR_DUPLICATE",
        )
        keys.add(key)
        selected.append(item)
    selected.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    return selected


def _reconstruct_v3_instance_rows(
    report: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """Strictly reconstruct the normalized rows committed by projection v3.

    Capacity issuance consumes semantic instance rows, not their wire layout.
    Every table digest, index, complete-row digest and source-ledger digest is
    replayed here so a malformed compact report cannot acquire a complete
    capacity receipt merely by naming the expected counts.
    """

    projection = report.get("obligation_instance_projection")
    expanded_rows = report.get("obligation_instances")
    definitions = report.get("pass_instance_definitions")
    if not (
        type(projection) is dict
        and projection.get("schema_version") == _PASS_TABLE_PROJECTION_SCHEMA
        and projection.get("transport") == _PASS_TABLE_TRANSPORT
        and type(expanded_rows) is list
        and type(definitions) is list
    ):
        return None
    object_table = projection.get("object_table")
    route_table = projection.get("route_table")
    check_definitions = projection.get("check_definitions")
    pass_entries = projection.get("pass_entries")
    expanded_indexes = projection.get("expanded_nonpass_source_indexes")
    if not all(type(value) is list for value in (
        object_table, route_table, check_definitions, pass_entries,
        expanded_indexes,
    )):
        return None
    source_count = projection.get("source_instance_count")
    verifier_id = projection.get("verifier_id")
    if not (
        type(source_count) is int and source_count > 0
        and type(verifier_id) is str and bool(verifier_id)
        and projection.get("object_field_order")
        == list(_PASS_TABLE_OBJECT_FIELDS)
        and projection.get("route_field_order")
        == list(_PASS_TABLE_ROUTE_FIELDS)
        and projection.get("pass_entry_field_order")
        == list(_PASS_TABLE_ENTRY_FIELDS)
        and projection.get("pass_reference_count") == len(pass_entries)
        and projection.get("expanded_nonpass_count") == len(expanded_rows)
        and len(pass_entries) + len(expanded_rows) == source_count
        and len(expanded_indexes) == len(expanded_rows)
        and projection.get("definition_count") == len(definitions)
        and projection.get("check_definition_count") == len(check_definitions)
        and projection.get("definitions_digest") == binding.value_digest(definitions)
        and projection.get("object_table_digest") == binding.value_digest(object_table)
        and projection.get("route_table_digest") == binding.value_digest(route_table)
        and projection.get("check_definitions_digest")
        == binding.value_digest(check_definitions)
        and projection.get("pass_entries_digest") == binding.value_digest(pass_entries)
    ):
        return None

    def unique_catalog(values: list[Any]) -> bool:
        digests = [binding.value_digest(value) for value in values]
        return len(digests) == len(set(digests))

    if not unique_catalog(object_table) or not unique_catalog(route_table):
        return None
    definition_digests = []
    for definition in definitions:
        if not (
            type(definition) is dict
            and _is_digest(definition.get("definition_digest"))
            and definition["definition_digest"] == binding.value_digest({
                key: value for key, value in definition.items()
                if key != "definition_digest"
            })
            and definition.get("definition_kind")
            in {"SEMANTIC", "KIND_REQUIREMENT"}
        ):
            return None
        definition_digests.append(definition["definition_digest"])
    if (
        definition_digests != sorted(definition_digests)
        or len(definition_digests) != len(set(definition_digests))
    ):
        return None

    check_digests = []
    for definition in check_definitions:
        template = definition.get("template")
        identity_fields = (
            template.get(_PASS_CHECK_IDENTITY_MARKER)
            if type(template) is dict else None
        )
        recompute_result = (
            template.get(_PASS_CHECK_RESULT_MARKER)
            if type(template) is dict else None
        )
        if not (
            type(definition) is dict
            and set(definition) == {
                "definition_digest", "checker_status", "template",
            }
            and definition.get("checker_status") in {"PASS", "NOT_REQUIRED"}
            and type(template) is dict
            and type(identity_fields) is list
            and identity_fields == [
                field for field in _PASS_CHECK_IDENTITY_FIELDS
                if field in identity_fields
            ]
            and len(identity_fields) == len(set(identity_fields))
            and type(recompute_result) is bool
            and not any(field in template for field in identity_fields)
            and not any(field in template for field in (
                "full_check_digest", "adaptation_result_digest", "result_digest",
            ))
            and definition.get("definition_digest") == binding.value_digest({
                "checker_status": definition["checker_status"],
                "template": definition["template"],
            })
        ):
            return None
        check_digests.append(definition["definition_digest"])
    if (
        check_digests != sorted(check_digests)
        or len(check_digests) != len(set(check_digests))
    ):
        return None

    source_rows: list[dict[str, Any] | None] = [None] * source_count
    committed_rows: list[dict[str, Any] | None] = [None] * source_count
    used_source_indexes: set[int] = set()
    previous_expanded_index = -1
    for source_index, row in zip(expanded_indexes, expanded_rows):
        if not (
            type(source_index) is int
            and previous_expanded_index < source_index < source_count
            and source_index not in used_source_indexes
            and type(row) is dict
            and not (row.get("status") == "PASS" and row.get("blockers") == [])
        ):
            return None
        previous_expanded_index = source_index
        used_source_indexes.add(source_index)
        source_rows[source_index] = row
        committed_rows[source_index] = row

    used_definition_indexes: set[int] = set()
    used_object_indexes: set[int] = set()
    used_route_indexes: set[int] = set()
    used_check_indexes: set[int] = set()
    first_object_indexes: list[int] = []
    first_route_indexes: list[int] = []
    previous_pass_index = -1
    for entry in pass_entries:
        if not (
            type(entry) is list
            and len(entry) == len(_PASS_TABLE_ENTRY_FIELDS)
        ):
            return None
        values = dict(zip(_PASS_TABLE_ENTRY_FIELDS, entry))
        source_index = values["source_index"]
        object_index = values["object_index"]
        route_index = values["route_index"]
        semantic_index = values["semantic_definition_index"]
        kind_index = values["kind_requirement_definition_index"]
        check_index = values["check_definition_index"]
        indexes = (
            (source_index, source_count),
            (object_index, len(object_table)),
            (route_index, len(route_table)),
            (semantic_index, len(definitions)),
            (check_index, len(check_definitions)),
        )
        if not all(type(index) is int and 0 <= index < bound
                   for index, bound in indexes):
            return None
        if kind_index is not None and not (
            type(kind_index) is int and 0 <= kind_index < len(definitions)
        ):
            return None
        if not (
            previous_pass_index < source_index
            and source_index not in used_source_indexes
        ):
            return None
        previous_pass_index = source_index
        used_source_indexes.add(source_index)
        object_values = object_table[object_index]
        route_values = route_table[route_index]
        semantic = definitions[semantic_index]
        kind = definitions[kind_index] if kind_index is not None else None
        check_definition = check_definitions[check_index]
        if not (
            type(object_values) is list
            and len(object_values) == len(_PASS_TABLE_OBJECT_FIELDS)
            and type(route_values) is list
            and len(route_values) == len(_PASS_TABLE_ROUTE_FIELDS)
            and semantic.get("definition_kind") == "SEMANTIC"
            and (kind is None or kind.get("definition_kind") == "KIND_REQUIREMENT")
        ):
            return None
        if object_index not in used_object_indexes:
            first_object_indexes.append(object_index)
        if route_index not in used_route_indexes:
            first_route_indexes.append(route_index)
        used_object_indexes.add(object_index)
        used_route_indexes.add(route_index)
        used_check_indexes.add(check_index)
        used_definition_indexes.add(semantic_index)
        if kind_index is not None:
            used_definition_indexes.add(kind_index)

        checker_status = check_definition["checker_status"]
        selected_check = dict(check_definition["template"])
        identity_fields = selected_check.pop(_PASS_CHECK_IDENTITY_MARKER)
        recompute_result = selected_check.pop(_PASS_CHECK_RESULT_MARKER)
        identity_values = {
            "object_id": object_values[
                _PASS_TABLE_OBJECT_FIELDS.index("object_id")
            ],
            "object_digest": object_values[
                _PASS_TABLE_OBJECT_FIELDS.index("object_digest")
            ],
            "coordinate": route_values[
                _PASS_TABLE_ROUTE_FIELDS.index("coordinate")
            ],
            "proposition_digest": route_values[
                _PASS_TABLE_ROUTE_FIELDS.index("proposition_digest")
            ],
            "checking_mechanism": route_values[
                _PASS_TABLE_ROUTE_FIELDS.index("checking_mechanism")
            ],
            "native_coordinate": route_values[
                _PASS_TABLE_ROUTE_FIELDS.index("coordinate")
            ],
            "conditional_coordinate": route_values[
                _PASS_TABLE_ROUTE_FIELDS.index("coordinate")
            ],
        }
        for field in identity_fields:
            selected_check[field] = identity_values[field]
        if checker_status == "PASS":
            if not (
                _is_digest(values["full_check_digest"])
                and values["adaptation_result_digest"] is None
                and values["result_digest"] is None
            ):
                return None
            selected_check["full_check_digest"] = values["full_check_digest"]
            if recompute_result:
                selected_check["result_digest"] = binding.value_digest(
                    selected_check
                )
            if not (
                selected_check.get("schema_version")
                == "verifier-package-check-reference-1"
                and selected_check.get("status") == "PASS"
                and selected_check.get("transport") == "DIGEST_BOUND_REFERENCE"
                and type(selected_check.get("full_check_bytes")) is int
                and selected_check["full_check_bytes"] > 0
            ):
                return None
        else:
            if not (
                values["full_check_digest"] is None
                and _is_digest(values["adaptation_result_digest"])
                and _is_digest(values["result_digest"])
                and recompute_result is False
            ):
                return None
            selected_check["adaptation_result_digest"] = values[
                "adaptation_result_digest"
            ]
            selected_check["result_digest"] = values["result_digest"]
            if not (
                selected_check.get("status") == "PASS"
                and selected_check.get("fulfillment_required") is False
                and selected_check.get("condition_status") == "NOT_TRIGGERED"
                and selected_check["result_digest"] == binding.value_digest({
                    key: value for key, value in selected_check.items()
                    if key != "result_digest"
                })
            ):
                return None

        semantic_digest = semantic["definition_digest"]
        realization = {
            "schema_version": "verifier-pass-instance-definition-reference-2",
            "semantic_definition_digest": semantic_digest,
            "complete_instance_digest": values["complete_instance_digest"],
            "transport": "REPORT_PASS_INSTANCE_FACTORED_DEFINITIONS",
        }
        if kind is not None:
            realization["kind_requirement_definition_digest"] = kind[
                "definition_digest"
            ]
        reference_reason = (
            "See pass_instance_definitions semantic definition "
            + semantic_digest + "."
        )
        source_applicability = semantic.get("applicability")
        if type(source_applicability) is not dict:
            return None
        row = {
            **dict(zip(_PASS_TABLE_OBJECT_FIELDS, object_values)),
            **dict(zip(_PASS_TABLE_ROUTE_FIELDS, route_values)),
            "instance_digest": values["instance_digest"],
            "verifier_id": verifier_id,
            "reason": reference_reason,
            "repository_realization": realization,
            "applicability": {
                "status": source_applicability.get("status"),
                "classification": source_applicability.get("classification"),
                "assessment_required": True,
                "reason": reference_reason,
            },
            "selected_package_check": selected_check,
            "checker_status": checker_status,
            "status": "PASS",
            "blockers": [],
            "native_specimen_is_instance_evidence": values[
                "native_specimen_is_instance_evidence"
            ],
            "package_graph_replay_is_instance_evidence": values[
                "package_graph_replay_is_instance_evidence"
            ],
        }
        if not all(_is_digest(row.get(field)) for field in (
            "object_digest", "proposition_digest", "instance_digest",
        )):
            return None
        committed = dict(row)
        committed["reason"] = semantic.get("reason")
        committed["repository_realization"] = semantic.get(
            "repository_realization"
        )
        committed["applicability"] = source_applicability
        if kind is not None:
            committed["kind_requirement"] = kind.get("kind_requirement")
        if not (
            _is_digest(values["complete_instance_digest"])
            and values["complete_instance_digest"]
            == binding.value_digest(committed)
        ):
            return None
        source_rows[source_index] = row
        committed_rows[source_index] = committed

    if not (
        used_source_indexes == set(range(source_count))
        and first_object_indexes == list(range(len(object_table)))
        and first_route_indexes == list(range(len(route_table)))
        and used_check_indexes == set(range(len(check_definitions)))
        and used_definition_indexes == set(range(len(definitions)))
        and all(row is not None for row in source_rows)
        and all(row is not None for row in committed_rows)
        and projection.get("source_instances_digest")
        == binding.value_digest(committed_rows)
    ):
        return None
    return [row for row in source_rows if row is not None]


def _capacity_source_rows(report: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Return semantic rows for ordinary, v2, or table-projected reports."""

    rows = report.get("obligation_instances")
    if type(rows) is not list or not all(type(row) is dict for row in rows):
        return None
    projection = report.get("obligation_instance_projection")
    if type(projection) is not dict:
        return rows
    if projection.get("schema_version") == _PASS_TABLE_PROJECTION_SCHEMA:
        return _reconstruct_v3_instance_rows(report)
    if projection.get("schema_version") == "verifier-pass-instance-projection-2":
        return rows
    return None


def _capacity_denominator_commitment(
    report: dict[str, Any],
    rows: list[dict[str, Any]] | None = None,
    *,
    source_report_digest: str | None = None,
) -> dict[str, Any] | None:
    """Return the denominator form a row-free capacity receipt can retain.

    A normal projected report may derive its conditional ledger from the full
    projected rows.  A capacity receipt binds that already-validated commitment
    to the exact encoded source report instead of materializing the same large
    conditional ledger again.  Replaying the named source report reconstructs
    the ledger; the portable receipt never claims that its compact fields alone
    carry the omitted row evidence.
    """

    execution = report.get("verifier_execution")
    if rows is None:
        rows = _capacity_source_rows(report)
    if type(execution) is not dict or type(rows) is not list:
        return None
    commitment = execution.get("obligation_denominator_commitment")
    if type(commitment) is not dict:
        return None
    common_fields = {
        "schema_version", "status", "selected_instance_count",
        "selected_instance_index_digest", "conditional_refutation_count",
        "conditional_refutations_digest", "claim_boundary",
        "commitment_digest",
    }
    schema_version = commitment.get("schema_version")
    if schema_version == _PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA:
        projection = report.get("obligation_instance_projection")
        if not (
            type(projection) is dict
            and projection.get("schema_version") in {
                "verifier-pass-instance-projection-2",
                _PASS_TABLE_PROJECTION_SCHEMA,
            }
            and type(report.get("pass_instance_definitions")) is list
            and (
                projection.get("schema_version")
                == "verifier-pass-instance-projection-2"
                or len(rows) == projection.get("source_instance_count")
            )
        ):
            return None
    expected_fields = (
        common_fields | {"conditional_refutations"}
        if schema_version == _EXPANDED_DENOMINATOR_COMMITMENT_SCHEMA
        else common_fields | {"conditional_refutations_transport"}
    )
    if not (
        schema_version in {
            _EXPANDED_DENOMINATOR_COMMITMENT_SCHEMA,
            _PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA,
        }
        and set(commitment) == expected_fields
        and commitment.get("status") == "COMMITTED"
        and type(commitment.get("selected_instance_count")) is int
        and commitment["selected_instance_count"] > 0
        and _is_digest(commitment.get("selected_instance_index_digest"))
        and type(commitment.get("conditional_refutation_count")) is int
        and commitment["conditional_refutation_count"] >= 0
        and _is_digest(commitment.get("conditional_refutations_digest"))
        and type(commitment.get("claim_boundary")) is str
        and bool(commitment["claim_boundary"].strip())
        and _is_digest(commitment.get("commitment_digest"))
        and commitment["commitment_digest"] == binding.value_digest({
            key: value for key, value in commitment.items()
            if key != "commitment_digest"
        })
    ):
        return None
    try:
        conditional_refutations = _conditional_refutation_index(rows)
    except (KeyError, TypeError, ValueError, UnicodeError, *_RESOURCE_ERRORS):
        return None
    if not (
        commitment["conditional_refutation_count"]
        == len(conditional_refutations)
        and commitment["conditional_refutations_digest"]
        == binding.value_digest(conditional_refutations)
    ):
        return None
    if schema_version == _EXPANDED_DENOMINATOR_COMMITMENT_SCHEMA:
        if commitment.get("conditional_refutations") != conditional_refutations:
            return None
        return {
            key: (
                [dict(item) for item in value]
                if key == "conditional_refutations" else value
            )
            for key, value in commitment.items()
        }
    if commitment.get(
        "conditional_refutations_transport"
    ) != _PROJECTED_CONDITIONAL_TRANSPORT:
        return None
    for row in rows:
        if row.get("checker_status") != "NOT_REQUIRED":
            continue
        check = row.get("selected_package_check")
        if not (
            type(check) is dict
            and _is_digest(check.get("result_digest"))
            and check["result_digest"] == binding.value_digest({
                key: value for key, value in check.items()
                if key != "result_digest"
            })
        ):
            return None
    if not _is_digest(source_report_digest):
        return None
    compact_body = {
        "schema_version": _CAPACITY_DENOMINATOR_COMMITMENT_SCHEMA,
        "status": "COMMITTED",
        "selected_instance_count": commitment["selected_instance_count"],
        "selected_instance_index_digest": commitment[
            "selected_instance_index_digest"
        ],
        "conditional_refutation_count": len(conditional_refutations),
        "conditional_refutations_digest": binding.value_digest(
            conditional_refutations
        ),
        "conditional_refutations_transport": _CAPACITY_CONDITIONAL_TRANSPORT,
        "source_report_digest": source_report_digest,
        "claim_boundary": (
            "Trusted capacity issuance freshly replayed the caller-selected source "
            "and validated the exact conditional-refutation count and digest. The "
            "ledger is reconstructed only by replaying the named digest-bound source "
            "report; it is not present in this compact receipt. Portable unsigned "
            "hashes establish internal consistency and accidental-corruption detection "
            "only; source replay or a trusted signature remains necessary for authority."
        ),
    }
    return {
        **compact_body,
        "commitment_digest": binding.value_digest(compact_body),
    }


def _fit_capacity_body(body: dict[str, Any]) -> dict[str, Any] | None:
    """Digest a receipt body and return it only if it fits the wire envelope."""

    if _preencoding_refusal(body, byte_limit=MAX_REPORT_BYTES) is not None:
        return None
    detailed = {**body, "report_digest": binding.value_digest(body)}
    if len(binding.canonical_bytes(detailed)) <= MAX_REPORT_BYTES:
        return detailed
    return None


def _expand_capacity_obligation_index(
    index: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """Reconstruct a v2 capacity index exactly, rejecting malformed tables."""

    if index.get("schema_version") != "verifier-package-obligation-index-2":
        return None
    body = {key: value for key, value in index.items() if key != "index_digest"}
    if index.get("index_digest") != binding.value_digest(body):
        return None
    objects = index.get("object_table")
    routes = index.get("route_table")
    passes = index.get("pass_entries")
    nonpasses = index.get("nonpass_entries")
    order = index.get("entry_order")
    if not all(type(value) is list for value in (
        objects, routes, passes, nonpasses, order,
    )):
        return None
    if (
        index.get("object_field_order") != ["object_id", "object_kind"]
        or index.get("route_field_order")
        != ["coordinate", "obligation_id", "tier"]
        or index.get("pass_entry_field_order")
        != ["object_index", "route_index", "checker_status", "instance_digest"]
        or index.get("object_table_digest") != binding.value_digest(objects)
        or index.get("route_table_digest") != binding.value_digest(routes)
        or index.get("pass_entries_digest") != binding.value_digest(passes)
        or index.get("nonpass_entries_digest") != binding.value_digest(nonpasses)
        or index.get("entry_order_digest") != binding.value_digest(order)
    ):
        return None
    expanded_passes: list[dict[str, Any]] = []
    try:
        for row in passes:
            object_index, route_index, checker_status, instance_digest = row
            object_id, object_kind = objects[object_index]
            coordinate, obligation_id, tier = routes[route_index]
            if checker_status not in {"PASS", "NOT_REQUIRED"}:
                return None
            expanded_passes.append({
                "object_id": object_id,
                "object_kind": object_kind,
                "coordinate": coordinate,
                "obligation_id": obligation_id,
                "tier": tier,
                "status": "PASS",
                "checker_status": checker_status,
                "instance_digest": instance_digest,
                "blockers": [],
                "reason": None,
                "actions": [],
                "rerun_argv": None,
            })
        expanded = [
            expanded_passes[row_index] if table_index == 0
            else nonpasses[row_index]
            for table_index, row_index in order
        ]
    except (IndexError, TypeError, ValueError):
        return None
    if (
        len(expanded) != index.get("instance_count")
        or dict(Counter(row.get("status") for row in expanded))
        != index.get("status_counts")
    ):
        return None
    return expanded


def _compact_capacity_obligation_index(
    index: dict[str, Any],
) -> dict[str, Any] | None:
    """Factor repeated PASS identities after the expanded index was replayed."""

    if index.get("schema_version") != "verifier-package-obligation-index-1":
        return None
    source_body = {
        key: value for key, value in index.items() if key != "index_digest"
    }
    entries = index.get("entries")
    if (
        index.get("index_digest") != binding.value_digest(source_body)
        or type(entries) is not list
        or len(entries) != index.get("instance_count")
    ):
        return None
    objects: list[list[Any]] = []
    object_indexes: dict[tuple[Any, Any], int] = {}
    routes: list[list[Any]] = []
    route_indexes: dict[tuple[Any, Any, Any], int] = {}
    passes: list[list[Any]] = []
    nonpasses: list[dict[str, Any]] = []
    order: list[list[int]] = []
    for entry in entries:
        if type(entry) is not dict:
            return None
        if entry.get("status") != "PASS":
            order.append([1, len(nonpasses)])
            nonpasses.append(entry)
            continue
        if not (
            entry.get("checker_status") in {"PASS", "NOT_REQUIRED"}
            and entry.get("blockers") == []
            and entry.get("reason") is None
            and entry.get("actions") == []
            and entry.get("rerun_argv") is None
        ):
            return None
        object_key = entry.get("object_id"), entry.get("object_kind")
        route_key = (
            entry.get("coordinate"), entry.get("obligation_id"),
            entry.get("tier"),
        )
        object_index = object_indexes.get(object_key)
        if object_index is None:
            object_index = len(objects)
            object_indexes[object_key] = object_index
            objects.append(list(object_key))
        route_index = route_indexes.get(route_key)
        if route_index is None:
            route_index = len(routes)
            route_indexes[route_key] = route_index
            routes.append(list(route_key))
        order.append([0, len(passes)])
        passes.append([
            object_index, route_index, entry["checker_status"],
            entry.get("instance_digest"),
        ])
    compact_body = {
        "schema_version": "verifier-package-obligation-index-2",
        "instance_count": len(entries),
        "status_counts": index.get("status_counts"),
        "object_field_order": ["object_id", "object_kind"],
        "object_table": objects,
        "object_table_digest": binding.value_digest(objects),
        "route_field_order": ["coordinate", "obligation_id", "tier"],
        "route_table": routes,
        "route_table_digest": binding.value_digest(routes),
        "pass_entry_field_order": [
            "object_index", "route_index", "checker_status", "instance_digest",
        ],
        "pass_entries": passes,
        "pass_entries_digest": binding.value_digest(passes),
        "nonpass_entries": nonpasses,
        "nonpass_entries_digest": binding.value_digest(nonpasses),
        "entry_order": order,
        "entry_order_digest": binding.value_digest(order),
        "transport": "DIGEST_BOUND_PASS_TABLE_REFERENCES",
    }
    compact = {
        **compact_body,
        "index_digest": binding.value_digest(compact_body),
    }
    return compact if _expand_capacity_obligation_index(compact) == entries else None


def _capacity_body_candidates(body: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield receipt bodies from most to least detailed, built only on demand.

    Each step drops prose that repeats per instance, never an instance: the index
    keeps every identity, status, digest, reason and rerun command.  Repeated
    per-instance findings and actions become counted groups with exact examples,
    and ``omitted_finding_count`` states how many findings were folded.  Native
    per-record detail is dropped last, and only with its count, which also
    withdraws a COMPLETE denominator claim that depended on it.
    """

    from verifier.runtime import manifest_gate

    yield body
    index = body["obligation_index"]
    index_schema = index.get("schema_version")
    if index_schema == "verifier-package-obligation-index-1":
        entries = [{**entry, "actions": []} for entry in index["entries"]]
        index_body = {
            key: value for key, value in index.items() if key != "index_digest"
        }
        index_body["entries"] = entries
    elif index_schema == "verifier-package-obligation-index-2":
        nonpasses = [
            {**entry, "actions": []}
            for entry in index["nonpass_entries"]
        ]
        index_body = {
            key: value for key, value in index.items()
            if key not in {
                "index_digest", "nonpass_entries", "nonpass_entries_digest",
            }
        }
        index_body["nonpass_entries"] = nonpasses
        index_body["nonpass_entries_digest"] = binding.value_digest(nonpasses)
    else:
        return
    grouped = manifest_gate.group_findings(body["findings"])
    sections = list(body["omitted_sections"]) + [
        name for name in ("obligation_instances.actions", "findings.instance_detail")
        if name not in body["omitted_sections"]
    ]
    compact = {
        **body,
        "obligation_index": {**index_body, "index_digest": binding.value_digest(index_body)},
        "findings": grouped,
        "finding_count": len(grouped),
        "omitted_finding_count": len(body["findings"]) - len(grouped),
        "omitted_sections": sections,
    }
    yield compact
    native = body.get("native_diagnostics")
    prerequisites = native.get("prerequisites") if type(native) is dict else None
    if type(prerequisites) is not dict:
        return
    stripped = {}
    for depth, prerequisite in prerequisites.items():
        if type(prerequisite) is dict and type(prerequisite.get("nonpass_records")) is list:
            prerequisite = {
                **{key: value for key, value in prerequisite.items()
                   if key != "nonpass_records"},
                "nonpass_record_count": len(prerequisite["nonpass_records"]),
            }
        stripped[depth] = prerequisite
    detail = native.get("nonpass_detail")
    reduced = {
        **{key: value for key, value in native.items() if key != "nonpass_detail"},
        "prerequisites": stripped,
    }
    if type(detail) is dict and type(detail.get("nonpass_records")) is list:
        reduced["nonpass_detail"] = {
            **{key: value for key, value in detail.items() if key != "nonpass_records"},
            "nonpass_record_count": len(detail["nonpass_records"]),
        }
    yield {
        **compact,
        "native_diagnostics": reduced,
        "denominator_status": "NOT_RETAINED",
        "omitted_sections": sections + ["native_diagnostics.nonpass_records"],
    }


def _capacity_receipt(
    report: dict[str, Any],
    *,
    source_root: str | Path | None = None,
    source_identity: tuple[str, str | None, int | None] | None = None,
) -> dict[str, Any]:
    """Retain the complete denominator and actionable failures under capacity.

    A report-size failure must not erase the exact objects and obligations that
    were already evaluated.  The compact index keeps every instance identity and
    status, while bulky evidence bodies remain omitted.  Extremely small test or
    embedding limits still receive the historical minimal fail-closed receipt.
    """

    refused = _preencoding_refusal(report) is not None
    # One identity pass serves both receipts; a refused source is never encoded.
    if source_identity is None:
        source_identity = _source_report_identity(report, refused=refused)
    minimal = _minimal_capacity_receipt(report, source_identity=source_identity)
    try:
        from verifier.runtime import manifest_gate

        retained_rows = report.get("obligation_instances", [])
        if type(retained_rows) is not list:
            retained_rows = []
        if refused:
            # A refused source is neither reconstructed nor replayed. Its raw
            # rows name every instance only when no projection replaced them.
            reconstructed_rows = None
            rows = (
                retained_rows
                if "obligation_instance_projection" not in report else None
            )
        else:
            reconstructed_rows = _capacity_source_rows(report)
            rows = (
                reconstructed_rows if reconstructed_rows is not None
                else retained_rows
            )
        # The actionable index is bounded by an explicit row count as well as by
        # the byte envelope checked before the receipt is returned.
        index_rows = (
            rows if type(rows) is list and len(rows) <= MAX_OBLIGATION_INSTANCES
            else []
        )
        source_count = (
            len(rows) if type(rows) is list else minimal["source_instance_count"]
        )
        named = {
            row["coordinate"]: row for row in manifest_gate.obligation_catalog()
        }
        entries = []
        for row in index_rows:
            route = named.get(row.get("coordinate"), {})
            nonpass = row.get("status") != "PASS"
            actions = []
            if nonpass and route:
                actions = manifest_gate.instance_findings(row, route)
            reason = row.get("reason") if nonpass else None
            if nonpass and type(reason) is not str:
                explanations = [
                    item["explanation"] for item in actions
                    if type(item.get("explanation")) is str
                ]
                reason = " ".join(explanations) or (
                    "The evaluated obligation did not pass; inspect its blockers "
                    "and retained actions."
                )
            entries.append({
                "object_id": row.get("object_id"),
                "object_kind": row.get("object_kind"),
                "coordinate": row.get("coordinate"),
                "obligation_id": route.get("obligation_id"),
                "tier": row.get("tier"),
                "status": row.get("status"),
                "checker_status": row.get("checker_status"),
                "instance_digest": row.get("instance_digest"),
                "blockers": row.get("blockers", []),
                "reason": reason,
                "actions": actions,
                "rerun_argv": (
                    manifest_gate._rerun(
                        row["object_id"], route["obligation_id"]
                    )
                    if (row.get("status") != "PASS"
                        and type(row.get("object_id")) is str
                        and type(route.get("obligation_id")) is str)
                    else None
                ),
            })
        entries.sort(key=lambda item: (
            item["tier"] if type(item["tier"]) is int else -1,
            item["object_id"] or "", item["obligation_id"] or "",
            item["instance_digest"] or "",
        ))
        findings = _package_findings_with_exact_native_focus(report)
        graph = report.get("package_graph")
        graph_reference = None
        if type(graph) is dict:
            effective_kinds: dict[str, tuple[str | None, list[str]]] = {}
            for row in index_rows:
                if type(row) is not dict or type(row.get("object_id")) is not str:
                    continue
                declared = row.get("declared_kind")
                specializations = row.get("specializations")
                profile = (
                    declared if type(declared) is str else None,
                    list(specializations) if type(specializations) is list else [],
                )
                prior = effective_kinds.setdefault(row["object_id"], profile)
                if prior != profile:
                    effective_kinds[row["object_id"]] = (None, [])
            graph_reference = {
                key: graph.get(key) for key in (
                    "status", "root_id", "root_kind", "manifest_digest",
                    "collection_digest", "object_count", "declaration_count",
                    "declaration_digest", "object_payloads_transport",
                ) if key in graph
            }
            graph_objects = graph.get("objects")
            if type(graph_objects) is list:
                graph_reference["objects"] = [
                    {
                        "object_id": item.get("object_id"),
                        "kind": item.get("kind"),
                        "object_digest": (
                            item.get("object_digest")
                            if type(item.get("object_digest")) is str
                            else binding.value_digest(item)
                        ),
                        "specializations": effective_kinds.get(
                            item.get("object_id"), (None, [])
                        )[1],
                    }
                    for item in graph_objects if type(item) is dict
                ]
            verifier_execution = report.get("verifier_execution")
            if type(verifier_execution) is dict and not refused:
                self_polish = verifier_execution.get("self_polish")
                if type(self_polish) is dict:
                    tier_results = self_polish.get("tier_results", [])
                    nonpass_members = [
                        {
                            key: member.get(key) for key in (
                                "verifier_id", "declared_kind",
                                "verifier_classification", "owner_resolution",
                                "mechanism_count", "mechanism_digest",
                                "subject_object_count", "subject_object_digest",
                                "obligation_instance_count",
                                "obligation_instance_digest", "status_counts",
                                "status", "blockers", "member_digest",
                            )
                        }
                        for member in self_polish.get("member_verifiers", [])
                        if type(member) is dict and member.get("status") != "PASS"
                    ]
                    nonpass_subjects = [
                        {
                            key: subject.get(key) for key in (
                                "object_id", "aggregate",
                                "obligation_instance_count",
                                "obligation_instance_digest", "status_counts",
                                "status", "blockers", "subject_digest",
                            )
                        }
                        for subject in self_polish.get(
                            "polish_system_subjects", []
                        )
                        if type(subject) is dict and subject.get("status") != "PASS"
                    ]
                    graph_reference["self_polish_reference"] = {
                        key: self_polish.get(key) for key in (
                            "schema_version", "status", "aggregate_verifier_id",
                            "aggregate_verifier_digest", "verified_graph_id",
                            "verified_graph_digest", "requested_tier",
                            "member_verifier_count", "member_status_counts",
                            "member_verifier_digest", "edge_count", "edge_digest",
                            "polish_system_subject_count", "polish_system_status",
                            "polish_system_subject_digest", "blockers",
                            "aggregate_result_is_member_evidence",
                            "self_application_authority", "graph_digest",
                            "claim_boundary",
                        )
                    }
                    graph_reference["self_polish_reference"][
                        "tier_results_digest"
                    ] = binding.value_digest(tier_results)
                    graph_reference["self_polish_reference"].update(
                        nonpass_member_count=len(nonpass_members),
                        nonpass_members=nonpass_members,
                        nonpass_polish_system_subject_count=len(nonpass_subjects),
                        nonpass_polish_system_subjects=nonpass_subjects,
                    )
                commitment = _capacity_denominator_commitment(
                    report, reconstructed_rows,
                    source_report_digest=source_identity[1],
                )
                if commitment is not None:
                    graph_reference["obligation_denominator_commitment"] = \
                        commitment
        status_counts = dict(Counter(
            entry["status"] for entry in entries if type(entry["status"]) is str
        ))
        index_body = {
            "schema_version": "verifier-package-obligation-index-1",
            "instance_count": len(entries),
            "status_counts": status_counts,
            "entries": entries,
        }
        obligation_index = {
            **index_body,
            "index_digest": binding.value_digest(index_body),
        }
        source_status, source_digest, source_bytes = source_identity
        if source_status == "UNAVAILABLE" and not refused:
            # A detailed receipt must name the exact source it was issued from.
            return minimal
        refusals: list[PackageGraphCompositionRefusal] = []
        denominator_complete = (
            not refused
            and reconstructed_rows is not None
            and _capacity_denominator_complete(
                report, entries, graph_reference, source_root,
                reconstructed_rows, refusals=refusals,
                source_report_digest=source_identity[1],
            )
        )
        actions_withheld = False
        if (
            denominator_complete
            and (
                len(entries) > MAX_INLINE_CAPACITY_INDEX_ENTRIES
                or _preencoding_refusal(
                    index_body, byte_limit=MAX_INLINE_OBLIGATION_ROWS_BYTES,
                ) is not None
            )
        ):
            compact_index = _compact_capacity_obligation_index(obligation_index)
            if compact_index is not None:
                obligation_index = compact_index
        else:
            if (
                len(entries) == source_count
                and _preencoding_refusal(index_body, byte_limit=MAX_REPORT_BYTES)
                is not None
            ):
                # Per-instance actions repeat the same prose; the identities,
                # statuses, reasons and rerun commands are the part worth keeping.
                lean = {
                    **index_body,
                    "entries": [{**entry, "actions": []} for entry in entries],
                }
                if _preencoding_refusal(lean, byte_limit=MAX_REPORT_BYTES) is None:
                    index_body, actions_withheld = lean, True
            if (
                len(entries) != source_count
                or _preencoding_refusal(index_body, byte_limit=MAX_REPORT_BYTES)
                is not None
            ):
                # Exact source counts remain. The complete index is withheld rather
                # than digested or retained beyond its explicit finite bounds.
                index_body = {
                    "schema_version": "verifier-package-obligation-index-1",
                    "instance_count": source_count,
                    "status_counts": {},
                    "entries": [],
                }
            obligation_index = {
                **index_body,
                "index_digest": binding.value_digest(index_body),
            }
        if refusals:
            # The fresh source replay is newer than the report's own graph
            # verdict, so its typed result replaces any earlier composition row.
            findings = [
                row for row in findings
                if row.get("code") not in _GRAPH_COMPOSITION_CODES
            ] + [
                _graph_composition_finding(
                    item.verdict, item.reason, report.get("requested_tier", 0),
                )
                for item in refusals
            ]
        if not denominator_complete:
            capacity_finding = manifest_gate.repository_finding(
                "PACKAGE_REPORT_CAPACITY_EXHAUSTED", "UNKNOWN",
                tier=report.get("requested_tier", 0),
            )
            findings.append(capacity_finding)
        omitted_sections = [
            "package_graph.objects.payloads",
            "obligation_instances.evidence_bodies",
        ]
        if actions_withheld:
            omitted_sections.append("obligation_instances.actions")
        if refused:
            omitted_sections.append("source_report_encoding_unavailable")
        if not denominator_complete:
            omitted_sections.append("cumulative_tier_evidence_unavailable")
        claim_boundary = (
            "The package assessment exceeded its pre-encoding envelope. The "
            "source report was neither encoded nor replayed, so no complete "
            "denominator is claimed. No omitted row is interpreted as passing "
            "or inapplicable."
            if refused else
            "The complete source assessment exceeded the ordinary inline wire "
            "target, so trusted issuance freshly replayed the caller-selected "
            "source and emitted a complete digest-bound projection. This is a "
            "transport projection, not a capacity blocker. Portable unsigned "
            "hashes establish internal consistency and accidental-corruption "
            "detection only; source replay or a trusted signature remains "
            "necessary for authority."
            if denominator_complete else
            "Trusted capacity issuance freshly replayed the caller-selected "
            "source before retaining this denominator. The portable unsigned "
            "receipt hashes establish internal consistency and accidental-"
            "corruption detection only; source replay or a trusted signature "
            "remains necessary for authority."
        )
        body = {
            **{key: value for key, value in minimal.items()
               if key != "report_digest"},
            "source_coordinate_digest": report.get("source_coordinate_digest"),
            "mechanism_digest": report.get("mechanism_digest"),
            "package_graph_reference": graph_reference,
            "native_diagnostics": report.get("native_diagnostics"),
            "tier_results": report.get("tier_results", []),
            "source_instance_count": source_count,
            "denominator_status": (
                "COMPLETE" if denominator_complete else "NOT_RETAINED"
            ),
            "obligation_index": obligation_index,
            "finding_count": len(findings),
            "findings": findings,
            "next_target": _package_next_target(
                findings, report.get("requested_tier", 0),
            ),
            "omitted_finding_count": 0,
            "source_report_digest": source_digest,
            "source_report_bytes": source_bytes,
            "source_report_encoding_status": source_status,
            "omitted_sections": omitted_sections,
            "claim_boundary": claim_boundary,
        }
        if denominator_complete:
            source_blockers = report.get("blockers")
            body["status"] = report.get("status")
            body["blockers"] = sorted(set(
                item for item in source_blockers
                if type(item) is str
                and item != "PACKAGE_REPORT_CAPACITY_EXHAUSTED"
            )) if type(source_blockers) is list else []
            body["whole_package_conformance"] = report.get(
                "whole_package_conformance", "NOT_ESTABLISHED"
            )
            body["polished"] = report.get("polished", False)
        if any(item.verdict == "FAIL" for item in refusals):
            # A replayed source refutation is not downgraded to a capacity UNKNOWN.
            body["status"] = "FAIL"
        # Measure the receipt body before digesting or encoding it, so an
        # oversized retained index cannot itself become a whole-body encoding.
        # The receipt degrades in steps, each keeping every instance identity
        # and status: full detail, grouped next actions, then grouped next
        # actions without native per-record detail.  Only after those does it
        # fall back to the minimal fail-closed receipt.
        for candidate in _capacity_body_candidates(body):
            fitted = _fit_capacity_body(candidate)
            if fitted is not None:
                return fitted
    except (KeyError, TypeError, ValueError, UnicodeError, *_RESOURCE_ERRORS):
        pass
    return minimal


def _seal(
    report: dict[str, Any],
    *,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    report["blockers"] = sorted(set(report["blockers"]))
    # Refuse an obviously over-envelope source before its first whole-report
    # encoding; the capacity receipt names it UNAVAILABLE rather than encoding it.
    # A normal package assessment may already have produced the complete v2
    # PASS-row projection, however.  Its repeated per-instance mapping keys can
    # exceed the raw envelope even though the bounded, exactly reconstructable
    # v3 table fits.  Give only that already-established projection its one
    # table-upgrade step before refusing the source; arbitrary over-envelope
    # reports still go directly to the fail-closed receipt.
    refusal = _preencoding_refusal(report)
    projection = report.get("obligation_instance_projection")
    if (
        refusal is not None
        and type(projection) is dict
        and projection.get("schema_version")
        == "verifier-pass-instance-projection-2"
    ):
        try:
            if _attach_successful_instance_projection(report, force=True):
                refusal = _preencoding_refusal(report)
        except (KeyError, TypeError, ValueError, UnicodeError, *_RESOURCE_ERRORS):
            pass
    if refusal is not None:
        return _capacity_receipt(report, source_root=source_root)
    source_identity: tuple[str, str | None, int | None] | None = None
    try:
        encoded = binding.canonical_bytes(report)
        encoded = _project_report_toward_target(report, encoded)
        source_identity = (
            "AVAILABLE", binding.bytes_digest(encoded), len(encoded),
        )
        if len(encoded) > MAX_REPORT_BYTES:
            return _capacity_receipt(
                report, source_root=source_root,
                source_identity=source_identity,
            )
    except (KeyError, TypeError, ValueError, UnicodeError,
            MemoryError, RecursionError, OverflowError):
        return _capacity_receipt(report, source_root=source_root)
    try:
        report["findings"] = _package_findings_with_exact_native_focus(report)
    except _RESOURCE_ERRORS:
        if report["status"] != "FAIL":
            report["status"] = "UNKNOWN"
        # Losing the diagnostic formatter must itself remain a reasoned,
        # actionable finding.  An empty list would preserve the blocker code
        # while erasing the human-facing reason for this non-PASS report.
        from verifier.runtime import manifest_gate

        unavailable = manifest_gate.repository_finding(
            "PACKAGE_FINDINGS_UNAVAILABLE",
            "UNKNOWN",
            tier=report.get("requested_tier", 0),
        )
        explanation = (
            "The package finding formatter exhausted a local runtime resource, "
            "so the complete focused diagnostic set could not be produced."
        )
        unavailable.update(
            reason=explanation,
            explanation=explanation,
            next_action=(
                "Restore the required local runtime resource and rerun the "
                "same package polish gate retained in rerun_argv."
            ),
        )
        report["findings"] = [unavailable]
        report["blockers"] = sorted(set(report["blockers"] + ["PACKAGE_FINDINGS_UNAVAILABLE"]))
    if report.get("schema_version") == EXTENSIBLE_REPORT_SCHEMA:
        report["next_target"] = _package_next_target(
            report["findings"], report.get("requested_tier", 0),
        )
    try:
        encoded = binding.canonical_bytes(report)
        encoded = _project_report_toward_target(report, encoded)
        if len(encoded) > MAX_REPORT_BYTES:
            return _capacity_receipt(
                report, source_root=source_root,
                source_identity=source_identity,
            )
        if "obligation_instance_projection" not in report:
            rows = report.get("obligation_instances")
            if type(rows) is list:
                # Check-only compaction is a final size optimization for a
                # report that already fits. Whole-report projection must run
                # first so complete-instance digests bind evaluated rows, not
                # an intermediate projection of those rows.
                _compact_successful_instance_checks(rows)
                encoded = binding.canonical_bytes(report)
        if len(encoded) > MAX_REPORT_BYTES:
            return _capacity_receipt(
                report, source_root=source_root,
                source_identity=source_identity,
            )
    except (KeyError, TypeError, ValueError, UnicodeError,
            MemoryError, RecursionError, OverflowError):
        return _capacity_receipt(
            report, source_root=source_root,
            source_identity=source_identity,
        )
    report["report_digest"] = binding.bytes_digest(encoded)
    try:
        if len(binding.canonical_bytes(report)) > MAX_REPORT_BYTES:
            return _capacity_receipt(
                report, source_root=source_root,
                source_identity=source_identity,
            )
    except (MemoryError, RecursionError, OverflowError):
        return _capacity_receipt(
            report, source_root=source_root,
            source_identity=source_identity,
        )
    return report


def _project_report_toward_target(
    report: dict[str, Any],
    encoded: bytes,
) -> bytes:
    """Best-effort lossless projection toward the ordinary report target.

    The 24 MiB target is an optimization; the 32 MiB envelope is the hard
    contract.  An under-cap report therefore keeps its ordinary evidence if a
    projection cannot be established.  The already-produced canonical bytes
    are also the rollback image, avoiding a second speculative object graph.
    Over-cap reports still fail closed through the caller's capacity receipt.
    """

    projection_boundary = min(TARGET_REPORT_BYTES, MAX_REPORT_BYTES)
    if len(encoded) <= projection_boundary:
        return encoded
    rollback = encoded if len(encoded) <= MAX_REPORT_BYTES else None
    projection_applied = False
    try:
        # Evaluate complete rows first, then use at most two lossless steps:
        # full rows -> inspectable v2 references -> reconstructable v3 tables.
        for _projection_step in range(2):
            if len(encoded) <= projection_boundary:
                break
            if not _attach_successful_instance_projection(report, force=True):
                break
            projection_applied = True
            encoded = binding.canonical_bytes(report)
    except (KeyError, TypeError, ValueError, UnicodeError,
            MemoryError, RecursionError, OverflowError):
        if rollback is None:
            raise
        restored = json.loads(rollback)
        _require(type(restored) is dict, "PACKAGE_REPORT_ROLLBACK_INVALID")
        report.clear()
        report.update(restored)
        return rollback
    if (
        rollback is not None
        and projection_applied
        and (len(encoded) >= len(rollback) or len(encoded) > MAX_REPORT_BYTES)
    ):
        restored = json.loads(rollback)
        _require(type(restored) is dict, "PACKAGE_REPORT_ROLLBACK_INVALID")
        report.clear()
        report.update(restored)
        return rollback
    return encoded


def mechanism_digest() -> str:
    """Bind this evaluator, its manifest reader and executed checking paths."""
    from verifier.runtime import package_admission
    root = Path(__file__).parents[1]
    return binding.value_digest({
        "files": {name: binding.bytes_digest((root / name).read_bytes()) for name in (
            "runtime/package_polish.py", "runtime/manifest_gate.py", "runtime/tier_zero_manifest.py",
            "runtime/package_instance_evidence.py",
            "runtime/package_kind_requirements.py",
            "runtime/package_harness_applicability.py",
            "runtime/package_contract_coverage.py",
            "runtime/package_contract_profiles.py",
            "runtime/added_kind_behavioral_routes.py",
            "runtime/package_source_contracts.py",
            "runtime/package_graph_representation.py",
            "runtime/local_ledger_execution.py", "runtime/local_ledger_worker.py",
            "runtime/local_ledger_controls.py", "runtime/local_ledger_control_checks.py",
            "runtime/package_execution.py", "runtime/manifest_write_execution.py", "runtime/manifest_write_worker.py",
            "runtime/package_execution_observation.py",
            "runtime/worker_protocol_execution.py", "runtime/worker_protocol_worker.py",
            "runtime/provenance_policy_execution.py", "runtime/provenance_policy_worker.py",
            "runtime/resource_measurement_execution.py", "runtime/resource_measurement_worker.py",
            "runtime/token_asset_execution.py", "runtime/token_asset_worker.py",
            "runtime/emulator_control_execution.py", "runtime/emulator_control_worker.py",
            "domains/contracts/market_checks.py", "domains/contracts/robot_checks.py",
            "domains/contracts/finbot_checks.py",
            "runtime/tier_zero_reasons.py", "runtime/package_self_polish.py",
            "runtime/package_verifier_graph.py",
            "core/namespace.py", "standard/PACKAGE_POLISH.md",
            "schemas/verifier-manifest-package-polish-1.schema.json",
            "schemas/verifier-manifest-package-polish-2.schema.json",
            "schemas/verifier-manifest-package-polish-capacity-2.schema.json",
            "schemas/verifier-package-contract-coverage-1.schema.json",
            "schemas/verifier-package-contract-coverage-2.schema.json",
            "schemas/verifier-manifest-object-gate-1.schema.json",
        )},
        "admission": package_admission.mechanism_digest(),
        "native_diagnostics": self_polish_statics.mechanism_digest(),
        "generic_facets": package_self_polish.object_facets.mechanism_digest(),
        "typed_facets": package_self_polish.typed_facets.mechanism_digest(),
    })


def _read_manifest(root: Path) -> bytes:
    path = root / "objects.vstd"
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise FileNotFoundError("PACKAGE_MANIFEST_MISSING") from None
    _require(not path.is_symlink() and stat.S_ISREG(info.st_mode),
             "PACKAGE_MANIFEST_NOT_REGULAR_FILE")
    with path.open("rb") as stream:
        raw = stream.read(tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES + 1)
    _require(0 < len(raw) <= tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES,
             "PACKAGE_MANIFEST_CAPACITY_EXHAUSTED")
    return raw


def _semantic_namespace(document: dict[str, Any]) -> dict[str, Any]:
    """Select the validated inline namespace consumed by Polish semantics.

    Version 6 stores repeated evidence arrays behind content-digest selectors.
    Those selectors are transport only: compact validation expands them before
    kind, evidence, graph-report, or capacity-replay consumers can inspect the
    declaration. Versions 3 through 5 retain their established object identity
    and are returned unchanged.
    """
    declared = document.get("namespace")
    if (
        document.get("schema_version")
        == package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    ):
        _require(type(declared) is dict, "PACKAGE_NAMESPACE_REQUIRED")
        return package_manifest.namespace_manifest.normalize_manifest(declared)
    return declared if type(declared) is dict else {}


def _graph_declaration_profile(
    document: dict[str, Any], manifest: dict[str, Any], *,
    semantic_namespace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Retain declarations inline unless the v5/v6 transport needs a reference.

    Versions 3 and 4 fit the original report contract and remain directly
    inspectable. Versions 5 and 6 can carry declarations that exceed that older
    report envelope. Version 6 is normalized before this profile is computed,
    so an evidence-set digest remains a transport selector and never becomes
    evidence. The compact report profile binds the exact semantic declaration
    array by count and canonical digest. The selected manifest digest remains
    alongside it, so this is a reference to evidence, not an omitted or sampled
    denominator.
    """
    selected_namespace = (
        _semantic_namespace(document)
        if semantic_namespace is None else semantic_namespace
    )
    declarations = selected_namespace.get(
        "objects", manifest["objects"]
    )
    if document.get("schema_version") in {
        package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
    }:
        return {
            "declaration_count": len(declarations),
            "declaration_digest": binding.value_digest(declarations),
            "object_payloads_transport": "MANIFEST_DIGEST_BOUND_REFERENCES",
            "object_payloads_claim": (
                "Every object ID, kind and operand edge remains inline. Each repeated "
                "payload is replaced only in this report by its exact byte digest and "
                "length; the selected root objects.vstd at manifest_digest is the "
                "authoritative payload transport."
            ),
        }
    return {"declarations": declarations}


def _graph_object_profile(
    objects: tuple[namespace.NamespaceObject, ...], document: dict[str, Any]
) -> list[dict[str, Any]]:
    """Represent the full graph without copying a large v5/v6 manifest into its report.

    The root manifest is already selected by exact bytes and its composition is
    checked before this projection. Keeping IDs, kinds and operands inline retains
    the package topology operators need to inspect; the object and payload digests
    bind the omitted payload bytes without allowing a different object to substitute.
    Versions 3 and 4 retain their established fully-inline representation.
    """

    if document.get("schema_version") not in {
        package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
    }:
        return [item.to_dict() for item in objects]
    return [
        {
            "object_id": item.object_id,
            "kind": item.kind.value,
            "object_digest": item.digest,
            "payload": {
                "schema_version": "verifier-namespace-payload-reference-1",
                "payload_digest": binding.bytes_digest(item.payload_bytes),
                "payload_bytes": len(item.payload_bytes),
                "transport": "SELECTED_ROOT_OBJECTS_VSTD",
            },
            "operands": {
                role: list(targets) for role, targets in item.operands
            },
        }
        for item in objects
    ]


_NATIVE_TIER_NAMES = {
    0: "ADMISSION", 1: "FACETS", 2: "DYNAMICS", 3: "STATICS",
}


def _native_execution_record(
    tier: int,
    *,
    execution_status: str,
    status: str,
    reason: str,
    evidence_digest: str | None = None,
    blocking_prerequisite: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the same sealed execution record used by native Tier 3.

    Package polish 1 and 2 have always executed their cumulative native
    prerequisites.  Keeping that fact only in the nested reports made the
    lower-tier package receipts weaker than polish 3.  This local wrapper keeps
    the lower-tier producer independent of the Tier-3 orchestration entry point
    while retaining its exact, public execution-record contract.
    """

    return self_polish_statics._tier_execution_record(
        tier,
        execution_status=execution_status,
        status=status,
        reason=reason,
        evidence_digest=evidence_digest,
        blocking_prerequisite=blocking_prerequisite,
    )


def _run_native_diagnostics(tier: int, root: Path) -> dict[str, Any]:
    """Fresh cumulative controls, never package-instance fulfillment."""
    if tier == 3:
        return self_polish_statics.assess_self_polish_statics(root)
    _require(tier in {1, 2}, "PACKAGE_NATIVE_TIER_INVALID")
    reports: dict[str, dict[str, Any]] = {}
    execution: dict[str, dict[str, Any]] = {}
    status = "UNKNOWN"
    for depth in range(tier + 1):
        if depth == 0:
            prior = tier_zero.assess_tier_zero(root)
        elif depth == 1:
            prior = self_polish_tiers.assess_self_polish_tier(
                1, source_root=root,
            )
        else:
            one = reports["1"]
            prior = self_polish_tiers.assess_self_polish_tier(
                2,
                source_root=root,
                tier1_report_bytes=binding.canonical_bytes(one),
                expected_tier1_report_digest=one["report_digest"],
            )
        _require(
            prior.get("report_digest") == binding.value_digest({
                key: value for key, value in prior.items()
                if key != "report_digest"
            }),
            "PACKAGE_NATIVE_PREREQUISITE_DIGEST_DIFFERS",
        )
        _require(
            prior.get("status") in {"PASS", "FAIL", "UNKNOWN"},
            "PACKAGE_NATIVE_PREREQUISITE_STATUS_INVALID",
        )
        reports[str(depth)] = prior
        status = prior["status"]
        execution[str(depth)] = _native_execution_record(
            depth,
            execution_status="EXECUTED",
            status=status,
            reason=(
                f"Fresh Tier {depth} {_NATIVE_TIER_NAMES[depth]} prerequisite "
                "assessment was executed for this source coordinate."
            ),
            evidence_digest=prior["report_digest"],
        )
        if status == "PASS":
            continue
        blockers = prior.get("blockers")
        selected_blockers = (
            list(blockers)
            if type(blockers) is list
            and blockers
            and all(type(item) is str and bool(item) for item in blockers)
            else [f"TIER{depth}_FRESH_PASS_REQUIRED"]
        )
        blocking = {
            "tier": depth,
            "tier_name": _NATIVE_TIER_NAMES[depth],
            "required_status": "PASS",
            "observed_status": status,
            "report_digest": prior["report_digest"],
            "blockers": selected_blockers,
        }
        for skipped_depth in range(depth + 1, tier + 1):
            execution[str(skipped_depth)] = _native_execution_record(
                skipped_depth,
                execution_status="NOT_RUN",
                status="UNKNOWN",
                reason=(
                    f"Tier {skipped_depth} "
                    f"{_NATIVE_TIER_NAMES[skipped_depth]} was not executed "
                    f"because fresh Tier {depth} {_NATIVE_TIER_NAMES[depth]} "
                    f"status was {status}; dependent execution requires PASS."
                ),
                blocking_prerequisite=blocking,
            )
        break
    body = {
        "status": status,
        "prerequisites": reports,
        "tier_execution": execution,
        "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
    }
    return {**body, "report_digest": binding.value_digest(body)}


def _tier3_replay_evidence_digest(replay: Any) -> str | None:
    """Return the exact digest selected by the Tier-3 execution producer."""

    if type(replay) is not dict:
        return None
    receipt = replay.get("receipt_digest")
    if receipt:
        return receipt if _is_digest(receipt) else None
    try:
        return binding.value_digest(replay)
    except (
        TypeError, ValueError, UnicodeError, MemoryError, RecursionError,
        OverflowError,
    ):
        return None


def _native_execution_prefix_complete(
    native: Any,
    *,
    requested_tier: int,
    source_coordinate_digest: str,
    manifest_digest: str,
) -> bool:
    """Validate the exact native execution prefix selected by package polish.

    Execution is cumulative: polish 1 retains native Tiers 0--1, polish 2
    retains 0--2, and polish 3 retains 0--3.  Every executed lower native tier
    is sealed and bound to the exact retained prerequisite report digest.  Once
    an executed prerequisite is non-PASS, every remaining selected tier must be
    explicitly UNKNOWN/NOT_RUN and share that exact blocking anchor.
    """

    if (
        requested_tier not in {1, 2, 3}
        or type(native) is not dict
        or native.get("status") not in {"PASS", "FAIL", "UNKNOWN"}
        or not _is_digest(native.get("report_digest"))
        or not _is_digest(source_coordinate_digest)
        or not _is_digest(manifest_digest)
    ):
        return False
    execution = native.get("tier_execution")
    prerequisites = native.get("prerequisites")
    expected_execution = {
        str(depth) for depth in range(requested_tier + 1)
    }
    if not (
        type(execution) is dict
        and set(execution) == expected_execution
        and type(prerequisites) is dict
        and set(prerequisites).issubset({"0", "1", "2"})
    ):
        return False
    replay = native.get("complete_tier_evidence_replay")
    if requested_tier == 3:
        if "complete_tier_evidence_replay" not in native:
            return False
    elif replay is not None:
        return False

    expected_prerequisites: set[str] = set()
    executed_nonpass: tuple[int, str, str, list[str]] | None = None
    retained_blocking_anchor: dict[str, Any] | None = None
    for depth in range(requested_tier + 1):
        record = execution[str(depth)]
        if not (
            type(record) is dict
            and record.get("schema_version")
            == "verifier-self-polish-tier-execution-1"
            and record.get("tier") == depth
            and record.get("tier_name") == _NATIVE_TIER_NAMES[depth]
            and record.get("execution_status") in {"EXECUTED", "NOT_RUN"}
            and record.get("status") in {"PASS", "FAIL", "UNKNOWN"}
            and type(record.get("reason")) is str
            and bool(record["reason"].strip())
            and _is_digest(record.get("execution_record_digest"))
            and record["execution_record_digest"] == binding.value_digest({
                key: value for key, value in record.items()
                if key != "execution_record_digest"
            })
        ):
            return False
        if record["execution_status"] == "EXECUTED":
            if executed_nonpass is not None or retained_blocking_anchor is not None:
                return False
            if depth == 3:
                replay_digest = _tier3_replay_evidence_digest(replay)
                if not (
                    type(replay) is dict
                    and replay.get("status") in {"PASS", "FAIL", "UNKNOWN"}
                    and replay_digest is not None
                    and record.get("evidence_digest") == replay_digest
                    and record.get("blocking_prerequisite") is None
                    and record["status"] == replay["status"]
                ):
                    return False
                if record["status"] != "PASS":
                    blockers = replay.get("blockers")
                    if not (
                        type(blockers) is list
                        and blockers
                        and all(
                            type(item) is str and bool(item)
                            for item in blockers
                        )
                    ):
                        blockers = ["TIER3_FRESH_PASS_REQUIRED"]
                    executed_nonpass = (
                        depth,
                        record["status"],
                        record["evidence_digest"],
                        list(blockers),
                    )
                continue
            prerequisite = prerequisites.get(str(depth))
            if not (
                depth <= 2
                and type(prerequisite) is dict
                and _is_digest(record.get("evidence_digest"))
                and record["evidence_digest"] == prerequisite.get("report_digest")
                and record.get("blocking_prerequisite") is None
                and record["status"] == prerequisite.get("status")
            ):
                return False
            expected_prerequisites.add(str(depth))
            if depth == 0:
                obligations = prerequisite.get("obligations")
                if not (
                    prerequisite.get("manifest_digest") == manifest_digest
                    and prerequisite.get("obligation_count") == 9
                    and type(obligations) is list
                    and len(obligations) == 9
                    and [
                        item.get("coordinate")
                        for item in obligations if type(item) is dict
                    ] == [f"VSTD-T0.{index}" for index in range(1, 10)]
                    and all(
                        type(item.get("assessment_reason")) is str
                        and bool(item["assessment_reason"].strip())
                        for item in obligations if type(item) is dict
                    )
                ):
                    return False
                statuses = Counter(
                    item.get("status") for item in obligations
                    if type(item) is dict
                    and item.get("status") in {"PASS", "FAIL", "UNKNOWN"}
                )
                derived = (
                    "FAIL" if statuses["FAIL"] else
                    "PASS" if statuses["PASS"] == 9 else "UNKNOWN"
                )
                if not (
                    sum(statuses.values()) == 9
                    and prerequisite.get("obligation_status_counts") == {
                        status: statuses[status]
                        for status in ("PASS", "FAIL", "UNKNOWN")
                    }
                    and prerequisite.get("status") == derived
                ):
                    return False
            elif not (
                prerequisite.get("schema_version")
                == self_polish_tiers.REPORT_SCHEMA
                and prerequisite.get("tier") == depth
                and prerequisite.get("source_coordinate_digest")
                == source_coordinate_digest
                and (
                    record["status"] != "PASS"
                    or prerequisite.get("post_replay_full_source_recapture")
                    == "PASS"
                )
            ):
                return False
            if record["status"] != "PASS":
                blockers = prerequisite.get("blockers")
                if not (
                    type(blockers) is list
                    and blockers
                    and all(type(item) is str and bool(item) for item in blockers)
                ):
                    blockers = [f"TIER{depth}_FRESH_PASS_REQUIRED"]
                executed_nonpass = (
                    depth,
                    record["status"],
                    record["evidence_digest"],
                    list(blockers),
                )
            continue

        blocking = record.get("blocking_prerequisite")
        if depth == 3 and replay is not None:
            return False
        if not (
            record["status"] == "UNKNOWN"
            and record.get("evidence_digest") is None
            and type(blocking) is dict
            and type(blocking.get("tier")) is int
            and 0 <= blocking["tier"] <= depth
            and blocking.get("tier_name")
            == _NATIVE_TIER_NAMES[blocking["tier"]]
            and blocking.get("required_status") == "PASS"
            and blocking.get("observed_status") in {"FAIL", "UNKNOWN"}
            and (
                blocking.get("report_digest") is None
                or _is_digest(blocking.get("report_digest"))
            )
            and type(blocking.get("blockers")) is list
            and bool(blocking["blockers"])
            and all(
                type(item) is str and bool(item)
                for item in blocking["blockers"]
            )
        ):
            return False
        if retained_blocking_anchor is None:
            if executed_nonpass is not None:
                failed_depth, failed_status, failed_digest, failed_blockers = (
                    executed_nonpass
                )
                if not (
                    blocking["tier"] == failed_depth
                    and blocking["tier_name"]
                    == _NATIVE_TIER_NAMES[failed_depth]
                    and blocking["observed_status"] == failed_status
                    and blocking["report_digest"] == failed_digest
                    and blocking["blockers"] == failed_blockers
                ):
                    return False
            elif not (
                blocking["tier"] == depth
                and blocking["tier_name"] == _NATIVE_TIER_NAMES[depth]
                and blocking["observed_status"] == "UNKNOWN"
                and blocking["report_digest"] is None
            ):
                return False
            retained_blocking_anchor = blocking
        elif blocking != retained_blocking_anchor:
            return False

    if set(prerequisites) != expected_prerequisites:
        return False
    execution_outcome = (
        executed_nonpass[1] if executed_nonpass is not None
        else "UNKNOWN" if retained_blocking_anchor is not None
        else "PASS"
    )
    if requested_tier == 3:
        recapture = native.get("post_replay_full_source_recapture")
        if recapture is None:
            recapture = "UNKNOWN"
        if recapture == "NOT_ESTABLISHED":
            recapture = "UNKNOWN"
        if recapture not in {"PASS", "FAIL", "UNKNOWN"}:
            return False
        expected_status = (
            "FAIL" if "FAIL" in {execution_outcome, recapture}
            else "PASS" if execution_outcome == recapture == "PASS"
            else "UNKNOWN"
        )
        return native.get("status") == expected_status
    return native.get("status") == execution_outcome


def _native_nonpass_records(
    value: Any, *, tier: int, path: str = "$",
) -> list[dict[str, Any]]:
    """Extract bounded actionable native failures without copying PASS ledgers."""

    records: list[dict[str, Any]] = []
    identity_fields = (
        "coordinate", "obligation_id", "object_id", "object_kind", "kind",
        "classification_kind", "tier", "tier_name", "scope", "case_kind",
        "candidate_id", "gate_id", "execution_status", "required_status",
        "observed_status", "expected_native_status", "native_status",
    )
    reason_fields = ("reason", "assessment_reason", "explanation")
    action_fields = ("next_action",)

    def safe_identifier(selected: Any, *, maximum: int = 512) -> bool:
        """Admit a readable argv atom, never shell or control syntax."""

        return (
            type(selected) is str
            and 1 <= len(selected) <= maximum
            and selected[0] in _FOCUS_IDENTIFIER_CHARACTERS
            and all(
                character in _FOCUS_IDENTIFIER_CHARACTERS
                for character in selected
            )
        )

    def focused_action(
        object_id: Any, obligation_id: Any,
    ) -> tuple[list[str], str] | None:
        if not (
            safe_identifier(object_id, maximum=256)
            and safe_identifier(obligation_id)
        ):
            return None
        argv = [
            "vstd", "gate", "--object", object_id,
            "--obligation", obligation_id,
        ]
        return argv, " ".join(argv)

    def validated_rerun(selected: Any) -> tuple[list[str], str] | None:
        if not (
            type(selected) is list
            and len(selected) == 6
            and selected[:3] == ["vstd", "gate", "--object"]
            and selected[4] == "--obligation"
        ):
            return None
        return focused_action(selected[3], selected[5])

    def inherited_context(
        item: dict[str, Any], parent: dict[str, Any],
    ) -> dict[str, Any]:
        """Carry exact focus down a diagnostic tree without crossing siblings."""

        context = dict(parent)
        for field in identity_fields:
            if field not in item:
                continue
            selected = item[field]
            maximum = 256 if field == "object_id" else 512
            if type(selected) is int or safe_identifier(
                selected, maximum=maximum,
            ):
                context[field] = selected
            else:
                # An unsafe child value masks, rather than silently inheriting,
                # a parent identity that may describe a different result.
                context.pop(field, None)
        for field in reason_fields:
            if field not in item:
                continue
            selected = item[field]
            if (
                type(selected) is str
                and 1 <= len(selected) <= 8192
                and "\x00" not in selected
            ):
                context[field] = selected
            else:
                context.pop(field, None)
        for field in action_fields:
            if field not in item:
                continue
            selected = item[field]
            if (
                type(selected) is str
                and 1 <= len(selected) <= 8192
                and "\x00" not in selected
            ):
                context[field] = selected
            else:
                context.pop(field, None)
        return context

    def visit(
        item: Any, location: str, parent_context: dict[str, Any],
    ) -> None:
        if type(item) is dict:
            context = inherited_context(item, parent_context)
            status = item.get("status")
            blockers = item.get("blockers")
            case_kind = item.get("case_kind")
            expected_native = item.get("expected_native_status")
            observed_native = item.get("native_status")
            native_case = (
                case_kind in {"POSITIVE", "NEGATIVE", "UNKNOWN"}
                and expected_native in {"PASS", "FAIL", "UNKNOWN"}
                and observed_native in {"PASS", "FAIL", "UNKNOWN"}
            )
            derived_case_status = (
                "PASS" if native_case and observed_native == expected_native
                else "UNKNOWN" if native_case and case_kind == "POSITIVE"
                and observed_native == "UNKNOWN"
                else "FAIL" if native_case else None
            )
            # A negative or unavailable native control is a successful test case
            # when its enclosing case derives PASS.  Recursing into the raw
            # checker result used to misreport those expected FAIL/UNKNOWN
            # outcomes as package-native failures without their case context.
            effective_status = (
                derived_case_status
                if native_case and status == "PASS"
                and derived_case_status != "PASS"
                else status
            )
            native_result = item.get("native_result")
            native_blockers = (
                native_result.get("blockers")
                if type(native_result) is dict else None
            )
            selected_blockers = (
                [entry for entry in blockers if type(entry) is str]
                if type(blockers) is list else []
            )
            if not selected_blockers and type(native_blockers) is list:
                selected_blockers = [
                    entry for entry in native_blockers if type(entry) is str
                ]
            if effective_status in {"FAIL", "UNKNOWN", "NOT_ESTABLISHED", "NOT_RUN"} \
                    or selected_blockers:
                selected_action = focused_action(
                    context.get("object_id"), context.get("obligation_id"),
                )
                if selected_action is None:
                    selected_action = validated_rerun(item.get("rerun_argv"))
                if selected_action is None:
                    selected_rerun = (
                        ["vstd", "polish", str(tier)]
                        + (["--native-specimens"] if tier else [])
                        + ["--json"]
                    )
                    generated_next_action = None
                else:
                    selected_rerun, generated_next_action = selected_action
                record = {
                    "path": location,
                    "status": (
                        effective_status
                        if type(effective_status) is str else "UNKNOWN"
                    ),
                    "blockers": selected_blockers,
                    "rerun_argv": list(selected_rerun),
                }
                for field in (*identity_fields, *reason_fields, *action_fields):
                    selected = context.get(field)
                    if type(selected) in {str, int}:
                        record[field] = selected
                if (
                    "next_action" not in record
                    and generated_next_action is not None
                ):
                    record["next_action"] = generated_next_action
                if type(native_result) is dict:
                    if not any(field in record for field in reason_fields):
                        for field in reason_fields:
                            selected = native_result.get(field)
                            if type(selected) is str:
                                record[field] = selected
                                break
                    details = native_result.get("details")
                    if details is not None:
                        try:
                            details_raw = binding.canonical_bytes(details)
                        except (TypeError, ValueError, UnicodeError,
                                MemoryError, RecursionError, OverflowError):
                            details_raw = None
                        if details_raw is not None:
                            if len(details_raw) <= 4096:
                                record["details"] = details
                            else:
                                record.update(
                                    details_digest=binding.bytes_digest(details_raw),
                                    details_bytes=len(details_raw),
                                )
                records.append(record)
            for key, child in item.items():
                if key not in {"report_digest", "receipt_digest"} and not (
                    native_case and key == "native_result"
                ):
                    visit(child, location + "." + str(key), context)
        elif type(item) is list:
            for index, child in enumerate(item):
                visit(child, f"{location}[{index}]", parent_context)

    visit(value, path, {})
    return records


def _graph_composition_finding(verdict: str, reason: str, tier: Any) -> dict[str, Any]:
    """Name the graph's own typed verdict with the assessment's exact reason.

    The generic blocker summary would substitute a code-derived default for the
    same proposition. A refuted graph keeps the FAILED code; an unestablished
    graph keeps NOT_PASS and remains UNKNOWN.
    """

    from verifier.runtime.manifest_gate import repository_finding

    code = (
        "PACKAGE_GRAPH_COMPOSITION_FAILED" if verdict == "FAIL"
        else "PACKAGE_GRAPH_COMPOSITION_NOT_PASS"
    )
    finding = repository_finding(code, verdict, tier=tier)
    finding.update(
        explanation=reason,
        reason=reason,
        next_action=(
            "Repair the refuted typed package-graph composition named by the "
            "reason, then rerun the same polish command."
            if verdict == "FAIL" else
            "Establish the typed package-graph composition named by the reason; "
            "UNKNOWN is not a pass; then rerun the same polish command."
        ),
        rerun_argv=["vstd", "polish", str(tier), "--json"],
    )
    return finding


def _record_graph_composition_refusal(
    report: dict[str, Any],
    refusal: PackageGraphCompositionRefusal,
) -> None:
    """Keep a non-PASS typed graph verdict as its own bounded package result.

    An unestablished graph is never a FAIL. Only a refuted graph sets FAIL. A
    refuted or unestablished graph also leaves its tier-zero representation
    unestablished, matching the sibling self-polish assessor's blocker set.
    """

    report["blockers"].extend([
        "PACKAGE_GRAPH_COMPOSITION_NOT_PASS",
        "TIER_ZERO_REPRESENTATION_NOT_PASS",
    ])
    if refusal.verdict == "FAIL":
        report["status"] = "FAIL"
        report["blockers"].append("PACKAGE_GRAPH_COMPOSITION_FAILED")
    report["findings"] = [
        _graph_composition_finding(
            refusal.verdict, refusal.reason, report["requested_tier"],
        )
    ]


def _record_estate_refusal(report: dict[str, Any], exc: Exception) -> None:
    """Keep live source drift retryable while contract refutations stay FAIL."""

    code = str(exc) or "PACKAGE_ASSESSMENT_CONTRACT_REJECTED"
    if code not in self_polish_tiers.LIVE_SOURCE_DRIFT_CODES:
        report["status"] = "FAIL"
    report["blockers"].append(code)


def _live_source_drift_finding(code: str, tier: int) -> dict[str, Any]:
    """Name retryable source drift with the exact root rerun in its action."""

    from verifier.runtime.manifest_gate import repository_finding

    finding = repository_finding(code, "UNKNOWN", tier=tier)
    finding.update(
        gate_id="source-freshness",
        explanation=self_polish_tiers.LIVE_SOURCE_DRIFT_EXPLANATION,
        reason=self_polish_tiers.LIVE_SOURCE_DRIFT_EXPLANATION,
        next_action=self_polish_tiers.LIVE_SOURCE_DRIFT_ACTION.format(tier=tier),
        rerun_argv=["vstd", "polish", str(tier), "--json"],
    )
    return finding


def _package_findings_with_exact_native_focus(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Restore exact source-native focus after generic finding projection.

    ``manifest_gate.package_findings`` deliberately provides a uniform package
    summary.  The native reference is the authoritative bounded transport for
    an individual Tier-0 closure cell, so the summary must not replace its
    object kind, classification kind, reason, or remediation text.  Only a
    record with the same diagnostic path, object, obligation, and validated
    focused argv may enrich the projected finding.
    """

    from verifier.runtime.manifest_gate import package_findings

    findings = package_findings(report)
    retained = report.get("findings")
    if type(retained) is list:
        # A typed graph verdict carries its own reason; the generic blocker row
        # for the same code would replace that reason with a code-derived default.
        composition = [
            row for row in retained
            if type(row) is dict and row.get("code") in _GRAPH_COMPOSITION_CODES
        ]
        if composition:
            findings = [
                row for row in findings
                if row.get("code") not in _GRAPH_COMPOSITION_CODES
            ] + composition
    for code in report["blockers"]:
        if code in self_polish_tiers.LIVE_SOURCE_DRIFT_CODES:
            # Replace the generic projection: drift needs its own retry action.
            findings = [row for row in findings if row.get("code") != code]
            findings.append(
                _live_source_drift_finding(code, report["requested_tier"])
            )
    native = report.get("native_diagnostics")
    if type(native) is not dict:
        return findings
    groups: list[Any] = []
    prerequisites = native.get("prerequisites")
    if type(prerequisites) is dict:
        for depth in sorted(prerequisites):
            prerequisite = prerequisites[depth]
            if type(prerequisite) is dict:
                groups.append(prerequisite.get("nonpass_records"))
    detail = native.get("nonpass_detail")
    if type(detail) is dict:
        groups.append(detail.get("nonpass_records"))
    records = [
        record
        for group in groups if type(group) is list
        for record in group if type(record) is dict
    ]

    # A repository-scale report holds tens of thousands of findings and records,
    # so records are indexed by the identity a finding must match; each bucket
    # keeps record order, so the first match is the one a scan would select.
    index: dict[Any, list[dict[str, Any]]] = {}
    unhashable: list[dict[str, Any]] = []
    for item in records:
        try:
            index.setdefault(
                (item.get("path"), item.get("object_id"), item.get("obligation_id")),
                [],
            ).append(item)
        except TypeError:
            unhashable.append(item)
    for finding in findings:
        if type(finding) is not dict:
            continue
        path = finding.get("diagnostic_path")
        object_id = finding.get("object_id")
        obligation_id = finding.get("obligation_id")
        try:
            candidates = index.get((path, object_id, obligation_id), [])
        except TypeError:
            candidates = []
        expected_rerun = [
            "vstd", "gate", "--object", object_id, "--obligation", obligation_id,
        ]
        record = next((
            item for item in [*candidates, *unhashable]
            if item.get("path") == path
            and item.get("object_id") == object_id
            and item.get("obligation_id") == obligation_id
            and item.get("rerun_argv") == expected_rerun
        ), None)
        if record is None:
            continue
        for field in (
            "gate_id", "object_id", "object_kind", "classification_kind",
            "obligation_id", "coordinate",
        ):
            value = record.get(field)
            maximum = 256 if field == "object_id" else 512
            if (
                type(value) is str
                and 1 <= len(value) <= maximum
                and value[0] in _FOCUS_IDENTIFIER_CHARACTERS
                and all(
                    character in _FOCUS_IDENTIFIER_CHARACTERS
                    for character in value
                )
            ):
                finding[field] = value
        reason = next((
            record[field]
            for field in ("reason", "assessment_reason", "explanation")
            if type(record.get(field)) is str
            and 1 <= len(record[field]) <= 8192
            and "\x00" not in record[field]
        ), None)
        if reason is not None:
            finding["reason"] = reason
            finding["explanation"] = reason
        action = record.get("next_action")
        if (
            type(action) is str
            and 1 <= len(action) <= 8192
            and "\x00" not in action
        ):
            finding["next_action"] = action
        finding["rerun_argv"] = list(record["rerun_argv"])
    return findings


def _package_next_target(
    findings: Any,
    requested_tier: Any,
) -> dict[str, Any] | None:
    """Select one exact, deterministic non-PASS object obligation to fix next.

    Repository-scale reports group thousands of instance findings.  A grouped
    row is useful for accounting but its top-level object is intentionally
    null, which previously forced callers to rediscover ``examples[0]``.  This
    projection exposes one executable target while preserving the complete
    findings and their counts.  Lower-tier prerequisites precede higher-tier
    work; within one tier, a refutation precedes an uncertainty.
    """

    if type(findings) is not list:
        return None
    selected_requested_tier = (
        requested_tier
        if type(requested_tier) is int and requested_tier in {1, 2, 3}
        else None
    )
    candidates: list[tuple[tuple[int, int, int, int], dict[str, Any]]] = []
    for finding_index, finding in enumerate(findings):
        if type(finding) is not dict:
            continue
        status = finding.get("status")
        if status not in {"FAIL", "UNKNOWN"}:
            continue
        examples = finding.get("examples")
        possible: list[tuple[int | None, Mapping[str, Any]]] = [(None, finding)]
        if type(examples) is list:
            possible.extend(
                (example_index, example)
                for example_index, example in enumerate(examples)
                if isinstance(example, Mapping)
            )
        for example_index, item in possible:
            object_id = item.get("object_id")
            obligation_id = item.get("obligation_id")
            if not (
                type(object_id) is str
                and object_id
                and type(obligation_id) is str
                and obligation_id
            ):
                continue
            expected_rerun = [
                "vstd", "gate", "--object", object_id,
                "--obligation", obligation_id,
            ]
            rerun = item.get("rerun_argv")
            if rerun != expected_rerun:
                rerun = finding.get("rerun_argv")
            if rerun != expected_rerun:
                continue
            match = re.search(r"-T?([0-3])\.", obligation_id)
            obligation_tier = int(match.group(1)) if match is not None else None
            explanation = finding.get("explanation")
            reason = (
                explanation
                if type(explanation) is str and explanation.strip()
                else finding.get("reason")
            )
            action = finding.get("next_action")
            code = finding.get("code")
            gate_id = finding.get("gate_id")
            if not all(
                type(value) is str and value.strip()
                for value in (reason, action, code, gate_id)
            ):
                continue
            focus: str | None = None
            if type(explanation) is str:
                prefix, separator, _remainder = explanation.partition(":")
                if separator and re.fullmatch(r"[A-Z][A-Z0-9_-]*", prefix):
                    focus = prefix
            coordinate = finding.get("coordinate")
            if type(coordinate) is not str or not coordinate:
                coordinate = obligation_id
            target = {
                "schema_version": "verifier-package-polish-next-target-1",
                "source_path": "objects.vstd",
                "requested_tier": selected_requested_tier,
                "obligation_tier": obligation_tier,
                "status": status,
                "code": code,
                "object_id": object_id,
                "obligation_id": obligation_id,
                "coordinate": coordinate,
                "gate_id": gate_id,
                "focus": focus,
                "reason": reason,
                "next_action": action,
                "rerun_argv": expected_rerun,
                "finding_index": finding_index,
                "example_index": example_index,
                "claim_boundary": (
                    "This is the first deterministic non-PASS target in the "
                    "cumulative package report. Resolving it is necessary but "
                    "does not by itself establish tier or package polish."
                ),
            }
            rank = (
                obligation_tier if obligation_tier is not None else 99,
                0 if status == "FAIL" else 1,
                finding_index,
                -1 if example_index is None else example_index,
            )
            candidates.append((rank, target))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def _native_diagnostic_reference(report: dict[str, Any]) -> dict[str, Any]:
    """Retain a reproducible reference without nesting a second full ledger.

    Native diagnostics and package-instance obligations are independent evidence
    classes.  A current Tier-1 diagnostic is larger than 20 MiB, so embedding
    all of its obligation rows again can exhaust the package report envelope and
    erase the package ledger that this command exists to report.  The full
    diagnostic is validated before this projection is made.  Its digest and the
    exact source/manifest recapture coordinates remain bound here; no diagnostic
    status is recomputed or promoted by the projection.
    """
    prerequisites = report.get("prerequisites", {})
    _require(type(prerequisites) is dict, "PACKAGE_NATIVE_PREREQUISITES_INVALID")
    selected_fields = (
        "schema_version", "tier", "requested_tier", "status", "report_digest",
        "manifest_digest", "source_coordinate_digest",
        "obligation_count", "obligation_status_counts",
        "post_replay_full_source_recapture", "post_replay_source_recapture",
        "post_replay_manifest_recapture",
    )
    summaries: dict[str, dict[str, Any]] = {}
    for depth, prerequisite in sorted(prerequisites.items()):
        _require(type(depth) is str and type(prerequisite) is dict,
                 "PACKAGE_NATIVE_PREREQUISITE_INVALID")
        summaries[depth] = {
            field: prerequisite[field]
            for field in selected_fields
            if field in prerequisite
        }
        if depth == "0":
            # Tier 0 is the small, ubiquitous repository-admission surface. Keep
            # its complete obligation ledger inline so a higher polish command
            # remains sufficient to inspect admission without a second command.
            summaries[depth]["obligations"] = prerequisite.get("obligations", [])
            if "finalization" in prerequisite:
                summaries[depth]["finalization"] = prerequisite["finalization"]
        if prerequisite.get("status") != "PASS":
            # Keep exact non-PASS paths and blockers, never the unrelated PASS
            # bulk that made the source-native report large in the first place.
            summaries[depth]["blockers"] = prerequisite.get("blockers", [])
            summaries[depth]["nonpass_records"] = _native_nonpass_records(
                prerequisite, tier=int(depth), path=f"$.prerequisites.{depth}",
            )
        _require(summaries[depth].get("status") in {"PASS", "FAIL", "UNKNOWN"},
                 "PACKAGE_NATIVE_PREREQUISITE_STATUS_INVALID")
        _require(type(summaries[depth].get("report_digest")) is str,
                 "PACKAGE_NATIVE_PREREQUISITE_DIGEST_MISSING")
    replay_reference = None
    execution = report.get("tier_execution")
    if type(execution) is dict and "3" in execution:
        replay = report.get("complete_tier_evidence_replay")
        if replay is not None:
            replay_digest = _tier3_replay_evidence_digest(replay)
            _require(
                type(replay) is dict
                and replay.get("status") in {"PASS", "FAIL", "UNKNOWN"}
                and replay_digest is not None,
                "PACKAGE_NATIVE_TIER3_REPLAY_INVALID",
            )
            replay_reference = {
                "status": replay["status"],
                "evidence_digest": replay_digest,
                "transport": "DIGEST_BOUND_REFERENCE",
            }
            if replay.get("receipt_digest"):
                replay_reference["receipt_digest"] = replay["receipt_digest"]
            else:
                replay_reference["value_digest"] = replay_digest
    reference = {
        "schema_version": "verifier-native-diagnostic-reference-1",
        "status": report["status"],
        "report_digest": report["report_digest"],
        "report_bytes": len(binding.canonical_bytes(report)),
        "claim_scope": report.get(
            "claim_scope", "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES"
        ),
        "transport": "DIGEST_BOUND_REFERENCE",
        "prerequisites": summaries,
        "tier_execution": report.get("tier_execution", {}),
        "claim_boundary": (
            "This is a digest-bound projection of a fresh, fully validated native "
            "diagnostic report. It does not replace package-instance evidence or "
            "promote diagnostic PASS into package conformance."
        ),
    }
    if type(execution) is dict and "3" in execution:
        reference["complete_tier_evidence_replay"] = replay_reference
    if report["status"] != "PASS":
        selected = {
            key: value for key, value in report.items()
            if key in {
                "schema_version", "requested_tier", "tier", "tier_name",
                "status", "selected_tier_status", "selected_depth", "blockers",
                "source_coordinate_digest", "post_replay_full_source_recapture",
            }
        }
        selected["nonpass_records"] = _native_nonpass_records(
            {key: value for key, value in report.items()
             if key not in {"prerequisites", "report_digest"}},
            tier=int(report.get("requested_tier", report.get("tier", 3))),
        )
        reference["nonpass_detail"] = selected
    return reference


def _not_run_native_diagnostic_reference(
    stage: str, blockers: list[str], *, requested_tier: int = 3,
) -> dict[str, Any]:
    """Close the requested native prefix when package work stops first.

    The tiers module owns this ledger so the refresh-blocked envelope can name
    the same NOT_RUN contract without importing this package mechanism.
    """

    return self_polish_tiers.not_run_native_diagnostic_reference(
        stage=stage, blockers=blockers, requested_tier=requested_tier,
    )


def _close_incomplete_cumulative_accounting(
    report: dict[str, Any], *, tier: int, stage: str,
) -> None:
    """Keep a post-admission package exception schema-valid and explicit."""

    if not (
        tier in {1, 2, 3}
        and report.get("schema_version") == EXTENSIBLE_REPORT_SCHEMA
        and type(report.get("package_graph")) is dict
    ):
        return
    rows = report.get("obligation_instances")
    if type(rows) is not list:
        rows = []
    results = report.get("tier_results")
    if type(results) is not list:
        results = []
        report["tier_results"] = results
    retained = {
        item.get("tier") for item in results if type(item) is dict
    }
    for depth in range(1, tier + 1):
        if depth in retained:
            continue
        selected = [
            row for row in rows
            if type(row) is dict and row.get("tier") == depth
        ]
        statuses = Counter(
            row.get("status") for row in selected
            if row.get("status") in {"PASS", "FAIL", "UNKNOWN"}
        )
        results.append({
            "tier": depth,
            "instance_count": len(selected),
            "status_counts": dict(statuses),
            "status": "FAIL" if statuses["FAIL"] else "UNKNOWN",
            "checker_status_counts": dict(Counter(
                row.get("checker_status") for row in selected
                if type(row.get("checker_status")) is str
            )),
            "prerequisite_tiers": list(range(depth)),
            "execution_status": "NOT_RUN",
            "reason": (
                f"Package Tier {depth} aggregation did not complete because "
                f"assessment stopped at {stage}. Retained rows are diagnostic, "
                "not a complete denominator."
            ),
        })
    results.sort(key=lambda item: item.get("tier", -1))
    if report.get("native_diagnostics") is None:
        report["blockers"].append("PACKAGE_NATIVE_DIAGNOSTICS_NOT_RUN")
        native = _not_run_native_diagnostic_reference(
            stage, report.get("blockers", []), requested_tier=tier,
        )
        # The package-v2 cumulative ledger accounts for Tier 3 replay even
        # when package work stops first.  Keep that package-only field out of
        # the refresh-blocked envelope, which consumes the same native helper
        # under its own closed schema.
        if tier == 3:
            native.pop("report_digest", None)
            native["complete_tier_evidence_replay"] = None
            native["report_digest"] = binding.value_digest(native)
        report["native_diagnostics"] = native
        verifier_execution = report.get("verifier_execution")
        if type(verifier_execution) is dict:
            verifier_execution["native_diagnostic_report_digest"] = native[
                "report_digest"
            ]


def _selected_check_reference(
    check: dict[str, Any], *, encoded: bytes | None = None,
) -> dict[str, Any]:
    """Bind a large successful check without repeating its source payload.

    Package aggregation consumes the full check before this projection. The
    instance retains its human-readable obligation reason, applicability and
    focused gate coordinate; this reference preserves the fields needed to
    distinguish a necessary PASS from an evidenced conditional non-trigger.
    Non-PASS checks are never projected, so failure detail stays feature-near.
    """
    _require(check.get("status") == "PASS", "PACKAGE_CHECK_REFERENCE_NOT_PASS")
    if check.get("schema_version") == "verifier-package-check-reference-1":
        _require(
            check.get("transport") == "DIGEST_BOUND_REFERENCE"
            and _is_digest(check.get("full_check_digest"))
            and type(check.get("full_check_bytes")) is int
            and check["full_check_bytes"] > 0
            and type(check.get("claim_boundary")) is str
            and bool(check["claim_boundary"].strip()),
            "PACKAGE_CHECK_REFERENCE_INVALID",
        )
        # Projection can be requested first by the aggregate payload gate and
        # later by the whole-report gate.  Keep the original check binding;
        # wrapping a reference again would bind the first reference instead of
        # the executed check and break conditional-refutation provenance.
        return check
    if encoded is None:
        encoded = binding.canonical_bytes(check)
    else:
        _require(type(encoded) is bytes, "PACKAGE_CHECK_REFERENCE_BYTES_INVALID")
    reference = {
        "schema_version": "verifier-package-check-reference-1",
        "status": "PASS",
        "full_check_digest": binding.bytes_digest(encoded),
        "full_check_bytes": len(encoded),
        "transport": "DIGEST_BOUND_REFERENCE",
        "claim_boundary": (
            "The full current check was consumed by package aggregation before "
            "projection. Re-run the named focused gate to reproduce its detail."
        ),
    }
    for field in (
        # Contract aggregation consumes this bounded reference before wire
        # projection. Retain every exact route/subject binding it validates;
        # the large replay/observation body remains content-addressed below.
        "object_id", "object_digest", "collection_digest", "coordinate",
        "obligation_id", "semantic_version", "proposition_digest",
        "checking_mechanism", "adapter",
        "evidence_origin", "applicability_established",
        "applicability_classification", "fulfillment_required",
        "condition", "condition_status", "native_coordinate",
        "conditional_coordinate", "adaptation_obligation_id",
        "adaptation_result_digest", "classification_decision_digest",
        "applicability_retention_digest",
        "applicability_digest", "reason",
        "report_digest", "assessment_digest", "certificate_digest",
    ):
        if field in check:
            reference[field] = check[field]
    # Self-bind the bounded transport for source-route and conditional-
    # refutation consumers. ``full_check_digest`` already commits the complete
    # original result, including any producer-owned result digest.
    reference["result_digest"] = binding.value_digest(reference)
    return reference


def _repository_realization_reference(
    realization: dict[str, Any], *, encoded: bytes | None = None,
) -> dict[str, Any]:
    """Bind repeated route-level detail while retaining its human explanation."""
    if encoded is None:
        encoded = binding.canonical_bytes(realization)
    else:
        _require(
            type(encoded) is bytes,
            "PACKAGE_REPOSITORY_REALIZATION_REFERENCE_BYTES_INVALID",
        )
    _require(type(realization.get("explanation")) is str
             and bool(realization["explanation"].strip()),
             "PACKAGE_REPOSITORY_REALIZATION_EXPLANATION_MISSING")
    reference = {
        "schema_version": "verifier-repository-realization-reference-1",
        "explanation": realization["explanation"],
        "full_realization_digest": binding.bytes_digest(encoded),
        "full_realization_bytes": len(encoded),
        "transport": "DIGEST_BOUND_REFERENCE",
        "claim_boundary": (
            "The full route realization was consumed before projection. Re-run "
            "the enclosing focused gate to reproduce mechanism and falsifier detail."
        ),
    }
    for field in ("class", "adaptation_necessity", "obligation_semantic_digest"):
        if field in realization:
            reference[field] = realization[field]
    return reference


def _selected_check_observation_reference(
    check: dict[str, Any], *, encoded: bytes | None = None,
) -> dict[str, Any]:
    """Content-address one repeated non-PASS checker observation.

    The first occurrence remains expanded and actionable. Later byte-identical
    in-process observations retain their status, reason, route/subject binding
    and complete digest without serializing the same diagnostic body again.
    """

    if check.get("status") == "PASS":
        return _selected_check_reference(check, encoded=encoded)
    if encoded is None:
        encoded = binding.canonical_bytes(check)
    else:
        _require(type(encoded) is bytes,
                 "PACKAGE_CHECK_OBSERVATION_REFERENCE_BYTES_INVALID")
    status = check.get("status")
    _require(status in {"FAIL", "UNKNOWN"},
             "PACKAGE_CHECK_OBSERVATION_REFERENCE_STATUS_INVALID")
    reference = {
        "schema_version": "verifier-package-check-observation-reference-1",
        "status": status,
        "full_check_digest": binding.bytes_digest(encoded),
        "full_check_bytes": len(encoded),
        "transport": "DIGEST_BOUND_REPEATED_OBSERVATION",
        "claim_boundary": (
            "The first byte-identical non-PASS observation remains expanded in "
            "this report. Re-run the named focused gate for another full copy."
        ),
    }
    for field in (
        "object_id", "object_digest", "collection_digest", "coordinate",
        "obligation_id", "semantic_version", "proposition_digest",
        "checking_mechanism", "adapter", "evidence_origin",
        "applicability_established", "applicability_classification",
        "fulfillment_required", "condition", "condition_status",
        "native_coordinate", "conditional_coordinate",
        "adaptation_obligation_id", "adaptation_result_digest",
        "classification_decision_digest", "applicability_retention_digest",
        "applicability_digest", "reason", "report_digest",
        "assessment_digest", "certificate_digest",
    ):
        if field in check:
            reference[field] = check[field]
    return reference


def _compact_successful_instance_checks(rows: list[dict[str, Any]]) -> None:
    """Normalize repeated bulky payloads only after full package consumption.

    Small and focused assessments remain fully inspectable, including fresh
    replay nonces and selected mechanisms.  Large package graphs first consume
    every full result, then cross this aggregate payload bound. PASS rows
    receive digest-bound references; the first FAIL and UNKNOWN occurrence per
    status remains expanded while later identical observations are referenced.
    The threshold is about report transport, not a semantic shortcut.
    """
    payload_bytes = 0
    encoded_checks: dict[tuple[Any, ...], bytes] = {}
    encoded_realizations: dict[tuple[Any, ...], bytes] = {}

    def check_key(check: dict[str, Any]) -> tuple[Any, ...] | None:
        """Name one shared in-process value without trusting a claimed digest."""

        # Rows are assembled in one evaluation and retain shared immutable
        # producer values by identity. Identity reuse is therefore exact and
        # cannot let a caller-authored digest alias different content. Distinct
        # dictionaries are encoded independently even when they claim the same
        # digest.
        return ("in-process-identity", id(check))

    def encoded_check(check: dict[str, Any]) -> bytes:
        key = check_key(check)
        if key is not None and key in encoded_checks:
            return encoded_checks[key]
        encoded = binding.canonical_bytes(check)
        if key is not None:
            encoded_checks[key] = encoded
        return encoded

    def realization_key(value: dict[str, Any]) -> tuple[Any, ...] | None:
        return ("in-process-identity", id(value))

    def encoded_realization(value: dict[str, Any]) -> bytes:
        key = realization_key(value)
        if key is not None and key in encoded_realizations:
            return encoded_realizations[key]
        encoded = binding.canonical_bytes(value)
        if key is not None:
            encoded_realizations[key] = encoded
        return encoded

    for row in rows:
        for field in ("selected_package_check", "repository_realization"):
            value = row.get(field)
            if type(value) is dict:
                payload_bytes += len(
                    encoded_check(value)
                    if field == "selected_package_check"
                    else encoded_realization(value)
                )
                if payload_bytes > MAX_INLINE_INSTANCE_PAYLOAD_BYTES:
                    break
        if payload_bytes > MAX_INLINE_INSTANCE_PAYLOAD_BYTES:
            break
    if payload_bytes <= MAX_INLINE_INSTANCE_PAYLOAD_BYTES:
        return
    references: dict[tuple[Any, ...], dict[str, Any]] = {}
    realization_references: dict[tuple[Any, ...], dict[str, Any]] = {}
    retained_nonpass_checks: set[tuple[tuple[Any, ...], Any]] = set()
    retained_nonpass_realizations: set[tuple[tuple[Any, ...], Any]] = set()
    for row in rows:
        check = row.get("selected_package_check")
        pass_row = row.get("status") == "PASS" and row.get("blockers") == []
        if not pass_row:
            status = row.get("status")
            if type(check) is dict:
                encoded = encoded_check(check)
                key = check_key(check)
                occurrence = (key, status) if key is not None else None
                if (
                    len(encoded) > MAX_INLINE_SELECTED_CHECK_BYTES
                    and occurrence in retained_nonpass_checks
                    and check.get("status") in {"PASS", "FAIL", "UNKNOWN"}
                ):
                    row["selected_package_check"] = dict(
                        _selected_check_observation_reference(
                            check, encoded=encoded,
                        )
                    )
                elif occurrence is not None:
                    retained_nonpass_checks.add(occurrence)
            realization = row.get("repository_realization")
            if type(realization) is dict:
                encoded = encoded_realization(realization)
                key = realization_key(realization)
                occurrence = (key, status) if key is not None else None
                if (
                    len(encoded) > MAX_INLINE_REPOSITORY_REALIZATION_BYTES
                    and occurrence in retained_nonpass_realizations
                    and type(realization.get("explanation")) is str
                    and bool(realization["explanation"].strip())
                ):
                    row["repository_realization"] = dict(
                        _repository_realization_reference(
                            realization, encoded=encoded,
                        )
                    )
                elif occurrence is not None:
                    retained_nonpass_realizations.add(occurrence)
            continue
        # A conditional non-trigger keeps its complete check: the denominator
        # commitment digests it, a digest-bound reference is larger than the
        # check it names, and a later recomputation must bind the same evidence.
        if (
            type(check) is dict
            and check.get("status") == "PASS"
            and row.get("checker_status") != "NOT_REQUIRED"
        ):
            encoded = encoded_check(check)
            if len(encoded) > MAX_INLINE_SELECTED_CHECK_BYTES:
                key = check_key(check)
                reference = references.get(key) if key is not None else None
                if reference is None:
                    reference = _selected_check_reference(
                        check, encoded=encoded,
                    )
                    if key is not None:
                        references[key] = reference
                # Keep rows independently mutable while sharing no large
                # observation body. The reference itself is bounded.
                row["selected_package_check"] = dict(reference)
        realization = row.get("repository_realization")
        if type(realization) is dict:
            encoded = encoded_realization(realization)
            if len(encoded) > MAX_INLINE_REPOSITORY_REALIZATION_BYTES:
                key = realization_key(realization)
                reference = (
                    realization_references.get(key)
                    if key is not None else None
                )
                if reference is None:
                    reference = _repository_realization_reference(
                        realization, encoded=encoded,
                    )
                    if key is not None:
                        realization_references[key] = reference
                row["repository_realization"] = dict(reference)


def _compact_successful_instance_rows(
    rows: list[dict[str, Any]],
    *,
    force: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    """Project only PASS rows when their repeated evidence exceeds the wire budget.

    Package aggregation consumes the complete rows before this function runs.
    Non-PASS rows remain untouched and directly actionable.  Repeated PASS-only
    reason, applicability, realization and kind-requirement material is interned
    once by digest; every projected row keeps its exact object, obligation,
    proposition, checker status and the digest of its reconstructable normalized
    source row.
    """

    encoded_bytes = 0
    for row in rows:
        encoded_bytes += len(binding.canonical_bytes(row))
        if encoded_bytes > MAX_INLINE_OBLIGATION_ROWS_BYTES:
            break
    if not force and encoded_bytes <= MAX_INLINE_OBLIGATION_ROWS_BYTES:
        return None

    definitions: dict[str, dict[str, Any]] = {}

    def retain_definition(body: dict[str, Any]) -> str:
        """Intern one independently reusable PASS-row field group."""

        definition_digest = binding.value_digest(body)
        definitions.setdefault(definition_digest, {
            "definition_digest": definition_digest,
            **body,
        })
        return definition_digest

    committed_rows: list[dict[str, Any]] = []
    projected = 0
    for row in rows:
        if row.get("status") != "PASS" or row.get("blockers") != []:
            committed_rows.append(row)
            continue
        selected_check = row.get("selected_package_check")
        if (
            row.get("checker_status") != "NOT_REQUIRED"
            and type(selected_check) is dict
            and selected_check.get("status") == "PASS"
        ):
            selected_check = _selected_check_reference(selected_check)
        # The publication validator can reconstruct this normalized source row
        # exactly: all interned fields live in its definition, while a bulky
        # ordinary PASS check is represented by its original digest and byte
        # count. Conditional non-trigger checks remain complete so their
        # committed reason and evidence digest are independently replayable.
        committed_row = {
            **row,
            "selected_package_check": selected_check,
        }
        committed_rows.append(committed_row)
        complete_instance_digest = binding.value_digest(committed_row)
        semantic_definition = {
            "definition_kind": "SEMANTIC",
            "reason": row["reason"],
            "repository_realization": row["repository_realization"],
            "applicability": row["applicability"],
        }
        semantic_definition_digest = retain_definition(semantic_definition)
        kind_requirement_definition_digest = None
        if "kind_requirement" in row:
            kind_requirement_definition_digest = retain_definition({
                "definition_kind": "KIND_REQUIREMENT",
                "kind_requirement": row["kind_requirement"],
            })
        reference_reason = (
            "See pass_instance_definitions semantic definition "
            + semantic_definition_digest + "."
        )
        row.pop("kind_requirement", None)
        realization_reference = {
            "schema_version": "verifier-pass-instance-definition-reference-2",
            "semantic_definition_digest": semantic_definition_digest,
            "complete_instance_digest": complete_instance_digest,
            "transport": "REPORT_PASS_INSTANCE_FACTORED_DEFINITIONS",
        }
        if kind_requirement_definition_digest is not None:
            realization_reference[
                "kind_requirement_definition_digest"
            ] = kind_requirement_definition_digest
        row.update(
            reason=reference_reason,
            repository_realization=realization_reference,
            applicability={
                "status": semantic_definition["applicability"]["status"],
                "classification": semantic_definition["applicability"][
                    "classification"
                ],
                "assessment_required": True,
                "reason": reference_reason,
            },
            selected_package_check=selected_check,
        )
        projected += 1

    # A projection with no PASS rows cannot reduce the report and would only
    # wrap actionable FAIL/UNKNOWN evidence in a transport that has no table
    # entries. Keep the ordinary rows exactly as evaluated.
    if projected == 0:
        return None

    catalog = [definitions[key] for key in sorted(definitions)]
    profile = {
        "schema_version": "verifier-pass-instance-projection-2",
        "transport": "DIGEST_BOUND_PASS_FACTORED_REFERENCES",
        "source_instance_count": len(rows),
        "pass_reference_count": projected,
        "expanded_nonpass_count": len(rows) - projected,
        "source_instances_digest": binding.value_digest(committed_rows),
        "definition_count": len(catalog),
        "definitions_digest": binding.value_digest(catalog),
        "claim_boundary": (
            "Only blocker-free PASS rows are projected. Their normalized source "
            "rows are exactly reconstructable from independently factored "
            "semantic and kind-requirement definitions plus "
            "digest-bound ordinary PASS checks; conditional non-trigger checks "
            "remain complete. Every FAIL or UNKNOWN row remains expanded, and "
            "focused vstd gate commands remain in findings."
        ),
    }
    return catalog, profile


def _compact_projected_denominator_commitment(
    report: dict[str, Any],
) -> bool:
    """Replace only a projection's reconstructable conditional ledger.

    The expanded denominator remains the authoritative producer form until the
    PASS-row projection is attached.  Conditional checks stay complete in
    those projected rows, so this transport removes only their duplicate
    top-level index and seals the exact reconstruction count and digest.
    """

    execution = report.get("verifier_execution")
    if type(execution) is not dict:
        return False
    commitment = execution.get("obligation_denominator_commitment")
    if type(commitment) is not dict:
        return False
    rows = report.get("obligation_instances")
    _require(type(rows) is list and bool(rows),
             "PACKAGE_PROJECTED_DENOMINATOR_ROWS_MISSING")
    expected_fields = {
        "schema_version", "status", "selected_instance_count",
        "selected_instance_index_digest", "conditional_refutation_count",
        "conditional_refutations", "conditional_refutations_digest",
        "claim_boundary", "commitment_digest",
    }
    _require(
        set(commitment) == expected_fields
        and commitment.get("schema_version")
        == _EXPANDED_DENOMINATOR_COMMITMENT_SCHEMA
        and commitment.get("status") == "COMMITTED"
        and type(commitment.get("selected_instance_count")) is int
        and commitment["selected_instance_count"] > 0
        and _is_digest(commitment.get("selected_instance_index_digest"))
        and type(commitment.get("conditional_refutation_count")) is int
        and commitment["conditional_refutation_count"] >= 0
        and type(commitment.get("conditional_refutations")) is list
        and _is_digest(commitment.get("conditional_refutations_digest"))
        and type(commitment.get("claim_boundary")) is str
        and bool(commitment["claim_boundary"].strip())
        and _is_digest(commitment.get("commitment_digest"))
        and commitment["commitment_digest"] == binding.value_digest({
            key: value for key, value in commitment.items()
            if key != "commitment_digest"
        }),
        "PACKAGE_PROJECTED_DENOMINATOR_COMMITMENT_INVALID",
    )
    selected_index = _selected_instance_commitment_index(rows)
    conditional_refutations = _conditional_refutation_index(rows)
    _require(
        commitment["selected_instance_count"] == len(selected_index)
        and commitment["selected_instance_index_digest"]
        == binding.value_digest(selected_index)
        and commitment["conditional_refutation_count"]
        == len(conditional_refutations)
        and commitment["conditional_refutations"] == conditional_refutations
        and commitment["conditional_refutations_digest"]
        == binding.value_digest(conditional_refutations),
        "PACKAGE_PROJECTED_DENOMINATOR_COMMITMENT_DIFFERS",
    )
    for row in rows:
        if row.get("checker_status") != "NOT_REQUIRED":
            continue
        check = row.get("selected_package_check")
        _require(
            type(check) is dict
            and _is_digest(check.get("result_digest"))
            and check["result_digest"] == binding.value_digest({
                key: value for key, value in check.items()
                if key != "result_digest"
            }),
            "PACKAGE_PROJECTED_CONDITIONAL_CHECK_NOT_COMPLETE",
        )
    compact_body = {
        "schema_version": _PROJECTED_DENOMINATOR_COMMITMENT_SCHEMA,
        "status": "COMMITTED",
        "selected_instance_count": len(selected_index),
        "selected_instance_index_digest": binding.value_digest(selected_index),
        "conditional_refutation_count": len(conditional_refutations),
        "conditional_refutations_digest": binding.value_digest(
            conditional_refutations
        ),
        "conditional_refutations_transport": _PROJECTED_CONDITIONAL_TRANSPORT,
        "claim_boundary": (
            "The exact conditional-refutation ledger is reconstructed from "
            "the complete self-bound conditional checks retained in projected "
            "obligation rows."
        ),
    }
    execution["obligation_denominator_commitment"] = {
        **compact_body,
        "commitment_digest": binding.value_digest(compact_body),
    }
    return True


def _upgrade_successful_instance_projection_v3(
    report: dict[str, Any],
) -> bool:
    """Replace projected PASS rows with reconstructable digest-bound tables.

    Version 2 factors repeated semantic bodies but intentionally leaves one
    mapping per PASS instance.  At package scale those repeated mapping keys,
    object/route identities and check envelopes dominate the report.  Version 3
    runs only after the complete Version-2 projection exists: it retains every
    non-PASS row byte-for-byte and encodes each PASS row as indexes into bounded
    object, route, definition and check tables.  The Version-2
    ``source_instances_digest`` remains the reconstruction oracle.
    """

    profile = report.get("obligation_instance_projection")
    definitions = report.get("pass_instance_definitions")
    rows = report.get("obligation_instances")
    if not (
        type(profile) is dict
        and profile.get("schema_version")
        == "verifier-pass-instance-projection-2"
        and profile.get("transport")
        == "DIGEST_BOUND_PASS_FACTORED_REFERENCES"
        and type(definitions) is list
        and type(rows) is list
    ):
        return False
    _require(
        profile.get("source_instance_count") == len(rows)
        and profile.get("pass_reference_count")
        == sum(
            row.get("status") == "PASS" and row.get("blockers") == []
            for row in rows if type(row) is dict
        )
        and profile.get("expanded_nonpass_count")
        == sum(
            not (row.get("status") == "PASS" and row.get("blockers") == [])
            for row in rows if type(row) is dict
        )
        and profile.get("definition_count") == len(definitions)
        and profile.get("definitions_digest") == binding.value_digest(definitions)
        and _is_digest(profile.get("source_instances_digest")),
        "PACKAGE_PASS_TABLE_SOURCE_PROJECTION_INVALID",
    )
    definition_indexes: dict[str, int] = {}
    for index, definition in enumerate(definitions):
        _require(
            type(definition) is dict
            and _is_digest(definition.get("definition_digest"))
            and definition["definition_digest"] == binding.value_digest({
                key: value for key, value in definition.items()
                if key != "definition_digest"
            })
            and definition["definition_digest"] not in definition_indexes,
            "PACKAGE_PASS_TABLE_DEFINITION_INVALID",
        )
        definition_indexes[definition["definition_digest"]] = index

    object_table: list[list[Any]] = []
    object_indexes: dict[bytes, int] = {}
    route_table: list[list[Any]] = []
    route_indexes: dict[bytes, int] = {}
    check_definitions_by_digest: dict[str, dict[str, Any]] = {}
    pending_entries: list[dict[str, Any]] = []
    expanded_nonpass: list[dict[str, Any]] = []
    expanded_indexes: list[int] = []
    verifier_id: str | None = None
    projected_row_fields = set(
        (*_PASS_TABLE_OBJECT_FIELDS, *_PASS_TABLE_ROUTE_FIELDS,
         "instance_digest", "verifier_id", "reason",
         "repository_realization", "applicability",
         "selected_package_check", "checker_status", "status", "blockers",
         "native_specimen_is_instance_evidence",
         "package_graph_replay_is_instance_evidence")
    )
    from verifier.runtime import manifest_gate
    installed_routes = {
        (route["object_kind"], route["tier"], route["coordinate"]): route
        for route in manifest_gate.obligation_catalog()
    }

    def intern(value: list[Any], table: list[list[Any]],
               indexes: dict[bytes, int]) -> int:
        key = binding.canonical_bytes(value)
        selected = indexes.get(key)
        if selected is None:
            selected = len(table)
            indexes[key] = selected
            table.append(value)
        return selected

    for source_index, row in enumerate(rows):
        _require(type(row) is dict, "PACKAGE_PASS_TABLE_ROW_INVALID")
        if row.get("status") != "PASS" or row.get("blockers") != []:
            expanded_indexes.append(source_index)
            expanded_nonpass.append(row)
            continue
        _require(
            set(row) == projected_row_fields
            and _is_digest(row.get("instance_digest"))
            and row.get("checker_status") in {"PASS", "NOT_REQUIRED"}
            and type(row.get("verifier_id")) is str
            and bool(row["verifier_id"])
            and type(row.get("native_specimen_is_instance_evidence")) is bool
            and type(row.get("package_graph_replay_is_instance_evidence")) is bool,
            "PACKAGE_PASS_TABLE_ROW_INVALID",
        )
        if verifier_id is None:
            verifier_id = row["verifier_id"]
        _require(
            row["verifier_id"] == verifier_id,
            "PACKAGE_PASS_TABLE_VERIFIER_DIFFERS",
        )
        realization = row.get("repository_realization")
        _require(
            type(realization) is dict
            and realization.get("schema_version")
            == "verifier-pass-instance-definition-reference-2"
            and realization.get("transport")
            == "REPORT_PASS_INSTANCE_FACTORED_DEFINITIONS"
            and _is_digest(realization.get("semantic_definition_digest"))
            and _is_digest(realization.get("complete_instance_digest")),
            "PACKAGE_PASS_TABLE_REALIZATION_INVALID",
        )
        semantic_index = definition_indexes.get(
            realization["semantic_definition_digest"]
        )
        kind_digest = realization.get("kind_requirement_definition_digest")
        kind_index = (
            definition_indexes.get(kind_digest)
            if kind_digest is not None else None
        )
        _require(
            semantic_index is not None
            and (kind_digest is None or kind_index is not None),
            "PACKAGE_PASS_TABLE_DEFINITION_REFERENCE_INVALID",
        )
        selected_check = row.get("selected_package_check")
        checker_status = row["checker_status"]
        _require(type(selected_check) is dict,
                 "PACKAGE_PASS_TABLE_CHECK_INVALID")
        _require(
            _PASS_CHECK_IDENTITY_MARKER not in selected_check
            and _PASS_CHECK_RESULT_MARKER not in selected_check,
            "PACKAGE_PASS_TABLE_CHECK_MARKER_FORGED",
        )
        identity_values = {
            "object_id": row["object_id"],
            "object_digest": row["object_digest"],
            "coordinate": row["coordinate"],
            "proposition_digest": row["proposition_digest"],
            "checking_mechanism": row["checking_mechanism"],
            "native_coordinate": row["coordinate"],
            "conditional_coordinate": row["coordinate"],
        }
        projected_identity_fields = [
            field for field in _PASS_CHECK_IDENTITY_FIELDS
            if field in selected_check
        ]
        _require(
            all(
                selected_check[field] == identity_values[field]
                for field in projected_identity_fields
            ),
            "PACKAGE_PASS_TABLE_CHECK_IDENTITY_DIFFERS",
        )
        if checker_status == "PASS":
            full_check_digest = selected_check.get("full_check_digest")
            adaptation_result_digest = None
            result_digest = None
            _require(
                selected_check.get("schema_version")
                == "verifier-package-check-reference-1"
                and selected_check.get("status") == "PASS"
                and selected_check.get("transport") == "DIGEST_BOUND_REFERENCE"
                and _is_digest(full_check_digest),
                "PACKAGE_PASS_TABLE_CHECK_INVALID",
            )
            check_template = {
                key: value for key, value in selected_check.items()
                if key not in {
                    "full_check_digest", "result_digest",
                    *projected_identity_fields,
                }
            }
            check_template[_PASS_CHECK_RESULT_MARKER] = (
                "result_digest" in selected_check
            )
        else:
            full_check_digest = None
            adaptation_result_digest = selected_check.get(
                "adaptation_result_digest"
            )
            result_digest = selected_check.get("result_digest")
            installed_route = installed_routes.get((
                row.get("object_kind"), row.get("tier"), row.get("coordinate")
            ))
            _require(
                type(installed_route) is dict
                and _conditional_refutation_matches_route(
                    installed_route, selected_check
                )
                and selected_check.get("status") == "PASS"
                and selected_check.get("fulfillment_required") is False
                and selected_check.get("condition_status") == "NOT_TRIGGERED"
                and _is_digest(adaptation_result_digest)
                and _is_digest(result_digest)
                and result_digest == binding.value_digest({
                    key: value for key, value in selected_check.items()
                    if key != "result_digest"
                }),
                "PACKAGE_PASS_TABLE_CONDITIONAL_CHECK_INVALID",
            )
            check_template = {
                key: value for key, value in selected_check.items()
                if key not in {
                    "adaptation_result_digest", "result_digest",
                    *projected_identity_fields,
                }
            }
            check_template[_PASS_CHECK_RESULT_MARKER] = False
        check_template[_PASS_CHECK_IDENTITY_MARKER] = (
            projected_identity_fields
        )
        check_body = {
            "checker_status": checker_status,
            "template": check_template,
        }
        check_definition_digest = binding.value_digest(check_body)
        check_definitions_by_digest.setdefault(check_definition_digest, {
            "definition_digest": check_definition_digest,
            **check_body,
        })
        object_index = intern(
            [row[field] for field in _PASS_TABLE_OBJECT_FIELDS],
            object_table,
            object_indexes,
        )
        route_index = intern(
            [row[field] for field in _PASS_TABLE_ROUTE_FIELDS],
            route_table,
            route_indexes,
        )
        pending_entries.append({
            "source_index": source_index,
            "object_index": object_index,
            "route_index": route_index,
            "instance_digest": row["instance_digest"],
            "semantic_definition_index": semantic_index,
            "kind_requirement_definition_index": kind_index,
            "complete_instance_digest": realization["complete_instance_digest"],
            "native_specimen_is_instance_evidence": row[
                "native_specimen_is_instance_evidence"
            ],
            "package_graph_replay_is_instance_evidence": row[
                "package_graph_replay_is_instance_evidence"
            ],
            "check_definition_digest": check_definition_digest,
            "full_check_digest": full_check_digest,
            "adaptation_result_digest": adaptation_result_digest,
            "result_digest": result_digest,
        })

    check_definitions = [
        check_definitions_by_digest[digest]
        for digest in sorted(check_definitions_by_digest)
    ]
    check_indexes = {
        definition["definition_digest"]: index
        for index, definition in enumerate(check_definitions)
    }
    pass_entries = [
        [
            entry[field] if field != "check_definition_index"
            else check_indexes[entry["check_definition_digest"]]
            for field in _PASS_TABLE_ENTRY_FIELDS
        ]
        for entry in pending_entries
    ]
    _require(
        len(pass_entries) == profile["pass_reference_count"]
        and len(expanded_nonpass) == profile["expanded_nonpass_count"]
        and len(pass_entries) + len(expanded_nonpass) == len(rows)
        and verifier_id is not None,
        "PACKAGE_PASS_TABLE_COUNT_DIFFERS",
    )
    table_profile = {
        "schema_version": _PASS_TABLE_PROJECTION_SCHEMA,
        "transport": _PASS_TABLE_TRANSPORT,
        "source_instance_count": profile["source_instance_count"],
        "pass_reference_count": profile["pass_reference_count"],
        "expanded_nonpass_count": profile["expanded_nonpass_count"],
        "source_instances_digest": profile["source_instances_digest"],
        "definition_count": profile["definition_count"],
        "definitions_digest": profile["definitions_digest"],
        "verifier_id": verifier_id,
        "object_field_order": list(_PASS_TABLE_OBJECT_FIELDS),
        "object_table": object_table,
        "object_table_digest": binding.value_digest(object_table),
        "route_field_order": list(_PASS_TABLE_ROUTE_FIELDS),
        "route_table": route_table,
        "route_table_digest": binding.value_digest(route_table),
        "check_definition_count": len(check_definitions),
        "check_definitions": check_definitions,
        "check_definitions_digest": binding.value_digest(check_definitions),
        "pass_entry_field_order": list(_PASS_TABLE_ENTRY_FIELDS),
        "pass_entries": pass_entries,
        "pass_entries_digest": binding.value_digest(pass_entries),
        "expanded_nonpass_source_indexes": expanded_indexes,
        "claim_boundary": (
            "Every blocker-free PASS row was fully evaluated before projection. "
            "The digest-bound tables reconstruct its Version-2 normalized row "
            "and complete committed source row exactly. Every FAIL or UNKNOWN "
            "row remains expanded and directly actionable."
        ),
    }
    report["obligation_instances"] = expanded_nonpass
    report["obligation_instance_projection"] = table_profile
    return True


def _attach_successful_instance_projection(
    report: dict[str, Any],
    *,
    force: bool = False,
) -> bool:
    """Attach one digest-bound PASS-row projection to a package report.

    The normal assessment path projects when the obligation ledger itself is
    large.  The final wire gate can additionally request a projection when the
    *whole* report exceeds its envelope even though that ledger stayed below
    its independent threshold.  This closes the gap between the per-section
    and aggregate byte bounds without raising ``MAX_REPORT_BYTES`` or dropping
    any non-PASS evidence.
    """

    if report.get("schema_version") != EXTENSIBLE_REPORT_SCHEMA:
        return False
    if "obligation_instance_projection" in report:
        return bool(
            force and _upgrade_successful_instance_projection_v3(report)
        )
    if "pass_instance_definitions" in report:
        return False
    rows = report.get("obligation_instances")
    if type(rows) is not list or not rows:
        return False
    projection = _compact_successful_instance_rows(rows, force=force)
    if projection is None:
        return False
    definitions, profile = projection
    _compact_projected_denominator_commitment(report)
    report["pass_instance_definitions"] = definitions
    report["obligation_instance_projection"] = profile
    return True


def _contract_coverage_reference(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize a large aggregation ledger while retaining every contract key.

    The assessment digest binds the complete, already-validated report. PASS
    contracts become small per-object/per-kind references. Non-PASS contracts
    retain their actionable residual requirements and every non-PASS clause,
    while their already successful clauses are represented by an exact digest.
    This prevents thousands of repeated successful clause bodies from making
    the package report itself exceed the finite traversal envelope. Every
    denominator finding remains expanded.
    """
    _require(type(report) is dict, "PACKAGE_CONTRACT_COVERAGE_INVALID")
    full = {key: value for key, value in report.items() if key != "assessment_digest"}
    _require(report.get("assessment_digest") == binding.value_digest(full),
             "PACKAGE_CONTRACT_COVERAGE_DIGEST_DIFFERS")
    contracts = report.get("contracts")
    findings = report.get("findings")
    _require(type(contracts) is list and type(findings) is list,
             "PACKAGE_CONTRACT_COVERAGE_LEDGER_INVALID")
    nonpass = [row for row in contracts if row.get("status") != "PASS"]
    passed = [row for row in contracts if row.get("status") == "PASS"]
    references = [{
        "object_id": row["object_id"],
        "object_digest": row["object_digest"],
        "kind": row["kind"],
        "status": "PASS",
        "finite_check_status": row["finite_check_status"],
        "clause_count": len(row["clauses"]),
        "clauses_digest": binding.value_digest(row["clauses"]),
        "kind_requirement_digest": binding.value_digest(row["kind_requirement"]),
        "contract_digest": binding.value_digest(row),
    } for row in passed]
    nonpass_references = []
    for row in nonpass:
        clauses = row["clauses"]
        actionable_clauses = [
            clause for clause in clauses
            if clause.get("closure_status") != "PASS"
        ]
        nonpass_references.append({
            "object_id": row["object_id"],
            "object_digest": row["object_digest"],
            "kind": row["kind"],
            "status": row["status"],
            "finite_check_status": row["finite_check_status"],
            "profile_status": row.get("profile_status"),
            "clause_count": len(clauses),
            "clauses_digest": binding.value_digest(clauses),
            "nonpass_clause_count": len(actionable_clauses),
            "nonpass_clauses": actionable_clauses,
            "residual_requirements": row["residual_requirements"],
            "kind_requirement_digest": binding.value_digest(
                row["kind_requirement"]
            ),
            "contract_digest": binding.value_digest(row),
        })
    selected_fields = (
        "through_tier", "registry_digest", "collection_digest",
        "source_census_digest", "verifier_id", "expected_instance_count",
        "observed_instance_count", "denominator_status", "finite_check_status",
        "status", "normative_coverage", "assessment_digest",
    )
    reference = {
        "schema_version": "verifier-package-contract-coverage-reference-1",
        "source_schema_version": report.get("schema_version"),
        **{field: report[field] for field in selected_fields},
        "assessment_bytes": len(binding.canonical_bytes(report)),
        "contract_count": len(contracts),
        "pass_contract_count": len(passed),
        "nonpass_contract_count": len(nonpass),
        "pass_contract_references": references,
        "contracts": nonpass_references,
        "findings": findings,
        "transport": "DIGEST_BOUND_REFERENCE",
        "claim_boundary": (
            "The complete current aggregation was validated before projection. "
            "PASS contracts retain exact object/kind and digest bindings. Non-PASS "
            "contracts retain actionable residuals and non-PASS clauses; their "
            "complete successful clause sets remain bound by digest. Denominator "
            "findings remain expanded."
        ),
    }
    if len(binding.canonical_bytes(reference)) <= MAX_INLINE_CONTRACT_COVERAGE_BYTES:
        return reference

    definitions: list[dict[str, Any]] = []
    definition_indexes: dict[str, int] = {}
    contract_rows: list[list[Any]] = []
    for contract, retained in zip(nonpass, nonpass_references):
        object_id = retained["object_id"]
        object_id_paths: list[list[str | int]] = []

        def factor_object_id(value: Any, path: list[str | int]) -> Any:
            if type(value) is str and value == object_id:
                object_id_paths.append(path)
                return None
            if type(value) is list:
                return [
                    factor_object_id(item, [*path, index])
                    for index, item in enumerate(value)
                ]
            if type(value) is dict:
                return {
                    key: factor_object_id(item, [*path, key])
                    for key, item in value.items()
                }
            return value

        definition_body = factor_object_id({
            key: retained[key] for key in (
                "status", "finite_check_status", "profile_status",
                "clause_count", "nonpass_clause_count",
                "nonpass_clauses", "residual_requirements",
            )
        }, [])
        definition_body["object_id_paths"] = object_id_paths
        definition_body["object_id_path_encoding"] = "JSON_PATH_SEGMENTS_V1"
        definition_digest = binding.value_digest(definition_body)
        definition_index = definition_indexes.get(definition_digest)
        if definition_index is None:
            definition_index = len(definitions)
            definition_indexes[definition_digest] = definition_index
            definitions.append({
                **definition_body,
                "definition_digest": definition_digest,
            })
        contract_rows.append([
            retained["object_id"],
            retained["object_digest"],
            retained["kind"],
            retained["kind_requirement_digest"],
            retained["contract_digest"],
            retained["clauses_digest"],
            definition_index,
        ])

    return {
        **{key: value for key, value in reference.items() if key not in {
            "schema_version", "contracts", "transport", "claim_boundary",
        }},
        "schema_version": "verifier-package-contract-coverage-reference-2",
        "nonpass_definition_count": len(definitions),
        "nonpass_definitions": definitions,
        "nonpass_definitions_digest": binding.value_digest(definitions),
        "contract_reference_field_order": [
            "object_id", "object_digest", "kind", "kind_requirement_digest",
            "contract_digest", "clauses_digest", "nonpass_definition_index",
        ],
        "contracts": contract_rows,
        "contracts_digest": binding.value_digest(contract_rows),
        "transport": "DIGEST_BOUND_FACTORED_NONPASS_REFERENCE",
        "claim_boundary": (
            "The complete current aggregation was validated before projection. "
            "PASS contracts retain exact object/kind and digest bindings. Every "
            "non-PASS contract key and exact contract digest remains inline; "
            "repeated actionable clauses and residuals are interned by digest, "
            "with explicit object-ID substitution paths. Denominator findings "
            "remain expanded."
        ),
    }


def _verifier_selection(manifest: dict[str, Any], objects: tuple[namespace.NamespaceObject, ...]) -> namespace.NamespaceObject:
    rules = {row["category"]: row for row in manifest["surface_rules"]}
    route = rules["installed_route"]
    mechanism = rules["installed_mechanism"]
    if route["disposition"] != "OWNED" or mechanism["disposition"] != "OWNED":
        raise PackagePolishUnknown("PACKAGE_VERIFIER_ASSIGNMENT_UNRESOLVED")
    _require(route["owner_object_id"] == mechanism["owner_object_id"],
             "PACKAGE_VERIFIER_ASSIGNMENT_CONFLICT")
    selected = next((item for item in objects if item.object_id == route["owner_object_id"]), None)
    _require(selected is not None and selected.kind is namespace.ObjectKind.VERIFIER,
             "PACKAGE_POLISH_OWNER_NOT_VERIFIER")
    return selected


def _route_applies_to_record(
    item: namespace.NamespaceObject,
    route: dict[str, Any],
    kinds: KindRequirements | None,
    represented_kind: str,
) -> bool:
    """Select routes required by the effective role without casting the record.

    Source and consequence classification can add a necessary role even when
    the manifest still declares only ``OBJECT``.  Selection must retain that
    role's obligations; the later typed-representation gate then keeps them
    UNKNOWN until an actual subject of ``represented_kind`` is declared.
    """
    if package_source_contracts.is_route(route):
        return kinds is not None and package_source_contracts.applies_to(
            item, kinds.declarations[item.object_id], route, kinds
        )
    if (
        package_execution.route_mechanism(route) is not None
        and "object_kind" in route
    ):
        selected = getattr(kinds, "execution_mechanisms", {}).get(
            item.object_id, frozenset()
        )
        return kinds is not None and package_execution.requires_route_assessment(
            kinds.declarations[item.object_id], route,
            selected_mechanisms=selected,
        )
    if added_kind_behavioral_routes.is_route(route):
        return represented_kind == route["object_kind"]
    return accepts_subject(route, represented_kind)


def _obligation_selection_preflight(
    tier: int,
    objects: tuple[namespace.NamespaceObject, ...],
    kinds: KindRequirements | None,
    coordinates: set[str] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Commit the exact selected denominator before any subject check runs."""

    inventory = core_tier_progression.installed_core_route_inventory()
    declarations = core_tier_progression.installed_core_route_declarations()
    cells = [{
        **cell,
        "registered_route_memberships": [{
            **route,
            **declarations[
                cell["object_kind"], cell["tier"], route["coordinate"]
            ],
        } for route in cell["registered_route_memberships"]],
    } for cell in inventory["family_cells"]]
    if kinds is not None:
        cells.extend({
            "object_kind": route["object_kind"],
            "tier": route["tier"],
            "registered_route_memberships": [route],
        } for route in package_execution.catalog())
        cells.extend({
            "object_kind": route["object_kind"],
            "tier": route["tier"],
            "registered_route_memberships": [route],
        } for route in added_kind_behavioral_routes.catalog())
        cells.extend({
            "object_kind": route["object_kind"],
            "tier": route["tier"],
            "registered_route_memberships": [route],
        } for route in package_source_contracts.catalog())
    selected_index = []
    for item in objects:
        required_kinds = (
            kinds.kinds(item.object_id)
            if kinds is not None else {item.kind.value}
        )
        for cell in cells:
            if cell["object_kind"] not in required_kinds or cell["tier"] > tier:
                continue
            for route in cell["registered_route_memberships"]:
                if (
                    coordinates is not None
                    and route["coordinate"] not in coordinates
                ) or not _route_applies_to_record(
                    item, route, kinds, cell["object_kind"]
                ):
                    continue
                identity = {
                    "object_id": item.object_id,
                    "object_digest": item.digest,
                    "coordinate": route["coordinate"],
                    "tier": cell["tier"],
                    "proposition_digest": route["proposition_digest"],
                }
                selected_index.append({
                    "object_id": item.object_id,
                    "object_kind": cell["object_kind"],
                    "coordinate": route["coordinate"],
                    "tier": cell["tier"],
                    "instance_digest": binding.value_digest(identity),
                })
                if len(selected_index) > MAX_OBLIGATION_INSTANCES:
                    raise PackagePolishCapacity
    selected_index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    if len({
        (item["object_id"], item["coordinate"])
        for item in selected_index
    }) != len(selected_index):
        raise ValueError("PACKAGE_OBLIGATION_SELECTION_DUPLICATE")
    return cells, selected_index


def _conditional_refutation_index(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Retain exact, explicit evidence for every selected non-trigger."""

    from verifier.runtime import manifest_gate
    routes = {
        (route["object_kind"], route["tier"], route["coordinate"]): route
        for route in manifest_gate.obligation_catalog()
    }
    retained = []
    for row in rows:
        if row.get("checker_status") != "NOT_REQUIRED":
            continue
        check = row.get("selected_package_check")
        _require(type(check) is dict, "PACKAGE_CONDITIONAL_REFUTATION_MISSING")
        route = routes.get((
            row.get("object_kind"), row.get("tier"), row.get("coordinate")
        ))
        _require(
            type(route) is dict
            and _conditional_refutation_matches_route(route, check),
            "PACKAGE_CONDITIONAL_REFUTATION_ROUTE_BINDING_INVALID",
        )
        reason = check.get("reason")
        _require(type(reason) is str and bool(reason.strip()),
                 "PACKAGE_CONDITIONAL_REFUTATION_REASON_MISSING")
        retained.append({
            "object_id": row["object_id"],
            "object_kind": row["object_kind"],
            "coordinate": row["coordinate"],
            "tier": row["tier"],
            "instance_digest": row["instance_digest"],
            "status": row["status"],
            "checker_status": row["checker_status"],
            "reason": reason,
            "evidence_digest": binding.value_digest(check),
        })
    retained.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["instance_digest"],
    ))
    return retained


def _instance_route_reason(
    route: dict[str, Any],
    obligation_reasons: dict[tuple[str, str], dict[str, Any]] | None,
    object_id: str,
    execution_mechanism: Any,
    *,
    source_route: bool,
    added_behavioral_route: bool,
) -> dict[str, Any]:
    """Select the one root reason for an exact compiled obligation.

    ``route["reason"]`` is retained only as the compiled obligation's
    definition when this low-level helper is exercised without a selected root
    authority (for example, isolated checker tests).  Public package polish
    always supplies ``obligation_reasons`` from ``ROOT/reasons.vstd`` and
    separately reports any missing exact object/coordinate decision.
    """

    selected = (
        obligation_reasons.get((object_id, route["coordinate"]))
        if obligation_reasons is not None else None
    )
    reason_text = selected["reason"] if selected is not None else route["reason"]
    authored_binding = (
        {
            "reason_id": selected["reason_id"],
            "decision": selected["decision"],
            "evidence": selected["evidence"],
        }
        if selected is not None else None
    )

    def realization(explanation: str, claim_boundary: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "explanation": explanation,
            "claim_boundary": claim_boundary,
        }
        if authored_binding is not None:
            body["root_reason"] = authored_binding
        return body

    if execution_mechanism is not None:
        return {"reason": reason_text, "repository_realization": realization(
            (
                "Select the exact owned implementation and fresh execution "
                "binding; no specimen supplies it."
            ),
            execution_mechanism.BOUNDARY,
        ), "_root_obligation_reason": selected}
    if source_route:
        return {"reason": reason_text, "repository_realization": realization(
            (
                "Replay the installed object-specific semantic review against "
                "the exact current owned-source and interface census. Native "
                "runtime specimens cannot supply it."
            ),
            (
                "Source-representation conformance only; runtime-domain truth, "
                "external authority, physical or financial effects, release and "
                "deployment remain separate."
            ),
        ), "_root_obligation_reason": selected}
    if added_behavioral_route:
        return {"reason": reason_text, "repository_realization": realization(
            (
                "Select and recheck the exact source-bound retained behavioral "
                "certificate. For Verifier's current source-representation "
                "objects, the installed semantic review may instead establish "
                "that the retained runtime-domain condition is not triggered."
            ),
            (
                "Finite retained MARKET, ROBOT, or FINBOT evidence only. The "
                "route's explicit NOT_ESTABLISHED boundaries remain outside PASS."
            ),
        ), "_root_obligation_reason": selected}
    return {
        "reason": reason_text,
        "repository_realization": realization(
            "The package VERIFIER evaluates this exact object/coordinate "
            "instance through the installed checking mechanism.",
            "The root reason establishes only that assessment is required; "
            "the installed checker result remains independent evidence.",
        ),
        "_root_obligation_reason": selected,
    }


def _instance_obligations_for_selection(
                          tier: int, objects: tuple[namespace.NamespaceObject, ...],
                          root: Path, verifier: namespace.NamespaceObject,
                          facets: dict[str, Any], *, evidence: InstanceEvidence | None = None,
                          kinds: KindRequirements | None = None,
                          source_contracts: package_source_contracts.SourceContractAssessment | None = None,
                          coordinates: set[str] | None = None,
                          selection_commitment: dict[str, Any] | None = None,
                          obligation_reasons: dict[tuple[str, str], dict[str, Any]] | None = None,
                          ) -> list[dict[str, Any]]:
    cells, preflight_index = _obligation_selection_preflight(
        tier, objects, kinds, coordinates,
    )
    if selection_commitment is not None:
        selection_commitment.clear()
        selection_commitment.update({
            "schema_version":
                "verifier-package-obligation-denominator-commitment-1",
            "status": "PRECOMMITTED",
            "selected_instance_count": len(preflight_index),
            "selected_instance_index_digest":
                binding.value_digest(preflight_index),
            "conditional_refutation_count": 0,
            "conditional_refutations": [],
            "conditional_refutations_digest": binding.value_digest([]),
            "claim_boundary": (
                "The exact selected route-instance denominator was committed "
                "before per-instance evaluation. Outcomes and conditional "
                "non-trigger evidence are retained separately."
            ),
        })
    selected = {row["object_id"]: row for row in facets["results"]}
    selected_collection_digest = namespace.composition_digest(objects)
    rows = []
    for item in objects:
        required_kinds = kinds.kinds(item.object_id) if kinds is not None else {item.kind.value}
        for cell in cells:
            if cell["object_kind"] not in required_kinds or cell["tier"] > tier:
                continue
            for route in cell["registered_route_memberships"]:
                coordinate = route["coordinate"]
                if ((coordinates is not None and coordinate not in coordinates)
                        or not _route_applies_to_record(
                            item, route, kinds, cell["object_kind"]
                        )):
                    continue
                execution_mechanism = package_execution.route_mechanism(route)
                source_route = package_source_contracts.is_route(route)
                added_behavioral_route = added_kind_behavioral_routes.is_route(route)
                specialized = (
                    execution_mechanism is not None
                    or source_route
                    or added_behavioral_route
                )
                reason = _instance_route_reason(
                    route,
                    obligation_reasons,
                    item.object_id,
                    execution_mechanism,
                    source_route=source_route,
                    added_behavioral_route=added_behavioral_route,
                )
                _require(bool(reason["reason"].strip()) and bool(
                    reason["repository_realization"]["explanation"].strip()),
                    "PACKAGE_OBLIGATION_REASON_MISSING")
                match = next((branch for name in ("generic_object_facets", "typed_facets")
                    if (branch := selected.get(item.object_id, {}).get(name)) is not None
                    and branch["coordinate"] == coordinate), None)
                if match is not None:
                    # A route-bound result is not transferable between two
                    # same-kind objects or package snapshots.  Retain the
                    # exact subject identity beside the replay evidence.
                    match = {
                        **match,
                        "object_id": item.object_id,
                        "object_digest": item.digest,
                        "collection_digest": selected_collection_digest,
                    }
                    for field in ("semantic_version", "proposition_digest", "checking_mechanism",
                                  "certificate_schema_version"):
                        _require(match[field] == route[field], "PACKAGE_CHECKER_ROUTE_BINDING_DIFFERS")
                identity = {"object_id": item.object_id, "object_digest": item.digest,
                            "coordinate": coordinate, "tier": cell["tier"],
                            "proposition_digest": route["proposition_digest"]}
                instance = {
                    **identity, "instance_digest": binding.value_digest(identity),
                    "object_kind": cell["object_kind"], "verifier_id": verifier.object_id,
                    "checking_mechanism": route["checking_mechanism"], "scope": route["scope"],
                    "reason": reason["reason"],
                    "repository_realization": reason["repository_realization"],
                    "applicability": {
                        "status": "UNKNOWN", "classification": "UNDETERMINED",
                        "assessment_required": True,
                        "reason": "Every installed obligation must be assessed for this declared object. A selected layout alone supplies no instance-specific necessity predicate or evidenced refutation of a conditional trigger. Missing applicability is not an optional obligation.",
                    },
                    "selected_package_check": match,
                    "checker_status": "NOT_RUN" if match is None else match["status"],
                    "status": "FAIL" if match is not None and match["status"] == "FAIL" else "UNKNOWN",
                    "blockers": (["PACKAGE_INSTANCE_EVIDENCE_MISSING"] if match is None else
                                 ["PACKAGE_INSTANCE_CHECK_REFUTED"] if match["status"] == "FAIL" else
                                 ["PACKAGE_INSTANCE_CHECK_UNAVAILABLE"] if match["status"] != "PASS" else
                                 ["PACKAGE_INSTANCE_SEMANTIC_FULFILLMENT_NOT_ESTABLISHED"])
                                + ["PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED"],
                    "native_specimen_is_instance_evidence": False,
                }
                root_obligation_reason = reason["_root_obligation_reason"]
                if root_obligation_reason is not None:
                    instance["applicability"] = {
                        "status": "PASS",
                        "classification": "NECESSARY",
                        "assessment_required": True,
                        "reason": root_obligation_reason["reason"],
                    }
                    instance["blockers"] = [
                        blocker for blocker in instance["blockers"]
                        if blocker != "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED"
                    ]
                if kinds is not None:
                    declaration = kinds.declarations[item.object_id]
                    instance.update(declared_kind=declaration["kind"], specializations=declaration["specializations"],
                                    kind_requirement=kinds.basis(item.object_id, cell["object_kind"]),
                                    package_graph_replay_is_instance_evidence=False)
                # A newly required kind is not an implicit conversion of the
                # selected record. Native checkers must see a genuinely typed
                # representation; never reuse another role's passing facets.
                # The facets replay above is executed over these exact manifest
                # objects and the exact full collection.  It is package-instance
                # evidence, unlike the separately retained native specimens.
                # Structural applicability is necessary for every admitted
                # record; a successful positive/negative/missing-evidence
                # discrimination therefore closes this bounded instance.
                structural_match = (
                    kinds is not None
                    and match is not None
                    and route["scope"] in STRUCTURAL
                    and (
                        route["scope"]
                        == "generic_canonical_representation_and_address"
                        or cell["object_kind"] == item.kind.value
                    )
                )
                if structural_match:
                    observed = match["status"]
                    instance.update(
                        selected_package_check=match,
                        checker_status=observed,
                        applicability={
                            "status": "PASS",
                            "classification": "NECESSARY",
                            "assessment_required": True,
                            "reason": (
                                "Every admitted package record requires its exact canonical representation "
                                "and declared typed layout. The package VERIFIER freshly replayed the "
                                "registered positive, negative and unavailable cases over this exact object "
                                "and selected package collection."
                            ),
                        },
                        blockers=([] if observed == "PASS" else
                                  ["PACKAGE_INSTANCE_CHECK_REFUTED"] if observed == "FAIL" else
                                  ["PACKAGE_INSTANCE_CHECK_UNAVAILABLE"]),
                        status=observed,
                        package_graph_replay_is_instance_evidence=True,
                    )
                replayed = None
                if source_route and source_contracts is not None:
                    replayed = source_contracts.evaluate(item, route)
                elif execution_mechanism is not None and evidence is not None:
                    replayed = package_execution.evaluate(evidence, item, route)
                elif evidence is not None:
                    replayed = evidence.evaluate(item, route)
                if (replayed is None and source_contracts is not None
                        and not source_route):
                    refutation = source_contracts.refute_native_runtime_variant(
                        item, route, object_kind=cell["object_kind"], tier=cell["tier"]
                    )
                    if _conditional_refutation_matches_route(route, refutation):
                        instance.update(
                            selected_package_check=refutation,
                            checker_status="NOT_REQUIRED",
                            applicability={
                                "status": "PASS",
                                "classification": "CONDITION_NOT_MET",
                                "assessment_required": True,
                                "reason": refutation["reason"],
                            },
                            blockers=[],
                            status="PASS",
                            # This row closes a different question: current
                            # source review proved that the retained runtime
                            # variant's trigger is false.  A structural replay
                            # may have run earlier, but it is not evidence for
                            # a conditionally inapplicable runtime instance.
                            package_graph_replay_is_instance_evidence=False,
                        )
                        rows.append(instance)
                        continue
                # A reviewed source representation may prove that the native
                # runtime-record variant is not the selected subject.  Perform
                # that exact adaptation check before reporting a missing typed
                # runtime representation.  Unsupported/source-only hints have
                # no installed review, so they still remain visibly UNKNOWN.
                if (not structural_match and not specialized
                        and cell["object_kind"] != item.kind.value
                        and not accepts_subject(route, item.kind.value)):
                    instance.update(selected_package_check=None, checker_status="NOT_RUN", status="UNKNOWN",
                        blockers=["PACKAGE_INSTANCE_TYPED_REPRESENTATION_UNRESOLVED",
                                  "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED"])
                    rows.append(instance)
                    continue
                if replayed is not None:
                    instance["selected_package_check"] = replayed
                    instance["checker_status"] = replayed["status"]
                    if (
                        replayed.get("evidence_origin")
                        == "PACKAGE_GRAPH_BOUND_FRESH_REPLAY"
                    ):
                        # Unlike retained native specimens, this adapter is
                        # rebuilt from the exact current package root and full
                        # selected collection.  The distinct origin prevents
                        # another fresh execution from borrowing this stronger
                        # package-instance meaning.
                        instance["package_graph_replay_is_instance_evidence"] = True
                    if replayed["applicability_established"]:
                        instance["applicability"] = {"status": "PASS", "classification": "NECESSARY",
                            "assessment_required": True,
                            "reason": replayed.get("applicability_reason") or "The selected declared record necessarily requires its registered exact representation and typed layout. Current owned-source references and the exact request bind this instance; payload truth, execution and wider domain semantics are separate."}
                    instance["blockers"] = ([] if replayed["status"] == "PASS" else
                        ["PACKAGE_INSTANCE_SELECTION_REFUTED"] if replayed["status"] == "FAIL" else
                        ["PACKAGE_INSTANCE_SELECTION_UNAVAILABLE"])
                    if not replayed["applicability_established"]:
                        instance["blockers"].append("PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED")
                    instance["status"] = ("FAIL" if replayed["status"] == "FAIL" else
                        "PASS" if not instance["blockers"] else "UNKNOWN")
                    if match is not None and match["status"] == "FAIL":
                        instance["status"] = "FAIL"
                        instance["blockers"].append("PACKAGE_INSTANCE_CHECK_REFUTED")
                rows.append(instance)
    evaluated_index = [{
        "object_id": row["object_id"],
        "object_kind": row["object_kind"],
        "coordinate": row["coordinate"],
        "tier": row["tier"],
        "instance_digest": row["instance_digest"],
    } for row in rows]
    evaluated_index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    _require(evaluated_index == preflight_index,
             "PACKAGE_OBLIGATION_SELECTION_CHANGED_DURING_EVALUATION")
    if selection_commitment is not None:
        conditional_refutations = _conditional_refutation_index(rows)
        body = {
            **selection_commitment,
            "status": "COMMITTED",
            "conditional_refutation_count": len(conditional_refutations),
            "conditional_refutations": conditional_refutations,
            "conditional_refutations_digest":
                binding.value_digest(conditional_refutations),
        }
        selection_commitment.clear()
        selection_commitment.update({
            **body,
            "commitment_digest": binding.value_digest(body),
        })
    return rows


def _package_gate_status(rows: list[dict[str, Any]]) -> str:
    """Aggregate one exact package gate without borrowing another gate."""

    if any(row["status"] == "FAIL" for row in rows):
        return "FAIL"
    if rows and all(row["status"] == "PASS" for row in rows):
        return "PASS"
    return "UNKNOWN"


def _blocked_gate_reason(
    blocking_depth: int,
    blocking_status: str,
    blocking_rows: list[dict[str, Any]],
    skipped_depth: int,
) -> str:
    """Name the lower package instances that stopped execution, within a bound.

    Every skipped row repeats this text in two fields, so the blocking set is
    named in full only while it is small. A larger set names the refuting
    instances first, counts the rest by status and binds the complete set by
    digest; each blocking instance remains a full row at its own tier.
    """

    blocking = sorted(
        (row for row in blocking_rows if row["status"] != "PASS"),
        key=lambda row: row["status"] != "FAIL",
    )
    selected = [
        f"{row['object_id']}:{row['coordinate']}={row['status']}"
        for row in blocking
    ]
    if len(selected) <= _BLOCKED_GATE_NAMED_INSTANCES:
        focus = ", ".join(selected) if selected else "no passing instance set"
    else:
        counts = Counter(row["status"] for row in blocking)
        by_status = ", ".join(
            f"{counts[status]} {status}" for status in ("FAIL", "UNKNOWN")
            if counts[status]
        )
        omitted = len(selected) - _BLOCKED_GATE_NAMED_INSTANCES
        focus = (
            ", ".join(selected[:_BLOCKED_GATE_NAMED_INSTANCES])
            + f", and {omitted} more ({by_status} in all; complete set "
            + f"{binding.value_digest(selected)}, each a tier-{blocking_depth} "
            + "instance row in this report)"
        )
    return (
        f"Package gate {skipped_depth} was not executed because required "
        f"package gate {blocking_depth} status was {blocking_status}. "
        f"Blocking package instance(s): {focus}."
    )


def _not_run_package_instance(
    selected: dict[str, Any],
    *,
    item: namespace.NamespaceObject,
    verifier: namespace.NamespaceObject,
    route: dict[str, Any],
    reason: dict[str, Any],
    blocking_reason: str,
    kinds: KindRequirements | None,
) -> dict[str, Any]:
    """Retain a denominator row for a gate stopped by a lower non-PASS."""

    identity = {
        "object_id": item.object_id,
        "object_digest": item.digest,
        "coordinate": route["coordinate"],
        # Tier belongs to the installed family cell.  Retained route records
        # intentionally do not duplicate it, so bind the preflight selection.
        "tier": selected["tier"],
        "proposition_digest": route["proposition_digest"],
    }
    _require(
        binding.value_digest(identity) == selected["instance_digest"],
        "PACKAGE_OBLIGATION_SELECTION_CHANGED_DURING_EVALUATION",
    )
    row = {
        **identity,
        "instance_digest": selected["instance_digest"],
        "object_kind": selected["object_kind"],
        "verifier_id": verifier.object_id,
        "checking_mechanism": route["checking_mechanism"],
        "scope": route["scope"],
        "reason": reason["reason"],
        "repository_realization": reason["repository_realization"],
        "applicability": {
            "status": "UNKNOWN",
            "classification": "UNDETERMINED",
            "assessment_required": True,
            "reason": blocking_reason,
        },
        "selected_package_check": {
            "status": "UNKNOWN",
            "reason": blocking_reason,
        },
        "checker_status": "NOT_RUN",
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_SELECTION_UNAVAILABLE"],
        "native_specimen_is_instance_evidence": False,
    }
    if kinds is not None:
        declaration = kinds.declarations[item.object_id]
        row.update(
            declared_kind=declaration["kind"],
            specializations=declaration["specializations"],
            kind_requirement=kinds.basis(
                item.object_id, selected["object_kind"]
            ),
            package_graph_replay_is_instance_evidence=False,
        )
    return row


def _instance_obligations(
    tier: int,
    objects: tuple[namespace.NamespaceObject, ...],
    root: Path,
    verifier: namespace.NamespaceObject,
    facets: dict[str, Any],
    *,
    evidence: InstanceEvidence | None = None,
    kinds: KindRequirements | None = None,
    source_contracts: package_source_contracts.SourceContractAssessment | None = None,
    coordinates: set[str] | None = None,
    selection_commitment: dict[str, Any] | None = None,
    reason_selection: reason_integration.RootReasonSelection | None = None,
) -> list[dict[str, Any]]:
    """Execute the selected package GRAPH in strict cumulative gate order.

    Gate zero has already admitted the root ``objects.vstd`` before this
    function is reached.  A contradicted lower package gate stops dependent
    execution; an UNKNOWN lower gate remains in every cumulative result while
    later diagnostic checks may still expose additional gaps. Denominator rows
    for failure-skipped gates remain explicit UNKNOWN/NOT_RUN records so an
    early stop cannot erase obligations or masquerade as direct-tier success.
    """

    cells, preflight_index = _obligation_selection_preflight(
        tier, objects, kinds, coordinates,
    )
    if selection_commitment is not None:
        selection_commitment.clear()
        selection_commitment.update({
            "schema_version":
                "verifier-package-obligation-denominator-commitment-1",
            "status": "PRECOMMITTED",
            "selected_instance_count": len(preflight_index),
            "selected_instance_index_digest":
                binding.value_digest(preflight_index),
            "conditional_refutation_count": 0,
            "conditional_refutations": [],
            "conditional_refutations_digest": binding.value_digest([]),
            "claim_boundary": (
                "The exact selected route-instance denominator was committed "
                "before per-instance evaluation. Outcomes and conditional "
                "non-trigger evidence are retained separately."
            ),
        })

    obligation_reasons = (
        {
            (row["object_id"], row["coordinate"]): row
            for row in reason_selection.obligation_decisions
        }
        if reason_selection is not None else None
    )
    route_index = {
        (cell["object_kind"], cell["tier"], route["coordinate"]): route
        for cell in cells
        for route in cell["registered_route_memberships"]
    }
    object_index = {item.object_id: item for item in objects}
    rows: list[dict[str, Any]] = []
    blocking_depth: int | None = None
    blocking_status = "UNKNOWN"
    blocking_rows: list[dict[str, Any]] = []

    for depth in _cumulative_gate_depths(tier)[1:]:
        selected = [row for row in preflight_index if row["tier"] == depth]
        selected_coordinates = {row["coordinate"] for row in selected}
        if blocking_depth is None:
            current = _instance_obligations_for_selection(
                depth,
                objects,
                root,
                verifier,
                facets,
                evidence=evidence,
                kinds=kinds,
                source_contracts=source_contracts,
                coordinates=selected_coordinates,
                obligation_reasons=obligation_reasons,
            )
            rows.extend(current)
            current_status = _package_gate_status(current)
            if current_status == "FAIL":
                blocking_depth = depth
                blocking_status = current_status
                blocking_rows = current
            continue

        blocking_reason = _blocked_gate_reason(
            blocking_depth,
            blocking_status,
            blocking_rows,
            depth,
        )
        for selected_row in selected:
            key = (
                selected_row["object_kind"],
                selected_row["tier"],
                selected_row["coordinate"],
            )
            route = route_index.get(key)
            item = object_index.get(selected_row["object_id"])
            _require(
                type(route) is dict and item is not None,
                "PACKAGE_OBLIGATION_SELECTION_CHANGED_DURING_EVALUATION",
            )
            execution_mechanism = package_execution.route_mechanism(route)
            reason = _instance_route_reason(
                route,
                obligation_reasons,
                item.object_id,
                execution_mechanism,
                source_route=package_source_contracts.is_route(route),
                added_behavioral_route=
                    added_kind_behavioral_routes.is_route(route),
            )
            _require(
                bool(reason["reason"].strip())
                and bool(reason["repository_realization"]["explanation"].strip()),
                "PACKAGE_OBLIGATION_REASON_MISSING",
            )
            rows.append(_not_run_package_instance(
                selected_row,
                item=item,
                verifier=verifier,
                route=route,
                reason=reason,
                blocking_reason=blocking_reason,
                kinds=kinds,
            ))

    rows.sort(key=lambda row: (
        row["tier"], row["object_id"], row["coordinate"],
        row["object_kind"], row["instance_digest"],
    ))
    evaluated_index = [{
        "object_id": row["object_id"],
        "object_kind": row["object_kind"],
        "coordinate": row["coordinate"],
        "tier": row["tier"],
        "instance_digest": row["instance_digest"],
    } for row in rows]
    _require(
        evaluated_index == preflight_index,
        "PACKAGE_OBLIGATION_SELECTION_CHANGED_DURING_EVALUATION",
    )
    if selection_commitment is not None:
        conditional_refutations = _conditional_refutation_index(rows)
        body = {
            **selection_commitment,
            "status": "COMMITTED",
            "conditional_refutation_count": len(conditional_refutations),
            "conditional_refutations": conditional_refutations,
            "conditional_refutations_digest":
                binding.value_digest(conditional_refutations),
        }
        selection_commitment.clear()
        selection_commitment.update({
            **body,
            "commitment_digest": binding.value_digest(body),
        })
    return rows


def _root_obligation_reason_reconciliation(
    rows: list[dict[str, Any]],
    selection: reason_integration.RootReasonSelection,
) -> dict[str, Any]:
    """Reconcile root reasons with the exact selected package prefix."""

    selected = sorted({
        (row["object_id"], row["coordinate"])
        for row in rows
    })
    reasons = {
        (row["object_id"], row["coordinate"]): row
        for row in selection.obligation_decisions
    }
    missing = [key for key in selected if key not in reasons]
    missing_rows = [
        {"object_id": object_id, "coordinate": coordinate}
        for object_id, coordinate in missing
    ]
    return {
        "schema_version": "verifier-package-root-reason-reconciliation-1",
        "status": "PASS" if not missing else "UNKNOWN",
        "selected_obligation_count": len(selected),
        "root_obligation_reason_count": len(reasons),
        "reconciled_obligation_count": len(selected) - len(missing),
        "missing_obligation_reason_count": len(missing),
        "missing_obligation_reasons": missing_rows[:256],
        "missing_obligation_reasons_digest": binding.value_digest(missing_rows),
        "root_reason_ir_digest": selection.ir_digest,
        "claim_boundary": (
            "PASS establishes one checked REQUIRED reason in root reasons.vstd "
            "for every selected object/coordinate obligation. It does not "
            "supply the obligation checker result or promote a non-PASS check."
        ),
    }


def assess_package_polish(tier: int, source_root: str | Path = ".", *,
                          cancelled: bool = False) -> dict[str, Any]:
    """Evaluate the selected root manifest as a package through the requested tier.

The current manifest describes layouts, not all per-instance evidence. This
version therefore reports the actual graph and every installed obligation gap;
successful native controls cannot turn that package result into PASS.
"""
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA, "claim_scope": "MANIFEST_PACKAGE_GRAPH",
        "requested_tier": tier, "status": "UNKNOWN", "blockers": [],
        "manifest": {"path": "objects.vstd", "status": "NOT_SELECTED", "digest": None},
        "source_coordinate": None, "source_coordinate_digest": None,
        "mechanism_digest": None, "package_graph": None, "verifier_execution": None,
        "reason_authority": None, "reason_reconciliation": None,
        "native_diagnostics": None, "package_facet_replay": None,
        "obligation_instances": [], "tier_results": [],
        "execution_observations": [],
        "post_replay_source_recapture": "NOT_ESTABLISHED",
        "post_replay_manifest_recapture": "NOT_ESTABLISHED",
        "whole_package_conformance": "NOT_ESTABLISHED", "polished": False,
        "release_authorized": False, "deployment_authorized": False,
        "claim_boundary": "The root objects.vstd selects the package GRAPH and its aggregate VERIFIER. Polish evaluates that VERIFIER as the representation of the complete obligation graph, including the polish system itself. Declared layouts, package-instance checks and native control specimens are distinct. No aggregate result supplies evidence for one of its own members, and no missing reason, applicability decision, object evidence or prerequisite is supplied by a specimen PASS. Portable unsigned report hashes establish internal consistency and accidental-corruption detection only; source replay or a trusted signature is required for authority. Release and deployment are separate.",
    }
    root = None
    raw = None
    instance_evidence = None
    kind_requirements = None
    source_contracts = None
    active_stage = "PACKAGE_INPUT_VALIDATION"
    try:
        _require(type(tier) is int and tier in (1, 2, 3), "PACKAGE_TIER_UNSUPPORTED")
        _require(type(cancelled) is bool, "PACKAGE_CANCELLATION_INVALID")
        if cancelled:
            report["blockers"].append("PACKAGE_POLISH_CANCELLED")
            return _seal(report)
        root = Path(source_root).resolve(strict=True)
        raw = _read_manifest(root)
        reason_selection = reason_integration.select_root_reasons(root)
        report["reason_authority"] = reason_selection.authority
        report["manifest"].update(status="SELECTED", digest=binding.bytes_digest(raw))
        document = tier_zero_manifest._strict_json_document(raw)
        if document.get("schema_version") in package_manifest.SCHEMAS:
            report["schema_version"] = EXTENSIBLE_REPORT_SCHEMA
            report["kind_denominators"] = namespace_contracts.kind_denominators()
            report["manifest_refresh"] = _initial_manifest_refresh_binding(
                report["manifest"]["digest"]
            )
        coordinate = self_polish_estate._git_coordinate(root)
        manifest, validation, objects = package_manifest.select(document,
            repository=coordinate["repository"], revision=coordinate["revision"])
        semantic_namespace = _semantic_namespace(document)
        report["manifest"]["validation"] = validation
        source = self_polish_statics._capture_coordinate(root)
        report.update(source_coordinate=source, source_coordinate_digest=binding.value_digest(source),
                      mechanism_digest=mechanism_digest())
        if report["schema_version"] == EXTENSIBLE_REPORT_SCHEMA:
            report["manifest_refresh"] = _no_refresh_binding(
                report["manifest"]["digest"],
                report["source_coordinate_digest"],
            )
        # Build from the selected declaration bytes, not build_package_graph's template.
        root_id = next(row["object_id"] for row in manifest["objects"] if row["object_kind"] == "GRAPH")
        graph = next(item for item in objects if item.object_id == root_id)
        graph_digest = namespace.composition_digest(objects)
        composition = namespace.assess_composition(objects, expected_digest=graph_digest)
        outcome, composition_reason = _graph_composition_outcome(
            composition, graph_digest=graph_digest, object_count=len(objects),
        )
        if outcome != "PASS":
            raise PackageGraphCompositionRefusal(outcome, composition_reason)
        active_stage = "PACKAGE_GRAPH_REPRESENTATION"
        report["package_graph"] = {
            "status": "PASS", "root_id": graph.object_id, "root_kind": "GRAPH",
            "manifest_digest": report["manifest"]["digest"], "collection_digest": graph_digest,
            "object_count": len(objects),
            "objects": _graph_object_profile(objects, document),
            **_graph_declaration_profile(
                document, manifest, semantic_namespace=semantic_namespace,
            ),
            "claim_boundary": "Exact manifest-defined typed composition; payload truth and completeness of concrete repository-instance representation are not established by layout validation.",
        }
        active_stage = "PACKAGE_VERIFIER_SELECTION"
        verifier = _verifier_selection(manifest, objects)
        report["verifier_execution"] = {
            "object_id": verifier.object_id, "object_digest": verifier.digest,
            "subject_id": verifier.object_id,
            "subject_kind": "VERIFIER",
            "verified_graph_id": graph.object_id,
            "verified_graph_kind": "GRAPH",
            "subject_collection_digest": graph_digest,
            "manifest_digest": report["manifest"]["digest"],
            "assignment": "objects.vstd:surface_rules:installed_route+installed_mechanism",
            "checking_mechanism": "verifier.runtime.package_polish.assess_package_polish",
            "mechanism_digest": report["mechanism_digest"], "requested_tier": tier,
            "self_application": True, "self_application_authority": "NOT_ESTABLISHED",
        }
        active_stage = "PACKAGE_FACET_REPLAY"
        facets = package_self_polish._native_facets_replay(objects, report["source_coordinate_digest"])
        report["package_facet_replay"] = facets
        if facets["status"] == "FAIL":
            report["status"] = "FAIL"
            report["blockers"].append("PACKAGE_FACET_REPLAY_FAILED")
        if document.get("schema_version") in package_manifest.SCHEMAS:
            active_stage = "PACKAGE_KIND_AND_EVIDENCE_SELECTION"
            instance_evidence = InstanceEvidence(root, objects, semantic_namespace, package_graph_id=root_id,
                representation_updates=document.get("representation_updates"))
            kind_requirements = KindRequirements(root, semantic_namespace)
            source_contracts = package_source_contracts.SourceContractAssessment(
                root, objects, kind_requirements
            )
            report["kind_requirements"] = kind_requirements.report
            harness_applicability = kind_requirements.report["harness_applicability"]
            if harness_applicability["selection_status"] == "SELECTED" \
                    and harness_applicability["status"] != "PASS":
                report["blockers"].extend(harness_applicability["blockers"])
                if harness_applicability["status"] == "FAIL":
                    report["status"] = "FAIL"
            if kind_requirements.report["status"] != "PASS":
                report["blockers"].append("PACKAGE_KIND_REQUIREMENTS_NOT_ESTABLISHED")
                if kind_requirements.report["status"] == "FAIL":
                    report["status"] = "FAIL"
        active_stage = "PACKAGE_OBLIGATION_INSTANCES"
        denominator_commitment: dict[str, Any] = {}
        rows = _instance_obligations(tier, objects, root, verifier, facets,
                                    evidence=instance_evidence, kinds=kind_requirements,
                                    source_contracts=source_contracts,
                                    selection_commitment=denominator_commitment,
                                    reason_selection=reason_selection)
        reason_reconciliation = _root_obligation_reason_reconciliation(
            rows, reason_selection,
        )
        report["reason_reconciliation"] = reason_reconciliation
        if reason_reconciliation["status"] != "PASS":
            report["blockers"].append(
                "PACKAGE_ROOT_OBLIGATION_REASONS_INCOMPLETE"
            )
        # Publish only the final COMMITTED denominator.  If per-instance
        # evaluation raises, exception telemetry must not expose a mutable
        # PRECOMMITTED value as if it were a retained denominator receipt.
        report["verifier_execution"][
            "obligation_denominator_commitment"
        ] = denominator_commitment
        report["obligation_instances"] = rows
        self_polish = package_verifier_graph.compile_self_polish_graph(
            document=document,
            objects=objects,
            obligation_rows=rows,
            aggregate_verifier=verifier,
            package_graph_id=graph.object_id,
            package_graph_digest=graph_digest,
            requested_tier=tier,
        )
        report["verifier_execution"]["self_polish"] = self_polish
        if self_polish["status"] != "PASS":
            report["blockers"].append("PACKAGE_SELF_POLISH_NOT_ESTABLISHED")
            if self_polish["status"] == "FAIL":
                report["status"] = "FAIL"
        if any(row["status"] == "FAIL" for row in rows):
            report["status"] = "FAIL"
        # Full checks have already executed and their per-instance verdicts,
        # applicability, bindings and denominator commitment are fixed. Factor
        # repeated immutable observation bodies now, before contract coverage
        # hashes every row. Delaying this until final JSON sealing made graph
        # repetition dominate Tier-3 work even when no repository process ran.
        _compact_successful_instance_checks(rows)
        if kind_requirements is not None:
            active_stage = "PACKAGE_CONTRACT_COVERAGE"
            coverage = package_contract_coverage.assess(tier, objects, kind_requirements, rows,
                                                       verifier_id=verifier.object_id)
            report["kind_requirements"]["contract_coverage"] = coverage
            if coverage["denominator_status"] == "FAIL":
                report["status"] = "FAIL"
                report["blockers"].append("PACKAGE_CONTRACT_DENOMINATOR_REFUTED")
            # Base-kind checks are inherited, never evidence that the refinement's
            # higher-tier contract exists. Keep each extra kind visibly unclosed.
            unresolved = ([] if coverage["status"] == "PASS"
                          else kind_requirements.refinements(tier))
            report["refinement_coverage"] = unresolved
            if unresolved:
                report["blockers"].append("PACKAGE_REFINEMENT_HIGHER_TIER_CONTRACT_NOT_ESTABLISHED")
            if len(binding.canonical_bytes(coverage)) > MAX_INLINE_CONTRACT_COVERAGE_BYTES:
                report["kind_requirements"]["contract_coverage"] = \
                    _contract_coverage_reference(coverage)
        active_stage = "PACKAGE_TIER_AGGREGATION"
        for depth in range(1, tier + 1):
            # Numeric Polish is cumulative: a later tier cannot report green
            # while an earlier required tier is unresolved.  Retain the full
            # prefix in each summary instead of presenting direct-tier counts
            # as if they were cumulative closure.
            selected = [row for row in rows if row["tier"] <= depth]
            statuses = Counter(row["status"] for row in selected)
            self_polish_tier = self_polish["tier_results"][depth - 1]
            report["tier_results"].append({
                "tier": depth, "instance_count": len(selected), "status_counts": dict(statuses),
                "status": ("FAIL" if statuses["FAIL"] else "PASS"
                           if selected and statuses["PASS"] == len(selected) else "UNKNOWN"),
                "checker_status_counts": dict(Counter(row["checker_status"] for row in selected)),
                "prerequisite_tiers": list(range(depth)),
                "self_polish_status": self_polish_tier["status"],
                "member_verifier_count": self_polish_tier["member_verifier_count"],
                "member_status_counts": self_polish_tier["member_status_counts"],
                "polish_system_status": self_polish_tier["polish_system_status"],
                "self_polish_result_digest": self_polish_tier["tier_result_digest"],
            })
        from verifier.runtime import manifest_gate
        route_catalog = {
            (route["object_kind"], route["tier"], route["coordinate"]): route
            for route in manifest_gate.obligation_catalog()
        }
        if any(row["applicability"]["status"] != "PASS" for row in rows):
            report["blockers"].append("PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED")
        if any(
            row["checker_status"] != "PASS"
            and not (
                row["status"] == "PASS"
                and row["checker_status"] == "NOT_REQUIRED"
                and row["applicability"].get("status") == "PASS"
                and row["applicability"].get("classification") == "CONDITION_NOT_MET"
                and type(row.get("selected_package_check")) is dict
                and row["selected_package_check"].get("status") == "PASS"
                and row["selected_package_check"].get("fulfillment_required") is False
                and row["selected_package_check"].get("condition_status") == "NOT_TRIGGERED"
                and (
                    route := route_catalog.get((
                        row["object_kind"], row["tier"], row["coordinate"]
                    ))
                ) is not None
                and _conditional_refutation_matches_route(
                    route, row["selected_package_check"]
                )
            )
            for row in rows
        ):
            report["blockers"].append("PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE")
        if (kind_requirements is None
                or report["kind_requirements"]["contract_coverage"]["status"] != "PASS"):
            report["blockers"].append("PACKAGE_NORMATIVE_COVERAGE_NOT_ESTABLISHED")
        active_stage = "PACKAGE_NATIVE_DIAGNOSTICS"
        diagnostics = _run_native_diagnostics(tier, root)
        report["verifier_execution"]["native_diagnostic_report_digest"] = diagnostics["report_digest"]
        report["verifier_execution"]["package_facet_replay_digest"] = facets["replay_digest"]
        _require(diagnostics["report_digest"] == binding.value_digest({
            key: value for key, value in diagnostics.items() if key != "report_digest"}),
            "PACKAGE_NATIVE_DIAGNOSTIC_DIGEST_DIFFERS")
        _require(diagnostics["status"] in {"PASS", "FAIL", "UNKNOWN"},
                 "PACKAGE_NATIVE_DIAGNOSTIC_STATUS_INVALID")
        # Give an otherwise typed native PASS its precise binding error before
        # the strict cumulative validator classifies every other prefix defect.
        native_prerequisites = diagnostics.get("prerequisites")
        native_tier_zero = (
            native_prerequisites.get("0")
            if type(native_prerequisites) is dict else None
        )
        if (
            diagnostics["status"] == "PASS"
            and type(native_tier_zero) is dict
            and _is_digest(native_tier_zero.get("manifest_digest"))
        ):
            _require(
                native_tier_zero["manifest_digest"]
                == report["manifest"]["digest"],
                "PACKAGE_DIAGNOSTIC_MANIFEST_DIFFERS",
            )
        _require(
            _native_execution_prefix_complete(
                diagnostics,
                requested_tier=tier,
                source_coordinate_digest=report["source_coordinate_digest"],
                manifest_digest=report["manifest"]["digest"],
            ),
            "PACKAGE_NATIVE_EXECUTION_PREFIX_INVALID",
        )
        if diagnostics["status"] == "PASS":
            prerequisites = diagnostics["prerequisites"]
            _require(prerequisites["0"]["manifest_digest"] == report["manifest"]["digest"],
                     "PACKAGE_DIAGNOSTIC_MANIFEST_DIFFERS")
            selected_reports = [prerequisites[str(depth)] for depth in range(1, tier + 1)
                                if depth != 3]
            if tier == 3:
                selected_reports.append(diagnostics)
            for prior in selected_reports:
                _require(prior["status"] == "PASS" and prior["source_coordinate"] == source
                         and prior["source_coordinate_digest"] == report["source_coordinate_digest"]
                         and prior["post_replay_full_source_recapture"] == "PASS",
                         "PACKAGE_DIAGNOSTIC_SOURCE_DIFFERS")
        if diagnostics["status"] != "PASS":
            report["blockers"].append("PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS")
            if diagnostics["status"] == "FAIL":
                report["status"] = "FAIL"
        report["native_diagnostics"] = _native_diagnostic_reference(diagnostics)
        # All semantic consumers above received the full checks and aggregation
        # ledger. Normalize only successful bulky payloads for the bounded wire
        # report; failures remain expanded and directly actionable.
        active_stage = "PACKAGE_REPORT_PROJECTION"
        _attach_successful_instance_projection(report)
        # Recapture below runs even when a later stage fails or is unavailable.
    except PackagePolishCapacity:
        report["blockers"].append("PACKAGE_REPORT_CAPACITY_EXHAUSTED")
    except PackageGraphCompositionRefusal as exc:
        _record_graph_composition_refusal(report, exc)
    except PackagePolishUnknown as exc:
        report["blockers"].append(str(exc))
    except package_self_polish.PackageAssessmentUnavailable as exc:
        if exc.blockers:
            report["status"] = "FAIL"
            report["blockers"].extend(exc.blockers)
        report["blockers"].append("PACKAGE_FACETS_UNAVAILABLE")
    except FileNotFoundError as exc:
        report["blockers"].append("PACKAGE_MANIFEST_MISSING" if str(exc) == "PACKAGE_MANIFEST_MISSING"
                                  else "PACKAGE_SOURCE_OR_EVIDENCE_UNAVAILABLE")
    except _RESOURCE_ERRORS:
        report["blockers"].append("PACKAGE_ASSESSMENT_UNAVAILABLE")
    except self_polish_estate.EstateError as exc:
        _record_estate_refusal(report, exc)
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, StopIteration) as exc:
        report["status"] = "FAIL"
        report["blockers"].append(str(exc) or "PACKAGE_ASSESSMENT_CONTRACT_REJECTED")
    _close_incomplete_cumulative_accounting(
        report, tier=tier, stage=active_stage,
    )
    if root is not None and raw is not None:
        try:
            if instance_evidence is not None:
                instance_evidence.recapture()
            if kind_requirements is not None:
                kind_requirements.recapture()
            unchanged = _read_manifest(root) == raw
            report["post_replay_manifest_recapture"] = "PASS" if unchanged else "FAIL"
            if not unchanged:
                report["status"] = "FAIL"
                report["blockers"].append("PACKAGE_MANIFEST_CHANGED_DURING_REPLAY")
            if report["source_coordinate"] is not None:
                recapture = self_polish_tiers._post_replay_source_recapture(root, report["source_coordinate"])
                report["post_replay_source_recapture"] = recapture["status"]
                if recapture["status"] != "PASS":
                    report["blockers"].append("PACKAGE_SOURCE_RECAPTURE_NOT_PASS")
                    if recapture["status"] == "FAIL":
                        report["status"] = "FAIL"
                _require(mechanism_digest() == report["mechanism_digest"], "PACKAGE_MECHANISM_CHANGED")
        except _RESOURCE_ERRORS:
            report["blockers"].append("PACKAGE_CLOSING_RECAPTURE_UNAVAILABLE")
        except self_polish_estate.EstateError as exc:
            _record_estate_refusal(report, exc)
        except (ValueError, KeyError, TypeError) as exc:
            report["status"] = "FAIL"
            report["blockers"].append(str(exc))
    if instance_evidence is not None:
        report["execution_observations"] = package_execution.observation.retained(instance_evidence)
    if (report["status"] != "FAIL" and not report["blockers"]
            and report["obligation_instances"]
            and all(row["status"] == "PASS" for row in report["obligation_instances"])
            and report["verifier_execution"] is not None
            and report["verifier_execution"].get("self_polish", {}).get("status") == "PASS"
            and report["native_diagnostics"] is not None
            and report["native_diagnostics"]["status"] == "PASS"
            and report["post_replay_source_recapture"] == "PASS"
            and report["post_replay_manifest_recapture"] == "PASS"):
        report.update(status="PASS", whole_package_conformance="PASS", polished=True)
    return _seal(report, source_root=root)
