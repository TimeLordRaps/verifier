"""Conjunctive Tier-0 admission of the full package GRAPH through its VERIFIER.

The original nine gates are retained, not renamed away. Each now additionally
requires the corresponding namespace check. A narrower declaration receipt
cannot substitute for full route, slot, reason, estate or source closure.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from verifier.core.namespace import composition_digest
from verifier.runtime import (
    namespace_admission,
    namespace_consequences,
    namespace_contracts,
    namespace_manifest,
    package_manifest,
)
from verifier.runtime import package_semantic_review_partitions
from verifier.runtime import self_polish_estate, tier_zero, tier_zero_profile


LEGACY_REPORT_SCHEMA = "verifier-tier-zero-package-admission-report-3"
REPORT_SCHEMA = "verifier-tier-zero-package-admission-report-4"
REPORT_SCHEMAS = frozenset({LEGACY_REPORT_SCHEMA, REPORT_SCHEMA})
SEMANTIC_REVIEW_REPLAY_SCHEMA = "verifier-package-semantic-review-replay-1"
SEMANTIC_REVIEW_COORDINATES = ("VSTD-T0.2", "VSTD-T0.6")
# Audit codes for owned bytes that drifted, vanished, or were unreadable.
# Every other audit rejection is a conflict with the installed review.
_RETRYABLE_REVIEW_CODES = (
    "PACKAGE_SEMANTIC_REVIEW_ROOT_INVALID",
    "PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:",
    "PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:",
    "PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:",
)


def _component_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Retain component identity and nine outcomes without embedding its body."""
    return {
        key: report.get(key)
        for key in (
            "schema_version",
            "status",
            "profile_id",
            "profile_digest",
            "manifest_digest",
            "mechanism_digest",
            "obligation_count",
            "obligation_status_counts",
            "obligations",
            "blockers",
            "report_digest",
        )
    }


def profile_digest() -> str:
    return tier_zero_profile.value_digest({
        "composition": "ALL_RETAINED_AND_NAMESPACE_CHECKS_REQUIRED",
        "retained": tier_zero_profile.installed_tier_zero_profile()["profile_digest"],
        "namespace": namespace_admission.profile()["profile_digest"],
    })


def mechanism_digest() -> str:
    root = Path(__file__).parent
    return tier_zero_profile.value_digest({
        "retained": tier_zero.mechanism_digest(),
        "namespace": namespace_admission.mechanism_binding(),
        "composition": {name: self_polish_estate.bytes_digest((root / name).read_bytes())
                        for name in ("package_admission.py", "package_manifest.py")},
        "schema": self_polish_estate.bytes_digest((root.parent / "schemas/verifier-objects-manifest-3.schema.json").read_bytes()),
        "representations_schema": self_polish_estate.bytes_digest((root.parent / "schemas/verifier-objects-manifest-4.schema.json").read_bytes()),
        "package_representations_schema": self_polish_estate.bytes_digest((root.parent / "schemas/verifier-objects-manifest-5.schema.json").read_bytes()),
    })


def _reviewed_obligation(name: str) -> bool:
    """Name the obligations that the installed semantic audit owns."""
    return name.split("-", 1)[0] in package_semantic_review_partitions.REVIEW_KINDS


def _is_open_review_cell(cell: Any) -> bool:
    """An applicability cell that asserts nothing: UNRESOLVED and citing no evidence."""
    return (type(cell) is dict and cell.get("status") == "UNRESOLVED"
            and not cell.get("evidence"))


def _is_blank_review_binding(binding: Any) -> bool:
    """An obligation binding that asserts nothing: no reason, evidence or declared text."""
    if type(binding) is not dict or binding.get("evidence"):
        return False
    reason = binding.get("reason")
    declaration = binding.get("declaration")
    return (type(reason) is str and not reason.strip() and type(declaration) is dict
            and all(type(value) is str and not value.strip()
                    for value in declaration.values()))


def _matches_compiled_classification(
    selected: Any, expected: dict[str, Any]
) -> bool:
    """Accept the full audit cell or its sole deterministic compiled projection."""

    if selected == expected or type(selected) is not dict:
        return selected == expected
    projected = dict(expected)
    projected["reason"] = namespace_consequences.compiled_classification_reason(
        expected["status"], expected["reason"]
    )
    return selected == projected


def _documented_retention_binding_matches(
    row: dict[str, Any],
    obligation_id: str,
    binding: Any,
    files: dict[str, str],
    answers: dict[tuple[str, str], str],
    contracts: dict[str, dict[str, Any]],
) -> bool:
    """Recognize one exact demand-only reason binding outside source review.

    Source review owns semantic classification and its own declarations.  The
    sole root reasons ledger can independently retain a kind's Tier-0 obligation
    while fulfillment remains unestablished.  Admit only the compiler's exact
    representation of that separate claim; arbitrary non-empty prose remains a
    source-review conflict.
    """

    kind = obligation_id.split("-", 1)[0]
    reason_id = answers.get((row.get("object_id"), kind))
    if reason_id is None or type(binding) is not dict or set(binding) != {
        "reason", "evidence", "declaration"
    }:
        return False
    if binding["reason"] != (
        "reasons.vstd:" + reason_id + "; fulfillment NOT_ESTABLISHED."
    ):
        return False
    contract = contracts.get(obligation_id)
    declaration = binding["declaration"]
    if (
        contract is None
        or type(declaration) is not dict
        or set(declaration) != set(contract["declaration_fields"])
        or not all(value == "NOT_ESTABLISHED" for value in declaration.values())
    ):
        return False
    evidence = binding["evidence"]
    if type(evidence) is not list or len(evidence) != 1:
        return False
    reference = evidence[0]
    owned_paths = sorted(
        {
        surface.removeprefix("file:")
        for surface in row.get("surfaces", ())
        if type(surface) is str and surface.startswith("file:")
        and surface.removeprefix("file:") in files
        },
        key=lambda path: (len(path.encode("utf-8")), path),
    )
    return (
        type(reference) is dict
        and set(reference) == {"path", "sha256"}
        and bool(owned_paths)
        and reference["path"] == owned_paths[0]
        and files.get(reference["path"]) == reference["sha256"]
    )


def _semantic_review_replay(root: Path, objects: list[dict[str, Any]],
                            files: dict[str, str]) -> dict[str, Any]:
    """Replay the installed 318-object semantic audit against the selected bytes.

    Validation only: the audit deep-copies its input and this function compares
    rather than adopts. Generic Tier-0 shapes cannot see a same-status reason or
    a non-empty declaration substitution, so each reviewed cell and declaration
    must equal the replayed value exactly. Source drift or absence is UNKNOWN;
    a reopened or blank cell asserts nothing, so it is an unadopted answer (UNKNOWN)
    rather than a contradiction; any other rejection is a conflict and FAILS.
    """
    rows = {row.get("object_id"): row for row in objects}
    subset = {object_id: rows[object_id]
              for object_id in package_semantic_review_partitions.PARTITION_OBJECT_IDS
              if object_id in rows}
    # The audit preserves any non-empty binding it is handed, so replay over
    # copies whose reviewed bindings are blank. Its output is then canonical
    # for current bytes, and the caller's rows are compared against that output.
    blanked = {}
    for object_id, row in subset.items():
        if type(row.get("classification")) is dict and type(row.get("obligations")) is dict:
            row = {**row, "classification": {}, "obligations": {
                name: value for name, value in row["obligations"].items()
                if not _reviewed_obligation(name)}}
        blanked[object_id] = row
    blockers: list[str] = []
    try:
        if len(rows) != len(objects):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_DUPLICATE_OBJECT")
        replayed = package_semantic_review_partitions.apply_package_semantic_review_partitions(
            root, blanked, files)
    except OSError:
        status, blockers = "UNKNOWN", ["PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE"]
    except ValueError as exc:
        code = str(exc)
        status = "UNKNOWN" if code.startswith(_RETRYABLE_REVIEW_CODES) else "FAIL"
        blockers = [code]
    else:
        mismatches: list[str] = []
        unadopted: list[str] = []
        documented_answers: dict[tuple[str, str], str] | None = None
        reviewed_contracts: dict[str, dict[str, Any]] | None = None

        def checked_documented_answers() -> dict[tuple[str, str], str]:
            nonlocal documented_answers
            if documented_answers is not None:
                return documented_answers
            from verifier.runtime.tier_zero_reasoning import integration

            try:
                selection = integration.select_root_reasons(root)
                selected = integration.documented_applicability_answers(
                    selection, objects
                )
            except (OSError, TypeError, ValueError):
                documented_answers = {}
                return documented_answers
            documented_answers = {
                (answer["object_id"], answer["object_kind"]): answer["reason_id"]
                for answer in selected
                if type(answer) is dict
                and answer.get("decision") == "APPLIES"
                and type(answer.get("object_id")) is str
                and type(answer.get("object_kind")) is str
                and type(answer.get("reason_id")) is str
            }
            return documented_answers

        def checked_reviewed_contracts() -> dict[str, dict[str, Any]]:
            nonlocal reviewed_contracts
            if reviewed_contracts is None:
                reviewed_contracts = {
                    obligation["id"]: obligation
                    for obligation in namespace_contracts.requirements_for(
                        namespace_contracts.namespace_registry(),
                        package_semantic_review_partitions.REVIEW_KINDS,
                    )
                    if obligation["kind"]
                    in package_semantic_review_partitions.REVIEW_KINDS
                }
            return reviewed_contracts

        for object_id in package_semantic_review_partitions.PARTITION_OBJECT_IDS:
            expected, actual = replayed[object_id], subset[object_id]
            for kind in package_semantic_review_partitions.REVIEW_KINDS:
                selected = actual["classification"].get(kind)
                if not _matches_compiled_classification(
                    selected, expected["classification"][kind]
                ):
                    # Source drift reopens an answer instead of replacing it. An open
                    # cell makes no claim, so it cannot contradict the audit; it is
                    # simply not adopted yet. A cell that asserts something different
                    # is a contradiction.
                    (unadopted if _is_open_review_cell(selected) else mismatches).append(
                        ("PACKAGE_SEMANTIC_REVIEW_UNADOPTED:"
                         if _is_open_review_cell(selected)
                         else "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_CONFLICT:")
                        + object_id + ":" + kind)
            expected_obligations = {name: value for name, value in expected["obligations"].items()
                                    if _reviewed_obligation(name)}
            actual_obligations = {name: value for name, value in actual["obligations"].items()
                                  if _reviewed_obligation(name)}
            for name in sorted(set(expected_obligations) | set(actual_obligations)):
                if actual_obligations.get(name) != expected_obligations.get(name):
                    if (
                        name not in expected_obligations
                        and _documented_retention_binding_matches(
                            actual,
                            name,
                            actual_obligations.get(name),
                            files,
                            checked_documented_answers(),
                            checked_reviewed_contracts(),
                        )
                    ):
                        continue
                    # Only an installed obligation can be merely unadopted; a binding
                    # the installed contract never defined stays a conflict.
                    blank = (name in expected_obligations
                             and _is_blank_review_binding(actual_obligations.get(name)))
                    (unadopted if blank else mismatches).append(
                        ("PACKAGE_SEMANTIC_REVIEW_UNADOPTED:" if blank
                         else "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:")
                        + object_id + ":" + name)
        if mismatches:
            status, blockers = "FAIL", sorted(mismatches + unadopted)
        else:
            # An UNRESOLVED cell carries no authority, so it blocks PASS until
            # the installed audit resolves it against current bytes.
            blockers = sorted(unadopted + [
                "PACKAGE_SEMANTIC_REVIEW_UNRESOLVED:" + object_id + ":" + kind
                for object_id, kinds in package_semantic_review_partitions.unresolved_inventory().items()
                for kind in kinds
            ])
            status = "UNKNOWN" if blockers else "PASS"
    return {
        "schema_version": SEMANTIC_REVIEW_REPLAY_SCHEMA,
        "status": status,
        "object_count": len(package_semantic_review_partitions.PARTITION_OBJECT_IDS),
        "review_counts": package_semantic_review_partitions.review_counts(),
        "audit_digest": tier_zero_profile.value_digest(
            package_semantic_review_partitions.review_document()),
        "blockers": blockers,
        "claim_boundary": "Exact replay of the installed semantic audit against the "
            "selected source bytes. It admits the reviewed declarations only and "
            "establishes neither mechanism execution nor semantic truth.",
    }


def _namespace_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the namespace rows with every evidence set expanded in place.

    A compact (version-6) namespace stores evidence-set pointers rather than the
    reviewed evidence, so replaying the audit over its raw rows would report every
    reviewed cell as a conflict. Inline namespaces are already expanded.
    """
    namespace = document["namespace"]
    if type(namespace) is dict and namespace.get("schema_version") == namespace_manifest.COMPACT_SCHEMA:
        namespace = namespace_manifest.normalize_manifest(namespace)
    return namespace["objects"]


def assess(source_root: str | Path = ".", *, manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Run both contracts on one selected file and require equal source captures."""
    root = Path(source_root).resolve(strict=True)
    path = root / "objects.vstd" if manifest_path is None else Path(manifest_path).resolve(strict=True)
    raw, document = namespace_manifest.read_manifest(path)
    coordinate = self_polish_estate._git_coordinate(root)
    retained, _, objects = package_manifest.select(document,
        repository=coordinate["repository"], revision=coordinate["revision"])
    # Select the executor from the root's route and mechanism assignments. This
    # is the same selection function used for tiers 1-3, not a parallel template.
    from verifier.runtime.package_polish import _verifier_selection
    verifier = _verifier_selection(retained, objects)
    graph_id = next(row["object_id"] for row in retained["objects"] if row["object_kind"] == "GRAPH")
    opening_mechanism = mechanism_digest()
    core = tier_zero.assess_legacy_tier_zero(root, manifest_path=path)
    extension = namespace_admission.assess(root, manifest_path=path)
    outcomes = []
    for original, added in zip(core["obligations"], extension["obligations"], strict=True):
        statuses = {original["status"], added["status"]}
        outcomes.append({**original,
            "status": "FAIL" if "FAIL" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS",
            "blockers": sorted(set(original["blockers"] + added["blockers"])),
            "assessment_reason": "Retained contract: " + original["assessment_reason"]
                + " Namespace addition (" + added["name"] + "): " + added["assessment_reason"],
            "namespace_check": added,
        })
    final_census = self_polish_estate.capture_candidate_source_census(root)
    try:
        closing_raw = namespace_manifest.read_manifest(path)[0]
    except (OSError, ValueError):
        closing_raw = None
    unchanged = (closing_raw == raw and mechanism_digest() == opening_mechanism
        and final_census["census_digest"] == core["finalization"]["source_census_digest"]
        == extension.get("source_census_digest")
        and self_polish_estate._git_coordinate(root) == coordinate)
    if not unchanged:
        outcomes[6]["status"] = "FAIL"
        outcomes[6]["blockers"] = sorted(set(outcomes[6]["blockers"] + ["PACKAGE_ADMISSION_SOURCE_CHANGED"]))
        outcomes[6]["assessment_reason"] += " The two assessments or final recapture differ in source or mechanism bytes."
    # A census without its file digests makes every owned path unresolved, so the
    # replay reports UNKNOWN through its existing source check instead of raising.
    files = {row["path"]: row["sha256"] for row in final_census.get("files", [])}
    declarations = _namespace_rows(document)
    replay = _semantic_review_replay(root, declarations, files)
    for row in outcomes:
        if row["coordinate"] not in SEMANTIC_REVIEW_COORDINATES:
            continue
        row["semantic_review_replay"] = replay
        if replay["status"] != "PASS":
            row["status"] = "FAIL" if "FAIL" in (row["status"], replay["status"]) else "UNKNOWN"
            row["blockers"] = sorted(set(row["blockers"] + replay["blockers"]))
            row["assessment_reason"] += (" Installed semantic review replay (" + replay["status"]
                + ") did not exactly reproduce the reviewed classification and declarations"
                " against the selected source bytes.")
    counts = Counter(row["status"] for row in outcomes)
    status = "FAIL" if counts["FAIL"] else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
    from verifier.runtime.manifest_gate import admission_findings
    findings = [*admission_findings(core), *extension["findings"]]
    report = {
        "schema_version": REPORT_SCHEMA,
        "profile_id": "vstd-package-admission-4",
        "profile_digest": profile_digest(), "mechanism_digest": opening_mechanism,
        "status": status,
        "source_coordinate": core["source_coordinate"],
        "manifest_digest": core["manifest_digest"],
        "obligation_count": len(outcomes),
        "obligations": outcomes,
        "obligation_status_counts": {key: counts[key] for key in ("PASS", "FAIL", "UNKNOWN")},
        "blockers": sorted({code for row in outcomes for code in row["blockers"]}),
        "tier_1_plus_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": core["claim_boundary"],
        "retained_admission": _component_summary(core),
        "namespace_admission": _component_summary(extension),
        "object_assessments": extension["object_assessments"],
        "required_obligations": extension["required_obligations"],
        "assessment_executed": extension["assessment_executed"],
        "package_graph": {"root_id": graph_id, "object_count": len(objects),
            "collection_digest": composition_digest(objects),
            "declaration_count": len(declarations),
            "declaration_digest": tier_zero_profile.value_digest(declarations)},
        "verifier_execution": {"object_id": verifier.object_id, "subject_id": graph_id,
            "checking_mechanism": "verifier.runtime.package_admission.assess",
            "manifest_digest": self_polish_estate.bytes_digest(raw), "mechanism_digest": opening_mechanism,
            "self_application": True, "self_application_authority": "NOT_ESTABLISHED"},
        "findings": findings,
        "next_obligation": extension["next_obligation"],
    }
    report["finalization"] = {**core["finalization"], "status": status,
        "complete": status == "PASS", "finalized": status == "PASS",
        "profile_digest": report["profile_digest"], "mechanism_digest": opening_mechanism,
        "closed_coordinates": [row["coordinate"] for row in outcomes if row["status"] == "PASS"],
        "unclosed_coordinates": [row["coordinate"] for row in outcomes if row["status"] != "PASS"],
        "reason": "All retained and namespace checks must pass on the same package GRAPH: " + status,
    }
    report.pop("report_digest", None)
    return {**report, "report_digest": tier_zero_profile.value_digest(report)}
