"""Compose every source-owned original-kind audit without hiding unknowns.

Terminology: application programming interface (API); JavaScript Object
Notation (JSON).

The eight feature-near catalogs deliberately remain independently reviewable.
This module is the package boundary: it proves that their object denominators
are disjoint and exhaustive, exposes the exact unresolved cells, and refuses to
construct a full-closure profile while even one applicability question remains
unanswered.  A collection of partial green checks is therefore never confused
with Tier-0 repository admission.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy
from dataclasses import fields as dataclass_fields
from dataclasses import is_dataclass
from hashlib import sha256
import json
import multiprocessing
import os
from pathlib import Path
import re
from typing import Any

from verifier.runtime import (
    package_original_kind_catalog_domains as domains,
    package_original_kind_catalog_experiments_hardware as experiments_hardware,
    package_original_kind_catalog_python_apps_public_cli as python_apps_public_cli,
    package_original_kind_catalog_repository_assets as repository_assets,
    package_original_kind_catalog_retained as retained,
    package_original_kind_catalog_runtime as runtime,
    package_original_kind_catalog_scripts_examples as scripts_examples,
    package_original_kind_catalog_tests_normative as tests_normative,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    OriginalKindProfile,
    seal_profile,
    validate_full_closure,
    validate_profile,
)
from verifier.runtime.package_original_kind_review import (
    apply_original_kind_profile,
    audit_closed_effects,
    closed_effect_audit_document,
)


FULL_PROFILE_ID = "verifier-package-original-kind-full-closure"
FULL_PROFILE_REVISION = 1
FULL_PROFILE_BOUNDARY = (
    "Exact current Verifier package applicability over all original non-OBJECT "
    "kinds. This is Tier-0 classification evidence only; it does not execute "
    "mechanisms or establish Polish tiers 1 through 3."
)
ORIGINAL_KIND_QUESTION_DENOMINATOR = (
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR * len(ORIGINAL_NON_OBJECT_KINDS)
)


_PARALLEL_AUDIT_THRESHOLD = 128
_MAX_AUDIT_WORKERS = 8


def _catalog_audit_task(
    task: tuple[str, tuple[str, ...], dict[str, str]],
) -> dict[str, Any]:
    """Run one exact closed-effect audit and retain its prior error boundary."""
    root, paths, expected = task
    try:
        return {
            "audit": closed_effect_audit_document(
                audit_closed_effects(
                    root,
                    paths,
                    expected_source_digests=expected,
                )
            ),
            "error_type": None,
            "error": None,
        }
    except Exception as error:
        return {
            "audit": None,
            "error_type": type(error).__name__,
            "error": str(error),
        }


def _catalog_audit_results(
    tasks: list[tuple[str, tuple[str, ...], dict[str, str]]],
) -> list[dict[str, Any]]:
    workers = min(_MAX_AUDIT_WORKERS, os.cpu_count() or 1, len(tasks))
    if len(tasks) < _PARALLEL_AUDIT_THRESHOLD or workers == 1:
        return [_catalog_audit_task(task) for task in tasks]
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=multiprocessing.get_context("spawn"),
    ) as executor:
        return list(executor.map(_catalog_audit_task, tasks, chunksize=4))


_CATALOGS: tuple[tuple[str, Any, OriginalKindProfile], ...] = (
    ("retained", retained, retained.RETAINED_PARTIAL_PROFILE),
    ("runtime", runtime, runtime.RUNTIME_PARTIAL_PROFILE),
    ("domains", domains, domains.DOMAIN_ORIGINAL_KIND_PROFILE),
    (
        "experiments_hardware",
        experiments_hardware,
        experiments_hardware.EXPERIMENTS_HARDWARE_PARTIAL_PROFILE,
    ),
    (
        "python_apps_public_cli",
        python_apps_public_cli,
        python_apps_public_cli.PARTIAL_PROFILE,
    ),
    (
        "repository_assets",
        repository_assets,
        repository_assets.REPOSITORY_ASSET_PARTIAL_PROFILE,
    ),
    (
        "scripts_examples",
        scripts_examples,
        scripts_examples.SCRIPT_EXAMPLE_PARTIAL_PROFILE,
    ),
    ("tests_normative", tests_normative, tests_normative.PARTIAL_PROFILE),
)
_CANONICAL_CATALOG_NAMES = tuple(name for name, _module, _profile in _CATALOGS)


_EVIDENCE_SCHEMA = "verifier-package-original-kind-catalog-evidence-1"
_EVIDENCE_CLAIM_BOUNDARY = (
    "Closed-effect status is supporting source evidence only. CLOSED never "
    "assigns an original kind or proves DOES_NOT_APPLY; UNKNOWN preserves "
    "unsupported assets, import escapes, dynamic execution, callbacks, and "
    "other unclosed effects without exempting any applicability question."
)
_SOURCE_BINDING_BLOCKERS = (
    "EXPECTED_SOURCE_DENOMINATOR_DIFFERS",
    "SOURCE_DIGEST_DIFFERS:",
    "SOURCE_UNAVAILABLE:",
    "SOURCE_CHANGED_DURING_AUDIT:",
)
_SOURCE_VALIDATOR_CATALOGS = frozenset({
    "runtime",
    "experiments_hardware",
    "python_apps_public_cli",
    "repository_assets",
    "scripts_examples",
    "tests_normative",
})
# Execution order is dependency order: behavioral bytes, then declared-source
# bytes, then the composite runtime review.  This mirrors the order that
# ``validate_runtime_review`` applies internally.
_EXTRA_VALIDATOR_NAMES = {
    "runtime": (
        "validate_behavioral_evidence",
        "validate_declared_source_bytes",
        "validate_runtime_review",
    ),
    "python_apps_public_cli": ("validate_owned_source_bytes",),
}
_DELEGATED_VALIDATOR_NAMES = {
    # validate_source_partition calls this once for every exact source row.
    "python_apps_public_cli": frozenset({"validate_audit_row"}),
}
_EFFECTIVE_REVIEW_ERROR = "PACKAGE_ORIGINAL_KIND_CATALOG_EFFECTIVE_REVIEW_INVALID:"
_OVERLAY_UNBOUND_ERROR = "PACKAGE_ORIGINAL_KIND_CATALOG_OVERLAY_UNBOUND:"
_OVERLAY_REASON_PREFIX = "Behavior overlay "
_VALIDATED_REVIEW_HOOKS = {
    # The runtime component's plain review validates semantic coordinates, but
    # only this hook binds behavioral claims to the current source bytes.
    "runtime": "validate_runtime_review",
}
_VALIDATED_ROOT_REQUIRED = (
    "PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_ROOT_REQUIRED"
)
# Counted beside a refused DOES_NOT_APPLY whose validated cell is still UNRESOLVED,
# so the report shows that the validated view could not be exempted by a manifest.
_VALIDATED_UNRESOLVED_BLOCKER = "VALIDATED_UNRESOLVED"
# Denominator-level refusals of a manifest DOES_NOT_APPLY.  Each keeps its cell
# UNRESOLVED and reports the exact cause here; the cell reason itself stays one
# of the decision-binding codes that the manifest gate already renders.
_DOES_NOT_APPLY_BLOCKER_ACTIONS = {
    "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE": (
        "Cite every owned file of this object, each once with its current "
        "sha256, in one DOES_NOT_APPLY refutation; until then the cell stays "
        "UNRESOLVED."
    ),
    "DOES_NOT_APPLY_EVIDENCE_PATH_DUPLICATED": (
        "List each owned file of this object exactly once in the refutation's "
        "evidence."
    ),
    "DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN": (
        "Restore this object's validated owned-file set and its current source "
        "census, then rerun this gate."
    ),
    "DOES_NOT_APPLY_SOURCE_DRIFT": (
        "Re-audit the owned files at their current bytes, record their fresh "
        "digests, and rerun from a quiescent tree."
    ),
    "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED": (
        "Close the named effect boundary (dynamic execution, unsupported "
        "language, callbacks, or unresolved imports) in the owned source, or "
        "keep this cell UNRESOLVED."
    ),
}


def _canonical_value(value: Any) -> Any:
    """Reduce validator output to deterministic JSON without provider types."""
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        selected = [_canonical_value(item) for item in value]
        return sorted(
            selected,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ),
        )
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _canonical_value(getattr(value, field.name))
            for field in dataclass_fields(value)
        }
    namespace = getattr(value, "__dict__", None)
    if type(namespace) is dict:
        return {
            name: _canonical_value(item)
            for name, item in sorted(namespace.items())
            if not name.startswith("_")
        }
    return {"type": type(value).__qualname__, "value": str(value)}


def _value_digest(value: Any) -> str:
    raw = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


def _json_value_digest(value: Any) -> str:
    """Hash an already-canonical JSON tree without recursively copying it."""
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


def _validator_success(name: str, result: Any) -> dict[str, Any]:
    try:
        count = len(result)
    except TypeError:
        count = 0 if result is None else 1
    return {
        "name": name,
        "status": "PASS",
        "result_count": count,
        "result_digest": _value_digest(result),
    }


def _validator_failure(
    catalog_name: str,
    name: str,
    error: Exception,
) -> tuple[dict[str, Any], str]:
    diagnostic = (
        "VALIDATOR_FAILED:"
        + catalog_name
        + ":"
        + name
        + ":"
        + type(error).__name__
        + ":"
        + str(error)
    )
    return (
        {
            "name": name,
            "status": "FAIL",
            "diagnostic": diagnostic,
        },
        diagnostic,
    )


def _validator_missing(
    catalog_name: str,
    name: str,
) -> tuple[dict[str, Any], str]:
    diagnostic = "VALIDATOR_MISSING:" + catalog_name + ":" + name
    return (
        {
            "name": name,
            "status": "MISSING",
            "diagnostic": diagnostic,
        },
        diagnostic,
    )


def _source_partition_validator(
    catalog_name: str,
    module: Any,
    root: Path,
) -> tuple[dict[str, Any], tuple[Any, ...], str | None]:
    """Run a partition's declaration validator and retain its exact rows."""
    current = getattr(module, "current_source_partition", None)
    validator = getattr(module, "validate_source_partition", None)
    if not callable(current):
        record, blocker = _validator_missing(
            catalog_name, "current_source_partition"
        )
        record["name"] = "validate_source_partition"
        return record, (), blocker
    if not callable(validator):
        record, blocker = _validator_missing(
            catalog_name, "validate_source_partition"
        )
        return record, (), blocker
    try:
        source_rows = tuple(current())
    except Exception as error:
        record, blocker = _validator_failure(
            catalog_name, "current_source_partition", error
        )
        record["name"] = "validate_source_partition"
        return record, (), blocker
    try:
        if catalog_name == "scripts_examples":
            result = validator(source_rows, root=root)
        else:
            result = validator(source_rows)
        return _validator_success("validate_source_partition", result), source_rows, None
    except Exception as error:
        record, blocker = _validator_failure(
            catalog_name, "validate_source_partition", error
        )
        return record, (), blocker


def _extra_partition_validators(
    catalog_name: str,
    module: Any,
    root: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Invoke every feature-near byte/evidence validator known to the boundary."""
    records: list[dict[str, Any]] = []
    blockers: list[str] = []
    expected: tuple[tuple[str, Any], ...]
    if catalog_name == "runtime":
        expected = (
            ("validate_behavioral_evidence", (root,)),
            ("validate_declared_source_bytes", (root,)),
            ("validate_runtime_review", (root,)),
        )
    elif catalog_name == "python_apps_public_cli":
        # Its aggregate source validator already calls ``validate_audit_row``
        # once for every exact source row; the byte validator is the separate
        # capability that must not be treated as optional here.
        expected = (("validate_owned_source_bytes", (),),)
    elif catalog_name == "domains":
        snapshot = getattr(module, "_source_snapshot", None)
        audits = getattr(module, "DOMAIN_ORIGINAL_KIND_AUDITS", None)
        if not callable(snapshot):
            record, blocker = _validator_missing(catalog_name, "_source_snapshot")
            return [record], [blocker]
        if audits is None:
            record, blocker = _validator_missing(
                catalog_name, "DOMAIN_ORIGINAL_KIND_AUDITS"
            )
            return [record], [blocker]
        try:
            result = tuple(
                (audit.object_id, snapshot(root, audit))
                for audit in sorted(tuple(audits), key=lambda row: row.object_id)
            )
            return [_validator_success("_source_snapshot", result)], []
        except Exception as error:
            record, blocker = _validator_failure(
                catalog_name, "_source_snapshot", error
            )
            return [record], [blocker]
    else:
        expected = ()
    for name, positional in expected:
        validator = getattr(module, name, None)
        if not callable(validator):
            record, blocker = _validator_missing(catalog_name, name)
            records.append(record)
            blockers.append(blocker)
            continue
        try:
            if name == "validate_owned_source_bytes":
                result = validator(root=root)
            else:
                result = validator(*positional)
            records.append(_validator_success(name, result))
        except Exception as error:
            record, blocker = _validator_failure(catalog_name, name, error)
            records.append(record)
            blockers.append(blocker)
    return records, blockers


def _partition_requires_source_validator(catalog_name: str) -> bool:
    return catalog_name in _SOURCE_VALIDATOR_CATALOGS


def _unplanned_validator_names(catalog_name: str, module: Any) -> tuple[str, ...]:
    """Reject a newly added source validator until the boundary invokes it."""
    module_name = getattr(module, "__name__", None)
    if type(module_name) is not str:
        return ()
    available = {
        name
        for name in dir(module)
        if name.startswith("validate_")
        and callable(getattr(module, name))
        and getattr(getattr(module, name), "__module__", None) == module_name
    }
    planned = set(_EXTRA_VALIDATOR_NAMES.get(catalog_name, ()))
    planned.update(_DELEGATED_VALIDATOR_NAMES.get(catalog_name, ()))
    if _partition_requires_source_validator(catalog_name):
        planned.add("validate_source_partition")
    return tuple(sorted(available - planned))


def _unbound_planned_validator_names(catalog_name: str, module: Any) -> tuple[str, ...]:
    """Reject a planned validator that was removed, renamed, or substituted.

    A planned name must resolve to a callable owned by the partition's own
    module.  A foreign callable, such as a test double or a forged success
    function, fails here even though it is callable.  Synthetic namespaces have
    no module identity, so they are judged only by the execution records.
    """
    module_name = getattr(module, "__name__", None)
    if type(module_name) is not str:
        return ()
    return tuple(
        name
        for name in _EXTRA_VALIDATOR_NAMES.get(catalog_name, ())
        if not (
            callable(getattr(module, name, None))
            and getattr(getattr(module, name), "__module__", None) == module_name
        )
    )


def _owned_paths(
    catalog_name: str,
    object_id: str,
    row: Mapping[str, Any],
    source_rows: Mapping[str, Any],
) -> tuple[str, ...]:
    selected = row.get("expected_owned_paths")
    if selected is None:
        source = source_rows.get(object_id)
        selected = getattr(source, "owned_paths", None)
    if not isinstance(selected, (tuple, list)) or any(
        type(path) is not str for path in selected
    ):
        raise ValueError(
            "OWNED_PATHS_UNAVAILABLE:" + catalog_name + ":" + object_id
        )
    paths = tuple(sorted(selected))
    if not paths or len(paths) != len(set(paths)):
        raise ValueError("OWNED_PATHS_INVALID:" + catalog_name + ":" + object_id)
    return paths


def _effect_source_binding_blockers(
    catalog_name: str,
    object_id: str,
    audit: Mapping[str, Any],
) -> list[str]:
    return [
        "SOURCE_BINDING_INVALID:"
        + catalog_name
        + ":"
        + object_id
        + ":"
        + blocker
        for blocker in audit["blockers"]
        if any(blocker.startswith(prefix) for prefix in _SOURCE_BINDING_BLOCKERS)
    ]


def catalog_evidence_report(
    root: str | Path,
    files: Mapping[str, str],
) -> dict[str, Any]:
    """Validate every catalog evidence hook and audit exact owned source effects.

    Effect closure is evidence, never a decision engine.  In particular, this
    report does not translate CLOSED into DOES_NOT_APPLY or UNKNOWN into an
    exemption.  Source-byte drift and unavailable required validators fail the
    report; static effect uncertainty remains explicitly visible to reviewers.
    """
    selected_root = Path(root).resolve(strict=True)
    if type(files) is not dict or any(
        type(path) is not str or type(digest) is not str
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_CATALOG_FILES_INVALID")

    partitions: list[dict[str, Any]] = []
    object_slots: list[dict[str, Any] | None] = []
    blockers: list[str] = []
    object_owners: dict[str, str] = {}
    owned_path_universe: set[str] = set()
    effect_counts = {"CLOSED": 0, "UNKNOWN": 0}
    audit_indexes: dict[
        tuple[tuple[str, ...], tuple[tuple[str, str], ...]], int
    ] = {}
    audit_tasks: list[tuple[str, tuple[str, ...], dict[str, str]]] = []
    pending_audits: list[
        tuple[int, int, str, str, tuple[str, ...], list[str]]
    ] = []

    for catalog_name, module, _profile in _CATALOGS:
        partition_blockers: list[str] = []
        validators: list[dict[str, Any]] = []
        source_sequence: tuple[Any, ...] = ()
        if catalog_name not in _CANONICAL_CATALOG_NAMES:
            partition_blockers.append(
                "VALIDATOR_PLAN_MISSING:" + catalog_name
            )
        partition_blockers.extend(
            "VALIDATOR_PLAN_MISSING:" + catalog_name + ":" + name
            for name in _unplanned_validator_names(catalog_name, module)
        )
        partition_blockers.extend(
            "VALIDATOR_PLAN_UNBOUND:" + catalog_name + ":" + name
            for name in _unbound_planned_validator_names(catalog_name, module)
        )
        if _partition_requires_source_validator(catalog_name):
            validator, source_sequence, blocker = _source_partition_validator(
                catalog_name, module, selected_root
            )
            validators.append(validator)
            if blocker is not None:
                partition_blockers.append(blocker)
        extra_records, extra_blockers = _extra_partition_validators(
            catalog_name, module, selected_root
        )
        validators.extend(extra_records)
        partition_blockers.extend(extra_blockers)
        executed = {record["name"] for record in validators}
        partition_blockers.extend(
            "VALIDATOR_PLAN_UNEXECUTED:" + catalog_name + ":" + name
            for name in _EXTRA_VALIDATOR_NAMES.get(catalog_name, ())
            if name not in executed
        )

        document_hook = getattr(module, "review_document", None)
        if not callable(document_hook):
            partition_blockers.append(
                "REVIEW_DOCUMENT_MISSING:" + catalog_name
            )
            document: Mapping[str, Any] = {}
        else:
            try:
                candidate = document_hook()
                if type(candidate) is not dict:
                    raise ValueError("DOCUMENT_INVALID")
                document = candidate
            except Exception as error:
                partition_blockers.append(
                    "REVIEW_DOCUMENT_FAILED:"
                    + catalog_name
                    + ":"
                    + type(error).__name__
                    + ":"
                    + str(error)
                )
                document = {}

        source_by_id = {
            spec.object_id: spec
            for spec in source_sequence
            if type(getattr(spec, "object_id", None)) is str
        }
        for object_id in sorted(document):
            row = document[object_id]
            try:
                if type(object_id) is not str or type(row) is not dict:
                    raise ValueError(
                        "REVIEW_ROW_INVALID:" + catalog_name + ":" + str(object_id)
                    )
                previous = object_owners.get(object_id)
                if previous is not None:
                    raise ValueError(
                        "REVIEW_OBJECT_OVERLAP:"
                        + object_id
                        + ":"
                        + previous
                        + ":"
                        + catalog_name
                    )
                object_owners[object_id] = catalog_name
                paths = _owned_paths(catalog_name, object_id, row, source_by_id)
                owned_path_universe.update(paths)
                expected = {path: files.get(path, "") for path in paths}
                cache_key = (paths, tuple(sorted(expected.items())))
                audit_index = audit_indexes.get(cache_key)
                if audit_index is None:
                    audit_index = len(audit_tasks)
                    audit_indexes[cache_key] = audit_index
                    audit_tasks.append((str(selected_root), paths, expected))
                slot = len(object_slots)
                object_slots.append(None)
                pending_audits.append((
                    slot,
                    audit_index,
                    catalog_name,
                    object_id,
                    paths,
                    partition_blockers,
                ))
            except Exception as error:
                diagnostic = (
                    "EFFECT_AUDIT_FAILED:"
                    + catalog_name
                    + ":"
                    + str(object_id)
                    + ":"
                    + type(error).__name__
                    + ":"
                    + str(error)
                )
                partition_blockers.append(diagnostic)
                effect_counts["UNKNOWN"] += 1
                object_slots.append(
                    {
                        "catalog": catalog_name,
                        "object_id": str(object_id),
                        "expected_owned_paths": [],
                        "source_binding_status": "FAIL",
                        "closed_effect_audit": {
                            "status": "UNKNOWN",
                            "blockers": [diagnostic],
                            "evidence_digest": _value_digest([diagnostic]),
                        },
                    }
                )

        partitions.append(
            {
                "catalog": catalog_name,
                "status": "PENDING",
                "object_count": len(document),
                "validators": validators,
                "blockers": partition_blockers,
            }
        )

    audit_results = _catalog_audit_results(audit_tasks)
    for (
        slot,
        audit_index,
        catalog_name,
        object_id,
        paths,
        partition_blockers,
    ) in pending_audits:
        result = audit_results[audit_index]
        audit_document = result["audit"]
        if audit_document is None:
            diagnostic = (
                "EFFECT_AUDIT_FAILED:"
                + catalog_name
                + ":"
                + object_id
                + ":"
                + result["error_type"]
                + ":"
                + result["error"]
            )
            partition_blockers.append(diagnostic)
            effect_counts["UNKNOWN"] += 1
            object_slots[slot] = {
                "catalog": catalog_name,
                "object_id": object_id,
                "expected_owned_paths": [],
                "source_binding_status": "FAIL",
                "closed_effect_audit": {
                    "status": "UNKNOWN",
                    "blockers": [diagnostic],
                    "evidence_digest": _value_digest([diagnostic]),
                },
            }
            continue
        effect_counts[audit_document["status"]] += 1
        binding_blockers = _effect_source_binding_blockers(
            catalog_name, object_id, audit_document
        )
        partition_blockers.extend(binding_blockers)
        object_slots[slot] = {
            "catalog": catalog_name,
            "object_id": object_id,
            "expected_owned_paths": list(paths),
            "source_binding_status": "FAIL" if binding_blockers else "PASS",
            "closed_effect_audit": audit_document,
        }

    objects = [row for row in object_slots if row is not None]
    if len(objects) != len(object_slots):
        raise ValueError("PACKAGE_ORIGINAL_KIND_AUDIT_RESULT_MISSING")
    for partition in partitions:
        partition["status"] = "FAIL" if partition["blockers"] else "PASS"
        blockers.extend(partition["blockers"])

    selected_names = tuple(name for name, _module, _profile in _CATALOGS)
    if selected_names == _CANONICAL_CATALOG_NAMES and len(object_owners) != (
        VERIFIER_PACKAGE_OBJECT_DENOMINATOR
    ):
        blockers.append(
            "OBJECT_DENOMINATOR_DIFFERS:" + str(len(object_owners))
        )

    # A package report can take longer than one object audit. Re-sample the
    # complete owned-path union at return time so a receipt cannot straddle a
    # source edit that happened after an earlier per-object closing snapshot.
    closing_sources: list[dict[str, str]] = []
    for path in sorted(owned_path_universe):
        try:
            target = (selected_root / path).resolve(strict=True)
            target.relative_to(selected_root)
            if not target.is_file():
                raise ValueError(path)
            digest = "sha256:" + sha256(target.read_bytes()).hexdigest()
        except (OSError, ValueError):
            blockers.append("CATALOG_SOURCE_CLOSING_UNAVAILABLE:" + path)
            continue
        closing_sources.append({"path": path, "sha256": digest})
        if files.get(path) != digest:
            blockers.append("CATALOG_SOURCE_CLOSING_DIFFERS:" + path)

    body = {
        "schema_version": _EVIDENCE_SCHEMA,
        "status": "FAIL" if blockers else "PASS",
        "partition_count": len(partitions),
        "object_count": len(objects),
        "closed_effect_status_counts": effect_counts,
        "partitions": partitions,
        "objects": objects,
        "closing_source_set_digest": _json_value_digest(closing_sources),
        "blockers": blockers,
        "claim_boundary": _EVIDENCE_CLAIM_BOUNDARY,
    }
    return {**body, "receipt_digest": _json_value_digest(body)}


def validate_catalog_evidence(
    root: str | Path,
    files: Mapping[str, str],
) -> dict[str, Any]:
    """Return the sealed report or reject before profile application begins."""
    report = catalog_evidence_report(root, files)
    if report["status"] != "PASS":
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:"
            + report["blockers"][0]
        )
    return report


def partial_profiles() -> tuple[OriginalKindProfile, ...]:
    """Return validated, object-disjoint profiles in deterministic order.

    The human review rows add feature-near scope to some source decision
    reasons.  The sealed decision's exact reason must therefore be preserved
    as a literal part of that fuller explanation, rather than requiring both
    representations to be byte-identical.
    """
    profiles: list[OriginalKindProfile] = []
    owners: dict[str, str] = {}
    for catalog_name, module, profile in _CATALOGS:
        selected = validate_profile(profile)
        document = module.review_document()
        for assignment in selected.assignments:
            previous = owners.setdefault(assignment.object_id, catalog_name)
            if previous != catalog_name:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_CATALOG_PROFILE_OVERLAP:"
                    + assignment.object_id
                    + ":"
                    + previous
                    + ":"
                    + catalog_name
                )
            row = document.get(assignment.object_id)
            if type(row) is not dict or type(row.get("questions")) is not dict:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_CATALOG_PROFILE_ROW_MISSING:"
                    + assignment.object_id
                )
            decided = {
                kind: decision
                for kind, decision in row["questions"].items()
                if decision.get("status") != "UNRESOLVED"
            }
            profile_decisions = {
                decision.kind: decision for decision in assignment.decisions
            }
            if set(decided) != set(profile_decisions):
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_CATALOG_PROFILE_DECISIONS_DIFFER:"
                    + assignment.object_id
                )
            for kind, decision in profile_decisions.items():
                documented = decided[kind]
                if (
                    documented.get("status") != decision.status
                    or decision.reason not in documented.get("reason", "")
                ):
                    raise ValueError(
                        "PACKAGE_ORIGINAL_KIND_CATALOG_PROFILE_DECISION_DIFFERS:"
                        + assignment.object_id
                        + ":"
                        + kind
                    )
        profiles.append(selected)
    return tuple(profiles)


def _overlay_reason(
    catalog_name: str,
    object_id: str,
    entry: Mapping[str, Any] | None,
    kind: str,
    status: str,
) -> str:
    """Return the overlay's own text for one cell; no cell is decided without it."""
    if entry is not None:
        if status == APPLIES:
            for applied_kind, reason, _cites in entry["applies"]:
                if applied_kind == kind:
                    return _OVERLAY_REASON_PREFIX + "APPLIES: " + reason
        elif kind in entry["dne"]:
            return (
                _OVERLAY_REASON_PREFIX
                + "DOES_NOT_APPLY: "
                + entry["auditor_closure"]
            )
    raise ValueError(
        _EFFECTIVE_REVIEW_ERROR
        + catalog_name
        + ":UNSUPPORTED:"
        + object_id
        + ":"
        + kind
    )


def _effective_cell_view(
    catalog_name: str,
    module: Any,
    document: Mapping[str, Any],
    *,
    source_validated: bool = False,
) -> dict[str, Any]:
    """Overlay a component's effective review onto its exact source rows.

    The component's own ``effective_review_document`` is the only route to
    overlay decisions.  Source decisions are never overridden, the overlay may
    decide only cells the source left UNRESOLVED, and each decided cell must
    carry the overlay's own reason.  Any failure raises; nothing falls back to
    a weaker view.
    """
    hook = getattr(module, "effective_review_document", None)
    if not callable(hook):
        return dict(document)
    if not source_validated:
        current = getattr(module, "current_source_partition", None)
        validator = getattr(module, "validate_source_partition", None)
        if not callable(current) or not callable(validator):
            raise ValueError(
                _EFFECTIVE_REVIEW_ERROR
                + catalog_name
                + ":SOURCE_VALIDATOR_MISSING"
            )
        try:
            validator(tuple(current()))
        except Exception as error:
            raise ValueError(
                _EFFECTIVE_REVIEW_ERROR
                + catalog_name
                + ":SOURCE_VALIDATOR:"
                + type(error).__name__
                + ":"
                + str(error)
            ) from error
    overlay = getattr(module, "BEHAVIOR_OVERLAY", None)
    try:
        effective = hook()
    except Exception as error:
        raise ValueError(
            _EFFECTIVE_REVIEW_ERROR
            + catalog_name
            + ":"
            + type(error).__name__
            + ":"
            + str(error)
        ) from error
    if type(effective) is not dict or set(effective) != set(document):
        raise ValueError(
            _EFFECTIVE_REVIEW_ERROR + catalog_name + ":OBJECT_DENOMINATOR"
        )
    selected: dict[str, Any] = {}
    for object_id, row in document.items():
        questions = row.get("questions") if type(row) is dict else None
        view = effective[object_id]
        if (
            type(questions) is not dict
            or type(view) is not dict
            or set(view) != set(questions)
        ):
            raise ValueError(
                _EFFECTIVE_REVIEW_ERROR + catalog_name + ":KINDS:" + object_id
            )
        entry = overlay.get(object_id) if isinstance(overlay, Mapping) else None
        decided: dict[str, Any] = {}
        for kind, decision in questions.items():
            status = view[kind]
            source_status = decision.get("status") if type(decision) is dict else None
            if status not in {APPLIES, DOES_NOT_APPLY, "UNRESOLVED"}:
                raise ValueError(
                    _EFFECTIVE_REVIEW_ERROR
                    + catalog_name
                    + ":STATUS:"
                    + object_id
                    + ":"
                    + kind
                )
            if source_status not in {APPLIES, DOES_NOT_APPLY, "UNRESOLVED"}:
                raise ValueError(
                    _EFFECTIVE_REVIEW_ERROR
                    + catalog_name
                    + ":SOURCE:"
                    + object_id
                    + ":"
                    + kind
                )
            if source_status != "UNRESOLVED":
                if status != source_status:
                    raise ValueError(
                        _EFFECTIVE_REVIEW_ERROR
                        + catalog_name
                        + ":SOURCE_OVERRIDDEN:"
                        + object_id
                        + ":"
                        + kind
                    )
                decided[kind] = decision
            elif status == "UNRESOLVED":
                decided[kind] = decision
            else:
                decided[kind] = {
                    "status": status,
                    "reason": _overlay_reason(
                        catalog_name, object_id, entry, kind, status
                    ),
                }
        selected[object_id] = {**row, "questions": decided}
    return selected


def _compose_review_documents(
    documents: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate and compose already-selected component documents exactly once."""

    result: dict[str, dict[str, Any]] = {}
    for catalog_name, _module, _profile in _CATALOGS:
        document = documents.get(catalog_name)
        if type(document) is not dict:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_CATALOG_DOCUMENT_INVALID:" + catalog_name
            )
        for object_id, row in document.items():
            if type(object_id) is not str or type(row) is not dict:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_CATALOG_ROW_INVALID:" + catalog_name
                )
            if object_id in result:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_OVERLAP:" + object_id
                )
            questions = row.get("questions")
            if type(questions) is not dict or tuple(questions) != tuple(
                ORIGINAL_NON_OBJECT_KINDS
            ):
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_CATALOG_QUESTION_DENOMINATOR_DIFFERS:"
                    + object_id
                )
            for kind, decision in questions.items():
                if (
                    type(decision) is not dict
                    or decision.get("status")
                    not in {APPLIES, DOES_NOT_APPLY, "UNRESOLVED"}
                    or type(decision.get("reason")) is not str
                    or not decision["reason"].strip()
                ):
                    raise ValueError(
                        "PACKAGE_ORIGINAL_KIND_CATALOG_DECISION_INVALID:"
                        + object_id
                        + ":"
                        + kind
                    )
            selected = dict(row)
            selected["catalog"] = catalog_name
            result[object_id] = selected
    if len(result) != VERIFIER_PACKAGE_OBJECT_DENOMINATOR:
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_DIFFERS:"
            + str(len(result))
        )
    return result


def _validated_component_document(
    catalog_name: str,
    module: Any,
    root: Path,
) -> dict[str, Any]:
    """Return one component only through its strongest declared review route."""

    source_validated = False
    if _partition_requires_source_validator(catalog_name):
        record, _source_rows, blocker = _source_partition_validator(
            catalog_name, module, root
        )
        if blocker is not None:
            raise ValueError(blocker)
        if record["status"] != "PASS":
            raise ValueError(
                "VALIDATOR_FAILED:"
                + catalog_name
                + ":validate_source_partition"
            )
        source_validated = True

    selected_hook = _VALIDATED_REVIEW_HOOKS.get(catalog_name)
    if selected_hook is None:
        hook = getattr(module, "review_document", None)
        hook_name = "review_document"
        positional: tuple[Any, ...] = ()
    else:
        hook = getattr(module, selected_hook, None)
        hook_name = selected_hook
        positional = (root,)
    if not callable(hook):
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_REVIEW_MISSING:"
            + catalog_name
            + ":"
            + hook_name
        )
    try:
        candidate = hook(*positional)
    except Exception as error:
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_REVIEW_FAILED:"
            + catalog_name
            + ":"
            + hook_name
            + ":"
            + type(error).__name__
            + ":"
            + str(error)
        ) from error
    if type(candidate) is not dict:
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_REVIEW_INVALID:"
            + catalog_name
            + ":"
            + hook_name
        )
    return _effective_cell_view(
        catalog_name,
        module,
        candidate,
        source_validated=source_validated,
    )


def _validate_document_source_inventory(
    root: Path,
    files: Mapping[str, str],
    document: Mapping[str, Mapping[str, Any]],
) -> None:
    """Close the validated view against the same inventory used by admission."""

    paths: set[str] = set()
    for row in document.values():
        selected = row.get("expected_owned_paths")
        if not isinstance(selected, (tuple, list)) or any(
            type(path) is not str for path in selected
        ):
            raise ValueError("PACKAGE_ORIGINAL_KIND_CATALOG_OWNED_PATHS_INVALID")
        paths.update(selected)
    for path in sorted(paths):
        expected = files.get(path)
        if type(expected) is not str or _SHA256_TEXT.fullmatch(expected) is None:
            raise ValueError("SOURCE_DIGEST_INVALID:" + path)
        try:
            target = (root / path).resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise ValueError(path)
            observed = "sha256:" + sha256(target.read_bytes()).hexdigest()
        except (OSError, ValueError) as error:
            raise ValueError("SOURCE_UNAVAILABLE:" + path) from error
        if observed != expected:
            raise ValueError("SOURCE_DIGEST_DIFFERS:" + path)


def _overlay_decided_cells() -> tuple[tuple[str, str], ...]:
    """Return every cell the behavior overlay decides beyond the source rows."""
    cells: list[tuple[str, str]] = []
    for catalog_name, module, _profile in _CATALOGS:
        source = module.review_document()
        effective = _effective_cell_view(catalog_name, module, source)
        for object_id in sorted(source):
            for kind, decision in source[object_id]["questions"].items():
                if (
                    decision["status"] == "UNRESOLVED"
                    and effective[object_id]["questions"][kind]["status"]
                    != "UNRESOLVED"
                ):
                    cells.append((object_id, kind))
    return tuple(cells)


def review_document() -> dict[str, dict[str, Any]]:
    """Return the semantic 468-by-25 audit for inspection, not admission.

    Each component contributes its effective review where one exists, so
    overlay-decided cells appear with the overlay's reason.  Source decisions
    are preserved exactly, and any effective-view failure raises.  This
    rootless view cannot validate behavior evidence bytes; admission must use
    :func:`validated_review_document`.
    """
    documents: dict[str, dict[str, Any]] = {}
    for catalog_name, module, _profile in _CATALOGS:
        document = module.review_document()
        if type(document) is not dict:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_CATALOG_DOCUMENT_INVALID:" + catalog_name
            )
        documents[catalog_name] = _effective_cell_view(
            catalog_name, module, document
        )
    return _compose_review_documents(documents)


def validated_review_document(
    root: str | Path,
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Return the aggregate only after every component and source byte binds.

    The evidence preflight rejects missing or failing component validators and
    stale opening bytes.  Each component is then read through its strongest
    declared review API (for example ``validate_runtime_review`` or an
    effective overlay after source-partition validation).  A final byte pass
    over the exact owned-path union prevents mid-flight mutation from exposing
    a partially validated decision set.
    """

    selected_root = Path(root).resolve(strict=True)
    if type(files) is not dict or any(
        type(path) is not str or type(digest) is not str
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_CATALOG_FILES_INVALID")
    validate_catalog_evidence(selected_root, files)
    documents = {
        catalog_name: _validated_component_document(
            catalog_name, module, selected_root
        )
        for catalog_name, module, _profile in _CATALOGS
    }
    selected = _compose_review_documents(documents)
    _validate_document_source_inventory(selected_root, files, selected)
    return selected


def unresolved_questions() -> dict[str, tuple[str, ...]]:
    """Expose every unanswered applicability question; omission is impossible."""
    return {
        object_id: tuple(
            kind
            for kind, decision in row["questions"].items()
            if decision["status"] == "UNRESOLVED"
        )
        for object_id, row in review_document().items()
        if any(
            decision["status"] == "UNRESOLVED"
            for decision in row["questions"].values()
        )
    }


def unresolved_cells() -> tuple[tuple[str, str], ...]:
    """Return each unresolved cell as one exact object/kind coordinate."""
    return tuple(
        (object_id, kind)
        for object_id, kinds in unresolved_questions().items()
        for kind in kinds
    )


def full_closure_profile() -> OriginalKindProfile:
    """Seal one full profile only after every ORIGINAL_KIND_QUESTION_DENOMINATOR question is decided.

    Overlay decisions are reviewable but cannot seal closure here.  This path
    takes no root and performs no byte recapture of the overlay's evidence set,
    so any overlay-decided cell refuses the seal rather than manufacturing it.
    """
    unresolved = unresolved_cells()
    if unresolved:
        object_id, kind = unresolved[0]
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
            + object_id
            + ":"
            + kind
        )
    overlay_cells = _overlay_decided_cells()
    if overlay_cells:
        object_id, kind = overlay_cells[0]
        raise ValueError(_OVERLAY_UNBOUND_ERROR + object_id + ":" + kind)
    assignments = tuple(
        sorted(
            (
                assignment
                for profile in partial_profiles()
                for assignment in profile.assignments
            ),
            key=lambda row: row.object_id,
        )
    )
    selected = seal_profile(
        FULL_PROFILE_ID,
        FULL_PROFILE_REVISION,
        FULL_PROFILE_BOUNDARY,
        assignments,
    )
    return validate_full_closure(
        selected,
        tuple(sorted(review_document())),
        expected_object_count=VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    )


def apply_partial_profiles(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
    *,
    record_gaps: bool = False,
    documented_retention_keys: frozenset[tuple[str, str]] = frozenset(),
) -> dict[str, dict[str, Any]]:
    """Apply every partition's decided cells as one externally atomic operation.

    ``record_gaps`` selects the receipt-producing policy for all three review gaps
    (an unsupported primary label, paths added after review, a refutation that
    cited applicability supersedes).  Each is recorded, never forgiven; the default
    refuses, as maintainers need.

    Every partition validator and per-object source/effect audit completes
    before the first applicator is called.  A defensive copy then prevents a
    later semantic conflict from mutating the caller's draft.  The domain
    catalog additionally repeats its stricter source-pin checks while applying.
    """
    validate_catalog_evidence(root, files)
    policy = "record" if record_gaps else "refuse"
    selected: Mapping[str, dict[str, Any]] = deepcopy(rows)
    profiles = partial_profiles()
    if len(profiles) != len(_CATALOGS):
        raise ValueError("PACKAGE_ORIGINAL_KIND_CATALOG_PARTITION_COUNT_DIFFERS")
    for (catalog_name, module, expected_profile), profile in zip(
        _CATALOGS, profiles, strict=True
    ):
        if profile is not validate_profile(expected_profile):
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_CATALOG_PROFILE_IDENTITY_DIFFERS:"
                + catalog_name
            )
        if module is domains:
            selected = module.apply_domain_original_kind_profile(
                root, selected, files
            )
            continue
        retention = (
            {"documented_retention_keys": documented_retention_keys}
            if documented_retention_keys
            else {}
        )
        selected = apply_original_kind_profile(
            root,
            selected,
            files,
            profile,
            unestablished_primary=policy,
            unreviewed_paths=policy,
            superseded_refutations=policy,
            **retention,
        )
    return dict(selected)


UNRESOLVED_SAMPLE_LIMIT = 16
_SHA256_TEXT = re.compile(r"sha256:[0-9a-f]{64}")


def _surface_file_paths(row: Any) -> frozenset[str]:
    """Return the object's manifest-declared owned files; malformed means none."""
    surfaces = row.get("surfaces") if isinstance(row, Mapping) else None
    if type(surfaces) is not list:
        return frozenset()
    return frozenset(
        item.removeprefix("file:")
        for item in surfaces
        if type(item) is str and item.startswith("file:")
    )


def _decision_binding_blocker(
    row: Any,
    decision: Any,
    source_inventory: Mapping[str, str] | None,
) -> str | None:
    """Return the first fail-closed reason a decided cell is not byte-bound.

    A decision binds only when every evidence reference names an object-owned
    file that is present in the current source inventory, whose canonical
    sha256 equals the current bytes.  Presence of a nonempty digest is never
    sufficient.
    """
    if (
        not isinstance(decision, Mapping)
        or decision.get("status") not in {APPLIES, DOES_NOT_APPLY}
        or type(decision.get("reason")) is not str
        or not decision["reason"].strip()
        or type(decision.get("evidence")) is not list
        or not decision["evidence"]
    ):
        return "DECISION_UNRESOLVED"
    references = decision["evidence"]
    if any(
        type(reference) is not dict
        or set(reference) != {"path", "sha256"}
        or type(reference["path"]) is not str
        or not reference["path"]
        or type(reference["sha256"]) is not str
        for reference in references
    ):
        return "EVIDENCE_MALFORMED"
    if any(
        _SHA256_TEXT.fullmatch(reference["sha256"]) is None
        for reference in references
    ):
        return "EVIDENCE_DIGEST_MALFORMED"
    if source_inventory is None:
        return "SOURCE_INVENTORY_ABSENT"
    owned = _surface_file_paths(row)
    if any(reference["path"] not in owned for reference in references):
        return "EVIDENCE_PATH_UNOWNED"
    if any(reference["path"] not in source_inventory for reference in references):
        return "EVIDENCE_PATH_NOT_IN_INVENTORY"
    if any(
        source_inventory[reference["path"]] != reference["sha256"]
        for reference in references
    ):
        return "EVIDENCE_DIGEST_STALE"
    return None


def _document_owned_paths(row: Any) -> tuple[str, ...] | None:
    """Return one object's validated owned-file denominator, or None if unknown."""
    selected = row.get("expected_owned_paths") if isinstance(row, Mapping) else None
    if (
        not isinstance(selected, (tuple, list))
        or not selected
        or any(type(path) is not str or not path for path in selected)
        or len(set(selected)) != len(selected)
    ):
        return None
    return tuple(sorted(selected))


def _owned_effect_closure(
    root: str | Path,
    owned_paths: tuple[str, ...],
    source_inventory: Mapping[str, str],
) -> str | None:
    """Re-audit the whole owned set at its current bytes; None means CLOSED.

    The census must name every owned file, and the static effect audit must be
    CLOSED over exactly those bytes.  Source drift and an unclosed effect
    boundary are reported separately so the next action is specific.
    """
    if any(path not in source_inventory for path in owned_paths):
        return "DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN"
    try:
        audit = closed_effect_audit_document(
            audit_closed_effects(
                root,
                owned_paths,
                expected_source_digests={
                    path: source_inventory[path] for path in owned_paths
                },
            )
        )
    except (OSError, ValueError):
        return "DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN"
    if audit["status"] == "CLOSED":
        return None
    if any(
        blocker.startswith(_SOURCE_BINDING_BLOCKERS)
        for blocker in audit["blockers"]
    ):
        return "DOES_NOT_APPLY_SOURCE_DRIFT"
    return "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED"


def _does_not_apply_refusal(
    root: str | Path,
    decision: Mapping[str, Any],
    owned_paths: tuple[str, ...] | None,
    source_inventory: Mapping[str, str],
    closures: dict[tuple[str, ...], str | None],
) -> tuple[str, str | None] | None:
    """Return (cell reason, denominator detail) when a refutation is inadmissible.

    Only a refutation that cites the exact validated owned denominator, each file
    once, over a CLOSED owner/effect audit at current bytes may establish
    DOES_NOT_APPLY.  Partial, duplicated, foreign, or unclosed coverage leaves
    the cell UNRESOLVED; none of it is ever an exemption.
    """
    if owned_paths is None:
        return "DECISION_UNRESOLVED", "DOES_NOT_APPLY_OWNER_CLOSURE_UNKNOWN"
    cited = [reference["path"] for reference in decision["evidence"]]
    if any(path not in owned_paths for path in cited):
        return "EVIDENCE_PATH_UNOWNED", None
    if len(set(cited)) != len(cited):
        return "DECISION_UNRESOLVED", "DOES_NOT_APPLY_EVIDENCE_PATH_DUPLICATED"
    if set(cited) != set(owned_paths):
        return "DECISION_UNRESOLVED", "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE"
    if owned_paths not in closures:
        closures[owned_paths] = _owned_effect_closure(
            root, owned_paths, source_inventory
        )
    closure = closures[owned_paths]
    if closure is None:
        return None
    return "DECISION_UNRESOLVED", closure


def bounded_unresolved_summary(
    unresolved: list[dict[str, str]],
    reasons: list[str],
    details: list[str | None] | None = None,
) -> dict[str, Any]:
    """Summarize an unresolved set without emitting every cell.

    The digest covers the sorted (object, kind, reason) set, so it is independent
    of enumeration order yet changes when any omitted cell changes.  A refused
    DOES_NOT_APPLY keeps its cell reason and adds its exact denominator detail to
    the digest and sample.  The sample is the denominator-ordered prefix, so its
    first entry is the exact focus.
    """
    selected_details = [None] * len(reasons) if details is None else details
    if len(unresolved) != len(reasons) or len(selected_details) != len(reasons):
        raise ValueError("PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED_SUMMARY_INVALID")
    triples = sorted(
        (
            item["object_id"],
            item["kind"],
            reason if detail is None else reason + ":" + detail,
        )
        for item, reason, detail in zip(
            unresolved, reasons, selected_details, strict=True
        )
    )
    sample: list[dict[str, str]] = []
    for item, reason, detail in zip(
        unresolved[:UNRESOLVED_SAMPLE_LIMIT],
        reasons[:UNRESOLVED_SAMPLE_LIMIT],
        selected_details[:UNRESOLVED_SAMPLE_LIMIT],
        strict=True,
    ):
        entry = {**item, "reason": reason}
        if detail is not None:
            entry["denominator_blocker"] = detail
            entry["next_action"] = _DOES_NOT_APPLY_BLOCKER_ACTIONS[detail]
        sample.append(entry)
    return {
        "unresolved_digest": _value_digest(triples),
        "unresolved_reason_counts": dict(sorted(Counter(reasons).items())),
        "unresolved_sample": sample,
        "unresolved_sample_limit": UNRESOLVED_SAMPLE_LIMIT,
        "unresolved_truncated": len(unresolved) > UNRESOLVED_SAMPLE_LIMIT,
    }


def _unknown_admission_closure(
    diagnostic: str,
    *,
    focus: Mapping[str, str] | None,
) -> dict[str, Any]:
    """Return a bounded all-UNKNOWN denominator without consulting weak review.

    Missing source authority and denominator disagreement prevent any cell from
    being admitted.  The report retains one exact retry focus and a digest of
    the reason, but deliberately does not materialize every duplicate row.
    """

    selected_focus = dict(focus) if focus is not None else None
    sample = (
        []
        if selected_focus is None
        else [{**selected_focus, "reason": diagnostic}]
    )
    return {
        "status": "UNKNOWN",
        "question_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
        "decided_count": 0,
        "unresolved_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
        "unresolved": [],
        "next_unresolved": selected_focus,
        "conflict_count": 0,
        "conflicts": [],
        "next_conflict": None,
        "diagnostic": diagnostic,
        "source_inventory_bound": False,
        "denominator_first": selected_focus,
        "unresolved_digest": _value_digest(
            {
                "diagnostic": diagnostic,
                "question_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
                "focus": selected_focus,
            }
        ),
        "unresolved_reason_counts": {
            diagnostic: ORIGINAL_KIND_QUESTION_DENOMINATOR
        },
        "unresolved_sample": sample,
        "unresolved_sample_limit": UNRESOLVED_SAMPLE_LIMIT,
        "unresolved_truncated": True,
        "blocker_counts": {},
    }


def admission_closure_report(
    rows: Mapping[str, Mapping[str, Any]],
    *,
    root: str | Path | None = None,
    source_inventory: Mapping[str, str] | None = None,
    documented_retention_keys: frozenset[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Assess the exact ORIGINAL_KIND_QUESTION_DENOMINATOR-cell admission denominator.

    ``root`` is mandatory because rootless component review cannot validate
    mechanism evidence bytes.  ``source_inventory`` maps each current source
    path to its canonical sha256 at this Tier-0 snapshot.  Without an inventory
    no decided cell can bind; the semantic inspection view is used only to
    enumerate the all-UNKNOWN denominator.  DOES_NOT_APPLY is admissible only
    when its evidence cites the exact validated owned-file set, each file once,
    at current census bytes, and that owned set's effect audit is CLOSED.
    Partial, duplicated, foreign, stale, or unclosed coverage stays UNRESOLVED
    and is named in ``blocker_counts`` and in the sample's
    ``denominator_blocker``.  A checked root-ledger APPLIES answer may retain
    demand for an exactly open cell, or for a byte-bound DOES_NOT_APPLY whose
    owner/effect denominator cannot establish absence.  It never repairs stale,
    malformed, foreign, or otherwise unbound source evidence and never changes
    the source classification.  A manifest decision that contradicts a
    validated component decision is FAIL, even when its own evidence bytes bind.
    ``unresolved`` retains the full coordinate list for internal
    reviewers; callers that publish the report should use the bounded
    ``unresolved_*`` fields instead.
    """
    if root is None:
        raise ValueError(_VALIDATED_ROOT_REQUIRED)
    row_ids = set(rows)
    first_row = min(row_ids) if row_ids else None
    first_focus = (
        None
        if first_row is None
        else {"object_id": first_row, "kind": ORIGINAL_NON_OBJECT_KINDS[0]}
    )
    if source_inventory is None:
        return _unknown_admission_closure(
            "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_ABSENT",
            focus=first_focus,
        )
    document = validated_review_document(root, source_inventory)
    document_ids = set(document)
    retention_keys = (
        frozenset()
        if documented_retention_keys is None
        else documented_retention_keys
    )
    if type(retention_keys) is not frozenset or any(
        type(key) is not tuple
        or len(key) != 2
        or type(key[0]) is not str
        or key[0] not in document_ids
        or type(key[1]) is not str
        or key[1] not in ORIGINAL_NON_OBJECT_KINDS
        for key in retention_keys
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_DOCUMENTED_RETENTION_INVALID")
    if row_ids != document_ids:
        missing = sorted(document_ids - row_ids)
        extra = sorted(row_ids - document_ids)
        object_id = missing[0] if missing else extra[0]
        mismatch = "MISSING" if missing else "EXTRA"
        return _unknown_admission_closure(
            "PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_"
            + mismatch
            + ":"
            + object_id,
            focus={"object_id": object_id, "kind": ORIGINAL_NON_OBJECT_KINDS[0]},
        )
    unresolved: list[dict[str, str]] = []
    reasons: list[str] = []
    details: list[str | None] = []
    conflicts: list[dict[str, str]] = []
    blocker_counts: Counter[str] = Counter()
    closures: dict[tuple[str, ...], str | None] = {}
    decided_count = 0
    documented_retention_applied_count = 0
    for object_id in document:
        row = rows.get(object_id)
        owned_paths = _document_owned_paths(document[object_id])
        classification = row.get("classification") if isinstance(row, Mapping) else None
        for kind in ORIGINAL_NON_OBJECT_KINDS:
            decision = (
                classification.get(kind)
                if isinstance(classification, Mapping)
                else None
            )
            expected_status = document[object_id]["questions"][kind].get("status")
            blocker = _decision_binding_blocker(row, decision, source_inventory)
            binding_blocker = blocker
            detail: str | None = None
            if (
                blocker is None
                and isinstance(decision, Mapping)
                and decision["status"] == DOES_NOT_APPLY
            ):
                refusal = _does_not_apply_refusal(
                    root, decision, owned_paths, source_inventory, closures
                )
                if refusal is not None:
                    blocker, detail = refusal
            retained_open = (
                (object_id, kind) in retention_keys
                and isinstance(decision, Mapping)
                and decision.get("status") == "UNRESOLVED"
                and type(decision.get("reason")) is str
                and bool(decision["reason"].strip())
                and decision.get("evidence") == []
            )
            retained_denial = (
                (object_id, kind) in retention_keys
                and isinstance(decision, Mapping)
                and decision.get("status") == DOES_NOT_APPLY
                and binding_blocker is None
                and blocker == "DECISION_UNRESOLVED"
                and detail is not None
            )
            if blocker is not None and (retained_open or retained_denial):
                blocker = None
                detail = None
                documented_retention_applied_count += 1
            if blocker is None:
                decided_count += 1
            else:
                unresolved.append({"object_id": object_id, "kind": kind})
                reasons.append(blocker)
                details.append(detail)
                if detail is not None:
                    blocker_counts[detail] += 1
                    if expected_status == "UNRESOLVED":
                        blocker_counts[_VALIDATED_UNRESOLVED_BLOCKER] += 1
            actual_status = (
                decision.get("status") if isinstance(decision, Mapping) else None
            )
            if (
                expected_status in {APPLIES, DOES_NOT_APPLY}
                and actual_status in {APPLIES, DOES_NOT_APPLY}
                and actual_status != expected_status
            ):
                conflicts.append(
                    {
                        "object_id": object_id,
                        "kind": kind,
                        "expected_status": expected_status,
                        "actual_status": actual_status,
                    }
                )
    first = unresolved[0] if unresolved else None
    first_conflict = conflicts[0] if conflicts else None
    diagnostic = (
        "PACKAGE_ORIGINAL_KIND_CATALOG_CONFLICT:"
        + first_conflict["object_id"]
        + ":"
        + first_conflict["kind"]
        if first_conflict is not None
        else None
        if first is None
        else "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
        + first["object_id"]
        + ":"
        + first["kind"]
    )
    return {
        "status": "FAIL" if conflicts else "UNKNOWN" if unresolved else "PASS",
        "question_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
        "decided_count": decided_count,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved,
        "next_unresolved": first,
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
        "next_conflict": first_conflict,
        "diagnostic": diagnostic,
        "source_inventory_bound": source_inventory is not None,
        "documented_retention_selected_count": len(retention_keys),
        "documented_retention_applied_count": documented_retention_applied_count,
        "documented_retention_digest": _value_digest(sorted(retention_keys)),
        "denominator_first": (
            None
            if not document
            else {
                "object_id": next(iter(document)),
                "kind": ORIGINAL_NON_OBJECT_KINDS[0],
            }
        ),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        **bounded_unresolved_summary(unresolved, reasons, details),
    }

__all__ = [
    "FULL_PROFILE_BOUNDARY",
    "FULL_PROFILE_ID",
    "FULL_PROFILE_REVISION",
    "ORIGINAL_KIND_QUESTION_DENOMINATOR",
    "UNRESOLVED_SAMPLE_LIMIT",
    "admission_closure_report",
    "apply_partial_profiles",
    "bounded_unresolved_summary",
    "catalog_evidence_report",
    "full_closure_profile",
    "partial_profiles",
    "review_document",
    "unresolved_cells",
    "unresolved_questions",
    "validate_catalog_evidence",
    "validated_review_document",
]
