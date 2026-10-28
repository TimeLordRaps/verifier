"""Fail-closed automatic refresh of Verifier's root ``objects.vstd``.

Terminology: intermediate representation (IR).

The migration engine knows how Verifier represents its own source.  This
module adds the transaction boundary needed by ``vstd polish``: inspect exact
current bytes, reject semantic weakening or a mismatched installed engine,
admit only a compact version-6 candidate that binds the opening source census
and passes the package selector, retain recovery material outside the
repository, atomically replace one root manifest, and publish a bounded
receipt.  A source-matched root is CURRENT only in that exact compact version-6
transport; an inline version-5 root is refresh-required so automatic polish
remigrates it once.  A refresh is neither admission nor a polish verdict.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import hmac
import json
import multiprocessing
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import tempfile
from collections.abc import Mapping
from typing import Any
import re

from verifier.runtime import (
    namespace_consequences,
    namespace_contracts,
    namespace_discovery,
    namespace_manifest,
    package_manifest,
    package_manifest_migration,
    package_semantic_ownership,
    self_polish_estate,
    tier_zero_manifest,
    tier_zero_profile,
)


PLAN_SCHEMA = "verifier-package-manifest-refresh-plan-1"
RECEIPT_SCHEMA = "verifier-package-manifest-refresh-receipt-1"
OUTCOME_SCHEMA = "verifier-package-manifest-refresh-outcome-1"
LOCK_SCHEMA = "verifier-package-manifest-refresh-lock-1"
VERIFIER_REMOTE = "https://github.com/TimeLordRaps/verifier.git"
_PACKAGE_SUFFIXES = frozenset(
    {".py", ".pyi", ".json", ".mjs", ".md", ".html", ".css", ".js"}
)
_PLAN_SEAL_KEY = secrets.token_bytes(32)
# A refusal is one stable code, optionally followed by the colon-separated codes and
# identifiers its wrappers add.  Segments are bounded, relative and free of spaces,
# so a provider message (prose, absolute or parent paths) still never matches.
_REFUSAL_CHAIN = re.compile(
    r"[A-Z][A-Z0-9_]{2,127}(?::[A-Za-z0-9_.@-][A-Za-z0-9_.@/-]{0,199}){0,15}")
_MAX_REFUSAL_CHAIN_BYTES = 1024
_SOURCE_REFUSAL_CODES = frozenset({
    "CANDIDATE_SOURCE_BYTE_CAPACITY_EXHAUSTED",
    "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED",
    "CANDIDATE_SOURCE_GIT_STATE_DIGEST_INVALID",
    "CANDIDATE_SOURCE_MUTATED",
    "CANDIDATE_SOURCE_NOT_REGULAR_FILE",
    "CANDIDATE_SOURCE_PATH_DUPLICATED",
    "CANDIDATE_SOURCE_PATH_ESCAPES_ROOT",
    "CANDIDATE_SOURCE_PATH_INVALID",
    "CANDIDATE_SOURCE_PATH_ORDER_DIFFERS",
    "CANDIDATE_SOURCE_PATH_SET_INVALID",
    "CANDIDATE_SOURCE_PROVENANCE_OVERLAP",
    "CANDIDATE_SOURCE_REPARSE_POINT",
    "GIT_COORDINATE_INVALID",
    "GIT_INDEX_INVALID",
    "GIT_INDEX_TRACKED_SET_DIFFERS",
    "GIT_IGNORED_PATH_INVALID",
    "GIT_STATE_UNAVAILABLE",
    "GIT_STATUS_INVALID",
    "IGNORED_DISCOVERABLE_SOURCE_PRESENT",
    "IGNORED_PATH_CAPACITY_EXHAUSTED",
    "IGNORED_PATH_DUPLICATED",
    "IGNORED_PATH_INVALID",
    "IGNORED_PATH_ORDER_DIFFERS",
    "TRACKED_PATH_INVALID",
})


class ManifestRefreshError(ValueError):
    """A stable refresh refusal with an explicit epistemic result."""

    def __init__(
        self,
        code: str,
        *,
        status: str = "UNKNOWN",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.details = {} if details is None else details


def _digest(raw: bytes) -> str:
    return self_polish_estate.bytes_digest(raw)


def _canonical(value: Any) -> bytes:
    return tier_zero_profile.canonical_bytes(value) + b"\n"


def _target_is_safe(target: Path) -> os.stat_result:
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_TARGET_UNSAFE") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ManifestRefreshError("MANIFEST_REFRESH_TARGET_UNSAFE")
    return metadata


def _package_inventory(root: Path) -> dict[str, str]:
    if not root.is_dir():
        raise ManifestRefreshError("MANIFEST_REFRESH_INSTALLED_SOURCE_MISMATCH")
    inventory: dict[str, str] = {}
    try:
        for path in root.rglob("*"):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path.suffix == ".pyc"
                or path.suffix not in _PACKAGE_SUFFIXES
            ):
                continue
            relative = path.relative_to(root).as_posix()
            inventory[relative] = _digest(path.read_bytes())
    except OSError as exc:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_INSTALLED_SOURCE_MISMATCH"
        ) from exc
    return inventory


def _require_installed_source_match(root: Path) -> None:
    selected = _package_inventory(root / "src" / "verifier")
    executing_root = Path(package_manifest_migration.__file__).resolve().parents[1]
    executing = _package_inventory(executing_root)
    if not selected or selected != executing:
        raise ManifestRefreshError("MANIFEST_REFRESH_INSTALLED_SOURCE_MISMATCH")


def _source_coordinate(root: Path) -> tuple[str, dict[str, Any]]:
    try:
        return package_manifest_migration.source_refresh_coordinate(root)
    except self_polish_estate.EstateError as exc:
        code = str(exc)
        safe_code = code if code in _SOURCE_REFUSAL_CODES else "UNCLASSIFIED"
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_SOURCE_UNAVAILABLE",
            details={"source_refusal": safe_code},
        ) from exc
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_SOURCE_UNAVAILABLE") from exc


def _selected_source_refresh_coordinate(document: dict[str, Any]) -> str | None:
    namespace = document.get("namespace", {})
    rows = namespace.get("objects", []) if type(namespace) is dict else []
    graph = next(
        (
            row for row in rows
            if type(row) is dict and row.get("object_id") == "vstd-package-graph"
        ),
        {},
    )
    payload = graph.get("payload", {}) if type(graph) is dict else {}
    value = payload.get("source_refresh_coordinate") if type(payload) is dict else None
    return value if type(value) is str else None


def _selected_source_semantic_profile(
    document: dict[str, Any],
) -> dict[str, Any] | None:
    namespace = document.get("namespace", {})
    rows = namespace.get("objects", []) if type(namespace) is dict else []
    graph = next(
        (
            row for row in rows
            if type(row) is dict and row.get("object_id") == "vstd-package-graph"
        ),
        {},
    )
    payload = graph.get("payload", {}) if type(graph) is dict else {}
    profile = payload.get("source_semantic_profile") if type(payload) is dict else None
    return profile if type(profile) is dict else None


def _validated_semantic_profile(profile: dict[str, Any]) -> dict[str, dict]:
    retained = dict(profile)
    claimed = retained.pop("digest", None)
    if (
        profile.get("schema_version")
        != package_manifest_migration.SOURCE_SEMANTIC_PROFILE_SCHEMA
        or not _is_digest(claimed)
        or claimed != tier_zero_profile.value_digest(retained)
        or type(profile.get("reason")) is not str
        or not profile["reason"].strip()
        or type(profile.get("binding_sets")) is not list
        or type(profile.get("records")) is not list
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
        )
    binding_sets = profile["binding_sets"]
    decoded_binding_sets = []
    for encoded_bindings in binding_sets:
        if type(encoded_bindings) is not str:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            )
        try:
            bindings = json.loads(encoded_bindings)
        except (TypeError, ValueError) as exc:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            ) from exc
        if (
            type(bindings) is not list
            or tier_zero_profile.canonical_bytes(bindings).decode("utf-8")
            != encoded_bindings
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            )
        for binding in bindings:
            if (
                type(binding) is not dict
                or type(binding.get("object_id")) is not str
                or not binding["object_id"]
                or any(
                    type(binding.get(field)) is not list
                    or any(type(value) is not str or not value for value in binding[field])
                    for field in ("classifications", "obligations")
                )
            ):
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
                )
        decoded_binding_sets.append(bindings)
    by_path: dict[str, dict] = {}
    for record in profile["records"]:
        if type(record) is not str:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            )
        parts = record.split("\t")
        if len(parts) != 4:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            )
        path, semantic_kind, semantic_sha256, binding_set_text = parts
        try:
            binding_set = int(binding_set_text)
        except ValueError as exc:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            ) from exc
        pure = PurePosixPath(path)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or "\\" in path
            or path in by_path
            or semantic_kind not in {"python-location-free-ast", "byte-exact"}
            or not _is_digest(semantic_sha256)
            or str(binding_set) != binding_set_text
            or not 0 <= binding_set < len(decoded_binding_sets)
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SEMANTIC_PROFILE_INVALID", status="FAIL"
            )
        by_path[path] = {
            "path": path,
            "semantic_kind": semantic_kind,
            "semantic_sha256": semantic_sha256,
            "binding_set": binding_set,
            "bindings": deepcopy(decoded_binding_sets[binding_set]),
        }
    return by_path


def _review_required_entries(
    row: dict, *, reason: str,
) -> list[dict[str, Any]]:
    return [
        {
            "path": row["path"],
            "reason": reason,
            "object_id": binding["object_id"],
            "classifications": list(binding["classifications"]),
            "obligations": list(binding["obligations"]),
        }
        for binding in row["bindings"]
    ]


_PARALLEL_SEMANTIC_THRESHOLD = 128
_MAX_SEMANTIC_WORKERS = 8


def _semantic_identity_task(
    task: tuple[str, str],
) -> tuple[str, dict[str, str] | None]:
    root, path = task
    try:
        return path, package_manifest_migration.source_semantic_identity(
            Path(root), path
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return path, None


def _semantic_identities(
    root: Path, paths: list[str],
) -> dict[str, dict[str, str] | None]:
    tasks = [(str(root), path) for path in paths]
    workers = min(_MAX_SEMANTIC_WORKERS, os.cpu_count() or 1, len(tasks))
    if len(tasks) < _PARALLEL_SEMANTIC_THRESHOLD or workers == 1:
        return dict(_semantic_identity_task(task) for task in tasks)
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=multiprocessing.get_context("spawn"),
    ) as executor:
        return dict(executor.map(_semantic_identity_task, tasks, chunksize=4))


def _source_semantic_deltas(
    root: Path, profile: dict[str, Any],
) -> list[dict[str, Any]]:
    """Name every reviewed answer whose source semantics no longer match."""

    deltas = []
    validated = _validated_semantic_profile(profile)
    current_by_path = _semantic_identities(root, list(validated))
    for path, prior in validated.items():
        current = current_by_path[path]
        if current is None:
            deltas.extend(_review_required_entries(prior, reason="SOURCE_UNAVAILABLE"))
            continue
        if (
            current["semantic_kind"] != prior["semantic_kind"]
            or current["semantic_sha256"] != prior["semantic_sha256"]
        ):
            deltas.extend(
                _review_required_entries(prior, reason="SOURCE_SEMANTICS_CHANGED")
            )
    return deltas


_REVIEW_POLICIES = frozenset({"refuse", "record"})


def _reopened_coordinates(
    deltas: list[dict[str, Any]],
) -> dict[str, tuple[frozenset[str], frozenset[str]]]:
    """Group reopened answers by object: (classification kinds, obligation ids)."""

    grouped: dict[str, tuple[set[str], set[str]]] = {}
    for delta in deltas:
        kinds, obligations = grouped.setdefault(delta["object_id"], (set(), set()))
        kinds.update(delta["classifications"])
        obligations.update(delta["obligations"])
    return {
        object_id: (frozenset(kinds), frozenset(obligations))
        for object_id, (kinds, obligations) in grouped.items()
    }


def _semantic_profile_transition_deltas(
    prior: dict[str, Any], current: dict[str, Any],
) -> list[dict[str, Any]]:
    """Refuse automatic selection of new answers or semantic baselines."""

    prior_rows = _validated_semantic_profile(prior)
    current_rows = _validated_semantic_profile(current)
    deltas = []
    for path in sorted(set(prior_rows) | set(current_rows)):
        before = prior_rows.get(path)
        after = current_rows.get(path)
        selected = after if after is not None else before
        assert selected is not None
        if before is None:
            reason = "NEW_REVIEWED_SOURCE_REQUIRES_SELECTION"
        elif after is None:
            reason = "REVIEWED_SOURCE_BINDING_REMOVED"
        elif (
            before["semantic_kind"] != after["semantic_kind"]
            or before["semantic_sha256"] != after["semantic_sha256"]
            or before["bindings"] != after["bindings"]
        ):
            reason = "REVIEWED_SOURCE_BINDING_CHANGED"
        else:
            continue
        deltas.extend(_review_required_entries(selected, reason=reason))
    return deltas


def _evidence_paths(references: Any) -> tuple[str, ...]:
    if type(references) is not list:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_NON_MONOTONE", status="FAIL"
        )
    try:
        paths = tuple(row["path"] for row in references)
    except (KeyError, TypeError) as exc:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_NON_MONOTONE", status="FAIL"
        ) from exc
    if len(set(paths)) != len(paths):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_NON_MONOTONE", status="FAIL"
        )
    return paths


def _without_evidence_hashes(value: dict[str, Any]) -> dict[str, Any]:
    retained = deepcopy(value)
    retained["evidence"] = [
        {"path": row["path"]} for row in retained.get("evidence", [])
    ]
    return retained


def _surface_semantic_identity(value: str) -> str:
    """Remove source-location coordinates while retaining the exposed shape.

    Python duplicate-symbol identifiers include line numbers so users can focus
    a finding. Moving a definition must update that coordinate, but is not by
    itself removal of the exposed route. Markup element numbers are structural
    ordinals, not lines, and therefore remain part of identity. The automatic
    refresh compares the multiset while the published manifest retains every
    exact new location.
    """

    if value.startswith(("python:", "python-source-import:")):
        return re.sub(r"@\d+$", "@<line>", value)
    return value


def _surfaces_do_not_drop(prior: Any, current: Any) -> bool:
    if (
        type(prior) is not list
        or type(current) is not list
        or any(type(value) is not str for value in [*prior, *current])
    ):
        return False
    return Counter(map(_surface_semantic_identity, prior)) <= Counter(
        map(_surface_semantic_identity, current)
    )


def _harness_payload_rebinds_source_only(prior: Any, current: Any) -> bool:
    """Accept only volatile source coordinates in the reviewed launch payload."""

    if type(prior) is not dict or type(current) is not dict:
        return False
    prior_body, current_body = deepcopy(prior), deepcopy(current)
    prior_denominator = prior_body.pop("direct_launch_denominator", None)
    current_denominator = current_body.pop("direct_launch_denominator", None)
    if prior_body != current_body:
        return False
    if type(prior_denominator) is not dict or type(current_denominator) is not dict:
        return False
    for field in ("schema_version", "profile"):
        if prior_denominator.get(field) != current_denominator.get(field):
            return False
    prior_launches = prior_denominator.get("launches")
    current_launches = current_denominator.get("launches")
    if type(prior_launches) is not list or type(current_launches) is not list:
        return False
    try:
        prior_by_id = {row["launch_id"]: deepcopy(row) for row in prior_launches}
        current_by_id = {row["launch_id"]: deepcopy(row) for row in current_launches}
    except (KeyError, TypeError):
        return False
    if (
        len(prior_by_id) != len(prior_launches)
        or len(current_by_id) != len(current_launches)
        or set(prior_by_id) != set(current_by_id)
    ):
        return False
    volatile = {"line", "source_sha256", "container_sha256"}
    for launch_id, prior_launch in prior_by_id.items():
        current_launch = current_by_id[launch_id]
        for field in volatile:
            prior_launch.pop(field, None)
            current_launch.pop(field, None)
        if prior_launch != current_launch:
            return False
    return True


_GRAPH_DEPENDENCY_COMMITMENTS = ("nodes_digest", "edges_digest")


def _derived_graph_commitments(rows: dict[str, Any]) -> dict[str, str] | None:
    """Re-derive the package root's dependency commitments from the final rows.

    ``None`` means there is nothing to derive: no declared commitment pair, or rows
    that cannot be projected.  Nothing is ever guessed, so an unprojectable manifest
    keeps its commitments compared exactly.
    """

    if type(rows.get("vstd-package-graph")) is not dict:
        return None
    try:
        return package_manifest_migration.derived_package_graph_commitments(
            rows, namespace_contracts.namespace_registry(), "vstd-package-graph"
        )
    except ValueError:
        return None


def _graph_payload_rebinds_source_coordinate_only(
    prior: Any,
    current: Any,
    *,
    profile_may_advance: bool = False,
    derived_commitments: Mapping[str, str] | None = None,
) -> bool:
    """Permit source-only GRAPH coordinates to advance without new meaning.

    ``profile_may_advance`` is the recording policy: reopened and newly derived
    answers legitimately change which sources the semantic profile binds, so only
    its validity is required, not its equality to the prior profile.

    ``derived_commitments`` are the dependency commitments re-derived from the final
    rows.  A commitment may differ from the prior one only when it equals that exact
    derivation, because adding or removing a member legitimately moves the projection
    of the member list; any other value is still a changed meaning.
    """

    if type(prior) is not dict or type(current) is not dict:
        return False
    prior_body, current_body = deepcopy(prior), deepcopy(current)
    for field in _GRAPH_DEPENDENCY_COMMITMENTS:
        if (
            derived_commitments is not None
            and field in derived_commitments
            and current_body.get(field) == derived_commitments[field]
        ):
            prior_body.pop(field, None)
            current_body.pop(field, None)
    prior_coordinate = prior_body.pop("source_refresh_coordinate", None)
    current_coordinate = current_body.pop("source_refresh_coordinate", None)
    prior_profile = prior_body.pop("source_semantic_profile", None)
    current_profile = current_body.pop("source_semantic_profile", None)
    try:
        if type(prior_profile) is dict and type(current_profile) is dict:
            if profile_may_advance:
                _validated_semantic_profile(current_profile)
                profile_unchanged = True
            else:
                profile_unchanged = not _semantic_profile_transition_deltas(
                    prior_profile, current_profile
                )
        else:
            profile_unchanged = False
    except ManifestRefreshError:
        profile_unchanged = False
    return (
        prior_body == current_body
        and profile_unchanged
        and type(prior_coordinate) is str
        and type(current_coordinate) is str
        and prior_coordinate.startswith("sha256:")
        and current_coordinate.startswith("sha256:")
        and len(prior_coordinate) == len(current_coordinate) == 71
    )


_COMPACT_TRANSPORT_SCHEMAS = frozenset({
    package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
    package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
})


def _normalized_transport_namespace(document: dict[str, Any]) -> dict[str, Any]:
    """Expand one package namespace only when its outer transport permits it.

    The outer version is part of the transport contract.  Accepting a compact
    namespace under version 5 (or an inline namespace under version 6) would
    make this refresh check more permissive than package admission itself.
    Compact evidence digests are selectors, never substitute evidence.
    """

    outer_schema = document.get("schema_version")
    declared = document.get("namespace")
    if type(declared) is not dict:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_NAMESPACE_TRANSPORT_INVALID", status="FAIL"
        )
    expected = (
        namespace_manifest.COMPACT_SCHEMA
        if outer_schema == package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
        else namespace_manifest.SCHEMA
    )
    if declared.get("schema_version") != expected:
        raise ManifestRefreshError(
            "NAMESPACE_MANIFEST_VERSION", status="FAIL"
        )
    try:
        return namespace_manifest.normalize_manifest(declared)
    except (TypeError, ValueError) as exc:
        # Retain the exact compact validation gate so a missing, forged, or
        # unused evidence selector is actionable at its actual failure.
        raise ManifestRefreshError(str(exc) or "NAMESPACE_MANIFEST_INVALID",
                                   status="FAIL") from exc


def _transport_namespaces(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    content_may_change: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Select semantic namespaces and identify an exact v5/v6 transition.

    A strict refresh may switch transport only as a pure representation change, so
    the two expanded namespaces must be equal.  ``content_may_change`` is the
    recording policy, where the refresh also regenerates content; equality is then
    not required here because the per-cell comparison in ``_require_non_weakening``
    runs over both expanded namespaces, exactly as it does for a same-transport
    refresh that changes content.
    """

    before_schema = before.get("schema_version")
    after_schema = after.get("schema_version")
    transition = before_schema != after_schema
    if transition and {before_schema, after_schema} != _COMPACT_TRANSPORT_SCHEMAS:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_SCHEMA_CHANGED", status="FAIL"
        )

    # Preserve the established v3-v5 comparison path byte-for-byte. Version 6
    # must be expanded before semantic checks, and a v5/v6 transition validates
    # both sides because only their representation is allowed to change.
    normalize = transition or (
        before_schema == package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
        and after_schema == before_schema
    )
    if not normalize:
        return before.get("namespace", {}), after.get("namespace", {}), False

    prior = _normalized_transport_namespace(before)
    current = _normalized_transport_namespace(after)
    if transition and prior != current and not content_may_change:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_NAMESPACE_TRANSPORT_SEMANTICS_CHANGED",
            status="FAIL",
        )
    return prior, current, transition


def _surface_source_path(surface: str) -> str:
    """Name the repository path inside ``<kind>:<path>[:<detail>]``."""

    return surface.partition(":")[2].partition(":")[0]


def _graph_semantic_identities(
    rows: dict[str, Any],
) -> dict[str, tuple[str, str]]:
    """Map each profiled source path to its (semantic kind, identity digest)."""

    payload = rows.get("vstd-package-graph", {}).get("payload")
    profile = payload.get("source_semantic_profile") if type(payload) is dict else None
    if type(profile) is not dict:
        return {}
    return {
        path: (row["semantic_kind"], row["semantic_sha256"])
        for path, row in _validated_semantic_profile(profile).items()
    }


_REVIEWED_SURFACE_RETIREMENTS = {
    "vstd-package-object": {
        (
            "python:tests/test_package_semantic_ownership_aggregate.py:"
            "test_batch_statuses_accept_only_the_43_ready_system_rows"
        ): (
            "python:tests/test_package_semantic_ownership_aggregate.py:"
            "test_batch_statuses_accept_ready_system_and_agency_rows"
        ),
        (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_bot_and_agent_never_inherit_robot_or_finbot_by_primary_kind"
        ): (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_bot_and_agent_never_source_inherit_robot_or_finbot_by_primary_kind"
        ),
        (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_aggregation_is_not_ready_while_typed_slots_are_unbound"
        ): (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_aggregation_is_ready_when_every_typed_slot_is_exactly_bound"
        ),
        (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_mutant_1_agent_actuator_applies_is_unknown_not_invocation_match"
        ): (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_mutant_1_agent_actuator_retention_is_not_invocation_match_evidence"
        ),
        (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_arch_roles_are_unknown_and_never_inherit_from_the_scope_label"
        ): (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_arch_roles_are_retained_without_inheriting_from_the_scope_label"
        ),
        (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_human_absence_of_controller_actuator_robot_finbot_is_unknown_not_silence_based_dna"
        ): (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_human_absence_of_controller_actuator_robot_finbot_is_retained_not_silence_based_dna"
        ),
        (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_bench_transaction_stays_unknown_without_atomicity_evidence"
        ): (
            "python:tests/test_package_semantic_ownership_domains_agency_collective.py:"
            "test_bench_transaction_is_retained_without_atomicity_evidence"
        ),
    }
}


def _reviewed_surface_retirement_paths(
    object_id: str, prior: list[str], current: list[str]
) -> list[str] | None:
    """Recognize one exact, reviewed replacement for unprofiled old surfaces."""

    transition = _REVIEWED_SURFACE_RETIREMENTS.get(object_id)
    if transition is None:
        return None
    prior_counts = Counter(map(_surface_semantic_identity, prior))
    current_counts = Counter(map(_surface_semantic_identity, current))
    dropped = prior_counts - current_counts
    if dropped != Counter(transition.keys()):
        return None
    if any(
        current_counts[replacement] <= prior_counts[replacement]
        for replacement in transition.values()
    ):
        return None
    return sorted({_surface_source_path(surface) for surface in transition})


def _retired_surface_paths(
    prior: list[str],
    current: list[str],
    prior_identities: dict[str, tuple[str, str]],
    current_identities: dict[str, tuple[str, str]],
) -> list[str] | None:
    """Name the changed sources behind dropped surfaces, or None if one is anomalous.

    A surface is a shape the object exposes in a source file.  It may disappear
    only because that file's semantics changed or the file left the profile; a
    surface that vanishes while its file is semantically identical, or whose file
    was never profiled, is a lost route and still refuses.
    """

    dropped = Counter(map(_surface_semantic_identity, prior)) - Counter(
        map(_surface_semantic_identity, current)
    )
    paths: set[str] = set()
    for surface in dropped:
        path = _surface_source_path(surface)
        before = prior_identities.get(path)
        if before is None or before == current_identities.get(path):
            return None
        paths.add(path)
    return sorted(paths)


def _harness_launches_regenerated(
    prior: Any, current: Any,
) -> dict[str, list[str]] | None:
    """Compare two launch denominators; None when anything else about them differs.

    Only the reviewed ``direct_launch_denominator`` is regenerated from the live
    source and the reviewed launch list.  The rest of the payload and the
    denominator's schema and profile must be equal.  The result names launches
    that were added, removed, or changed in any field.
    """

    if type(prior) is not dict or type(current) is not dict:
        return None
    prior_body, current_body = deepcopy(prior), deepcopy(current)
    prior_denominator = prior_body.pop("direct_launch_denominator", None)
    current_denominator = current_body.pop("direct_launch_denominator", None)
    if (
        prior_body != current_body
        or type(prior_denominator) is not dict
        or type(current_denominator) is not dict
        or any(
            prior_denominator.get(field) != current_denominator.get(field)
            for field in ("schema_version", "profile")
        )
    ):
        return None
    try:
        prior_by_id = {
            row["launch_id"]: row for row in prior_denominator["launches"]
        }
        current_by_id = {
            row["launch_id"]: row for row in current_denominator["launches"]
        }
    except (KeyError, TypeError):
        return None
    if len(prior_by_id) != len(prior_denominator["launches"]) or len(
        current_by_id
    ) != len(current_denominator["launches"]):
        return None
    return {
        "added": sorted(set(current_by_id) - set(prior_by_id)),
        "removed": sorted(set(prior_by_id) - set(current_by_id)),
        "changed": sorted(
            launch_id
            for launch_id in set(prior_by_id) & set(current_by_id)
            if prior_by_id[launch_id] != current_by_id[launch_id]
        ),
    }


def _regeneration_status_move_allowed(before: Any, after: Any) -> bool:
    """Whether regeneration may move one applicability status to another.

    Regeneration may keep a status, reopen any answer as ``UNRESOLVED``, answer an
    open question as ``APPLIES``, or tighten a refutation to ``APPLIES``.  Each of
    those can only add questions.  It may never move an answer into
    ``DOES_NOT_APPLY``, because that shrinks the obligation denominator.
    """

    if before == after or after == "UNRESOLVED":
        return True
    return after == "APPLIES" and before in {"UNRESOLVED", "DOES_NOT_APPLY"}


def _bound_to_source(decision: Any, source_digests: Mapping[str, str] | None) -> bool:
    """Whether a refutation cites evidence, all of it the current source bytes.

    The installed reviewed catalogs derive a refutation from positive anchors over
    the bytes they cite.  A cell that cites nothing, or cites bytes that are no
    longer the current inventory, therefore carries no such derivation and must not
    be accepted as a regenerated answer.
    """

    if source_digests is None or type(decision) is not dict:
        return False
    evidence = decision.get("evidence")
    if type(evidence) is not list or not evidence:
        return False
    return all(
        type(reference) is dict
        and source_digests.get(reference.get("path")) == reference.get("sha256")
        for reference in evidence
    )


def _obligation_kind(obligation_id: str) -> str:
    """Name the classification kind an obligation identifier is owned by."""

    return obligation_id.split("-0.", 1)[0]


def _note_regenerated_status(
    regenerated: list[dict[str, Any]],
    object_id: str,
    kind: str,
    before: Any,
    after: Any,
) -> None:
    """Record the regenerated moves a developer still has to act on."""

    if after == "UNRESOLVED" and before != "UNRESOLVED":
        gap = "APPLICABILITY_REOPENED"
    elif after == "APPLIES" and before == "DOES_NOT_APPLY":
        gap = "REFUTATION_WITHDRAWN"
    else:
        return
    regenerated.append(
        {
            "stage": "regeneration",
            "gap": gap,
            "object_id": object_id,
            "classification": kind,
            "was": before,
        }
    )


def _compiled_consequence_graph_rebinds_source_only(
    before: Any,
    after: Any,
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
    source_digests: Mapping[str, str] | None,
) -> bool:
    """Permit only current hash rebinding of an already selected graph profile."""

    if source_digests is None or not namespace_consequences.is_compiled_effect_graph(
        after, after_rows
    ):
        return False

    def identity(graph: dict[str, Any]) -> dict[str, list[tuple[Any, ...]]]:
        return {
            "edges": [
                (
                    edge["source"],
                    edge["relation"],
                    edge["target"],
                    edge["reason"],
                    tuple(
                        reference.get("path") for reference in edge["evidence"]
                    ),
                )
                for edge in graph["edges"]
            ],
            "effects": [
                (
                    effect["object_id"],
                    effect["domain"],
                    effect["reason"],
                    tuple(
                        reference.get("path") for reference in effect["evidence"]
                    ),
                )
                for effect in graph["effects"]
            ],
        }

    same_profile = (
        namespace_consequences.is_compiled_effect_graph(before, before_rows)
        and identity(before) == identity(after)
    )
    exact_retention_prune = namespace_consequences.is_exact_retention_prune(
        before, after, before_rows, after_rows
    )
    exact_control_path = (
        namespace_consequences.is_exact_reviewed_control_path_addition(
            before, after, before_rows, after_rows
        )
    )
    if not (same_profile or exact_retention_prune or exact_control_path):
        return False
    return all(
        type(reference) is dict
        and set(reference) == {"path", "sha256"}
        and source_digests.get(reference["path"]) == reference["sha256"]
        for record in [*after["edges"], *after["effects"]]
        for reference in record["evidence"]
    )


def _retention_prune_observation(
    root: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    documented_withdrawal_authority: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Discover source only for transitions that must prove no current demand."""

    exact_retention_prune = all(
        type(document.get("namespace", {}).get("consequence_graph")) is dict
        for document in (before, after)
    )
    if exact_retention_prune:
        prior, current, _ = _transport_namespaces(
            before, after, content_may_change=True
        )
        exact_retention_prune = namespace_consequences.is_exact_retention_prune(
            prior.get("consequence_graph"),
            current.get("consequence_graph"),
            prior.get("objects", []),
            current.get("objects", []),
        )
    withdrawals = (
        documented_withdrawal_authority.get("withdrawals", {})
        if isinstance(documented_withdrawal_authority, Mapping)
        else {}
    )
    if not exact_retention_prune and not withdrawals:
        return None
    return namespace_discovery.discover(root)


def _documented_withdrawal_authority(root: Path) -> dict[str, Any] | None:
    """Read exact checked denials from the sole co-located root reason ledger.

    A denial is not source-role evidence and cannot erase an independently
    required obligation.  It can authorize only withdrawal of the exact
    ``reasons.vstd:<same-reason-id>`` NOT_ESTABLISHED bindings previously
    generated for that object/kind coordinate.  The non-weakening comparison
    below separately proves the current source-bound refutation and absence of
    every independent demand.
    """

    if not (root / "reasons.vstd").is_file():
        return None
    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    selection = reason_integration.select_root_reasons(root)
    registered_kinds = namespace_contracts.namespace_registry()
    withdrawals = {
        (decision["object_id"], decision["object_kind"]): decision["reason_id"]
        for decision in selection.classification_decisions
        if decision.get("decision") == "DOES_NOT_APPLY"
        and decision.get("object_kind") in registered_kinds
    }
    return {
        "path": selection.authority["path"],
        "sha256": selection.authority["sha256"],
        "ir_digest": selection.ir_digest,
        "withdrawals": withdrawals,
    }


def _semantic_catalog_role_retirements(
    identifier: str,
    prior: dict[str, Any],
    current: dict[str, Any],
    registry: dict[str, namespace_contracts.KindContract],
) -> set[str]:
    """Recognize only stale extra roles retired by the exact semantic catalog.

    The generated current row must carry the catalog's primary kind, rationale,
    representation, operands, owned file paths, and every catalog specialization.
    A prior extra role remains protected when its APPLIES evidence and complete
    obligation denominator materialize an independent review.  Only the residue
    may be retired during regeneration.
    """

    spec = next(
        (
            item
            for item in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
            if item.object_id == identifier
        ),
        None,
    )
    if spec is None:
        return set()
    expected_operands = {role: list(targets) for role, targets in spec.operands}
    current_files = {
        surface.removeprefix("file:")
        for surface in current.get("surfaces", ())
        if type(surface) is str and surface.startswith("file:")
    }
    current_roles = set(current.get("specializations", ()))
    current_payload = current.get("payload")
    exact_payload = {"representation_role": spec.representation_role}
    predecessor_role = (
        package_manifest_migration._PRE_APPLICABILITY_REPRESENTATION_ROLES.get(
            identifier
        )
    )
    exact_preserved_predecessor = (
        predecessor_role is not None
        and current_payload == {"representation_role": predecessor_role}
        and prior.get("payload") == current_payload
    )
    if not (
        current.get("kind") == spec.primary_kind
        and current.get("reason")
        == spec.necessity_reason + " Boundary: " + spec.consequence_boundary
        and (current_payload == exact_payload or exact_preserved_predecessor)
        and current.get("operands") == expected_operands
        and current_files == set(spec.owned_paths)
        and set(spec.specializations) <= current_roles
    ):
        return set()
    retained = set(
        package_manifest_migration._reviewed_semantic_specializations(
            {"specializations": list(spec.specializations)}, prior, registry
        )
    )
    dropped = set(prior.get("specializations", ())) - {prior.get("kind")}
    return dropped - current_roles - retained


def _exact_revision_rebinding(before: Any, after: Any, live: Any) -> bool:
    """Accept only a repository revision rebound to the captured live Git head."""
    return (
        type(before) is dict and type(after) is dict and type(live) is dict
        and set(before) == set(after) == {"remote", "revision", "source_root"}
        and set(live) == {"repository", "revision"}
        and before.get("remote") == after.get("remote") == live.get("repository") == VERIFIER_REMOTE
        and before.get("source_root") == after.get("source_root") == "."
        and type(before.get("revision")) is str
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", before["revision"]) is not None
        and type(live.get("revision")) is str
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", live["revision"]) is not None
        and after.get("revision") == live["revision"]
    )


def _require_non_weakening(
    before: dict,
    after: dict,
    *,
    reopened: dict[str, tuple[frozenset[str], frozenset[str]]] | None = None,
    regenerated: list[dict[str, Any]] | None = None,
    source_digests: Mapping[str, str] | None = None,
    observed: dict[str, Any] | None = None,
    documented_retention_keys: frozenset[tuple[str, str]] = frozenset(),
    documented_withdrawal_authority: Mapping[str, Any] | None = None,
    live_repository: dict[str, str] | None = None,
) -> None:
    """Reject every removal or semantic substitution before publication.

    ``reopened`` is the recording policy: the listed classification kinds and
    obligations were reopened because their cited source changed meaning, so they
    alone may become unanswered.  Every other cell is still compared exactly.

    ``regenerated`` additionally accepts the generator's own current output for
    cells whose text it owns.  Wording and cited evidence may change, an answer may
    be reopened or tightened (see ``_regeneration_status_move_allowed``), and an
    obligation may vanish only when its kind is reopened.  Each move that leaves a
    question for a person is appended to the list.  Kinds, surfaces, operands
    and the object set are still compared exactly.  Specializations may change
    only when the legacy compiler transition retires its own exact role marker
    after the repaired graph stops deriving that role, or when an exact semantic-
    catalog row retires a stale extra role with no materialized independent
    review.  Both transitions are recorded.
    The retained graph may add the one exact verifier-core-to-HARNESS operand
    selected by the installed Tier-0 declaration; every other retained field
    remains exact. Payloads also remain exact except for the closed predecessor-to-current
    representation-role transitions reviewed by the installed semantic catalog;
    those transitions are recorded as gaps rather than silently accepted.

    ``source_digests`` is the current source inventory.  With it, a kind that was
    left open may be answered ``DOES_NOT_APPLY`` again, but only by a refutation
    whose every cited reference is the current bytes of that source; the reviewed
    catalogs derive such a refutation from the bytes themselves, so it is neither
    inherited nor invented here.  Without it no move into ``DOES_NOT_APPLY`` is
    accepted.

    ``documented_retention_keys`` permits one otherwise weakening source-only
    APPLIES-to-DOES_NOT_APPLY reversal when checked reasons.vstd independently
    retains the exact object/kind obligation denominator.  The replacement must
    still be current-source-bound and every prior obligation must remain present.

    ``documented_withdrawal_authority`` is the checked current ``reasons.vstd``
    coordinate map and its exact byte/IR digests.  A DOES_NOT_APPLY decision may
    remove only the complete set of bindings previously generated from the same
    reason identifier, only while every declaration is still NOT_ESTABLISHED,
    the compiled cell carries a current-source-bound refutation, and neither a
    local declaration nor the consequence graph independently demands the kind.
    """

    if type(documented_retention_keys) is not frozenset or any(
        type(key) is not tuple
        or len(key) != 2
        or type(key[0]) is not str
        or type(key[1]) is not str
        for key in documented_retention_keys
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_DOCUMENTED_RETENTION_INVALID", status="FAIL"
        )
    documented_withdrawals: Mapping[tuple[str, str], str] = {}
    withdrawal_ir_digest: str | None = None
    withdrawal_sha256: str | None = None
    if documented_withdrawal_authority is not None:
        withdrawals = (
            documented_withdrawal_authority.get("withdrawals")
            if isinstance(documented_withdrawal_authority, Mapping)
            else None
        )
        if (
            not isinstance(documented_withdrawal_authority, Mapping)
            or set(documented_withdrawal_authority) != {
                "path", "sha256", "ir_digest", "withdrawals"
            }
            or documented_withdrawal_authority.get("path") != "reasons.vstd"
            or not _is_digest(documented_withdrawal_authority.get("sha256"))
            or not _is_digest(documented_withdrawal_authority.get("ir_digest"))
            or not isinstance(withdrawals, Mapping)
            or any(
                type(key) is not tuple
                or len(key) != 2
                or any(type(part) is not str or not part for part in key)
                or type(reason_id) is not str
                or not reason_id
                for key, reason_id in withdrawals.items()
            )
            or source_digests is None
            or source_digests.get("reasons.vstd")
            != documented_withdrawal_authority.get("sha256")
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_DOCUMENTED_WITHDRAWAL_INVALID", status="FAIL"
            )
        documented_withdrawals = withdrawals
        withdrawal_ir_digest = documented_withdrawal_authority["ir_digest"]
        withdrawal_sha256 = documented_withdrawal_authority["sha256"]

    recording = reopened is not None
    reopened = reopened or {}
    regenerating = regenerated is not None

    prior_namespace, next_namespace, transport_transition = _transport_namespaces(
        before, after, content_may_change=recording
    )
    excluded = {"namespace", "representation_updates"}
    prior_retained = {key: deepcopy(value) for key, value in before.items()
                      if key not in excluded}
    next_retained = {key: deepcopy(value) for key, value in after.items()
                     if key not in excluded}
    if _exact_revision_rebinding(
        prior_retained.get("repository"), next_retained.get("repository"), live_repository,
    ):
        prior_retained["repository"]["revision"] = next_retained["repository"]["revision"]
    if transport_transition:
        # The exact outer versions remain bound by before_digest/after_digest
        # in the sealed plan and receipt.  Only this semantic comparison uses
        # a common token so a representation-only v5/v6 change can proceed.
        prior_retained["schema_version"] = package_manifest.PACKAGE_REPRESENTATION_SCHEMA
        next_retained["schema_version"] = package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    for value in (prior_retained, next_retained):
        for field in ("node_reconciler", "obligation_reason_provider"):
            if type(value.get(field)) is dict:
                value[field].pop("sha256", None)
    prior_reason = prior_retained.get("obligation_reason_provider")
    next_reason = next_retained.get("obligation_reason_provider")
    if (
        type(prior_reason) is dict
        and type(next_reason) is dict
        and prior_reason.get("selection_status") == "SELECTED"
        and next_reason == {
            "selection_status": "SELECTED",
            "path": "reasons.vstd",
        }
        and prior_reason.get("path")
        == "src/verifier/runtime/tier_zero_reasons.py"
    ):
        prior_reason["path"] = "reasons.vstd"
    core_harness_transition = (
        package_manifest_migration
        ._is_exact_verifier_core_harness_retained_transition(
            prior_retained, next_retained
        )
    )
    if core_harness_transition:
        prior_retained["objects"] = deepcopy(next_retained["objects"])
        if regenerating:
            regenerated.append(
                {
                    "stage": "regeneration",
                    "gap": "VERIFIER_CORE_HARNESS_BINDING_ADDED",
                    "object_id": "verifier-core-self",
                    "harness_object_id": "vstd-harness",
                }
            )
    if prior_retained != next_retained:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_RETAINED_CONTRACT_CHANGED", status="FAIL"
        )

    prior_graph = prior_namespace.get("consequence_graph")
    next_graph = next_namespace.get("consequence_graph")
    exact_retention_prune = namespace_consequences.is_exact_retention_prune(
        prior_graph,
        next_graph,
        prior_namespace.get("objects", []),
        next_namespace.get("objects", []),
    )
    exact_control_path = (
        namespace_consequences.is_exact_reviewed_control_path_addition(
            prior_graph,
            next_graph,
            prior_namespace.get("objects", []),
            next_namespace.get("objects", []),
        )
    )
    graph_rebound = (
        prior_graph == next_graph
        or _compiled_consequence_graph_rebinds_source_only(
            prior_graph,
            next_graph,
            prior_namespace.get("objects", []),
            next_namespace.get("objects", []),
            source_digests,
        )
    )
    if (
        prior_namespace.get("schema_version")
        != next_namespace.get("schema_version")
        or prior_namespace.get("extensions") != next_namespace.get("extensions")
        or prior_namespace.get("instance_checks")
        != next_namespace.get("instance_checks")
        or not graph_rebound
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_NAMESPACE_POLICY_CHANGED", status="FAIL"
        )
    if exact_control_path and regenerating:
        regenerated.append(
            {
                "stage": "regeneration",
                "gap": "VERIFIER_CORE_ROBOT_CONTROL_PATH_ADDED",
                "object_id": "verifier-core-self",
                "controller_object_id": "vstd-hardware-cli-protocol",
                "actuator_object_id": "vstd-accelerator-discovery-command",
            }
        )

    prior_rows = {
        row["object_id"]: row for row in prior_namespace.get("objects", [])
    }
    next_rows = {
        row["object_id"]: row for row in next_namespace.get("objects", [])
    }
    if not set(prior_rows) <= set(next_rows):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_OBJECT_DROPPED", status="FAIL"
        )
    prior_identities = _graph_semantic_identities(prior_rows) if regenerating else {}
    next_identities = _graph_semantic_identities(next_rows) if regenerating else {}
    consequence_registry = None
    semantic_registry = (
        namespace_contracts.namespace_registry() if regenerating else None
    )
    consequence_required: dict[str, set[str]] = {}
    consequence_surfaces: dict[str, dict[str, Any]] = {}
    if regenerating and observed is not None:
        consequence_registry = namespace_contracts.namespace_registry()
        consequence_surfaces = {
            surface["surface_id"]: surface
            for surface in observed.get("surfaces", ())
            if type(surface) is dict
            and type(surface.get("surface_id")) is str
        }
        if type(next_graph) is dict and namespace_consequences.is_compiled_effect_graph(
            next_graph, list(next_rows.values())
        ):
            consequence_required = {
                object_id: set(kinds)
                for object_id, kinds in namespace_consequences.derive_consequences(
                    list(next_rows.values()),
                    consequence_registry,
                    observed,
                    next_graph,
                )["required_kinds"].items()
            }
    for identifier, prior in prior_rows.items():
        current = next_rows[identifier]
        payload_unchanged = prior.get("payload") == current.get("payload")
        harness_source_rebound = (
            identifier == "vstd-harness"
            and _harness_payload_rebinds_source_only(
                prior.get("payload"), current.get("payload")
            )
        )
        launch_changes = (
            _harness_launches_regenerated(prior.get("payload"), current.get("payload"))
            if regenerating and identifier == "vstd-harness"
            else None
        )
        if launch_changes is not None and any(launch_changes.values()):
            regenerated.append(
                {
                    "stage": "regeneration",
                    "gap": "LAUNCH_DENOMINATOR_REGENERATED",
                    "object_id": identifier,
                    **launch_changes,
                }
            )
        retired = (
            _retired_surface_paths(
                prior.get("surfaces", []),
                current.get("surfaces", []),
                prior_identities,
                next_identities,
            )
            if regenerating
            and type(prior.get("surfaces")) is list
            and type(current.get("surfaces")) is list
            else None
        )
        if retired is None and regenerating:
            retired = _reviewed_surface_retirement_paths(
                identifier,
                prior.get("surfaces", []),
                current.get("surfaces", []),
            )
        if retired:
            regenerated.append(
                {
                    "stage": "regeneration",
                    "gap": "SURFACES_RETIRED",
                    "object_id": identifier,
                    "paths": retired,
                }
            )
        graph_source_rebound = (
            identifier == "vstd-package-graph"
            and _graph_payload_rebinds_source_coordinate_only(
                prior.get("payload"),
                current.get("payload"),
                profile_may_advance=recording,
                derived_commitments=_derived_graph_commitments(next_rows),
            )
        )
        reviewed_representation_rebound = (
            regenerating
            and package_manifest_migration._is_exact_reviewed_representation_role_transition(
                identifier, prior.get("payload"), current.get("payload")
            )
        )
        if reviewed_representation_rebound:
            regenerated.append(
                {
                    "stage": "regeneration",
                    "gap": "OBJECT_REPRESENTATION_ROLE_REGENERATED",
                    "object_id": identifier,
                }
            )
        if (
            prior.get("kind") != current.get("kind")
            or not (
                payload_unchanged
                or harness_source_rebound
                or graph_source_rebound
                or reviewed_representation_rebound
                or launch_changes is not None
            )
            or (prior.get("reason") != current.get("reason") and not regenerating)
            or not (
                _surfaces_do_not_drop(
                    prior.get("surfaces", []), current.get("surfaces", [])
                )
                or retired is not None
            )
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED",
                status="FAIL",
                details={
                    "object_id": identifier,
                    "kind_changed": prior.get("kind") != current.get("kind"),
                    "payload_unchanged": payload_unchanged,
                    "harness_source_rebound": harness_source_rebound,
                    "graph_source_rebound": graph_source_rebound,
                    "reviewed_representation_rebound": (
                        reviewed_representation_rebound
                    ),
                    "launch_denominator_regenerated": launch_changes is not None,
                    "reason_changed_without_regeneration": (
                        prior.get("reason") != current.get("reason")
                        and not regenerating
                    ),
                    "surfaces_preserved": _surfaces_do_not_drop(
                        prior.get("surfaces", []), current.get("surfaces", [])
                    ),
                    "retired_surfaces_classified": retired is not None,
                },
            )
        removable_primary = {prior.get("kind")}
        dropped_specializations = (
            set(prior.get("specializations", [])) - removable_primary
        ) - set(current.get("specializations", []))
        retired_semantic_roles = (
            _semantic_catalog_role_retirements(
                identifier, prior, current, semantic_registry
            )
            if semantic_registry is not None
            else set()
        )
        for kind in sorted(retired_semantic_roles):
            regenerated.append(
                {
                    "stage": "regeneration",
                    "gap": "SEMANTIC_OWNERSHIP_SPECIALIZATION_RETIRED",
                    "object_id": identifier,
                    "classification": kind,
                }
            )
        retired_compiler_roles: set[str] = set()
        if consequence_registry is not None:
            for kind in dropped_specializations:
                prior_decision = prior.get("classification", {}).get(kind)
                current_decision = current.get("classification", {}).get(kind)
                if (
                    type(prior_decision) is dict
                    and prior_decision.get("status") == "APPLIES"
                    and prior_decision.get("reason")
                    == namespace_consequences.compiled_role_reason(identifier, kind)
                    and type(current_decision) is dict
                    and current_decision.get("status") == "DOES_NOT_APPLY"
                    and _bound_to_source(current_decision, source_digests)
                    and kind not in consequence_required.get(identifier, set())
                    and not package_manifest_migration._row_demands_kind_without_compiler_retention(
                        current,
                        kind,
                        consequence_registry,
                        consequence_surfaces,
                    )
                ):
                    retired_compiler_roles.add(kind)
        if dropped_specializations - retired_compiler_roles - retired_semantic_roles:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_SPECIALIZATION_DROPPED", status="FAIL"
            )
        prior_operands = prior.get("operands", {})
        current_operands = current.get("operands", {})
        if not set(prior_operands) <= set(current_operands) or any(
            not set(targets) <= set(current_operands[role])
            for role, targets in prior_operands.items()
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_OPERAND_DROPPED", status="FAIL"
            )
        prior_classes = prior.get("classification", {})
        current_classes = current.get("classification", {})
        if not set(prior_classes) <= set(current_classes):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_CLASSIFICATION_DROPPED", status="FAIL"
            )
        reopened_kinds, reopened_obligations = reopened.get(
            identifier, (frozenset(), frozenset())
        )
        reanswered: set[str] = set()
        documented_retained_kinds: set[str] = set()
        for kind, decision in prior_classes.items():
            replacement = current_classes[kind]
            if kind in retired_compiler_roles:
                reanswered.add(kind)
                regenerated.append(
                    {
                        "stage": "regeneration",
                        "gap": "COMPILED_CONSEQUENCE_ROLE_RETIRED",
                        "object_id": identifier,
                        "classification": kind,
                        "was": decision.get("status"),
                    }
                )
                continue
            if kind in reopened_kinds:
                if not regenerating:
                    continue
                # Reopened means open again: the same pass may answer it only the
                # way regeneration answers any open question (APPLIES, or a
                # refutation bound to the current bytes), never with a free pass.
                decision = {"status": "UNRESOLVED"}
            if regenerating:
                if (
                    decision.get("status") == "UNRESOLVED"
                    and replacement.get("status") == "DOES_NOT_APPLY"
                    and _bound_to_source(replacement, source_digests)
                ):
                    reanswered.add(kind)
                    regenerated.append(
                        {
                            "stage": "regeneration",
                            "gap": "REFUTATION_REANSWERED",
                            "object_id": identifier,
                            "classification": kind,
                            "was": "UNRESOLVED",
                        }
                    )
                    continue
                if (
                    decision.get("status") == "APPLIES"
                    and replacement.get("status") == "DOES_NOT_APPLY"
                    and (identifier, kind) in documented_retention_keys
                    and _bound_to_source(replacement, source_digests)
                ):
                    documented_retained_kinds.add(kind)
                    regenerated.append(
                        {
                            "stage": "regeneration",
                            "gap": "SOURCE_REFUTATION_RESTORED_WITH_DOCUMENTED_RETENTION",
                            "object_id": identifier,
                            "classification": kind,
                            "was": "APPLIES",
                        }
                    )
                    continue
                if not _regeneration_status_move_allowed(
                    decision.get("status"), replacement.get("status")
                ):
                    raise ManifestRefreshError(
                        "MANIFEST_REFRESH_CLASSIFICATION_CHANGED", status="FAIL"
                    )
                _note_regenerated_status(
                    regenerated,
                    identifier,
                    kind,
                    decision.get("status"),
                    replacement.get("status"),
                )
                continue
            if (
                decision.get("status") != replacement.get("status")
                or decision.get("reason") != replacement.get("reason")
                or _evidence_paths(decision.get("evidence"))
                != _evidence_paths(replacement.get("evidence"))
            ):
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_CLASSIFICATION_CHANGED", status="FAIL"
                )
        prior_obligations = prior.get("obligations", {})
        current_obligations = current.get("obligations", {})
        vanished = set(prior_obligations) - set(current_obligations)
        documented_withdrawn: set[str] = set()
        if vanished and documented_withdrawals:
            if observed is None or consequence_registry is None:
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_DOCUMENTED_WITHDRAWAL_OBSERVATION_REQUIRED",
                    status="FAIL",
                )
            for kind in sorted({_obligation_kind(item) for item in vanished}):
                reason_id = documented_withdrawals.get((identifier, kind))
                if reason_id is None:
                    continue
                expected = {
                    requirement["id"]
                    for requirement in namespace_contracts.requirements_for(
                        consequence_registry, (kind,)
                    )
                    if requirement["kind"] == kind
                }
                candidate = {
                    obligation_id
                    for obligation_id in vanished
                    if _obligation_kind(obligation_id) == kind
                }
                current_decision = current_classes.get(kind)
                exact_generated_predecessor = bool(expected) and all(
                    type(prior_obligations.get(obligation_id)) is dict
                    and set(prior_obligations[obligation_id])
                    == {"reason", "evidence", "declaration"}
                    and prior_obligations[obligation_id]["reason"]
                    == (
                        "reasons.vstd:"
                        + reason_id
                        + "; fulfillment NOT_ESTABLISHED."
                    )
                    and type(prior_obligations[obligation_id]["declaration"])
                    is dict
                    and bool(prior_obligations[obligation_id]["declaration"])
                    and all(
                        value == "NOT_ESTABLISHED"
                        for value in prior_obligations[obligation_id][
                            "declaration"
                        ].values()
                    )
                    and _bound_to_source(
                        prior_obligations[obligation_id], source_digests
                    )
                    for obligation_id in expected
                )
                if not (
                    candidate == expected
                    and expected <= set(prior_obligations)
                    and expected.isdisjoint(current_obligations)
                    and type(current_decision) is dict
                    and current_decision.get("status") == "DOES_NOT_APPLY"
                    and _bound_to_source(current_decision, source_digests)
                    and kind not in consequence_required.get(identifier, set())
                    and not package_manifest_migration._row_demands_kind_without_compiler_retention(
                        current,
                        kind,
                        consequence_registry,
                        consequence_surfaces,
                    )
                    and exact_generated_predecessor
                ):
                    continue
                documented_withdrawn.update(expected)
                regenerated.append(
                    {
                        "stage": "regeneration",
                        "gap": "DOCUMENTED_RETENTION_WITHDRAWN",
                        "object_id": identifier,
                        "classification": kind,
                        "reason_id": reason_id,
                        "reason_sha256": withdrawal_sha256,
                        "reason_ir_digest": withdrawal_ir_digest,
                    }
                )
        if vanished and not (
            regenerating
            and all(
                obligation_id in documented_withdrawn
                or current_classes.get(_obligation_kind(obligation_id), {}).get("status")
                == "UNRESOLVED"
                or _obligation_kind(obligation_id) in reanswered
                for obligation_id in vanished
            )
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_OBLIGATION_DROPPED", status="FAIL"
            )
        for obligation_id, binding in prior_obligations.items():
            if obligation_id in reopened_obligations or obligation_id in vanished:
                continue
            replacement = current_obligations[obligation_id]
            if (
                regenerating
                and _obligation_kind(obligation_id) in documented_retained_kinds
            ):
                continue
            if regenerating and current_classes.get(
                _obligation_kind(obligation_id), {}
            ).get("status") in {"APPLIES", "UNRESOLVED"}:
                continue
            if (
                binding.get("reason") != replacement.get("reason")
                or binding.get("declaration") != replacement.get("declaration")
                or _evidence_paths(binding.get("evidence"))
                != _evidence_paths(replacement.get("evidence"))
            ):
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_OBLIGATION_CHANGED", status="FAIL"
                )

    prior_checks = prior_namespace.get("execution_checks", [])
    next_checks = next_namespace.get("execution_checks", [])
    prior_by_key = {
        (row.get("object_id"), row.get("mechanism")): row
        for row in prior_checks
    }
    next_by_key = {
        (row.get("object_id"), row.get("mechanism")): row
        for row in next_checks
    }
    if not set(prior_by_key) <= set(next_by_key):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_EXECUTION_SELECTION_DROPPED", status="FAIL"
        )
    for key, check in prior_by_key.items():
        if _without_evidence_hashes(check) != _without_evidence_hashes(
            next_by_key[key]
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_EXECUTION_SELECTION_CHANGED", status="FAIL"
            )

    prior_updates = {
        row["object_id"]: row for row in before.get("representation_updates", [])
    }
    next_updates = {
        row["object_id"]: row for row in after.get("representation_updates", [])
    }
    if set(prior_updates) != set(next_updates):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_REPRESENTATION_SELECTION_CHANGED", status="FAIL"
        )
    for identifier, update in prior_updates.items():
        replacement = next_updates[identifier]
        for field in ("object_id", "retained_object_digest", "reason"):
            if update.get(field) != replacement.get(field):
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_REPRESENTATION_CHANGED", status="FAIL"
                )
        if _evidence_paths(update.get("evidence")) != _evidence_paths(
            replacement.get("evidence")
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_REPRESENTATION_CHANGED", status="FAIL"
            )


def _mechanism_digest() -> str:
    """Bind receipts to the complete installed Verifier provider inventory."""

    executing_root = Path(package_manifest_migration.__file__).resolve().parents[1]
    return tier_zero_profile.value_digest(_package_inventory(executing_root))


def _plan_seal_payload(plan: dict[str, Any]) -> bytes:
    """Encode every publication-relevant field without embedding manifest bytes."""

    before = plan.get("before")
    after = plan.get("after")
    value = {
        "schema_version": plan.get("schema_version"),
        "status": plan.get("status"),
        "root": str(plan.get("root")),
        "target": str(plan.get("target")),
        "before_digest_claim": plan.get("before_digest"),
        "after_digest_claim": plan.get("after_digest"),
        "before_bytes_digest": _digest(before) if type(before) is bytes else None,
        "after_bytes_digest": _digest(after) if type(after) is bytes else None,
        "source_census_digest": plan.get("source_census_digest"),
        "source_binding": plan.get("source_binding"),
        "mechanism_digest": plan.get("mechanism_digest"),
        "target_mode": plan.get("target_mode"),
    }
    if "review_policy" in plan:
        # Present only for the recording policy, so strict seals are unchanged.
        value["review_policy"] = plan["review_policy"]
    return tier_zero_profile.canonical_bytes(value)


def _seal_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Return an in-process attested snapshot rather than a mutable bare plan."""

    sealed = dict(plan)
    sealed["plan_seal"] = "sha256:" + hmac.new(
        _PLAN_SEAL_KEY, _plan_seal_payload(sealed), "sha256"
    ).hexdigest()
    return sealed


def _is_compact_transport(document: Any) -> bool:
    return (
        type(document) is dict
        and document.get("schema_version")
        == package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    )


def _format_upgrade_required(raw: bytes) -> bool:
    """Name a root whose transport is not the exact compact version 6."""

    try:
        document = json.loads(raw)
    except (TypeError, ValueError):
        return False
    return not _is_compact_transport(document)


def _compact_transport(candidate: dict[str, Any]) -> dict[str, Any]:
    """Emit a refreshed inline version-5 candidate as compact version 6.

    ``migrate`` chooses the compact transport only when it is smaller, so a
    small valid root would be re-emitted inline on every refresh and could never
    become CURRENT. Refresh always asks for the compact transport instead. This
    is the same bounded representation change ``migrate`` applies to large
    roots; the transport, semantic, and package-selector gates that follow still
    validate it exactly.
    """

    if (
        candidate.get("schema_version")
        != package_manifest.PACKAGE_REPRESENTATION_SCHEMA
        or type(candidate.get("namespace")) is not dict
    ):
        return candidate
    compact = deepcopy(candidate)
    compact["namespace"] = namespace_manifest.compact_manifest(compact["namespace"])
    compact["schema_version"] = package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    compact.setdefault("representation_updates", [])
    namespace_manifest.structure_node_count(
        compact, limit=namespace_manifest.MAX_PACKAGE_NAMESPACE_NODES,
    )
    return compact


def _is_bound_census(binding: Any) -> bool:
    """Accept only a census that opened and closed on the same inventory."""

    return (
        type(binding) is dict
        and binding.get("status") == "BOUND"
        and _is_digest(binding.get("opening_census_digest"))
        and binding.get("opening_census_digest") == binding.get("closing_census_digest")
        and binding.get("unavailable") is None
    )


def _require_complete_candidate(
    candidate: dict[str, Any], opening_coordinate: str, repository: Any,
) -> None:
    """Admit a refresh candidate only as the exact current compact version 6.

    The candidate must be the compact transport, must bind the source census
    captured before generation, and must pass the same package selector used
    by admission. Any miss is refused before a byte of the root is written.
    """

    if (
        candidate.get("schema_version")
        != package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_CANDIDATE_NOT_COMPACT_V6", status="FAIL"
        )
    if _selected_source_refresh_coordinate(candidate) != opening_coordinate:
        raise ManifestRefreshError("MANIFEST_REFRESH_CANDIDATE_UNBOUND", status="FAIL")
    try:
        package_manifest.select(
            candidate,
            repository=repository["remote"],
            revision=repository["revision"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_CANDIDATE_INCOMPLETE", status="FAIL"
        ) from exc


def inspect_manifest_refresh(
    root: str | Path, *, review_policy: str = "refuse"
) -> dict[str, Any]:
    """Plan one deterministic refresh without changing repository bytes.

    ``review_policy`` ``"refuse"`` (the default) stops at every reviewed answer that
    needs a person.  ``"record"`` is the polish policy: an answer whose cited source
    changed meaning is reopened, remaining questions stay unanswered, and each gap is
    returned in the plan's ``review_gaps`` rather than blocking the receipt.
    Corruption (evidence citing a file the object does not own, a dropped profile,
    a weakened unrelated answer) still refuses under both policies.
    """

    if review_policy not in _REVIEW_POLICIES:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_REVIEW_POLICY_INVALID", status="FAIL"
        )
    record = review_policy == "record"
    selected_root = Path(root).resolve(strict=True)
    target = selected_root / "objects.vstd"
    metadata = _target_is_safe(target)
    try:
        before, document = namespace_manifest.read_manifest(target)
    except (OSError, TypeError, ValueError) as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_INPUT_INVALID", status="FAIL") from exc
    repository = document.get("repository", {})
    if repository.get("remote") != VERIFIER_REMOTE:
        digest = _digest(before)
        return _seal_plan({
            "schema_version": PLAN_SCHEMA,
            "status": "NOT_APPLICABLE",
            "root": selected_root,
            "target": target,
            "before": before,
            "after": before,
            "before_digest": digest,
            "after_digest": digest,
            "source_census_digest": None,
            "mechanism_digest": _mechanism_digest(),
            "target_mode": stat.S_IMODE(metadata.st_mode),
        })
    _require_installed_source_match(selected_root)
    opening_coordinate, _ = _source_coordinate(selected_root)
    try:
        live_repository = self_polish_estate._git_coordinate(selected_root)
    except (self_polish_estate.EstateError, OSError, ValueError) as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_SOURCE_UNAVAILABLE") from exc
    selected_repository = {
        "remote": live_repository["repository"],
        "revision": live_repository["revision"],
        "source_root": ".",
    }
    if not _exact_revision_rebinding(repository, selected_repository, live_repository):
        raise ManifestRefreshError("MANIFEST_REFRESH_REPOSITORY_BINDING_INVALID", status="FAIL")
    semantic_profile = _selected_source_semantic_profile(document)
    if semantic_profile is not None:
        _validated_semantic_profile(semantic_profile)
    # A matching census certifies source only.  An inline version-5 root must
    # still be remigrated to the compact transport before it is CURRENT.
    if (
        _selected_source_refresh_coordinate(document) == opening_coordinate
        and repository == selected_repository
        and _is_compact_transport(document)
    ):
        try:
            package_manifest.select(
                document,
                repository=repository["remote"],
                revision=repository["revision"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_INPUT_INVALID", status="FAIL"
            ) from exc
        closing_coordinate, _ = _source_coordinate(selected_root)
        try:
            current = namespace_manifest.read_manifest(target)[0]
        except (OSError, TypeError, ValueError) as exc:
            raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE") from exc
        if current != before or closing_coordinate != opening_coordinate:
            raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE")
        digest = _digest(before)
        return _seal_plan({
            "schema_version": PLAN_SCHEMA,
            "status": "CURRENT",
            "root": selected_root,
            "target": target,
            "before": before,
            "after": before,
            "before_digest": digest,
            "after_digest": digest,
            "source_census_digest": opening_coordinate,
            "mechanism_digest": _mechanism_digest(),
            "target_mode": stat.S_IMODE(metadata.st_mode),
        })
    if semantic_profile is None:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_SEMANTIC_BASELINE_REQUIRED",
            details={
                "review_required": [{
                    "path": "objects.vstd",
                    "reason": "SOURCE_SEMANTIC_PROFILE_NOT_SELECTED",
                    "object_id": "vstd-package-graph",
                    "classifications": [],
                    "obligations": ["VSTD-T0.1"],
                }],
            },
        )
    semantic_deltas = _source_semantic_deltas(selected_root, semantic_profile)
    if semantic_deltas and not record:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_REVIEW_REQUIRED",
            details={"review_required": semantic_deltas},
        )
    review_gaps: list[dict[str, Any]] = []
    # Open the census the candidate is generated from; close it after generation.
    # Only the same BOUND inventory may decide review, so an unreadable or moving
    # source refuses here, before any candidate is admitted or written.
    opening_census = package_manifest_migration._capture_source_inventory(selected_root)
    if opening_census["unavailable"] is not None:
        raise ManifestRefreshError("MANIFEST_REFRESH_SOURCE_INVENTORY_UNAVAILABLE")
    try:
        if record:
            migrated = package_manifest_migration.refresh_selected_manifest(
                selected_root,
                document,
                record_review_gaps=True,
                review_gaps=review_gaps,
                source_deltas=semantic_deltas,
            )
        else:
            migrated = package_manifest_migration.refresh_selected_manifest(
                selected_root, document
            )
        migrated["repository"] = selected_repository
        migrated = _compact_transport(migrated)
        after = _canonical(migrated)
        tier_zero_manifest._strict_json_document(after)
    except ManifestRefreshError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        cause_type = next(
            name
            for error_type, name in (
                (OSError, "OSError"),
                (RuntimeError, "RuntimeError"),
                (TypeError, "TypeError"),
                (ValueError, "ValueError"),
            )
            if isinstance(exc, error_type)
        )
        details = {"cause_type": cause_type}
        # Only a ValueError whose whole message is a stable refusal chain is named;
        # an arbitrary provider message (paths, text) is never copied out.
        message = str(exc)
        if (type(exc) is ValueError and len(message) <= _MAX_REFUSAL_CHAIN_BYTES
                and ".." not in message and _REFUSAL_CHAIN.fullmatch(message)):
            details["cause"] = message
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_PREVIEW_FAILED",
            status="FAIL",
            details=details,
        ) from exc
    closing_census = package_manifest_migration._capture_source_inventory(selected_root)
    source_binding = package_manifest_migration._bind_source_inventory(
        opening_census, closing_census
    )
    if source_binding["status"] != "BOUND":
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_SOURCE_INVENTORY_" + source_binding["status"]
        )
    _require_complete_candidate(migrated, opening_coordinate, selected_repository)
    if record:
        regenerated: list[dict[str, Any]] = []
        withdrawal_authority = _documented_withdrawal_authority(selected_root)
        transition_observed = _retention_prune_observation(
            selected_root, document, migrated, withdrawal_authority
        )
        _require_non_weakening(
            document,
            migrated,
            reopened=_reopened_coordinates(semantic_deltas),
            regenerated=regenerated,
            source_digests=opening_census["inventory"],
            observed=transition_observed,
            documented_retention_keys=(
                package_manifest_migration._documented_applies_keys(
                    selected_root
                )
            ),
            documented_withdrawal_authority=withdrawal_authority,
            live_repository=live_repository,
        )
        review_gaps.extend(regenerated)
    else:
        if repository == selected_repository:
            _require_non_weakening(document, migrated)
        else:
            _require_non_weakening(document, migrated, live_repository=live_repository)
    migrated_profile = _selected_source_semantic_profile(migrated)
    if migrated_profile is None:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_SEMANTIC_PROFILE_DROPPED", status="FAIL"
        )
    if not record:
        transition_deltas = _semantic_profile_transition_deltas(
            semantic_profile, migrated_profile
        )
        if transition_deltas:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_REVIEW_REQUIRED",
                details={"review_required": transition_deltas},
            )
    gaps = package_manifest_migration._review_gap_report(
        migrated, root=selected_root, source_binding=source_binding
    )
    if record:
        # Unanswered questions are the receipt's content; only corruption refuses.
        if gaps["status"] == "FAIL" or gaps["unowned_evidence_count"] != 0:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_REVIEW_GAPS_REMAIN", status="UNKNOWN"
            )
    elif gaps["status"] != "PASS" or any(
        gaps[key] != 0
        for key in (
            "unresolved_decision_count",
            "incomplete_obligation_count",
            "unowned_evidence_count",
        )
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_REVIEW_GAPS_REMAIN", status="UNKNOWN"
        )
    closing_coordinate, _ = _source_coordinate(selected_root)
    try:
        current = namespace_manifest.read_manifest(target)[0]
    except (OSError, TypeError, ValueError) as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE") from exc
    if current != before or opening_coordinate != closing_coordinate:
        raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE")
    plan = {
        "schema_version": PLAN_SCHEMA,
        "status": "CURRENT" if after == before else "REFRESH_REQUIRED",
        "root": selected_root,
        "target": target,
        "before": before,
        "after": after,
        "before_digest": _digest(before),
        "after_digest": _digest(after),
        "source_census_digest": opening_coordinate,
        "source_binding": gaps["source_binding"],
        "mechanism_digest": _mechanism_digest(),
        "target_mode": stat.S_IMODE(metadata.st_mode),
    }
    if record:
        # The gaps are informational: the manifest itself carries every open
        # question.  The policy is sealed because publication and recovery must
        # repeat the same comparison that admitted this candidate.
        plan["review_policy"] = "record"
        plan["review_gaps"] = review_gaps
    return _seal_plan(plan)


def _default_journal_root() -> Path:
    selected = os.environ.get("VSTD_STATE_DIR")
    if selected:
        return Path(selected).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "vstd"
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "vstd"
    return Path.home() / ".local" / "state" / "vstd"


def _outside_root(directory: Path, root: Path) -> Path:
    selected = _journal_root_outside_repository(directory, root)
    try:
        selected.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_UNAVAILABLE") from exc
    return selected


def _journal_root_outside_repository(directory: Path, root: Path) -> Path:
    """Resolve the journal location without creating it.

    Check mode uses this narrower helper so merely looking for an interrupted
    transaction cannot create a state directory or otherwise mutate storage.
    """

    selected = directory.expanduser().resolve()
    if selected == root or root in selected.parents:
        raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_INSIDE_REPOSITORY")
    return selected


def _attempt_directory_fsync(directory: Path) -> bool:
    """Best-effort directory synchronization without overstating Windows.

    A successful file ``fsync`` does not itself establish durable directory
    metadata.  Portable Operating System Interface (POSIX) platforms expose a
    directory descriptor that can be
    synchronized after creation or replacement.  Python does not expose an
    equivalent durable-directory primitive on Windows, so that platform stays
    explicitly unestablished even though the file handles themselves flush.
    """

    if os.name == "nt":
        return False
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return False
    try:
        os.fsync(descriptor)
    except OSError:
        return False
    finally:
        os.close(descriptor)
    return True


def _exclusive_or_equal(path: Path, raw: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_CONFLICT") from exc
        if existing != raw:
            raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_CONFLICT")
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_UNAVAILABLE") from exc


def _transaction_identity(
    root: Path,
    before_digest: str,
    after_digest: str,
    source_census_digest: str,
    mechanism_digest: str,
) -> str:
    """Bind a cooperative lock to one root and one byte transition."""

    return tier_zero_profile.value_digest({
        "root": str(root),
        "before_digest": before_digest,
        "after_digest": after_digest,
        "source_census_digest": source_census_digest,
        "mechanism_digest": mechanism_digest,
    })


def _transaction_directory(
    base: Path, before_digest: str, after_digest: str,
) -> Path:
    return base / "transactions" / (
        before_digest.removeprefix("sha256:")
        + "-"
        + after_digest.removeprefix("sha256:")
    )


def _advisory_lock(descriptor: int, *, blocking: bool) -> bool:
    """Acquire a one-byte lock where the operating system (OS) supports it."""

    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            msvcrt.locking(descriptor, mode, 1)
        except OSError:
            return False
        return True
    try:
        import fcntl
    except ImportError:
        return False
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(descriptor, flags)
    except OSError:
        return False
    return True


def _advisory_unlock(descriptor: int) -> None:
    """Release a lock acquired by :func:`_advisory_lock`."""

    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except (ImportError, OSError):
        pass


def _public_plan(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in plan.items()
        if key not in {
            "root", "target", "before", "after", "target_mode", "plan_seal",
            "review_policy", "review_gaps",
        }
    }


def _is_digest(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _require_plan_non_weakening(
    plan: dict[str, Any], before_document: Any, after_document: Any,
) -> None:
    """Repeat the comparison under the policy that produced the plan."""

    before_repository = before_document.get("repository") if type(before_document) is dict else None
    after_repository = after_document.get("repository") if type(after_document) is dict else None
    live_repository = None
    if before_repository != after_repository:
        try:
            live_repository = self_polish_estate._git_coordinate(Path(plan["root"]))
        except (self_polish_estate.EstateError, OSError, ValueError) as exc:
            raise ManifestRefreshError("MANIFEST_REFRESH_SOURCE_UNAVAILABLE") from exc
    if plan.get("review_policy") == "record":
        # The recording comparison binds re-answered refutations to the current
        # source bytes, so it reads the same inventory the plan was made from.
        inventory = package_manifest_migration._capture_source_inventory(
            Path(plan["root"])
        )
        plan_root = Path(plan["root"])
        withdrawal_authority = _documented_withdrawal_authority(plan_root)
        transition_observed = _retention_prune_observation(
            plan_root, before_document, after_document, withdrawal_authority
        )
        _require_non_weakening(
            before_document,
            after_document,
            reopened={},
            regenerated=[],
            source_digests=inventory["inventory"],
            observed=transition_observed,
            documented_retention_keys=(
                package_manifest_migration._documented_applies_keys(
                    plan_root
                )
            ),
            documented_withdrawal_authority=withdrawal_authority,
            live_repository=live_repository,
        )
    else:
        if live_repository is None:
            _require_non_weakening(before_document, after_document)
        else:
            _require_non_weakening(before_document, after_document, live_repository=live_repository)


def _validate_publish_plan(
    plan: dict[str, Any],
) -> tuple[Path, Path, os.stat_result]:
    """Re-establish a sealed plan's local invariants before any side effect."""

    if type(plan) is not dict or plan.get("schema_version") != PLAN_SCHEMA:
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_INVALID", status="FAIL")
    seal = plan.get("plan_seal")
    if type(seal) is not str or not seal.startswith("sha256:"):
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_UNSEALED", status="FAIL")
    expected_seal = "sha256:" + hmac.new(
        _PLAN_SEAL_KEY, _plan_seal_payload(plan), "sha256"
    ).hexdigest()
    if not hmac.compare_digest(seal, expected_seal):
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_MUTATED", status="FAIL")

    try:
        root = Path(plan["root"]).resolve(strict=True)
        target = Path(plan["target"])
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_INVALID", status="FAIL") from exc
    expected_target = root / "objects.vstd"
    if target != expected_target:
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_TARGET_MISMATCH", status="FAIL")
    metadata = _target_is_safe(expected_target)

    before = plan.get("before")
    after = plan.get("after")
    if type(before) is not bytes or type(after) is not bytes:
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_INVALID", status="FAIL")
    if (
        plan.get("before_digest") != _digest(before)
        or plan.get("after_digest") != _digest(after)
    ):
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_DIGEST_MISMATCH", status="FAIL")
    if plan.get("mechanism_digest") != _mechanism_digest():
        raise ManifestRefreshError("MANIFEST_REFRESH_MECHANISM_CHANGED")
    if (
        type(plan.get("target_mode")) is not int
        or plan["target_mode"] != stat.S_IMODE(metadata.st_mode)
    ):
        raise ManifestRefreshError("MANIFEST_REFRESH_TARGET_MODE_CHANGED")
    try:
        current = expected_target.read_bytes()
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE") from exc
    if current != before:
        raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE")

    try:
        before_document = tier_zero_manifest._strict_json_document(before)
        after_document = tier_zero_manifest._strict_json_document(after)
    except (TypeError, ValueError) as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_DOCUMENT_INVALID", status="FAIL") from exc
    status = plan.get("status")
    source_coordinate = plan.get("source_census_digest")
    if status == "NOT_APPLICABLE":
        valid_status = before == after and source_coordinate is None
    elif status == "CURRENT":
        valid_status = before == after and _is_digest(source_coordinate)
    elif status == "REFRESH_REQUIRED":
        if not _is_bound_census(plan.get("source_binding")):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_PLAN_SOURCE_UNBOUND", status="FAIL"
            )
        valid_status = before != after and _is_digest(source_coordinate)
        if valid_status:
            _require_plan_non_weakening(plan, before_document, after_document)
    else:
        valid_status = False
    if not valid_status:
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_STATUS_INVALID", status="FAIL")
    return root, expected_target, metadata


@contextmanager
def _transaction_lock(base: Path, identity: dict[str, Any]):
    """Serialize publishers and leave a machine-checkable crash identity."""

    lock = base / "active.lock"
    try:
        descriptor = os.open(
            lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
        )
    except FileExistsError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_TRANSACTION_BUSY") from exc
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_UNAVAILABLE") from exc
    acquired = False
    retention = {"recovery_required": False}
    try:
        # Windows byte-range locks require the selected range to exist.
        os.write(descriptor, b"\0")
        os.fsync(descriptor)
        acquired = _advisory_lock(descriptor, blocking=True)
        if not acquired:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_LOCK_LIVENESS_UNAVAILABLE"
            )
        raw = _canonical(identity)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, raw)
        os.fsync(descriptor)
        _attempt_directory_fsync(base)
        yield retention
    finally:
        if acquired:
            _advisory_unlock(descriptor)
        os.close(descriptor)
        if not retention["recovery_required"]:
            try:
                lock.unlink()
                _attempt_directory_fsync(base)
            except FileNotFoundError:
                pass


def _active_transaction_exists_read_only(
    plan: dict[str, Any], *, journal_root: str | Path | None,
) -> bool:
    """Observe an unresolved transaction without acquiring or creating state."""

    root, _, _ = _validate_publish_plan(plan)
    selected_journal = _journal_root_outside_repository(
        Path(journal_root) if journal_root is not None else _default_journal_root(),
        root,
    )
    root_key = _digest(str(root).encode("utf-8")).removeprefix("sha256:")
    lock = selected_journal / "manifest-refresh" / root_key / "active.lock"
    # A broken link or other non-regular directory entry is still unresolved
    # state. `lexists` observes it without following or modifying the entry.
    return os.path.lexists(lock)


def _strict_canonical_journal(path: Path, code: str) -> tuple[bytes, dict[str, Any]]:
    """Read one journal record without accepting aliases or duplicate keys."""

    try:
        raw = path.read_bytes()
        value = tier_zero_manifest._strict_json_document(raw)
    except (OSError, TypeError, ValueError) as exc:
        raise ManifestRefreshError(code) from exc
    if type(value) is not dict or raw != _canonical(value):
        raise ManifestRefreshError(code)
    return raw, value


def _validate_recovery_lock(
    raw: bytes,
    body: dict[str, Any],
    *,
    root: Path,
) -> tuple[str, str, str, str]:
    """Return the exact transaction coordinates named by a stale lock."""

    expected_keys = {
        "schema_version",
        "owner_pid",
        "root_digest",
        "transaction_id",
        "before_digest",
        "after_digest",
        "source_census_digest",
        "mechanism_digest",
        "prepared_receipt_digest",
    }
    before_digest = body.get("before_digest")
    after_digest = body.get("after_digest")
    source_census_digest = body.get("source_census_digest")
    mechanism_digest = body.get("mechanism_digest")
    prepared_receipt_digest = body.get("prepared_receipt_digest")
    transaction_id = body.get("transaction_id")
    if (
        raw != _canonical(body)
        or set(body) != expected_keys
        or body.get("schema_version") != LOCK_SCHEMA
        or type(body.get("owner_pid")) is not int
        or body["owner_pid"] <= 0
        or body.get("root_digest") != _digest(str(root).encode("utf-8"))
        or not _is_digest(before_digest)
        or not _is_digest(after_digest)
        or not _is_digest(source_census_digest)
        or not _is_digest(mechanism_digest)
        or not _is_digest(prepared_receipt_digest)
        or transaction_id
        != _transaction_identity(
            root,
            before_digest,
            after_digest,
            source_census_digest,
            mechanism_digest,
        )
    ):
        raise ManifestRefreshError("MANIFEST_REFRESH_RECOVERY_LOCK_INVALID")
    return transaction_id, before_digest, after_digest, prepared_receipt_digest


def _validate_recovery_prepared(
    raw: bytes,
    body: dict[str, Any],
    *,
    transaction_id: str,
    before_digest: str,
    after_digest: str,
    prepared_receipt_digest: str,
    backup: Path,
) -> bytes:
    """Revalidate PREPARED plus retained original bytes independently."""

    expected_keys = {
        "schema_version",
        "phase",
        "transaction_id",
        "status",
        "before_digest",
        "after_digest",
        "source_census_digest",
        "source_binding",
        "mechanism_digest",
        "backup_digest",
        "backup_locator",
        "refresh_is_admission",
        "refresh_is_polish",
    }
    source_binding = body.get("source_binding")
    if (
        set(body) != expected_keys
        or body.get("schema_version") != RECEIPT_SCHEMA
        or body.get("phase") != "PREPARED"
        or body.get("status") != "REFRESH_REQUIRED"
        or body.get("transaction_id") != transaction_id
        or body.get("before_digest") != before_digest
        or body.get("after_digest") != after_digest
        or _digest(raw) != prepared_receipt_digest
        or body.get("backup_digest") != before_digest
        or body.get("backup_locator") != str(backup)
        or body.get("refresh_is_admission") is not False
        or body.get("refresh_is_polish") is not False
        or not _is_digest(body.get("source_census_digest"))
        or not _is_digest(body.get("mechanism_digest"))
        or not _is_bound_census(source_binding)
        or set(source_binding) != {
            "status",
            "opening_census_digest",
            "closing_census_digest",
            "unavailable",
        }
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_RECOVERY_JOURNAL_CONFLICT"
        )
    try:
        retained = backup.read_bytes()
    except OSError as exc:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_RECOVERY_BACKUP_UNAVAILABLE"
        ) from exc
    if _digest(retained) != before_digest:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_RECOVERY_BACKUP_CONFLICT"
        )
    return retained


def _recovery_receipt(
    prepared: dict[str, Any], prepared_raw: bytes, backup: Path,
) -> tuple[dict[str, Any], bytes]:
    """Reconstruct the only compatible committed receipt from fresh checks."""

    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "status": "REMIGRATED",
        "before_digest": prepared["before_digest"],
        "after_digest": prepared["after_digest"],
        "backup_digest": prepared["before_digest"],
        "backup_locator": str(backup),
        "source_census_digest": prepared["source_census_digest"],
        "migration_mechanism_digest": prepared["mechanism_digest"],
        "prepared_receipt_digest": _digest(prepared_raw),
        # End-to-end directory durability is intentionally not promoted.  The
        # implementation attempts real POSIX directory fsyncs, while Windows
        # has no established equivalent through this zero-dependency surface.
        "directory_durability": "NOT_ESTABLISHED",
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    return receipt, _canonical({
        **receipt,
        "phase": "COMMITTED",
        "source_binding": prepared["source_binding"],
    })


def _archive_recovered_lock(
    transition: Path, lock_raw: bytes, descriptor: int,
) -> None:
    """Preserve stale-lock evidence before making the lock reusable."""

    suffix = _digest(lock_raw).removeprefix("sha256:")[:12]
    _exclusive_or_equal(transition / f"recovered-lock-{suffix}.json", lock_raw)
    tombstone = _canonical({
        "schema_version": LOCK_SCHEMA,
        "state": "RECOVERED",
        "archived_lock_digest": _digest(lock_raw),
    })
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    os.write(descriptor, tombstone)
    os.fsync(descriptor)
    _attempt_directory_fsync(transition)


def _revalidate_recovery_boundary(
    root: Path,
    target: Path,
    *,
    expected_target: bytes,
    expected_source_coordinate: str,
) -> None:
    """Close the restart census immediately before recording a transition."""

    try:
        observed_target = target.read_bytes()
        observed_source_coordinate, _ = _source_coordinate(root)
    except (OSError, ManifestRefreshError) as exc:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_RECOVERY_CONCURRENT_CHANGE"
        ) from exc
    if (
        observed_target != expected_target
        or observed_source_coordinate != expected_source_coordinate
    ):
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_RECOVERY_CONCURRENT_CHANGE"
        )


def _recover_interrupted_transaction(
    plan: dict[str, Any], *, journal_root: str | Path | None,
) -> dict[str, Any] | None:
    """Reconcile one dead publisher only from newly revalidated current state.

    ``plan`` is produced again in the restarting process.  The old process's
    hash-based message authentication code (HMAC) is deliberately irrelevant:
    the recovery path rechecks source,
    selected target bytes, candidate digest and non-weakening before it may
    retire a stale lock or synthesize the missing committed receipt.
    """

    root, target, _ = _validate_publish_plan(plan)
    selected_journal = (
        Path(journal_root) if journal_root is not None else _default_journal_root()
    ).expanduser().resolve()
    root_key = _digest(str(root).encode("utf-8")).removeprefix("sha256:")
    base = selected_journal / "manifest-refresh" / root_key
    lock = base / "active.lock"
    if not lock.exists():
        return None
    if selected_journal == root or root in selected_journal.parents:
        raise ManifestRefreshError(
            "MANIFEST_REFRESH_JOURNAL_INSIDE_REPOSITORY"
        )
    try:
        descriptor = os.open(lock, os.O_RDWR)
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_RECOVERY_LOCK_UNAVAILABLE") from exc
    acquired = False
    retire = False
    try:
        acquired = _advisory_lock(descriptor, blocking=False)
        if not acquired:
            raise ManifestRefreshError("MANIFEST_REFRESH_TRANSACTION_BUSY")
        os.lseek(descriptor, 0, os.SEEK_SET)
        lock_raw = os.read(descriptor, 1024 * 1024)
        try:
            lock_body = tier_zero_manifest._strict_json_document(lock_raw)
        except (TypeError, ValueError) as exc:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_LOCK_INVALID"
            ) from exc
        if type(lock_body) is not dict:
            raise ManifestRefreshError("MANIFEST_REFRESH_RECOVERY_LOCK_INVALID")
        (
            transaction_id,
            before_digest,
            after_digest,
            prepared_receipt_digest,
        ) = _validate_recovery_lock(lock_raw, lock_body, root=root)
        transition = _transaction_directory(base, before_digest, after_digest)
        backup = base / "backups" / (
            before_digest.removeprefix("sha256:") + ".vstd"
        )
        prepared_raw, prepared = _strict_canonical_journal(
            transition / "prepared.json",
            "MANIFEST_REFRESH_RECOVERY_JOURNAL_CONFLICT",
        )
        retained = _validate_recovery_prepared(
            prepared_raw,
            prepared,
            transaction_id=transaction_id,
            before_digest=before_digest,
            after_digest=after_digest,
            prepared_receipt_digest=prepared_receipt_digest,
            backup=backup,
        )
        if (
            prepared.get("source_census_digest")
            != lock_body.get("source_census_digest")
            or prepared.get("mechanism_digest")
            != lock_body.get("mechanism_digest")
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_JOURNAL_CONFLICT"
            )
        try:
            current = target.read_bytes()
        except OSError as exc:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_TARGET_UNAVAILABLE"
            ) from exc
        current_digest = _digest(current)
        if current_digest not in {before_digest, after_digest}:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_TARGET_AMBIGUOUS"
            )
        if (
            prepared.get("mechanism_digest") != plan.get("mechanism_digest")
            or prepared.get("source_census_digest")
            != plan.get("source_census_digest")
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_TRANSACTION_MISMATCH"
            )

        committed_path = transition / "committed.json"
        if current_digest == before_digest:
            if committed_path.exists():
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_RECOVERY_TARGET_AMBIGUOUS"
                )
            if (
                plan.get("status") != "REFRESH_REQUIRED"
                or plan.get("before_digest") != before_digest
                or plan.get("after_digest") != after_digest
                or not _is_bound_census(plan.get("source_binding"))
            ):
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_RECOVERY_TRANSACTION_MISMATCH"
                )
            _revalidate_recovery_boundary(
                root,
                target,
                expected_target=current,
                expected_source_coordinate=prepared["source_census_digest"],
            )
            _write_aborted_receipt(
                transition,
                prepared_raw,
                plan,
                backup=backup,
                phase="ABANDONED_PREPARE",
                observed_target=current,
                observed_source_coordinate=plan["source_census_digest"],
            )
            _archive_recovered_lock(transition, lock_raw, descriptor)
            retire = True
            return None

        if (
            plan.get("status") != "CURRENT"
            or plan.get("before_digest") != after_digest
            or plan.get("after_digest") != after_digest
        ):
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_TRANSACTION_MISMATCH"
            )
        try:
            before_document = tier_zero_manifest._strict_json_document(retained)
            after_document = tier_zero_manifest._strict_json_document(current)
        except (TypeError, ValueError) as exc:
            raise ManifestRefreshError(
                "MANIFEST_REFRESH_RECOVERY_DOCUMENT_INVALID", status="FAIL"
            ) from exc
        _require_plan_non_weakening(plan, before_document, after_document)
        _revalidate_recovery_boundary(
            root,
            target,
            expected_target=current,
            expected_source_coordinate=prepared["source_census_digest"],
        )
        receipt, committed = _recovery_receipt(prepared, prepared_raw, backup)
        if committed_path.exists():
            existing, _ = _strict_canonical_journal(
                committed_path,
                "MANIFEST_REFRESH_RECOVERY_COMMITTED_CONFLICT",
            )
            if existing != committed:
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_RECOVERY_COMMITTED_CONFLICT"
                )
        else:
            _exclusive_or_equal(committed_path, committed)
            _attempt_directory_fsync(transition)
        _archive_recovered_lock(transition, lock_raw, descriptor)
        retire = True
        return receipt
    finally:
        if acquired:
            _advisory_unlock(descriptor)
        os.close(descriptor)
        if retire:
            try:
                lock.unlink()
                _attempt_directory_fsync(base)
            except FileNotFoundError:
                pass


def _write_aborted_receipt(
    transition: Path,
    prepared: bytes,
    plan: dict[str, Any],
    *,
    backup: Path,
    phase: str,
    observed_target: bytes | None,
    observed_source_coordinate: str | None,
) -> None:
    body = {
        "schema_version": RECEIPT_SCHEMA,
        "phase": phase,
        **_public_plan(plan),
        "backup_digest": _digest(plan["before"]),
        "backup_locator": str(backup),
        "prepared_receipt_digest": _digest(prepared),
        "observed_target_digest": (
            _digest(observed_target) if observed_target is not None else None
        ),
        "observed_source_census_digest": observed_source_coordinate,
        "target_mutation_occurred": observed_target != plan["before"],
        "directory_durability": "NOT_ESTABLISHED",
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    raw = _canonical(body)
    suffix = _digest(raw).removeprefix("sha256:")[:12]
    _exclusive_or_equal(
        transition / (phase.lower() + "-" + suffix + ".json"), raw
    )


def publish_manifest_refresh(
    plan: dict[str, Any], *, journal_root: str | Path | None = None
) -> dict[str, Any]:
    """Publish one inspected plan with an external recovery journal."""

    root, target, _ = _validate_publish_plan(plan)
    if plan.get("status") in {"CURRENT", "NOT_APPLICABLE"}:
        return {
            "schema_version": RECEIPT_SCHEMA,
            "status": plan["status"],
            "before_digest": plan["before_digest"],
            "after_digest": plan["after_digest"],
            "backup_digest": None,
            "source_census_digest": plan["source_census_digest"],
            "migration_mechanism_digest": plan["mechanism_digest"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }
    if plan.get("status") != "REFRESH_REQUIRED":
        raise ManifestRefreshError("MANIFEST_REFRESH_PLAN_INVALID", status="FAIL")
    root_key = _digest(str(root).encode("utf-8")).removeprefix("sha256:")
    base = _outside_root(
        Path(journal_root) if journal_root is not None else _default_journal_root(),
        root,
    ) / "manifest-refresh" / root_key
    backups = base / "backups"
    transition = _transaction_directory(
        base, plan["before_digest"], plan["after_digest"]
    )
    transaction_id = _transaction_identity(
        root,
        plan["before_digest"],
        plan["after_digest"],
        plan["source_census_digest"],
        plan["mechanism_digest"],
    )
    backup = backups / (
        plan["before_digest"].removeprefix("sha256:") + ".vstd"
    )
    prepared_body = {
        **_public_plan(plan),
        "schema_version": RECEIPT_SCHEMA,
        "phase": "PREPARED",
        "transaction_id": transaction_id,
        "backup_digest": _digest(plan["before"]),
        "backup_locator": str(backup),
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    prepared = _canonical(prepared_body)
    lock_identity = {
        "schema_version": LOCK_SCHEMA,
        "owner_pid": os.getpid(),
        "root_digest": _digest(str(root).encode("utf-8")),
        "transaction_id": transaction_id,
        "before_digest": plan["before_digest"],
        "after_digest": plan["after_digest"],
        "source_census_digest": plan["source_census_digest"],
        "mechanism_digest": plan["mechanism_digest"],
        "prepared_receipt_digest": _digest(prepared),
    }
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_UNAVAILABLE") from exc

    with _transaction_lock(base, lock_identity) as lock_retention:
        try:
            backups.mkdir(parents=True, exist_ok=True)
            transition.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ManifestRefreshError("MANIFEST_REFRESH_JOURNAL_UNAVAILABLE") from exc
        _exclusive_or_equal(backup, plan["before"])
        _attempt_directory_fsync(backups)
        _exclusive_or_equal(transition / "prepared.json", prepared)
        _attempt_directory_fsync(transition)
        # The durable PREPARED receipt and exact backup now support recovery.
        # Preserve the lock unless a later branch proves a terminal committed
        # or safely abandoned state.
        lock_retention["recovery_required"] = True

        temporary: Path | None = None
        try:
            # The source census counts every untracked file in the root, including
            # this publication's own staged temporary, so the coordinate is read
            # before that file exists.  A source change after this read is caught by
            # the closing coordinate below, exactly as one during the replace is.
            try:
                current_coordinate, _ = _source_coordinate(root)
                current = target.read_bytes()
            except (OSError, ManifestRefreshError) as exc:
                _write_aborted_receipt(
                    transition,
                    prepared,
                    plan,
                    backup=backup,
                    phase="ABORTED_BEFORE_REPLACE",
                    observed_target=None,
                    observed_source_coordinate=None,
                )
                lock_retention["recovery_required"] = False
                if isinstance(exc, ManifestRefreshError):
                    raise
                raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE") from exc
            if (
                current != plan["before"]
                or current_coordinate != plan["source_census_digest"]
            ):
                _write_aborted_receipt(
                    transition,
                    prepared,
                    plan,
                    backup=backup,
                    phase="ABORTED_BEFORE_REPLACE",
                    observed_target=current,
                    observed_source_coordinate=current_coordinate,
                )
                lock_retention["recovery_required"] = False
                raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE")

            try:
                with tempfile.NamedTemporaryFile(
                    dir=target.parent,
                    prefix=".vstd-refresh-",
                    delete=False,
                ) as stream:
                    temporary = Path(stream.name)
                    stream.write(plan["after"])
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, plan["target_mode"])
            except OSError as exc:
                raise ManifestRefreshError("MANIFEST_REFRESH_TEMPORARY_UNAVAILABLE") from exc

            # Staging took time; the target is the one input that can still race.
            try:
                staged_against = target.read_bytes()
            except OSError:
                staged_against = None
            if staged_against != plan["before"]:
                _write_aborted_receipt(
                    transition,
                    prepared,
                    plan,
                    backup=backup,
                    phase="ABORTED_BEFORE_REPLACE",
                    observed_target=staged_against,
                    observed_source_coordinate=current_coordinate,
                )
                lock_retention["recovery_required"] = False
                raise ManifestRefreshError("MANIFEST_REFRESH_CONCURRENT_CHANGE")

            try:
                os.replace(temporary, target)
                temporary = None
                _attempt_directory_fsync(target.parent)
            except OSError as exc:
                try:
                    observed_target = target.read_bytes()
                except OSError:
                    observed_target = None
                competing = observed_target != plan["before"]
                _write_aborted_receipt(
                    transition,
                    prepared,
                    plan,
                    backup=backup,
                    phase=(
                        "ABORTED_COMPETING_TARGET"
                        if competing
                        else "ABORTED_REPLACE_FAILED"
                    ),
                    observed_target=observed_target,
                    observed_source_coordinate=current_coordinate,
                )
                # An OS replace can report failure after changing the directory
                # entry. Only unchanged opening bytes prove safe retirement.
                lock_retention["recovery_required"] = competing
                code = (
                    "MANIFEST_REFRESH_CONCURRENT_CHANGE"
                    if competing
                    else "MANIFEST_REFRESH_REPLACE_FAILED"
                )
                raise ManifestRefreshError(code) from exc

            published: bytes | None
            closing_coordinate: str | None
            try:
                published = target.read_bytes()
            except OSError:
                published = None
            try:
                closing_coordinate, _ = _source_coordinate(root)
            except ManifestRefreshError:
                closing_coordinate = None
            if (
                published != plan["after"]
                or closing_coordinate != plan["source_census_digest"]
            ):
                _write_aborted_receipt(
                    transition,
                    prepared,
                    plan,
                    backup=backup,
                    phase="PUBLISHED_STALE",
                    observed_target=published,
                    observed_source_coordinate=closing_coordinate,
                )
                raise ManifestRefreshError("MANIFEST_REFRESH_PUBLISHED_STALE")

            receipt = {
                "schema_version": RECEIPT_SCHEMA,
                "status": "REMIGRATED",
                "before_digest": plan["before_digest"],
                "after_digest": plan["after_digest"],
                "backup_digest": _digest(plan["before"]),
                "backup_locator": str(backup),
                "source_census_digest": plan["source_census_digest"],
                "migration_mechanism_digest": plan["mechanism_digest"],
                "prepared_receipt_digest": _digest(prepared),
                "directory_durability": "NOT_ESTABLISHED",
                "refresh_is_admission": False,
                "refresh_is_polish": False,
            }
            # The journal records the census that bound this publication; the
            # returned receipt keeps the exact public key set consumers validate.
            committed = _canonical({
                **receipt,
                "phase": "COMMITTED",
                "source_binding": plan["source_binding"],
            })
            try:
                _exclusive_or_equal(transition / "committed.json", committed)
                _attempt_directory_fsync(transition)
            except ManifestRefreshError as exc:
                try:
                    _write_aborted_receipt(
                        transition,
                        prepared,
                        plan,
                        backup=backup,
                        phase="COMMIT_RECEIPT_UNAVAILABLE",
                        observed_target=published,
                        observed_source_coordinate=closing_coordinate,
                    )
                except ManifestRefreshError:
                    pass
                raise ManifestRefreshError(
                    "MANIFEST_REFRESH_COMMIT_RECEIPT_UNAVAILABLE"
                ) from exc
            lock_retention["recovery_required"] = False
            return receipt
        finally:
            if temporary is not None and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass


def ensure_current_manifest(
    root: str | Path,
    *,
    mode: str = "auto",
    journal_root: str | Path | None = None,
    review_policy: str = "refuse",
) -> dict[str, Any]:
    """Inspect every invocation; publish only in explicit automatic mode."""

    if mode not in {"auto", "check"}:
        raise ManifestRefreshError("MANIFEST_REFRESH_MODE_INVALID", status="FAIL")
    if review_policy == "refuse":
        plan = inspect_manifest_refresh(root)
    else:
        plan = inspect_manifest_refresh(root, review_policy=review_policy)
    if mode == "check" and _active_transaction_exists_read_only(
        plan, journal_root=journal_root
    ):
        return {
            "schema_version": OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "before_digest": plan["before_digest"],
            "after_digest": plan["after_digest"],
            "backup_digest": None,
            "source_census_digest": plan["source_census_digest"],
            "migration_mechanism_digest": plan["mechanism_digest"],
            "blockers": ["MANIFEST_REFRESH_RECOVERY_REQUIRED_READ_ONLY"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }
    if mode == "auto":
        recovered = _recover_interrupted_transaction(
            plan, journal_root=journal_root
        )
        if recovered is not None:
            return recovered
    if plan["status"] != "REFRESH_REQUIRED":
        return publish_manifest_refresh(plan, journal_root=journal_root)
    if mode == "check":
        blockers = ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"]
        if _format_upgrade_required(plan["before"]):
            # Auto mode remigrates this root once to the compact version 6.
            blockers.append("MANIFEST_REFRESH_FORMAT_UPGRADE_REQUIRED")
        return {
            "schema_version": OUTCOME_SCHEMA,
            "status": "REFRESH_REQUIRED",
            "before_digest": plan["before_digest"],
            "after_digest": plan["after_digest"],
            "backup_digest": None,
            "source_census_digest": plan["source_census_digest"],
            "migration_mechanism_digest": plan["mechanism_digest"],
            "blockers": blockers,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }
    return publish_manifest_refresh(plan, journal_root=journal_root)
