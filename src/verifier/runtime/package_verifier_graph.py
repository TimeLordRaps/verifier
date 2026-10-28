"""Compile package polish as one recursive Verifier Standard (VSTD) VERIFIER graph.

The root ``objects.vstd`` graph remains the typed subject representation.  This
module projects the checking mechanisms that evaluate its obligation instances
into member ``VERIFIER`` nodes and represents their cumulative result as the
selected aggregate ``VERIFIER``.  The aggregate result is never accepted as
evidence for one of its own members; member outcomes come only from the already
executed obligation rows.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping, Sequence

from verifier.core import namespace
from verifier.runtime import core_obligation_union as binding


SCHEMA = "verifier-package-self-polish-graph-1"
_STATUSES = {"PASS", "FAIL", "UNKNOWN"}


class VerifierGraphError(ValueError):
    """A package obligation cannot be assigned to one declared verifier."""


def _status(values: Iterable[str]) -> str:
    selected = tuple(values)
    if any(value == "FAIL" for value in selected):
        return "FAIL"
    if selected and all(value == "PASS" for value in selected):
        return "PASS"
    return "UNKNOWN"


def _mechanism_surface_candidates(mechanism: str) -> tuple[str, ...]:
    """Return every exact Python surface spelling a dotted callable can name."""
    if type(mechanism) is not str or not mechanism.strip():
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_MECHANISM_INVALID")
    parts = mechanism.split(".")
    if len(parts) < 2 or any(not part for part in parts):
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_MECHANISM_INVALID")
    return tuple(
        "python:src/" + "/".join(parts[:cut]) + ".py:" + ".".join(parts[cut:])
        for cut in range(len(parts) - 1, 0, -1)
    )


def _semantic_rows(document: Mapping[str, Any] | None) -> tuple[dict[str, Any], ...]:
    if type(document) is not dict:
        return ()
    declared = document.get("namespace")
    rows = declared.get("objects") if type(declared) is dict else None
    if type(rows) is not list or not all(type(row) is dict for row in rows):
        return ()
    return tuple(rows)


def _owner_index(rows: Sequence[Mapping[str, Any]]) -> dict[str, tuple[str, ...]]:
    owners: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        object_id = row.get("object_id")
        surfaces = row.get("surfaces")
        if type(object_id) is not str or type(surfaces) is not list:
            continue
        for surface in surfaces:
            if type(surface) is str:
                owners[surface].append(object_id)
    return {
        surface: tuple(sorted(set(object_ids)))
        for surface, object_ids in owners.items()
    }


def _mechanism_owner(
    mechanism: str,
    owners: Mapping[str, tuple[str, ...]],
) -> tuple[str | None, str]:
    matched = sorted({
        owner
        for surface in _mechanism_surface_candidates(mechanism)
        for owner in owners.get(surface, ())
    })
    if not matched:
        return None, "NOT_FOUND"
    if len(matched) != 1:
        return None, "AMBIGUOUS"
    return matched[0], "EXACT"


def _verifier_classification(row: Mapping[str, Any] | None) -> str:
    if type(row) is not dict:
        return "UNKNOWN"
    if row.get("kind") == "VERIFIER":
        return "APPLIES"
    classification = row.get("classification")
    verifier = classification.get("VERIFIER") if type(classification) is dict else None
    status = verifier.get("status") if type(verifier) is dict else None
    return status if status in {"APPLIES", "DOES_NOT_APPLY", "UNRESOLVED"} else "UNKNOWN"


def _row_index(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "object_id": row.get("object_id"),
        "object_kind": row.get("object_kind"),
        "coordinate": row.get("coordinate"),
        "tier": row.get("tier"),
        "checking_mechanism": row.get("checking_mechanism"),
        "instance_digest": row.get("instance_digest"),
        "status": row.get("status"),
    }


def _member(
    verifier_id: str,
    rows: Sequence[Mapping[str, Any]],
    declaration: Mapping[str, Any] | None,
    *,
    aggregate_verifier_id: str,
    resolution: str,
) -> dict[str, Any]:
    indexes = sorted(
        (_row_index(row) for row in rows),
        key=lambda item: (
            item["tier"], item["object_id"], item["coordinate"],
            item["object_kind"], item["instance_digest"],
        ),
    )
    mechanisms = sorted({row["checking_mechanism"] for row in rows})
    subjects = sorted({row["object_id"] for row in rows})
    row_status = _status(row["status"] for row in rows)
    classification = _verifier_classification(declaration)
    blockers = []
    if resolution != "EXACT":
        blockers.append("MEMBER_VERIFIER_OWNER_NOT_EXACT")
    if classification in {"UNRESOLVED", "UNKNOWN"}:
        blockers.append("MEMBER_VERIFIER_CLASSIFICATION_NOT_ESTABLISHED")
    elif classification == "DOES_NOT_APPLY":
        blockers.append("MEMBER_VERIFIER_CLASSIFICATION_REFUTED")
    if row_status != "PASS":
        blockers.append("MEMBER_VERIFIER_OBLIGATIONS_NOT_PASS")
    status = (
        "FAIL"
        if row_status == "FAIL" or classification == "DOES_NOT_APPLY"
        else "PASS"
        if row_status == "PASS" and classification == "APPLIES" and resolution == "EXACT"
        else "UNKNOWN"
    )
    body = {
        "verifier_id": verifier_id,
        "represented_kind": "VERIFIER",
        "declared_kind": declaration.get("kind") if type(declaration) is dict else None,
        "verifier_classification": classification,
        "owner_resolution": resolution,
        "self_member": verifier_id == aggregate_verifier_id,
        "mechanism_count": len(mechanisms),
        "checking_mechanisms": mechanisms,
        "mechanism_digest": binding.value_digest(mechanisms),
        "subject_object_count": len(subjects),
        "subject_objects": subjects,
        "subject_object_digest": binding.value_digest(subjects),
        "obligation_instance_count": len(indexes),
        "obligation_instances": indexes,
        "obligation_instance_digest": binding.value_digest(indexes),
        "status_counts": dict(Counter(row["status"] for row in rows)),
        "status": status,
        "blockers": sorted(set(blockers)),
    }
    return {**body, "member_digest": binding.value_digest(body)}


def _polish_subject_ids(
    declarations: Sequence[Mapping[str, Any]],
    aggregate_verifier_id: str,
) -> tuple[str, ...]:
    selected = {aggregate_verifier_id}
    for row in declarations:
        object_id = row.get("object_id")
        surfaces = row.get("surfaces")
        if type(object_id) is not str or type(surfaces) is not list:
            continue
        if any(
            type(surface) is str
            and "src/verifier/runtime/" in surface
            and "polish" in surface.rsplit("/", 1)[-1].split(":", 1)[0]
            and surface.split(":", 1)[0] in {"file", "python"}
            for surface in surfaces
        ):
            selected.add(object_id)
    return tuple(sorted(selected))


def _polish_subjects(
    declarations: Sequence[Mapping[str, Any]],
    obligation_rows: Sequence[Mapping[str, Any]],
    aggregate_verifier_id: str,
) -> tuple[dict[str, Any], ...]:
    by_subject: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in obligation_rows:
        by_subject[row["object_id"]].append(row)
    selected = []
    for object_id in _polish_subject_ids(declarations, aggregate_verifier_id):
        rows = by_subject.get(object_id, [])
        indexes = sorted(
            (_row_index(row) for row in rows),
            key=lambda item: (
                item["tier"], item["object_id"], item["coordinate"],
                item["object_kind"], item["instance_digest"],
            ),
        )
        status = _status(row["status"] for row in rows)
        blockers = [] if status == "PASS" else [
            "POLISH_SYSTEM_SUBJECT_HAS_NO_OBLIGATIONS"
            if not rows else "POLISH_SYSTEM_OBLIGATIONS_NOT_PASS"
        ]
        body = {
            "object_id": object_id,
            "aggregate": object_id == aggregate_verifier_id,
            "obligation_instance_count": len(indexes),
            "obligation_instances": indexes,
            "obligation_instance_digest": binding.value_digest(indexes),
            "status_counts": dict(Counter(row["status"] for row in rows)),
            "status": status,
            "blockers": blockers,
        }
        selected.append({**body, "subject_digest": binding.value_digest(body)})
    return tuple(selected)


def _tier_projection(
    depth: int,
    obligation_rows: Sequence[Mapping[str, Any]],
    members: Sequence[Mapping[str, Any]],
    polish_subjects: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    rows = [row for row in obligation_rows if row["tier"] <= depth]
    member_ids = sorted({row.get("resolved_verifier_id") for row in rows})
    member_ids = [item for item in member_ids if type(item) is str]
    member_by_id = {row["verifier_id"]: row for row in members}
    selected_member_statuses = []
    for verifier_id in member_ids:
        selected = [
            row for row in rows
            if row.get("resolved_verifier_id") == verifier_id
        ]
        declaration = member_by_id[verifier_id]
        row_status = _status(row["status"] for row in selected)
        selected_member_statuses.append(
            "FAIL"
            if row_status == "FAIL"
            or declaration["verifier_classification"] == "DOES_NOT_APPLY"
            else "PASS"
            if row_status == "PASS"
            and declaration["verifier_classification"] == "APPLIES"
            and declaration["owner_resolution"] == "EXACT"
            else "UNKNOWN"
        )
    polish_ids = [row["object_id"] for row in polish_subjects]
    selected_polish_statuses = []
    for object_id in polish_ids:
        selected = [row for row in rows if row["object_id"] == object_id]
        selected_polish_statuses.append(
            _status(row["status"] for row in selected)
        )
    member_status = _status(selected_member_statuses)
    polish_status = _status(selected_polish_statuses)
    status = _status((member_status, polish_status))
    body = {
        "tier": depth,
        "obligation_instance_count": len(rows),
        "member_verifier_count": len(member_ids),
        "member_verifier_digest": binding.value_digest(member_ids),
        "member_status_counts": dict(Counter(selected_member_statuses)),
        "polish_system_subject_count": len(polish_subjects),
        "polish_system_status": polish_status,
        "status": status,
    }
    return {**body, "tier_result_digest": binding.value_digest(body)}


def compile_self_polish_graph(
    *,
    document: Mapping[str, Any] | None,
    objects: Sequence[namespace.NamespaceObject],
    obligation_rows: Sequence[Mapping[str, Any]],
    aggregate_verifier: namespace.NamespaceObject,
    package_graph_id: str,
    package_graph_digest: str,
    requested_tier: int,
) -> dict[str, Any]:
    """Compile already evaluated rows into the aggregate self-polish graph."""
    if requested_tier not in {1, 2, 3}:
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_TIER_INVALID")
    if aggregate_verifier.kind is not namespace.ObjectKind.VERIFIER:
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_ROOT_NOT_VERIFIER")
    selected_objects = {item.object_id: item for item in objects}
    if (
        len(selected_objects) != len(objects)
        or selected_objects.get(aggregate_verifier.object_id) != aggregate_verifier
    ):
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_AGGREGATE_NOT_IN_SUBJECT")
    package_graph = selected_objects.get(package_graph_id)
    if package_graph is None or package_graph.kind is not namespace.ObjectKind.GRAPH:
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_SUBJECT_NOT_GRAPH")
    if namespace.composition_digest(objects) != package_graph_digest:
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_DIGEST_DIFFERS")
    if not obligation_rows:
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_OBLIGATIONS_EMPTY")
    if any(
        type(row) is not dict
        or row.get("status") not in _STATUSES
        or type(row.get("checking_mechanism")) is not str
        or type(row.get("tier")) is not int
        for row in obligation_rows
    ):
        raise VerifierGraphError("PACKAGE_VERIFIER_GRAPH_OBLIGATION_INVALID")

    declarations = _semantic_rows(document)
    by_id = {
        row["object_id"]: row
        for row in declarations
        if type(row.get("object_id")) is str
    }
    owners = _owner_index(declarations)
    legacy_fallback = not declarations
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    resolution: dict[str, str] = {}
    resolved_rows = []
    for row in obligation_rows:
        owner, owner_status = _mechanism_owner(row["checking_mechanism"], owners)
        if legacy_fallback:
            owner, owner_status = aggregate_verifier.object_id, "EXACT"
        if owner is None:
            owner = "unresolved:" + binding.value_digest(
                row["checking_mechanism"]
            ).split(":", 1)[1][:24]
        grouped[owner].append(row)
        resolution[owner] = owner_status
        resolved_rows.append({**row, "resolved_verifier_id": owner})

    members = tuple(
        _member(
            verifier_id,
            grouped[verifier_id],
            by_id.get(verifier_id),
            aggregate_verifier_id=aggregate_verifier.object_id,
            resolution=resolution[verifier_id],
        )
        for verifier_id in sorted(grouped)
    )
    edges = tuple({
        "from_verifier_id": aggregate_verifier.object_id,
        "to_verifier_id": row["verifier_id"],
        "relation": (
            "SELF_MEMBER" if row["self_member"] else "AGGREGATES_MEMBER"
        ),
        "member_digest": row["member_digest"],
    } for row in members)
    if declarations:
        polish_subjects = _polish_subjects(
            declarations, obligation_rows, aggregate_verifier.object_id
        )
    else:
        legacy_subject = {
            "object_id": aggregate_verifier.object_id,
            "aggregate": True,
            "obligation_instance_count": len(obligation_rows),
            "obligation_instances": [
                _row_index(row) for row in obligation_rows
            ],
            "obligation_instance_digest": binding.value_digest([
                _row_index(row) for row in obligation_rows
            ]),
            "status_counts": dict(Counter(
                row["status"] for row in obligation_rows
            )),
            "status": _status(row["status"] for row in obligation_rows),
            "blockers": (
                [] if all(row["status"] == "PASS" for row in obligation_rows)
                else ["POLISH_SYSTEM_OBLIGATIONS_NOT_PASS"]
            ),
        }
        polish_subjects = ({
            **legacy_subject,
            "subject_digest": binding.value_digest(legacy_subject),
        },)
    member_status = _status(row["status"] for row in members)
    polish_status = _status(row["status"] for row in polish_subjects)
    status = _status((member_status, polish_status))
    tier_results = tuple(
        _tier_projection(depth, resolved_rows, members, polish_subjects)
        for depth in range(1, requested_tier + 1)
    )
    blockers = []
    if any(row["owner_resolution"] != "EXACT" for row in members):
        blockers.append("PACKAGE_MEMBER_VERIFIER_OWNERSHIP_NOT_ESTABLISHED")
    if member_status != "PASS":
        blockers.append("PACKAGE_MEMBER_VERIFIER_OBLIGATIONS_NOT_PASS")
    if polish_status != "PASS":
        blockers.append("PACKAGE_POLISH_SYSTEM_SELF_ASSESSMENT_NOT_PASS")
    body = {
        "schema_version": SCHEMA,
        "status": status,
        "aggregate_verifier_id": aggregate_verifier.object_id,
        "aggregate_verifier_digest": aggregate_verifier.digest,
        "aggregate_subject_kind": "VERIFIER",
        "verified_graph_id": package_graph_id,
        "verified_graph_digest": package_graph_digest,
        "requested_tier": requested_tier,
        "member_verifier_count": len(members),
        "member_status_counts": dict(Counter(row["status"] for row in members)),
        "member_verifiers": list(members),
        "member_verifier_digest": binding.value_digest(members),
        "edge_count": len(edges),
        "edges": list(edges),
        "edge_digest": binding.value_digest(edges),
        "polish_system_subject_count": len(polish_subjects),
        "polish_system_status": polish_status,
        "polish_system_subjects": list(polish_subjects),
        "polish_system_subject_digest": binding.value_digest(polish_subjects),
        "tier_results": list(tier_results),
        "blockers": sorted(set(blockers)),
        "aggregate_result_is_member_evidence": False,
        "self_application_authority": "NOT_ESTABLISHED",
        "claim_boundary": (
            "The selected aggregate VERIFIER represents and evaluates the exact "
            "package obligation graph, including the polish implementation. Its "
            "aggregate result is not evidence for a member obligation, and "
            "self-observation is not independent authority."
        ),
    }
    return {**body, "graph_digest": binding.value_digest(body)}


def validate_self_polish_graph(
    value: Mapping[str, Any],
    *,
    aggregate_verifier_id: str,
    aggregate_verifier_digest: str,
    package_graph_id: str,
    package_graph_digest: str,
    requested_tier: int,
    obligation_rows: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Recheck a retained recursive graph without trusting its summary fields."""
    if type(value) is not dict or value.get("schema_version") != SCHEMA:
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_SCHEMA_INVALID")
    body = {key: item for key, item in value.items() if key != "graph_digest"}
    if value.get("graph_digest") != binding.value_digest(body):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_DIGEST_DIFFERS")
    if (
        value.get("aggregate_verifier_id") != aggregate_verifier_id
        or value.get("aggregate_verifier_digest") != aggregate_verifier_digest
        or value.get("aggregate_subject_kind") != "VERIFIER"
        or value.get("verified_graph_id") != package_graph_id
        or value.get("verified_graph_digest") != package_graph_digest
        or value.get("requested_tier") != requested_tier
        or value.get("aggregate_result_is_member_evidence") is not False
        or value.get("self_application_authority") != "NOT_ESTABLISHED"
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_BINDING_DIFFERS")

    members = value.get("member_verifiers")
    if (
        type(members) is not list
        or not members
        or any(type(row) is not dict for row in members)
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_MEMBERS_INVALID")
    if (
        value.get("member_verifier_count") != len(members)
        or value.get("member_verifier_digest") != binding.value_digest(members)
        or value.get("member_status_counts")
        != dict(Counter(row.get("status") for row in members))
        or len({row.get("verifier_id") for row in members}) != len(members)
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_MEMBER_SUMMARY_DIFFERS")
    for row in members:
        if type(row) is not dict:
            raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_MEMBER_INVALID")
        indexes = row.get("obligation_instances")
        mechanisms = row.get("checking_mechanisms")
        subjects_for_member = row.get("subject_objects")
        if (
            row.get("represented_kind") != "VERIFIER"
            or row.get("status") not in _STATUSES
            or type(indexes) is not list
            or not indexes
            or any(
                type(item) is not dict
                or type(item.get("object_id")) is not str
                or type(item.get("checking_mechanism")) is not str
                or item.get("status") not in _STATUSES
                for item in indexes
            )
            or row.get("obligation_instance_count") != len(indexes)
            or row.get("obligation_instance_digest")
            != binding.value_digest(indexes)
            or row.get("status_counts")
            != dict(Counter(item.get("status") for item in indexes))
            or type(mechanisms) is not list
            or mechanisms != sorted({
                item.get("checking_mechanism") for item in indexes
            })
            or row.get("mechanism_count") != len(mechanisms)
            or row.get("mechanism_digest") != binding.value_digest(mechanisms)
            or type(subjects_for_member) is not list
            or subjects_for_member
            != sorted({item.get("object_id") for item in indexes})
            or row.get("subject_object_count") != len(subjects_for_member)
            or row.get("subject_object_digest")
            != binding.value_digest(subjects_for_member)
            or row.get("member_digest") != binding.value_digest({
                key: item for key, item in row.items() if key != "member_digest"
            })
        ):
            raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_MEMBER_INVALID")
        row_status = _status(item["status"] for item in indexes)
        classification = row.get("verifier_classification")
        resolution = row.get("owner_resolution")
        expected_blockers = []
        if resolution != "EXACT":
            expected_blockers.append("MEMBER_VERIFIER_OWNER_NOT_EXACT")
        if classification in {"UNRESOLVED", "UNKNOWN"}:
            expected_blockers.append(
                "MEMBER_VERIFIER_CLASSIFICATION_NOT_ESTABLISHED"
            )
        elif classification == "DOES_NOT_APPLY":
            expected_blockers.append("MEMBER_VERIFIER_CLASSIFICATION_REFUTED")
        if row_status != "PASS":
            expected_blockers.append("MEMBER_VERIFIER_OBLIGATIONS_NOT_PASS")
        expected_status = (
            "FAIL"
            if row_status == "FAIL" or classification == "DOES_NOT_APPLY"
            else "PASS"
            if row_status == "PASS"
            and classification == "APPLIES"
            and resolution == "EXACT"
            else "UNKNOWN"
        )
        if (
            classification
            not in {"APPLIES", "DOES_NOT_APPLY", "UNRESOLVED", "UNKNOWN"}
            or resolution not in {"EXACT", "NOT_FOUND", "AMBIGUOUS"}
            or row.get("status") != expected_status
            or row.get("blockers") != sorted(set(expected_blockers))
        ):
            raise VerifierGraphError(
                "PACKAGE_SELF_POLISH_GRAPH_MEMBER_STATUS_DIFFERS"
            )

    represented_indexes = [
        item
        for member in members
        for item in member["obligation_instances"]
    ]
    if obligation_rows is not None:
        actual_indexes = [_row_index(row) for row in obligation_rows]
        if binding.value_digest(sorted(
            represented_indexes, key=binding.value_digest
        )) != binding.value_digest(sorted(
            actual_indexes, key=binding.value_digest
        )):
            raise VerifierGraphError(
                "PACKAGE_SELF_POLISH_GRAPH_OBLIGATION_PARTITION_DIFFERS"
            )

    expected_edges = [{
        "from_verifier_id": aggregate_verifier_id,
        "to_verifier_id": row["verifier_id"],
        "relation": (
            "SELF_MEMBER" if row["self_member"] else "AGGREGATES_MEMBER"
        ),
        "member_digest": row["member_digest"],
    } for row in members]
    if (
        value.get("edges") != expected_edges
        or value.get("edge_count") != len(expected_edges)
        or value.get("edge_digest") != binding.value_digest(expected_edges)
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_EDGES_DIFFER")

    subjects = value.get("polish_system_subjects")
    if (
        type(subjects) is not list
        or not subjects
        or any(type(row) is not dict for row in subjects)
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_SUBJECTS_INVALID")
    if (
        value.get("polish_system_subject_count") != len(subjects)
        or value.get("polish_system_subject_digest")
        != binding.value_digest(subjects)
        or len({row.get("object_id") for row in subjects}) != len(subjects)
        or aggregate_verifier_id
        not in {row.get("object_id") for row in subjects}
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_SUBJECT_SUMMARY_DIFFERS")
    for row in subjects:
        indexes = row.get("obligation_instances")
        if (
            type(row) is not dict
            or row.get("status") not in _STATUSES
            or type(indexes) is not list
            or any(
                type(item) is not dict
                or item.get("status") not in _STATUSES
                for item in indexes
            )
            or row.get("obligation_instance_count") != len(indexes)
            or row.get("obligation_instance_digest")
            != binding.value_digest(indexes)
            or row.get("status_counts")
            != dict(Counter(item.get("status") for item in indexes))
            or row.get("status") != _status(
                item.get("status") for item in indexes
            )
            or row.get("subject_digest") != binding.value_digest({
                key: item for key, item in row.items() if key != "subject_digest"
            })
        ):
            raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_SUBJECT_INVALID")
        subject_status = _status(item["status"] for item in indexes)
        expected_subject_blockers = (
            [] if subject_status == "PASS" else [
                "POLISH_SYSTEM_SUBJECT_HAS_NO_OBLIGATIONS"
                if not indexes else "POLISH_SYSTEM_OBLIGATIONS_NOT_PASS"
            ]
        )
        if (
            row.get("aggregate")
            is (row.get("object_id") == aggregate_verifier_id)
            and row.get("blockers") == expected_subject_blockers
        ):
            pass
        else:
            raise VerifierGraphError(
                "PACKAGE_SELF_POLISH_GRAPH_SUBJECT_STATUS_DIFFERS"
            )

    tiers = value.get("tier_results")
    if (
        type(tiers) is not list
        or any(type(row) is not dict for row in tiers)
        or [row.get("tier") for row in tiers]
        != list(range(1, requested_tier + 1))
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_TIERS_INVALID")
    resolved_rows = [
        {**item, "resolved_verifier_id": member["verifier_id"]}
        for member in members
        for item in member["obligation_instances"]
    ]
    expected_tiers = [
        _tier_projection(depth, resolved_rows, members, subjects)
        for depth in range(1, requested_tier + 1)
    ]
    for row in tiers:
        if (
            type(row) is not dict
            or row.get("status") not in _STATUSES
            or row.get("tier_result_digest") != binding.value_digest({
                key: item for key, item in row.items()
                if key != "tier_result_digest"
            })
        ):
            raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_TIER_INVALID")
    if tiers != expected_tiers:
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_TIER_RESULT_DIFFERS")

    member_status = _status(row["status"] for row in members)
    polish_status = _status(row["status"] for row in subjects)
    expected_blockers = []
    if any(row["owner_resolution"] != "EXACT" for row in members):
        expected_blockers.append(
            "PACKAGE_MEMBER_VERIFIER_OWNERSHIP_NOT_ESTABLISHED"
        )
    if member_status != "PASS":
        expected_blockers.append("PACKAGE_MEMBER_VERIFIER_OBLIGATIONS_NOT_PASS")
    if polish_status != "PASS":
        expected_blockers.append("PACKAGE_POLISH_SYSTEM_SELF_ASSESSMENT_NOT_PASS")
    if (
        value.get("polish_system_status") != polish_status
        or value.get("status") != _status((member_status, polish_status))
        or value.get("blockers") != sorted(set(expected_blockers))
    ):
        raise VerifierGraphError("PACKAGE_SELF_POLISH_GRAPH_STATUS_DIFFERS")


__all__ = [
    "SCHEMA", "VerifierGraphError", "compile_self_polish_graph",
    "validate_self_polish_graph",
]
