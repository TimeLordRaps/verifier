"""Literal package-graph coverage for the shared worker dependency relation."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.runtime import (
    namespace_manifest,
    package_contract_profiles,
    package_namespace_review,
    package_protocol_dependency_relation as relation,
    package_semantic_ownership,
)
from verifier.runtime.namespace_contracts import namespace_registry


ROOT = Path(__file__).resolve().parents[1]


def _spec():
    return next(
        item
        for item in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if item.object_id == relation.OBJECT_ID
    )


def test_relation_is_one_source_owned_hyper_with_exact_three_edges() -> None:
    spec = _spec()
    assert spec.primary_kind == "HYPER"
    assert spec.specializations == ()
    assert spec.owned_paths == (relation.SOURCE_PATH,)
    assert spec.operands == relation.OPERANDS == (
        (
            "dependents",
            ("vstd-invocation-ledger", "vstd-manifest-write"),
        ),
        ("protocol_exchange", ("vstd-package-worker-exchange",)),
    )
    assert sum(len(targets) for _role, targets in spec.operands) == 3
    assert spec.root_role_decisions == ()

    # The HYPER relation carries the edges. The participant objects retain the
    # base OBJECT layout instead of gaining typed operands they cannot carry.
    manifest = json.loads((ROOT / "objects.vstd").read_text(encoding="utf-8"))
    rows = {
        item["object_id"]: item for item in manifest["namespace"]["objects"]
    }
    for object_id in (*relation.DEPENDENT_OBJECT_IDS, *relation.PROTOCOL_EXCHANGE_OBJECT_IDS):
        assert rows[object_id]["operands"] == {}


@pytest.mark.parametrize(
    "operands",
    [
        (("dependents", ("vstd-invocation-ledger",)),
         ("protocol_exchange", ("vstd-package-worker-exchange",))),
        (("dependents", ("vstd-package-worker-exchange",)),
         ("protocol_exchange", ("vstd-invocation-ledger", "vstd-manifest-write"))),
        (("dependents", ("vstd-invocation-ledger", "vstd-manifest-write")),
         ("protocol_exchange", ("vstd-missing-exchange",))),
        (("dependents", ("vstd-invocation-ledger", "vstd-manifest-write", "vstd-extra")),
         ("protocol_exchange", ("vstd-package-worker-exchange",))),
    ],
)
def test_relation_refuses_missing_swapped_dangling_or_extra_endpoints(
    operands: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    with pytest.raises(
        ValueError,
        match="PACKAGE_PROTOCOL_DEPENDENCY_RELATION_OPERANDS_DIFFER",
    ):
        relation.validate_operands(operands)


def test_review_denominator_consumes_shared_relation_constants() -> None:
    catalog = package_namespace_review.review_document()
    item = catalog[relation.OBJECT_ID]
    assert item["primary_kind"] == "HYPER"
    assert item["owned_paths"] == [relation.SOURCE_PATH]
    assert item["declarations"] == {}
    assert {
        kind: decision["status"]
        for kind, decision in item["classification"].items()
    } == {kind: "UNRESOLVED" for kind in package_namespace_review.REVIEW_KINDS}

    for object_id in relation.DEPENDENT_OBJECT_IDS:
        dependency = catalog[object_id]["dependency_operands"]["protocol_exchange"]
        assert dependency["targets"] == list(relation.PROTOCOL_EXCHANGE_OBJECT_IDS)
        assert dependency["reason"] == relation.PARTICIPANT_DEPENDENCY_REASON
        assert relation.SOURCE_PATH in dependency["target_evidence_paths"]
        anchors = package_namespace_review._REVIEWS[
            object_id
        ].dependency_operands["protocol_exchange"].anchors
        assert anchors[relation.SOURCE_PATH] == relation.SOURCE_ANCHORS


def test_generic_migration_discovers_relation_without_a_special_case() -> None:
    source = (ROOT / "src/verifier/runtime/package_manifest_migration.py").read_text(
        encoding="utf-8"
    )
    assert relation.OBJECT_ID not in source
    assert _spec() in package_semantic_ownership.validate_catalog(ROOT)


def test_literal_relation_adds_one_graph_member_and_exactly_three_edges() -> None:
    manifest = json.loads((ROOT / "objects.vstd").read_text(encoding="utf-8"))
    namespace = manifest["namespace"]
    if namespace.get("schema_version") == namespace_manifest.COMPACT_SCHEMA:
        namespace = namespace_manifest.normalize_manifest(namespace)
    # The regenerated manifest may already carry the relation; the claim is about what
    # the relation adds, so measure against the same graph without it.
    before = [
        deepcopy(row) for row in namespace["objects"] if row["object_id"] != relation.OBJECT_ID
    ]
    for row in before:
        if row["kind"] == "GRAPH":
            row["operands"]["members"] = [
                member for member in row["operands"]["members"] if member != relation.OBJECT_ID
            ]
    after = deepcopy(before)
    graph = next(row for row in after if row["kind"] == "GRAPH")

    def nonmembership_edges(rows: list[dict]) -> int:
        return sum(
            len(targets)
            for row in rows
            for role, targets in row["operands"].items()
            if not (row["kind"] == "GRAPH" and role == "members")
        )

    spec = _spec()
    after.append(
        {
            "object_id": spec.object_id,
            "kind": spec.primary_kind,
            "specializations": list(spec.specializations),
            "payload": {"representation_role": spec.representation_role},
            "operands": {role: list(targets) for role, targets in spec.operands},
            "surfaces": ["file:" + path for path in spec.owned_paths],
            "reason": spec.necessity_reason + " Boundary: " + spec.consequence_boundary,
            "classification": {},
            "obligations": {},
        }
    )
    graph["operands"]["members"].append(spec.object_id)
    graph["operands"]["members"].sort()

    assert len(after) == len(before) + 1
    before_graph = next(row for row in before if row["kind"] == "GRAPH")
    assert len(graph["operands"]["members"]) == len(
        before_graph["operands"]["members"]
    ) + 1
    assert nonmembership_edges(after) == nonmembership_edges(before) + 3
    assert namespace_manifest.check_composition(after, namespace_registry())[
        "status"
    ] == "PASS"
    for object_id in (*relation.DEPENDENT_OBJECT_IDS, *relation.PROTOCOL_EXCHANGE_OBJECT_IDS):
        assert next(row for row in after if row["object_id"] == object_id)[
            "operands"
        ] == {}


def test_hyper_tier_one_through_three_remain_registered_not_discharged() -> None:
    assert package_contract_profiles.required_coordinates("HYPER", 1) == (
        "HYPER-1.90",
        "HYPER-1.1",
    )
    assert package_contract_profiles.required_coordinates("HYPER", 2) == (
        "HYPER-1.90",
        "HYPER-2.90",
        "HYPER-1.1",
        "HYPER-2.3",
    )
    assert package_contract_profiles.required_coordinates("HYPER", 3) == (
        "HYPER-1.90",
        "HYPER-2.90",
        "HYPER-3.90",
        "HYPER-1.1",
        "HYPER-2.3",
        "HYPER-3.1",
    )
    assert _spec().primary_kind == "HYPER"
    assert package_namespace_review.review_document()[relation.OBJECT_ID][
        "declarations"
    ] == {}
