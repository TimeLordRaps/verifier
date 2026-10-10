"""Private checks for frozen PRDEL schemas and the order-preserving successor."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELECTED = {
    "verifier-prdel-compilation-shards-1.schema.json": (
        "46ea7241a6f2f35c98401096b0be19d10d34f6f2ae42083dec3e65b034576536"
    ),
    "verifier-prdel-shard-description-1.schema.json": (
        "e93b3223143e82e3528d3666a42bef55b812ad76e1d9cb2d8117d41d1908e86f"
    ),
}
SPACETIME = "spacetime-context-extension-1.schema.json"
SUCCESSOR_RELATION = (
    ROOT / "src" / "verifier" / "profiles" / "prdel-manifest-2-selection.json"
)
SUCCESSOR_RELATION_SHA256 = (
    "41a9387521882b91e736079172cc42d1570841cbb530165cb7939db237ec4875"
)
SUCCESSOR = "verifier-prdel-compilation-shards-2.schema.json"
NATIVE_V2_OVERLAY_SCHEMAS = {
    "verifier-prdel-2.schema.json",
    "verifier-prdel-cli-2.schema.json",
    "verifier-prdel-v2-document-shard-1.schema.json",
    "verifier-prdel-v2-release-subject-2.schema.json",
    "verifier-prdel-v2-shard-manifest-1.schema.json",
}
R31_ADDITIONAL_SCHEMAS = {
    "claim-garden-dangerous-pathway-assessment-1.schema.json",
    "claim-garden-dangerous-pathway-assessment-2.schema.json",
    "verifier-dangerous-pathway-certificate-1.schema.json",
    "verifier-dangerous-pathway-request-1.schema.json",
    "verifier-prdel-replay-plan-1.schema.json",
    "verifier-self-polish-native-replay-manifest-2.schema.json",
    "verifier-self-polish-native-replay-receipt-2.schema.json",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _release_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "PACKAGED_SCHEMA_NAMES"
            for target in node.targets
        ):
            continue
        return {
            value.value
            for value in ast.walk(node.value)
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value.endswith(".json")
        }
    raise AssertionError("PACKAGED_SCHEMA_NAMES is absent")


def _candidate_paths(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name)
            and target.id == "REVIEWED_CANDIDATE_SOURCE_PATHS"
            for target in node.targets
        ):
            continue
        return {
            value.value
            for value in ast.walk(node.value)
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        }
    raise AssertionError("REVIEWED_CANDIDATE_SOURCE_PATHS is absent")


def _feature_rows(path: Path) -> dict[str, dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            row_path = value.get("path")
            if isinstance(row_path, str):
                rows[row_path] = value
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(json.loads(path.read_text(encoding="utf-8")))
    return rows


def test_selected_sources_match_frozen_receiving_relation() -> None:
    relation = json.loads(SUCCESSOR_RELATION.read_text(encoding="utf-8"))[
        "predecessor_selection"
    ]
    assert relation["receiving_relation_commitment"] == {
        "bytes": 28097,
        "sha256": "34ed3ba8fa45be87c7087a9d062ece1909c704b8bf1c07eb95d6d4354f518be9",
    }
    assert relation["handoff_commitment"] == {
        "bytes": 54565,
        "sha256": "1db712862b3857f81615b09f95944c9d9ff16b325bde762dba1fa0e1a6885003",
    }
    assert relation["producer_source_coordinate"] == {
        "repository": "https://github.com/TimeLordRaps/verifier.git",
        "head": "20b2a7bc58d2c39e074de044fc20fee915e0230e",
        "tree": "8f665500bc48149fa7cc519abb0387ae49c4c972",
        "scope": "SELECTED_PATHS_ONLY",
        "working_tree_completeness": "UNKNOWN",
    }
    recorded = {entry["name"]: entry for entry in relation["selected_schemas"]}
    for name, expected in SELECTED.items():
        source_record = recorded[name]
        assert source_record["sha256"] == expected
        assert source_record["producer_path"] == f"src/verifier/schemas/{name}"
        assert type(source_record["tracked_at_producer_head"]) is bool
        installed = ROOT / "src" / "verifier" / "schemas" / name
        assert installed.stat().st_size == source_record["bytes"]
        assert _sha256(installed) == expected
        schema = json.loads(installed.read_text(encoding="utf-8"))
        assert schema["$id"] == (
            "https://timelordraps.github.io/verifier/schemas/" + name
        )
    assert recorded["verifier-prdel-compilation-shards-1.schema.json"][
        "tracked_at_producer_head"
    ] is True
    assert recorded["verifier-prdel-shard-description-1.schema.json"][
        "tracked_at_producer_head"
    ] is False
    assert relation["excluded_test_only_schema"] == {
        "name": SPACETIME,
        "sha256": "97345bb1997b9abeaae4b5048de4f748cc5ab24a303638cbd1f38412c056b9b6",
        "package_admitted": False,
    }
    assert not (ROOT / "src" / "verifier" / "schemas" / SPACETIME).exists()


def test_order_preserving_successor_is_exact_and_does_not_claim_release() -> None:
    assert _sha256(SUCCESSOR_RELATION) == SUCCESSOR_RELATION_SHA256
    relation = json.loads(SUCCESSOR_RELATION.read_text(encoding="utf-8"))
    assert relation["candidate_status"] == "DEVELOPMENT_CANDIDATE"
    assert relation["authority_scope"] == "VERIFIER_PRDEL_IMPLEMENTATION_METADATA"
    assert relation["semantic_completeness"] == "UNKNOWN"
    assert relation["release_authorized"] is False
    selected = relation["successor_selection"]
    assert selected["relation"] == "ORDER_PRESERVING_WIRE_SUCCESSOR"
    assert selected["schema_name"] == SUCCESSOR
    installed = ROOT / selected["schema_path"]
    assert _sha256(installed) == selected["schema_sha256"]
    schema = json.loads(installed.read_text(encoding="utf-8"))
    assert schema["$id"] == selected["schema_id"]


def test_release_inventory_is_exact_50_plus_named_additions() -> None:
    relation = json.loads(SUCCESSOR_RELATION.read_text(encoding="utf-8"))[
        "predecessor_selection"
    ]
    actual = {
        path.name for path in (ROOT / "src" / "verifier" / "schemas").glob("*.json")
    }
    declared = _release_names(ROOT / "scripts" / "release_artifacts.py")
    old_names = (
        declared
        - set(SELECTED)
        - {SUCCESSOR}
        - NATIVE_V2_OVERLAY_SCHEMAS
        - R31_ADDITIONAL_SCHEMAS
    )
    canonical_old_names = json.dumps(
        sorted(old_names), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    inventory = relation["reviewed_predecessor_schema_inventory"]
    assert len(old_names) == inventory["count"]
    assert hashlib.sha256(canonical_old_names).hexdigest() == inventory["sha256"]
    assert len(old_names) == 50
    assert R31_ADDITIONAL_SCHEMAS <= declared
    assert R31_ADDITIONAL_SCHEMAS <= actual
    assert actual == declared
    assert declared - old_names == (
        set(SELECTED)
        | {SUCCESSOR}
        | NATIVE_V2_OVERLAY_SCHEMAS
        | R31_ADDITIONAL_SCHEMAS
    )
    assert old_names - declared == set()
    assert SPACETIME not in declared


def test_component_candidate_paths_admit_frozen_schemas_and_successor() -> None:
    paths = _candidate_paths(ROOT / "scripts" / "build_component_index.py")
    selected_paths = {f"src/verifier/schemas/{name}" for name in SELECTED}
    selected_paths.add(f"src/verifier/schemas/{SUCCESSOR}")
    selected_paths.add("src/verifier/profiles/prdel-manifest-2-selection.json")
    assert selected_paths <= paths
    assert f"src/verifier/schemas/{SPACETIME}" not in paths


def test_feature_rows_bind_selected_sources_and_changed_scripts() -> None:
    features = ROOT / "docs" / "PR_SOURCE_FEATURES.json"
    rows = _feature_rows(features)
    for name, expected in SELECTED.items():
        row = rows[f"src/verifier/schemas/{name}"]
        assert row["sha256"] == expected
        assert row["summary"]
        assert row["limits"]
    successor = json.loads(SUCCESSOR_RELATION.read_text(encoding="utf-8"))[
        "successor_selection"
    ]
    for relative, expected in (
        (successor["schema_path"], successor["schema_sha256"]),
        (
            "src/verifier/profiles/prdel-manifest-2-selection.json",
            SUCCESSOR_RELATION_SHA256,
        ),
    ):
        assert rows[relative]["sha256"] == expected
        assert rows[relative]["summary"]
        assert rows[relative]["limits"]
    for relative in (
        "scripts/build_component_index.py",
        "scripts/release_artifacts.py",
    ):
        assert rows[relative]["sha256"] == _sha256(ROOT / relative)
