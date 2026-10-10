"""Refutable coverage for the reviewed application dependency lower bound."""
from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import ObjectKind
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes
from verifier.domains.contracts import facet_coverage as coverage
from verifier.domains.contracts import receipt_chain, subject_security


EXPECTED_CORRECTED = {
    ("GRAPH-3.1", "GRAPH-4.1"), ("GRAPH-3.1", "GRAPH-9.2"),
    ("SIM-2.1", "SIM-2.2"), ("SIM-2.1", "SIM-2.3"),
    ("SIM-2.1", "SIM-4.1"), ("SIM-2.3", "SIM-2.5"),
    ("TRAIN-4.1", "TRAIN-1.5"), ("DATA-1.2", "TRAIN-1.5"),
    ("ENV-1.2", "ENV-1.3"), ("ENV-1.1", "ENV-1.4"),
}
EXPECTED_MULTI_COORDINATE = {
    ("ENV-1.2", "ENV-4.1"), ("DATA-1.2", "MODEL-3.4"),
}
EXPECTED_DYNAMIC_SOURCES = {
    "HYPER-2.3:DIRECT_OPERAND_CHILD_SELECTION": {
        "path": "src/verifier/domains/contracts/hyper_unknown_absorption.py",
        "sha256": "7fcadd2d7ddc563c983918e4a910d3d2ca4645920b384d396987772bbcffb8d5",
    },
    "VERIFIER-3.1:TRACE_CHILD_SELECTION": {
        "path": "src/verifier/domains/contracts/verifier_run_constraints.py",
        "sha256": "09343c6daecabb55e728076c7b42cdc38b87479117d8fa824c605debfa175592",
    },
    "VERIFIER-4.1:APPROVED_PROFILE_BOUNDARY_SELECTION": {
        "path": "src/verifier/domains/contracts/verifier_coverage_closure.py",
        "sha256": "046666618f9c0278fc1981d265a6a0e55ffba1af1926a2743365afd7f4b43fe9",
    },
    "CERTIFICATE-DAG:SELECTED_NODE_PREREQUISITES": {
        "path": "src/verifier/domains/contracts/certificate_dag.py",
        "sha256": "b185b4b32c1dcc36701141b6b0853e8351ee7ed1895c9a27fe5c2e4a26b999d7",
    },
}


def pair_set(rows):
    return {(row["prerequisite"], row["dependent"]) for row in rows}


def test_reviewed_lower_bound_counts_routes_sources_and_boundaries() -> None:
    inventory = coverage.installed_native_dependency_inventory()
    assert inventory["counts"] == {"fixed_pairs": 36, "parametric_pairs": 26,
        "inline_completion_rules": 5, "unresolved_dynamic_families": 4}
    assert len(pair_set(inventory["fixed_pairs"])) == 36
    assert EXPECTED_CORRECTED | EXPECTED_MULTI_COORDINATE <= pair_set(inventory["fixed_pairs"])
    catalog = current_object_routes.current_object_route_catalog()
    coordinates = {row["objective"] for row in catalog}
    assert all(row["prerequisite"] in coordinates and row["dependent"] in coordinates
               for row in inventory["fixed_pairs"])
    root = Path(coverage.__file__).parents[2]
    for row in inventory["fixed_pairs"]:
        source = row["source"]
        assert source["digest"] == dag._digest((root / source["path"].removeprefix("verifier/")).read_bytes())
    assert inventory["full_source_dependency_inventory"] == "UNKNOWN"
    assert inventory["complete_application_profile"] == "NOT_SELECTED"
    assert inventory["release_admissible"] is False


def test_parametric_subject_security_pairs_are_exact_registered_routes() -> None:
    inventory = coverage.installed_native_dependency_inventory()
    expected = {(receipt_chain.COORDINATE, subject_security.coordinate(kind.value))
                for kind in ObjectKind}
    assert pair_set(inventory["parametric_pairs"]) == expected
    assert {row["parameter"]["object_kind"] for row in inventory["parametric_pairs"]} == {
        kind.value for kind in ObjectKind}
    assert all(row["application"] == "CONDITIONAL_ON_EXTERNAL_PROFILE_SELECTION"
               for row in inventory["parametric_pairs"])


def test_inline_rules_and_dynamic_families_remain_distinct() -> None:
    inventory = coverage.installed_native_dependency_inventory()
    inline = {row["source_rule_id"]: (row["dependent_objectives"], row["prerequisites"])
              for row in inventory["inline_completion_rules"]}
    assert inline == {
        "native-facet:DATA:selected_retained_data_inventory":
            (["DATA-1.2"], ["RETAINED_DATA_INVENTORY_PASS"]),
        "native-facet:DATA:selected_retained_data_lineage":
            (["DATA-2.1"], ["RETAINED_DATA_INVENTORY_PASS"]),
        "native-facet:TOKEN:selected_capability_token_parent_grants":
            (["TOKEN-4.1"], ["EXACT_NAMESPACE_COMPOSITION_PASS", "RETAINED_TOKEN_INVENTORY_PASS"]),
        "native-facet:TOKEN:selected_capability_token_tenure":
            (["TOKEN-2.1"], ["EXACT_NAMESPACE_COMPOSITION_PASS", "RETAINED_TOKEN_INVENTORY_PASS"]),
        "native-facet:TOKEN:selected_capability_token_windows":
            (["TOKEN-3.1"], ["EXACT_NAMESPACE_COMPOSITION_PASS", "RETAINED_TOKEN_INVENTORY_PASS"]),
    }
    dynamic = {row["family"]: row for row in inventory["unresolved_dynamic_families"]}
    assert {family: row["source"] for family, row in dynamic.items()} == EXPECTED_DYNAMIC_SOURCES
    assert all(row["expansion_status"] == "UNKNOWN_UNTIL_EXTERNAL_SELECTION"
               for row in inventory["unresolved_dynamic_families"])
    source_root = Path(coverage.__file__).parents[4]
    assert all(source["sha256"] == dag._digest(
        (source_root / source["path"]).read_bytes()).removeprefix("sha256:")
        for source in EXPECTED_DYNAMIC_SOURCES.values())


def _direct_module_pairs() -> set[tuple[str, str]]:
    """Repeat the bounded direct module-qualified scan; it is not exhaustive."""
    package = Path(coverage.__file__).parent
    coordinates = {}
    trees = {}
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        trees[path.stem] = tree
        for node in tree.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "COORDINATE"
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                coordinates[path.stem] = node.value.value
    pairs = set()
    for module, tree in trees.items():
        dependent = coordinates.get(module)
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "verifier.domains.contracts":
                aliases.update({name.asname or name.name: name.name for name in node.names})
        for node in ast.walk(tree):
            if (dependent is None or not isinstance(node, ast.Call)
                    or not isinstance(node.func, ast.Attribute)
                    or not node.func.attr.startswith("recheck_")
                    or not node.func.attr.endswith("_certificate")
                    or not isinstance(node.func.value, ast.Name)):
                continue
            prerequisite = coordinates.get(aliases.get(node.func.value.id, ""))
            if prerequisite is not None and prerequisite != dependent:
                pairs.add((prerequisite, dependent))
    return pairs


def test_every_direct_fixed_source_consumer_is_declared() -> None:
    declared = pair_set(coverage.installed_native_dependency_inventory()["fixed_pairs"])
    assert _direct_module_pairs() <= declared
    assert EXPECTED_MULTI_COORDINATE <= declared


def test_exact_inventory_replay_refutes_omission_and_digest_substitution() -> None:
    installed = coverage.installed_native_dependency_inventory()
    raw = canonical_bytes(installed)
    selected = dag._digest(raw)
    exact = coverage.recheck_native_dependency_inventory(raw,
        expected_inventory_digest=selected)
    assert exact["status"] == "PASS" and exact["replay_status"] == "REPRODUCED"
    missing = coverage.recheck_native_dependency_inventory(None,
        expected_inventory_digest=selected)
    assert missing["status"] == "UNKNOWN" and missing["replay_status"] == "UNAVAILABLE"
    changed = deepcopy(installed)
    changed["fixed_pairs"] = changed["fixed_pairs"][:-1]
    rejected = coverage.recheck_native_dependency_inventory(canonical_bytes(changed),
        expected_inventory_digest=selected)
    assert rejected["status"] == "FAIL" and rejected["replay_status"] == "REJECTED"
    foreign = coverage.recheck_native_dependency_inventory(raw,
        expected_inventory_digest="sha256:" + "0" * 64)
    assert foreign["status"] == "FAIL" and foreign["replay_status"] == "REJECTED"
