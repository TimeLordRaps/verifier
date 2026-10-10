#!/usr/bin/env python3
"""Build a fail-closed external Tier 1 (FACETS) Verifier Standard (VSTD) ledger.

abstract syntax tree (AST); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).

The denominator is read from ``installed_core_route_inventory`` at runtime. The
builder maps every installed checker to one exact positive, negative, and
unknown test node, binds source/test/mechanism bytes, and can translate a frozen
replay receipt into candidate artifacts. Translation does not authenticate a
caller-carried PASS or establish provider review, whole-tier conformance, or
release readiness; the stable digests require comparison with a fresh replay.
"""

from __future__ import annotations

import argparse
import ast
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from verifier.runtime import core_obligation_union  # noqa: E402
from verifier.runtime import self_polish_evidence, self_polish_tiers  # noqa: E402
from verifier.runtime.core_tier_progression import (  # noqa: E402
    installed_core_route_inventory,
)


LEDGER_SCHEMA = self_polish_tiers.TIER_LEDGER_SCHEMA
INVENTORY_SCHEMA = "verifier-current-nine-core-installed-route-inventory-1"
EXPECTED_INVENTORY_DIGEST = (
    "sha256:674bab9a72bb4e94103c0f582f3fc1e32c87d6a73747400de5e8e9ca792fa07f"
)
EXPECTED_TIER1_IDENTITY_DIGEST = (
    "sha256:c7206a2c3efd9af4c52590ea7d700bb6f6e56d748e888e6e27f42dfedc6d0b95"
)
EXPECTED_GLOBAL_CELLS = 234
EXPECTED_GLOBAL_MEMBERSHIPS = 408
EXPECTED_OBJECT_KINDS = 26
EXPECTED_TIERS = 9
EXPECTED_TIER1_CELLS = 26
EXPECTED_TIER1_MEMBERSHIPS = 45
EXPECTED_TIER1_CHECKERS = 15
EXPECTED_EVIDENCE_CASES = EXPECTED_TIER1_MEMBERSHIPS * 3
EVIDENCE_CANDIDATE_SCHEMA = "verifier-self-polish-tier1-evidence-candidate-1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTITY_FIELDS = (
    "object_kind",
    "tier",
    "coordinate",
    "proposition_digest",
    "semantic_version",
    "certificate_schema_version",
    "checking_mechanism",
    "scope",
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _source_coordinate(value: Any) -> dict[str, str]:
    fields = {
        "source_head", "source_tree", "source_worktree_status_digest",
        "source_manifest_digest",
    }
    _require(type(value) is dict and set(value) == fields,
             "source coordinate fields differ")
    _require(type(value["source_head"]) is str
             and _GIT_OBJECT.fullmatch(value["source_head"]) is not None,
             "source head is not a Git object identifier")
    _require(type(value["source_tree"]) is str
             and _GIT_OBJECT.fullmatch(value["source_tree"]) is not None,
             "source tree is not a Git object identifier")
    for name in ("source_worktree_status_digest", "source_manifest_digest"):
        _require(type(value[name]) is str
                 and _SHA256.fullmatch(value[name]) is not None,
                 f"{name} is not a canonical SHA-256 digest")
    return {name: value[name] for name in sorted(fields)}


def _tier1_identities(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate the complete installed inventory and select exact FACETS members."""

    _require(inventory.get("schema_version") == INVENTORY_SCHEMA
             and inventory.get("status") == "PASS",
             "installed route inventory is unavailable")
    _require(inventory.get("object_kind_count") == EXPECTED_OBJECT_KINDS
             and inventory.get("tier_count") == EXPECTED_TIERS
             and inventory.get("family_cell_count") == EXPECTED_GLOBAL_CELLS
             and inventory.get("registered_route_membership_count")
                 == EXPECTED_GLOBAL_MEMBERSHIPS,
             "installed route inventory totals differ")
    cells = inventory.get("family_cells")
    _require(type(cells) is list and len(cells) == EXPECTED_GLOBAL_CELLS,
             "installed family-cell denominator differs")

    observed_cells: set[tuple[str, int]] = set()
    observed_memberships: set[tuple[str, str]] = set()
    by_tier = {str(tier): 0 for tier in range(1, EXPECTED_TIERS + 1)}
    identities: list[dict[str, Any]] = []
    tier1_kinds: set[str] = set()
    for cell in cells:
        _require(type(cell) is dict
                 and type(cell.get("object_kind")) is str
                 and type(cell.get("tier")) is int,
                 "installed family cell is malformed")
        cell_key = (cell["object_kind"], cell["tier"])
        _require(cell_key not in observed_cells, "installed family cell is duplicated")
        observed_cells.add(cell_key)
        memberships = cell.get("registered_route_memberships")
        _require(type(memberships) is list and memberships
                 and cell.get("registered_route_membership_count") == len(memberships),
                 "installed family-cell membership count differs")
        _require(str(cell["tier"]) in by_tier, "installed tier is outside the profile")
        by_tier[str(cell["tier"])] += len(memberships)
        for member in memberships:
            _require(type(member) is dict
                     and set(member) == {
                         "semantic_version", "coordinate", "proposition_digest",
                         "certificate_schema_version", "checking_mechanism", "scope",
                     },
                     "installed membership fields differ")
            key = (cell["object_kind"], member["coordinate"])
            _require(key not in observed_memberships,
                     "installed route membership is duplicated")
            observed_memberships.add(key)
            if cell["tier"] == 1:
                _require(cell.get("tier_name") == "FACETS",
                         "Tier 1 name differs from FACETS")
                tier1_kinds.add(cell["object_kind"])
                identities.append({
                    "object_kind": cell["object_kind"],
                    "tier": 1,
                    **member,
                })

    declared_by_tier = inventory.get("registered_route_membership_count_by_tier")
    _require(type(declared_by_tier) is dict and declared_by_tier == by_tier,
             "installed per-tier membership totals differ")
    _require(sum(by_tier.values()) == EXPECTED_GLOBAL_MEMBERSHIPS,
             "installed membership denominator differs")
    identities.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
    _require(len(tier1_kinds) == EXPECTED_TIER1_CELLS
             and len(identities) == EXPECTED_TIER1_MEMBERSHIPS,
             "Tier 1 denominator differs")
    _require(len({row["checking_mechanism"] for row in identities})
             == EXPECTED_TIER1_CHECKERS,
             "Tier 1 installed-checker subset differs")
    _require(core_obligation_union.value_digest(identities)
             == EXPECTED_TIER1_IDENTITY_DIGEST,
             "Tier 1 membership identity digest differs")
    _require(core_obligation_union.value_digest(inventory)
             == EXPECTED_INVENTORY_DIGEST,
             "installed route inventory digest differs")
    return identities


def _checker_source(mechanism: str, root: Path) -> tuple[str | None, str]:
    """Resolve a dotted installed checker to one repository file and symbol."""

    _require(type(mechanism) is str and mechanism.count(".") >= 2,
             "checking mechanism is not a dotted symbol")
    module_name, symbol = mechanism.rsplit(".", 1)
    if not module_name.startswith("verifier."):
        return None, symbol
    relative = Path("src", *module_name.split(".")).with_suffix(".py")
    path = root / relative
    if not path.is_file():
        return None, symbol
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return None, symbol
    definitions = {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    if symbol not in definitions:
        return None, symbol
    return relative.as_posix(), symbol


_GENERIC_CASE_RULES = {
    "agent_checks": (
        "agent_checks", "test_current_agent_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
    "bench_checks": (
        "bench_checks", "test_current_bench_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
    "bot_checks": (
        "bot_checks", "test_current_bot_positive_replay_is_deterministic_and_bounded",
        "test_current_bot_native_counterexamples_are_refuted",
        "test_missing_evidence_is_unknown",
    ),
    "data_checks": (
        "data_checks", "test_current_data_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
    "env_checks": (
        "env_checks", "test_current_env_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
    "harness_checks": (
        "harness_checks", "test_current_harness_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
    "model_checks": (
        "model_checks", "test_current_model_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
    "train_checks": (
        "train_checks", "test_current_train_positive_replay_is_bounded_and_deterministic",
        "test_rehashed_rebound_false_native_evidence_is_refuted",
        "test_missing_retained_evidence_is_unknown",
    ),
}

_CHECK_BY_COORDINATE = {
    "AGENT-1.8": "harness",
    "BENCH-1.2": "problems",
    "BENCH-1.4": "oracles",
    "BOT-1.6": "binding",
    "DATA-1.2": "inventory",
    "DATA-1.4": "schema",
    "ENV-1.2": "closure",
    "ENV-1.5": "configuration",
    "HARNESS-1.6": "surface",
    "MODEL-1.2": "tensors",
    "MODEL-1.5": "artifacts",
    "TRAIN-1.2": "configuration",
    "TRAIN-1.3": "checkpoints",
}

_SPECIAL_CASE_RULES = {
    "env_configuration_surface": (
        "env_configuration_surface",
        "test_selected_required_configuration_domains_replay",
        "test_out_of_domain_and_incomplete_configuration_fail[config0]",
        "test_missing_selected_facet_certificate_is_unknown",
    ),
    "env_executable": (
        "env_executable",
        "test_exact_entrypoint_interpreter_and_selected_versions_replay",
        "test_changed_interpreter_bytes_refute_retained_inventory",
        "test_missing_selected_inventory_is_unknown",
    ),
    "hardware_inventory": (
        "hardware_inventory",
        "test_retained_inventory_replays_at_distinct_coordinate_without_physical_promotion",
        "test_substituted_retained_devices_fail_without_changing_the_selected_subject",
        "test_missing_retained_inputs_remain_unknown",
    ),
    "hardware_topology": (
        "hardware_topology",
        "test_exact_retained_containment_replays_without_physical_promotion",
        "test_cycle_self_edge_unresolved_or_duplicate_containment_fails[edges0]",
        "test_missing_inputs_remain_unknown_and_budget_exhaustion_does_not_pass",
    ),
    "object_facets": (
        "object_facets",
        "test_positive_generic_object_certificate_replays_exact_bytes_without_tier_promotion",
        "test_rehashed_result_forgery_is_rejected_by_reexecution[status-FAIL]",
        "test_missing_selected_evidence_is_replayable_unknown",
    ),
    "train_data_bridge": (
        "train_data_bridge",
        "test_exact_linked_native_children_replay",
        "test_individually_valid_substituted_data_is_refuted_by_bridge",
        "test_missing_selected_train_child_is_unknown",
    ),
}


def _function_source(path: Path, function: str) -> str:
    """Return one exact test function after rejecting missing/ambiguous names."""

    base = function.split("[", 1)[0]
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    matches = [node for node in tree.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == base]
    _require(len(matches) == 1, f"test function is missing or ambiguous: {path}:{base}")
    segment = ast.get_source_segment(text, matches[0])
    _require(type(segment) is str and segment, f"test function cannot be inspected: {path}:{base}")
    return segment


def _semantic_case_check(root: Path, row: dict[str, str]) -> None:
    """Reject a mapped node whose inspected assertion does not match its lane."""

    path = root / row["test_path"]
    function = row["node_id"].split("::", 1)[1]
    source = _function_source(path, function)
    kind = row["case_kind"]
    if row["test_path"] == "tests/test_polish_requirements.py":
        markers = ("registered_objective_binding", "mechanism_digest", "proposition_digest")
    elif (row["test_path"] == "tests/test_current_typed_facets.py"
          and kind == "UNKNOWN"):
        markers = ("computational_status", "PASS", "NOT_ESTABLISHED")
    elif kind == "POSITIVE":
        markers = ("PASS",)
    elif kind == "NEGATIVE":
        markers = ("FAIL",)
    else:
        markers = ("UNKNOWN",)
    inspected = source + "\n" + function
    _require(all(marker in inspected for marker in markers),
             f"test assertion mechanism is not relevant to {kind}: {row['node_id']}")


def _case_nodes(membership: dict[str, Any]) -> tuple[str, str, str]:
    kind = membership["object_kind"]
    coordinate = membership["coordinate"]
    leaf = membership["checking_mechanism"].rsplit(".", 2)[-2]
    if leaf == "typed_facets":
        return (
            "tests/test_polish_requirements.py::"
            "test_every_registered_objective_has_an_installed_binding_for_each_admitted_kind"
            f"[{coordinate}/{kind}]",
            "tests/test_current_typed_facets.py::"
            f"test_native_facets_refute_a_selected_malformed_kind_contract[{kind}]",
            "tests/test_current_typed_facets.py::"
            f"test_native_typed_facets_replay_each_kind_without_profile_promotion[{kind}]",
        )
    if leaf in _GENERIC_CASE_RULES:
        filename, positive, negative, unknown = _GENERIC_CASE_RULES[leaf]
        check = _CHECK_BY_COORDINATE.get(coordinate)
        _require(check is not None, f"checking mechanism coordinate is unmapped: {coordinate}")
        prefix = f"tests/test_current_{filename}.py::"
        return tuple(f"{prefix}{function}[{check}]"
                     for function in (positive, negative, unknown))
    special = _SPECIAL_CASE_RULES.get(leaf)
    _require(special is not None, f"checking mechanism is unmapped: {leaf}")
    filename, positive, negative, unknown = special
    prefix = f"tests/test_current_{filename}.py::"
    return tuple(prefix + function for function in (positive, negative, unknown))


def _mapping_rows(identities: list[dict[str, Any]], root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for membership in identities:
        source, _ = _checker_source(membership["checking_mechanism"], root)
        _require(source is not None,
                 f"checking mechanism source is unresolved: {membership['checking_mechanism']}")
        obligation_id = f"{membership['object_kind']}:{membership['coordinate']}"
        for case_kind, node_id in zip(self_polish_evidence.CASE_KIND_ORDER,
                                      _case_nodes(membership), strict=True):
            test_path = node_id.split("::", 1)[0]
            row = {
                "obligation_id": obligation_id,
                "case_kind": case_kind,
                "node_id": node_id,
                "source_path": source,
                "test_path": test_path,
                "mechanism_path": self_polish_evidence.PRIMARY_MECHANISM_PATH,
            }
            _semantic_case_check(root, row)
            rows.append(row)
    rows.sort(key=lambda row: (
        row["obligation_id"], self_polish_evidence.CASE_KIND_ORDER.index(row["case_kind"])
    ))
    _require(len(rows) == EXPECTED_EVIDENCE_CASES, "Tier 1 evidence case denominator differs")
    _require(len({row["node_id"] for row in rows}) == EXPECTED_EVIDENCE_CASES,
             "Tier 1 evidence node is duplicated or borrowed")
    _require(all(not Path(row["test_path"]).name.startswith("test_self_polish") for row in rows),
             "self-polish tests cannot evidence self-polish")
    return rows


@lru_cache(maxsize=4)
def _collected_nodes(root_text: str, selected: tuple[tuple[str, str], ...]) -> frozenset[str]:
    root = Path(root_text)
    paths = [path for path, _ in selected]
    environment = dict(os.environ)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTHONPATH"] = str(root / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--noconftest", *paths],
        cwd=root, env=environment, capture_output=True, text=True, timeout=60, check=False,
    )
    _require(completed.returncode == 0,
             "selected pytest node collection failed: " + completed.stderr[-1000:])
    return frozenset(line.strip() for line in completed.stdout.splitlines()
                     if line.startswith("tests/"))


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def build_evidence_manifest(*, root: Path = ROOT,
                            inventory: dict[str, Any] | None = None,
                            repository: str | None = None,
                            revision: str | None = None,
                            validate_collection: bool = True) -> dict[str, Any]:
    """Build the exact 45-membership, 135-node frozen replay manifest."""

    selected_inventory = (installed_core_route_inventory()
                          if inventory is None else inventory)
    identities = _tier1_identities(selected_inventory)
    rows = _mapping_rows(identities, root)
    test_paths = sorted({row["test_path"] for row in rows})
    if validate_collection:
        selected = tuple((path, _file_digest(root / path)) for path in test_paths)
        collected = _collected_nodes(str(root.resolve()), selected)
        missing = sorted({row["node_id"] for row in rows} - collected)
        _require(not missing, f"selected pytest nodes do not exist: {missing[:3]}")
    if repository is None or revision is None:
        repository, revision = _git_source_coordinate(root)
    _require(type(repository) is str and bool(repository), "repository coordinate is unavailable")
    _require(type(revision) is str and _GIT_OBJECT.fullmatch(revision) is not None,
             "revision coordinate is unavailable")
    roles: dict[str, str] = {self_polish_evidence.PRIMARY_MECHANISM_PATH: "MECHANISM"}
    for row in rows:
        roles[row["source_path"]] = "SOURCE"
        roles[row["test_path"]] = "TEST"
    files = [{"path": path, "role": roles[path], "sha256": _file_digest(root / path)}
             for path in sorted(roles)]
    return {
        "schema_version": self_polish_evidence.MANIFEST_SCHEMA,
        "source_coordinate": {"repository": repository, "revision": revision},
        "files": files,
        "obligations": rows,
    }


def _git_source_coordinate(root: Path) -> tuple[str, str]:
    def selected(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments], cwd=root, capture_output=True, text=True,
            timeout=10, check=False,
        )
        _require(completed.returncode == 0 and bool(completed.stdout.strip()),
                 "Git source coordinate is unavailable")
        return completed.stdout.strip()
    return selected("config", "--get", "remote.origin.url"), selected("rev-parse", "HEAD")


def _entry(membership: dict[str, Any], *, coordinate_digest: str,
           root: Path, mapped_cases: tuple[dict[str, str], ...]) -> dict[str, Any]:
    mechanism = membership["checking_mechanism"]
    module_name, _ = mechanism.rsplit(".", 1)
    source, symbol = _checker_source(mechanism, root)
    files = ([source] if source is not None else [f"UNMAPPED:{module_name}"])
    files.extend(sorted({row["test_path"] for row in mapped_cases}))
    files.append(self_polish_evidence.PRIMARY_MECHANISM_PATH)
    sources = list(files)
    mapping_state = "EXACT_THREE_CASE_MAPPING"
    kind = membership["object_kind"]
    route = membership["coordinate"]
    return {
        "membership": dict(membership),
        "applicability_status": "UNKNOWN",
        "authority_status": "UNKNOWN",
        "observation_status": "UNKNOWN",
        "native_assessment_status": "UNKNOWN",
        "provider_review_status": "UNKNOWN",
        "native_assessment_digest": None,
        "obligation_id": f"{kind}:{route}",
        "definition_source": {
            "proposition_digest": membership["proposition_digest"],
            "scope": membership["scope"],
        },
        "definition_version": membership["semantic_version"],
        "implementation": {
            "checking_mechanism": mechanism,
            "files": files,
            "symbols": [symbol],
        },
        "evidence": {
            "native_assessment_digest": None,
            "source_coordinate_digest": coordinate_digest,
            "freshness": "UNKNOWN",
            "sources": sources,
        },
        "dependencies": [
            f"certificate-schema:{membership['certificate_schema_version']}",
            f"checking-mechanism:{mechanism}",
        ],
        "prerequisites": [
            "exact-native-request",
            "independently-selected-checker-policy",
            "retained-bound-evidence",
        ],
        "applicability": {
            "platform_status": "UNKNOWN",
            "binding_status": "UNKNOWN",
        },
        "expected_behavior": {
            "positive": (
                f"PASS requires replay by {mechanism} for the exact {kind}/{route} "
                "binding and retained evidence; this template supplies no PASS receipt."
            ),
            "negative": (
                "FAIL requires a mechanically supplied native counterexample or binding "
                "failure receipt. The mapped NEGATIVE node is only a candidate until "
                "the frozen replay mechanism supplies a source-bound receipt."
            ),
            "unknown": (
                "UNKNOWN is required while applicability, authority, observation, "
                "provider review, focused validation, independent replay, or freshness "
                f"is absent. Test mapping is {mapping_state}; coverage remains "
                "UNKNOWN. Any source-coordinate, inventory, implementation, or "
                "candidate-test change invalidates prior evidence. This installed-route "
                "subledger does not establish repository/package semantic closure or "
                "completion of vstd polish 1."
            ),
        },
        "ownership": {
            "supervisor": "SUPERVISOR_D",
            "owner": "UNASSIGNED_EXTERNAL_REVIEWER",
        },
        "provider_records": {
            "claude": {
                "state": "CLAUDE_PROVIDER_BLOCKED",
                "receipt_digest": None,
            },
            "antigravity": {
                "state": "ANTIGRAVITY_PROVIDER_BLOCKED",
                "receipt_digest": None,
            },
        },
        "implementation_status": "NOT_ESTABLISHED",
        "focused_validation": {"status": "UNKNOWN", "receipt_digest": None},
        "independent_replay": {"status": "UNKNOWN", "receipt_digest": None},
        "final_disposition": "UNKNOWN",
        "justified_exclusion": None,
    }


def build_ledger(source_coordinate: dict[str, str], *, root: Path = ROOT,
                 inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the exact installed FACETS template without granting tier status."""

    coordinate = _source_coordinate(source_coordinate)
    selected_inventory = (installed_core_route_inventory()
                          if inventory is None else inventory)
    identities = _tier1_identities(selected_inventory)
    coordinate_digest = core_obligation_union.value_digest(coordinate)
    case_rows = _mapping_rows(identities, root)
    cases_by_obligation = {
        f"{row['object_kind']}:{row['coordinate']}": tuple(
            case for case in case_rows
            if case["obligation_id"] == f"{row['object_kind']}:{row['coordinate']}"
        )
        for row in identities
    }
    entries = [
        _entry(
            membership,
            coordinate_digest=coordinate_digest,
            root=root,
            mapped_cases=cases_by_obligation[
                f"{membership['object_kind']}:{membership['coordinate']}"
            ],
        )
        for membership in identities
    ]
    body: dict[str, Any] = {
        "schema_version": LEDGER_SCHEMA,
        "tier": 1,
        "tier_name": "FACETS",
        "source_coordinate": coordinate,
        "source_coordinate_digest": coordinate_digest,
        "installed_inventory_digest": core_obligation_union.value_digest(
            selected_inventory
        ),
        "installed_family_cell_count_total": selected_inventory[
            "family_cell_count"
        ],
        "installed_membership_count_total": selected_inventory[
            "registered_route_membership_count"
        ],
        "tier_family_cell_count": len({row["object_kind"] for row in identities}),
        "tier_membership_count": len(identities),
        "entries": entries,
    }
    return {**body, "ledger_digest": core_obligation_union.value_digest(body)}


def validate_evidence_manifest(manifest: dict[str, Any], *, root: Path = ROOT,
                               inventory: dict[str, Any] | None = None,
                               validate_collection: bool = False) -> None:
    """Validate a manifest against fresh inventory, mappings, and file bytes."""

    _require(type(manifest) is dict
             and type(manifest.get("source_coordinate")) is dict,
             "evidence manifest is malformed")
    coordinate = manifest["source_coordinate"]
    _require(set(coordinate) == {"repository", "revision"},
             "evidence manifest source coordinate differs")
    expected = build_evidence_manifest(
        root=root,
        inventory=inventory,
        repository=coordinate["repository"],
        revision=coordinate["revision"],
        validate_collection=validate_collection,
    )
    _require(manifest == expected,
             "evidence manifest is incomplete, substituted, duplicated, or stale")


def _obligation_mapping_digest(obligation_ids: list[str]) -> str:
    mapping = [{
        "obligation_id": identifier,
        "required_case_kinds": list(self_polish_evidence.CASE_KIND_ORDER),
    } for identifier in sorted(obligation_ids)]
    return self_polish_evidence.bytes_digest(
        self_polish_evidence.canonical_bytes(mapping)
    )


def _validated_replay_projection(receipt: dict[str, Any],
                                 manifest: dict[str, Any]) -> dict[str, Any]:
    """Validate receipt structure without authenticating its carried PASS label."""

    manifest_digest = self_polish_evidence.bytes_digest(
        self_polish_evidence.canonical_bytes(manifest)
    )
    files = {row["path"]: row for row in manifest["files"]}
    mechanism_digest = files[self_polish_evidence.PRIMARY_MECHANISM_PATH]["sha256"]
    obligations = manifest["obligations"]
    identifiers = sorted({row["obligation_id"] for row in obligations})
    mapping_digest = _obligation_mapping_digest(identifiers)
    _require(type(receipt) is dict
             and set(receipt) == {
                 "schema_version", "status", "tier", "polished",
                 "release_authority", "whole_tier_conformance", "provider_states",
                 "manifest_digest", "expected_manifest_digest", "mechanism_digest",
                 "expected_mechanism_digest", "obligation_mapping_digest",
                 "stable_replay_set_digest", "evidence_digest", "run_artifacts",
                 "source_coordinate", "memberships", "counts", "invalidators",
                 "claim_boundary", "receipt_digest",
             }
             and receipt.get("schema_version") == self_polish_evidence.RECEIPT_SCHEMA
             and receipt.get("status") == "PASS"
             and receipt.get("invalidators") == []
             and receipt.get("tier") == 1
             and receipt.get("polished") is False
             and receipt.get("release_authority") == "NONE"
             and receipt.get("whole_tier_conformance") == "NOT_ESTABLISHED"
             and receipt.get("provider_states") == "OUT_OF_SCOPE",
             "candidate replay receipt does not carry a complete replay")
    _require(receipt.get("manifest_digest") == manifest_digest
             and receipt.get("expected_manifest_digest") == manifest_digest
             and receipt.get("mechanism_digest") == mechanism_digest
             and receipt.get("expected_mechanism_digest") == mechanism_digest
             and receipt.get("obligation_mapping_digest") == mapping_digest,
             "candidate replay receipt binding differs")
    coordinate = receipt.get("source_coordinate")
    observed_files = {row["path"]: row["sha256"] for row in manifest["files"]}
    _require(type(coordinate) is dict
             and coordinate == {
                 "repository": manifest["source_coordinate"]["repository"],
                 "revision": manifest["source_coordinate"]["revision"],
                 "selected_files_digest": self_polish_evidence.bytes_digest(
                     self_polish_evidence.canonical_bytes(observed_files)
                 ),
                 "scope": "SELECTED_FILES_ONLY",
             }, "candidate replay source coordinate differs")
    _require(receipt.get("counts") == {
                 "expected": EXPECTED_EVIDENCE_CASES,
                 "collected": EXPECTED_EVIDENCE_CASES,
                 "passed": EXPECTED_EVIDENCE_CASES,
                 "failed": 0,
                 "skipped": 0,
                 "xfailed": 0,
                 "xpassed": 0,
             }, "candidate replay case denominator differs")
    run_artifacts = receipt.get("run_artifacts")
    _require(type(run_artifacts) is dict
             and set(run_artifacts) == {
                 "pytest_trace_digest", "junit_xml_digest", "stdout_digest",
                 "stderr_digest",
             }
             and all(type(value) is str and _SHA256.fullmatch(value) is not None
                     for value in run_artifacts.values())
             and type(receipt.get("evidence_digest")) is str
             and _SHA256.fullmatch(receipt["evidence_digest"]) is not None,
             "candidate replay event evidence differs")
    expected_rows = {(row["obligation_id"], row["case_kind"]): row
                     for row in obligations}
    memberships = receipt.get("memberships")
    _require(type(memberships) is list and len(memberships) == EXPECTED_TIER1_MEMBERSHIPS,
             "candidate replay membership denominator differs")
    stable_memberships: dict[str, str] = {}
    observed_nodes: set[str] = set()
    for membership in memberships:
        _require(type(membership) is dict
                 and set(membership) == {
                     "obligation_id", "cases", "status", "stable_replay_digest",
                 }
                 and membership["obligation_id"] in identifiers
                 and membership["obligation_id"] not in stable_memberships
                 and membership["status"] == "PASS"
                 and type(membership["stable_replay_digest"]) is str
                 and _SHA256.fullmatch(membership["stable_replay_digest"]) is not None,
                 "candidate replay membership differs")
        cases = membership["cases"]
        _require(type(cases) is list and len(cases) == 3,
                 "candidate replay case differs")
        for case_kind, case in zip(self_polish_evidence.CASE_KIND_ORDER,
                                   cases, strict=True):
            expected = expected_rows[(membership["obligation_id"], case_kind)]
            _require(type(case) is dict
                     and set(case) == {
                         "case_kind", "node_id", "source", "test", "mechanism", "status",
                     }
                     and case["case_kind"] == case_kind
                     and case["node_id"] == expected["node_id"]
                     and case["node_id"] not in observed_nodes
                     and case["source"] == {
                         "path": expected["source_path"],
                         "sha256": files[expected["source_path"]]["sha256"],
                     }
                     and case["test"] == {
                         "path": expected["test_path"],
                         "sha256": files[expected["test_path"]]["sha256"],
                     }
                     and case["mechanism"] == {
                         "path": expected["mechanism_path"],
                         "sha256": files[expected["mechanism_path"]]["sha256"],
                     }
                     and case["status"] == "PASS",
                     "candidate replay case differs")
            observed_nodes.add(case["node_id"])
        stable_memberships[membership["obligation_id"]] = membership[
            "stable_replay_digest"
        ]
    _require(set(stable_memberships) == set(identifiers),
             "candidate replay membership differs")
    stable_set = receipt.get("stable_replay_set_digest")
    _require(type(stable_set) is str and _SHA256.fullmatch(stable_set) is not None,
             "candidate replay stable-set digest is absent")
    _require(type(receipt.get("receipt_digest")) is str
             and receipt["receipt_digest"] == self_polish_evidence.bytes_digest(
                 self_polish_evidence.canonical_bytes({
                     key: value for key, value in receipt.items()
                     if key != "receipt_digest"
                 })
             ), "candidate replay event receipt digest differs")
    return {
        "manifest_digest": manifest_digest,
        "mechanism_digest": mechanism_digest,
        "obligation_mapping_digest": mapping_digest,
        "stable_membership_replay_digests": dict(sorted(stable_memberships.items())),
        "stable_replay_set_digest": stable_set,
        "event_receipt_digest": receipt["receipt_digest"],
    }


def consume_replay_receipt(ledger: dict[str, Any], manifest: dict[str, Any],
                           receipt: dict[str, Any], *, root: Path = ROOT,
                           inventory: dict[str, Any] | None = None,
                           prior_whole_tier_report_digest: str | None = None,
                           ) -> dict[str, Any]:
    """Create candidate artifacts whose carried PASS still needs a fresh replay."""

    validate_evidence_manifest(manifest, root=root, inventory=inventory)
    _require(ledger.get("source_coordinate", {}).get("source_head")
             == manifest["source_coordinate"]["revision"],
             "ledger and evidence source revisions differ")
    expected_ledger = build_ledger(
        ledger["source_coordinate"], root=root, inventory=inventory
    )
    _require(ledger == expected_ledger, "candidate ledger template differs")
    projection = _validated_replay_projection(receipt, manifest)
    denominators = self_polish_tiers._denominators("verifier-core-self")
    reason_assessment = self_polish_tiers._validated_facet_reason_assessment(
        denominators
    )
    reason_partition = reason_assessment["consumer_route_partition"]
    candidate_ledger = deepcopy(ledger)
    stable = projection["stable_membership_replay_digests"]
    for entry in candidate_ledger["entries"]:
        entry["independent_replay"] = {
            "status": "PASS",
            "receipt_digest": stable[entry["obligation_id"]],
        }
    ledger_body = {key: value for key, value in candidate_ledger.items()
                   if key != "ledger_digest"}
    candidate_ledger["ledger_digest"] = core_obligation_union.value_digest(ledger_body)
    representation_body = {
        "schema_version": self_polish_tiers.SELF_REPRESENTATION_SCHEMA,
        "subject": {"object_id": "verifier-core-self", "object_kind": "VERIFIER"},
        "source_coordinate": candidate_ledger["source_coordinate"],
        "source_coordinate_digest": candidate_ledger["source_coordinate_digest"],
        "installed_inventory_digest": candidate_ledger["installed_inventory_digest"],
        "installed_family_cell_count_total": candidate_ledger[
            "installed_family_cell_count_total"
        ],
        "installed_membership_count_total": candidate_ledger[
            "installed_membership_count_total"
        ],
        "represented_tiers": [1],
        "tier_ledger_digest": candidate_ledger["ledger_digest"],
        "prior_whole_tier_report_digest": prior_whole_tier_report_digest,
        "representation_status": "PASS",
        "provider_review_status": "NOT_ESTABLISHED",
        "unobserved_fields": [],
        "representation_evidence_digest": projection["stable_replay_set_digest"],
        "tier1_facet_reason_assessment_digest": reason_assessment[
            "assessment_digest"
        ],
        "tier1_facet_reason_ledger_digest": reason_assessment["ledger_digest"],
        "tier1_facet_choice_identity_digest": reason_assessment[
            "choice_identity_digest"
        ],
        "tier1_reasoned_structural_membership_digest": reason_assessment[
            "reasoned_structural_membership_digest"
        ],
        "tier1_reasoned_route_membership_digest": reason_assessment[
            "reasoned_route_membership_digest"
        ],
        "tier1_reasoned_slot_digest": reason_assessment[
            "reasoned_slot_digest"
        ],
        "tier1_domain_route_reason_status": reason_assessment[
            "domain_route_reason_status"
        ],
        "tier1_domain_route_reason_identity_digest": reason_assessment[
            "domain_route_reason_identity_digest"
        ],
        "tier1_domain_route_reasons_digest": reason_partition[
            "domain_route_reasons_digest"
        ],
        "tier1_facet_direct_route_membership_count": reason_partition[
            "facet_direct_route_membership_count"
        ],
        "tier1_facet_direct_route_membership_digest": reason_partition[
            "facet_direct_route_membership_digest"
        ],
        "tier1_domain_route_membership_count": reason_partition[
            "domain_route_membership_count"
        ],
        "tier1_domain_route_membership_digest": reason_partition[
            "domain_route_membership_digest"
        ],
        "tier1_reason_route_union_membership_count": reason_partition[
            "route_union_membership_count"
        ],
        "tier1_reason_route_union_membership_digest": reason_partition[
            "route_union_membership_digest"
        ],
        "tier1_reason_route_partition_digest": reason_assessment[
            "consumer_route_partition_digest"
        ],
    }
    representation = {
        **representation_body,
        "representation_digest": core_obligation_union.value_digest(representation_body),
    }
    stable_candidate = {
        "authentication_status": "NOT_ESTABLISHED",
        "requires_fresh_replay": True,
        **projection,
    }
    return {
        "schema_version": EVIDENCE_CANDIDATE_SCHEMA,
        "claim_boundary": (
            "This 45-membership installed-route subledger spans 15 unique checkers. It "
            "is a replay-bound candidate, not the complete repository/package VERIFIER "
            "denominator, a Tier 1 clearance, or completion of vstd polish 1. "
            "Caller-carried PASS labels remain unauthenticated until the numeric gate "
            "performs a fresh replay; a match establishes only this required subset."
        ),
        "stable_candidate": stable_candidate,
        "candidate_ledger": candidate_ledger,
        "complete_self_representation": representation,
        "volatile_event_receipt": deepcopy(receipt),
    }


def compare_candidate_to_fresh_replay(candidate: dict[str, Any],
                                      fresh_receipt: dict[str, Any],
                                      manifest: dict[str, Any]) -> dict[str, str]:
    """Compare only stable digests; this comparison does not authenticate replay."""

    projection = _validated_replay_projection(fresh_receipt, manifest)
    stable = candidate.get("stable_candidate")
    _require(type(stable) is dict
             and stable.get("stable_membership_replay_digests")
                 == projection["stable_membership_replay_digests"]
             and stable.get("stable_replay_set_digest")
                 == projection["stable_replay_set_digest"],
             "fresh stable replay digest differs from candidate")
    return {
        "comparison_status": "MATCHED",
        "authentication_status": "NOT_ESTABLISHED",
        "stable_replay_set_digest": projection["stable_replay_set_digest"],
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load_coordinate(path: Path) -> dict[str, str]:
    raw = path.read_bytes()
    _require(len(raw) <= 1024 * 1024, "source coordinate exceeds one mebibyte")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("source coordinate is not strict UTF-8 JSON") from exc
    return _source_coordinate(value)


def _load_json(path: Path, *, maximum_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    raw = path.read_bytes()
    _require(len(raw) <= maximum_bytes, "selected JSON exceeds the input bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("selected input is not strict UTF-8 JSON") from exc
    _require(type(value) is dict, "selected JSON is not an object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the fail-closed external Tier 1 FACETS ledger template."
    )
    parser.add_argument(
        "--source-coordinate", type=Path, required=True,
        help="Strict JSON source coordinate emitted by the selected self-polish run.",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Write pretty JSON to this path; omit to write to standard output.",
    )
    parser.add_argument(
        "--evidence-manifest-output", type=Path,
        help="Also write the exact 45-membership, 135-node replay manifest.",
    )
    parser.add_argument(
        "--replay-receipt", type=Path,
        help="Consume a frozen replay receipt as unauthenticated candidate evidence.",
    )
    parser.add_argument(
        "--candidate-output", type=Path,
        help="Write candidate ledger, self-representation, stable digests, and volatile receipt.",
    )
    args = parser.parse_args(argv)
    try:
        ledger = build_ledger(_load_coordinate(args.source_coordinate))
        manifest = build_evidence_manifest() if (
            args.evidence_manifest_output is not None
            or args.replay_receipt is not None
        ) else None
        _require((args.replay_receipt is None) == (args.candidate_output is None),
                 "--replay-receipt and --candidate-output must be selected together")
        candidate = (
            consume_replay_receipt(
                ledger, manifest, _load_json(args.replay_receipt)
            )
            if args.replay_receipt is not None and manifest is not None else None
        )
    except (OSError, ValueError) as exc:
        print(f"[TIER1 LEDGER FAILED] {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        try:
            _write_json(args.output, ledger)
        except OSError as exc:
            print(f"[TIER1 LEDGER FAILED] {exc}", file=sys.stderr)
            return 2
        print(
            "[TIER1 LEDGER WRITTEN] "
            f"{args.output} {ledger['ledger_digest']} status=UNKNOWN"
        )
    try:
        if args.evidence_manifest_output is not None and manifest is not None:
            _write_json(args.evidence_manifest_output, manifest)
            print(
                "[TIER1 EVIDENCE MANIFEST WRITTEN] "
                f"{args.evidence_manifest_output} "
                f"{self_polish_evidence.bytes_digest(self_polish_evidence.canonical_bytes(manifest))}"
            )
        if args.candidate_output is not None and candidate is not None:
            _write_json(args.candidate_output, candidate)
            print(
                "[TIER1 EVIDENCE CANDIDATE WRITTEN] "
                f"{args.candidate_output} authentication=NOT_ESTABLISHED"
            )
    except OSError as exc:
        print(f"[TIER1 LEDGER FAILED] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
