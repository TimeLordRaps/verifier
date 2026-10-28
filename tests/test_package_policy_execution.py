"""Fresh provenance POLICY checks for Verifier Standard (VSTD)."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from test_package_polish import declared_package
from test_package_ledger_execution import select_execution as ledger_selection
from test_package_kind_requirements import save
from verifier.runtime import package_polish as package, provenance_policy_execution as execution
from verifier.runtime.local_ledger_worker import source_pins
from verifier.runtime.manifest_gate import obligation_catalog, assess_object_gate


PROVENANCE_NAMES = {
    "POLICY-1.1-provenance-input-scope", "POLICY-1.2-provenance-rule-defaults",
    "POLICY-2.1-provenance-decision-encoding", "POLICY-2.2-license-selection",
    "POLICY-3.1-incomplete-lineage", "POLICY-3.2-encoding-contradiction",
}
ENFORCEMENT_NAMES = {
    "POLICY-1.3-enforcement-rule-semantics",
    "POLICY-2.3-enforcement-exceptions-and-revisions",
    "POLICY-3.3-enforcement-decision-correspondence",
}
NAMES = PROVENANCE_NAMES | ENFORCEMENT_NAMES
POLICY_ROUTES_BY_TIER = {
    1: {
        "POLICY-1.1-provenance-input-scope",
        "POLICY-1.2-provenance-rule-defaults",
        "POLICY-1.3-enforcement-rule-semantics",
    },
    2: {
        "POLICY-2.1-provenance-decision-encoding",
        "POLICY-2.2-license-selection",
        "POLICY-2.3-enforcement-exceptions-and-revisions",
    },
    3: {
        "POLICY-3.1-incomplete-lineage",
        "POLICY-3.2-encoding-contradiction",
        "POLICY-3.3-enforcement-decision-correspondence",
    },
}
POLICY_COORDINATES_BY_TIER = {
    1: {"POLICY-1.1", "POLICY-1.2", "POLICY-1.3"},
    2: {"POLICY-2.1", "POLICY-2.2", "POLICY-2.3"},
    3: {"POLICY-3.1", "POLICY-3.2", "POLICY-3.3"},
}


def _assert_cumulative_policy_routes(
    rows: list[dict[str, Any]], *, tier: int,
    status: str | dict[str, str],
) -> None:
    expected = set().union(*(
        POLICY_COORDINATES_BY_TIER[depth] for depth in range(1, tier + 1)
    ))
    observed = [row["coordinate"] for row in rows]
    assert len(observed) == len(expected)
    assert set(observed) == expected
    assert Counter(observed) == Counter({name: 1 for name in expected})
    expected_status = (
        {coordinate: status for coordinate in expected}
        if type(status) is str else status
    )
    assert expected_status.keys() == expected
    observed_status = {row["coordinate"]: row["status"] for row in rows}
    assert observed_status == expected_status, [
        {
            "coordinate": row["coordinate"],
            "status": row["status"],
            "checker_status": row.get("checker_status"),
            "blockers": row.get("blockers"),
            "selected_status": (
                row.get("selected_package_check") or {}
            ).get("status"),
            "selected_reason": (
                row.get("selected_package_check") or {}
            ).get("reason"),
            "applicability_established": (
                row.get("selected_package_check") or {}
            ).get("applicability_established"),
        }
        for row in rows
    ]


def test_policy_has_reasoned_executable_routes() -> None:
    routes = {row["obligation_id"]: row for row in obligation_catalog()}
    assert NAMES <= routes.keys()
    assert all(routes[name]["reason"].strip() and routes[name]["exact_claim"].strip() for name in NAMES)


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = {"schema_version": execution.REQUEST_SCHEMA, "nonce": "policy-control-regression",
        "object_id": "policy", "object_digest": "sha256:" + "1" * 64, "collection_digest": "sha256:" + "2" * 64}
    result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(execution.__file__).with_name(execution.WORKER))],
        input=json.dumps(request).encode(), capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)
    assert report["request"] == request and report["source_pins"] == source_pins()
    assert len(result.stdout) < 1024 * 1024
    return report["observations"]


@pytest.mark.parametrize("coordinate", ["POLICY-1.1", "POLICY-1.2", "POLICY-2.1", "POLICY-2.2", "POLICY-3.1", "POLICY-3.2"])
def test_actual_policy_executions_satisfy_finite_claim(observations: dict[str, Any], coordinate: str) -> None:
    assert execution.check_observations(coordinate, observations)


@pytest.mark.parametrize("coordinate,path,replacement", [
    ("POLICY-1.1", ("missing", "licenses", "passed"), True),
    ("POLICY-1.1", ("matrix", 0, "all_valid", "target_artifact_id"), "unrelated"),
    ("POLICY-1.1", ("matrix",), []),
    ("POLICY-1.2", ("matrix", 5, "all_valid", "passed"), True),
    ("POLICY-1.2", ("matrix", 5, "no_revoked", "passed"), False),
    ("POLICY-1.2", ("matrix", 0, "all_valid", "passed"), 1),
    ("POLICY-1.2", ("status_values",), ["VALID"]),
    ("POLICY-2.1", ("matrix", 0, "all_valid", "clauses"), [[1]]),
    ("POLICY-2.1", ("matrix", 0, "all_valid", "variable_map", "VALID_root"), True),
    ("POLICY-2.1", ("matrix", 0, "no_revoked", "variable_map", "CLEAN_target"), 2),
    ("POLICY-2.2", ("licenses", 4, "result", "passed"), True),
    ("POLICY-2.2", ("licenses", 2, "result", "verdict"), "VERIFIED"),
    ("POLICY-2.2", ("licenses", 6, "result", "passed"), False),
    ("POLICY-2.2", ("licenses", 3, "allowed"), None),
    ("POLICY-3.1", ("invalid", "no_revoked", "returned"), True),
    ("POLICY-3.1", ("cycle", "passed"), True),
    ("POLICY-3.2", ("controls", "direct-conflict", "returned"), True),
    ("POLICY-3.2", ("controls", "solver-conflict", "exception"), None),
    ("POLICY-3.2", ("controls", "missing-fact", "returned"), True),
    ("POLICY-3.2", ("controls", "pass", "certificate", "header", "binding"), "sha256:" + "0" * 64),
    ("POLICY-3.2", ("controls", "fail", "certificate", "formula"), [[1]]),
])
def test_policy_oracle_refuses_wrong_inputs_decisions_and_proofs(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    changed = deepcopy(observations)
    row = changed
    for part in path[:-1]:
        row = row[part]
    row[path[-1]] = replacement
    assert not execution.check_observations(coordinate, changed)


@pytest.mark.parametrize("coordinate,section,name", [
    ("POLICY-3.1", "invalid", "licenses"),
    ("POLICY-3.2", "controls", "missing-target"),
])
def test_numeric_refusal_is_not_a_boolean_observation(observations: dict[str, Any], coordinate: str,
        section: str, name: str) -> None:
    changed = deepcopy(observations)
    changed[section][name]["returned"] = 0
    assert not execution.check_observations(coordinate, changed)


def test_disabled_encoding_enforcement_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.data import policy
    from verifier.runtime.provenance_policy_worker import observe
    monkeypatch.setattr(policy, "_require_every_variable_bound", lambda *args: None)
    assert not execution.check_observations("POLICY-3.2", observe())


def test_swapped_policy_meaning_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.data import policy
    from verifier.runtime.provenance_policy_worker import observe
    monkeypatch.setattr(policy.ProvenancePolicyVerifier, "verify_all_ancestors_valid",
                        policy.ProvenancePolicyVerifier.verify_no_revoked_ancestors)
    assert not execution.check_observations("POLICY-1.2", observe())


def test_actual_policy_selection_reaches_package_and_focused_gate(declared_package: tuple) -> None:
    root, retained, _ = declared_package
    document = ledger_selection(root, retained)
    row = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    row["specializations"].append("POLICY")
    row["surfaces"].append("file:" + execution.IMPLEMENTATION)
    save(root, document)
    missing = package.assess_package_polish(1, root)
    own = [row for row in missing["obligation_instances"] if row["object_id"] == "external" and row["object_kind"] == "POLICY"]
    _assert_cumulative_policy_routes(own, tier=1, status="UNKNOWN")
    document["namespace"]["execution_checks"].append({"object_id": "external", "mechanism": execution.ADAPTER,
        "reason": "This object owns the installed provenance-policy decision engine; finite rule executions require separate evidence.",
        "evidence": [{"path": execution.IMPLEMENTATION,
            "sha256": package.binding.bytes_digest((root / execution.IMPLEMENTATION).read_bytes())}]})
    save(root, document)
    report = package.assess_package_polish(3, root)
    own = [row for row in report["obligation_instances"] if row["object_id"] == "external" and row["object_kind"] == "POLICY"]
    _assert_cumulative_policy_routes(
        own,
        tier=3,
        status={
            coordinate: (
                "UNKNOWN" if coordinate.endswith(".3") else "PASS"
            )
            for coordinate in set().union(*POLICY_COORDINATES_BY_TIER.values())
        },
    )
    contract = next(row for row in report["kind_requirements"]["contract_coverage"]["contracts"]
                    if row["object_id"] == "external" and row["kind"] == "POLICY")
    assert contract["finite_check_status"] == "UNKNOWN"
    assert contract["status"] == "UNKNOWN" and contract["residual_requirements"]
    assert report["status"] == "UNKNOWN" and not report["polished"]
    gate = assess_object_gate("external", "POLICY-3.2-encoding-contradiction", root)
    assert gate["status"] == "PASS", gate["findings"]
    assert gate["instance"]["selected_package_check"]["replay"]["request"]["nonce"] != own[0]["selected_package_check"]["replay"]["request"]["nonce"]
    enforcement_gate = assess_object_gate(
        "external", "POLICY-3.3-enforcement-decision-correspondence", root,
    )
    assert enforcement_gate["status"] == "UNKNOWN"
    assert enforcement_gate["instance"]["coordinate"] == "POLICY-3.3"
    assert "PACKAGE_INSTANCE_EVIDENCE_MISSING" in enforcement_gate["instance"]["blockers"]


@pytest.mark.parametrize("mutation", ["omission", "duplicate", "old-two-route"])
def test_cumulative_policy_route_set_rejects_incomplete_or_duplicate_selection(
        mutation: str) -> None:
    if mutation == "old-two-route":
        tier = 1
        selected = [
            {"coordinate": coordinate, "status": "UNKNOWN"}
            for coordinate in ("POLICY-1.1", "POLICY-1.2")
        ]
        status = "UNKNOWN"
    else:
        tier = 3
        selected = [
            {"coordinate": coordinate, "status": "PASS"}
            for coordinate in sorted(set().union(
                *POLICY_COORDINATES_BY_TIER.values()
            ))
        ]
        status = "PASS"
        if mutation == "omission":
            selected = [
                row for row in selected
                if row["coordinate"] != "POLICY-2.3"
            ]
        else:
            selected.append(deepcopy(selected[0]))
    with pytest.raises(AssertionError):
        _assert_cumulative_policy_routes(selected, tier=tier, status=status)


@pytest.mark.parametrize("conflict", [None, "source", "ownership", "decision", "declaration", "selection"])
def test_reviewed_policy_selection_is_explicit_idempotent_and_no_overwrite(conflict: str | None) -> None:
    from verifier.runtime import package_manifest_migration, package_semantic_review_records

    select = package_manifest_migration._select_provenance_policy
    root = Path(execution.__file__).resolve().parents[3]
    review = package_semantic_review_records.review_document()[
        "vstd-dataset-provenance-policy"
    ]
    files = {
        path: package.binding.bytes_digest((root / path).read_bytes())
        for path in review["owned_paths"]
    }
    row = {"object_id": "vstd-dataset-provenance-policy", "kind": "POLICY",
           "surfaces": ["file:" + path for path in review["owned_paths"]], "specializations": [],
           "classification": {"POLICY": {"status": "UNRESOLVED", "reason": "", "evidence": []}}, "obligations": {}}
    namespace = {"objects": [row], "execution_checks": []}
    if conflict == "source":
        files[execution.IMPLEMENTATION] = "sha256:" + "0" * 64
    elif conflict == "ownership":
        row["surfaces"] = []
    elif conflict == "decision":
        row["classification"]["POLICY"]["status"] = "DOES_NOT_APPLY"
    elif conflict == "declaration":
        row["obligations"]["POLICY-0.1-rules-and-precedence"] = {"reason": "Prior review", "declaration": {"scope": "different"}}
    elif conflict == "selection":
        namespace["execution_checks"] = [{"object_id": row["object_id"], "mechanism": execution.ADAPTER, "reason": "different", "evidence": []}]
    before = deepcopy(namespace)
    if conflict:
        with pytest.raises(ValueError, match="PACKAGE_MIGRATION_"):
            select(root, namespace, row, files)
        assert namespace == before
    else:
        select(root, namespace, row, files)
        selected = deepcopy(namespace)
        select(root, namespace, row, files)
        assert namespace == selected
        assert row["specializations"] == []
        expected = review["classification"]["POLICY"]
        assert row["classification"]["POLICY"] == {
            "status": expected["status"],
            "reason": expected["reason"],
            "evidence": [
                {"path": path, "sha256": files[path]}
                for path in expected["evidence_paths"]
            ],
        }
        assert {
            name: binding["declaration"] for name, binding in row["obligations"].items()
        } == review["declarations"]
        assert namespace["execution_checks"][0]["evidence"] == [
            {"path": execution.IMPLEMENTATION, "sha256": files[execution.IMPLEMENTATION]}
        ]
        assert len(row["obligations"]) == 3 and len(namespace["execution_checks"]) == 1
