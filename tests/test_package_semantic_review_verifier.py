# Terminology: abstract syntax tree (AST).
from __future__ import annotations

import ast
import dataclasses
import re
import shutil
import subprocess
import sys
import traceback
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_current_model_hardware_observation import selected as selected_model_fixture
from verifier.domains import verifier_execution as execution_module
from verifier.domains.contracts import model_hardware_observation as observation
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import verifier_run_constraints as run_constraints
from verifier.runtime import gates
from verifier.runtime import namespace_discovery
from verifier.runtime import package_semantic_review_verifier as review
from verifier.runtime import self_polish_estate as estate
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS


EXPECTED_OBJECT_IDS = (
    "vstd-verifier-native-execution-controller",
    "vstd-verifier-run-constraint-controller",
    "vstd-repository-admission-reconciler",
    "vstd-native-gate-suite",
    "vstd-source-provenance-observer",
    "vstd-core-self-polish-assessor",
    "vstd-added-kind-behavioral-verifier",
    "vstd-asset-tier0-execution-verifier",
)
EXPECTED_PATHS = {
    "vstd-added-kind-behavioral-verifier": (
        "src/verifier/domains/contracts/finbot_checks.py",
        "src/verifier/domains/contracts/market_checks.py",
        "src/verifier/domains/contracts/robot_checks.py",
        "src/verifier/runtime/added_kind_behavioral_routes.py",
    ),
    "vstd-asset-tier0-execution-verifier": (
        "src/verifier/runtime/asset_execution.py",
    ),
    "vstd-verifier-native-execution-controller": (
        "src/verifier/domains/verifier_execution.py",
    ),
    "vstd-verifier-run-constraint-controller": (
        "src/verifier/domains/contracts/verifier_run_constraints.py",
    ),
    "vstd-repository-admission-reconciler": (
        "src/verifier/runtime/namespace_admission.py",
        "src/verifier/runtime/namespace_reconcile.mjs",
        "src/verifier/runtime/package_admission.py",
        "src/verifier/runtime/tier_zero_reconcile.mjs",
    ),
    "vstd-native-gate-suite": (
        "src/verifier/runtime/gate.py",
        "src/verifier/runtime/gates.py",
        "src/verifier/runtime/manifest_gate.py",
    ),
    "vstd-source-provenance-observer": (
        "src/verifier/runtime/explanation_projection.py",
        "src/verifier/runtime/prdel.py",
        "src/verifier/runtime/self_polish_estate.py",
    ),
    "vstd-core-self-polish-assessor": ("src/verifier/runtime/polish_requirements.py",),
}

ADDED_KIND_APPLICABILITY = {
    "ACTUATOR",
    "ASSET",
    "CONTROLLER",
    "FINBOT",
    "LEDGER",
    "MARKET",
    "MEASUREMENT",
    "POLICY",
    "PROTOCOL",
    "ROBOT",
    "SENSOR",
    "TRANSACTION",
}


EXPECTED_APPLICABILITY = {
    "vstd-added-kind-behavioral-verifier": ADDED_KIND_APPLICABILITY,
    "vstd-asset-tier0-execution-verifier": {"POLICY"},
    "vstd-verifier-native-execution-controller": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-verifier-run-constraint-controller": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "POLICY",
    },
    "vstd-repository-admission-reconciler": {
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-native-gate-suite": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-source-provenance-observer": {
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
    },
    "vstd-core-self-polish-assessor": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
}

# Ownership roles that this review holds UNRESOLVED (not refuted) pending an exact
# transaction boundary.  Reported for atomic reconciliation of the central ownership file.
EXPECTED_OWNERSHIP_UNRESOLVED = {
    "vstd-repository-admission-reconciler": {"TRANSACTION"},
    "vstd-source-provenance-observer": {"TRANSACTION"},
}

# No DOES_NOT_APPLY cell is audited.  The former ACTUATOR questions remain
# UNRESOLVED: reaching another owner's worker or accepting a process command does
# not transfer that worker's command-to-effect role, and fsmonitor is disabled.
EXPECTED_REFUTATIONS: dict[str, set[str]] = {}

# Reachability checks below prove that these foreign sources can execute.  They
# deliberately are not evidence for the caller's ACTUATOR classification.
DOWNSTREAM_WORKER_CHAIN = (
    "src/verifier/domains/contracts/current_object_routes.py",
    "src/verifier/domains/contracts/model_hardware_observation.py",
    "src/verifier/core/evidence.py",
    "src/verifier/domains/verifier_execution.py",
)
DISCOVERY_OBSERVER_CHAIN = (
    "src/verifier/runtime/namespace_discovery.py",
    "src/verifier/runtime/self_polish_estate.py",
)


def _expected_evidence(object_id: str, kind: str) -> tuple[str, ...]:
    """Exact evidence of one applicable or refuted cell: owned source only."""
    if object_id == "vstd-added-kind-behavioral-verifier" and kind in {
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "PROTOCOL",
        "SENSOR",
    }:
        return ("src/verifier/runtime/added_kind_behavioral_routes.py",)
    if object_id == "vstd-added-kind-behavioral-verifier" and kind == "FINBOT":
        return (
            "src/verifier/domains/contracts/finbot_checks.py",
            "src/verifier/runtime/added_kind_behavioral_routes.py",
        )
    if object_id == "vstd-added-kind-behavioral-verifier" and kind == "MARKET":
        return (
            "src/verifier/domains/contracts/market_checks.py",
            "src/verifier/runtime/added_kind_behavioral_routes.py",
        )
    if object_id == "vstd-added-kind-behavioral-verifier" and kind == "ROBOT":
        return (
            "src/verifier/domains/contracts/robot_checks.py",
            "src/verifier/runtime/added_kind_behavioral_routes.py",
        )
    return EXPECTED_PATHS[object_id]

RUNTIME = Path(review.__file__).resolve().parent
PACKAGE = RUNTIME.parent
REPO = PACKAGE.parent.parent
READ_ONLY_GIT_VERBS = frozenset(
    {"ls-tree", "cat-file", "rev-parse", "log", "merge-base", "ls-files", "status", "config"}
)
_GIT_HELPERS = {"_git", "_run_git"}
_PROCESS_CALLS = {"run", "Popen", "call", "check_call", "check_output"}
_WRITE_ATTRIBUTES = {
    "write_text",
    "write_bytes",
    "unlink",
    "mkdir",
    "makedirs",
    "touch",
    "rmdir",
    "symlink_to",
    "chmod",
}
_OS_WRITE_ATTRIBUTES = {"replace", "rename", "remove"}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _git_launch_findings(source: str) -> list[str]:
    """Return why a Git launch is not provably read-only; empty means it is."""
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    findings: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in _GIT_HELPERS and len(node.args) >= 2:
            verb = _string(node.args[1])
            following = [_string(arg) for arg in node.args[2:]]
            if verb is None:
                findings.append("dynamic git verb")
                continue
        elif name in _PROCESS_CALLS and node.args and isinstance(node.args[0], ast.List):
            items = node.args[0].elts
            if not items or _string(items[0]) != "git":
                continue
            if any(isinstance(item, ast.Starred) for item in items):
                cursor = parents.get(node)
                while cursor is not None and not isinstance(cursor, ast.FunctionDef):
                    cursor = parents.get(cursor)
                if cursor is not None and cursor.name in _GIT_HELPERS:
                    continue
                findings.append("dynamic git argv")
                continue
            literals = [_string(item) for item in items[1:]]
            literals = [value for value in literals if value and not value.startswith("-")]
            if not literals:
                findings.append("dynamic git verb")
                continue
            verb, following = literals[0], literals[1:]
        else:
            continue
        if verb not in READ_ONLY_GIT_VERBS:
            findings.append(verb)
        elif verb == "config" and (not following or following[0] != "--get"):
            findings.append("config without --get")
        elif verb == "status" and "--no-optional-locks" not in source:
            findings.append("status without --no-optional-locks")
    return findings


def _write_findings(source: str) -> list[str]:
    """Return every filesystem write call; the empty list means none is present."""
    findings: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = _call_name(node)
        if isinstance(func, ast.Attribute) and name in _WRITE_ATTRIBUTES:
            findings.append(name)
        elif (
            isinstance(func, ast.Attribute)
            and name in _OS_WRITE_ATTRIBUTES
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            findings.append("os." + name)
        elif name == "open":
            modes = [_string(arg) for arg in node.args[:2]] + [
                _string(keyword.value) for keyword in node.keywords if keyword.arg == "mode"
            ]
            if any(mode and set(mode) & set("wax+") for mode in modes):
                findings.append("open-write")
    return findings


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _all_obligations() -> dict[str, dict]:
    result = {}
    registry = namespace_registry()
    for kind in review.REVIEW_KINDS:
        for obligation in requirements_for(registry, (kind,)):
            if obligation["kind"] != kind:
                continue
            result[obligation["id"]] = {
                "reason": "",
                "evidence": [],
                "declaration": {
                    field: "" for field in obligation["declaration_fields"]
                },
            }
    return result


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows = {}
    files = {}
    for object_id, item in review.review_document().items():
        # Every evidence path must be owned by the reviewed object.
        evidence = dict.fromkeys(
            path
            for decision in item["classification"].values()
            for path in decision["evidence_paths"]
        )
        for path in (*item["owned_paths"], *evidence):
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = ("reviewed source " + path + "\n").encode()
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for semantic-review tests.",
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Current source has not yet been reviewed.",
                    "evidence": [],
                }
                for kind in review.REVIEW_KINDS
            },
            "obligations": _all_obligations(),
        }
    return tmp_path, rows, files


def test_review_document_has_exact_complete_eight_object_denominator():
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.VERIFIER_OBJECT_IDS == EXPECTED_OBJECT_IDS
    assert set(catalog) == set(EXPECTED_PATHS) == set(EXPECTED_APPLICABILITY)
    assert len(catalog) == 8
    assert sum(len(row["classification"]) for row in catalog.values()) == 96
    assert sum(len(row["declarations"]) for row in catalog.values()) == 129

    for object_id, item in catalog.items():
        assert tuple(item["owned_paths"]) == EXPECTED_PATHS[object_id]
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        refuted = EXPECTED_REFUTATIONS.get(object_id, set())
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert all(
            decision["status"]
            == (
                "APPLIES"
                if kind in applies
                else "DOES_NOT_APPLY"
                if kind in refuted
                else "UNRESOLVED"
            )
            and decision["reason"].strip()
            and bool(decision["evidence_paths"]) == (kind in applies or kind in refuted)
            for kind, decision in item["classification"].items()
        )
        assert all(
            tuple(decision["evidence_paths"]) == _expected_evidence(object_id, kind)
            for kind, decision in item["classification"].items()
            if kind in applies or kind in refuted
        )
        assert all(
            set(decision["evidence_paths"]) <= set(item["owned_paths"])
            for decision in item["classification"].values()
        )
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        } == refuted
        expected = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in applies
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected[obligation_id]
            assert all(value.strip() for value in declaration.values())
        assert "Tier-0" in item["claim_boundary"]
        assert "full-application" in item["claim_boundary"]

    catalog["vstd-native-gate-suite"]["owned_paths"].clear()
    assert review.review_document()["vstd-native-gate-suite"]["owned_paths"]


def test_review_matches_exact_semantic_ownership_partition():
    catalog = review.review_document()
    ownership = {
        spec.object_id: spec
        for spec in SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id in catalog
    }

    assert set(ownership) == set(catalog)
    for object_id, item in catalog.items():
        spec = ownership[object_id]
        assert item["primary_kind"] == spec.primary_kind
        assert item["owned_paths"] == list(spec.owned_paths)
        ownership_roles = {
            kind
            for kind in (spec.primary_kind, *spec.specializations)
            if kind in review.REVIEW_KINDS
        }
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        refuted = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        }
        assert refuted == EXPECTED_REFUTATIONS.get(object_id, set())
        assert applies <= ownership_roles
        # TRANSACTION remains an ownership specialization for these objects while the
        # semantic review leaves its exact applicability UNRESOLVED.
        assert ownership_roles - applies == EXPECTED_OWNERSHIP_UNRESOLVED.get(
            object_id, set()
        )


def test_role_boundaries_do_not_promote_in_process_replay_or_narrow_receipts():
    catalog = review.review_document()

    in_process = catalog["vstd-verifier-run-constraint-controller"]
    assert in_process["classification"]["PROTOCOL"]["status"] == "UNRESOLVED"
    assert in_process["classification"]["PROTOCOL"]["evidence_paths"] == []
    assert "same process" not in in_process["classification"]["PROTOCOL"]["reason"]
    assert not any(name.startswith("PROTOCOL-") for name in in_process["declarations"])
    assert (
        "whole-application polish remain UNKNOWN"
        in in_process["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )

    self_polish = catalog["vstd-core-self-polish-assessor"]
    assert (
        "polished false"
        in self_polish["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    assert "full-application" in self_polish["claim_boundary"]

    added = catalog["vstd-added-kind-behavioral-verifier"]
    assert added["primary_kind"] == "VERIFIER"
    assert {
        kind
        for kind, decision in added["classification"].items()
        if decision["status"] == "APPLIES"
    } == ADDED_KIND_APPLICABILITY
    assert set(added["declarations"]) == {
        "ACTUATOR-0.1-command-to-effect",
        "ACTUATOR-0.2-response-and-limits",
        "ACTUATOR-0.3-feedback-and-interlocks",
        "ASSET-0.1-identity-and-quantity",
        "ASSET-0.2-issuance-and-redemption",
        "ASSET-0.3-custody-and-encumbrance",
        "CONTROLLER-0.1-feedback-and-authority",
        "CONTROLLER-0.2-timing-and-stability",
        "CONTROLLER-0.3-intervention-and-failure",
        "FINBOT-0.1-agent-and-financial-authority",
        "FINBOT-0.2-financial-exposure-and-dependencies",
        "FINBOT-0.3-decisions-effects-and-recovery",
        "LEDGER-0.1-authoritative-history",
        "LEDGER-0.2-accounting-invariants",
        "LEDGER-0.3-correction-and-recovery",
        "MARKET-0.1-orders-and-access",
        "MARKET-0.2-matching-and-allocation",
        "MARKET-0.3-settlement-and-disruption",
        "MEASUREMENT-0.1-phenomenon-and-method",
        "MEASUREMENT-0.2-units-time-and-uncertainty",
        "MEASUREMENT-0.3-validity-and-missingness",
        "POLICY-0.1-rules-and-precedence",
        "POLICY-0.2-authority-and-exceptions",
        "POLICY-0.3-enforcement-and-decisions",
        "PROTOCOL-0.1-participants-and-states",
        "PROTOCOL-0.2-ordering-and-replay",
        "PROTOCOL-0.3-failures-and-progress",
        "ROBOT-0.1-agent-to-actuator-binding",
        "ROBOT-0.2-physical-reach-and-observation",
        "ROBOT-0.3-consequences-and-intervention",
        "SENSOR-0.1-acquisition-and-observations",
        "SENSOR-0.2-calibration-and-envelope",
        "SENSOR-0.3-sampling-and-faults",
        "TRANSACTION-0.1-effects-and-authority",
        "TRANSACTION-0.2-commit-and-failure",
        "TRANSACTION-0.3-retry-and-replay",
    }
    policy_text = " ".join(
        field
        for declaration in added["declarations"].values()
        for field in declaration.values()
    )
    assert "exact" in policy_text.lower()
    assert "trust-root" in policy_text
    assert "4 MiB" in policy_text
    assert "8 MiB" in policy_text
    assert "NOT_ESTABLISHED" in policy_text

    for kind in review.REVIEW_KINDS:
        if kind in ADDED_KIND_APPLICABILITY:
            continue
        decision = added["classification"][kind]
        assert decision["status"] == "UNRESOLVED"
        assert decision["evidence_paths"] == []
        assert decision["reason"].endswith("refute a " + kind + " role.")

    for object_id, item in catalog.items():
        if object_id != "vstd-added-kind-behavioral-verifier":
            assert item["classification"]["ROBOT"]["status"] == "UNRESOLVED"
        if object_id != "vstd-added-kind-behavioral-verifier":
            assert item["classification"]["FINBOT"]["status"] == "UNRESOLVED"


def test_apply_is_pure_deterministic_complete_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_verifier(root, rows, files)
    second = review.apply_package_semantic_review_verifier(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        applies = EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        assert applies - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applies for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and binding["evidence"]
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )
        assert all(
            tuple(reference["path"] for reference in decision["evidence"])
            == _expected_evidence(object_id, kind)
            for kind, decision in row["classification"].items()
            if kind in applies
        )
        refuted = EXPECTED_REFUTATIONS.get(object_id, set())
        assert all(
            decision["evidence"] == []
            for kind, decision in row["classification"].items()
            if kind not in applies and kind not in refuted
        )
        for name, binding in row["obligations"].items():
            kind = name.split("-", 1)[0]
            assert tuple(reference["path"] for reference in binding["evidence"]) == (
                _expected_evidence(object_id, kind)
            )


def test_apply_preserves_exact_current_reviews_and_reviewed_declaration_text(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    object_id = "vstd-source-provenance-observer"
    obligation_id = "SENSOR-0.1-acquisition-and-observations"
    declaration = selected[object_id]["obligations"][obligation_id]["declaration"]
    selected[object_id]["obligations"][obligation_id]["declaration"] = {
        field: "Reviewed exact nonblank " + field + "." for field in declaration
    }
    expected = deepcopy(selected)

    result = review.apply_package_semantic_review_verifier(root, selected, files)

    assert result == expected


def test_added_kind_apply_binds_exact_consequence_role_paths(tmp_path):
    root, rows, files = _workspace(tmp_path)
    first = review.apply_package_semantic_review_verifier(root, rows, files)
    second = review.apply_package_semantic_review_verifier(root, first, files)
    row = first["vstd-added-kind-behavioral-verifier"]

    assert first == second
    assert row["kind"] == "VERIFIER"
    assert row["specializations"] == [
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    ]
    assert {
        kind
        for kind, decision in row["classification"].items()
        if decision["status"] == "APPLIES"
    } == ADDED_KIND_APPLICABILITY
    assert set(row["obligations"]) == {
        "ACTUATOR-0.1-command-to-effect",
        "ACTUATOR-0.2-response-and-limits",
        "ACTUATOR-0.3-feedback-and-interlocks",
        "ASSET-0.1-identity-and-quantity",
        "ASSET-0.2-issuance-and-redemption",
        "ASSET-0.3-custody-and-encumbrance",
        "CONTROLLER-0.1-feedback-and-authority",
        "CONTROLLER-0.2-timing-and-stability",
        "CONTROLLER-0.3-intervention-and-failure",
        "FINBOT-0.1-agent-and-financial-authority",
        "FINBOT-0.2-financial-exposure-and-dependencies",
        "FINBOT-0.3-decisions-effects-and-recovery",
        "LEDGER-0.1-authoritative-history",
        "LEDGER-0.2-accounting-invariants",
        "LEDGER-0.3-correction-and-recovery",
        "MARKET-0.1-orders-and-access",
        "MARKET-0.2-matching-and-allocation",
        "MARKET-0.3-settlement-and-disruption",
        "MEASUREMENT-0.1-phenomenon-and-method",
        "MEASUREMENT-0.2-units-time-and-uncertainty",
        "MEASUREMENT-0.3-validity-and-missingness",
        "POLICY-0.1-rules-and-precedence",
        "POLICY-0.2-authority-and-exceptions",
        "POLICY-0.3-enforcement-and-decisions",
        "PROTOCOL-0.1-participants-and-states",
        "PROTOCOL-0.2-ordering-and-replay",
        "PROTOCOL-0.3-failures-and-progress",
        "ROBOT-0.1-agent-to-actuator-binding",
        "ROBOT-0.2-physical-reach-and-observation",
        "ROBOT-0.3-consequences-and-intervention",
        "SENSOR-0.1-acquisition-and-observations",
        "SENSOR-0.2-calibration-and-envelope",
        "SENSOR-0.3-sampling-and-faults",
        "TRANSACTION-0.1-effects-and-authority",
        "TRANSACTION-0.2-commit-and-failure",
        "TRANSACTION-0.3-retry-and-replay",
    }
    assert tuple(
        item["path"] for item in row["classification"]["POLICY"]["evidence"]
    ) == (EXPECTED_PATHS["vstd-added-kind-behavioral-verifier"])
    assert tuple(
        item["path"] for item in row["classification"]["ACTUATOR"]["evidence"]
    ) == ("src/verifier/runtime/added_kind_behavioral_routes.py",)
    assert tuple(
        item["path"] for item in row["classification"]["FINBOT"]["evidence"]
    ) == (
        "src/verifier/domains/contracts/finbot_checks.py",
        "src/verifier/runtime/added_kind_behavioral_routes.py",
    )
    assert all(
        decision["evidence"] == []
        for kind, decision in row["classification"].items()
        if kind not in ADDED_KIND_APPLICABILITY
    )
    for name, binding in row["obligations"].items():
        assert tuple(item["path"] for item in binding["evidence"]) == (
            _expected_evidence(
                "vstd-added-kind-behavioral-verifier", name.split("-", 1)[0]
            )
        )
        assert all(item["sha256"] == files[item["path"]] for item in binding["evidence"])


def test_added_kind_actuator_declaration_bounds_local_worker_not_subject_effect():
    added = review.review_document()["vstd-added-kind-behavioral-verifier"]
    fields = " ".join(
        value
        for name, declaration in added["declarations"].items()
        if name.startswith("ACTUATOR-")
        for value in declaration.values()
    )

    assert "python -I -S -B" in fields
    assert "return status" in fields
    assert "timeout" in fields.lower()
    assert "represented runtime correspondence" in fields


def test_added_kind_asset_declaration_retains_obligations_without_claiming_asset_truth():
    added = review.review_document()["vstd-added-kind-behavioral-verifier"]
    fields = " ".join(
        value
        for name, declaration in added["declarations"].items()
        if name.startswith("ASSET-")
        for value in declaration.values()
    )

    assert "retained asset and party identifiers" in fields
    assert "asset backing and custody are NOT_ESTABLISHED" in fields
    assert "actual financial authority is NOT_ESTABLISHED" in fields


def test_added_kind_finbot_declaration_retains_obligations_without_claiming_effect():
    added = review.review_document()["vstd-added-kind-behavioral-verifier"]
    fields = " ".join(
        value
        for name, declaration in added["declarations"].items()
        if name.startswith("FINBOT-")
        for value in declaration.values()
    )

    assert "obligation-bearing FINBOT consequence role" in fields
    assert "financial authority" in fields
    assert "NOT_ESTABLISHED" in fields
    assert "real-money movement" in fields


def test_asset_tier0_review_is_verifier_policy_not_asset_subject(tmp_path):
    catalog = review.review_document()
    object_id = "vstd-asset-tier0-execution-verifier"
    item = catalog[object_id]

    assert item["primary_kind"] == "VERIFIER"
    assert tuple(item["owned_paths"]) == EXPECTED_PATHS[object_id]
    assert item["classification"]["POLICY"]["status"] == "APPLIES"
    assert tuple(item["classification"]["POLICY"]["evidence_paths"]) == (
        EXPECTED_PATHS[object_id]
    )
    assert item["classification"]["ASSET"] == {
        "status": "UNRESOLVED",
        "reason": review._shared._unresolved_reason("ASSET"),
        "evidence_paths": [],
    }
    assert set(item["declarations"]) == {
        "POLICY-0.1-rules-and-precedence",
        "POLICY-0.2-authority-and-exceptions",
        "POLICY-0.3-enforcement-and-decisions",
    }
    policy_text = " ".join(
        value
        for declaration in item["declarations"].values()
        for value in declaration.values()
    )
    assert "not an ASSET subject or instance" in policy_text
    assert "owns no ASSET route" in policy_text
    assert "no real instrument is issued or redeemed" in policy_text
    assert "never promoted to route PASS" in policy_text

    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    row = selected[object_id]
    assert row["kind"] == "VERIFIER"
    assert row["specializations"] == ["POLICY"]
    assert row["classification"]["ASSET"]["status"] == "UNRESOLVED"
    assert row["classification"]["ASSET"]["evidence"] == []
    assert not any(name.startswith("ASSET-") for name in row["obligations"])
    for binding in row["obligations"].values():
        assert tuple(reference["path"] for reference in binding["evidence"]) == (
            EXPECTED_PATHS[object_id]
        )
        assert all(
            reference["sha256"] == files[reference["path"]]
            for reference in binding["evidence"]
        )


@pytest.mark.parametrize(
    "failure",
    [
        "stale_inventory",
        "mutated_source",
        "foreign_decision_evidence",
        "foreign_obligation_evidence",
        "partial_policy_declaration",
        "wrong_primary_kind",
    ],
)
def test_added_kind_review_rejects_stale_mutated_foreign_or_partial_state_atomically(
    tmp_path, failure
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-added-kind-behavioral-verifier"
    path = EXPECTED_PATHS[object_id][0]
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    candidate = deepcopy(selected)
    if failure == "stale_inventory":
        candidate[object_id]["classification"]["POLICY"]["evidence"][0][
            "sha256"
        ] = "sha256:" + "0" * 64
    elif failure == "mutated_source":
        (root / path).write_bytes(b"mutated after the selected source inventory\n")
    elif failure == "foreign_decision_evidence":
        candidate[object_id]["classification"]["POLICY"]["evidence"] = deepcopy(
            candidate["vstd-native-gate-suite"]["classification"]["POLICY"][
                "evidence"
            ]
        )
    elif failure == "foreign_obligation_evidence":
        candidate[object_id]["obligations"][
            "POLICY-0.1-rules-and-precedence"
        ]["evidence"] = deepcopy(
            candidate["vstd-native-gate-suite"]["obligations"][
                "POLICY-0.1-rules-and-precedence"
            ]["evidence"]
        )
    elif failure == "partial_policy_declaration":
        candidate[object_id]["obligations"][
            "POLICY-0.2-authority-and-exceptions"
        ]["declaration"]["authority"] = ""
    else:
        candidate[object_id]["kind"] = "OBJECT"
    before = deepcopy(candidate)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_verifier(root, candidate, files)
    assert candidate == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_atomically(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-native-gate-suite"
    path = EXPECTED_PATHS[object_id][0]
    if failure == "stale":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing":
        (root / path).unlink()
    elif failure == "unowned":
        rows[object_id]["surfaces"].remove("file:" + path)
    else:
        rows[object_id]["surfaces"].append("file:unreviewed/extra.py")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_verifier(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "stale_decision",
        "partial_declaration",
        "refuted_declaration",
        "malformed_unresolved",
        "label_conflict",
        "unknown_obligation",
    ],
)
def test_apply_rejects_conflicting_or_partial_reviews_atomically(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    native = selected["vstd-verifier-native-execution-controller"]
    in_process = selected["vstd-verifier-run-constraint-controller"]
    if failure == "status":
        native["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        native["classification"]["TRANSACTION"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "partial_declaration":
        native["obligations"]["TRANSACTION-0.1-effects-and-authority"]["declaration"][
            "effects"
        ] = ""
    elif failure == "refuted_declaration":
        in_process["obligations"]["PROTOCOL-0.1-participants-and-states"] = {
            "reason": "Contradictory protocol declaration.",
            "evidence": deepcopy(in_process["classification"]["PROTOCOL"]["evidence"]),
            "declaration": {
                "participants": "Contradictory participants.",
                "roles": "Contradictory roles.",
                "states": "Contradictory states.",
                "transitions": "Contradictory transitions.",
            },
        }
    elif failure == "malformed_unresolved":
        native["classification"]["ASSET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        native["specializations"].append("ASSET")
    else:
        native["obligations"]["TRANSACTION-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_apply_rechecks_complete_source_denominator_before_mutation(
    tmp_path, monkeypatch
):
    root, rows, files = _workspace(tmp_path)
    target = EXPECTED_PATHS["vstd-core-self-polish-assessor"][0]
    original = review._shared._read_digest
    calls = 0

    def drifting_digest(selected_root: Path, path: str) -> str:
        nonlocal calls
        value = original(selected_root, path)
        if path == target:
            calls += 1
            if calls == 2:
                return "sha256:" + "a" * 64
        return value

    monkeypatch.setattr(review._shared, "_read_digest", drifting_digest)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_verifier(root, rows, files)
    assert rows == before


def test_does_not_apply_is_emitted_only_for_audited_refutations():
    catalog = review.review_document()

    for object_id, item in catalog.items():
        refuted = EXPECTED_REFUTATIONS.get(object_id, set())
        for kind, decision in item["classification"].items():
            if kind in EXPECTED_APPLICABILITY[object_id]:
                assert decision["status"] == "APPLIES"
            elif kind in refuted:
                assert decision["status"] == "DOES_NOT_APPLY"
                assert decision["evidence_paths"] == list(
                    _expected_evidence(object_id, kind)
                )
            else:
                assert decision["status"] == "UNRESOLVED"
                assert decision["evidence_paths"] == []
                assert decision["reason"] == review._SOURCE_BOUND_UNRESOLVED_REASONS.get(
                    (object_id, kind), review._shared._unresolved_reason(kind)
                )
    emitted = {
        (object_id, kind)
        for object_id, item in catalog.items()
        for kind, decision in item["classification"].items()
        if decision["status"] == "DOES_NOT_APPLY"
    }
    assert emitted == set()
    assert (
        sum(
            decision["status"] == "APPLIES"
            for item in catalog.values()
            for decision in item["classification"].values()
        )
        == 43
    )


def test_absent_kinds_are_unresolved_not_refuted_for_every_catalog_object():
    for object_id, item in review._REVIEWS.items():
        for kind in review.REVIEW_KINDS:
            if kind in item.applicable:
                expected = "APPLIES"
            elif kind in item.refuted:
                expected = "DOES_NOT_APPLY"
            else:
                expected = "UNRESOLVED"
            assert review._shared._basis(item, kind) == expected, (object_id, kind)
        assert set(item.refuted) == EXPECTED_REFUTATIONS.get(object_id, set())


def test_unlisted_object_cannot_inherit_or_receive_a_does_not_apply_decision(tmp_path):
    root, rows, files = _workspace(tmp_path)
    foreign_id = "vstd-unlisted-object"
    foreign_path = EXPECTED_PATHS["vstd-native-gate-suite"][0]
    rows[foreign_id] = deepcopy(rows["vstd-native-gate-suite"])
    rows[foreign_id]["object_id"] = foreign_id
    rows[foreign_id]["classification"] = {
        kind: {
            "status": "DOES_NOT_APPLY",
            "reason": "Foreign unlisted refutation.",
            "evidence": [{"path": foreign_path, "sha256": files[foreign_path]}],
        }
        for kind in review.REVIEW_KINDS
    }
    before = deepcopy(rows)

    result = review.apply_package_semantic_review_verifier(root, rows, files)

    assert rows == before
    assert result[foreign_id] == before[foreign_id]
    for object_id in review.VERIFIER_OBJECT_IDS:
        refuted = {
            kind
            for kind, decision in result[object_id]["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        }
        assert refuted == EXPECTED_REFUTATIONS.get(object_id, set())


@pytest.mark.parametrize(
    ("object_id", "kind"),
    [
        ("vstd-verifier-run-constraint-controller", "PROTOCOL"),
        ("vstd-verifier-run-constraint-controller", "ASSET"),
        ("vstd-asset-tier0-execution-verifier", "ROBOT"),
        ("vstd-native-gate-suite", "FINBOT"),
        ("vstd-source-provenance-observer", "TRANSACTION"),
        ("vstd-repository-admission-reconciler", "TRANSACTION"),
    ],
)
def test_forged_does_not_apply_without_a_basis_is_rejected_not_erased(
    tmp_path, object_id, kind
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    selected[object_id]["classification"][kind] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Forged refutation.",
        "evidence": [
            {"path": path, "sha256": files[path]}
            for path in EXPECTED_PATHS[object_id]
        ],
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_UNBACKED_DECISION:" + object_id + ":" + kind,
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("substitution", ["reason", "evidence_order", "foreign_evidence"])
def test_same_status_reason_or_evidence_substitution_is_rejected(
    tmp_path, substitution
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    object_id = "vstd-source-provenance-observer"
    decision = selected[object_id]["classification"]["SENSOR"]
    if substitution == "reason":
        decision["reason"] = "Prior exact current-source sensor review."
    elif substitution == "evidence_order":
        decision["evidence"] = list(reversed(decision["evidence"]))
    else:
        decision["evidence"] = deepcopy(
            selected["vstd-native-gate-suite"]["classification"]["SENSOR"]["evidence"]
        )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":SENSOR",
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_same_status_declaration_reason_substitution_is_rejected(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    object_id = "vstd-source-provenance-observer"
    obligation_id = "SENSOR-0.1-acquisition-and-observations"
    selected[object_id]["obligations"][obligation_id]["reason"] = (
        "Prior exact complete current-source declaration."
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:" + object_id,
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_unresolved_candidate_is_kept_only_with_canonical_reason_and_owned_evidence(
    tmp_path,
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-native-gate-suite"
    path = EXPECTED_PATHS[object_id][0]
    candidate = {
        "status": "UNRESOLVED",
        "reason": review._shared._unresolved_reason("ASSET"),
        "evidence": [{"path": path, "sha256": files[path]}],
    }
    rows[object_id]["classification"]["ASSET"] = deepcopy(candidate)

    result = review.apply_package_semantic_review_verifier(root, rows, files)
    assert result[object_id]["classification"]["ASSET"] == candidate

    rows[object_id]["classification"]["ASSET"]["reason"] = "Substituted candidate reason."
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":ASSET",
    ):
        review.apply_package_semantic_review_verifier(root, rows, files)
    assert rows == before


def test_catalog_guard_rejects_a_refutation_without_a_reviewed_module_change(
    monkeypatch,
):
    original = review._REVIEWS["vstd-native-gate-suite"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-native-gate-suite",
        dataclasses.replace(original, refuted=("ASSET",)),
    )

    with pytest.raises(AssertionError, match="unaudited refutation"):
        review._catalog_check()


DISCLAIMER = "This does not apply as ASSET; nothing is refuted or exempted here."


def _owned_references(files: dict[str, str], object_id: str) -> list[dict[str, str]]:
    return [{"path": path, "sha256": files[path]} for path in EXPECTED_PATHS[object_id]]


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        ("object_obligation", "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN"),
        ("lowercase_obligation", "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN"),
        ("object_specialization", "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID"),
        (
            "non_string_specialization",
            "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID",
        ),
        (
            "invented_classification_kind",
            "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_KIND_UNKNOWN",
        ),
        (
            "object_classification_key",
            "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_KIND_UNKNOWN",
        ),
        (
            "non_string_classification_key",
            "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_KIND_UNKNOWN",
        ),
    ],
)
def test_invented_or_foreign_labels_cannot_escape_the_review_atomically(
    tmp_path, failure, code
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-native-gate-suite"
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    row = selected[object_id]
    if failure == "object_obligation":
        row["obligations"]["OBJECT-0.1-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    elif failure == "lowercase_obligation":
        row["obligations"]["transaction-0.1-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    elif failure == "object_specialization":
        row["specializations"].append("OBJECT")
    elif failure == "non_string_specialization":
        row["specializations"].append(7)
    elif failure == "invented_classification_kind":
        row["classification"]["OBJEKT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Invented.",
            "evidence": [],
        }
    elif failure == "object_classification_key":
        # OBJECT is the generic fallback, not a question: no refutation via it.
        row["classification"]["OBJECT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Generic fallback refutation.",
            "evidence": [],
        }
    else:
        row["classification"][7] = {
            "status": "UNRESOLVED",
            "reason": "Invented.",
            "evidence": [],
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match=code + ":" + object_id):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


@pytest.mark.parametrize(
    ("kind", "decision", "code"),
    [
        (
            "ASSET",
            {"status": "UNRESOLVED", "reason": DISCLAIMER, "evidence": []},
            None,
        ),
        (
            "ASSET",
            {"status": "DOES_NOT_APPLY", "reason": DISCLAIMER, "evidence": []},
            "PACKAGE_SEMANTIC_REVIEW_UNBACKED_DECISION",
        ),
        (
            "ASSET",
            {"status": "UNRESOLVED", "reason": DISCLAIMER, "evidence": "OWNED"},
            "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT",
        ),
        (
            "SENSOR",
            {"status": "APPLIES", "reason": DISCLAIMER, "evidence": "OWNED"},
            "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT",
        ),
    ],
)
def test_negative_or_disclaimer_text_never_mints_or_erases_a_decision(
    tmp_path, kind, decision, code
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-native-gate-suite"
    if decision["evidence"] == "OWNED":
        decision = {**decision, "evidence": _owned_references(files, object_id)}
    rows[object_id]["classification"][kind] = deepcopy(decision)
    before = deepcopy(rows)

    if code is None:
        # Disclaimer prose carries no status: the candidate is canonicalized,
        # never read as a refutation or as an exemption.
        result = review.apply_package_semantic_review_verifier(root, rows, files)
        assert result[object_id]["classification"][kind] == {
            "status": "UNRESOLVED",
            "reason": review._shared._unresolved_reason(kind),
            "evidence": [],
        }
    else:
        with pytest.raises(ValueError, match=code + ":" + object_id):
            review.apply_package_semantic_review_verifier(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("alias", ["dot_prefix", "backslash", "case_fold"])
def test_path_aliases_of_owned_surfaces_do_not_inherit_ownership(tmp_path, alias):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-source-provenance-observer"
    path = EXPECTED_PATHS[object_id][0]
    spelled = {
        "dot_prefix": "./" + path,
        "backslash": path.replace("/", "\\"),
        "case_fold": path.upper(),
    }[alias]
    surfaces = rows[object_id]["surfaces"]
    surfaces[surfaces.index("file:" + path)] = "file:" + spelled
    before = deepcopy(rows)

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + object_id
    ):
        review.apply_package_semantic_review_verifier(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "payload",
    [
        b"import importlib\nimportlib.import_module('subprocess')\n",
        b"HANDLER = getattr(__builtins__, 'eval')\n",
        b"CALLBACK = lambda route: __import__(route)\n",
        b"import subprocess\nsubprocess.run(['echo', 'reviewed'])\n",
    ],
)
def test_dynamic_or_effectful_source_after_review_invalidates_the_inventory(
    tmp_path, payload
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-verifier-native-execution-controller"
    path = EXPECTED_PATHS[object_id][0]
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    (root / path).write_bytes(payload)
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path,
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_other_partition_decisions_and_prior_roles_are_retained_not_erased(tmp_path):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-verifier-native-execution-controller"
    other = {
        "status": "DOES_NOT_APPLY",
        "reason": "Owned by another partition's reviewed catalog.",
        "evidence": _owned_references(files, object_id)[:1],
    }
    rows[object_id]["classification"]["BENCH"] = deepcopy(other)
    rows[object_id]["specializations"] = ["POLICY"]

    result = review.apply_package_semantic_review_verifier(root, rows, files)

    row = result[object_id]
    assert row["classification"]["BENCH"] == other
    assert row["specializations"][0] == "POLICY"
    assert set(row["specializations"]) == EXPECTED_APPLICABILITY[object_id] - {
        row["kind"]
    }


def test_observer_actuator_is_unresolved_when_fsmonitor_is_disabled():
    observer = review.review_document()["vstd-source-provenance-observer"]
    object_id = "vstd-source-provenance-observer"

    assert {
        kind
        for kind, decision in observer["classification"].items()
        if decision["status"] == "APPLIES"
    } == {"MEASUREMENT", "SENSOR", "PROTOCOL"}
    # Transaction boundaries are not established, so the cell is UNRESOLVED, never refuted.
    transaction = observer["classification"]["TRANSACTION"]
    assert transaction["status"] == "UNRESOLVED"
    assert transaction["evidence_paths"] == []
    assert transaction["reason"] == review._SOURCE_BOUND_UNRESOLVED_REASONS[(object_id, "TRANSACTION")]
    assert "not refuted" in transaction["reason"]
    actuator = observer["classification"]["ACTUATOR"]
    assert actuator["status"] == "UNRESOLVED"
    assert actuator["evidence_paths"] == []
    assert not any(name.startswith("ACTUATOR-") for name in observer["declarations"])
    source = (RUNTIME / "self_polish_estate.py").read_text(encoding="utf-8")
    assert '"-c", "core.fsmonitor=false"' in source


def test_run_constraint_actuator_is_unresolved_despite_downstream_worker_replay():
    controller = review.review_document()["vstd-verifier-run-constraint-controller"]

    assert controller["classification"]["ACTUATOR"] == {
        "status": "UNRESOLVED",
        "reason": review._SOURCE_BOUND_UNRESOLVED_REASONS[
            ("vstd-verifier-run-constraint-controller", "ACTUATOR")
        ],
        "evidence_paths": [],
    }
    assert controller["classification"]["CONTROLLER"]["status"] == "APPLIES"
    assert not any(name.startswith("ACTUATOR-") for name in controller["declarations"])
    # The controller reaches another object's worker, but that callee owns the
    # command-to-effect endpoint and its feedback/failure surface.
    source = (PACKAGE / "domains" / "contracts" / "verifier_run_constraints.py").read_text(
        encoding="utf-8"
    )
    assert "replay_current_object_certificate" in source


@pytest.mark.parametrize(
    "object_id",
    [
        "vstd-verifier-run-constraint-controller",
        "vstd-native-gate-suite",
        "vstd-repository-admission-reconciler",
        "vstd-source-provenance-observer",
    ],
)
def test_false_actuator_cells_apply_as_empty_unresolved_without_declarations(
    tmp_path, object_id
):
    root, rows, files = _workspace(tmp_path)

    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    actuator = selected[object_id]["classification"]["ACTUATOR"]

    assert actuator == {
        "status": "UNRESOLVED",
        "reason": review._SOURCE_BOUND_UNRESOLVED_REASONS[(object_id, "ACTUATOR")],
        "evidence": [],
    }
    assert not any(
        name.startswith("ACTUATOR-")
        for name in selected[object_id]["obligations"]
    )


@pytest.mark.parametrize(
    "module",
    [
        "explanation_projection.py",
        "prdel.py",
        "self_polish_estate.py",
        "namespace_admission.py",
        "package_admission.py",
        "gate.py",
        "gates.py",
        "manifest_gate.py",
    ],
)
def test_audited_mechanisms_use_only_read_only_git_verbs_lexically(module):
    """Lexically constrain the fixed Git observation surface."""
    source = (RUNTIME / module).read_text(encoding="utf-8")

    assert _git_launch_findings(source) == []


@pytest.mark.parametrize(
    ("fixture", "finding"),
    [
        ('def f(root):\n    return _git(root, "commit", "-m", "x")\n', "commit"),
        ('import subprocess\nsubprocess.run(["git", "-C", root, "add", "."])\n', "add"),
        (
            'import subprocess\nsubprocess.run(["git", "config", "user.name", "x"])\n',
            "config without --get",
        ),
        ("def f(root, cmd):\n    return _git(root, *cmd)\n", "dynamic git verb"),
        ('import subprocess\nsubprocess.run(["git", *argv])\n', "dynamic git argv"),
        (
            'def f(root):\n    return _git(root, "status")\n',
            "status without --no-optional-locks",
        ),
        (
            'import subprocess\nsubprocess.run(["git", "update-ref", "refs/x", "y"])\n',
            "update-ref",
        ),
    ],
)
def test_git_launch_guard_flags_mutating_or_unprovable_launches(fixture, finding):
    assert _git_launch_findings(fixture) == [finding]


def test_git_launch_guard_accepts_fixed_read_only_queries():
    fixture = (
        'import subprocess\n'
        'subprocess.run(["git", "--no-optional-locks", "rev-parse", "--verify", "HEAD"])\n'
        "def f(root, oid):\n"
        '    return _git(root, "cat-file", "blob", oid)\n'
        "def g(root):\n"
        '    return _run_git(root, "config", "--get", "remote.origin.url")\n'
    )

    assert _git_launch_findings(fixture) == []


@pytest.mark.parametrize(
    "module",
    [
        "explanation_projection.py",
        "prdel.py",
        "self_polish_estate.py",
        "namespace_admission.py",
        "package_admission.py",
    ],
)
def test_audited_mechanisms_have_no_direct_write_calls_lexically(module):
    """Lexical absence of direct writes, complemented by Git-hook isolation tests."""
    source = (RUNTIME / module).read_text(encoding="utf-8")

    assert _write_findings(source) == []


@pytest.mark.parametrize(
    ("fixture", "finding"),
    [
        ('from pathlib import Path\nPath(p).write_text("x")\n', "write_text"),
        ('open(p, "w").write("x")\n', "open-write"),
        ('from pathlib import Path\nPath(p).open("ab")\n', "open-write"),
        ("import os\nos.replace(a, b)\n", "os.replace"),
        ("from pathlib import Path\nPath(d).mkdir(parents=True)\n", "mkdir"),
    ],
)
def test_write_guard_flags_persistent_effects(fixture, finding):
    assert _write_findings(fixture) == [finding]


def test_inserted_git_commit_in_observer_source_invalidates_the_read_only_review(
    tmp_path,
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-source-provenance-observer"
    path = EXPECTED_PATHS[object_id][0]
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    payload = b'\nimport subprocess\nsubprocess.run(["git", "commit", "-m", "x"])\n'
    (root / path).write_bytes((root / path).read_bytes() + payload)
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path,
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before
    assert _git_launch_findings(payload.decode("ascii")) == ["commit"]


@pytest.mark.parametrize(
    ("object_id", "kind"),
    [
        ("vstd-source-provenance-observer", "TRANSACTION"),
        ("vstd-repository-admission-reconciler", "TRANSACTION"),
        ("vstd-verifier-run-constraint-controller", "ACTUATOR"),
        ("vstd-native-gate-suite", "ACTUATOR"),
        ("vstd-source-provenance-observer", "ACTUATOR"),
        ("vstd-repository-admission-reconciler", "ACTUATOR"),
    ],
)
def test_stored_applies_on_a_formerly_refuted_unresolved_cell_is_unbacked(
    tmp_path, object_id, kind
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    selected[object_id]["classification"][kind] = {
        "status": "APPLIES",
        "reason": review._shared._reason(
            review._REVIEWS[object_id].profile, kind, True
        ),
        "evidence": [
            {"path": path, "sha256": files[path]}
            for path in _expected_evidence(object_id, kind)
        ],
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_UNBACKED_DECISION:" + object_id + ":" + kind,
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_stale_specialization_for_a_non_applicable_kind_is_a_label_conflict(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    object_id = "vstd-source-provenance-observer"
    selected[object_id]["specializations"].append("TRANSACTION")
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":TRANSACTION",
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_populated_non_applicable_declaration_is_a_conflict_not_erased(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    object_id = "vstd-source-provenance-observer"
    obligation_id = "TRANSACTION-0.1-effects-and-authority"
    assert not any(name.startswith("TRANSACTION-") for name in selected[object_id]["obligations"])
    fields = next(
        row["declaration_fields"]
        for row in review._shared._contract_rows("TRANSACTION")
        if row["id"] == obligation_id
    )
    selected[object_id]["obligations"][obligation_id] = {
        "reason": "",
        "evidence": [],
        "declaration": {field: "Prior populated text." for field in fields},
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)
    assert selected == before


def test_catalog_guard_requires_an_audit_entry_for_each_refutation(monkeypatch):
    original = review._REVIEWS["vstd-native-gate-suite"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-native-gate-suite",
        dataclasses.replace(original, refuted=("ASSET",)),
    )

    with pytest.raises(AssertionError, match="unaudited refutation"):
        review._catalog_check()


def test_dne_evidence_is_owned_and_fresh(tmp_path, monkeypatch):
    # No refutation is audited today. If one is, its DOES_NOT_APPLY evidence must
    # stay within the object's owned source and drift there must fail.
    object_id = "vstd-native-gate-suite"
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        dataclasses.replace(review._REVIEWS[object_id], refuted=("ASSET",)),
    )
    monkeypatch.setitem(
        review._AUDITED_REFUTATIONS,
        object_id,
        {
            "ASSET": review._Refutation(
                basis="Audited against the complete owned native-gate source boundary.",
            )
        },
    )
    root, rows, files = _workspace(tmp_path)
    decision = review.review_document()[object_id]["classification"]["ASSET"]
    assert decision["status"] == "DOES_NOT_APPLY"
    assert decision["evidence_paths"] == list(EXPECTED_PATHS[object_id])

    selected = review.apply_package_semantic_review_verifier(root, rows, files)
    assert [item["path"] for item in selected[object_id]["classification"]["ASSET"]["evidence"]] == (
        list(EXPECTED_PATHS[object_id])
    )
    owned = EXPECTED_PATHS[object_id][0]
    (root / owned).write_bytes(b"mutated owned refutation source\n")
    with pytest.raises(
        ValueError,
        match=r"PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + re.escape(owned),
    ):
        review.apply_package_semantic_review_verifier(root, selected, files)


@pytest.mark.parametrize("basis", ["", "Reviewed gate.py."])
def test_refutation_without_an_exact_owned_source_basis_is_rejected(monkeypatch, basis):
    object_id = "vstd-native-gate-suite"
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        dataclasses.replace(review._REVIEWS[object_id], refuted=("ASSET",)),
    )
    monkeypatch.setitem(
        review._AUDITED_REFUTATIONS,
        object_id,
        {
            "ASSET": review._Refutation(basis=basis)
        },
    )

    with pytest.raises(AssertionError, match="lacks owned-source basis"):
        review._catalog_check()


def test_catalog_guard_rejects_a_refutation_that_overlaps_an_applicable_kind(
    monkeypatch,
):
    original = review._REVIEWS["vstd-native-gate-suite"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-native-gate-suite",
        dataclasses.replace(original, refuted=("ACTUATOR", "TRANSACTION")),
    )

    with pytest.raises(AssertionError, match="not disjoint or registered"):
        review._catalog_check()


FORMER_REFUTATIONS = (
    ("vstd-source-provenance-observer", "TRANSACTION", "UNRESOLVED"),
    ("vstd-source-provenance-observer", "ACTUATOR", "UNRESOLVED"),
    ("vstd-verifier-run-constraint-controller", "ACTUATOR", "UNRESOLVED"),
    ("vstd-repository-admission-reconciler", "TRANSACTION", "UNRESOLVED"),
    ("vstd-repository-admission-reconciler", "ACTUATOR", "UNRESOLVED"),
    ("vstd-native-gate-suite", "ACTUATOR", "UNRESOLVED"),
)


@pytest.mark.parametrize(("object_id", "kind", "status"), FORMER_REFUTATIONS)
def test_former_refutations_are_withdrawn_to_exact_applies_or_unresolved(
    object_id, kind, status
):
    decision = review.review_document()[object_id]["classification"][kind]

    assert decision["status"] == status
    assert decision["evidence_paths"] == []
    assert decision["reason"] == review._SOURCE_BOUND_UNRESOLVED_REASONS[(object_id, kind)]
    assert "not refuted" in decision["reason"]


def test_every_emitted_evidence_path_is_owned(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_verifier(root, rows, files)

    for object_id, row in selected.items():
        owned = set(EXPECTED_PATHS[object_id])
        evidence_paths = {
            reference["path"]
            for decision in row["classification"].values()
            for reference in decision["evidence"]
        } | {
            reference["path"]
            for binding in row["obligations"].values()
            for reference in binding["evidence"]
        }
        assert evidence_paths <= owned, object_id


def _verifier_frames() -> set[str]:
    """Return the repository-relative verifier source files on the live stack."""
    frames = set()
    for frame in traceback.extract_stack():
        try:
            relative = Path(frame.filename).resolve().relative_to(REPO).as_posix()
        except ValueError:
            continue
        if relative.startswith("src/verifier/"):
            frames.add(relative)
    return frames


def _model_fixture():
    # The bounded MODEL-3.2 fixture belongs to its own statically bound test module.
    return selected_model_fixture()


@pytest.mark.skipif(
    sys.platform != "win32",
    reason=(
        "OS_CAPABILITY_GUARD: Windows Job Object process containment is unavailable "
        "on non-Windows hosts"
    ),
)
def test_reaching_downstream_worker_does_not_transfer_actuator_ownership(monkeypatch):
    catalog = review.review_document()
    assert catalog["vstd-verifier-run-constraint-controller"]["classification"][
        "ACTUATOR"
    ]["status"] == "UNRESOLVED"
    assert catalog["vstd-native-gate-suite"]["classification"]["ACTUATOR"][
        "status"
    ] == "UNRESOLVED"
    # Both callers can reach the separately owned Job launcher, but neither caller
    # owns that command-to-effect endpoint or its feedback/failure surface.
    request, policy, evidence = _model_fixture()
    certificate = observation.build_model_hardware_certificate(
        request, evidence, policy=policy
    )
    # The function the replay calls is the Job launcher defined in verifier_execution.
    assert observation._run_windows is execution_module._run_windows
    original = observation._run_windows
    launches: list[set[str]] = []

    def counting(argv, data, cap, wall):
        launches.append(_verifier_frames())
        return original(argv, data, cap, wall)

    monkeypatch.setattr(observation, "_run_windows", counting)
    chain = set(DOWNSTREAM_WORKER_CHAIN) - {
        "src/verifier/domains/verifier_execution.py"
    }

    child_selector = {
        "child_semantic_version": observation.SEMANTIC_VERSION,
        "child_objective": observation.COORDINATE,
        "child_represented_kind": "MODEL",
    }
    report, failure, exhausted, intact = run_constraints._traced_replay(
        routes, certificate, child_selector, request, policy, 10**9
    )
    assert failure is None and not exhausted and intact
    assert report is not None and report["computational_status"] == "PASS"
    assert len(launches) >= 1
    assert launches[0] - {
        "src/verifier/domains/contracts/verifier_run_constraints.py"
    } == chain

    launches.clear()
    entry = next(
        row
        for row in routes.current_object_route_catalog()
        if row["objective"] == observation.COORDINATE
    )
    descriptor = next(
        row
        for row in gates.shipped_registry()
        if row["id"] == "current-object:" + entry["semantic_version"] + ":" + entry["objective"]
    )
    replay = routes.replay_current_object_certificate(
        certificate,
        semantic_version=observation.SEMANTIC_VERSION,
        objective=observation.COORDINATE,
        represented_kind="MODEL",
        expected_request=request,
        policy=policy,
    )
    launches.clear()
    cert_path = "retained/model_hardware.json"
    snapshot = SimpleNamespace(files={cert_path: certificate})
    documents = {
        cert_path: {"schema_version": entry["certificate_schema_version"], "request": request}
    }
    selections = [
        {
            "gate_id": descriptor["id"],
            "path": cert_path,
            "represented_kind": "MODEL",
            "request": request,
            "policy": policy,
            "contract_version": replay["schema_version"].rsplit("-", 1)[-1],
        }
    ]
    row = gates._native(descriptor, snapshot, documents, selections)

    assert row["status"] == "PASS"
    assert len(launches) >= 1
    assert launches[0] - {"src/verifier/runtime/gates.py"} == chain


def _require_git() -> None:
    if shutil.which("git") is None:
        pytest.skip(
            "OPTIONAL_DEPENDENCY_ABSENT: git executable is unavailable on PATH; "
            "the core.fsmonitor fixture cannot run here"
        )


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments], cwd=root, capture_output=True, check=True
    ).stdout


def _candidate_repository(root: Path, *, fsmonitor: bool, content: str = "alpha\n") -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "fixture" "@example.invalid")
    _git(root, "config", "user.name", "fixture")
    (root / "file.txt").write_text(content, encoding="utf-8")
    _git(root, "add", "file.txt")
    _git(root, "commit", "-q", "-m", "initial")
    _git(root, "remote", "add", "origin", "https://example.invalid/fixture.git")
    if fsmonitor:
        # The candidate repository, not the caller, configures this hook.  Git runs it
        # with the worktree as working directory, so each invocation writes into it.
        script = root.parent / (root.name + "_fsmonitor.sh")
        script.write_text(
            '#!/bin/sh\necho fired >> "$PWD/hook_fired.txt"\n',
            encoding="utf-8",
            newline="\n",
        )
        _git(root, "config", "core.fsmonitor", "sh " + script.as_posix())
    return root


def _fired(root: Path) -> int:
    marker = root / "hook_fired.txt"
    return 0 if not marker.exists() else len(marker.read_text(encoding="utf-8").splitlines())


def test_candidate_fsmonitor_hook_cannot_fire_on_observer_status_and_ls_files(tmp_path):
    _require_git()
    control = _candidate_repository(tmp_path / "control", fsmonitor=False)
    hooked = _candidate_repository(tmp_path / "hooked", fsmonitor=True)

    estate._git_status_digest(control)
    estate._git_untracked_paths(control)
    assert _fired(control) == 0

    estate._git_status_digest(hooked)
    after_status = _fired(hooked)
    estate._git_untracked_paths(hooked)
    assert after_status == 0
    assert _fired(hooked) == 0


def test_candidate_fsmonitor_cannot_bypass_observer_isolation(tmp_path):
    _require_git()
    source = (RUNTIME / "self_polish_estate.py").read_text(encoding="utf-8")
    # Lexical review and process isolation are separate gates.  The latter must
    # prevent repository-controlled fsmonitor configuration from creating effects.
    assert _write_findings(source) == []
    hooked = _candidate_repository(tmp_path / "hooked", fsmonitor=True)

    estate._git_status_digest(hooked)

    assert _fired(hooked) == 0


def test_admission_discovery_reaches_observer_chain_without_running_candidate_fsmonitor(
    tmp_path, monkeypatch
):
    _require_git()
    hooked = _candidate_repository(tmp_path / "hooked", fsmonitor=True)
    seen: set[str] = set()
    original = estate._run_git

    def recording(root, *arguments):
        seen.update(_verifier_frames())
        return original(root, *arguments)

    monkeypatch.setattr(estate, "_run_git", recording)
    namespace_discovery.discover(hooked)

    assert _fired(hooked) == 0
    assert seen == set(DISCOVERY_OBSERVER_CHAIN)


def test_observer_git_queries_isolate_ambient_git_dir(tmp_path, monkeypatch):
    _require_git()
    control = _candidate_repository(tmp_path / "control", fsmonitor=False, content="alpha\n")
    other = _candidate_repository(tmp_path / "other", fsmonitor=False, content="beta\n")
    control_head = _git(control, "rev-parse", "HEAD").decode().strip()
    other_head = _git(other, "rev-parse", "HEAD").decode().strip()
    assert control_head != other_head

    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    coordinate = estate._git_coordinate(control)

    assert coordinate["revision"] == control_head


def test_no_refutation_is_emitted_for_any_catalog_object():
    for object_id, item in review.review_document().items():
        for kind, decision in item["classification"].items():
            assert decision["status"] in {"APPLIES", "UNRESOLVED"}, (object_id, kind)


# Observer review prose may claim fsmonitor disabling only for the mutable
# worktree-state capture.  The read-only object-database helpers assert neither
# index refresh nor fsmonitor behavior.  Mirrors the declaration-side guard in
# tests/test_package_semantic_ownership.py.
OBSERVER_CAPTURE = "mutable worktree-state capture"
OBSERVER_DISCLAIMER = "assert neither index refresh nor fsmonitor behavior"


def _observer_review_texts() -> list[str]:
    texts = []
    for field in dataclasses.fields(review._SOURCE_OBSERVER):
        value = getattr(review._SOURCE_OBSERVER, field.name)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, tuple):
            texts.extend(item for item in value if isinstance(item, str))
    texts.extend(
        reason
        for (object_id, _kind), reason in review._SOURCE_BOUND_UNRESOLVED_REASONS.items()
        if object_id == "vstd-source-provenance-observer"
    )
    return texts


def _unscoped_fsmonitor_clauses(text: str) -> list[str]:
    clauses = text.replace(". ", "; ").split("; ")
    return [
        clause
        for clause in clauses
        if "fsmonitor" in clause
        and OBSERVER_CAPTURE not in clause
        and OBSERVER_DISCLAIMER not in clause
    ]


def _asserts_refutation(reason: str) -> bool:
    return "refuted" in reason.replace("not refuted", "") or "DOES_NOT_APPLY" in reason


def test_observer_review_prose_scopes_fsmonitor_disabling_to_the_capture():
    offenders = [
        clause
        for text in _observer_review_texts()
        for clause in _unscoped_fsmonitor_clauses(text)
    ]
    assert offenders == []


@pytest.mark.parametrize(
    "claim",
    [
        "Fixed Git observation runs with repository-configured fsmonitor disabled.",
        "Every observer Git query runs with repository-configured fsmonitor disabled.",
        "These paths observe selected source with repository-configured fsmonitor execution disabled.",
    ],
)
def test_rebroadened_observer_review_prose_is_rejected(claim):
    assert _unscoped_fsmonitor_clauses(claim) != []


def test_observer_transaction_and_actuator_are_unresolved_never_refuted_or_evidenced():
    observer = review.review_document()["vstd-source-provenance-observer"]
    for kind in ("TRANSACTION", "ACTUATOR"):
        decision = observer["classification"][kind]
        assert decision["status"] == "UNRESOLVED"
        assert decision["evidence_paths"] == []
        assert "not refuted" in decision["reason"]
        assert not _asserts_refutation(decision["reason"])
    assert "vstd-source-provenance-observer" not in review._AUDITED_REFUTATIONS


@pytest.mark.parametrize(
    "reason",
    [
        "Actuator applicability is refuted by the fixed Git launch.",
        "Transaction applicability is DOES_NOT_APPLY for the observer.",
    ],
)
def test_refutation_inversion_text_is_detected(reason):
    assert _asserts_refutation(reason)
