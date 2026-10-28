"""Source-derived evidence gates and wrong-reason mutants for the systems ownership batch of the Verifier Standard (VSTD).

Terminology: application programming interface (API).

Each carried role is checked against a fact read from its owned source: an abstract syntax tree (AST) launch
call, an executable verifier behavior, an agency or admission anchor, or a multi-artifact linkage.
No check compares the module with a copy of its own table.  Every unresolved slot must
appear as a typed UNKNOWN record with a diagnostic and a next action.  Each mutant must
fail on exactly the rule it targets, so a failure for an unrelated reason cannot pass.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from verifier.runtime import package_semantic_ownership as central
from verifier.runtime import package_semantic_ownership_domains_systems as domains
from verifier.runtime.namespace_contracts import compatible_specialization, namespace_registry
from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    root_role_decision,
)


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src/verifier/runtime/package_semantic_ownership_domains_systems.py"
REGISTRY = namespace_registry()
SPECS = domains.DOMAIN_SYSTEMS_OWNERSHIP_SPECS
UNRESOLVED = tuple(getattr(domains, "UNRESOLVED_RECORDS", ()))
AUDITED_PATHS = tuple(sorted(domains.AUDITED_SOURCE_DIGESTS))
DOCS_UNRESOLVED_PRIMARY_PATHS = frozenset({
    "docs/assets/vstd-overview.png",
    "docs/guides.html",
    "docs/index.html",
    "docs/reference.html",
})

# (object_id, slot, candidate) of every role slot the audit leaves UNKNOWN.  A slot is
# absent from its spec and present here, never recorded as DOES_NOT_APPLY.
EXPECTED_UNRESOLVED: frozenset[tuple[str, str, str | None]] = frozenset({
    ("vstd-hardware-retained-device-records", "specialization", "POLICY"),
    ("vstd-hardware-retained-device-records", "specialization", "TRANSACTION"),
    ("vstd-hardware-capacity-reservation", "specialization", "TRANSACTION"),
    ("vstd-data-retained-records", "specialization", "POLICY"),
    ("vstd-token-facet-projection", "specialization", "POLICY"),
    ("vstd-train-run-specification", "specialization", "POLICY"),
    ("vstd-train-run-specification", "specialization", "PROTOCOL"),
    ("vstd-verifier-engine-specification", "specialization", "POLICY"),
    ("vstd-run-reproduction-protocol", "specialization", "POLICY"),
    ("vstd-train-native-checks", "specialization", "PROTOCOL"),
    ("vstd-verifier-bootstrap-evidence", "specialization", "PROTOCOL"),
    ("vstd-manifest-write-cli", "specialization", "PROTOCOL"),
    ("vstd-manifest-write-execution-checks", "specialization", "PROTOCOL"),
    ("vstd-verifier-replacement-replay", "root", "AGENT"),
    ("vstd-harness-applicability-denominator", "root", "AGENT"),
    ("vstd-package-overview-raster", "primary", None),
    ("vstd-package-guides-page", "primary", None),
    ("vstd-package-index-page", "primary", None),
    ("vstd-package-generated-reference", "primary", None),
})

# Source anchors: (path, marker).  A marker must occur in the owned file after whitespace
# collapse.  Each anchor is the textual evidence a carried claim relies on.
AGENCY_ANCHORS = {
    "vstd-run-harness-capture": ("src/verifier/core/run.py",
                                 "an agent or command executed under a VSTD harness"),
    "vstd-language-runner-selection": ("src/verifier/runtime/language_runners.py",
                                       '"AGENT": "agent-open-ended"'),
}
PROTOCOL_ANCHORS = {
    "vstd-run-harness-capture": ("src/verifier/core/run.py", "class ProvenanceLinkage"),
}
ADMISSION_ANCHORS = {
    "vstd-hardware-capacity-reservation": (
        "src/verifier/domains/contracts/hardware_capacity.py",
        (
            "policy differs from installed mechanism",
            "bounded sorted unique trust-root labels required",
            "certificate byte bound is unsupported",
            "finite checker limit is unsupported",
        ),
    ),
    "vstd-run-planning-protocol": ("src/verifier/core/run_planning.py",
                                   "String/shell commands are rejected"),
    "vstd-data-checks-projection": ("src/verifier/domains/contracts/data_checks_projection.py",
                                    "check is outside the fixed reviewed five-row set"),
    "vstd-token-checks-projection": ("src/verifier/domains/contracts/token_checks_projection.py",
                                    "check is outside the fixed reviewed TOKEN set"),
    "vstd-verifier-bootstrap-evidence": ("src/verifier/domains/verifier_bootstrap.py",
                                         "admit_ed25519_public_key"),
    "vstd-run-validation-protocol": ("src/verifier/core/run_validation.py",
                                     "Canonical digest mismatch"),
    "vstd-language-runner-selection": ("src/verifier/runtime/language_runners.py",
                                       "RUNNER_TRUSTED_LOCAL_SELECTION_REQUIRED"),
    "vstd-train-native-checks": (
        "src/verifier/domains/contracts/train_checks.py",
        (
            "policy differs from installed mechanism",
            "bounded sorted unique trust-root labels required",
            "certificate byte bound is unsupported",
            "finite checker limit is unsupported",
        ),
    ),
}
# Audited files whose POLICY claim is admitted only through an ADMISSION_ANCHORS entry.
POLICY_AUDITED = frozenset({
    "vstd-hardware-retained-device-records", "vstd-hardware-capacity-reservation",
    "vstd-data-retained-records", "vstd-data-checks-projection", "vstd-token-facet-projection",
    "vstd-token-checks-projection", "vstd-train-run-specification",
    "vstd-verifier-engine-specification", "vstd-run-planning-protocol",
    "vstd-run-validation-protocol", "vstd-run-reproduction-protocol",
    "vstd-train-native-checks",
})
# Replay or check artifacts that carry no multi-artifact protocol claim of their own.
SINGLE_ARTIFACT_PROTOCOL = frozenset({
    "vstd-train-run-specification", "vstd-train-native-checks", "vstd-verifier-bootstrap-evidence",
    "vstd-manifest-write-cli", "vstd-manifest-write-execution-checks",
})
LAUNCH_NAMES = frozenset({"capture_run", "_run_owned_process", "Popen"})
DOCS_SUFFIXES = (".png", ".html", ".svg", ".js", ".css")
OPEN_OBLIGATION_CLAUSE = "remain OPEN; the role label is not conformance"

# Exact source-structure contracts for every carried VERIFIER role.  A source digest
# binds the bytes; this table binds the named executable entry point and the kind of
# decision it must actually make.  Dead names and free-floating status literals do not
# satisfy any contract.
VERIFIER_BEHAVIOR_ANCHORS = {
    "vstd-data-distribution-certificate": ("src/verifier/domains/contracts/data_distribution.py", "_evaluate", "mechanism-decision"),
    "vstd-data-native-checks": ("src/verifier/domains/contracts/data_checks.py", "_evaluate", "mechanism-decision"),
    "vstd-data-retained-records": ("src/verifier/domains/data.py", "evaluate", "domain-evaluator"),
    "vstd-hardware-capacity-reservation": ("src/verifier/domains/contracts/hardware_capacity.py", "_evaluate", "mechanism-decision"),
    "vstd-hardware-containment-topology": ("src/verifier/domains/contracts/hardware_topology.py", "_evaluate", "mechanism-decision"),
    "vstd-hardware-inventory-certificate": ("src/verifier/domains/contracts/hardware_inventory.py", "_evaluate", "mechanism-decision"),
    "vstd-hardware-inventory-closure": ("src/verifier/domains/contracts/hardware_inventory_closure.py", "_evaluate", "mechanism-decision"),
    "vstd-hardware-measurement-envelope": ("src/verifier/domains/contracts/hardware_measurements.py", "_evaluate", "mechanism-decision"),
    "vstd-hardware-retained-device-records": ("src/verifier/domains/hardware.py", "evaluate", "domain-evaluator"),
    "vstd-hardware-substrate-observation": ("src/verifier/domains/contracts/hardware_substrate_observations.py", "_evaluate", "mechanism-decision"),
    "vstd-harness-applicability-denominator": ("src/verifier/runtime/package_harness_applicability.py", "assess_repository", "sealed-report"),
    "vstd-harness-gap-boundary": ("src/verifier/domains/contracts/harness_gap_boundary.py", "_evaluate", "mechanism-decision"),
    "vstd-harness-native-checks": ("src/verifier/domains/contracts/harness_checks.py", "_evaluate", "mechanism-decision"),
    "vstd-harness-observation-surface": ("src/verifier/domains/harness.py", "evaluate", "domain-evaluator"),
    "vstd-language-runner-selection": ("src/verifier/runtime/language_runners.py", "assess_runner", "delegated-report"),
    "vstd-manifest-write-execution-checks": ("src/verifier/runtime/manifest_write_execution.py", "check_observations", "boolean-check"),
    "vstd-run-validation-protocol": ("src/verifier/core/run_validation.py", "validate_run_receipt", "exit-status"),
    "vstd-token-holding-replay": ("src/verifier/domains/token.py", "evaluate", "domain-evaluator"),
    "vstd-token-native-checks": ("src/verifier/domains/contracts/token_checks.py", "_evaluate", "mechanism-decision"),
    "vstd-train-accumulation-certificate": ("src/verifier/domains/contracts/train_accumulation.py", "_evaluate", "mechanism-decision"),
    "vstd-train-data-bridge": ("src/verifier/domains/contracts/train_data_bridge.py", "_evaluate", "mechanism-decision"),
    "vstd-train-native-checks": ("src/verifier/domains/contracts/train_checks.py", "_evaluate", "mechanism-decision"),
    "vstd-train-run-specification": ("src/verifier/domains/train.py", "evaluate", "domain-evaluator"),
}

# Markers are phrases the owned source must contain.  Each names the source sentence a
# row's reason was read from; drift in a file surfaces first in the digest test.
MARKERS: dict[str, str | bytes] = {
    "src/verifier/domains/hardware.py": "never physical attestation",
    "src/verifier/domains/contracts/hardware_capacity.py": "does not attest physical devices",
    "src/verifier/domains/contracts/hardware_inventory.py": "does not attest physical devices",
    "src/verifier/domains/contracts/hardware_inventory_closure.py": "proves no physical coverage",
    "src/verifier/domains/contracts/hardware_measurements.py": "validates retained declarations, not physical devices",
    "src/verifier/domains/contracts/hardware_substrate_observations.py": "authenticates no device, observer, signature",
    "src/verifier/domains/contracts/hardware_topology.py": "Acyclicity applies to containment, not communication links",
    "src/verifier/domains/harness.py": "the instrumented observation surface, not the actor",
    "src/verifier/domains/contracts/harness_checks.py": "Retained observations do not establish live execution or physical isolation",
    "src/verifier/domains/contracts/harness_gap_boundary.py": "named gaps bounded by retained instrument placements",
    "src/verifier/core/run.py": "wrap any consequential",
    "src/verifier/core/run_process_observation.py": "intentionally narrower than a whole HARNESS observation",
    "src/verifier/core/run_validation.py": "Fail-closed structural and canonical-digest validation",
    "src/verifier/core/run_impact.py": "Recorded-ancestry impact analysis",
    "src/verifier/core/run_inspection.py": "Human-readable inspection",
    "src/verifier/core/run_planning.py": "Side-effect-free generic-run manifest loading",
    "src/verifier/core/run_reproduction.py": "Opt-in rerun and side-effect-free artifact-rehash",
    "src/verifier/core/run_support.py": "Shared internal coordinates",
    "src/verifier/runtime/language_runners.py": "trusted-local process runner is NOT a security sandbox",
    "extensions/languages/src/vstd_languages/__init__.py": "no verification obligation is discharged",
    "extensions/languages/pyproject.toml": "dependencies = []",
    "src/verifier/runtime/package_harness_applicability.py": "never imports subject modules or starts a process",
    "src/verifier/domains/data.py": "Retained statistics establish no external ancestry",
    "src/verifier/domains/contracts/data_checks.py": "do not establish external origin or rights",
    "src/verifier/domains/contracts/data_checks_projection.py": "grants no reverse equivalence",
    "src/verifier/domains/contracts/data_distribution.py": "entropy and its selected tolerance",
    "src/verifier/domains/token.py": "Zero-identity zero-knowledge token",
    "src/verifier/domains/contracts/token_checks.py": "never authority grants",
    "src/verifier/domains/contracts/token_checks_projection.py": "Fixed one-way projections for three reviewed TOKEN registrations",
    "src/verifier/domains/contracts/token_facets.py": "Commitment anchors do not establish",
    "src/verifier/domains/train.py": "checkpoint and numerical replay",
    "src/verifier/domains/contracts/train_accumulation.py": "The executing hardware is never observed",
    "src/verifier/domains/contracts/train_checks.py": "Retained observations do not establish live execution",
    "src/verifier/domains/contracts/train_data_bridge.py": "selected retained representations",
    "src/verifier/domains/verifier.py": "content-bound inventory",
    "src/verifier/domains/verifier_bootstrap.py": "exhaustive truth-table evaluation",
    "src/verifier/domains/contracts/verifier_composed_security.py": "RECEIPT-9.2 issuer-key replay",
    "src/verifier/domains/contracts/verifier_coverage_closure.py": "Completeness beyond the declared finite class remains NOT_ESTABLISHED",
    "src/verifier/domains/contracts/verifier_replacement.py": "never callbacks",
    "src/verifier/runtime/manifest_write_execution.py": "power-loss durability",
    "src/verifier/runtime/manifest_write_worker.py": "Only installed handlers and fixed fixtures execute",
    "src/verifier/runtime/namespace_cli.py": "read-only preview",
    "docs/assets/orientation-previews.js": 'data-orientation-preview="repository"',
    "docs/assets/site.css": "color-scheme: dark",
    "docs/assets/vstd-overview.png": b"\x89PNG",
    "docs/assets/vstd-overview.svg": "later profiles never substitute for prerequisites",
    "docs/guides.html": "Maintained Verifier Standard guides",
    "docs/index.html": "verification-domain language and Python reference implementation",
    "docs/reference.html": "Generated reference for the Verifier Standard",
    "pyproject.toml": "dependencies = []",
    "src/verifier/hardware/accelerator_registry.json": "No core guarantee is inferred from registry membership.",
}


def _by_id(specs):
    return {item.object_id: item for item in specs}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _census_mismatches(root: Path, digests: dict[str, str]) -> list[tuple[str, str]]:
    found = []
    for path, expected in sorted(digests.items()):
        candidate = root / path
        if not candidate.is_file():
            found.append((path, "MISSING"))
        elif _digest(candidate) != expected:
            found.append((path, "DIGEST_DRIFT"))
    return found


def _marker_present(root: Path, path: str, marker: str | bytes) -> bool:
    data = (root / path).read_bytes()
    if isinstance(marker, bytes):
        return marker in data
    text = re.sub(r"\s+", " ", data.decode("utf-8"))
    return " ".join(marker.split()) in text


def _marker_failures(root: Path, markers: dict[str, str | bytes]) -> list[str]:
    return [path for path, marker in sorted(markers.items()) if not _marker_present(root, path, marker)]


def _admission_anchor_present(root: Path, object_id: str) -> bool:
    path, required = ADMISSION_ANCHORS[object_id]
    markers = required if isinstance(required, tuple) else (required,)
    return all(_marker_present(root, path, marker) for marker in markers)


def _tree(path: str) -> ast.AST:
    return ast.parse((ROOT / path).read_text(encoding="utf-8"))


def _launches(path: str) -> bool:
    """True when the source contains a real process-launch call, not a mention of one."""
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and ast.unparse(func.value) == "subprocess":
                return True
            if isinstance(func, ast.Name) and func.id in LAUNCH_NAMES:
                return True
    return False


class _ReachableNodes(ast.NodeVisitor):
    """Collect possible execution nodes while refusing literal-dead branches and nested definitions."""

    def __init__(self) -> None:
        self.nodes: list[ast.AST] = []

    def generic_visit(self, node: ast.AST) -> None:
        self.nodes.append(node)
        super().generic_visit(node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802 - ast visitor API
        self.nodes.append(node)
        self.visit(node.test)
        if isinstance(node.test, ast.Constant) and type(node.test.value) is bool:
            selected = node.body if node.test.value else node.orelse
            for child in selected:
                self.visit(child)
            return
        for child in (*node.body, *node.orelse):
            self.visit(child)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 - ast visitor API
        self.nodes.append(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.nodes.append(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802 - ast visitor API
        self.nodes.append(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802 - ast visitor API
        self.nodes.append(node)


def _function_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    visitor = _ReachableNodes()
    for statement in function.body:
        visitor.visit(statement)
    return visitor.nodes


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _function_closure(tree: ast.AST, entrypoint: str) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef | None, list[ast.AST]]:
    functions = {
        node.name: node
        for node in getattr(tree, "body", ())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    entry = functions.get(entrypoint)
    if entry is None:
        return None, []
    queue = [entrypoint]
    seen: set[str] = set()
    closure: list[ast.AST] = []
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        nodes = _function_nodes(functions[name])
        closure.extend(nodes)
        for node in nodes:
            if isinstance(node, ast.Call):
                target = _call_name(node)
                if target in functions and target not in seen:
                    queue.append(cast(str, target))
    return entry, closure


def _strings(node: ast.AST) -> set[str]:
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def _status_values(nodes: list[ast.AST]) -> set[str]:
    values: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "status":
                    values.update(_strings(value))
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "status"):
                    values.update(_strings(node.value))
    return values


def _behavior_contract(tree: ast.AST, entrypoint: str, contract: str) -> bool:
    entry, closure = _function_closure(tree, entrypoint)
    if entry is None:
        return False
    direct = _function_nodes(entry)
    annotation = ast.unparse(entry.returns) if entry.returns is not None else ""
    returns = [node for node in direct if isinstance(node, ast.Return) and node.value is not None]
    raises = {
        _call_name(node.exc)
        for node in closure
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
    }
    if contract == "mechanism-decision":
        return any(
            isinstance(node.value, ast.Call) and _call_name(node.value) == "MechanismDecision"
            for node in returns
        )
    if contract == "domain-evaluator":
        return annotation == "dict" and bool(returns) and {"Refuted", "Unavailable"} <= raises
    if contract == "boolean-check":
        return (annotation == "bool" and bool(returns) and "ValueError" in raises
                and all(not isinstance(node.value, ast.Constant) for node in returns))
    if contract == "exit-status":
        outcomes = {
            node.value.value
            for node in returns
            if isinstance(node.value, ast.Constant) and type(node.value.value) is int
        }
        return annotation == "int" and {0, 1} <= outcomes
    if contract == "sealed-report":
        sealed = any(
            isinstance(node.value, ast.Call) and _call_name(node.value) == "_seal"
            for node in returns
        )
        return annotation.startswith("dict[") and sealed and {"PASS", "REFUTED", "UNKNOWN"} <= _status_values(closure)
    if contract == "delegated-report":
        delegates = any(
            isinstance(node.value, ast.Call)
            and {"_with_guidance", "_assess_runner"} <= {
                item.id for item in ast.walk(node.value) if isinstance(item, ast.Name)
            }
            for node in returns
        )
        return annotation.startswith("dict[") and delegates and {"PASS", "FAIL", "UNKNOWN"} <= _status_values(closure)
    raise AssertionError("unknown verifier behavior contract " + contract)


def _verifier_behavior_established(object_id: str, path: str) -> bool:
    anchor = VERIFIER_BEHAVIOR_ANCHORS.get(object_id)
    if anchor is None:
        return False
    anchored_path, entrypoint, contract = anchor
    return path == anchored_path and _behavior_contract(_tree(path), entrypoint, contract)


def _unresolved_keys(records=UNRESOLVED) -> set[tuple[str, str, str | None]]:
    return {(record.object_id, record.slot, record.candidate) for record in records}


def _rule_violations(specs, unresolved=UNRESOLVED, *, registry=REGISTRY) -> list[tuple[str, str]]:
    """Independent refutation rules.  Each returns (rule, object_id); the message says the next action."""
    found: list[tuple[str, str]] = []
    seen_paths: dict[str, str] = {}
    for spec in specs:
        primary = spec.primary_kind
        path = spec.owned_paths[0] if spec.owned_paths else ""
        if primary == "OBJECT" or "OBJECT" in spec.specializations:
            found.append(("OBJECT_FALLBACK", spec.object_id))
        if primary not in registry:
            found.append(("PRIMARY_UNREGISTERED", spec.object_id))
        if primary == "DATA" and (path.startswith("docs/") or path.endswith(DOCS_SUFFIXES)):
            found.append(("DOCS_OR_RASTER_AS_DATA", spec.object_id))
        for kind in spec.specializations:
            if kind not in registry or registry[kind].extends is None or not compatible_specialization(registry, primary, kind):
                found.append(("SPECIALIZATION_INVALID", spec.object_id))
        for text in (spec.representation_role, spec.necessity_reason, spec.consequence_boundary):
            if not text.strip():
                found.append(("REASON_REQUIRED", spec.object_id))
        if spec.operands:
            found.append(("OPERAND_TARGET_INVENTED", spec.object_id))
        if primary == "HARDWARE" and {"MEASUREMENT", "SENSOR"} & set(spec.specializations):
            found.append(("HARDWARE_LIVE_ROLE_PROMOTED", spec.object_id))
        if primary == "TOKEN" and {"ASSET", "FINBOT", "MARKET", "LEDGER"} & set(spec.specializations):
            found.append(("TOKEN_FINANCIAL_ROLE_PROMOTED", spec.object_id))
        if "ACTUATOR" in spec.specializations and not _launches(path):
            found.append(("ACTUATOR_WITHOUT_LAUNCH_CALL", spec.object_id))
        if "POLICY" in spec.specializations and spec.object_id in POLICY_AUDITED:
            if spec.object_id not in ADMISSION_ANCHORS or not _admission_anchor_present(ROOT, spec.object_id):
                found.append(("POLICY_WITHOUT_ADMISSION_ANCHOR", spec.object_id))
        if "PROTOCOL" in spec.specializations and spec.object_id in SINGLE_ARTIFACT_PROTOCOL:
            found.append(("SINGLE_ARTIFACT_PROTOCOL", spec.object_id))
        if "PROTOCOL" in spec.specializations and spec.object_id in PROTOCOL_ANCHORS:
            if not _marker_present(ROOT, *PROTOCOL_ANCHORS[spec.object_id]):
                found.append(("PROTOCOL_ANCHOR_ABSENT", spec.object_id))
        for decision in spec.root_role_decisions:
            if decision.kind == primary:
                found.append(("ROOT_DECISION_ON_PRIMARY", spec.object_id))
            if decision.kind not in registry or registry[decision.kind].extends is not None:
                found.append(("ROOT_DECISION_NOT_ROOT", spec.object_id))
            if decision.status not in {"APPLIES", "DOES_NOT_APPLY"} or not decision.reason.strip():
                found.append(("ROOT_DECISION_INVALID", spec.object_id))
            if decision.kind == "AGENT" and decision.status == "APPLIES":
                anchor = AGENCY_ANCHORS.get(spec.object_id)
                rule = "HARNESS_AGENT_PROMOTED" if primary == "HARNESS" and anchor is None else None
                if anchor is None:
                    found.append((rule or "AGENT_APPLIES_WITHOUT_AGENCY_ANCHOR", spec.object_id))
                elif not _marker_present(ROOT, *anchor):
                    found.append(("AGENCY_ANCHOR_ABSENT", spec.object_id))
            if (decision.kind == "VERIFIER" and decision.status == "APPLIES"
                    and not _verifier_behavior_established(spec.object_id, path)):
                found.append(("VERIFIER_APPLIES_WITHOUT_BEHAVIOR", spec.object_id))
        for owned in spec.owned_paths:
            if owned in seen_paths:
                found.append(("PATH_DUPLICATED", owned))
            seen_paths[owned] = spec.object_id
    specs_by_id = _by_id(specs)
    for record in unresolved:
        if not (record.reason.strip() and record.next_action.strip()):
            found.append(("UNRESOLVED_WITHOUT_DIAGNOSTIC", record.object_id))
        spec = specs_by_id.get(record.object_id)
        if spec is None:
            continue
        if record.slot == "root" and any(d.kind == record.candidate for d in spec.root_role_decisions):
            found.append(("UNKNOWN_ALSO_DECIDED", record.object_id))
        if record.slot == "specialization" and record.candidate in spec.specializations:
            found.append(("UNKNOWN_ALSO_CARRIED", record.object_id))
        if record.slot == "primary":
            found.append(("UNKNOWN_ALSO_DECIDED", record.object_id))
    return found


def _mutant(name: str):
    """Return (specs, unresolved, expected_rule, central_accepts) for one wrong-reason mutant."""
    rows = {item.object_id: item for item in SPECS}

    def swap(object_id: str, **changes):
        return tuple(dataclasses.replace(item, **changes) if item.object_id == object_id else item for item in SPECS)

    def without(object_id: str, slot: str, candidate: str | None):
        return tuple(r for r in UNRESOLVED if (r.object_id, r.slot, r.candidate) != (object_id, slot, candidate))

    if name == "actuator_on_namespace_cli":
        row = rows["vstd-manifest-write-cli"]
        return swap("vstd-manifest-write-cli", specializations=tuple(sorted((*row.specializations, "ACTUATOR")))), UNRESOLVED, "ACTUATOR_WITHOUT_LAUNCH_CALL", True
    if name == "actuator_on_process_observation":
        row = rows["vstd-run-process-observation"]
        return swap("vstd-run-process-observation", specializations=tuple(sorted((*row.specializations, "ACTUATOR")))), UNRESOLVED, "ACTUATOR_WITHOUT_LAUNCH_CALL", True
    if name == "agent_on_harness_checks":
        decisions = (root_role_decision("AGENT", "APPLIES", "treated as the actor"),
                     root_role_decision("VERIFIER", "APPLIES", "certificate replay"))
        return swap("vstd-harness-native-checks", root_role_decisions=decisions), UNRESOLVED, "HARNESS_AGENT_PROMOTED", True
    if name == "agent_decided_where_unknown":
        decisions = (root_role_decision("AGENT", "DOES_NOT_APPLY", "not an agent"),)
        return swap("vstd-verifier-replacement-replay", root_role_decisions=decisions), UNRESOLVED, "UNKNOWN_ALSO_DECIDED", True
    if name == "measurement_on_hardware":
        row = rows["vstd-hardware-measurement-envelope"]
        return swap("vstd-hardware-measurement-envelope", specializations=tuple(sorted((*row.specializations, "MEASUREMENT")))), UNRESOLVED, "HARDWARE_LIVE_ROLE_PROMOTED", True
    if name == "asset_on_token":
        row = rows["vstd-token-native-checks"]
        return swap("vstd-token-native-checks", specializations=tuple(sorted((*row.specializations, "ASSET")))), UNRESOLVED, "TOKEN_FINANCIAL_ROLE_PROMOTED", True
    if name == "object_primary":
        return swap("vstd-run-support-coordinates", primary_kind="OBJECT"), UNRESOLVED, "OBJECT_FALLBACK", False
    if name == "docs_raster_as_data":
        raster = ownership_row_factory("vstd-package-overview-raster", "DATA", "docs/assets/vstd-overview.png")
        return SPECS + (raster,), without("vstd-package-overview-raster", "primary", None), "DOCS_OR_RASTER_AS_DATA", False
    if name == "policy_on_data_without_gate":
        row = rows["vstd-data-retained-records"]
        return swap("vstd-data-retained-records", specializations=tuple(sorted((*row.specializations, "POLICY")))), without("vstd-data-retained-records", "specialization", "POLICY"), "POLICY_WITHOUT_ADMISSION_ANCHOR", True
    if name == "protocol_on_single_artifact_bootstrap":
        row = rows["vstd-verifier-bootstrap-evidence"]
        return swap("vstd-verifier-bootstrap-evidence", specializations=tuple(sorted((*row.specializations, "PROTOCOL")))), without("vstd-verifier-bootstrap-evidence", "specialization", "PROTOCOL"), "SINGLE_ARTIFACT_PROTOCOL", True
    if name == "verifier_applies_without_behavior":
        decisions = (root_role_decision("VERIFIER", "APPLIES", "claims verifier behavior"),)
        return swap("vstd-manifest-write-cli", root_role_decisions=decisions), UNRESOLVED, "VERIFIER_APPLIES_WITHOUT_BEHAVIOR", True
    if name == "unknown_root_status":
        decisions = (RootRoleDecision("VERIFIER", cast(Any, "UNKNOWN"), "not a decision"),)
        return swap("vstd-data-native-checks", root_role_decisions=decisions), UNRESOLVED, "ROOT_DECISION_INVALID", False
    if name == "duplicate_path":
        # Neither row claims VERIFIER, so only the duplication rule can fire.
        return swap("vstd-run-impact-analysis", owned_paths=("src/verifier/core/run_support.py",)), UNRESOLVED, "PATH_DUPLICATED", False
    if name == "blank_reason":
        return swap("vstd-run-impact-analysis", necessity_reason="  "), UNRESOLVED, "REASON_REQUIRED", False
    if name == "invented_operand":
        return swap("vstd-data-native-checks", operands=(("data", ("vstd-invented-data-target",)),)), UNRESOLVED, "OPERAND_TARGET_INVENTED", False
    if name == "root_decision_on_primary":
        decisions = (root_role_decision("DATA", "APPLIES", "self-decision"),)
        return swap("vstd-data-native-checks", root_role_decisions=decisions), UNRESOLVED, "ROOT_DECISION_ON_PRIMARY", False
    raise AssertionError("unknown mutant " + name)


def ownership_row_factory(object_id: str, primary: str, path: str):
    from verifier.runtime.package_semantic_ownership_model import ownership_spec

    return ownership_spec(object_id, primary, (path,), "mutant", "mutant reason", "mutant boundary")


def test_census_partitions_the_audited_paths_exactly():
    assert len(AUDITED_PATHS) == 51 == len(set(AUDITED_PATHS))
    owned = sorted(path for spec in SPECS for path in spec.owned_paths)
    unresolved_primary = sorted(record.path for record in UNRESOLVED if record.slot == "primary")
    assert sorted(owned + unresolved_primary) == list(AUDITED_PATHS), (
        "owned plus unresolved-primary paths must equal the audited census; next action: "
        "record an unowned path as a typed UNKNOWN primary or give it a registered owner"
    )
    assert set(unresolved_primary) == DOCS_UNRESOLVED_PRIMARY_PATHS


def test_audited_digests_match_current_sources():
    assert _census_mismatches(ROOT, domains.AUDITED_SOURCE_DIGESTS) == [], (
        "digest drift: re-audit the named source before rebinding its digest"
    )
    for path, digest in domains.AUDITED_SOURCE_DIGESTS.items():
        assert _digest(ROOT / path) == digest, path


def test_source_drift_is_detected_in_a_scratch_copy(tmp_path):
    for path in domains.AUDITED_SOURCE_DIGESTS:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / path, target)
    assert _census_mismatches(tmp_path, domains.AUDITED_SOURCE_DIGESTS) == []
    drifted = "src/verifier/domains/data.py"
    (tmp_path / drifted).write_bytes((ROOT / drifted).read_bytes() + b"\n# drift\n")
    (tmp_path / "src/verifier/domains/train.py").unlink()
    assert _census_mismatches(tmp_path, domains.AUDITED_SOURCE_DIGESTS) == [
        ("src/verifier/domains/data.py", "DIGEST_DRIFT"),
        ("src/verifier/domains/train.py", "MISSING"),
    ]


def test_source_markers_anchor_every_audited_file():
    assert set(MARKERS) == set(AUDITED_PATHS)
    assert _marker_failures(ROOT, MARKERS) == []


def test_rule_refutations_hold_on_the_shipped_rows():
    assert _rule_violations(SPECS, UNRESOLVED) == [], "a shipped row violates a refutation rule"


def test_unresolved_slots_are_typed_unknown_records_with_next_actions():
    keys = _unresolved_keys()
    missing = sorted(EXPECTED_UNRESOLVED - keys, key=str)
    unexpected = sorted(keys - EXPECTED_UNRESOLVED, key=str)
    assert not missing and not unexpected, (
        f"missing UNKNOWN records {missing}; unexpected {unexpected}; "
        "next action: record each unresolved slot as a typed UNKNOWN, never as DOES_NOT_APPLY"
    )
    for record in UNRESOLVED:
        assert record.status == "UNKNOWN", record.object_id
        assert record.reason.strip() and record.next_action.strip(), record.object_id


def test_unknown_roles_are_never_recorded_as_does_not_apply():
    decided = {(s.object_id, d.kind): d.status for s in SPECS for d in s.root_role_decisions}
    for object_id, slot, candidate in EXPECTED_UNRESOLVED:
        if slot == "root" and candidate is not None:
            assert (object_id, candidate) not in decided, (
                f"{object_id} {candidate} is UNKNOWN but recorded as {decided[(object_id, candidate)]}; "
                "next action: remove the decision and keep the typed UNKNOWN record"
            )


def test_agent_applies_only_with_an_explicit_agency_anchor():
    applies = {s.object_id for s in SPECS for d in s.root_role_decisions if d.kind == "AGENT" and d.status == "APPLIES"}
    assert applies == set(AGENCY_ANCHORS), (
        f"AGENT APPLIES set {sorted(applies)} must equal the anchored set {sorted(AGENCY_ANCHORS)}; "
        "next action: keep AGENT APPLIES only where the owned source names an agent"
    )
    for object_id, (path, marker) in AGENCY_ANCHORS.items():
        assert _marker_present(ROOT, path, marker), f"{object_id}: agency anchor absent in {path}"


def test_harness_and_replacement_agent_roles_are_not_refuted_by_process_absence():
    # The applicability and replacement rows stay UNKNOWN; absence of a process call is not agency refutation.
    kinds = {(record.object_id, record.candidate) for record in UNRESOLVED if record.slot == "root"}
    assert ("vstd-verifier-replacement-replay", "AGENT") in kinds
    assert ("vstd-harness-applicability-denominator", "AGENT") in kinds


def test_actuator_claims_require_a_real_launch_call():
    for spec in SPECS:
        if "ACTUATOR" in spec.specializations:
            assert _launches(spec.owned_paths[0]), (
                f"{spec.object_id}: ACTUATOR without a launch call in {spec.owned_paths[0]}; "
                "next action: drop ACTUATOR or name the command-to-effect endpoint"
            )
    carried = {s.object_id for s in SPECS if "ACTUATOR" in s.specializations}
    assert "vstd-run-process-observation" not in carried and "vstd-manifest-write-cli" not in carried


def test_verifier_applies_only_with_exact_executable_behavior():
    applies = {
        spec.object_id
        for spec in SPECS
        for decision in spec.root_role_decisions
        if decision.kind == "VERIFIER" and decision.status == "APPLIES"
    }
    assert applies == set(VERIFIER_BEHAVIOR_ANCHORS)
    for spec in SPECS:
        for decision in spec.root_role_decisions:
            if decision.kind == "VERIFIER" and decision.status == "APPLIES":
                assert _verifier_behavior_established(spec.object_id, spec.owned_paths[0]), (
                    f"{spec.object_id}: VERIFIER APPLIES without its exact executable behavior; "
                    "next action: bind a real evaluator or retain a typed UNKNOWN"
                )
    assert ("vstd-run-validation-protocol", "VERIFIER") in {
        (s.object_id, d.kind) for s in SPECS for d in s.root_role_decisions if d.status == "APPLIES"
    }


def test_verifier_detection_rejects_dead_names_and_unreachable_literals(tmp_path):
    dead = tmp_path / "dead_verdict.py"
    dead.write_text(
        "MechanismDecision = object\n"
        "def evaluate():\n"
        "    if False:\n"
        "        return 'PASS'\n"
        "    return 'UNKNOWN'\n"
        "def validate() -> int:\n"
        "    if False:\n"
        "        return 0\n"
        "    return 1\n",
        encoding="utf-8",
    )
    tree = _tree(str(dead))
    assert not _behavior_contract(tree, "evaluate", "mechanism-decision")
    assert not _behavior_contract(tree, "validate", "exit-status")
    assert _verifier_behavior_established(
        "vstd-manifest-write-execution-checks",
        "src/verifier/runtime/manifest_write_execution.py",
    )


def test_boolean_and_exit_status_validators_are_verifiers():
    rows = _by_id(SPECS)
    for object_id in (
        "vstd-manifest-write-execution-checks",
        "vstd-run-validation-protocol",
    ):
        decisions = {(decision.kind, decision.status) for decision in rows[object_id].root_role_decisions}
        assert ("VERIFIER", "APPLIES") in decisions, object_id


def test_domain_evaluators_keep_verifier_obligations():
    rows = _by_id(SPECS)
    for object_id in (
        "vstd-data-retained-records",
        "vstd-hardware-retained-device-records",
        "vstd-harness-observation-surface",
        "vstd-token-holding-replay",
        "vstd-train-run-specification",
    ):
        decisions = {(decision.kind, decision.status) for decision in rows[object_id].root_role_decisions}
        assert ("VERIFIER", "APPLIES") in decisions, object_id


def test_installed_policy_mechanisms_have_symmetric_policy_ownership():
    rows = _by_id(SPECS)
    for object_id in (
        "vstd-hardware-capacity-reservation",
        "vstd-train-native-checks",
    ):
        assert "POLICY" in rows[object_id].specializations, object_id
        assert object_id in ADMISSION_ANCHORS, object_id
        assert _admission_anchor_present(ROOT, object_id), object_id


def test_single_artifact_replay_is_not_protocol_and_runs_keep_linkage():
    for object_id in SINGLE_ARTIFACT_PROTOCOL:
        spec = _by_id(SPECS).get(object_id)
        assert spec is None or "PROTOCOL" not in spec.specializations, object_id
        assert (object_id, "specialization", "PROTOCOL") in _unresolved_keys() or spec is None or "PROTOCOL" not in spec.specializations
    path, marker = PROTOCOL_ANCHORS["vstd-run-harness-capture"]
    assert _marker_present(ROOT, path, marker), "run receipt PROTOCOL needs its multi-artifact linkage"


def test_policy_is_carried_only_through_an_exact_admission_anchor():
    specs = _by_id(SPECS)
    for object_id in POLICY_AUDITED:
        spec = specs.get(object_id)
        carried = spec is not None and "POLICY" in spec.specializations
        if carried:
            assert object_id in ADMISSION_ANCHORS, object_id
            assert _admission_anchor_present(ROOT, object_id), f"{object_id}: admission anchor absent"
        else:
            assert (object_id, "specialization", "POLICY") in _unresolved_keys() or spec is None, (
                f"{object_id}: POLICY neither admitted nor recorded UNKNOWN"
            )


def test_docs_pages_and_raster_are_not_data_primaries():
    for spec in SPECS:
        if spec.primary_kind == "DATA":
            assert not spec.owned_paths[0].startswith("docs/"), spec.object_id
            assert not spec.owned_paths[0].endswith(DOCS_SUFFIXES), spec.object_id
    primaries = {record.path for record in UNRESOLVED if record.slot == "primary"}
    assert primaries == DOCS_UNRESOLVED_PRIMARY_PATHS, (
        f"docs primaries must be UNKNOWN blockers; missing {sorted(DOCS_UNRESOLVED_PRIMARY_PATHS - primaries)}"
    )


def test_train_blockers_say_a_data_owner_exists_without_an_operand_binding():
    data = [item for item in domains.INTEGRATION_BLOCKERS if item.operand_role == "data"]
    assert len(data) == 4
    for item in data:
        assert "DATA owner exists" in item.reason, item.object_id
        assert "no exact DATA operand binding" in item.reason, item.object_id
        assert "no DATA object identifier" not in item.reason and "no DATA identifier" not in item.reason, item.object_id
        assert getattr(item, "next_action", "").strip(), item.object_id


def test_carried_consequential_roles_expose_open_admission_obligations():
    for spec in SPECS:
        carried = bool(spec.specializations) or any(d.status == "APPLIES" for d in spec.root_role_decisions)
        if carried:
            assert OPEN_OBLIGATION_CLAUSE in spec.consequence_boundary, (
                f"{spec.object_id}: carried role lacks the open-obligation statement; "
                "next action: keep admission obligations OPEN in consequence_boundary"
            )


def test_module_has_zero_third_party_or_aggregate_imports():
    import ast as _ast

    tree = _ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, _ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "dataclasses", "verifier.runtime.package_semantic_ownership_model"}
    assert "verifier.runtime.package_semantic_ownership" not in imported


def test_central_validator_accepts_every_non_typed_row_and_refuses_train_layouts():
    non_typed = tuple(s for s in SPECS if s.primary_kind != "TRAIN")
    accepted = central.validate_catalog(ROOT, non_typed)
    assert len(accepted) == len(non_typed) == 43, (
        f"central validate_catalog accepted {len(accepted)} of {len(non_typed)}; next action: inspect the refused row"
    )
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_OWNERSHIP_TYPED_LAYOUT_INVALID"):
        central.validate_catalog(ROOT, tuple(s for s in SPECS if s.primary_kind == "TRAIN"))


def test_completeness_flags_only_the_unresolved_docs_primaries():
    failures = central.completeness_failures(AUDITED_PATHS, SPECS)
    assert sorted((f.kind, f.path) for f in failures) == sorted(
        (central.FAILURE_UNOWNED, path) for path in DOCS_UNRESOLVED_PRIMARY_PATHS
    )


def test_importing_the_module_does_not_load_the_central_aggregate():
    code = (
        "import sys\n"
        "import verifier.runtime.package_semantic_ownership_domains_systems as module\n"
        "assert module.DOMAIN_SYSTEMS_OWNERSHIP_SPECS\n"
        "assert 'verifier.runtime.package_semantic_ownership' not in sys.modules\n"
        "assert 'verifier.core.namespace' not in sys.modules\n"
        "assert 'verifier.runtime.namespace_contracts' not in sys.modules\n"
        "print('isolated')\n"
    )
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "isolated"


@pytest.mark.parametrize(
    "mutant",
    [
        "actuator_on_namespace_cli",
        "actuator_on_process_observation",
        "agent_on_harness_checks",
        "agent_decided_where_unknown",
        "measurement_on_hardware",
        "asset_on_token",
        "object_primary",
        "docs_raster_as_data",
        "policy_on_data_without_gate",
        "protocol_on_single_artifact_bootstrap",
        "verifier_applies_without_behavior",
        "unknown_root_status",
        "duplicate_path",
        "blank_reason",
        "invented_operand",
        "root_decision_on_primary",
    ],
)
def test_wrong_reason_mutants_fail_on_exactly_their_rule(mutant):
    specs, unresolved, expected_rule, central_accepts = _mutant(mutant)
    found = _rule_violations(specs, unresolved)
    rules = {rule for rule, _ in found}
    assert rules == {expected_rule}, (
        f"{mutant}: expected exactly {expected_rule}, found {sorted(found)}; "
        "next action: the mutant must fail on its own rule and no other"
    )
    if central_accepts:
        non_typed = tuple(s for s in specs if s.primary_kind != "TRAIN")
        central.validate_catalog(ROOT, non_typed)
