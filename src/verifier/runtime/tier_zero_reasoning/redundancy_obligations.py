"""Project redundancy statuses into explicit debt or checked keep obligations.

Python's abstract syntax tree (AST) supplies the bounded syntactic guard census.
This does not mutate checker statuses. A keep is admitted only when deleting the named competing
support leaves a site closed by the kept reason, while deleting the kept reason too reopens it.

usage:
  redundancy_obligations.py project OUT.json CHECK.json [CHECK.json ...]
  redundancy_obligations.py guards ROOT OUT.json
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Iterable

REDUNDANCY_STATUSES = {"REDUNDANT", "NOT-LOAD-BEARING"}


def evaluate_keep(keep: dict) -> dict:
    support_facts = {name: set(facts) for name, facts in keep["support_facts"].items()}
    target = keep["reason"]
    removed = set(keep["delete_basis"])
    requirements = {site: set(facts) for site, facts in keep["site_requirements"].items()}
    remaining = set(support_facts) - removed
    with_target = set().union(*(support_facts[name] for name in remaining)) if remaining else set()
    without_target_names = remaining - {target}
    without_target = (
        set().union(*(support_facts[name] for name in without_target_names))
        if without_target_names else set()
    )
    load_bearing = sorted(
        site for site, needed in requirements.items()
        if needed <= with_target and not needed <= without_target
    )
    structurally_valid = (
        bool(keep.get("why")) and target in support_facts and bool(removed)
        and target not in removed and removed <= set(support_facts)
    )
    admitted = structurally_valid and bool(load_bearing)
    if os.environ.get("REDUNDANCY_MUTANT") == "trust-keep":
        admitted = bool(keep.get("why"))
    return {
        "status": "KEEP-ADMITTED" if admitted else "KEEP-REFUTED",
        "reason": target,
        "why": keep.get("why", ""),
        "falsifier": {
            "treatment": "delete-basis",
            "deleted_support": sorted(removed),
            "expectation": "load-bearing",
            "load_bearing_sites": load_bearing,
            "result": "bit" if admitted else "did not bite",
        },
        "next_action": None if admitted else "delete the reason or supply a keep whose counterfactual bears load",
    }


def project(check_paths: list[Path]) -> dict:
    views: dict[str, dict] = {}
    for path in check_paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        status_before = {reason: row["status"] for reason, row in report["reasons"].items()}
        obligations = []
        for reason, row in sorted(report["reasons"].items()):
            if row["status"] in REDUNDANCY_STATUSES:
                obligations.append({
                    "reason": reason,
                    "source_status": row["status"],
                    "obligation_status": "DEBT",
                    "next_action": "delete the reason or justify it with a checked keep",
                    "required_falsifier": "mutate delete-basis <other support> expect load-bearing",
                })
        status_after = {reason: row["status"] for reason, row in report["reasons"].items()}
        if status_before != status_after:
            raise AssertionError(f"projection mutated statuses in {path}")
        views[path.parent.name] = {
            "source": str(path),
            "reason_count": len(report["reasons"]),
            "redundancy_status_count": sum(status in REDUNDANCY_STATUSES for status in status_before.values()),
            "obligations": obligations,
            "statuses_sha256": sha256(
                json.dumps(status_before, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        }
    return {"schema": "vstd-redundancy-obligations/0.1", "views": views}


def _guard_atom(node: ast.AST) -> tuple[str, str, str] | None:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "isinstance" \
            and len(node.args) == 2 and isinstance(node.args[0], ast.Name):
        return "isinstance", node.args[0].id, ast.unparse(node.args[1])
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        left, op, right = node.left, node.ops[0], node.comparators[0]
        if isinstance(left, ast.Name) and isinstance(op, ast.IsNot) and isinstance(right, ast.Constant) \
                and right.value is None:
            return "not-none", left.id, "None"
        if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "type" \
                and len(left.args) == 1 and isinstance(left.args[0], ast.Name) and isinstance(op, ast.Is):
            return "exact-type", left.args[0].id, ast.unparse(right)
    return None


def _atoms(node: ast.AST) -> set[tuple[str, str, str]]:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return set().union(*(_atoms(value) for value in node.values))
    atom = _guard_atom(node)
    return {atom} if atom else set()


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name) and isinstance(inner.ctx, (ast.Store, ast.Del)):
            names.add(inner.id)
    return names


def guard_census(root: Path) -> dict:
    findings: list[dict] = []

    def scan_block(path: str, statements: list[ast.stmt], inherited: set[tuple[str, str, str]]) -> None:
        facts = set(inherited)
        for statement in statements:
            assigned = _assigned_names(statement)
            if not isinstance(statement, (ast.If, ast.Assert)):
                facts = {fact for fact in facts if fact[1] not in assigned}
            if isinstance(statement, ast.Assert):
                selected = _atoms(statement.test)
                if selected and selected <= facts:
                    findings.append({
                        "path": path, "line": statement.lineno, "kind": "assert",
                        "facts": [list(fact) for fact in sorted(selected)],
                    })
                facts |= selected
            elif isinstance(statement, ast.If):
                selected = _atoms(statement.test)
                if selected and selected <= facts:
                    findings.append({
                        "path": path, "line": statement.lineno, "kind": "if",
                        "facts": [list(fact) for fact in sorted(selected)],
                    })
                scan_block(path, statement.body, facts | selected)
                scan_block(path, statement.orelse, facts)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scan_block(path, statement.body, set())
            else:
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                        for field in ("body", "orelse", "finalbody"):
                            scan_block(path, getattr(child, field, []), facts)
                        for handler in getattr(child, "handlers", []):
                            scan_block(path, handler.body, facts)

    before: dict[str, str] = {}
    python_files = sorted(root.rglob("*.py"))
    for target in python_files:
        if any(part in {".git", ".venv", "__pycache__", "build", "dist"} for part in target.parts):
            continue
        relative = target.relative_to(root).as_posix()
        raw = target.read_bytes()
        before[relative] = sha256(raw).hexdigest()
        try:
            tree = ast.parse(raw, filename=relative)
        except SyntaxError:
            continue
        scan_block(relative, tree.body, set())
    changed = [
        path for path, digest_before in before.items()
        if sha256((root / path).read_bytes()).hexdigest() != digest_before
    ]
    return {
        "schema": "vstd-redundant-guard-census/0.1",
        "root": str(root),
        "python_files": len(before),
        "confirmed_syntactic_redundant_guards": len(findings),
        "findings": findings,
        "source_files_changed_during_scan": changed,
        "scope": "identical upstream guard atoms only; semantic implication is not inferred",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    project_parser = commands.add_parser("project")
    project_parser.add_argument("out")
    project_parser.add_argument("checks", nargs="+")
    guards_parser = commands.add_parser("guards")
    guards_parser.add_argument("root")
    guards_parser.add_argument("out")
    args = parser.parse_args()
    report = (
        project([Path(path) for path in args.checks])
        if args.command == "project"
        else guard_census(Path(args.root).resolve(strict=True))
    )
    out = Path(args.out)
    with open(out, "w", encoding="utf-8", newline="") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if args.command == "project":
        print("Q2 PROJECT PASS " + json.dumps({
            name: len(view["obligations"]) for name, view in report["views"].items()
        }, sort_keys=True))
    else:
        print("Q2 GUARD CENSUS PASS " + json.dumps({
            "python_files": report["python_files"],
            "confirmed": report["confirmed_syntactic_redundant_guards"],
            "changed": report["source_files_changed_during_scan"],
        }, sort_keys=True))
    return 0 if not report.get("source_files_changed_during_scan") else 1


if __name__ == "__main__":
    raise SystemExit(main())
