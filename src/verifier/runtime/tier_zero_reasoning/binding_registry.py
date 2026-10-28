"""Compile and apply position-free reason binding keys.

The intermediate representation (IR) is indexed through Python's abstract syntax tree (AST).

The registry is review-only prototype infrastructure. It maps a five-part semantic key

    module, enclosing qualname, node kind, canonical digest, equal-key ordinal

to a line/column hint. References in the compiled reasons IR point to those keys. Rewriting
recomputes the registry on a target tree and updates only the textual location hints. If the
number of equal-key nodes changes, a recorded neighboring-statement context must identify one
candidate uniquely; otherwise the reference remains unchanged and is reported STALE.

usage:
  binding_registry.py compile --root ROOT --out REGISTRY.json REASONS.vstd ...
  binding_registry.py rewrite --root ROOT --registry REGISTRY.json --out-dir DIR REASONS.vstd ...
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Iterable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reasons_dsl as dsl  # noqa: E402


def canonical_ast(node: object) -> str:
    if isinstance(node, ast.AST):
        parts = []
        for name in node._fields:
            value = getattr(node, name, None)
            if value is None or (isinstance(value, list) and not value):
                continue
            parts.append(name + "=" + canonical_ast(value))
        return type(node).__name__ + "(" + ",".join(parts) + ")"
    if isinstance(node, list):
        return "[" + ",".join(canonical_ast(item) for item in node) + "]"
    return repr(node)


def digest(value: object) -> str:
    text = canonical_ast(value) if isinstance(value, (ast.AST, list)) else str(value)
    return "sha256:" + sha256(text.encode("utf-8")).hexdigest()


def module_name(path: str) -> str:
    parts = Path(path).with_suffix("").parts
    if "src" in parts:
        parts = parts[parts.index("src") + 1:]
    return ".".join(parts)


@dataclass
class Record:
    path: str
    module: str
    qual: str
    kind: str
    node_digest: str
    line: int
    col: int
    end_line: int
    context_digest: str
    role: str
    ordinal: int = -1
    group_count: int = -1

    @property
    def base(self) -> tuple[str, str, str, str]:
        return self.module, self.qual, self.kind, self.node_digest

    @property
    def key_parts(self) -> tuple[str, str, str, str, int]:
        return (*self.base, self.ordinal)

    @property
    def key(self) -> str:
        return json.dumps(self.key_parts, separators=(",", ":"))


class SourceIndex:
    def __init__(self, root: Path, paths: Iterable[str]) -> None:
        self.root = root
        self.records: list[Record] = []
        for path in sorted(set(paths)):
            self._add(path)
        groups: dict[tuple[str, str, str, str], list[Record]] = {}
        for record in self.records:
            groups.setdefault(record.base, []).append(record)
        for rows in groups.values():
            rows.sort(key=lambda row: (row.line, row.col, row.end_line, row.role))
            for ordinal, row in enumerate(rows):
                row.ordinal = ordinal
                row.group_count = len(rows)
        self.groups = groups

    def _add(self, relative: str) -> None:
        raw = (self.root / relative).read_bytes()
        tree = ast.parse(raw, filename=relative)
        parents: dict[ast.AST, ast.AST] = {}
        sibling_context: dict[ast.AST, tuple[ast.stmt | None, ast.stmt | None]] = {}
        for parent in ast.walk(tree):
            for _field, value in ast.iter_fields(parent):
                children = value if isinstance(value, list) else [value]
                for child in children:
                    if isinstance(child, ast.AST):
                        parents[child] = parent
                if isinstance(value, list) and all(isinstance(item, ast.stmt) for item in value):
                    for index, item in enumerate(value):
                        sibling_context[item] = (
                            value[index - 1] if index else None,
                            value[index + 1] if index + 1 < len(value) else None,
                        )

        def context(node: ast.AST) -> str:
            selected = node
            while not isinstance(selected, ast.stmt) and selected in parents:
                selected = parents[selected]
            before, after = sibling_context.get(selected, (None, None))
            return digest([before, selected, after])

        module = module_name(relative)

        def record(node: ast.AST, qual: str, role: str) -> None:
            if getattr(node, "lineno", None) is None:
                return
            self.records.append(Record(
                path=relative,
                module=module,
                qual=qual,
                kind=type(node).__name__,
                node_digest=digest(node),
                line=node.lineno,
                col=node.col_offset + 1,
                end_line=getattr(node, "end_lineno", None) or node.lineno,
                context_digest=context(node),
                role=role,
            ))

        def walk(node: ast.AST, qual: str) -> None:
            selected_qual = qual
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                selected_qual = ".".join(part for part in (qual, node.name) if part)
            if isinstance(node, ast.expr):
                record(node, qual, "expression")
            if isinstance(node, ast.arg) and node.annotation is not None:
                record(node.annotation, selected_qual, "annotation")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
                record(node.returns, selected_qual, "annotation")
            if isinstance(node, ast.AnnAssign):
                record(node.annotation, qual, "annotation")
            for child in ast.iter_child_nodes(node):
                walk(child, selected_qual)

        walk(tree, "")

    def expression_matches(self, path: str, qual: str, expression: str,
                           line: int, col: int | None) -> list[Record]:
        wanted = ast.parse(expression, mode="eval").body
        return [
            row for row in self.records
            if row.role == "expression" and row.path == path and row.qual == qual
            and row.kind == type(wanted).__name__ and row.node_digest == digest(wanted)
            and row.line == line and (col is None or row.col == col)
        ]

    def annotation_matches(self, path: str, line: int) -> list[Record]:
        return [
            row for row in self.records
            if row.role == "annotation" and row.path == path and row.line <= line <= row.end_line
        ]


def _site_token(site: dict) -> str:
    token = f"{site['path']}::{site['qual']}"
    if site.get("line") is not None:
        token += f":{site['line']}"
    if site.get("col") is not None:
        token += f":{site['col']}"
    return token


def _paths_and_parsed(names: list[str]) -> tuple[set[str], list[tuple[Path, dict]]]:
    paths: set[str] = set()
    parsed: list[tuple[Path, dict]] = []
    for name in names:
        selected = Path(name)
        result = dsl.parse(selected.read_text(encoding="utf-8"), selected.name)
        parsed.append((selected, result))
        for reason in result["ir"]["reasons"]:
            claim = reason["claim"]
            if isinstance(claim.get("site"), dict):
                paths.add(claim["site"]["path"])
            for basis in reason.get("basis", []):
                if basis["kind"] == "annotation":
                    paths.add(basis["location"]["path"])
    return paths, parsed


def _entry(row: Record) -> dict:
    return {
        "key": list(row.key_parts),
        "path": row.path,
        "line": row.line,
        "col": row.col,
        "end_line": row.end_line,
        "context_digest": row.context_digest,
        "group_count": row.group_count,
        "role": row.role,
    }


def compile_registry(root: Path, names: list[str]) -> dict:
    paths, parsed = _paths_and_parsed(names)
    index = SourceIndex(root, paths)
    entries: dict[str, dict] = {}
    references: list[dict] = []
    problems: list[str] = []
    for selected, result in parsed:
        for reason in result["ir"]["reasons"]:
            claim = reason["claim"]
            site = claim.get("site")
            expression = claim.get("expr") if claim["form"] == "type" else claim.get("call")
            if isinstance(site, dict) and site.get("line") is not None and expression:
                matches = index.expression_matches(
                    site["path"], site["qual"], expression, site["line"], site.get("col")
                )
                if not matches:
                    problems.append(f"{reason['id']}: claim site not found: {_site_token(site)} {expression!r}")
                else:
                    for row in matches:
                        entries[row.key] = _entry(row)
                    references.append({
                        "source": selected.name,
                        "reason": reason["id"],
                        "slot": "claim",
                        "keys": [row.key for row in matches],
                        "old_token": _site_token(site),
                        "keep_column": site.get("col") is not None,
                    })
            for basis_index, basis in enumerate(reason.get("basis", [])):
                if basis["kind"] != "annotation":
                    continue
                location = basis["location"]
                matches = index.annotation_matches(location["path"], location["line"])
                if not matches:
                    problems.append(
                        f"{reason['id']}: annotation not found: {location['path']}:{location['line']}"
                    )
                else:
                    for row in matches:
                        entries[row.key] = _entry(row)
                    references.append({
                        "source": selected.name,
                        "reason": reason["id"],
                        "slot": f"basis:{basis_index}:annotation",
                        "keys": [row.key for row in matches],
                        "old_token": f"{location['path']}:{location['line']}",
                        "keep_column": False,
                    })
    return {
        "schema": "vstd-reason-binding-registry/0.1",
        "root": str(root),
        "entries": {key: entries[key] for key in sorted(entries)},
        "references": sorted(references, key=lambda row: (row["source"], row["reason"], row["slot"])),
        "problems": sorted(problems),
    }


def _resolve_key(index: SourceIndex, baseline: dict) -> tuple[Record | None, str]:
    module, qual, kind, node_digest, ordinal = baseline["key"]
    rows = index.groups.get((module, qual, kind, node_digest), [])
    if os.environ.get("BINDING_REGISTRY_MUTANT") == "absolute-line":
        absolute = [
            row for row in rows
            if row.line == baseline["line"] and row.col == baseline["col"]
        ]
        return (
            (absolute[0], "MUTANT: absolute line and column")
            if len(absolute) == 1
            else (None, f"MUTANT: absolute location matches {len(absolute)}")
        )
    if len(rows) == baseline["group_count"] and ordinal < len(rows):
        return rows[ordinal], "equal-key cardinality and ordinal unchanged"
    context = [row for row in rows if row.context_digest == baseline["context_digest"]]
    if len(context) == 1:
        return context[0], "equal-key cardinality changed; unique context re-anchor"
    if not rows:
        return None, "semantic key base absent"
    return None, f"equal-key cardinality {baseline['group_count']} -> {len(rows)}; context matches {len(context)}"


def _rewrite_text(text: str, changes: list[dict]) -> tuple[str, list[dict]]:
    by_reason: dict[str, list[dict]] = {}
    for change in changes:
        by_reason.setdefault(change["reason"], []).append(change)
    current: str | None = None
    applied: list[dict] = []
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("reason "):
            current = line.split()[1]
        for change in by_reason.get(current or "", []):
            field = "claim" if change["slot"] == "claim" else "basis"
            # A note may quote the old location.  Rewrite only the owning DSL
            # field, once, or provenance text can be silently altered too.
            if line.lstrip().startswith(field + " ") and change["old_token"] in line and change not in applied:
                line = line.replace(change["old_token"], change["new_token"], 1)
                applied.append(change)
        output.append(line)
    return "".join(output), applied


def _stale_token(reference: dict) -> str:
    """A valid but impossible hint, so unresolved registry state cannot bind old bytes silently."""
    if reference["slot"] == "claim":
        path, tail = reference["old_token"].split("::", 1)
        qual = tail.split(":", 1)[0]
        return f"{path}::{qual}:999999999" + (":999999999" if reference["keep_column"] else "")
    path, _line = reference["old_token"].rsplit(":", 1)
    return f"{path}:999999999"


def rewrite(root: Path, registry: dict, names: list[str], out_dir: Path) -> dict:
    paths, _parsed = _paths_and_parsed(names)
    index = SourceIndex(root, paths)
    changes: list[dict] = []
    for reference in registry["references"]:
        resolved: list[Record] = []
        details: list[str] = []
        for key in reference["keys"]:
            row, detail = _resolve_key(index, registry["entries"][key])
            details.append(detail)
            if row is not None:
                resolved.append(row)
        locations = {(row.path, row.line, row.col if reference["keep_column"] else None) for row in resolved}
        ok = len(resolved) == len(reference["keys"]) and len(locations) == 1
        if ok:
            path, line, col = next(iter(locations))
            if reference["slot"] == "claim":
                old_parts = reference["old_token"].split("::", 1)
                qual = old_parts[1].split(":", 1)[0]
                new_token = f"{path}::{qual}:{line}" + (f":{col}" if col is not None else "")
            else:
                new_token = f"{path}:{line}"
        else:
            new_token = _stale_token(reference)
        changes.append({
            **reference,
            "resolved": ok,
            "new_token": new_token,
            "detail": "; ".join(details),
            "next_action": None if ok else "re-anchor this reference against the intended node",
        })
    out_dir.mkdir(parents=True, exist_ok=True)
    applied: list[dict] = []
    for name in names:
        selected = Path(name)
        rewritten, file_applied = _rewrite_text(
            selected.read_bytes().decode("utf-8"),
            [change for change in changes if change["source"] == selected.name],
        )
        with open(out_dir / selected.name, "w", encoding="utf-8", newline="") as handle:
            handle.write(rewritten)
        applied.extend(file_applied)
    missing_application = [
        change for change in changes if change not in applied
    ]
    return {
        "schema": "vstd-reason-binding-rewrite/0.1",
        "root": str(root),
        "resolved": sum(change["resolved"] for change in changes),
        "stale": sum(not change["resolved"] for change in changes),
        "missing_application": missing_application,
        "changes": changes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    compile_parser = commands.add_parser("compile")
    compile_parser.add_argument("--root", required=True)
    compile_parser.add_argument("--out", required=True)
    compile_parser.add_argument("reasons", nargs="+")
    rewrite_parser = commands.add_parser("rewrite")
    rewrite_parser.add_argument("--root", required=True)
    rewrite_parser.add_argument("--registry", required=True)
    rewrite_parser.add_argument("--out-dir", required=True)
    rewrite_parser.add_argument("reasons", nargs="+")
    args = parser.parse_args()
    root = Path(args.root).resolve(strict=True)
    if args.command == "compile":
        report = compile_registry(root, args.reasons)
        with open(args.out, "w", encoding="utf-8", newline="") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(json.dumps({
            "entries": len(report["entries"]),
            "references": len(report["references"]),
            "problems": report["problems"],
            "bytes": Path(args.out).stat().st_size,
        }, sort_keys=True))
        return 0 if not report["problems"] else 1
    registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
    report = rewrite(root, registry, args.reasons, Path(args.out_dir))
    report_path = Path(args.out_dir) / "binding_rewrite_report.json"
    with open(report_path, "w", encoding="utf-8", newline="") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({
        "resolved": report["resolved"],
        "stale": report["stale"],
        "missing_application": len(report["missing_application"]),
        "report": str(report_path),
    }, sort_keys=True))
    return 0 if not report["missing_application"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
