"""Conservative Python conditional dispatch for Verifier Standard (VSTD) Tier zero.

Python's abstract syntax tree (AST) supplies the read-only call-site inventory.
This module does not label a call pure merely because its visible callee is in
the Python standard library.  It records the hidden Python dispatch of
``dataclasses.replace`` and ``copy.replace`` and the registry dependence of
codec lookup.  A syntactically closed row remains conditional on the reported
facts; it is not a general purity proof.
"""

from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any


SCHEMA = "verifier-tier-zero-conditional-dispatch-1"
_BUILTIN_ERRORS = frozenset({
    "strict", "ignore", "replace", "xmlcharrefreplace", "backslashreplace",
    "namereplace", "surrogateescape", "surrogatepass",
})
_KNOWN_CODECS = frozenset({
    "ascii", "latin-1", "latin1", "utf-8", "utf8", "utf-16", "utf16",
    "utf-32", "utf32",
})


def _git_python_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode == 0:
        names = completed.stdout.decode("utf-8", errors="surrogateescape").split("\0")
        return [root / name for name in names if name.endswith((".py", ".pyi"))]
    return [path for path in root.rglob("*.py") if not any(
        part in {".git", ".venv", "__pycache__", "build", "dist"}
        for part in path.parts
    )]


def _aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = node.module + "." + item.name
    return aliases


def _dotted(node: ast.AST, aliases: dict[str, str]) -> str | None:
    parts: list[str] = []
    selected = node
    while isinstance(selected, ast.Attribute):
        parts.append(selected.attr)
        selected = selected.value
    if not isinstance(selected, ast.Name):
        return None
    parts.append(selected.id)
    parts.reverse()
    if parts[0] in aliases:
        parts[:1] = aliases[parts[0]].split(".")
    return ".".join(parts)


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _codec_arguments(node: ast.Call, target: str) -> tuple[ast.AST | None, ast.AST | None] | None:
    by_keyword = {item.arg: item.value for item in node.keywords if item.arg is not None}
    tail = target.rpartition(".")[2]
    if tail in {"encode", "decode", "lookup"}:
        encoding = by_keyword.get("encoding")
        if encoding is None:
            if target.startswith("codecs."):
                encoding = node.args[0] if node.args else None
            elif tail in {"encode", "decode"}:
                encoding = node.args[0] if node.args else ast.Constant(value="utf-8")
        errors = by_keyword.get("errors")
        if errors is None:
            position = 1 if target.startswith("codecs.") else 1
            errors = node.args[position] if len(node.args) > position else ast.Constant(value="strict")
        return encoding, errors
    if target in {"builtins.open", "io.open", "open"}:
        encoding = by_keyword.get("encoding")
        if encoding is None and len(node.args) > 3:
            encoding = node.args[3]
        if encoding is None:
            return None
        errors = by_keyword.get("errors")
        if errors is None and len(node.args) > 4:
            errors = node.args[4]
        return encoding, errors or ast.Constant(value="strict")
    if target == "io.TextIOWrapper":
        encoding = by_keyword.get("encoding") or (node.args[1] if len(node.args) > 1 else None)
        if encoding is None:
            return None
        errors = by_keyword.get("errors") or (node.args[2] if len(node.args) > 2 else ast.Constant(value="strict"))
        return encoding, errors
    if target in {"str", "builtins.str"} and len(node.args) > 1:
        return node.args[1], node.args[2] if len(node.args) > 2 else ast.Constant(value="strict")
    return None


def _registry_mutation(node: ast.AST, target: str | None) -> str | None:
    if target in {"codecs.register", "codecs.unregister", "codecs.register_error"}:
        return target
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
        targets: list[ast.AST]
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.Delete):
            targets = list(node.targets)
        else:
            targets = [node.target]
        for selected in targets:
            text = ast.unparse(selected)
            if text.startswith(("encodings.aliases.aliases", "encodings._cache", "sys.modules")):
                return text
    return None


def scan(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    files = _git_python_files(root)
    parsed: list[tuple[Path, ast.AST, dict[str, str]]] = []
    before: dict[str, str] = {}
    errors: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        before[relative] = sha256(raw).hexdigest()
        try:
            tree = ast.parse(raw, filename=relative)
        except (SyntaxError, ValueError) as exc:
            errors.append({"path": relative, "error": type(exc).__name__})
            continue
        aliases = _aliases(tree)
        parsed.append((path, tree, aliases))
        for node in ast.walk(tree):
            target = _dotted(node.func, aliases) if isinstance(node, ast.Call) else None
            mutation = _registry_mutation(node, target)
            if mutation:
                mutations.append({"path": relative, "line": getattr(node, "lineno", 0), "operation": mutation})

    rows: list[dict[str, Any]] = []
    for path, tree, aliases in parsed:
        relative = path.relative_to(root).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = _dotted(node.func, aliases)
            if target in {"dataclasses.replace", "copy.replace"}:
                hooks = (
                    ["__getattribute__", "descriptor.__get__", "metaclass.__call__", "__new__", "__init__", "__post_init__"]
                    if target == "dataclasses.replace" else ["__replace__"]
                )
                rows.append({
                    "path": relative, "line": node.lineno, "target": target,
                    "status": "CONDITIONAL", "hidden_dispatch": hooks,
                    "condition": "the exact runtime class and every named hook are effect-closed",
                })
                continue
            codec = _codec_arguments(node, target or "")
            if codec is None and isinstance(node.func, ast.Attribute) and node.func.attr in {"encode", "decode"}:
                codec = _codec_arguments(node, node.func.attr)
                target = "<receiver>." + node.func.attr
            if codec is None:
                continue
            encoding_node, errors_node = codec
            encoding = _literal_string(encoding_node)
            errors_name = _literal_string(errors_node)
            closed = (
                encoding is not None and encoding.lower().replace("_", "-") in _KNOWN_CODECS
                and errors_name in _BUILTIN_ERRORS and not mutations
            )
            rows.append({
                "path": relative, "line": node.lineno, "target": target,
                "status": "CONDITIONALLY_CLOSED" if closed else "UNKNOWN",
                "encoding": encoding, "errors": errors_name,
                "registry_mutation_count": len(mutations),
                "condition": (
                    "literal bundled codec, built-in error policy, and no codec or encoding-registry mutation"
                ),
                "next_action": None if closed else (
                    "bind the codec and error handler and rule out registry, alias, cache, and module mutation"
                ),
            })
    changed = [
        relative for relative, digest in before.items()
        if sha256((root / relative).read_bytes()).hexdigest() != digest
    ]
    return {
        "schema_version": SCHEMA,
        "root": str(root),
        "python_files": len(before),
        "parse_errors": errors,
        "registry_mutations": mutations,
        "calls": rows,
        "counts": {
            "CONDITIONAL": sum(row["status"] == "CONDITIONAL" for row in rows),
            "CONDITIONALLY_CLOSED": sum(row["status"] == "CONDITIONALLY_CLOSED" for row in rows),
            "UNKNOWN": sum(row["status"] == "UNKNOWN" for row in rows),
        },
        "source_files_changed_during_scan": changed,
        "claim_boundary": (
            "A conditionally closed row proves only the stated syntactic preconditions at this source coordinate; "
            "it does not prove runtime class identity, registry immutability outside the selected tree, or package polish."
        ),
    }


def write_report(root: Path, output: Path) -> dict[str, Any]:
    report = scan(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return report


__all__ = ["SCHEMA", "scan", "write_report"]
