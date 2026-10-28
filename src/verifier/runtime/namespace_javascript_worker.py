"""Isolated, optional JavaScript syntax census for Verifier Standard (VSTD).

An abstract syntax tree (AST); JavaScript Object Notation (JSON). Only installed
parser libraries execute. Subject bytes are parsed, never imported or evaluated.
This is a static declaration census, not runtime reachability or effect proof.
"""
from __future__ import annotations

import base64
import hashlib
from importlib import metadata
import json
from pathlib import Path
import re
import sys
from typing import Any


PROTOCOL = "verifier-javascript-discovery-1"
LIMIT = 16 * 1024 * 1024
VERSIONS = {"tree-sitter": "0.25.2", "tree-sitter-javascript": "0.25.0"}
DEFINITIONS = frozenset({"function_declaration", "generator_function_declaration", "function_expression",
    "generator_function", "arrow_function", "class_declaration", "class", "method_definition",
    "field_definition", "variable_declarator", "pair"})


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism() -> dict[str, Any]:
    """Pin actual parser/runtime bytes, not merely dependency version labels."""
    result = {}
    for name, expected in VERSIONS.items():
        distribution = metadata.distribution(name)
        if distribution.version != expected:
            raise ValueError("NAMESPACE_JAVASCRIPT_PARSER_VERSION_UNSUPPORTED")
        files = {}
        for entry in distribution.files or ():
            if entry.suffix in {".py", ".pyd", ".so", ".dll"} or entry.name == "METADATA":
                if ".." in entry.parts or entry.is_absolute():
                    raise ValueError("NAMESPACE_JAVASCRIPT_PARSER_LAYOUT_UNSUPPORTED")
                files[str(entry).replace("\\", "/")] = digest(Path(distribution.locate_file(entry)).read_bytes())
        if not files:
            raise ValueError("NAMESPACE_JAVASCRIPT_PARSER_BYTES_UNAVAILABLE")
        result[name] = {"version": expected, "files": files}
    return result


def parse(path: str, raw: bytes, parser: Any) -> dict[str, Any]:
    tree = parser.parse(raw)
    gaps: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []

    def gap(code: str, reason: str) -> None:
        if not any(row["code"] == code for row in gaps):
            gaps.append({"path": path, "code": code, "reason": reason})

    def text(node: Any) -> str:
        return raw[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    if tree.root_node.has_error:
        gap("NAMESPACE_JAVASCRIPT_PARSE_UNAVAILABLE", "The parser reports an error or missing syntax node; partial syntax is not coverage.")
        return {"path": path, "source_digest": digest(raw), "surfaces": [], "gaps": gaps}

    nodes, pending = [], [tree.root_node]
    while pending:
        node = pending.pop()
        nodes.append(node)
        if len(nodes) > 250_000:
            raise ValueError("NAMESPACE_JAVASCRIPT_NODE_CAPACITY")
        pending.extend(reversed(node.named_children))

    # Only a module-level immutable literal declaration defines source roles.
    # Any other reference/write remains unresolved; a role is never erased by it.
    kinds, marker_nodes = set(), set()
    unresolved_marker = False
    for node in nodes:
        if node.type != "variable_declarator" or text(node.child_by_field_name("name")) != "__vstd_kinds__":
            continue
        parent = node.parent
        container = parent.parent
        if container.type == "export_statement":
            container = container.parent
        value = node.child_by_field_name("value")
        valid = (parent.type == "lexical_declaration" and text(parent).startswith("const ")
                 and container.type == "program" and value is not None and value.type == "array")
        items = value.named_children if valid else []
        names = [text(item)[1:-1] for item in items if item.type == "string"]
        valid = valid and len(names) == len(items) and bool(names) and all(re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", name) for name in names)
        # Named-child iteration omits commas: without this grammar check,
        # sparse arrays such as ["BOT",,] would masquerade as literal lists.
        valid = valid and all(child.type == ("string" if index % 2 == 0 else ",")
                              for index, child in enumerate(value.children[1:-1]))
        if valid:
            kinds.update(names)
            marker_nodes.add(node.child_by_field_name("name").id)
        else:
            unresolved_marker = True
    if len(marker_nodes) > 1 or any(node.type in {"identifier", "property_identifier", "shorthand_property_identifier"}
            and text(node) == "__vstd_kinds__" and node.id not in marker_nodes for node in nodes):
        unresolved_marker = True

    def record(node: Any, form: str, name: str, scope: str) -> None:
        identifier = "javascript-export:" + path + ":" + name if form == "Export" else "javascript:" + path + ":" + scope
        rows.append({"surface_id": identifier, "path": path, "line": node.start_point.row + 1,
            "form": "JavaScriptExport" if form == "Export" else form,
            "source_kinds": sorted(kinds), "hints": [], "unresolved_marker": unresolved_marker})

    def assignment_root(node: Any) -> str:
        """Return the literal root of a property write, when syntax fixes it.

        A property mutation is itself an exposed source surface and therefore
        must not disappear behind one file-level row.  It is not, however,
        automatically a module export.  Global/CommonJS roots keep the
        stronger unresolved-export treatment because their runtime namespace
        can escape this source file.
        """
        current = node
        while current is not None and current.type in {"member_expression", "subscript_expression"}:
            current = current.child_by_field_name("object")
        return text(current) if current is not None and current.type == "identifier" else ""

    record(tree.root_node, "Module", "", "<module>")
    # Suggestions are lexical only. The module row retains these signals even
    # when a named member is assigned to another object by a manifest author.
    words = {word.lower() for node in nodes if node.type in {"identifier", "property_identifier"}
             for word in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", text(node))}
    candidates = ("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
                  "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT")
    rows[0]["hints"] = sorted(kind for kind in candidates if kind.lower() in words)
    scopes = {}
    local_names = set()
    for node in nodes:
        if node.type not in {"variable_declarator", "function_declaration", "generator_function_declaration", "class_declaration"}:
            continue
        parent = node.parent
        if node.type == "variable_declarator":
            parent = parent.parent
        if parent.type == "export_statement":
            parent = parent.parent
        name = node.child_by_field_name("name")
        if parent.type == "program" and name is not None and name.type == "identifier":
            local_names.add(text(name))
    for node in nodes:
        parent = node.parent
        scope = scopes.get(parent.id, "") if parent is not None else ""
        if node.type in DEFINITIONS:
            name_node = node.child_by_field_name("name") or node.child_by_field_name("key")
            name = text(name_node)
            if name_node is None or name_node.type not in {"identifier", "property_identifier", "private_property_identifier", "string", "number"}:
                name = "<" + node.type + "@" + str(node.start_point.row + 1) + ":" + str(node.start_point.column + 1) + ">"
            scope = (scope + "." if scope else "") + name
            record(node, node.type, name, scope)
        scopes[node.id] = scope
        if node.type == "export_statement":
            if any(child.type == "default" for child in node.children):
                record(node, "Export", "default", "")
            else:
                declaration = node.child_by_field_name("declaration")
                if declaration is not None:
                    declared = [declaration] if declaration.type in {"class_declaration", "function_declaration", "generator_function_declaration"} else declaration.named_children
                    for child in declared:
                        name = child.child_by_field_name("name")
                        if name is not None and name.type == "identifier":
                            record(node, "Export", text(name), "")
                        else:
                            gap("NAMESPACE_JAVASCRIPT_EXPORTS_UNRESOLVED", "Destructured or unsupported export binding needs a target-binding adapter.")
                for clause in node.named_children:
                    if clause.type == "export_clause":
                        for child in clause.named_children:
                            name = child.child_by_field_name("alias") or child.child_by_field_name("name")
                            if name is not None:
                                record(child, "Export", text(name), "")
                            if text(child.child_by_field_name("name")) not in local_names:
                                gap("NAMESPACE_JAVASCRIPT_EXPORTS_UNRESOLVED", "An export alias has no local declaration; imported or absent targets need binding evidence.")
                if node.child_by_field_name("source") is not None or any(child.type == "*" for child in node.children):
                    gap("NAMESPACE_JAVASCRIPT_EXPORTS_UNRESOLVED", "Cross-module and wildcard export targets are not resolved by this syntax census.")
        if node.type in {"computed_property_name", "with_statement", "decorator", "jsx_element", "jsx_self_closing_element"}:
            gap("NAMESPACE_JAVASCRIPT_DYNAMIC_SURFACES_UNRESOLVED", "Computed properties, decorators or dynamic scope require additional interface evidence.")
        if node.type in {"call_expression", "new_expression"}:
            target = text(node.child_by_field_name("function") or node.child_by_field_name("constructor"))
            if target in {"eval", "Function", "Proxy", "import", "require", "Object.defineProperty", "Object.defineProperties", "Object.assign", "Reflect.set", "Reflect.defineProperty"}:
                gap("NAMESPACE_JAVASCRIPT_DYNAMIC_SURFACES_UNRESOLVED", "Reflective construction or runtime loading may expose additional interfaces.")
        if node.type in {"identifier", "property_identifier"} and text(node) in {"eval", "Function", "Proxy", "Reflect", "require", "defineProperty", "defineProperties"}:
            gap("NAMESPACE_JAVASCRIPT_DYNAMIC_SURFACES_UNRESOLVED", "Reflective names, including aliases, need additional interface evidence.")
        if node.type in {"assignment_expression", "augmented_assignment_expression"}:
            left = node.child_by_field_name("left")
            if left is not None and left.type in {"member_expression", "subscript_expression"}:
                root = assignment_root(left)
                if root in {"exports", "module", "globalThis", "window", "self"}:
                    gap("NAMESPACE_JAVASCRIPT_DYNAMIC_SURFACES_UNRESOLVED", "A global or CommonJS property assignment may publish or replace interfaces outside this module census.")
                else:
                    # The identity is the exact bounded mutation site, not a
                    # claim about which runtime object or key it reaches.
                    record(node, "JavaScriptPropertyWrite", text(left),
                           scope + ".<property-write@" + str(node.start_byte) + ">")

    seen = set()
    for row in rows:
        if row["surface_id"] in seen:
            row["surface_id"] += "@" + str(row["line"]) + ":" + str(len(seen))
        seen.add(row["surface_id"])
    return {"path": path, "source_digest": digest(raw), "surfaces": rows, "gaps": gaps}


def main() -> None:
    request = json.loads(sys.stdin.buffer.read(LIMIT + 1))
    if request["schema_version"] != PROTOCOL:
        raise ValueError("NAMESPACE_JAVASCRIPT_PROTOCOL_DIFFERS")
    opening = mechanism()
    from tree_sitter import Language, Parser
    import tree_sitter_javascript
    parser = Parser(Language(tree_sitter_javascript.language()))
    files = [parse(row["path"], base64.b64decode(row["source"], validate=True), parser) for row in request["files"]]
    if mechanism() != opening:
        raise ValueError("NAMESPACE_JAVASCRIPT_PARSER_CHANGED")
    result = {"schema_version": PROTOCOL, "mechanism": opening, "files": files}
    encoded = json.dumps(result, ensure_ascii=True).encode("ascii")
    if len(encoded) > LIMIT:
        raise ValueError("NAMESPACE_JAVASCRIPT_OUTPUT_CAPACITY")
    sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    try:
        main()
    except (ImportError, metadata.PackageNotFoundError, OSError, ValueError, MemoryError, RecursionError) as exc:
        # No parser tracebacks or host paths become public report content.
        code = str(exc) if str(exc).startswith("NAMESPACE_JAVASCRIPT_") else "NAMESPACE_JAVASCRIPT_PARSER_UNAVAILABLE"
        print(json.dumps({"schema_version": PROTOCOL, "unavailable": type(exc).__name__, "code": code}))
        raise SystemExit(2)
