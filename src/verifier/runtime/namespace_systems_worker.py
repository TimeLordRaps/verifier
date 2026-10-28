"""Optional Rust/Bash syntax census for Verifier Standard (VSTD).

The abstract syntax tree (AST) uses JavaScript Object Notation (JSON). This fixed worker
parses bytes only. It never invokes Cargo, expands macros, sources a shell file
or evaluates commands. Parser code is trusted optional tooling, not a sandbox.
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


PROTOCOL = "verifier-systems-discovery-1"
LIMIT = 16 * 1024 * 1024
GRAMMARS = {"rust": ("tree-sitter-rust", "0.24.2"), "bash": ("tree-sitter-bash", "0.25.1")}
RUST_DECLARATION_NEUTRAL_MACROS = frozenset({"assert", "debug_assert", "eprintln", "println", "vec"})
# These are the compiler-provided derives documented by the Rust standard
# library. A bare name is still treated as unresolved when source in the same
# census could shadow the macro namespace; third-party derives are procedural
# code and never inherit this closed treatment.
RUST_BUILTIN_DERIVES = frozenset({
    "Clone", "Copy", "Debug", "Default", "Eq", "Hash", "Ord", "PartialEq", "PartialOrd",
})
RUST_CLOSED_MACRO_NAMES = RUST_DECLARATION_NEUTRAL_MACROS | RUST_BUILTIN_DERIVES
RUST_DEFINITIONS = frozenset({"function_item", "function_signature_item", "struct_item", "enum_item",
    "enum_variant", "union_item", "trait_item", "impl_item", "mod_item", "type_item", "associated_type",
    "const_item", "static_item", "field_declaration", "macro_definition", "closure_expression",
    "foreign_mod_item", "use_declaration", "extern_crate_declaration", "ordered_field_declaration_list"})
BASH_DEFINITIONS = frozenset({"function_definition", "variable_assignment", "command", "declaration_command",
    "file_redirect", "heredoc_redirect", "herestring_redirect", "process_substitution", "command_substitution"})


def rust_shadowed_macro_names(files: list[tuple[str, bytes]], parser: Any) -> frozenset[str]:
    """Return built-in-looking names whose Rust macro resolution is not closed.

    Rust resolves unqualified macros through textual, path-based, macro-use and
    prelude scopes. We therefore inspect the complete selected Rust source set,
    not just the invocation's file. A wildcard import, macro-use attribute,
    disabled implicit prelude, same-name macro definition or same-name import
    is conservatively enough to withhold built-in semantics. False positives
    retain UNKNOWN; they cannot turn custom expansion into coverage.
    """
    shadowed: set[str] = set()
    for _, raw in files:
        tree = parser.parse(raw)
        if tree.root_node.has_error:
            return frozenset(RUST_CLOSED_MACRO_NAMES)
        pending = [tree.root_node]
        while pending:
            node = pending.pop()
            pending.extend(reversed(node.named_children))
            source = raw[node.start_byte:node.end_byte].decode("utf-8", errors="strict")
            if node.type in {"attribute_item", "inner_attribute_item"} and re.match(
                    r"#\s*!?\s*\[\s*(?:macro_use|no_implicit_prelude)\b", source):
                shadowed.update(RUST_CLOSED_MACRO_NAMES)
            elif node.type == "macro_definition":
                name = node.child_by_field_name("name")
                candidate = raw[name.start_byte:name.end_byte].decode("utf-8") if name is not None else ""
                if candidate in RUST_CLOSED_MACRO_NAMES:
                    shadowed.add(candidate)
            elif node.type == "use_declaration":
                # Within a use declaration `*` is a glob token, never an
                # arithmetic operator, including inside nested use groups.
                if "*" in source:
                    shadowed.update(RUST_CLOSED_MACRO_NAMES)
                else:
                    shadowed.update(name for name in RUST_CLOSED_MACRO_NAMES
                        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", source))
    return frozenset(shadowed)


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism(languages: list[str]) -> dict[str, Any]:
    distributions = {}
    for name, expected in [("tree-sitter", "0.25.2"), *(GRAMMARS[language] for language in languages)]:
        distribution = metadata.distribution(name)
        if distribution.version != expected:
            raise ValueError("NAMESPACE_SYSTEMS_PARSER_VERSION_UNSUPPORTED")
        files = {}
        for entry in distribution.files or ():
            if entry.suffix in {".py", ".pyd", ".so", ".dll"} or entry.name == "METADATA":
                if ".." in entry.parts or entry.is_absolute():
                    raise ValueError("NAMESPACE_SYSTEMS_PARSER_LAYOUT_UNSUPPORTED")
                files[str(entry).replace("\\", "/")] = digest(Path(distribution.locate_file(entry)).read_bytes())
        if not files:
            raise ValueError("NAMESPACE_SYSTEMS_PARSER_BYTES_UNAVAILABLE")
        distributions[name] = {"version": expected, "files": files}
    return {"languages": languages, "distributions": distributions}


def parse(path: str, raw: bytes, language: str, parser: Any,
        rust_shadowed: frozenset[str] = frozenset()) -> dict[str, Any]:
    raw.decode("utf-8", errors="strict")
    tree = parser.parse(raw)
    surfaces: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []

    def gap(code: str, reason: str) -> None:
        if not any(row["code"] == code for row in gaps):
            gaps.append({"path": path, "code": code, "reason": reason})

    def text(node: Any) -> str:
        return raw[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    def result() -> dict[str, Any]:
        return {"path": path, "source_digest": digest(raw), "surfaces": surfaces, "gaps": gaps}

    if tree.root_node.has_error:
        gap("NAMESPACE_SYSTEMS_PARSE_UNAVAILABLE", "The parser reports erroneous or missing syntax; a partial tree cannot establish coverage.")
        return result()
    if language == "bash" and raw.startswith(b"#!"):
        first = raw.splitlines()[0].decode("utf-8")
        if re.fullmatch(r"#!\s*(?:/usr/bin/env\s+|/(?:usr/)?bin/)(?:bash|sh)\s*", first) is None:
            gap("NAMESPACE_SHELL_DIALECT_UNRESOLVED", "The shebang does not select the supported Bash/sh syntax; parser success is not interpreter equivalence.")
    nodes, pending = [], [tree.root_node]
    while pending:
        node = pending.pop()
        nodes.append(node)
        if len(nodes) > 250000:
            raise ValueError("NAMESPACE_SYSTEMS_NODE_CAPACITY")
        pending.extend(reversed(node.named_children))

    # Source role declarations accumulate; ambiguity never erases a known role.
    # Only an immutable top-level Rust constant has the closed marker grammar.
    # Bash assignments remain mutable, even when their literal roles are known.
    kinds: set[str] = set()
    inspected: set[int] = set()
    unresolved = False
    for node in nodes:
        if node.type not in {"const_item", "static_item", "variable_assignment"}:
            continue
        name = node.child_by_field_name("name")
        if text(name).removeprefix("r#") != "__vstd_kinds__":
            continue
        inspected.add(name.id)
        value = node.child_by_field_name("value")
        if value is not None and value.type == "reference_expression":
            value = value.child_by_field_name("value")
        literal = value is not None and value.type in {"array_expression", "array"}
        members = []
        for child in value.named_children if literal else []:
            candidate = text(child)
            if child.type in {"string_literal", "raw_string", "string"} and re.fullmatch(r'["\'][A-Z][A-Z0-9]{0,63}["\']', candidate):
                candidate = candidate[1:-1]
            if re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", candidate) and child.type in {"string_literal", "raw_string", "string", "word"}:
                members.append(candidate)
            else:
                literal = False
        kinds.update(members)
        if (not literal or not members or node.type != "const_item" or node.parent != tree.root_node
                or value is None or any(child.type == "identifier" for child in value.named_children)):
            unresolved = True
    if len(inspected) > 1 or any(node.type in {"identifier", "variable_name", "field_identifier"}
            and text(node).removeprefix("r#") == "__vstd_kinds__" and node.id not in inspected for node in nodes):
        unresolved = True

    scopes: dict[int, str] = {}
    seen: set[str] = set()

    def record(node: Any, form: str, name: str, scope: str) -> None:
        identifier = language + ":" + path + ":" + scope
        if identifier in seen:
            identifier += "@" + str(node.start_byte)
        seen.add(identifier)
        words = {word.lower() for word in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", name)}
        hints = sorted(kind for kind in ("LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
            "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT") if kind.lower() in words)
        surfaces.append({"surface_id": identifier, "path": path, "line": node.start_point.row + 1,
            "form": form, "source_kinds": sorted(kinds), "hints": hints, "unresolved_marker": unresolved})

    record(tree.root_node, "Module", "", "<module>")
    definitions = RUST_DEFINITIONS if language == "rust" else BASH_DEFINITIONS
    for node in nodes:
        parent = node.parent
        scope = scopes.get(parent.id, "") if parent is not None else ""
        tuple_field = language == "rust" and parent is not None and parent.type == "ordered_field_declaration_list" and node.type not in {"visibility_modifier", "attribute_item"}
        if node.type in definitions or tuple_field:
            name_node = node.child_by_field_name("name")
            if node.type == "impl_item":
                name = "impl " + text(node.child_by_field_name("trait")) + " for " + text(node.child_by_field_name("type"))
            else:
                name = text(name_node)
            if not name or len(name) > 256:
                name = "<" + node.type + "@" + str(node.start_byte) + ">"
            scope = (scope + "." if scope else "") + name
            record(node, "TupleField" if tuple_field else node.type, name, scope)
        scopes[node.id] = scope
        if language == "rust":
            if node.type == "macro_invocation":
                macro = text(node.child_by_field_name("macro"))
                if macro in RUST_DECLARATION_NEUTRAL_MACROS and macro not in rust_shadowed:
                    # These compiler/prelude macros are expressions or checks;
                    # inventory the invocation without pretending it generates
                    # a declaration. Potentially shadowed names never enter
                    # this branch.
                    record(node, "RustBuiltinMacroInvocation", macro,
                        scope + ".<builtin-macro:" + macro + "@" + str(node.start_byte) + ">")
                else:
                    record(node, node.type, macro, scope + ".<expansion@" + str(node.start_byte) + ">")
                    gap("NAMESPACE_RUST_EXPANSION_UNRESOLVED", "Macro expansion can generate additional interfaces; the selected source does not bind this invocation to a declaration-neutral built-in.")
            elif node.type == "attribute_item":
                source = text(node)
                match = re.fullmatch(
                    r"#\s*\[\s*derive\s*\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s*,?)\s*\)\s*\]",
                    source,
                )
                traits = [part.strip() for part in match.group(1).rstrip(",").split(",")] if match else []
                target = node.next_named_sibling
                while target is not None and target.type in {"line_comment", "block_comment"}:
                    target = target.next_named_sibling
                target_name_node = target.child_by_field_name("name") if target is not None else None
                target_name = text(target_name_node)
                closed_target = (target is not None and target.type in {"struct_item", "enum_item", "union_item"}
                    and bool(target_name) and len(traits) == len(set(traits)))
                for trait in traits if closed_target else []:
                    if trait in RUST_BUILTIN_DERIVES and trait not in rust_shadowed:
                        target_scope = (scope + "." if scope else "") + target_name
                        record(node, "RustDerive", trait + " for " + target_name,
                            target_scope + ".<derive:" + trait + "@" + str(node.start_byte) + ">")
                unresolved_traits = (not closed_target or not traits or any(
                    trait not in RUST_BUILTIN_DERIVES or trait in rust_shadowed for trait in traits))
                if unresolved_traits:
                    record(node, node.type, "derive", scope + ".<expansion@" + str(node.start_byte) + ">")
                    gap("NAMESPACE_RUST_EXPANSION_UNRESOLVED", "A custom, shadowable, malformed or non-data-item derive can generate interfaces that source parsing alone does not bind.")
            elif node.type in {"macro_definition", "inner_attribute_item"}:
                record(node, node.type, text(node.child_by_field_name("macro")), scope + ".<expansion@" + str(node.start_byte) + ">")
                gap("NAMESPACE_RUST_EXPANSION_UNRESOLVED", "Macro definitions and inner attributes can generate or conditionally expose additional interfaces; source parsing is not expansion evidence.")
            if node.type == "mod_item" and node.child_by_field_name("body") is None:
                gap("NAMESPACE_RUST_MODULE_UNRESOLVED", "An out-of-line module needs exact source/feature binding; this file's declarations cannot cover its contents.")
            if node.type == "use_declaration" and any(child.type == "visibility_modifier" for child in node.named_children):
                # Retain every alias/leaf of a grouped re-export, not just the
                # enclosing use statement. Target resolution remains a gap.
                members = [node.child_by_field_name("argument")]
                while members:
                    member = members.pop()
                    if member is None:
                        continue
                    if member.type == "scoped_use_list":
                        # The path is a qualifier, not a separately exported
                        # name. Only the nested list contributes export leaves.
                        members.append(member.child_by_field_name("list"))
                        continue
                    if member.type in {"identifier", "self", "scoped_identifier", "use_as_clause", "use_wildcard"}:
                        alias = member.child_by_field_name("alias") or member.child_by_field_name("name")
                        label = text(alias) or text(member)
                        record(member, "RustExport", label, scope + ".<export:" + label + "@" + str(member.start_byte) + ">")
                    else:
                        members.extend(reversed(member.named_children))
                gap("NAMESPACE_RUST_EXPORTS_UNRESOLVED", "Re-export names are inventoried, but local/imported target and feature resolution still need evidence.")
        elif node.type == "command":
            name = node.child_by_field_name("name")
            command = text(name)
            # Quotes, expansion, aliases and eval/source cannot certify a closed
            # interface set. Never execute them in order to discover it.
            if (name is None or not re.fullmatch(r"[A-Za-z0-9_./:+-]+", command)
                    or command in {"eval", "source", ".", "alias", "unalias", "builtin", "command", "exec", "bash", "sh", "dash", "zsh", "ksh"}):
                gap("NAMESPACE_SHELL_DYNAMIC_SURFACES_UNRESOLVED", "Dynamic command selection, source/eval or alias dispatch may introduce interfaces outside this syntax census.")
        elif node.type == "declaration_command" and any(child.type in {"string", "concatenation", "expansion", "simple_expansion", "command_substitution"}
                for child in node.named_children):
            gap("NAMESPACE_SHELL_DYNAMIC_SURFACES_UNRESOLVED", "A computed exported/declaration name needs binding evidence; it is not a closed literal variable interface.")
    return result()


def main() -> None:
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("NAMESPACE_SYSTEMS_INPUT_CAPACITY")
    request = json.loads(raw)
    if (type(request) is not dict or set(request) != {"schema_version", "languages", "files"}
            or request["schema_version"] != PROTOCOL or type(request["languages"]) is not list
            or not request["languages"] or any(type(name) is not str or name not in GRAMMARS for name in request["languages"])
            or request["languages"] != sorted(set(request["languages"])) or type(request["files"]) is not list):
        raise ValueError("NAMESPACE_SYSTEMS_PROTOCOL_DIFFERS")
    languages = request["languages"]
    opening = mechanism(languages)
    from tree_sitter import Language, Parser
    parsers = {}
    if "rust" in languages:
        import tree_sitter_rust
        parsers["rust"] = Parser(Language(tree_sitter_rust.language()))
    if "bash" in languages:
        import tree_sitter_bash
        parsers["bash"] = Parser(Language(tree_sitter_bash.language()))
    selected = []
    for row in request["files"]:
        if (type(row) is not dict or set(row) != {"path", "source", "language"}
                or type(row["path"]) is not str or row["language"] not in parsers):
            raise ValueError("NAMESPACE_SYSTEMS_PROTOCOL_DIFFERS")
        selected.append((row["path"], base64.b64decode(row["source"], validate=True), row["language"]))
    rust_files = [(path, source) for path, source, language in selected if language == "rust"]
    rust_shadowed = rust_shadowed_macro_names(rust_files, parsers["rust"]) if rust_files else frozenset()
    files = [parse(path, source, language, parsers[language], rust_shadowed)
        for path, source, language in selected]
    if mechanism(languages) != opening:
        raise ValueError("NAMESPACE_SYSTEMS_PARSER_CHANGED")
    encoded = json.dumps({"schema_version": PROTOCOL, "mechanism": opening, "files": files}, ensure_ascii=True).encode("ascii")
    if len(encoded) > LIMIT:
        raise ValueError("NAMESPACE_SYSTEMS_OUTPUT_CAPACITY")
    sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    try:
        main()
    except (ImportError, metadata.PackageNotFoundError, OSError, ValueError, TypeError, KeyError, MemoryError, RecursionError) as exc:
        code = str(exc) if str(exc).startswith("NAMESPACE_SYSTEMS_") else "NAMESPACE_SYSTEMS_PARSER_UNAVAILABLE"
        print(json.dumps({"schema_version": PROTOCOL, "code": code}))
        raise SystemExit(2)
