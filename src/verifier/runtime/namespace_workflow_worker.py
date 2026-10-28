"""Isolated executable-document census for Verifier Standard (VSTD).

YAML Ain't Markup Language (YAML); abstract syntax tree (AST). The worker
composes YAML with ``BaseLoader`` and, when the pinned optional Bash grammar is
present, parses literal workflow commands. It never constructs subject Python
objects, evaluates an expression, downloads an action, or executes a command.
"""
from __future__ import annotations

import ast
import base64
from collections import deque
import hashlib
from importlib import metadata
import json
from pathlib import Path
import posixpath
import re
import shlex
import sys
from typing import Any


PROTOCOL = "verifier-workflow-discovery-1"
LIMIT = 16 * 1024 * 1024
VERSIONS = {"PyYAML": "6.0.3", "tree-sitter": "0.25.2", "tree-sitter-bash": "0.25.1"}
EXPRESSION_CONTEXTS = frozenset({
    "env", "github", "inputs", "job", "matrix", "needs", "runner", "secrets",
    "steps", "strategy", "vars",
})
EXPRESSION_FUNCTIONS = frozenset({
    "always", "cancelled", "contains", "endsWith", "failure", "format",
    "fromJSON", "hashFiles", "join", "startsWith", "success", "toJSON",
})
SHELL_DISPATCHERS = frozenset({
    ".", "alias", "bash", "builtin", "command", "dash", "eval", "exec", "ksh",
    "sh", "source", "unalias", "zsh",
})
REMOTE_COMMIT_REFERENCE = re.compile(
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"(?P<subpath>/[A-Za-z0-9_./-]+)?@(?P<revision>[0-9a-f]{40})\Z"
)
_PATH_BOUNDARY_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./+@-"
)


class _ExactPathIndex:
    """Find every selected path in one source scan without executing it.

    The automaton indexes both accepted lexical spellings once per worker
    request. Its boundary check deliberately stays ASCII-identical to the
    replaced regular-expression lookaround: Unicode neighbors are boundaries.
    """

    def __init__(self, selected: dict[str, str]) -> None:
        self._rows = sorted(selected.items())
        self._transitions: list[dict[str, int]] = [{}]
        self._failures = [0]
        self._terminals: list[list[tuple[int, int]]] = [[]]
        for row_index, (target, _) in enumerate(self._rows):
            for pattern in (target, "./" + target):
                state = 0
                for character in pattern:
                    next_state = self._transitions[state].get(character)
                    if next_state is None:
                        next_state = len(self._transitions)
                        self._transitions[state][character] = next_state
                        self._transitions.append({})
                        self._failures.append(0)
                        self._terminals.append([])
                    state = next_state
                terminal = (len(pattern), row_index)
                if terminal not in self._terminals[state]:
                    self._terminals[state].append(terminal)

        pending: deque[int] = deque(self._transitions[0].values())
        while pending:
            state = pending.popleft()
            for character, next_state in self._transitions[state].items():
                pending.append(next_state)
                failure = self._failures[state]
                while failure and character not in self._transitions[failure]:
                    failure = self._failures[failure]
                self._failures[next_state] = self._transitions[failure].get(
                    character, 0
                )
                inherited = self._terminals[self._failures[next_state]]
                if inherited:
                    self._terminals[next_state].extend(inherited)

    def scan(self, source: str) -> list[dict[str, str]]:
        """Return distinct selected targets in deterministic target order."""
        matched: set[int] = set()
        state = 0
        for end, character in enumerate(source):
            while state and character not in self._transitions[state]:
                state = self._failures[state]
            state = self._transitions[state].get(character, 0)
            for length, row_index in self._terminals[state]:
                start = end - length + 1
                before = source[start - 1] if start else None
                after = source[end + 1] if end + 1 < len(source) else None
                if (
                    (before is None or before not in _PATH_BOUNDARY_ALPHABET)
                    and (after is None or after not in _PATH_BOUNDARY_ALPHABET)
                ):
                    matched.add(row_index)
        return [
            {
                "target_path": self._rows[index][0],
                "target_source_digest": self._rows[index][1],
                "scope": "LEXICAL_EXACT_PATH_NOT_EXECUTION",
            }
            for index in range(len(self._rows))
            if index in matched
        ]


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism() -> dict[str, Any]:
    """Bind a finite parser inventory; optional shell absence stays visible.

    The distribution selector comes only from the immutable literal mapping.
    Keeping the metadata call in this loop is part of the namespace-admission
    grammar: factoring it through an arbitrary-name helper would look like a
    plugin loader even though this worker never loads entry points.
    """
    bindings: dict[str, dict[str, Any] | None] = {}
    for name, expected in VERSIONS.items():
        try:
            distribution = metadata.distribution(name)
            if distribution.version != expected:
                raise ValueError("NAMESPACE_WORKFLOW_PARSER_VERSION_UNSUPPORTED")
            files = {}
            for entry in distribution.files or ():
                if entry.suffix in {".py", ".pyd", ".so", ".dll"} or entry.name == "METADATA":
                    if ".." in entry.parts or entry.is_absolute():
                        raise ValueError("NAMESPACE_WORKFLOW_PARSER_LAYOUT_UNSUPPORTED")
                    files[str(entry).replace("\\", "/")] = digest(Path(distribution.locate_file(entry)).read_bytes())
            if not files:
                raise ValueError("NAMESPACE_WORKFLOW_PARSER_BYTES_UNAVAILABLE")
            bindings[name] = {"version": expected, "files": files}
        except (metadata.PackageNotFoundError, ValueError, OSError):
            if name == "PyYAML":
                raise
            bindings[name] = None
    shell = {name: bindings[name] for name in ("tree-sitter", "tree-sitter-bash")}
    return {"PyYAML": bindings["PyYAML"],
            "bash_parser": shell if all(shell.values()) else None}


class _ExpressionParser:
    """Closed parser for GitHub expression syntax and context reads."""

    _token = re.compile(
        r"\s*(?:(?P<string>'(?:[^']|'')*')|(?P<number>-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)|"
        r"(?P<identifier>[A-Za-z_][A-Za-z0-9_-]*)|(?P<operator>\|\||&&|==|!=|<=|>=|[!<>()\[\].,*]))"
    )
    _precedence = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, "<=": 4, ">": 4, ">=": 4}

    def __init__(self, source: str) -> None:
        self.tokens: list[tuple[str, str]] = []
        position = 0
        while position < len(source):
            match = self._token.match(source, position)
            if match is None:
                raise ValueError("unsupported expression token")
            kind = next(name for name, value in match.groupdict().items() if value is not None)
            self.tokens.append((kind, match.group(kind)))
            position = match.end()
        self.tokens.append(("end", ""))
        self.index = 0
        self.dependencies: set[str] = set()
        self.functions: set[str] = set()

    def peek(self, value: str | None = None) -> bool:
        return self.tokens[self.index][1] == value if value is not None else self.tokens[self.index][0] != "end"

    def take(self, value: str | None = None) -> tuple[str, str]:
        token = self.tokens[self.index]
        if value is not None and token[1] != value:
            raise ValueError("unexpected expression token")
        self.index += 1
        return token

    def parse(self) -> tuple[list[str], list[str]]:
        self.expression(0)
        if self.tokens[self.index][0] != "end":
            raise ValueError("trailing expression token")
        return sorted(self.dependencies), sorted(self.functions)

    def expression(self, minimum: int) -> None:
        if self.peek("!"):
            self.take("!")
            self.expression(5)
        else:
            self.primary()
        while self.tokens[self.index][1] in self._precedence and self._precedence[self.tokens[self.index][1]] >= minimum:
            operator = self.take()[1]
            self.expression(self._precedence[operator] + 1)

    def primary(self) -> None:
        kind, value = self.take()
        if value == "(":
            self.expression(0)
            self.take(")")
            return
        if kind in {"string", "number"} or (kind == "identifier" and value.lower() in {"true", "false", "null"}):
            return
        if kind != "identifier":
            raise ValueError("expression operand differs")
        if self.peek("("):
            if value not in EXPRESSION_FUNCTIONS:
                raise ValueError("unknown expression function")
            self.functions.add(value)
            self.take("(")
            if not self.peek(")"):
                while True:
                    self.expression(0)
                    if not self.peek(","):
                        break
                    self.take(",")
            self.take(")")
            return
        if value not in EXPRESSION_CONTEXTS:
            raise ValueError("unbound expression root")
        parts = [value]
        while True:
            if self.peek("."):
                self.take(".")
                kind, member = self.take()
                if kind != "identifier" and member != "*":
                    raise ValueError("computed expression member")
                parts.append(member)
            elif self.peek("["):
                self.take("[")
                kind, member = self.take()
                if kind == "string":
                    member = member[1:-1].replace("''", "'")
                elif kind != "number":
                    raise ValueError("dynamic expression subscript")
                parts.append("[" + member + "]")
                self.take("]")
            else:
                break
        self.dependencies.add(".".join(parts).replace(".[", "["))


def _expressions(source: str) -> list[tuple[str, int, int]]:
    """Return expression bodies and exact character spans, refusing ambiguity."""
    result: list[tuple[str, int, int]] = []
    cursor = 0
    while True:
        opening = source.find("${{", cursor)
        if opening < 0:
            return result
        index = opening + 3
        quoted = False
        while index < len(source):
            if source[index] == "'":
                if quoted and index + 1 < len(source) and source[index + 1] == "'":
                    index += 2
                    continue
                quoted = not quoted
                index += 1
                continue
            if not quoted and source.startswith("${{", index):
                raise ValueError("nested expression marker")
            if not quoted and source.startswith("}}", index):
                body = source[opening + 3:index].strip()
                if not body:
                    raise ValueError("empty expression")
                result.append((body, opening, index + 2))
                cursor = index + 2
                break
            index += 1
        else:
            raise ValueError("unterminated expression")


def _masked_expressions(source: str) -> bytes:
    """Mask expression bytes for shell parsing without changing AST offsets."""
    raw = bytearray(source.encode("utf-8"))
    for _, start, end in _expressions(source):
        offset = len(source[:start].encode("utf-8"))
        span = source[start:end].encode("utf-8")
        for index, value in enumerate(span):
            if value not in {10, 13}:
                raw[offset + index] = ord("x")
    return bytes(raw)


def _literal_scalar(yaml: Any, node: Any) -> str:
    if not isinstance(node, yaml.ScalarNode):
        raise ValueError("expected literal scalar")
    return node.value


def _runner_shells(yaml: Any, job: dict[str, Any]) -> list[str]:
    """Resolve default-shell families only from literal runner matrix bytes."""
    runs = job.get("runs-on")
    values: list[str] = []
    if isinstance(runs, yaml.ScalarNode):
        source = runs.value.strip()
        match = re.fullmatch(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*}}", source)
        if match:
            strategy = job.get("strategy")
            matrix = None
            if isinstance(strategy, yaml.MappingNode):
                matrix = {key.value: value for key, value in strategy.value}.get("matrix")
            fields = {key.value: value for key, value in matrix.value} if isinstance(matrix, yaml.MappingNode) else {}
            axis = fields.get(match.group(1))
            if isinstance(axis, yaml.SequenceNode):
                values.extend(_literal_scalar(yaml, item) for item in axis.value)
            include = fields.get("include")
            if isinstance(include, yaml.SequenceNode):
                for row in include.value:
                    if isinstance(row, yaml.MappingNode):
                        member = {key.value: value for key, value in row.value}.get(match.group(1))
                        if member is not None:
                            values.append(_literal_scalar(yaml, member))
        elif "${{" not in source:
            values.append(source)
    elif isinstance(runs, yaml.SequenceNode):
        values.extend(_literal_scalar(yaml, item) for item in runs.value)
    shells = set()
    for value in values:
        lower = value.lower()
        if lower.startswith(("ubuntu", "macos")):
            shells.add("bash")
        elif lower.startswith("windows"):
            shells.add("pwsh")
        else:
            shells.add("UNKNOWN")
    return sorted(shells)


def _declared_shell(value: str) -> list[str]:
    if "${{" in value:
        return []
    try:
        first = shlex.split(value, posix=True)[0]
    except (ValueError, IndexError):
        return []
    name = posixpath.basename(first).lower()
    if name in {"bash", "sh"}:
        return ["bash"]
    if name in {"pwsh", "powershell"}:
        return ["pwsh"]
    if name in {"python", "python3"}:
        return ["python"]
    return []


def parse(
    path: str,
    raw: bytes,
    selected: dict[str, str],
    bash_parser: Any | None,
    path_index: _ExactPathIndex | None = None,
) -> dict[str, Any]:
    import yaml  # Optional and isolated from repository module shadowing.

    exact_paths = path_index if path_index is not None else _ExactPathIndex(selected)

    rows: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    commands: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    external_references: list[dict[str, Any]] = []
    expressions: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []
    result = {"path": path, "source_digest": digest(raw), "surfaces": rows, "gaps": gaps,
              "commands": commands, "references": references,
              "external_references": external_references,
              "expressions": expressions,
              "documents": documents}

    def gap(code: str, reason: str) -> None:
        if not any(row["code"] == code for row in gaps):
            gaps.append({"path": path, "code": code, "reason": reason})

    def record_at(address: str, form: str, line: int) -> str:
        identity = "workflow:" + path + ":" + address
        rows.append({"surface_id": identity, "path": path, "line": line, "form": form,
                     "source_kinds": [], "hints": [], "unresolved_marker": False})
        return identity

    def record(node: Any, address: str, form: str) -> str:
        return record_at(address, form, node.start_mark.line + 1)

    def mapping(node: Any) -> dict[str, Any]:
        if not isinstance(node, yaml.MappingNode):
            raise ValueError("expected mapping")
        return {key.value: value for key, value in node.value}

    def text(node: Any) -> str:
        return _literal_scalar(yaml, node)

    def sequence(node: Any) -> list[Any]:
        if not isinstance(node, yaml.SequenceNode):
            raise ValueError("expected sequence")
        return node.value

    def boolean(node: Any) -> bool:
        value = text(node).lower()
        if value not in {"true", "false"}:
            raise ValueError("expected boolean")
        return value == "true"

    def expression_rows(node: Any, address: str) -> None:
        source = text(node)
        if "${{" not in source:
            return
        try:
            for index, (body, start, end) in enumerate(_expressions(source)):
                dependencies, functions = _ExpressionParser(body).parse()
                identity = record_at(address + "/expression/" + str(index), "WorkflowExpression",
                                     node.start_mark.line + source[:start].count("\n") + 1)
                expressions.append({"surface_id": identity, "path": path,
                    "source_digest": digest(source[start:end].encode("utf-8")),
                    "dependencies": dependencies, "functions": functions,
                    "scope": "STATIC_SYNTAX_AND_CONTEXT_READS_NOT_EVALUATION"})
        except ValueError:
            gap("NAMESPACE_WORKFLOW_EXPRESSION_UNRESOLVED",
                "An expression is malformed, uses computed selection, or has an unbound context/function; it was not evaluated.")

    def reference(node: Any, address: str, *, local_action: bool = False, relative: bool = False) -> None:
        value = text(node)
        remote = REMOTE_COMMIT_REFERENCE.fullmatch(value) if not relative else None
        if remote is not None:
            subpath = (remote.group("subpath") or "").lstrip("/")
            if subpath and any(
                part in {"", ".", ".."} for part in subpath.split("/")
            ):
                remote = None
        identity = record(
            node,
            address,
            "WorkflowExternalReference" if remote is not None else "WorkflowReference",
        )
        if remote is not None:
            # A full commit identifier closes the repository's dependency edge,
            # not the referenced implementation. No source is downloaded and
            # no remote action receives local source-admission authority.
            external_references.append(
                {
                    "surface_id": identity,
                    "path": path,
                    "line": node.start_mark.line + 1,
                    "repository": remote.group("repository"),
                    "subpath": subpath or ".",
                    "revision": remote.group("revision"),
                    "scope": "DECLARED_PINNED_EXTERNAL_REFERENCE_NOT_SOURCE_ADMISSION_OR_EXECUTION",
                }
            )
            return
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), value)) if relative else posixpath.normpath(value)
        candidates = [target + "/action.yml", target + "/action.yaml"] if local_action else [target]
        available = [candidate for candidate in candidates if candidate in selected]
        if (not value or (not relative and not value.startswith("./")) or value.startswith(("/", "\\"))
                or "\\" in value or "\x00" in value or ":" in value or "${{" in value
                or target == ".." or target.startswith("../") or len(available) != 1):
            gap("NAMESPACE_WORKFLOW_REFERENCE_UNRESOLVED",
                "A referenced action, reusable workflow, or runtime is not one uniquely selected local source; no resource was downloaded.")
        else:
            references.append({"surface_id": identity, "target_path": available[0],
                "target_source_digest": selected[available[0]], "scope": "DECLARED_LOCAL_SOURCE_NOT_EXECUTION"})

    def context(fields: dict[str, Any], fallback_shells: list[str], fallback_directory: str) -> tuple[list[str], str]:
        shells = fallback_shells
        directory = fallback_directory
        if "defaults" in fields:
            declared = mapping(fields["defaults"])
            run = mapping(declared["run"]) if "run" in declared else {}
            if "shell" in run:
                shells = _declared_shell(text(run["shell"]))
            if "working-directory" in run:
                candidate = text(run["working-directory"])
                directory = candidate if "${{" not in candidate else ""
        return shells, directory

    def command_binding(node: Any, identity: str, shells: list[str], directory: str) -> None:
        source = text(node)
        entry: dict[str, Any] = {"surface_id": identity, "path": path, "line": node.start_mark.line + 1,
            "source_digest": digest(source.encode("utf-8")), "shell": shells[0] if len(shells) == 1 else "MULTI_RUNNER_DEFAULT",
            "shell_candidates": shells, "working_directory": directory or "DYNAMIC_OR_UNRESOLVED",
            "programs": [], "source_bindings": [], "location_scope": "DECLARED_SCALAR",
            "scope": "STATIC_COMMAND_SYNTAX_NOT_EXECUTION"}
        commands.append(entry)
        if not shells or "UNKNOWN" in shells or not directory:
            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                "The command bytes are bound, but the runner-selected interpreter or working directory is not statically bounded.")
            return
        if shells == ["python"]:
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "A declared Python shell body is not a complete static syntax tree.")
                return
            entry["programs"].append({"program": "python", "line": node.start_mark.line + 1,
                                      "scope": "DECLARED_PYTHON_SHELL"})
            for index, child in enumerate(ast.walk(tree)):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    record_at(identity.removeprefix("workflow:" + path + ":") + "/python/" + str(index),
                              type(child).__name__, node.start_mark.line + getattr(child, "lineno", 1))
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in {"eval", "exec", "__import__"}:
                    gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "Dynamic Python evaluation can dispatch interfaces outside the literal command source.")
            return
        if bash_parser is None:
            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                "Literal shell commands require the pinned discovery-shell parser; no command was executed as a substitute.")
            return
        try:
            masked = _masked_expressions(source)
        except ValueError:
            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "A malformed expression prevents a stable command syntax tree.")
            return
        tree = bash_parser.parse(masked)
        if tree.root_node.has_error:
            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                "The selected shell parser reports erroneous or missing syntax; partial syntax is not command coverage.")
            return
        pending = [tree.root_node]
        nodes = []
        while pending:
            current = pending.pop()
            nodes.append(current)
            if len(nodes) > 250_000:
                raise ValueError("NAMESPACE_WORKFLOW_COMMAND_NODE_CAPACITY")
            pending.extend(reversed(current.named_children))
        if "pwsh" in shells and any(item.type in {"case_statement", "for_statement", "if_statement", "pipeline",
                "process_substitution", "redirected_statement", "variable_assignment", "while_statement"} for item in nodes):
            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                "A multi-runner default shell uses non-portable control syntax; every selected shell needs a parser-bound interpretation.")
        if "pwsh" in shells and any(item.type in {"arithmetic_expansion", "command_substitution", "expansion",
                "herestring_redirect", "simple_expansion", "subshell"} for item in nodes):
            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                "A PowerShell-selected command uses syntax whose meaning is not established by the Bash parser binding.")
        original = source.encode("utf-8")
        for index, current in enumerate(nodes):
            if current.type == "function_definition":
                name = current.child_by_field_name("name")
                label = masked[name.start_byte:name.end_byte].decode("utf-8") if name is not None else ""
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", label):
                    gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "A shell function name is not one literal interface.")
                else:
                    record_at(identity.removeprefix("workflow:" + path + ":") + "/shell-function/" + str(index) + "/" + label,
                              "WorkflowShellFunction", node.start_mark.line + current.start_point.row + 1)
            if current.type != "command":
                continue
            name = current.child_by_field_name("name")
            command = masked[name.start_byte:name.end_byte].decode("utf-8") if name is not None else ""
            original_name = original[name.start_byte:name.end_byte].decode("utf-8") if name is not None else ""
            if (name is None or not re.fullmatch(r"[A-Za-z0-9_./:+-]+", command)
                    or "${{" in original_name or "$" in original_name or command in SHELL_DISPATCHERS):
                gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                    "Dynamic command selection, source/eval, alias, or nested shell dispatch may introduce interfaces outside the static syntax census.")
                continue
            program = {"program": command, "line": node.start_mark.line + current.start_point.row + 1,
                       "scope": "LITERAL_DISPATCH_NOT_EXECUTION"}
            if program not in entry["programs"]:
                entry["programs"].append(program)
            record_at(identity.removeprefix("workflow:" + path + ":") + "/program/" + str(index),
                      "WorkflowCommand", node.start_mark.line + current.start_point.row + 1)
            if posixpath.basename(command).lower() in {"python", "python3", "python.exe", "python3.exe"}:
                command_bytes = original[current.start_byte:current.end_byte]
                masked_bytes = masked[current.start_byte:current.end_byte]
                try:
                    arguments = shlex.split(masked_bytes.decode("utf-8"), posix=True)
                except ValueError:
                    gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "A Python interpreter command has ambiguous shell quoting.")
                    continue
                if "-c" in arguments:
                    position = arguments.index("-c")
                    if position + 1 >= len(arguments) or b"${{" in command_bytes:
                        gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                            "Inline Python source is absent or expression-generated; its interfaces are not a literal syntax tree.")
                        continue
                    inline = arguments[position + 1]
                    try:
                        python_tree = ast.parse(inline)
                    except (SyntaxError, ValueError):
                        gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "Inline Python source is not a complete static syntax tree.")
                        continue
                    record_at(identity.removeprefix("workflow:" + path + ":") + "/inline-python/" + str(index),
                              "WorkflowInlinePython", node.start_mark.line + current.start_point.row + 1)
                    for child_index, child in enumerate(ast.walk(python_tree)):
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            record_at(identity.removeprefix("workflow:" + path + ":") + "/inline-python/" + str(index)
                                      + "/definition/" + str(child_index), type(child).__name__,
                                      node.start_mark.line + current.start_point.row + getattr(child, "lineno", 1))
                        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in {
                                "__import__", "compile", "eval", "exec"}:
                            gap("NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED",
                                "Dynamic inline Python evaluation can dispatch interfaces outside the literal syntax census.")
        entry["source_bindings"].extend(exact_paths.scan(source))

    def steps(node: Any, address: str, shells: list[str], directory: str) -> None:
        for index, step in enumerate(sequence(node)):
            base = address + "/" + str(index)
            record(step, base, "WorkflowStep")
            fields = mapping(step)
            step_shells = _declared_shell(text(fields["shell"])) if "shell" in fields else shells
            step_directory = text(fields["working-directory"]) if "working-directory" in fields else directory
            if "${{" in step_directory:
                step_directory = ""
            if "run" in fields:
                identity = record(fields["run"], base + "/run", "WorkflowRun")
                command_binding(fields["run"], identity, step_shells, step_directory)
            if "uses" in fields:
                reference(fields["uses"], base + "/uses", local_action=True)
            if ("run" in fields) == ("uses" in fields):
                gap("NAMESPACE_WORKFLOW_SHAPE_UNRESOLVED", "Each step requires exactly one declared run or uses boundary.")

    def issue_config(fields: dict[str, Any]) -> None:
        if set(fields) - {"blank_issues_enabled", "contact_links"} or not fields:
            raise ValueError("issue config keys differ")
        if "blank_issues_enabled" in fields:
            boolean(fields["blank_issues_enabled"])
        links = sequence(fields["contact_links"]) if "contact_links" in fields else []
        for index, link in enumerate(links):
            values = mapping(link)
            if set(values) != {"name", "url", "about"} or any(not text(values[key]).strip() for key in values):
                raise ValueError("contact link differs")
            record(link, "issue-config/contact-link/" + str(index), "GitHubIssueContactLink")

    def issue_form(fields: dict[str, Any]) -> None:
        if not {"name", "description", "body"} <= set(fields) or set(fields) - {"name", "description", "title", "labels", "assignees", "body"}:
            raise ValueError("issue form keys differ")
        if not text(fields["name"]).strip() or not text(fields["description"]).strip():
            raise ValueError("issue form metadata differs")
        if "title" in fields:
            text(fields["title"])
        for optional in ("labels", "assignees"):
            if optional in fields:
                for member in sequence(fields[optional]):
                    text(member)
        identifiers = set()
        allowed_attributes = {
            "markdown": {"value"},
            "input": {"label", "description", "placeholder", "value"},
            "textarea": {"label", "description", "placeholder", "value", "render"},
            "dropdown": {"label", "description", "options", "multiple"},
            "checkboxes": {"label", "description", "options"},
        }
        for index, item in enumerate(sequence(fields["body"])):
            values = mapping(item)
            if not {"type", "attributes"} <= set(values) or set(values) - {"type", "id", "attributes", "validations"}:
                raise ValueError("issue form control keys differ")
            kind = text(values["type"])
            if kind not in allowed_attributes or (kind != "markdown" and "id" not in values) or (kind == "markdown" and "id" in values):
                raise ValueError("issue form control type differs")
            if "id" in values:
                identifier = text(values["id"])
                if not re.fullmatch(r"[A-Za-z0-9_-]+", identifier) or identifier in identifiers:
                    raise ValueError("issue form identifier differs")
                identifiers.add(identifier)
            attributes = mapping(values["attributes"])
            if set(attributes) - allowed_attributes[kind]:
                raise ValueError("issue form attributes differ")
            if kind == "markdown":
                if set(attributes) != {"value"} or not text(attributes["value"]).strip():
                    raise ValueError("markdown control differs")
            else:
                if "label" not in attributes or not text(attributes["label"]).strip():
                    raise ValueError("control label differs")
                for key in set(attributes) - {"options", "multiple"}:
                    text(attributes[key])
                if "multiple" in attributes:
                    boolean(attributes["multiple"])
                if kind == "dropdown":
                    if "options" not in attributes or not sequence(attributes["options"]):
                        raise ValueError("dropdown options differ")
                    for option in sequence(attributes["options"]):
                        if not text(option).strip():
                            raise ValueError("dropdown option differs")
                if kind == "checkboxes":
                    if "options" not in attributes or not sequence(attributes["options"]):
                        raise ValueError("checkbox options differ")
                    for option in sequence(attributes["options"]):
                        option_fields = mapping(option)
                        if "label" not in option_fields or set(option_fields) - {"label", "required"} or not text(option_fields["label"]).strip():
                            raise ValueError("checkbox option differs")
                        if "required" in option_fields:
                            boolean(option_fields["required"])
            if "validations" in values:
                validations = mapping(values["validations"])
                if set(validations) - {"required"}:
                    raise ValueError("issue form validations differ")
                if "required" in validations:
                    boolean(validations["required"])
            record(item, "issue-form/control/" + str(index), "GitHubIssueFormControl")

    try:
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("YAML input capacity exceeded")
        for index, token in enumerate(yaml.scan(raw, Loader=yaml.BaseLoader)):
            if index > 250_000 or isinstance(token, (yaml.AliasToken, yaml.TagToken, yaml.DirectiveToken)):
                raise ValueError("YAML aliases, tags, directives or capacity require explicit interpretation")
        root = yaml.compose(raw, Loader=yaml.BaseLoader)
        if root is None:
            raise ValueError("empty YAML source")
        pending = [(root, "document", 0)]
        count = 0
        while pending:
            node, address, depth = pending.pop()
            count += 1
            if depth > 64 or count > 250_000:
                raise ValueError("YAML structure capacity exceeded")
            record(node, "node/" + address, "YAMLNode")
            if isinstance(node, yaml.MappingNode):
                seen = set()
                for index, (key, value) in enumerate(node.value):
                    name = text(key)
                    if name in seen or name == "<<":
                        raise ValueError("duplicate or merged YAML keys")
                    seen.add(name)
                    pending.extend(((key, address + "/key/" + str(index), depth + 1),
                                    (value, address + "/value/" + str(index), depth + 1)))
            elif isinstance(node, yaml.SequenceNode):
                pending.extend((value, address + "/item/" + str(index), depth + 1) for index, value in enumerate(node.value))
            else:
                expression_rows(node, "node/" + address)
        fields = mapping(root)
    except (yaml.YAMLError, ValueError, KeyError, RecursionError) as exc:
        rows.clear()
        commands.clear()
        references.clear()
        expressions.clear()
        documents.clear()
        gap("NAMESPACE_WORKFLOW_PARSE_UNAVAILABLE", "YAML composition unavailable: " + type(exc).__name__)
        return result

    workflow = path.startswith(".github/workflows/") and len(path.split("/")) == 3
    action = posixpath.basename(path) in {"action.yml", "action.yaml"}
    issue_config_path = path in {".github/ISSUE_TEMPLATE/config.yml", ".github/ISSUE_TEMPLATE/config.yaml"}
    issue_form_path = path.startswith(".github/ISSUE_TEMPLATE/") and path.endswith((".yml", ".yaml")) and not issue_config_path
    dialect = "UNKNOWN_YAML"
    try:
        if workflow:
            dialect = "GITHUB_ACTIONS_WORKFLOW"
            jobs = mapping(fields["jobs"])
            workflow_shells, workflow_directory = context(fields, [], ".")
            for name, node in jobs.items():
                base = "job/" + json.dumps(name, ensure_ascii=True)
                record(node, base, "WorkflowJob")
                job = mapping(node)
                job_shells, job_directory = context(job, _runner_shells(yaml, job) or workflow_shells, workflow_directory)
                if "steps" in job:
                    steps(job["steps"], base + "/steps", job_shells, job_directory)
                if "uses" in job:
                    reference(job["uses"], base + "/uses")
                if ("steps" in job) == ("uses" in job):
                    gap("NAMESPACE_WORKFLOW_SHAPE_UNRESOLVED", "A job needs exactly one declared steps or reusable-workflow boundary.")
        elif action:
            dialect = "GITHUB_ACTION"
            runs = mapping(fields["runs"])
            using = text(runs["using"])
            if using == "composite":
                steps(runs["steps"], "runs/steps", [], ".")
            elif using.startswith("node"):
                if "main" not in runs:
                    raise ValueError("missing action main source")
                for name in ("pre", "main", "post"):
                    if name in runs:
                        reference(runs[name], "runs/" + name, relative=True)
            else:
                gap("NAMESPACE_WORKFLOW_RUNTIME_UNRESOLVED", "The action runtime or image needs its own selected source and execution boundary.")
        elif issue_config_path:
            dialect = "GITHUB_ISSUE_CONFIG"
            issue_config(fields)
        elif issue_form_path:
            dialect = "GITHUB_ISSUE_FORM"
            issue_form(fields)
        else:
            gap("NAMESPACE_YAML_INTERPRETATION_UNRESOLVED",
                "YAML nodes are inventoried, but this document's consumer/dialect is not selected; data syntax cannot prove passive behavior.")
    except (ValueError, KeyError, RecursionError):
        code = "NAMESPACE_ISSUE_FORM_SCHEMA_UNRESOLVED" if issue_config_path or issue_form_path else "NAMESPACE_WORKFLOW_SHAPE_UNRESOLVED"
        gap(code, "The path selects a known document dialect, but its bounded structural grammar is not satisfied.")
    document_identity = record(root, "document", {
        "GITHUB_ACTIONS_WORKFLOW": "WorkflowDocument", "GITHUB_ACTION": "WorkflowActionDocument",
        "GITHUB_ISSUE_CONFIG": "GitHubIssueConfig", "GITHUB_ISSUE_FORM": "GitHubIssueForm",
    }.get(dialect, "YAMLDocument"))
    documents.append({"surface_id": document_identity, "path": path, "source_digest": digest(raw),
                      "dialect": dialect, "scope": "STATIC_DOCUMENT_GRAMMAR_NOT_HOSTED_BEHAVIOR"})
    return result


def main() -> None:
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("NAMESPACE_WORKFLOW_INPUT_CAPACITY")
    request = json.loads(raw)
    if (type(request) is not dict or set(request) != {"schema_version", "files", "selected"}
            or request["schema_version"] != PROTOCOL or type(request["files"]) is not list
            or len(request["files"]) > 8192 or type(request["selected"]) is not dict):
        raise ValueError("NAMESPACE_WORKFLOW_PROTOCOL_DIFFERS")
    opening = mechanism()
    bash_parser = None
    if opening["bash_parser"] is not None:
        from tree_sitter import Language, Parser
        import tree_sitter_bash
        bash_parser = Parser(Language(tree_sitter_bash.language()))
    path_index = _ExactPathIndex(request["selected"])
    rows = [parse(row["path"], base64.b64decode(row["source"], validate=True), request["selected"], bash_parser, path_index)
            for row in request["files"]]
    if mechanism() != opening:
        raise ValueError("NAMESPACE_WORKFLOW_MECHANISM_CHANGED")
    wire = json.dumps({"schema_version": PROTOCOL, "mechanism": opening, "files": rows}).encode("utf-8")
    if len(wire) > LIMIT:
        raise ValueError("NAMESPACE_WORKFLOW_OUTPUT_CAPACITY")
    sys.stdout.buffer.write(wire)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, ImportError, metadata.PackageNotFoundError, RecursionError) as exc:
        print(json.dumps({"code": "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE", "reason": type(exc).__name__}))
        raise SystemExit(2)
