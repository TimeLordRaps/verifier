"""Bounded abstract syntax tree (AST) relationships for pull request descriptions.

Pull Request Domain Explanation Language (PRDEL) uses this data-only index to
ask about affected contracts. Strongly connected components (SCCs) preserve cycles
when rendered as a directed acyclic graph (DAG). No candidate source is executed.
Resolved syntax is not a verified contract, and the graph does not prove runtime
effects, complete applicability, or arbitrary dynamic dispatch.
"""

from __future__ import annotations

import ast
from collections import deque
import hashlib
import json
from typing import Any


def _identifier(prefix: str, *parts: Any) -> str:
    data = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return prefix + ":" + hashlib.sha256(data.encode("utf-8")).hexdigest()[:24]


def _module_name(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if parts[0] == "src":
        parts = parts[1:]
    parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id] + list(reversed(parts)))


def _expression_identity(node: ast.AST) -> str:
    """Return a bounded identity for cross-snapshot call-site comparison."""
    rendered = ast.dump(node, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


class _Limit(Exception):
    pass


class _Graph:
    def __init__(self, changes: list[dict[str, Any]], limits: dict[str, int]) -> None:
        self.changes = changes
        self.selected_change_ids = sorted({str(change["id"]) for change in changes})
        self.path_changes: dict[str, list[dict[str, Any]]] = {}
        for change in changes:
            self.path_changes.setdefault(change.get("path", ""), []).append(change)
        self.limits = limits
        self.operations = 0
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.frontier: dict[str, dict[str, Any]] = {}
        self.frontier_context: dict[
            str,
            tuple[
                str | None,
                str | None,
                dict[str, Any] | None,
                str | None,
            ],
        ] = {}
        self.edge_context: dict[str, str | None] = {}
        self.incomplete = False

    def step(self, count: int = 1) -> None:
        if self.operations + count > self.limits["max_operations"]:
            self.boundary(
                "operation_bound",
                "",
                "both",
                None,
                "Increase the declared operation bound and rerun the graph.",
            )
            raise _Limit
        self.operations += count

    def affected(self, path: str, side: str, start: int, end: int) -> list[str]:
        result: list[str] = []
        for change in self.path_changes.get(path, []):
            self.step()
            span = change.get("old_range" if side == "before" else "new_range", [])
            if len(span) == 2 and span[0] > 0 and start <= span[1] and span[0] <= end:
                result.append(str(change["id"]))
        return sorted(set(result))

    def boundary(
        self,
        kind: str,
        path: str,
        side: str,
        ref: dict[str, Any] | None,
        question: str,
        changes: list[str] | None = None,
        consumer_id: str | None = None,
        relationship: str | None = None,
        expression_identity: str | None = None,
    ) -> None:
        key = _identifier("frontier", kind, path, side, ref, question)
        if len(self.frontier) >= self.limits["max_edges"] and key not in self.frontier:
            key = "frontier:frontier_bound"
            kind, path, side, ref = "frontier_bound", "", "both", None
            question = (
                "Additional unresolved boundaries were truncated; "
                "rerun with larger bounds."
            )
            self.incomplete = True
            if key in self.frontier:
                return
            changes = self.selected_change_ids
            consumer_id = None
            relationship = None
            expression_identity = None
        self.frontier[key] = {
            "id": key,
            "kind": kind,
            "path": path,
            "side": side,
            "source_ref": ref,
            "question": question,
            "source_obligations": sorted(set(changes or [])),
            "consumer_id": consumer_id,
        }
        self.frontier_context[key] = (
            consumer_id,
            relationship,
            ref,
            expression_identity,
        )
        if (
            kind.endswith("_bound")
            or kind.startswith("incomplete_")
            or kind in {"parse_failure", "source_size_bound"}
        ):
            self.incomplete = True

    def node(
        self,
        path: str,
        side: str,
        symbol: str,
        kind: str,
        ref: dict[str, Any],
        *,
        parent: str | None = None,
    ) -> str:
        key = _identifier("node", side, path, symbol, kind)
        if key in self.nodes:
            existing = self.nodes[key]
            changes = set(existing["source_obligations"])
            changes.update(
                self.affected(path, side, ref["start_line"], ref["end_line"])
            )
            existing["source_obligations"] = sorted(changes)
            existing["changed"] = bool(changes)
            return key
        if len(self.nodes) >= self.limits["max_nodes"]:
            self.boundary(
                "node_bound",
                path,
                side,
                ref,
                "The node bound omitted source relationships; increase it and rerun.",
            )
            raise _Limit
        changes = self.affected(path, side, ref["start_line"], ref["end_line"])
        self.nodes[key] = {
            "id": key,
            "path": path,
            "side": side,
            "symbol": symbol,
            "node_kind": kind,
            "source_ref": ref,
            "parent": parent,
            "changed": bool(changes),
            "source_obligations": changes,
        }
        return key

    def edge(
        self,
        source: str,
        target: str,
        kind: str,
        side: str,
        ref: dict[str, Any],
        state: str = "resolved_relationship",
        expression_identity: str | None = None,
    ) -> None:
        key = _identifier("edge", side, source, target, kind, ref)
        if key in self.edges:
            return
        if len(self.edges) >= self.limits["max_edges"]:
            self.boundary(
                "edge_bound",
                ref["path"],
                side,
                ref,
                "The edge bound omitted relationships; increase it and rerun.",
            )
            raise _Limit
        changes = set(self.nodes[source]["source_obligations"])
        changes.update(self.nodes[target]["source_obligations"])
        changes.update(
            self.affected(ref["path"], side, ref["start_line"], ref["end_line"])
        )
        self.edges[key] = {
            "id": key,
            "source": source,
            "target": target,
            "relationship": kind,
            "direction": "dependency_to_consumer",
            "side": side,
            "source_ref": ref,
            "evidence_state": state,
            "source_obligations": sorted(changes),
        }
        self.edge_context[key] = expression_identity


class _Snapshot:
    def __init__(self, graph: _Graph, files: dict[str, bytes], side: str) -> None:
        self.graph, self.files, self.side = graph, files, side
        self.modules: dict[str, list[str]] = {}
        self.definitions: dict[tuple[str, str], str] = {}
        self.imports: dict[tuple[str, str, str], str] = {}
        self.instances: dict[tuple[str, str, str], str] = {}
        self.shadowed: set[tuple[str, str, str]] = set()
        self.instance_writes: dict[tuple[str, str, str], int] = {}
        self.items: list[tuple[str, ast.AST, str, str | None]] = []
        self.file_nodes: dict[str, str] = {}
        self.blobs: dict[str, str] = {}

    def ref(self, path: str, node: ast.AST | None = None) -> dict[str, Any]:
        return {
            "path": path,
            "start_line": getattr(node, "lineno", 1),
            "end_line": getattr(node, "end_lineno", None) or getattr(node, "lineno", 1),
            "blob_sha256": self.blobs[path],
        }

    def incomplete_source(
        self, kind: str, path: str, ref: dict[str, Any], question: str
    ) -> None:
        consumer = self.file_nodes[path]
        direct = self.graph.nodes[consumer]["source_obligations"]
        changes = sorted({str(change["id"]) for change in self.graph.changes})
        if not direct:
            question += (
                " This unindexed path remains UNKNOWN; parsing did not expose "
                "enough relationships to exclude any selected producer, so "
                "establish applicability before removing a binding."
            )
        self.graph.boundary(
            kind, path, self.side, ref, question, changes, consumer_id=consumer
        )

    def index(self) -> None:
        for path in sorted(self.files):
            self.graph.step()
            data = self.files[path]
            self.blobs[path] = hashlib.sha256(data).hexdigest()
            ref = self.ref(path)
            ref["end_line"] = max(1, data.count(b"\n") + 1)
            file_id = self.graph.node(path, self.side, "<module>", "module", ref)
            self.file_nodes[path] = file_id
            if not path.endswith(".py"):
                if self.graph.nodes[file_id]["changed"]:
                    self.graph.boundary(
                        "unsupported_language",
                        path,
                        self.side,
                        ref,
                        (
                            "Supply schema/configuration or "
                            "language-specific relationship evidence."
                        ),
                        self.graph.nodes[file_id]["source_obligations"],
                    )
                continue
            module = _module_name(path)
            self.modules.setdefault(module, []).append(path)
            # Parsing is bounded separately because ast.parse itself is not
            # interruptible.
            if len(data) > self.graph.limits["max_operations"] * 64:
                self.incomplete_source(
                    "source_size_bound",
                    path,
                    ref,
                    (
                        "This source exceeds the parse-size bound; "
                        "increase bounds or split analysis."
                    ),
                )
                continue
            try:
                tree = ast.parse(data, filename=path, type_comments=True)
            except (
                SyntaxError,
                ValueError,
                TypeError,
                RecursionError,
                MemoryError,
            ) as exc:
                self.incomplete_source(
                    "parse_failure",
                    path,
                    ref,
                    "Provide parseable source or explicit relationship evidence: "
                    + type(exc).__name__,
                )
                tree = None
                if isinstance(exc, SyntaxError) and exc.lineno and exc.lineno > 1:
                    prefix = b"".join(data.splitlines(keepends=True)[: exc.lineno - 1])
                    try:
                        tree = ast.parse(prefix, filename=path, type_comments=True)
                    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
                        tree = None
                if tree is None:
                    continue
            queue: list[tuple[ast.AST, str, str | None]] = [(tree, "", None)]
            while queue:
                self.graph.step()
                node, owner, class_name = queue.pop()
                if isinstance(
                    node,
                    (
                        ast.Call,
                        ast.Import,
                        ast.ImportFrom,
                        ast.ClassDef,
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.AnnAssign,
                    ),
                ) or (isinstance(node, ast.Assign) and node.type_comment is not None):
                    self.items.append((path, node, owner, class_name))
                child_owner, child_class = owner, class_name
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    name = owner + "." + node.name if owner else node.name
                    kind = "class" if isinstance(node, ast.ClassDef) else "function"
                    parent = self.definitions.get((path, owner), file_id)
                    key = self.graph.node(
                        path, self.side, name, kind, self.ref(path, node), parent=parent
                    )
                    self.definitions[(path, name)] = key
                    child_owner = name
                    if isinstance(node, ast.ClassDef):
                        child_class = name
                    else:
                        args = (
                            node.args.posonlyargs
                            + node.args.args
                            + node.args.kwonlyargs
                        )
                        args += [
                            arg for arg in (node.args.vararg, node.args.kwarg) if arg
                        ]
                        self.shadowed.update((path, name, arg.arg) for arg in args)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.imports[
                            (path, owner, alias.asname or alias.name.split(".")[0])
                        ] = (alias.name if alias.asname else alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    package = (
                        module.split(".")
                        if path.endswith("/__init__.py")
                        else module.split(".")[:-1]
                    )
                    prefix = node.module or ""
                    if node.level:
                        trim = node.level - 1
                        prefix = ".".join(
                            package[: len(package) - trim]
                            + ([prefix] if prefix else [])
                        )
                    for alias in node.names:
                        self.imports[(path, owner, alias.asname or alias.name)] = (
                            ".".join(part for part in (prefix, alias.name) if part)
                        )
                elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    constructor = _dotted(node.value.func)
                    if constructor:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.instances[(path, owner, target.id)] = constructor
                if isinstance(node, ast.Name) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    key = (path, owner, node.id)
                    self.shadowed.add(key)
                    self.instance_writes[key] = self.instance_writes.get(key, 0) + 1
                children = list(ast.iter_child_nodes(node))
                queue.extend(
                    (child, child_owner, child_class) for child in reversed(children)
                )
            # Module, class and outer-function nodes are structural containers.
            # A change wholly contained by a nested definition belongs to that
            # nested node rather than seeding every relationship of its owners.
            # A region spanning both module/container syntax and a definition is
            # deliberately retained on both.
            definition_nodes = [
                self.graph.nodes[definition_id]
                for (definition_path, _), definition_id in self.definitions.items()
                if definition_path == path
            ]
            changes_by_id = {
                str(change["id"]): change
                for change in self.graph.path_changes.get(path, [])
            }
            for container in [self.graph.nodes[file_id], *definition_nodes]:
                container_ref = container["source_ref"]
                nested_refs = [
                    candidate["source_ref"]
                    for candidate in definition_nodes
                    if candidate["id"] != container["id"]
                    and container_ref["start_line"] <= candidate["source_ref"]["start_line"]
                    and candidate["source_ref"]["end_line"] <= container_ref["end_line"]
                ]
                retained: set[str] = set()
                for change_id in container["source_obligations"]:
                    change = changes_by_id[change_id]
                    span = change.get(
                        "old_range" if self.side == "before" else "new_range", []
                    )
                    nested_only = (
                        len(span) == 2
                        and span[0] > 0
                        and span[1] >= span[0]
                        and any(
                            nested_ref["start_line"] < span[0]
                            and span[1] <= nested_ref["end_line"]
                            for nested_ref in nested_refs
                        )
                    )
                    if not nested_only:
                        retained.add(change_id)
                container["source_obligations"] = sorted(retained)
                container["changed"] = bool(retained)

    def resolve(
        self,
        path: str,
        owner: str,
        name: str,
        class_name: str | None,
        *,
        instance: bool = True,
    ) -> str | None:
        self.graph.step()
        first, _, suffix = name.partition(".")
        if first in {"self", "cls"} and class_name and suffix:
            return self.definitions.get((path, class_name + "." + suffix))
        scopes = owner.split(".")
        for size in range(len(scopes), -1, -1):
            self.graph.step()
            scope = ".".join(scopes[:size])
            if instance and suffix:
                constructor = self.instances.get((path, scope, first))
                if constructor and self.instance_writes.get((path, scope, first)) == 1:
                    target = self.resolve(
                        path, scope, constructor, class_name, instance=False
                    )
                    if target:
                        definition = self.graph.nodes[target]
                        found = self.definitions.get(
                            (definition["path"], definition["symbol"] + "." + suffix)
                        )
                        if found:
                            return found
            if (path, scope, first) in self.shadowed:
                return None
            local = scope + "." + name if scope else name
            found = self.definitions.get((path, local))
            if found:
                return found
            imported = self.imports.get((path, scope, first))
            if imported:
                return self.absolute(imported + ("." + suffix if suffix else ""))
        return self.absolute(name)

    def absolute(self, name: str) -> str | None:
        parts = name.split(".")
        for size in range(len(parts), 0, -1):
            self.graph.step()
            paths = self.modules.get(".".join(parts[:size]), [])
            if len(paths) != 1:
                continue
            path = paths[0]
            suffix = ".".join(parts[size:])
            return (
                self.definitions.get((path, suffix))
                if suffix
                else self.file_nodes[path]
            )
        return None

    def connection(
        self,
        path: str,
        owner: str,
        class_name: str | None,
        expression: ast.AST,
        kind: str,
    ) -> str | None:
        name = _dotted(expression)
        expression_identity = _expression_identity(expression)
        target = self.definitions.get((path, owner), self.file_nodes[path])
        source = self.resolve(path, owner, name, class_name) if name else None
        if source:
            candidate = False
            if name and kind in {"call", "registration"}:
                first, _, suffix = name.partition(".")
                candidate = bool(suffix and first in {"self", "cls"} and class_name)
                scopes = owner.split(".")
                candidate = candidate or bool(
                    suffix
                    and any(
                        (path, ".".join(scopes[:size]), first) in self.instances
                        for size in range(len(scopes), -1, -1)
                    )
                )
            state = "syntactic_candidate" if candidate else "resolved_relationship"
            self.graph.edge(
                source,
                target,
                kind,
                self.side,
                self.ref(path, expression),
                state,
                expression_identity,
            )
            if candidate:
                changes = sorted(
                    set(self.graph.nodes[source]["source_obligations"])
                    | set(self.graph.nodes[target]["source_obligations"])
                )
                self.graph.boundary(
                    "dynamic_dispatch",
                    path,
                    self.side,
                    self.ref(path, expression),
                    (
                        "Establish the actual receiver, overrides "
                        "and mutation boundaries for "
                    )
                    + name
                    + (
                        "; the retained class endpoint is a "
                        "syntactic candidate, not a resolved runtime "
                        "target."
                    ),
                    changes,
                    consumer_id=target,
                    relationship=kind,
                    expression_identity=expression_identity,
                )
        else:
            self.graph.boundary(
                "unresolved_" + kind,
                path,
                self.side,
                self.ref(path, expression),
                "Resolve "
                + (name or "dynamic expression")
                + " and supply its contract or external-boundary evidence.",
                self.graph.nodes[target]["source_obligations"],
                consumer_id=target,
                relationship=kind,
                expression_identity=expression_identity,
            )
        return source

    def relationships(self) -> None:
        for path, node, owner, class_name in self.items:
            self.graph.step()
            if isinstance(node, ast.Call):
                name = _dotted(node.func) or ""
                kind = (
                    "registration"
                    if any(word in name.lower() for word in ("register", "registry"))
                    else "call"
                )
                self.connection(path, owner, class_name, node.func, kind)
                if kind == "registration":
                    for argument in node.args + [
                        keyword.value for keyword in node.keywords
                    ]:
                        if isinstance(argument, (ast.Name, ast.Attribute)):
                            self.connection(
                                path, owner, class_name, argument, "registration_input"
                            )
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local = alias.asname or (
                        alias.name.split(".")[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    self.connection(
                        path,
                        owner,
                        class_name,
                        ast.copy_location(ast.Name(id=local), node),
                        "import",
                    )
            elif isinstance(node, ast.ClassDef):
                derived = owner + "." + node.name if owner else node.name
                for base in node.bases:
                    base_id = self.connection(
                        path, derived, class_name, base, "inheritance"
                    )
                    if base_id:
                        base_node = self.graph.nodes[base_id]
                        for child in node.body:
                            if isinstance(
                                child, (ast.FunctionDef, ast.AsyncFunctionDef)
                            ):
                                overridden = self.definitions.get(
                                    (
                                        base_node["path"],
                                        base_node["symbol"] + "." + child.name,
                                    )
                                )
                                overriding = self.definitions.get(
                                    (path, derived + "." + child.name)
                                )
                                if overridden and overriding:
                                    self.graph.edge(
                                        overridden,
                                        overriding,
                                        "override",
                                        self.side,
                                        self.ref(path, child),
                                    )
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.AnnAssign, ast.Assign)
            ):
                annotation_owner = owner
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    annotation_owner = owner + "." + node.name if owner else node.name
                annotations: list[tuple[ast.AST, ast.AST, bool]] = []

                def append_type_comment(
                    value: str, mode: str, location: ast.AST
                ) -> None:
                    self.graph.step()
                    try:
                        parsed = ast.parse(value, mode=mode)
                    except (
                        SyntaxError,
                        ValueError,
                        TypeError,
                        RecursionError,
                        MemoryError,
                    ) as exc:
                        target = self.definitions.get(
                            (path, annotation_owner), self.file_nodes[path]
                        )
                        self.graph.boundary(
                            "unresolved_annotation",
                            path,
                            self.side,
                            self.ref(path, location),
                            (
                                "Parse the retained type comment and establish its "
                                "annotation relationships: " + type(exc).__name__
                            ),
                            self.graph.nodes[target]["source_obligations"],
                            consumer_id=target,
                            relationship="annotation",
                            expression_identity=_identifier("type-comment", value),
                        )
                        return
                    annotations.append((parsed, location, True))

                if isinstance(node, ast.AnnAssign):
                    annotations = [(node.annotation, node.annotation, False)]
                elif isinstance(node, ast.Assign):
                    if node.type_comment is not None:
                        append_type_comment(node.type_comment, "eval", node)
                else:
                    args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                    args += [arg for arg in (node.args.vararg, node.args.kwarg) if arg]
                    annotations = [
                        (arg.annotation, arg.annotation, False)
                        for arg in args
                        if arg.annotation is not None
                    ]
                    if node.returns is not None:
                        annotations.append((node.returns, node.returns, False))
                    for arg in args:
                        if arg.type_comment is not None:
                            append_type_comment(arg.type_comment, "eval", arg)
                    if node.type_comment is not None:
                        append_type_comment(node.type_comment, "func_type", node)
                for annotation, location, from_type_comment in annotations:
                    pending = [annotation]
                    while pending:
                        self.graph.step()
                        expression = pending.pop()
                        if isinstance(
                            expression, (ast.Name, ast.Attribute, ast.Constant)
                        ):
                            if from_type_comment:
                                expression = ast.copy_location(expression, location)
                            self.connection(
                                path,
                                annotation_owner,
                                class_name,
                                expression,
                                "annotation",
                            )
                        else:
                            pending.extend(ast.iter_child_nodes(expression))


def _propagate(graph: _Graph) -> None:
    callers: dict[str, list[dict[str, Any]]] = {}
    callees: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.edges.values():
        if edge["evidence_state"] != "resolved_relationship":
            continue
        callers.setdefault(edge["source"], []).append(edge)
        callees.setdefault(edge["target"], []).append(edge)
    for edges in list(callers.values()) + list(callees.values()):
        edges.sort(key=lambda row: row["id"])

    # Traverse the caller and callee cones independently. Crossing directions at
    # every reached node would turn one change into the whole connected import
    # component by pulling in a caller's unrelated dependencies and their callers.
    direct = {
        node["id"]: set(node["source_obligations"]) for node in graph.nodes.values()
    }
    reached = {
        "callers": {node_id: set(values) for node_id, values in direct.items()},
        "callees": {node_id: set(values) for node_id, values in direct.items()},
    }
    queued: set[tuple[str, str]] = set()
    queue: deque[tuple[str, str]] = deque()
    for node in sorted(graph.nodes.values(), key=lambda row: row["id"]):
        if node["source_obligations"]:
            for direction in ("callers", "callees"):
                item = (node["id"], direction)
                queue.append(item)
                queued.add(item)
    while queue:
        graph.step()
        current_id, direction = queue.popleft()
        queued.discard((current_id, direction))
        carried = reached[direction][current_id]
        adjacency = callers if direction == "callers" else callees
        for edge in adjacency.get(current_id, []):
            graph.step()
            edge_values = set(edge["source_obligations"]) | carried
            edge["source_obligations"] = sorted(edge_values)
            neighbor_id = (
                edge["target"] if direction == "callers" else edge["source"]
            )
            neighbor = graph.nodes[neighbor_id]
            neighbor_values = reached[direction][neighbor_id] | carried
            if neighbor_values != reached[direction][neighbor_id]:
                reached[direction][neighbor_id] = neighbor_values
                neighbor["source_obligations"] = sorted(
                    set(neighbor["source_obligations"]) | neighbor_values
                )
                item = (neighbor["id"], direction)
                if item not in queued:
                    queue.append(item)
                    queued.add(item)

    # A frontier inside a reached consumer remains a required UNKNOWN because
    # static syntax has not established its independence from the carried change.
    # Cross-snapshot recovery is narrower: it requires the same canonical
    # expression identity, not merely the same line span.
    counterparts: dict[tuple[str, str, str], set[str]] = {}
    for node in graph.nodes.values():
        graph.step()
        key = (node["path"], node["symbol"], node["node_kind"])
        counterparts.setdefault(key, set()).update(node["source_obligations"])
    edge_sites: dict[
        tuple[str, int, int, str, tuple[str, str, str], str], set[str]
    ] = {}
    for edge in graph.edges.values():
        graph.step()
        if edge["evidence_state"] != "resolved_relationship":
            continue
        ref = edge["source_ref"]
        consumer = graph.nodes[edge["target"]]
        consumer_key = (consumer["path"], consumer["symbol"], consumer["node_kind"])
        expression_identity = graph.edge_context.get(edge["id"])
        if expression_identity is None:
            continue
        key = (
            ref["path"],
            ref["start_line"],
            ref["end_line"],
            edge["relationship"],
            consumer_key,
            expression_identity,
        )
        edge_sites.setdefault(key, set()).update(edge["source_obligations"])
    for boundary_id, boundary in graph.frontier.items():
        graph.step()
        consumer_id, relationship, ref, expression_identity = graph.frontier_context.get(
            boundary_id, (None, None, None, None)
        )
        consumer = graph.nodes.get(consumer_id)
        values = set(boundary["source_obligations"])
        if consumer:
            values.update(consumer["source_obligations"])
            consumer_key = (consumer["path"], consumer["symbol"], consumer["node_kind"])
            if boundary["kind"] in {"parse_failure", "source_size_bound"}:
                values.update(counterparts.get(consumer_key, set()))
        if consumer and relationship and ref and expression_identity:
            consumer_key = (consumer["path"], consumer["symbol"], consumer["node_kind"])
            site = (
                ref["path"],
                ref["start_line"],
                ref["end_line"],
                relationship,
                consumer_key,
                expression_identity,
            )
            values.update(edge_sites.get(site, set()))
        boundary["source_obligations"] = sorted(values)


def _snapshot_completeness(
    graph: _Graph,
    before: dict[str, bytes],
    after: dict[str, bytes],
) -> None:
    """Refuse an internally contradictory before/after selection."""
    by_path: dict[str, list[dict[str, Any]]] = {}
    all_changes = sorted({str(row["id"]) for row in graph.changes})
    for row in graph.changes:
        by_path.setdefault(str(row.get("path", "")), []).append(row)

    def emit(side: str, path: str, changes: list[str], reason: str) -> None:
        graph.boundary(
            "incomplete_" + side + "_snapshot",
            path,
            side,
            None,
            reason,
            changes,
        )

    for path, rows in sorted(by_path.items()):
        identifiers = sorted({str(row["id"]) for row in rows})
        kinds = {row.get("kind") for row in rows}
        if "removed" not in kinds and path not in after:
            emit("after", path, identifiers, "The selected changed path is absent from the after snapshot.")
    for path in sorted(set(before) - set(after)):
        if not any(row.get("kind") == "removed" for row in by_path.get(path, [])):
            emit(
                "after",
                path,
                all_changes,
                "A before-snapshot path is missing after without a selected removal.",
            )


def _rows_digest(rows: list[dict[str, Any]]) -> str:
    """Digest exact canonical rows without retaining a second encoded aggregate."""
    state = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["id"]):
        encoded = json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        state.update(len(encoded).to_bytes(8, "big"))
        state.update(encoded)
    return state.hexdigest()


def _project_source_bound(graph: _Graph) -> dict[str, Any]:
    """Retain only changed-reachable materialized rows after complete discovery.

    Whole-source scanning is still required to discover callers when no separately
    authenticated relationship index exists.  The projection changes only emitted
    graph materialization: reached resolved relationships, their endpoints and
    ancestors, and reached or global-bound frontiers remain explicit.  Unrelated
    diagnostics are counted and digested rather than silently treated as proof of
    independence.
    """
    discovered = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "frontiers": len(graph.frontier),
    }
    graph.step(sum(discovered.values()))
    edge_ids = {
        key for key, row in graph.edges.items() if row["source_obligations"]
    }
    frontier_ids = {
        key
        for key, row in graph.frontier.items()
        if row["source_obligations"] or row["kind"].endswith("_bound")
    }
    node_ids = {
        key for key, row in graph.nodes.items() if row["source_obligations"]
    }
    for key in edge_ids:
        row = graph.edges[key]
        node_ids.update((row["source"], row["target"]))
    for key in frontier_ids:
        consumer_id = graph.frontier[key].get("consumer_id")
        if consumer_id in graph.nodes:
            node_ids.add(consumer_id)

    pending = list(node_ids)
    while pending:
        node_id = pending.pop()
        parent = graph.nodes[node_id].get("parent")
        if parent and parent not in node_ids:
            graph.step()
            node_ids.add(parent)
            pending.append(parent)

    omitted_nodes = [row for key, row in graph.nodes.items() if key not in node_ids]
    omitted_edges = [row for key, row in graph.edges.items() if key not in edge_ids]
    omitted_frontiers = [
        row for key, row in graph.frontier.items() if key not in frontier_ids
    ]
    frontier_kinds: dict[str, int] = {}
    for row in omitted_frontiers:
        kind = str(row["kind"])
        frontier_kinds[kind] = frontier_kinds.get(kind, 0) + 1

    graph.nodes = {key: graph.nodes[key] for key in node_ids}
    graph.edges = {key: graph.edges[key] for key in edge_ids}
    graph.frontier = {key: graph.frontier[key] for key in frontier_ids}
    graph.edge_context = {
        key: value for key, value in graph.edge_context.items() if key in edge_ids
    }
    graph.frontier_context = {
        key: value for key, value in graph.frontier_context.items() if key in frontier_ids
    }
    return {
        "status": (
            "UNKNOWN" if discovered["frontiers"] else "BOUNDED_ANALYSIS_COMPLETE"
        ),
        "discovered_nodes": discovered["nodes"],
        "discovered_edges": discovered["edges"],
        "discovered_frontiers": discovered["frontiers"],
        "omitted_nodes": len(omitted_nodes),
        "omitted_edges": len(omitted_edges),
        "omitted_frontiers": len(omitted_frontiers),
        "omitted_frontier_kinds": [
            {"kind": kind, "count": count}
            for kind, count in sorted(frontier_kinds.items())
        ],
        "omitted_frontier_digest": _rows_digest(omitted_frontiers),
    }


def _intern_source_obligations(result: dict[str, Any]) -> None:
    """Intern repeated selected-change sets in a version-two graph."""
    sets: dict[str, list[str]] = {}
    for name in ("nodes", "edges", "obligations", "frontier"):
        for row in result[name]:
            values = sorted(set(row.pop("source_obligations", [])))
            identifier = _identifier("source-set", values)
            sets[identifier] = values
            row["source_obligation_set_id"] = identifier
    result["source_obligation_sets"] = [
        {"id": identifier, "source_obligations": values}
        for identifier, values in sorted(sets.items())
    ]


def _condense(graph: _Graph) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Iterative SCC condensation retains all original edges, including cycles."""
    adjacency: dict[str, list[str]] = {key: [] for key in graph.nodes}
    reverse: dict[str, list[str]] = {key: [] for key in graph.nodes}
    for edge in graph.edges.values():
        adjacency[edge["source"]].append(edge["target"])
        reverse[edge["target"]].append(edge["source"])
    seen: set[str] = set()
    order: list[str] = []
    for initial in sorted(adjacency):
        stack = [(initial, False)]
        while stack:
            graph.step()
            node, complete = stack.pop()
            if complete:
                order.append(node)
            elif node not in seen:
                seen.add(node)
                stack.append((node, True))
                stack.extend(
                    (child, False)
                    for child in sorted(set(adjacency[node]), reverse=True)
                    if child not in seen
                )
    components: list[dict[str, Any]] = []
    owner: dict[str, str] = {}
    for initial in reversed(order):
        if initial in owner:
            continue
        members: list[str] = []
        pending = [initial]
        temporary: set[str] = set()
        while pending:
            graph.step()
            node = pending.pop()
            if node in owner or node in temporary:
                continue
            temporary.add(node)
            members.append(node)
            pending.extend(reverse[node])
        members.sort()
        key = _identifier("component", members)
        components.append(
            {
                "id": key,
                "members": members,
                "cyclic": len(members) > 1
                or any(node in adjacency[node] for node in members),
            }
        )
        owner.update((node, key) for node in members)
    dag: dict[tuple[str, str], list[str]] = {}
    for edge in graph.edges.values():
        graph.step()
        pair = (owner[edge["source"]], owner[edge["target"]])
        if pair[0] != pair[1]:
            dag.setdefault(pair, []).append(edge["id"])
    return sorted(components, key=lambda item: item["id"]), [
        {"source": source, "target": target, "edge_ids": sorted(ids)}
        for (source, target), ids in sorted(dag.items())
    ]


# vstd-explanation: begin prdel.self.prdel-graph
# Authored intent (not verified):
#   Retain syntactic relationships and unresolved consumers for the exact selected
# changes.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): Resolved syntax does not establish runtime compatibility or complete
# consumer discovery.
# vstd-explanation: end prdel.self.prdel-graph
def _build_impact_graph(
    before: dict[str, bytes],
    after: dict[str, bytes],
    changes: list[dict[str, Any]],
    *,
    max_nodes: int = 10000,
    max_edges: int = 20000,
    max_operations: int = 200000,
    source_bound: bool = False,
    max_output_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Index exact snapshots without importing them; unresolved relationships stay open.

    Changes carry id/path/old_range/new_range. Edges point from dependencies to
    consumers; before and after remain distinct. Operation counts bound explicit
    traversal work, while the parse-size bound is max_operations * 64 bytes/file.
    Neither bound is a wall-clock, memory, semantic, or runtime correctness proof.
    """
    limits = {
        "max_nodes": max_nodes,
        "max_edges": max_edges,
        "max_operations": max_operations,
    }
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 1
        for value in limits.values()
    ):
        raise ValueError("Graph bounds must be positive integers.")
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes < 1
    ):
        raise ValueError("Graph output bound must be a positive integer.")
    graph = _Graph(changes, limits)
    _snapshot_completeness(graph, before, after)
    components: list[dict[str, Any]] = []
    dag_edges: list[dict[str, Any]] = []
    projection: dict[str, Any] | None = None
    phase = {
        "before_index": False,
        "after_index": False,
        "before_relationships": False,
        "after_relationships": False,
        "propagation": False,
        "projection": False,
        "condensation": False,
    }
    try:
        snapshots: list[_Snapshot] = []
        for side, files in (("before", before), ("after", after)):
            snapshot = _Snapshot(graph, files, side)
            snapshot.index()
            phase[side + "_index"] = True
            snapshots.append(snapshot)
        for snapshot in snapshots:
            snapshot.relationships()
            phase[snapshot.side + "_relationships"] = True
        _propagate(graph)
        phase["propagation"] = True
        if source_bound:
            projection = _project_source_bound(graph)
            phase["projection"] = True
        components, dag_edges = _condense(graph)
        phase["condensation"] = True
    except _Limit:
        graph.incomplete = True
        graph.boundary(
            "analysis_bound",
            "",
            "both",
            None,
            (
                "Analysis stopped at a declared bound; omitted "
                "relationships and condensation remain unresolved."
            ),
        )
        selected = sorted({str(change["id"]) for change in changes})
        if not phase["after_index"]:
            graph.boundary(
                "analysis_bound",
                "",
                "after",
                None,
                (
                    "The after snapshot was not completely indexed before the "
                    "declared analysis bound; omitted current-source relationships "
                    "remain UNKNOWN."
                ),
                changes=selected,
            )
        elif not phase["after_relationships"]:
            graph.boundary(
                "analysis_bound",
                "",
                "after",
                None,
                (
                    "The after-snapshot relationship phase did not complete before "
                    "the declared analysis bound."
                ),
                changes=selected,
            )
        elif (
            not phase["propagation"]
            or (source_bound and not phase["projection"])
            or not phase["condensation"]
        ):
            graph.boundary(
                "analysis_bound",
                "",
                "both",
                None,
                (
                    "Reachability propagation, source-bound projection or "
                    "condensation did not complete; "
                    "the selected impact scope remains UNKNOWN."
                ),
                changes=selected,
            )
    obligations = []
    for edge in sorted(graph.edges.values(), key=lambda item: item["id"]):
        if (
            not edge["source_obligations"]
            or edge["evidence_state"] != "resolved_relationship"
        ):
            continue
        source, target = graph.nodes[edge["source"]], graph.nodes[edge["target"]]
        obligations.append(
            {
                "id": _identifier("contract", edge["id"]),
                "kind": "contract",
                "path": target["path"],
                "source_obligations": edge["source_obligations"],
                "endpoints": [edge["source"], edge["target"]],
                "edge_id": edge["id"],
                "question": "Explain the "
                + edge["relationship"]
                + " contract from "
                + source["path"]
                + ":"
                + source["symbol"]
                + " to "
                + target["path"]
                + ":"
                + target["symbol"]
                + ", including compatibility, invariants and impacted behavior.",
                ("evidence_requirement"): (
                    "Bind relevant executed producer/consumer and "
                    "negative-case evidence; syntax does not "
                    "establish the invariant."
                ),
            }
        )

    def digest(files: dict[str, bytes]) -> str:
        return hashlib.sha256(
            json.dumps(
                [
                    [path, hashlib.sha256(data).hexdigest()]
                    for path, data in sorted(files.items())
                ],
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    result = {
        "schema_version": "verifier-prdel-impact-1",
        "status": (
            "UNKNOWN"
            if graph.incomplete or graph.frontier
            else "BOUNDED_ANALYSIS_COMPLETE"
        ),
        "snapshot_digests": {"before": digest(before), "after": digest(after)},
        "nodes": sorted(graph.nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(graph.edges.values(), key=lambda item: item["id"]),
        "obligations": obligations,
        "frontier": sorted(graph.frontier.values(), key=lambda item: item["id"]),
        "components": components,
        "dag_edges": dag_edges,
        "bounds": limits,
        "counters": {
            "operations": graph.operations,
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
        },
        "limits": [
            "No source execution; syntax is not verified contract evidence.",
            (
                "Dynamic, external and unsupported-language "
                "relationships require additional evidence."
            ),
            (
                "Traversal and parse bounds do not establish "
                "complete runtime impact or correctness."
            ),
        ],
    }
    if not source_bound:
        return result

    def minimal_source_bound(
        kind: str,
        question: str,
        diagnostics: dict[str, Any] | None,
        attempted_output_bytes: int | None = None,
    ) -> dict[str, Any]:
        selected = sorted({str(change["id"]) for change in changes})
        source_set_id = _identifier("source-set", selected)
        diagnostic = diagnostics or {
            "status": "UNKNOWN",
            "discovered_nodes": len(graph.nodes),
            "discovered_edges": len(graph.edges),
            "discovered_frontiers": len(graph.frontier),
            "omitted_nodes": len(graph.nodes),
            "omitted_edges": len(graph.edges),
            "omitted_frontiers": len(graph.frontier),
            "omitted_frontier_kinds": [],
            "omitted_frontier_digest": _rows_digest(list(graph.frontier.values())),
        }
        counters: dict[str, Any] = {
            "operations": graph.operations,
            "nodes": 0,
            "edges": 0,
            "discovered_nodes": diagnostic["discovered_nodes"],
            "discovered_edges": diagnostic["discovered_edges"],
            "discovered_frontiers": diagnostic["discovered_frontiers"],
        }
        if attempted_output_bytes is not None:
            counters["attempted_output_bytes"] = attempted_output_bytes
        return {
            "schema_version": "verifier-prdel-impact-2",
            "projection": "changed_source_bound",
            "status": "UNKNOWN",
            "snapshot_digests": {"before": digest(before), "after": digest(after)},
            "source_obligation_sets": [
                {"id": source_set_id, "source_obligations": selected}
            ],
            "nodes": [],
            "edges": [],
            "obligations": [],
            "frontier": [
                {
                    "id": _identifier("frontier", kind, "both", question),
                    "kind": kind,
                    "path": "",
                    "side": "both",
                    "source_ref": None,
                    "question": question,
                    "consumer_id": None,
                    "source_obligation_set_id": source_set_id,
                }
            ],
            "components": [],
            "dag_edges": [],
            "whole_estate_diagnostics": diagnostic,
            "bounds": {**limits, "max_output_bytes": max_output_bytes},
            "counters": counters,
            "limits": [
                "No source execution; syntax is not verified contract evidence.",
                (
                    "Incomplete discovery or materialization retains every selected "
                    "change as UNKNOWN; no partial graph is a completeness claim."
                ),
                (
                    "max_output_bytes bounds the attempted materialized projection; "
                    "the minimal UNKNOWN receipt retains every selected change and "
                    "is never truncated merely to fit that projection bound."
                ),
            ],
        }

    if projection is None:
        return minimal_source_bound(
            "analysis_bound",
            (
                "Source discovery, relationship analysis or projection stopped at a "
                "declared bound; every selected change remains UNKNOWN."
            ),
            None,
        )

    result["schema_version"] = "verifier-prdel-impact-2"
    result["projection"] = "changed_source_bound"
    result["whole_estate_diagnostics"] = projection
    result["bounds"] = {**limits, "max_output_bytes": max_output_bytes}
    result["counters"].update(
        {
            "discovered_nodes": projection["discovered_nodes"],
            "discovered_edges": projection["discovered_edges"],
            "discovered_frontiers": projection["discovered_frontiers"],
        }
    )
    result["limits"].extend(
        [
            (
                "The source-bound result materializes only changed-reachable syntax; "
                "omitted whole-estate diagnostics are counted and digested, not "
                "treated as verified independence."
            ),
            (
                "Whole-source scanning is still required to discover callers without "
                "an independently authenticated relationship index."
            ),
        ]
    )
    _intern_source_obligations(result)
    result["counters"]["materialized_bytes"] = 0
    attempted = 0
    for _ in range(8):
        attempted = len(
            json.dumps(
                result, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        )
        if result["counters"]["materialized_bytes"] == attempted:
            break
        result["counters"]["materialized_bytes"] = attempted
    else:
        raise AssertionError("canonical materialized size did not stabilize")
    if attempted > max_output_bytes:
        return minimal_source_bound(
            "output_bound",
            (
                "The source-bound impact payload exceeded the declared output bound; "
                "split the selected scope or raise the bound and rerun."
            ),
            projection,
            attempted,
        )
    return result


def build_impact_graph(
    before: dict[str, bytes],
    after: dict[str, bytes],
    changes: list[dict[str, Any]],
    *,
    max_nodes: int = 10000,
    max_edges: int = 20000,
    max_operations: int = 200000,
) -> dict[str, Any]:
    """Build the byte-compatible whole-estate version-one impact graph."""
    return _build_impact_graph(
        before,
        after,
        changes,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_operations=max_operations,
    )


def build_source_bound_impact_graph(
    before: dict[str, bytes],
    after: dict[str, bytes],
    changes: list[dict[str, Any]],
    *,
    max_nodes: int = 10000,
    max_edges: int = 20000,
    max_operations: int = 200000,
    max_output_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Build an opt-in version-two changed-source-bound impact projection.

    This function does not change the version-one generator or claim that omitted
    whole-estate diagnostics are independent of selected changes.  Any incomplete
    discovery, projection, condensation or output phase remains source-bound
    ``UNKNOWN``.
    """
    return _build_impact_graph(
        before,
        after,
        changes,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_operations=max_operations,
        source_bound=True,
        max_output_bytes=max_output_bytes,
    )
