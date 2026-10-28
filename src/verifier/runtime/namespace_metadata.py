"""Closed dependency-data reads for Verifier Standard (VSTD) discovery.

The abstract syntax tree (AST) binds reader imports, finite package selection and
every use of a local distribution. Nothing imports the subject or queries its
environment. This is source-shape evidence, not import success, installed-package
authenticity, absence of host finder hooks or a general alias/reachability proof.
"""
from __future__ import annotations

import ast
from typing import Any


def _chain(node: ast.AST) -> tuple[str, ...]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return (node.id, *reversed(parts)) if isinstance(node, ast.Name) else ()


def _writes(nodes: list[ast.AST]) -> dict[str, list[ast.AST]]:
    result: dict[str, list[ast.AST]] = {}
    for node in nodes:
        names = []
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            names = [node.id]
        elif isinstance(node, ast.arg):
            names = [node.arg]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)
                     for alias in node.names]
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names = node.names
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names = [node.name]
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names = [node.rest]
        elif type(node).__name__ in {'TypeVar', 'ParamSpec', 'TypeVarTuple'}:
            # These named binders exist on newer supported parsers without
            # appearing as Name(Store) or argument nodes. Do not confuse their
            # scoped value with a same-spelled imported metadata reader.
            names = [node.name]
        for name in names:
            result.setdefault(name, []).append(node)
    return result


def _scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST:
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                             ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            break
    return node


def inventory_inspections(tree: ast.Module, nodes: list[ast.AST],
                          parents: dict[ast.AST, ast.AST]) -> set[ast.AST]:
    """Return only the exact reader references justified by the closed grammar."""
    readers: dict[tuple[str, ...], tuple[str, ast.AST]] = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and not statement.level:
            for alias in statement.names:
                if statement.module == 'importlib.metadata' and alias.name in {
                        'version', 'distribution', 'requires'}:
                    readers[(alias.asname or alias.name,)] = (alias.name, statement)
                elif statement.module == 'importlib' and alias.name == 'metadata':
                    for name in ('version', 'distribution', 'requires', 'PackageNotFoundError'):
                        readers[(alias.asname or alias.name, name)] = (name, statement)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in {'importlib', 'importlib.metadata'}:
                    prefix = ((alias.asname,) if alias.asname and alias.name == 'importlib.metadata'
                              else (alias.asname or 'importlib', 'metadata'))
                    for name in ('version', 'distribution', 'requires', 'PackageNotFoundError'):
                        readers[(*prefix, name)] = (name, statement)
    if not readers:
        return set()
    writes = _writes(nodes)
    # Replacing a reader or an allowed distribution member invalidates its local
    # standard-library meaning; this check deliberately does not guess aliases.
    if any(isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))
           and node.attr in {'version', 'distribution', 'requires', 'files', 'locate_file'} for node in nodes):
        return set()
    loads: dict[str, list[ast.Name]] = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loads.setdefault(node.id, []).append(node)

    def literal(node: ast.AST) -> Any:
        parts = list(ast.walk(node))
        if len(parts) > 1024 or any(not isinstance(part, (ast.Dict, ast.Tuple, ast.List, ast.Constant, ast.Load))
                                    or isinstance(part, ast.Constant) and type(part.value) is not str for part in parts):
            raise ValueError('Unbounded metadata selector')
        return ast.literal_eval(node)

    def table(node: ast.AST) -> dict[str, Any] | None:
        if not isinstance(node, ast.Name) or len(writes.get(node.id, [])) != 1:
            return None
        target = writes[node.id][0]
        assignment = parents.get(target)
        if (not isinstance(assignment, ast.Assign) or assignment.targets != [target]
                or parents.get(assignment) is not tree or assignment.lineno >= node.lineno):
            return None
        try:
            value = literal(assignment.value)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            return None
        if (type(value) is not dict or not value or len(value) > 256
                or any(type(key) is not str or not (type(item) is str or type(item) is tuple
                       and all(type(part) is str for part in item)) for key, item in value.items())):
            return None
        # A literal outer dictionary does not make nested lists immutable. Only
        # strings/tuples of strings can bound selection without alias tracking.
        for reference in loads.get(node.id, []):
            parent = parents.get(reference)
            call = parents.get(parent)
            indexed = isinstance(parent, ast.Subscript) and parent.value is reference and isinstance(parent.ctx, ast.Load)
            membership = isinstance(parent, ast.Compare) and all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
            outer = parents.get(call)
            items = (isinstance(parent, ast.Attribute) and parent.value is reference and parent.attr == 'items'
                     and isinstance(call, ast.Call) and call.func is parent and not call.args and not call.keywords
                     and isinstance(outer, ast.For) and outer.iter is call)
            copied_keys = (
                isinstance(parent, ast.Call)
                and parent.args == [reference]
                and not parent.keywords
                and isinstance(parent.func, ast.Name)
                and parent.func.id == 'set'
                and not writes.get('set')
            )
            if not (indexed or membership or items or copied_keys):
                return None  # A copied, passed, mutated or otherwise escaped table is not finite evidence.
        return value

    def rows(node: ast.AST) -> list[Any] | None:
        if isinstance(node, (ast.List, ast.Tuple)):
            result = []
            for member in node.elts:
                if isinstance(member, ast.Starred):
                    selected = rows(member.value)
                    if selected is None:
                        return None
                    result.extend(selected)
                else:
                    try:
                        result.append(literal(member))
                    except (ValueError, TypeError, SyntaxError, RecursionError):
                        return None
            return result if len(result) <= 256 else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'items' and not node.args and not node.keywords:
            selected = table(node.func.value)
            return list(selected.items()) if selected is not None else None
        if isinstance(node, ast.GeneratorExp) and len(node.generators) == 1:
            generator = node.generators[0]
            if (not generator.is_async and isinstance(generator.target, ast.Name)
                    and isinstance(node.elt, ast.Subscript) and isinstance(node.elt.slice, ast.Name)
                    and node.elt.slice.id == generator.target.id and not generator.ifs):
                selected = table(node.elt.value)
                return list(selected.values()) if selected is not None else None
        return None

    def package_argument(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return type(node.value) is str
        if not isinstance(node, ast.Name):
            return False
        child = node
        while child in parents:
            loop = parents[child]
            if isinstance(loop, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                break
            if isinstance(loop, ast.For) and child in loop.body:
                local_writes = [item for item in writes.get(node.id, [])
                                if _scope(item, parents) is _scope(node, parents)]
                selected = rows(loop.iter)
                # A scalar target over a finite literal sequence is the same
                # bounded package selection as one column of a literal row.
                # Exact local-write identity prevents post-loop or nested
                # rebinding from borrowing that proof.
                if isinstance(loop.target, ast.Name) and loop.target.id == node.id:
                    return ((local_writes == [loop.target]
                             or writes.get(node.id, []) == [loop.target]) and bool(selected)
                            and all(type(row) is str for row in selected))
                if isinstance(loop.target, (ast.Tuple, ast.List)):
                    targets = loop.target.elts
                    matches = [index for index, target in enumerate(targets)
                               if isinstance(target, ast.Name) and target.id == node.id]
                    if len(matches) == 1 and all(isinstance(target, ast.Name) for target in targets):
                        index = matches[0]
                        return ((local_writes == [targets[index]]
                                 or writes.get(node.id, []) == [targets[index]]) and bool(selected)
                                and all(type(row) in (tuple, list) and len(row) == len(targets)
                                        and type(row[index]) is str for row in selected))
            child = loop
        return False

    def data_use(value: ast.AST) -> bool:
        member = parents.get(value)
        call = parents.get(member)
        if not isinstance(member, ast.Attribute) or member.value is not value or not isinstance(member.ctx, ast.Load):
            return False
        if member.attr in {'version', 'files'}:
            return not (isinstance(call, ast.Call) and call.func is member)
        if member.attr == 'metadata':
            getter = call
            invocation = parents.get(getter)
            return (isinstance(getter, ast.Attribute) and getter.value is member
                    and getter.attr == 'get' and isinstance(invocation, ast.Call)
                    and invocation.func is getter and len(invocation.args) == 1
                    and isinstance(invocation.args[0], ast.Constant)
                    and type(invocation.args[0].value) is str
                    and not invocation.keywords)
        return (member.attr == 'locate_file' and isinstance(call, ast.Call) and call.func is member
                and len(call.args) == 1 and not isinstance(call.args[0], ast.Starred) and not call.keywords)

    permitted: set[ast.AST] = set()
    for reference in nodes:
        path = _chain(reference)
        selected = readers.get(path)
        if not selected or len(writes.get(path[0], [])) != 1:
            continue
        operation, statement = selected
        if reference.lineno <= statement.lineno:
            continue
        call = parents.get(reference)
        allowed = False
        if operation == 'PackageNotFoundError':
            parent = parents.get(call) if isinstance(call, ast.Tuple) else call
            allowed = isinstance(parent, ast.ExceptHandler) and parent.type in (call, reference)
        elif (isinstance(call, ast.Call) and call.func is reference and len(call.args) == 1
              and not call.keywords and package_argument(call.args[0])):
            allowed = operation in {'version', 'requires'} or data_use(call)
            assignment = parents.get(call)
            if (not allowed and isinstance(assignment, ast.Assign) and assignment.value is call
                    and len(assignment.targets) == 1 and isinstance(assignment.targets[0], ast.Name)
                    and isinstance(_scope(assignment, parents), (ast.FunctionDef, ast.AsyncFunctionDef))):
                name = assignment.targets[0].id
                uses = loads.get(name, [])
                allowed = len(writes.get(name, [])) == 1 and bool(uses) and all(
                    use.lineno > assignment.lineno and _scope(use, parents) is _scope(assignment, parents)
                    and data_use(use) for use in uses)
        if allowed:
            # Mark this exact chain only. Another reference to the same imported
            # module can still expose a loader, reflection or an escaped reader.
            permitted.add(reference)
            while isinstance(reference, ast.Attribute):
                reference = reference.value
                permitted.add(reference)
    return permitted
