"""Non-executing Python export bindings for Verifier Standard (VSTD) admission.

An abstract syntax tree (AST) proves a declared source binding, not successful
import, runtime confinement or arbitrary future monkey-patching. Literal exports
and a closed lazy-dispatch grammar are supported. Unresolved targets, mutation,
ambiguous modules and other dispatch programs remain explicit discovery gaps.
"""
from __future__ import annotations

import ast
from pathlib import PurePosixPath
from typing import Any

from verifier.runtime.namespace_metadata import inventory_inspections


_DISPATCH = '''def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value
'''
_DEPRECATION = '''deprecation = _API_DEPRECATIONS.get(name)
if deprecation is not None:
    since, replacement = deprecation
    warnings.warn(
        f"verifier.{name} is deprecated since {since}; use {replacement}",
        DeprecationWarning, stacklevel=2)
'''
_DIRECTORY = '''def __dir__():
    return sorted(set(globals()) | set(__all__))
'''


def _shape(node: ast.AST | None) -> str:
    return ast.dump(node, include_attributes=False) if node is not None else "None"


def _body(function: ast.FunctionDef) -> list[str]:
    return [_shape(node) for node in function.body]


def _literal(node: ast.AST | None) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return None


def _names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for child in target.elts for name in _names(child)]
    return []


def _deferred_annotations(tree: ast.Module) -> bool:
    return any(isinstance(node, ast.ImportFrom) and node.module == "__future__"
               and any(alias.name == "annotations" for alias in node.names) for node in tree.body)


def _signature(function: ast.FunctionDef, names: tuple[str, ...], deferred: bool) -> bool:
    """Defaults/decorators execute during definition; annotations may too."""
    args = function.args
    annotations = [function.returns, *(arg.annotation for arg in args.args)]
    return (not function.decorator_list and tuple(arg.arg for arg in args.args) == names
            and not (args.posonlyargs or args.kwonlyargs or args.defaults or args.vararg or args.kwarg)
            and (deferred or all(node is None or isinstance(node, (ast.Name, ast.Constant)) for node in annotations)))


def _read_only_namespace_call(call: ast.Call,
                              parents: dict[ast.AST, ast.AST]) -> bool:
    """Accept a namespace view only when syntax cannot mutate or return it.

    Membership, comparison and fixed read methods inspect data. Keyword
    expansion makes a new argument mapping. A raw mapping, subscript, update,
    assignment, return or arbitrary-call argument remains dynamic.
    """
    if not isinstance(call.func, ast.Name) or call.func.id not in {"globals", "locals", "vars"}:
        return False
    if call.keywords or (call.func.id in {"globals", "locals"} and call.args) \
            or (call.func.id == "vars" and len(call.args) != 1):
        return False
    def fixed_comparison(compare: ast.Compare, value: ast.AST) -> bool:
        """Prove that ``value`` is inspected against fixed syntax, not escaped.

        Equality is restricted to literal mappings because a runtime-selected
        peer can receive the namespace through reflected ``__eq__``. Membership
        is accepted only for a literal key looked up in the namespace view.
        Identity against ``None`` cannot invoke user code.
        """
        if len(compare.ops) != 1 or len(compare.comparators) != 1:
            return False
        left, operation, right = compare.left, compare.ops[0], compare.comparators[0]
        if isinstance(operation, (ast.In, ast.NotIn)):
            return (right is value and isinstance(left, ast.Constant)
                    and type(left.value) is str)
        if isinstance(operation, (ast.Is, ast.IsNot)):
            other = right if left is value else left if right is value else None
            return isinstance(other, ast.Constant) and other.value is None
        if not isinstance(operation, (ast.Eq, ast.NotEq)) or left is not value:
            return False
        try:
            return isinstance(ast.literal_eval(right), dict)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            return False

    parent = parents.get(call)
    if isinstance(parent, ast.Compare):
        return fixed_comparison(parent, call)
    if isinstance(parent, (ast.BoolOp, ast.UnaryOp)):
        return True
    if isinstance(parent, ast.Attribute) and parent.value is call \
            and parent.attr in {"copy", "get", "items", "keys", "values"}:
        invocation = parents.get(parent)
        if not isinstance(invocation, ast.Call) or invocation.func is not parent \
                or invocation.keywords:
            return False
        if parent.attr == "get":
            return (1 <= len(invocation.args) <= 2
                    and isinstance(invocation.args[0], ast.Constant)
                    and type(invocation.args[0].value) is str)
        if invocation.args:
            return False
        if parent.attr == "copy":
            use = parents.get(invocation)
            if isinstance(use, ast.Compare):
                return fixed_comparison(use, invocation)
            if isinstance(use, (ast.Assign, ast.AnnAssign)):
                targets = use.targets if isinstance(use, ast.Assign) else [use.target]
                if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                    return False
                owner = parents.get(use)
                if not isinstance(owner, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
                    return False
                alias = targets[0].id
                loads = [node for node in ast.walk(owner) if isinstance(node, ast.Name)
                         and node.id == alias and isinstance(node.ctx, ast.Load)]
                return bool(loads) and all(
                    isinstance(parents.get(node), ast.Compare)
                    and fixed_comparison(parents[node], node) for node in loads)
            return False
        view = parents.get(invocation)
        if not isinstance(view, ast.comprehension) or view.iter is not invocation:
            return False
        owner = parents.get(view)
        if not isinstance(owner, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return False
        targets = (list(view.target.elts) if isinstance(view.target, (ast.Tuple, ast.List))
                   else [view.target])
        names = {target.id for target in targets if isinstance(target, ast.Name)}
        if len(names) != len(targets):
            return False
        for node in ast.walk(owner):
            if not isinstance(node, ast.Name) or node.id not in names \
                    or not isinstance(node.ctx, ast.Load):
                continue
            use = parents.get(node)
            if not isinstance(use, ast.Compare) or not fixed_comparison(use, node):
                return False
        return True
    return False


def _has_module_registry_reference(tree: ast.Module, nodes: list[ast.AST],
                                   permitted: set[ast.AST]) -> bool:
    """The process module registry is always a runtime-selected namespace."""
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    sys_names = {alias.asname or "sys" for node in nodes if isinstance(node, ast.Import)
                 for alias in node.names if alias.name == "sys"}
    direct = {alias.asname or alias.name for node in nodes if isinstance(node, ast.ImportFrom)
              and node.level == 0 and node.module == "sys" for alias in node.names
              if alias.name == "modules"}

    # A test can make one exact module unavailable without installing or
    # constructing an interface.  Accept only ``setitem(registry, literal,
    # None)``: a computed key, non-None value, direct assignment, deletion or
    # registry escape still has the ordinary unresolved result.  The call's
    # receiver is intentionally irrelevant; even a hostile receiver cannot use
    # the referenced registry value because the registry is only the fixed
    # first argument and no construction capability is exempted here.
    for node in nodes:
        if not (isinstance(node, ast.Attribute) and node.attr == "modules"
                and isinstance(node.value, ast.Name) and node.value.id in sys_names):
            continue
        call = parents.get(node)
        if not (isinstance(call, ast.Call) and len(call.args) == 3
                and call.args[0] is node and not call.keywords
                and isinstance(call.func, ast.Attribute) and call.func.attr == "setitem"
                and isinstance(call.args[1], ast.Constant)
                and isinstance(call.args[1].value, str) and call.args[1].value
                and isinstance(call.args[2], ast.Constant) and call.args[2].value is None):
            continue
        permitted.add(node)
    return any(node not in permitted and (
               (isinstance(node, ast.Attribute) and node.attr == "modules"
                and isinstance(node.value, ast.Name) and node.value.id in sys_names)
               or (isinstance(node, ast.Name) and node.id in direct
                   and isinstance(node.ctx, (ast.Load, ast.Store, ast.Del))))
               for node in nodes)


def _closed_lazy(tree: ast.Module, assignments: dict[str, list[ast.AST]], bindings: dict[str, list[dict[str, Any]]]) -> bool:
    """Recognize one inspectable program; a table name is never a waiver.

Every reference to its mutable tables must occur inside the accepted statements.
This rejects aliases, updates, later rebinding and escapes to arbitrary calls.
    Evaluated annotations, decorators and argument defaults cannot be alternate
    mutation paths. Postponed annotations are inert at definition time only.
"""
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "__getattr__"]
    if (len(functions) != 1 or len(bindings.get("__getattr__", [])) != 1
            or len(assignments.get("_LAZY_EXPORTS", [])) != 1):
        return False
    function = functions[0]
    deferred = _deferred_annotations(tree)
    if not _signature(function, ("name",), deferred):
        return False
    expected = _body(ast.parse(_DISPATCH).body[0])
    actual = _body(function)
    ordinary = actual == expected
    deprecation = actual == expected[:2] + [_shape(node) for node in ast.parse(_DEPRECATION).body] + expected[2:]
    if not ordinary and not deprecation:
        return False
    if deprecation and (len(assignments.get("_API_DEPRECATIONS", [])) != 1
                        or _literal(assignments["_API_DEPRECATIONS"][0]) != {}):
        return False  # Nonempty warnings can invoke arbitrary configured handlers.
    imported = bindings.get("import_module", [])
    if imported != [{"kind": "import", "module": "importlib", "name": "import_module", "level": 0}]:
        return False
    if any(name in bindings for name in ("list", "getattr", "globals", "AttributeError")):
        return False
    accepted = set(ast.walk(function))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and targets[0].id in {
                    "_LAZY_EXPORTS", "_API_DEPRECATIONS", "__all__"}:
                if isinstance(node, ast.AnnAssign) and not deferred and not isinstance(node.annotation, (ast.Name, ast.Constant)):
                    return False
                accepted.update(ast.walk(node))
        if isinstance(node, ast.FunctionDef) and node.name == "__dir__":
            if not _signature(node, (), deferred) or _body(node) != _body(ast.parse(_DIRECTORY).body[0]):
                return False
            accepted.update(ast.walk(node))
    return all(node in accepted for node in ast.walk(tree) if isinstance(node, ast.Name)
               and node.id in {"_LAZY_EXPORTS", "_API_DEPRECATIONS"})


def summarize(path: str, tree: ast.Module, definitions: list[dict[str, Any]]) -> dict[str, Any]:
    """Retain compact source bindings, not every module's full syntax tree."""
    bindings: dict[str, list[dict[str, Any]]] = {}
    deferred = _deferred_annotations(tree)
    assignments: dict[str, list[ast.AST]] = {}
    root_surface = definitions[0]
    definitions_by_name = {row["surface_id"].split(":", 2)[-1]: row for row in definitions}

    def add(name: str, binding: dict[str, Any]) -> None:
        bindings.setdefault(name, []).append(binding)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name, {"kind": "local", "surface": definitions_by_name[node.name]})
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                add(alias.asname or alias.name, {"kind": "import", "module": node.module or "",
                    "name": alias.name, "level": node.level})
        elif isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.asname or alias.name.split(".")[0], {"kind": "unresolved"})
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _names(target):
                    assignments.setdefault(name, []).append(node.value)
                    binding = {"kind": "local", "surface": {**root_surface,
                        "surface_id": "python-binding:" + path + ":" + name,
                        "line": node.lineno, "form": "Binding"}} if node.value is not None else {"kind": "unresolved"}
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Name):
                        binding = {"kind": "alias", "name": node.value.id}
                    add(name, binding)
    # Conditional/repeated module bindings are not the unconditional target.
    # TYPE_CHECKING imports are the one recognized non-runtime branch; its
    # imported name must itself have exactly one unshadowed stdlib binding.
    conditional_exports = False
    pending = []
    for node in tree.body:
        if isinstance(node, (ast.If, ast.Try, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            typing_guard = (isinstance(node, ast.If) and _shape(node.test) == _shape(ast.Name(id="TYPE_CHECKING", ctx=ast.Load()))
                and bindings.get("TYPE_CHECKING") == [{"kind": "import", "module": "typing", "name": "TYPE_CHECKING", "level": 0}])
            pending.extend(node.orelse if typing_guard else ast.iter_child_nodes(node))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name, {"kind": "unresolved"})
            continue
        if isinstance(node, (ast.ImportFrom, ast.Import)):
            for alias in node.names:
                add(alias.asname or alias.name.split(".")[0], {"kind": "unresolved"})
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            add(node.id, {"kind": "unresolved"})
            conditional_exports |= node.id == "__all__"
        pending.extend(ast.iter_child_nodes(node))
    # A function can replace a module binding through a global declaration.
    # Read-only global references do not do this; nested lexical scopes are
    # inspected separately so their local assignments are not misattributed.
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        global_names, written = set(), set()
        pending = list(function.body)
        while pending:
            node = pending.pop()
            if isinstance(node, ast.Global):
                global_names.update(node.names)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                written.add(node.name)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                written.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                written.add(node.id)
            pending.extend(ast.iter_child_nodes(node))
        for name in global_names & written:
            add(name, {"kind": "unresolved"})
    selected = assignments.get("__all__", [])
    names: list[str] = []
    lazy: dict[str, tuple[str, str]] = {}
    problems = ["The export list has a conditional definition."] if conditional_exports else []
    closed = False
    if selected:
        value = _literal(selected[0]) if len(selected) == 1 else None
        if (type(value) in (list, tuple) and all(type(name) is str and name.isidentifier() for name in value)
                and len(value) == len(set(value))):
            names = list(value)
        elif len(selected) == 1 and _shape(selected[0]) == _shape(ast.parse("list(_LAZY_EXPORTS)", mode="eval").body):
            tables = assignments.get("_LAZY_EXPORTS", [])
            table = _literal(tables[0]) if len(tables) == 1 else None
            if (type(table) is dict and isinstance(tables[0], ast.Dict) and len(table) == len(tables[0].keys)
                    and all(type(name) is str and name.isidentifier() and type(target) in (list, tuple)
                            and len(target) == 2 and all(type(part) is str for part in target)
                            and all(part.isidentifier() for part in target[0].split(".")) and target[1].isidentifier()
                            for name, target in table.items())):
                lazy = table
                names = list(table)
                closed = _closed_lazy(tree, assignments, bindings)
            else:
                problems.append("The lazy export map is not one unique literal name-to-target table.")
        else:
            problems.append("The explicit export list is dynamic, duplicated or unsupported.")
        # A literal declaration must not hide a later mutation, even inside a
        # function. Normal __dir__ inspection is a read, not a replacement.
        allowed = set()
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if len(targets) == 1 and isinstance(targets[0], ast.Name) and targets[0].id == "__all__":
                    allowed.update(ast.walk(statement))
            if isinstance(statement, ast.FunctionDef) and statement.name == "__dir__" and _signature(statement, (), deferred) \
                    and _body(statement) == _body(ast.parse(_DIRECTORY).body[0]):
                allowed.update(ast.walk(statement))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Subscript, ast.Attribute)) and any(
                    isinstance(child, ast.Name) and child.id == "__all__" for child in ast.walk(node)):
                problems.append("The explicit export list is accessed through an unsupported mutable operation.")
                break
            if isinstance(node, ast.Name) and node.id == "__all__" and node not in allowed:
                problems.append("The explicit export list has an unsupported reference, write or deletion.")
                break
    for name, (module, attribute) in lazy.items():
        # A real local binding shadows __getattr__; do not silently pick either.
        add(name, {"kind": "import", "module": module, "name": attribute, "level": 0})
    permitted_globals = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and ((node.name == "__getattr__" and closed)
                or (node.name == "__dir__" and _signature(node, (), deferred) and _body(node) == _body(ast.parse(_DIRECTORY).body[0]))):
            permitted_globals.update(ast.walk(node))
    nodes = list(ast.walk(tree))
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    unknown_globals = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "globals" and node not in permitted_globals
        and not _read_only_namespace_call(node, parents) for node in nodes)
    return {"path": path, "bindings": bindings, "exports": names, "root_surface": root_surface,
            "closed_lazy": closed and not problems and not unknown_globals,
            "unknown_globals": unknown_globals, "problems": problems}




def has_dynamic_construction(tree: ast.Module, *, closed_lazy: bool,
                             permitted_source_imports: set[ast.AST] | None = None) -> bool:
    """Keep known construction capabilities visible even when their names escape.

    This is conservative syntax analysis, not runtime alias or reachability proof.
    Imports in all scopes contribute possible bindings; shadowing cannot establish
    absence. A capability copied, returned or passed elsewhere is unresolved at
    that reference, without guessing what its eventual caller will do. Ordinary
    same-spelled methods on unrelated objects are not builtin construction.
    """
    builtins = {"eval", "exec", "setattr", "delattr", "__import__", "globals", "locals", "vars", "type"}
    loaders = {"import_module", "__import__", "exec_module", "load_module", "module_from_spec",
               "spec_from_file_location", "spec_from_loader"}
    # These exact submodule exports inspect packaged resources or module specs;
    # importing the leaf function does not bind an ``importlib`` module object.
    # Keep this allowlist symbol-specific so actual loaders and module aliases
    # continue through the conservative capability checks below.
    closed_importlib_reads = {("importlib.resources", "files"), ("importlib.util", "find_spec")}
    names = {name: {name} for name in builtins}
    modules = {"__builtins__": {"builtins"}}
    metadata_roots: set[tuple[str, ...]] = set()
    nodes = list(ast.walk(tree))
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    if _has_module_registry_reference(tree, nodes, permitted_source_imports or set()):
        return True
    shadowed = {node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))}
    shadowed.update(node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    shadowed.update(node.arg for node in nodes if isinstance(node, ast.arg))
    annotations = set()
    if _deferred_annotations(tree):
        annotations.update(node.annotation for node in nodes if isinstance(node, (ast.AnnAssign, ast.arg)))
        annotations.update(node.returns for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                shadowed.add(alias.asname or alias.name.split(".")[0])
                base = alias.name.split(".")[0]
                if base in {"builtins", "importlib"}:
                    modules.setdefault(alias.asname or base, set()).add(base)
                if base == "importlib" and not alias.asname:
                    metadata_roots.add((base, "metadata"))
                elif alias.name == "importlib":
                    metadata_roots.add((alias.asname, "metadata"))
                elif alias.name == "importlib.metadata" or alias.name.startswith("importlib.metadata."):
                    metadata_roots.add((alias.asname,))
        elif isinstance(node, ast.ImportFrom) and not node.level:
            shadowed.update(alias.asname or alias.name for alias in node.names)
            base = (node.module or "").split(".")[0]
            if base not in {"builtins", "importlib"}:
                continue
            for alias in node.names:
                if alias.name == "*":
                    return True  # An unbounded imported capability set is not empty coverage.
                if node.module == "importlib" and alias.name == "metadata":
                    metadata_roots.add((alias.asname or alias.name,))
                if alias.name in (builtins if base == "builtins" else loaders):
                    names.setdefault(alias.asname or alias.name, set()).add(alias.name)
                elif node.module == "importlib.metadata" and alias.name in {
                        "version", "distribution", "requires"}:
                    # These are functions, not aliases for the importlib module.
                    # Their reflective or escaped uses still carry a capability.
                    names.setdefault(alias.asname or alias.name, set()).add("metadata:" + alias.name)
                elif base == "importlib" and (node.module, alias.name) not in closed_importlib_reads:
                    modules.setdefault(alias.asname or alias.name, set()).add(base)
                    if (node.module or "").startswith("importlib.metadata.") or node.module == "importlib.metadata":
                        metadata_roots.add((alias.asname or alias.name,))

    # Exempt only the exact already-checked dispatcher/directory bodies. A loader
    # reference elsewhere in the same module must not inherit that exemption.
    permitted = inventory_inspections(tree, nodes, parents)
    # Source-import admission supplies node identities from the same parsed tree.
    # Only those exact loader references are exempt; another use of the same
    # imported function remains a capability escape below.
    permitted.update(permitted_source_imports or ())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and (
                (node.name == "__getattr__" and closed_lazy)
                or (node.name == "__dir__" and _signature(node, (), _deferred_annotations(tree))
                    and _body(node) == _body(ast.parse(_DIRECTORY).body[0]))):
            permitted.update(child for statement in node.body for child in ast.walk(statement)
                             if isinstance(child, ast.Name) and child.id in {"globals", "import_module"})

    for node in nodes:
        if node in permitted:
            continue
        capability = set()
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            capability = names.get(node.id, set())
            if node.id in modules:
                parent = parents.get(node)
                if not isinstance(parent, ast.Attribute) or parent.value is not node:
                    return True  # Module copy, lookup, subscript or argument escape.
        elif isinstance(node, ast.Attribute):
            base = node.value
            path = [node.attr]
            while isinstance(base, ast.Attribute):
                path.append(base.attr)
                base = base.value
            if isinstance(base, ast.Name):
                qualified = (base.id, *reversed(path))
                # Exact dependency-data reads were checked above. Any remaining
                # module-style reference can still expose plugins or reflection;
                # matching only import_module misses entry-point loading entirely.
                if any(qualified[:len(root)] == root for root in metadata_roots):
                    return True
                possible = modules.get(base.id, set())
                if possible and (node.attr == "__dict__"
                        or "builtins" in possible and node.attr in builtins
                        or "importlib" in possible and node.attr in loaders):
                    capability = {node.attr}
        if capability:
            parent = parents.get(node)
            inspection = (capability == {"type"} and isinstance(parent, ast.Call)
                          and parent.func is node and len(parent.args) == 1
                          and not isinstance(parent.args[0], ast.Starred) and not parent.keywords)
            if capability in ({"globals"}, {"locals"}, {"vars"}) \
                    and isinstance(parent, ast.Call) and parent.func is node:
                inspection |= _read_only_namespace_call(parent, parents)
            if capability == {"type"}:
                # These source shapes inspect a type or store a postponed type
                # annotation; they do not pass its constructor to arbitrary code.
                inspection |= (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                    and parent.func.id in {"isinstance", "issubclass"} and parent.func.id not in shadowed
                    and len(parent.args) == 2 and parent.args[1] is node and not parent.keywords)
                cursor = node
                while cursor not in annotations and isinstance(parents.get(cursor), (ast.Subscript, ast.Tuple, ast.List, ast.BinOp)):
                    cursor = parents[cursor]
                inspection |= cursor in annotations
            if not inspection:
                return True
    return False


def resolve(modules: dict[str, dict[str, Any]], files: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, str]], set[str]]:
    """Resolve local module/export chains under observed regular-package roots.

    No import path is executed or guessed from the operator environment. Missing
    or ambiguous modules, star imports and cycles cannot supply a target binding.
    """
    index: dict[str, list[str]] = {}
    qualified: dict[str, str] = {}
    for path in modules:
        pure = PurePosixPath(path)
        parts = [] if pure.name in {"__init__.py", "__init__.pyi"} else [pure.stem]
        # A regular package can contain namespace-package children without an
        # initializer. Retain intervening components beneath an observed anchor;
        # do not invent an import root above the outermost regular package.
        anchors = [parent for parent in pure.parents if parent.name and any(
            str(parent / name) in modules for name in ("__init__.py", "__init__.pyi"))]
        if anchors:
            anchor = anchors[-1]
            parts = list(pure.parent.relative_to(anchor.parent).parts) + parts
        name = ".".join(parts)
        qualified[path] = name
        if name:
            index.setdefault(name, []).append(path)

    def target(path: str, name: str, seen: set[tuple[str, str]]) -> dict[str, Any] | None:
        key = path, name
        if key in seen or len(seen) >= 64:
            return None
        choices = modules[path]["bindings"].get(name, [])
        if len(choices) != 1:
            return None
        binding = choices[0]
        if binding["kind"] == "local":
            return binding["surface"]
        if binding["kind"] == "alias":
            return target(path, binding["name"], seen | {key})
        if binding["kind"] != "import" or binding["name"] == "*":
            return None
        module = binding["module"]
        if binding["level"]:
            package = qualified[path].split(".")
            if PurePosixPath(path).name not in {"__init__.py", "__init__.pyi"}:
                package = package[:-1]
            if len(package) < binding["level"]:
                return None
            module = ".".join(package[:len(package) - binding["level"] + 1] + ([module] if module else []))
        candidates = index.get(module, [])
        # A stub beside an implementation is not a second runtime module.
        candidates = [candidate for candidate in candidates if not candidate.endswith(".pyi")
                      or candidate[:-1] not in candidates]
        if len(candidates) != 1:
            return None
        return target(candidates[0], binding["name"], seen | {key})

    surfaces, gaps, closed = [], [], set()
    retained = set()
    for path, module in modules.items():
        problems = list(module["problems"])
        for name in module["exports"]:
            destination = target(path, name, set())
            base = module["root_surface"]
            row = {**base, "surface_id": "python-export:" + path + ":" + name, "form": "Export",
                "target_surface_id": destination["surface_id"] if destination else None,
                "target_source_digest": files[destination["path"]] if destination else None,
                "binding_scope": "DECLARED_STATIC_SOURCE_BINDING_NOT_RUNTIME_IMPORT"}
            if destination:
                for field in ("source_kinds", "hints"):
                    row[field] = sorted(set(base[field]) | set(destination[field]))
                row["unresolved_marker"] = base["unresolved_marker"] or destination["unresolved_marker"]
                if destination["form"] == "Binding" and destination["surface_id"] not in retained:
                    surfaces.append(destination)
                    retained.add(destination["surface_id"])
            else:
                problems.append("No unique local target binding for export " + name + ".")
            surfaces.append(row)
        if problems:
            gaps.append({"path": path, "code": "NAMESPACE_PYTHON_EXPORTS_UNRESOLVED", "reason": " ".join(dict.fromkeys(problems))})
        elif module["closed_lazy"]:
            closed.add(path)
    return surfaces, gaps, closed
