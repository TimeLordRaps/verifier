"""Closed, non-executing bindings for local Python source loads.

This module recognizes one deliberately small abstract syntax tree (AST)
program shape. It binds a default Python source loader to a current Git-census
target; it does not claim that the runtime import succeeds or that executing
the target is safe. Any alias escape, custom loader, mutable path, open module
registry write, or dynamic selector leaves the ordinary dynamic-surface warning
in place.
"""
from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from verifier.runtime.self_polish_estate import bytes_digest


_MODULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_SCOPE = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_BINDING_REASON = (
    "A finite local module name, current target digest, and every post-import "
    "attribute read are statically bound; no subject import was executed."
)
_REGISTRY_REASON = (
    " The literal module-registry key, inserted module, non-clobber guard, and "
    "unconditional cleanup are bound by one adjacent try/finally source shape."
)
_HELD_SOURCE_REASON = (
    "The checker worker's exact source-path guard confines selection to the "
    "current verifier/runtime directory; every selectable regular Python file "
    "and digest is enumerated from the current source census. The held-source "
    "execution was not run, and this binding does not assert checker safety."
)
_TEST_WORKER_SOURCE_REASON = (
    "The test executes one current embedded worker string only inside an "
    "isolated __main__ namespace. The worker attribute, defining source file, "
    "current digest, execution filename, and every function containing an "
    "execution site are finite and structurally checked; this does not assert "
    "that the worker execution succeeds."
)
_TEST_CHECKER_SOURCE_REASON = (
    "The adversarial checker test intentionally constructs a test-local module "
    "from source templates embedded in this digest-bound test file. Its two "
    "loader helpers retain exact syntax and expose only ADAPTER and "
    "check_observations to the checker boundary; this does not admit a runtime "
    "package interface."
)


def _syntax_shape(source: str) -> str:
    """Return a location-neutral syntax identity for one function."""

    parsed = ast.parse(source)
    if len(parsed.body) != 1 or not isinstance(parsed.body[0], ast.FunctionDef):
        raise AssertionError("one function source shape required")
    return ast.dump(parsed.body[0], include_attributes=False)


_HELD_SAFE_PATH_SHAPE = _syntax_shape('''
def _safe_checker_path(source_root: Path, relative: Any) -> Path:
    if type(relative) is not str or not relative.startswith("verifier/runtime/"):
        raise ValueError("checker source coordinate invalid")
    candidate = (source_root / Path(*relative.split("/"))).resolve(strict=True)
    if (
        candidate.suffix != ".py"
        or not candidate.is_relative_to(source_root)
        or candidate.parent != source_root / "verifier" / "runtime"
    ):
        raise ValueError("checker source coordinate invalid")
    return candidate
''')

_HELD_LOAD_SHAPE = _syntax_shape('''
def _load_held_checker(path: Path, raw: bytes) -> ModuleType:
    """Compile the held source bytes without consulting a bytecode cache."""

    name = "verifier.runtime." + path.stem
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = "verifier.runtime"
    sys.modules[name] = module
    code = compile(
        raw,
        str(path),
        "exec",
        dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    exec(code, module.__dict__)
    return module
''')

_TEST_CHECKER_FIXTURE_SHAPE = _syntax_shape('''
def _fixture_module(path: Path, source: str) -> ModuleType:
    module = ModuleType("verifier.runtime.fixture_checker_execution")
    module.__file__ = str(path)
    module.__package__ = "verifier.runtime"
    exec(
        compile(
            source,
            str(path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        ),
        module.__dict__,
    )
    return module
''')

_TEST_CHECKER_ORDINARY_SHAPE = _syntax_shape('''
def _normally_imported_fixture_module(path: Path) -> ModuleType:
    """Load source through Python's ordinary source loader, without caller flags."""

    name = "verifier.runtime.fixture_checker_execution"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
''')

_TEST_WORKER_SITES = {
    "tests/test_native_language_top24_adapters.py": (
        "extensions/languages/src/vstd_languages/__init__.py",
        "WORKER",
        frozenset({"_worker"}),
        frozenset({"<vstd-worker>"}),
    ),
    "tests/test_native_language_extensions_batch_two.py": (
        "extensions/languages/src/vstd_languages/extended_batch_two.py",
        "WORKER",
        frozenset({
            "_worker",
            "_worker_namespace",
            "test_missing_compiler_at_spawn_is_the_toolchain_token_not_a_traceback",
            "test_artifact_that_cannot_start_is_the_resource_token",
        }),
        frozenset({"<vstd-batch-two-worker>"}),
    ),
    "tests/test_native_language_extensions_batch_three.py": (
        "extensions/languages/src/vstd_languages/extended_batch_three.py",
        "WORKER",
        frozenset({
            "_worker",
            "_run_helper",
            "_probe_worker",
            "test_scratch_runner_missing_at_spawn_is_the_toolchain_token",
            "test_visual_basic_artifact_that_cannot_start_is_the_resource_token",
        }),
        frozenset({"<vstd-batch-three-worker>"}),
    ),
    "tests/test_native_language_package_dispatch_batch_three.py": (
        "extensions/languages/src/vstd_languages/extended_batch_three.py",
        "WORKER_LAUNCHER",
        frozenset({"test_dispatched_worker_never_touches_the_subject_source"}),
        frozenset({"<vstd-batch-three-worker>"}),
    ),
}


def _chain(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return (node.id, *reversed(parts)) if isinstance(node, ast.Name) else ()


def _scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST:
    if isinstance(node, ast.Module):
        return node
    while node in parents:
        node = parents[node]
        if isinstance(node, _SCOPE):
            return node
    raise ValueError("Python node is outside its module")


def _bound_name(node: ast.Import | ast.ImportFrom, alias: ast.alias) -> str:
    return alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)


def _binding_records(nodes: list[ast.AST]) -> list[tuple[str, ast.AST]]:
    """Return every binder, including declarations that change name ownership."""
    result: list[tuple[str, ast.AST]] = []
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            result.append((node.id, node))
        elif isinstance(node, ast.arg):
            result.append((node.arg, node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result.append((node.name, node))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            result.extend((_bound_name(node, alias), alias) for alias in node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            result.append((node.name, node))
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            result.append((node.name, node))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            result.append((node.rest, node))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            # These declarations can redirect an otherwise local-looking
            # assignment. The closed adapter does not model that indirection.
            result.extend((name, node) for name in node.names)
    return result


def _bindings(nodes: list[ast.AST]) -> dict[str, list[ast.AST]]:
    """Index all binders for conservative ownership of top-level imports."""
    result: dict[str, list[ast.AST]] = {}
    for name, node in _binding_records(nodes):
        result.setdefault(name, []).append(node)
    return result


def _scoped_bindings(nodes: list[ast.AST], parents: dict[ast.AST, ast.AST]) \
        -> dict[tuple[ast.AST, str], list[ast.AST]]:
    """Index binders by their actual lexical owner, not merely by spelling."""
    result: dict[tuple[ast.AST, str], list[ast.AST]] = {}
    for name, node in _binding_records(nodes):
        result.setdefault((_scope(node, parents), name), []).append(node)
    return result


def _imports(tree: ast.Module, bindings: dict[str, list[ast.AST]]) \
        -> tuple[dict[tuple[str, ...], str], set[tuple[str, ...]]]:
    """Return exact function and ``Path`` spellings with unshadowed owners."""
    candidates: list[tuple[tuple[str, ...], str, str, ast.alias]] = []
    path_candidates: list[tuple[tuple[str, ...], str, ast.alias]] = []
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "importlib.util":
                    prefix = ((alias.asname,) if alias.asname else ("importlib", "util"))
                    owner = alias.asname or "importlib"
                    candidates.extend(((*prefix, name), name, owner, alias)
                                      for name in ("spec_from_file_location", "module_from_spec"))
                elif alias.name == "importlib":
                    prefix = (alias.asname or "importlib",)
                    candidates.append(((*prefix, "import_module"), "import_module",
                                       prefix[0], alias))
                elif alias.name == "pathlib":
                    prefix = (alias.asname or "pathlib", "Path")
                    path_candidates.append((prefix, alias.asname or "pathlib", alias))
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
            for alias in statement.names:
                if statement.module == "importlib" and alias.name == "util":
                    prefix = (alias.asname or "util",)
                    candidates.extend(((*prefix, name), name, prefix[0], alias)
                                      for name in ("spec_from_file_location", "module_from_spec"))
                elif statement.module == "importlib.util" and alias.name in {
                        "spec_from_file_location", "module_from_spec"}:
                    local = alias.asname or alias.name
                    candidates.append(((local,), alias.name, local, alias))
                elif statement.module == "importlib" and alias.name == "import_module":
                    local = alias.asname or alias.name
                    candidates.append(((local,), alias.name, local, alias))
                elif statement.module == "pathlib" and alias.name == "Path":
                    local = alias.asname or alias.name
                    path_candidates.append(((local,), local, alias))

    functions: dict[tuple[str, ...], str] = {}
    for spelling, operation, owner, alias in candidates:
        if bindings.get(owner) == [alias]:
            functions[spelling] = operation
    paths = {spelling for spelling, owner, alias in path_candidates
             if bindings.get(owner) == [alias]}
    return functions, paths


def _literal_strings(node: ast.AST, scope: ast.AST, before: int, *,
                     tree: ast.Module,
                     parents: dict[ast.AST, ast.AST],
                     assignments: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]],
                     bindings: dict[tuple[ast.AST, str], list[ast.AST]],
                     seen: frozenset[tuple[ast.AST, str]] = frozenset()) -> set[str] | None:
    """Evaluate a finite literal string set without choosing a runtime branch."""
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return {node.value}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values: set[str] = set()
        for item in node.elts:
            selected = _literal_strings(item, scope, before, tree=tree, parents=parents,
                                        assignments=assignments, bindings=bindings, seen=seen)
            if selected is None:
                return None
            values.update(selected)
        return values or None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_strings(node.left, scope, before, tree=tree, parents=parents,
                                assignments=assignments, bindings=bindings, seen=seen)
        right = _literal_strings(node.right, scope, before, tree=tree, parents=parents,
                                 assignments=assignments, bindings=bindings, seen=seen)
        if left is None or right is None or len(left) * len(right) > 256:
            return None
        return {first + second for first in left for second in right}
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "lower" and not node.args and not node.keywords):
        # ``str.lower`` is the sole source transform admitted here. Its receiver
        # must itself reduce to literal strings, so arbitrary method dispatch or
        # a runtime-selected string-like object cannot enter the import name.
        values = _literal_strings(
            node.func.value, scope, before, tree=tree, parents=parents,
            assignments=assignments, bindings=bindings, seen=seen)
        return None if values is None else {value.lower() for value in values}
    if isinstance(node, ast.Name):
        # A comprehension or loop target has exactly the values of its finite
        # iterable for this call site. No iteration is performed here.
        cursor: ast.AST = node
        while cursor in parents and parents[cursor] is not scope:
            cursor = parents[cursor]
            if isinstance(cursor, (ast.comprehension, ast.For, ast.AsyncFor)):
                target = cursor.target
                if isinstance(target, ast.Name) and target.id == node.id:
                    if bindings.get((scope, node.id)) != [target]:
                        return None
                    return _literal_strings(cursor.iter, scope, before, tree=tree,
                                            parents=parents, assignments=assignments,
                                            bindings=bindings, seen=seen)
            if isinstance(cursor, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for generator in cursor.generators:
                    if isinstance(generator.target, ast.Name) and generator.target.id == node.id:
                        if bindings.get((scope, node.id)) != [generator.target]:
                            return None
                        return _literal_strings(generator.iter, scope, before, tree=tree,
                                                parents=parents, assignments=assignments,
                                                bindings=bindings, seen=seen)
        key = (scope, node.id)
        if key in seen:
            return None
        selected = assignments.get(key, [])
        if not (len(selected) == 1 and bindings.get(key) == [selected[0][0]]
                and selected[0][2].lineno < before):
            key = (tree, node.id)
            selected = assignments.get(key, [])
        if (len(selected) == 1 and bindings.get(key) == [selected[0][0]]
                and selected[0][2].lineno < before):
            return _literal_strings(selected[0][1], scope, before, tree=tree,
                                    parents=parents, assignments=assignments,
                                    bindings=bindings, seen=seen | {key})
        if isinstance(scope, ast.FunctionDef):
            positional = [*scope.args.posonlyargs, *scope.args.args]
            parameter = next((index for index, argument in enumerate(positional)
                              if argument.arg == node.id), None)
            if parameter is not None:
                key = (scope, node.id)
                if key in seen or bindings.get((tree, scope.name)) != [scope]:
                    return None
                values: set[str] = set()
                calls: list[ast.Call] = []
                for load in (item for item in ast.walk(tree) if isinstance(item, ast.Name)
                             and item.id == scope.name and isinstance(item.ctx, ast.Load)):
                    parent = parents.get(load)
                    if not isinstance(parent, ast.Call) or parent.func is not load:
                        return None
                    calls.append(parent)
                for call in calls:
                    argument = (call.args[parameter] if parameter < len(call.args) else
                                next((word.value for word in call.keywords
                                      if word.arg == node.id), None))
                    if argument is None:
                        return None
                    selected_values = _literal_strings(
                        argument, _scope(call, parents), call.lineno, tree=tree,
                        parents=parents, assignments=assignments, bindings=bindings,
                        seen=seen | {key})
                    if selected_values is None:
                        return None
                    values.update(selected_values)
                # Pytest owns this parameter only for one unshadowed, ordinary
                # top-level parametrization. Named tables must be immutable
                # tuple literals with one prior, unconditional binding.
                if scope.decorator_list:
                    if (parents.get(scope) is not tree or not scope.name.startswith("test_")
                            or calls or len(scope.decorator_list) != 1):
                        return None
                    decorator = scope.decorator_list[0]
                    pytest_binding = bindings.get((tree, "pytest"), [])
                    if (not isinstance(decorator, ast.Call)
                            or _chain(decorator.func) != ("pytest", "mark", "parametrize")
                            or len(decorator.args) != 2 or decorator.keywords
                            or len(pytest_binding) != 1
                            or not isinstance(pytest_binding[0], ast.alias)
                            or pytest_binding[0].name != "pytest"
                            or pytest_binding[0].asname is not None):
                        return None
                    declared = decorator.args[0].value if isinstance(
                        decorator.args[0], ast.Constant) else None
                    if type(declared) is not str:
                        return None
                    names = [part.strip() for part in declared.split(",")]
                    if (not names or any(not name for name in names)
                            or len(set(names)) != len(names) or node.id not in names):
                        return None
                    rows = decorator.args[1]
                    if isinstance(rows, ast.Name):
                        table_key = (tree, rows.id)
                        table = assignments.get(table_key, [])
                        if (len(table) != 1 or bindings.get(table_key) != [table[0][0]]
                                or table[0][2].lineno >= decorator.lineno
                                or not isinstance(table[0][1], ast.Tuple)):
                            return None
                        rows = table[0][1]
                    if not isinstance(rows, (ast.Tuple, ast.List)):
                        return None
                    index = names.index(node.id)
                    for row in rows.elts:
                        value = row if len(names) == 1 else (
                            row.elts[index] if isinstance(row, (ast.Tuple, ast.List))
                            and len(row.elts) == len(names) else None)
                        if value is None:
                            return None
                        selected_values = _literal_strings(
                            value, scope, before, tree=tree, parents=parents,
                            assignments=assignments, bindings=bindings,
                            seen=seen | {key})
                        if selected_values is None:
                            return None
                        values.update(selected_values)
                return values or None
    return None


def _target_attributes(raw: bytes, relative: str) -> dict[str, str] | None:
    """Map exact top-level declarations to existing census surfaces.

    Functions and classes have their own definition surfaces. A unique direct
    assignment is a declared module attribute and therefore binds to the
    module surface whose digest contains that assignment. Conditional,
    unpacked, annotation-only, rebound, imported, and deleted names are not
    promoted by this adapter.
    """
    try:
        tree = ast.parse(raw, filename=relative)
    except (SyntaxError, UnicodeError, RecursionError, ValueError):
        return None
    nodes = list(ast.walk(tree))
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    bindings = _scoped_bindings(nodes, parents)
    result: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # A later assignment/import/deletion with the same public spelling
            # would make the imported attribute runtime-selected rather than a
            # binding to this definition surface.
            if bindings.get((tree, statement.name)) == [statement]:
                result[statement.name] = f"python:{relative}:{statement.name}"
            continue
        target: ast.Name | None = None
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)):
            target = statement.targets[0]
        elif (isinstance(statement, ast.AnnAssign) and statement.value is not None
                and isinstance(statement.target, ast.Name)):
            target = statement.target
        if target is not None and bindings.get((tree, target.id)) == [target]:
            result[target.id] = f"python:{relative}:<module>"
    return result


def _local_module_target(root: Path, importer: str, module_name: str,
                         files: dict[str, dict[str, Any]]) \
        -> tuple[str, dict[str, Any], dict[str, str]] | None:
    """Resolve one current, tracked local module without modeling ``sys.path``."""
    if _MODULE_NAME.fullmatch(module_name) is None:
        return None
    stem = module_name.replace(".", "/")
    suffixes = (stem + ".py", stem + "/__init__.py")
    candidates = [path for path in files if path in suffixes
                  or any(path.endswith("/" + suffix) for suffix in suffixes)]
    if len(candidates) != 1:
        return None
    relative = candidates[0]
    target_parent = PurePosixPath(relative).parent
    importer_parent = PurePosixPath(importer).parent
    package_initializer = relative.endswith("/" + stem + "/__init__.py") \
        or relative == stem + "/__init__.py"
    if "." not in module_name and target_parent != importer_parent \
            and target_parent != PurePosixPath(".") and not package_initializer:
        return None
    entry = files[relative]
    if (relative == importer or entry.get("provenance") != "GIT_TRACKED"
            or not _ordinary_target(root, importer) or not _ordinary_target(root, relative)):
        return None
    target = root / Path(*PurePosixPath(relative).parts)
    raw = target.read_bytes()
    if bytes_digest(raw) != entry["sha256"]:
        return None
    attributes = _target_attributes(raw, relative)
    return None if attributes is None else (relative, entry, attributes)


def _unshadowed(name: str, scope: ast.AST, parents: dict[ast.AST, ast.AST],
                bindings: dict[tuple[ast.AST, str], list[ast.AST]]) -> bool:
    """Prove a builtin spelling has no binder in an enclosing source scope."""
    cursor = scope
    while True:
        if bindings.get((cursor, name)):
            return False
        if isinstance(cursor, ast.Module):
            return True
        cursor = _scope(cursor, parents)


def _attribute_reads(call: ast.Call, scope: ast.AST, nodes: list[ast.AST],
                     parents: dict[ast.AST, ast.AST],
                     scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
                     *, tree: ast.Module,
                     assignments: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]],
                     seen_functions: frozenset[ast.AST] = frozenset()) \
        -> set[str] | None:
    """Follow only a direct result or one unique local alias to named reads."""

    def selected(value: ast.AST) -> set[str] | None:
        parent = parents.get(value)
        if isinstance(parent, ast.Attribute) and parent.value is value \
                and isinstance(parent.ctx, ast.Load) and parent.attr != "__dict__":
            return {parent.attr}
        if (isinstance(parent, ast.Call) and len(parent.args) == 2
                and not parent.keywords and parent.args[0] is value
                and isinstance(parent.func, ast.Name)
                and parent.func.id in {"getattr", "hasattr"}
                and _unshadowed(parent.func.id, scope, parents, scoped_bindings)):
            return _literal_strings(
                parent.args[1], scope, parent.lineno, tree=tree, parents=parents,
                assignments=assignments, bindings=scoped_bindings)
        return None

    attributes = selected(call)
    if attributes is not None:
        return attributes
    parent = parents.get(call)
    if isinstance(parent, ast.Return) and parent.value is call:
        returns = [node for node in ast.walk(scope) if isinstance(node, ast.Return)
                   and _scope(node, parents) is scope]
        if parents.get(parent) is not scope or returns != [parent]:
            return None
        return _function_result_attributes(
            scope, nodes, parents, scoped_bindings, tree=tree,
            assignments=assignments, seen_functions=seen_functions)
    assignment = parent
    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)) \
            or parents.get(assignment) is not scope:
        return None
    targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return None
    alias = targets[0]
    if scoped_bindings.get((scope, alias.id)) != [alias]:
        return None
    attributes = set()
    for load in (item for item in nodes if isinstance(item, ast.Name)
                 and item.id == alias.id and isinstance(item.ctx, ast.Load)
                 and _scope(item, parents) is scope):
        selected_attributes = selected(load)
        if selected_attributes is None or load.lineno <= call.lineno:
            return None
        attributes.update(selected_attributes)
    return attributes or None


def _pytest_fixture_declaration(function: ast.FunctionDef, tree: ast.Module,
                                bindings: dict[tuple[ast.AST, str], list[ast.AST]]) \
        -> bool:
    """Recognize only pytest's ordinary, non-parameterized fixture decorator."""
    pytest_binding = bindings.get((tree, "pytest"), [])
    if (len(pytest_binding) != 1 or not isinstance(pytest_binding[0], ast.alias)
            or pytest_binding[0].name != "pytest" or pytest_binding[0].asname is not None
            or len(function.decorator_list) != 1):
        return False
    decorator = function.decorator_list[0]
    if _chain(decorator) == ("pytest", "fixture"):
        return True
    if (not isinstance(decorator, ast.Call)
            or _chain(decorator.func) != ("pytest", "fixture")
            or decorator.args):
        return False
    for keyword in decorator.keywords:
        if (keyword.arg != "scope" or not isinstance(keyword.value, ast.Constant)
                or keyword.value.value not in {
                    "function", "class", "module", "package", "session",
                }):
            return False
    return True


def _required_parameter(function: ast.FunctionDef, argument: ast.arg) -> bool:
    """Pytest owns only an ordinary named parameter without a Python default."""
    positional = list(function.args.args)
    if argument in positional:
        first_default = len(positional) - len(function.args.defaults)
        return positional.index(argument) < first_default
    if argument in function.args.kwonlyargs:
        return function.args.kw_defaults[function.args.kwonlyargs.index(argument)] is None
    return False


def _pytest_test_consumer(function: ast.FunctionDef, fixture_name: str,
                          tree: ast.Module,
                          bindings: dict[tuple[ast.AST, str], list[ast.AST]]) -> bool:
    """Reject decorators that can replace the fixture value at collection time."""
    if not function.name.startswith("test_"):
        return _pytest_fixture_declaration(function, tree, bindings)
    for decorator in function.decorator_list:
        selected = decorator.func if isinstance(decorator, ast.Call) else decorator
        chain = _chain(selected)
        if chain[:2] != ("pytest", "mark"):
            return False
        if chain == ("pytest", "mark", "parametrize"):
            if (not isinstance(decorator, ast.Call) or not decorator.args
                    or not isinstance(decorator.args[0], ast.Constant)
                    or type(decorator.args[0].value) is not str):
                return False
            parameters = {name.strip() for name in decorator.args[0].value.split(",")}
            if fixture_name in parameters:
                return False
    return True


def _pytest_fixture_result_attributes(
        function: ast.FunctionDef, nodes: list[ast.AST],
        parents: dict[ast.AST, ast.AST],
        bindings: dict[tuple[ast.AST, str], list[ast.AST]], tree: ast.Module) \
        -> set[str] | None:
    """Follow one fixture result through pytest-owned named parameters only."""
    if not _pytest_fixture_declaration(function, tree, bindings):
        return None
    # A direct read of the decorated fixture function bypasses the dependency
    # protocol and may receive a wrapper-selected value.
    if any(isinstance(node, ast.Name) and node.id == function.name
           and isinstance(node.ctx, ast.Load)
           and (_scope(node, parents) is tree
                or not bindings.get((_scope(node, parents), function.name)))
           for node in nodes):
        return None
    attributes: set[str] = set()
    consumers = 0
    for argument in (node for node in nodes if isinstance(node, ast.arg)
                     and node.arg == function.name):
        consumer = _scope(argument, parents)
        if (not isinstance(consumer, ast.FunctionDef)
                or parents.get(consumer) is not tree
                or not _required_parameter(consumer, argument)
                or bindings.get((consumer, function.name)) != [argument]
                or not _pytest_test_consumer(consumer, function.name, tree, bindings)):
            continue
        # A manually invoked consumer can supply a value unrelated to the
        # fixture. Collected pytest ownership must be the only call route.
        if any(isinstance(node, ast.Name) and node.id == consumer.name
               and isinstance(node.ctx, ast.Load) for node in nodes):
            return None
        consumers += 1
        for load in (node for node in nodes if isinstance(node, ast.Name)
                     and node.id == function.name and isinstance(node.ctx, ast.Load)
                     and _scope(node, parents) is consumer):
            selected = parents.get(load)
            if (not isinstance(selected, ast.Attribute) or selected.value is not load
                    or not isinstance(selected.ctx, ast.Load)
                    or selected.attr == "__dict__"):
                return None
            attributes.add(selected.attr)
    return attributes if consumers and attributes else None


def _function_result_attributes(scope: ast.AST, nodes: list[ast.AST],
                                parents: dict[ast.AST, ast.AST],
                                scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
                                *, tree: ast.Module,
                                assignments: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]],
                                seen_functions: frozenset[ast.AST] = frozenset()) \
        -> set[str] | None:
    """Trace one undecorated top-level helper only through named reads."""
    if (scope in seen_functions or not isinstance(scope, ast.FunctionDef)
            or not isinstance(parents.get(scope), ast.Module)):
        return None
    module = parents[scope]
    if scoped_bindings.get((module, scope.name)) != [scope]:
        return None
    if scope.decorator_list:
        return _pytest_fixture_result_attributes(
            scope, nodes, parents, scoped_bindings, module)
    attributes: set[str] = set()
    calls: list[ast.Call] = []
    for load in (item for item in nodes if isinstance(item, ast.Name)
                 and item.id == scope.name and isinstance(item.ctx, ast.Load)):
        parent = parents.get(load)
        if not isinstance(parent, ast.Call) or parent.func is not load:
            return None
        calls.append(parent)
    if not calls:
        return None
    for call in calls:
        selected = _attribute_reads(
            call, _scope(call, parents), nodes, parents, scoped_bindings,
            tree=tree, assignments=assignments,
            seen_functions=seen_functions | {scope})
        if selected is None:
            return None
        attributes.update(selected)
    return attributes or None


def _returned_attributes(scope: ast.AST, module_name: str, nodes: list[ast.AST],
                         parents: dict[ast.AST, ast.AST],
                         scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
                         *, tree: ast.Module,
                         assignments: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]]) \
        -> set[str] | None:
    """Follow a loader function result only through closed local call sites."""
    if (not isinstance(scope, ast.FunctionDef)
            or not isinstance(parents.get(scope), ast.Module)):
        return None
    returned = [item for item in ast.walk(scope) if isinstance(item, ast.Return)
                and _scope(item, parents) is scope]
    if (len(returned) != 1 or parents.get(returned[0]) is not scope
            or not isinstance(returned[0].value, ast.Name)
            or returned[0].value.id != module_name):
        return None
    return _function_result_attributes(
        scope, nodes, parents, scoped_bindings, tree=tree,
        assignments=assignments)


def _direct_assignments(nodes: list[ast.AST], parents: dict[ast.AST, ast.AST]) \
        -> dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]]:
    result: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]] = {}
    for node in nodes:
        target: ast.AST | None = None
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        if not isinstance(target, ast.Name) or value is None:
            continue
        owner = parents.get(node)
        if not isinstance(owner, _SCOPE):
            continue  # Conditional/repeated assignment is not an unconditional coordinate.
        result.setdefault((owner, target.id), []).append((target, value, node))
    return result


class _Paths:
    def __init__(self, root: Path, importer: str, tree: ast.Module,
                 parents: dict[ast.AST, ast.AST],
                 assignments: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]],
                 bindings: dict[tuple[ast.AST, str], list[ast.AST]],
                 constructors: set[tuple[str, ...]]) -> None:
        self.root = root.resolve()
        self.importer = self.root / Path(*PurePosixPath(importer).parts)
        self.tree = tree
        self.parents = parents
        self.assignments = assignments
        self.bindings = bindings
        self.constructors = constructors

    @staticmethod
    def _portable(value: str) -> tuple[str, ...] | None:
        if (not value or "\\" in value or value.startswith("/") or ":" in value
                or any(ord(character) < 32 for character in value)):
            return None
        parts = PurePosixPath(value).parts
        return tuple(parts) if parts and all(part not in {"", ".", ".."} for part in parts) else None

    def _assignment(self, name: str, scope: ast.AST, before: int) -> ast.AST | None:
        selected = self.assignments.get((scope, name), [])
        if (len(selected) == 1 and self.bindings.get((scope, name)) == [selected[0][0]]
                and selected[0][2].lineno < before):
            return selected[0][1]
        selected = self.assignments.get((self.tree, name), [])
        if (len(selected) == 1 and self.bindings.get((self.tree, name)) == [selected[0][0]]
                and selected[0][2].lineno < before):
            return selected[0][1]
        return None

    def evaluate(self, node: ast.AST, scope: ast.AST, before: int,
                 seen: frozenset[tuple[ast.AST, str]] = frozenset()) -> Path | None:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            parts = self._portable(node.value)
            return self.root.joinpath(*parts) if parts else None
        if isinstance(node, ast.Name):
            if node.id == "__file__":
                return self.importer
            key = (scope, node.id)
            if key in seen:
                return None
            value = self._assignment(node.id, scope, before)
            return None if value is None else self.evaluate(value, scope, before, seen | {key})
        if isinstance(node, ast.Call) and _chain(node.func) in self.constructors \
                and len(node.args) == 1 and not node.keywords:
            argument = node.args[0]
            if isinstance(argument, ast.Name) and argument.id == "__file__":
                return self.importer
            if isinstance(argument, ast.Constant) and type(argument.value) is str:
                parts = self._portable(argument.value)
                return self.root.joinpath(*parts) if parts else None
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self.evaluate(node.left, scope, before, seen)
            if left is None or not isinstance(node.right, ast.Constant) or type(node.right.value) is not str:
                return None
            parts = self._portable(node.right.value)
            return left.joinpath(*parts) if parts else None
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            selected = self.evaluate(node.value, scope, before, seen)
            return selected.parent if selected is not None else None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) \
                and node.value.attr == "parents" and isinstance(node.slice, ast.Constant) \
                and type(node.slice.value) is int and 0 <= node.slice.value <= 32:
            selected = self.evaluate(node.value.value, scope, before, seen)
            return selected.parents[node.slice.value] if selected is not None else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            selected = self.evaluate(node.func.value, scope, before, seen)
            if selected is None:
                return None
            if node.func.attr in {"resolve", "absolute"} and not node.args and not node.keywords:
                return selected
            if node.func.attr == "joinpath" and node.args and not node.keywords:
                parts: list[str] = []
                for argument in node.args:
                    if not isinstance(argument, ast.Constant) or type(argument.value) is not str:
                        return None
                    selected_parts = self._portable(argument.value)
                    if selected_parts is None:
                        return None
                    parts.extend(selected_parts)
                return selected.joinpath(*parts)
            if node.func.attr == "with_name" and len(node.args) == 1 and not node.keywords:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and type(argument.value) is str:
                    parts = self._portable(argument.value)
                    if parts is not None and len(parts) == 1:
                        return selected.with_name(parts[0])
        return None


def _call_operation(call: ast.Call, functions: dict[tuple[str, ...], str]) -> str | None:
    return functions.get(_chain(call.func))


def _safe_spec_guard(node: ast.Name, spec_name: str,
                     parents: dict[ast.AST, ast.AST]) -> bool:
    cursor: ast.AST = node
    while cursor in parents and not isinstance(parents[cursor], _SCOPE):
        cursor = parents[cursor]
        statement = parents.get(cursor)
        test = (statement.test if isinstance(statement, (ast.If, ast.While)) else
                statement.test if isinstance(statement, ast.Assert) else None)
        if test is not None and node in set(ast.walk(test)):
            allowed = (ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Name, ast.Attribute,
                       ast.Constant, ast.Load, ast.And, ast.Or, ast.Not, ast.Is, ast.IsNot)
            return (all(isinstance(part, allowed) for part in ast.walk(test))
                    and all(not isinstance(part, ast.Name) or part.id == spec_name
                            for part in ast.walk(test))
                    and all(not isinstance(part, ast.Attribute)
                            or _chain(part) == (spec_name, "loader") for part in ast.walk(test)))
    return False


def _ordinary_target(root: Path, relative: str) -> bool:
    selected = root
    for part in PurePosixPath(relative).parts:
        selected /= part
        try:
            information = selected.lstat()
        except OSError:
            return False
        if selected.is_symlink() or getattr(information, "st_file_attributes", 0) & 0x400:
            return False
    try:
        return stat.S_ISREG(selected.lstat().st_mode) and selected.resolve(strict=True).is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _bounded_registry_lifetime(
        tree: ast.Module, scope: ast.AST, execution: ast.Call,
        module_name: str, module_local: str, nodes: list[ast.AST],
        parents: dict[ast.AST, ast.AST],
        bindings: dict[tuple[ast.AST, str], list[ast.AST]]) \
        -> tuple[set[ast.AST], set[ast.Name]] | None:
    """Recognize one non-escaping ``sys.modules`` insertion lifetime.

    The accepted source shape guards against replacing an existing key, inserts
    the newly created module immediately before a ``try``, executes the loader
    in that ``try``, and deletes the same literal key in its sole ``finally``.
    This binds source syntax only; it is not a claim of thread isolation.
    """
    sys_names: set[str] = set()
    for node in nodes:
        if not isinstance(node, ast.Import):
            continue
        owner = _scope(node, parents)
        if owner not in {tree, scope}:
            continue
        for alias in node.names:
            if alias.name != "sys":
                continue
            name = alias.asname or "sys"
            if bindings.get((owner, name)) == [alias]:
                sys_names.add(name)

    def registry(node: ast.AST) -> bool:
        return (isinstance(node, ast.Attribute) and node.attr == "modules"
                and isinstance(node.value, ast.Name)
                and node.value.id in sys_names)

    scope_registry = [node for node in nodes if registry(node)
                      and _scope(node, parents) is scope]
    if not scope_registry:
        return set(), set()
    if not sys_names or not isinstance(getattr(scope, "body", None), list):
        return None

    execution_statement = parents.get(execution)
    selected_try = parents.get(execution_statement) if isinstance(
        execution_statement, ast.Expr) else None
    if (not isinstance(selected_try, ast.Try) or execution_statement not in selected_try.body
            or selected_try.handlers or selected_try.orelse
            or len(selected_try.finalbody) != 1):
        return None
    body = scope.body
    try:
        position = body.index(selected_try)
    except ValueError:
        return None
    if position < 2:
        return None
    guard, insertion = body[position - 2:position]

    guard_registry: ast.AST | None = None
    if (isinstance(guard, ast.If) and not guard.orelse and len(guard.body) == 1
            and isinstance(guard.body[0], ast.Raise)
            and isinstance(guard.test, ast.Compare) and len(guard.test.ops) == 1
            and isinstance(guard.test.ops[0], ast.In)
            and len(guard.test.comparators) == 1
            and isinstance(guard.test.left, ast.Constant)
            and guard.test.left.value == module_name
            and registry(guard.test.comparators[0])):
        guard_registry = guard.test.comparators[0]
    if guard_registry is None:
        return None

    insertion_registry: ast.AST | None = None
    inserted_module: ast.Name | None = None
    if (isinstance(insertion, ast.Assign) and len(insertion.targets) == 1
            and isinstance(insertion.targets[0], ast.Subscript)
            and registry(insertion.targets[0].value)
            and isinstance(insertion.targets[0].slice, ast.Constant)
            and insertion.targets[0].slice.value == module_name
            and isinstance(insertion.value, ast.Name)
            and insertion.value.id == module_local):
        insertion_registry = insertion.targets[0].value
        inserted_module = insertion.value
    if insertion_registry is None or inserted_module is None:
        return None

    cleanup = selected_try.finalbody[0]
    cleanup_registry: ast.AST | None = None
    if (isinstance(cleanup, ast.Delete) and len(cleanup.targets) == 1
            and isinstance(cleanup.targets[0], ast.Subscript)
            and registry(cleanup.targets[0].value)
            and isinstance(cleanup.targets[0].slice, ast.Constant)
            and cleanup.targets[0].slice.value == module_name):
        cleanup_registry = cleanup.targets[0].value
    if cleanup_registry is None:
        return None

    accepted = {guard_registry, insertion_registry, cleanup_registry}
    if set(scope_registry) != accepted:
        return None
    return accepted, {inserted_module}


def _descends_from(node: ast.AST, ancestor: ast.AST,
                   parents: dict[ast.AST, ast.AST]) -> bool:
    while node in parents:
        node = parents[node]
        if node is ancestor:
            return True
    return False


def _site(root: Path, importer: str, tree: ast.Module, call: ast.Call,
          nodes: list[ast.AST], parents: dict[ast.AST, ast.AST],
          functions: dict[tuple[str, ...], str],
          paths: _Paths, files: dict[str, dict[str, Any]]) \
        -> tuple[dict[str, Any], set[ast.AST]] | None:
    if _call_operation(call, functions) != "spec_from_file_location" \
            or len(call.args) != 2 or call.keywords:
        return None
    module_name = call.args[0].value if isinstance(call.args[0], ast.Constant) else None
    if type(module_name) is not str or _MODULE_NAME.fullmatch(module_name) is None:
        return None
    scope = _scope(call, parents)
    assignment = parents.get(call)
    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)) or parents.get(assignment) is not scope:
        return None
    targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return None
    spec_name, spec_target = targets[0].id, targets[0]
    target = paths.evaluate(call.args[1], scope, call.lineno)
    if target is None:
        return None
    try:
        relative = target.resolve(strict=True).relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None
    entry = files.get(relative)
    if (relative == importer or not relative.endswith(".py") or entry is None
            or entry.get("provenance") != "GIT_TRACKED"
            or not _ordinary_target(root, importer) or not _ordinary_target(root, relative)):
        return None
    target_raw = target.read_bytes()
    if bytes_digest(target_raw) != entry["sha256"]:
        return None
    try:
        target_attributes = _target_attributes(target_raw, relative)
    except (SyntaxError, UnicodeError, RecursionError, ValueError):
        return None
    if target_attributes is None:
        return None

    scope_nodes = [node for node in nodes if node is scope or _scope(node, parents) is scope]
    spec_writes = [node for node in scope_nodes if isinstance(node, ast.Name)
                   and node.id == spec_name and isinstance(node.ctx, (ast.Store, ast.Del))]
    if (spec_writes != [spec_target]
            or paths.bindings.get((scope, spec_name)) != [spec_target]):
        return None
    module_calls = [node for node in scope_nodes if isinstance(node, ast.Call)
                    and _call_operation(node, functions) == "module_from_spec"
                    and len(node.args) == 1 and not node.keywords
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == spec_name]
    if len(module_calls) != 1 or module_calls[0].lineno <= call.lineno:
        return None
    module_call = module_calls[0]
    module_assignment = parents.get(module_call)
    if (not isinstance(module_assignment, (ast.Assign, ast.AnnAssign))
            or parents.get(module_assignment) is not scope):
        return None
    module_targets = (module_assignment.targets if isinstance(module_assignment, ast.Assign)
                      else [module_assignment.target])
    if len(module_targets) != 1 or not isinstance(module_targets[0], ast.Name):
        return None
    module_name_local, module_target = module_targets[0].id, module_targets[0]
    module_writes = [node for node in scope_nodes if isinstance(node, ast.Name)
                     and node.id == module_name_local and isinstance(node.ctx, (ast.Store, ast.Del))]
    if (module_writes != [module_target]
            or paths.bindings.get((scope, module_name_local)) != [module_target]):
        return None

    executions = [node for node in scope_nodes if isinstance(node, ast.Call)
                  and _chain(node.func) == (spec_name, "loader", "exec_module")
                  and len(node.args) == 1 and not node.keywords
                  and isinstance(node.args[0], ast.Name) and node.args[0].id == module_name_local]
    if len(executions) != 1 or executions[0].lineno <= module_call.lineno:
        return None
    execution = executions[0]
    registry_lifetime = _bounded_registry_lifetime(
        tree, scope, execution, module_name, module_name_local, nodes, parents,
        paths.bindings)
    if registry_lifetime is None:
        return None
    registry_nodes, registry_module_loads = registry_lifetime

    spec_loads = [node for node in scope_nodes if isinstance(node, ast.Name)
                  and node.id == spec_name and isinstance(node.ctx, ast.Load)]
    for load in spec_loads:
        if load is module_call.args[0] or load in set(ast.walk(execution.func)):
            continue
        if not _safe_spec_guard(load, spec_name, parents):
            return None
    attribute_names: set[str] = set()
    module_loads = [node for node in scope_nodes if isinstance(node, ast.Name)
                    and node.id == module_name_local and isinstance(node.ctx, ast.Load)]
    for load in module_loads:
        if load is execution.args[0] or load in registry_module_loads:
            continue
        parent = parents.get(load)
        if isinstance(parent, ast.Return) and parent.value is load:
            returned = _returned_attributes(scope, module_name_local, nodes, parents,
                                            paths.bindings, tree=tree,
                                            assignments=paths.assignments)
            if returned is None:
                return None
            attribute_names.update(returned)
            continue
        if (not isinstance(parent, ast.Attribute) or parent.value is not load
                or not isinstance(parent.ctx, ast.Load) or parent.attr == "__dict__"
                or load.lineno <= execution.lineno):
            return None
        attribute_names.add(parent.attr)
    if any(name not in target_attributes for name in attribute_names):
        return None

    # A local target alias belongs only to this binding. Module-level path
    # constants may feed several independently checked sites.
    if isinstance(call.args[1], ast.Name):
        local = paths.assignments.get((scope, call.args[1].id), [])
        if local:
            if paths.bindings.get((scope, call.args[1].id)) != [local[0][0]]:
                return None
            target_loads = [node for node in scope_nodes if isinstance(node, ast.Name)
                            and node.id == call.args[1].id and isinstance(node.ctx, ast.Load)]
            if target_loads != [call.args[1]]:
                return None

    path_nodes = set(ast.walk(call.args[1]))
    protected = {target.resolve(), (root / Path(*PurePosixPath(importer).parts)).resolve()}
    for candidate in (node for node in nodes if isinstance(node, ast.Call) and node not in path_nodes):
        if candidate is call:
            continue
        if (_chain(candidate.func) in paths.constructors
                or isinstance(candidate.func, ast.Attribute)
                and candidate.func.attr in {"resolve", "absolute", "joinpath", "with_name"}):
            continue  # Static path construction has no filesystem effect.
        receiver = candidate.func.value if isinstance(candidate.func, ast.Attribute) else None
        selected = paths.evaluate(receiver, _scope(candidate, parents), candidate.lineno) if receiver else None
        if selected is not None and selected.resolve() in protected:
            return None
        for argument in candidate.args:
            selected = paths.evaluate(argument, _scope(candidate, parents), candidate.lineno)
            if selected is not None and selected.resolve() in protected:
                return None
    # A closure referring to these aliases defeats this scope-local ownership
    # proof even if the outer loads themselves look finite. References in a
    # sibling function are unrelated and must not reject an otherwise closed
    # site merely because that sibling chose the same conventional name.
    for name in (spec_name, module_name_local,
                 call.args[1].id if isinstance(call.args[1], ast.Name) else ""):
        if any(isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
               and _scope(node, parents) is not scope and _descends_from(node, scope, parents)
               for node in nodes):
            return None

    permitted = (set(ast.walk(call.func)) | set(ast.walk(module_call.func))
                 | set(ast.walk(execution.func)) | registry_nodes)
    surface = {
        "surface_id": f"python-source-import:{importer}:{module_name}@{call.lineno}",
        "path": importer,
        "line": call.lineno,
        "form": "SourceImport",
        "source_kinds": [],
        "hints": [],
        "unresolved_marker": False,
        "module_name": module_name,
        "target_path": relative,
        "target_surface_id": f"python:{relative}:<module>",
        "target_attribute_names": sorted(attribute_names),
        "target_attribute_surface_ids": sorted(
            {target_attributes[name] for name in attribute_names}),
        "target_source_digest": entry["sha256"],
        "importer_source_digest": files[importer]["sha256"],
        "binding_scope": (
            "DECLARED_STATIC_LOCAL_SOURCE_IMPORT_WITH_BOUNDED_REGISTRY_LIFETIME_"
            "NOT_RUNTIME_EXECUTION" if registry_nodes else
            "DECLARED_STATIC_LOCAL_SOURCE_IMPORT_NOT_RUNTIME_EXECUTION"
        ),
        "binding_reason": _BINDING_REASON + (_REGISTRY_REASON if registry_nodes else ""),
    }
    return surface, permitted


def _module_import_site(root: Path, importer: str, tree: ast.Module, call: ast.Call,
                        nodes: list[ast.AST], parents: dict[ast.AST, ast.AST],
                        functions: dict[tuple[str, ...], str],
                        assignments: dict[tuple[ast.AST, str], list[tuple[ast.Name, ast.AST, ast.AST]]],
                        scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
                        files: dict[str, dict[str, Any]]) \
        -> tuple[list[dict[str, Any]], set[ast.AST]] | None:
    if (_call_operation(call, functions) != "import_module" or len(call.args) != 1
            or call.keywords):
        return None
    scope = _scope(call, parents)
    module_names = _literal_strings(call.args[0], scope, call.lineno, tree=tree,
                                    parents=parents, assignments=assignments,
                                    bindings=scoped_bindings)
    attribute_names = _attribute_reads(
        call, scope, nodes, parents, scoped_bindings, tree=tree,
        assignments=assignments)
    if module_names is None or attribute_names is None or len(module_names) > 256:
        return None
    selected: list[tuple[str, str, dict[str, Any], dict[str, str]]] = []
    for module_name in sorted(module_names):
        target = _local_module_target(root, importer, module_name, files)
        if target is None:
            return None
        relative, entry, attributes = target
        if any(name not in attributes for name in attribute_names):
            return None
        selected.append((module_name, relative, entry, attributes))
    surfaces = [{
        "surface_id": f"python-source-import:{importer}:{module_name}@{call.lineno}",
        "path": importer,
        "line": call.lineno,
        "form": "SourceImport",
        "source_kinds": [],
        "hints": [],
        "unresolved_marker": False,
        "module_name": module_name,
        "target_path": relative,
        "target_surface_id": f"python:{relative}:<module>",
        "target_attribute_names": sorted(attribute_names),
        "target_attribute_surface_ids": sorted(
            {attributes[name] for name in attribute_names}),
        "target_source_digest": entry["sha256"],
        "importer_source_digest": files[importer]["sha256"],
        "binding_scope": "DECLARED_STATIC_LOCAL_MODULE_IMPORT_NOT_RUNTIME_EXECUTION",
        "binding_reason": _BINDING_REASON,
    } for module_name, relative, entry, attributes in selected]
    return surfaces, set(ast.walk(call.func))


def _isolated_main_namespace(
    node: ast.AST,
    scope: ast.AST,
    parents: dict[ast.AST, ast.AST],
    scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
) -> bool:
    def exact_dict(value: ast.AST | None) -> bool:
        return (
            isinstance(value, ast.Dict)
            and len(value.keys) == len(value.values) == 1
            and isinstance(value.keys[0], ast.Constant)
            and value.keys[0].value == "__name__"
            and isinstance(value.values[0], ast.Constant)
            and value.values[0].value == "__main__"
        )

    if exact_dict(node):
        return True
    if not isinstance(node, ast.Name):
        return False
    bindings = scoped_bindings.get((scope, node.id), [])
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
        return False
    statement = parents.get(bindings[0])
    if isinstance(statement, ast.Assign):
        value = statement.value
    elif isinstance(statement, ast.AnnAssign):
        value = statement.value
    else:
        return False
    return exact_dict(value)


def _test_worker_source_sites(
    root: Path,
    importer: str,
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
    files: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[ast.AST]] | None:
    """Bind the finite worker strings deliberately executed by adapter tests."""

    declared = _TEST_WORKER_SITES.get(importer)
    if declared is None:
        return None
    target_path, worker_attribute, allowed_functions, filenames = declared
    entry = files.get(target_path)
    if entry is None or not _ordinary_target(root, target_path):
        return None
    raw = (root / Path(*PurePosixPath(target_path).parts)).read_bytes()
    if bytes_digest(raw) != entry["sha256"]:
        return None
    attributes = _target_attributes(raw, target_path)
    if attributes is None or worker_attribute not in attributes:
        return None

    executions = [
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
    ]
    if not executions:
        return None
    surfaces: list[dict[str, Any]] = []
    permitted: set[ast.AST] = set()
    for execution in executions:
        scope = _scope(execution, parents)
        if not isinstance(scope, ast.FunctionDef) or scope.name not in allowed_functions:
            return None
        if not _unshadowed("exec", scope, parents, scoped_bindings):
            return None
        if len(execution.args) != 2 or execution.keywords:
            return None
        compiled = execution.args[0]
        if not (
            isinstance(compiled, ast.Call)
            and isinstance(compiled.func, ast.Name)
            and compiled.func.id == "compile"
            and _unshadowed("compile", scope, parents, scoped_bindings)
            and len(compiled.args) == 3
            and not compiled.keywords
            and isinstance(compiled.args[1], ast.Constant)
            and compiled.args[1].value in filenames
            and isinstance(compiled.args[2], ast.Constant)
            and compiled.args[2].value == "exec"
            and _isolated_main_namespace(
                execution.args[1], scope, parents, scoped_bindings
            )
        ):
            return None
        source = compiled.args[0]
        source_attributes = {
            node.attr for node in ast.walk(source) if isinstance(node, ast.Attribute)
        }
        if worker_attribute not in source_attributes:
            if not (
                scope.name == "_run_helper"
                and isinstance(source, ast.Name)
                and source.id == "source"
            ):
                return None
        permitted.update(ast.walk(execution.func))
        surfaces.append(
            {
                "surface_id": (
                    f"python-source-import:{importer}:"
                    f"test-worker-{worker_attribute}@{execution.lineno}"
                ),
                "path": importer,
                "line": execution.lineno,
                "form": "SourceImport",
                "source_kinds": [],
                "hints": [],
                "unresolved_marker": False,
                "module_name": f"test-worker:{worker_attribute}",
                "target_path": target_path,
                "target_surface_id": f"python:{target_path}:<module>",
                "target_attribute_names": [worker_attribute],
                "target_attribute_surface_ids": [attributes[worker_attribute]],
                "target_source_digest": entry["sha256"],
                "importer_source_digest": files[importer]["sha256"],
                "binding_scope": (
                    "DECLARED_DIGEST_BOUND_ISOLATED_TEST_WORKER_SOURCE_"
                    "NOT_RUNTIME_INTERFACE"
                ),
                "binding_reason": _TEST_WORKER_SOURCE_REASON,
            }
        )
    return surfaces, permitted


def _test_checker_source_sites(
    importer: str,
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
    files: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[ast.AST]] | None:
    """Bind the exact test-local generated checker module construction."""

    if importer != "tests/test_package_checker_source_binding.py":
        return None
    selected = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_fixture_module", "_normally_imported_fixture_module"}
    }
    if set(selected) != {"_fixture_module", "_normally_imported_fixture_module"}:
        return None
    fixture = selected["_fixture_module"]
    ordinary = selected["_normally_imported_fixture_module"]
    if (
        ast.dump(fixture, include_attributes=False) != _TEST_CHECKER_FIXTURE_SHAPE
        or ast.dump(ordinary, include_attributes=False)
        != _TEST_CHECKER_ORDINARY_SHAPE
        or not _unshadowed("exec", fixture, parents, scoped_bindings)
        or not _unshadowed("compile", fixture, parents, scoped_bindings)
    ):
        return None
    executions = [
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
    ]
    if len(executions) != 1 or _scope(executions[0], parents) is not fixture:
        return None
    permitted: set[ast.AST] = set(ast.walk(executions[0].func))
    for node in ast.walk(ordinary):
        if isinstance(node, ast.Attribute) and _chain(node) in {
            ("importlib", "util", "spec_from_file_location"),
            ("importlib", "util", "module_from_spec"),
        }:
            permitted.add(node)
    line = executions[0].lineno
    surface = {
        "surface_id": (
            f"python-source-import:{importer}:"
            f"verifier.runtime.fixture_checker_execution@{line}"
        ),
        "path": importer,
        "line": line,
        "form": "SourceImport",
        "source_kinds": [],
        "hints": [],
        "unresolved_marker": False,
        "module_name": "verifier.runtime.fixture_checker_execution",
        "target_path": importer,
        "target_surface_id": f"python:{importer}:<module>",
        "target_attribute_names": ["ADAPTER", "check_observations"],
        "target_attribute_surface_ids": [],
        "target_source_digest": files[importer]["sha256"],
        "importer_source_digest": files[importer]["sha256"],
        "binding_scope": (
            "DECLARED_DIGEST_BOUND_TEST_LOCAL_CHECKER_SOURCE_"
            "NOT_RUNTIME_INTERFACE"
        ),
        "binding_reason": _TEST_CHECKER_SOURCE_REASON,
    }
    return [surface], permitted


def _held_checker_source_sites(
    root: Path,
    importer: str,
    tree: ast.Module,
    nodes: list[ast.AST],
    parents: dict[ast.AST, ast.AST],
    scoped_bindings: dict[tuple[ast.AST, str], list[ast.AST]],
    files: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[ast.AST]] | None:
    """Bind the fresh checker worker's finite held-source execution surface.

    The worker intentionally compiles current source bytes rather than trusting
    bytecode or a stale import.  Admission is therefore not an ``exec`` waiver:
    both guarding functions must retain their exact syntax, their runtime names
    must be unshadowed, and every path the guard can select is enumerated from
    the current census with its digest.  Any drift leaves the ordinary dynamic
    construction finding in place.
    """

    pure = PurePosixPath(importer)
    if pure.parts[-3:] != (
        "verifier",
        "runtime",
        "package_checker_worker.py",
    ):
        return None

    selected_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_safe_checker_path", "_load_held_checker"}
    ]
    if len(selected_functions) != 2 or {
        node.name for node in selected_functions
    } != {"_safe_checker_path", "_load_held_checker"}:
        return None
    functions = {node.name: node for node in selected_functions}
    safe = functions["_safe_checker_path"]
    loader = functions["_load_held_checker"]
    if (
        ast.dump(safe, include_attributes=False) != _HELD_SAFE_PATH_SHAPE
        or ast.dump(loader, include_attributes=False) != _HELD_LOAD_SHAPE
    ):
        return None

    def exact_import(module: str, name: str | None, bound: str) -> bool:
        aliases: list[ast.alias] = []
        for statement in tree.body:
            if name is None and isinstance(statement, ast.Import):
                aliases.extend(
                    alias
                    for alias in statement.names
                    if alias.name == module and (alias.asname or module) == bound
                )
            elif (
                name is not None
                and isinstance(statement, ast.ImportFrom)
                and statement.level == 0
                and statement.module == module
            ):
                aliases.extend(
                    alias
                    for alias in statement.names
                    if alias.name == name and (alias.asname or name) == bound
                )
        return len(aliases) == 1 and scoped_bindings.get((tree, bound)) == aliases

    if not (
        exact_import("sys", None, "sys")
        and exact_import("pathlib", "Path", "Path")
        and exact_import("types", "ModuleType", "ModuleType")
        and all(
            _unshadowed(name, scope, parents, scoped_bindings)
            for scope, names in (
                (safe, ("type", "str")),
                (loader, ("str", "compile", "exec")),
            )
            for name in names
        )
    ):
        return None

    executions = [
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
    ]
    registries = [
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    ]
    if (
        len(executions) != 1
        or _scope(executions[0], parents) is not loader
        or len(registries) != 1
        or _scope(registries[0], parents) is not loader
    ):
        return None

    source_prefix = PurePosixPath(*pure.parts[:-3])
    runtime_parent = source_prefix / "verifier" / "runtime"
    targets: list[tuple[str, dict[str, Any], dict[str, str]]] = []
    for relative, entry in sorted(files.items()):
        candidate = PurePosixPath(relative)
        if candidate.parent != runtime_parent or candidate.suffix != ".py":
            continue
        if not _ordinary_target(root, relative):
            return None
        raw = (root / Path(*candidate.parts)).read_bytes()
        if bytes_digest(raw) != entry["sha256"]:
            return None
        attributes = _target_attributes(raw, relative)
        if attributes is None:
            return None
        targets.append((relative, entry, attributes))
    if not targets or len(targets) > 1024:
        return None

    line = executions[0].lineno
    surfaces: list[dict[str, Any]] = []
    for relative, entry, attributes in targets:
        stem = PurePosixPath(relative).stem
        module_name = "verifier.runtime." + stem
        selected_names = sorted(
            {"ADAPTER", "CHECKER_CONTRACT", "check_observations"} & attributes.keys()
        )
        surfaces.append(
            {
                "surface_id": (
                    f"python-source-import:{importer}:{module_name}@{line}"
                ),
                "path": importer,
                "line": line,
                "form": "SourceImport",
                "source_kinds": [],
                "hints": [],
                "unresolved_marker": False,
                "module_name": module_name,
                "target_path": relative,
                "target_surface_id": f"python:{relative}:<module>",
                "target_attribute_names": selected_names,
                "target_attribute_surface_ids": sorted(
                    {attributes[name] for name in selected_names}
                ),
                "target_source_digest": entry["sha256"],
                "importer_source_digest": files[importer]["sha256"],
                "binding_scope": (
                    "DECLARED_FINITE_DIRECTORY_HELD_SOURCE_IMPORT_"
                    "NOT_RUNTIME_EXECUTION"
                ),
                "binding_reason": _HELD_SOURCE_REASON,
            }
        )
    permitted = set(ast.walk(executions[0].func)) | set(registries)
    return surfaces, permitted


def discover(root: Path, importer: str, tree: ast.Module,
             entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[ast.AST]]:
    """Return digest-bound import surfaces and exactly exempted loader references."""
    nodes = list(ast.walk(tree))
    if len(nodes) > 250_000:
        return [], set()
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    bindings = _bindings(nodes)
    functions, constructors = _imports(tree, bindings)
    assignments = _direct_assignments(nodes, parents)
    scoped_bindings = _scoped_bindings(nodes, parents)
    paths = _Paths(root, importer, tree, parents, assignments, scoped_bindings,
                   constructors)
    files = {entry["path"]: entry for entry in entries}
    if importer not in files:
        return [], set()
    surfaces: list[dict[str, Any]] = []
    permitted: set[ast.AST] = set()
    held_checker = _held_checker_source_sites(
        root, importer, tree, nodes, parents, scoped_bindings, files
    )
    if held_checker is not None:
        selected_surfaces, accepted = held_checker
        surfaces.extend(selected_surfaces)
        permitted.update(accepted)
    test_workers = _test_worker_source_sites(
        root, importer, tree, nodes, parents, scoped_bindings, files
    )
    if test_workers is not None:
        selected_surfaces, accepted = test_workers
        surfaces.extend(selected_surfaces)
        permitted.update(accepted)
    test_checker = _test_checker_source_sites(
        importer, tree, nodes, parents, scoped_bindings, files
    )
    if test_checker is not None:
        selected_surfaces, accepted = test_checker
        surfaces.extend(selected_surfaces)
        permitted.update(accepted)
    for call in (node for node in nodes if isinstance(node, ast.Call)):
        if (any(operation == "spec_from_file_location" for operation in functions.values())
                and any(operation == "module_from_spec" for operation in functions.values())):
            selected = _site(root, importer, tree, call, nodes, parents, functions,
                             paths, files)
            if selected is not None:
                surface, accepted = selected
                surfaces.append(surface)
                permitted.update(accepted)
        module_import = _module_import_site(
            root, importer, tree, call, nodes, parents, functions,
            assignments, scoped_bindings, files)
        if module_import is not None:
            selected_surfaces, accepted = module_import
            surfaces.extend(selected_surfaces)
            permitted.update(accepted)
    surfaces.sort(key=lambda row: (row["line"], row["surface_id"]))
    if len({row["surface_id"] for row in surfaces}) != len(surfaces):
        return [], set()
    return surfaces, permitted
