"""Non-executing source discovery for Verifier Standard (VSTD) admission.

Terminology: JavaScript Object Notation (JSON).

Terminology: reduced instruction set computer (RISC).

Python abstract syntax tree (AST) identities are per definition, including
methods and nested/async functions. File ownership does not imply ownership of
new definitions or export aliases. An optional isolated JavaScript parser adds
syntax surfaces. Markup exposes individual elements, attributes and embedded
code without rendering; vector documents and optional workflow syntax expose
their own boundaries. Optional Rust/Bash parsers retain unexpanded or dynamic
interface questions. Other language bodies remain unsupported. Export
target bindings never assert successful imports.

Evidence boundary: a literal __vstd_kinds__ is a source declaration. A name or
operation pattern is only a hint. Neither proves real-world financial behavior.
Hypertext Markup Language (HTML); Scalable Vector Graphics (SVG);
YAML Ain't Markup Language (YAML).
"""
from __future__ import annotations

import ast
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
import multiprocessing
import os
from pathlib import Path
import re
from typing import Any, Iterator

from verifier.core.namespace import ObjectKind
from verifier.runtime.self_polish_estate import (
    MAX_AST_BYTES, bytes_digest, capture_candidate_source_census,
)
from verifier.runtime import (namespace_exports, namespace_html, namespace_javascript,
                              namespace_source_imports, namespace_svg, namespace_systems,
                              namespace_workflows)


_CODE_SUFFIXES = frozenset({".lean", ".js", ".ts", ".tsx", ".jsx", ".rs", ".c", ".cpp", ".h",
    ".java", ".go", ".cs", ".rb", ".php", ".swift", ".kt", ".scala", ".r", ".jl", ".lua",
    ".pl", ".lisp", ".cl", ".ex", ".exs", ".erl", ".hs", ".fs", ".f90", ".sql", ".sh", ".ps1"})
_ARTIFACT_SUFFIXES = frozenset({".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".csv", ".tsv", ".lock", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".vstd",
    ".cff", ".pem", ".cose", ".msgpack", ".css"})
# A compressed JSON result is still a DATA artifact, not an undiscovered source
# language. Keep the compound suffix exact so source archives such as ``.py.gz``
# continue to fail closed until a real discovery adapter is selected.
_ARTIFACT_COMPOUND_SUFFIXES = (".json.gz",)
_ARTIFACT_NAMES = frozenset({"LICENSE", "NOTICE", "MANIFEST.in", "PKG-INFO"})
_ADDED_KIND_NAMES = (
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
)
_HINT_KIND_NAMES = tuple(
    kind.value for kind in ObjectKind if kind is not ObjectKind.OBJECT
) + _ADDED_KIND_NAMES


def _hint_kinds(words: set[str]) -> list[str]:
    """Suggest installed roles without treating a lexical match as evidence.

    These are deliberately transparent name signals, not a behavioral detector.
    In particular, a robot-shaped name neither proves physical reach nor proves
    confinement; an Agent-shaped name does not prove agency; and removing a name
    is not a supported non-applicability decision.  Original kinds are included
    because a generic OBJECT label must not make their applicability invisible.
    """
    hints = {kind for kind in _HINT_KIND_NAMES if kind.lower() in words}
    if {"debit", "credit"} <= words:
        hints.add("LEDGER")
    if {"commit", "rollback"} <= words:
        hints.add("TRANSACTION")
    if {"fin", "bot"} <= words:
        hints.add("FINBOT")
    return sorted(hints)


def _hints(node: ast.AST) -> list[str]:
    """Small inspectable heuristics; never a classifier claiming semantic proof."""
    names = [child.id for child in ast.walk(node) if isinstance(child, ast.Name)]
    names += [child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)]
    names += [child.name for child in ast.walk(node)
              if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
    words = {word.lower() for name in names
             for word in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", name)}
    return _hint_kinds(words)


def _definition_hints(tree: ast.AST) -> dict[ast.AST, list[str]]:
    """Accumulate name signals in one traversal instead of re-walking each body.

    Ancestor definitions receive the same lexical signals as a whole-body walk.
    This is only a cost reduction, not a stronger classification claim.
    """
    words: dict[ast.AST, set[str]] = {tree: set()}
    scopes = [tree]

    @lru_cache(maxsize=4096)
    def split(name: str) -> frozenset[str]:
        return frozenset(word.lower() for word in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", name))

    class Names(ast.NodeVisitor):
        def generic_visit(self, node: ast.AST) -> None:
            definition = isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            if definition:
                scopes.append(node)
                words[node] = set()
            name = (node.name if definition else node.id if isinstance(node, ast.Name)
                    else node.attr if isinstance(node, ast.Attribute) else None)
            if name is not None:
                tokens = split(name)
                for scope in scopes:
                    words[scope].update(tokens)
            super().generic_visit(node)
            if definition:
                scopes.pop()

    Names().visit(tree)
    return {node: _hint_kinds(names) for node, names in words.items()}


def _markers(node: ast.AST) -> tuple[set[str], bool]:
    kinds: set[str] = set()
    unresolved = False
    inspected: set[ast.AST] = set()
    # Scope-local declarations inherit downward. A module declaration cannot be
    # evaded by assigning its methods to a different manifest object.
    for statement in getattr(node, "body", []):
        targets = statement.targets if isinstance(statement, ast.Assign) else (
            [statement.target] if isinstance(statement, ast.AnnAssign) else [])
        if not any(isinstance(target, ast.Name) and target.id == "__vstd_kinds__" for target in targets):
            continue
        inspected.add(statement)
        try:
            value = ast.literal_eval(statement.value)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            unresolved = True
            continue
        if not isinstance(value, (list, tuple)) or not value or any(
                not isinstance(item, str) or re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", item) is None for item in value):
            unresolved = True
        else:
            kinds.update(value)
    # Nonliteral control flow, unpacking, deletion and attribute assignment are
    # not absence of a marker. Keep them unresolved instead of dropping the role.
    pending = [item for item in getattr(node, "body", []) if item not in inspected]
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # These have their own lexical scope.
        marker = ((isinstance(child, ast.Name) and child.id == "__vstd_kinds__")
                  or (isinstance(child, ast.Attribute) and child.attr == "__vstd_kinds__"))
        if marker and isinstance(child.ctx, (ast.Store, ast.Del)):
            unresolved = True
        pending.extend(ast.iter_child_nodes(child))
    return kinds, unresolved


def _python_surfaces(path: str, raw: bytes, tree: ast.Module | None = None) -> list[dict[str, Any]]:
    if len(raw) > MAX_AST_BYTES:
        raise ValueError("Python syntax census exceeds its byte bound")
    tree = ast.parse(raw, filename=path) if tree is None else tree
    if sum(1 for _ in ast.walk(tree)) > 250_000:
        raise ValueError("Python syntax census exceeds its node bound")
    surfaces: list[dict[str, Any]] = []
    hints = _definition_hints(tree)

    class Definitions(ast.NodeVisitor):
        def __init__(self) -> None:
            self.parents: list[str] = []
            self.required: set[str] = set()
            self.unresolved = False

        def record(self, node: ast.AST, name: str) -> None:
            prior_required, prior_unresolved = self.required, self.unresolved
            local, unresolved = _markers(node)
            self.required = prior_required | local
            self.unresolved = prior_unresolved or unresolved
            identifier = "python:" + path + ":" + (".".join(self.parents + [name]) if name else "<module>")
            surfaces.append({"surface_id": identifier, "path": path,
                "line": getattr(node, "lineno", 1), "form": type(node).__name__,
                "source_kinds": sorted(self.required), "hints": hints[node],
                "unresolved_marker": self.unresolved})
            if name:
                self.parents.append(name)
            self.generic_visit(node)
            if name:
                self.parents.pop()
            self.required, self.unresolved = prior_required, prior_unresolved

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.record(node, node.name)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.record(node, node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.record(node, node.name)

    Definitions().record(tree, "")
    # Same-name redefinitions cannot silently collapse into one owned identity.
    seen: set[str] = set()
    for row in surfaces:
        if row["surface_id"] in seen:
            row["surface_id"] += "@" + str(row["line"])
        seen.add(row["surface_id"])
    return surfaces


def _static_exec_surfaces(
    path: str,
    tree: ast.Module,
) -> tuple[list[dict[str, Any]], set[ast.AST]]:
    """Discover one closed literal ``exec`` into an isolated namespace.

    This adapter is deliberately narrower than Python evaluation.  It accepts
    one unshadowed module-level ``exec(SOURCE, NAMESPACE)`` only when SOURCE is
    one prior literal string, NAMESPACE is one prior empty dictionary, and
    every later namespace read is a literal-key extraction into a module name.
    The embedded source must itself have no dynamic-construction capability.
    Anything else returns no exemption, so ordinary discovery keeps the file
    unresolved.
    """
    nodes = list(ast.walk(tree))
    parents = {
        child: parent
        for parent in nodes
        for child in ast.iter_child_nodes(parent)
    }
    calls = [
        node
        for node in nodes
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
    ]
    if len(calls) != 1:
        return [], set()
    call = calls[0]
    statement = parents.get(call)
    if (
        not isinstance(statement, ast.Expr)
        or parents.get(statement) is not tree
        or len(call.args) != 2
        or call.keywords
        or not all(isinstance(argument, ast.Name) for argument in call.args)
    ):
        return [], set()

    # No local binder may replace the builtin selected above.
    if any(
        (
            isinstance(node, ast.Name)
            and node.id == "exec"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        )
        or isinstance(node, ast.arg)
        and node.arg == "exec"
        or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == "exec"
        or isinstance(node, (ast.Import, ast.ImportFrom))
        and any((alias.asname or alias.name.split(".")[0]) == "exec" for alias in node.names)
        for node in nodes
    ):
        return [], set()

    source_name = call.args[0].id
    namespace_name = call.args[1].id
    direct: dict[str, tuple[ast.AST, ast.AST]] = {}
    for candidate in tree.body:
        if (
            isinstance(candidate, ast.Assign)
            and len(candidate.targets) == 1
            and isinstance(candidate.targets[0], ast.Name)
        ):
            direct[candidate.targets[0].id] = (candidate.targets[0], candidate.value)
        elif (
            isinstance(candidate, ast.AnnAssign)
            and isinstance(candidate.target, ast.Name)
            and candidate.value is not None
        ):
            direct[candidate.target.id] = (candidate.target, candidate.value)
    source_binding = direct.get(source_name)
    namespace_binding = direct.get(namespace_name)
    if source_binding is None or namespace_binding is None:
        return [], set()
    source_target, source_value = source_binding
    namespace_target, namespace_value = namespace_binding
    if (
        not isinstance(source_value, ast.Constant)
        or type(source_value.value) is not str
        or not isinstance(namespace_value, ast.Dict)
        or namespace_value.keys
        or source_target.lineno >= call.lineno
        or namespace_target.lineno >= call.lineno
    ):
        return [], set()

    # Rebinding either input, even in a nested/global scope, invalidates the
    # adapter.  Read-only reuse of the literal source is harmless.
    for selected, target in (
        (source_name, source_target),
        (namespace_name, namespace_target),
    ):
        stores = [
            node
            for node in nodes
            if isinstance(node, ast.Name)
            and node.id == selected
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        if stores != [target] or any(
            isinstance(node, (ast.Global, ast.Nonlocal)) and selected in node.names
            for node in nodes
        ):
            return [], set()

    extractions: dict[str, str] = {}
    allowed_namespace_names = {namespace_target, call.args[1]}
    for name in (
        node
        for node in nodes
        if isinstance(node, ast.Name) and node.id == namespace_name
    ):
        if name in allowed_namespace_names:
            continue
        subscript = parents.get(name)
        assignment = parents.get(subscript) if isinstance(subscript, ast.Subscript) else None
        if (
            not isinstance(subscript, ast.Subscript)
            or subscript.value is not name
            or not isinstance(subscript.ctx, ast.Load)
            or not isinstance(subscript.slice, ast.Constant)
            or type(subscript.slice.value) is not str
            or not isinstance(assignment, (ast.Assign, ast.AnnAssign))
            or assignment not in tree.body
            or assignment.value is not subscript
        ):
            return [], set()
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return [], set()
        key = subscript.slice.value
        alias = targets[0].id
        if key in extractions or alias in extractions.values():
            return [], set()
        extractions[key] = alias
        allowed_namespace_names.add(name)
    if not extractions:
        return [], set()

    embedded_raw = source_value.value.encode("utf-8")
    if len(embedded_raw) > MAX_AST_BYTES:
        return [], set()
    try:
        embedded = ast.parse(embedded_raw, filename=path + "::<static-exec>")
    except (SyntaxError, UnicodeError, RecursionError, ValueError):
        return [], set()
    direct_definitions = {
        node.name
        for node in embedded.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if set(extractions) != direct_definitions or namespace_exports.has_dynamic_construction(
        embedded,
        closed_lazy=False,
    ):
        return [], set()

    surfaces: list[dict[str, Any]] = []
    prefix = "python:" + path + ":"
    for surface in _python_surfaces(path, embedded_raw, embedded)[1:]:
        qualified = surface["surface_id"].removeprefix(prefix)
        root, separator, remainder = qualified.partition(".")
        alias = extractions.get(root)
        if alias is None:
            continue
        exposed = alias + (separator + remainder if separator else "")
        surfaces.append(
            {
                **surface,
                "surface_id": (
                    "python-static-exec:"
                    + path
                    + ":"
                    + namespace_name
                    + "."
                    + exposed
                ),
                "line": source_target.lineno,
                "form": "StaticExec" + surface["form"],
            }
        )
    if not surfaces:
        return [], set()
    return surfaces, {call.func}


# Inside ``discovery_scope`` the census is still captured fresh on every call; only the
# parse of bytes whose census digest has already been discovered is skipped.  A changed
# byte changes the digest, so a stale discovery can never be returned.  Callers receive
# independent copies.
_SCOPE_DEPTH = 0
_SCOPED_DISCOVERIES: dict[tuple[str, str], dict[str, Any]] = {}

# A current repository has enough Python sources that repeating every AST walk in
# one interpreter can exceed the safe idle windows of a shared workstation.  The
# worker boundary receives exact census entries and returns only deterministic
# source summaries.  Output is merged in census order, so scheduling cannot alter
# manifest bytes.  Small repositories stay in-process to avoid spawn overhead.
_PARALLEL_PYTHON_THRESHOLD = 128
_MAX_PYTHON_WORKERS = 4
_WORKER_ROOT: Path | None = None
_WORKER_CENSUS_FILES: list[dict[str, Any]] | None = None


def _discover_python_source(
    root: Path,
    entry: dict[str, Any],
    census_files: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return one digest-bound Python source summary without importing it."""
    relative = entry["path"]
    raw = (root / relative).read_bytes()
    if bytes_digest(raw) != entry["sha256"]:
        raise ValueError("NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY")
    try:
        if len(raw) > MAX_AST_BYTES:
            raise ValueError("Python syntax census exceeds its byte bound")
        tree = ast.parse(raw, filename=relative)
        parsed = _python_surfaces(relative, raw, tree)
        static_exec_surfaces, static_exec_permitted = _static_exec_surfaces(
            relative,
            tree,
        )
        parsed.extend(static_exec_surfaces)
        module = namespace_exports.summarize(relative, tree, parsed)
        imports, permitted_imports = namespace_source_imports.discover(
            root, relative, tree, census_files)
        permitted_imports.update(static_exec_permitted)
        parsed.extend(imports)
        source_import_bindings = [
            {key: row[key] for key in (
                "surface_id", "module_name", "target_path", "target_surface_id",
                "target_source_digest", "importer_source_digest", "binding_scope")}
            for row in imports
        ]
        dynamic = namespace_exports.has_dynamic_construction(
            tree,
            closed_lazy=module["closed_lazy"],
            permitted_source_imports=permitted_imports,
        ) or module["unknown_globals"]
        dispatches = [
            row for row in parsed
            if row["surface_id"].rsplit(":", 1)[-1].split(".")[-1] == "__getattr__"
        ]
        dispatch = bool(dispatches)
        dynamic = dynamic or (
            dispatch
            and (len(dispatches) != 1
                 or dispatches[0]["surface_id"] != "python:" + relative + ":__getattr__")
        )
        return {
            "surfaces": parsed,
            "module": module,
            "source_import_bindings": source_import_bindings,
            "dynamic": dynamic,
            "dispatch": dispatch,
            "gap": None,
        }
    except (SyntaxError, UnicodeError, RecursionError, ValueError) as exc:
        return {
            "surfaces": [],
            "module": None,
            "source_import_bindings": [],
            "dynamic": False,
            "dispatch": False,
            "gap": {
                "path": relative,
                "code": "NAMESPACE_PYTHON_PARSE_UNAVAILABLE",
                "reason": "The Python definition census could not be established: "
                + type(exc).__name__,
            },
        }


def _initialize_python_worker(
    root: str,
    census_files: list[dict[str, Any]],
) -> None:
    global _WORKER_ROOT, _WORKER_CENSUS_FILES
    _WORKER_ROOT = Path(root)
    _WORKER_CENSUS_FILES = census_files


def _discover_python_worker(entry: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if _WORKER_ROOT is None or _WORKER_CENSUS_FILES is None:
        raise RuntimeError("namespace discovery worker was not initialized")
    return entry["path"], _discover_python_source(
        _WORKER_ROOT,
        entry,
        _WORKER_CENSUS_FILES,
    )


def _python_discoveries(root: Path, census: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = [
        entry for entry in census["files"]
        if entry["path"] != "objects.vstd"
        and Path(entry["path"]).suffix.lower() in {".py", ".pyi"}
    ]
    workers = min(_MAX_PYTHON_WORKERS, os.cpu_count() or 1, len(entries))
    if len(entries) < _PARALLEL_PYTHON_THRESHOLD or workers == 1:
        return {
            entry["path"]: _discover_python_source(root, entry, census["files"])
            for entry in entries
        }
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=multiprocessing.get_context("spawn"),
        initializer=_initialize_python_worker,
        initargs=(str(root), census["files"]),
    ) as executor:
        return dict(executor.map(_discover_python_worker, entries, chunksize=4))


@contextmanager
def discovery_scope() -> Iterator[None]:
    """Discover each distinct source census once for the enclosed command."""
    global _SCOPE_DEPTH
    _SCOPE_DEPTH += 1
    try:
        yield
    finally:
        _SCOPE_DEPTH -= 1
        if _SCOPE_DEPTH == 0:
            _SCOPED_DISCOVERIES.clear()


def discover(root: Path) -> dict[str, Any]:
    """Select Git working bytes, then parse them without importing the subject."""
    census = capture_candidate_source_census(root, allow_untracked_only=True)
    if not _SCOPE_DEPTH:
        return _discover_census(root, census)
    key = (str(Path(root).resolve()), census["census_digest"])
    cached = _SCOPED_DISCOVERIES.get(key)
    if cached is None:
        observed = _discover_census(root, census)
        _SCOPED_DISCOVERIES[key] = deepcopy(observed)
        return observed
    return deepcopy(cached)


def _discover_census(root: Path, census: dict[str, Any]) -> dict[str, Any]:
    surfaces, gaps = [], []
    modules, dynamic_calls, dynamic_dispatch = {}, set(), set()
    source_import_bindings: list[dict[str, Any]] = []
    javascript, workflows, systems, systems_support = [], [], [], []
    fragments, references, html_mechanism, svg_mechanism = {}, [], None, None
    files = {entry["path"]: entry["sha256"] for entry in census["files"]}
    python_discoveries = _python_discoveries(root, census)
    for entry in census["files"]:
        relative = entry["path"]
        if relative == "objects.vstd":
            continue  # The manifest is bound separately; it cannot own itself.
        surfaces.append({"surface_id": "file:" + relative, "path": relative, "line": 1,
                         "form": "file", "source_kinds": [], "hints": [], "unresolved_marker": False})
        suffix = Path(relative).suffix.lower()
        if Path(relative).name in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}:
            raw = (root / relative).read_bytes()
            if bytes_digest(raw) != entry["sha256"]:
                raise ValueError("NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY")
            systems_support.append((relative, raw))
        if suffix in {".py", ".pyi"}:
            discovered = python_discoveries[relative]
            surfaces.extend(discovered["surfaces"])
            source_import_bindings.extend(discovered["source_import_bindings"])
            if discovered["module"] is not None:
                modules[relative] = discovered["module"]
            if discovered["dynamic"]:
                dynamic_calls.add(relative)
            if discovered["dispatch"]:
                dynamic_dispatch.add(relative)
            if discovered["gap"] is not None:
                gaps.append(discovered["gap"])
        elif namespace_html.supports(relative) or suffix == ".svg":
            raw = (root / relative).read_bytes()
            if bytes_digest(raw) != entry["sha256"]:
                raise ValueError("NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY")
            if suffix == ".svg":
                if svg_mechanism is None:
                    svg_mechanism = namespace_svg.mechanism()
                markup = namespace_svg.discover(relative, raw, files)
            else:
                if html_mechanism is None:
                    html_mechanism = namespace_html.mechanism()
                markup = namespace_html.discover(relative, raw, files)
            surfaces.extend(markup["surfaces"])
            gaps.extend(markup["gaps"])
            references.extend(markup["references"])
            for fragment in markup["fragments"]:
                fragments[fragment["key"]] = fragment
                javascript.append((fragment["key"], fragment["source"]))
        elif suffix in {".yaml", ".yml"}:
            raw = (root / relative).read_bytes()
            if bytes_digest(raw) != entry["sha256"]:
                raise ValueError("NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY")
            workflows.append((relative, raw))
        elif suffix in namespace_javascript.SUFFIXES:
            raw = (root / relative).read_bytes()
            if bytes_digest(raw) != entry["sha256"]:
                raise ValueError("NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY")
            javascript.append((relative, raw))
        elif suffix in namespace_systems.SUFFIXES:
            raw = (root / relative).read_bytes()
            if bytes_digest(raw) != entry["sha256"]:
                raise ValueError("NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY")
            systems.append((relative, raw))
        elif (Path(relative).name not in _ARTIFACT_NAMES and
              (suffix in _CODE_SUFFIXES or (
                  suffix not in _ARTIFACT_SUFFIXES
                  and not relative.lower().endswith(_ARTIFACT_COMPOUND_SUFFIXES)
                  and not Path(relative).name.startswith(".")
              ))):
            gaps.append({"path": relative, "code": "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED",
                         "reason": "Only file bytes were inventoried; language definitions require a discovery adapter."})
    exports, export_gaps, closed = namespace_exports.resolve(modules,
        {entry["path"]: entry["sha256"] for entry in census["files"]})
    surfaces.extend(exports)
    gaps.extend(export_gaps)
    additional = namespace_javascript.discover(javascript)
    surfaces.extend(namespace_html.bind_fragment(row, fragments) for row in additional["surfaces"])
    gaps.extend(namespace_html.bind_fragment(row, fragments) for row in additional["gaps"])
    namespace_html.recapture(html_mechanism)
    namespace_svg.recapture(svg_mechanism)
    workflow = namespace_workflows.discover(workflows, files)
    surfaces.extend(workflow["surfaces"])
    gaps.extend(workflow["gaps"])
    system = namespace_systems.discover(systems, systems_support)
    surfaces.extend(system["surfaces"])
    gaps.extend(system["gaps"])
    for relative in sorted(dynamic_calls | (dynamic_dispatch - closed)):
        gaps.append({"path": relative, "code": "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED",
                     "reason": "Dynamic construction may expose interfaces outside the static definition/export census."})
    export_bindings = [{key: row[key] for key in ("surface_id", "target_surface_id", "target_source_digest")}
                       for row in exports if row["form"] == "Export"]
    return {"census": census, "surfaces": surfaces, "gaps": gaps, "export_bindings": export_bindings,
            "source_import_bindings": source_import_bindings,
            "javascript_mechanism": additional["mechanism"],
            "html_mechanism": html_mechanism, "svg_mechanism": svg_mechanism,
            "workflow_binding": workflow["binding"], "markup_code_references": references,
            "systems_mechanism": system["mechanism"],
            "embedded_sources": [{"surface_id": row["surface_id"], "path": row["path"], "line": row["line"],
                "mode": row["mode"], "source_digest": bytes_digest(row["source"])} for row in fragments.values()],
            "scope": "Git-tracked and nonignored working files; Python definitions and exports; HTML/SVG source tokens and bound embedded fragments; optional JavaScript, Rust, Bash and YAML workflow syntax. Exact pinned Serde and RISC Zero expansion families may add bounded static interface names from source/manifests/locks/toolchains. No subject execution, general macro expansion, generated values, browser equivalence, workflow execution, runtime reachability or import proof."}
