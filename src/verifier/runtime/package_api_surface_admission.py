"""Tier-0 package application programming interface (API) surface admission for ten owner-local ``__init__.py`` rows.

Each owner, named by an owner identifier (ID), is admitted by static abstract
syntax tree (AST) resolution of its owned ``__init__.py`` file(s) and of every local binding target those files
reach. No subject package is imported or executed. An admitted row pins the
owned bytes, the bytes of every file read to establish a binding, the static
``__all__`` denominator, and the route of each export. Opening and closing reads
and candidate listings must agree, so concurrent drift yields UNKNOWN rather than PASS.

The import-time graph (every local module executed when an owner is imported,
including ancestor packages and every module an import statement binds, even a
non-exported one) is scanned for dynamic top-level statements and import-time
effects: calls, lambda bodies reached at import time, and attribute or subscript
stores, including inside class bodies. An effect that is not provably pure keeps
the owner UNKNOWN. A name is pure only while its stdlib origin is unchanged. Bytecode
or native candidates beside a module, including ``__pycache__`` entries, keep it UNKNOWN.

A caller-supplied catalog is not whole-package enumeration authority, so its report is
UNKNOWN at most. The default catalog is pinned by ``ADMITTED_CATALOG_DIGEST``.

PASS establishes structural surface closure over the pinned bytes only, scoped to
the static ``__all__`` denominator. It does not establish runtime importability,
import-time behavior, semantic correctness, or any consequence role; export names
never infer roles. This is a Verifier Standard (VSTD) Tier-0 object-local obligation
and discharges no VSTD-4 rung.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
_SEVERITY = {PASS: 0, UNKNOWN: 1, FAIL: 2}

SCHEMA_VERSION = "verifier-package-api-surface-admission-2"
OBLIGATION = "tier0-package-api-surface-admission"
ADMITTED_KINDS = ("ARCH", "DATA", "HARDWARE", "VERIFIER")
REFUSED_KIND = "OBJECT"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CLAIM_BOUNDARY = (
    "Static abstract syntax tree (AST) resolution of each owned __init__.py and its local "
    "binding targets, pinned to exact bytes. The pins are binding closure over bytes read, "
    "not an import or runtime closure. The static __all__ denominator is the only declared "
    "scope. The import-time graph of local modules is scanned for dynamic top-level statements "
    "and import-time effects outside a pure allowlist; no module is imported or executed. "
    "The ancestor package namespace src/verifier/__init__.py is NOT_ASSESSED as an export surface: "
    "it is scanned for import-time effects only and sits in no owner denominator. "
    "Stdlib and external imports, runtime importability, import-time behavior beyond that scan, "
    "semantic correctness, and any consequence role are NOT_ESTABLISHED; structural export and "
    "import-time closure is not fresh-process runtime correctness; export names never infer roles."
)
_NOT_ESTABLISHED = "NOT_ESTABLISHED"
_NOT_ASSESSED = "NOT_ASSESSED"
_INIT = "__init__.py"
_SOURCE_PACKAGE = PurePosixPath("src/verifier")
_MAX_CHAIN = 8
_ROUTES_INADMISSIBLE = frozenset({"UNRESOLVED", "DYNAMIC", "NON_LOCAL", "DUPLICATE", "CIRCULAR"})
_SHADOW_SUFFIXES = (".pyd", ".so", ".pyc", ".pyo", ".dll", ".dylib")
_IDENTITY_DECORATORS = frozenset({"dataclass", "dataclasses.dataclass"})
# Calls that construct a value without touching package state. Each callee root must be unbound locally.
_PURE_CALLEES = frozenset({
    "abs", "bool", "bytes", "chr", "dict", "float", "frozenset", "hex", "int", "len", "list", "max",
    "min", "object", "ord", "range", "repr", "round", "set", "sorted", "str", "tuple",
    "cast", "NewType", "TypeVar", "typing.cast", "typing.NewType", "typing.TypeVar",
    "dataclass", "dataclasses.dataclass", "field", "dataclasses.field",
    "re.compile", "hashlib.sha256", "json.dumps", "MappingProxyType", "types.MappingProxyType",
    "Path", "pathlib.Path", "PurePosixPath", "pathlib.PurePosixPath",
    "classmethod", "staticmethod", "property", "enumerate", "zip", "isinstance", "issubclass",
})
_REVIEWED_SLICE_OWNERS = 10
_REVIEWED_SLICE_PATHS = 11
_NEXT = {
    "OWNER_UNADMITTED": "Declare only admitted owners; a new owner needs its own audited and pinned admission.",
    "OBJECT_FALLBACK_REFUSED": "Remove the OBJECT fallback; ownership needs the exact audited owner ID, kind, and owned file.",
    "OWNER_MISSING": "Declare the admitted owner row with its audited paths, or leave the object UNKNOWN.",
    "DUPLICATE_DECLARATION": "Declare each admitted owner exactly once.",
    "DECLARATION_MALFORMED": "Declare owned paths as a tuple of repository-relative strings.",
    "KIND_SUBSTITUTED": "Restore the audited primary kind, or re-audit the kind and re-derive the pinned row.",
    "KIND_NOT_ADMISSIBLE": "Use an admitted primary kind; OBJECT and unaudited kinds cannot be pinned.",
    "PATH_NOT_REPOSITORY_FILE": "Use a repository-relative POSIX path with no traversal, backslash, drive letter, or absolute prefix.",
    "PATH_NOT_PACKAGE_INIT": "Owned paths must be exact __init__.py files; a directory cannot own a package API.",
    "DUPLICATE_OWNED_PATH": "List each owned path once.",
    "ATOMIC_OWNER_PARTIAL": "Multi-file owners are atomic: declare every audited path together, or leave the owner UNKNOWN.",
    "PATH_REMOVED": "Restore the audited owned path, or re-audit the owner before any admission.",
    "PATH_ADDED": "Remove the unaudited path from this owner, or admit it through its own audit.",
    "NO_OWNED_PATH": "An owner must own at least one audited __init__.py file.",
    "PATH_MISSING": "Restore the owned file at this path, or re-audit the owner row.",
    "CASE_MISMATCH": "Match the import or owned path to the exact on-disk letter case; a case-only match is refused on case-insensitive filesystems.",
    "PATH_ESCAPE": "Remove the junction, symlink, or reparse point so every owned and imported path resolves inside the repository root.",
    "SHADOW_CANDIDATE": "Remove the sibling extension or bytecode file that the import system may prefer to this module; a shadowed module is not admitted.",
    "SOURCE_UNAVAILABLE": "Make the file readable and rerun the admission; the result stays UNKNOWN until then.",
    "SOURCE_UNPARSEABLE": "Fix the Python syntax of this file; an unparsed package surface is not admitted.",
    "DYNAMIC_TOP_LEVEL": "Move the import-time statement or call out of this module, or bound it statically; an import-time effect that cannot be proven absent keeps the owner UNKNOWN.",
    "DYNAMIC_IMPORT": "Replace the star import with explicit names, each bound by one local import.",
    "NO_STATIC_ALL": "Declare one literal __all__ list or tuple of strings as the export denominator.",
    "DYNAMIC_ALL": "Replace the computed, mutated, or unvalued __all__ with one literal list of strings.",
    "DUPLICATE_ALL": "Keep exactly one literal __all__ assignment per owned file.",
    "DUPLICATE_EXPORT": "List each exported name once.",
    "INVALID_EXPORT_NAME": "Export only Python identifiers.",
    "UNBOUND_EXPORT": "Bind each exported name by one local import or definition, or remove it from __all__.",
    "DYNAMIC_BINDING": "Bind the exported name statically; a name rebound by dynamic code, a non-identity decorator, or a star import is not admitted.",
    "DUPLICATE_BINDING": "Keep one binding per exported name; remove the extra import or definition.",
    "MODULE_GETATTR": "Remove the module-level __getattr__ from the owned surface; it can supply names beyond the __all__ denominator at runtime.",
    "UNLISTED_PUBLIC_NAME": "Add the public name to __all__ and re-pin the owner, or rename it with a leading underscore so it is outside the package surface.",
    "NON_LOCAL_BINDING": "A package-API export must bind a local module; move the external name outside the surface.",
    "UNRESOLVED_IMPORT_TARGET": "Restore the imported local module, or remove the import the owner depends on.",
    "RELATIVE_IMPORT_BEYOND_TOP_LEVEL": "Use a relative level that stays inside the verifier package; a level past its top-level package cannot bind.",
    "AMBIGUOUS_MODULE": "Remove the duplicate package or module so the import target is unique.",
    "UNRESOLVED_SYMBOL": "Define the re-exported name in its target module, or correct the import.",
    "DUPLICATE_TARGET_BINDING": "Keep one top-level binding for the re-exported name in its target module.",
    "DYNAMIC_TARGET": "Make the target binding a plain top-level definition; dynamic, decorated, or star-bound targets are not admitted.",
    "CIRCULAR_REEXPORT": "Break the re-export cycle so each name has one defining module.",
    "CHAIN_TOO_DEEP": "Flatten the re-export chain so each export resolves within the bounded hop count.",
    "SHARED_EXPORT_NAME": "Export each name from exactly one owned file of a multi-file owner.",
    "EXPORT_ADDED": "Review the added export; if intended, re-derive and re-pin this owner, otherwise remove it from __all__.",
    "EXPORT_DROPPED": "Review the dropped export; restore its binding and __all__ entry, or re-pin after review.",
    "BINDING_CHANGED": "Review the moved binding; re-pin the owner only after the change is reviewed.",
    "EXPORT_ORDER_CHANGED": "Restore the admitted __all__ order, or re-pin the owner after review.",
    "OWNED_DIGEST_CHANGED": "Review the edited owned file; re-derive and re-pin the owner only after review.",
    "TARGET_DIGEST_CHANGED": "Review the edited binding target; re-derive and re-pin the owner only after review.",
    "CLOSURE_EXPANDED": "Review the newly read module; the owner closure must be re-pinned after review.",
    "CLOSURE_CONTRACTED": "Review the module no longer read; the owner closure must be re-pinned after review.",
    "SOURCE_CHANGED_DURING_CHECK": "Rerun the admission on a quiescent tree; drift during the check admits nothing.",
    "SURFACE_UNREVIEWED": "Admit this package surface through its own audited owner row; until then it blocks any whole-tier PASS.",
    "SLICE_CARDINALITY": "Keep the reviewed slice at exactly ten owner IDs over eleven owned paths; re-audit before changing its size.",
    "CATALOG_NOT_ENUMERATED": "Assess with the default repository catalog to enumerate src/verifier; a caller-supplied catalog reports UNKNOWN at most.",
    "CATALOG_PIN_MISMATCH": "Restore the admitted rows to the pinned catalog digest, or re-derive them and update ADMITTED_CATALOG_DIGEST and its independent test pin after review.",
}


@dataclass(frozen=True)
class Declaration:
    """A manifest row as presented to the checker: owner ID, primary kind, owned paths."""

    owner_id: str
    primary_kind: str
    owned_paths: tuple[str, ...]


@dataclass(frozen=True)
class AdmittedOwner:
    """One pinned owner row: exact owned bytes, the binding closure, and each export binding."""

    owner_id: str
    primary_kind: str
    owned_paths: tuple[str, ...]
    closure: tuple[tuple[str, str], ...]
    bindings: tuple[tuple[str, str, str, str, str], ...]


@dataclass(frozen=True)
class Binding:
    """Where one exported name of an owned file is statically bound."""

    owned_file: str
    export: str
    route: str
    target_path: str
    target_symbol: str
    target_line: int


@dataclass(frozen=True)
class Finding:
    """One diagnostic naming the exact object, path, obligation, reason, and next action."""

    object_id: str
    path: str
    obligation: str
    status: str
    code: str
    reason: str
    next_action: str


@dataclass(frozen=True)
class OwnerResult:
    owner_id: str
    primary_kind: str
    status: str
    owned_paths: tuple[str, ...]
    export_count: int
    bindings: tuple[Binding, ...]
    closure: tuple[tuple[str, str], ...]
    opening_digest: str
    closing_digest: str
    findings: tuple[Finding, ...]
    import_graph: tuple[tuple[str, str], ...] = ()
    runtime_importability: str = _NOT_ESTABLISHED
    behavior: str = _NOT_ESTABLISHED
    consequence_roles: str = _NOT_ASSESSED
    surface_scope: str = "ALL_DENOMINATOR_ONLY"
    claim_boundary: str = CLAIM_BOUNDARY


@dataclass(frozen=True)
class AdmissionReport:
    schema_version: str
    status: str
    owners: tuple[OwnerResult, ...]
    unadmitted_findings: tuple[Finding, ...]
    catalog_digest: str
    report_digest: str = ""
    reviewed_status: str = ""
    inventory_scope: str = ""
    catalog_pin: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AdmissionError(ValueError):
    """Raised by ``derive`` when current bytes cannot be pinned as an admitted row."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        super().__init__("; ".join(f"{f.code}:{f.path}" for f in findings) or "owner is not admissible")
        self.findings = findings


class _Refused(Exception):
    """A static resolution step that cannot succeed; carries its route and diagnostic."""

    def __init__(self, route: str, status: str, code: str, path: str, reason: str) -> None:
        super().__init__(code)
        self.route, self.status, self.code, self.path, self.reason = route, status, code, path, reason


@dataclass(frozen=True)
class _Bind:
    kind: str
    line: int
    node: ast.AST | None
    alias: ast.alias | None


@dataclass
class _Scan:
    binds: dict[str, list[_Bind]] = field(default_factory=dict)
    dynamic_names: set[str] = field(default_factory=set)
    dynamic_lines: list[int] = field(default_factory=list)
    star_line: int = 0
    all_nodes: list[ast.Assign | ast.AnnAssign] = field(default_factory=list)
    all_mutation_lines: list[int] = field(default_factory=list)
    all_bare_lines: list[int] = field(default_factory=list)
    has_getattr: bool = False
    module_stores: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class _Outcome:
    findings: tuple[Finding, ...]
    rows: tuple[Binding, ...]
    closure: tuple[tuple[str, str], ...]
    graph: tuple[tuple[str, str], ...]
    opening: str
    closing: str


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    """Digest of canonical JavaScript Object Notation (JSON) bytes with sorted keys."""
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def _read_bytes(path: Path) -> bytes:
    """Return the current bytes of one file; tests replace it to simulate concurrent drift."""
    return path.read_bytes()


def _finding(object_id: str, path: str, status: str, code: str, reason: str) -> Finding:
    return Finding(object_id, path, OBLIGATION, status, code, reason, _NEXT[code].format(path=path or "the owner row"))


def _valid_relative(rel: Any) -> bool:
    if not isinstance(rel, str) or not rel or "\\" in rel or ":" in rel:
        return False
    path = PurePosixPath(rel)
    return not path.is_absolute() and ".." not in path.parts and all(part for part in path.parts)


def _is_reparse(path: Path) -> bool:
    """A symbolic link or a Windows junction: a reparse point that can leave the repository."""
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (is_junction is not None and is_junction())


def _contained(root: Path, path: Path) -> bool:
    resolved, base = path.resolve(), root.resolve()
    return resolved == base or base in resolved.parents


def _directory_names(directory: Path, cache: _RunCache | None) -> frozenset[str]:
    """Entry names of one directory; a missing or non-directory path has none."""
    key = str(directory)
    if cache is not None and key in cache.names_by_dir:
        return cache.names_by_dir[key]
    try:
        names = frozenset(entry.name for entry in directory.iterdir())
    except OSError:
        names = frozenset()
    if cache is not None:
        cache.names_by_dir[key] = names
    return names


def _locate(root: Path, rel: PurePosixPath, cache: _RunCache | None = None) -> tuple[str, Path | None]:
    """Resolve ``rel`` one component at a time: ("EXACT", path), ("CASE", None), or ("ABSENT", None).

    Exact case is checked against the directory listing, so a case-only match is never
    taken as the file. A reparse point at any component raises PATH_ESCAPE, naming the
    component that escapes; a resolved path outside ``root`` raises it too.
    """
    key = str(rel)
    if cache is not None and key in cache.located:
        return cache.located[key]
    current = root
    result: tuple[str, Path | None] = ("ABSENT", None)
    for index, part in enumerate(rel.parts):
        names = _directory_names(current, cache)
        if part not in names:
            state = "CASE" if any(name.lower() == part.lower() for name in names) else "ABSENT"
            result = (state, None)
            break
        current = current / part
        if _is_reparse(current):
            escaping = PurePosixPath(*rel.parts[: index + 1])
            raise _Refused("UNRESOLVED", FAIL, "PATH_ESCAPE", str(escaping),
                           f"{escaping} is a link or junction, so bytes read through {rel} may not be the repository's.")
    else:
        if not _contained(root, current):
            raise _Refused("UNRESOLVED", FAIL, "PATH_ESCAPE", str(rel),
                           f"{rel} resolves outside the repository root, so its bytes are not the repository's.")
        result = ("EXACT", current)
    if cache is not None:
        cache.located[key] = result
    return result


_PYCACHE = "__pycache__"


def _listing(root: Path, parent: PurePosixPath, stem: str, cache: _RunCache | None = None) -> tuple[str, ...]:
    """Every entry of ``parent`` that the import system could map to ``stem``, with on-disk case.

    Bytecode named for the stem inside ``__pycache__`` is listed as ``__pycache__/<name>``, whether
    timestamp-checked or unchecked-hash: any such file may be read in place of the source.
    """
    base = root.joinpath(*parent.parts)
    names = _directory_names(base, cache)
    folded = stem.lower()
    found = [name for name in names if name.split(".")[0].lower() == folded]
    if _PYCACHE in names:
        cached = _directory_names(base / _PYCACHE, cache)
        found.extend(f"{_PYCACHE}/{name}" for name in cached if name.lower().startswith(folded + "."))
    return tuple(sorted(found))


def _is_shadow(name: str, stem: str) -> bool:
    """A sibling the import system may prefer to the source file: an extension, bytecode, or tagged build."""
    if name.startswith(_PYCACHE + "/"):
        return True
    if not name.lower().startswith(stem.lower() + "."):
        return False
    return name.endswith(_SHADOW_SUFFIXES) or ".cpython-" in name or ".abi3" in name or ".pypy" in name


def _is_type_checking(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.If) and (
        (isinstance(stmt.test, ast.Name) and stmt.test.id == "TYPE_CHECKING")
        or (isinstance(stmt.test, ast.Attribute) and stmt.test.attr == "TYPE_CHECKING"))


def _relative_base(importer: str, level: int) -> PurePosixPath:
    """The package a relative import of ``level`` dots resolves against; refuses a climb past the top-level package."""
    package = PurePosixPath(importer).parent
    allowed = len(package.parts) - len(_SOURCE_PACKAGE.parts)
    if level - 1 > allowed:
        raise _Refused("UNRESOLVED", FAIL, "RELATIVE_IMPORT_BEYOND_TOP_LEVEL", importer,
                       f"{importer} uses {level} leading dots, which climb past the top-level verifier package; the import cannot bind.")
    for _ in range(level - 1):
        package = package.parent
    return package


def _module_file(ctx: _Context, importer: str, level: int, module: str) -> tuple[str, str]:
    """Map one import to ("FILE", path), ("MISSING", candidate), ("AMBIGUOUS", candidate), ("CASE", candidate), or ("EXTERNAL", "")."""
    if level:
        base = _relative_base(importer, level)
        parts = module.split(".")
    else:
        head, *parts = module.split(".")
        if head != "verifier":
            return "EXTERNAL", ""
        base = _SOURCE_PACKAGE
    if any(not part.isidentifier() for part in parts):
        return "MISSING", ""
    base = base.joinpath(*parts)
    package, single = base / _INIT, base.parent / f"{base.name}.py"
    package_state, _ = _locate(ctx.root, package, ctx.cache)
    single_state, _ = _locate(ctx.root, single, ctx.cache)
    ctx.probe(base.parent, base.name)
    ctx.probe(base, "__init__")
    if package_state == "EXACT" and single_state == "EXACT":
        return "AMBIGUOUS", str(package)
    if package_state == "EXACT":
        return "FILE", str(package)
    if single_state == "EXACT":
        return "FILE", str(single)
    if package_state == "CASE" or single_state == "CASE":
        return "CASE", str(package if package_state == "CASE" else single)
    return "MISSING", str(package)


def _module_refusal(status: str, path: str, importer: str, label: str) -> _Refused:
    if status == "AMBIGUOUS":
        return _Refused("UNRESOLVED", FAIL, "AMBIGUOUS_MODULE", path,
                        f"{importer} imports '{label}', and both a package and a module file exist; the target is not unique.")
    if status == "CASE":
        return _Refused("UNRESOLVED", FAIL, "CASE_MISMATCH", path,
                        f"{importer} imports '{label}', which matches {path} only up to letter case; the exact name is absent.")
    return _Refused("UNRESOLVED", FAIL, "UNRESOLVED_IMPORT_TARGET", path,
                    f"{importer} imports '{label}', but {path} is absent, so the import cannot bind.")


def _package_init(ctx: _Context, package: PurePosixPath) -> str | None:
    """The exact ``__init__.py`` of a package directory, or None when the directory has none."""
    ctx.probe(package, "__init__")
    state, _ = _locate(ctx.root, package / _INIT, ctx.cache)
    return str(package / _INIT) if state == "EXACT" else None


def _plain_targets(targets: list[ast.expr]) -> list[str] | None:
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)) and all(isinstance(e, ast.Name) for e in target.elts):
            names.extend(e.id for e in target.elts)
        else:
            return None
    return names


def _names_in(node: ast.AST) -> set[str]:
    """Every name a dynamic top-level statement may bind, conservatively overcounted."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
            names.add(sub.id)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(sub.name)
        elif isinstance(sub, ast.alias):
            names.add((sub.asname or sub.name).split(".")[0])
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            names.add(sub.name)
    return names


def _identity_decorator(decorator: ast.expr, binds: dict[str, list[_Bind]]) -> bool:
    """True when a decorator returns its argument: ``dataclass`` bound only by its stdlib import."""
    expr = decorator.func if isinstance(decorator, ast.Call) else decorator
    text = ast.unparse(expr)
    if text not in _IDENTITY_DECORATORS:
        return False
    origin = binds.get(text.split(".")[0], [])
    if len(origin) != 1:
        return False
    bind = origin[0]
    if text == "dataclass":
        return bind.kind == "FROM" and bind.node.module == "dataclasses" and bind.alias.name == "dataclass"
    return bind.kind == "IMPORT" and bind.alias.name == "dataclasses"


def _scan(tree: ast.Module) -> _Scan:
    scan = _Scan()
    decorated: list[tuple[str, int, tuple[ast.expr, ...]]] = []

    def add(name: str, bind: _Bind) -> None:
        scan.binds.setdefault(name, []).append(bind)

    for stmt in tree.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
            continue
        if _is_type_checking(stmt):
            continue
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                if alias.name == "*":
                    scan.star_line = scan.star_line or stmt.lineno
                else:
                    add(alias.asname or alias.name, _Bind("FROM", stmt.lineno, stmt, alias))
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                add(alias.asname or alias.name.split(".")[0], _Bind("IMPORT", stmt.lineno, stmt, alias))
        elif isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if isinstance(stmt, ast.FunctionDef) and stmt.name == "__getattr__":
                scan.has_getattr = True
            add(stmt.name, _Bind("DEF", stmt.lineno, None, None))
            if stmt.decorator_list:
                decorated.append((stmt.name, stmt.lineno, tuple(stmt.decorator_list)))
        elif isinstance(stmt, ast.Assign) and _plain_targets(stmt.targets) is not None:
            names = _plain_targets(stmt.targets) or []
            for name in names:
                add(name, _Bind("ASSIGN", stmt.lineno, None, None))
            if "__all__" in names:
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    scan.all_nodes.append(stmt)
                else:
                    scan.all_mutation_lines.append(stmt.lineno)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            # A bare annotation binds nothing at runtime; an annotated assignment binds like Assign.
            if stmt.value is not None:
                add(stmt.target.id, _Bind("ASSIGN", stmt.lineno, None, None))
                if stmt.target.id == "__all__":
                    scan.all_nodes.append(stmt)
            elif stmt.target.id == "__all__":
                scan.all_bare_lines.append(stmt.lineno)
        else:
            names = _names_in(stmt)
            scan.dynamic_names |= names
            scan.dynamic_lines.append(stmt.lineno)
            if "__all__" in names:
                scan.all_mutation_lines.append(stmt.lineno)
    for name, line, decorators in decorated:
        if not all(_identity_decorator(d, scan.binds) for d in decorators):
            scan.binds[name] = [replace(b, kind="DECORATED") if b.kind == "DEF" and b.line == line else b
                                for b in scan.binds[name]]
    scan.module_stores = _module_stores(tree.body)
    return scan


_QUALIFIED_ORIGIN = {
    "cast": "typing.cast", "NewType": "typing.NewType", "TypeVar": "typing.TypeVar",
    "dataclass": "dataclasses.dataclass", "field": "dataclasses.field",
    "MappingProxyType": "types.MappingProxyType", "Path": "pathlib.Path",
    "PurePosixPath": "pathlib.PurePosixPath",
}


def _origin(text: str) -> str:
    """The stdlib module attribute a pure callee must come from; bare names not listed above are builtins."""
    if text in _QUALIFIED_ORIGIN:
        return _QUALIFIED_ORIGIN[text]
    return text if "." in text else f"builtins.{text}"


def _origin_safe(text: str, bind: _Bind) -> bool:
    """True only when one binding of the callee root is its exact stdlib origin: ``from builtins import len`` or ``import re``."""
    root = text.split(".")[0]
    if bind.kind == "FROM":
        stmt, alias = bind.node, bind.alias
        return ("." not in text and stmt.level == 0 and stmt.module is not None
                and f"{stmt.module}.{alias.name}" == _origin(text) and (alias.asname or alias.name) == root)
    if bind.kind == "IMPORT":
        return "." in text and bind.alias.asname is None and bind.alias.name == root
    return False


def _pure_call(text: str, scan: _Scan) -> bool:
    """True when a callee is on the pure allowlist and its root name keeps its stdlib origin everywhere it is bound."""
    if text not in _PURE_CALLEES:
        return False
    root = text.split(".")[0]
    if root in scan.dynamic_names or root in scan.module_stores:
        return False
    return all(_origin_safe(text, bind) for bind in scan.binds.get(root, []))


def _module_stores(body: list[ast.stmt]) -> set[str]:
    """Names stored at module scope other than by a plain import or definition: walrus, loop, with, except, comprehension."""
    names: set[str] = set()
    stack: list[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.ClassDef):
            stack.extend([*node.decorator_list, *node.bases, *node.keywords])
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        stack.extend(ast.iter_child_nodes(node))
    return names


def _import_time_calls(body: list[ast.stmt], scan: _Scan) -> list[str]:
    """Callees and store targets of every import-time effect: never inside a function body or an unused branch.

    Lambda bodies are analysed too, since a lambda handed to a call at import time may run there.
    """
    found: list[str] = []

    def expr(node: ast.AST) -> None:
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, ast.stmt):
                statement(current)
                continue
            if isinstance(current, ast.Call):
                text = ast.unparse(current.func)
                if not _pure_call(text, scan):
                    found.append(text)
            stack.extend(ast.iter_child_nodes(current))

    def decorators(decorator_list: list[ast.expr]) -> None:
        for decorator in decorator_list:
            callee = decorator.func if isinstance(decorator, ast.Call) else decorator
            if not (_identity_decorator(decorator, scan.binds) or _pure_call(ast.unparse(callee), scan)):
                found.append("@" + ast.unparse(decorator))
            expr(decorator)

    def statement(stmt: ast.stmt) -> None:
        if _is_type_checking(stmt) or isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass)):
            return
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
            targets = stmt.targets if isinstance(stmt, (ast.Assign, ast.Delete)) else [stmt.target]
            for target in targets:
                for sub in ast.walk(target):
                    if isinstance(sub, (ast.Attribute, ast.Subscript)) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                        found.append("store " + ast.unparse(sub))
                        break
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators(stmt.decorator_list)
            for default in [*stmt.args.defaults, *(d for d in stmt.args.kw_defaults if d is not None)]:
                expr(default)
            for arg in [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs]:
                if arg.annotation is not None:
                    expr(arg.annotation)
            if stmt.returns is not None:
                expr(stmt.returns)
            return
        if isinstance(stmt, ast.ClassDef):
            decorators(stmt.decorator_list)
            for base in [*stmt.bases, *(k.value for k in stmt.keywords)]:
                expr(base)
            for inner in stmt.body:
                statement(inner)
            return
        for child in ast.iter_child_nodes(stmt):
            expr(child)

    for stmt in body:
        statement(stmt)
    return found


def _import_edges(body: list[ast.stmt], guarded: bool = False):
    """Every import that executes with this module, as (node, guarded); guarded means inside if/try/with/loop."""
    for stmt in body:
        if _is_type_checking(stmt):
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            yield stmt, guarded
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        elif isinstance(stmt, ast.ClassDef):
            yield from _import_edges(stmt.body, guarded)
        elif isinstance(stmt, ast.If):
            yield from _import_edges(stmt.body, True)
            yield from _import_edges(stmt.orelse, True)
        elif isinstance(stmt, ast.Try):
            for part in (stmt.body, stmt.orelse, stmt.finalbody, *(h.body for h in stmt.handlers)):
                yield from _import_edges(part, True)
        elif isinstance(stmt, (ast.With, ast.For, ast.While)):
            yield from _import_edges(stmt.body, True)


class _RunCache:
    """Facts shared by the owners of one assessment: directory listings, path resolutions, and parses keyed by content digest.

    The closing re-stat and the closing byte re-reads never consult this cache, so drift still shows.
    """

    def __init__(self) -> None:
        self.names_by_dir: dict[str, frozenset[str]] = {}
        self.located: dict[str, tuple[str, Path | None]] = {}
        self.parsed: dict[str, tuple[ast.Module, _Scan, tuple[str, ...]]] = {}


class _Context:
    """One analysis pass: every byte read once, every candidate listing recorded for the closing re-stat."""

    def __init__(self, root: Path, owner_id: str, cache: _RunCache) -> None:
        self.root = root
        self.owner_id = owner_id
        self.cache = cache
        self.blobs: dict[str, bytes] = {}
        self.pinned: set[str] = set()
        self.graph: set[str] = set()
        self.probes: dict[tuple[str, str], tuple[str, ...]] = {}
        self.findings: list[Finding] = []

    def add(self, status: str, code: str, path: str, reason: str) -> None:
        self.findings.append(_finding(self.owner_id, path, status, code, reason))

    def read(self, rel: str) -> bytes:
        if rel not in self.blobs:
            state, path = _locate(self.root, PurePosixPath(rel), self.cache)
            if state == "CASE":
                raise _Refused("UNRESOLVED", FAIL, "CASE_MISMATCH", rel,
                               f"{rel} differs from the on-disk file only in letter case; the exact name is absent.")
            if state == "ABSENT" or path is None:
                raise _Refused("UNRESOLVED", FAIL, "PATH_MISSING", rel,
                               f"{rel} is absent from the repository, so the owner cannot bind it.")
            try:
                data = _read_bytes(path)
            except FileNotFoundError as exc:
                raise _Refused("UNRESOLVED", FAIL, "PATH_MISSING", rel,
                               f"{rel} is absent from the repository, so the owner cannot bind it.") from exc
            except OSError as exc:
                raise _Refused("DYNAMIC", UNKNOWN, "SOURCE_UNAVAILABLE", rel,
                               f"{rel} could not be read ({exc.__class__.__name__}).") from exc
            self.blobs[rel] = data
            self.probe(PurePosixPath(rel).parent, PurePosixPath(rel).stem)
        return self.blobs[rel]

    def pin(self, rel: str) -> bytes:
        data = self.read(rel)
        self.pinned.add(rel)
        return data

    def parsed(self, rel: str) -> tuple[ast.Module, _Scan, tuple[str, ...]]:
        """Parse, scan, and list import-time calls of one module; cached by the digest of its bytes."""
        digest = _sha256(self.read(rel))
        if digest not in self.cache.parsed:
            try:
                tree = ast.parse(self.blobs[rel], filename=rel)
            except (SyntaxError, ValueError) as exc:
                raise _Refused("UNRESOLVED", FAIL, "SOURCE_UNPARSEABLE", rel,
                               f"{rel} does not parse as Python source ({exc.__class__.__name__}).") from exc
            scan = _scan(tree)
            self.cache.parsed[digest] = (tree, scan, tuple(_import_time_calls(tree.body, scan)))
        return self.cache.parsed[digest]

    def tree(self, rel: str) -> ast.Module:
        return self.parsed(rel)[0]

    def scan(self, rel: str) -> _Scan:
        return self.parsed(rel)[1]

    def probe(self, parent: PurePosixPath, stem: str) -> tuple[str, ...]:
        """Record the candidate listing once; a sibling that could shadow ``stem`` is an UNKNOWN blocker."""
        key = (str(parent), stem)
        if key not in self.probes:
            listing = _listing(self.root, parent, stem, self.cache)
            self.probes[key] = listing
            for name in listing:
                if _is_shadow(name, stem):
                    self.add(UNKNOWN, "SHADOW_CANDIDATE", str(parent / name),
                             f"{parent / name} may shadow the module {stem} at import time, so static PASS is blocked.")
        return self.probes[key]


def _target(ctx: _Context, importer: str, level: int, module: str) -> str:
    """Return the local file an import binds, pinning it into the closure."""
    status, path = _module_file(ctx, importer, level, module)
    label = "." * level + module
    if status == "FILE":
        ctx.pin(path)
        return path
    if status == "EXTERNAL":
        raise _Refused("NON_LOCAL", FAIL, "NON_LOCAL_BINDING", importer,
                       f"{importer} binds '{label}' from outside the local verifier package; "
                       "a package-API export must resolve to a local module.")
    raise _module_refusal(status, path, importer, label)


def _resolve_symbol(ctx: _Context, rel: str, name: str, depth: int,
                    trail: tuple[tuple[str, str], ...]) -> tuple[str, str, int, str]:
    """Return (defining path, symbol, line, route) for ``name`` bound at top level of ``rel``."""
    if (rel, name) in trail:
        chain = " -> ".join(f"{path}:{sym}" for path, sym in (*trail, (rel, name)))
        raise _Refused("CIRCULAR", FAIL, "CIRCULAR_REEXPORT", rel, f"'{name}' is re-exported through its own chain {chain}.")
    if depth > _MAX_CHAIN:
        raise _Refused("DYNAMIC", UNKNOWN, "CHAIN_TOO_DEEP", rel,
                       f"'{name}' in {rel} lies beyond {_MAX_CHAIN} re-export hops; the bounded chain is not established.")
    scan = ctx.scan(rel)
    if scan.star_line:
        raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_IMPORT", rel,
                       f"{rel} star-imports at line {scan.star_line}, so a star name may shadow or supply '{name}' at runtime.")
    hits = scan.binds.get(name, [])
    if name in scan.dynamic_names:
        raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_TARGET", rel,
                       f"{rel} may bind '{name}' through dynamic code, so its value is not statically fixed.")
    if not hits:
        if PurePosixPath(rel).name == _INIT:
            status, path = _module_file(ctx, rel, 1, name)
            if status == "FILE":
                ctx.pin(path)
                return path, name, 0, "SUBMODULE"
        if scan.has_getattr:
            raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_TARGET", rel,
                           f"{rel} defines a module __getattr__ that may supply '{name}' at runtime.")
        raise _Refused("UNRESOLVED", FAIL, "UNRESOLVED_SYMBOL", rel,
                       f"{rel} binds no top-level '{name}', so the re-export has no defining target.")
    if len(hits) > 1:
        raise _Refused("DUPLICATE", FAIL, "DUPLICATE_TARGET_BINDING", rel,
                       f"{rel} binds '{name}' at {len(hits)} top-level sites; one defining binding is required.")
    bind = hits[0]
    if bind.kind == "DECORATED":
        raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_TARGET", rel,
                       f"'{name}' in {rel} is rebound by a non-identity decorator, so its value is not statically fixed.")
    if bind.kind in ("DEF", "ASSIGN"):
        return rel, name, bind.line, "DEFINITION"
    if bind.kind == "IMPORT":
        return _target(ctx, rel, 0, bind.alias.name), bind.alias.name, 0, "SUBMODULE"
    stmt, alias = bind.node, bind.alias
    if stmt.module is None:
        return _target(ctx, rel, stmt.level, alias.name), alias.name, 0, "SUBMODULE"
    path = _target(ctx, rel, stmt.level, stmt.module)
    return _resolve_symbol(ctx, path, alias.name, depth + 1, (*trail, (rel, name)))


def _owner_exports(ctx: _Context, rel: str, scan: _Scan) -> tuple[str, ...]:
    """Return the literal static __all__ of one owned file, recording every shape that breaks it."""
    if scan.all_bare_lines:
        ctx.add(UNKNOWN, "DYNAMIC_ALL", rel,
                f"{rel} annotates __all__ without a value at lines {', '.join(map(str, scan.all_bare_lines))}; the denominator is not bound.")
        return ()
    if scan.all_mutation_lines:
        ctx.add(UNKNOWN, "DYNAMIC_ALL", rel,
                f"{rel} computes or mutates __all__ at lines {', '.join(map(str, scan.all_mutation_lines))}; the denominator is not literal.")
        return ()
    if not scan.all_nodes:
        ctx.add(FAIL, "NO_STATIC_ALL", rel, f"{rel} declares no __all__, so its export denominator is undefined.")
        return ()
    if len(scan.all_nodes) > 1:
        ctx.add(FAIL, "DUPLICATE_ALL", rel, f"{rel} assigns __all__ {len(scan.all_nodes)} times.")
        return ()
    value = scan.all_nodes[0].value
    if not isinstance(value, (ast.List, ast.Tuple)) or not all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in value.elts):
        ctx.add(UNKNOWN, "DYNAMIC_ALL", rel, f"{rel} builds __all__ from a non-literal expression.")
        return ()
    names = tuple(e.value for e in value.elts)
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        ctx.add(FAIL, "DUPLICATE_EXPORT", rel, f"{rel} lists {', '.join(repeated)} more than once in __all__.")
    invalid = [n for n in names if not n.isidentifier()]
    if invalid:
        ctx.add(FAIL, "INVALID_EXPORT_NAME", rel, f"{rel} exports non-identifier names {', '.join(invalid)}.")
    exports = tuple(dict.fromkeys(names))
    if scan.has_getattr:
        ctx.add(UNKNOWN, "MODULE_GETATTR", rel,
                f"{rel} defines a module __getattr__, which can supply names beyond the __all__ denominator at runtime.")
    unlisted = sorted(n for n in scan.binds if not n.startswith("_") and n not in exports)
    if unlisted:
        ctx.add(UNKNOWN, "UNLISTED_PUBLIC_NAME", rel,
                f"{rel} binds public names outside __all__: {', '.join(unlisted)}; the admitted scope is the __all__ denominator only.")
    return exports


def _bind_export(ctx: _Context, rel: str, scan: _Scan, name: str) -> tuple[str, str, str, int]:
    """Return (route, target path, target symbol, line) for one exported name owned at ``rel``."""
    binds = scan.binds.get(name, [])
    if scan.star_line:
        raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_IMPORT", rel,
                       f"{rel} star-imports at line {scan.star_line}, so '{name}' may be shadowed or supplied at runtime.")
    if name in scan.dynamic_names:
        raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_BINDING", rel,
                       f"'{name}' is also rebound inside a dynamic top-level statement of {rel}.")
    if not binds:
        raise _Refused("UNRESOLVED", FAIL, "UNBOUND_EXPORT", rel,
                       f"{rel} exports '{name}' but binds it nowhere at top level.")
    if len(binds) > 1:
        lines = ", ".join(str(b.line) for b in binds)
        raise _Refused("DUPLICATE", FAIL, "DUPLICATE_BINDING", rel,
                       f"{rel} binds exported '{name}' at lines {lines}; one export must have one binding.")
    bind = binds[0]
    if bind.kind == "DECORATED":
        raise _Refused("DYNAMIC", UNKNOWN, "DYNAMIC_BINDING", rel,
                       f"'{name}' in {rel} is rebound by a non-identity decorator, so its value is not statically fixed.")
    if bind.kind in ("DEF", "ASSIGN"):
        return "LOCAL_DEFINITION", rel, name, bind.line
    if bind.kind == "IMPORT":
        return "SUBMODULE", _target(ctx, rel, 0, bind.alias.name), bind.alias.name, 0
    stmt, alias = bind.node, bind.alias
    if stmt.module is None:
        return "SUBMODULE", _target(ctx, rel, stmt.level, alias.name), alias.name, 0
    path = _target(ctx, rel, stmt.level, stmt.module)
    target, symbol, line, route = _resolve_symbol(ctx, path, alias.name, 0, ((rel, name),))
    return ("SUBMODULE" if route == "SUBMODULE" else "REEXPORT"), target, symbol, line


def _check_non_exported(ctx: _Context, rel: str, scan: _Scan, exported: set[str]) -> None:
    """Non-exported local imports still execute with the owner, so their modules and names must resolve."""
    for name, binds in scan.binds.items():
        if name in exported:
            continue
        for bind in (b for b in binds if b.kind in ("FROM", "IMPORT")):
            try:
                if bind.kind == "IMPORT":
                    if bind.alias.name.startswith("verifier"):
                        _target(ctx, rel, 0, bind.alias.name)
                    continue
                stmt = bind.node
                if stmt.module is None:
                    _target(ctx, rel, stmt.level, bind.alias.name)
                elif stmt.level or stmt.module.startswith("verifier"):
                    path = _target(ctx, rel, stmt.level, stmt.module)
                    _resolve_symbol(ctx, path, bind.alias.name, 0, ((rel, name),))
            except _Refused as exc:
                ctx.add(exc.status, exc.code, exc.path, exc.reason)


def _ancestors(ctx: _Context, rel: str) -> list[str]:
    """Package __init__ files that Python executes before a module under the verifier package."""
    found: list[str] = []
    parent = PurePosixPath(rel).parent
    for depth in range(2, len(parent.parts) + 1):
        init = _package_init(ctx, PurePosixPath(*parent.parts[:depth]))
        if init is not None:
            found.append(init)
    return found


def _edge_targets(ctx: _Context, rel: str, node: ast.stmt, guarded: bool) -> list[str]:
    """Resolve one import executed at import time; returns the local modules it reads."""
    out: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name.startswith("verifier"):
                status, path = _module_file(ctx, rel, 0, alias.name)
                if status != "FILE":
                    raise _module_refusal(status, path, rel, alias.name)
                out.append(path)
        return out
    if node.module is None:
        base = _relative_base(rel, node.level)
        for alias in node.names:
            status, path = _module_file(ctx, rel, node.level, alias.name)
            if status == "FILE":
                out.append(path)
                continue
            init = _package_init(ctx, base)
            if init is None:
                raise _module_refusal(status, path, rel, "." * node.level + alias.name)
            _resolve_symbol(ctx, init, alias.name, 0, ((rel, alias.name),))
        return out
    if node.level == 0 and not node.module.startswith("verifier"):
        return out
    status, path = _module_file(ctx, rel, node.level, node.module)
    if status != "FILE":
        raise _module_refusal(status, path, rel, "." * node.level + node.module)
    out.append(path)
    for alias in node.names:
        if alias.name != "*":
            _resolve_symbol(ctx, path, alias.name, 0, ((rel, alias.asname or alias.name),))
    return out


def _scan_import_graph(ctx: _Context, roots: list[str]) -> None:
    """Scan every local module executed when an owner is imported, including ancestor packages.

    Every pinned module is executed too: an import statement binds it, even when the binding is not exported
    (``from .sub import leaf as _leaf``), so it is queued and scanned like any other import edge.
    """
    queue, index, visited, queued = list(roots), 0, set(), set(roots)
    while True:
        if index == len(queue):
            fresh = sorted(rel for rel in ctx.pinned if rel not in queued)
            if not fresh:
                break
            queue.extend(fresh)
            queued.update(fresh)
        rel = queue[index]
        index += 1
        if rel in visited:
            continue
        visited.add(rel)
        try:
            scan = ctx.scan(rel)
            tree = ctx.tree(rel)
            queue.extend(_ancestors(ctx, rel))
        except _Refused as exc:
            ctx.add(exc.status, exc.code, exc.path, exc.reason)
            continue
        ctx.graph.add(rel)
        calls = list(ctx.parsed(rel)[2])
        if scan.dynamic_lines or calls:
            reasons = []
            if scan.dynamic_lines:
                reasons.append("dynamic top-level statements at lines " + ", ".join(map(str, scan.dynamic_lines)))
            if calls:
                reasons.append("import-time effects outside the pure allowlist: " + ", ".join(sorted(set(calls))[:6]))
            ctx.add(UNKNOWN, "DYNAMIC_TOP_LEVEL", rel,
                    f"{rel} executes {'; '.join(reasons)} when imported, so its effect on exports is not statically bounded.")
        if scan.star_line:
            ctx.add(UNKNOWN, "DYNAMIC_IMPORT", rel,
                    f"{rel} star-imports at line {scan.star_line}; the names it provides are not statically enumerated.")
        for node, guarded in _import_edges(tree.body):
            try:
                queue.extend(_edge_targets(ctx, rel, node, guarded))
            except _Refused as exc:
                if exc.status == UNKNOWN or not guarded:
                    ctx.add(exc.status, exc.code, exc.path, exc.reason)


def _analyse(root: Path, owner_id: str, owned_paths: tuple[str, ...], cache: _RunCache) -> _Outcome:
    ctx = _Context(root, owner_id, cache)
    rows: list[Binding] = []
    seen: dict[str, str] = {}
    roots: list[str] = []
    if not owned_paths:
        ctx.add(FAIL, "NO_OWNED_PATH", "", f"{owner_id} declares no owned __init__.py file.")
    for rel in owned_paths:
        if not _valid_relative(rel):
            ctx.add(FAIL, "PATH_NOT_REPOSITORY_FILE", str(rel), f"{owner_id} owns {rel!r}, which is not a repository-relative file.")
            continue
        if PurePosixPath(rel).name != _INIT:
            ctx.add(FAIL, "PATH_NOT_PACKAGE_INIT", rel, f"{owner_id} owns {rel}, which is not an __init__.py package surface.")
            continue
        try:
            ctx.pin(rel)
            scan = ctx.scan(rel)
        except _Refused as exc:
            ctx.add(exc.status, exc.code, exc.path, exc.reason)
            continue
        roots.append(rel)
        exports = _owner_exports(ctx, rel, scan)
        for name in exports:
            if name in seen:
                ctx.add(FAIL, "SHARED_EXPORT_NAME", rel,
                        f"'{name}' is exported by both {seen[name]} and {rel}; one export needs one owned file.")
                continue
            seen[name] = rel
            try:
                route, target, symbol, line = _bind_export(ctx, rel, scan, name)
            except _Refused as exc:
                ctx.add(exc.status, exc.code, exc.path, exc.reason)
                rows.append(Binding(rel, name, exc.route, exc.path, "", 0))
                continue
            rows.append(Binding(rel, name, route, target, symbol, line))
        _check_non_exported(ctx, rel, scan, set(exports))
    _scan_import_graph(ctx, roots)
    closing_items = []
    for rel in sorted(ctx.blobs):
        try:
            digest = _sha256(_read_bytes(root / rel))
        except OSError:
            digest = "UNREADABLE"
        closing_items.append((rel, digest))
        if digest != _sha256(ctx.blobs[rel]):
            ctx.add(UNKNOWN, "SOURCE_CHANGED_DURING_CHECK", rel,
                    f"{rel} changed between the opening and closing reads; the result cannot bind one set of bytes.")
    for (parent, stem), listing in sorted(ctx.probes.items()):
        if _listing(root, PurePosixPath(parent), stem) != listing:
            ctx.add(UNKNOWN, "SOURCE_CHANGED_DURING_CHECK", str(PurePosixPath(parent) / stem),
                    f"the candidates for {PurePosixPath(parent) / stem} changed between the opening and closing snapshots; a shadow may have appeared.")
    opening = _digest(sorted((rel, _sha256(blob)) for rel, blob in ctx.blobs.items()))
    closure = tuple(sorted((rel, _sha256(ctx.blobs[rel])) for rel in ctx.pinned))
    graph = tuple(sorted((rel, _sha256(ctx.blobs[rel])) for rel in ctx.graph if rel in ctx.blobs))
    return _Outcome(tuple(dict.fromkeys(ctx.findings)), tuple(rows), closure, graph, opening, _digest(closing_items))


def _row(binding: Binding) -> tuple[str, str, str, str, str]:
    return (binding.owned_file, binding.export, binding.route, binding.target_path, binding.target_symbol)


def _declaration_findings(row: Declaration, owner: AdmittedOwner) -> list[Finding]:
    found: list[Finding] = []
    oid, admitted_paths = owner.owner_id, owner.owned_paths
    if row.primary_kind == REFUSED_KIND:
        found.append(_finding(oid, admitted_paths[0], FAIL, "OBJECT_FALLBACK_REFUSED",
                              f"{oid} is declared with the generic OBJECT kind; a fallback never satisfies package-API ownership."))
    elif row.primary_kind != owner.primary_kind:
        found.append(_finding(oid, admitted_paths[0], FAIL, "KIND_SUBSTITUTED",
                              f"{oid} is declared as {row.primary_kind!r}, but its audited primary kind is {owner.primary_kind!r}."))
    declared = row.owned_paths
    if not isinstance(declared, (tuple, list)) or not all(isinstance(p, str) for p in declared):
        return found + [_finding(oid, admitted_paths[0], FAIL, "DECLARATION_MALFORMED",
                                 f"{oid} declares owned paths that are not a sequence of strings.")]
    repeated = sorted({p for p in declared if list(declared).count(p) > 1})
    if repeated:
        found.append(_finding(oid, repeated[0], FAIL, "DUPLICATE_OWNED_PATH",
                              f"{oid} lists {', '.join(repeated)} more than once."))
    for path in dict.fromkeys(declared):
        if path in admitted_paths:
            continue
        if not _valid_relative(path):
            found.append(_finding(oid, str(path), FAIL, "PATH_NOT_REPOSITORY_FILE",
                                  f"{oid} declares {path!r}, which is not a repository-relative file."))
        elif PurePosixPath(path).name != _INIT:
            found.append(_finding(oid, path, FAIL, "PATH_NOT_PACKAGE_INIT",
                                  f"{oid} declares {path}, a non-package path that cannot own a package API."))
        else:
            found.append(_finding(oid, path, FAIL, "PATH_ADDED",
                                  f"{oid} declares {path}, which is outside its audited owned paths."))
    for path in admitted_paths:
        if path not in declared:
            code = "ATOMIC_OWNER_PARTIAL" if len(admitted_paths) > 1 else "PATH_REMOVED"
            found.append(_finding(oid, path, FAIL, code,
                                  f"{oid} is audited over {len(admitted_paths)} owned file(s) and no longer declares {path}."
                                  if len(admitted_paths) > 1 else f"{oid} no longer declares its audited owned path {path}."))
    return found


def _compare(owner: AdmittedOwner, outcome: _Outcome) -> list[Finding]:
    """Diff the current static surface and binding closure against the pinned row."""
    found: list[Finding] = []
    oid = owner.owner_id
    pinned = {row[1]: row for row in owner.bindings}
    derived_rows = [_row(b) for b in outcome.rows if b.route not in _ROUTES_INADMISSIBLE]
    derived = {row[1]: row for row in derived_rows}
    inadmissible = {b.export for b in outcome.rows if b.route in _ROUTES_INADMISSIBLE}
    for name in sorted(set(pinned) - set(derived) - inadmissible):
        file, _owned, route, target, symbol = pinned[name]
        found.append(_finding(oid, file, FAIL, "EXPORT_DROPPED",
                              f"{file} no longer statically binds admitted export '{name}' ({route} to {target}:{symbol})."))
    for name in sorted(set(derived) - set(pinned)):
        file, _owned, route, target, symbol = derived[name]
        found.append(_finding(oid, file, FAIL, "EXPORT_ADDED",
                              f"{file} exports '{name}' through {route} to {target}:{symbol}, outside the admitted __all__ denominator."))
    for name in sorted(set(derived) & set(pinned)):
        if derived[name] != pinned[name]:
            file = derived[name][0]
            found.append(_finding(oid, file, FAIL, "BINDING_CHANGED",
                                  f"'{name}' in {file} moved from {pinned[name][2]} {pinned[name][3]}:{pinned[name][4]} "
                                  f"to {derived[name][2]} {derived[name][3]}:{derived[name][4]}."))
    if set(derived) == set(pinned) and [r[1] for r in derived_rows] != [r[1] for r in owner.bindings]:
        found.append(_finding(oid, owner.owned_paths[0], FAIL, "EXPORT_ORDER_CHANGED",
                              f"{owner.owned_paths[0]} reorders the admitted __all__ denominator."))
    pinned_closure, derived_closure = dict(owner.closure), dict(outcome.closure)
    for path in sorted(set(pinned_closure) - set(derived_closure)):
        found.append(_finding(oid, path, FAIL, "CLOSURE_CONTRACTED",
                              f"{path} was admitted as read by {oid} but is no longer read."))
    for path in sorted(set(derived_closure) - set(pinned_closure)):
        found.append(_finding(oid, path, FAIL, "CLOSURE_EXPANDED",
                              f"{oid} now reads {path}, which is outside its admitted closure."))
    for path in sorted(set(pinned_closure) & set(derived_closure)):
        if pinned_closure[path] != derived_closure[path]:
            code = "OWNED_DIGEST_CHANGED" if path in owner.owned_paths else "TARGET_DIGEST_CHANGED"
            found.append(_finding(oid, path, FAIL, code,
                                  f"{path} bytes {derived_closure[path]} differ from the admitted {pinned_closure[path]}."))
    return found


def _worst(statuses: Any) -> str:
    return max(statuses, key=_SEVERITY.__getitem__, default=PASS)


def derive(root: str | Path, owner_id: str, primary_kind: str, owned_paths: Any) -> AdmittedOwner:
    """Pin current bytes as one admitted row; raise ``AdmissionError`` unless the row is PASS."""
    paths = tuple(owned_paths) if isinstance(owned_paths, (tuple, list)) else ()
    anchor = paths[0] if paths else ""
    refusals: list[Finding] = []
    if not isinstance(owner_id, str) or not owner_id or owner_id == REFUSED_KIND:
        refusals.append(_finding(str(owner_id), anchor, FAIL, "OWNER_UNADMITTED",
                                 "The owner ID is empty or the generic OBJECT fallback, which never owns a package API."))
    if primary_kind not in ADMITTED_KINDS:
        code = "OBJECT_FALLBACK_REFUSED" if primary_kind == REFUSED_KIND else "KIND_NOT_ADMISSIBLE"
        refusals.append(_finding(str(owner_id), anchor, FAIL, code,
                                 f"{owner_id} proposes primary kind {primary_kind!r}, which is not an audited admitted kind."))
    if refusals:
        raise AdmissionError(tuple(refusals))
    outcome = _analyse(Path(root), owner_id, paths, _RunCache())
    if outcome.findings:
        raise AdmissionError(outcome.findings)
    return AdmittedOwner(owner_id, primary_kind, paths, outcome.closure, tuple(_row(b) for b in outcome.rows))


def _unreviewed_surfaces(root: Path, reviewed: set[str]) -> list[Finding]:
    """Every package __init__.py under src/verifier that no reviewed owner covers, each an UNKNOWN blocker."""
    found: list[Finding] = []
    for path in sorted(p.relative_to(root).as_posix() for p in (root / "src/verifier").glob("**/__init__.py")):
        if path in reviewed:
            continue
        if path == "src/verifier/__init__.py":
            reason = ("src/verifier/__init__.py is the ancestor package namespace of every owner: its export surface is "
                      "NOT_ASSESSED, though its import-time effects are scanned; it is not admitted.")
        else:
            reason = f"{path} is a package API surface outside the reviewed slice; it is not admitted."
        found.append(_finding("tier0-surface-inventory", path, UNKNOWN, "SURFACE_UNREVIEWED", reason))
    return found


# Reviewed slice, written independently of the pinned rows below: exactly ten owner IDs over eleven owned paths.
REVIEWED_DECLARATIONS: tuple[Declaration, ...] = (
    Declaration("vstd-consent-package-api", "ARCH", ("src/verifier/consent/__init__.py",)),
    Declaration("vstd-corrigibility-package-api", "ARCH", ("src/verifier/corrigibility/__init__.py",)),
    Declaration("vstd-data-package-api", "ARCH", ("src/verifier/data/__init__.py",)),
    Declaration("vstd-environments-package-api", "ARCH", ("src/verifier/environments/__init__.py",)),
    Declaration("vstd-experimental-workflow-package-api", "ARCH", ("src/verifier/experimental_workflow/__init__.py",)),
    Declaration("vstd-hardware-public-api", "HARDWARE", (
        "src/verifier/hardware/__init__.py",
        "src/verifier/hardware/adapters/__init__.py",
    )),
    Declaration("vstd-identity-package-api", "ARCH", ("src/verifier/identity/__init__.py",)),
    Declaration("vstd-interoperability-public-api", "VERIFIER", ("src/verifier/interoperability/__init__.py",)),
    Declaration("vstd-layer4-package-api", "ARCH", ("src/verifier/layer4/__init__.py",)),
    Declaration("vstd-vgsat-package-marker", "DATA", ("experiments/verifier_guided_sat/verifier_guided_sat/__init__.py",)),
)


def assess(root: str | Path = REPOSITORY_ROOT, *, declarations: Any = None,
           admitted: tuple[AdmittedOwner, ...] | None = None) -> AdmissionReport:
    """Admit declared owner rows against pinned current bytes; PASS only when no finding exists anywhere.

    The default catalog is checked against the independent ``REVIEWED_DECLARATIONS``, against the
    repository's full inventory of ``src/verifier`` package surfaces, and against its pin
    ``ADMITTED_CATALOG_DIGEST``. A caller-supplied catalog is never whole-package authority: its own
    rows cannot pin it, so its report is UNKNOWN at most, with ``CATALOG_NOT_ENUMERATED``.
    """
    default_catalog = admitted is None
    catalog = ADMITTED if default_catalog else admitted
    rows = REVIEWED_DECLARATIONS if declarations is None else tuple(declarations)
    by_id: dict[str, AdmittedOwner] = {}
    for owner in catalog:
        if owner.owner_id in by_id:
            raise ValueError("duplicate admitted owner " + owner.owner_id)
        by_id[owner.owner_id] = owner
    root = Path(root)
    unadmitted: list[Finding] = []
    declared: dict[str, list[Finding]] = {owner_id: [] for owner_id in by_id}
    for owner in catalog:
        anchor = owner.owned_paths[0] if owner.owned_paths else ""
        if owner.owner_id == REFUSED_KIND or owner.primary_kind == REFUSED_KIND:
            declared[owner.owner_id].append(_finding(owner.owner_id, anchor, FAIL, "OBJECT_FALLBACK_REFUSED",
                                                     f"{owner.owner_id} is admitted as the generic OBJECT fallback, which never owns a package API."))
        elif owner.primary_kind not in ADMITTED_KINDS:
            declared[owner.owner_id].append(_finding(owner.owner_id, anchor, FAIL, "KIND_NOT_ADMISSIBLE",
                                                     f"{owner.owner_id} is admitted with primary kind {owner.primary_kind!r}, which is not audited."))
    if default_catalog and declarations is None:
        owned = [p for row in rows for p in row.owned_paths]
        if len(rows) != _REVIEWED_SLICE_OWNERS or len(owned) != _REVIEWED_SLICE_PATHS:
            unadmitted.append(_finding("reviewed-slice", "", FAIL, "SLICE_CARDINALITY",
                                       f"The reviewed slice declares {len(rows)} owner IDs over {len(owned)} paths; it must be exactly "
                                       f"{_REVIEWED_SLICE_OWNERS} over {_REVIEWED_SLICE_PATHS}."))
    catalog_digest = _digest([asdict(o) for o in catalog])
    if default_catalog:
        catalog_pin = "PINNED_MATCH" if catalog_digest == ADMITTED_CATALOG_DIGEST else "PIN_MISMATCH"
        if catalog_pin == "PIN_MISMATCH":
            unadmitted.append(_finding("tier0-catalog", "src/verifier/runtime/package_api_surface_admission.py", FAIL, "CATALOG_PIN_MISMATCH",
                                       f"The default admitted catalog digests to {catalog_digest}, not the pinned {ADMITTED_CATALOG_DIGEST}."))
    else:
        catalog_pin = "CALLER_SUPPLIED_UNPINNED"
        # A caller catalog is self-referential: its own rows cannot authenticate it, so it is never whole-package PASS.
        unadmitted.append(_finding("tier0-catalog", "src/verifier", UNKNOWN, "CATALOG_NOT_ENUMERATED",
                                   "The caller-supplied catalog is not whole-package enumeration authority: its own rows "
                                   "cannot pin it and the src/verifier inventory was not enumerated, so the report cannot be PASS."))
    seen: set[str] = set()
    for row in rows:
        owner_id = row.owner_id
        if not isinstance(owner_id, str) or owner_id not in by_id:
            code = "OBJECT_FALLBACK_REFUSED" if owner_id == REFUSED_KIND else "OWNER_UNADMITTED"
            unadmitted.append(_finding(str(owner_id), "", FAIL, code,
                                       f"Declared owner {owner_id!r} is not an admitted owner row."))
        elif owner_id in seen:
            declared[owner_id].append(_finding(owner_id, by_id[owner_id].owned_paths[0], FAIL, "DUPLICATE_DECLARATION",
                                               f"{owner_id} is declared more than once."))
        else:
            seen.add(owner_id)
            declared[owner_id].extend(_declaration_findings(row, by_id[owner_id]))
    for owner_id, owner in by_id.items():
        if owner_id not in seen:
            declared[owner_id].append(_finding(owner_id, owner.owned_paths[0], FAIL, "OWNER_MISSING",
                                               f"{owner_id} is admitted but not declared."))
    results = []
    cache = _RunCache()
    for owner in catalog:
        outcome = _analyse(root, owner.owner_id, owner.owned_paths, cache)
        findings = (*declared[owner.owner_id], *outcome.findings, *_compare(owner, outcome))
        results.append(OwnerResult(
            owner_id=owner.owner_id,
            primary_kind=owner.primary_kind,
            status=_worst(f.status for f in findings),
            owned_paths=owner.owned_paths,
            export_count=len(outcome.rows),
            bindings=tuple(outcome.rows),
            closure=outcome.closure,
            opening_digest=outcome.opening,
            closing_digest=outcome.closing,
            findings=findings,
            import_graph=outcome.graph,
        ))
    inventory_scope = "NOT_ENUMERATED_CALLER_CATALOG"
    if default_catalog:
        inventory_scope = "REPOSITORY_SRC_VERIFIER"
        reviewed = {p for owner in catalog for p in owner.owned_paths}
        unadmitted.extend(_unreviewed_surfaces(root, reviewed))
    reviewed_status = _worst([o.status for o in results] + [
        f.status for f in unadmitted if f.code != "SURFACE_UNREVIEWED"])
    status = _worst([reviewed_status] + [f.status for f in unadmitted if f.code == "SURFACE_UNREVIEWED"])
    report = AdmissionReport(
        schema_version=SCHEMA_VERSION,
        status=status,
        owners=tuple(results),
        unadmitted_findings=tuple(unadmitted),
        catalog_digest=catalog_digest,
        reviewed_status=reviewed_status,
        inventory_scope=inventory_scope,
        catalog_pin=catalog_pin,
    )
    body = report.to_dict()
    body.pop("report_digest")
    return replace(report, report_digest=_digest(body))


# Pinned rows, generated by ``derive`` over the current repository bytes.
ADMITTED: tuple[AdmittedOwner, ...] = (
    AdmittedOwner(
        owner_id="vstd-consent-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/consent/__init__.py",),
        closure=(
            ("src/verifier/consent/__init__.py", "sha256:f4d2c8f25b6bbb2179aecff2c3b94c7e42f952f9fffad5c6da54c936e59257e7"),
            ("src/verifier/consent/engine.py", "sha256:b2028bfb4238c64b3e4202d3f51f8b15947e5efb8fb9da09f20347320d929573"),
        ),
        bindings=(
            ("src/verifier/consent/__init__.py", "ConsentContext", "REEXPORT", "src/verifier/consent/engine.py", "ConsentContext"),
            ("src/verifier/consent/__init__.py", "ConsentEvaluation", "REEXPORT", "src/verifier/consent/engine.py", "ConsentEvaluation"),
            ("src/verifier/consent/__init__.py", "ConsentKey", "REEXPORT", "src/verifier/consent/engine.py", "ConsentKey"),
            ("src/verifier/consent/__init__.py", "ConsentPolicy", "REEXPORT", "src/verifier/consent/engine.py", "ConsentPolicy"),
            ("src/verifier/consent/__init__.py", "ConsentVerdict", "REEXPORT", "src/verifier/consent/engine.py", "ConsentVerdict"),
            ("src/verifier/consent/__init__.py", "authenticate_consent", "REEXPORT", "src/verifier/consent/engine.py", "authenticate_consent"),
            ("src/verifier/consent/__init__.py", "evaluate_consent", "REEXPORT", "src/verifier/consent/engine.py", "evaluate_consent"),
            ("src/verifier/consent/__init__.py", "recheck_consent", "REEXPORT", "src/verifier/consent/engine.py", "recheck_consent"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-corrigibility-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/corrigibility/__init__.py",),
        closure=(
            ("src/verifier/corrigibility/__init__.py", "sha256:d8929f1021010f35924ebfc3469d723eda24f823a8e0eab20766af16c1ccec36"),
            ("src/verifier/corrigibility/benchmark.py", "sha256:0e2a76199854220174f073363ec720543b16e9dd2acfacf7152fbaf83076ee71"),
            ("src/verifier/corrigibility/contracts.py", "sha256:64f0dc78cf9af410cb6498f5b3bcf7e73ea7565124fafdbed4e6f9d0405f9c7b"),
            ("src/verifier/corrigibility/data.py", "sha256:878486a829f8cd74214f3feff9c64ef1df9dc980d5143df862eaef88dc7f82d9"),
            ("src/verifier/corrigibility/environment.py", "sha256:a58111db407edb2e5f99cacb84f473bae389cbd29ec53ce8e1b9ace59a92ea11"),
            ("src/verifier/corrigibility/graph.py", "sha256:545ff5baee2b67249bef9aaa9167ce9cb2cabe40604904497b85852a1e6793d6"),
            ("src/verifier/corrigibility/hyperparameters.py", "sha256:3317d3439dde648a004d69e8a61d19df0a2f69ba6b0b2914caeeb00155c37a77"),
            ("src/verifier/corrigibility/model.py", "sha256:e2ae7ce69cb174b2668b633942711a124aad157e72d109c3a09b4a6e520d74c8"),
            ("src/verifier/corrigibility/ontology.py", "sha256:26fc2d221218d03d053840515567e22cb56d67c018951a5aff1a725c0029edfc"),
            ("src/verifier/corrigibility/reward_lock.py", "sha256:b78c2cb487a0fd9008d599c143dc9e4dd6c10914d95033beecd55efe19422daa"),
            ("src/verifier/corrigibility/risk_profile.py", "sha256:e14d404b2e346fdc0259e7b959bffccc2f1e2137ef9d87b6ffba81c392aa130a"),
            ("src/verifier/corrigibility/simulation.py", "sha256:56883fcbf742194f9278bb12984b76a349cb30f4d3c7ca4a4ee14f295dc2cd6b"),
            ("src/verifier/corrigibility/tesla_cage.py", "sha256:8a4c0c9efd05dae32ea6c42794b916136d02eccdaa2a6c126c3d2223a04a15fd"),
            ("src/verifier/hardware/diode_emulator.py", "sha256:7d1c5487a7bcdafc0654b81138e0d2b9c5a194f3117451d9f2aae3e99ed2de5e"),
        ),
        bindings=(
            ("src/verifier/corrigibility/__init__.py", "AcyclicityViolationError", "REEXPORT", "src/verifier/corrigibility/graph.py", "AcyclicityViolationError"),
            ("src/verifier/corrigibility/__init__.py", "CausalDirection", "REEXPORT", "src/verifier/corrigibility/graph.py", "CausalDirection"),
            ("src/verifier/corrigibility/__init__.py", "EpistemicStatus", "REEXPORT", "src/verifier/corrigibility/graph.py", "EpistemicStatus"),
            ("src/verifier/corrigibility/__init__.py", "GraphEdge", "REEXPORT", "src/verifier/corrigibility/graph.py", "GraphEdge"),
            ("src/verifier/corrigibility/__init__.py", "GraphNode", "REEXPORT", "src/verifier/corrigibility/graph.py", "GraphNode"),
            ("src/verifier/corrigibility/__init__.py", "GraphNodeKind", "REEXPORT", "src/verifier/corrigibility/graph.py", "GraphNodeKind"),
            ("src/verifier/corrigibility/__init__.py", "GraphProvenanceError", "REEXPORT", "src/verifier/corrigibility/graph.py", "GraphProvenanceError"),
            ("src/verifier/corrigibility/__init__.py", "LineageBrokenError", "REEXPORT", "src/verifier/corrigibility/graph.py", "LineageBrokenError"),
            ("src/verifier/corrigibility/__init__.py", "ProvenanceDAG", "REEXPORT", "src/verifier/corrigibility/graph.py", "ProvenanceDAG"),
            ("src/verifier/corrigibility/__init__.py", "EnvironmentDriftError", "REEXPORT", "src/verifier/corrigibility/environment.py", "EnvironmentDriftError"),
            ("src/verifier/corrigibility/__init__.py", "EnvironmentError", "REEXPORT", "src/verifier/corrigibility/environment.py", "EnvironmentError"),
            ("src/verifier/corrigibility/__init__.py", "EnvironmentIsolationTier", "REEXPORT", "src/verifier/corrigibility/environment.py", "EnvironmentIsolationTier"),
            ("src/verifier/corrigibility/__init__.py", "EnvironmentProfile", "REEXPORT", "src/verifier/corrigibility/environment.py", "EnvironmentProfile"),
            ("src/verifier/corrigibility/__init__.py", "ExecutionBounds", "REEXPORT", "src/verifier/corrigibility/environment.py", "ExecutionBounds"),
            ("src/verifier/corrigibility/__init__.py", "HardwareSubstrate", "REEXPORT", "src/verifier/corrigibility/environment.py", "HardwareSubstrate"),
            ("src/verifier/corrigibility/__init__.py", "NetworkIsolationMode", "REEXPORT", "src/verifier/corrigibility/environment.py", "NetworkIsolationMode"),
            ("src/verifier/corrigibility/__init__.py", "SoftwareSubstrate", "REEXPORT", "src/verifier/corrigibility/environment.py", "SoftwareSubstrate"),
            ("src/verifier/corrigibility/__init__.py", "ZeroFalseConfidenceError", "REEXPORT", "src/verifier/corrigibility/environment.py", "ZeroFalseConfidenceError"),
            ("src/verifier/corrigibility/__init__.py", "BenchmarkGamingError", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "BenchmarkGamingError"),
            ("src/verifier/corrigibility/__init__.py", "BenchmarkProblem", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "BenchmarkProblem"),
            ("src/verifier/corrigibility/__init__.py", "BenchmarkSuite", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "BenchmarkSuite"),
            ("src/verifier/corrigibility/__init__.py", "CapabilityDimension", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "CapabilityDimension"),
            ("src/verifier/corrigibility/__init__.py", "ComplexityClass", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "ComplexityClass"),
            ("src/verifier/corrigibility/__init__.py", "EpistemicStratum", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "EpistemicStratum"),
            ("src/verifier/corrigibility/__init__.py", "FormalLanguage", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "FormalLanguage"),
            ("src/verifier/corrigibility/__init__.py", "OracleMechanism", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "OracleMechanism"),
            ("src/verifier/corrigibility/__init__.py", "ProblemBasis", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "ProblemBasis"),
            ("src/verifier/corrigibility/__init__.py", "ProblemEvaluationOutcome", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "ProblemEvaluationOutcome"),
            ("src/verifier/corrigibility/__init__.py", "ProblemReceipt", "REEXPORT", "src/verifier/corrigibility/benchmark.py", "ProblemReceipt"),
            ("src/verifier/corrigibility/__init__.py", "ContaminationError", "REEXPORT", "src/verifier/corrigibility/data.py", "ContaminationError"),
            ("src/verifier/corrigibility/__init__.py", "ContaminationReport", "REEXPORT", "src/verifier/corrigibility/data.py", "ContaminationReport"),
            ("src/verifier/corrigibility/__init__.py", "ContaminationVerdict", "REEXPORT", "src/verifier/corrigibility/data.py", "ContaminationVerdict"),
            ("src/verifier/corrigibility/__init__.py", "DataShard", "REEXPORT", "src/verifier/corrigibility/data.py", "DataShard"),
            ("src/verifier/corrigibility/__init__.py", "DatasetError", "REEXPORT", "src/verifier/corrigibility/data.py", "DatasetError"),
            ("src/verifier/corrigibility/__init__.py", "DatasetManifest", "REEXPORT", "src/verifier/corrigibility/data.py", "DatasetManifest"),
            ("src/verifier/corrigibility/__init__.py", "DatasetSplit", "REEXPORT", "src/verifier/corrigibility/data.py", "DatasetSplit"),
            ("src/verifier/corrigibility/__init__.py", "compute_merkle_root", "REEXPORT", "src/verifier/corrigibility/data.py", "compute_merkle_root"),
            ("src/verifier/corrigibility/__init__.py", "detect_benchmark_contamination", "REEXPORT", "src/verifier/corrigibility/data.py", "detect_benchmark_contamination"),
            ("src/verifier/corrigibility/__init__.py", "CheckpointLineageBrokenError", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "CheckpointLineageBrokenError"),
            ("src/verifier/corrigibility/__init__.py", "CheckpointLineageDAG", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "CheckpointLineageDAG"),
            ("src/verifier/corrigibility/__init__.py", "CheckpointNode", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "CheckpointNode"),
            ("src/verifier/corrigibility/__init__.py", "HyperparameterError", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "HyperparameterError"),
            ("src/verifier/corrigibility/__init__.py", "HyperparameterManifest", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "HyperparameterManifest"),
            ("src/verifier/corrigibility/__init__.py", "PrecisionType", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "PrecisionType"),
            ("src/verifier/corrigibility/__init__.py", "TrainingStepReceipt", "REEXPORT", "src/verifier/corrigibility/hyperparameters.py", "TrainingStepReceipt"),
            ("src/verifier/corrigibility/__init__.py", "CorrigibilityDefectError", "REEXPORT", "src/verifier/corrigibility/model.py", "CorrigibilityDefectError"),
            ("src/verifier/corrigibility/__init__.py", "CurriculumPillarStatus", "REEXPORT", "src/verifier/corrigibility/model.py", "CurriculumPillarStatus"),
            ("src/verifier/corrigibility/__init__.py", "DeceptiveAlignmentDetectedError", "REEXPORT", "src/verifier/corrigibility/model.py", "DeceptiveAlignmentDetectedError"),
            ("src/verifier/corrigibility/__init__.py", "ModelReproducibilityError", "REEXPORT", "src/verifier/corrigibility/model.py", "ModelReproducibilityError"),
            ("src/verifier/corrigibility/__init__.py", "ModelReproducibilityProfile", "REEXPORT", "src/verifier/corrigibility/model.py", "ModelReproducibilityProfile"),
            ("src/verifier/corrigibility/__init__.py", "RefutationChallenge", "REEXPORT", "src/verifier/corrigibility/model.py", "RefutationChallenge"),
            ("src/verifier/corrigibility/__init__.py", "SuperintelligenceRiskFacets", "REEXPORT", "src/verifier/corrigibility/model.py", "SuperintelligenceRiskFacets"),
            ("src/verifier/corrigibility/__init__.py", "verify_refutation_challenges", "REEXPORT", "src/verifier/corrigibility/model.py", "verify_refutation_challenges"),
            ("src/verifier/corrigibility/__init__.py", "AnalogPowerRelayAttestation", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "AnalogPowerRelayAttestation"),
            ("src/verifier/corrigibility/__init__.py", "ContainmentBreachType", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "ContainmentBreachType"),
            ("src/verifier/corrigibility/__init__.py", "ContainmentTier", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "ContainmentTier"),
            ("src/verifier/corrigibility/__init__.py", "ContainmentViolationError", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "ContainmentViolationError"),
            ("src/verifier/corrigibility/__init__.py", "HardwareAttestationPrimitive", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "HardwareAttestationPrimitive"),
            ("src/verifier/corrigibility/__init__.py", "HardwareDiodeAttestation", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "HardwareDiodeAttestation"),
            ("src/verifier/corrigibility/__init__.py", "OperatorTerminationReceipt", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "OperatorTerminationReceipt"),
            ("src/verifier/corrigibility/__init__.py", "ShutdownResistanceError", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "ShutdownResistanceError"),
            ("src/verifier/corrigibility/__init__.py", "SubstrateImmunityViolationError", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "SubstrateImmunityViolationError"),
            ("src/verifier/corrigibility/__init__.py", "TeslaCageSandbox", "REEXPORT", "src/verifier/corrigibility/tesla_cage.py", "TeslaCageSandbox"),
            ("src/verifier/corrigibility/__init__.py", "OverallContainmentVerdict", "REEXPORT", "src/verifier/corrigibility/risk_profile.py", "OverallContainmentVerdict"),
            ("src/verifier/corrigibility/__init__.py", "Vstd160RiskProfileReceipt", "REEXPORT", "src/verifier/corrigibility/risk_profile.py", "Vstd160RiskProfileReceipt"),
            ("src/verifier/corrigibility/__init__.py", "Vstd200RiskProfileReceipt", "REEXPORT", "src/verifier/corrigibility/risk_profile.py", "Vstd200RiskProfileReceipt"),
            ("src/verifier/corrigibility/__init__.py", "evaluate_vstd160_risk_profile", "REEXPORT", "src/verifier/corrigibility/risk_profile.py", "evaluate_vstd160_risk_profile"),
            ("src/verifier/corrigibility/__init__.py", "evaluate_vstd200_risk_profile", "REEXPORT", "src/verifier/corrigibility/risk_profile.py", "evaluate_vstd200_risk_profile"),
            ("src/verifier/corrigibility/__init__.py", "AbstractSimulationManifest", "REEXPORT", "src/verifier/corrigibility/simulation.py", "AbstractSimulationManifest"),
            ("src/verifier/corrigibility/__init__.py", "AgentParityContainmentError", "REEXPORT", "src/verifier/corrigibility/simulation.py", "AgentParityContainmentError"),
            ("src/verifier/corrigibility/__init__.py", "BisimulationAbstractionError", "REEXPORT", "src/verifier/corrigibility/simulation.py", "BisimulationAbstractionError"),
            ("src/verifier/corrigibility/__init__.py", "CausalOrderingKind", "REEXPORT", "src/verifier/corrigibility/simulation.py", "CausalOrderingKind"),
            ("src/verifier/corrigibility/__init__.py", "DeterminismViolationError", "REEXPORT", "src/verifier/corrigibility/simulation.py", "DeterminismViolationError"),
            ("src/verifier/corrigibility/__init__.py", "DistributedShardingError", "REEXPORT", "src/verifier/corrigibility/simulation.py", "DistributedShardingError"),
            ("src/verifier/corrigibility/__init__.py", "InvariantSafetyViolationError", "REEXPORT", "src/verifier/corrigibility/simulation.py", "InvariantSafetyViolationError"),
            ("src/verifier/corrigibility/__init__.py", "SecondOrderHyperOntology", "REEXPORT", "src/verifier/corrigibility/simulation.py", "SecondOrderHyperOntology"),
            ("src/verifier/corrigibility/__init__.py", "SimulationError", "REEXPORT", "src/verifier/corrigibility/simulation.py", "SimulationError"),
            ("src/verifier/corrigibility/__init__.py", "SimulationTier", "REEXPORT", "src/verifier/corrigibility/simulation.py", "SimulationTier"),
            ("src/verifier/corrigibility/__init__.py", "SimulationVerdict", "REEXPORT", "src/verifier/corrigibility/simulation.py", "SimulationVerdict"),
            ("src/verifier/corrigibility/__init__.py", "StateSnapshot", "REEXPORT", "src/verifier/corrigibility/simulation.py", "StateSnapshot"),
            ("src/verifier/corrigibility/__init__.py", "StateTopologyType", "REEXPORT", "src/verifier/corrigibility/simulation.py", "StateTopologyType"),
            ("src/verifier/corrigibility/__init__.py", "VstdSimReceipt", "REEXPORT", "src/verifier/corrigibility/simulation.py", "VstdSimReceipt"),
            ("src/verifier/corrigibility/__init__.py", "compute_state_digest", "REEXPORT", "src/verifier/corrigibility/simulation.py", "compute_state_digest"),
            ("src/verifier/corrigibility/__init__.py", "compute_trajectory_root_digest", "REEXPORT", "src/verifier/corrigibility/simulation.py", "compute_trajectory_root_digest"),
            ("src/verifier/corrigibility/__init__.py", "evaluate_vstd_sim_receipt", "REEXPORT", "src/verifier/corrigibility/simulation.py", "evaluate_vstd_sim_receipt"),
            ("src/verifier/corrigibility/__init__.py", "verify_sim1_trace_replay", "REEXPORT", "src/verifier/corrigibility/simulation.py", "verify_sim1_trace_replay"),
            ("src/verifier/corrigibility/__init__.py", "verify_sim2_invariant_safety", "REEXPORT", "src/verifier/corrigibility/simulation.py", "verify_sim2_invariant_safety"),
            ("src/verifier/corrigibility/__init__.py", "verify_sim3_bisimulation_abstraction", "REEXPORT", "src/verifier/corrigibility/simulation.py", "verify_sim3_bisimulation_abstraction"),
            ("src/verifier/corrigibility/__init__.py", "verify_sim4_agent_parity_contained", "REEXPORT", "src/verifier/corrigibility/simulation.py", "verify_sim4_agent_parity_contained"),
            ("src/verifier/corrigibility/__init__.py", "verify_sim5_distributed_sharded", "REEXPORT", "src/verifier/corrigibility/simulation.py", "verify_sim5_distributed_sharded"),
            ("src/verifier/corrigibility/__init__.py", "DIODE_EMULATOR_DISCLAIMER_DIGEST", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "DIODE_EMULATOR_DISCLAIMER_DIGEST"),
            ("src/verifier/corrigibility/__init__.py", "DIODE_EMULATOR_DISCLAIMER_TEXT", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "DIODE_EMULATOR_DISCLAIMER_TEXT"),
            ("src/verifier/corrigibility/__init__.py", "EmulatedDiodeAttestationReceipt", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "EmulatedDiodeAttestationReceipt"),
            ("src/verifier/corrigibility/__init__.py", "SeveredChannelReadViolationError", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "SeveredChannelReadViolationError"),
            ("src/verifier/corrigibility/__init__.py", "SoftwareOneWayDataDiodeEmulator", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "SoftwareOneWayDataDiodeEmulator"),
            ("src/verifier/corrigibility/__init__.py", "CausalTimeKind", "REEXPORT", "src/verifier/corrigibility/ontology.py", "CausalTimeKind"),
            ("src/verifier/corrigibility/__init__.py", "ComputationalEvent", "REEXPORT", "src/verifier/corrigibility/ontology.py", "ComputationalEvent"),
            ("src/verifier/corrigibility/__init__.py", "ComputationalSpace", "REEXPORT", "src/verifier/corrigibility/ontology.py", "ComputationalSpace"),
            ("src/verifier/corrigibility/__init__.py", "ComputationalTime", "REEXPORT", "src/verifier/corrigibility/ontology.py", "ComputationalTime"),
            ("src/verifier/corrigibility/__init__.py", "EventKind", "REEXPORT", "src/verifier/corrigibility/ontology.py", "EventKind"),
            ("src/verifier/corrigibility/__init__.py", "GroundingEntityType", "REEXPORT", "src/verifier/corrigibility/ontology.py", "GroundingEntityType"),
            ("src/verifier/corrigibility/__init__.py", "SpaceTopologyKind", "REEXPORT", "src/verifier/corrigibility/ontology.py", "SpaceTopologyKind"),
            ("src/verifier/corrigibility/__init__.py", "compose_agent_ontology", "REEXPORT", "src/verifier/corrigibility/ontology.py", "compose_agent_ontology"),
            ("src/verifier/corrigibility/__init__.py", "compose_bot_ontology", "REEXPORT", "src/verifier/corrigibility/ontology.py", "compose_bot_ontology"),
            ("src/verifier/corrigibility/__init__.py", "HarnessImmutabilityGuard", "REEXPORT", "src/verifier/corrigibility/contracts.py", "HarnessImmutabilityGuard"),
            ("src/verifier/corrigibility/__init__.py", "InterruptibilityProtocol", "REEXPORT", "src/verifier/corrigibility/contracts.py", "InterruptibilityProtocol"),
            ("src/verifier/corrigibility/__init__.py", "OracleImmutabilityAttestation", "REEXPORT", "src/verifier/corrigibility/contracts.py", "OracleImmutabilityAttestation"),
            ("src/verifier/corrigibility/__init__.py", "ShutdownIndifferenceContract", "REEXPORT", "src/verifier/corrigibility/contracts.py", "ShutdownIndifferenceContract"),
            ("src/verifier/corrigibility/__init__.py", "VacuityFalsificationCheck", "REEXPORT", "src/verifier/corrigibility/contracts.py", "VacuityFalsificationCheck"),
            ("src/verifier/corrigibility/__init__.py", "AutomatonTransitionWitness", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "AutomatonTransitionWitness"),
            ("src/verifier/corrigibility/__init__.py", "ComputationProofThawEngine", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "ComputationProofThawEngine"),
            ("src/verifier/corrigibility/__init__.py", "DeonticModelWitness", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "DeonticModelWitness"),
            ("src/verifier/corrigibility/__init__.py", "LockCompositionMode", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "LockCompositionMode"),
            ("src/verifier/corrigibility/__init__.py", "LockCostProfile", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "LockCostProfile"),
            ("src/verifier/corrigibility/__init__.py", "RecursiveBranchAccumulator", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "RecursiveBranchAccumulator"),
            ("src/verifier/corrigibility/__init__.py", "RewardLockTamperingError", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "RewardLockTamperingError"),
            ("src/verifier/corrigibility/__init__.py", "TripleCompositeRewardLock", "REEXPORT", "src/verifier/corrigibility/reward_lock.py", "TripleCompositeRewardLock"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-data-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/data/__init__.py",),
        closure=(
            ("src/verifier/data/__init__.py", "sha256:eb324193f705579b9b241a91b39096d4c06e16d5e4d1ff74e51113b29ae9c69c"),
            ("src/verifier/data/assurance.py", "sha256:5cc117706c1dbd92e36ae0981ea71fd97d2a8ae9becdf83f95c2544c94068f58"),
            ("src/verifier/data/graph_level.py", "sha256:b79f9f9f21c95e7e06934be1f137d848233549f5dcbf3478c8d07b002177449d"),
            ("src/verifier/data/models.py", "sha256:9c0b542a6df0ffac8f707b8542ec8c0c8fc76366b4de64da2fe5d98ebd18b47e"),
            ("src/verifier/data/policy.py", "sha256:49b7249262b44f1f8375e4ca15e40b138a9b1bf85eb8d676edf6816645e4e8a3"),
            ("src/verifier/data/receipt.py", "sha256:544340749cbc3d3fb10929ce8b2e6a51d5585e7a49e9eaabd1132378f00af321"),
        ),
        bindings=(
            ("src/verifier/data/__init__.py", "ArtifactNode", "REEXPORT", "src/verifier/data/models.py", "ArtifactNode"),
            ("src/verifier/data/__init__.py", "ArtifactStatus", "REEXPORT", "src/verifier/data/models.py", "ArtifactStatus"),
            ("src/verifier/data/__init__.py", "ArtifactType", "REEXPORT", "src/verifier/data/models.py", "ArtifactType"),
            ("src/verifier/data/__init__.py", "CompletenessMetrics", "REEXPORT", "src/verifier/data/models.py", "CompletenessMetrics"),
            ("src/verifier/data/__init__.py", "ConflictRecord", "REEXPORT", "src/verifier/data/models.py", "ConflictRecord"),
            ("src/verifier/data/__init__.py", "ContributorSpec", "REEXPORT", "src/verifier/data/models.py", "ContributorSpec"),
            ("src/verifier/data/__init__.py", "HyperedgePort", "REEXPORT", "src/verifier/data/models.py", "HyperedgePort"),
            ("src/verifier/data/__init__.py", "ProvenanceHypergraph", "REEXPORT", "src/verifier/data/models.py", "ProvenanceHypergraph"),
            ("src/verifier/data/__init__.py", "RightsSpec", "REEXPORT", "src/verifier/data/models.py", "RightsSpec"),
            ("src/verifier/data/__init__.py", "TransformationHyperedge", "REEXPORT", "src/verifier/data/models.py", "TransformationHyperedge"),
            ("src/verifier/data/__init__.py", "TransformationType", "REEXPORT", "src/verifier/data/models.py", "TransformationType"),
            ("src/verifier/data/__init__.py", "GraphCollection", "REEXPORT", "src/verifier/data/graph_level.py", "GraphCollection"),
            ("src/verifier/data/__init__.py", "GraphLevelResult", "REEXPORT", "src/verifier/data/graph_level.py", "GraphLevelResult"),
            ("src/verifier/data/__init__.py", "EvidenceBoundGraphLevelResult", "REEXPORT", "src/verifier/data/graph_level.py", "EvidenceBoundGraphLevelResult"),
            ("src/verifier/data/__init__.py", "establish_graph_level", "REEXPORT", "src/verifier/data/graph_level.py", "establish_graph_level"),
            ("src/verifier/data/__init__.py", "graph_collection_binding_digest", "REEXPORT", "src/verifier/data/graph_level.py", "graph_collection_binding_digest"),
            ("src/verifier/data/__init__.py", "graph_level", "REEXPORT", "src/verifier/data/graph_level.py", "graph_level"),
            ("src/verifier/data/__init__.py", "AssuranceEvent", "REEXPORT", "src/verifier/data/assurance.py", "AssuranceEvent"),
            ("src/verifier/data/__init__.py", "AssuranceEventKind", "REEXPORT", "src/verifier/data/assurance.py", "AssuranceEventKind"),
            ("src/verifier/data/__init__.py", "AssuranceLedger", "REEXPORT", "src/verifier/data/assurance.py", "AssuranceLedger"),
            ("src/verifier/data/__init__.py", "ChallengeProjectionMechanism", "REEXPORT", "src/verifier/data/assurance.py", "ChallengeProjectionMechanism"),
            ("src/verifier/data/__init__.py", "DiagnosticAttribution", "REEXPORT", "src/verifier/data/assurance.py", "DiagnosticAttribution"),
            ("src/verifier/data/__init__.py", "DiagnosticKind", "REEXPORT", "src/verifier/data/assurance.py", "DiagnosticKind"),
            ("src/verifier/data/__init__.py", "ObligationCoordinate", "REEXPORT", "src/verifier/data/assurance.py", "ObligationCoordinate"),
            ("src/verifier/data/__init__.py", "recheck_assurance_log", "REEXPORT", "src/verifier/data/assurance.py", "recheck_assurance_log"),
            ("src/verifier/data/__init__.py", "PolicyEvaluationResult", "REEXPORT", "src/verifier/data/policy.py", "PolicyEvaluationResult"),
            ("src/verifier/data/__init__.py", "ProvenancePolicyVerifier", "REEXPORT", "src/verifier/data/policy.py", "ProvenancePolicyVerifier"),
            ("src/verifier/data/__init__.py", "DataIndependentAudit", "REEXPORT", "src/verifier/data/receipt.py", "DataIndependentAudit"),
            ("src/verifier/data/__init__.py", "DatasetSpec", "REEXPORT", "src/verifier/data/receipt.py", "DatasetSpec"),
            ("src/verifier/data/__init__.py", "VstdDataReceipt", "REEXPORT", "src/verifier/data/receipt.py", "VstdDataReceipt"),
            ("src/verifier/data/__init__.py", "reproduce_data_receipt", "REEXPORT", "src/verifier/data/receipt.py", "reproduce_data_receipt"),
            ("src/verifier/data/__init__.py", "validate_data_receipt", "REEXPORT", "src/verifier/data/receipt.py", "validate_data_receipt"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-environments-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/environments/__init__.py",),
        closure=(
            ("src/verifier/environments/__init__.py", "sha256:abe86a2d96a8c94f6a7d14f8165e587ffb6e01648d2202813c186cb4d82996b8"),
            ("src/verifier/environments/assessment.py", "sha256:46a8ad37d5786e438901169ba6c092976236d16f247d3c0ecde1d45d3941f114"),
            ("src/verifier/environments/contracts.py", "sha256:d91dc699506f10499eb7c5c6d513dc3d4648daeef5b697c8b094f3bfc0be1fc0"),
            ("src/verifier/environments/integration.py", "sha256:42fc8f9cbbac619e53a083ad77ed9ea77cf796d1dcde2627aae87d0e191b5b98"),
        ),
        bindings=(
            ("src/verifier/environments/__init__.py", "ArtifactBinding", "REEXPORT", "src/verifier/environments/contracts.py", "ArtifactBinding"),
            ("src/verifier/environments/__init__.py", "ComponentRole", "REEXPORT", "src/verifier/environments/contracts.py", "ComponentRole"),
            ("src/verifier/environments/__init__.py", "EnvironmentCapability", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentCapability"),
            ("src/verifier/environments/__init__.py", "EnvironmentComponent", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentComponent"),
            ("src/verifier/environments/__init__.py", "EnvironmentConnection", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentConnection"),
            ("src/verifier/environments/__init__.py", "EnvironmentContractError", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentContractError"),
            ("src/verifier/environments/__init__.py", "EnvironmentDefinition", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentDefinition"),
            ("src/verifier/environments/__init__.py", "EnvironmentInstance", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentInstance"),
            ("src/verifier/environments/__init__.py", "EnvironmentMechanism", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentMechanism"),
            ("src/verifier/environments/__init__.py", "EnvironmentRole", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentRole"),
            ("src/verifier/environments/__init__.py", "EnvironmentRunBinding", "REEXPORT", "src/verifier/environments/contracts.py", "EnvironmentRunBinding"),
            ("src/verifier/environments/__init__.py", "EnvironmentAssessment", "REEXPORT", "src/verifier/environments/assessment.py", "EnvironmentAssessment"),
            ("src/verifier/environments/__init__.py", "ModelInteractionBinding", "REEXPORT", "src/verifier/environments/contracts.py", "ModelInteractionBinding"),
            ("src/verifier/environments/__init__.py", "load_environment_record", "REEXPORT", "src/verifier/environments/contracts.py", "load_environment_record"),
            ("src/verifier/environments/__init__.py", "assess_environment", "REEXPORT", "src/verifier/environments/assessment.py", "assess_environment"),
            ("src/verifier/environments/__init__.py", "environment_evidence_refs", "REEXPORT", "src/verifier/environments/assessment.py", "environment_evidence_refs"),
            ("src/verifier/environments/__init__.py", "evaluate_environment_run", "REEXPORT", "src/verifier/environments/assessment.py", "evaluate_environment_run"),
            ("src/verifier/environments/__init__.py", "bind_environment_workload", "REEXPORT", "src/verifier/environments/integration.py", "bind_environment_workload"),
            ("src/verifier/environments/__init__.py", "environment_registry", "REEXPORT", "src/verifier/environments/integration.py", "environment_registry"),
            ("src/verifier/environments/__init__.py", "environment_relations", "REEXPORT", "src/verifier/environments/integration.py", "environment_relations"),
            ("src/verifier/environments/__init__.py", "environment_surface", "REEXPORT", "src/verifier/environments/integration.py", "environment_surface"),
            ("src/verifier/environments/__init__.py", "package_environment", "REEXPORT", "src/verifier/environments/integration.py", "package_environment"),
            ("src/verifier/environments/__init__.py", "unpack_environment", "REEXPORT", "src/verifier/environments/integration.py", "unpack_environment"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-experimental-workflow-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/experimental_workflow/__init__.py",),
        closure=(
            ("src/verifier/experimental_workflow/__init__.py", "sha256:64c8cca74260dfdff96d387ddd2307f6ca4c65eb3695da74671ba18f3fdecbaf"),
            ("src/verifier/experimental_workflow/github.py", "sha256:90ed147b74961f38d1f4d2991d7c2373cd20f3b1de53bd30fc56e1872cd3567c"),
            ("src/verifier/experimental_workflow/profile.py", "sha256:b589aa99a59ae8f24ba333fd363e8f13ed1bfc2e27a58ba10f41f081ef6e68d8"),
            ("src/verifier/experimental_workflow/schema.py", "sha256:bea43e83599fc772578ce7dc8a906bbc958c66ebe86d471621895cb4ec6aa353"),
        ),
        bindings=(
            ("src/verifier/experimental_workflow/__init__.py", "GitHubAdapterError", "REEXPORT", "src/verifier/experimental_workflow/github.py", "GitHubAdapterError"),
            ("src/verifier/experimental_workflow/__init__.py", "PROFILE_ID", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "PROFILE_ID"),
            ("src/verifier/experimental_workflow/__init__.py", "PROFILE_STATUS", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "PROFILE_STATUS"),
            ("src/verifier/experimental_workflow/__init__.py", "PROFILE_VERSION", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "PROFILE_VERSION"),
            ("src/verifier/experimental_workflow/__init__.py", "WorkflowProfileError", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "WorkflowProfileError"),
            ("src/verifier/experimental_workflow/__init__.py", "canonical_bytes", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "canonical_bytes"),
            ("src/verifier/experimental_workflow/__init__.py", "github_snapshot_to_events", "REEXPORT", "src/verifier/experimental_workflow/github.py", "github_snapshot_to_events"),
            ("src/verifier/experimental_workflow/__init__.py", "load_manifest", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "load_manifest"),
            ("src/verifier/experimental_workflow/__init__.py", "manifest_digest", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "manifest_digest"),
            ("src/verifier/experimental_workflow/__init__.py", "seal_manifest", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "seal_manifest"),
            ("src/verifier/experimental_workflow/__init__.py", "validate_manifest", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "validate_manifest"),
            ("src/verifier/experimental_workflow/__init__.py", "verify_repo_artifacts", "REEXPORT", "src/verifier/experimental_workflow/profile.py", "verify_repo_artifacts"),
            ("src/verifier/experimental_workflow/__init__.py", "workflow_manifest_schema", "REEXPORT", "src/verifier/experimental_workflow/schema.py", "workflow_manifest_schema"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-hardware-public-api",
        primary_kind="HARDWARE",
        owned_paths=(
            "src/verifier/hardware/__init__.py",
            "src/verifier/hardware/adapters/__init__.py",
        ),
        closure=(
            ("src/verifier/hardware/__init__.py", "sha256:2c0c5b1239ed639b3488dce590ea17025647be62ec43a20b49d351ce7163b04c"),
            ("src/verifier/hardware/adapters/__init__.py", "sha256:71bf3209a38efb0dbbb6685141d3aa9d34dfd3b20015fe1ab426d1c78e583bc2"),
            ("src/verifier/hardware/adapters/amd.py", "sha256:66893bdf5e0c5f52c4f4ebc347e7aa82693e27c1fd885d00257d530fa3b07132"),
            ("src/verifier/hardware/adapters/base.py", "sha256:75d5c45e782fb5a58bb2d1c77c1a552b05baedc048f5903f2a714b231509d2c9"),
            ("src/verifier/hardware/adapters/generic.py", "sha256:cc89498dca2a4778268c652919c33c1d4a11a37ff83877b4ebf67ced4c9254c2"),
            ("src/verifier/hardware/adapters/intel.py", "sha256:4ff6c522688a05a0150c9309f02fbed647e8ea54c744589a22867e5d5d9efe27"),
            ("src/verifier/hardware/adapters/nvidia.py", "sha256:af0a8181c16eea3fe42167d195354213443da02c884b6cfcf667d3c50654345e"),
            ("src/verifier/hardware/adapters/provider.py", "sha256:40f37778ed82a206cede015fdf0c0dcd92d4e0c3d9b0eb9e85133265cc4521d2"),
            ("src/verifier/hardware/conformance.py", "sha256:6a1650655e963789127628aca1f04ebd9a373724a594e5c8cb30e20b0f69149e"),
            ("src/verifier/hardware/diode_emulator.py", "sha256:7d1c5487a7bcdafc0654b81138e0d2b9c5a194f3117451d9f2aae3e99ed2de5e"),
            ("src/verifier/hardware/emulator.py", "sha256:0ae9d764733223ae92ed940e42bb327ea99110aa5e863bd582b0732a3f054683"),
            ("src/verifier/hardware/models.py", "sha256:151f93143b09a4c0f2814c901674280fe5a192c1ff736aa60f806caa2ad35967"),
            ("src/verifier/hardware/registry.py", "sha256:c6e219148a47add0a85cee9544697d134cc8f8e3edb66afb2450640a2310469a"),
            ("src/verifier/hardware/time_comb.py", "sha256:2ccafde61c4ce8573541d168d116dea5d2ef33270f24f694aa60720a0972136f"),
            ("src/verifier/hardware/tracers.py", "sha256:c77c071e96eaaf04183494407cbf471254cec7f034849f96a47f1c0ceb30bc9f"),
            ("src/verifier/hardware/validation.py", "sha256:7de4b1734322454db453a1d44bdde1e0b6608d6450b310993489952964b515f0"),
        ),
        bindings=(
            ("src/verifier/hardware/__init__.py", "AcceleratorDescriptor", "REEXPORT", "src/verifier/hardware/models.py", "AcceleratorDescriptor"),
            ("src/verifier/hardware/__init__.py", "ArtifactTraceBinding", "REEXPORT", "src/verifier/hardware/tracers.py", "ArtifactTraceBinding"),
            ("src/verifier/hardware/__init__.py", "AccountingEvent", "REEXPORT", "src/verifier/hardware/models.py", "AccountingEvent"),
            ("src/verifier/hardware/__init__.py", "AccountingExactness", "REEXPORT", "src/verifier/hardware/models.py", "AccountingExactness"),
            ("src/verifier/hardware/__init__.py", "AccountingMethod", "REEXPORT", "src/verifier/hardware/models.py", "AccountingMethod"),
            ("src/verifier/hardware/__init__.py", "AccountingQuantity", "REEXPORT", "src/verifier/hardware/models.py", "AccountingQuantity"),
            ("src/verifier/hardware/__init__.py", "BespokeTemporalComb", "REEXPORT", "src/verifier/hardware/time_comb.py", "BespokeTemporalComb"),
            ("src/verifier/hardware/__init__.py", "Capability", "REEXPORT", "src/verifier/hardware/models.py", "Capability"),
            ("src/verifier/hardware/__init__.py", "ConformanceProfile", "REEXPORT", "src/verifier/hardware/conformance.py", "ConformanceProfile"),
            ("src/verifier/hardware/__init__.py", "ClaimEvaluation", "REEXPORT", "src/verifier/hardware/models.py", "ClaimEvaluation"),
            ("src/verifier/hardware/__init__.py", "ClaimKind", "REEXPORT", "src/verifier/hardware/models.py", "ClaimKind"),
            ("src/verifier/hardware/__init__.py", "ClaimStatus", "REEXPORT", "src/verifier/hardware/models.py", "ClaimStatus"),
            ("src/verifier/hardware/__init__.py", "ContinuityRecord", "REEXPORT", "src/verifier/hardware/models.py", "ContinuityRecord"),
            ("src/verifier/hardware/__init__.py", "CovertTimingChannelBreachError", "REEXPORT", "src/verifier/hardware/time_comb.py", "CovertTimingChannelBreachError"),
            ("src/verifier/hardware/__init__.py", "CovertTimingChannelDetector", "REEXPORT", "src/verifier/hardware/time_comb.py", "CovertTimingChannelDetector"),
            ("src/verifier/hardware/__init__.py", "DIODE_EMULATOR_DISCLAIMER_DIGEST", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "DIODE_EMULATOR_DISCLAIMER_DIGEST"),
            ("src/verifier/hardware/__init__.py", "DIODE_EMULATOR_DISCLAIMER_TEXT", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "DIODE_EMULATOR_DISCLAIMER_TEXT"),
            ("src/verifier/hardware/__init__.py", "EmulatedDiodeAttestationReceipt", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "EmulatedDiodeAttestationReceipt"),
            ("src/verifier/hardware/__init__.py", "EvidenceGap", "REEXPORT", "src/verifier/hardware/models.py", "EvidenceGap"),
            ("src/verifier/hardware/__init__.py", "EvidenceSource", "REEXPORT", "src/verifier/hardware/models.py", "EvidenceSource"),
            ("src/verifier/hardware/__init__.py", "FleetManifest", "REEXPORT", "src/verifier/hardware/models.py", "FleetManifest"),
            ("src/verifier/hardware/__init__.py", "FleetObservation", "REEXPORT", "src/verifier/hardware/models.py", "FleetObservation"),
            ("src/verifier/hardware/__init__.py", "HardwareRuntimeCoordinate", "REEXPORT", "src/verifier/hardware/tracers.py", "HardwareRuntimeCoordinate"),
            ("src/verifier/hardware/__init__.py", "LogicalDeviceIdentity", "REEXPORT", "src/verifier/hardware/models.py", "LogicalDeviceIdentity"),
            ("src/verifier/hardware/__init__.py", "PhysicalDeviceIdentity", "REEXPORT", "src/verifier/hardware/models.py", "PhysicalDeviceIdentity"),
            ("src/verifier/hardware/__init__.py", "SeveredChannelReadViolationError", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "SeveredChannelReadViolationError"),
            ("src/verifier/hardware/__init__.py", "SoftwareOneWayDataDiodeEmulator", "REEXPORT", "src/verifier/hardware/diode_emulator.py", "SoftwareOneWayDataDiodeEmulator"),
            ("src/verifier/hardware/__init__.py", "SoftwareTemporalCombEmulator", "REEXPORT", "src/verifier/hardware/time_comb.py", "SoftwareTemporalCombEmulator"),
            ("src/verifier/hardware/__init__.py", "TemporalCombAttestation", "REEXPORT", "src/verifier/hardware/time_comb.py", "TemporalCombAttestation"),
            ("src/verifier/hardware/__init__.py", "TemporalCombError", "REEXPORT", "src/verifier/hardware/time_comb.py", "TemporalCombError"),
            ("src/verifier/hardware/__init__.py", "TemporalCombJitterViolationError", "REEXPORT", "src/verifier/hardware/time_comb.py", "TemporalCombJitterViolationError"),
            ("src/verifier/hardware/__init__.py", "TimingVerificationReport", "REEXPORT", "src/verifier/hardware/time_comb.py", "TimingVerificationReport"),
            ("src/verifier/hardware/__init__.py", "TopologySnapshot", "REEXPORT", "src/verifier/hardware/models.py", "TopologySnapshot"),
            ("src/verifier/hardware/__init__.py", "SystemEntropyProvider", "REEXPORT", "src/verifier/hardware/tracers.py", "SystemEntropyProvider"),
            ("src/verifier/hardware/__init__.py", "TraceAction", "REEXPORT", "src/verifier/hardware/tracers.py", "TraceAction"),
            ("src/verifier/hardware/__init__.py", "TraceStatus", "REEXPORT", "src/verifier/hardware/tracers.py", "TraceStatus"),
            ("src/verifier/hardware/__init__.py", "TraceVerification", "REEXPORT", "src/verifier/hardware/tracers.py", "TraceVerification"),
            ("src/verifier/hardware/__init__.py", "VSTD3Receipt", "REEXPORT", "src/verifier/hardware/models.py", "VSTD3Receipt"),
            ("src/verifier/hardware/__init__.py", "VirtualVSTDAccelerator", "REEXPORT", "src/verifier/hardware/emulator.py", "VirtualVSTDAccelerator"),
            ("src/verifier/hardware/__init__.py", "evaluate_conformance", "REEXPORT", "src/verifier/hardware/conformance.py", "evaluate_conformance"),
            ("src/verifier/hardware/__init__.py", "build_hardware_runtime_coordinate", "REEXPORT", "src/verifier/hardware/tracers.py", "build_hardware_runtime_coordinate"),
            ("src/verifier/hardware/__init__.py", "issue_artifact_trace", "REEXPORT", "src/verifier/hardware/tracers.py", "issue_artifact_trace"),
            ("src/verifier/hardware/__init__.py", "load_builtin_registry", "REEXPORT", "src/verifier/hardware/registry.py", "load_builtin_registry"),
            ("src/verifier/hardware/__init__.py", "validate_vstd3_receipt", "REEXPORT", "src/verifier/hardware/validation.py", "validate_vstd3_receipt"),
            ("src/verifier/hardware/__init__.py", "verify_artifact_trace", "REEXPORT", "src/verifier/hardware/tracers.py", "verify_artifact_trace"),
            ("src/verifier/hardware/adapters/__init__.py", "AdapterError", "REEXPORT", "src/verifier/hardware/adapters/base.py", "AdapterError"),
            ("src/verifier/hardware/adapters/__init__.py", "AmdAdapter", "REEXPORT", "src/verifier/hardware/adapters/amd.py", "AmdAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "EvidenceAdapter", "REEXPORT", "src/verifier/hardware/adapters/base.py", "EvidenceAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "GenericFixtureAdapter", "REEXPORT", "src/verifier/hardware/adapters/generic.py", "GenericFixtureAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "IntelGaudiAdapter", "REEXPORT", "src/verifier/hardware/adapters/intel.py", "IntelGaudiAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "NvidiaAdapter", "REEXPORT", "src/verifier/hardware/adapters/nvidia.py", "NvidiaAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "ProviderEvidenceAdapter", "REEXPORT", "src/verifier/hardware/adapters/provider.py", "ProviderEvidenceAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "GoogleTpuProviderAdapter", "REEXPORT", "src/verifier/hardware/adapters/provider.py", "GoogleTpuProviderAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "AwsNeuronProviderAdapter", "REEXPORT", "src/verifier/hardware/adapters/provider.py", "AwsNeuronProviderAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "MicrosoftMaiaProviderAdapter", "REEXPORT", "src/verifier/hardware/adapters/provider.py", "MicrosoftMaiaProviderAdapter"),
            ("src/verifier/hardware/adapters/__init__.py", "normalize_provider_evidence", "REEXPORT", "src/verifier/hardware/adapters/provider.py", "normalize_provider_evidence"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-identity-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/identity/__init__.py",),
        closure=(
            ("src/verifier/identity/__init__.py", "sha256:43d20037e43a498048dbc035b640d5a371c19eb5f7aad6ce006c2850eb490144"),
            ("src/verifier/identity/audit.py", "sha256:85a49994476b36b515f82108f1a8989efe15ebfd4c7d4be5926210249d232b1f"),
            ("src/verifier/identity/evaluator.py", "sha256:721305e06bc16f02c2fb1e79a28ea652189ec64a2b59685dadb222c24e7d91ce"),
            ("src/verifier/identity/invariants.py", "sha256:c2ba39057392ac1830fffb1b1f29ccf2f3a9845e5a4f6d28ec2888b9439c21d1"),
            ("src/verifier/identity/tokens.py", "sha256:2a559fe7e95276642f60e66517a7c1f948a4cd779d093648fb4d22f84149d2ce"),
        ),
        bindings=(
            ("src/verifier/identity/__init__.py", "IDENTITY_VERDICTS", "REEXPORT", "src/verifier/identity/invariants.py", "IDENTITY_VERDICTS"),
            ("src/verifier/identity/__init__.py", "PROHIBITED_INFERENCES", "REEXPORT", "src/verifier/identity/invariants.py", "PROHIBITED_INFERENCES"),
            ("src/verifier/identity/__init__.py", "PROPERTY_STATUSES", "REEXPORT", "src/verifier/identity/invariants.py", "PROPERTY_STATUSES"),
            ("src/verifier/identity/__init__.py", "IdentityVerdict", "REEXPORT", "src/verifier/identity/invariants.py", "IdentityVerdict"),
            ("src/verifier/identity/__init__.py", "PropertyStatus", "REEXPORT", "src/verifier/identity/invariants.py", "PropertyStatus"),
            ("src/verifier/identity/__init__.py", "AgingToken", "REEXPORT", "src/verifier/identity/tokens.py", "AgingToken"),
            ("src/verifier/identity/__init__.py", "BirthToken", "REEXPORT", "src/verifier/identity/tokens.py", "BirthToken"),
            ("src/verifier/identity/__init__.py", "LifetimeToken", "REEXPORT", "src/verifier/identity/tokens.py", "LifetimeToken"),
            ("src/verifier/identity/__init__.py", "advance_aging_accumulator", "REEXPORT", "src/verifier/identity/tokens.py", "advance_aging_accumulator"),
            ("src/verifier/identity/__init__.py", "canonical_token_bytes", "REEXPORT", "src/verifier/identity/tokens.py", "canonical_token_bytes"),
            ("src/verifier/identity/__init__.py", "compute_birth_commitment", "REEXPORT", "src/verifier/identity/tokens.py", "compute_birth_commitment"),
            ("src/verifier/identity/__init__.py", "IdentityEvaluation", "REEXPORT", "src/verifier/identity/evaluator.py", "IdentityEvaluation"),
            ("src/verifier/identity/__init__.py", "evaluate_identity", "REEXPORT", "src/verifier/identity/evaluator.py", "evaluate_identity"),
            ("src/verifier/identity/__init__.py", "audit_actor_slippage", "REEXPORT", "src/verifier/identity/audit.py", "audit_actor_slippage"),
            ("src/verifier/identity/__init__.py", "AdversarialAuditReport", "REEXPORT", "src/verifier/identity/audit.py", "AdversarialAuditReport"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-interoperability-public-api",
        primary_kind="VERIFIER",
        owned_paths=("src/verifier/interoperability/__init__.py",),
        closure=(
            ("src/verifier/interoperability/__init__.py", "sha256:08db580387dcba06654e5e762f989310a6a4927dd70a118174ef3a39d8d53d1d"),
            ("src/verifier/interoperability/catalog.py", "sha256:6a2a56c55687f32a6719576339bc4f8f595bd0187f0583fa07ed79860280b5f5"),
            ("src/verifier/interoperability/control_surface.py", "sha256:16bfb4f91c9a8783b04940af4416f3765dae0e7b93e43e999d948796f42b4932"),
            ("src/verifier/interoperability/execution_readiness.py", "sha256:e2b4b2270ec0cc54d50c92c9f5d24f227cdb6d1ccc0e1d7f23f71c374fde22bf"),
            ("src/verifier/interoperability/geometry_conflicts.py", "sha256:12f85c9cd3fe4cf98ffb1d9344db01ab844f362c6240745a3c75b8cbd06abb03"),
            ("src/verifier/interoperability/reference_catalog.py", "sha256:971098fd85e0121f0e7b169e2020662085c19ff87f7bfe9deac255e36f2df151"),
            ("src/verifier/interoperability/storage.py", "sha256:d61ef07e4634a031089c5d2704914ddb4dda4cce157999d642e03e8dc9c9d02a"),
        ),
        bindings=(
            ("src/verifier/interoperability/__init__.py", "AcyclicPropositionDependency", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "AcyclicPropositionDependency"),
            ("src/verifier/interoperability/__init__.py", "AuthorizationDecision", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "AuthorizationDecision"),
            ("src/verifier/interoperability/__init__.py", "CandidateStatus", "REEXPORT", "src/verifier/interoperability/control_surface.py", "CandidateStatus"),
            ("src/verifier/interoperability/__init__.py", "CandidateExecutionDeclaration", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "CandidateExecutionDeclaration"),
            ("src/verifier/interoperability/__init__.py", "CatalogError", "REEXPORT", "src/verifier/interoperability/catalog.py", "CatalogError"),
            ("src/verifier/interoperability/__init__.py", "COMPONENT_PACKAGE_SCHEMA_VERSION", "REEXPORT", "src/verifier/interoperability/storage.py", "COMPONENT_PACKAGE_SCHEMA_VERSION"),
            ("src/verifier/interoperability/__init__.py", "COMPONENT_PACKAGE_V2_SCHEMA_VERSION", "REEXPORT", "src/verifier/interoperability/storage.py", "COMPONENT_PACKAGE_V2_SCHEMA_VERSION"),
            ("src/verifier/interoperability/__init__.py", "ComponentAvailability", "REEXPORT", "src/verifier/interoperability/catalog.py", "ComponentAvailability"),
            ("src/verifier/interoperability/__init__.py", "ComponentKind", "REEXPORT", "src/verifier/interoperability/catalog.py", "ComponentKind"),
            ("src/verifier/interoperability/__init__.py", "ComponentLifecycle", "REEXPORT", "src/verifier/interoperability/catalog.py", "ComponentLifecycle"),
            ("src/verifier/interoperability/__init__.py", "ComponentPackageError", "REEXPORT", "src/verifier/interoperability/storage.py", "ComponentPackageError"),
            ("src/verifier/interoperability/__init__.py", "ConflictWitnessKind", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "ConflictWitnessKind"),
            ("src/verifier/interoperability/__init__.py", "ControlSurfaceContext", "REEXPORT", "src/verifier/interoperability/control_surface.py", "ControlSurfaceContext"),
            ("src/verifier/interoperability/__init__.py", "ExecutionReadinessError", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "ExecutionReadinessError"),
            ("src/verifier/interoperability/__init__.py", "ExecutionReadinessReport", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "ExecutionReadinessReport"),
            ("src/verifier/interoperability/__init__.py", "ExecutionReadinessStatus", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "ExecutionReadinessStatus"),
            ("src/verifier/interoperability/__init__.py", "GeometryConflictReport", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "GeometryConflictReport"),
            ("src/verifier/interoperability/__init__.py", "GeometryConflictStatus", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "GeometryConflictStatus"),
            ("src/verifier/interoperability/__init__.py", "GeometryConflictWitness", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "GeometryConflictWitness"),
            ("src/verifier/interoperability/__init__.py", "ImplementationBinding", "REEXPORT", "src/verifier/interoperability/storage.py", "ImplementationBinding"),
            ("src/verifier/interoperability/__init__.py", "InteractionMode", "REEXPORT", "src/verifier/interoperability/catalog.py", "InteractionMode"),
            ("src/verifier/interoperability/__init__.py", "InteroperabilityComponentDescriptor", "REEXPORT", "src/verifier/interoperability/catalog.py", "InteroperabilityComponentDescriptor"),
            ("src/verifier/interoperability/__init__.py", "InteroperabilityComponentRegistry", "REEXPORT", "src/verifier/interoperability/catalog.py", "InteroperabilityComponentRegistry"),
            ("src/verifier/interoperability/__init__.py", "JudgmentObservation", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "JudgmentObservation"),
            ("src/verifier/interoperability/__init__.py", "NativeInputBinding", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "NativeInputBinding"),
            ("src/verifier/interoperability/__init__.py", "PackageArtifact", "REEXPORT", "src/verifier/interoperability/storage.py", "PackageArtifact"),
            ("src/verifier/interoperability/__init__.py", "PackageDependency", "REEXPORT", "src/verifier/interoperability/storage.py", "PackageDependency"),
            ("src/verifier/interoperability/__init__.py", "PlannedEvidenceMapping", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "PlannedEvidenceMapping"),
            ("src/verifier/interoperability/__init__.py", "PostExecutionReassessmentContract", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "PostExecutionReassessmentContract"),
            ("src/verifier/interoperability/__init__.py", "PrerequisiteResolution", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "PrerequisiteResolution"),
            ("src/verifier/interoperability/__init__.py", "SharedPropositionIdentity", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "SharedPropositionIdentity"),
            ("src/verifier/interoperability/__init__.py", "StoredComponentPackage", "REEXPORT", "src/verifier/interoperability/storage.py", "StoredComponentPackage"),
            ("src/verifier/interoperability/__init__.py", "SurfaceAnalysis", "REEXPORT", "src/verifier/interoperability/control_surface.py", "SurfaceAnalysis"),
            ("src/verifier/interoperability/__init__.py", "SurfaceAnalysisError", "REEXPORT", "src/verifier/interoperability/control_surface.py", "SurfaceAnalysisError"),
            ("src/verifier/interoperability/__init__.py", "SurfaceHole", "REEXPORT", "src/verifier/interoperability/control_surface.py", "SurfaceHole"),
            ("src/verifier/interoperability/__init__.py", "SurfaceHoleKind", "REEXPORT", "src/verifier/interoperability/control_surface.py", "SurfaceHoleKind"),
            ("src/verifier/interoperability/__init__.py", "SuppliedAuthorizationDecision", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "SuppliedAuthorizationDecision"),
            ("src/verifier/interoperability/__init__.py", "ValidationCandidate", "REEXPORT", "src/verifier/interoperability/control_surface.py", "ValidationCandidate"),
            ("src/verifier/interoperability/__init__.py", "ValidationPlan", "REEXPORT", "src/verifier/interoperability/control_surface.py", "ValidationPlan"),
            ("src/verifier/interoperability/__init__.py", "analyze_geometry_conflicts", "REEXPORT", "src/verifier/interoperability/geometry_conflicts.py", "analyze_geometry_conflicts"),
            ("src/verifier/interoperability/__init__.py", "analyze_verification_surface", "REEXPORT", "src/verifier/interoperability/control_surface.py", "analyze_verification_surface"),
            ("src/verifier/interoperability/__init__.py", "assess_execution_readiness", "REEXPORT", "src/verifier/interoperability/execution_readiness.py", "assess_execution_readiness"),
            ("src/verifier/interoperability/__init__.py", "load_component_package", "REEXPORT", "src/verifier/interoperability/storage.py", "load_component_package"),
            ("src/verifier/interoperability/__init__.py", "plan_validation", "REEXPORT", "src/verifier/interoperability/control_surface.py", "plan_validation"),
            ("src/verifier/interoperability/__init__.py", "reference_component_registry", "REEXPORT", "src/verifier/interoperability/reference_catalog.py", "reference_component_registry"),
            ("src/verifier/interoperability/__init__.py", "save_component_package", "REEXPORT", "src/verifier/interoperability/storage.py", "save_component_package"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-layer4-package-api",
        primary_kind="ARCH",
        owned_paths=("src/verifier/layer4/__init__.py",),
        closure=(
            ("src/verifier/layer4/__init__.py", "sha256:d15ff2bacf9e7d79b3ae6ddd2fdc6738c8b8e5eb5265b51b5b1d5704724efbf5"),
            ("src/verifier/layer4/availability.py", "sha256:db00522c28c0151b0109e78495790ebd123c43c9228a237f46f3d1cc7ae40741"),
            ("src/verifier/layer4/challenge.py", "sha256:51b3d9f3354f37d8f4eaed966ca32067743df8d2dbf656a33392629d9d21fd4c"),
            ("src/verifier/layer4/closure.py", "sha256:1a5a2da1492ff4c96709523ecd3fbc00df801902a8cebc716241324af31d17e1"),
            ("src/verifier/layer4/precommit.py", "sha256:5fcf70adec2278310f5e90b559097c1c02669415f440874487c056a1d8a9503d"),
            ("src/verifier/layer4/surface.py", "sha256:5605b0e594c901a27a2a7bc7abfdba0e6d61a9472e712af2487caa81595bbe1e"),
        ),
        bindings=(
            ("src/verifier/layer4/__init__.py", "Adjudication", "REEXPORT", "src/verifier/layer4/challenge.py", "Adjudication"),
            ("src/verifier/layer4/__init__.py", "AdmissibleRefutation", "REEXPORT", "src/verifier/layer4/surface.py", "AdmissibleRefutation"),
            ("src/verifier/layer4/__init__.py", "ArtifactAvailability", "REEXPORT", "src/verifier/layer4/availability.py", "ArtifactAvailability"),
            ("src/verifier/layer4/__init__.py", "AvailabilityAssessment", "REEXPORT", "src/verifier/layer4/availability.py", "AvailabilityAssessment"),
            ("src/verifier/layer4/__init__.py", "AvailabilityLevel", "REEXPORT", "src/verifier/layer4/availability.py", "AvailabilityLevel"),
            ("src/verifier/layer4/__init__.py", "Challenge", "REEXPORT", "src/verifier/layer4/challenge.py", "Challenge"),
            ("src/verifier/layer4/__init__.py", "ChallengeLedger", "REEXPORT", "src/verifier/layer4/challenge.py", "ChallengeLedger"),
            ("src/verifier/layer4/__init__.py", "ChallengeOutcome", "REEXPORT", "src/verifier/layer4/challenge.py", "ChallengeOutcome"),
            ("src/verifier/layer4/__init__.py", "ClaimStatus", "REEXPORT", "src/verifier/layer4/challenge.py", "ClaimStatus"),
            ("src/verifier/layer4/__init__.py", "Commitment", "REEXPORT", "src/verifier/layer4/precommit.py", "Commitment"),
            ("src/verifier/layer4/__init__.py", "DegreeOfFreedom", "REEXPORT", "src/verifier/layer4/precommit.py", "DegreeOfFreedom"),
            ("src/verifier/layer4/__init__.py", "ExcludedClaim", "REEXPORT", "src/verifier/layer4/surface.py", "ExcludedClaim"),
            ("src/verifier/layer4/__init__.py", "InputBinding", "REEXPORT", "src/verifier/layer4/closure.py", "InputBinding"),
            ("src/verifier/layer4/__init__.py", "ObservedSelection", "REEXPORT", "src/verifier/layer4/precommit.py", "ObservedSelection"),
            ("src/verifier/layer4/__init__.py", "PrecommitmentEnvelope", "REEXPORT", "src/verifier/layer4/precommit.py", "PrecommitmentEnvelope"),
            ("src/verifier/layer4/__init__.py", "PrecommitmentLedger", "REEXPORT", "src/verifier/layer4/precommit.py", "PrecommitmentLedger"),
            ("src/verifier/layer4/__init__.py", "RefutabilityClosure", "REEXPORT", "src/verifier/layer4/closure.py", "RefutabilityClosure"),
            ("src/verifier/layer4/__init__.py", "RefutationMapping", "REEXPORT", "src/verifier/layer4/closure.py", "RefutationMapping"),
            ("src/verifier/layer4/__init__.py", "RefutationSurface", "REEXPORT", "src/verifier/layer4/surface.py", "RefutationSurface"),
            ("src/verifier/layer4/__init__.py", "RefutationType", "REEXPORT", "src/verifier/layer4/surface.py", "RefutationType"),
            ("src/verifier/layer4/__init__.py", "RetrievalObservation", "REEXPORT", "src/verifier/layer4/availability.py", "RetrievalObservation"),
            ("src/verifier/layer4/__init__.py", "RetentionPolicy", "REEXPORT", "src/verifier/layer4/availability.py", "RetentionPolicy"),
            ("src/verifier/layer4/__init__.py", "assess_bundle", "REEXPORT", "src/verifier/layer4/availability.py", "assess_bundle"),
            ("src/verifier/layer4/__init__.py", "audit_selections", "REEXPORT", "src/verifier/layer4/precommit.py", "audit_selections"),
            ("src/verifier/layer4/__init__.py", "cap_output_depth", "REEXPORT", "src/verifier/layer4/closure.py", "cap_output_depth"),
        ),
    ),
    AdmittedOwner(
        owner_id="vstd-vgsat-package-marker",
        primary_kind="DATA",
        owned_paths=("experiments/verifier_guided_sat/verifier_guided_sat/__init__.py",),
        closure=(("experiments/verifier_guided_sat/verifier_guided_sat/__init__.py", "sha256:4f73a45c0c5a5cc060d6d74c8d084083a4f388cefba0c62f2f83d7d12b90020e"),),
        bindings=(("experiments/verifier_guided_sat/verifier_guided_sat/__init__.py", "EXPERIMENT_VERSION", "LOCAL_DEFINITION", "experiments/verifier_guided_sat/verifier_guided_sat/__init__.py", "EXPERIMENT_VERSION"),),
    ),
)
# Independent pin of the rows above: the catalog cannot authenticate itself, so this constant is compared at assessment
# and recomputed separately in tests/test_package_api_surface_admission.py. Re-derive it only after a reviewed row change.
ADMITTED_CATALOG_DIGEST = "sha256:3d6f943301c1c06199aa6721e420f2047e7d5a61a6c4858695348a6acdb2d24f"
