"""Verifier-self launch denominator for bounded HARNESS applicability.

Terminology: JavaScript Object Notation (JSON); software development kit (SDK).

The mechanism reads Python source and its one declared embedded worker; it never
imports subject modules or starts a process.  A passing assessment means only
that the declared, direct, statically parseable launch syntax is still present
with the exact declared bytes.  It does not establish reachability, argument
values, child behaviour, external effects, sandboxing, or HARNESS conformance.
This frozen profile applies only to Verifier's own repository layout; it is not
a generic requirement for third-party packages.

Verifier Standard (VSTD); abstract syntax tree (AST); Secure Hash Algorithm
256-bit (SHA-256).
"""
from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
from typing import Any


SCHEMA = "verifier-package-harness-applicability-1"
PROFILE = "verifier-self-direct-python-launches-1"
MANIFEST_DENOMINATOR_SCHEMA = "verifier-package-harness-launch-denominator-1"
APPLICABILITY = "VERIFIER_SELF_ONLY"
SELECTION_SURFACE = "file:src/verifier/runtime/package_harness_applicability.py"
CLAIM_BOUNDARY = (
    "Verifier-self-only exact denominator of direct statically parseable calls in the "
    "declared subprocess, asyncio, and os launch vocabulary in src/verifier plus the "
    "literal language-extension WORKER. Recognized multiprocessing.Process.start "
    "launches refute this denominator instead of being silently omitted. The scan is "
    "not exhaustive over native, operating-system-specific, or third-party launch "
    "application programming interfaces (APIs). "
    "This profile is not a generic third-party package requirement. "
    "No claim about reachability, arguments, runtime outcomes, descendants, "
    "external effects, confinement, sandboxing, or HARNESS conformance."
)
EMBEDDED_WORKER_PATH = "extensions/languages/src/vstd_languages/__init__.py"
EMBEDDED_WORKER_NAME = "WORKER"
DISPOSITIONS = frozenset({
    "SOURCE_ENUMERATION_ONLY",
    "PARENT_INTERFACE_OBSERVED",
    "RUNTIME_RESULT_OBSERVED",
    "NOT_OBSERVED",
})
DEFAULT_UNOBSERVED = (
    "reachability",
    "resolved-arguments",
    "runtime-outcome",
    "child-effects",
    "descendants",
    "sandboxing",
    "process-apis-outside-vocabulary",
)

_SOURCE_DRIFT_CODES = frozenset({
    "DIRECT_LAUNCH_SOURCE_CHANGED",
    "DIRECT_LAUNCH_CALL_CHANGED",
    "EMBEDDED_WORKER_CONTAINER_CHANGED",
})
_UNAVAILABLE_DISCOVERY_CODES = frozenset({
    "PACKAGE_SOURCE_UNAVAILABLE",
    "PYTHON_SOURCE_UNREADABLE",
    "EMBEDDED_WORKER_CONTAINER_UNREADABLE",
})

_MODULES = frozenset({"subprocess", "asyncio", "os", "multiprocessing"})
_MULTIPROCESSING_CONSTRUCTOR = "multiprocessing.Process"
_MULTIPROCESSING_INSTANCE = "multiprocessing.Process()"
_SUPPORTED = frozenset({
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.system",
    "os.popen",
    "os.fork",
    "os.forkpty",
    "os.startfile",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.posix_spawn",
    "os.posix_spawnp",
})


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def mechanism_digest() -> str:
    """Bind the installed checker bytes, never a same-named subject file."""
    return _digest(Path(__file__).read_bytes())


def report_digest(report: Mapping[str, Any]) -> str:
    """Digest one report without allowing its seal to authenticate itself."""
    from verifier.runtime.tier_zero_profile import value_digest
    return value_digest({key: value for key, value in report.items()
                         if key != "report_digest"})


def _seal(report: dict[str, Any]) -> dict[str, Any]:
    report["mechanism_digest"] = mechanism_digest()
    report["report_digest"] = report_digest(report)
    return report


def _manifest_owner(declaration: Mapping[str, Any],
                    classified_objects: Sequence[Mapping[str, Any]] | None
                    ) -> tuple[Mapping[str, Any] | None, list[dict[str, Any]]]:
    """Select only an effective HARNESS owner of this checker's exact surface."""
    objects = declaration.get("objects")
    if type(objects) is not list:
        return None, [{"code": "SELECTION_DECLARATION_INVALID"}]
    classified = ({row.get("object_id"): row for row in classified_objects or ()
                   if isinstance(row, Mapping)})
    owners: list[tuple[str, set[Any], Mapping[str, Any]]] = []
    for row in objects:
        if not isinstance(row, Mapping) or SELECTION_SURFACE not in row.get("surfaces", ()):
            continue
        object_id = row.get("object_id")
        declared = {row.get("kind"), *row.get("specializations", ())}
        classified_row = classified.get(object_id)
        if classified_row is not None:
            declared.update(classified_row.get("declared_kinds", ()))
        if type(object_id) is not str or not object_id.strip():
            return None, [{"code": "SELECTION_OWNER_ID_INVALID"}]
        owners.append((object_id, declared, row))
    if len(owners) > 1:
        return None, [{"code": "SELECTION_OWNER_AMBIGUOUS",
            "owners": sorted(object_id for object_id, _, _ in owners)}]
    if not owners:
        return None, []
    object_id, declared, row = owners[0]
    if "HARNESS" not in declared:
        return None, []
    return row, []


def denominator_document(declarations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Represent the reviewed exact launch denominator in one HARNESS payload."""

    issues = _declaration_issues(declarations)
    if issues or any("source_ast_sha256" not in row for row in declarations):
        raise ValueError("PACKAGE_HARNESS_DECLARATIONS_INVALID")
    return {
        "schema_version": MANIFEST_DENOMINATOR_SCHEMA,
        "profile": PROFILE,
        "launches": [dict(row) for row in declarations],
    }


def declarations_from_manifest_owner(
    owner: Mapping[str, Any],
) -> tuple[dict[str, Any], ...] | None:
    """Read a selected denominator, retaining compatibility with older manifests."""

    payload = owner.get("payload")
    if not isinstance(payload, Mapping):
        return None
    denominator = payload.get("direct_launch_denominator")
    if denominator is None:
        return None
    if (
        not isinstance(denominator, Mapping)
        or denominator.get("schema_version") != MANIFEST_DENOMINATOR_SCHEMA
        or denominator.get("profile") != PROFILE
        or type(denominator.get("launches")) is not list
    ):
        raise ValueError("PACKAGE_HARNESS_MANIFEST_DENOMINATOR_INVALID")
    declarations = tuple(dict(row) for row in denominator["launches"]
                         if isinstance(row, Mapping))
    if (
        len(declarations) != len(denominator["launches"])
        or any("source_ast_sha256" not in row for row in declarations)
        or _declaration_issues(declarations)
    ):
        raise ValueError("PACKAGE_HARNESS_MANIFEST_DENOMINATOR_INVALID")
    return declarations


def integration_findings(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Map checker evidence to the existing Tier-0 coordinates and epistemic types."""
    if report.get("selection_status") != "SELECTED":
        return []
    mapped: list[dict[str, Any]] = []
    for finding in report.get("findings", ()):
        if not isinstance(finding, Mapping):
            finding = {"code": "ASSESSMENT_RESULT_INVALID"}
        source_code = finding.get("code")
        issue = finding.get("issue") if source_code == "DISCOVERY_AMBIGUITY" else None
        issue_code = issue.get("code") if isinstance(issue, Mapping) else None
        unavailable = (source_code == "ASSESSMENT_UNAVAILABLE"
                       or issue_code in _UNAVAILABLE_DISCOVERY_CODES)
        drift = source_code in _SOURCE_DRIFT_CODES
        coordinate = "VSTD-T0.7" if unavailable or drift else "VSTD-T0.2"
        status = "UNKNOWN" if unavailable else "FAIL"
        blocker = ("PACKAGE_HARNESS_APPLICABILITY_UNAVAILABLE" if unavailable else
                   "PACKAGE_HARNESS_APPLICABILITY_SOURCE_DRIFT" if drift else
                   "PACKAGE_HARNESS_APPLICABILITY_DENOMINATOR_REFUTED")
        code = "PACKAGE_HARNESS_" + (source_code if type(source_code) is str
                                     else "ASSESSMENT_RESULT_INVALID")
        mapped.append({"code": code, "source_code": source_code,
            "coordinate": coordinate, "status": status, "blocker": blocker,
            "object_id": report.get("owner_object_id"), "detail": dict(finding)})
    return mapped


def _discovery_issue_unavailable(issue: Mapping[str, Any]) -> bool:
    return issue.get("code") in _UNAVAILABLE_DISCOVERY_CODES


def assess_selected_repository(repository_root: str | Path,
                               declaration: Mapping[str, Any],
                               classified_objects: Sequence[Mapping[str, Any]] | None = None
                               ) -> dict[str, Any]:
    """Run the frozen self profile only after exact manifest selection.

    Merely containing a HARNESS object, or merely owning this path under another
    kind, does not select the Verifier-self profile.  This keeps third-party
    repositories outside a checker whose frozen denominator is intentionally
    specific to Verifier.
    """
    owner, selection_findings = _manifest_owner(declaration, classified_objects)
    if owner is None and not selection_findings:
        return _seal({"schema_version": SCHEMA, "profile": PROFILE,
            "applicability": APPLICABILITY, "selection_status": "NOT_SELECTED",
            "status": "NOT_SELECTED", "owner_object_id": None,
            "selected_surface": SELECTION_SURFACE, "findings": [], "blockers": [],
            "execution_established": False, "confinement_established": False,
            "harness_conformance_established": False,
            "claim_boundary": CLAIM_BOUNDARY})
    owner_id = owner.get("object_id") if owner is not None else None
    if selection_findings:
        assessment: dict[str, Any] = {"status": "REFUTED", "findings": selection_findings}
    else:
        try:
            selected = declarations_from_manifest_owner(owner)
            assessment = (
                assess_repository(repository_root)
                if selected is None
                else assess_repository(repository_root, selected)
            )
        except (OSError, ImportError, MemoryError, RecursionError, OverflowError) as exc:
            assessment = {"status": "UNKNOWN", "findings": [{
                "code": "ASSESSMENT_UNAVAILABLE", "error_type": type(exc).__name__}]}
        except ValueError as exc:
            assessment = {"status": "REFUTED", "findings": [{
                "code": str(exc) or "MANIFEST_DENOMINATOR_INVALID"}]}
    result = {key: value for key, value in assessment.items()
              if key not in {"mechanism_digest", "report_digest", "status"}}
    result.update(schema_version=SCHEMA, profile=PROFILE, applicability=APPLICABILITY,
        selection_status="SELECTED", owner_object_id=owner_id,
        selected_surface=SELECTION_SURFACE, execution_established=False,
        confinement_established=False, harness_conformance_established=False,
        claim_boundary=CLAIM_BOUNDARY)
    mapped = integration_findings(result)
    result["status"] = ("FAIL" if any(row["status"] == "FAIL" for row in mapped) else
                        "UNKNOWN" if mapped or assessment.get("status") != "PASS" else "PASS")
    result["blockers"] = sorted({row["blocker"] for row in mapped})
    return _seal(result)


def _call_digest(node: ast.Call) -> str:
    encoded = ast.dump(node, annotate_fields=True, include_attributes=False).encode("utf-8")
    return _digest(encoded)


def _ast_digest(node: ast.AST) -> str:
    """Bind parsed Python semantics while ignoring comments and coordinates."""

    encoded = ast.dump(node, annotate_fields=True, include_attributes=False).encode(
        "utf-8"
    )
    return _digest(encoded)


def _identity(path: str, embedded_name: str | None, scope: str,
              callee: str, ordinal: int) -> str:
    source = path if embedded_name is None else f"{path}::{embedded_name}"
    return f"{source}|scope={scope}|callee={callee}|ordinal={ordinal}"


class _LaunchVisitor(ast.NodeVisitor):
    """Resolve direct launch aliases while retaining lexical diagnostics."""

    def __init__(self, path: str, source_sha256: str, source_ast_sha256: str, *,
                 embedded_name: str | None = None,
                 container_sha256: str | None = None) -> None:
        self.path = path
        self.source_sha256 = source_sha256
        self.source_ast_sha256 = source_ast_sha256
        self.embedded_name = embedded_name
        self.container_sha256 = container_sha256
        self.launches: list[dict[str, Any]] = []
        self.issues: list[dict[str, Any]] = []
        self._scopes = ["<module>"]
        self._aliases: list[dict[str, str]] = [{}]
        self._tainted: list[set[str]] = [set()]
        self._ordinals: dict[tuple[str, str], int] = {}
        self._definition_ordinals: dict[tuple[str, str], int] = {}

    @property
    def _scope(self) -> str:
        return ".<locals>.".join(self._scopes)

    def _issue(self, node: ast.AST, code: str, detail: str) -> None:
        self.issues.append({
            "path": self.path,
            "embedded_name": self.embedded_name,
            "scope": self._scope,
            "line": getattr(node, "lineno", None),
            "column": getattr(node, "col_offset", None),
            "code": code,
            "detail": detail,
        })

    def _lookup(self, name: str) -> str | None:
        for aliases in reversed(self._aliases):
            if name in aliases:
                return aliases[name]
        return None

    def _is_tainted(self, name: str) -> bool:
        return any(name in names for names in reversed(self._tainted))

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self._lookup(node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            candidate = f"{base}.{node.attr}" if base in _MODULES else None
            if candidate in _SUPPORTED or candidate == _MULTIPROCESSING_CONSTRUCTOR:
                return candidate
        return None

    def _module_reference(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            value = self._lookup(node.id)
            return value if value in _MODULES else None
        return None

    def _dynamic_process_callee(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return self._is_tainted(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and self._is_tainted(node.value.id):
            return True
        if isinstance(node, ast.IfExp):
            candidates = (node.body, node.orelse)
            return any(self._resolve(candidate) in _SUPPORTED
                       or self._dynamic_process_callee(candidate)
                       for candidate in candidates)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "getattr" and len(node.args) >= 2:
            module = self._module_reference(node.args[0])
            if module is None:
                return False
            member = node.args[1]
            if not isinstance(member, ast.Constant) or not isinstance(member.value, str):
                return True
            return f"{module}.{member.value}" in _SUPPORTED
        if isinstance(node, ast.Subscript):
            value = node.value
            if isinstance(value, ast.Attribute) and value.attr == "__dict__":
                return self._module_reference(value.value) is not None
        return False

    def _multiprocessing_start(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Attribute) or node.attr != "start":
            return False
        value = node.value
        if isinstance(value, ast.Name):
            return self._lookup(value.id) == _MULTIPROCESSING_INSTANCE
        return (isinstance(value, ast.Call)
                and self._resolve(value.func) == _MULTIPROCESSING_CONSTRUCTOR)

    def _bind_name(self, name: str, value: str | None, *, tainted: bool = False) -> None:
        self._aliases[-1].pop(name, None)
        self._tainted[-1].discard(name)
        if value is not None:
            self._aliases[-1][name] = value
        elif tainted:
            self._tainted[-1].add(name)

    def _bind(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            resolved = self._resolve(value)
            if isinstance(value, ast.Call) \
                    and self._resolve(value.func) == _MULTIPROCESSING_CONSTRUCTOR:
                resolved = _MULTIPROCESSING_INSTANCE
            self._bind_name(target.id, resolved,
                            tainted=self._dynamic_process_callee(value))
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                and len(target.elts) == len(value.elts):
            for child_target, child_value in zip(target.elts, value.elts):
                self._bind(child_target, child_value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child_target in target.elts:
                if isinstance(child_target, ast.Name):
                    self._bind_name(child_target.id, None)

    def visit_Import(self, node: ast.Import) -> None:
        for name in node.names:
            if name.name in _MODULES:
                self._bind_name(name.asname or name.name, name.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module not in _MODULES:
            return
        for name in node.names:
            if name.name == "*":
                self._issue(node, "WILDCARD_PROCESS_IMPORT",
                            f"wildcard import from {node.module} cannot be bounded")
                continue
            candidate = f"{node.module}.{name.name}"
            if candidate in _SUPPORTED or candidate == _MULTIPROCESSING_CONSTRUCTOR:
                self._bind_name(name.asname or name.name, candidate)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._bind(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._bind(node.target, node.value)
        elif isinstance(node.target, ast.Name):
            self._bind_name(node.target.id, None)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind(node.target, node.value)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._resolve(node.func)
        if callee in _SUPPORTED:
            key = (self._scope, callee)
            ordinal = self._ordinals.get(key, 0) + 1
            self._ordinals[key] = ordinal
            record = {
                "launch_id": _identity(self.path, self.embedded_name, self._scope,
                                       callee, ordinal),
                "path": self.path,
                "embedded_name": self.embedded_name,
                "source_kind": "embedded-python-literal" if self.embedded_name else "python-file",
                "scope": self._scope,
                "callee": callee,
                "ordinal": ordinal,
                "line": node.lineno,
                "column": node.col_offset,
                "source_sha256": self.source_sha256,
                "source_ast_sha256": self.source_ast_sha256,
                "call_sha256": _call_digest(node),
            }
            if self.container_sha256 is not None:
                record["container_sha256"] = self.container_sha256
            self.launches.append(record)
        elif self._multiprocessing_start(node.func):
            self._issue(node, "UNSUPPORTED_PROCESS_FAMILY",
                        "multiprocessing.Process.start is outside the frozen launch vocabulary")
        elif self._dynamic_process_callee(node.func):
            self._issue(node, "DYNAMIC_PROCESS_CALLEE",
                        "process launch member cannot be resolved statically")
        elif isinstance(node.func, ast.Attribute) \
                and self._module_reference(node.func.value) == "subprocess" \
                and f"subprocess.{node.func.attr}" not in {
                    "subprocess.CalledProcessError", "subprocess.CompletedProcess",
                    "subprocess.STARTUPINFO", "subprocess.TimeoutExpired",
                    "subprocess.list2cmdline",
                }:
            self._issue(node, "UNSUPPORTED_PROCESS_API",
                        f"subprocess.{node.func.attr} is not in the direct-launch vocabulary")
        self.generic_visit(node)

    def _branch_state(self) -> tuple[dict[str, str], set[str]]:
        return dict(self._aliases[-1]), set(self._tainted[-1])

    def _restore_branch_state(self, state: tuple[dict[str, str], set[str]]) -> None:
        aliases, tainted = state
        self._aliases[-1] = dict(aliases)
        self._tainted[-1] = set(tainted)

    def _visit_branch(self, statements: Sequence[ast.stmt],
                      initial: tuple[dict[str, str], set[str]]
                      ) -> tuple[dict[str, str], set[str]]:
        self._restore_branch_state(initial)
        for statement in statements:
            self.visit(statement)
        return self._branch_state()

    def _merge_branch_states(self, states: Sequence[tuple[dict[str, str], set[str]]]) -> None:
        aliases: dict[str, str] = {}
        tainted: set[str] = set()
        names = {name for state_aliases, state_tainted in states
                 for name in (*state_aliases, *state_tainted)}
        for name in names:
            values = {state_aliases.get(name) for state_aliases, _ in states}
            has_taint = any(name in state_tainted for _, state_tainted in states)
            if len(values) == 1 and not has_taint:
                value = next(iter(values))
                if value is not None:
                    aliases[name] = value
                continue
            process_related = has_taint or any(
                value in _MODULES or value in _SUPPORTED
                or value in {_MULTIPROCESSING_CONSTRUCTOR, _MULTIPROCESSING_INSTANCE}
                for value in values if value is not None)
            if process_related:
                tainted.add(name)
        self._aliases[-1] = aliases
        self._tainted[-1] = tainted

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        initial = self._branch_state()
        body = self._visit_branch(node.body, initial)
        otherwise = self._visit_branch(node.orelse, initial) if node.orelse else initial
        self._merge_branch_states((body, otherwise))

    def _definition_scope(self, name: str) -> str:
        key = (self._scope, name)
        ordinal = self._definition_ordinals.get(key, 0) + 1
        self._definition_ordinals[key] = ordinal
        return name if ordinal == 1 else f"{name}#{ordinal}"

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for value in (*node.args.defaults, *node.args.kw_defaults):
            if value is not None:
                self.visit(value)
        if node.returns is not None:
            self.visit(node.returns)
        self._bind_name(node.name, None)
        inherited = dict(self._aliases[-1])
        scope = self._definition_scope(node.name)
        self._scopes.append(scope)
        self._aliases.append(inherited)
        self._tainted.append(set(self._tainted[-1]))
        arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        for argument in arguments:
            self._bind_name(argument.arg, None)
        if node.args.vararg:
            self._bind_name(node.args.vararg.arg, None)
        if node.args.kwarg:
            self._bind_name(node.args.kwarg.arg, None)
        for statement in node.body:
            self.visit(statement)
        self._tainted.pop()
        self._aliases.pop()
        self._scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind_name(node.name, None)
        inherited = dict(self._aliases[-1])
        scope = self._definition_scope(node.name)
        self._scopes.append(scope)
        self._aliases.append(inherited)
        self._tainted.append(set(self._tainted[-1]))
        for statement in node.body:
            self.visit(statement)
        self._tainted.pop()
        self._aliases.pop()
        self._scopes.pop()


def _parse_python(data: bytes, path: str, *, embedded_name: str | None = None,
                  container_sha256: str | None = None
                  ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], ast.Module | None]:
    digest = _digest(data)
    try:
        source = data.decode("utf-8")
        tree = ast.parse(source, filename=path)
    except (SyntaxError, UnicodeError) as exc:
        issue = {
            "path": path,
            "embedded_name": embedded_name,
            "scope": "<module>",
            "line": getattr(exc, "lineno", None),
            "column": getattr(exc, "offset", None),
            "code": "PYTHON_SOURCE_UNPARSEABLE",
            "detail": f"{type(exc).__name__}: {exc}",
        }
        return [], [issue], None
    visitor = _LaunchVisitor(path, digest, _ast_digest(tree), embedded_name=embedded_name,
                             container_sha256=container_sha256)
    visitor.visit(tree)
    return visitor.launches, visitor.issues, tree


def _worker_literal(tree: ast.Module, path: str) -> tuple[str | None, list[dict[str, Any]]]:
    values: list[tuple[ast.AST, Any]] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == EMBEDDED_WORKER_NAME:
                    values.append((node, ast.literal_eval(node.value) if isinstance(node.value, ast.Constant) else None))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id == EMBEDDED_WORKER_NAME:
            values.append((node, ast.literal_eval(node.value) if isinstance(node.value, ast.Constant) else None))
    if len(values) != 1 or type(values[0][1]) is not str:
        line = getattr(values[0][0], "lineno", None) if values else None
        return None, [{
            "path": path,
            "embedded_name": EMBEDDED_WORKER_NAME,
            "scope": "<module>",
            "line": line,
            "column": None,
            "code": "EMBEDDED_WORKER_LITERAL_UNAVAILABLE",
            "detail": "exactly one module-level literal WORKER string is required",
        }]
    return values[0][1], []


def discover_repository(repository_root: str | Path) -> dict[str, Any]:
    """Read a selected Verifier repository without importing or executing it."""
    root = Path(repository_root).resolve()
    package = root / "src" / "verifier"
    launches: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    scanned: list[dict[str, Any]] = []
    if not package.is_dir():
        issues.append({"path": "src/verifier", "embedded_name": None, "scope": "<module>",
            "line": None, "column": None, "code": "PACKAGE_SOURCE_UNAVAILABLE",
            "detail": "selected repository has no src/verifier directory"})
    else:
        try:
            source_paths = sorted(package.rglob("*.py"))
        except OSError as exc:
            source_paths = []
            issues.append({"path": "src/verifier", "embedded_name": None,
                "scope": "<module>", "line": None, "column": None,
                "code": "PACKAGE_SOURCE_UNAVAILABLE",
                "detail": f"{type(exc).__name__}: {exc}"})
        for source_path in source_paths:
            relative = source_path.relative_to(root).as_posix()
            try:
                if not source_path.resolve().is_relative_to(root):
                    raise OSError("source resolves outside selected repository")
                data = source_path.read_bytes()
            except OSError as exc:
                issues.append({"path": relative, "embedded_name": None, "scope": "<module>",
                    "line": None, "column": None, "code": "PYTHON_SOURCE_UNREADABLE",
                    "detail": f"{type(exc).__name__}: {exc}"})
                continue
            found, found_issues, _ = _parse_python(data, relative)
            launches.extend(found)
            issues.extend(found_issues)
            scanned.append({"path": relative, "sha256": _digest(data), "bytes": len(data)})

    worker_path = root / EMBEDDED_WORKER_PATH
    try:
        if not worker_path.resolve().is_relative_to(root):
            raise OSError("worker container resolves outside selected repository")
        worker_container = worker_path.read_bytes()
    except OSError as exc:
        issues.append({"path": EMBEDDED_WORKER_PATH, "embedded_name": EMBEDDED_WORKER_NAME,
            "scope": "<module>", "line": None, "column": None,
            "code": "EMBEDDED_WORKER_CONTAINER_UNREADABLE",
            "detail": f"{type(exc).__name__}: {exc}"})
    else:
        _, outer_issues, tree = _parse_python(worker_container, EMBEDDED_WORKER_PATH)
        issues.extend(outer_issues)
        if tree is not None:
            literal, literal_issues = _worker_literal(tree, EMBEDDED_WORKER_PATH)
            issues.extend(literal_issues)
            if literal is not None:
                found, found_issues, _ = _parse_python(
                    literal.encode("utf-8"), EMBEDDED_WORKER_PATH,
                    embedded_name=EMBEDDED_WORKER_NAME,
                    container_sha256=_digest(worker_container),
                )
                launches.extend(found)
                issues.extend(found_issues)
                scanned.append({"path": EMBEDDED_WORKER_PATH,
                    "embedded_name": EMBEDDED_WORKER_NAME,
                    "container_sha256": _digest(worker_container),
                    "sha256": _digest(literal.encode("utf-8")),
                    "bytes": len(literal.encode("utf-8"))})

    launches.sort(key=lambda row: row["launch_id"])
    issues.sort(key=lambda row: (row["path"], row["line"] or -1, row["code"]))
    ordinary = sum(row["embedded_name"] is None for row in launches)
    embedded = len(launches) - ordinary
    unavailable = any(_discovery_issue_unavailable(issue) for issue in issues)
    refuted = any(not _discovery_issue_unavailable(issue) for issue in issues)
    return _seal({
        "schema_version": SCHEMA,
        "profile": PROFILE,
        "applicability": APPLICABILITY,
        "operation": "DISCOVER_DIRECT_PROCESS_LAUNCHES",
        "status": "REFUTED" if refuted else "UNKNOWN" if unavailable else "PASS",
        "claim_boundary": CLAIM_BOUNDARY,
        "ordinary_launch_count": ordinary,
        "embedded_launch_count": embedded,
        "launch_count": len(launches),
        "launches": launches,
        "issues": issues,
        "scanned_sources": scanned,
    })


def declarations_from_discovery(discovery: Mapping[str, Any],
                                annotations: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Bind reviewed reasons and gaps to one already-discovered exact source state."""
    launches = discovery.get("launches")
    if discovery.get("status") != "PASS" or type(launches) is not list:
        raise ValueError("PACKAGE_HARNESS_DISCOVERY_NOT_ADMISSIBLE")
    records: list[dict[str, Any]] = []
    ids = {row.get("launch_id") for row in launches if type(row) is dict}
    if set(annotations) != ids:
        raise ValueError("PACKAGE_HARNESS_ANNOTATION_DENOMINATOR_DIFFERS")
    for launch in launches:
        annotation = annotations[launch["launch_id"]]
        if not isinstance(annotation, Mapping):
            raise ValueError("PACKAGE_HARNESS_ANNOTATION_INVALID")
        record = {key: launch[key] for key in (
            "launch_id", "path", "embedded_name", "source_kind", "scope", "callee",
            "ordinal", "line", "source_sha256", "source_ast_sha256", "call_sha256",
        )}
        if "container_sha256" in launch:
            record["container_sha256"] = launch["container_sha256"]
        record.update({
            "necessity_reason": annotation.get("necessity_reason"),
            "observation_disposition": annotation.get("observation_disposition"),
            "unobserved_gaps": annotation.get("unobserved_gaps"),
        })
        records.append(record)
    return tuple(records)


def _declaration_issues(declarations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(declarations):
        if not isinstance(record, Mapping):
            issues.append({"code": "DECLARATION_RECORD_INVALID",
                           "launch_id": f"declaration[{index}]"})
            continue
        launch_id = record.get("launch_id")
        prefix = launch_id if type(launch_id) is str else f"declaration[{index}]"
        if type(launch_id) is not str or not launch_id.strip() or launch_id in seen:
            issues.append({"code": "DECLARATION_ID_INVALID", "launch_id": prefix})
        elif launch_id:
            seen.add(launch_id)
        path, embedded = record.get("path"), record.get("embedded_name")
        scope, callee = record.get("scope"), record.get("callee")
        ordinal, line = record.get("ordinal"), record.get("line")
        if (type(path) is not str or not path.strip() or "\\" in path
                or embedded not in (None, EMBEDDED_WORKER_NAME)
                or type(scope) is not str or not scope.strip()
                or callee not in _SUPPORTED
                or type(ordinal) is not int or ordinal < 1
                or type(line) is not int or line < 1
                or record.get("source_kind") != (
                    "embedded-python-literal" if embedded else "python-file")
                or type(launch_id) is str
                and launch_id != _identity(path, embedded, scope, callee, ordinal)):
            issues.append({"code": "DECLARATION_COORDINATE_INVALID", "launch_id": prefix})
        reason = record.get("necessity_reason")
        if type(reason) is not str or not reason.strip():
            issues.append({"code": "DECLARATION_REASON_REQUIRED", "launch_id": prefix})
        disposition = record.get("observation_disposition")
        if disposition not in DISPOSITIONS:
            issues.append({"code": "DECLARATION_DISPOSITION_INVALID", "launch_id": prefix})
        gaps = record.get("unobserved_gaps")
        if (type(gaps) is not list and type(gaps) is not tuple) or not gaps \
                or any(type(gap) is not str or not gap.strip() for gap in gaps) \
                or len(set(gaps)) != len(gaps):
            issues.append({"code": "DECLARATION_GAPS_REQUIRED", "launch_id": prefix})
        for key in ("source_sha256", "call_sha256"):
            value = record.get(key)
            if type(value) is not str or len(value) != 71 or not value.startswith("sha256:") \
                    or any(char not in "0123456789abcdef" for char in value[7:]):
                issues.append({"code": "DECLARATION_DIGEST_INVALID", "launch_id": prefix,
                               "field": key})
        ast_digest = record.get("source_ast_sha256")
        if ast_digest is not None and (
            type(ast_digest) is not str
            or len(ast_digest) != 71
            or not ast_digest.startswith("sha256:")
            or any(char not in "0123456789abcdef" for char in ast_digest[7:])
        ):
            issues.append({"code": "DECLARATION_DIGEST_INVALID", "launch_id": prefix,
                           "field": "source_ast_sha256"})
        if record.get("embedded_name") is not None:
            value = record.get("container_sha256")
            if type(value) is not str or len(value) != 71 or not value.startswith("sha256:") \
                    or any(char not in "0123456789abcdef" for char in value[7:]):
                issues.append({"code": "DECLARATION_DIGEST_INVALID", "launch_id": prefix,
                               "field": "container_sha256"})
    return issues


def refresh_source_bindings(
    repository_root: str | Path,
    declarations: Sequence[Mapping[str, Any]],
    *,
    allow_ast_bootstrap: bool = False,
) -> tuple[dict[str, Any], ...]:
    """Refresh location and exact-source bytes without changing reviewed semantics.

    Automatic remigration may absorb a file-wide byte or line-coordinate change
    only while the complete launch identity set and every launch call AST digest
    remain identical.  Added, removed, or changed calls therefore still require
    explicit denominator review.
    """

    if _declaration_issues(declarations):
        raise ValueError("PACKAGE_HARNESS_DECLARATIONS_INVALID")
    discovery = discover_repository(repository_root)
    if discovery.get("status") != "PASS":
        raise ValueError("PACKAGE_HARNESS_DISCOVERY_NOT_ADMISSIBLE")
    observed = {row["launch_id"]: row for row in discovery["launches"]}
    selected = {row["launch_id"]: row for row in declarations}
    if set(observed) != set(selected):
        raise ValueError("PACKAGE_HARNESS_LAUNCH_DENOMINATOR_CHANGED")
    refreshed: list[dict[str, Any]] = []
    for launch_id in sorted(selected):
        prior, current = selected[launch_id], observed[launch_id]
        if prior.get("call_sha256") != current.get("call_sha256"):
            raise ValueError("PACKAGE_HARNESS_LAUNCH_CALL_CHANGED")
        prior_ast = prior.get("source_ast_sha256")
        if prior_ast is None and not allow_ast_bootstrap:
            raise ValueError("PACKAGE_HARNESS_SOURCE_AST_BINDING_REQUIRED")
        if prior_ast is not None and prior_ast != current.get("source_ast_sha256"):
            raise ValueError("PACKAGE_HARNESS_SOURCE_AST_CHANGED")
        annotation = {
            "necessity_reason": prior.get("necessity_reason"),
            "observation_disposition": prior.get("observation_disposition"),
            "unobserved_gaps": prior.get("unobserved_gaps"),
        }
        record = {key: current[key] for key in (
            "launch_id", "path", "embedded_name", "source_kind", "scope", "callee",
            "ordinal", "line", "source_sha256", "source_ast_sha256", "call_sha256",
        )}
        if "container_sha256" in current:
            record["container_sha256"] = current["container_sha256"]
        record.update(annotation)
        refreshed.append(record)
    result = tuple(refreshed)
    if _declaration_issues(result):
        raise ValueError("PACKAGE_HARNESS_REFRESHED_DECLARATIONS_INVALID")
    return result


def assess_repository(repository_root: str | Path,
                      declarations: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Refute Verifier-self drift against its explicit source-owned denominator."""
    selected = PACKAGE_LAUNCH_DECLARATIONS if declarations is None else declarations
    discovery = discover_repository(repository_root)
    findings: list[dict[str, Any]] = list(_declaration_issues(selected))
    declared = {row.get("launch_id"): row for row in selected
                if isinstance(row, Mapping) and type(row.get("launch_id")) is str}
    observed = {row["launch_id"]: row for row in discovery["launches"]}
    unavailable_ordinary_paths = {
        issue.get("path") for issue in discovery["issues"]
        if issue.get("code") == "PYTHON_SOURCE_UNREADABLE"
    }
    all_ordinary_unavailable = any(
        issue.get("code") == "PACKAGE_SOURCE_UNAVAILABLE"
        for issue in discovery["issues"]
    )
    embedded_unavailable = any(
        issue.get("code") == "EMBEDDED_WORKER_CONTAINER_UNREADABLE"
        for issue in discovery["issues"]
    )
    for launch_id in sorted(observed.keys() - declared.keys()):
        findings.append({"code": "UNDECLARED_DIRECT_LAUNCH", "launch_id": launch_id,
                         "line": observed[launch_id]["line"]})
    for launch_id in sorted(declared.keys() - observed.keys()):
        expected = declared[launch_id]
        source_unavailable = (
            embedded_unavailable if expected.get("embedded_name") is not None
            else all_ordinary_unavailable or expected.get("path") in unavailable_ordinary_paths
        )
        if source_unavailable:
            continue
        findings.append({"code": "DECLARED_DIRECT_LAUNCH_MISSING", "launch_id": launch_id,
                         "declared_line": expected.get("line")})
    for launch_id in sorted(observed.keys() & declared.keys()):
        actual, expected = observed[launch_id], declared[launch_id]
        for field, code in (
            ("source_sha256", "DIRECT_LAUNCH_SOURCE_CHANGED"),
            ("call_sha256", "DIRECT_LAUNCH_CALL_CHANGED"),
            ("container_sha256", "EMBEDDED_WORKER_CONTAINER_CHANGED"),
        ):
            if actual.get(field) != expected.get(field):
                findings.append({"code": code, "launch_id": launch_id,
                                 "expected": expected.get(field), "observed": actual.get(field)})
    for issue in discovery["issues"]:
        findings.append({"code": "DISCOVERY_AMBIGUITY", "issue": issue})
    gaps = sorted({gap for row in selected if isinstance(row, Mapping)
                   for gap in (row.get("unobserved_gaps") or []) if type(gap) is str})
    unavailable = any(
        finding.get("code") == "DISCOVERY_AMBIGUITY"
        and isinstance(finding.get("issue"), Mapping)
        and _discovery_issue_unavailable(finding["issue"])
        for finding in findings
    )
    refuted = any(not (
        finding.get("code") == "DISCOVERY_AMBIGUITY"
        and isinstance(finding.get("issue"), Mapping)
        and _discovery_issue_unavailable(finding["issue"])
    ) for finding in findings)
    return _seal({
        "schema_version": SCHEMA,
        "profile": PROFILE,
        "applicability": APPLICABILITY,
        "operation": "ASSESS_DECLARED_DIRECT_PROCESS_LAUNCHES",
        "status": "REFUTED" if refuted else "UNKNOWN" if unavailable else "PASS",
        "claim_boundary": CLAIM_BOUNDARY,
        "declared_launch_count": len(selected),
        "discovered_launch_count": discovery["launch_count"],
        "ordinary_launch_count": discovery["ordinary_launch_count"],
        "embedded_launch_count": discovery["embedded_launch_count"],
        "unobserved_gaps": gaps,
        "findings": findings,
        "discovery": discovery,
    })


def _frozen(path: str, embedded_name: str | None, scope: str, callee: str,
            ordinal: int, line: int, source_sha256: str, call_sha256: str,
            necessity_reason: str, container_sha256: str | None = None, *,
            source_ast_sha256: str,
            observation_disposition: str = "SOURCE_ENUMERATION_ONLY",
            unobserved_gaps: Sequence[str] = DEFAULT_UNOBSERVED,
            ) -> dict[str, Any]:
    record: dict[str, Any] = {
        "launch_id": _identity(path, embedded_name, scope, callee, ordinal),
        "path": path,
        "embedded_name": embedded_name,
        "source_kind": "embedded-python-literal" if embedded_name else "python-file",
        "scope": scope,
        "callee": callee,
        "ordinal": ordinal,
        "line": line,
        "source_sha256": source_sha256,
        "source_ast_sha256": source_ast_sha256,
        "call_sha256": call_sha256,
        "necessity_reason": necessity_reason,
        "observation_disposition": observation_disposition,
        "unobserved_gaps": list(unobserved_gaps),
    }
    if container_sha256 is not None:
        record["container_sha256"] = container_sha256
    return record


# Frozen after the reviewed 40-to-45 direct-launch advance.  Each row binds the exact
# source bytes, parsed-source AST, call AST, and embedded-container digest observed at
# review.  Assessment never regenerates rows; any digest drift refutes until a reviewer
# re-reviews and updates the row.  Removed from the prior 32: run.py capture_run (now
# _run_owned_process -> owned_process) and package_execution execute_bound (now
# _run_package_worker, same call AST).  Changed call AST on existing rows: WORKER
# ordinal 2 (identity retained, meaning now the Go build), amd, nvidia, self_polish _run_git.
#
# 40th row, reviewed 2026-10-16: model_corrigibility.py _invoke_worker.  The review read
# both sides of the launch.  Launcher: fixed argv [sys.executable, -I, -S, -B, -u, worker]
# with no shell, PYTHONPATH and PYTHONHOME removed, a wall-time timeout, a nonzero exit or
# any stderr refused, stdout bounded, and the worker digest compared before and after the
# run.  Worker (model_corrigibility_worker.py, 10,221 bytes, sha256:bc1faf1c...3bed41 at
# review): standard library only (base64, hashlib, hmac, json, sys); no os, process, file,
# network, or dynamic-code names; reads at most 1 MiB from stdin and writes bounded
# canonical JSON to stdout; its loops are capped at 64 steps over 8 commands; it
# authenticates correction and stop commands with HMAC-SHA-256 and acts on no external
# state.  That review is source reading only.  This row does not bind the worker's bytes
# (see the worker-source-not-bound-by-this-row gap); the guard
# tests/test_package_harness_applicability.py::
# test_model_corrigibility_worker_stays_inside_the_reviewed_pure_boundary fails if the
# worker gains an import or name outside the reviewed set, which forces a new review.
# The 2026-10-20 advance adds the five Tier-zero reasoning launches: read-only Git
# inventory, exact Git source-coordinate queries, bounded integration steps, Git-bound
# reason receipts, and isolated witness execution.  Four existing rows were rebound with
# unchanged call digests: namespace_admission (2), self_polish_estate, and tier_zero.
# The 2026-10-23 documented-applicability reviews rebind the two namespace_admission
# rows and then the Tier-zero, integration (2), and reason-checker rows after the sole
# reasons ledger became an exact input to both reconcilers and documented APPLIES was
# allowed to retain obligations over an unestablished compiled denial.  The later
# consequence-parity repair passes the exact catalog/compiler role decisions to the
# Node reconciler without creating a second authored ledger.  Their launch identities,
# call ASTs, necessity annotations, dispositions, and explicit unobserved gaps remain
# unchanged; only source-wide AST, bytes, and lines advance through closed transitions
# in package_manifest_migration.  The 2026-10-26 PRDEL large-artifact review retains
# the PRDEL Git launch identity and call AST while making the wrapper's accepted output
# ceiling an explicit finite argument.  The corresponding closed source-only transition
# in package_manifest_migration binds that exact wrapper successor.
PACKAGE_LAUNCH_DECLARATIONS: tuple[dict[str, Any], ...] = (
    _frozen("extensions/languages/src/vstd_languages/__init__.py", "WORKER",
        "<module>", "subprocess.run", 1, 30,
        "sha256:fe4424f4ac01a2a2226130960778d36b0d6283de1b02f02ed41b36fde1222014",
        "sha256:6cfc63091a06491789ac3c676cbe47b423835df39be943746e5a77083df1ab3c",
        "The language worker must invoke the selected compiler in its fresh artifact directory.",
        "sha256:31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
        source_ast_sha256="sha256:82a52519ba0e871a034cdcdfd7115163aa4f579c92ecbaec154271f3be6514b6",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment"),
    ),
    _frozen("extensions/languages/src/vstd_languages/__init__.py", "WORKER",
        "<module>", "subprocess.run", 2, 36,
        "sha256:fe4424f4ac01a2a2226130960778d36b0d6283de1b02f02ed41b36fde1222014",
        "sha256:90c2f41828557537472707df4d109d92aa923b825c58d4e9ad90a2f53472768a",
        "The Go language branch must build the selected subject in module-off, proxy-disabled mode inside its fresh artifact directory.",
        "sha256:31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
        source_ast_sha256="sha256:82a52519ba0e871a034cdcdfd7115163aa4f579c92ecbaec154271f3be6514b6",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment"),
    ),
    _frozen("extensions/languages/src/vstd_languages/__init__.py", "WORKER",
        "<module>", "subprocess.run", 3, 38,
        "sha256:fe4424f4ac01a2a2226130960778d36b0d6283de1b02f02ed41b36fde1222014",
        "sha256:d3f44c3b3ab82412bebee799fc161c4b6f2fb4d0f7ead9649c8fc99f3935187d",
        "The Swift language branch must compile the selected subject with the selected swiftc into its fresh artifact directory.",
        "sha256:31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
        source_ast_sha256="sha256:82a52519ba0e871a034cdcdfd7115163aa4f579c92ecbaec154271f3be6514b6",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment"),
    ),
    _frozen("extensions/languages/src/vstd_languages/__init__.py", "WORKER",
        "<module>", "subprocess.run", 4, 44,
        "sha256:fe4424f4ac01a2a2226130960778d36b0d6283de1b02f02ed41b36fde1222014",
        "sha256:cdbfcc63063de765484751fa921399e4c5a6805c25a81140d64963fe9893dbe1",
        "The C# language branch must query the selected dotnet SDK major version so its temporary project targets the matching framework.",
        "sha256:31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
        source_ast_sha256="sha256:82a52519ba0e871a034cdcdfd7115163aa4f579c92ecbaec154271f3be6514b6",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment", "outer-runner-bounds-only"),
    ),
    _frozen("extensions/languages/src/vstd_languages/__init__.py", "WORKER",
        "<module>", "subprocess.run", 5, 55,
        "sha256:fe4424f4ac01a2a2226130960778d36b0d6283de1b02f02ed41b36fde1222014",
        "sha256:45dda0fb988cf3b02c54e647dae84280e8a260bfb0b1edc305166342d60c7c2a",
        "The C# language branch must build the temporary project with the selected dotnet SDK so the private subject copy is compiled for the probed framework.",
        "sha256:31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
        source_ast_sha256="sha256:82a52519ba0e871a034cdcdfd7115163aa4f579c92ecbaec154271f3be6514b6",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment", "package-restore-network-not-disabled"),
    ),
    _frozen("extensions/languages/src/vstd_languages/__init__.py", "WORKER",
        "<module>", "subprocess.run", 6, 62,
        "sha256:fe4424f4ac01a2a2226130960778d36b0d6283de1b02f02ed41b36fde1222014",
        "sha256:8ab8c03a43ca545669187e5c9569971be2dc3b916bcd16922c10a3ca5947f025",
        "The language worker must execute the newly compiled subject to return its exit status.",
        "sha256:31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
        source_ast_sha256="sha256:82a52519ba0e871a034cdcdfd7115163aa4f579c92ecbaec154271f3be6514b6",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment"),
    ),
    _frozen("src/verifier/core/owned_process.py", None,
        "<module>.<locals>.PosixOwnedTree.<locals>.launch", "subprocess.Popen", 1, 279,
        "sha256:3bbc6610b122384130a205228a1e93c844e879174f0e5306dbe42014207fb4e2",
        "sha256:a7a41b6f65df507eccc4ab68b4f1d8a14aa5dc2045a969d0ce9fe26af2f98a46",
        "The POSIX owned-process primitive must start the child as a new session leader so the parent can address that process group for bounded termination.",
        source_ast_sha256="sha256:737b4d7648e46a34c0178397f92ca43caca3765e54e93ef961e08de7c1c695f1",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "caller-supplied-environment", "windows-owned-tree-outside-denominator", "process-group-cleanup-result"),
    ),
    _frozen("src/verifier/core/provenance.py", None,
        "<module>.<locals>.discover_git_provenance", "subprocess.run", 1, 154,
        "sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6",
        "sha256:1e86cfeca94b27d3f64224d76644c98e225ef650cc7baddb4d77ecefb060d046",
        "Git work-tree detection is required before repository provenance can be described.",
        source_ast_sha256="sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263",
    ),
    _frozen("src/verifier/core/provenance.py", None,
        "<module>.<locals>.discover_git_provenance", "subprocess.run", 2, 169,
        "sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6",
        "sha256:fce1e4748ac1f196cd7f5672c307403af57d5434514a36056f255d1336a25e51",
        "The exact Git commit is required for the repository provenance coordinate.",
        source_ast_sha256="sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263",
    ),
    _frozen("src/verifier/core/provenance.py", None,
        "<module>.<locals>.discover_git_provenance", "subprocess.run", 3, 179,
        "sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6",
        "sha256:3141316fd08f0168196bfe951d17914dd374ae8ed54c148279695203126e2e6f",
        "The selected branch name is queried so provenance does not infer it from a commit alone.",
        source_ast_sha256="sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263",
    ),
    _frozen("src/verifier/core/provenance.py", None,
        "<module>.<locals>.discover_git_provenance", "subprocess.run", 4, 189,
        "sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6",
        "sha256:93ada0cd0facddff5ee319d1c0a082b3aa7c1f7e92fb9bd9ab6d61cd76f4221e",
        "The configured remote is queried to distinguish local identity from repository origin.",
        source_ast_sha256="sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263",
    ),
    _frozen("src/verifier/core/provenance.py", None,
        "<module>.<locals>.discover_git_provenance", "subprocess.run", 5, 201,
        "sha256:df8f90e53e08968f4a9ffe8a13448526242926ad666ad8f1cb5fb85bcee267a6",
        "sha256:efd89269839d5d65da7c7fea949182ed92a3f8fbdfe44b5dca31ad643fa433d0",
        "Git status is required to retain whether the provenance coordinate has local changes.",
        source_ast_sha256="sha256:8a7c213bbaa62953a2aaafa88285d260a2427b176cb81556802534f39940d263",
    ),
    _frozen("src/verifier/domains/contracts/model_corrigibility.py", None,
        "<module>.<locals>._invoke_worker", "subprocess.run", 1, 592,
        "sha256:a36e5671ca925910f7e5c323d921f33e7a969a005564d17da02db55eb425daaf",
        "sha256:83a973550b9c130b65abd23b7e332702dc586a7ce2abb2a84649700093a56926",
        "MODEL corrigibility checking must launch the installed fixed model_corrigibility_worker.py in a fresh isolated interpreter (-I -S -B -u, no shell, bounded wall time and output) so the reported correction, stop and restart behavior comes from a new process that the parent then reconstructs, not from parent memory.",
        source_ast_sha256="sha256:526a84c30269114907534741e8c139f37ca0495a6f9cfce198ff451672504a4f",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment", "worker-source-not-bound-by-this-row"),
    ),
    _frozen("src/verifier/domains/contracts/sim_resource.py", None,
        "<module>.<locals>.assess_fresh_sim_resource", "subprocess.run", 1, 434,
        "sha256:838da6f7729ff4559bd13163ab2bb2586059750ecc113b9037d6746cca3dfde1",
        "sha256:95feab46e5ce02bed8ba1b1796c1e0435efe82c6cc84e600b9f1fd42324d3878",
        "SIM resource capture requires a fresh isolated meter process for the selected trajectory.",
        source_ast_sha256="sha256:17f36f4198fa8887182b363779b33b72cfb76a338515b0e59dfbbe665b29faed",
    ),
    _frozen("src/verifier/domains/contracts/sim_resource_fresh.py", None,
        "<module>.<locals>._run", "subprocess.run", 1, 141,
        "sha256:36a8064c33cc390386aa7093a06a25107458314a58672b44348a2ffb2cbe1e42",
        "sha256:5688600163e33882502b1f9ae5d8032d46440a92965e5421d5aea34fb311574a",
        "The fresh SIM mechanism requires a new isolated interpreter for its selected bootstrap.",
        source_ast_sha256="sha256:6653cfcd051b032dff53ac45ea75d6fe6e986a4ecc301edbfd1c8c8c3af0e31a",
    ),
    _frozen("src/verifier/hardware/adapters/amd.py", None,
        "<module>.<locals>.AmdAdapter.<locals>.discover", "subprocess.run", 1, 95,
        "sha256:66893bdf5e0c5f52c4f4ebc347e7aa82693e27c1fd885d00257d530fa3b07132",
        "sha256:3a0d35f3425badd9f6402257e0b1b7d26c95775c6e9d00911fa64b2a83c8ab96",
        "Advanced Micro Devices (AMD) device discovery requires the selected vendor utility to report local adapter data.",
        source_ast_sha256="sha256:d539f0d0634ec10ca3f9462a10909972242cc7069d4dcb6d7ebe59d3dc636d92",
    ),
    _frozen("src/verifier/hardware/adapters/nvidia.py", None,
        "<module>.<locals>.NvidiaAdapter.<locals>.discover", "subprocess.run", 1, 62,
        "sha256:af0a8181c16eea3fe42167d195354213443da02c884b6cfcf667d3c50654345e",
        "sha256:39e424678be26a4e0c427f817ae52a4af3a155f47fb87389a691957642a3822d",
        "NVIDIA device discovery requires the selected vendor utility to report local adapter data.",
        source_ast_sha256="sha256:c329267ebef5ae19ab3f53d44f935b24658189c3f86d7d84bb5d9347f79800a0",
    ),
    _frozen("src/verifier/interoperability/deriver_self_status.py", None,
        "<module>.<locals>._execute", "subprocess.Popen", 1, 449,
        "sha256:dea126b0b249a9fe2b08a4ce369c4eeb5dc45fa8155b7492a8fa87a578c4f4fd",
        "sha256:2c72c7be80dcc6ace0eb68bb034b6482833cb2e42f4625d2bc9397872a755bd5",
        "The selected external deriver must run for its bounded self-status transcript to exist.",
        source_ast_sha256="sha256:87feb5bf401b1ff9235f799823b4e87cf01c14c87be99227fe2ca9c772f7748f",
    ),
    _frozen("src/verifier/interoperability/deriver_self_status.py", None,
        "<module>.<locals>._recheck_execute", "subprocess.Popen", 1, 573,
        "sha256:dea126b0b249a9fe2b08a4ce369c4eeb5dc45fa8155b7492a8fa87a578c4f4fd",
        "sha256:71d9998e14fca589b1d516f2fd1def39c9647eb71b591cba0e43b5ff47e37ab4",
        "Independent deriver recheck requires a separate fresh process rather than replaying one transcript.",
        source_ast_sha256="sha256:87feb5bf401b1ff9235f799823b4e87cf01c14c87be99227fe2ca9c772f7748f",
    ),
    _frozen("src/verifier/runtime/added_kind_behavioral_routes.py", None,
        "<module>.<locals>.retained_policy_observations", "subprocess.run", 1, 872,
        "sha256:19f121645632ef499d6dc60ff5fc8b7ab7c0ed8a3fc34cdf9d023cbf44687775",
        "sha256:0a904bb3db7c80f7e1d357ea4afdd0a92a44417ef26690caf85719cff1166137",
        "The retained policy observation must run the isolated policy oracle once in a fresh no-site interpreter so raw observations and source pins come from the worker, not the parent.",
        source_ast_sha256="sha256:9fac1ad860c73b7223d50edd954db41557788982159b6e3ab5639e8313cf5ae5",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment", "undeclared-filesystem"),
    ),
    _frozen("src/verifier/runtime/explanation_projection.py", None,
        "<module>.<locals>._git", "subprocess.run", 1, 650,
        "sha256:bacaae61fcb927d78018366d66a1ff7d7936f1dd4bcb6c5ea6fb099d2337d91c",
        "sha256:fefc3f7b78fdfdd75907e75e1a73a3db06707b3a5cf443bc1396381d4b9e5b49",
        "Explanation projection queries selected Git state rather than guessing repository metadata.",
        source_ast_sha256="sha256:01d0ad415a8f2148dfe790a6bce18d9bcb0e44d11bfe440156e6b2af4803b732",
    ),
    _frozen("src/verifier/runtime/gate.py", None,
        "<module>.<locals>.run_pr_gate", "subprocess.run", 1, 525,
        "sha256:944105d4c12e4a0465301e7c52717a4042ab167e6139d231db6e96dab5d60f67",
        "sha256:b5ab93e1ce18eae9b36b599466e5a3d25dab8d3f92a1ed0ce5f79e728e0c302d",
        "The pull-request gate queries HEAD so its result is bound to an exact repository revision.",
        source_ast_sha256="sha256:e2cdaeffa92c26e68c1a130f0b49205088d5635d7e40f3aef2786d220be29ff3",
    ),
    _frozen("src/verifier/runtime/gate_pipeline.py", None,
        "<module>.<locals>._command", "subprocess.Popen", 1, 269,
        "sha256:1f1d8fa869a6efe40a84ab9ab46aae3e79eebbf75458d6b47f3fde73184c41cf",
        "sha256:1a2351b12918695e6c73f88cf54c5371ea618d235b3557ad46b268b0515a8734",
        "A declared gate command must run for the pipeline to collect its bounded output and exit status.",
        source_ast_sha256="sha256:b05ad705b33666d429da93787527bd3b39a67febd98059b742b5367ab21e6e73",
    ),
    _frozen("src/verifier/runtime/manifest_write_worker.py", None,
        "<module>.<locals>.observe.<locals>.repository", "subprocess.run", 1, 47,
        "sha256:f35b0af2432af8ce488b9e21f294269c1e1013765ef2be0f292f152ca48e69ff",
        "sha256:78813266fac7fb293b9b790a4e45d3ae2902af1689095ffa94efa8676c68d46b",
        "The manifest-write worker creates a private Git repository to observe repository-bound behavior.",
        source_ast_sha256="sha256:58898ef0065ca5f9bdda4b1406acf1bc77f891125379c512cf520496013f1332",
    ),
    _frozen("src/verifier/runtime/namespace_admission.py", None,
        "<module>.<locals>._run_bounded_reconciler", "subprocess.Popen", 1, 270,
        "sha256:9de470e6d3005a189a277757620d816603909f6654c0d15aa0073ec7d8aefa8e",
        "sha256:288a9016396a98bed557a6110c085d2956fb6c50387276f1891e491e1d31122c",
        "Namespace admission requires the independent Node reconciler under bounded input, output, error, and deadline controls for its cross-runtime comparison.",
        source_ast_sha256="sha256:7c1d95849c9e57820d4f8711a0e2923b467756c1c9bd9f09a05e86af47a13984",
    ),
    _frozen("src/verifier/runtime/namespace_admission.py", None,
        "<module>.<locals>._source_revision", "subprocess.run", 1, 346,
        "sha256:9de470e6d3005a189a277757620d816603909f6654c0d15aa0073ec7d8aefa8e",
        "sha256:b4fa577ea2b5c26b7be4e46ab75140952aa6f91a18e7f13a2c01ef08b3b990dc",
        "Namespace admission queries the selected source revision to bind the admission record.",
        source_ast_sha256="sha256:7c1d95849c9e57820d4f8711a0e2923b467756c1c9bd9f09a05e86af47a13984",
    ),
    _frozen("src/verifier/runtime/namespace_javascript.py", None,
        "<module>.<locals>._run", "subprocess.run", 1, 31,
        "sha256:e84e53346d634512a5d880597248b83a6d1e6cc8fd1ed89ad94c88736f4d1050",
        "sha256:6928fb95ea13a383c0ecf65c968f174acca0bdd973730af670cf3e7f9b8b78fd",
        "JavaScript namespace inspection requires a fresh fixed Python worker boundary.",
        source_ast_sha256="sha256:4a50bd2bd26421d270080b8a5bd24169565d77475bd46e355d7dd9a4bdd109ee",
    ),
    _frozen("src/verifier/runtime/namespace_systems.py", None,
        "<module>.<locals>._run", "subprocess.run", 1, 91,
        "sha256:124bc6737eb4d69828c29a12c640dec6846cbf6c188be9fab5910a105e388439",
        "sha256:85fbce03f249538099714f844afccd17f93d1777391b03e35be21fc8fc7ad006",
        "Systems-language namespace inspection requires a fresh fixed Python worker boundary.",
        source_ast_sha256="sha256:48bfee0eb4d5b949ed6254ebace478e4674a9eeee70c8fa894696818d95f8dd8",
    ),
    _frozen("src/verifier/runtime/namespace_workflows.py", None,
        "<module>.<locals>._run", "subprocess.Popen", 1, 67,
        "sha256:81c8eabb6b0b82c6b22ba8ee149e81b662553be793bb23cc63381c9ea2728b33",
        "sha256:4abaacd64144c7ef5c2d7f23020d3203d860df071ebdb7f838f938a200713df2",
        "Workflow namespace inspection requires a fresh fixed Python worker boundary.",
        source_ast_sha256="sha256:2bdeed1da028f181517561ad0e1448467cf046222a245ec347e5c8b776bd4cbe",
    ),
    _frozen("src/verifier/runtime/package_execution.py", None,
        "<module>.<locals>._run_package_worker", "subprocess.run", 1, 72,
        "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
        "sha256:efddd4e037130fe0e623fe3075b338ce202d6fab2f045b41849a94790a285097",
        "A trusted in-process test seam must route the package worker invocation through the injected subprocess.run object; production launches use the owned-process primitive instead.",
        source_ast_sha256="sha256:c81bf8df7e3f025abe9ab9ed07ce6ed5a539f896ef02924e11dc5cd8e4e0312e",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "test-seam-only-when-run-replaced"),
    ),
    _frozen("src/verifier/runtime/policy_enforcement_execution.py", None,
        "<module>.<locals>._repository_state", "subprocess.run", 1, 1268,
        "sha256:f868d74e9c353b8a2c4b469cc0b79b72d2ab9d2439e97646890954be93a80e92",
        "sha256:df3ba2fd5458b809360ab6fb5fc09afc12b12b8ef33dc6caacb12bfdb77aefad",
        "Read-only git status for one bound file must report its dirty or clean state beside its bytes without blessing the file.",
        source_ast_sha256="sha256:a7652b7c001045066923e4fbcdc401db04bd481473ef729efe04f1dd5ad1c4ef",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment", "repository-configured-helpers"),
    ),
    _frozen("src/verifier/runtime/policy_enforcement_routes.py", None,
        "<module>.<locals>.evaluate_routes", "subprocess.run", 1, 683,
        "sha256:5069898d7814d811c41c5938513a3bf88843ce488358bb68cd5fb5f2c911d8af",
        "sha256:06acd7482b62d503200e8b2221126234919a0d4a9d766a20f5ec1ffba8e14659",
        "The isolated route oracle must run once in a fresh no-site interpreter so route observations come from the worker and are checked against the echoed nonce and source pins.",
        source_ast_sha256="sha256:d29b93fbe00e13a23af6a3d570529e2a1504c7b4b051640fd5cd9dbef41e31b9",
        unobserved_gaps=("reachability", "resolved-arguments", "runtime-outcome", "child-effects", "descendants", "sandboxing", "process-apis-outside-vocabulary", "inherited-environment", "undeclared-filesystem"),
    ),
    _frozen("src/verifier/runtime/polish_requirements.py", None,
        "<module>.<locals>._git", "subprocess.run", 1, 164,
        "sha256:9db0cdd5c87ac777fc8e5ef97f52820c345eee57f36c64995f381732421001cb",
        "sha256:3d033cef4f408b37ccbe9085804e4fe31f918ededb5488097f987ee9c0fdcc87",
        "Polish requirement evidence queries Git so repository state is explicit rather than inferred.",
        source_ast_sha256="sha256:102e7c619cb5959b289f47be6d48bd09f1564642ec8378bbf3a1a03de3e65ba8",
    ),
    _frozen("src/verifier/runtime/prdel.py", None,
        "<module>.<locals>._git", "subprocess.run", 1, 153,
        "sha256:3cbee89fc9fa6c7372b7a90bfa98b90b2717e4436ec87e82cd27faa937efdd0b",
        "sha256:796e6e983c2502fd1f2a918b8b54dcea185fe04084a689598c584cb389534404",
        "PRDEL metadata queries Git so its source coordinate is captured from the selected repository.",
        source_ast_sha256="sha256:d038cda8c61e47cff07428281543349638c416f5d9bc50683a4d1b65d54b5a88",
    ),
    _frozen("src/verifier/runtime/prdel_evidence.py", None,
        "<module>.<locals>._run_check", "subprocess.Popen", 1, 389,
        "sha256:c777c20300db63c849bb68d2a00b7ee61057c41f01167208b5718dba05631e23",
        "sha256:6572298ae2a9765b625d1679211bc0dc4d2dd22f332b9fd963a0e28d19b99c36",
        "PRDEL evidence requires the selected replay checks to run with bounded streamed output.",
        source_ast_sha256="sha256:039a9195872d39915a4a94f564435906082a685b37c6a36e5997fab75aa58238",
    ),
    _frozen("src/verifier/runtime/secret_gate.py", None,
        "<module>.<locals>._process", "subprocess.Popen", 1, 158,
        "sha256:e797d5d9d74f809a75f75a7c5dcbfa662220e8235ed9a82dba45d7605ffb6aac",
        "sha256:89085ee5e6c928276b54d46e4c0f10c6c138c491d4223664832a3539fb7fcdc7",
        "Secret scanning requires the selected scanner process to receive content and return bounded output.",
        source_ast_sha256="sha256:702344ee261072f8d99e0ec4acf8f44374b9e37c9d99e2bdc1e4acb0f35152b5",
    ),
    _frozen("src/verifier/runtime/self_polish_estate.py", None,
        "<module>.<locals>._run_git", "subprocess.run", 1, 238,
        "sha256:f684845a2b9ceada66152c1a7f21f2dfe86caa68bd99c2c38f883f4dfef1bea8",
        "sha256:a7370679af120583456c4198c8f60dd07eef4e184a73ff675f446e1f9b85f4d4",
        "Self-polish estate inventory queries Git to bind repository state and retained source changes.",
        source_ast_sha256="sha256:acf69289621f0a60ab3e02d754b3f0add5be6153c18ff970e824c66272833e61",
    ),
    _frozen("src/verifier/runtime/self_polish_evidence.py", None,
        "<module>.<locals>._run_pytest", "subprocess.run", 1, 467,
        "sha256:492e32066ffcbcbe8d73d5e4743c6b7be31380dd9595abb2ae483d1cc8f64ef3",
        "sha256:945936464576c96e1cf9ac0442419cfb70e9fbe7f4a0778c667d959039703fc3",
        "Selected self-polish tests must run to produce fresh bounded test evidence.",
        source_ast_sha256="sha256:e95f6775c20fa6a1ab1649a8e36efa7cb809d8f62213c5b56d2348af680a04fa",
    ),
    _frozen("src/verifier/runtime/tier_zero.py", None,
        "<module>.<locals>._node_structural_reconciliation", "subprocess.run", 1, 342,
        "sha256:9f507c509df6e3070a678de3483d29dd034010f79a0217c19be5b00898a4243d",
        "sha256:107329286e428cc7af69aaf409b103ae6b4179e714649552c083cad67e915790",
        "Tier-zero structural reconciliation requires the independent Node implementation.",
        source_ast_sha256="sha256:fe2734b9e67bb75adb9ebcecfc146e4a2da57cb3d6cedfc180f3fe3347b77cf0",
    ),
    _frozen("src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py", None,
        "<module>.<locals>._git_python_files", "subprocess.run", 1, 33,
        "sha256:99888cd44970250e5882e0ae6c7a1815d4ef7f89e727199493d2c212e4007742",
        "sha256:1711fa7baf1277551bf452c4259f55e9f36a6e373d902334abd0156d489dbacb",
        "Conditional-dispatch analysis queries Git for the exact tracked-plus-unignored Python source denominator before its conservative fallback scan.",
        source_ast_sha256="sha256:cf2394824eeb5c2bb0139df95b50a42db28fba7f4f1549ca62827c4295ba51fb",
        unobserved_gaps=(*DEFAULT_UNOBSERVED, "inherited-environment", "repository-configured-helpers", "fallback-path-set"),
    ),
    _frozen("src/verifier/runtime/tier_zero_reasoning/integration.py", None,
        "<module>.<locals>._git", "subprocess.run", 1, 227,
        "sha256:0ee986f94a3b63fa5ed482f4cb30ed8c86942b50a4a398141fd48104d383f9d7",
        "sha256:d3147cecf7b4a07e14e43f513fe4988847a4e6f2caebbbeb4a370b32f85d55b9",
        "Tier-zero reason integration queries Git to bind the selected source files, revision, branch, and dirty-state coordinate.",
        source_ast_sha256="sha256:df8183fd45448ff3aae49524ebfcd627da5513f0bc2043482da336e0831344a9",
        unobserved_gaps=(*DEFAULT_UNOBSERVED, "inherited-environment", "repository-configured-helpers", "caller-supplied-git-arguments"),
    ),
    _frozen("src/verifier/runtime/tier_zero_reasoning/integration.py", None,
        "<module>.<locals>._step", "subprocess.run", 1, 271,
        "sha256:0ee986f94a3b63fa5ed482f4cb30ed8c86942b50a4a398141fd48104d383f9d7",
        "sha256:c0b31aa96aff4705130f2cfb252b4e70bfd27728f85f8cbd2e7f2ff19473be60",
        "Tier-zero reason integration must execute each selected checker step with its explicit root, environment, output capture, and timeout.",
        source_ast_sha256="sha256:df8183fd45448ff3aae49524ebfcd627da5513f0bc2043482da336e0831344a9",
        unobserved_gaps=(*DEFAULT_UNOBSERVED, "caller-supplied-argv", "caller-supplied-environment", "timeout-descendant-cleanup", "written-log-durability"),
    ),
    _frozen("src/verifier/runtime/tier_zero_reasoning/reasons_check.py", None,
        "<module>.<locals>.coordinate.<locals>.git", "subprocess.run", 1, 2730,
        "sha256:197c54a6749f8c35d9ebe0cf3a43f7947a783ff666f85ed1d854742985156d23",
        "sha256:5ed7b948da41867f435ff7d6c8ddbd1284b2f39340d7dee08179f5891f4d1e75",
        "Reason checking queries Git so every result receipt is bound to the checked tree revision and dirty-state digest.",
        source_ast_sha256="sha256:048a8f6d3d858c9aa6ee2a66c2d1565c2b7e0add5ac40dad91090ab66300d9cd",
        unobserved_gaps=(*DEFAULT_UNOBSERVED, "inherited-environment", "repository-configured-helpers"),
    ),
    _frozen("src/verifier/runtime/tier_zero_reasoning/witness_runner.py", None,
        "<module>.<locals>.run_one", "subprocess.run", 1, 118,
        "sha256:65d0349a7df7bce88596f2f0e71ac43047dcc2274632acb19e86f407990450e5",
        "sha256:fd53f6725ec03faf5f7eea22088195baa05a26fe68f7ac6758524ac764b31413",
        "The witness runner starts the fixed receipt-producing Python child for one selected witness specification before evaluating its observed outcome.",
        source_ast_sha256="sha256:e55a9641e98bd624609c7b558614410da96707054dfbe0ff3beee9bde8edc7b6",
        unobserved_gaps=(*DEFAULT_UNOBSERVED, "caller-supplied-witness-spec", "inherited-environment", "no-wall-time-timeout", "temporary-artifact-cleanup"),
    ),
    _frozen("src/verifier/runtime/worker_protocol_worker.py", None,
        "<module>.<locals>.observe.<locals>.capture", "subprocess.run", 1, 98,
        "sha256:48a143de2b0839d58f6a0c6841dd09af389f7bbbcc521d45f2708398d481e659",
        "sha256:5303f8e6361bad7d97ac89d02d7b1bb866e22e76306b5b934d497b6128aedd0a",
        "The worker-protocol control must invoke the original launch function while capturing its arguments.",
        source_ast_sha256="sha256:8f2a55b7851eb0353e59cc16009e92da21afb00f5827a47baa04f4b6c02db5d8",
    ),
)
