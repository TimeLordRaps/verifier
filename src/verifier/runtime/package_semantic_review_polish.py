"""Current-source Tier-0 reviews for eighteen polish and PRDEL objects.

Terminology: abstract syntax tree (AST); directed acyclic graph (DAG);
hash-based message authentication code (HMAC); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format,
8-bit (UTF-8).

These reviews answer a repository-admission question for the exact twenty-three
owned runtime sources below: which of the twelve consequential object kinds
apply, why, and what each applicable Tier-0 declaration means for those bytes.
They do not execute a gate, authenticate an authority, establish explanation
truth, authorize release, or promote a package to any polish tier.

Application is pure, atomic, and fail closed.  Every source is checked against
the caller's digest census before and after semantic preflight.  Compatible
complete reviews are preserved; stale, partial, contradictory, mislabeled, or
unowned bindings abort the complete eighteen-object operation.

Only four DOES_NOT_APPLY kinds are admitted, ROBOT, FINBOT, LEDGER and TRANSACTION,
and each must be backed by an exact AST census of the owned bytes: a refutation
holds only while the owned sources contain none of its named channel classes and
their import surface is closed.  Every other non-applicable role is UNRESOLVED,
because a source that merely lacks a role does not refute it.  APPLIES requires an audited source anchor, except where the
registry fixes the kind as the owner's primary kind; that case is an open blocker.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.runtime import package_semantic_review_operations as _shared
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


REVIEW_KINDS = _shared.REVIEW_KINDS

POLISH_OBJECT_IDS = (
    "vstd-tier-progression-controller",
    "vstd-application-release-controller",
    "vstd-package-polish-controller",
    "vstd-package-self-polish-controller",
    "vstd-package-self-polish-rechecker",
    "vstd-polish-assessment-engine",
    "vstd-polish-command-controller",
    "vstd-polish-capacity-policy",
    "vstd-polish-findings-projection",
    "vstd-polish-inventory-policy",
    "vstd-polish-inventory-authority",
    "vstd-polish-public-authority",
    "vstd-prdel-coverage-policy",
    "vstd-prdel-impact-graph",
    "vstd-prdel-source-compiler",
    "vstd-prdel-shard-protocol",
    "vstd-prdel-v2-shard-protocol",
    "vstd-public-checkability-protocol",
)

CLAIM_BOUNDARY = (
    "Current-source Tier-0 applicability and declaration review for these "
    "eighteen path-owned objects only. It establishes neither mechanism "
    "execution nor declaration truth, complete application coverage, polish "
    "promotion, human or legal authority, publication, release, physical "
    "confinement, real-money effects, or Tier-1-plus conformance."
)


@dataclass(frozen=True)
class _Review:
    primary_kind: str
    owned_paths: tuple[str, ...]
    applicable: tuple[str, ...]
    role_paths: Mapping[str, tuple[str, ...]]
    profile: _shared._Profile
    refuted: tuple[str, ...]
    anchors: Mapping[str, str]
    blocked: tuple[str, ...]


def _unresolved_reason(kind: str) -> str:
    return (
        "Migration retains this applicability question. Static ownership "
        "alone cannot refute a " + kind + " role."
    )


def _basis(review: _Review, kind: str) -> str:
    if kind in review.applicable:
        return "APPLIES"
    if kind in review.refuted:
        return "DOES_NOT_APPLY"
    return "UNRESOLVED"


# Capability census vocabulary.  NET, PROC, DEV and WRITE name the channel
# classes a refutation must exclude.  A refutation needs both an exact channel
# census and a closed surface: every import is a pure standard-library module
# or a censused effect module whose calls are classified here, and the owned
# bytes contain no reflection, callback, dynamic dispatch, or verifier-internal
# import.  Anything the scan cannot resolve keeps the surface open.
REFUTABLE_CHANNELS: dict[str, tuple[str, ...]] = {
    "ROBOT": ("NET", "PROC", "DEV", "WRITE"),
    "FINBOT": ("NET", "PROC"),
    "LEDGER": ("WRITE",),
    "TRANSACTION": ("NET", "PROC", "DEV", "WRITE"),
}
_CHANNEL_CLASSES = ("NET", "PROC", "DEV", "WRITE")
_CHANNEL_MODULES = {
    "NET": frozenset({
        "aiohttp", "ftplib", "http", "httpx", "requests", "smtplib", "socket",
        "socketserver", "ssl", "telnetlib", "urllib", "urllib3", "websocket",
        "xmlrpc",
    }),
    "PROC": frozenset({"multiprocessing", "pexpect", "pty", "subprocess"}),
    "DEV": frozenset({
        "ctypes", "fcntl", "gpiozero", "mmap", "msvcrt", "RPi", "serial",
        "smbus", "termios", "usb", "winreg",
    }),
    "WRITE": frozenset({"dbm", "shelve", "sqlite3", "tempfile"}),
}
# Modules whose calls and references are classified call by call.  Importing them
# adds no channel by itself; every other non-pure import leaves the surface open.
_CENSUSED_MODULES = frozenset({"builtins", "io", "os", "pathlib"})
_PURE_MODULES = frozenset({
    "__future__", "abc", "ast", "base64", "binascii", "collections", "copy",
    "dataclasses", "datetime", "decimal", "enum", "fractions", "functools",
    "hashlib", "itertools", "json", "math", "operator", "re", "stat", "string",
    "struct", "typing", "unicodedata", "zlib",
})
_NETWORK_CALLS = frozenset({
    "create_connection", "create_datagram_endpoint", "open_connection",
    "open_unix_connection", "start_server", "start_unix_server",
})
_PROCESS_CALLS = frozenset({
    "fork", "kill", "popen", "posix_spawn", "posix_spawnp", "system",
})
_OS_WRITE_CALLS = frozenset({
    "chmod", "chown", "dup2", "fchmod", "fchown", "fdopen", "ftruncate", "lchown",
    "link", "makedirs", "mkdir", "mkfifo", "mknod", "open", "pwrite", "remove",
    "removedirs", "rename", "renames", "replace", "rmdir", "symlink", "truncate",
    "unlink", "utime", "write", "writev",
})
_SHUTIL_WRITE_CALLS = frozenset({
    "chown", "copy", "copy2", "copyfile", "copytree", "move", "rmtree",
})
_PATH_WRITE_CALLS = frozenset({
    "chmod", "hardlink_to", "mkdir", "rename", "rmdir", "symlink_to", "touch",
    "unlink", "write_bytes", "write_text",
})
# Case-insensitive device namespaces and Windows reserved device names.  A string
# or bytes literal naming one reaches a device whatever call later uses it.
_DEVICE_LITERALS = ("/dev/", "\\\\.\\", "//./")
_DEVICE_NAME = re.compile(
    r"(?:com[0-9]+|lpt[0-9]+|con|prn|aux|nul)(?:\.[a-z0-9]+)?", re.IGNORECASE
)
_DYNAMIC_IMPORTS = frozenset({"__import__", "import_module"})
# Callees that may call an argument they receive, whatever module they come from.
_INVOKING_NAMES = frozenset({
    "accumulate", "classmethod", "cmp_to_key", "defaultdict", "dropwhile",
    "filter", "filterfalse", "groupby", "iter", "map", "partial", "property",
    "reduce", "sort", "staticmethod", "starmap", "sub", "subn", "takewhile",
})
# Keywords whose value a callee may call, such as sorted(key=) or json object_hook.
_CALLBACK_KEYWORDS = frozenset({
    "default", "default_factory", "key", "object_hook", "object_pairs_hook",
    "parse_constant", "parse_float", "parse_int", "repl",
})
_KNOWN_MODULES = _PURE_MODULES | _CENSUSED_MODULES
# Stand-in call for classifying a callable that is referenced but not called.
_BARE_CALL = ast.Call(func=ast.Name(id="_", ctx=ast.Load()), args=[], keywords=[])
_REFLECTION_NAMES = frozenset({
    "__import__", "breakpoint", "compile", "delattr", "eval", "exec", "getattr",
    "globals", "locals", "setattr", "vars",
})
_REFLECTION_ATTRS = frozenset({
    "__builtins__", "__class__", "__code__", "__dict__", "__globals__",
    "__subclasses__", "f_back", "f_globals", "f_locals",
})
_CALLBACK_CARRIERS = frozenset({"filter", "map", "partial"})
# Receiver methods that only read or transform data.  Path-writing names are
# deliberately absent, so a parameter-held path cannot hide a write.
_DATA_METHODS = frozenset({
    "add", "append", "appendleft", "as_posix", "bit_length", "clear", "copy",
    "count", "date", "decode", "difference", "digest", "discard",
    "elements", "encode", "endswith", "exists", "extend", "find", "findall",
    "finditer", "format", "from_bytes", "fullmatch", "get", "group", "groups",
    "hexdigest", "index", "insert", "intersection", "is_dir", "is_file",
    "is_relative_to", "isalnum", "isalpha", "isdigit", "isidentifier",
    "isoformat", "issubset", "issuperset", "items", "join", "keys", "ljust",
    "lower", "lstrip", "match", "most_common", "pop", "popitem", "popleft",
    "read_bytes", "read_text", "relative_to", "removeprefix", "removesuffix",
    "resolve", "rjust", "rsplit", "rstrip", "search", "setdefault", "sort",
    "span", "split", "splitlines", "startswith", "strip", "sub", "timestamp",
    "to_bytes", "total", "union", "update", "upper", "values", "with_name",
    "with_suffix", "zfill", "partition", "rpartition", "casefold", "title",
    "capitalize", "center", "expandtabs", "isspace", "islower", "isupper",
    "isdecimal", "isnumeric", "isprintable", "isascii", "swapcase", "translate",
    "rfind", "rindex", "format_map",
})
_SAFE_BUILTINS = frozenset({
    "abs", "all", "any", "bool", "bytearray", "bytes", "callable", "chr",
    "classmethod", "dict", "divmod", "enumerate", "float", "format", "frozenset",
    "hasattr", "hash", "id", "int", "isinstance", "issubclass", "iter", "len",
    "list", "max", "min", "next", "object", "oct", "ord", "pow", "property",
    "range", "repr", "reversed", "round", "set", "slice", "sorted",
    "staticmethod", "str", "sum", "super", "tuple", "type", "zip",
})


def _read_bytes(root: Path, path: str) -> bytes:
    """Read one exact in-root ordinary source without following an escape."""
    candidate = root.joinpath(*path.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(root)
            or not resolved.is_file()
        ):
            raise OSError("owned source is not an in-root ordinary file")
        return resolved.read_bytes()
    except OSError as exc:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:" + path) from exc


def _module_channels(name: str) -> tuple[str, ...]:
    module_root = name.split(".")[0]
    return tuple(
        channel for channel, modules in _CHANNEL_MODULES.items()
        if module_root in modules
    )


def _open_channel(node: ast.Call, mode_index: int) -> str | None:
    """Classify an open-style call whose mode is positional or keyword."""
    mode = node.args[mode_index] if len(node.args) > mode_index else None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None:
        return None
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return "WRITE" if any(flag in mode.value for flag in "wax+") else None
    return "WRITE"


def _call_channel(node: ast.Call, module: str | None, attr: str) -> str | None:
    """Classify one call given the module it resolves to, if any."""
    top = module.split(".")[0] if module else ""
    if top == "os":
        if attr in _PROCESS_CALLS or attr == "startfile" or attr.startswith(
            ("exec", "spawn", "posix_spawn")
        ):
            return "PROC"
        return "WRITE" if attr in _OS_WRITE_CALLS else None
    if top == "shutil":
        return "WRITE" if attr in _SHUTIL_WRITE_CALLS else None
    if top in {"builtins", "io"} and attr in {"FileIO", "open"}:
        return _open_channel(node, 1)
    if attr.startswith("create_subprocess"):
        return "PROC"
    if attr in _NETWORK_CALLS:
        return "NET"
    if module is None and attr == "open":
        # Path.open(mode) on an owner the scan cannot resolve.
        return _open_channel(node, 0)
    if attr in _PATH_WRITE_CALLS:
        return "WRITE"
    return None


def _reference_channel(module: str | None, attr: str) -> str | None:
    """Classify a callable taken as a value.  Its later call can run unseen.

    An open-style builtin referenced without a call may be called with a write
    mode, so it is conservatively WRITE.  Otherwise the call classification
    applies to a bare call with no arguments.
    """
    top = module.split(".")[0] if module else ""
    if attr in {"open", "FileIO"} and top in {"", "builtins", "io"}:
        return "WRITE"
    if top == "os" and attr == "devnull":
        return "DEV"
    return _call_channel(_BARE_CALL, module, attr)


def _device_literal(text: str) -> bool:
    lowered = text.lower()
    return (
        lowered.rstrip("/") == "/dev"
        or any(literal in lowered for literal in _DEVICE_LITERALS)
        or _DEVICE_NAME.fullmatch(text.strip()) is not None
    )


class _Scan(ast.NodeVisitor):
    """One pass over an owned module: channels, imports, and dynamic surface."""

    def __init__(
        self,
        path: str,
        defined: set[str],
        class_methods: dict[str, frozenset[str]],
    ) -> None:
        self.path = path
        self.class_methods = class_methods
        self.channels: set[str] = set()
        self.findings: set[str] = set()
        self.modules: dict[str, str] = {}
        self.names: dict[str, tuple[str, str]] = {}
        self.local_defs = frozenset(defined)
        self.defined = set(defined) | set(_SAFE_BUILTINS) | {"getattr", "open"}
        self.params: list[dict[str, frozenset[str] | None]] = []
        self.callees: set[int] = set()
        # Names that are the value of an attribute access, never a bare value.
        self.bases: set[int] = set()

    def _hit(self, channel: str | None) -> None:
        if channel is not None:
            self.channels.add(channel)

    def _import(self, module: str) -> None:
        for channel in _module_channels(module):
            self.channels.add(channel)
        top = module.split(".")[0]
        if top not in _PURE_MODULES and top not in _CENSUSED_MODULES:
            self.findings.add("IMPORT:" + module)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            self.modules[alias.asname or top] = alias.name if alias.asname else top
            self._import(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level:
            self.findings.add("RELATIVE_IMPORT:" + (module or "."))
        else:
            self._import(module)
        for alias in node.names:
            if alias.name == "*":
                self.findings.add("STAR_IMPORT:" + module)
                continue
            bound = alias.asname or alias.name
            self.defined.add(bound)
            if not node.level:
                self.names[bound] = (module, alias.name)

    def _function(self, node: ast.AST) -> None:
        args = node.args  # type: ignore[attr-defined]
        frame: dict[str, frozenset[str] | None] = {}
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if arg is None or arg.arg in {"self", "cls"}:
                continue
            annotation = arg.annotation
            typed = annotation.id if isinstance(annotation, ast.Name) else None
            # A parameter annotated with a class defined in this file has its
            # methods resolved statically; every other receiver stays open.
            frame[arg.arg] = self.class_methods.get(typed) if typed else None
        self.params.append(frame)
        self.generic_visit(node)
        self.params.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def _is_param(self, name: str) -> bool:
        return any(name in frame for frame in self.params)

    def _param_methods(self, name: str) -> frozenset[str] | None:
        for frame in reversed(self.params):
            if name in frame:
                return frame[name]
        return None

    def visit_Name(self, node: ast.Name) -> None:
        # getattr in call position with a literal attribute name is an ordinary
        # attribute read; its calls are judged in _name_call instead.  Passed as a
        # value it can reflect any attribute, so it stays open.
        if node.id in _REFLECTION_NAMES and node.id != "getattr":
            self.findings.add("REFLECTION:" + node.id)
        elif node.id == "getattr" and id(node) not in self.callees:
            self.findings.add("REFLECTION:getattr-value")
        if id(node) in self.callees or id(node) in self.bases or self._is_param(node.id):
            return
        # A bare value is a referent that a later call may invoke.  A module object
        # gives its attributes; a from-imported or builtin effect is the effect.
        if node.id in self.modules:
            self.findings.add("MODULE_VALUE:" + node.id)
        elif node.id in self.names:
            self._hit(_reference_channel(*self.names[node.id]))
        elif node.id == "open":
            self._hit(_reference_channel("builtins", "open"))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _REFLECTION_ATTRS:
            self.findings.add("REFLECTION:." + node.attr)
        self.bases.add(id(node.value))
        if id(node) not in self.callees:
            module = (
                self.modules.get(node.value.id)
                if isinstance(node.value, ast.Name)
                else None
            )
            self._hit(_reference_channel(module, node.attr))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        text = node.value
        if isinstance(text, bytes):
            text = text.decode("latin-1")
        if isinstance(text, str) and _device_literal(text):
            self.channels.add("DEV")

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            self.callees.add(id(func))
            self._name_call(node, func.id)
        elif isinstance(func, ast.Attribute):
            self.callees.add(id(func))
            self._attribute_call(node, func)
        else:
            self.findings.add("DYNAMIC_CALLEE")
        self._getattr_reference(node)
        self._callback_arguments(node)
        self._dynamic_import(node)
        self.generic_visit(node)

    def _getattr_reference(self, node: ast.Call) -> None:
        """Classify a literal getattr(owner, name) as a reference to that name."""
        func = node.func
        if not (
            isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2
        ):
            return
        target, attr = node.args[0], node.args[1]
        if (
            isinstance(target, ast.Name)
            and isinstance(attr, ast.Constant)
            and isinstance(attr.value, str)
        ):
            self._hit(_reference_channel(self.modules.get(target.id), attr.value))

    def _callback_arguments(self, node: ast.Call) -> None:
        """Flag a parameter handed to code that may call it as a callable.

        A parameter may hold any callable.  Its callee is data-only when the
        callee is known not to call an argument: a safe builtin, a local function,
        a data method, or a pure or censused module function.  A named invoking
        callee or callback keyword is never data-only, and an unknown callee
        leaves the parameter open.
        """
        func = node.func
        if isinstance(func, ast.Name) and self._is_param(func.id):
            return
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        known = self._known_callee(func, name)
        arguments = [(None, value) for value in node.args]
        arguments += [(keyword.arg, keyword.value) for keyword in node.keywords]
        for keyword, value in arguments:
            if (
                isinstance(value, ast.Name)
                and self._is_param(value.id)
                and (
                    keyword in _CALLBACK_KEYWORDS
                    or name in _INVOKING_NAMES
                    or not known
                )
            ):
                self.findings.add("CALLBACK_ARGUMENT:" + value.id)

    def _known_callee(self, func: ast.expr, name: str | None) -> bool:
        """Whether the callee is known not to call an argument it is passed."""
        if name is None or name in _INVOKING_NAMES:
            return False
        if isinstance(func, ast.Name) and (
            name in self.local_defs or name in _SAFE_BUILTINS or name == "open"
        ):
            return True
        if isinstance(func, ast.Attribute) and name in _DATA_METHODS:
            return True
        module = self._callee_module(func)
        return module is not None and module.split(".")[0] in _KNOWN_MODULES

    def _callee_module(self, func: ast.expr) -> str | None:
        """Return the module a callee resolves to through an import, if any."""
        if isinstance(func, ast.Name):
            return self.names[func.id][0] if func.id in self.names else None
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            if root.id in self.modules:
                return self.modules[root.id]
            if root.id in self.names:
                return self.names[root.id][0]
        return None

    def _name_call(self, node: ast.Call, name: str) -> None:
        literal = len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(
            node.args[1].value, str
        )
        if self._is_param(name):
            self.findings.add("CALLBACK:" + name)
        elif name == "getattr" and not literal:
            self.findings.add("REFLECTION:getattr")
        elif name in _REFLECTION_NAMES and name != "getattr":
            self.findings.add("REFLECTION:" + name)
        elif name in self.names:
            module, attr = self.names[name]
            self._hit(_call_channel(node, module, attr))
        elif name == "open":
            self._hit(_call_channel(node, "builtins", "open"))
        elif name in _CALLBACK_CARRIERS and node.args:
            first = node.args[0]
            if isinstance(first, ast.Name) and self._is_param(first.id):
                self.findings.add("CALLBACK_CARRIER:" + first.id)
        elif name not in self.defined and not name.endswith(
            ("Error", "Exception", "Warning")
        ):
            self.findings.add("UNRESOLVED_CALLEE:" + name)

    def _attribute_call(self, node: ast.Call, func: ast.Attribute) -> None:
        root = func.value
        while isinstance(root, ast.Attribute):
            root = root.value
        attr = func.attr
        if isinstance(root, ast.Name):
            if self._is_param(root.id):
                typed = self._param_methods(root.id) or frozenset()
                if attr not in _DATA_METHODS and attr not in typed:
                    self.findings.add("PARAMETER_METHOD:" + root.id + "." + attr)
            elif root.id == "self" and attr not in self.defined and attr not in _DATA_METHODS:
                self.findings.add("SELF_ATTRIBUTE_CALL:" + attr)
            if root.id in self.modules:
                module = self.modules[root.id]
                self._hit(_call_channel(node, module, attr))
                return
        self._hit(_call_channel(node, None, attr))

    def _dynamic_import(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name not in _DYNAMIC_IMPORTS:
            return
        literal = node.args[0] if node.args else None
        if not (isinstance(literal, ast.Constant) and isinstance(literal.value, str)):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:" + self.path)
        if literal.value.split(".")[0] in _CENSUSED_MODULES:
            # The returned module's calls are not classified at this import site.
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:" + self.path)
        self._import(literal.value)
        for channel in _module_channels(literal.value):
            self.channels.add(channel)


def _scan(path: str, raw: bytes) -> _Scan:
    try:
        tree = ast.parse(raw, filename=path)
    except (SyntaxError, ValueError) as exc:
        raise ValueError(
            "PACKAGE_SEMANTIC_REVIEW_CHANNEL_UNVERIFIABLE:" + path
        ) from exc
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    class_methods = {
        node.name: frozenset(
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }
    scan = _Scan(path, defined, class_methods)
    scan.visit(tree)
    return scan


def channel_census(root: Path, paths: tuple[str, ...]) -> dict[str, bool]:
    """Return which capability channel classes the exact owned bytes contain.

    Aliases, from-imports, open-style writes on any owner, and device literals
    are classified.  Unparsable sources and dynamic imports without a literal
    module name are unverifiable and raise.
    """
    found: dict[str, bool] = {channel: False for channel in _CHANNEL_CLASSES}
    for path in paths:
        for channel in _scan(path, _read_bytes(root, path)).channels:
            found[channel] = True
    return found


def surface_findings(root: Path, paths: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    """Return, per owned path, every reason its import surface is not closed.

    An empty tuple means the path imports only pure or censused modules, every
    censused call is a non-channel, and no reflection, callback, dispatch,
    unresolved callee, or verifier-internal import occurs in its bytes.
    """
    report: dict[str, tuple[str, ...]] = {}
    for path in paths:
        scan = _scan(path, _read_bytes(root, path))
        reasons = set(scan.findings)
        reasons |= {"CHANNEL:" + channel for channel in scan.channels}
        report[path] = tuple(sorted(reasons))
    return report


def refutation_reason(profile: _shared._Profile, kind: str) -> str:
    """State one owned-bytes capability refutation at its exact boundary."""
    if kind not in REFUTABLE_CHANNELS:
        raise AssertionError("unaudited refutation kind " + kind)
    return (
        profile.name
        + " does not apply as "
        + kind
        + ". The exact owned sources "
        + _REFUTATION_BASES[kind]
        + " in their closed AST census, verified at application. They import only "
        "pure standard-library modules and the censused builtins, io, os, and "
        "pathlib modules, and contain no reflection, callback, dynamic dispatch, "
        "or verifier-internal import. Device classification reads literal strings "
        "and os.devnull only, so a runtime-built path is outside this census. "
        "Reviewed boundary: "
        + profile.boundary
    )


_REFUTATION_BASES = {
    "ROBOT": (
        "contain no network, subprocess, device-path literal, or write channel "
        "through which this owner could command a physical endpoint"
    ),
    "FINBOT": (
        "contain no network or subprocess channel through which this owner could "
        "reach a real-money endpoint"
    ),
    "LEDGER": (
        "contain no write channel through which this owner could persist an "
        "authoritative ordered history"
    ),
    "TRANSACTION": (
        "contain no network, subprocess, device-path literal, or write channel "
        "through which this owner could carry a coordinated external commit unit"
    ),
}


def _profile(
    *,
    name: str,
    scope: str,
    mechanism: str,
    inputs: str,
    authority: str,
    states: str,
    ordering: str,
    commands: str,
    targets: str,
    effect_domains: str,
    effects: str,
    commit: str,
    limits: str,
    observations: str,
    failure: str,
    boundary: str,
) -> _shared._Profile:
    """Build explicit software-boundary vocabulary without inventing effects."""
    return _shared._Profile(
        name=name,
        scope=scope,
        mechanism=mechanism,
        participants=(
            "The caller, the exact selected records and source bytes, the bounded "
            + name
            + " mechanism, and the consumer of its returned record."
        ),
        inputs=inputs,
        authority=authority,
        states=states,
        ordering=ordering,
        commands=commands,
        targets=targets,
        effect_domains=effect_domains,
        effects=effects,
        commit=commit,
        retry=(
            "A repeated call is a fresh bounded evaluation or construction over "
            "the newly supplied exact bytes. Digest equality detects byte identity "
            "only; it neither proves idempotent external effects nor reuses truth."
        ),
        timing=(
            "Results are current only for the supplied invocation and source "
            "coordinate. No wall-clock freshness, eventual progress, real-time "
            "response, provider availability, or release deadline is promised."
        ),
        limits=limits,
        observations=observations,
        units=(
            "Exact UTF-8 or binary bytes, SHA-256 identities, finite object, node, "
            "edge, obligation and finding counts, and bounded software operations."
        ),
        failure=failure,
        recovery=(
            "Retain the fail-closed result, inspect the exact selected inputs and "
            "current source, correct the bounded cause, and start a fresh evaluation; "
            "never reinterpret UNKNOWN or a construction receipt as prior success."
        ),
        boundary=boundary,
    )


def _review(
    primary_kind: str,
    paths: tuple[str, ...],
    applicable: tuple[str, ...],
    profile: _shared._Profile,
    role_paths: Mapping[str, tuple[str, ...]] | None = None,
    *,
    refuted: tuple[str, ...],
    anchors: Mapping[str, str] | None = None,
    blocked: tuple[str, ...] = (),
) -> _Review:
    return _Review(
        primary_kind=primary_kind,
        owned_paths=paths,
        applicable=applicable,
        role_paths=(
            {kind: paths for kind in applicable}
            if role_paths is None
            else dict(role_paths)
        ),
        profile=profile,
        refuted=refuted,
        anchors=dict(anchors or {}),
        blocked=blocked,
    )


def _reason(profile: _shared._Profile, kind: str, applies: bool) -> str:
    """Explain necessity or refutation at the exact reviewed boundary."""
    if applies:
        necessity = {
            "TRANSACTION": (
                "Its bounded construction or evaluation has explicit preconditions, "
                "commit, partial-failure, retry, and replay consequences."
            ),
            "MEASUREMENT": (
                "It derives finite observations from selected bytes or execution "
                "returns, which must remain distinct from completeness and truth."
            ),
            "SENSOR": (
                "It actively acquires those digital observations, requiring explicit "
                "source, range, freshness, latency, and fault boundaries."
            ),
            "CONTROLLER": (
                "It sequences checks or construction commands from bounded feedback "
                "and therefore owns stop, arbitration, and intervention semantics."
            ),
            "ACTUATOR": (
                "It invokes a bounded software operation with a named target while "
                "keeping invocation separate from downstream semantic success."
            ),
            "PROTOCOL": (
                "Its ordered records, participants, compatibility and replay rules "
                "form a distinct finite exchange boundary."
            ),
            "POLICY": (
                "Its selection, precedence, exception, default, or admission rules "
                "decide which finite result may be accepted or carried."
            ),
        }[kind]
        basis = {
            "TRANSACTION": profile.effects,
            "MEASUREMENT": profile.observations,
            "SENSOR": profile.mechanism,
            "CONTROLLER": profile.scope,
            "ACTUATOR": profile.commands,
            "PROTOCOL": profile.participants,
            "POLICY": profile.scope,
        }[kind]
        return (
            profile.name
            + " applies as "
            + kind
            + ". "
            + necessity
            + " Exact source-specific basis: "
            + basis
            + " Reviewed boundary: "
            + profile.boundary
        )
    return refutation_reason(profile, kind)


def _applies_reason(review: _Review, kind: str) -> str:
    reason = _reason(review.profile, kind, True)
    if kind in review.blocked:
        return (
            reason
            + " The source audit did not establish this kind; it is retained only "
            "because the registry fixes it as this owner's primary kind, so it "
            "remains an open blocker."
        )
    return reason + " Audited source anchor: " + review.anchors[kind] + "."


def _classification_reason(review: _Review, kind: str) -> str:
    basis = _basis(review, kind)
    if basis == "APPLIES":
        return _applies_reason(review, kind)
    if basis == "DOES_NOT_APPLY":
        return _reason(review.profile, kind, False)
    return _unresolved_reason(kind)


def _evidence_paths(review: _Review, kind: str) -> tuple[str, ...]:
    basis = _basis(review, kind)
    if basis == "APPLIES":
        return review.role_paths[kind]
    if basis == "DOES_NOT_APPLY":
        return review.owned_paths
    return ()


def _obligation_reason(review: _Review, kind: str) -> str:
    return (
        _applies_reason(review, kind)
        + " This Tier-0 declaration names the reviewed boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    )


_TIER_PROGRESSION = _profile(
    name="finite tier progression assessment",
    scope=(
        "Bind a caller-selected nine-core-tier or historical ten-tier rank overlay "
        "to exact graph, policy, artifact and native certificate instances and "
        "derive cumulative PASS, FAIL or UNKNOWN progression."
    ),
    mechanism=(
        "Strict bounded JSON parsing, digest and source binding, DAG checks, installed-"
        "route inventory, native assessment replay and cumulative status derivation."
    ),
    inputs=(
        "Exact selection, bundle, policy, artifact bytes, native certificate instances, "
        "external selection/mechanism pins, cancellation state and bounded reports."
    ),
    authority=(
        "The caller selects the overlay and external pins. A selected or passing "
        "overlay does not authenticate applicability, inventory authority, release, "
        "publication, model correctness or whole-application completeness."
    ),
    states=(
        "Unselected, bound, checking, cancelled, exhausted, PASS, FAIL and UNKNOWN "
        "states for each selected tier and its cumulative prefix."
    ),
    ordering=(
        "Schema and digest checks precede graph binding and native replay; tier results "
        "are evaluated in rank order and a lower FAIL or UNKNOWN constrains successors."
    ),
    commands=(
        "Parse and bind the selected graph, invoke exact native assessment functions, "
        "and derive the cumulative progression report."
    ),
    targets="In-memory selected records, native mechanism functions and returned report.",
    effect_domains="TRUSTED_IN_PROCESS_ASSESSMENT_ONLY",
    effects=(
        "Invoke bounded assessment code and return a progression report; no release, "
        "publication, signing, physical or financial effect is represented."
    ),
    commit=(
        "Commit is return of one internally consistent report for the selected finite "
        "overlay; it is not whole-tier or full-application conformance."
    ),
    limits=(
        "Declared byte, node, edge, report and tier bounds fail closed; absent external "
        "pins, missing applicability or incomplete census remains UNKNOWN."
    ),
    observations=(
        "The mechanism observes supplied digests, graph relationships, installed route "
        "inventory and returned native statuses, not external correctness or authority."
    ),
    failure=(
        "Contradiction yields FAIL; cancellation, exhaustion, unavailable bytes, absent "
        "pins or incomplete applicability remains UNKNOWN without promotion."
    ),
    boundary=(
        "A finite progression overlay never authorizes release or proves whole-tier, "
        "complete-application, safety, explanation, publication or real-world truth."
    ),
)


_APPLICATION_RELEASE = _profile(
    name="finite application release assessment",
    scope=(
        "Bind an exact declared application membership and source archive to selected "
        "native instances and independently replay the finite release prerequisites."
    ),
    mechanism=(
        "Strict bounded JSON and archive screening, exact digest/member/context binding, "
        "typed composition checks, selected native replay and full-gate status reduction."
    ),
    inputs=(
        "Exact selection, membership, source manifest/archive, operations, contexts, "
        "artifact files, native shards, requirements and independently selected pins."
    ),
    authority=(
        "The caller selects exact records and configured gate instances. Neither a "
        "selected signer nor a finite PASS grants human, legal or release authority."
    ),
    states=(
        "Unbound, screened, bound, replaying, cancelled, unavailable, PASS, FAIL and "
        "UNKNOWN states with release_authorized remaining false absent separate authority."
    ),
    ordering=(
        "Archive/member/context binding precedes native replay; disjoint selected gate "
        "instances are checked before a full finite status is reduced."
    ),
    commands=(
        "Parse archives and records, invoke selected native gate assessments, and return "
        "the bounded application release-consumer report."
    ),
    targets="In-memory archive bytes, selected native mechanisms and returned report.",
    effect_domains="TRUSTED_IN_PROCESS_RELEASE_ASSESSMENT_ONLY",
    effects=(
        "Read supplied bytes, replay selected assessment functions and construct a report; "
        "the mechanism does not publish, deploy, sign, release or transfer value."
    ),
    commit=(
        "Commit is return of the exact finite assessment. Even PASS records finite binding "
        "only and never changes release_authorized without separate authority."
    ),
    limits=(
        "File, source, shard, instance and byte ceilings fail closed; mandatory unavailable "
        "gates, applicability gaps and unpinned selections remain UNKNOWN."
    ),
    observations=(
        "It observes supplied archive/member bytes, hashes and selected native returns, "
        "not independent deployment, public availability or application correctness."
    ),
    failure=(
        "Contradiction yields FAIL; missing mandatory material, unselected authority, "
        "cancelled replay or unavailable mechanisms remains UNKNOWN and blocks release."
    ),
    boundary=(
        "A finite selected PASS never authorizes release or proves a whole application, "
        "normative completeness, deployment, safety, publication or real-world effect."
    ),
)


def _polish_controller_profile(
    name: str, specific: str, boundary: str
) -> _shared._Profile:
    return _profile(
        name=name,
        scope=specific,
        mechanism=(
            "Strict manifest and graph screening, exact source and digest binding, bounded "
            "applicability reduction, declared VERIFIER invocation and fail-closed reporting."
        ),
        inputs=(
            "Current objects.vstd graph bytes, exact source digests, selected object and "
            "obligation records, verifier routes, retained evidence and explicit limits."
        ),
        authority=(
            "The root declaration and caller select the finite subject; neither selection "
            "nor an internal report supplies owner, human, legal, release or publication authority."
        ),
        states=(
            "Unadmitted, admitted, selected, checking, cancelled, PASS, FAIL and UNKNOWN "
            "states at gate, object, obligation and whole-report coordinates."
        ),
        ordering=(
            "Admission and exact binding precede applicability and declared route execution; "
            "failures and unknowns propagate without skipping required lower-tier dependencies."
        ),
        commands=(
            "Invoke the exact selected in-process or bounded child VERIFIER routes and "
            "construct their package graph assessment records."
        ),
        targets="Selected verifier mechanisms, bounded child processes and returned records.",
        effect_domains="BOUNDED_VERIFIER_INVOCATION_AND_REPORTING_ONLY",
        effects=(
            "Run selected verification mechanisms and construct reports; no result itself "
            "publishes, releases, deploys, controls hardware or transfers money."
        ),
        commit=(
            "Commit is only a returned source-bound report at its exact graph coordinate; "
            "individual PASS does not atomically commit a package-wide promotion."
        ),
        limits=(
            "Declared graph, byte, route, output and operation limits fail closed; missing "
            "applicability, evidence, route or source binding remains UNKNOWN."
        ),
        observations=(
            "It observes current manifest/source bindings and bounded verifier returns, not "
            "unrepresented external state, hidden routes, semantic truth or effect confinement."
        ),
        failure=(
            "Explicit contradiction is FAIL; missing or inapplicable-unresolved material, "
            "unavailable mechanisms, cancellation or uncertain child effects remains UNKNOWN."
        ),
        boundary=boundary,
    )


_PACKAGE_POLISH = _polish_controller_profile(
    "package graph polish controller",
    "Assess the manifest-declared package GRAPH through its exact object obligations and declared VERIFIER routes.",
    "A report covers only admitted current graph bytes and executed routes; it does not prove hidden-source completeness, release authority or external safety.",
)
_PACKAGE_SELF_POLISH = _polish_controller_profile(
    "recursive package self-polish controller",
    "Represent the package as one finite typed GRAPH and evaluate its numeric meta-tier obligations through the graph's VERIFIER records.",
    "Recursive self-application remains bounded to selected current bytes; it does not bootstrap truth, authority, confinement or Tier-1-plus conformance.",
)
_PACKAGE_RECHECK = _polish_controller_profile(
    "independent package self-polish rechecker",
    "Reconstruct typed graph and cross-section invariants from retained report bytes without importing the report producer.",
    "Rechecker PASS means internal retained-report consistency only and never promotes the producer verdict or proves execution chronology.",
)

_POLISH_ASSESSMENT = _profile(
    name="bounded polish assessment engine",
    scope=(
        "Catalog installed routes, bind one exact bundle/request pair, assess its "
        "declared object composition and registered objectives, or independently "
        "recheck one retained assessment against the same exact inputs."
    ),
    mechanism=(
        "Strict bounded JSON parsing, canonical digest binding, typed composition, "
        "registered current-object route selection and deterministic objective replay."
    ),
    inputs=(
        "Exact bundle, request or retained assessment bytes, contract version, "
        "registered routes, selected object coordinates and explicit capacities."
    ),
    authority=(
        "The caller selects exact input bytes and version. Installed route registration "
        "authorizes only bounded invocation; it supplies no external or release authority."
    ),
    states=(
        "Unparsed, admitted, composition-checked, replaying, reproduced, rejected, "
        "PASS, FAIL and UNKNOWN states, with polished fixed false."
    ),
    ordering=(
        "Byte and schema admission precede object composition and route selection; "
        "registered objective replay precedes status reduction and assessment digesting."
    ),
    commands=(
        "Select and invoke the exact registered in-process current-object replay route "
        "for each admitted objective, then construct or compare the bounded assessment."
    ),
    targets=(
        "Caller-supplied in-memory records, installed registered replay functions and "
        "the returned catalog, assessment or recheck record."
    ),
    effect_domains="REGISTERED_IN_PROCESS_OBJECTIVE_REPLAY_ONLY",
    effects=(
        "Invoke bounded registered assessment functions and derive a result record; "
        "no publication, release, deployment, physical or financial effect is represented."
    ),
    commit=(
        "Commit is return of one canonical source-bound record or exact reproduction; "
        "polished remains false and no package-wide promotion is committed."
    ),
    limits=(
        "Bundle, request, output, object, objective and registered-route bounds fail "
        "closed; unavailable inputs or routes cannot become PASS."
    ),
    observations=(
        "It observes admitted input structure, declared composition, route returns and "
        "canonical correspondence, not hidden execution, completeness or external truth."
    ),
    failure=(
        "Malformed, substituted or contradictory inputs yield FAIL; unavailable selected "
        "inputs yield UNKNOWN, and retained mismatch remains rejected without promotion."
    ),
    boundary=(
        "Polished remains false. Assessment covers only selected bounded bytes and "
        "registered routes; it proves neither inventory completeness, external "
        "authority, polish, release nor effects."
    ),
)

_POLISH_COMMAND = _profile(
    name="polish command controller",
    scope=(
        "Parse one selected polish subcommand, acquire its named local inputs, dispatch "
        "the corresponding bounded mechanism and render the returned status."
    ),
    mechanism=(
        "Argument admission, explicit subcommand routing, bounded regular-file reads, "
        "status-to-exit-code reduction and deterministic text or JSON rendering."
    ),
    inputs=(
        "Parsed command arguments, exact named local files, digest pins, contract version, "
        "format selection and explicit preparation or recheck selectors."
    ),
    authority=(
        "The caller selects the command and files. Routing grants only that bounded local "
        "invocation and never supplies preparation, release or publication authority."
    ),
    states=(
        "Unparsed, selected, reading, dispatched, rendered, refused, PASS, FAIL and "
        "UNKNOWN command states; catalog output remains non-promoting."
    ),
    ordering=(
        "Parser admission and option compatibility precede bounded file acquisition; "
        "dispatch precedes exit-code reduction and result rendering."
    ),
    commands=(
        "Read the named bounded local inputs and invoke exactly one selected assessment, "
        "recheck, report, authority, application or preparation command handler."
    ),
    targets=(
        "Named local input files, the selected installed command handler and standard "
        "output; workflow mutations remain owned by the preparation transaction."
    ),
    effect_domains="LOCAL_COMMAND_DISPATCH_AND_RESULT_RENDERING_ONLY",
    effects=(
        "Acquire selected files, invoke one bounded command handler and emit its result; "
        "downstream handler success and external effects are not inferred from dispatch."
    ),
    commit=(
        "Commit is return of the selected handler exit code after rendering its bounded "
        "record, not transactional package polish or atomic preparation."
    ),
    limits=(
        "Parser choices, file kinds, bytes, output and delegated mechanism limits fail "
        "closed; unavailable files produce bounded UNKNOWN where specified."
    ),
    observations=(
        "It observes selected file bytes and delegated return records at the command "
        "boundary, not hidden mechanism state, filesystem exclusivity or external effects."
    ),
    failure=(
        "Incompatible options or malformed inputs fail; unavailable selected files remain "
        "UNKNOWN, and unknown handler status cannot be promoted by rendering."
    ),
    boundary=(
        "Command dispatch is not a sandbox, mechanism proof, atomic preparation, polish "
        "promotion, release, deployment, physical control or financial authority."
    ),
)


def _policy_profile(
    name: str, scope: str, mechanism: str, boundary: str
) -> _shared._Profile:
    return _profile(
        name=name,
        scope=scope,
        mechanism=mechanism,
        inputs="Exact caller-supplied records, selections, bounds, digests and current source bytes.",
        authority=(
            "The caller selects the records and policy inputs. A selected record or digest "
            "has no independent human, legal, normative, publication or release authority."
        ),
        states="Unselected, selected, admitted, rejected, unavailable, PASS, FAIL and UNKNOWN states.",
        ordering="Strict input and digest screening precedes bounded rule evaluation and report construction.",
        commands="Evaluate deterministic in-process selection, projection and admission rules only.",
        targets="Caller-supplied in-memory records and the returned deterministic projection.",
        effect_domains="PURE_OR_IN_PROCESS_POLICY_EVALUATION_ONLY",
        effects="Construct a finite policy decision or projection without external mutation.",
        commit="Commit is return of the bounded deterministic record; it does not commit external state.",
        limits="Declared byte, count, graph and operation ceilings fail closed; missing applicability remains UNKNOWN.",
        observations="It observes supplied record structure and values, not unrepresented execution or external truth.",
        failure="Malformed or contradictory input is rejected; missing necessary evidence remains UNKNOWN.",
        boundary=boundary,
    )


_CAPACITY = _policy_profile(
    "polish capacity policy",
    "Select and validate explicit version-2 assessment capacity and exact retained native certificate bytes.",
    "Bounded base64 transport, typed composition checks and exact capacity/count validation.",
    "Capacity admits transport size and shape only; it discharges no numbered profile and issues no polished artifact.",
)
_FINDINGS = _policy_profile(
    "polish findings projection",
    "Project stable bounded findings across successive exact report attempts without executing checks or fixes.",
    "Strict report parsing, digest capture, stable identifier matching and carried-status projection.",
    "A projection is an observation of carried reports, not chronology, authenticated execution, evidence truth or a cleared finding.",
)
_INVENTORY = _policy_profile(
    "polish inventory policy",
    "Assess exact finite objective inventory coverage and replay the declared applicability rules.",
    "Typed object binding, deterministic applicability replay, finite plan coverage and bounded status reduction.",
    "Inventory PASS does not establish normative exhaustiveness, authenticated inapplicability, native objective truth or polished admission.",
)
_PRDEL_COVERAGE = _policy_profile(
    "PRDEL coverage policy",
    "Compare selected explanation obligations, retained evidence and preventative relationship notices.",
    "Bounded selected-record matching, digest comparison and deterministic evidence/coverage status reduction.",
    "Coverage status does not authenticate execution, prove source behavior, discharge numbered profiles or send notifications.",
)
_PRDEL_GRAPH = _policy_profile(
    "PRDEL impact graph policy",
    "Index bounded Python AST relationships and preserve cycles as finite component graph relationships.",
    "Pure AST parsing, name/reference indexing, strongly connected component reduction and deterministic graph serialization.",
    "The impact graph executes no candidate source and proves neither runtime effects, complete applicability nor dynamic dispatch.",
)


def _authority_profile(
    name: str, scope: str, mechanism: str, boundary: str
) -> _shared._Profile:
    return _profile(
        name=name,
        scope=scope,
        mechanism=mechanism,
        inputs="Exact finite subject, configured key policy, signed statement, revocation data, time and digest pins.",
        authority=(
            "Authority is relative only to caller-configured cryptographic keys and exact "
            "policy terms; key control does not prove personhood, legal authority, consent, "
            "denominator completeness or source truth."
        ),
        states="Unconfigured, selected, authenticated, revoked, expired, rejected and UNKNOWN states.",
        ordering="Policy and subject binding precede signature/authenticator, revocation and bounded-time checks.",
        commands="Verify the exact configured-key statement and construct its bounded admission result.",
        targets="In-memory policy, subject and evidence records; no external authority service is contacted.",
        effect_domains="CONFIGURED_KEY_AUTHENTICATION_ONLY",
        effects="Authenticate a finite statement relative to configured keys and return a record.",
        commit="Commit is return of configured-key admission for one exact subject, not consumption or external issuance.",
        limits="Strict schema, key, signature, digest, count, timestamp and byte bounds fail closed.",
        observations="It observes configured cryptographic verification and record consistency, not human or legal facts.",
        failure="Invalid statements fail; unavailable required keys, time or applicability remains UNKNOWN without admission.",
        boundary=boundary,
    )


_INVENTORY_AUTHORITY = _authority_profile(
    "polish inventory authority protocol",
    "Admit one exact finite inventory statement relative to independently selected operator roots.",
    "Strict JSON, digest binding and HMAC verification against caller-provisioned symmetric governance keys.",
    "Configured-key admission supplies no human or legal authority and leaves normative completeness, native objective truth, public proof and release authority open.",
)
_PUBLIC_AUTHORITY = _authority_profile(
    "polish public authority protocol",
    "Admit one exact finite polish issuance subject under an experimental public configured-key policy.",
    "Strict JSON and subject binding, Ed25519/HMAC configured-key verification, revocation and bounded timestamp checks.",
    "Configured-key statements do not prove personhood, legal authority, consent, completeness, native truth or atomic invocation consumption.",
)
_PUBLIC_CHECKABILITY = _authority_profile(
    "public checkability protocol",
    "Bind exact public disclosure admission to retained native witnesses and replay supported public-checkability nodes.",
    "Strict request/policy screening, configured-key disclosure checks, exact witness/context binding and retained native replay.",
    "Protocol PASS does not publish bytes, prove public availability, establish overall safety or authorize polished issuance.",
)


_PRDEL_COMPILER = _profile(
    name="PRDEL source compiler",
    scope=(
        "Compile bounded exact-source facts, selected quotations, authored associations, "
        "coverage and residual records for a Pull Request Domain Explanation document."
    ),
    mechanism=(
        "Read selected repository source, parse supported syntax, apply deterministic "
        "authoring rules and validators, and construct a digest-bound compilation."
    ),
    inputs="Selected repository root, base/head, requirements, definitions, evidence, source bytes and bounds.",
    authority=(
        "The caller selects source and authored definitions; compiler output has no developer-"
        "motivation, reviewer, publication, merge or release authority."
    ),
    states="Unselected, reading, compiled, validated, rejected, FAIL, UNKNOWN and PASS states.",
    ordering="Source binding precedes parsing and rule application; validation follows construction.",
    commands="Read exact selected files, parse supported syntax, invoke bounded rules and construct compilation records.",
    targets="Selected repository files and in-memory PRDEL compilation records.",
    effect_domains="LOCAL_SOURCE_ACQUISITION_AND_COMPILATION_ONLY",
    effects="Read selected source and construct authored PRDEL records without executing candidate code.",
    commit="Commit is return of one deterministic compilation, not merge, publication or verification clearance.",
    limits="Path, byte, region, record and operation bounds fail closed; unsupported predicates remain UNKNOWN.",
    observations="It observes exact source syntax and supplied associations, not runtime effects or developer motivation.",
    failure="Malformed source or contradiction fails; unsupported or unavailable semantic evidence remains UNKNOWN.",
    boundary=(
        "Compilation success grants no execution evidence, explanation truth, developer intent, "
        "gate promotion, merge, publication or release authority."
    ),
)


def _shard_profile(name: str, scope: str, boundary: str) -> _shared._Profile:
    return _profile(
        name=name,
        scope=scope,
        mechanism="Strict canonical serialization, bounded partitioning, digest linkage, reconstruction and optional source replay.",
        inputs="Exact logical PRDEL document, manifest, ordered shard bytes, selected digests, bounds and optional replay inputs.",
        authority="The caller selects packet bytes and pins; transport integrity supplies no reviewer, publication, merge or release authority.",
        states="Unpartitioned, partitioned, linked, incomplete, reconstructed, replayed, PASS, FAIL and UNKNOWN states.",
        ordering="Logical validation precedes partitioning; manifest and ordered shard linkage precede reconstruction and optional replay.",
        commands="Construct, parse, reconstruct and validate bounded PRDEL packet bytes and optional exact-source replay.",
        targets="In-memory manifest, shard, index, reconstruction and validation records.",
        effect_domains="BOUNDED_PRDEL_PACKET_CONSTRUCTION_AND_REPLAY_ONLY",
        effects="Construct or validate packet bytes and invoke bounded compilation replay when explicitly selected.",
        commit="Commit is return of an exact packet or validation record; shards have no independent verdict.",
        limits="Strict byte, shard, row, node, edge and operation ceilings fail closed; missing selected bytes remains UNKNOWN.",
        observations="It observes packet bytes, digest linkage and replay returns, not explanation or source-behavior truth.",
        failure="Malformed linkage fails; missing material or unavailable replay remains UNKNOWN without gate credit.",
        boundary=boundary,
    )


_PRDEL_SHARDS = _shard_profile(
    "PRDEL shard and index protocol",
    "Partition one complete PRDEL compilation, preserve required residuals in a human index, reconstruct it and optionally replay exact source.",
    "Static/compiler and shard integrity does not prove execution, explanation truth, source predicates, gate clearance or publication authority.",
)
_PRDEL_V2_SHARDS = _shard_profile(
    "PRDEL v2 shard protocol",
    "Transport one complete logical PRDEL v2 document while retaining the complete impact graph in its manifest.",
    "Transport and recomposition integrity grants no semantic correctness, source grounding, gate promotion or release claim.",
)


_TIER_PATHS = (
    "src/verifier/runtime/core_tier_progression.py",
    "src/verifier/runtime/tier_progression.py",
)
_RELEASE_PATHS = (
    "src/verifier/runtime/application_release.py",
    "src/verifier/runtime/core_application_release.py",
)
_PRDEL_SHARD_PATHS = (
    "src/verifier/runtime/prdel_shards.py",
    "src/verifier/runtime/prdel_shard_index.py",
)
_PRDEL_SHARD_ACTIVE_PATH = ("src/verifier/runtime/prdel_shards.py",)


_REVIEWS = {
    "vstd-tier-progression-controller": _review(
        "VERIFIER",
        _TIER_PATHS,
        ("MEASUREMENT", "CONTROLLER", "ACTUATOR", "POLICY"),
        _TIER_PROGRESSION,
        refuted=(),
        anchors={
            "MEASUREMENT": "core_tier_progression.py:536,594-609",
            "CONTROLLER": "core_tier_progression.py:600-624",
            "ACTUATOR": "core_tier_progression.py:588-591",
            "POLICY": "core_tier_progression.py:457,515-523,580-587,604-607",
        },
    ),
    "vstd-application-release-controller": _review(
        "VERIFIER",
        _RELEASE_PATHS,
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY"),
        _APPLICATION_RELEASE,
        refuted=(),
        anchors={
            "TRANSACTION": "core_application_release.py:761-794,816-824",
            "MEASUREMENT": "core_application_release.py:771-779,807-810",
            "SENSOR": "core_application_release.py:874-931",
            "CONTROLLER": "core_application_release.py:599-603,652-659,762-763,803-824",
            "ACTUATOR": "core_application_release.py:765-788",
            "POLICY": "core_application_release.py:315-370,373-396",
        },
    ),
    "vstd-package-polish-controller": _review(
        "VERIFIER",
        ("src/verifier/runtime/package_polish.py", "src/verifier/runtime/package_polish_schema_validation.py", "src/verifier/runtime/package_source_contracts.py"),
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY", "PROTOCOL"),
        _PACKAGE_POLISH,
        refuted=(),
        anchors={
            "TRANSACTION": "package_polish.py:4222-4474,4570-4722",
            "MEASUREMENT": "package_polish.py:2336-2339,2375-2387,4873-4886; package_source_contracts.py:467-533",
            "SENSOR": "package_polish.py:2375-2387,4760-4776",
            "CONTROLLER": "package_polish.py:2518-2590,4627-4690",
            "ACTUATOR": "package_polish.py:396-412,2518-2535,4373-4384",
            "POLICY": "package_polish.py:4004-4035,4437-4745",
            "PROTOCOL": "package_polish.py:1557-1866,2622-2867; package_polish_schema_validation.py:982-1386,1605-2114; package_source_contracts.py:87-101,155-168,257-260,549-550",
        },
    ),
    "vstd-package-self-polish-controller": _review(
        "VERIFIER",
        ("src/verifier/runtime/package_self_polish.py",),
        ("MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY", "PROTOCOL"),
        _PACKAGE_SELF_POLISH,
        refuted=(),
        anchors={
            "MEASUREMENT": "package_self_polish.py:1737-1817,934-1116",
            "SENSOR": "package_self_polish.py:1750-1780",
            "CONTROLLER": "package_self_polish.py:2271-2286",
            "ACTUATOR": "package_self_polish.py:610-618,835-856,2108-2126",
            "POLICY": "package_self_polish.py:1031-1072,960-966,1869-1881,2275-2282",
            "PROTOCOL": "package_self_polish.py:1982-2301",
        },
    ),
    "vstd-package-self-polish-rechecker": _review(
        "VERIFIER",
        ("src/verifier/runtime/package_self_polish_recheck.py",),
        ("MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY", "PROTOCOL"),
        _PACKAGE_RECHECK,
        refuted=(),
        anchors={
            "MEASUREMENT": "package_self_polish_recheck.py:4152-4231,4236-4245,1001-1055",
            "SENSOR": "package_self_polish_recheck.py:1970-2021,2901-2908,1794-1819",
            "CONTROLLER": "package_self_polish_recheck.py:4262-4295,2912-2919,1996-2005",
            "ACTUATOR": "package_self_polish_recheck.py:1797-1800,1980-1995",
            "POLICY": "package_self_polish_recheck.py:356-365,1023-1032,2041-2101,4116-4124",
            "PROTOCOL": "package_self_polish_recheck.py:745-749,823-909,4164-4180,4214-4217",
        },
    ),
    "vstd-polish-assessment-engine": _review(
        "VERIFIER",
        ("src/verifier/runtime/polish.py",),
        ("MEASUREMENT", "ACTUATOR", "POLICY"),
        _POLISH_ASSESSMENT,
        refuted=(),
        anchors={
            "MEASUREMENT": "polish.py:278-287,370-385",
            "ACTUATOR": "polish.py:269-277",
            "POLICY": "polish.py:349-361,375-376,391-392",
        },
    ),
    "vstd-polish-command-controller": _review(
        "CONTROLLER",
        ("src/verifier/runtime/polish_cli.py",),
        ("TRANSACTION", "MEASUREMENT", "SENSOR", "CONTROLLER", "ACTUATOR", "POLICY"),
        _POLISH_COMMAND,
        refuted=(),
        anchors={
            "MEASUREMENT": "polish_cli.py:269,328,397,413",
            "SENSOR": "polish_cli.py:234-269,349-396",
            "ACTUATOR": "polish_cli.py:272-327",
            "POLICY": "polish_cli.py:289-321,335-348",
            "TRANSACTION": "polish_cli.py:272-327",
        },
        blocked=("CONTROLLER",),
    ),
    "vstd-polish-capacity-policy": _review(
        "POLICY",
        ("src/verifier/runtime/polish_capacity.py",),
        ("POLICY",),
        _CAPACITY,
        refuted=(),
        anchors={
            "POLICY": "polish_capacity.py:19-51,197-211,251-254",
        },
    ),
    "vstd-polish-findings-projection": _review(
        "VERIFIER",
        ("src/verifier/runtime/polish_findings.py",),
        ("MEASUREMENT", "POLICY"),
        _FINDINGS,
        refuted=(),
        anchors={
            "MEASUREMENT": "polish_findings.py:373-394,431-449",
            "POLICY": "polish_findings.py:33-40,45,166-167,367-372,422-430",
        },
    ),
    "vstd-polish-inventory-policy": _review(
        "VERIFIER",
        ("src/verifier/runtime/polish_inventory.py",),
        ("POLICY",),
        _INVENTORY,
        refuted=(),
        anchors={
            "POLICY": "polish_inventory.py:140-145,268-282,354-356,430-433",
        },
    ),
    "vstd-polish-inventory-authority": _review(
        "PROTOCOL",
        ("src/verifier/runtime/polish_inventory_authority.py",),
        ("PROTOCOL", "POLICY"),
        _INVENTORY_AUTHORITY,
        refuted=(),
        anchors={
            "PROTOCOL": "polish_inventory_authority.py:119-139,196-269,272-284",
            "POLICY": "polish_inventory_authority.py:222-223,252-254",
        },
    ),
    "vstd-polish-public-authority": _review(
        "PROTOCOL",
        ("src/verifier/runtime/polish_public_authority.py",),
        ("PROTOCOL", "POLICY"),
        _PUBLIC_AUTHORITY,
        refuted=(),
        anchors={
            "PROTOCOL": "polish_public_authority.py:261-298,407-408,443-521",
            "POLICY": "polish_public_authority.py:153-210,322-339,382-383,424-425",
        },
    ),
    "vstd-prdel-coverage-policy": _review(
        "VERIFIER",
        ("src/verifier/runtime/prdel_coverage.py",),
        ("POLICY",),
        _PRDEL_COVERAGE,
        refuted=(),
        anchors={
            "POLICY": "prdel_coverage.py:238-239,378-387,434-440,512-536,555-560",
        },
    ),
    "vstd-prdel-impact-graph": _review(
        "VERIFIER",
        ("src/verifier/runtime/prdel_graph.py",),
        ("POLICY",),
        _PRDEL_GRAPH,
        refuted=(),
        anchors={
            "POLICY": "prdel_graph.py:279-292,297-307,466-495,1229-1233",
        },
    ),
    "vstd-prdel-source-compiler": _review(
        "VERIFIER",
        ("src/verifier/runtime/prdel_rules.py",),
        ("MEASUREMENT", "SENSOR", "POLICY", "ACTUATOR", "PROTOCOL"),
        _PRDEL_COMPILER,
        refuted=(),
        anchors={
            "MEASUREMENT": "prdel_rules.py:168-176,230-233,429-470",
            "POLICY": "prdel_rules.py:207-212,355-369,475-488,517-533,699-710",
            "ACTUATOR": "prdel_rules.py:370-397",
            "PROTOCOL": "prdel_rules.py:746-768,770-807,847-868",
            "SENSOR": "prdel_rules.py:313-397",
        },
    ),
    "vstd-prdel-shard-protocol": _review(
        "PROTOCOL",
        _PRDEL_SHARD_PATHS,
        ("PROTOCOL", "POLICY", "MEASUREMENT", "SENSOR", "ACTUATOR"),
        _PRDEL_SHARDS,
        {
            "PROTOCOL": _PRDEL_SHARD_PATHS,
            "POLICY": _PRDEL_SHARD_PATHS,
            "MEASUREMENT": _PRDEL_SHARD_ACTIVE_PATH,
            "SENSOR": _PRDEL_SHARD_ACTIVE_PATH,
            "ACTUATOR": _PRDEL_SHARD_ACTIVE_PATH,
        },
        refuted=(),
        anchors={
            "PROTOCOL": "prdel_shards.py:108-153,156-176; prdel_shard_index.py:120-228,312-345",
            "POLICY": "prdel_shards.py:25,195-212,262,285,348; prdel_shard_index.py:198-205",
            "MEASUREMENT": "prdel_shards.py:77-81,216-225,353",
            "ACTUATOR": "prdel_shards.py:103-104,163-166,272-281",
            "SENSOR": "prdel_shards.py:98-104,156-166",
        },
    ),
    "vstd-prdel-v2-shard-protocol": _review(
        "PROTOCOL",
        ("src/verifier/runtime/prdel_v2_shards.py",),
        ("PROTOCOL", "POLICY"),
        _PRDEL_V2_SHARDS,
        refuted=(),
        anchors={
            "PROTOCOL": "prdel_v2_shards.py:261-377,411-527,544-660",
            "POLICY": "prdel_v2_shards.py:64-92,436-439,590-607,616",
        },
    ),
    "vstd-public-checkability-protocol": _review(
        "PROTOCOL",
        ("src/verifier/runtime/public_checkability.py",),
        ("PROTOCOL", "POLICY"),
        _PUBLIC_CHECKABILITY,
        refuted=(),
        anchors={
            "PROTOCOL": "public_checkability.py:255-287,434-450,482-552",
            "POLICY": "public_checkability.py:267,277,296-300,434-435,447-450",
        },
    ),
}


def _contract_rows(kind: str) -> list[dict[str, Any]]:
    return [
        row
        for row in requirements_for(namespace_registry(), (kind,))
        if row["kind"] == kind
    ]


def _declarations(review: _Review) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for kind in review.applicable:
        try:
            selected = _shared._DECLARATION_BUILDERS[kind](review.profile)
        except KeyError as exc:
            raise AssertionError("missing declaration builder for " + kind) from exc
        overlap = set(result).intersection(selected)
        if overlap:
            raise AssertionError("duplicate declaration ids: " + ", ".join(overlap))
        result.update(selected)
    return result


def _catalog_check() -> None:
    if tuple(_REVIEWS) != POLISH_OBJECT_IDS:
        raise AssertionError("polish review order differs from public object order")
    owned_paths: set[str] = set()
    for object_id, review in _REVIEWS.items():
        if (
            review.primary_kind in REVIEW_KINDS
            and review.primary_kind not in review.applicable
        ):
            raise AssertionError(object_id + " primary kind is not applicable")
        if len(review.owned_paths) != len(set(review.owned_paths)):
            raise AssertionError(object_id + " repeats an owned path")
        overlap = owned_paths.intersection(review.owned_paths)
        if overlap:
            raise AssertionError(
                "polish ownership overlaps: " + ", ".join(sorted(overlap))
            )
        owned_paths.update(review.owned_paths)
        if len(review.applicable) != len(set(review.applicable)):
            raise AssertionError(object_id + " repeats an applicable kind")
        if not set(review.applicable) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " has an unsupported review kind")
        if len(review.refuted) != len(set(review.refuted)):
            raise AssertionError(object_id + " repeats a refuted kind")
        if not set(review.refuted) <= set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutes an unsupported review kind")
        if set(review.applicable) & set(review.refuted):
            raise AssertionError(object_id + " applies and refutes one kind")
        if not set(review.refuted) <= set(REFUTABLE_CHANNELS):
            raise AssertionError(
                object_id + " refutes a kind without an audited channel census"
            )
        if set(review.applicable) | set(review.refuted) == set(REVIEW_KINDS):
            raise AssertionError(object_id + " refutation table is complement-shaped")
        if not set(review.blocked) <= set(review.applicable) or not set(
            review.blocked
        ) <= {review.primary_kind}:
            raise AssertionError(
                object_id + " blocks a kind other than its primary kind"
            )
        if set(review.anchors) != set(review.applicable) - set(review.blocked) or any(
            not anchor.strip() for anchor in review.anchors.values()
        ):
            raise AssertionError(object_id + " APPLIES lacks an exact source anchor")
        if set(review.role_paths) != set(review.applicable):
            raise AssertionError(object_id + " role evidence denominator differs")
        if any(
            not paths or not set(paths) <= set(review.owned_paths)
            for paths in review.role_paths.values()
        ):
            raise AssertionError(object_id + " role evidence leaves owned source")
        reasons = {kind: _classification_reason(review, kind) for kind in REVIEW_KINDS}
        if any(not reason.strip() for reason in reasons.values()):
            raise AssertionError(object_id + " classification matrix is incomplete")
        expected = {
            row["id"]: set(row["declaration_fields"])
            for kind in review.applicable
            for row in _contract_rows(kind)
        }
        declarations = _declarations(review)
        if set(declarations) != set(expected):
            raise AssertionError(object_id + " declaration denominator differs")
        for obligation_id, fields in declarations.items():
            if set(fields) != expected[obligation_id] or any(
                type(value) is not str or not value.strip() for value in fields.values()
            ):
                raise AssertionError(object_id + " declaration fields differ")
    if len(owned_paths) != 23:
        raise AssertionError("polish review source denominator differs")


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return a defensive deterministic review of the eighteen exact owners."""
    return {
        object_id: {
            "primary_kind": review.primary_kind,
            "owned_paths": list(review.owned_paths),
            "classification": {
                kind: {
                    "status": _basis(review, kind),
                    "reason": _classification_reason(review, kind),
                    "evidence_paths": list(_evidence_paths(review, kind)),
                }
                for kind in REVIEW_KINDS
            },
            "declarations": deepcopy(_declarations(review)),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for object_id, review in _REVIEWS.items()
    }


def _read_digest(root: Path, path: str) -> str:
    """Digest one exact in-root ordinary source."""
    return "sha256:" + sha256(_read_bytes(root, path)).hexdigest()


def _source_evidence(root: Path, paths: tuple[str, ...]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": _read_digest(root, path)} for path in paths]


def _current_evidence(
    root: Path,
    paths: tuple[str, ...],
    files: Mapping[str, str],
    *,
    object_id: str,
) -> list[dict[str, str]]:
    evidence = _source_evidence(root, paths)
    for reference in evidence:
        path = reference["path"]
        if files.get(path) != reference["sha256"]:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:" + object_id + ":" + path
            )
    return evidence


def apply_package_semantic_review_polish(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply all eighteen exact-source reviews atomically to a deep copy."""
    selected_root = Path(root).resolve(strict=True)
    if not selected_root.is_dir():
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_ROOT_INVALID")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_ROWS_INVALID")
    if type(files) is not dict or any(
        type(path) is not str
        or type(digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_FILES_INVALID")

    live_obligations = {
        kind: {
            row["id"]: tuple(row["declaration_fields"]) for row in _contract_rows(kind)
        }
        for kind in REVIEW_KINDS
    }
    plans: dict[str, dict[str, Any]] = {}
    for object_id, review in _REVIEWS.items():
        row = rows.get(object_id)
        if type(row) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING:" + object_id)
        if row.get("object_id") != object_id or row.get("kind") != review.primary_kind:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_PRIMARY_KIND_DIFFERS:" + object_id
            )
        owned = _shared._owned_file_paths(row)
        if owned != set(review.owned_paths):
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + object_id)
        current = _current_evidence(
            selected_root, review.owned_paths, files, object_id=object_id
        )
        evidence_by_path = {item["path"]: item for item in current}
        census = channel_census(selected_root, review.owned_paths)
        for kind in review.refuted:
            if any(census[channel] for channel in REFUTABLE_CHANNELS[kind]):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_REFUTATION_CHANNEL_PRESENT:"
                    + object_id
                    + ":"
                    + kind
                )
        if review.refuted and any(
            surface_findings(selected_root, review.owned_paths).values()
        ):
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_REFUTATION_SURFACE_OPEN:" + object_id
            )

        classification = row.get("classification")
        obligations = row.get("obligations")
        specializations = row.get("specializations")
        if type(classification) is not dict or type(obligations) is not dict:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id)
        if (
            type(specializations) is not list
            or any(type(kind) is not str for kind in specializations)
            or len(specializations) != len(set(specializations))
        ):
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID:" + object_id
            )
        for kind in REVIEW_KINDS:
            if _basis(review, kind) != "APPLIES" and (
                row["kind"] == kind or kind in specializations
            ):
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id + ":" + kind
                )

        known_obligations = {
            name for values in live_obligations.values() for name in values
        }
        for name in obligations:
            if type(name) is not str or name not in known_obligations:
                raise ValueError(
                    "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:"
                    + object_id
                    + ":"
                    + str(name)
                )

        preserve_decisions: set[str] = set()
        preserve_obligations: set[str] = set()
        remove_obligations: set[str] = set()
        unresolved_candidates: dict[str, list[dict[str, str]]] = {}
        for kind in REVIEW_KINDS:
            basis = _basis(review, kind)
            decision = classification.get(kind)
            if basis == "UNRESOLVED":
                code = "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind
                if decision is not None and not (
                    type(decision) is dict and decision.get("status") == "UNRESOLVED"
                ):
                    raise ValueError(code)
                if (
                    _shared._unresolved_decision(
                        decision, files, owned, kind=kind, code=code
                    )
                    and decision is not None
                    and decision["evidence"]
                ):
                    unresolved_candidates[kind] = [
                        deepcopy(evidence_by_path[item["path"]])
                        for item in decision["evidence"]
                    ]
            else:
                paths = review.role_paths[kind] if basis == "APPLIES" else review.owned_paths
                expected_decision = {
                    "status": basis,
                    "reason": _classification_reason(review, kind),
                    "evidence": [deepcopy(evidence_by_path[path]) for path in paths],
                }
                if _shared._preserve_explicit_decision(
                    decision,
                    expected_decision,
                    files,
                    owned,
                    object_id=object_id,
                    kind=kind,
                ):
                    preserve_decisions.add(kind)
            for obligation_id, fields in live_obligations[kind].items():
                binding = obligations.get(obligation_id)
                if basis == "APPLIES":
                    expected_evidence = [
                        deepcopy(evidence_by_path[path])
                        for path in review.role_paths[kind]
                    ]
                    if _shared._preserve_explicit_obligation(
                        binding,
                        fields,
                        _obligation_reason(review, kind),
                        expected_evidence,
                        files,
                        owned,
                        object_id=object_id,
                        obligation_id=obligation_id,
                    ):
                        preserve_obligations.add(obligation_id)
                elif binding is not None:
                    prefix = (
                        "PACKAGE_SEMANTIC_REVIEW_REFUTED_DECLARATION_CONFLICT:"
                        if basis == "DOES_NOT_APPLY"
                        else "PACKAGE_SEMANTIC_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
                    )
                    code = prefix + object_id + ":" + obligation_id
                    if not _shared._blank_obligation(
                        binding, fields, files, owned, code=code
                    ):
                        raise ValueError(code)
                    remove_obligations.add(obligation_id)

        plans[object_id] = {
            "opening_evidence": current,
            "evidence_by_path": evidence_by_path,
            "preserve_decisions": preserve_decisions,
            "preserve_obligations": preserve_obligations,
            "remove_obligations": remove_obligations,
            "unresolved_candidates": unresolved_candidates,
        }

    # Re-read the whole source denominator only after all semantic checks, so a
    # concurrent write cannot produce a partially current generated review.
    for object_id, review in _REVIEWS.items():
        closing = _source_evidence(selected_root, review.owned_paths)
        if closing != plans[object_id]["opening_evidence"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED:" + object_id)

    result = deepcopy(rows)
    for object_id, review in _REVIEWS.items():
        row = result[object_id]
        plan = plans[object_id]
        declarations = _declarations(review)
        for kind in REVIEW_KINDS:
            if kind in plan["preserve_decisions"]:
                continue
            basis = _basis(review, kind)
            if basis == "UNRESOLVED":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": _unresolved_reason(kind),
                    "evidence": deepcopy(plan["unresolved_candidates"].get(kind, [])),
                }
            else:
                paths = review.role_paths[kind] if basis == "APPLIES" else review.owned_paths
                row["classification"][kind] = {
                    "status": basis,
                    "reason": _classification_reason(review, kind),
                    "evidence": [
                        deepcopy(plan["evidence_by_path"][path]) for path in paths
                    ],
                }
        for name in plan["remove_obligations"]:
            row["obligations"].pop(name, None)
        for name, declaration in declarations.items():
            if name in plan["preserve_obligations"]:
                continue
            kind = name.split("-", 1)[0]
            row["obligations"][name] = {
                "reason": _obligation_reason(review, kind),
                "evidence": [
                    deepcopy(plan["evidence_by_path"][path])
                    for path in review.role_paths[kind]
                ],
                "declaration": dict(declaration),
            }
        for kind in review.applicable:
            if kind != row["kind"] and kind not in row["specializations"]:
                row["specializations"].append(kind)
    return result


__all__ = [
    "CLAIM_BOUNDARY",
    "POLISH_OBJECT_IDS",
    "REFUTABLE_CHANNELS",
    "REVIEW_KINDS",
    "apply_package_semantic_review_polish",
    "channel_census",
    "refutation_reason",
    "review_document",
]
