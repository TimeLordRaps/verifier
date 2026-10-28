"""Whole-program Python effect reach for Verifier Standard (VSTD) Tier zero.

Terminology: American Standard Code for Information Interchange (ASCII).

Inputs and outputs use JavaScript Object Notation (JSON). Python's abstract syntax tree (AST)
and application programming interface (API) calls are analyzed as source, never trusted as claims.

usage: python -B effect_reach_prototype.py OBJECTS_DUMP_JSON OUT_JSON

Question: if polish followed calls across objects, instead of stopping at each object's owned
files, how many census-item objects would have a closed effect summary, and what would still
block the rest?

Per-call rules are the installed closed-effect audit's own (package_original_kind_review:
_effect_channels, _PURE_BUILTINS, _PURE_METHODS, _PURE_STDLIB_PREFIXES, _DYNAMIC_OPERATIONS,
_POSITIONAL_CALLBACKS, _CALLBACK_KEYWORDS).  What changes is reach: a call into project code is
followed instead of being a blocker.  Resolution, each named:
  * project names through imports and aliases across every census .py file (re-exports too);
  * constructors through project bases (__init__, __post_init__, __new__);
  * self/cls/super/type(self) by class hierarchy: lookup through project bases plus overrides
    in project subclasses;
  * receivers typed by local facts: x = ProjectClass(...), annotations, return annotations,
    self.attr = ProjectClass(...) anywhere in the class;
  * callables passed as arguments resolved at project call sites (context-insensitive);
  * literal getattr / importlib / dispatch-table targets resolved exactly;
  * import-time effects: a module's top-level code, the project modules it imports, and its
    parent packages.
Everything else is a named gap.  Tiers are cumulative assumption sets:
  S  installed per-call rules, followed across the project.  Untyped parameter receivers stay
     gaps (the installed audit treats any call rooted at a parameter as injected); untyped
     local receivers follow the installed name rules (pure name -> pure, effect name ->
     accounted, other -> gap).
  N  + every untyped receiver dispatched by method name to every project method of that name
     (this also closes the installed pure-name shortcut for project methods named get/update...);
  T  + a DRAFT standard-library table: stdlib functions and stdlib-object methods are pure
     unless an installed channel, or a listed draft effect, names an effect;
  C  + callables supplied from outside the project attributed to their supplier.
Counting only: nothing here is a verdict, and the selected source root is not written.
"""
from __future__ import annotations

import ast
import collections
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import project_effect_first as projection  # noqa: E402
from verifier.runtime import namespace_classification as classification  # noqa: E402
from verifier.runtime import namespace_refutation as refutation  # noqa: E402
from verifier.runtime import package_original_kind_review as audit  # noqa: E402
from verifier.runtime import package_semantic_review_operations as review_operations  # noqa: E402

ROOT = Path(os.environ.get("REASONS_ROOT", ".")).resolve(strict=True)
STDLIB = set(sys.stdlib_module_names)
CHANNELS = sorted(audit._EFFECT_CHANNELS)
CHANNEL_BIT = {name: 1 << index for index, name in enumerate(CHANNELS)}
WRITE_MASK = sum(CHANNEL_BIT[name] for name in classification._EXTERNAL_WRITE_CHANNELS)
GAPS = [
    "dynamic: computed reflection name", "dynamic: computed import", "dynamic: eval/exec/compile",
    "dynamic: call of a call result", "dynamic: subscript dispatch", "dynamic: local callable value",
    "dynamic: other callee expression", "callback: supplied from outside the project",
    "callback: unresolved argument at a project call site", "receiver: untyped parameter",
    "receiver: untyped local or expression", "method: stdlib-object name", "method: unknown name",
    "stdlib: unclassified function", "third-party: call or import", "inherited: external base method",
    "language: unsupported file", "syntax error", "name: unbound value called",
    "census: empty, undecodable or oversize", "import: ambiguous sys.path-local module",
    "subject: reaches unshipped code",
    "implicit: operation on an untyped parameter", "implicit: operation on a value of unknown type",
    "implicit: attribute access on an untyped parameter", "implicit: attribute access on a value of unknown type",
]
# REACH_SUBJECT selects the subject program; everything outside it is a witness: its subclasses are
# not dispatch targets, its methods are not name-dispatch targets, its call sites do not type or
# supply subject parameters, and a subject call into it is the named gap above, never dropped.
#   shipped  the distributions: src/ (verifier-standard) and extensions/*/src/ (the extension packages)
#   nontest  every file except tests: the repository's own code, with tests as its witnesses
# REACH_SHIPPED=1 is the older spelling of REACH_SUBJECT=shipped.
SUBJECT = os.environ.get("REACH_SUBJECT") or ("shipped" if os.environ.get("REACH_SHIPPED") == "1" else "")
if SUBJECT not in ("", "shipped", "nontest"):
    raise SystemExit(f"REACH_SUBJECT must be shipped or nontest, not {SUBJECT!r}")
SHIPPED_ONLY = bool(SUBJECT)
# REACH_NAME_RULE=off withdraws the installed pure-name rule for unknown receivers: `x.get()` on a
# value of unknown type is a gap, as the alias-hole fix would make it.  Known builtin receivers
# (literals, builtin constructors, str/bytes annotations) are unaffected.
NAME_RULE = os.environ.get("REACH_NAME_RULE", "on")
if NAME_RULE not in ("on", "off"):
    raise SystemExit(f"REACH_NAME_RULE must be on or off, not {NAME_RULE!r}")
# REACH_IMPLICIT counts code that runs with no call expression: an operator, comparison, subscript,
# iteration, truth test, `with`, f-string, builtin protocol call (len, str, hash, ...) or dict/set key
# runs a dunder of the operand's type.  On a value of unknown type that is unseen code, the same
# question as a method call on it.  `is`, `type(x)`, `id(x)`, passing or returning a value run nothing.
#   off  the installed audit's view (and the earlier prototype): only `with` and project @property
#        reads on known classes are followed; nothing implicit is a gap
#   ops  + operators and protocols: a gap on a parameter or a value of unknown type, an edge to the
#        dunder on a project class, name dispatch at tier N
#   all  + attribute reads and writes on a parameter or a value of unknown type (a property,
#        descriptor or __getattr__ of an unseen class can run)
# Named exclusions in every mode: isinstance/issubclass (an adversarial __class__ property or
# __instancecheck__), and an element of a builtin or stdlib container counts as a builtin value.
IMPLICIT = os.environ.get("REACH_IMPLICIT", "off")
if IMPLICIT not in ("off", "ops", "all"):
    raise SystemExit(f"REACH_IMPLICIT must be off, ops or all, not {IMPLICIT!r}")
# REACH_ANNOTATIONS: Python never checks annotations, so each one read is a stated fact.
#   on        the earlier prototype: parameter annotations and project-class return annotations read
#   concrete  + an abstract annotation (typing.Mapping, collections.abc.*, os.PathLike, a project
#             typing.Protocol) leaves the parameter untyped: any class may implement it, and a
#             Protocol's stub is not the implementation that runs
#   off       no annotation read: how much of a result rests on stated facts
ANNOTATIONS = os.environ.get("REACH_ANNOTATIONS", "on")
if ANNOTATIONS not in ("on", "concrete", "off"):
    raise SystemExit(f"REACH_ANNOTATIONS must be on, concrete or off, not {ANNOTATIONS!r}")
# REACH_FACTS names a JSON file of facts admitted from reasons (reasons_check.py writes it): site and
# attribute types, return types, calls discharged by a contract, and the supplier edges that replace them.
FACTS_PATH = os.environ.get("REACH_FACTS", "")
# Two more fact kinds come from the boundary rule: a (definition, parameter) whose uses belong to each
# caller, and the gaps moved to the callers that pass a value of unknown type.
FACTS: dict = {"sites": {}, "attrs": {}, "returns": {}, "suppress": set(), "edges": {}, "boundary": set(),
               "site_gaps": {}}
SOURCE_OVERRIDES: dict[str, bytes] = {}  # mutation tests: census path -> replacement source


def load_facts(data: dict) -> None:
    def origin(f: dict) -> tuple[str, str | None]:
        return f["kind"], f.get("value")
    # a site fact names its occurrence by line and, when the expression occurs twice on the line, column
    FACTS["sites"] = {(f["def"], f["expr"], f.get("line"), f.get("col")): origin(f) for f in data.get("site_types", [])}
    FACTS["attrs"] = {(f["class"], f["attr"]): origin(f) for f in data.get("attr_types", [])}
    FACTS["returns"] = {f["def"]: origin(f) for f in data.get("return_types", [])}
    FACTS["suppress"] = {(f["def"], f["call"], f.get("line")) for f in data.get("discharged_calls", [])}
    FACTS["edges"] = {}
    for f in data.get("supplier_edges", []):
        FACTS["edges"].setdefault(f["from"], set()).update(f["to"])
    FACTS["boundary"] = {(f["def"], f["param"]) for f in data.get("boundary", [])}
    FACTS["site_gaps"] = {}
    for f in data.get("site_gaps", []):
        FACTS["site_gaps"].setdefault(f["def"], []).append(f["category"])


def shipped(path: str) -> bool:
    """In the subject program (named 'shipped' for the default subject)."""
    if SUBJECT == "nontest":
        return not is_test_path(path)
    return path.startswith("src/") or (path.startswith("extensions/") and "/src/" in path)
GAP_BIT = {name: 1 << index for index, name in enumerate(GAPS)}
UNTYPED_PARAM = GAP_BIT["receiver: untyped parameter"]
IMPLICIT_CATEGORY = {("op", True): "implicit: operation on an untyped parameter",
                     ("op", False): "implicit: operation on a value of unknown type",
                     ("attr", True): "implicit: attribute access on an untyped parameter",
                     ("attr", False): "implicit: attribute access on a value of unknown type"}
IMPLICIT_PARAM_BIT = {"op": GAP_BIT[IMPLICIT_CATEGORY["op", True]], "attr": GAP_BIT[IMPLICIT_CATEGORY["attr", True]]}
BASE_GAPS = GAP_BIT["language: unsupported file"] | GAP_BIT["syntax error"] | GAP_BIT["census: empty, undecodable or oversize"]
_T = {"method: stdlib-object name", "stdlib: unclassified function"}
_C = _T | {"callback: supplied from outside the project"}
TIERS = {  # tier -> (graph, gap categories the tier's assumptions resolve); cumulative
    "S": ("strict", set()),
    "I": ("inferred", set()),     # + receiver types inferred from project call sites
    "T": ("inferred", _T),        # + DRAFT stdlib table
    "C": ("inferred", _C),        # + outside callbacks attributed to their supplier
    "N": ("named", _C),           # + any still-untyped receiver dispatched by method name
}
# Annotations that say nothing about the receiver's class: such a parameter stays untyped.
UNTYPED_ANNOTATIONS = {"typing.Any", "Any", "object", "builtins.object", "typing_extensions.Any", "typing.Callable",
                       "collections.abc.Callable", "Callable", "typing.Hashable", "collections.abc.Hashable"}
SAFE_EXTERNAL_BASES = {
    "object", "Exception", "BaseException", "ValueError", "TypeError", "KeyError", "RuntimeError", "OSError",
    "LookupError", "IndexError", "AttributeError", "NotImplementedError", "AssertionError", "dict", "list",
    "tuple", "set", "frozenset", "str", "int", "float", "bytes", "bool", "typing.NamedTuple", "typing.Protocol",
    "typing.Generic", "typing.TypedDict", "enum.Enum", "enum.IntEnum", "enum.StrEnum", "enum.Flag",
    "enum.IntFlag", "abc.ABC", "collections.UserDict", "json.JSONEncoder", "ast.NodeVisitor",
    "ast.NodeTransformer", "html.parser.HTMLParser", "argparse.Action", "argparse.ArgumentParser",
}
# DRAFT stdlib table (tier T): effects that the installed channel list does not name.
DRAFT_STDLIB_EFFECTS: dict[str, str | None] = {  # None: classified, no installed channel applies
    "sys.exit": None, "os._exit": None, "os.kill": "subprocess_process",
    "os.chdir": "environment", "os.getcwd": "environment", "atexit.register": "callback_injected_callable",
    "webbrowser.": "subprocess_process", "importlib.metadata.": "filesystem_read", "platform.": "environment",
    "getpass.": "environment", "logging.FileHandler": "filesystem_write", "signal.": "subprocess_process",
    "ctypes.": "dynamic_import_eval_exec_reflection", "sys.setrecursionlimit": "environment",
}
# Everything tier T assumes pure is listed in full in the report, so a reviewer can refute it.
TIER_T_ASSUMPTIONS = ("unclassified_stdlib", "stdlib_object_method", "stdlib_like_method", "draft_stdlib_effect")
BUILTIN_TYPE_METHODS: set[str] = set()
for _type in (str, bytes, bytearray, list, dict, set, frozenset, tuple, int, float, complex, memoryview,
              range, slice, bool):
    BUILTIN_TYPE_METHODS.update(name for name in dir(_type) if not name.startswith("__"))
# Receivers whose builtin type is known: a literal's node kind, or a builtin type name (annotation).
LITERAL_TYPES = {"JoinedStr": (str,), "List": (list,), "ListComp": (list,), "Dict": (dict,), "DictComp": (dict,),
                 "Set": (set,), "SetComp": (set,), "Tuple": (tuple,), "Compare": (bool,),
                 "Constant": (str, bytes, int, float, complex, bool)}
NAMED_BUILTIN_TYPES = {t.__name__: t for t in (str, bytes, bytearray, list, dict, set, frozenset, tuple, int, float,
                                               complex, bool)}


def builtin_types(kind: str, value: str | None) -> tuple[type, ...]:
    """The builtin types an origin can be: () when it is not a known builtin value."""
    if kind == "json":
        return (dict, list, str, int, float, bool)
    if not value or kind not in ("stdlib", "builtin"):
        return ()
    name = value.split("[")[0].removeprefix("builtins.")
    types = LITERAL_TYPES.get(name, ()) if kind == "builtin" else ()
    if not types and name in NAMED_BUILTIN_TYPES:
        types = (NAMED_BUILTIN_TYPES[name],)
    return types


def builtin_receiver_method(kind: str, value: str | None, method: str) -> bool:
    """The receiver's builtin type is known and defines the method: it is that type's method, pure, whatever
    effect the same name has on another type (str.replace is not Path.replace)."""
    if kind == "json":
        return False
    return any(hasattr(t, method) for t in builtin_types(kind, value))


# ----- implicit dispatch (REACH_IMPLICIT) -----------------------------------------------------------
_BINOP = {"Add": "add", "Sub": "sub", "Mult": "mul", "MatMult": "matmul", "Div": "truediv", "FloorDiv": "floordiv",
          "Mod": "mod", "Pow": "pow", "LShift": "lshift", "RShift": "rshift", "BitOr": "or", "BitXor": "xor",
          "BitAnd": "and"}
_COMPARE = {"Eq": ("__eq__",), "NotEq": ("__ne__", "__eq__"), "Lt": ("__lt__", "__gt__"), "LtE": ("__le__", "__ge__"),
            "Gt": ("__gt__", "__lt__"), "GtE": ("__ge__", "__le__")}
_UNARY = {"USub": ("__neg__",), "UAdd": ("__pos__",), "Invert": ("__invert__",)}
TRUTH = ("__bool__", "__len__")
ITER = ("__iter__", "__next__", "__getitem__", "__len__", "__length_hint__")
AITER = ("__aiter__", "__anext__")
HASH = ("__hash__", "__eq__")
MAPPING = ("keys", "__getitem__", "__iter__")
# builtin functions and types that run a protocol of their non-callable arguments
PROTOCOL_BUILTINS = {
    "str": ("__str__", "__repr__", "__format__"), "repr": ("__repr__",), "ascii": ("__repr__",),
    "format": ("__format__", "__str__"), "len": ("__len__",), "hash": ("__hash__",), "bool": TRUTH,
    "int": ("__int__", "__index__", "__trunc__"), "float": ("__float__", "__index__"),
    "complex": ("__complex__", "__float__", "__index__"), "abs": ("__abs__",), "round": ("__round__",),
    "divmod": ("__divmod__", "__rdivmod__"), "pow": ("__pow__", "__rpow__"), "iter": ITER, "next": ("__next__",),
    "reversed": ("__reversed__", "__len__", "__getitem__"), "list": ITER, "tuple": ITER, "set": ITER + HASH,
    "frozenset": ITER + HASH, "sorted": ITER + ("__lt__", "__gt__"), "min": ITER + ("__lt__", "__gt__"),
    "max": ITER + ("__lt__", "__gt__"), "sum": ITER + ("__add__", "__radd__"), "any": ITER + TRUTH,
    "all": ITER + TRUTH, "enumerate": ITER, "zip": ITER, "map": ITER, "filter": ITER + TRUTH,
    "dict": MAPPING + ITER + HASH, "bytes": ("__bytes__", "__index__", "__buffer__") + ITER,
    "bytearray": ("__index__", "__buffer__") + ITER, "memoryview": ("__buffer__",), "print": ("__str__",),
    "dir": ("__dir__",), "vars": ("__dict__",),
}
_SKIP_FIRST = {"map", "filter"}  # their first argument is a callback, not an operand
# DRAFT table: standard-library functions that run a protocol of their arguments.  Every other stdlib
# call is assumed to run none (named, like DRAFT_STDLIB_EFFECTS; logging's lazy %-formatting is a
# known omission).
PROTOCOL_STDLIB = {
    "copy.copy": ("__copy__", "__reduce_ex__", "__reduce__"),
    "copy.deepcopy": ("__deepcopy__", "__reduce_ex__", "__reduce__", "__getstate__", "__setstate__"),
    "json.dumps": MAPPING + ITER + ("items",), "json.dump": MAPPING + ITER + ("items",),
    "dataclasses.asdict": ("__deepcopy__", "__reduce_ex__"), "dataclasses.astuple": ("__deepcopy__", "__reduce_ex__"),
    "dataclasses.replace": ("__init__", "__post_init__"),
    "os.fspath": ("__fspath__",), "pathlib.Path": ("__fspath__",), "pathlib.PurePath": ("__fspath__",),
    "pathlib.PurePosixPath": ("__fspath__",), "pathlib.PureWindowsPath": ("__fspath__",),
    "hashlib.sha256": ("__buffer__",), "hashlib.sha1": ("__buffer__",), "hashlib.md5": ("__buffer__",),
    "hashlib.blake2b": ("__buffer__",), "hashlib.new": ("__buffer__",),
    "base64.b64encode": ("__buffer__",), "base64.b64decode": ("__buffer__",),
    "base64.urlsafe_b64encode": ("__buffer__",), "base64.urlsafe_b64decode": ("__buffer__",),
    "operator.index": ("__index__",), "math.floor": ("__floor__",), "math.ceil": ("__ceil__",),
    "math.trunc": ("__trunc__",), "math.isfinite": ("__float__", "__index__"), "math.isnan": ("__float__", "__index__"),
    "heapq.heappush": ("__lt__",), "bisect.bisect": ("__lt__",), "bisect.bisect_left": ("__lt__",),
    "bisect.insort": ("__lt__",), "functools.reduce": ITER, "itertools.chain": ITER,
    "itertools.chain.from_iterable": ITER, "itertools.islice": ITER, "itertools.groupby": ITER + ("__eq__",),
    "collections.Counter": ITER + HASH, "collections.OrderedDict": MAPPING + ITER + HASH,
    "types.MappingProxyType": MAPPING,
}
PROTOCOL_STR_METHODS = {"format": ("__format__", "__str__", "__repr__", "__getitem__"),
                        "format_map": ("__getitem__", "__format__", "__str__"), "join": ITER}
# A known builtin receiver's method is C code, but it runs dunders of its arguments: dict.get hashes the key,
# list.extend iterates, list.index compares.  (builtin type, method) -> (dunders, argument positions or None
# for all).  Known omission: str.encode / bytes.decode with a codec name run registered codec search functions.
BUILTIN_METHOD_HOOKS = {
    ("dict", "get"): (HASH, (0,)), ("dict", "pop"): (HASH, (0,)), ("dict", "setdefault"): (HASH, (0,)),
    ("dict", "update"): (MAPPING + ITER + HASH, None), ("dict", "fromkeys"): (ITER + HASH, (0,)),
    ("set", "add"): (HASH, None), ("set", "discard"): (HASH, None), ("set", "remove"): (HASH, None),
    ("list", "extend"): (ITER, None), ("list", "index"): (("__eq__",), (0,)), ("list", "count"): (("__eq__",), None),
    ("list", "remove"): (("__eq__",), None), ("list", "insert"): (("__index__",), (0,)),
    ("list", "pop"): (("__index__",), (0,)), ("tuple", "index"): (("__eq__",), (0,)),
    ("tuple", "count"): (("__eq__",), None), ("str", "join"): (ITER, None),
    ("str", "format"): (("__format__", "__str__", "__repr__", "__getitem__"), None),
    ("str", "format_map"): (("__getitem__", "__format__", "__str__"), None), ("str", "translate"): (("__getitem__",), None),
    ("bytes", "join"): (ITER + ("__buffer__",), None), ("bytearray", "extend"): (ITER + ("__index__",), None),
}
for _set_type in ("set", "frozenset"):
    for _method in ("union", "intersection", "difference", "symmetric_difference", "issubset", "issuperset",
                    "isdisjoint", "update", "intersection_update", "difference_update"):
        if _set_type == "set" or "update" not in _method:
            BUILTIN_METHOD_HOOKS[(_set_type, _method)] = (ITER + HASH, None)
BUILTIN_METHOD_HOOK_NAMES = {method for _, method in BUILTIN_METHOD_HOOKS}
# getattr(...), vars(), __import__(...) and friends give back a value nothing here can type
DYNAMIC_RESULTS = {"getattr", "__import__", "importlib.import_module", "eval", "vars", "globals", "locals"}
# process-wide state whose mutation changes what child processes see or what a later import runs; counted only
PROCESS_STATE = ("os.environ", "sys.path", "sys.modules", "sys.meta_path", "sys.path_hooks", "sys.path_importer_cache")
MUTATORS = {"append", "extend", "insert", "pop", "popitem", "remove", "clear", "update", "setdefault", "add", "discard"}
# builtin calls whose result is an exact builtin value, whatever the argument
BUILTIN_RESULT = {"isinstance", "issubclass", "hasattr", "callable", "len", "bool", "int", "float", "complex",
                  "str", "bytes", "bytearray", "repr", "ascii", "format", "hash", "id", "ord", "chr", "bin",
                  "hex", "oct", "sorted", "list", "tuple", "dict", "set", "frozenset", "any", "all", "range",
                  "type", "enumerate", "zip", "map", "filter", "reversed", "iter"}
JSON_SOURCES = {"json.loads", "json.load"}  # exact None/bool/int/float/str/list/dict all the way down
# REACH_ANNOTATIONS=concrete: an annotation naming an abstract type says nothing about the class
# (any class can implement Mapping or a Protocol), so the parameter stays untyped.
_CONCRETE_TYPING = {"List", "Dict", "Set", "FrozenSet", "Tuple", "DefaultDict", "OrderedDict", "Counter", "Deque",
                    "ChainMap", "Text", "Pattern", "Match", "Type"}


def abstract_annotation(annotation: str) -> bool:
    root, _, name = annotation.split("[")[0].rpartition(".")
    if root in ("typing", "typing_extensions"):
        return name not in _CONCRETE_TYPING
    return root.startswith("collections.abc") or annotation in ("os.PathLike", "io.IOBase", "io.TextIOBase",
                                                                 "io.RawIOBase", "io.BufferedIOBase")


def truth_leaves(expr: ast.AST):
    """The values a truth test calls __bool__/__len__ on.  `not`, comparisons and `and`/`or` give a
    bool or one of their operands; their operands are tested where those nodes are visited."""
    if isinstance(expr, ast.BoolOp):
        for value in expr.values:
            yield from truth_leaves(value)
    elif isinstance(expr, ast.NamedExpr):
        yield from truth_leaves(expr.value)
    elif not (isinstance(expr, ast.Compare) or (isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not))):
        yield expr


# Frozen from the reviewed CPython 3.13 standard-library class surface used by
# this analyzer.  Interpreter upgrades do not silently expand the Tier-T
# assumption: additions require a source change and fresh review.
STDLIB_METHODS = frozenset(
    """
    AF_APPLETALK AF_BLUETOOTH AF_HYPERV AF_INET AF_INET6 AF_IPX AF_IRDA AF_LINK AF_SNA AF_UNSPEC AI_ADDRCONFIG
    AI_ALL AI_CANONNAME AI_NUMERICHOST AI_NUMERICSERV AI_PASSIVE AI_V4MAPPED AND ARITH ASCII ATOM AWAIT BAND
    BOOLEAN_STATES BXOR BinaryIO CDATA_CONTENT_ELEMENTS CMP CONFORM CONTINUOUS CRC Close Context DEBUG DOTALL
    DataError DatabaseError Detach EJECT EXPR Emax Emin Error Etiny Etop FACTOR FORMAT FileHeader GETTERCRE
    IGNORECASE IO IntegrityError InterfaceError InternalError KEEP KEYWORD_ONLY LOCALE MAX_DIGEST_SIZE
    MAX_KEY_SIZE MAX_N MAX_SEEK_READ MIN_READ_SIZE MSG_BCAST MSG_CTRUNC MSG_DONTROUTE MSG_ERRQUEUE MSG_MCAST
    MSG_OOB MSG_PEEK MSG_TRUNC MSG_WAITALL MULTILINE Match NAMED_EXPR NAMED_FLAGS ND NONSPACECRE NOT
    NotSupportedError OPEN_METH OPTCRE OPTCRE_NV OR OperationalError PERSON_SIZE POSITIONAL_ONLY
    POSITIONAL_OR_KEYWORD POWER Pattern ProgrammingError READ SALT_SIZE SECTCRE SHIFT SOCK_DGRAM SOCK_RAW
    SOCK_RDM SOCK_SEQPACKET SOCK_STREAM STRICT TEMPLATE TERM TEST TUPLE TextIO UNICODE UNIQUE VAR_KEYWORD
    VAR_POSITIONAL VERBOSE VERSION WRITABLE WRITE Warning YIELD _ALL_ONES _CHUNK_SIZE _ChoicesPseudoAction
    _DEFAULT_INTERPOLATION _EVENT_READ _EVENT_WRITE _Future__get_result _HEXTET_COUNT _HEX_DIGITS
    _HTMLParser__starttag_text _Info _KEYCRE _Local _MutableMapping__marker _NonCallableMock__get_return_value
    _NonCallableMock__get_side_effect _NonCallableMock__return_value_doc _NonCallableMock__set_return_value
    _NonCallableMock__set_side_effect _OPT_NV_TMPL _OPT_TMPL _ORIGIN _Path__repr _Popen _RealGetContents
    _SECT_TMPL _SEP _Section _SequenceMatcher__chain_b _Stream__read _Stream__write _UserList__cast
    _WARNING_DETAILS _abc_caches_clear _abc_impl _abc_registry_clear _abort _accept _accept_connection
    _accept_connection2 _acquire_restore _active_patches _add _add_action _add_callback
    _add_callback_signalsafe _add_container_actions _add_item _add_multipart _add_reader _add_writer
    _address_class _adjust_process_count _adjust_thread_count _aexit _after_fork _alive _annotation _apply
    _apply_pax_info _args _asdict _assert_is_element _asyncgen_finalizer_hook _asyncgen_firstiter_hook
    _asyncio_future_blocking _at_fork_reinit _attach _attr_type _attributes _base _bind _blksize _block
    _body_types _bootstrap _bootstrap_inner _bound_arguments_cls _break _buffer_decode _buffer_encode
    _call_matcher _call_soon _callback _callbacks _calls_repr _cancel_message _cancelled _check _checkClosed
    _checkReadable _checkSeekable _checkWritable _check_callback _check_can_read _check_can_seek
    _check_can_write _check_close _check_closed _check_conflict _check_default_executor
    _check_for_existing_members_ _check_int_address _check_not_closed _check_packed_address _check_running
    _check_sendfile_params _check_thread _check_timeout _check_value _child_created _class_getitem_inner
    _cleanup _clear_cache _close_and_return_root _close_conn _close_pipe_fds _close_self_pipe _closed _cls_type
    _co_code_adaptive _collect_lines _commit_removals _communicate _compress_hextets _compresslevel
    _connect_sock _constants _context _convert_ _convert_egg_info_reqs_to_simple_reqs _convert_flags
    _convert_to_boolean _coro _counter _create_ _create_async_cb_wrapper _create_async_exit_wrapper
    _create_cb_wrapper _create_connection_transport _create_exit_wrapper _create_gnu_long_header _create_header
    _create_pax_generic_header _create_payload _create_server_getaddrinfo _current _dbg _dealloc_warn
    _decl_otherchars _decodeExtra _decode_pax_field _decoded_counterpart _decref_socketios _dedent _default
    _default_prefix _delete _denominator _deps_from_requires_text _detach _determine_new_args _dict_to_list
    _dirty _disassemble _discover_resolvers _dispatch _div _divmod _do_shutdown _drain_helper _drv _dump
    _dump_registry _encodeFilenameFlags _encode_request _encoded_counterpart _end_offset
    _ensure_fd_no_transport _ensure_resolved _enter _evaluate _exception _execute_child _execute_mock_call
    _exit _exitfunc _expand_help _explode_shorthand_ip_string _extra _extract_from_extended_frame_gen
    _extract_member _extract_mock_name _extract_one _fancy_helper _fancy_replace _field_defaults _field_type
    _fields _file_template _fileobj _fileobj_lookup _fill_text _filter_handle_list _finalizing _find_body
    _find_data_repr_ _find_data_type_ _find_link_target _find_new_ _finish_recvfrom _fix_sentence_endings
    _fix_up_module _fixupChildren _fixupParents _flavour _floordiv _flush _for _for_helper _format
    _format_action _format_action_invocation _format_actions_usage _format_args _format_dict_items
    _format_items _format_line _format_mock_call_signature _format_mock_failure_message _format_namespace_items
    _format_parsed_parts _format_syntax_error _format_text _format_usage _fpclose _from_coprime_ints
    _from_flags _from_iterable _from_parsed_parts _from_text _from_text_for _func_ref _function_helper
    _fut_waiter _get _get_accept_socket _get_address_key _get_args _get_call_arguments
    _get_call_signature_from_name _get_child_mock _get_chunk_left _get_close_waiter _get_codename
    _get_content_length _get_conv _get_default_metavar_for_optional _get_default_metavar_for_positional
    _get_devnull _get_encoder _get_extract_tarinfo _get_filter_function _get_formatter _get_handler
    _get_handles _get_help_string _get_hostport _get_kwargs _get_loop _get_mixins_ _get_nargs_pattern
    _get_networks_key _get_option_tuples _get_optional_actions _get_optional_kwargs _get_params_preserve
    _get_positional_actions _get_positional_kwargs _get_subactions _get_value _get_values _getaddrinfo_debug
    _getitem _getmember _guess_delimiter _guess_quote_and_delimiter _handle_conflict_error
    _handle_conflict_resolve _handle_error _handle_fatal_error _handle_long_word _handle_nonfatal_error _hash
    _hash_basis _hmac _hostinfo _http_vsn _http_vsn_str _implied_dirs _increment_mock_call _indent _index_iter
    _init _init_decrypter _init_hmac _init_old _init_read _init_read_gz _init_write _init_write_gz _initialized
    _initializer_failed _inner _internal_poll _interpolate_some _interpolation_replace _invalid
    _invoke_callbacks _io_refs _ip _ip_int_from_prefix _ip_int_from_string _is_base_error _is_child _is_owned
    _is_protocol _is_runtime_protocol _is_subnet_of _is_textIO _is_text_encoding _iter_indented_subactions
    _iter_namespaces _iterate_directories _join_multiline_values _join_parts _keep_positive _key _key_from_fd
    _kind _launch_processes _lazy_init _legend _line _line_wrapper _lines _lines_cached _link_target
    _linklocal_network _load _load_lines _load_parts _lock _log _log_destroy_pending _log_subprocess
    _log_traceback _loop _loop_factory _loop_self_reading _loopback_network _make _make_cancelled_error
    _make_child_relpath _make_datagram_transport _make_duplex_pipe_transport _make_inheritable _make_multipart
    _make_netmask _make_prefix _make_read_pipe_transport _make_self_pipe _make_socket_transport
    _make_ssl_transport _make_subprocess_transport _make_substitution _make_unbound_method
    _make_write_pipe_transport _mapping _match_argument _match_arguments_partial _max_prefixlen
    _maybe_resume_transport _metavar_formatter _meth_type _mock_add_spec _mock_call _mock_check_sig
    _mock_return_value _mock_set_magics _mock_side_effect _mod _mu _mul _multicast_network _munge_whitespace
    _must_cancel _name _name_from_stem _name_set _netmask_cache _next _normalized_name _notimplemented
    _numerator _on_error_fd_closer _on_sigint _on_task_done _on_timeout _open _open_to_write
    _operator_fallbacks _options _original_line _outer _output _parameter_cls _parameters
    _parse_doctype_attlist _parse_doctype_element _parse_doctype_entity _parse_doctype_notation
    _parse_doctype_subset _parse_hextet _parse_known_args _parse_known_args2 _parse_octet _parse_optional
    _parse_path _parse_whole _parts_normcase _parts_normcase_cached _patch_dict _path _peek_chunked
    _plain_replace _poll _pop_action_class _posix_split_name _pprint_bytearray _pprint_bytes _pprint_chain_map
    _pprint_counter _pprint_dataclass _pprint_default_dict _pprint_deque _pprint_dict _pprint_list
    _pprint_mappingproxy _pprint_ordered_dict _pprint_set _pprint_simplenamespace _pprint_str _pprint_tuple
    _pprint_user_dict _pprint_user_list _pprint_user_string _prefix_from_ip_int _prefix_from_ip_string
    _prefix_from_prefix_string _print_message _private_networks _private_networks_exceptions _proc_builtin
    _proc_gnulong _proc_gnusparse_00 _proc_gnusparse_01 _proc_gnusparse_10 _proc_member _proc_pax _proc_sparse
    _process_events _process_self_data _public_network _push_async_cm_exit _push_cm_exit _push_exit_callback
    _put _qformat _qname _qsize _randbelow _randbelow_with_getrandbits _randbelow_without_getrandbits
    _raw_paths _raw_time _read _read1 _read1_chunked _read2 _read_and_discard_trailer _read_args_from_files
    _read_chunked _read_defaults _read_dist_info_reqs _read_egg_info_reqs _read_eof _read_files_distinfo
    _read_files_egginfo_installed _read_files_egginfo_sources _read_from_self _read_gzip_header
    _read_next_chunk_size _read_readable _read_status _readerthread _readinto_chunked _real_close _recreate_cm
    _recursion_count _register _register_with_iocp _registered_with_atexit _registry _registry_get _release
    _release_save _remaining_time _remove_action _remove_reader _remove_writer _replace _replace_writer
    _report_invalid_netmask _repr _repr_info _reserved_network _reserved_networks _reset_internal_locks
    _resolve_filename _resolve_prefix_name _result _return_annotation _reverse_pointer _rewind _richcmp _rmtree
    _rolled _root _run _run_once _safe_read _safe_readinto _safe_repr _sample _sanitize_windows_name _scan_name
    _scandir _scheduled _scope_id _scrub_removals _search_paths _select _select_for_exit _select_from
    _selector_cls _send_output _send_request _sendfile_fallback _sendfile_native _sendfile_use_send
    _sendfile_use_sendfile _set_coroutine_origin_tracking _set_ident _set_native_id _set_tstate_lock _setevents
    _setroot _shutdown _sigma _signature _sitelocal_network _sock_accept _sock_connect _sock_connect_cb
    _sock_read_done _sock_recv _sock_recv_into _sock_recvfrom _sock_recvfrom_into _sock_sendall
    _sock_sendfile_fallback _sock_sendfile_native _sock_sendto _sock_write_done _source_traceback
    _sparse_structs _spawn_process _split _split_addr_prefix _split_chunks _split_line _split_lines
    _split_scope_id _start _start_executor_manager_thread _start_method _start_serving _state _stdin_write
    _stop _stop_accept_futures _stop_serving _str _str_literal_helper _str_normcase _str_normcase_cached
    _stream _stream_reader _string_from_ip_int _styles _sub _tab_newline_replace _table_template _tail
    _tail_cached _timer_handle_cancelled _translate_newlines _tunnel _type_params_helper _unify_values
    _unpatch_dict _unregister _unspecified_address _update_crc _userinfo _valid _validate _validate_host
    _validate_method _validate_path _validate_value_types _varname_from_oparg _version _vformat _wait
    _wait_cancel _wait_for_data _wait_for_handle _wait_for_tstate_lock _wake_up_first _wake_up_next _wakeup
    _wakeup_next _wakeup_waiter _warn _when _windows_illegal_name_trans_table _wrap_chunks _wrap_ipv6
    _write_constant _write_docstring _write_docstring_and_traverse_body _write_end_record _write_fstring_inner
    _write_gzip_header _write_raw _write_section _write_str_avoiding_backslashes _write_to_self _writecheck a
    abort abs absolute accept accept_pipe aclose acquire add addFilter addHandler add_alternative add_argument
    add_argument_group add_arguments add_attachment add_done_callback add_header add_mutually_exclusive_group
    add_note add_parser add_reader add_related add_section add_signal_handler add_subparsers add_text add_usage
    add_whitespace add_writer addfile address_exclude adjusted ag_await ag_code ag_frame ag_running
    ag_suspended alive anchor annotation annotations append appendleft apply_defaults arg argrepr args
    arguments argval arraysize as_bytes as_integer_ratio as_posix as_string as_tuple as_uri asctime_format
    asctime_search asend asname assert_any_await assert_any_call assert_awaited assert_awaited_once
    assert_awaited_once_with assert_awaited_with assert_called assert_called_once assert_called_once_with
    assert_called_with assert_has_awaits assert_has_calls assert_not_awaited assert_not_called astimezone at
    at_eof atexit athrow attach attach_mock attr attrib attribute_name authkey auto_open autocommit await_args
    await_args_list await_count b backup before_get before_read before_set before_write begin betavariate
    bidirectional bind bind_partial binomialvariate binop binop_precedence binop_rassoc bit_count bit_length
    blobopen block block_size blocksize body_encode boolop_precedence boolops bound braceidpattern
    broadcast_address broken buffer buffer_info buffer_updated buffered builtins bytes bytes_le byteswap
    bz2open c_contiguous cache_clear cache_info callHandlers call_args call_args_list call_at call_count
    call_exception_handler call_later call_list call_soon call_soon_threadsafe callback called can_write_eof
    cancel cancelled cancelling canonical capitalize capitals casefold cast category cause cdf cell_contents
    center characters characters_written charbuffertype check check_for_whole_start_tag check_returncode
    check_unused_args children children_system children_user chksum chmod choice choices chown clamp cleanup
    cleanup_called clear clear_cdata_mode clear_content clear_flags clear_traps clock_seq clock_seq_hi_variant
    clock_seq_low close close_called closed closefd cmpops co_argcount co_cellvars co_code co_consts
    co_exceptiontable co_filename co_firstlineno co_flags co_freevars co_kwonlyargcount co_lines co_linetable
    co_lnotab co_name co_names co_nlocals co_positions co_posonlyargcount co_qualname co_stacksize co_varnames
    code_context col_offset colno columns combine combining comment commit communicate compare compare_networks
    compare_signal compare_total compare_total_mag compat compress compress_size compress_type compressed
    configure_mock conjugate connect connect_accepted_socket connect_ex connect_pipe connect_read_pipe
    connect_write_pipe connection connection_lost connection_made contiguous convert_arg_line_to_args
    convert_field converter converters copy copy_abs copy_decimal copy_negate copy_sign copy_with count
    cr_await cr_code cr_frame cr_origin cr_running cr_suspended createLock create_aggregate create_collation
    create_connection create_datagram_endpoint create_decimal create_decimal_from_float create_function
    create_future create_gnu_header create_mock create_module create_pax_global_header create_pax_header
    create_pipe_connection create_server create_system create_task create_unix_connection create_unix_server
    create_ustar_header create_version create_window_function critical ctime currsize cursor cwd daemon data
    data_encoding data_received datagram_received date date_time day days debug debuglevel decimal decode
    decomposition decompress decorate_async_callable decorate_callable decorate_class decoration_helper default
    default_exception_handler default_factory default_format default_msec_format default_port
    default_time_format defaults defining_class del_param deleter delimit delimit_if delimiter denominator
    depth dereference description deserialize detach devmajor devminor difference difference_update digest
    digest_size digit digits dims dis disable discard discover dist divide divide_int divmod do_visit_try done
    doublequote drain drive dst dup east_asian_width elapsed elements emit empty enable_load_extension encode
    encoding end end_col_offset end_colno end_lineno end_offset end_section endheaders endpos endswith
    enter_async_context enter_context entity entry_points eof eof_received eq errno error error_leader
    error_received errorlevel errors escape_brackets escapechar events exact_type exc exc_traceback exc_type
    exc_value exception exec_module execute executemany executescript exists exit exitcode exp expand
    expandtabs expanduser expired exploded exponent expovariate extend extendleft external_attr extra extract
    extract_version extractall extractfile extraction_filter extras f_back f_bavail f_bfree f_blocks f_bsize
    f_builtins f_code f_contiguous f_favail f_ffree f_files f_flag f_frsize f_fsid f_globals f_lasti f_lineno
    f_locals f_namemax f_trace f_trace_lines f_trace_opcodes family fatal fd feed feed_data feed_eof fetchall
    fetchmany fetchone field_spec fieldnames fields file_encoding file_size filename filename2 fileno fileobj
    fileobject files fill filter find findCaller find_distributions find_longest_match find_spec findall
    finditer findtext finish_socket_func flag_bits flags flush fma fmt_spec fold format formatException
    formatFooter formatHeader formatMessage formatStack formatTime format_exception_only format_field
    format_frame_summary format_help format_map format_spec format_usage fp fragment frame free freeze
    from_bytes from_callable from_decimal from_exception from_file from_float from_iterable from_list from_name
    from_samples from_traceback frombuf frombytes fromfile fromhex fromisocalendar fromisoformat fromkeys
    fromlist fromordinal fromtarfile fromtimestamp fromunicode fromutc frozen full fullmatch func function
    gammavariate gauss generic_visit get getChild getChildren getEffectiveLevel getLogger getMessage getName
    get_all get_body get_body_encoding get_boundary get_buffer get_charset get_charsets get_child_watcher
    get_code get_content get_content_charset get_content_disposition get_content_maintype get_content_subtype
    get_content_type get_context get_coro get_debug get_default get_default_type get_event_loop
    get_exception_handler get_extra_info get_field get_filename get_grouped_opcodes get_identifiers get_info
    get_inheritable get_key get_loop get_map get_matching_blocks get_name get_nowait get_opcodes get_original
    get_output_charset get_param get_params get_payload get_pid get_pipe_transport get_precedence get_protocol
    get_proxy_response_headers get_raw_docstring get_returncode get_source get_stack get_starttag_text
    get_task_factory get_token get_type_comment get_unixfrom get_value get_write_buffer_limits
    get_write_buffer_size getaddrinfo getallmatchingheaders getblocking getboolean getbuffer getcode
    getcomptype getconfig getfloat getheader getheaders getinfo getint getlimit getmember getmembers
    getnameinfo getnames getpeername getpos getrandbits getresponse getroot getsockname getsockopt getstate
    gettarinfo getter gettimeout geturl getvalue gi_code gi_frame gi_running gi_suspended gi_yieldfrom gid glob
    globals gname goahead group groupdict groupindex groups guard gzopen handle handleError handle_charref
    handle_comment handle_data handle_decl handle_endtag handle_entityref handle_pi handle_startendtag
    handle_starttag hardlink_to hasHandlers has_header has_option has_section hash hashvalue header_encode
    header_encode_lines header_offset hex hexdigest hits home hostmask hostname hosts hour ident idpattern
    ignore_zeros imag in_transaction indent index info infolist init inode insert int intercept interleave
    internal_attr interrupt intersection intersection_update inv_cdf invalidate_caches ioctl ip ipv4_mapped
    isDaemon isEnabledFor isSet is_absolute is_alive is_attachment is_block_device is_canonical is_char_device
    is_closed is_closing is_dir is_fifo is_file is_finite is_global is_infinite is_integer is_jump_target
    is_junction is_link_local is_loopback is_mount is_multicast is_multipart is_nan is_normal is_normalized
    is_package is_private is_qnan is_reading is_relative_to is_reserved is_running is_safe is_serving is_set
    is_signed is_site_local is_snan is_socket is_subnormal is_symlink is_unspecified is_valid is_zero isalnum
    isalpha isascii isatty isblk ischr isclosed isdecimal isdev isdigit isdir isdisjoint isfifo isfile
    isidentifier islnk islower isnumeric isocalendar isoformat isolation_level isoweekday isprintable
    isreadable isrecursive isreg isspace issparse issubset issuperset issym istitle isupper item_separator
    items items_view itemsize iter iter_attachments iter_parts iter_unpack iterdir iterdump iterencode iterfind
    itertext itervaluerefs join joinpath json key key_separator keyrefs keys keywords kill kind kw_only kwarg
    kwargs kwonlyargs kwonlydefaults lastgroup lasti lastindex lastrowid lchmod left_end_offset
    legacy_normalize legacy_normalized level limit_denominator line line_buffering lineno lines lineterminator
    linkname linkpath list listen ljust ln load load_extension load_module locals locate locate_file locked log
    log10 logb logical_and logical_invert logical_or logical_xor lognormvariate lookup lower lstat lstrip
    machine make makeRecord make_alternative make_file make_mixed make_related make_table makedev makedir
    makeelement makefifo makefile makelink maketrans makeunknown manager map match match_args matches max
    max_mag max_prefixlen maxlen maxsize maybe_newline mean median member metadata microsecond microseconds min
    min_mag minus minute mirrored misses mkdir mock_add_spec mock_calls mode modify module month most_common
    move_to_end mro msg mtime multiply myfileobj n n_fields n_sequence_fields n_unnamed_fields n_waiting name
    name_from namelist names native_id nbytes ndim needs_input netloc new_child new_event_loop newlines next
    next_minus next_plus next_toward node nodename nonlocals normalize normalized normalvariate notify
    notifyAll notify_all now num_addresses number_class numerator numeric obj object offset offset_data opcode
    open opname optional_vars options optionxform order orig_filename overlap overlaps owner pack pack_into
    packed parameters params parent parents paretovariate parse parse_args parse_bogus_comment parse_comment
    parse_declaration parse_endtag parse_html_declaration parse_intermixed_args parse_known_args
    parse_known_intermixed_args parse_marked_section parse_pi parse_starttag parser parties partition parts
    password path pattern pause_reading pause_writing pax_headers pdf peek pformat pi pid pipe_connection_lost
    pipe_data_received plus poll pop pop_all pop_source popitem popleft port pos positions power pprint prec
    prefixlen prepend prev primary_char print print_file_and_line print_help print_stack print_usage printdir
    process process_exited proto punctuation_chars push push_async_callback push_async_exit push_source
    push_token put put_nowait putheader putrequest qsize quantiles quantize query quick_ratio quotechar quoting
    radix randbytes randint random randrange ratio raw raw_decode raw_items re read read1 read_binary
    read_bytes read_dict read_events read_file read_string read_text read_token readable readall readexactly
    readinto readinto1 readline readlines readlink readonly readuntil real real_quick_ratio reconfigure recv
    recv_into recvfrom recvfrom_into register regs relative_to release remainder remainder_near remove
    removeFilter removeHandler remove_done_callback remove_option remove_reader remove_section
    remove_signal_handler remove_writer removeprefix removesuffix rename replace replace_header repr request
    require_parens requires reschedule reserved reset reset_mock resolution resolve resolve_dir response_class
    rest result resume_reading resume_writing return_annotation return_value returns reverse reverse_pointer
    rewind rfind rglob right_start_offset rindex rjust rmdir rng rollback rollover root rotate rounding
    row_factory rowcount rpartition rsplit rstrip run run_forever run_in_executor run_until_complete running s
    safe safe_substitute same_quantum samefile sample samples scaleb scan scanner scheme scope_id search second
    secondary_char seconds section_pairs sections seed seek seekable select select_from send send_signal
    sendall sendfile sendto sentence_end_re sentinel serialize serve_forever set setDaemon setFormatter
    setLevel setLogRecordFactory setLoggerClass setName setStream set_authorizer set_boundary set_cdata_mode
    set_charset set_child_watcher set_content set_debug set_debuglevel set_default_executor set_default_type
    set_defaults set_event_loop set_exception set_exception_handler set_inheritable set_loop set_name set_param
    set_payload set_precedence set_progress_handler set_protocol set_raw set_result
    set_running_or_notify_cancel set_seq1 set_seq2 set_seqs set_task_factory set_trace_callback set_transport
    set_tunnel set_type set_unixfrom set_write_buffer_limits setblocking setconfig setdefault setinputsizes
    setlimit setoutputsize setpassword setsockopt setstate setter settimeout shape share shift shuffle shutdown
    shutdown_asyncgens shutdown_default_executor side_effect sign signature sixtofour size skipinitialspace
    slope slots sniff sock_accept sock_connect sock_recv sock_recv_into sock_recvfrom sock_recvfrom_into
    sock_sendall sock_sendfile sock_sendto sockets sort sourcehook span sparse split splitlines sqrt st_atime
    st_atime_ns st_birthtime st_birthtime_ns st_ctime st_ctime_ns st_dev st_file_attributes st_gid st_ino
    st_mode st_mtime st_mtime_ns st_nlink st_reparse_tag st_size st_uid start start_ns start_section
    start_serving start_serving_pipe start_tls starts_line startswith stat stdev stdout stem step stop stream
    strerror strftime strict strides string strip strptime sub submit subn subnet_of subnets suboffsets
    subprocess_exec subprocess_shell substitute subtract suffix suffixes supernet supernet_of swapcase
    symlink_to symmetric_difference symmetric_difference_update sysname system tag tail tarfile target tarinfo
    taropen task_done tb_frame tb_lasti tb_lineno tb_next tell teredo terminate terminator testzip text
    text_factory thread throw time time_hi_version time_low time_mid timeout timestamp timetuple timetz title
    tm_gmtoff tm_hour tm_isdst tm_mday tm_min tm_mon tm_sec tm_wday tm_yday tm_year tm_zone to_bytes
    to_eng_string to_integral to_integral_exact to_integral_value to_sci_string tobuf tobytes today tofile
    tokeneater tolist toordinal toreadonly total total_changes total_seconds touch tounicode translate
    transport traverse triangular truncate type type_comment typecode tzinfo tzname uid uname unbound uncancel
    unicode_whitespace_trans unidata_version uniform union universal_newlines unknown unknown_decl unlink unop
    unop_precedence unpack unpack_from unregister unsafe unsafe_hash untokenize unused_data update updatepos
    upper url urn used user username usesTime utc utcfromtimestamp utcnow utcoffset utctimetuple utime valid
    validate validation_pattern value valuerefs values vararg varargs variance variant varkw version vformat
    visit visit_AnnAssign visit_Assert visit_Assign visit_AsyncFor visit_AsyncFunctionDef visit_AsyncWith
    visit_Attribute visit_AugAssign visit_Await visit_BinOp visit_BoolOp visit_Break visit_Call visit_ClassDef
    visit_Compare visit_Constant visit_Continue visit_Delete visit_Dict visit_DictComp visit_Ellipsis
    visit_ExceptHandler visit_Expr visit_For visit_FormattedValue visit_FunctionDef visit_FunctionType
    visit_GeneratorExp visit_Global visit_If visit_IfExp visit_Import visit_ImportFrom visit_JoinedStr
    visit_Lambda visit_List visit_ListComp visit_Match visit_MatchAs visit_MatchClass visit_MatchMapping
    visit_MatchOr visit_MatchSequence visit_MatchSingleton visit_MatchStar visit_MatchValue visit_Module
    visit_Name visit_NamedExpr visit_Nonlocal visit_ParamSpec visit_Pass visit_Raise visit_Return visit_Set
    visit_SetComp visit_Slice visit_Starred visit_Subscript visit_Try visit_TryStar visit_Tuple visit_TypeAlias
    visit_TypeVar visit_TypeVarTuple visit_UnaryOp visit_While visit_With visit_Yield visit_YieldFrom
    visit_alias visit_arg visit_arguments visit_comprehension visit_keyword visit_match_case visit_withitem
    volume vonmisesvariate wait wait_closed wait_for wait_for_handle walk warn warning weakref_slot weekday
    weibullvariate when winerror with_hostmask with_name with_netmask with_prefixlen with_segments with_stem
    with_suffix with_traceback wordsep_re wordsep_simple_re wrap writable write write_bytes write_c14n
    write_eof write_text write_through writeheader writelines writepy writerow writerows writestr xzopen year
    zfill zip_children zscore
    """.split()
)


def say(text: str) -> None:
    print(time.strftime("%H:%M:%S"), text, flush=True)


@dataclass
class Definition:
    qual: str
    path: str
    module: str
    node: ast.AST | None            # None: the module's top-level code
    class_qual: str | None = None   # the class a method is defined directly in
    params: tuple[str, ...] = ()
    annotations: dict[str, str | None] = field(default_factory=dict)
    returns: str | None = None
    channels: int = 0
    gaps: int = 0                   # strict graph
    gaps_n: int = 0                 # name-dispatch graph
    edges: set[str] = field(default_factory=set)
    edges_name: set[str] = field(default_factory=set)
    gap_sites: collections.Counter = field(default_factory=collections.Counter)
    callback_params: set[str] = field(default_factory=set)
    enclosing: str | None = None    # the definition this one is nested in
    outer_class: str | None = None  # the class of the nearest enclosing method
    param_receivers: list = field(default_factory=list)  # (own parameter, method, call node)
    other_param_sites: int = 0      # untyped-parameter receivers that are not this definition's own
    edges_inferred: set[str] = field(default_factory=set)
    inferred_channels: int = 0
    inferred_gaps: int = 0
    param_inferred_ok: bool = False
    implicit_params: list = field(default_factory=list)  # (own parameter, dunders, site node, 'op' or 'attr')
    other_implicit_params: collections.Counter = field(default_factory=collections.Counter)
    implicit_inferred_ok: dict = field(default_factory=dict)  # 'op'/'attr' -> every implicit parameter site typed


@dataclass
class ClassInfo:
    qual: str
    path: str
    raw_bases: list[str]
    bases: list[str] = field(default_factory=list)
    external_bases: list[str] = field(default_factory=list)
    methods: dict[str, str] = field(default_factory=dict)
    attr_types: dict[str, set[str]] = field(default_factory=dict)
    attr_params: dict[str, tuple[str, str]] = field(default_factory=dict)


class Program:
    def __init__(self, files: dict[str, str]) -> None:
        self.paths = sorted(path for path in files if path.endswith(".py"))
        self.trees: dict[str, ast.Module] = {}
        self.syntax_errors: dict[str, str] = {}
        self.module_of: dict[str, str] = {}
        self.module_path: dict[str, str] = {}
        for path in self.paths:
            try:
                tree = ast.parse(SOURCE_OVERRIDES.get(path) or (ROOT / path).read_bytes(), filename=path)
            except (SyntaxError, ValueError, OSError) as exc:
                self.syntax_errors[path] = f"{type(exc).__name__}: {exc}"[:200]
                continue
            self.trees[path] = tree
            self.module_of[path] = audit._preferred_module_name(path)
            for name in audit._module_names(path):
                self.module_path.setdefault(name, path)
        # sys.path-local names: pytest prepends a test file's directory, a script's directory is on
        # its path, and src layouts import from src.  Every unambiguous path suffix is registered
        # (precise names above win); ambiguous suffixes are recorded and resolve to a named gap.
        suffixes: dict[str, set[str]] = collections.defaultdict(set)
        for path in self.trees:
            parts = path[:-3].split("/")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            for size in range(1, len(parts)):
                name = ".".join(parts[-size:])
                if name.partition(".")[0] not in STDLIB:
                    suffixes[name].add(path)
        self.local_names = 0
        self.ambiguous_modules: set[str] = set()
        for name, paths in suffixes.items():
            if name in self.module_path:
                continue
            if len(paths) == 1:
                self.module_path[name] = next(iter(paths))
                self.local_names += 1
            else:
                self.ambiguous_modules.add(name)
        self.package_prefixes = {".".join(name.split(".")[:size]) for name in self.module_path
                                 for size in range(1, name.count(".") + 1)}
        self.defs: dict[str, Definition] = {}
        self.classes: dict[str, ClassInfo] = {}
        self.top_names: dict[str, dict[str, str]] = {}
        self.top_values: dict[str, dict[str, ast.AST]] = {}
        self.top_values_all: dict[str, dict[str, list[ast.AST]]] = collections.defaultdict(
            lambda: collections.defaultdict(list))
        self.aliases: dict[str, dict[str, str]] = {}
        self.import_edges: dict[str, set[str]] = collections.defaultdict(set)
        self.third_party_imports: dict[str, list[str]] = collections.defaultdict(list)
        self.methods_by_name: dict[str, set[str]] = collections.defaultdict(set)
        self.subclasses: dict[str, set[str]] = collections.defaultdict(set)
        self.call_sites: dict[str, list[tuple[str, ast.Call, int]]] = collections.defaultdict(list)
        self.counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        self.fanout: list[int] = []
        self.properties: dict[str, set[str]] = collections.defaultdict(set)
        self.decorated: dict[str, set[str]] = collections.defaultdict(set)  # decorator def -> decorated defs
        self._visitors: dict[str, BodyVisitor] = {}

    def module_pseudo(self, module: str) -> str:
        return module + ".<module>"

    def project_module(self, dotted: str) -> str | None:
        """Census path of the longest project-module prefix of ``dotted``."""
        parts = dotted.split(".")
        for size in range(len(parts), 0, -1):
            path = self.module_path.get(".".join(parts[:size]))
            if path is not None:
                return path
        return None

    def classify_root(self, dotted: str) -> str:
        if not dotted:
            return "unknown"
        if self.project_module(dotted) is not None or dotted in self.package_prefixes:
            return "project"
        parts = dotted.split(".")
        if any(".".join(parts[:size]) in self.ambiguous_modules for size in range(1, len(parts) + 1)):
            return "ambiguous"
        top = dotted.partition(".")[0]
        if top in STDLIB:
            return "stdlib"
        if top in review_operations.STATIC_BUILTIN_NAMES:
            return "builtin"
        return "third"

    def is_external(self, dotted: str) -> bool:
        return self.classify_root(dotted) in ("third", "ambiguous")

    # ----- collection -------------------------------------------------------------------------------
    def collect(self) -> None:
        for path, tree in self.trees.items():
            self.aliases[path], self.top_names[path], self.top_values[path] = {}, {}, {}
            self._aliases(path, tree)
        for path, tree in self.trees.items():
            module = self.module_of[path]
            self.defs[self.module_pseudo(module)] = Definition(self.module_pseudo(module), path, module, None)
            self._definitions(path, module, tree.body, (), None)
            for statement in self._module_statements(tree.body):  # module scope, through if/try/with/for/while
                if isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        if isinstance(target, ast.Name):
                            self.top_values[path].setdefault(target.id, statement.value)
                            self.top_values_all[path][target.id].append(statement.value)
                elif isinstance(statement, ast.AnnAssign) and statement.value and isinstance(statement.target, ast.Name):
                    self.top_values[path].setdefault(statement.target.id, statement.value)
                    self.top_values_all[path][statement.target.id].append(statement.value)
        for info in self.classes.values():
            for raw in info.raw_bases:
                resolved = self.class_qual(info.path, raw)
                (info.bases if resolved else info.external_bases).append(resolved or raw)
            for base in info.bases:
                self.subclasses[base].add(info.qual)
        changed = True
        while changed:
            changed = False
            for base in list(self.subclasses):
                subs = self.subclasses[base]
                extra = set().union(*(self.subclasses.get(s, set()) for s in list(subs))) - subs
                if extra:
                    subs |= extra
                    changed = True
        for path, tree in self.trees.items():
            self._import_edges(path, tree)
            parts = self.module_of[path].split(".")
            for size in range(1, len(parts)):  # parent packages run first
                parent = self.module_path.get(".".join(parts[:size]))
                if parent is not None and parent != path:
                    self.import_edges[self.module_pseudo(self.module_of[path])].add(
                        self.module_pseudo(self.module_of[parent]))

    def _aliases(self, path: str, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    bound = item.asname or item.name.partition(".")[0]
                    self.aliases[path][bound] = item.name if item.asname else bound
            elif isinstance(node, ast.ImportFrom):
                base = audit._absolute_import_name(node.module, node.level, current_path=path)
                for item in node.names:
                    if item.name != "*":
                        self.aliases[path][item.asname or item.name] = ".".join(filter(None, (base, item.name)))

    def _import_edges(self, path: str, tree: ast.Module) -> None:
        """Top-level imports only (imports inside functions run when the function runs)."""
        pseudo = self.module_pseudo(self.module_of[path])
        for node in self._top_level_nodes(tree.body):
            if isinstance(node, ast.Import):
                targets = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = audit._absolute_import_name(node.module, node.level, current_path=path)
                targets = [base] + [".".join(filter(None, (base, item.name))) for item in node.names if item.name != "*"]
            else:
                continue
            for imported in targets:
                kind = self.classify_root(imported)
                if kind == "project":
                    parts = imported.split(".")
                    for size in range(1, len(parts) + 1):
                        target = self.module_path.get(".".join(parts[:size]))
                        if target is not None and target != path:
                            self.import_edges[pseudo].add(self.module_pseudo(self.module_of[target]))
                elif kind in ("third", "ambiguous") and imported == targets[0]:
                    self.third_party_imports[path].append(imported)

    def _module_statements(self, body: list[ast.stmt]):
        """Simple statements in module scope, through if/try/with/for/while (not class or def bodies)."""
        for statement in body:
            if isinstance(statement, ast.If) and "TYPE_CHECKING" in ast.unparse(statement.test):
                yield from self._module_statements(statement.orelse)
            elif isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                yield from self._module_statements(statement.body)
                yield from self._module_statements(statement.orelse)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                yield from self._module_statements(statement.body)
            elif isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                for block in (statement.body, *[h.body for h in statement.handlers], statement.orelse,
                              statement.finalbody):
                    yield from self._module_statements(block)
            else:
                yield statement

    def _top_level_nodes(self, body: list[ast.stmt]):
        """What runs at import time: statements and the headers of compound statements, class
        bodies, decorators, defaults and bases.  TYPE_CHECKING blocks and function bodies are skipped.
        Compound statements are never yielded whole, so nothing is visited twice."""
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield from statement.decorator_list
                yield from statement.args.defaults
                yield from (d for d in statement.args.kw_defaults if d is not None)
                continue
            if isinstance(statement, ast.ClassDef):
                yield from statement.decorator_list
                yield from statement.bases
                yield from (k.value for k in statement.keywords)
                yield from self._top_level_nodes(statement.body)
                continue
            if isinstance(statement, ast.If):
                if "TYPE_CHECKING" in ast.unparse(statement.test):
                    yield from self._top_level_nodes(statement.orelse)
                    continue
                yield statement.test
                yield from self._top_level_nodes(statement.body)
                yield from self._top_level_nodes(statement.orelse)
                continue
            if isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                yield from self._top_level_nodes(statement.body)
                for handler in statement.handlers:
                    if handler.type is not None:
                        yield handler.type
                    yield from self._top_level_nodes(handler.body)
                yield from self._top_level_nodes(statement.orelse)
                yield from self._top_level_nodes(statement.finalbody)
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                yield from statement.items
                yield from self._top_level_nodes(statement.body)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                yield statement.iter
                yield from self._top_level_nodes(statement.body)
                yield from self._top_level_nodes(statement.orelse)
                continue
            if isinstance(statement, ast.While):
                yield statement.test
                yield from self._top_level_nodes(statement.body)
                yield from self._top_level_nodes(statement.orelse)
                continue
            yield statement

    def _definitions(self, path: str, module: str, body: list[ast.stmt], scope: tuple[str, ...],
                     class_qual: str | None, enclosing: str | None = None, outer_class: str | None = None) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = ".".join((module, *scope, node.name))
                args = node.args
                listed = (*args.posonlyargs, *args.args, *args.kwonlyargs)
                params = tuple(a.arg for a in listed) + tuple(a.arg for a in (args.vararg, args.kwarg) if a is not None)
                annotations = {a.arg: self.annotation(path, a.annotation) for a in listed if a.annotation is not None}
                self.defs[qual] = Definition(qual, path, module, node, class_qual, params, annotations,
                                             self.annotation(path, node.returns) if node.returns else None,
                                             enclosing=enclosing, outer_class=outer_class)
                if not scope:
                    self.top_names[path][node.name] = qual
                if class_qual is not None:
                    self.classes[class_qual].methods[node.name] = qual
                    # Shipped mode: a witness's method is never a production name-dispatch target, so a name
                    # defined only in tests falls through to the 'method: unknown name' gap.
                    target = not SHIPPED_ONLY or shipped(path)
                    if target:
                        self.methods_by_name[node.name].add(qual)
                    for decorator in node.decorator_list:
                        name = audit._dotted_name(decorator) or ""
                        if target and name.rpartition(".")[2] in ("property", "cached_property", "setter", "getter",
                                                                  "deleter"):
                            self.properties[node.name].add(qual)
                self._definitions(path, module, node.body, (*scope, node.name), None, qual,
                                  class_qual or outer_class)
            elif isinstance(node, ast.ClassDef):
                qual = ".".join((module, *scope, node.name))
                raw_bases = [audit._aliased_name(audit._dotted_name(b) or ast.unparse(b), self.aliases[path])
                             for b in node.bases]
                self.classes[qual] = ClassInfo(qual, path, raw_bases)
                if not scope:
                    self.top_names[path][node.name] = qual
                self._definitions(path, module, node.body, (*scope, node.name), qual, enclosing, outer_class)
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                for block in (getattr(node, "body", []), getattr(node, "orelse", []), getattr(node, "finalbody", []),
                              *[h.body for h in getattr(node, "handlers", [])]):
                    self._definitions(path, module, block, scope, class_qual, enclosing, outer_class)

    def visitor(self, qual: str) -> "BodyVisitor":
        """A cached visitor, used only to read a definition's local bindings."""
        if qual not in self._visitors:
            self._visitors[qual] = BodyVisitor(self, self.defs[qual])
        return self._visitors[qual]

    def annotation(self, path: str, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        text = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.split("[")[0].split("|")[0].strip()
        else:
            text = audit._dotted_name(node)
            if text is None and isinstance(node, ast.BinOp):
                text = audit._dotted_name(node.left) or audit._dotted_name(node.right)
            if text is None and isinstance(node, ast.Subscript) and audit._dotted_name(node.value) in (
                    "Optional", "typing.Optional"):
                text = audit._dotted_name(node.slice)
        return audit._aliased_name(text, self.aliases.get(path, {})) if text else None

    def class_qual(self, path: str, target: str | None) -> str | None:
        if not target:
            return None
        if target in self.classes:
            return target
        local = self.top_names.get(path, {}).get(target)
        if local in self.classes:
            return local
        module = self.module_of.get(path)
        if module and f"{module}.{target}" in self.classes:
            return f"{module}.{target}"
        resolved = self.resolve(path, target)
        return resolved if resolved in self.classes else None

    def resolve(self, path: str, target: str, depth: int = 0) -> str | None:
        """An aliased dotted name -> a project function, method or class qual."""
        if depth > 6 or not target:
            return None
        if target in self.defs or target in self.classes:
            return target
        first, _, rest = target.partition(".")
        local = self.top_names.get(path, {}).get(first)
        if local is not None:
            candidate = local + ("." + rest if rest else "")
            if candidate in self.defs or candidate in self.classes:
                return candidate
            if local in self.classes and rest and "." not in rest:
                return self.lookup(local, rest)
        parts = target.split(".")
        for size in range(len(parts) - 1, 0, -1):
            head = ".".join(parts[:size])
            head_path = self.module_path.get(head)
            if head_path is None:
                continue
            base, tail = self.module_of[head_path], parts[size:]
            candidate = ".".join((base, *tail))
            if candidate in self.defs or candidate in self.classes:
                return candidate
            if len(tail) == 2 and f"{base}.{tail[0]}" in self.classes:
                return self.lookup(f"{base}.{tail[0]}", tail[1])
            exported = self.aliases.get(head_path, {}).get(tail[0])
            if exported and exported != target and not exported.startswith(target):
                return self.resolve(head_path, ".".join((exported, *tail[1:])), depth + 1)
            return None
        return None

    def lookup(self, class_qual: str, method: str, seen: set[str] | None = None) -> str | None:
        seen = seen if seen is not None else set()
        if class_qual in seen or class_qual not in self.classes:
            return None
        seen.add(class_qual)
        info = self.classes[class_qual]
        if method in info.methods:
            return info.methods[method]
        for base in info.bases:
            found = self.lookup(base, method, seen)
            if found:
                return found
        return None

    def external_bases(self, class_qual: str, seen: set[str] | None = None) -> list[str]:
        seen = seen if seen is not None else set()
        if class_qual in seen or class_qual not in self.classes:
            return []
        seen.add(class_qual)
        info = self.classes[class_qual]
        out = list(info.external_bases)
        for base in info.bases:
            out += self.external_bases(base, seen)
        return out

    def attr_fact(self, class_qual: str, attr: str, seen: set[str] | None = None) -> tuple[str, str | None] | None:
        """An attribute type admitted from reasons.vstd for a class or a project base (REACH_FACTS)."""
        if not FACTS["attrs"]:
            return None
        seen = seen if seen is not None else set()
        if class_qual in seen or class_qual not in self.classes:
            return None
        seen.add(class_qual)
        hit = FACTS["attrs"].get((class_qual, attr))
        if hit is not None:
            return hit
        for base in self.classes[class_qual].bases:
            hit = self.attr_fact(base, attr, seen)
            if hit is not None:
                return hit
        return None

    def is_protocol(self, class_qual: str) -> bool:
        """A typing.Protocol: classes implement it structurally, so its methods are stubs."""
        return any(base.split("[")[0] in ("typing.Protocol", "typing_extensions.Protocol", "Protocol")
                   for base in self.external_bases(class_qual))

    def dispatch(self, class_qual: str, method: str) -> set[str]:
        found = set()
        primary = self.lookup(class_qual, method)
        if primary:
            found.add(primary)
        for sub in self.subclasses.get(class_qual, ()):
            if SHIPPED_ONLY and not shipped(self.classes[sub].path):
                continue  # a test double is a witness, not a production dispatch target
            override = self.classes[sub].methods.get(method)
            if override:
                found.add(override)
        return found

    def constructor(self, class_qual: str) -> tuple[set[str], list[str]]:
        targets = {found for name in ("__init__", "__post_init__", "__new__")
                   if (found := self.lookup(class_qual, name))}
        unsafe = [b for b in self.external_bases(class_qual)
                  if b not in SAFE_EXTERNAL_BASES and self.is_external(b)]
        return targets, unsafe


class BodyVisitor:
    """One definition's own code: its body (or a module's top-level code), lambdas inlined,
    decorators/defaults/bases of nested definitions included, nested bodies excluded."""

    def __init__(self, program: Program, definition: Definition) -> None:
        self.p, self.d, self.path = program, definition, definition.path
        self.aliases = program.aliases[definition.path]
        self.params = set(definition.params)
        self.locals: dict[str, list[tuple[str, ast.AST | None]]] = collections.defaultdict(list)
        self.nested: list[ast.AST] = []
        if definition.node is None:
            self.statements = list(program._top_level_nodes(program.trees[definition.path].body))
            self.top_level = True
        else:
            self.statements = list(definition.node.body)
            self.top_level = False
        self.nodes = [n for s in self.statements for n in self._own_nodes(s)]
        for node in self.nodes:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind(target, ("value", node.value))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.locals[node.target.id].append(("annotation", node.annotation))
                if node.value is not None:
                    self.locals[node.target.id].append(("value", node.value))
            elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                self.locals[node.target.id].append(("value", node.value))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                self._bind(node.target, ("unknown", None))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                self._bind(node.optional_vars, ("value", node.context_expr))
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.locals[node.name].append(("unknown", None))
            elif isinstance(node, ast.Lambda):  # inlined lambdas bind their parameters here
                args = node.args
                for argument in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg):
                    if argument is not None:
                        self.locals[argument.arg].append(("unknown", None))
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                self.locals[node.name].append(("unknown", None))
            elif isinstance(node, ast.MatchMapping) and node.rest:
                self.locals[node.rest].append(("unknown", None))
        if not self.top_level:  # a nested def or class is a local name bound to that definition
            for nested in self.nested:
                qual = f"{definition.qual}.{nested.name}"
                if qual in program.defs or qual in program.classes:
                    self.locals[nested.name].append(("nested", qual))

    def _own_nodes(self, node: ast.AST):
        """Walk one statement of this definition.  Any function or class met here is a nested
        definition: its decorators, defaults and bases run here, its body does not."""
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.nested.append(current)
                stack.extend(current.decorator_list)
                stack.extend(current.args.defaults)
                stack.extend(d for d in current.args.kw_defaults if d is not None)
                continue
            if isinstance(current, ast.ClassDef):
                self.nested.append(current)
                stack.extend(current.decorator_list)
                stack.extend(current.bases)
                stack.extend(k.value for k in current.keywords)
                continue
            yield current
            stack.extend(ast.iter_child_nodes(current))

    def _bind(self, target: ast.AST, value: tuple[str, ast.AST | None]) -> None:
        if isinstance(target, ast.Name):
            self.locals[target.id].append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, ("unknown", None))
        elif isinstance(target, ast.Starred):
            self._bind(target.value, ("unknown", None))

    # ----- recording ---------------------------------------------------------------------------------
    def gap(self, category: str, strict: bool = True, named: bool = True) -> None:
        if strict:
            self.d.gaps |= GAP_BIT[category]
            self.d.gap_sites[category] += 1
        if named:
            self.d.gaps_n |= GAP_BIT[category]

    def channel(self, names) -> None:
        for name in names:
            self.d.channels |= CHANNEL_BIT[name]

    def external(self, dotted: str) -> None:
        """Code outside the census: third-party, or a sys.path-local name that several files could be."""
        if self.p.classify_root(dotted) == "ambiguous":
            self.gap("import: ambiguous sys.path-local module")
            self.p.counts["ambiguous_module"][dotted.partition(".")[0]] += 1
        else:
            self.gap("third-party: call or import")
            self.p.counts["third_party"][dotted.partition(".")[0]] += 1

    def site(self, callee: str, node: ast.Call, offset: int) -> None:
        if SHIPPED_ONLY and not shipped(self.d.path):
            return  # a witness's call site does not type or supply a shipped definition's parameters
        self.p.call_sites[callee].append((self.d.qual, node, offset))

    def run(self) -> None:
        call_funcs = {id(n.func) for n in self.nodes if isinstance(n, ast.Call)}
        for node in self.nodes:
            if isinstance(node, ast.Call):
                self.call(node)
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                raw = audit._dotted_name(node.value)
                if raw and audit._aliased_name(raw, self.aliases) in PROCESS_STATE:
                    self.p.counts["process_state_write"][audit._aliased_name(raw, self.aliases) + "[...]"] += 1
            elif isinstance(node, ast.Attribute):
                raw = audit._dotted_name(node)
                if raw and audit._aliased_name(raw, self.aliases) == "os.environ":
                    self.channel(("environment",))
                if node.attr in self.p.properties and id(node) not in call_funcs and isinstance(node.ctx, ast.Load):
                    self.property_access(node)
            elif isinstance(node, ast.withitem):
                self.context_manager(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)) and not self.top_level:
                if isinstance(node, ast.Import):
                    names = [item.name for item in node.names]
                else:
                    base = audit._absolute_import_name(node.module, node.level, current_path=self.path)
                    names = [base] + [f"{base}.{item.name}" for item in node.names if item.name != "*"]
                for imported in names:
                    kind = self.p.classify_root(imported)
                    target = self.p.module_path.get(imported)
                    if kind == "project" and target is not None:
                        self.d.edges.add(self.p.module_pseudo(self.p.module_of[target]))
                    elif kind in ("third", "ambiguous") and imported == names[0]:
                        self.external(imported)
        if not self.top_level:
            for nested in self.nested:  # a definition may call what it defines (conservative)
                if isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qual = f"{self.d.qual}.{nested.name}"
                    if qual in self.p.defs:
                        self.d.edges.add(qual)
                elif isinstance(nested, ast.ClassDef):
                    prefix = f"{self.d.qual}.{nested.name}."
                    self.d.edges.update(q for q in self.p.defs if q.startswith(prefix) and q.count(".") == prefix.count("."))
        node = self.d.node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:  # calling a decorated function runs the decorator's wrapper
                factory = isinstance(decorator, ast.Call)
                target = decorator.func if factory else decorator
                raw = audit._dotted_name(target)
                resolved = self.p.resolve(self.path, audit._aliased_name(raw, self.aliases)) if raw else None
                if resolved in self.p.defs:
                    self.d.edges.add(resolved)
                    if factory:  # @factory(...): the decorator is a definition nested in the factory
                        prefix = resolved + "."
                        for qual in self.p.defs:
                            if qual.startswith(prefix) and "." not in qual[len(prefix):]:
                                self.p.decorated[qual].add(self.d.qual)
                                self.d.edges.add(qual)
                    else:
                        self.p.decorated[resolved].add(self.d.qual)
        if IMPLICIT != "off":
            self.implicit_sites(call_funcs)
        if FACTS["edges"].get(self.d.qual):  # contract discharge: the supplier reaches what it supplied
            self.d.edges |= FACTS["edges"][self.d.qual]
        for category in FACTS["site_gaps"].get(self.d.qual, ()):  # a gap a reason moved here from a callee
            self.p.counts["fact_site_gap"][category] += 1
            self.gap(category)
            if category == "receiver: untyped parameter":
                self.d.other_param_sites += 1

    # ----- implicit dispatch (REACH_IMPLICIT) ------------------------------------------------------------
    def implicit_sites(self, call_funcs: set[int]) -> None:
        seen: set[tuple[int, str, tuple[str, ...]]] = set()
        for node in self.nodes:
            for operand, names, kind in self.implicit_operands(node, call_funcs):
                key = (id(operand), kind, names)
                if key in seen:
                    continue
                seen.add(key)
                self.p.counts["implicit_construct"][type(node).__name__] += 1
                self.implicit(operand, names, kind)

    def implicit_operands(self, node: ast.AST, call_funcs: set[int]):
        """(operand, dunders it may run, 'op' or 'attr') for each implicit dispatch at one node."""
        if isinstance(node, ast.Compare):
            left = node.left
            for op, right in zip(node.ops, node.comparators):
                name = type(op).__name__
                if name in ("In", "NotIn"):
                    yield left, ("__eq__",), "op"
                    yield right, ("__contains__",) + ITER, "op"
                elif name in _COMPARE:
                    yield left, _COMPARE[name], "op"
                    yield right, _COMPARE[name], "op"
                left = right  # `is` / `is not` run nothing
        elif isinstance(node, ast.BinOp):
            n = _BINOP[type(node.op).__name__]
            names = (f"__{n}__", f"__r{n}__") + (("__str__", "__repr__", "__getitem__") if n == "mod" else ())
            yield node.left, names, "op"
            yield node.right, names, "op"
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                for leaf in truth_leaves(node.operand):
                    yield leaf, TRUTH, "op"
            else:
                yield node.operand, _UNARY[type(node.op).__name__], "op"
        elif isinstance(node, ast.AugAssign):
            n = _BINOP[type(node.op).__name__]
            names = (f"__i{n}__", f"__{n}__", f"__r{n}__")
            yield node.target, names, "op"
            yield node.value, names, "op"
        elif isinstance(node, ast.Subscript):
            names = {ast.Load: ("__getitem__", "__class_getitem__", "__missing__"), ast.Store: ("__setitem__",),
                     ast.Del: ("__delitem__",)}[type(node.ctx)]
            yield node.value, names, "op"
            if isinstance(node.slice, ast.Slice):
                for part in (node.slice.lower, node.slice.upper, node.slice.step):
                    if part is not None:
                        yield part, ("__index__",), "op"
            else:
                yield node.slice, HASH + ("__index__",), "op"
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            yield node.iter, AITER if isinstance(node, ast.AsyncFor) else ITER, "op"
        elif isinstance(node, ast.comprehension):
            yield node.iter, AITER if node.is_async else ITER, "op"
            for condition in node.ifs:
                for leaf in truth_leaves(condition):
                    yield leaf, TRUTH, "op"
        elif isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            for leaf in truth_leaves(node.test):
                yield leaf, TRUTH, "op"
        elif isinstance(node, ast.BoolOp):
            for value in node.values[:-1]:  # the last value is returned, not tested
                for leaf in truth_leaves(value):
                    yield leaf, TRUTH, "op"
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, (ast.Tuple, ast.List)) for t in node.targets):
                yield node.value, ITER, "op"
        elif isinstance(node, ast.Starred) and isinstance(node.ctx, ast.Load):
            yield node.value, ITER, "op"
        elif isinstance(node, ast.keyword) and node.arg is None:
            yield node.value, MAPPING, "op"
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is None:
                    yield value, MAPPING, "op"
                else:
                    yield key, HASH, "op"
        elif isinstance(node, ast.Set):
            for element in node.elts:
                yield element, HASH, "op"
        elif isinstance(node, ast.DictComp):
            yield node.key, HASH, "op"
        elif isinstance(node, ast.SetComp):
            yield node.elt, HASH, "op"
        elif isinstance(node, ast.withitem):
            yield node.context_expr, ("__enter__", "__exit__", "__aenter__", "__aexit__"), "op"
        elif isinstance(node, ast.FormattedValue):
            names = {115: ("__str__",), 114: ("__repr__",), 97: ("__repr__",)}.get(node.conversion,
                                                                                  ("__format__", "__str__"))
            yield node.value, names, "op"
        elif isinstance(node, ast.YieldFrom):
            yield node.value, ITER + ("send", "throw", "close"), "op"
        elif isinstance(node, ast.Await):
            yield node.value, ("__await__",), "op"
        elif isinstance(node, ast.Match):
            yield node.subject, ("__eq__", "__getitem__", "__len__", "__iter__", "keys", "get", "__match_args__"), "op"
        elif isinstance(node, ast.Call):
            yield from self.protocol_call(node)
        elif isinstance(node, ast.Attribute) and IMPLICIT == "all" and id(node) not in call_funcs:
            names = {ast.Load: ("__getattribute__", "__getattr__"), ast.Store: ("__setattr__",),
                     ast.Del: ("__delattr__",)}[type(node.ctx)]
            yield node.value, names + (node.attr,), "attr"

    def shadowed(self, name: str, imports: bool = True) -> bool:
        """The name is bound here (a local, parameter, module value or, unless imports=False, an import)."""
        return (name in self.locals or name in self.params or (imports and name in self.aliases)
                or name in self.p.top_names.get(self.path, {}) or name in self.p.top_values.get(self.path, {}))

    def protocol_call(self, node: ast.Call):
        """A builtin or stdlib call (or str.format/join) that runs a protocol of its arguments."""
        raw = audit._dotted_name(node.func)
        if raw is not None and "." not in raw and not self.shadowed(raw):
            if raw in PROTOCOL_BUILTINS:
                for argument in (node.args[1:] if raw in _SKIP_FIRST else node.args):
                    if not isinstance(argument, ast.Starred):
                        yield argument, PROTOCOL_BUILTINS[raw], "op"
            elif raw in ("getattr", "hasattr", "setattr", "delattr") and IMPLICIT == "all" and len(node.args) > 1:
                name = node.args[1]
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    yield node.args[0], ("__getattribute__", "__getattr__", "__setattr__", "__delattr__",
                                         name.value), "attr"
            return
        if raw is not None and not self.shadowed(raw.partition(".")[0], imports=False):
            names = PROTOCOL_STDLIB.get(audit._aliased_name(raw, self.aliases))
            if names:
                for argument in node.args:
                    if not isinstance(argument, ast.Starred):
                        yield argument, names, "op"
                for keyword in node.keywords:
                    if keyword.arg is not None and keyword.arg not in ("default", "cls", "key", "object_hook"):
                        yield keyword.value, names, "op"
                return
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr in PROTOCOL_STR_METHODS
                and isinstance(func.value, (ast.Constant, ast.JoinedStr))):
            for argument in node.args:
                if not isinstance(argument, ast.Starred):
                    yield argument, PROTOCOL_STR_METHODS[func.attr], "op"
            for keyword in node.keywords:
                if keyword.arg is not None:
                    yield keyword.value, PROTOCOL_STR_METHODS[func.attr], "op"
            return
        if isinstance(func, ast.Attribute) and func.attr in BUILTIN_METHOD_HOOK_NAMES:
            names, positions = self.builtin_method_hooks(func)
            if names:
                self.p.counts["implicit_builtin_method_hook"][func.attr] += 1
                for index, argument in enumerate(node.args):
                    if not isinstance(argument, ast.Starred) and (positions is None or index in positions):
                        yield argument, names, "op"

    def builtin_method_hooks(self, func: ast.Attribute) -> tuple[tuple[str, ...], tuple[int, ...] | None]:
        """The dunders a known builtin receiver's method runs on its arguments, and which arguments."""
        names: list[str] = []
        positions: set[int] | None = set()
        for kind, value in self.implicit_origin(func.value):
            types = builtin_types(kind, value)
            if not types:
                return (), None  # not a known builtin receiver: the receiver is the open question, not its hooks
            for builtin_type in types:
                hook = BUILTIN_METHOD_HOOKS.get((builtin_type.__name__, func.attr))
                if hook is None:
                    continue
                names.extend(hook[0])
                positions = None if positions is None or hook[1] is None else positions | set(hook[1])
        return tuple(dict.fromkeys(names)), (None if positions is None else tuple(sorted(positions)))

    def implicit_origin(self, expr: ast.AST) -> list[tuple[str, str | None]]:
        """value_origin, plus what an implicit operand needs: builtin results, json values, bools."""
        fact = self.fact_origin(expr)
        if fact is not None:
            return fact
        if isinstance(expr, ast.Call):
            raw = audit._dotted_name(expr.func)
            if raw is not None and "." not in raw and raw in BUILTIN_RESULT and not self.shadowed(raw):
                return [("builtin", "result")]
        if isinstance(expr, ast.UnaryOp):
            if isinstance(expr.op, ast.Not):
                return [("builtin", "bool")]
            inner = self.implicit_origin(expr.operand)
            return inner if all(k in ("builtin", "json") for k, _ in inner) else [("unknown", None)]
        if isinstance(expr, ast.BoolOp):
            return [o for v in expr.values for o in self.implicit_origin(v)]
        if isinstance(expr, ast.IfExp):
            return self.implicit_origin(expr.body) + self.implicit_origin(expr.orelse)
        if isinstance(expr, ast.NamedExpr):
            return self.implicit_origin(expr.value)
        if isinstance(expr, ast.Starred):
            return self.implicit_origin(expr.value)
        return self.value_origin(expr, 0)

    def implicit(self, operand: ast.AST, names: tuple[str, ...], kind: str) -> None:
        """One implicit dispatch: an edge to a project dunder, nothing on a known builtin value, a gap otherwise."""
        for origin, value in self.implicit_origin(operand):
            if origin in ("project_class", "self") and value:
                for name in names:
                    self.d.edges.update(self.p.dispatch(value, name))
                if any(b not in SAFE_EXTERNAL_BASES and self.p.is_external(b) for b in self.p.external_bases(value)):
                    self.gap("inherited: external base method")
            elif origin in ("builtin", "json", "lambda", "def"):
                if origin == "builtin" and value == "item":
                    self.p.counts["implicit_on_container_item"][kind] += 1  # named exclusion: element types
            elif origin == "module":
                if value and self.p.is_external(value):
                    self.external(value)
            elif origin == "stdlib":
                base = (value or "").split("[")[0].removeprefix("builtins.")
                if base in NAMED_BUILTIN_TYPES or value in JSON_SOURCES:
                    continue
                self.p.counts["implicit_on_stdlib_object"][kind] += 1
                self.gap("method: stdlib-object name")  # tier T: stdlib dunders are stdlib code
            elif origin == "third":
                self.external(value or "?")
            else:  # a parameter, or a value of unknown type
                param = origin == "param" and value in self.params
                if param and (self.d.qual, value) in FACTS["boundary"]:
                    self.p.counts["fact_boundary_discharged"][f"{self.d.qual} {value} implicit"] += 1
                    continue
                self.gap(IMPLICIT_CATEGORY[kind, origin == "param"], strict=True, named=False)
                if param:
                    self.d.implicit_params.append((value, names, operand, kind))
                elif origin == "param":
                    self.d.other_implicit_params[kind] += 1
                for name in names:  # tier N: any project dunder of that name
                    self.d.edges_name.update(self.p.methods_by_name.get(name, set()))

    def property_access(self, node: ast.Attribute) -> None:
        """Reading a project @property runs its getter."""
        getters = self.p.properties[node.attr]
        receiver = node.value
        owner = None
        if isinstance(receiver, ast.Name) and receiver.id in ("self", "cls"):
            if receiver.id in self.params and self.d.class_qual:
                owner = self.d.class_qual
            else:
                free = self.free_variable(receiver.id)
                if free is not None and free[0] == "self":
                    owner = free[1]
        origins = [("project_class", owner)] if owner else self.value_origin(receiver, 0)
        for kind, value in origins:
            if kind == "project_class" and value:
                self.d.edges.update(self.p.dispatch(value, node.attr) & getters)
            elif kind in ("unknown", "param"):
                self.d.edges_name.update(getters)  # tier N+: any project property of that name

    def context_manager(self, item: ast.withitem) -> None:
        """``with x:`` runs x.__enter__ and x.__exit__."""
        for kind, value in self.value_origin(item.context_expr, 0):
            if kind == "project_class" and value:
                for name in ("__enter__", "__exit__", "__aenter__", "__aexit__"):
                    self.d.edges.update(self.p.dispatch(value, name))
            elif kind in ("unknown", "param"):
                for name in ("__enter__", "__exit__", "__aenter__", "__aexit__"):
                    self.d.edges_name.update(self.p.methods_by_name.get(name, set()))

    # ----- origins of values ---------------------------------------------------------------------------
    def origins(self, name: str, depth: int = 0) -> list[tuple[str, str | None]]:
        if depth > 4:
            return [("unknown", None)]
        if name in self.params:
            stated = self.annotation_origin(self.d.annotations.get(name))
            if stated:
                return stated
            if name in ("self", "cls") and self.d.class_qual:
                return [("self", self.d.class_qual)]
            return [("param", name)]
        if name not in self.locals:
            if name in self.p.top_names.get(self.path, {}):
                qual = self.p.top_names[self.path][name]
                return [("project_class" if qual in self.p.classes else "def", qual)]
            if name in self.aliases:
                resolved = self.p.resolve(self.path, self.aliases[name])
                if resolved:
                    return [("project_class" if resolved in self.p.classes else "def", resolved)]
                return [("module", self.aliases[name])]
            if name in self.p.top_values.get(self.path, {}):
                return [o for value in self.p.top_values_all[self.path][name]
                        for o in self.value_origin(value, depth + 1)]
            if name in review_operations.STATIC_BUILTIN_NAMES:
                return [("builtin", name)]
            return [("unknown", None)]
        out: list[tuple[str, str | None]] = []
        for kind, value in self.locals[name]:
            if kind == "nested":
                out.append(("project_class" if value in self.p.classes else "def", value))
                continue
            if kind == "annotation":
                if ANNOTATIONS == "off":
                    continue
                annotation = self.p.annotation(self.path, value)
                resolved = self.p.class_qual(self.path, annotation)
                if resolved and not (ANNOTATIONS == "concrete" and self.p.is_protocol(resolved)):
                    return [("project_class", resolved)]
                continue
            out.extend(self.value_origin(value, depth + 1) if kind == "value" else [("unknown", None)])
        return out or [("unknown", None)]

    def annotation_origin(self, annotation: str | None) -> list[tuple[str, str | None]] | None:
        """What a parameter's stated annotation says about its class under REACH_ANNOTATIONS (None: nothing)."""
        if not annotation or annotation in UNTYPED_ANNOTATIONS or ANNOTATIONS == "off":
            return None
        resolved = self.p.class_qual(self.path, annotation)
        if resolved:
            if ANNOTATIONS == "concrete" and self.p.is_protocol(resolved):
                self.p.counts["protocol_annotation_untyped"][resolved] += 1
                return None
            return [("project_class", resolved)]
        if self.p.classify_root(annotation) in ("stdlib", "builtin"):
            if ANNOTATIONS == "concrete" and abstract_annotation(annotation):
                self.p.counts["abstract_annotation_untyped"][annotation] += 1
                return None
            self.p.counts["stdlib_annotation_receiver"][annotation] += 1  # tier-T assumption: behaves as stdlib
            return [("stdlib", annotation)]
        return None

    def returned(self, callee: Definition) -> str | None:
        """The project class a callee's return annotation names (a stated fact), under REACH_ANNOTATIONS."""
        if ANNOTATIONS == "off" or not callee.returns:
            return None
        resolved = self.p.class_qual(callee.path, callee.returns)
        if resolved and ANNOTATIONS == "concrete" and self.p.is_protocol(resolved):
            return None
        return resolved

    def fact_origin(self, expr: ast.AST) -> list[tuple[str, str | None]] | None:
        """A type admitted from reasons.vstd for this expression in this definition (REACH_FACTS)."""
        sites = FACTS["sites"]
        if not sites:
            return None
        text = ast.unparse(expr)
        line, col = getattr(expr, "lineno", None), getattr(expr, "col_offset", -1) + 1
        hit = (sites.get((self.d.qual, text, line, col)) or sites.get((self.d.qual, text, line, None))
               or sites.get((self.d.qual, text, None, None)))
        if hit is None:
            return None
        self.p.counts["fact_site_type_used"][f"{self.d.qual} {text}"] += 1
        return [hit]

    def value_origin(self, value: ast.AST | None, depth: int) -> list[tuple[str, str | None]]:
        if value is None:
            return [("unknown", None)]
        if isinstance(value, (ast.Constant, ast.JoinedStr, ast.List, ast.Dict, ast.Set, ast.Tuple, ast.ListComp,
                              ast.DictComp, ast.SetComp, ast.Compare)):
            return [("builtin", type(value).__name__)]
        if isinstance(value, ast.BinOp):
            left = self.value_origin(value.left, depth + 1)
            return left if all(k == "builtin" for k, _ in left) else [("unknown", None)]
        if isinstance(value, ast.Name):
            return self.origins(value.id, depth + 1)
        if isinstance(value, ast.Lambda):
            return [("lambda", None)]
        if isinstance(value, ast.IfExp):
            return self.value_origin(value.body, depth + 1) + self.value_origin(value.orelse, depth + 1)
        if isinstance(value, ast.BoolOp):
            return [o for v in value.values for o in self.value_origin(v, depth + 1)]
        if isinstance(value, ast.Await):
            return [("unknown", None)]
        if isinstance(value, ast.Call):
            raw = audit._dotted_name(value.func)
            if raw is None:
                return [("unknown", None)]
            target = audit._aliased_name(raw, self.aliases)
            first = raw.partition(".")[0]
            if (target in DYNAMIC_RESULTS or raw in DYNAMIC_RESULTS) and not self.shadowed(first, imports=False):
                self.p.counts["dynamic_operation_result"][target] += 1
                return [("unknown", None)]  # what getattr(...) hands back is not a known callable or value
            if first in ("self", "cls") and first in self.params and self.d.class_qual and raw.count(".") == 1:
                targets = self.p.dispatch(self.d.class_qual, raw.partition(".")[2])
                if targets and all(t in FACTS["returns"] for t in targets):
                    return sorted({FACTS["returns"][t] for t in targets}, key=str)
                returned = {self.returned(self.p.defs[t]) for t in targets}
                returned.discard(None)
                return [("project_class", r) for r in sorted(returned)] or [("unknown", None)]
            if first in self.locals or (first in self.params and first not in ("self", "cls")):
                return [("unknown", None)]
            if raw == "cls" and first in self.params and self.d.class_qual:
                return [("project_class", self.d.class_qual)]  # cls() in a classmethod builds the class or a subclass
            if first not in self.aliases and first not in self.p.top_names.get(self.path, {}):
                free = self.free_variable(first)
                if free is not None:  # a closure: the name is bound in an enclosing definition
                    kind, owner = free
                    if kind == "self" and raw == "cls":
                        return [("project_class", owner)]
                    if kind == "local" and raw == first:
                        out = []
                        for origin_kind, origin in self.p.visitor(owner).origins(first, depth + 1):
                            callee = self.p.defs.get(origin) if origin_kind == "def" and origin else None
                            if origin_kind == "project_class" and origin:
                                out.append(("project_class", origin))
                            elif callee is not None and callee.returns:
                                returned = self.returned(callee)
                                out.append(("project_class", returned) if returned else ("unknown", None))
                            else:
                                out.append(("unknown", None))
                        return out or [("unknown", None)]
                    return [("unknown", None)]
            if target in ("functools.partial", "partial") and value.args:
                inner = audit._dotted_name(value.args[0])
                resolved = self.p.resolve(self.path, audit._aliased_name(inner, self.aliases)) if inner else None
                return [("def", resolved)] if resolved else [("unknown", None)]
            resolved = self.p.resolve(self.path, target)
            if resolved in self.p.classes:
                return [("project_class", resolved)]
            if resolved in self.p.defs:
                if resolved in FACTS["returns"]:
                    self.p.counts["fact_return_type_used"][resolved] += 1
                    return [FACTS["returns"][resolved]]
                callee = self.p.defs[resolved]
                returned = self.returned(callee)
                return [("project_class", returned)] if returned else [("unknown", None)]
            root = self.p.classify_root(target)
            if root in ("stdlib", "builtin"):
                return [("stdlib", target)]
            if root in ("third", "ambiguous") and first in self.aliases:  # third-party only when rooted at an import
                return [("third", target)]
            return [("unknown", None)]
        if isinstance(value, ast.Attribute):
            raw = audit._dotted_name(value)
            if raw:
                if raw.startswith("self.") and raw.count(".") == 1 and self.d.class_qual:
                    info = self.p.classes.get(self.d.class_qual)
                    attr = raw.partition(".")[2]
                    fact = self.p.attr_fact(self.d.class_qual, attr)
                    if fact is not None:
                        self.p.counts["fact_attr_type_used"][f"{self.d.class_qual}.{attr}"] += 1
                        return [fact]
                    if info and attr in info.attr_types:
                        return [("project_class", q) for q in sorted(info.attr_types[attr])]
                    return [("unknown", None)]
                if raw.partition(".")[0] in self.locals or raw.partition(".")[0] in self.params:
                    return [("unknown", None)]
                resolved = self.p.resolve(self.path, audit._aliased_name(raw, self.aliases))
                if resolved:
                    return [("project_class" if resolved in self.p.classes else "def", resolved)]
                if self.p.classify_root(audit._aliased_name(raw, self.aliases)) in ("stdlib", "builtin"):
                    return [("stdlib", raw)]
            return [("unknown", None)]
        if isinstance(value, ast.Subscript):
            inner = self.value_origin(value.value, depth + 1)
            if inner and all(k == "json" for k, _ in inner):
                return [("json", "item")]
            return ([("unknown", None)] if any(k not in ("builtin", "stdlib", "json") for k, _ in inner)
                    else [("builtin", "item")])
        return [("unknown", None)]

    # ----- one call ------------------------------------------------------------------------------------
    def call(self, node: ast.Call) -> None:
        raw = audit._dotted_name(node.func)
        if FACTS["suppress"]:  # a contract discharges this call to the code that supplied the callee
            spelled = raw or ast.unparse(node.func)
            if ((self.d.qual, spelled, node.lineno) in FACTS["suppress"]
                    or (self.d.qual, spelled, None) in FACTS["suppress"]):
                self.p.counts["fact_discharged_call"][f"{self.d.qual} {spelled}"] += 1
                return
        if FACTS["sites"] and isinstance(node.func, ast.Attribute):
            fact = self.fact_origin(node.func.value)
            if fact is not None:
                self.receiver_call(node, node.func.attr, fact, "receiver: untyped local or expression")
                return
        if raw is None:
            self.expression_call(node)
            return
        target = audit._aliased_name(raw, self.aliases)
        first, _, rest = raw.partition(".")
        if target in audit._DYNAMIC_OPERATIONS or target.startswith("inspect.") or raw in audit._DYNAMIC_OPERATIONS:
            self.dynamic_operation(node, target if target in audit._DYNAMIC_OPERATIONS or target.startswith("inspect.") else raw)
            return
        if first in ("self", "cls") and first in self.params and self.d.class_qual:
            self.self_call(node, raw, self.d.class_qual)
            return
        if first in self.params:
            self.param_call(node, first, rest)
            return
        if first in self.locals:
            self.local_call(node, raw, first, rest)
            return
        free = self.free_variable(first)
        if free is not None:
            kind, value = free
            if kind == "self":
                self.self_call(node, raw, value)
            elif kind == "param" and not rest:
                self.p.defs[value].callback_params.add(first)  # resolved at the enclosing definition's call sites
            elif kind == "param":
                self.receiver_call(node, rest.rpartition(".")[2], self.p.visitor(value).origins(first) if "." not in rest
                                   else [("param", first)], "receiver: untyped parameter")
            elif not rest:
                origins = self.p.visitor(value).origins(first)
                for origin_kind, origin in origins:
                    if origin_kind in ("def", "project_class") and origin:
                        self.project_call(node, origin)
                    elif origin_kind not in ("lambda", "stdlib"):
                        self.gap("dynamic: local callable value")
            else:
                self.receiver_call(node, rest.rpartition(".")[2], self.p.visitor(value).origins(first)
                                   if "." not in rest else [("unknown", None)], "receiver: untyped local or expression")
            return
        resolved = self.p.resolve(self.path, target)
        if resolved:
            self.project_call(node, resolved, via_class="." in raw)
            return
        if not rest and target == raw:  # an unimported bare name: a module value or a builtin
            if first in self.p.top_values.get(self.path, {}):
                for kind, value in self.origins(first):
                    if kind == "def" and value:
                        self.project_call(node, value)
                    elif kind == "project_class" and value:
                        self.project_call(node, value)
                    elif kind != "lambda":
                        self.gap("dynamic: local callable value")
                return
            self.builtin_call(node, target)
            return
        root = self.p.classify_root(target)
        if root in ("stdlib", "builtin"):
            self.stdlib_call(node, target, raw)
            return
        if root == "project" and not rest:  # a from-imported project value that is not a definition or class
            module, _, name = target.rpartition(".")
            value_path = self.p.module_path.get(module)
            value = self.p.top_values.get(value_path or "", {}).get(name)
            if value is None or value_path is None:
                self.gap("name: unbound value called")
                self.p.counts["unbound_name"]["<from-import> " + target] += 1
                return
            owner = self.p.visitor(self.p.module_pseudo(self.p.module_of[value_path]))
            for kind, origin in owner.value_origin(value, 0):
                if kind in ("def", "project_class") and origin:
                    self.project_call(node, origin)
                elif kind not in ("lambda", "stdlib"):
                    self.gap("dynamic: local callable value")
            return
        if root == "project":
            # a module-level value inside a project module, e.g. REGISTRY.get(...)
            head, _, method = target.rpartition(".")
            value_path = self.p.project_module(head)
            value = self.p.top_values.get(value_path or "", {}).get(head.rpartition(".")[2])
            origins: list[tuple[str, str | None]] = [("unknown", None)]
            if value is not None and value_path:
                origins = self.p.visitor(self.p.module_pseudo(self.p.module_of[value_path])).value_origin(value, 0)
            self.receiver_call(node, method, origins, "receiver: untyped local or expression")
            return
        if first in self.p.top_values.get(self.path, {}):
            self.receiver_call(node, raw.rpartition(".")[2], self.origins(first), "receiver: untyped local or expression")
            return
        if first in self.p.top_names.get(self.path, {}):  # an attribute of a module-level class or function
            self.receiver_call(node, raw.rpartition(".")[2], [("unknown", None)], "receiver: untyped local or expression")
            return
        if first not in self.aliases:  # nothing imports or binds the root: not third-party code
            self.gap("name: unbound value called")
            self.p.counts["unbound_name"][target] += 1
            return
        self.external(target)

    def project_call(self, node: ast.Call, resolved: str, via_class: bool = False) -> None:
        if resolved in self.p.classes:
            targets, unsafe = self.p.constructor(resolved)
            for target in targets:
                self.d.edges.add(target)
                self.site(target, node, 1)
            for _ in unsafe:
                self.gap("inherited: external base method")
            return
        self.d.edges.add(resolved)
        callee = self.p.defs.get(resolved)
        offset = 1 if callee is not None and callee.class_qual and callee.params[:1] == ("cls",) else 0
        self.site(resolved, node, offset)

    def free_variable(self, name: str) -> tuple[str, str] | None:
        """A name bound in an enclosing definition (a closure): ('self', class), ('param', def) or ('local', def)."""
        qual = self.d.enclosing
        while qual is not None and qual in self.p.defs:
            outer = self.p.defs[qual]
            if name in outer.params:
                if name in ("self", "cls") and (outer.class_qual or outer.outer_class):
                    return "self", outer.class_qual or outer.outer_class or ""
                return "param", qual
            if name in self.p.visitor(qual).locals:
                return "local", qual
            qual = outer.enclosing
        return None

    def self_call(self, node: ast.Call, raw: str, owner: str) -> None:
        parts = raw.split(".")
        if len(parts) == 1:  # cls(...)
            for cls in {owner, *self.p.subclasses.get(owner, ())}:
                for target in self.p.constructor(cls)[0]:
                    self.d.edges.add(target)
                    self.site(target, node, 1)
            return
        info = self.p.classes.get(owner)
        if len(parts) == 2:
            method = parts[1]
            targets = self.p.dispatch(owner, method)
            if targets:
                for target in targets:
                    self.d.edges.add(target)
                    self.site(target, node, 1)
                return
            if info and method in info.attr_params:  # self.callback(...) stored from an __init__ parameter
                init, param = info.attr_params[method]
                self.p.defs[init].callback_params.add(param)
                return
            if info and method in info.attr_types:
                for cls in info.attr_types[method]:
                    self.d.edges.update(self.p.dispatch(cls, "__call__"))
                return
            externals = self.p.external_bases(owner)
            if any(b not in SAFE_EXTERNAL_BASES and self.p.is_external(b) for b in externals):
                self.gap("inherited: external base method")
                return
            if externals and not (method in audit._PURE_METHODS or method in BUILTIN_TYPE_METHODS):
                self.stdlib_method(node, method)
                return
            if method in audit._PURE_METHODS or method in BUILTIN_TYPE_METHODS:
                self.p.counts["pure_name_on_class_without_method"][method] += 1
                return
            self.receiver_call(node, method, [("unknown", None)], "receiver: untyped local or expression")
            return
        attr, method = parts[1], parts[-1]
        fact = self.p.attr_fact(owner, attr) if len(parts) == 3 else None
        if fact is not None:  # an attribute type admitted from reasons.vstd
            self.p.counts["fact_attr_type_used"][f"{owner}.{attr}"] += 1
            self.receiver_call(node, method, [fact], "receiver: untyped local or expression")
            return
        if info and len(parts) == 3 and attr in info.attr_types:
            targets = set().union(*(self.p.dispatch(cls, method) for cls in info.attr_types[attr]))
            if targets:
                for target in targets:
                    self.d.edges.add(target)
                    self.site(target, node, 1)
                return
        self.receiver_call(node, method, [("unknown", None)], "receiver: untyped local or expression")

    def param_call(self, node: ast.Call, first: str, rest: str) -> None:
        if not rest:
            origins = self.origins(first)
            if any(kind == "project_class" for kind, _ in origins):
                for kind, value in origins:
                    if kind == "project_class" and value:
                        self.d.edges.update(self.p.dispatch(value, "__call__"))
                return
            self.d.callback_params.add(first)
            return
        self.receiver_call(node, rest.rpartition(".")[2], self.origins(first) if "." not in rest
                           else [("param_attribute", first)], "receiver: untyped parameter")

    def local_call(self, node: ast.Call, raw: str, first: str, rest: str) -> None:
        origins = self.origins(first)
        if not rest:
            for kind, value in origins:
                if kind in ("def", "project_class") and value:
                    self.project_call(node, value)
                elif kind == "lambda":
                    continue
                elif kind == "param" and value:
                    self.d.callback_params.add(value)
                elif kind == "stdlib":
                    continue  # a stdlib-returned callable, e.g. operator.itemgetter(...)
                else:
                    self.gap("dynamic: local callable value")
            return
        self.receiver_call(node, rest.rpartition(".")[2], origins if "." not in rest else [("unknown", None)],
                           "receiver: untyped local or expression")

    def receiver_call(self, node: ast.Call, method: str, origins: list[tuple[str, str | None]], category: str) -> None:
        for kind, value in origins:
            if kind == "project_class" and value:
                targets = self.p.dispatch(value, method)
                if targets:
                    for target in targets:
                        self.d.edges.add(target)
                        self.site(target, node, 1)
                    continue
                externals = self.p.external_bases(value)
                if any(b not in SAFE_EXTERNAL_BASES and self.p.is_external(b) for b in externals):
                    self.gap("inherited: external base method")
                elif method in audit._PURE_METHODS or method in BUILTIN_TYPE_METHODS:
                    self.p.counts["pure_name_on_class_without_method"][method] += 1
                else:
                    self.stdlib_method(node, method)
            elif kind in ("stdlib", "builtin", "module"):
                if kind == "stdlib" and value and value.startswith(PROCESS_STATE) and method in MUTATORS:
                    self.p.counts["process_state_write"][f"{value} (through a local).{method}"] += 1
                if kind == "module" and value and self.p.is_external(value):
                    self.external(value)
                elif builtin_receiver_method(kind, value, method):
                    pass
                else:
                    self.stdlib_method(node, method)
            elif kind == "third":
                self.external(value or "?")
            elif kind == "def" and value:
                self.d.edges.add(value)  # a function object's attribute call: conservative
            elif kind == "json":
                pass  # an exact JSON value: only builtin methods exist on it
            else:
                self.untyped(node, method, category,
                             param=value if kind == "param" and value in self.params else None)

    def untyped(self, node: ast.Call, method: str, category: str, param: str | None = None) -> None:
        """S: installed name rules (param receivers always a gap).  I+: an own parameter's receiver
        type is inferred from project call sites.  N: dispatch by method name."""
        if param is not None and (self.d.qual, param) in FACTS["boundary"]:
            self.p.counts["fact_boundary_discharged"][f"{self.d.qual} {param}.{method}"] += 1
            return  # the boundary rule: what this use runs belongs to each caller (a site gap there when unknown)
        channels = audit._effect_channels("<receiver>." + method, "<receiver>." + method, node)
        if channels:
            self.channel(channels)
        pure = method in audit._PURE_METHODS
        trusted = pure and NAME_RULE == "on"  # off: a pure name says nothing about an unknown receiver
        if category == "receiver: untyped parameter" or not (trusted or channels):
            self.gap(category, strict=True, named=False)
        if category == "receiver: untyped parameter":
            if param is not None:
                self.d.param_receivers.append((param, method, node))
            else:
                self.d.other_param_sites += 1
        project = self.p.methods_by_name.get(method, set())
        if project:
            self.d.edges_name.update(project)
            self.p.fanout.append(len(project))
            if pure:
                self.p.counts["pure_name_shadowed_by_project_method"][method] += 1
        elif pure or channels or method in BUILTIN_TYPE_METHODS:
            pass
        elif method in STDLIB_METHODS:
            self.gap("method: stdlib-object name", strict=False, named=True)
            self.p.counts["stdlib_like_method"][method] += 1
        else:
            self.gap("method: unknown name", strict=False, named=True)
            self.p.counts["unknown_method"][method] += 1

    def builtin_call(self, node: ast.Call, target: str) -> None:
        channels = audit._effect_channels(target, target, node)
        for callback in self.callback_arguments(node, target):
            self.callback_value(callback)
        if channels:
            self.channel(channels)
            return
        if target in audit._PURE_BUILTINS or target in audit._PURE_BUILTIN_TYPES:
            return
        if target in ("exit", "quit"):
            self.channel(("subprocess_process",))
            return
        if target in review_operations.STATIC_BUILTIN_NAMES:
            return
        self.gap("name: unbound value called")
        self.p.counts["unbound_name"][target] += 1

    def callback_arguments(self, node: ast.Call, target: str) -> list[ast.AST]:
        selected = [node.args[i] for i in audit._POSITIONAL_CALLBACKS.get(target, ()) if i < len(node.args)]
        selected += [k.value for k in node.keywords
                     if k.arg in audit._CALLBACK_KEYWORDS or (target in audit._CALLBACK_BUILTINS and k.arg == "key")]
        return selected

    def callback_value(self, value: ast.AST) -> None:
        if isinstance(value, ast.Lambda):
            return
        raw = audit._dotted_name(value)
        if raw is None:
            if isinstance(value, ast.Call) and audit._dotted_name(value.func) in ("functools.partial", "partial", "operator.attrgetter", "operator.itemgetter"):
                return
            self.gap("dynamic: other callee expression")
            return
        first = raw.partition(".")[0]
        if first in self.params and "." not in raw:
            origins = self.origins(first)
            if any(kind == "project_class" for kind, _ in origins):
                return
            self.d.callback_params.add(first)
            return
        if first in self.locals:
            for kind, origin in self.origins(first):
                if kind in ("def", "project_class") and origin:
                    self.d.edges.add(origin) if origin in self.p.defs else self.d.edges.update(self.p.constructor(origin)[0])
                elif kind not in ("lambda", "stdlib", "builtin"):
                    self.gap("dynamic: local callable value")
            return
        if first in ("self", "cls") and self.d.class_qual and raw.count(".") == 1:
            self.d.edges.update(self.p.dispatch(self.d.class_qual, raw.partition(".")[2]))
            return
        target = audit._aliased_name(raw, self.aliases)
        resolved = self.p.resolve(self.path, target)
        if resolved in self.p.defs:
            self.d.edges.add(resolved)
        elif resolved in self.p.classes:
            self.d.edges.update(self.p.constructor(resolved)[0])
        elif self.p.classify_root(target) not in ("stdlib", "builtin"):
            self.gap("dynamic: local callable value")

    def stdlib_call(self, node: ast.Call, target: str, raw: str) -> None:
        """Installed channels first.  An unclassified stdlib function stays a gap until tier T; a
        draft-table effect is recorded in every tier (only ever adding a channel is conservative)."""
        channels = set(audit._effect_channels(target, raw, node))
        for callback in self.callback_arguments(node, target):
            self.callback_value(callback)
        if target.startswith(PROCESS_STATE) and target.rpartition(".")[2] in MUTATORS or target in (
                "os.putenv", "os.unsetenv"):
            self.p.counts["process_state_write"][target] += 1
        if channels:
            self.channel(sorted(channels))
            return
        if target.startswith(audit._PURE_STDLIB_PREFIXES):
            return
        if target.rpartition(".")[2] in audit._PURE_METHODS:  # e.g. sys.path.insert: trusted by its last name
            self.p.counts["pure_name_stdlib_function"][target] += 1
            return
        self.p.counts["unclassified_stdlib"][target] += 1
        self.gap("stdlib: unclassified function")
        for prefix, channel in DRAFT_STDLIB_EFFECTS.items():
            if target == prefix or (prefix.endswith(".") and target.startswith(prefix)):
                self.p.counts["draft_stdlib_effect"][target] += 1
                if channel in CHANNEL_BIT:
                    self.channel((channel,))

    def stdlib_method(self, node: ast.Call, method: str) -> None:
        channels = audit._effect_channels("<stdlib-object>." + method, "<stdlib-object>." + method, node)
        if channels:
            self.channel(channels)
            return
        if method in audit._PURE_METHODS or method in BUILTIN_TYPE_METHODS:
            self.p.counts["pure_name_on_stdlib_object"][method] += 1  # trusted by name on a stdlib object
            return
        self.p.counts["stdlib_object_method"][method] += 1
        self.gap("method: stdlib-object name")

    def dynamic_operation(self, node: ast.Call, target: str) -> None:
        if target in ("getattr", "hasattr", "setattr", "delattr"):
            literal = len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
            if not literal:
                self.gap("dynamic: computed reflection name")
                self.p.counts["computed_reflection"][target] += 1
            return  # a literal name is an ordinary attribute; calling the result is handled by the caller
        if target in ("importlib.import_module", "__import__"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                module = node.args[0].value
                path = self.p.module_path.get(module)
                if path is not None:
                    self.d.edges.add(self.p.module_pseudo(self.p.module_of[path]))
                elif self.p.is_external(module):
                    self.external(module)
                return
            self.gap("dynamic: computed import")
            return
        if target in ("eval", "exec", "compile"):
            self.gap("dynamic: eval/exec/compile")
            return
        if target in ("inspect.getsource", "inspect.getsourcefile", "inspect.getfile", "inspect.getsourcelines"):
            self.channel(("filesystem_read",))
        # dir/vars/globals/locals and other inspect.* calls read the namespace; calling a result is a gap elsewhere

    def expression_call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            method, receiver = func.attr, func.value
            if isinstance(receiver, ast.Call) and audit._dotted_name(receiver.func) == "super" and self.d.class_qual:
                info = self.p.classes.get(self.d.class_qual)
                found = {t for base in (info.bases if info else []) if (t := self.p.lookup(base, method))}
                if found:
                    for target in found:
                        self.d.edges.add(target)
                    return
                externals = self.p.external_bases(self.d.class_qual)
                if any(b not in SAFE_EXTERNAL_BASES and self.p.is_external(b) for b in externals):
                    self.gap("inherited: external base method")
                return  # object/builtin/stdlib base dunder or method
            if isinstance(receiver, ast.Call) and audit._dotted_name(receiver.func) == "getattr":
                self.untyped(node, method, "receiver: untyped local or expression")
                return
            self.receiver_call(node, method, self.value_origin(receiver, 0), "receiver: untyped local or expression")
            return
        if isinstance(func, ast.Call):
            inner = audit._dotted_name(func.func)
            if inner == "getattr":
                if len(func.args) > 1 and isinstance(func.args[1], ast.Constant) and isinstance(func.args[1].value, str):
                    self.receiver_call(node, func.args[1].value, self.value_origin(func.args[0], 0),
                                       "receiver: untyped local or expression")
                else:
                    self.gap("dynamic: computed reflection name")
                return
            if inner == "type" and func.args and self.d.class_qual:
                for cls in {self.d.class_qual, *self.p.subclasses.get(self.d.class_qual, ())}:
                    self.d.edges.update(self.p.constructor(cls)[0])
                return
            if inner in ("functools.partial", "partial", "operator.attrgetter", "operator.itemgetter",
                         "operator.methodcaller") and func.args:
                return  # visited as its own call; the partial's target is resolved there as a callback
            self.gap("dynamic: call of a call result")
            self.p.counts["call_of_call"][inner or type(func.func).__name__] += 1
            return
        if isinstance(func, ast.Subscript):
            names = self.dispatch_table(func.value)
            if names is None:
                self.gap("dynamic: subscript dispatch")
                return
            for raw in names:
                target = audit._aliased_name(raw, self.aliases)
                resolved = self.p.resolve(self.path, target)
                if resolved:
                    self.project_call(node, resolved)
                elif self.p.classify_root(target) in ("stdlib", "builtin"):
                    self.stdlib_call(node, target, raw)
                else:
                    self.gap("dynamic: subscript dispatch")
            return
        if isinstance(func, ast.Lambda):
            return
        self.gap("dynamic: other callee expression")
        self.p.counts["other_callee"][type(func).__name__] += 1

    def dispatch_table(self, table: ast.AST) -> list[str] | None:
        value: ast.AST | None = None
        if isinstance(table, ast.Name):
            bound = self.locals.get(table.id)
            if bound and len(bound) == 1 and bound[0][0] == "value":
                value = bound[0][1]
            elif table.id in self.p.top_values.get(self.path, {}):
                value = self.p.top_values[self.path][table.id]
        elif isinstance(table, (ast.Dict, ast.List, ast.Tuple)):
            value = table
        if isinstance(value, ast.Call) and value.args and audit._dotted_name(value.func) in (
                "types.MappingProxyType", "MappingProxyType", "dict", "frozenset", "tuple"):
            value = value.args[0]
        if isinstance(value, ast.Dict):
            elements = value.values
        elif isinstance(value, (ast.List, ast.Tuple)):
            elements = value.elts
        else:
            return None
        names = []
        for element in elements:
            if isinstance(element, ast.Tuple) and element.elts:
                element = element.elts[0]
            if isinstance(element, ast.Lambda):
                continue
            raw = audit._dotted_name(element)
            if raw is None:
                return None
            names.append(raw)
        return names


def class_attribute_facts(program: Program) -> None:
    for info in program.classes.values():
        for method_name, qual in info.methods.items():
            definition = program.defs[qual]
            visitor = BodyVisitor(program, definition)
            for node in visitor.nodes:
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                        for kind, value in visitor.value_origin(node.value, 0):
                            if kind == "project_class" and value:
                                info.attr_types.setdefault(target.attr, set()).add(value)
                        if (method_name == "__init__" and isinstance(node.value, ast.Name)
                                and node.value.id in definition.params):
                            annotation = definition.annotations.get(node.value.id)
                            if not (annotation and program.class_qual(definition.path, annotation)):
                                info.attr_params[target.attr] = (qual, node.value.id)


def resolve_callbacks(program: Program) -> collections.Counter:
    outcome: collections.Counter = collections.Counter()
    for _ in range(4):
        pending = [(q, d) for q, d in program.defs.items() if d.callback_params]
        if not pending:
            break
        for qual, definition in pending:
            params, definition.callback_params = sorted(definition.callback_params), set()
            sites = program.call_sites.get(qual, [])
            decorated = program.decorated.get(qual, set())
            for param in params:
                if param not in definition.params:
                    continue
                index = definition.params.index(param)
                if decorated and index == 0:  # a decorator calls the function it decorates
                    definition.edges |= decorated
                    outcome["decorated function"] += 1
                    if not sites:
                        continue
                if not sites:
                    definition.gaps |= GAP_BIT["callback: supplied from outside the project"]
                    definition.gaps_n |= GAP_BIT["callback: supplied from outside the project"]
                    definition.gap_sites["callback: supplied from outside the project"] += 1
                    outcome["no project call site (public API)"] += 1
                    continue
                for caller_qual, node, offset in sites:
                    caller = program.defs[caller_qual]
                    argument = next((k.value for k in node.keywords if k.arg == param), None)
                    position = index - offset
                    if argument is None and 0 <= position < len(node.args) and not any(
                            isinstance(a, ast.Starred) for a in node.args[:position + 1]):
                        argument = node.args[position]
                    if argument is None:
                        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
                            definition.gaps |= GAP_BIT["callback: unresolved argument at a project call site"]
                            definition.gaps_n |= GAP_BIT["callback: unresolved argument at a project call site"]
                            outcome["star arguments"] += 1
                        else:
                            outcome["default value"] += 1
                        continue
                    visitor = program.visitor(caller_qual)
                    before = (caller.gaps, caller.gaps_n, set(caller.edges), set(caller.callback_params))
                    visitor.callback_value(argument)
                    gained = (caller.edges - before[2]) | ({"<forward>"} if caller.callback_params - before[3] else set())
                    if caller.gaps != before[0]:
                        lost = caller.gaps & ~before[0]
                        caller.gaps, caller.gaps_n = before[0], before[1]
                        definition.gaps |= lost
                        definition.gaps_n |= lost
                        outcome["unresolved callable argument"] += 1
                    elif "<forward>" in gained:
                        outcome["forwarded caller parameter"] += 1
                    else:
                        new = caller.edges - before[2]
                        caller.edges = before[2]
                        definition.edges |= new
                        outcome["resolved (definition, class, lambda, stdlib)"] += 1
    leftover = sum(len(d.callback_params) for d in program.defs.values())
    outcome["still pending after 4 passes"] = leftover
    for definition in program.defs.values():
        if definition.callback_params:
            definition.gaps |= GAP_BIT["callback: unresolved argument at a project call site"]
            definition.gaps_n |= GAP_BIT["callback: unresolved argument at a project call site"]
    return outcome


def call_argument(definition: Definition, param: str, node: ast.Call, offset: int) -> tuple[ast.AST | None, bool]:
    """The argument a project call site passes for ``param``: (expression, star-arguments-hide-it)."""
    argument = next((k.value for k in node.keywords if k.arg == param), None)
    position = definition.params.index(param) - offset
    if argument is None and 0 <= position < len(node.args) and not any(
            isinstance(a, ast.Starred) for a in node.args[:position + 1]):
        argument = node.args[position]
    hidden = argument is None and (any(isinstance(a, ast.Starred) for a in node.args)
                                   or any(k.arg is None for k in node.keywords))
    return argument, hidden


def infer_receivers(program: Program) -> collections.Counter:
    """Tier I: an own parameter used as a receiver takes the classes its project call sites pass
    (context-insensitive, one level).  Any site passing an untyped value, a public API without
    project call sites, or arguments hidden by */** keeps the gap."""
    outcome: collections.Counter = collections.Counter()
    for qual, definition in program.defs.items():
        if not definition.param_receivers:
            definition.param_inferred_ok = definition.other_param_sites == 0
            continue
        ok_all = definition.other_param_sites == 0
        sites = program.call_sites.get(qual, [])
        for param, method, call in definition.param_receivers:
            if not sites:
                outcome["no project call site (public API)"] += 1
                ok_all = False
                continue
            ok = True
            for caller_qual, node, offset in sites:
                argument, hidden = call_argument(definition, param, node, offset)
                if argument is None:
                    if hidden:
                        ok = False
                        outcome["argument hidden by */**"] += 1
                        break
                    continue  # the default value is used at this site
                for kind, value in program.visitor(caller_qual).value_origin(argument, 0):
                    if kind == "project_class" and value:
                        targets = program.dispatch(value, method)
                        if targets:
                            definition.edges_inferred |= targets
                        elif any(b not in SAFE_EXTERNAL_BASES and program.is_external(b)
                                 for b in program.external_bases(value)):
                            ok = False
                        elif not (method in audit._PURE_METHODS or method in BUILTIN_TYPE_METHODS):
                            definition.inferred_gaps |= GAP_BIT["method: stdlib-object name"]
                    elif kind in ("stdlib", "builtin"):
                        channels = audit._effect_channels("<stdlib-object>." + method, "<stdlib-object>." + method, call)
                        for name in channels:
                            definition.inferred_channels |= CHANNEL_BIT[name]
                        if not (channels or method in audit._PURE_METHODS or method in BUILTIN_TYPE_METHODS):
                            definition.inferred_gaps |= GAP_BIT["method: stdlib-object name"]
                    else:
                        ok = False
                        outcome[f"a call site passes an untyped value ({kind})"] += 1
                        break
                if not ok:
                    break
            if ok:
                outcome["resolved from call sites"] += 1
            ok_all = ok_all and ok
        definition.param_inferred_ok = ok_all
    for key, value in infer_implicit(program).items():
        outcome["implicit: " + key] += value
    return outcome


def infer_implicit(program: Program) -> collections.Counter:
    """Tier I for implicit dispatch: an own parameter's operand type from its project call sites,
    exactly as infer_receivers types method receivers."""
    outcome: collections.Counter = collections.Counter()
    for qual, definition in program.defs.items():
        ok = {kind: definition.other_implicit_params[kind] == 0 for kind in ("op", "attr")}
        sites = program.call_sites.get(qual, [])
        for param, names, _operand, kind in definition.implicit_params:
            if not ok[kind]:
                continue
            if not sites:
                ok[kind] = False
                outcome["no project call site (public API)"] += 1
                continue
            for caller_qual, node, offset in sites:
                argument, hidden = call_argument(definition, param, node, offset)
                if argument is None:
                    if hidden:
                        ok[kind] = False
                        outcome["argument hidden by */**"] += 1
                        break
                    continue  # the default value is used at this site
                for origin, value in program.visitor(caller_qual).implicit_origin(argument):
                    if origin in ("project_class", "self") and value:
                        for name in names:
                            definition.edges_inferred |= program.dispatch(value, name)
                        if any(b not in SAFE_EXTERNAL_BASES and program.is_external(b)
                               for b in program.external_bases(value)):
                            ok[kind] = False
                    elif origin in ("builtin", "json", "lambda", "def"):
                        pass
                    elif origin == "stdlib":
                        base = (value or "").split("[")[0].removeprefix("builtins.")
                        if not (base in NAMED_BUILTIN_TYPES or value in JSON_SOURCES):
                            definition.inferred_gaps |= GAP_BIT["method: stdlib-object name"]
                    elif origin == "module" and not (value and program.is_external(value)):
                        pass
                    else:
                        ok[kind] = False
                        outcome[f"a call site passes an untyped value ({origin})"] += 1
                        break
                if not ok[kind]:
                    break
            if ok[kind]:
                outcome["resolved from call sites"] += 1
        definition.implicit_inferred_ok = ok
    return outcome


def cut_unshipped(program: Program) -> collections.Counter:
    """Shipped mode: a shipped definition's resolved call, inferred call or import into unshipped
    code becomes the gap 'subject: reaches unshipped code'.  Name-dispatch candidates are already
    limited to shipped code at registration; the drop below is a check and should count 0."""
    outcome: collections.Counter = collections.Counter()
    bit = GAP_BIT["subject: reaches unshipped code"]
    for qual, definition in program.defs.items():
        if not shipped(definition.path):
            continue
        for edges in (definition.edges, definition.edges_inferred, program.import_edges.get(qual, set())):
            outside = {e for e in edges if e in program.defs and not shipped(program.defs[e].path)}
            if outside:
                edges -= outside
                definition.gaps |= bit
                definition.gaps_n |= bit
                definition.gap_sites["subject: reaches unshipped code"] += len(outside)
                outcome["shipped edges into unshipped code"] += len(outside)
                for target in outside:
                    program.counts["unshipped_target"][program.defs[target].path] += 1
        dropped = {e for e in definition.edges_name if e in program.defs and not shipped(program.defs[e].path)}
        definition.edges_name -= dropped
        outcome["name-dispatch candidates dropped (unshipped)"] += len(dropped)
    return outcome


def own_state(definition: Definition, mode: str) -> tuple[int, int, set[str]]:
    """(channels, gaps, edges) of one definition's own code under a graph mode."""
    if mode == "named":
        return definition.channels, definition.gaps_n, definition.edges | definition.edges_name
    if mode == "inferred":
        gaps = definition.gaps & ~UNTYPED_PARAM if definition.param_inferred_ok else definition.gaps
        for kind, bit in IMPLICIT_PARAM_BIT.items():
            if definition.implicit_inferred_ok.get(kind):
                gaps &= ~bit
        return (definition.channels | definition.inferred_channels, gaps | definition.inferred_gaps,
                definition.edges | definition.edges_inferred)
    return definition.channels, definition.gaps, definition.edges


def fixpoint(program: Program, mode: str) -> tuple[dict[str, int], dict[str, int], dict]:
    named = mode == "named"
    graph: dict[str, list[str]] = {}
    for qual, definition in program.defs.items():
        edges = set(own_state(definition, mode)[2]) | program.import_edges.get(qual, set())
        if definition.node is not None:
            edges.add(program.module_pseudo(definition.module))
        graph[qual] = sorted(e for e in edges if e in program.defs and e != qual)
    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0
    for start in graph:
        if start in index_of:
            continue
        work = [(start, 0)]
        while work:
            node, position = work.pop()
            if position == 0:
                index_of[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            children = graph[node]
            if position < len(children):
                work.append((node, position + 1))
                child = children[position]
                if child not in index_of:
                    work.append((child, 0))
                elif child in on_stack:
                    low[node] = min(low[node], index_of[child])
                continue
            for child in children:
                if child in on_stack:
                    low[node] = min(low[node], low[child])
            if low[node] == index_of[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(component)
    component_of = {m: i for i, c in enumerate(components) for m in c}
    channels = [0] * len(components)
    gaps = [0] * len(components)
    for i, component in enumerate(components):  # Tarjan emits a component after everything it reaches
        c = g = 0
        for member in component:
            own_channels, own_gaps, _ = own_state(program.defs[member], mode)
            c |= own_channels
            g |= own_gaps
            for child in graph[member]:
                j = component_of[child]
                if j != i:
                    c |= channels[j]
                    g |= gaps[j]
        channels[i], gaps[i] = c, g
    sizes = sorted((len(c) for c in components), reverse=True)
    program.counts["largest_components_" + mode].update({str(s): 1 for s in sizes[:5]})
    structure = {"graph": graph, "components": components, "component_of": component_of, "named": named}
    return ({q: channels[component_of[q]] for q in graph}, {q: gaps[component_of[q]] for q in graph}, structure)


def blocking_sets(program: Program, structure: dict, mode: str, resolved: int,
                  entries: dict[str, list[str]]) -> dict[str, set[str]]:
    """For each object: the definitions in its reach whose OWN code carries a gap the tier leaves open."""
    graph, components, component_of = structure["graph"], structure["components"], structure["component_of"]
    carriers = {q for q, d in program.defs.items() if own_state(d, mode)[1] & ~resolved}
    component_carriers = [sorted(m for m in c if m in carriers) for c in components]
    children = [sorted({component_of[ch] for m in c for ch in graph[m]} - {i}) for i, c in enumerate(components)]
    out: dict[str, set[str]] = {}
    for identifier, quals in entries.items():
        seen: set[int] = set()
        stack = [component_of[q] for q in quals if q in component_of]
        found: set[str] = set()
        while stack:
            i = stack.pop()
            if i in seen:
                continue
            seen.add(i)
            found.update(component_carriers[i])
            stack.extend(children[i])
        out[identifier] = found
    return out


def is_test_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return (path.startswith("tests/") or "/tests/" in path or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py")


def bits(value: int, names: list[str]) -> list[str]:
    return [name for index, name in enumerate(names) if value >> index & 1]


def main() -> int:
    dump = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if FACTS_PATH:
        load_facts(json.loads(Path(FACTS_PATH).read_text(encoding="utf-8")))
        say(f"facts from {FACTS_PATH}: " + ", ".join(f"{k} {len(v)}" for k, v in FACTS.items()))
    out = Path(sys.argv[2])
    started = time.perf_counter()
    program = Program(dump["files"])
    program.collect()
    say(f"parsed {len(program.trees)} python files ({len(program.syntax_errors)} unparsable), {len(program.defs)} "
        f"definitions, {len(program.classes)} classes in {time.perf_counter() - started:.1f} s")
    started = time.perf_counter()
    class_attribute_facts(program)
    for definition in list(program.defs.values()):
        BodyVisitor(program, definition).run()
    for path, imports in program.third_party_imports.items():
        pseudo = program.defs[program.module_pseudo(program.module_of[path])]
        for imported in imports:
            category = ("import: ambiguous sys.path-local module" if program.classify_root(imported) == "ambiguous"
                        else "third-party: call or import")
            pseudo.gaps |= GAP_BIT[category]
            pseudo.gaps_n |= GAP_BIT[category]
            pseudo.gap_sites[category] += 1
            program.counts["third_party_import" if category.startswith("third") else "ambiguous_import"][
                imported.partition(".")[0]] += 1
    callbacks = resolve_callbacks(program)
    inferred = infer_receivers(program)
    shipped_cut = cut_unshipped(program) if SHIPPED_ONLY else collections.Counter()
    say(f"bodies, callbacks and receiver inference in {time.perf_counter() - started:.1f} s"
        + (f" (subject program: {SUBJECT})" if SHIPPED_ONLY else ""))
    started = time.perf_counter()
    reach = {mode: fixpoint(program, mode) for mode in ("strict", "inferred", "named")}
    say(f"fixpoints in {time.perf_counter() - started:.1f} s")

    by_path: dict[str, list[str]] = collections.defaultdict(list)
    for qual, definition in program.defs.items():
        by_path[definition.path].append(qual)
    gates: dict[str, dict] = {}
    rows: dict[str, dict] = {}
    entries_all: dict[str, list[str]] = {}
    owners: dict[str, list[str]] = collections.defaultdict(list)
    for identifier, item in sorted(dump["objects"].items()):
        owned = item["owned"]
        for p in owned:
            owners[p].append(identifier)
        code = [p for p in owned if not refutation.is_data_path(p)]
        data_files = len(owned) - len(code)
        if SHIPPED_ONLY:
            code = [p for p in code if shipped(p)]
        python = [p for p in code if p.endswith(".py")]
        other = sorted(p for p in code if not p.endswith(".py"))
        subject_python = [p for p in python if not is_test_path(p)]
        subject_other = [p for p in other if not is_test_path(p)]
        entries = [q for p in python for q in by_path.get(p, [])]
        subject_entries = [q for p in subject_python for q in by_path.get(p, [])]
        entries_all[identifier] = entries
        row = {"primary": item["primary"], "census_item": item["census_item"], "held": item["held"],
               "installed_main": item["main"], "selected_open": sum(1 for c in item["cells"].values()
                                                                   if c["open"] and c["selected"]),
               "python_files": len(python), "test_python_files": len(python) - len(subject_python),
               "other_code": other[:4], "data_files": data_files,
               "has_subject_code": bool(subject_python or subject_other),
               "owns_shipped": not owned or any(shipped(p) for p in owned)}
        census_gap = GAP_BIT["census: empty, undecodable or oversize"] if (
            not owned or item["main"] in ("EMPTY_CENSUS", "SOURCE_UNDECODABLE", "OVERSIZE")) else 0
        base = census_gap
        base |= GAP_BIT["syntax error"] if any(p in program.syntax_errors for p in python) else 0
        base |= GAP_BIT["language: unsupported file"] if other else 0
        subject_base = census_gap
        subject_base |= GAP_BIT["syntax error"] if any(p in program.syntax_errors for p in subject_python) else 0
        subject_base |= GAP_BIT["language: unsupported file"] if subject_other else 0
        row["base"], row["subject_base"] = base, subject_base
        for mode, (channels, gaps, _) in reach.items():
            for prefix, quals, start in (("", entries, base), ("subject_", subject_entries, subject_base)):
                c, g = 0, start
                for q in quals:
                    c |= channels[q]
                    g |= gaps[q]
                row[prefix + mode] = (c, g)
        hits = set()
        for p in owned:
            if p not in gates:
                gates[p] = projection.file_gate_hits(ROOT, p, refutation)
            hits.update((h["code"], h["token"]) for h in gates[p]["hits"] if h["class"] == "code")
        row["ast_gate_hits"] = sorted(hits)
        row["own_gaps"] = sorted({k for q in entries for k, v in program.defs[q].gap_sites.items() if v})
        rows[identifier] = row
    say("objects done")

    def mask(tier: str) -> int:
        return sum(GAP_BIT[name] for name in TIERS[tier][1])

    def view(row: dict, tier: str, prefix: str = "") -> tuple[bool, int, int]:
        channels, gaps = row[prefix + TIERS[tier][0]]
        remaining = gaps & ~mask(tier)
        return remaining == 0, channels, remaining

    in_scope = {i for i, r in rows.items() if not SHIPPED_ONLY or r["owns_shipped"]}
    census = [i for i, r in rows.items() if r["census_item"] and i in in_scope]
    clean = [i for i, r in rows.items() if not r["census_item"] and i in in_scope]
    say(f"in scope: {len(census)} census items, {len(clean)} clean objects"
        + (f" ({len(rows) - len(in_scope)} objects own no shipped code)" if SHIPPED_ONLY else ""))
    tiers = {}
    for tier in TIERS:
        closed = [i for i in census if view(rows[i], tier)[0]]
        no_write = [i for i in closed if not view(rows[i], tier)[1] & WRITE_MASK]
        regex_ok = [i for i in no_write if rows[i]["installed_main"] not in ("DYNAMIC_FEATURE_PRESENT",
                                                                             "EXTERNAL_EFFECT_PRESENT")]
        subject_closed = [i for i in census if rows[i]["has_subject_code"] and view(rows[i], tier, "subject_")[0]]
        subject_no_write = [i for i in subject_closed if not view(rows[i], tier, "subject_")[1] & WRITE_MASK]
        open_by = collections.Counter()
        exactly_one = collections.Counter()
        for i in census:
            ok, _, remaining = view(rows[i], tier)
            if not ok:
                names = bits(remaining, GAPS)
                open_by.update(names)
                if len(names) == 1:
                    exactly_one[names[0]] += 1
        profile = collections.Counter()
        for i in closed:
            profile.update(bits(view(rows[i], tier)[1], CHANNELS))
        tiers[tier] = {
            "graph": TIERS[tier][0], "assumed_resolved": sorted(TIERS[tier][1]),
            "census_items_closed": len(closed),
            "closed_without_external_write": len(no_write),
            "of_those_also_passing_installed_regex_gates": len(regex_ok),
            "held_cells_released_without_external_write": sum(rows[i]["held"] for i in no_write),
            "selected_open_kinds_on_closed_objects": sum(rows[i]["selected_open"] for i in closed),
            "channel_profile_of_closed": dict(profile.most_common()),
            "census_items_open_by_gap": dict(open_by.most_common()),
            "census_items_open_by_exactly_one_gap": dict(exactly_one.most_common()),
            "clean_objects_not_closed_by_reach": sum(1 for i in clean if not view(rows[i], tier)[0]),
            "clean_objects_whose_reach_writes": sum(1 for i in clean if view(rows[i], tier)[1] & WRITE_MASK),
            "subject_only": {"census_items_closed": len(subject_closed),
                             "closed_without_external_write": len(subject_no_write),
                             "held_cells_released_without_external_write": sum(rows[i]["held"] for i in subject_no_write)},
        }
    test_owning = [i for i in census if rows[i]["test_python_files"]]
    subject_view = {"census_items_owning_test_files": len(test_owning),
                    "census_items_with_no_subject_code": sum(1 for i in census if not rows[i]["has_subject_code"])}

    # Which definitions block the most objects at tier C, and how many objects close per definition declared.
    mode = TIERS["C"][0]
    resolved = mask("C")
    structure = reach[mode][2]
    declarable = [i for i in census if not rows[i]["base"]]
    blockers = blocking_sets(program, structure, mode, resolved, {i: entries_all[i] for i in declarable})

    def open_categories(qual: str) -> list[str]:
        return bits(own_state(program.defs[qual], mode)[1] & ~resolved, GAPS)

    def open_sites(qual: str) -> int:
        definition = program.defs[qual]
        names = set(open_categories(qual))
        return sum(v for k, v in definition.gap_sites.items() if k in names) or 1

    hub = collections.Counter(q for i in declarable for q in blockers[i])
    hubs = []
    for qual, count in hub.most_common(25):
        definition = program.defs[qual]
        hubs.append({"definition": qual, "file": definition.path,
                     "line": getattr(definition.node, "lineno", 0), "objects_blocked": count,
                     "open_gaps": open_categories(qual), "open_sites": open_sites(qual),
                     "owning_objects": owners.get(definition.path, [])[:3]})
    index: dict[str, set[str]] = collections.defaultdict(set)
    for i in declarable:
        for q in blockers[i]:
            index[q].add(i)
    left = {i: len(blockers[i]) for i in declarable}
    declared: set[str] = set()
    closed_set = {i for i in declarable if left[i] == 0}
    sites = 0
    curve = [{"definitions_declared": 0, "gap_sites_declared": 0, "objects_closed": len(closed_set)}]
    category_mix: collections.Counter = collections.Counter()
    marks = [10, 25, 50, 100, 200, 400, 800, 1600, 3200, 6400]
    while len(closed_set) < len(declarable):
        pick = min((i for i in declarable if i not in closed_set), key=lambda i: (left[i], -rows[i]["held"], i))
        for qual in blockers[pick] - declared:
            declared.add(qual)
            sites += open_sites(qual)
            category_mix.update(open_categories(qual))
            for i in index[qual]:
                left[i] -= 1
        closed_set |= {i for i in declarable if left[i] == 0}
        if (marks and len(declared) >= marks[0]) or len(closed_set) == len(declarable):
            while marks and len(declared) >= marks[0]:
                marks.pop(0)
            no_write = [i for i in closed_set if not view(rows[i], "C")[1] & WRITE_MASK]
            curve.append({"definitions_declared": len(declared), "gap_sites_declared": sites,
                          "objects_closed": len(closed_set), "closed_without_external_write": len(no_write),
                          "held_cells_released": sum(rows[i]["held"] for i in no_write),
                          "declaration_categories": dict(category_mix.most_common())})
    blocked_sizes = sorted(len(blockers[i]) for i in declarable)

    # Clean objects (installed audit CLOSED) whose followed reach is not closed or writes externally.
    suspicious = []
    for i in clean:
        ok, channels, remaining = view(rows[i], "S")
        if ok and not channels & WRITE_MASK:
            continue
        reached = blocking_sets(program, reach["strict"][2], "strict", 0, {i: entries_all[i]})[i]
        writers = sorted(q for q in reached if program.defs[q].channels & WRITE_MASK)[:5]
        suspicious.append({"object": i, "closed_at_S": ok, "open_gaps": bits(remaining, GAPS),
                           "channels": bits(channels, CHANNELS), "gap_carriers": sorted(reached)[:5],
                           "own_python_files": rows[i]["python_files"]})
        if writers:
            suspicious[-1]["write_reached_via"] = writers

    location = collections.Counter()
    for i in census:
        ok, _, remaining = view(rows[i], "C")
        if not ok:
            location["only via other objects' code" if not (set(bits(remaining, GAPS)) & set(rows[i]["own_gaps"]))
                     else "some in its own files"] += 1
    gap_sites = collections.Counter()
    for definition in program.defs.values():
        gap_sites.update({k: v for k, v in definition.gap_sites.items() if v})
    fan = sorted(program.fanout)
    report = {
        "coordinate": {**dump["coordinate"], "analysis_finished": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "analysis_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "program": {"python_files": len(program.trees), "unparsable": sorted(program.syntax_errors)[:10],
                    "definitions": len(program.defs), "classes": len(program.classes),
                    "sys_path_local_names_registered": program.local_names,
                    "ambiguous_local_module_names": len(program.ambiguous_modules),
                    "gap_sites_strict": dict(gap_sites.most_common()), "callback_resolution": dict(callbacks),
                    "receiver_inference": dict(inferred),
                    "subject_program": SUBJECT or "whole", "name_rule": NAME_RULE, "shipped_cut": dict(shipped_cut),
                    "implicit": IMPLICIT, "annotations": ANNOTATIONS, "facts": FACTS_PATH,
                    "facts_loaded": {k: len(v) for k, v in FACTS.items()},
                    "objects_without_shipped_code": len(rows) - len(in_scope),
                    "name_dispatch_fanout": {"calls": len(fan), "median": fan[len(fan) // 2] if fan else 0,
                                             "p90": fan[int(len(fan) * .9)] if fan else 0, "max": fan[-1] if fan else 0},
                    "counts": {k: dict(v.most_common(None if k in TIER_T_ASSUMPTIONS else 30))
                               for k, v in sorted(program.counts.items())}},
        "census_items": len(census), "clean_objects": len(clean), "tiers": tiers, "subject_view": subject_view,
        "tier_C_open_by_gap_location": dict(location),
        "tier_C_declaration": {"declarable_census_items": len(declarable),
                               "not_declarable_base_gaps": len(census) - len(declarable),
                               "distinct_blocking_definitions": len(hub),
                               "blocking_definitions_per_object": {
                                   "median": blocked_sizes[len(blocked_sizes) // 2] if blocked_sizes else 0,
                                   "p10": blocked_sizes[len(blocked_sizes) // 10] if blocked_sizes else 0,
                                   "p90": blocked_sizes[int(len(blocked_sizes) * .9)] if blocked_sizes else 0},
                               "hubs": hubs, "greedy_curve": curve},
        "clean_objects_flagged_by_reach": suspicious,
        # The installed audit reads only an object's own files.  These clean objects (audit CLOSED)
        # hold an implicit dispatch on a parameter or an unknown value in their own code.
        "clean_objects_with_own_implicit_gaps": {
            name: sum(1 for i in clean if name in rows[i]["own_gaps"])
            for name in GAPS if name.startswith("implicit:")},
        "clean_objects_with_any_own_implicit_gap": sorted(
            i for i in clean if any(g.startswith("implicit:") for g in rows[i]["own_gaps"])),
        "objects": {i: {**{k: v for k, v in r.items() if not isinstance(v, tuple)},
                        **{m: {"channels": bits(r[m][0], CHANNELS), "gaps": bits(r[m][1], GAPS)}
                           for m in r if isinstance(r[m], tuple)}}
                    for i, r in rows.items()},
    }
    out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    for tier in TIERS:
        t = tiers[tier]
        say(f"tier {tier}: closed {t['census_items_closed']}/{len(census)}; without external write "
            f"{t['closed_without_external_write']} (releases {t['held_cells_released_without_external_write']} cells); "
            f"subject-only closed {t['subject_only']['census_items_closed']}")
    say(f"tier C declaration curve: {[(p['definitions_declared'], p['objects_closed']) for p in curve]}")
    say(f"wrote {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
