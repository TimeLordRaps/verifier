"""Check reasons against the code, give each reason a status, write the facts the admitted ones carry.

Python's abstract syntax tree (AST) supplies position-free source structure.

usage: python -B reasons_check.py OUT_DIR REASONS.vstd [MORE.vstd ...]

Read-only on the selected source root.  The analysis switches (REACH_NAME_RULE, REACH_IMPLICIT,
REACH_ANNOTATIONS, REACH_SUBJECT) come from the environment; they decide which gaps a site has, so
REDUNDANT and NOT-LOAD-BEARING depend on them.  Builds the prototype's program over the census files
(the selected object dump; with REACH_SUBJECT set, only the subject's call sites count and the rest of the
tree is a witness, listed but never refuting: decision 16), runs every definition's own
body once with no facts, then checks the reasons to a least fixpoint: a reason whose bases verify
and whose falsifiers bite is admitted, its facts join the known facts, and the rest are checked
again until nothing changes.  A reason that needs another reason's fact waits for it; circular
reasons derive nothing.

Statuses, in precedence order:
  MALFORMED         does not compile (reasons_dsl)
  UNANSWERED        still holds a `?` slot: a stub, inert
  STALE             the site is gone, or a DOCUMENTED reason's bound digest no longer matches the code
  REFUTED           a basis check fails: the code does not say what the basis claims
  UNCHECKED         the checker cannot read a cited basis; inert and never admitted
  CONFLICTED        another admitted reason types the same site, attribute or definition differently
  NOT-LOAD-BEARING  a falsifier did not bite, or, admitted, it closes nothing at its sites
  REDUNDANT         its sites are not open without it (the machine or a stronger reason closes them)
  ESTABLISHED       every basis is a machine check and verified, and a falsifier ran and bit
  DOCUMENTED        verified up to a stated basis (an annotation, a declaration, a named assumption),
                    or no falsifier ran
Nothing is deleted: every status, with its evidence, is in OUT_DIR/check.json.

Writes OUT_DIR/check.json, OUT_DIR/facts_established.json (ESTABLISHED) and
OUT_DIR/facts_documented.json (ESTABLISHED and DOCUMENTED), in the REACH_FACTS format.
"""
from __future__ import annotations

import ast
import collections
import copy
import dataclasses
import hashlib
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# No facts preloaded: a reason is checked against the code, never against facts admitted from reasons.
# REACH_SUBJECT (and its older spelling REACH_SHIPPED=1) is kept: it chooses whose call sites count and
# which code is a witness.  Popping it here once made every run check the whole tree whatever it was told.
os.environ.pop("REACH_FACTS", None)
import reasons_dsl as dsl  # noqa: E402
import effect_reach_prototype as reach  # noqa: E402

audit = reach.audit
BUILTIN_TYPES = {"str", "bytes", "int", "float", "bool", "dict", "list", "tuple", "set", "frozenset"}
BUILTIN_RESULT_TYPES = {"dict": "dict", "list": "list", "tuple": "tuple", "set": "set", "frozenset": "frozenset",
                        "str": "str", "bytes": "bytes", "int": "int", "float": "float", "bool": "bool",
                        "sorted": "list", "repr": "str", "len": "int", "isinstance": "bool", "callable": "bool"}
STR_METHODS_STR = {"strip", "lstrip", "rstrip", "lower", "upper", "casefold", "replace", "format", "join",
                   "removeprefix", "removesuffix", "title", "capitalize", "zfill", "center", "ljust", "rjust"}
COPY_DUNDERS = ("__deepcopy__", "__copy__", "__reduce__", "__reduce_ex__", "__getstate__", "__setstate__")
# isinstance(v, C) is True for a subclass of C, and for any object whose __class__ property names C
# (unittest.mock.Mock(spec=C) does exactly this): redefinition_probe.py part 3, Python 3.10-3.14.
# type(v) is C admits neither.  A reason whose type comes from isinstance must name this assumption.
ASSUMPTION_BUILTIN_SUBCLASSES = "isinstance-means-exact"
CONSUMING_BUILTINS = {"isinstance", "len", "tuple", "list", "dict", "set", "frozenset", "sorted", "str", "repr", "bool",
                      "any", "all", "sum", "min", "max", "type", "id", "hash", "iter", "next", "enumerate", "zip"}
PLANTED = "_planted_unknown_value"
STDLIB_ANNOTATION_TYPES = {"pathlib.Path": "stdlib:pathlib.Path"}
RANK = {"ESTABLISHED": 2, "DOCUMENTED": 1}
# The gap categories each reach tier's assumptions resolve (the prototype's TIERS; S and I share the
# strict trial here: call-site inference is measured by the full reach run, not by a trial).
RESOLVED_AT = {tier: frozenset(reach.TIERS[tier][1]) for tier in ("S", "I", "T", "C")}
# Facts resting on "project callers are all callers" (A1): valid at tier I and above, never at tier S.
# Every tier, S included, already rests on A0: code outside the project rebinds no project global or
# attribute and patches no standard-library name.
A1_BASES = {"call-sites", "registry"}
A1_FORMS = {"boundary", "contract"}
# Writes spelled as a call: setattr-like (receiver, constant name) and dotted-string patches.
SETATTR_LIKE = {"setattr", "delattr", "object.__setattr__", "object.__delattr__"}
SETATTR_LAST = {"setattr", "delattr"}          # monkeypatch.setattr, mp.delattr, any *.setattr(obj, "name", ...)
DOTTED_PATCH_LAST = {"setattr", "delattr", "patch"}  # monkeypatch.setattr("pkg.mod.name", v), mock.patch("pkg.mod.name")


# ----- canonical AST digest: the form measured on five interpreters (Addendum 1 section 4.1) -------
def canonical_ast(node) -> str:
    if isinstance(node, ast.AST):
        parts = []
        for name in node._fields:
            value = getattr(node, name, None)
            if value is None or (isinstance(value, list) and not value):
                continue
            parts.append(name + "=" + canonical_ast(value))
        return type(node).__name__ + "(" + ",".join(parts) + ")"
    if isinstance(node, list):
        return "[" + ",".join(canonical_ast(item) for item in node) + "]"
    return repr(node)


def ast_digest(node) -> str:
    return "sha256:" + hashlib.sha256(canonical_ast(node).encode("utf-8")).hexdigest()


def shape(node) -> str:
    """Location-free structure, for matching a reason's expression to code on this interpreter."""
    return ast.dump(node, annotate_fields=True, include_attributes=False)


# ----- the standard-library table: each row is run on this interpreter -----------------------------
def _probe_json_loads() -> bool:
    def exact(value) -> bool:
        if type(value) in (str, int, float, bool, type(None)):
            return True
        if type(value) is list:
            return all(exact(v) for v in value)
        if type(value) is dict:
            return all(type(k) is str and exact(v) for k, v in value.items())
        return False
    return exact(json.loads('{"a": [1, 2.5, "x", null, true, {"b": {}}], "c": -3}')) and exact(json.loads(b'[1]'))


def _probe_re_compile() -> bool:
    import re as r
    return type(r.compile(r"^(?:sha256:)?([0-9a-f]{64})$")) is r.Pattern


def _probe_fullmatch() -> bool:
    import re as r
    pattern = r.compile(r"(a)")
    return (type(r.Pattern.fullmatch).__name__ == "method_descriptor" and type(pattern.fullmatch("a")) is r.Match
            and pattern.fullmatch("b") is None)


def _probe_group() -> bool:
    import re as r
    matched = r.compile("(a)").fullmatch("a")
    return type(r.Match.group).__name__ == "method_descriptor" and matched is not None and type(matched.group(1)) is str


def _probe_sha256() -> bool:
    return type(hashlib.sha256(b"x").hexdigest()) is str and type(hashlib.sha256).__name__ == "builtin_function_or_method"


def _probe_deepcopy() -> bool:
    @dataclasses.dataclass(frozen=True)
    class Probe:
        a: int

    class Sub(Probe):
        pass
    return type(copy.deepcopy(Probe(1))) is Probe and type(copy.deepcopy(Sub(1))) is Sub


def _probe_text_open_read() -> bool:
    with open(__file__, "r", encoding="utf-8") as handle:
        return isinstance(handle, io.TextIOBase) and type(handle.read(0)) is str


def _probe_path_parent() -> bool:
    return isinstance((Path("a") / "b").parent, Path)


ROWS = {  # name -> (result token, precondition, probe)
    "re.compile": ("stdlib:re.Pattern", "the pattern argument is a str constant", _probe_re_compile),
    "re.Pattern.fullmatch": ("optional:stdlib:re.Match", "C method; a str argument runs no Python code", _probe_fullmatch),
    "re.Match.group": ("optional:str", "C method", _probe_group),
    "json.loads": ("json", "no cls/object_hook/object_pairs_hook/parse_* keyword", _probe_json_loads),
    "json.dumps": ("str", "no cls/default keyword", lambda: type(json.dumps({"a": [1]})) is str),
    "str.encode": ("bytes", "an exact str receiver", lambda: type("x".encode("utf-8")) is bytes),
    "hashlib.sha256": ("stdlib:_hashlib.HASH", "C function", _probe_sha256),
    "hashlib.HASH.hexdigest": ("str", "C method", _probe_sha256),
    "copy.deepcopy": ("same", "no project class of the argument defines a copy or pickling dunder", _probe_deepcopy),
    "open.text": ("stdlib:io.TextIOBase", "builtin open in non-binary mode", _probe_text_open_read),
    "io.TextIOBase.read": ("str", "a text IO receiver", _probe_text_open_read),
    "pathlib.Path.parent": ("stdlib:pathlib.Path", "a pathlib.Path receiver", _probe_path_parent),
}
ROW_RESULTS = {name: bool(probe()) for name, (_, _, probe) in ROWS.items()}


def _sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


# the tools as loaded (an edit during a run must not change what the report says ran)
OBJECTS_DUMP = Path(os.environ.get("REASONS_OBJECTS_DUMP", str(HERE / "objects_dump.json")))
TOOLS_AT_START = {name: _sha(HERE / name) for name in
                  ("reasons_check.py", "reasons_dsl.py", "effect_reach_prototype.py")}
TOOLS_AT_START["objects_dump.json"] = _sha(OBJECTS_DUMP)
JSON_HOOKS = {"cls", "object_hook", "object_pairs_hook", "parse_float", "parse_int", "parse_constant"}


# ----- recording the gaps one definition's body raises (trials) -------------------------------------
class Recorder:
    qual: str | None = None
    hits: list = []


RECORDER = Recorder()
_ORIGINAL = {name: getattr(reach.BodyVisitor, name) for name in ("gap", "call", "implicit")}


def _call(self, node):
    previous = getattr(self, "_rc_node", None)
    self._rc_node = node
    try:
        return _ORIGINAL["call"](self, node)
    finally:
        self._rc_node = previous


def _implicit(self, operand, names, kind):
    previous = getattr(self, "_rc_node", None)
    self._rc_node = operand
    try:
        return _ORIGINAL["implicit"](self, operand, names, kind)
    finally:
        self._rc_node = previous


def _gap(self, category, strict=True, named=True):
    if strict and RECORDER.qual is not None and getattr(self.d, "_rc_trial", False):
        node = getattr(self, "_rc_node", None)
        RECORDER.hits.append((getattr(node, "lineno", 0), getattr(node, "col_offset", -1) + 1, category,
                              ast.unparse(node)[:160] if node is not None else ""))
    return _ORIGINAL["gap"](self, category, strict, named)


reach.BodyVisitor.call, reach.BodyVisitor.implicit, reach.BodyVisitor.gap = _call, _implicit, _gap


@dataclasses.dataclass
class Used:
    rows: set = dataclasses.field(default_factory=set)
    facts: set = dataclasses.field(default_factory=set)     # ids of admitted reasons whose facts were used
    notes: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Basis:
    kind: str
    ok: bool
    strength: str            # ESTABLISHED or DOCUMENTED
    detail: str
    types: frozenset | None = None
    narrowing: list | None = None
    checked: bool = True       # False means the checker lacks this mechanism: UNCHECKED, never REFUTED.


class Patches:
    """In-place AST edits for a falsifier run, undone in reverse order.

    The falsifier may edit only this closed set of abstract-syntax-tree fields.
    It never receives a general object-attribute mutation capability.
    """

    def __init__(self, code: "Code") -> None:
        self.code, self.undo = code, []

    @staticmethod
    def _read(obj: ast.AST, field: str):
        if field == "annotation":
            return obj.annotation
        if field == "returns":
            return obj.returns
        if field == "value":
            return obj.value
        if field == "args":
            return obj.args
        if field == "elts":
            return obj.elts
        if field == "test":
            return obj.test
        if field == "operand":
            return obj.operand
        if field == "values":
            return obj.values
        if field == "comparators":
            return obj.comparators
        if field == "ifs":
            return obj.ifs
        raise ValueError(f"UNREVIEWED_FALSIFIER_AST_FIELD:{field}")

    @staticmethod
    def _write(obj: ast.AST, field: str, value) -> None:
        if field == "annotation":
            obj.annotation = value
        elif field == "returns":
            obj.returns = value
        elif field == "value":
            obj.value = value
        elif field == "args":
            obj.args = value
        elif field == "elts":
            obj.elts = value
        elif field == "test":
            obj.test = value
        elif field == "operand":
            obj.operand = value
        elif field == "values":
            obj.values = value
        elif field == "comparators":
            obj.comparators = value
        elif field == "ifs":
            obj.ifs = value
        else:
            raise ValueError(f"UNREVIEWED_FALSIFIER_AST_FIELD:{field}")

    def set(self, obj, field: str, value, index: int | None = None) -> None:
        if index is None:
            self.undo.append((obj, field, None, self._read(obj, field)))
            self._write(obj, field, value)
        else:
            items = self._read(obj, field)
            self.undo.append((obj, field, index, items[index]))
            items[index] = value
        self.code.invalidate()

    def insert(self, body: list, index: int, statement: ast.stmt) -> None:
        body.insert(index, statement)
        self.undo.append((body, None, "inserted", statement))
        self.code.invalidate()

    def restore(self) -> None:
        for obj, field, index, old in reversed(self.undo):
            if index == "inserted":
                obj.remove(old)
            elif index is None:
                self._write(obj, field, old)
            else:
                self._read(obj, field)[index] = old
        self.undo = []
        self.code.invalidate()


class _Every:
    def __contains__(self, _item) -> bool:
        return True


_EVERY_NAME = _Every()  # a computed write into builtins could rebind any builtin name


def planted_name(near: ast.AST) -> ast.Name:
    return ast.copy_location(ast.Name(id=PLANTED, ctx=ast.Load()), near)


def statement(text: str, near: ast.AST) -> ast.stmt:
    node = ast.parse(text).body[0]
    for inner in ast.walk(node):
        ast.copy_location(inner, near)
    return node


class Code:
    """The census program, read through the prototype, plus the indexes the checks need."""

    def __init__(self) -> None:
        started = time.perf_counter()
        dump = json.loads(OBJECTS_DUMP.read_text(encoding="utf-8"))
        self.object_dump = dump.get("objects", {})
        self.open_obligations = dump.get("open_obligations", [])
        self.program = program = reach.Program(dump["files"])
        program.collect()
        reach.class_attribute_facts(program)
        for definition in list(program.defs.values()):
            reach.BodyVisitor(program, definition).run()
        self._attr_stores: dict | None = None
        self._computed: list | None = None
        self._dotted: dict | None = None
        self._witness: tuple | None = None
        self._builtins: set | None = None
        self._nodes: dict[str, list] = {}
        print(f"program: {len(program.trees)} files, {len(program.defs)} definitions, {len(program.classes)} classes "
              f"in {time.perf_counter() - started:.0f} s", flush=True)

    def invalidate(self) -> None:
        self._nodes.clear()
        self._attr_stores = self._computed = self._dotted = self._builtins = self._witness = None
        self.program._visitors.clear()

    @staticmethod
    def in_subject(path: str) -> bool:
        """In the subject program, cut as the prototype cuts it (REACH_SUBJECT).  Code outside it is a witness
        (decision 16): what a witness writes, constructs or subclasses bounds that witness's evidence and is
        listed, but never refutes a claim about the subject, which rests on A0 for everything outside it."""
        return not reach.SHIPPED_ONLY or reach.shipped(path)

    def witness_writes(self, name: str) -> list[str]:
        """Writes in witness code that could rebind `name`: by constant name, by dotted patch, or computed."""
        self.attr_stores("")
        index, computed, dotted = self._witness
        hits = [f"{self.program.defs[q].path}:{line} {how}" for q, line, how, _n in index.get(name, [])]
        hits += [f"{self.program.defs[q].path}:{line} {how}" for target, entries in dotted.items()
                 if target.rpartition(".")[2] == name for q, line, how, _n in entries]
        hits += [f"{self.program.defs[q].path}:{line} {how} (computed name)" for q, line, how, _r, _x in computed]
        return hits

    def qual(self, ref: dict) -> str | None:
        module = self.program.module_of.get(ref["path"])
        if module is None:
            return None
        qual = f"{module}.{ref['qual']}"
        return qual if qual in self.program.defs or qual in self.program.classes else None

    def own_nodes(self, qual: str) -> list:
        if qual not in self._nodes:
            self._nodes[qual] = reach.BodyVisitor(self.program, self.program.defs[qual]).nodes
        return self._nodes[qual]

    def enclosing_class(self, qual: str) -> str | None:
        definition = self.program.defs.get(qual)
        return (definition.class_qual or definition.outer_class) if definition else None

    def class_token(self, path: str, node: ast.AST, exact: bool) -> str | None:
        """A type expression -> a type token: a builtin type name, or a project class."""
        raw = audit._dotted_name(node)
        if raw is None:
            return None
        if raw in BUILTIN_TYPES and not self.shadowed(path, raw):
            return raw
        resolved = self.program.class_qual(path, audit._aliased_name(raw, self.program.aliases.get(path, {})))
        if resolved:
            return ("exact:" if exact else "class:") + resolved
        return None

    def shadowed(self, path: str, name: str) -> bool:
        """A builtin name that does not mean the builtin here: bound at module level in `path`, or rebound
        anywhere in the program through the builtins module."""
        return name in self.program.top_names.get(path, {}) or name in self.program.top_values.get(path, {}) \
            or name in self.program.aliases.get(path, {}) or name in self.builtin_rebinds()

    def builtin_rebinds(self) -> set:
        """Builtin names some project code rebinds: builtins.X = v, setattr(builtins, "X", v),
        monkeypatch.setattr("builtins.X", v), mock.patch("builtins.X"); "*" when a computed write could."""
        if getattr(self, "_builtins", None) is None:
            names: set = set()
            self.attr_stores("")
            for attr, entries in (self._attr_stores or {}).items():
                for qual, _line, how, node in entries:
                    receiver = node.value if how == "store" else node.args[0]
                    raw = audit._dotted_name(receiver)
                    dotted = audit._aliased_name(raw, self.program.aliases.get(self.program.defs[qual].path, {})) \
                        if raw else None
                    if dotted in ("builtins", "__builtins__"):
                        names.add(attr)
            for target in (self._dotted or {}):
                module, _, attr = target.rpartition(".")
                if module in ("builtins", "__builtins__"):
                    names.add(attr)
            for qual, _line, _how, receiver, _name in (self._computed or []):
                raw = audit._dotted_name(receiver) if receiver is not None else None
                dotted = audit._aliased_name(raw, self.program.aliases.get(self.program.defs[qual].path, {})) \
                    if raw else None
                if dotted in ("builtins", "__builtins__"):
                    names.add("*")
            self._builtins = names
        return self._builtins if "*" not in self._builtins else _EVERY_NAME

    def subclasses(self, class_qual: str) -> set:
        out, todo = set(), [class_qual]
        while todo:
            for sub in self.program.subclasses.get(todo.pop(), ()):
                if sub not in out:
                    out.add(sub)
                    todo.append(sub)
        return out

    def supers(self, class_qual: str) -> set:
        out, todo = set(), [class_qual]
        while todo:
            info = self.program.classes.get(todo.pop())
            for base in (info.bases if info else []):
                if base not in out:
                    out.add(base)
                    todo.append(base)
        return out

    def related(self, a: str, b: str) -> bool:
        family = {a} | self.subclasses(a) | self.supers(a)
        return b in family or bool(self.subclasses(b) & ({a} | self.subclasses(a)))

    def attr_stores(self, attr: str) -> list:
        """Every write of an attribute by constant name: stores, deletes, setattr/delattr/object.__setattr__,
        and the test-time spellings (monkeypatch.setattr(obj, "name", v), patch.object(obj, "name")).
        A dotted-string patch (monkeypatch.setattr("pkg.mod.name", v), mock.patch("pkg.mod.name")) is
        indexed separately, by its dotted target: see dotted_writes."""
        if self._attr_stores is None:
            built = {flag: (collections.defaultdict(list), [], collections.defaultdict(list)) for flag in (True, False)}
            for qual in self.program.defs:
                # subject writes refute; witness writes (outside the subject program) are only listed
                index, computed, dotted = built[self.in_subject(self.program.defs[qual].path)]
                for node in self.own_nodes(qual):
                    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        index[node.attr].append((qual, node.lineno, "store", node))
                    elif isinstance(node, ast.Call):
                        raw = audit._dotted_name(node.func)
                        last = raw.rpartition(".")[2] if raw else None
                        first = node.args[0] if node.args else None
                        if last in DOTTED_PATCH_LAST and isinstance(first, ast.Constant) and isinstance(first.value, str) \
                                and "." in first.value and (last == "patch" or len(node.args) <= 2):
                            dotted[first.value].append((qual, node.lineno, f"{raw}('{first.value}')", node))
                            continue
                        setattr_like = raw in SETATTR_LIKE or last in SETATTR_LAST or (raw or "").endswith("patch.object")
                        if setattr_like and len(node.args) >= 2:
                            name = node.args[1]
                            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                                index[name.value].append((qual, node.lineno, raw, node))
                            else:
                                computed.append((qual, node.lineno, raw, node.args[0], name))
                        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("update", "__setitem__", "setdefault") \
                                and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "__dict__":
                            computed.append((qual, node.lineno, "__dict__." + node.func.attr, node.func.value.value, None))
                    elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        inner = node.value
                        if isinstance(inner, ast.Attribute) and inner.attr == "__dict__":
                            computed.append((qual, node.lineno, "__dict__[...]", inner.value, None))
                        elif isinstance(inner, ast.Call) and audit._dotted_name(inner.func) == "vars" and inner.args:
                            computed.append((qual, node.lineno, "vars(...)[...]", inner.args[0], None))
            self._attr_stores, self._computed, self._dotted = built[True]
            self._witness = built[False]
        return self._attr_stores.get(attr, [])

    def computed_writes(self) -> list:
        self.attr_stores("")
        return self._computed or []

    def dotted_writes(self, path: str, name: str) -> list:
        """Dotted-string patches whose target is module `path`'s global `name`."""
        self.attr_stores("")
        hits = []
        for target, entries in (self._dotted or {}).items():
            module, _, attr = target.rpartition(".")
            if attr == name and self.program.module_path.get(module) == path:
                hits.extend(f"{self.program.defs[q].path}:{line} {how}" for q, line, how, _n in entries)
        return hits

    def module_attr_writes(self, path: str, name: str) -> list:
        """Every write that could rebind module `path`'s global `name` from outside its module-level
        statements: attribute stores and setattr-likes on the module, dotted patches, computed writes,
        and global statements anywhere in the module."""
        hits = []
        for qual, line, how, node in self.attr_stores(name):
            receiver = node.value if how == "store" else node.args[0]
            owner_path = self.program.defs[qual].path
            raw = audit._dotted_name(receiver)
            target = audit._aliased_name(raw, self.program.aliases.get(owner_path, {})) if raw else None
            if target is not None and self.program.module_path.get(target) == path:
                hits.append(f"{owner_path}:{line} {how}")
            elif target is not None and (target in self.program.module_path or target in ("self", "cls")
                                         or self.program.class_qual(owner_path, target) is not None):
                continue  # provably another module, a class, or an instance: not this module's global
            else:  # a local, a parameter, an attribute chain or an expression: it could hold the module
                hits.append(f"{owner_path}:{line} {how} on `{ast.unparse(receiver)[:40]}`, which could be the module")
        hits += self.dotted_writes(path, name)
        hits += self.void_writes("module", path, name)
        for inner in ast.walk(self.program.trees[path]):
            if isinstance(inner, ast.Global) and name in inner.names:
                hits.append(f"{path}:{inner.lineno} global {name}")
        return hits

    def param_values(self, qual: str, name: str, depth: int = 0) -> list | None:
        """The expressions every project call site passes for a parameter, through forwarding callers (None: unknown)."""
        definition = self.program.defs[qual]
        if name not in definition.params or depth > 3:
            return None
        sites = self.program.call_sites.get(qual, [])
        if not sites:
            return None
        values = []
        for caller, node, offset in sites:
            argument, hidden = reach.call_argument(definition, name, node, offset)
            if argument is None:
                return None
            if isinstance(argument, ast.Name) and argument.id in self.program.defs[caller].params:
                forwarded = self.param_values(caller, argument.id, depth + 1)
                if forwarded is None:
                    return None
                values.extend(forwarded)
            else:
                values.append((caller, argument))
        return values

    def write_targets(self, entry) -> tuple:
        """(receivers, names) a computed write can hit; None for either means anything."""
        qual, _line, _how, receiver, name = entry
        if name is None:
            names = None
        elif isinstance(name, ast.Name) and name.id in self.program.defs[qual].params:
            values = self.param_values(qual, name.id)
            names = None if values is None or not all(isinstance(v, ast.Constant) and isinstance(v.value, str)
                                                      for _c, v in values) else {v.value for _c, v in values}
        elif isinstance(name, ast.Name):
            module_path = self.program.defs[qual].path
            value = self.program.top_values.get(module_path, {}).get(name.id)
            names = {value.value} if isinstance(value, ast.Constant) and isinstance(value.value, str) \
                and len(self.program.top_values_all[module_path][name.id]) == 1 else None
        else:
            names = None
        owner = self.enclosing_class(qual)
        if isinstance(receiver, ast.Name) and receiver.id == "self" and owner:
            receivers = {("instance", owner)}
        elif isinstance(receiver, ast.Name) and receiver.id in self.program.defs[qual].params:
            values = self.param_values(qual, receiver.id)
            receivers = None if values is None else {self.module_or_class(c, v) for c, v in values}
            if receivers is not None and None in receivers:
                receivers = None
        else:
            receivers = {self.module_or_class(qual, receiver)}
            if None in receivers:
                receivers = None
        return receivers, names

    def module_or_class(self, qual: str, node: ast.AST):
        path = self.program.defs[qual].path
        raw = audit._dotted_name(node)
        if raw is None:
            return None
        dotted = audit._aliased_name(raw, self.program.aliases.get(path, {}))
        if dotted in self.program.module_path:
            return ("module", self.program.module_path[dotted])
        resolved = self.program.class_qual(path, dotted)
        return ("class", resolved) if resolved else None

    def void_writes(self, kind: str, target: str, name: str) -> list[str]:
        """Computed writes that could rebind module global `name` (kind 'module', target a path) or an instance
        attribute `name` of class `target` (kind 'instance')."""
        hits = []
        for entry in self.computed_writes():
            qual, line, how, _receiver, _name = entry
            receivers, names = self.write_targets(entry)
            if names is not None and name not in names:
                continue
            if receivers is not None:
                if kind == "module" and ("module", target) not in receivers:
                    continue
                if kind == "instance" and not any(r[0] == "instance" and self.related(r[1], target) for r in receivers):
                    continue
            hits.append(f"{self.program.defs[qual].path}:{line} {how}")
        return hits


class Checker:
    def __init__(self, code: Code, reasons: list[dict]) -> None:
        self.code, self.p = code, code.program
        self.reasons = {r["id"]: r for r in reasons}
        self.admitted: dict[str, dict] = {}
        self.attr_facts: dict[tuple, tuple] = {}
        self.return_facts: dict[str, tuple] = {}
        self.boundaries: set = set()
        self.results: dict[str, dict] = {}

    # ----- types of values ---------------------------------------------------------------------------
    def sole_local(self, qual: str, name: str) -> tuple[ast.AST | None, str]:
        definition = self.p.defs[qual]
        if name in definition.params:
            return None, "a parameter"
        node = definition.node
        if node is not None:
            for inner in ast.walk(node):
                if isinstance(inner, (ast.Global, ast.Nonlocal)) and name in inner.names:
                    return None, "declared global or nonlocal"
        stores = []
        for inner in self.code.own_nodes(qual):
            if isinstance(inner, ast.Name) and inner.id == name and isinstance(inner.ctx, (ast.Store, ast.Del)):
                stores.append(inner)
            elif isinstance(inner, (ast.Import, ast.ImportFrom)) and any((a.asname or a.name.split(".")[0]) == name
                                                                          for a in inner.names):
                stores.append(inner)
            elif isinstance(inner, ast.ExceptHandler) and inner.name == name:
                stores.append(inner)
        for nested in self.p.visitor(qual).nested:
            if nested.name == name:
                stores.append(nested)
        if not stores:
            return None, "not bound here"
        if len(stores) != 1:
            return None, f"{len(stores)} bindings"
        target = stores[0]

        def unpacked_value(left: ast.AST, right: ast.AST) -> ast.AST | None:
            if left is target:
                return right
            if isinstance(left, (ast.Tuple, ast.List)) and isinstance(right, (ast.Tuple, ast.List)) \
                    and len(left.elts) == len(right.elts):
                for left_item, right_item in zip(left.elts, right.elts):
                    found = unpacked_value(left_item, right_item)
                    if found is not None:
                        return found
            return None

        for inner in self.code.own_nodes(qual):
            if isinstance(inner, ast.Assign) and len(inner.targets) == 1 and inner.targets[0] is target:
                return inner.value, "sole assignment"
            if isinstance(inner, ast.Assign) and len(inner.targets) == 1:
                found = unpacked_value(inner.targets[0], inner.value)
                if found is not None:
                    return found, "sole literal-tuple unpacking"
            if isinstance(inner, ast.AnnAssign) and inner.target is target and inner.value is not None:
                return inner.value, "sole assignment"
            if isinstance(inner, (ast.With, ast.AsyncWith)):
                for item in inner.items:
                    if item.optional_vars is target:
                        return item.context_expr, "sole with binding"
        return None, "bound by unpacking, a loop, a with, or an import"

    def module_bindings(self, path: str, name: str) -> list:
        """(statement, binding node) for every module-level binding of `name` in `path`."""
        stores = []
        for statement_ in self.p._module_statements(self.p.trees[path].body):
            nodes = [statement_] if isinstance(statement_, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                else list(ast.walk(statement_))
            for inner in nodes:
                if isinstance(inner, ast.Name) and inner.id == name and isinstance(inner.ctx, (ast.Store, ast.Del)):
                    stores.append((statement_, inner))
                elif isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and inner.name == name:
                    stores.append((statement_, inner))
                elif isinstance(inner, (ast.Import, ast.ImportFrom)) and any((a.asname or a.name.split(".")[0]) == name
                                                                              for a in inner.names):
                    stores.append((statement_, inner))
        return stores

    def sole_global(self, path: str, name: str) -> tuple[ast.AST | None, str]:
        stores = self.module_bindings(path, name)
        writes = self.code.module_attr_writes(path, name)
        if writes:
            return None, f"it could be rebound ({'; '.join(writes[:3])}{'; ...' if len(writes) > 3 else ''})"
        if len(stores) != 1:
            return None, f"{len(stores)} module-level bindings"
        statement_, target = stores[0]
        if isinstance(statement_, ast.Assign) and len(statement_.targets) == 1 and statement_.targets[0] is target:
            return statement_.value, "sole module assignment"
        if isinstance(statement_, ast.AnnAssign) and statement_.target is target and statement_.value is not None:
            return statement_.value, "sole module assignment"
        return None, "bound by something other than one assignment"

    def infer(self, expr: ast.AST, qual: str, used: Used, depth: int = 0) -> frozenset | None:
        """The types an expression's value can have, from sole assignments, admitted facts and table rows."""
        if depth > 8:
            return None
        path = self.p.defs[qual].path
        if isinstance(expr, ast.Constant):
            return frozenset({"none" if expr.value is None else type(expr.value).__name__})
        if isinstance(expr, ast.JoinedStr):
            return frozenset({"str"})
        for node_type, token in ((ast.Dict, "dict"), (ast.DictComp, "dict"), (ast.List, "list"), (ast.ListComp, "list"),
                                 (ast.Set, "set"), (ast.SetComp, "set"), (ast.Tuple, "tuple")):
            if isinstance(expr, node_type):
                return frozenset({token})
        if isinstance(expr, ast.IfExp):
            a, b = self.infer(expr.body, qual, used, depth + 1), self.infer(expr.orelse, qual, used, depth + 1)
            return a | b if a is not None and b is not None else None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            a, b = self.infer(expr.left, qual, used, depth + 1), self.infer(expr.right, qual, used, depth + 1)
            for token in ("str", "bytes"):
                if a == {token} and b == {token}:
                    return frozenset({token})
            return None
        if isinstance(expr, ast.Subscript):
            inner = self.infer(expr.value, qual, used, depth + 1)
            return frozenset({"json"}) if inner == {"json"} else None
        if isinstance(expr, ast.Name):
            if expr.id == PLANTED:
                return None
            for inner in self.code.own_nodes(qual):
                if not isinstance(inner, (ast.With, ast.AsyncWith)):
                    continue
                if not any(candidate is expr for statement_ in inner.body for candidate in ast.walk(statement_)):
                    continue
                for item in inner.items:
                    if isinstance(item.optional_vars, ast.Name) and item.optional_vars.id == expr.id:
                        used.notes.append(f"{expr.id}: with binding at line {item.context_expr.lineno}")
                        return self.infer(item.context_expr, qual, used, depth + 1)
            value, why = self.sole_local(qual, expr.id)
            if value is not None:
                used.notes.append(f"{expr.id}: {why} at line {value.lineno}")
                return self.infer(value, qual, used, depth + 1)
            if why != "not bound here":
                return None
            value, why = self.sole_global(path, expr.id)
            if value is not None:
                used.notes.append(f"{expr.id}: {why} at {path}:{value.lineno}")
                return self.infer(value, self.p.module_pseudo(self.p.module_of[path]), used, depth + 1)
            used.notes.append(f"{expr.id}: {why}")
            return None
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name) and expr.value.id == "self" and self.p.defs[qual].class_qual:
                owner = self.p.defs[qual].class_qual
                for cls in [owner, *sorted(self.code.supers(owner))]:
                    hit = self.attr_facts.get((cls, expr.attr))
                    if hit is not None:
                        used.facts.add(hit[1])
                        return hit[0]
            return None
        if isinstance(expr, ast.Call):
            return self.infer_call(expr, qual, used, depth)
        return None

    def infer_call(self, expr: ast.Call, qual: str, used: Used, depth: int) -> frozenset | None:
        path = self.p.defs[qual].path
        raw = audit._dotted_name(expr.func)
        keywords = {k.arg for k in expr.keywords}
        if raw is not None:
            target = audit._aliased_name(raw, self.p.aliases.get(path, {}))
            if "." not in raw and raw in BUILTIN_RESULT_TYPES and not self.code.shadowed(path, raw) \
                    and raw not in self.p.visitor(qual).locals:
                return frozenset({BUILTIN_RESULT_TYPES[raw]})
            if target == "re.compile" and expr.args and isinstance(expr.args[0], ast.Constant) \
                    and isinstance(expr.args[0].value, str):
                return self.row("re.compile", used)
            if target in ("json.loads", "json.load") and not keywords & (JSON_HOOKS | {None}):
                return self.row("json.loads", used)
            if target == "json.dumps" and not keywords & {"cls", "default", None}:
                return self.row("json.dumps", used)
            if target == "hashlib.sha256":
                return self.row("hashlib.sha256", used)
            if raw == "open" and self.builtin_here(path, qual, "open"):
                mode_node = next((keyword.value for keyword in expr.keywords if keyword.arg == "mode"), None)
                if mode_node is None and len(expr.args) > 1:
                    mode_node = expr.args[1]
                # Omitted mode is the documented text default.  An explicit
                # non-literal mode may be binary, so it cannot discharge the
                # text-stream row.
                mode = "r" if mode_node is None else (
                    mode_node.value
                    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str)
                    else None
                )
                if mode is not None and "b" not in mode:
                    return self.row("open.text", used)
            if target == "copy.deepcopy" and expr.args:
                inner = self.infer(expr.args[0], qual, used, depth + 1)
                if inner is None or not ROW_RESULTS["copy.deepcopy"]:
                    return None
                for token in inner:
                    if token.startswith(("class:", "exact:")):
                        cls = token.partition(":")[2]
                        family = {cls} | (self.code.subclasses(cls) if token.startswith("class:") else set())
                        for member in family | self.code.supers(cls):
                            info = self.p.classes.get(member)
                            if info and any(d in info.methods for d in COPY_DUNDERS):
                                used.notes.append(f"copy.deepcopy: {member} defines a copy dunder")
                                return None
                used.rows.add("copy.deepcopy")
                return inner
            resolved = self.p.resolve(path, target)
            if resolved in self.p.defs and resolved in self.return_facts:
                hit = self.return_facts[resolved]
                used.facts.add(hit[1])
                return hit[0]
            if resolved in self.p.classes:
                return frozenset({"exact:" + resolved})
        if isinstance(expr.func, ast.Attribute):
            method = expr.func.attr
            if isinstance(expr.func.value, ast.Name) and expr.func.value.id in ("self", "cls") \
                    and self.p.defs[qual].class_qual:
                targets = self.p.dispatch(self.p.defs[qual].class_qual, method)
                hits = [self.return_facts.get(t) for t in targets]
                if targets and all(hits):
                    for hit in hits:
                        used.facts.add(hit[1])
                    return frozenset().union(*(hit[0] for hit in hits))
                return None
            receiver = self.infer(expr.func.value, qual, used, depth + 1)
            if receiver is None or len(receiver) != 1:
                return None
            token = next(iter(receiver))
            if token == "stdlib:re.Pattern" and method in ("fullmatch", "match", "search"):
                return self.row("re.Pattern.fullmatch", used)
            if token == "stdlib:re.Match" and method == "group":
                return self.row("re.Match.group", used)
            if token == "stdlib:_hashlib.HASH" and method == "hexdigest":
                return self.row("hashlib.HASH.hexdigest", used)
            if token == "str" and method == "encode":
                return self.row("str.encode", used)
            if token == "str" and method in STR_METHODS_STR:
                return frozenset({"str"})
            if token == "stdlib:io.TextIOBase" and method == "read":
                return self.row("io.TextIOBase.read", used)
        return None

    def row(self, name: str, used: Used) -> frozenset | None:
        if not ROW_RESULTS.get(name):
            used.notes.append(f"row {name} FAILED on this interpreter")
            return None
        used.rows.add(name)
        token = ROWS[name][0]
        if token.startswith("optional:"):
            return frozenset({token.partition(":")[2], "none"})
        return frozenset({token})

    # ----- narrowing by guards -----------------------------------------------------------------------
    def builtin_here(self, path: str, qual: str | None, name: str) -> bool:
        """`name` means the builtin in this definition: not shadowed in the module, not a local, not rebound."""
        return not self.code.shadowed(path, name) and (qual is None or name not in self.p.visitor(qual).locals)

    def guard_facts(self, path: str, test: ast.AST, name: str, positive: bool, origin: list | None = None,
                    qual: str | None = None) -> list:
        """Facts about `name` when `test` is true (positive) or false; `origin` collects the tests that gave them."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.guard_facts(path, test.operand, name, not positive, origin, qual)
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And) == positive:
                return [f for value in test.values for f in self.guard_facts(path, value, name, positive, origin, qual)]
            return []
        facts: list = []
        if isinstance(test, ast.Call) and audit._dotted_name(test.func) == "isinstance" and len(test.args) == 2 \
                and isinstance(test.args[0], ast.Name) and test.args[0].id == name and positive \
                and self.builtin_here(path, qual, "isinstance"):
            items = test.args[1].elts if isinstance(test.args[1], ast.Tuple) else [test.args[1]]
            tokens = [self.code.class_token(path, item, exact=False) for item in items]
            if all(tokens):
                facts = [("sub", frozenset(tokens))]
        elif isinstance(test, ast.Compare) and len(test.ops) == 1:
            left, op, right = test.left, test.ops[0], test.comparators[0]
            if (isinstance(left, ast.Call) and audit._dotted_name(left.func) == "type" and len(left.args) == 1
                    and isinstance(left.args[0], ast.Name) and left.args[0].id == name
                    and self.builtin_here(path, qual, "type")):
                holds = {ast.Is: True, ast.Eq: True, ast.IsNot: False, ast.NotEq: False, ast.In: True,
                         ast.NotIn: False}.get(type(op))
                if holds is not None and holds == positive:
                    items = right.elts if isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                        right, (ast.Tuple, ast.List, ast.Set)) else [right]
                    tokens = [self.code.class_token(path, item, exact=True) for item in items]
                    if all(tokens):
                        facts = [("exact", frozenset(tokens))]
            elif (isinstance(left, ast.Name) and left.id == name and isinstance(right, ast.Constant) and right.value is None
                  and isinstance(op, (ast.Is, ast.IsNot))):
                facts = [("none",)] if isinstance(op, ast.Is) == positive else [("notnone",)]
        if facts and origin is not None:
            origin.append(test)
        return facts

    @staticmethod
    def assigns(node: ast.AST, name: str) -> bool:
        return any(isinstance(inner, ast.Name) and inner.id == name and isinstance(inner.ctx, (ast.Store, ast.Del))
                   for inner in ast.walk(node))

    @staticmethod
    def exits(body: list) -> bool:
        return bool(body) and isinstance(body[-1], (ast.Raise, ast.Return, ast.Continue, ast.Break))

    @staticmethod
    def path_to(root: ast.AST, target: ast.AST) -> list | None:
        def walk(node):
            for field, value in ast.iter_fields(node):
                items = value if isinstance(value, list) else [value]
                for index, child in enumerate(items):
                    if not isinstance(child, ast.AST):
                        continue
                    step = (node, field, index if isinstance(value, list) else None, child)
                    if child is target:
                        return [step]
                    found = walk(child)
                    if found is not None:
                        return [step] + found
            return None
        return walk(root)

    def narrowing(self, qual: str, target: ast.AST, name: str, origin: list | None = None) -> list:
        definition = self.p.defs[qual]
        root = definition.node
        if root is None:
            return []
        for inner in ast.walk(root):
            if isinstance(inner, (ast.Global, ast.Nonlocal)) and name in inner.names:
                return []
        path = definition.path
        facts: list = []
        for parent, field, index, child in self.path_to(root, target) or []:
            block = getattr(parent, field, None)
            if isinstance(block, list) and index is not None and block and all(isinstance(s, ast.stmt) for s in block):
                for statement_ in block[:index]:
                    if self.assigns(statement_, name):
                        facts = []
                    if isinstance(statement_, ast.If) and not statement_.orelse and self.exits(statement_.body):
                        facts = facts + self.guard_facts(path, statement_.test, name, False, origin, qual)
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)) and parent is not root:
                facts = []
            elif isinstance(parent, ast.If) and field in ("body", "orelse"):
                facts = facts + self.guard_facts(path, parent.test, name, field == "body", origin, qual)
            elif isinstance(parent, ast.While) and field == "body":
                if self.assigns(parent, name):
                    facts = []
                facts = facts + self.guard_facts(path, parent.test, name, True, origin, qual)
            elif isinstance(parent, (ast.For, ast.AsyncFor)) and field == "body":
                if self.assigns(parent.target, name) or any(self.assigns(s, name) for s in parent.body):
                    facts = []
            elif isinstance(parent, ast.Try) and field in ("handlers", "orelse", "finalbody"):
                if any(self.assigns(s, name) for s in parent.body):
                    facts = []
            elif isinstance(parent, ast.BoolOp) and field == "values":
                for value in parent.values[:index]:
                    facts = facts + self.guard_facts(path, value, name, isinstance(parent.op, ast.And), origin, qual)
            elif isinstance(parent, ast.IfExp) and field in ("body", "orelse"):
                facts = facts + self.guard_facts(path, parent.test, name, field == "body", origin, qual)
            elif isinstance(parent, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                generators = parent.generators if field in ("elt", "key", "value") else parent.generators[:index or 0]
                for generator in generators:
                    if self.assigns(generator.target, name):
                        facts = []
                    for condition in generator.ifs:
                        facts = facts + self.guard_facts(path, condition, name, True, origin, qual)
            elif isinstance(parent, ast.comprehension) and field == "ifs":
                if self.assigns(parent.target, name):
                    facts = []
                for condition in parent.ifs[:index]:
                    facts = facts + self.guard_facts(path, condition, name, True, origin, qual)
        return facts

    @staticmethod
    def apply_narrowing(declared: frozenset | None, facts: list) -> frozenset | None:
        current = declared
        for fact in facts:
            if fact[0] in ("exact", "sub"):
                # an isinstance fact, builtin or project class alike, is "sub:": a subclass or a lying __class__
                tokens = fact[1] if fact[0] == "exact" else frozenset("sub:" + t for t in fact[1])
                current = tokens if current is None else (frozenset(t for t in current if t in tokens) or tokens)
            elif fact[0] == "notnone" and current is not None:
                current = frozenset(t for t in current if t != "none")
            elif fact[0] == "none":
                current = frozenset({"none"})
        return current

    def accepts(self, claim: str) -> set:
        if claim.startswith("optional:"):
            return self.accepts(claim.partition(":")[2]) | {"none"}
        head, _, rest = claim.partition(":")
        if head == "class":
            family = {rest} | self.code.subclasses(rest)
            return {f"class:{c}" for c in family} | {f"exact:{c}" for c in family}
        return {claim}

    # ----- claims ----------------------------------------------------------------------------------------
    def site_nodes(self, qual: str, expr: str, line: int | None, col: int | None = None) -> list:
        """The occurrences the claim is about: every match on the line, or the one at the column."""
        wanted = shape(ast.parse(expr, mode="eval").body)
        return [node for node in self.code.own_nodes(qual) if isinstance(node, ast.expr)
                and getattr(node, "lineno", None) is not None and (line is None or node.lineno == line)
                and (col is None or node.col_offset + 1 == col) and shape(node) == wanted]

    def parent_of(self, qual: str, child: ast.AST) -> ast.AST | None:
        for node in self.code.own_nodes(qual):
            for _field, value in ast.iter_fields(node):
                if value is child or (isinstance(value, list) and any(v is child for v in value)):
                    return node
        return None

    def check(self, reason: dict) -> dict:
        claim = reason["claim"]
        handler = getattr(self, "claim_" + claim["form"], None)
        if handler is None:
            declared = any(b["kind"] == "declared" for b in reason.get("basis", []))
            return {"status": "DOCUMENTED" if declared else "REFUTED", "bases": [], "facts": {},
                    "detail": f"form {claim['form']!r}: no machine check in this prototype; carried as a statement"}
        return handler(reason, claim)

    def _classification_claim(self, reason: dict, claim: dict, decision: str) -> dict:
        """Check one developer classification reason against the compiled registry cell.

        A reason can answer an open classification question or conservatively
        supersede a compiled denial by retaining obligations.  It cannot rewrite
        ``objects.vstd`` or establish adoption.  The result therefore remains
        DOCUMENTED until the registry compiler adopts the same decision with
        current source evidence.
        """

        object_id = claim["object"]
        kind = claim["kind"]
        object_row = self.code.object_dump.get(object_id)
        if not isinstance(object_row, dict):
            return {
                "status": "STALE",
                "detail": f"compiled objects.vstd has no object {object_id}",
                "bases": [],
                "facts": {},
            }
        cells = object_row.get("cells", {})
        cell = cells.get(kind) if isinstance(cells, dict) else None
        if not isinstance(cell, dict):
            return {
                "status": "STALE",
                "detail": f"compiled objects.vstd has no {kind} cell for {object_id}",
                "bases": [],
                "facts": {},
            }
        about = set(reason.get("about", []))
        if about and object_id not in about:
            return {
                "status": "REFUTED",
                "detail": f"claim names {object_id}, but about names {sorted(about)}",
                "bases": [],
                "facts": {},
            }
        declared_bases = [
            basis
            for basis in reason.get("basis", [])
            if basis.get("kind") == "declared"
        ]
        if not declared_bases:
            return {
                "status": "REFUTED",
                "detail": "classification reasons require a declared evidence basis",
                "bases": [],
                "facts": {},
            }
        compiled_applies = bool(cell.get("applies"))
        compiled_denial = bool(cell.get("dna"))
        compiled_open = bool(cell.get("open"))
        hard_applies = any(
            bool(cell.get(field))
            for field in ("declared", "source", "consequence")
        )
        if (
            decision == "DOES_NOT_APPLY"
            and (compiled_applies or hard_applies)
            and not compiled_open
        ):
            return {
                "status": "REFUTED",
                "detail": (
                    "the compiled registry or current source selects this kind; a "
                    "reason alone cannot erase its obligations"
                ),
                "bases": [],
                "facts": {},
            }
        compiled_agrees = compiled_applies if decision == "APPLIES" else compiled_denial
        compiled_conflicts = (
            compiled_denial
            if decision == "APPLIES"
            else compiled_applies or hard_applies
        )
        if compiled_agrees:
            detail = f"compiled registry agrees with {decision}"
        elif decision == "APPLIES" and compiled_denial:
            detail = (
                "developer APPLIES reason conservatively supersedes compiled "
                "DOES_NOT_APPLY for obligation retention only; registry adoption "
                "and current source binding remain required"
            )
        else:
            detail = (
                f"developer {decision} reason answers an open compiled classification "
                + (
                    "conflict; "
                    if compiled_conflicts
                    else "question; "
                )
                + "registry adoption and current source binding remain required"
            )
        return {
            "status": "DOCUMENTED",
            "detail": detail,
            "bases": [
                {
                    "kind": "declared",
                    "ok": True,
                    "strength": "DOCUMENTED",
                    "detail": "developer-supplied evidence tokens: "
                    + ", ".join(
                        token
                        for basis in declared_bases
                        for token in basis.get("evidence", [])
                    ),
                    "types": None,
                    "narrowing": None,
                    "checked": False,
                }
            ],
            "facts": {
                "classification": [
                    {
                        "object_id": object_id,
                        "kind": kind,
                        "decision": decision,
                    }
                ]
            },
            "object_id": object_id,
            "kind": kind,
            "compiled_agrees": compiled_agrees,
            "compiled_conflicts": compiled_conflicts,
        }

    def claim_applies(self, reason: dict, claim: dict) -> dict:
        return self._classification_claim(reason, claim, "APPLIES")

    def claim_denial(self, reason: dict, claim: dict) -> dict:
        return self._classification_claim(reason, claim, "DOES_NOT_APPLY")

    def claim_obligation(self, reason: dict, claim: dict) -> dict:
        """Check one fail-closed obligation-retention statement.

        ``REQUIRED`` never supplies the checker result.  It only binds the
        authored reason to one exact object/coordinate denominator member.
        The Tier-zero registry projection can establish an exact match here;
        package-polish tiers reconcile their own coordinates downstream.
        """

        object_id = claim["object"]
        coordinate = claim["coordinate"]
        decision = claim["decision"]
        if decision != "REQUIRED":
            return {
                "status": "REFUTED",
                "detail": "an obligation reason may only retain REQUIRED work",
                "bases": [],
                "facts": {},
            }
        if object_id not in self.code.object_dump:
            return {
                "status": "STALE",
                "detail": f"compiled objects.vstd has no object {object_id}",
                "bases": [],
                "facts": {},
            }
        about = set(reason.get("about", []))
        if about and object_id not in about:
            return {
                "status": "REFUTED",
                "detail": f"claim names {object_id}, but about names {sorted(about)}",
                "bases": [],
                "facts": {},
            }
        declared_bases = [
            basis
            for basis in reason.get("basis", [])
            if basis.get("kind") == "declared"
        ]
        if not declared_bases or not str(reason.get("note") or "").strip():
            return {
                "status": "REFUTED",
                "detail": "obligation reasons require declared evidence and an explanatory note",
                "bases": [],
                "facts": {},
            }
        matches = [
            row
            for row in self.code.open_obligations
            if isinstance(row, dict)
            and row.get("object_id") == object_id
            and row.get("obligation") == coordinate
        ]
        if len(matches) > 1:
            return {
                "status": "REFUTED",
                "detail": "compiled registry contains a duplicate exact obligation row",
                "bases": [],
                "facts": {},
            }
        compiled_match = len(matches) == 1
        detail = (
            "compiled Tier-zero registry denominator contains the exact REQUIRED obligation"
            if compiled_match
            else (
                "exact obligation is outside the Tier-zero open registry denominator; "
                "a downstream package-polish denominator must reconcile it"
            )
        )
        return {
            "status": "DOCUMENTED",
            "detail": detail,
            "bases": [{
                "kind": "declared",
                "ok": True,
                "strength": "DOCUMENTED",
                "detail": "developer-supplied evidence tokens: " + ", ".join(
                    token
                    for basis in declared_bases
                    for token in basis.get("evidence", [])
                ),
                "types": None,
                "narrowing": None,
                "checked": False,
            }],
            "facts": {
                "obligation": [{
                    "object_id": object_id,
                    "coordinate": coordinate,
                    "decision": decision,
                }],
            },
            "object_id": object_id,
            "coordinate": coordinate,
            "decision": decision,
            "compiled_match": compiled_match,
            "compiled_rows": matches,
        }

    def finish(self, reason: dict, bases: list[Basis], facts: dict, detail: str, bound_node: ast.AST | None,
               used: Used, extra: dict | None = None) -> dict:
        out = {"bases": [{"kind": b.kind, "ok": b.ok, "strength": b.strength, "detail": b.detail,
                          "types": sorted(b.types) if b.types else None,
                          "narrowing": [str(f) for f in b.narrowing] if b.narrowing else None,
                          "checked": b.checked} for b in bases],
               "rows": sorted(used.rows), "uses": sorted(used.facts), "notes": used.notes[:12], "detail": detail}
        out.update(extra or {})
        # What witness code patches among the names this claim is about: it bounds those witnesses' evidence
        witness = sorted({hit for name in claim_names(reason["claim"]) for hit in self.code.witness_writes(name)})
        if witness:
            out["witness_patches"] = {"count": len(witness), "first": witness[:6]}
        cited = {row for b in reason.get("basis", []) if b["kind"] == "stdlib" for row in b["row"]}
        uncited = sorted(used.rows - cited)
        failed = [b for b in bases if not b.ok]
        checked_failures = [b for b in failed if b.checked]
        unchecked = [b for b in failed if not b.checked]
        if checked_failures or uncited:
            out["status"], out["facts"] = "REFUTED", {}
            out["detail"] = "; ".join([f"{b.kind}: {b.detail}" for b in checked_failures]
                                      + ([f"uses table rows it does not cite: {', '.join(uncited)}"] if uncited else []))
            return out
        if unchecked:
            out["status"], out["facts"] = "UNCHECKED", {}
            out["detail"] = "; ".join(f"{b.kind}: checker cannot read: {b.detail}" for b in unchecked)
            return out
        strength = "DOCUMENTED" if any(b.strength == "DOCUMENTED" for b in bases) or reason.get("assume") else "ESTABLISHED"
        if strength == "DOCUMENTED" and bound_node is not None:
            current = ast_digest(bound_node)
            out["digest"] = current
            if reason.get("bound") != current:
                out["status"], out["facts"] = "STALE", {}
                out["detail"] = (f"no bound: bind it with `bound {current}`" if reason.get("bound") is None
                                 else f"the code changed since it was bound (now {current})")
                return out
        out["status"], out["facts"] = strength, facts
        return out

    def claim_type(self, reason: dict, claim: dict) -> dict:
        site = claim["site"]
        qual = self.code.qual(site)
        if qual is None or qual not in self.p.defs:
            return {"status": "STALE", "detail": f"no definition {site['path']}::{site['qual']}", "bases": [], "facts": {}}
        nodes = self.site_nodes(qual, claim["expr"], site.get("line"), site.get("col"))
        if not nodes:
            where = f"line {site.get('line')}" + (f" column {site['col']}" if site.get("col") else "")
            return {"status": "STALE", "detail": f"`{claim['expr']}` not at {where}", "bases": [], "facts": {}}
        definition = self.p.defs[qual]
        used, bases = Used(), []
        expr_node = nodes[0]
        kinds = [b["kind"] for b in reason.get("basis", [])]
        via_returns = isinstance(expr_node, ast.Attribute) and "returns" in kinds
        subjects = [n.value for n in nodes] if via_returns else nodes
        subject = subjects[0]
        name = subject.id if isinstance(subject, ast.Name) else None
        declared, narrowing, guards = None, None, []
        for basis in reason.get("basis", []):
            kind = basis["kind"]
            if kind == "guard":
                if name is None:
                    bases.append(Basis(kind, False, "ESTABLISHED", "a guard narrows a name, not an expression"))
                    continue
                per_node = [self.narrowing(qual, node, name, guards) for node in subjects]
                common = per_node[0] if all(facts == per_node[0] for facts in per_node) else []
                narrowing = common
                bases.append(Basis(kind, bool(common), "ESTABLISHED",
                                   "guards in force: " + (", ".join(map(str, common)) or "none"), narrowing=common))
            elif kind == "assigned":
                types_ = self.infer(subject, qual, used)
                declared = types_
                checked = True
                detail = f"its assignments give {sorted(types_) if types_ else 'nothing'}"
                if types_ is None and isinstance(subject, ast.Name):
                    value, why = self.sole_local(qual, subject.id)
                    if value is None and why.startswith("bound by"):
                        checked = False
                        detail = why
                bases.append(Basis(kind, types_ is not None, "ESTABLISHED",
                                   detail, types_, checked=checked))
            elif kind == "stdlib":
                bad = [row for row in basis["row"] if row not in ROWS or not ROW_RESULTS.get(row)]
                bases.append(Basis(kind, not bad, "ESTABLISHED", "rows verified on this interpreter: "
                                   + ", ".join(basis["row"]) if not bad else f"rows missing or failing: {', '.join(bad)}"))
            elif kind == "call-sites":
                types_, detail = self.from_call_sites(qual, subject, used)
                declared = types_
                bases.append(Basis(kind, types_ is not None, "ESTABLISHED", detail, types_))
            elif kind == "annotation":
                types_, detail = self.stated_type(qual, subject, basis["location"], used)
                declared = types_ if declared is None else declared
                bases.append(Basis(kind, types_ is not None, "DOCUMENTED", detail, types_))
            elif kind == "returns":
                bases.append(Basis(kind, True, "ESTABLISHED", "the attribute is read through admitted return facts"))
            else:
                bases.append(Basis(kind, False, "ESTABLISHED", f"basis {kind!r} does not apply to a type claim"))
        receiver = self.apply_narrowing(declared, narrowing or [])
        derived = receiver
        if via_returns:
            derived = None
            if receiver is not None:
                tokens: set = set()
                for token in receiver:
                    if not token.startswith(("class:", "exact:")):
                        tokens = set()
                        break
                    cls = token.partition(":")[2]
                    targets = self.p.dispatch(cls, expr_node.attr) if token.startswith("class:") else \
                        {t for t in [self.p.lookup(cls, expr_node.attr)] if t}
                    if not targets or not all(t in self.return_facts and t in self.p.properties.get(expr_node.attr, ())
                                              for t in targets):
                        tokens = set()
                        used.notes.append(f"{cls}.{expr_node.attr}: not every target is a property with a return fact")
                        break
                    for t in targets:
                        used.facts.add(self.return_facts[t][1])
                        tokens |= self.return_facts[t][0]
                derived = frozenset(tokens) if tokens else None
        accepted = self.accepts(claim["type"])
        methods = sorted({p.attr for n in nodes if isinstance(p := self.parent_of(qual, n), ast.Attribute)})
        residual = []
        if derived is None:
            bases.append(Basis("derivation", False, "ESTABLISHED", "the bases give no type for the expression",
                               checked=not any(not basis.checked for basis in bases)))
        else:
            for token in sorted(derived):
                if token in accepted:
                    continue
                if token.startswith("sub:") and token[4:] in accepted:
                    every = sorted(c for c in self.p.classes if self.builtin_subclass(c, token[4:])
                                   and any(m in self.p.classes[c].methods for m in methods))
                    overriding = [c for c in every if self.code.in_subject(self.p.classes[c].path)]
                    witness = [c for c in every if c not in overriding]
                    if witness:  # a witness's subclass is a value from outside the subject: the assumption's business
                        used.notes.append(f"witness classes break {ASSUMPTION_BUILTIN_SUBCLASSES} in their runs: {witness}")
                    named = ASSUMPTION_BUILTIN_SUBCLASSES in reason.get("assume", [])
                    if not overriding and named:
                        residual.append(f"{token}: isinstance admits subclasses and any object whose __class__ says "
                                        f"{token[4:]}; no subject subclass overrides {', '.join(methods) or 'the method'}; "
                                        f"values that pass are assumed exact ({ASSUMPTION_BUILTIN_SUBCLASSES})"
                                        + (f"; witness classes that do: {witness}" if witness else ""))
                        continue
                    bases.append(Basis("derivation", False, "ESTABLISHED",
                                       f"{token}: isinstance admits subclasses and a lying __class__; subject code "
                                       f"overrides {', '.join(methods) or 'the method'} in {overriding}, which no "
                                       f"assumption about outside values can cover" if overriding else
                                       f"{token}: isinstance admits subclasses and a lying __class__; name the assumption "
                                       f"{ASSUMPTION_BUILTIN_SUBCLASSES} or guard with type(...) is"))
                    continue
                bases.append(Basis("derivation", False, "ESTABLISHED", f"derived {token} is not the claimed {claim['type']}"))
        kind, value = token_origin(claim["type"])
        fact = {"def": qual, "expr": ast.unparse(ast.parse(claim["expr"], mode="eval").body),
                "line": site.get("line"), "kind": kind, "value": value}
        if site.get("col"):
            fact["col"] = site["col"]
        facts = {"site_types": [fact]}
        return self.finish(reason, bases, facts, f"derived {sorted(derived) if derived else None}"
                           + (f"; {'; '.join(residual)}" if residual else ""), definition.node, used,
                           {"site": f"{definition.path}:{site.get('line')}", "def": qual, "guards": len(guards),
                            "_guard_nodes": guards})

    def builtin_subclass(self, class_qual: str, builtin: str) -> bool:
        return any(builtin in self.p.classes[c].external_bases for c in {class_qual} | self.code.supers(class_qual)
                   if c in self.p.classes)

    def annotation_entries(self, path: str, line: int) -> list[dict]:
        """Annotations at a location, carrying the definition/class that owns each one."""
        entries: list[dict] = []
        for owner, definition in self.p.defs.items():
            node = definition.node
            if definition.path != path or not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg:
                args.append(node.args.vararg)
            if node.args.kwarg:
                args.append(node.args.kwarg)
            for arg in args:
                annotation = arg.annotation
                if annotation is not None and annotation.lineno <= line <= (annotation.end_lineno or annotation.lineno):
                    entries.append({"name": arg.arg, "annotation": annotation, "where": "parameter",
                                    "owner": owner, "class": definition.class_qual})
            annotation = node.returns
            if annotation is not None and annotation.lineno <= line <= (annotation.end_lineno or annotation.lineno):
                entries.append({"name": node.name, "annotation": annotation, "where": "return",
                                "owner": owner, "class": definition.class_qual})
        for owner, info in self.p.classes.items():
            if info.path != path:
                continue
            node = class_node_of(info, self.p)
            for statement_ in node.body:
                if isinstance(statement_, ast.AnnAssign) and statement_.lineno == line:
                    name = statement_.target.attr if isinstance(statement_.target, ast.Attribute) \
                        else getattr(statement_.target, "id", None)
                    entries.append({"name": name, "annotation": statement_.annotation, "where": "field",
                                    "owner": owner, "class": owner})
        return entries

    def annotated_receiver_types(self, qual: str, subject: ast.AST) -> frozenset | None:
        """Types for an attribute receiver, from its own parameter or assigned call's return annotation."""
        if not isinstance(subject, ast.Name):
            return None
        definition = self.p.defs[qual]
        if subject.id in definition.params and isinstance(definition.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for entry in self.annotation_entries(definition.path, definition.node.lineno):
                # The declaration can span lines, so inspect the exact parameter nodes directly.
                if entry["where"] == "parameter" and entry["owner"] == qual and entry["name"] == subject.id:
                    return self.annotation_tokens(definition.path, entry["annotation"], False)
            for arg in [*definition.node.args.posonlyargs, *definition.node.args.args, *definition.node.args.kwonlyargs]:
                if arg.arg == subject.id and arg.annotation is not None:
                    return self.annotation_tokens(definition.path, arg.annotation, False)
        value, _why = self.sole_local(qual, subject.id)
        if isinstance(value, ast.Call):
            raw = audit._dotted_name(value.func)
            if raw:
                target = self.p.resolve(definition.path, audit._aliased_name(raw, self.p.aliases.get(definition.path, {})))
                callee = self.p.defs.get(target)
                if callee and isinstance(callee.node, (ast.FunctionDef, ast.AsyncFunctionDef)) and callee.node.returns:
                    return self.annotation_tokens(callee.path, callee.node.returns, False)
        return None

    def stated_type(self, qual: str, subject: ast.AST, location: dict,
                    used: Used) -> tuple[frozenset | None, str]:
        """What an owned cited annotation says about the expression."""
        path, line = location["path"], location["line"]
        if path not in self.p.trees:
            return None, f"no file {path}"
        annotations = self.annotation_entries(path, line)
        if not annotations:
            return None, f"no annotation at {path}:{line}"
        if isinstance(subject, ast.Name):
            binding = self.binding_of(qual, subject.id)
            for entry in annotations:
                name, annotation, where = entry["name"], entry["annotation"], entry["where"]
                if binding[0] == "param" and where == "parameter" and name == subject.id and entry["owner"] == qual:
                    return self.annotation_tokens(path, annotation, False), \
                        f"parameter annotation owned by {qual}: `{ast.unparse(annotation)}`"
                if binding[0] == "element" and where == "parameter" and name == binding[1] \
                        and entry["owner"] == qual:
                    selector = binding[2] if len(binding) > 2 else True
                    return self.annotation_tokens(path, annotation, selector), \
                        f"element of parameter annotation owned by {qual}: `{ast.unparse(annotation)}`"
                if binding[0] == "unpacked-call" and where == "return" and entry["owner"] == binding[1]:
                    return self.annotation_tokens(path, annotation, binding[2]), \
                        f"element {binding[2]} of return annotation owned by {binding[1]}: `{ast.unparse(annotation)}`"
            return None, f"the annotation at line {line} is not about `{subject.id}` (bound as {binding[0]})"
        if isinstance(subject, ast.Attribute):
            receiver = self.annotated_receiver_types(qual, subject.value)
            if receiver == {"stdlib:pathlib.Path"} and subject.attr == "parent":
                for entry in annotations:
                    if entry["where"] == "parameter" and isinstance(subject.value, ast.Name) \
                            and entry["name"] == subject.value.id and entry["owner"] == qual:
                        return self.row("pathlib.Path.parent", used), \
                            f"stdlib attribute Path.parent from parameter annotation owned by {qual}"
            receiver_classes = {token.partition(":")[2] for token in (receiver or ())
                                if token.startswith(("class:", "exact:"))}
            for entry in annotations:
                if entry["where"] == "field" and entry["name"] == subject.attr \
                        and entry["class"] in receiver_classes:
                    return self.annotation_tokens(path, entry["annotation"], False), \
                        f"field annotation owned by receiver class {entry['class']}: `{ast.unparse(entry['annotation'])}`"
        return None, "the cited annotation does not name this expression"

    def binding_of(self, qual: str, name: str) -> tuple:
        definition = self.p.defs[qual]
        if name in definition.params:
            return ("param", name)
        for node in self.code.own_nodes(qual):
            if isinstance(node, ast.comprehension):
                source = node.iter
                if isinstance(source, ast.Call) and audit._dotted_name(source.func) == "sorted" and source.args:
                    source = source.args[0]
                if isinstance(node.target, ast.Name) and node.target.id == name \
                        and isinstance(source, ast.Name) and source.id in definition.params:
                    return ("element", source.id)
                if isinstance(node.target, (ast.Tuple, ast.List)) and isinstance(source, ast.Call) \
                        and isinstance(source.func, ast.Attribute) and source.func.attr == "items" \
                        and isinstance(source.func.value, ast.Name) and source.func.value.id in definition.params:
                    names = [getattr(item, "id", None) for item in node.target.elts]
                    if name in names:
                        return ("element", source.func.value.id, names.index(name))
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Tuple) \
                    and isinstance(node.value, ast.Call):
                names = [getattr(e, "id", None) for e in node.targets[0].elts]
                if name in names:
                    raw = audit._dotted_name(node.value.func) or ""
                    if isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) \
                            and node.value.func.value.id in ("self", "cls") and definition.class_qual:
                        callee = self.p.lookup(definition.class_qual, node.value.func.attr)
                    else:
                        callee = self.p.resolve(
                            definition.path, audit._aliased_name(raw, self.p.aliases.get(definition.path, {}))
                        )
                    return ("unpacked-call", callee, names.index(name))
        return ("other",)

    def annotation_tokens(self, path: str, annotation: ast.AST, element) -> frozenset | None:
        node = annotation
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node = ast.parse(node.value, mode="eval").body
        if element is False and isinstance(node, ast.Subscript):
            node = node.value
        elif element is not False:
            if not isinstance(node, ast.Subscript):
                return None
            inner = node.slice
            if isinstance(element, bool):
                node = inner.elts[0] if isinstance(inner, ast.Tuple) else inner
            elif isinstance(inner, ast.Tuple) and element < len(inner.elts):
                node = inner.elts[element]
            else:
                return None
        token = self.code.class_token(path, node, exact=False)
        if token is None:
            raw = audit._dotted_name(node)
            dotted = audit._aliased_name(raw, self.p.aliases.get(path, {})) if raw else None
            token = STDLIB_ANNOTATION_TYPES.get(dotted or "")
        return frozenset({token}) if token else None

    def from_call_sites(self, qual: str, subject: ast.AST, used: Used) -> tuple[frozenset | None, str]:
        """Every project call site gives the type (all or nothing): a parameter, or a dataclass field read as
        self.<field> in __post_init__ (whose call sites are the constructions)."""
        definition = self.p.defs[qual]
        if isinstance(subject, ast.Name) and subject.id in definition.params:
            param, fields = subject.id, None
        elif (isinstance(subject, ast.Attribute) and isinstance(subject.value, ast.Name) and subject.value.id == "self"
              and definition.node is not None and definition.node.name == "__post_init__" and definition.class_qual):
            fields = dataclass_fields(self.p.classes[definition.class_qual], self.p)
            if subject.attr not in fields:
                return None, f"{subject.attr} is not a dataclass field"
            param = subject.attr
        else:
            return None, "call-sites types a parameter, or a dataclass field in __post_init__"
        sites = self.p.call_sites.get(qual, [])
        if not sites:
            return None, "no project call site"
        tokens: set = set()
        failures, rebuilt = [], []
        if fields is not None:  # dataclasses.replace / copy.replace re-run __post_init__ with no construction site
            rebuilt = [f"{hit} constructs it without a visible call site" for hit in self.replace_sites(param)]
            witness = self.replace_sites(param, subject=False)
            if witness:
                used.notes.append(f"witness code rebuilds it {len(witness)} time(s), e.g. {witness[0]}")
        for caller, node, offset in sites:
            where = f"{self.p.defs[caller].path}:{node.lineno}"
            if fields is not None:
                argument = next((k.value for k in node.keywords if k.arg == param), None)
                position = fields[param][0]
                if argument is None and position < len(node.args) and not any(
                        isinstance(a, ast.Starred) for a in node.args[:position + 1]):
                    argument = node.args[position]
                hidden = argument is None and (any(isinstance(a, ast.Starred) for a in node.args)
                                               or any(k.arg is None for k in node.keywords))
                default = fields[param][1]
            else:
                argument, hidden = reach.call_argument(definition, param, node, offset)
                default_node = default_of(definition, param)
                default = self.infer(default_node, qual, used) if default_node is not None else None
            if argument is None and not hidden:
                if default is None:
                    failures.append(f"{where} leaves it to a default of unknown type")
                else:
                    tokens |= default
                continue
            if argument is None:
                failures.append(f"{where} hides it in */**")
                continue
            found = self.value_types(caller, argument, used)
            if found is None:
                failures.append(f"{where} passes `{ast.unparse(argument)[:50]}`")
                continue
            tokens |= found
        if failures or rebuilt:
            return None, "; ".join(part for part in (
                f"{len(failures)} of {len(sites)} call sites give no type: " + "; ".join(failures[:4]) if failures else "",
                f"{len(rebuilt)} replace(...) call(s) rebuild it: " + "; ".join(rebuilt[:2]) if rebuilt else "") if part)
        return frozenset(tokens), f"all {len(sites)} project call sites give {sorted(tokens)}"

    def value_types(self, qual: str, expr: ast.AST, used: Used) -> frozenset | None:
        found = self.infer(expr, qual, used)
        if found is not None:
            return found
        if isinstance(expr, ast.Name) and expr.id == PLANTED:
            return None
        origins = self.p.visitor(qual).value_origin(expr, 0)
        tokens = [origin_token(k, v) for k, v in origins]
        return frozenset(tokens) if tokens and all(tokens) else None

    def claim_attr(self, reason: dict, claim: dict) -> dict:
        cls = self.code.qual(claim["class"])
        if cls is None or cls not in self.p.classes:
            return {"status": "STALE", "detail": f"no class {claim['class']['qual']}", "bases": [], "facts": {}}
        attr, info = claim["name"], self.p.classes[cls]
        used, bases, declared = Used(), [], None
        assigned_params: set[str] = set()
        class_node = class_node_of(info, self.p)
        # The DSL canonicalizes bases by kind, so annotation may be evaluated
        # before assigned.  Discover owned parameter-to-attribute sources once
        # up front; basis meaning must not depend on textual or canonical order.
        for q, _line, how, node in self.code.attr_stores(attr):
            if how != "store" or not self.enclosing_in(q, cls):
                continue
            assignment = parent_assignment(self.code.own_nodes(q), node)
            if assignment is not None and isinstance(assignment.value, ast.Name) \
                    and assignment.value.id in self.p.defs[q].params:
                assigned_params.add(assignment.value.id)
        for basis in reason.get("basis", []):
            kind = basis["kind"]
            if kind == "assigned":
                stores = self.code.attr_stores(attr)
                own = [s for s in stores if s[2] == "store" and self.enclosing_in(s[0], cls)]
                # A known unrelated class's `self.<same name>` is a different instance field.
                problems = [f"{self.p.defs[q].path}:{line} {how}" for q, line, how, _n in stores
                            if (q, line, how, _n) not in own and self.p.defs[q].class_qual is None]
                problems += self.code.void_writes("instance", cls, attr)
                values = []
                for q, line, _how, node in own:
                    assignment = parent_assignment(self.code.own_nodes(q), node)
                    where = f"{self.p.defs[q].path}:{line}"
                    if assignment is None:
                        problems.append(f"{where} is not a plain assignment")
                    elif self.p.defs[q].node is None or self.p.defs[q].node.name != "__init__":
                        problems.append(f"{where} assigns outside __init__")
                    else:
                        found = self.infer(assignment.value, q, used)
                        if found is None:
                            if isinstance(assignment.value, ast.Name) and assignment.value.id in self.p.defs[q].params:
                                assigned_params.add(assignment.value.id)
                            else:
                                problems.append(f"{where} assigns `{ast.unparse(assignment.value)[:40]}`")
                        else:
                            values.append(found)
                if not own:
                    problems.append("no assignment in the class")
                assigned_declared = frozenset().union(*values) if values and not problems else None
                if assigned_declared is not None:
                    declared = assigned_declared if declared is None else declared
                bases.append(Basis(kind, not problems, "ESTABLISHED",
                                   f"{len(own)} assignment(s) in {cls} give {sorted(assigned_declared) if assigned_declared else '-'}"
                                   + (f"; from annotated parameter(s) {sorted(assigned_params)}" if assigned_params else "")
                                   + (f"; problems: {'; '.join(problems[:4])}" if problems else ""), assigned_declared))
            elif kind == "call-sites":
                init = self.p.lookup(cls, "__post_init__")
                fields = dataclass_fields(info, self.p)
                if init is None or attr not in fields or not is_frozen(info, self.p):
                    bases.append(Basis(kind, False, "ESTABLISHED",
                                       "call-sites types an attribute of a frozen dataclass with __post_init__"))
                    continue
                probe = ast.Attribute(value=ast.Name(id="self", ctx=ast.Load()), attr=attr, ctx=ast.Load())
                found, detail = self.from_call_sites(init, probe, used)
                writes = [f"{self.p.defs[q].path}:{line} {how}" for q, line, how, _n in self.code.attr_stores(attr)
                          if how != "store" and self.p.defs[q].node is not None and self.p.defs[q].node.name != "__post_init__"]
                writes += self.code.void_writes("instance", cls, attr) + self.replace_sites(attr)
                declared = found if not writes else None
                bases.append(Basis(kind, found is not None and not writes, "ESTABLISHED",
                                   detail + (f"; written after construction: {'; '.join(writes[:4])}" if writes else ""),
                                   declared))
            elif kind == "annotation":
                location, stated = basis["location"], None
                owner_detail = ""
                own_quals = {q for q, _line, _how, _node in self.code.attr_stores(attr)
                             if self.enclosing_in(q, cls)}
                for entry in self.annotation_entries(location["path"], location["line"]):
                    if entry["where"] == "field" and entry["name"] == attr and entry["class"] == cls:
                        stated = self.annotation_tokens(location["path"], entry["annotation"], False)
                        owner_detail = f"field owned by {cls}"
                    elif entry["where"] == "parameter" and entry["name"] in assigned_params \
                            and entry["class"] == cls and entry["owner"] in own_quals:
                        stated = self.annotation_tokens(location["path"], entry["annotation"], False)
                        owner_detail = f"parameter {entry['name']} owned by {entry['owner']} and assigned to self.{attr}"
                declared = stated if declared is None else declared
                bases.append(Basis(kind, stated is not None, "DOCUMENTED",
                                   f"annotation at line {location['line']} gives {sorted(stated) if stated else 'nothing'}"
                                   + (f"; {owner_detail}" if owner_detail else ""),
                                   stated))
            else:
                bases.append(Basis(kind, False, "ESTABLISHED", f"basis {kind!r} does not apply to an attribute claim"))
        if declared is None or not set(declared) <= self.accepts(claim["type"]):
            bases.append(Basis("derivation", False, "ESTABLISHED",
                               f"bases give {sorted(declared) if declared else None}, not {claim['type']}"))
        kind, value = token_origin(claim["type"])
        facts = {"attr_types": [{"class": cls, "attr": attr, "kind": kind, "value": value}]}
        return self.finish(reason, bases, facts, f"derived {sorted(declared) if declared else None}", class_node, used,
                           {"class": cls})

    def replace_sites(self, attr: str, subject: bool = True) -> list:
        """dataclasses.replace / copy.replace calls that could set `attr` (by keyword or through **), in the
        subject program (subject=True) or in witness code (subject=False)."""
        hits = []
        for qual in self.p.defs:
            path = self.p.defs[qual].path
            if self.code.in_subject(path) != subject:
                continue
            for node in self.code.own_nodes(qual):
                if isinstance(node, ast.Call) and audit._aliased_name(audit._dotted_name(node.func) or "",
                                                                       self.p.aliases.get(path, {})) \
                        in ("dataclasses.replace", "copy.replace") and any(k.arg in (attr, None) for k in node.keywords):
                    hits.append(f"{path}:{node.lineno} replace(..., {attr}=...)")
        return hits

    def enclosing_in(self, qual: str, cls: str) -> bool:
        owner = self.p.defs[qual].class_qual
        return owner == cls or (owner is not None and owner in self.code.subclasses(cls))

    def claim_returns(self, reason: dict, claim: dict) -> dict:
        qual = self.code.qual(claim["def"])
        if qual is None or qual not in self.p.defs:
            return {"status": "STALE", "detail": f"no definition {claim['def']['qual']}", "bases": [], "facts": {}}
        definition = self.p.defs[qual]
        used, bases, declared = Used(), [], None
        for basis in reason.get("basis", []):
            kind = basis["kind"]
            if kind == "returns":
                returns = [n for n in self.code.own_nodes(qual) if isinstance(n, ast.Return)]
                problems = []
                if any(isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)) for n in self.code.own_nodes(qual)):
                    problems.append("a generator or coroutine")
                if not returns or not self.exits(definition.node.body):
                    problems.append("a path falls off the end (returns None)")
                values = [self.infer(r.value, qual, used) if r.value is not None else frozenset({"none"}) for r in returns]
                if any(v is None for v in values):
                    problems.append("a return value of unknown type")
                declared = frozenset().union(*values) if values and not problems else None
                bases.append(Basis(kind, not problems, "ESTABLISHED",
                                   f"{len(returns)} return statement(s) give {sorted(declared) if declared else '-'}"
                                   + (f"; {'; '.join(problems)}" if problems else ""), declared))
            elif kind == "stdlib":
                bad = [row for row in basis["row"] if row not in ROWS or not ROW_RESULTS.get(row)]
                bases.append(Basis(kind, not bad, "ESTABLISHED", "rows verified: " + ", ".join(basis["row"]) if not bad
                                   else f"rows missing or failing: {', '.join(bad)}"))
            else:
                bases.append(Basis(kind, False, "ESTABLISHED", f"basis {kind!r} does not apply to a returns claim"))
        if declared is None or not set(declared) <= self.accepts(claim["type"]):
            bases.append(Basis("derivation", False, "ESTABLISHED",
                               f"bases give {sorted(declared) if declared else None}, not {claim['type']}"))
        kind, value = token_origin(claim["type"])
        facts = {"return_types": [{"def": qual, "kind": kind, "value": value}]}
        return self.finish(reason, bases, facts, f"derived {sorted(declared) if declared else None}", definition.node,
                           used, {"def": qual})

    def claim_dispatch(self, reason: dict, claim: dict) -> dict:
        site = claim["site"]
        qual = self.code.qual(site)
        if qual is None or qual not in self.p.defs:
            return {"status": "STALE", "detail": "no such definition", "bases": [], "facts": {}}
        pairs = self.dispatch_loops(qual, claim)
        calls = [call for call, _loops in pairs]
        if not calls:
            return {"status": "STALE", "detail": f"no call `{claim['call']}` at line {site.get('line')}", "bases": [], "facts": {}}
        claimed = {self.code.qual(ref) for ref in claim["targets"]}
        bases, found = [], set()
        path = self.p.defs[qual].path
        for basis in reason.get("basis", []):
            if basis["kind"] != "literal":
                bases.append(Basis(basis["kind"], False, "ESTABLISHED", "a dispatch claim takes the literal basis"))
                continue
            problems = []
            for call, loops in pairs:
                if len(loops) != 1 or not isinstance(loops[0].iter, (ast.Tuple, ast.List)):
                    problems.append("the receiver is not the name of one loop over a literal tuple or list")
                    continue
                for element in loops[0].iter.elts:
                    raw = audit._dotted_name(element)
                    dotted = audit._aliased_name(raw, self.p.aliases.get(path, {})) if raw else None
                    target = self.p.resolve(path, f"{dotted}.{call.func.attr}") if dotted else None
                    if target is None or target not in self.p.defs:
                        problems.append(f"`{ast.unparse(element)}` gives no project {call.func.attr}")
                        continue
                    module_path = self.p.module_path.get(dotted)
                    if module_path is None:
                        problems.append(f"`{dotted}` is not a module: class attributes are not checked for rebinding here")
                        continue
                    writes = self.code.module_attr_writes(module_path, call.func.attr)
                    bindings = self.module_bindings(module_path, call.func.attr)
                    if writes or len(bindings) != 1:
                        problems.append(f"`{dotted}.{call.func.attr}` could be rebound: "
                                        + "; ".join((writes or [f"{len(bindings)} module-level bindings"])[:3])
                                        + (f" (+{len(writes) - 3} more)" if len(writes) > 3 else ""))
                        continue
                    found.add(target)
            bases.append(Basis("literal", not problems and bool(found), "ESTABLISHED",
                               f"runs {sorted(found)}" + (f"; problems {problems}" if problems else "")))
        if found != claimed:
            bases.append(Basis("derivation", False, "ESTABLISHED",
                               f"the call runs {sorted(found)}, the claim names {sorted(t for t in claimed if t)}"))
        spelled = audit._dotted_name(calls[0].func) or ast.unparse(calls[0].func)
        facts = {"discharged_calls": [{"def": qual, "call": spelled, "line": c.lineno} for c in calls],
                 "supplier_edges": [{"from": qual, "to": sorted(found)}]}
        return self.finish(reason, bases, facts, f"runs {sorted(found)}", self.p.defs[qual].node, Used(), {"def": qual})

    def dispatch_loops(self, qual: str, claim: dict) -> list[tuple[ast.Call, list]]:
        """Each call a dispatch claim names, with the loops (for statements or comprehension clauses) that bind
        its receiver's name where it runs.  The literal basis reads these loops and its falsifier breaks them:
        a falsifier that broke the first literal loop in the body instead mutated an unrelated tuple (the
        document names in sim_surface_partition.mechanism_digest) and could never bite."""
        site = claim["site"]
        funcs = self.site_nodes(qual, claim["call"], site.get("line"), site.get("col"))
        calls = [n for n in self.code.own_nodes(qual) if isinstance(n, ast.Call) and any(n.func is f for f in funcs)]
        pairs = []
        for call in calls:
            receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
            loops = [n for n in self.code.own_nodes(qual) if isinstance(n, (ast.comprehension, ast.For))
                     and isinstance(receiver, ast.Name) and isinstance(n.target, ast.Name) and n.target.id == receiver.id
                     and self.encloses(qual, n, call)]
            pairs.append((call, loops))
        return pairs

    def encloses(self, qual: str, loop: ast.AST, node: ast.AST) -> bool:
        """The loop (a for statement or one comprehension clause) binds its target where `node` runs."""
        if isinstance(loop, (ast.For, ast.AsyncFor)):
            return any(node is inner for statement_ in loop.body for inner in ast.walk(statement_))
        owner = self.parent_of(qual, loop)
        parts = [getattr(owner, name) for name in ("elt", "key", "value") if getattr(owner, name, None) is not None]
        return any(node is inner for part in parts for inner in ast.walk(part))

    def claim_contract(self, reason: dict, claim: dict) -> dict:
        """The consumer's call runs only what reached the supplier's parameter.  Discharged at each function F
        that calls the consumer: F's session is a local F built, never stored, returned, passed on or captured,
        and every register on it passes a project class instance.  F then reaches what it registered."""
        consumer, supplier = self.code.qual(claim["consumer"]), self.code.qual(claim["supplier"])
        if consumer is None or supplier is None or consumer not in self.p.defs or supplier not in self.p.defs:
            return {"status": "STALE", "detail": "consumer or supplier not found", "bases": [], "facts": {}}
        cdef, sdef = self.p.defs[consumer], self.p.defs[supplier]
        cls, param = cdef.class_qual, claim["param"]
        wanted = shape(ast.parse(claim["call"], mode="eval").body)
        calls = [n for n in self.code.own_nodes(consumer) if isinstance(n, ast.Call) and shape(n.func) == wanted]
        if not calls or cls is None or sdef.class_qual != cls:
            return {"status": "STALE", "detail": f"no call `{claim['call']}` in a method of the supplier's class",
                    "bases": [], "facts": {}}
        used, bases = Used(), []
        receiver = calls[0].func.value if isinstance(calls[0].func, ast.Attribute) else calls[0].func
        dispatched = calls[0].func.attr if isinstance(calls[0].func, ast.Attribute) else None
        problems, registry = [], None
        value, why = self.sole_local(consumer, receiver.id) if isinstance(receiver, ast.Name) else (None, "not a name")
        if isinstance(value, ast.Call) and audit._dotted_name(value.func) == "getattr" and len(value.args) >= 2 \
                and isinstance(value.args[0], ast.Name) and isinstance(value.args[1], ast.Constant):
            dispatched = value.args[1].value
            value, why = self.sole_local(consumer, value.args[0].id)
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "get" \
                and isinstance(value.func.value, ast.Attribute) and isinstance(value.func.value.value, ast.Name) \
                and value.func.value.value.id == "self":
            registry = value.func.value.attr
        if registry is None:
            problems.append(f"the receiver does not come from self.<registry>.get(...) ({why})")
        else:
            for q, line, how, _node in self.code.attr_stores(registry):
                if self.p.defs[q].node is None or self.p.defs[q].node.name != "__init__" or self.p.defs[q].class_qual != cls:
                    problems.append(f"{self.p.defs[q].path}:{line} rebinds {registry}")
            for qual in self.p.defs:
                for node in self.code.own_nodes(qual):
                    touched = None
                    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        touched = node.value
                    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                            and node.func.attr in ("update", "setdefault", "__setitem__", "pop", "clear", "popitem"):
                        touched = node.func.value
                    if isinstance(touched, ast.Attribute) and touched.attr == registry:
                        if qual != supplier:
                            problems.append(f"{self.p.defs[qual].path}:{node.lineno} writes into {registry}")
                        elif isinstance(node, ast.Subscript):
                            assignment = parent_assignment(self.code.own_nodes(qual), node)
                            if assignment is None or not (isinstance(assignment.value, ast.Name) and assignment.value.id == param):
                                problems.append(f"{sdef.path}:{node.lineno} stores something other than {param}")
                    elif isinstance(node, ast.Attribute) and node.attr == registry and not (
                            isinstance(node.value, ast.Name) and node.value.id == "self" and self.enclosing_in(qual, cls)):
                        problems.append(f"{self.p.defs[qual].path}:{node.lineno} reaches {registry} from outside the class")
        bases.append(Basis("registry", not problems, "ESTABLISHED",
                           f"self.{registry} is filled only by {sdef.node.name}({param})" if not problems
                           else "; ".join(sorted(set(problems))[:5])))
        callers = collections.defaultdict(list)
        for caller, node, _offset in self.p.call_sites.get(consumer, []):
            callers[caller].append(node)
        discharged, undischarged = {}, {}
        for caller, nodes in sorted(callers.items()):
            verdict, targets = self.session_discharge(caller, nodes, cls, sdef.node.name, dispatched)
            if verdict is None:
                discharged[caller] = targets
            else:
                undischarged[caller] = verdict
        detail = f"{len(discharged)} callers discharged, {len(undischarged)} keep a gap"
        bases.append(Basis("discharge", bool(callers), "ESTABLISHED", detail if callers else "no project caller"))
        facts = {"discharged_calls": [{"def": consumer, "call": audit._dotted_name(c.func) or ast.unparse(c.func),
                                       "line": c.lineno} for c in calls],
                 "supplier_edges": [{"from": c, "to": sorted(t)} for c, t in sorted(discharged.items()) if t],
                 "site_gaps": [{"def": c, "category": "callback: unresolved argument at a project call site", "why": w}
                               for c, w in sorted(undischarged.items())]}
        return self.finish(reason, bases, facts, detail, cdef.node, used,
                           {"def": consumer, "discharged": sorted(discharged), "undischarged": undischarged,
                            "dispatched": dispatched})

    def session_discharge(self, caller: str, nodes: list, cls: str, register: str, dispatched: str | None):
        """(None, definitions reached) when the caller is discharged, else (why not, empty)."""
        targets: set = set()
        definition = self.p.defs[caller]
        if definition.node is None:
            return "module-level code", set()
        names = set()
        for node in nodes:
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            if not isinstance(receiver, ast.Name):
                return "the session is not a local name", set()
            names.add(receiver.id)
        for name in sorted(names):
            value, why = self.sole_local(caller, name)
            if not isinstance(value, ast.Call):
                return f"the session `{name}` is not built here ({why})", set()
            built = self.p.resolve(definition.path, audit._aliased_name(audit._dotted_name(value.func) or "",
                                                                         self.p.aliases.get(definition.path, {})))
            if built != cls:
                return f"`{name}` is built by {built}, not {cls}", set()
            for use in [n for n in self.code.own_nodes(caller) if isinstance(n, ast.Name) and n.id == name
                        and isinstance(n.ctx, ast.Load)]:
                parent = self.parent_of(caller, use)
                if isinstance(parent, ast.Attribute) and parent.value is use:
                    if parent.attr == register:
                        call = self.parent_of(caller, parent)
                        if not (isinstance(call, ast.Call) and call.func is parent and call.args):
                            return f"line {use.lineno}: {register} without an argument", set()
                        supplied = self.supplied_class(caller, call.args[0])
                        if supplied is None:
                            return f"line {call.lineno} registers `{ast.unparse(call.args[0])[:50]}`, not a project class", set()
                        found = self.p.dispatch(supplied, dispatched) if dispatched else set()
                        if dispatched and not found:  # nothing runs, unless a lookup hook or outside base supplies one
                            family = {supplied} | self.code.supers(supplied) | self.code.subclasses(supplied)
                            hooks = sorted(c for c in family if c in self.p.classes and any(
                                m in self.p.classes[c].methods for m in ("__getattr__", "__getattribute__")))
                            outside = [b for b in self.p.external_bases(supplied) if b not in ("object", "builtins.object")]
                            if hooks or outside:
                                return (f"{supplied} defines no {dispatched}, and "
                                        + (f"__getattr__ in {hooks[0]}" if hooks else f"the outside base {outside[0]}")
                                        + " could supply one"), set()
                        targets |= found
                    continue
                return f"the session escapes at line {use.lineno} (`{ast.unparse(parent)[:40]}`)", set()
            for nested in ast.walk(definition.node):
                if nested is not definition.node and isinstance(nested, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(nested)):
                    return "the session is captured by a nested function", set()
        return None, targets

    def supplied_class(self, caller: str, argument: ast.AST) -> str | None:
        path = self.p.defs[caller].path
        node = argument
        if isinstance(node, ast.Name):
            node, _ = self.sole_local(caller, node.id)
        if isinstance(node, ast.Call):
            resolved = self.p.resolve(path, audit._aliased_name(audit._dotted_name(node.func) or "",
                                                                self.p.aliases.get(path, {})))
            if resolved in self.p.classes:
                return resolved
        return None

    def claim_boundary(self, reason: dict, claim: dict) -> dict:
        """The parameter's uses run during the call, so what they run belongs to each caller: discharged where
        the caller passes a known value, a gap at the caller otherwise.  The parameter must not escape the call."""
        qual = self.code.qual(claim["def"])
        if qual is None or qual not in self.p.defs:
            return {"status": "STALE", "detail": "no such definition", "bases": [], "facts": {}}
        definition, param = self.p.defs[qual], claim["param"]
        if param not in definition.params:
            return {"status": "STALE", "detail": f"{param} is not a parameter of {qual}", "bases": [], "facts": {}}
        used, bases = Used(), []
        escapes = self.escapes(qual, param)
        bases.append(Basis("no-escape", not escapes, "ESTABLISHED",
                           "the parameter is only read during the call" if not escapes else "; ".join(escapes[:4])))
        methods = sorted({n.func.attr for n in self.code.own_nodes(qual) if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Attribute) and param in names_in(n.func.value)})
        sites = self.p.call_sites.get(qual, [])
        discharged, gaps, edges = [], [], collections.defaultdict(set)
        for caller, node, offset in sites:
            argument, hidden = reach.call_argument(definition, param, node, offset)
            where = f"{self.p.defs[caller].path}:{node.lineno}"
            if argument is None and not hidden:
                default = default_of(definition, param)
                if default is not None and self.infer(default, qual, used) is not None:
                    discharged.append(where)
                else:
                    gaps.append((caller, where, "a default of unknown type"))
                continue
            if argument is None:
                gaps.append((caller, where, "the argument is hidden in */**"))
                continue
            known = self.value_types(caller, argument, used)
            if known is None:
                gaps.append((caller, where, f"passes `{ast.unparse(argument)[:50]}`"))
                continue
            for token in known:
                if token.startswith(("class:", "exact:")):
                    for method in methods:
                        edges[caller] |= self.p.dispatch(token.partition(":")[2], method)
            discharged.append(where)
        bases.append(Basis("call-sites", bool(sites), "ESTABLISHED",
                           f"{len(discharged)} of {len(sites)} call sites discharged, {len(gaps)} keep the gap"
                           if sites else "no project call site: a public entry point keeps its gap"))
        facts = {"boundary": [{"def": qual, "param": param}],
                 "site_gaps": [{"def": c, "category": "receiver: untyped local or expression", "why": f"{w}: {y}"}
                               for c, w, y in gaps],
                 "supplier_edges": [{"from": c, "to": sorted(t)} for c, t in sorted(edges.items()) if t]}
        return self.finish(reason, bases, facts, f"{len(discharged)} call sites discharged, {len(gaps)} keep the gap",
                           definition.node, used, {"def": qual, "moved_count": len(gaps), "discharged_count": len(discharged),
                                                   "discharged_sites": sorted(discharged),
                                                   "moved_to": sorted({f"{w}: {y}" for _c, w, y in gaps})[:60]})

    def escapes(self, qual: str, param: str) -> list[str]:
        out = []
        root = self.p.defs[qual].node
        for node in self.code.own_nodes(qual):
            if not (isinstance(node, ast.Name) and node.id == param and isinstance(node.ctx, ast.Load)):
                continue
            chain, parent = node, self.parent_of(qual, node)
            while isinstance(parent, (ast.BoolOp, ast.IfExp, ast.Starred)):
                chain, parent = parent, self.parent_of(qual, parent)
            if isinstance(parent, ast.Attribute) and parent.value is chain:
                continue
            if isinstance(parent, (ast.Compare, ast.UnaryOp, ast.BinOp, ast.Subscript, ast.comprehension, ast.For,
                                   ast.If, ast.While, ast.Assert, ast.FormattedValue)):
                continue
            if isinstance(parent, ast.Call) and any(chain is a for a in parent.args) or (
                    isinstance(parent, ast.keyword)):
                call = parent if isinstance(parent, ast.Call) else self.parent_of(qual, parent)
                raw = audit._dotted_name(call.func) if isinstance(call, ast.Call) else None
                if raw in CONSUMING_BUILTINS and not self.code.shadowed(self.p.defs[qual].path, raw):
                    continue
                if isinstance(call, ast.Call) and self.passes_to_boundary(qual, call, chain):
                    continue
                out.append(f"passed to `{ast.unparse(call.func)[:40] if isinstance(call, ast.Call) else '?'}` at line {node.lineno}")
                continue
            out.append(f"`{ast.unparse(parent)[:40] if parent is not None else param}` at line {node.lineno}")
        for nested in ast.walk(root):
            if nested is not root and isinstance(nested, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and any(isinstance(n, ast.Name) and n.id == param for n in ast.walk(nested)):
                out.append("captured by a nested function")
        return out

    def passes_to_boundary(self, qual: str, call: ast.Call, argument: ast.AST) -> bool:
        """Passing the parameter on to a parameter that is itself an admitted boundary keeps it inside the call."""
        path = self.p.defs[qual].path
        raw = audit._dotted_name(call.func)
        target = self.p.resolve(path, audit._aliased_name(raw, self.p.aliases.get(path, {}))) if raw else None
        if target not in self.p.defs:
            return False
        callee = self.p.defs[target]
        offset = 1 if callee.class_qual and callee.params[:1] in (("self",), ("cls",)) and "." in (raw or "") else 0
        for index, value in enumerate(call.args):
            if value is argument and 0 <= index + offset < len(callee.params):
                return (target, callee.params[index + offset]) in self.boundaries
        for keyword in call.keywords:
            if keyword.value is argument:
                return (target, keyword.arg) in self.boundaries
        return False

    # ----- trials, load and falsifiers -------------------------------------------------------------------
    def trial(self, qual: str, facts: dict) -> list:
        saved = {key: copy.copy(value) for key, value in reach.FACTS.items()}
        reach.load_facts(facts)
        definition = self.p.defs[qual]
        clone = dataclasses.replace(definition, channels=0, gaps=0, gaps_n=0, edges=set(), edges_name=set(),
                                    gap_sites=collections.Counter(), callback_params=set(), param_receivers=[],
                                    other_param_sites=0, edges_inferred=set(), inferred_channels=0, inferred_gaps=0,
                                    param_inferred_ok=False, implicit_params=[], other_implicit_params=collections.Counter(),
                                    implicit_inferred_ok={})
        clone._rc_trial = True
        RECORDER.qual, RECORDER.hits = qual, []
        site = reach.BodyVisitor.site
        reach.BodyVisitor.site = lambda self, callee, node, offset: None
        try:
            reach.BodyVisitor(self.p, clone).run()
        finally:
            reach.BodyVisitor.site = site
            hits, RECORDER.qual = RECORDER.hits, None
            reach.FACTS.clear()
            reach.FACTS.update(saved)
        self.last_clone = clone
        return hits

    def anchors(self, reason: dict, result: dict) -> list:
        """(definition, lines or None, text) where the reason's facts should close a gap."""
        claim = reason["claim"]
        form = claim["form"]
        if form == "type":
            return [(result["def"], {claim["site"].get("line")} if claim["site"].get("line") else None, claim["expr"],
                     claim["site"].get("col"))]
        if form == "attr":
            out = []
            cls, attr = result["class"], claim["name"]
            for method in [q for q, d in self.p.defs.items() if d.class_qual and self.enclosing_in(q, cls)]:
                lines = {n.lineno for n in self.code.own_nodes(method) if isinstance(n, ast.Attribute) and n.attr == attr
                         and isinstance(n.value, ast.Name) and n.value.id == "self" and isinstance(n.ctx, ast.Load)}
                if lines:
                    out.append((method, lines, f"self.{attr}", None))
            return out
        if form in ("contract", "dispatch"):
            lines = {f["line"] for f in result["facts"].get("discharged_calls", [])}
            return [(result["def"], lines, claim["call"], None)]
        if form == "boundary":
            return [(result["def"], None, claim["param"], None)]
        return []

    @staticmethod
    def matching(hits: list, lines, text: str, col: int | None = None) -> list:
        out = []
        for line, column, category, spelled in hits:
            if lines is not None and line not in lines:
                continue
            if col is not None and column != col:
                continue
            if spelled == text or spelled.startswith(text + ".") or spelled.startswith(text + "(") \
                    or (text.isidentifier() and text in names_in_text(spelled)):
                out.append((line, column, category, spelled))
        return out

    def merged(self, rids) -> dict:
        out = collections.defaultdict(list)
        for rid in rids:
            for key, entries in self.admitted.get(rid, {}).items():
                out[key].extend(entries)
        return dict(out)

    def rank(self, rid: str) -> tuple:
        """Load order: ESTABLISHED before DOCUMENTED, then by id.  Uses the status a reason was admitted
        with, which the load test itself may later relabel REDUNDANT or NOT-LOAD-BEARING."""
        return (-RANK[self.results[rid]["admitted_as"]], rid)

    def load(self, rid: str) -> dict:
        """What this reason closes beyond every reason ranked before it: its marginal load, in rank order.
        Facts it uses are loaded with it, so a reason built on another is measured with its foundation."""
        reason, result = self.reasons[rid], self.results[rid]
        stronger = [r for r in self.admitted if r != rid and self.rank(r) < self.rank(rid)]
        anchors = self.anchors(reason, result)
        if not anchors:
            if reason["claim"]["form"] in {
                "applies", "denial", "obligation", "declare", "external", "world",
            }:
                return {
                    "verdict": "obligation-reference",
                    "used_by": [],
                }
            return {"verdict": "unused", "used_by": []}  # settled by the users pass in run()
        with_it = sorted(set(stronger) | {rid} | {u for u in result.get("uses", []) if u in self.admitted})
        before, after = [], []
        for qual, lines, text, col in anchors:
            before += self.matching(self.trial(qual, self.merged(stronger)), lines, text, col)
            after += self.matching(self.trial(qual, self.merged(with_it)), lines, text, col)
        # A site is open at a tier while any of its gaps is a category that tier does not resolve: a gap
        # that only changes category (to "method: stdlib-object name", say) closes at T and C, not at S or I.
        closes_at = {}
        for tier, resolved in RESOLVED_AT.items():
            open_before = {
                (line, column, text)
                for line, column, category, text in before
                if category not in resolved
            }
            open_after = {
                (line, column, text)
                for line, column, category, text in after
                if category not in resolved
            }
            closes_at[tier] = len(open_before - open_after)
        if result.get("tier") == "I":
            closes_at["S"] = None  # a fact resting on A1 never closes anything at tier S
        closed = max((v for v in closes_at.values() if v is not None), default=0)
        verdict = "redundant" if not before else ("closes nothing" if not closed else "closes")
        return {"verdict": verdict, "open_without": sorted(set(before))[:8], "open_with": sorted(set(after))[:8],
                "closed": closed, "closes_at": closes_at}

    def falsify(self, rid: str) -> list:
        reason, result = self.reasons[rid], self.results[rid]
        out = []
        for entry in reason.get("falsify", []):
            kind = entry["kind"]
            if kind == "mutate":
                out.append(self.mutate(reason, result, entry))
            elif kind == "plant":
                out.append(self.plant(reason, result, entry))
            elif kind == "row":
                rows = [row for b in reason.get("basis", []) if b["kind"] == "stdlib" for row in b["row"]]
                ok = bool(rows) and all(ROW_RESULTS.get(row) for row in rows)
                out.append({"kind": "row", "result": "bit" if ok else "did not bite",
                            "detail": f"rows run on Python {sys.version.split()[0]}: {', '.join(rows) or 'none cited'}"})
            else:
                out.append({"kind": kind, "result": "not run", "detail": "this prototype runs no test or observer falsifier"})
        return out

    def mutate(self, reason: dict, result: dict, entry: dict) -> dict:
        """Break the basis on the real AST (in memory), re-check, restore."""
        claim, patches = reason["claim"], Patches(self.code)
        form, kinds = claim["form"], [b["kind"] for b in reason.get("basis", [])]
        try:
            description = self.apply_mutation(reason, result, patches)
            if description is None:
                return {"kind": "mutate", "result": "not run", "detail": "no mutation known for these bases"}
            saved = (dict(self.attr_facts), dict(self.return_facts), set(self.boundaries))
            mutant = self.check(reason)
            self.attr_facts, self.return_facts, self.boundaries = saved[0], saved[1], saved[2]
        finally:
            patches.restore()
        if form == "boundary":
            bit = mutant.get("moved_count", 0) > result.get("moved_count", 0) or mutant["status"] not in RANK
            detail = f"{description}: moved {result.get('moved_count')} -> {mutant.get('moved_count')}, {mutant['status']}"
        elif form == "contract":
            bit = len(mutant.get("undischarged", {})) > len(result.get("undischarged", {})) or mutant["status"] not in RANK
            detail = f"{description}: undischarged {len(result.get('undischarged', {}))} -> {len(mutant.get('undischarged', {}))}"
        else:
            bit = mutant["status"] not in RANK
            detail = f"{description}: {mutant['status']} ({str(mutant.get('detail'))[:120]})"
        return {"kind": "mutate", "result": "bit" if bit else "did not bite", "detail": detail, "bases": kinds}

    def apply_mutation(self, reason: dict, result: dict, patches: Patches) -> str | None:
        claim = reason["claim"]
        form, kinds = claim["form"], [b["kind"] for b in reason.get("basis", [])]
        if form == "type" and "guard" in kinds:
            guards = result.get("_guard_nodes") or []
            if not guards:
                return None
            for test in guards:
                parent = self.parent_in(self.p.defs[result["def"]].node, test)
                if parent is None:
                    continue
                for field, value in ast.iter_fields(parent):
                    if value is test:
                        patches.set(parent, field, ast.copy_location(ast.Constant(value=isinstance(parent, ast.BoolOp) or
                                                                              not self.is_exit_guard(parent)), test))
                    elif isinstance(value, list) and any(v is test for v in value):
                        patches.set(parent, field, ast.copy_location(ast.Constant(value=True), test),
                                    index=[i for i, v in enumerate(value) if v is test][0])
            return f"deleted {len(guards)} guard test(s)"
        if form == "type" and "call-sites" in kinds or form == "attr" and "call-sites" in kinds or form == "boundary":
            if form == "attr":
                target = self.p.lookup(result["class"], "__post_init__")
                param = claim["name"]
            elif form == "boundary":
                target, param = result["def"], claim["param"]
            else:
                target = result["def"]
                expr = ast.parse(claim["expr"], mode="eval").body
                param = expr.attr if isinstance(expr, ast.Attribute) else expr.id
            for _caller, node, offset in self.p.call_sites.get(target, []):
                if form == "boundary":
                    definition = self.p.defs[target]
                    argument, hidden = reach.call_argument(definition, param, node, offset)
                    if argument is None or hidden or self.value_types(_caller, argument, Used()) is None:
                        continue
                keyword = next((k for k in node.keywords if k.arg == param), None)
                if keyword is not None:
                    patches.set(keyword, "value", planted_name(keyword.value))
                    return f"one call site ({self.p.defs[_caller].path}:{node.lineno}) now passes an unknown value"
                definition = self.p.defs[target]
                if form == "attr" or (definition.node.name == "__post_init__"):
                    fields = dataclass_fields(self.p.classes[definition.class_qual], self.p)
                    position = fields[param][0] if param in fields else None
                else:
                    position = definition.params.index(param) - offset if param in definition.params else None
                if position is not None and 0 <= position < len(node.args) and not isinstance(node.args[position], ast.Starred):
                    patches.set(node, "args", planted_name(node.args[position]), index=position)
                    return f"one call site ({self.p.defs[_caller].path}:{node.lineno}) now passes an unknown value"
            return None
        if form == "type" and "assigned" in kinds:
            if not claim["expr"].isidentifier():
                return None
            definition = self.p.defs[result["def"]]
            value, why = self.sole_local(result["def"], claim["expr"])
            root = definition.node
            if value is None and why == "not bound here":  # a module global: break its one module-level assignment
                value, _why = self.sole_global(definition.path, claim["expr"])
                root = self.p.trees[definition.path]
            if value is not None:
                parent = self.parent_in(root, value)
                if isinstance(parent, (ast.Tuple, ast.List)) and value in parent.elts:
                    patches.set(parent, "elts", planted_name(value), index=parent.elts.index(value))
                else:
                    patches.set(parent, "value", planted_name(value))
                return "its assignment now gives an unknown value"
            return None
        if form == "attr" and "assigned" in kinds:
            init = self.p.lookup(result["class"], "__init__")
            node = self.p.defs[init].node
            patches.insert(node.body, len(node.body), statement(f"self.{claim['name']} = {PLANTED}", node.body[-1]))
            return f"__init__ now also assigns self.{claim['name']} an unknown value"
        if "annotation" in kinds:  # the stated basis says nothing: every cited annotation now reads `object`
            changed = 0
            for basis in reason.get("basis", []):
                if basis["kind"] != "annotation":
                    continue
                tree, line = self.p.trees.get(basis["location"]["path"]), basis["location"]["line"]
                for node in (list(ast.walk(tree)) if tree is not None else []):
                    if isinstance(node, ast.arg) and node.annotation is not None \
                            and node.lineno <= line <= (node.end_lineno or line):
                        field = "annotation"
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None \
                            and node.returns.lineno <= line <= (node.returns.end_lineno or line):
                        field = "returns"
                    elif isinstance(node, ast.AnnAssign) and node.lineno == line:
                        field = "annotation"
                    else:
                        continue
                    patches.set(node, field, ast.copy_location(ast.Name(id="object", ctx=ast.Load()), getattr(node, field)))
                    changed += 1
            return f"{changed} cited annotation(s) now say object" if changed else None
        if form == "returns":
            node = self.p.defs[result["def"]].node
            for inner in ast.walk(node):
                if isinstance(inner, ast.Return) and inner.value is not None:
                    patches.set(inner, "value", planted_name(inner.value))
            return "every return now gives an unknown value"
        if form == "dispatch":  # break the loop the literal basis reads: the one binding the call's receiver
            for _call, loops in self.dispatch_loops(result["def"], claim):
                if len(loops) == 1 and isinstance(loops[0].iter, (ast.Tuple, ast.List)) and loops[0].iter.elts:
                    first = loops[0].iter.elts[0]
                    patches.set(loops[0].iter, "elts", planted_name(first), index=0)
                    return (f"the receiver's loop literal (line {loops[0].iter.lineno}) now starts with an unknown value "
                            f"in place of `{ast.unparse(first)}`")
            return None
        if form == "contract":
            discharged = result.get("discharged") or []
            if not discharged:
                return None
            caller = discharged[0]
            node = self.p.defs[caller].node
            session = next((n.func.value.id for n in ast.walk(node) if isinstance(n, ast.Call)
                            and isinstance(n.func, ast.Attribute) and n.func.attr == "register"
                            and isinstance(n.func.value, ast.Name)), None)
            if session is None:
                return None
            patches.insert(node.body, len(node.body), statement(f"_kept = [{session}]", node.body[-1]))
            return f"{caller} now stores its session"
        return None

    @staticmethod
    def is_exit_guard(node: ast.AST) -> bool:
        return isinstance(node, ast.If) and not node.orelse and bool(node.body) and isinstance(
            node.body[-1], (ast.Raise, ast.Return, ast.Continue, ast.Break))

    @staticmethod
    def parent_in(root: ast.AST, child: ast.AST) -> ast.AST | None:
        for node in ast.walk(root):
            for _field, value in ast.iter_fields(node):
                if value is child or (isinstance(value, list) and any(v is child for v in value)):
                    return node
        return None

    def plant(self, reason: dict, result: dict, entry: dict) -> dict:
        target = self.code.qual(entry["def"])
        if target is None or target not in self.p.defs:
            return {"kind": "plant", "result": "did not bite", "detail": f"no definition {entry['def']['qual']}"}
        reached = [e["from"] for e in result["facts"].get("supplier_edges", []) if target in e["to"]]
        patches = Patches(self.code)
        node = self.p.defs[target].node
        try:
            patches.insert(node.body, 0, statement("open('planted.txt', 'w').write('x')", node.body[0]))
            self.trial(target, {})
            channels = self.last_clone.channels
        finally:
            patches.restore()
        written = bool(channels & reach.CHANNEL_BIT.get("filesystem_write", 0))
        bit = written and bool(reached)
        return {"kind": "plant", "result": "bit" if bit else "did not bite",
                "detail": f"planted write {'seen' if written else 'NOT seen'} in {target}; reached from "
                          f"{len(reached)} discharged caller(s)" + (f", e.g. {reached[0]}" if reached else "")}

    # ----- the least fixpoint ---------------------------------------------------------------------------
    def run(self) -> None:
        pending = {}
        for rid, reason in self.reasons.items():
            if dsl.unanswered(reason):
                self.results[rid] = {"status": "UNANSWERED", "detail": "a stub: answer each ? slot", "facts": {}}
            else:
                pending[rid] = reason
        rounds = 0
        while True:
            rounds += 1
            changed = False
            for rid in sorted(pending):
                if rid in self.admitted:
                    continue
                result = self.check(pending[rid])
                self.results[rid] = result
                if result["status"] not in RANK:
                    continue
                falsifiers = self.falsify(rid)
                result["falsifiers"] = falsifiers
                if any(f["result"] == "did not bite" for f in falsifiers):
                    result["status"] = "NOT-LOAD-BEARING"
                    result["detail"] = "a falsifier did not bite: " + "; ".join(
                        f["detail"] for f in falsifiers if f["result"] == "did not bite")
                    continue
                if result["status"] == "ESTABLISHED" and not any(f["result"] == "bit" for f in falsifiers):
                    result["status"] = "DOCUMENTED"
                    result["detail"] += "; no falsifier ran, so DOCUMENTED at most"
                result["tier"] = self.reason_tier(rid)
                self.admit(rid, result)
                changed = True
            if not changed or rounds > 20:
                break
        self.rounds = rounds
        self.conflicts()
        for rid in sorted(self.admitted, key=self.rank):
            self.results[rid]["load"] = self.load(rid)
        # A reason whose own sites close nothing still bears load when an admitted reason that does is
        # built on it (normalize-matched on normalize-pattern, say): propagate to a fixpoint.
        changed = True
        while changed:
            changed = False
            for rid in sorted(self.admitted):
                load = self.results[rid]["load"]
                if load["verdict"] in ("closes", "used"):
                    continue
                users = sorted(r for r in self.admitted if rid in self.results[r].get("uses", [])
                               and self.results[r]["load"]["verdict"] in ("closes", "used"))
                if users:
                    load["own_verdict"], load["verdict"], load["used_by"] = load["verdict"], "used", users
                    changed = True
        for rid in sorted(self.admitted):
            load = self.results[rid]["load"]
            if load["verdict"] == "redundant":
                self.results[rid]["status"] = "REDUNDANT"
                self.results[rid]["detail"] = "its sites are not open without it: " + str(self.results[rid]["detail"])
            elif load["verdict"] in ("closes nothing", "unused"):
                self.results[rid]["status"] = "NOT-LOAD-BEARING"
                self.results[rid]["detail"] = f"admitted, it {load['verdict']}: " + str(self.results[rid]["detail"])

    def reason_tier(self, rid: str) -> str:
        """I when the reason rests on A1 (project callers are all callers), directly or through a fact it
        used; S otherwise (resting on A0 alone, as every tier does)."""
        reason, result = self.reasons[rid], self.results[rid]
        if reason["claim"]["form"] in A1_FORMS or any(b["kind"] in A1_BASES for b in reason.get("basis", [])):
            return "I"
        if any(self.results.get(used, {}).get("tier") == "I" for used in result.get("uses", [])):
            return "I"
        return "S"

    def admit(self, rid: str, result: dict) -> None:
        result["admitted_as"] = result["status"]
        self.admitted[rid] = result["facts"]
        for fact in result["facts"].get("attr_types", []):
            self.attr_facts[(fact["class"], fact["attr"])] = (frozenset({fact_token(fact)}), rid)
        for fact in result["facts"].get("return_types", []):
            self.return_facts[fact["def"]] = (frozenset({fact_token(fact)}), rid)
        for fact in result["facts"].get("boundary", []):
            self.boundaries.add((fact["def"], fact["param"]))

    def conflicts(self) -> None:
        seen = collections.defaultdict(set)
        columns = collections.defaultdict(set)  # (def, expr, line) -> columns some reason names
        for facts in self.admitted.values():
            for fact in facts.get("site_types", []):
                columns[(fact["def"], fact["expr"], fact["line"])].add(fact.get("col"))
        for rid, facts in self.admitted.items():
            for fact in facts.get("classification", []):
                seen[("classification", fact["object_id"], fact["kind"])].add(
                    (rid, "decision", fact["decision"])
                )
            for fact in facts.get("site_types", []):
                key = (fact["def"], fact["expr"], fact["line"])
                # a reason with no column speaks for every occurrence on the line, so it meets each column
                for col in ([fact["col"]] if fact.get("col") else sorted(c for c in columns[key] if c) or [None]):
                    seen[("site", *key, col)].add((rid, fact["kind"], fact["value"]))
            for fact in facts.get("attr_types", []):
                seen[("attr", fact["class"], fact["attr"])].add((rid, fact["kind"], fact["value"]))
            for fact in facts.get("return_types", []):
                seen[("returns", fact["def"])].add((rid, fact["kind"], fact["value"]))
        for key, entries in seen.items():
            if len({(k, v) for _r, k, v in entries}) > 1:
                for rid, _k, _v in entries:
                    self.results[rid]["status"] = "CONFLICTED"
                    self.results[rid]["detail"] = f"{key} is typed differently by {sorted(r for r, _, _ in entries)}"
                    self.admitted.pop(rid, None)

    def facts_for(self, statuses: tuple, tiers: tuple = ("S", "I")) -> dict:
        """Every fact of a reason admitted with one of `statuses` at one of `tiers`, including reasons the
        load test later labelled REDUNDANT or NOT-LOAD-BEARING: they were checked, and a reason built on
        one needs its facts.  A reason refused, or one whose falsifier did not bite, is never admitted."""
        out = collections.defaultdict(list)
        for rid in sorted(self.admitted):
            result = self.results[rid]
            if result["admitted_as"] in statuses and result.get("tier", "I") in tiers:
                for key, entries in self.admitted[rid].items():
                    out[key].extend(dict(e, reason=rid, tier=result.get("tier"), status=result["status"])
                                    for e in entries)
        return dict(out)


# ----- helpers --------------------------------------------------------------------------------------
def names_in(node: ast.AST) -> set:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def claim_names(claim: dict) -> set:
    """The global and attribute names a claim is about: what a witness would have to rebind to touch it."""
    out = set()
    for key in ("expr", "call"):
        if claim.get(key):
            try:
                tree = ast.parse(claim[key], mode="eval")
            except SyntaxError:
                continue
            out |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            out |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    if claim.get("name"):
        out.add(claim["name"])
    for ref in [claim.get(key) for key in ("def", "consumer", "supplier", "class")] + list(claim.get("targets") or []):
        if isinstance(ref, dict) and ref.get("qual"):
            out.add(ref["qual"].rpartition(".")[2])
    return out - {"self", "cls"}


def names_in_text(text: str) -> set:
    try:
        return names_in(ast.parse(text, mode="eval"))
    except SyntaxError:
        return set()


def default_of(definition, param: str) -> ast.AST | None:
    node = definition.node
    if node is None or not hasattr(node, "args"):
        return None
    args = node.args
    positional = [a.arg for a in (*args.posonlyargs, *args.args)]
    if param in positional:
        index = positional.index(param) - (len(positional) - len(args.defaults))
        return args.defaults[index] if index >= 0 else None
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if arg.arg == param:
            return default
    return None


def parent_assignment(nodes: list, target: ast.AST) -> ast.AST | None:
    for node in nodes:
        if isinstance(node, ast.Assign) and any(t is target for t in node.targets):
            return node
        if isinstance(node, ast.AnnAssign) and node.target is target and node.value is not None:
            return node
    return None


def class_node_of(info, program) -> ast.ClassDef | None:
    module = program.module_of[info.path]
    tail = info.qual[len(module) + 1:].split(".")
    body = program.trees[info.path].body
    node = None
    for name in tail:
        node = next((n for n in body if isinstance(n, ast.ClassDef) and n.name == name), None)
        if node is None:
            return None
        body = node.body
    return node


def dataclass_fields(info, program) -> dict:
    """field -> (positional index, default types or None), bases first, as dataclasses orders them."""
    order, defaults = [], {}
    chain = []
    todo = [info.qual]
    while todo:
        qual = todo.pop()
        if qual in program.classes and qual not in chain:
            chain.append(qual)
            todo.extend(reversed(program.classes[qual].bases))
    for qual in reversed(chain):
        node = class_node_of(program.classes[qual], program)
        for statement_ in (node.body if node is not None else []):
            if isinstance(statement_, ast.AnnAssign) and isinstance(statement_.target, ast.Name):
                name, value, default = statement_.target.id, statement_.value, None
                if isinstance(value, ast.Call) and audit._dotted_name(value.func) in ("field", "dataclasses.field"):
                    factory = next((k.value for k in value.keywords if k.arg == "default_factory"), None)
                    plain = next((k.value for k in value.keywords if k.arg == "default"), None)
                    if factory is not None and audit._dotted_name(factory) in BUILTIN_TYPES:
                        default = frozenset({audit._dotted_name(factory)})
                    elif isinstance(plain, ast.Constant):
                        default = frozenset({"none" if plain.value is None else type(plain.value).__name__})
                elif isinstance(value, ast.Constant):
                    default = frozenset({"none" if value.value is None else type(value.value).__name__})
                elif isinstance(value, ast.Tuple):
                    default = frozenset({"tuple"})
                if name not in order:
                    order.append(name)
                defaults[name] = default
    return {name: (index, defaults[name]) for index, name in enumerate(order)}


def is_frozen(info, program) -> bool:
    node = class_node_of(info, program)
    for decorator in (node.decorator_list if node is not None else []):
        if isinstance(decorator, ast.Call) and audit._dotted_name(decorator.func) in ("dataclass", "dataclasses.dataclass"):
            return any(k.arg == "frozen" and isinstance(k.value, ast.Constant) and k.value.value is True
                       for k in decorator.keywords)
    return False


def token_origin(token: str) -> tuple[str, str | None]:
    if token.startswith("optional:"):
        token = token.partition(":")[2]
    if token == "json":
        return "json", None
    if token in BUILTIN_TYPES:
        return "builtin", token
    head, _, rest = token.partition(":")
    if head in ("class", "exact"):
        return "project_class", rest
    if head == "stdlib":
        return "stdlib", rest
    return "unknown", None


def fact_token(fact: dict) -> str:
    kind, value = fact["kind"], fact.get("value")
    return {"json": "json", "builtin": value, "project_class": f"class:{value}", "stdlib": f"stdlib:{value}"}.get(kind, "?")


def origin_token(kind: str, value) -> str | None:
    if kind == "json":
        return "json"
    if kind == "builtin":
        return {"Dict": "dict", "DictComp": "dict", "List": "list", "ListComp": "list", "Tuple": "tuple",
                "Set": "set", "SetComp": "set", "JoinedStr": "str"}.get(value, value if value in BUILTIN_TYPES else None)
    if kind == "project_class" and value:
        return f"class:{value}"
    return None


def cited_paths(value) -> set:
    if isinstance(value, dict):
        return ({value["path"]} if isinstance(value.get("path"), str) else set()).union(
            *(cited_paths(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(cited_paths(v) for v in value)) if value else set()
    return set()


def coordinate(reasons: list) -> dict:
    """What the statuses are bound to: the checked tree's revision and dirty state, the bytes of every file
    a reason cites, and the tools.  A changed coordinate means the statuses must be checked again."""
    root = Path(reach.ROOT)

    def git(*args: str) -> str:
        try:
            done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=120,
                                  check=False)
            return done.stdout.strip() if done.returncode == 0 else f"UNKNOWN (git exit {done.returncode})"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"UNKNOWN ({type(exc).__name__})"

    status = git("status", "--porcelain=v1")
    return {"root": str(root), "branch": git("rev-parse", "--abbrev-ref", "HEAD"), "head": git("rev-parse", "HEAD"),
            "dirty_entries": len(status.splitlines()) if not status.startswith("UNKNOWN") else None,
            "status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
            "cited_files_sha256": {p: _sha(root / p) for p in sorted(set().union(*(cited_paths(r) for r in reasons)))},
            "tools_sha256_at_start": TOOLS_AT_START, "python": sys.version.split()[0], "platform": sys.platform}


def main() -> int:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    reasons, sources, malformed, files = [], {}, {}, {}
    for name in sys.argv[2:]:
        text = Path(name).read_text(encoding="utf-8")
        parsed = dsl.parse(text, Path(name).name)
        for reason in parsed["ir"]["reasons"]:
            reasons.append(reason)
            sources[reason["id"]] = Path(name).name
        for rid, messages in parsed["malformed"].items():
            malformed[rid] = messages
            sources[rid] = Path(name).name
        files[Path(name).name] = {"ir": dsl.ir_digest(parsed["ir"]), "errors": parsed["errors"],
                                  "file_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    code = Code()
    checker = Checker(code, reasons)
    started = time.perf_counter()
    checker.run()
    results = dict(checker.results)
    for rid, messages in malformed.items():
        results[rid] = {"status": "MALFORMED", "detail": "; ".join(messages), "facts": {}}
    counts = collections.Counter(r["status"] for r in results.values())
    switches = {k: os.environ.get(k, "") for k in ("REACH_NAME_RULE", "REACH_IMPLICIT", "REACH_ANNOTATIONS",
                                                   "REACH_SUBJECT")}
    subject = reach.SUBJECT or "whole"
    for result in results.values():
        result.pop("_guard_nodes", None)
    code.attr_stores("")
    w_index, w_computed, w_dotted = code._witness
    witness = {"subject_program": subject,
               "constant_name_writes": sum(len(v) for v in w_index.values()),
               "dotted_patches": sum(len(v) for v in w_dotted.values()),
               "computed_writes": [f"{code.program.defs[q].path}:{line} {how}" for q, line, how, _r, _x in w_computed]}
    report = {"vocabulary": dsl.vocabulary_digest(), "files": files, "rows": ROW_RESULTS, "switches": switches,
              "subject_program": subject, "witness_patches": witness,
              "coordinate": coordinate(reasons), "rounds": checker.rounds, "counts": dict(counts),
              "tiers": dict(collections.Counter(f"admitted {r['admitted_as']} tier {r.get('tier')}"
                                                for r in results.values() if r.get("admitted_as"))),
              "reasons": {rid: dict(results[rid], source=sources.get(rid)) for rid in sorted(results)}}
    (out / "check.json").write_text(json.dumps(report, indent=1, sort_keys=True, default=str), encoding="utf-8")
    # facts_<level>.json carries every admitted fact (load it only for tier I and above); facts_<level>_S.json
    # only those resting on A0 alone (loadable at every tier, S included).
    # The facts hold for this subject program only: with tests as witnesses, load them into nontest or shipped
    # reach runs (shipped's subject is smaller, so every write counted here is still counted), never whole.
    for level, statuses in (("established", ("ESTABLISHED",)), ("documented", ("ESTABLISHED", "DOCUMENTED"))):
        for suffix, tiers in (("", ("S", "I")), ("_S", ("S",))):
            facts = dict(checker.facts_for(statuses, tiers), _subject_program=subject)
            (out / f"facts_{level}{suffix}.json").write_text(json.dumps(facts, indent=1, sort_keys=True), encoding="utf-8")
    print(f"checked {len(results)} reasons in {checker.rounds} rounds ({time.perf_counter() - started:.1f} s), "
          f"subject {subject}, switches {switches}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    print(f"witness patches (outside the subject; listed, never refuting): {witness['constant_name_writes']} by name, "
          f"{witness['dotted_patches']} dotted, {len(witness['computed_writes'])} computed {witness['computed_writes'][:4]}")
    for rid in sorted(results):
        r = results[rid]
        admitted = f" (admitted {r['admitted_as']})" if r.get("admitted_as") and r["admitted_as"] != r["status"] else ""
        print(f"  {r['status']:16} {rid:30} {'tier ' + r['tier'] if r.get('tier') else '':7} "
              f"{str(r.get('detail', ''))[:170]}{admitted}")
        for f in r.get("falsifiers", []):
            print(f"  {'':16} {'':30}   falsify {f['kind']}: {f['result']} - {str(f['detail'])[:120]}")
        if r.get("witness_patches"):
            print(f"  {'':16} {'':30}   witness patches: {r['witness_patches']['count']}, e.g. "
                  f"{r['witness_patches']['first'][0]}")
        if r.get("load"):
            load = r["load"]
            print(f"  {'':16} {'':30}   load: {load.get('verdict')}"
                  + (f" (own sites: {load['own_verdict']}; used by {', '.join(load['used_by'])})" if load.get("own_verdict") else "")
                  + f" closes_at={load.get('closes_at')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
