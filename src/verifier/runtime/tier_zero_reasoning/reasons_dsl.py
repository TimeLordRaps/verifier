"""reasons.vstd: a line domain-specific language compiled to a canonical JavaScript Object
Notation (JSON) intermediate representation (IR). The IR is the normative form; this text is
one way to write it. Standard library only (requires-python >= 3.10 has no tomllib).

Source positions count Unicode Transformation Format, 8-bit (UTF-8) bytes; American Standard
Code for Information Interchange (ASCII) text therefore has matching byte and character columns.

    # a comment: never part of the IR
    reason <id>
      about    <object-id> ...
      claim    <form> <operand> ...        exactly one
      basis    <kind> <operand> ...        zero or more
      falsify  <kind> <operand> ...        zero or more
      assume   <assumption-id> ...         zero or more
      bound    <sha256 digest>             the site digest a DOCUMENTED reason was written against
      note     <free text>                 kept in the IR, never read by a check

A token is a bare word or a `backquoted` expression (no backquote inside either).  Code is named
as path.py::qualname, a site as path.py::qualname:line[:column]: the line, and the column when the
expression occurs more than once on it, pick the occurrence the claim is about (the column is
1-based and counts UTF-8 bytes, as Python's ast does; for an ASCII line it is the character
column); `bound` and the expression bind it.  `?` is an unanswered slot: polish writes stubs with them
(reasons.open.vstd), and a reason that still holds one is UNANSWERED, never admitted.

Every operand has exactly one shape, so the IR never changes type with the number of words: a
`*name` operand is always a list, every other operand one string or object.

The vocabulary below is registry data: its digest is part of every IR, so a reason checked under one
vocabulary is never silently read under another.  An unknown form, kind or operand shape makes that
one reason MALFORMED.  A malformed reason is never admitted and never dropped: its id stays in
the IR's "malformed" list.  Lines that belong to no reason are counted in "unattributed".
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path

OBLIGATION_DECISIONS = frozenset({"REQUIRED"})


VOCABULARY = {
    "version": "vstd-reasons-vocabulary/0.3",
    # operand grammars: a reader that does not know a grammar must not read the IR, so they are digested too
    "shapes": {"site": "path.py::qualname[:line[:column]]  (column: 1-based, UTF-8 bytes)",
               "ref": "path.py::qualname", "location": "path.py:line", "expr": "one Python expression",
               "type": "a type token", "ident": "a Python identifier", "object": "an object id",
               "word": "a bare word"},
    # operand list per form: "name:shape"; "=word" is a literal keyword; "*name:shape" takes the rest (one or more)
    "claims": {
        "type": ["site:site", "expr:expr", "type:type"],       # the expression, at the site, always has the type
        "attr": ["class:ref", "name:ident", "type:type"],      # every instance's attribute, once constructed
        "returns": ["def:ref", "type:type"],                   # every value the definition returns
        "contract": ["consumer:ref", "call:expr", "=supplier", "supplier:ref", "param:ident"],
        #   the call in the consumer runs only values that reached the supplier through the parameter
        "boundary": ["def:ref", "param:ident"],                # the parameter's uses belong to each caller
        "dispatch": ["site:site", "call:expr", "=to", "*targets:ref"],  # the call runs exactly these definitions
        "external": ["target:word", "=effects", "*effects:word"],  # code outside the census
        "world": ["channel:word", "=post", "postcondition:word"],  # a real-world channel's postcondition
        "declare": ["obligation:word", "field:ident", "value:word"],  # an AdmissionObligation declaration field
        "applies": ["object:object", "kind:word"],
        "denial": ["object:object", "kind:word"],              # the kind does not apply ([OPEN] for semantic kinds)
        # One exact compiled package obligation. REQUIRED says that this
        # object/coordinate pair must remain in the verifier denominator; it
        # does not claim that the obligation's checker has passed.
        "obligation": ["object:object", "coordinate:word", "decision:word"],
    },
    # basis kinds: operands, and the strongest status each can support
    "bases": {
        "guard": [[], "ESTABLISHED"],                  # a type/None guard in the site's definition dominates the use
        "construction": [["check:ref"], "ESTABLISHED"],  # the constructor raises unless the attribute has the type; frozen
        "assigned": [[], "ESTABLISHED"],               # every assignment in the program gives the type (void rules)
        "returns": [[], "ESTABLISHED"],                # every return statement's value has the type
        "stdlib": [["*row:word"], "ESTABLISHED"],      # rows of the stdlib table, each run on this interpreter
        "call-sites": [[], "ESTABLISHED"],             # every project call site passes the type
        "literal": [[], "ESTABLISHED"],                # the receiver ranges over a literal of project names
        "registry": [[], "ESTABLISHED"],               # contract: consumers' sessions are local, suppliers project classes
        "annotation": [["location:location"], "DOCUMENTED"],  # a stated annotation: Python never checks it
        "declared": [["*evidence:word"], "DOCUMENTED"],       # a declarant's statement, with the evidence it cites
    },
    "falsifiers": {
        "mutate": ["action:word", "=expect", "outcome:word"],             # mutate delete-basis expect reopen
        "plant": ["effect:word", "=in", "def:ref", "=expect", "outcome:word"],  # plant fs-write in <def> expect named
        "row": ["=expect", "outcome:word"],                               # row expect holds
        "test": ["node:word", "=expect", "outcome:word"],                 # a pytest node that must give the outcome
        "observe": ["run:word", "=expect", "outcome:word"],               # an audit-hook observer run
    },
    "types": ["str", "bytes", "int", "float", "bool", "none", "dict", "list", "tuple", "set", "frozenset", "json",
              "class:<dotted name>", "exact:<dotted name>", "stdlib:<dotted name>", "optional:<type>"],
    "statuses": ["ESTABLISHED", "DOCUMENTED", "STALE", "REDUNDANT", "REFUTED", "UNCHECKED", "MALFORMED", "NOT-LOAD-BEARING",
                 "UNANSWERED", "CONFLICTED"],
}
IR_VERSION = "vstd-reasons-ir/0.1"
OBSERVATION_IR_VERSION = "vstd-reasons-observation-ir/0.1"
FIELDS = ("about", "claim", "basis", "falsify", "assume", "bound", "note")
_ID = re.compile(r"[a-z0-9][a-z0-9.\-]{0,79}")
_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
_QUALNAME = r"[A-Za-z_<][A-Za-z0-9_<>]*(?:\.[A-Za-z_<][A-Za-z0-9_<>]*)*"
_PATH = r"[A-Za-z0-9_][A-Za-z0-9_./\-]*\.pyi?"
_SITE = re.compile(rf"(?P<path>{_PATH})::(?P<qual>{_QUALNAME})(?::(?P<line>[1-9][0-9]*)(?::(?P<col>[1-9][0-9]*))?)?")
_REF = re.compile(rf"(?P<path>{_PATH})::(?P<qual>{_QUALNAME})")
_LOCATION = re.compile(rf"(?P<path>{_PATH}):(?P<line>[1-9][0-9]*)")
_OBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,199}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SIMPLE_TYPES = {"str", "bytes", "int", "float", "bool", "none", "dict", "list", "tuple", "set", "frozenset", "json"}
STUB = "?"


def canonical(value) -> bytes:
    """Verifier's canonical JSON form (certificate.py canonical_bytes)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def vocabulary_digest() -> str:
    return "sha256:" + hashlib.sha256(canonical(VOCABULARY)).hexdigest()


def tokens(text: str) -> list[str]:
    out, i = [], 0
    while i < len(text):
        if text[i].isspace():
            i += 1
        elif text[i] == "`":
            end = text.find("`", i + 1)
            if end < 0:
                raise ValueError("unclosed backquote")
            if end == i + 1:
                raise ValueError("empty backquoted token")
            out.append(text[i + 1:end])
            i = end + 1
            if i < len(text) and not text[i].isspace():
                raise ValueError("a backquoted token must end at a space")
        else:
            end = i
            while end < len(text) and not text[end].isspace():
                end += 1
            word = text[i:end]
            if "`" in word:
                raise ValueError(f"a backquote inside a bare word: {word!r}")
            out.append(word)
            i = end
    return out


def valid_type(token: str) -> bool:
    if token in _SIMPLE_TYPES:
        return True
    head, _, rest = token.partition(":")
    if head in ("class", "exact", "stdlib"):
        return bool(_DOTTED.fullmatch(rest))
    if head == "optional":
        return valid_type(rest) and not rest.startswith("optional:")
    return False


def shaped(shape: str, word: str, what: str):
    """One operand, validated and put in its IR form."""
    if word == STUB:
        return STUB
    if shape == "site" or shape == "ref":
        matched = (_SITE if shape == "site" else _REF).fullmatch(word)
        if matched is None:
            want = "path.py::qualname[:line[:column]]" if shape == "site" else "path.py::qualname"
            raise ValueError(f"{what}: bad {shape} {word!r} (want {want})")
        out = {"path": matched["path"], "qual": matched["qual"]}
        if shape == "site" and matched["line"]:
            out["line"] = int(matched["line"])
            if matched["col"]:
                out["col"] = int(matched["col"])
        return out
    if shape == "location":
        matched = _LOCATION.fullmatch(word)
        if matched is None:
            raise ValueError(f"{what}: bad location {word!r} (want path.py:line)")
        return {"path": matched["path"], "line": int(matched["line"])}
    if shape == "expr":
        try:
            ast.parse(word, mode="eval")
        except SyntaxError as exc:
            raise ValueError(f"{what}: {word!r} is not one Python expression ({exc.msg})") from None
        return word
    if shape == "type":
        if not valid_type(word):
            raise ValueError(f"{what}: bad type {word!r}")
        return word
    if shape == "ident":
        if not word.isidentifier():
            raise ValueError(f"{what}: bad identifier {word!r}")
        return word
    if shape == "object":
        if not _OBJECT.fullmatch(word):
            raise ValueError(f"{what}: bad object id {word!r}")
        return word
    if shape == "word":
        return word
    raise ValueError(f"{what}: vocabulary names an unknown shape {shape!r}")


def operands(schema: list[str], words: list[str], what: str) -> dict:
    out: dict = {}
    index = 0
    for position, spec in enumerate(schema):
        if spec.startswith("="):
            if index >= len(words) or words[index] != spec[1:]:
                found = words[index] if index < len(words) else "nothing"
                raise ValueError(f"{what}: expected keyword {spec[1:]!r}, found {found!r}")
            index += 1
            continue
        variadic = spec.startswith("*")
        name, _, shape = spec.lstrip("*").partition(":")
        if index >= len(words):
            raise ValueError(f"{what}: missing {name}")
        if variadic:
            if position != len(schema) - 1:
                raise ValueError(f"{what}: vocabulary puts a variadic operand before the end")
            out[name] = [shaped(shape, word, f"{what} {name}") for word in words[index:]]
            index = len(words)
        else:
            out[name] = shaped(shape, words[index], f"{what} {name}")
            index += 1
    if index != len(words):
        raise ValueError(f"{what}: {len(words) - index} extra word(s): {' '.join(words[index:])}")
    return out


def compile_claim(words: list[str]) -> dict:
    if not words:
        raise ValueError("claim: missing form")
    form, rest = words[0], words[1:]
    if form not in VOCABULARY["claims"]:
        raise ValueError(f"claim: unknown form {form!r}")
    claim = {"form": form, **operands(VOCABULARY["claims"][form], rest, f"claim {form}")}
    if form == "obligation" and claim["decision"] not in OBLIGATION_DECISIONS:
        raise ValueError(
            "claim obligation: decision must be one of "
            + ", ".join(sorted(OBLIGATION_DECISIONS))
        )
    return claim


def compile_entry(table: str, words: list[str]) -> dict:
    if not words:
        raise ValueError(f"{table}: missing kind")
    kind, rest = words[0], words[1:]
    if kind == STUB:
        if rest:
            raise ValueError(f"{table}: words after an unanswered slot")
        return {"kind": STUB}
    known = VOCABULARY["bases" if table == "basis" else "falsifiers"]
    if kind not in known:
        raise ValueError(f"{table}: unknown kind {kind!r}")
    schema = known[kind][0] if table == "basis" else known[kind]
    return {"kind": kind, **operands(schema, rest, f"{table} {kind}")}


def _empty(identifier: str) -> dict:
    return {"id": identifier, "about": [], "claim": None, "basis": [], "falsify": [], "assume": [],
            "bound": None, "note": None}


def parse(text: str, source: str = "<reasons>") -> dict:
    """Text -> {"ir": canonical IR, "errors": [file-level messages], "malformed": {id: [messages]}}."""
    reasons: dict[str, dict] = {}
    malformed: dict[str, list[str]] = {}
    errors: list[str] = []
    unattributed = 0
    current: dict | None = None    # the reason the next field lines belong to (a throwaway for duplicates)
    current_id: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        where = f"{source}:{number}"
        if not line[0].isspace():
            current, current_id = None, None
            words = stripped.split()
            if words[0] != "reason" or len(words) != 2:
                errors.append(f"{where}: a line at column 0 must be 'reason <id>'")
                unattributed += 1
                continue
            identifier = words[1]
            if not _ID.fullmatch(identifier):
                errors.append(f"{where}: bad reason id {identifier!r}")
                unattributed += 1
                continue
            if identifier in reasons:  # both copies are malformed: which one is meant is not decidable
                malformed.setdefault(identifier, []).append(f"{where}: duplicate reason id")
                current, current_id = _empty(identifier), identifier  # fields go nowhere
                continue
            reasons[identifier] = current = _empty(identifier)
            current_id = identifier
            continue
        if current is None:
            errors.append(f"{where}: field outside a reason")
            unattributed += 1
            continue
        key, _, remainder = stripped.partition(" ")
        try:
            if key == "note":  # free text, whitespace collapsed; never tokenized
                text_part = " ".join(remainder.split())
                if not text_part:
                    raise ValueError("note: empty")
                current["note"] = text_part if current["note"] is None else current["note"] + " " + text_part
                continue
            words = tokens(remainder)
            if key not in FIELDS:
                raise ValueError(f"unknown field {key!r}")
            if key == "claim":
                if current["claim"] is not None:
                    raise ValueError("a reason has exactly one claim")
                current["claim"] = compile_claim(words)
            elif key in ("basis", "falsify"):
                current[key].append(compile_entry(key, words))
            elif key == "about":
                if not words:
                    raise ValueError("about: empty")
                current["about"].extend(shaped("object", word, "about") for word in words)
            elif key == "assume":
                if not words:
                    raise ValueError("assume: empty")
                current["assume"].extend(words)
            elif key == "bound":
                if len(words) != 1 or not _DIGEST.fullmatch(words[0]):
                    raise ValueError("bound: want one sha256:<64 hex> digest")
                if current["bound"] is not None:
                    raise ValueError("bound: given twice")
                current["bound"] = words[0]
        except ValueError as exc:
            malformed.setdefault(current_id, []).append(f"{where}: {exc}")
    for identifier, reason in reasons.items():
        if reason["claim"] is None:
            malformed.setdefault(identifier, []).append(f"{source}: reason {identifier} has no claim")
    ir_reasons = []
    for identifier in sorted(set(reasons) - set(malformed)):
        reason = dict(reasons[identifier])
        reason["about"] = sorted(set(reason["about"]))
        reason["assume"] = sorted(set(reason["assume"]))
        reason["basis"] = sorted(reason["basis"], key=lambda e: (e["kind"], canonical(e)))
        reason["falsify"] = sorted(reason["falsify"], key=lambda e: (e["kind"], canonical(e)))
        ir_reasons.append({k: v for k, v in reason.items() if v not in (None, [])})
    ir = {"ir": IR_VERSION, "vocabulary": vocabulary_digest(), "reasons": ir_reasons,
          "malformed": sorted(malformed)}
    if unattributed:
        ir["unattributed"] = unattributed
    return {"ir": ir, "errors": errors, "malformed": malformed}


def ir_digest(ir: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(ir)).hexdigest()


def falsifier_observation(reason: dict, entry: dict) -> dict:
    """Normalize one existing falsifier into the common observation ontology."""
    kind = entry["kind"]
    claim = reason["claim"]
    subject = {"reason": reason["id"], "claim": claim}
    if kind == "mutate":
        treatment = {"kind": "mutation", "action": entry["action"]}
        witness = {"kind": "static", "locator": "reasons-checker"}
    elif kind == "plant":
        treatment = {"kind": "plant", "effect": entry["effect"], "definition": entry["def"]}
        witness = {"kind": "static", "locator": "reasons-checker"}
    elif kind == "row":
        treatment = {"kind": "none"}
        witness = {"kind": "static", "locator": "stdlib-row-probe"}
    elif kind == "test":
        treatment = {"kind": "none"}
        witness = {"kind": "test", "locator": entry["node"]}
    elif kind == "observe":
        treatment = {"kind": "none"}
        witness = {"kind": "observer", "locator": entry["run"]}
    else:
        raise ValueError(f"unknown falsifier kind {kind!r}")
    return {
        "subject": subject,
        "treatment": treatment,
        "witness": witness,
        "expectation": entry["outcome"],
        "independence": {"class": "runtime-assessment-required" if kind in ("test", "observe") else "checker-static"},
    }


def observation_ir(ir: dict) -> dict:
    """Existing reasons IR -> one explicit observation for every falsifier, without dropping any."""
    observations = []
    for reason in ir["reasons"]:
        for index, entry in enumerate(reason.get("falsify", [])):
            observations.append({
                "id": f"{reason['id']}:{index}",
                "source_kind": entry["kind"],
                **falsifier_observation(reason, entry),
            })
    return {
        "ir": OBSERVATION_IR_VERSION,
        "source_ir": ir["ir"],
        "source_ir_digest": ir_digest(ir),
        "observations": observations,
    }


def unanswered(reason: dict) -> bool:
    """An unanswered slot anywhere in the claim, basis or falsifiers: a stub, inert until answered."""
    def walk(value) -> bool:
        if isinstance(value, dict):
            return any(walk(v) for v in value.values())
        if isinstance(value, list):
            return any(walk(v) for v in value)
        return value == STUB
    return any(walk(reason.get(key)) for key in ("claim", "basis", "falsify"))


def _word(value) -> str:
    text = str(value)
    return f"`{text}`" if any(c.isspace() for c in text) else text


def _render_value(shape: str, value) -> str:
    if value == STUB:
        return STUB
    if shape in ("site", "ref"):
        return (f"{value['path']}::{value['qual']}" + (f":{value['line']}" if value.get("line") else "")
                + (f":{value['col']}" if value.get("col") else ""))
    if shape == "location":
        return f"{value['path']}:{value['line']}"
    if shape == "expr":
        return f"`{value}`"
    return _word(value)


def _render_operands(schema: list[str], entry: dict) -> list[str]:
    words = []
    for spec in schema:
        if spec.startswith("="):
            words.append(spec[1:])
            continue
        name, _, shape = spec.lstrip("*").partition(":")
        if spec.startswith("*"):
            words.extend(_render_value(shape, item) for item in entry[name])
        else:
            words.append(_render_value(shape, entry[name]))
    return words


def render(ir: dict) -> str:
    """IR -> canonical text.  parse(render(ir))["ir"] == ir for every IR parse() produces with no
    malformed reasons (a malformed reason's text is not in the IR, so it cannot be rendered)."""
    lines = [f"# {ir['ir']}  vocabulary {ir['vocabulary']}"]
    if ir.get("malformed"):
        lines.append("# malformed, not rendered: " + " ".join(ir["malformed"]))
    for reason in ir["reasons"]:
        lines.append(f"reason {reason['id']}")
        if reason.get("about"):
            lines.append("  about    " + " ".join(reason["about"]))
        claim = reason["claim"]
        lines.append("  claim    " + " ".join([claim["form"], *_render_operands(VOCABULARY["claims"][claim["form"]], claim)]))
        for table, key in (("bases", "basis"), ("falsifiers", "falsify")):
            for entry in reason.get(key, []):
                if entry["kind"] == STUB:
                    lines.append(f"  {key:8} {STUB}")
                    continue
                schema = VOCABULARY[table][entry["kind"]]
                schema = schema[0] if table == "bases" else schema
                lines.append(f"  {key:8} " + " ".join([entry["kind"], *_render_operands(schema, entry)]))
        if reason.get("assume"):
            lines.append("  assume   " + " ".join(reason["assume"]))
        if reason.get("bound"):
            lines.append("  bound    " + reason["bound"])
        if reason.get("note"):
            lines.append("  note     " + reason["note"])
    return "\n".join(lines) + "\n"


def main() -> int:
    path = Path(sys.argv[1])
    result = parse(path.read_text(encoding="utf-8"), path.name)
    for message in result["errors"]:
        print("ERROR", message)
    for identifier, messages in sorted(result["malformed"].items()):
        for message in messages:
            print("MALFORMED", identifier, message)
    print(json.dumps(result["ir"], indent=1, sort_keys=True))
    print("IR digest", ir_digest(result["ir"]), "vocabulary", vocabulary_digest())
    return 1 if result["errors"] or result["malformed"] else 0


if __name__ == "__main__":
    sys.exit(main())
