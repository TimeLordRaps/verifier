"""Non-executing markup discovery for Verifier Standard (VSTD).

Hypertext Markup Language (HTML); JavaScript Object Notation (JSON);
Unicode Transformation Format, 8-bit (UTF-8). The standard
library tokenizer supplies source positions, not a browser document model.
Strict nesting, explicit ambiguity gaps and separately bound script fragments
prevent its permissive error recovery from becoming a completeness claim.
"""
from __future__ import annotations

import _markupbase
import html.entities
import html.parser
import json
from pathlib import Path
import posixpath
import re
import sys
from typing import Any
from urllib.parse import unquote, urlsplit

from verifier.runtime.self_polish_estate import MAX_AST_BYTES, bytes_digest


VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})
SCRIPT_TYPES = frozenset({"", "module", "text/javascript", "application/javascript"})
DATA_TYPES = frozenset({"application/json", "application/ld+json"})
_ACTIONS = {
    "TEMPLATE_UNRESOLVED": "Bind the renderer and its generated markup, then inventory that output.",
    "EXTERNAL_CODE_UNRESOLVED": "Bind the script's selected source bytes and address-resolution context; file ownership alone is insufficient.",
    "BASE_UNRESOLVED": "Bind the base-address and deployment resolution before claiming script-target coverage.",
    "SCRIPT_TYPE_UNSUPPORTED": "Provide a source parser and activation contract for the declared script or resource-mapping type.",
    "HANDLER_UNRESOLVED": "Supply inspectable handler source or evidence of its generation.",
    "EMBEDDED_DOCUMENT_UNRESOLVED": "Inventory and bind the embedded document and its activation boundary.",
    "EXECUTABLE_ADDRESS_UNRESOLVED": "Decode and inventory the address's embedded code under an explicit address-interpretation contract.",
    "CONTEXT_UNRESOLVED": "Bind a parser for the foreign, embedded or browser-dependent context and cover its interfaces.",
    "ENCODING_UNRESOLVED": "Bind the declared decoder and inventory its interpreted source; this census uses UTF-8.",
}
_TEMPLATE_PREFIX = "vstd-template-binding "
_TEMPLATE_TOKEN = re.compile(r"\{\{[a-z][a-z0-9_]*\}\}|@/")
_TEMPLATE_DECLARATION = re.compile(
    r"<!--\s*vstd-template-binding\s+\{.*?\}\s*-->", re.DOTALL
)


def supports(path: str) -> bool:
    return path.lower().endswith((".html", ".htm", ".html.in", ".htm.in"))


def mechanism() -> dict[str, Any]:
    """Expose selected interpreter/parser bytes without workstation paths."""
    return {"python": sys.version, "implementation": sys.implementation.name,
            "files": {name: bytes_digest(Path(module.__file__).read_bytes()) for name, module in (
                ("html.parser", html.parser), ("html.entities", html.entities), ("_markupbase", _markupbase))}}


def recapture(expected: dict[str, Any] | None) -> None:
    if expected is not None and mechanism() != expected:
        raise ValueError("NAMESPACE_HTML_MECHANISM_CHANGED")


def binding(observed: dict[str, Any]) -> dict[str, Any]:
    return {"mechanism": observed.get("html_mechanism"), "svg_mechanism": observed.get("svg_mechanism"),
            "embedded_sources": observed.get("embedded_sources", []),
            "code_references": observed.get("markup_code_references", [])}


def next_action(code: str, path: str) -> str:
    return _ACTIONS.get(code.removeprefix("NAMESPACE_HTML_"),
        "Correct ambiguous markup or bind explicit parser-recovery evidence.") + " Source: " + path


class _Census(html.parser.HTMLParser):
    def __init__(self, path: str, source: str, files: dict[str, str]) -> None:
        super().__init__(convert_charrefs=False)
        self.path, self.source, self.files = path, source, files
        self.line_offsets = [0]
        self.line_offsets.extend(index + 1 for index, char in enumerate(source) if char == "\n")
        self.surfaces: list[dict[str, Any]] = []
        self.gaps: list[dict[str, str]] = []
        self.fragments: list[dict[str, Any]] = []
        self.references: list[dict[str, str]] = []
        self.pending_references: list[tuple[str, str]] = []
        self.stack: list[tuple[str, list[str], bool]] = []
        self.script: dict[str, Any] | None = None
        self.has_base = False
        self.template_binding: dict[str, Any] | None = None
        self.ordinal = 0
        self.record("document", "HTMLDocument", [], False, 1)

    def gap(self, code: str, reason: str) -> None:
        if not any(row["code"] == code for row in self.gaps):
            self.gaps.append({"path": self.path, "code": code, "reason": reason})

    def record(self, name: str, form: str, kinds: list[str], unresolved: bool, line: int) -> str:
        if len(self.surfaces) >= 250_000:
            raise ValueError("NAMESPACE_HTML_SURFACE_CAPACITY")
        identity = "html:" + self.path + ":" + name
        self.surfaces.append({"surface_id": identity, "path": self.path, "line": line,
            "form": form, "source_kinds": kinds, "hints": [], "unresolved_marker": unresolved})
        return identity

    def fragment(self, identity: str, source: str, line: int, mode: str, kinds: list[str], unresolved: bool) -> None:
        self.fragments.append({"key": "html-fragment:" + identity, "surface_id": identity, "path": self.path,
            "source": source.encode("utf-8"), "line": line, "mode": mode,
            "source_kinds": kinds, "unresolved_marker": unresolved})

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.ordinal += 1
        line = self.getpos()[0]
        inherited = self.stack[-1][1:] if self.stack else ([], False)
        kinds, unresolved = set(inherited[0]), inherited[1]
        if len({name for name, _ in attrs}) != len(attrs):
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Duplicate attributes have ambiguous interpretations; no last-value-wins coverage.")
            unresolved = True
        for name, value in attrs:
            if name == "data-vstd-kinds":
                try:
                    labels = json.loads(value or "")
                    valid = (isinstance(labels, list) and bool(labels) and all(isinstance(label, str)
                             and re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", label) for label in labels))
                    if valid:
                        kinds.update(labels)
                    else:
                        unresolved = True
                except ValueError:
                    unresolved = True
        declared = sorted(kinds)
        element = "element:" + str(self.ordinal) + ":" + tag
        self.record(element, "HTMLElement", declared, unresolved, line)
        values = dict(attrs)
        for index, (name, value) in enumerate(attrs):
            self.record(element + ":attribute:" + str(index) + ":" + name, "HTMLAttribute", declared, unresolved, line)
            if (name.startswith(("@", ":", "[", "(", "v-", "x-", "on:", "bind:", "use:", "data-ng-"))
                    or name in {"data-bind", "ng-click", "ng-if"}):
                self.gap("NAMESPACE_HTML_TEMPLATE_UNRESOLVED", "Framework directives need their compiler and generated-interface evidence.")
            if re.fullmatch(r"[a-z_:][a-z0-9_.:-]*", name) is None:
                self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Nonordinary attribute syntax needs an explicit tokenizer or framework contract.")
            if name.startswith("on"):
                identity = self.record(element + ":" + name + ":" + str(index), "HTMLHandler", declared, unresolved, line)
                if value is None:
                    self.gap("NAMESPACE_HTML_HANDLER_UNRESOLVED", "A handler attribute has no inspectable source value.")
                else:
                    self.fragment(identity, value, line, "decoded-handler", declared, unresolved)
            if name == "srcdoc":
                self.gap("NAMESPACE_HTML_EMBEDDED_DOCUMENT_UNRESOLVED", "An embedded document needs its own source and activation evidence.")
            scheme = re.sub(r"[\x00-\x20]", "", value or "").split(":", 1)[0].lower()
            if name in {"href", "src", "action", "formaction", "data", "xlink:href"} and scheme in {"javascript", "vbscript", "data"}:
                self.gap("NAMESPACE_HTML_EXECUTABLE_ADDRESS_UNRESOLVED", "An executable or embedded-data address needs a separately decoded source boundary.")
        if tag == "base":
            self.has_base = True
            self.gap("NAMESPACE_HTML_BASE_UNRESOLVED", "A base address changes resource resolution; relative source bindings are withheld.")
        if tag == "meta" and (("charset" in values and (values["charset"] or "").lower() not in {"utf-8", "utf8"})
                or (values.get("http-equiv") or "").lower() == "content-type"):
            self.gap("NAMESPACE_HTML_ENCODING_UNRESOLVED", "A source decoding declaration needs evidence beyond the UTF-8 source census.")
        if "-" in tag or ":" in tag or tag in {"iframe", "object", "embed", "svg", "math", "noscript", "xmp", "plaintext", "textarea"}:
            self.gap("NAMESPACE_HTML_CONTEXT_UNRESOLVED", "Embedded documents, foreign markup or browser-dependent text contexts need additional coverage.")
        if tag == "script":
            identity = self.record("script:" + str(self.ordinal), "HTMLScript", declared, unresolved, line)
            kind = (values.get("type") or "").strip().lower()
            if "language" in values or kind not in SCRIPT_TYPES | DATA_TYPES:
                self.gap("NAMESPACE_HTML_SCRIPT_TYPE_UNSUPPORTED", "The script language or resource-mapping type lacks an applicable parser contract.")
            if "src" in values:
                self.pending_references.append((identity, values["src"] or ""))
            self.script = {"identity": identity, "line": line + (self.get_starttag_text() or "").count("\n"),
                "kind": kind, "parts": [], "kinds": declared, "unresolved": unresolved}
        if tag not in VOID:
            self.stack.append((tag, declared, unresolved))
            if len(self.stack) > 256:
                raise ValueError("NAMESPACE_HTML_NESTING_CAPACITY")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Self-closing non-void tags are not a browser-independent closing boundary.")
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self.script is not None:
            script = self.script
            source = "".join(script["parts"])
            if script["kind"] in SCRIPT_TYPES and source.strip():
                self.fragment(script["identity"], source, script["line"], "raw-script", script["kinds"], script["unresolved"])
            self.script = None
        if not self.stack or self.stack[-1][0] != tag:
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Implicit or mismatched closing tags need browser tree-construction evidence.")
        else:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if self.script is not None:
            self.script["parts"].append(data)
        elif "<" in data and (not self.stack or self.stack[-1][0] != "style"):
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Unparsed markup delimiters cannot establish complete source tokenization.")

    def handle_comment(self, data: str) -> None:
        # Recent standard-library versions may recover malformed declarations
        # as comments. Check the exact source opener at the parser's position,
        # rather than allowing recovery to erase the discovery gap.
        line, column = self.getpos()
        offset = self.line_offsets[line - 1] + column
        if self.source.startswith("<!-->", offset):
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "A prematurely closed comment requires explicit parser-recovery evidence.")
        elif self.source.startswith("<![", offset):
            self.gap("NAMESPACE_HTML_PARSE_UNAVAILABLE", "An unsupported markup declaration cannot establish complete source tokenization.")
        if data.strip().startswith(_TEMPLATE_PREFIX):
            if self.template_binding is not None:
                self.gap("NAMESPACE_HTML_TEMPLATE_UNRESOLVED", "A template must select exactly one renderer and token grammar.")
                return
            try:
                selected = json.loads(data.strip()[len(_TEMPLATE_PREFIX):])
                valid = (type(selected) is dict
                    and set(selected) == {"mode", "reason", "renderer", "tokens"}
                    and selected["mode"] == "literal-replacement"
                    and type(selected["reason"]) is str and bool(selected["reason"].strip())
                    and len(selected["reason"]) <= 1024
                    and type(selected["renderer"]) is str
                    and selected["renderer"] in self.files
                    and type(selected["tokens"]) is list
                    and selected["tokens"] == sorted(set(selected["tokens"]))
                    and all(type(token) is str and _TEMPLATE_TOKEN.fullmatch(token)
                            for token in selected["tokens"]))
                if not valid:
                    raise ValueError("invalid template binding")
                identity = self.record("template-binding", "HTMLTemplateBinding", [], False,
                                       self.getpos()[0])
                self.references.append({"surface_id": identity,
                    "target_path": selected["renderer"],
                    "target_source_digest": self.files[selected["renderer"]],
                    "scope": "DECLARED_TEMPLATE_RENDERER_SOURCE_NOT_EXECUTION"})
                self.template_binding = selected
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                self.gap("NAMESPACE_HTML_TEMPLATE_UNRESOLVED", "The template binding is malformed or does not select current renderer bytes and a closed token grammar.")
            return
        if "[if" in data.lower() or "--" in data or data.startswith((">", "->")):
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Conditional or malformed comments need an explicit parsing-context boundary.")

    def handle_decl(self, decl: str) -> None:
        if decl.strip().lower() != "doctype html":
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Only the ordinary HTML doctype is covered by this tokenizer contract.")

    def handle_pi(self, data: str) -> None:
        self.gap("NAMESPACE_HTML_TEMPLATE_UNRESOLVED", "Processing instructions may generate additional source interfaces.")

    def unknown_decl(self, data: str) -> None:
        self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "An unknown markup declaration is not evidence of absent interfaces.")

    def finish(self) -> None:
        self.feed(self.source)
        self.close()
        if self.stack or self.script is not None:
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Unclosed source elements require explicit browser-recovery evidence.")
        template_syntax = self.path.lower().endswith(".in") or any(
            token in self.source for token in ("{{", "{%", "<%"))
        if template_syntax:
            declared = self.template_binding
            template_body = _TEMPLATE_DECLARATION.sub("", self.source)
            actual = sorted(set(_TEMPLATE_TOKEN.findall(template_body)))
            unsupported = any(token in template_body for token in ("{%", "<%")) \
                or "{{" in _TEMPLATE_TOKEN.sub("", template_body)
            if declared is None or declared["tokens"] != actual or unsupported:
                self.gap("NAMESPACE_HTML_TEMPLATE_UNRESOLVED", "Template expansion may add interfaces; bind current renderer bytes and the exact closed token grammar.")
            else:
                for index, token in enumerate(actual):
                    self.record("template-token:" + str(index) + ":" + token,
                                "HTMLTemplateToken", [], False, 1)
        if "\x00" in self.source:
            self.gap("NAMESPACE_HTML_PARSE_UNRESOLVED", "Null-character replacement is outside the supported source-token boundary.")
        for identity, address in self.pending_references:
            parsed = urlsplit(address)
            decoded = unquote(parsed.path)
            target = posixpath.normpath(posixpath.join(posixpath.dirname(self.path), decoded))
            if (self.has_base or not address or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
                    or decoded.startswith("/") or "\\" in decoded or "\x00" in decoded or target not in self.files):
                self.gap("NAMESPACE_HTML_EXTERNAL_CODE_UNRESOLVED", "The script address is not a unique selected repository-relative source; no resource is fetched.")
            else:
                self.references.append({"surface_id": identity, "target_path": target,
                    "target_source_digest": self.files[target], "scope": "DECLARED_RELATIVE_SOURCE_NOT_RUNTIME_FETCH"})


def discover(path: str, raw: bytes, files: dict[str, str]) -> dict[str, Any]:
    try:
        if len(raw) > MAX_AST_BYTES:
            raise ValueError("NAMESPACE_HTML_INPUT_CAPACITY")
        parser = _Census(path, raw.decode("utf-8-sig"), files)
        parser.finish()
    except (ValueError, RecursionError, AssertionError) as exc:
        return {"surfaces": [], "fragments": [], "references": [], "gaps": [{"path": path,
            "code": "NAMESPACE_HTML_PARSE_UNAVAILABLE", "reason": "Markup source unavailable within the parser contract: " + type(exc).__name__}]}
    return {"surfaces": parser.surfaces, "fragments": parser.fragments, "references": parser.references, "gaps": parser.gaps}


def bind_fragment(row: dict[str, Any], fragments: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Translate virtual parser coordinates back to the real selected source."""
    source = fragments.get(row["path"])
    if source is None:
        return row
    result = {**row, "path": source["path"]}
    if "surface_id" in row:
        # Character references can insert decoded newlines that never occurred
        # in the file. Handler diagnostics therefore anchor at the enclosing tag.
        decoded = source["mode"] != "raw-script"
        result.update(line=source["line"] if decoded else source["line"] + row["line"] - 1,
            location_scope="ENCLOSING_TAG" if decoded else "SOURCE_LINE",
            source_kinds=sorted(set(source["source_kinds"]) | set(row["source_kinds"])),
            unresolved_marker=source["unresolved_marker"] or row["unresolved_marker"])
    return result
