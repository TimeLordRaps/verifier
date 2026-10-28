"""Non-executing Scalable Vector Graphics (SVG) source discovery.

Verifier Standard (VSTD); Extensible Markup Language (XML); JavaScript Object
Notation (JSON). XML token identity is not a browser, animation or confinement
proof. Document type declarations and entities are refused, never fetched.
"""
from __future__ import annotations

import json
from pathlib import Path
import posixpath
import re
import sys
import pyexpat
from typing import Any
from urllib.parse import unquote, urlsplit
from xml.parsers import expat

from verifier.runtime.self_polish_estate import MAX_AST_BYTES, bytes_digest


SVG = "http://www.w3.org/2000/svg"
XLINK = "http://www.w3.org/1999/xlink"
XML = "http://www.w3.org/XML/1998/namespace"


def mechanism() -> dict[str, Any]:
    """Bind the selected standard-library wrapper and actual parser binary."""
    return {"python": sys.version, "expat": expat.EXPAT_VERSION,
            "files": {
                "xml.parsers.expat": bytes_digest(Path(expat.__file__).read_bytes()),
                "pyexpat": bytes_digest(Path(pyexpat.__file__).read_bytes()),
            }}


def recapture(expected: dict[str, Any] | None) -> None:
    if expected is not None and mechanism() != expected:
        raise ValueError("NAMESPACE_SVG_MECHANISM_CHANGED")


def next_action(code: str, path: str) -> str:
    return "Bind the SVG source interpretation, referenced resources and any generated interfaces; source tokens do not prove rendering or execution. Source: " + path


class _Census:
    def __init__(self, path: str, files: dict[str, str]) -> None:
        self.path, self.files = path, files
        self.surfaces: list[dict[str, Any]] = []
        self.gaps: list[dict[str, str]] = []
        self.fragments: list[dict[str, Any]] = []
        self.references: list[dict[str, str]] = []
        self.pending: list[tuple[str, str]] = []
        self.namespaces: list[tuple[str | None, str | None]] = []
        self.stack: list[dict[str, Any]] = []
        self.has_base = False
        self.ordinal = 0
        self.parser = expat.ParserCreate(namespace_separator="\x1f")
        self.parser.StartElementHandler = self.start
        self.parser.StartNamespaceDeclHandler = self.namespace
        self.parser.EndElementHandler = self.end
        self.parser.CharacterDataHandler = self.data
        self.parser.StartDoctypeDeclHandler = self.refuse_entities
        self.parser.EntityDeclHandler = self.refuse_entities
        self.parser.ExternalEntityRefHandler = self.refuse_entities
        self.parser.ProcessingInstructionHandler = self.instruction
        self.parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        self.record("document", "SVGDocument", [], False, 1)

    @staticmethod
    def refuse_entities(*args: Any) -> None:
        raise ValueError("Document type declarations and entities require a separate source contract.")

    def gap(self, code: str, reason: str) -> None:
        if not any(row["code"] == code for row in self.gaps):
            self.gaps.append({"path": self.path, "code": code, "reason": reason})

    def record(self, suffix: str, form: str, kinds: list[str], unresolved: bool, line: int) -> str:
        if len(self.surfaces) >= 250_000:
            raise ValueError("SVG surface capacity exceeded")
        identity = "svg:" + self.path + ":" + suffix
        self.surfaces.append({"surface_id": identity, "path": self.path, "line": line, "form": form,
            "source_kinds": kinds, "hints": [], "unresolved_marker": unresolved})
        return identity

    def fragment(self, identity: str, value: str, kinds: list[str], unresolved: bool, line: int) -> None:
        self.fragments.append({"key": "svg-fragment:" + identity, "surface_id": identity,
            "path": self.path, "line": line, "mode": "decoded-svg", "source": value.encode("utf-8"),
            "source_kinds": kinds, "unresolved_marker": unresolved})

    def namespace(self, prefix: str | None, uri: str | None) -> None:
        self.namespaces.append((prefix, uri))

    def start(self, expanded: str, attrs: dict[str, str]) -> None:
        namespace, _, name = expanded.rpartition("\x1f")
        line = self.parser.CurrentLineNumber
        self.ordinal += 1
        inherited = self.stack[-1] if self.stack else {"kinds": [], "unresolved": False}
        kinds, unresolved = set(inherited["kinds"]), inherited["unresolved"]
        if "data-vstd-kinds" in attrs:
            try:
                values = json.loads(attrs["data-vstd-kinds"])
                if not isinstance(values, list) or not values or any(not isinstance(value, str)
                        or re.fullmatch(r"[A-Z][A-Z0-9]{0,63}", value) is None for value in values):
                    unresolved = True
                else:
                    kinds.update(values)
            except ValueError:
                unresolved = True
        labels = sorted(kinds)
        # Keep public identities readable; the parser's private namespace
        # separator must not leak as an invisible character in a gate argument.
        qualified = "{" + namespace + "}" + name if namespace else name
        suffix = "element:" + str(self.ordinal) + ":" + qualified
        identity = self.record(suffix, "SVGElement", labels, unresolved, line)
        for index, (prefix, _) in enumerate(self.namespaces):
            self.record(suffix + ":namespace:" + str(index) + ":" + (prefix or "default"),
                        "SVGNamespace", labels, unresolved, line)
        self.namespaces.clear()
        if namespace != SVG or (not self.stack and name != "svg"):
            self.gap("NAMESPACE_SVG_CONTEXT_UNRESOLVED", "Foreign or non-SVG document context needs its own interpreter.")
        if any(row["script"] or row["style"] for row in self.stack):
            self.gap("NAMESPACE_SVG_CONTEXT_UNRESOLVED", "Nested markup changes script/style text construction; partial text is not complete code coverage.")
        for index, (attribute, value) in enumerate(attrs.items()):
            uri, _, local = attribute.rpartition("\x1f")
            readable = "{" + uri + "}" + local if uri else local
            self.record(suffix + ":attribute:" + str(index) + ":" + readable, "SVGAttribute", labels, unresolved, line)
            if attribute.startswith("on"):
                handler = self.record(suffix + ":handler:" + attribute, "SVGHandler", labels, unresolved, line)
                if value.strip():
                    self.fragment(handler, value, labels, unresolved, line)
            if attribute == XML + "\x1fbase":
                self.has_base = True
                self.gap("NAMESPACE_SVG_RESOURCE_UNRESOLVED", "An XML base address changes resource resolution.")
            if attribute in {"href", XLINK + "\x1fhref"}:
                if name == "script":
                    self.pending.append((identity, value))
                else:
                    self.gap("NAMESPACE_SVG_RESOURCE_UNRESOLVED", "Referenced or instantiated content requires a separately bound resource/instance contract.")
            if "{{" in value or "${{" in value:
                self.gap("NAMESPACE_SVG_TEMPLATE_UNRESOLVED", "Attribute expansion requires generated-source evidence.")
            if attribute == "style" and re.search(r"url\s*\(|@import|expression\s*\(", value, re.I):
                self.gap("NAMESPACE_SVG_STYLE_UNRESOLVED", "Style resources or executable constructs require separate interpretation.")
        if name in {"foreignObject", "animate", "animateMotion", "animateTransform", "set", "use"}:
            self.gap("NAMESPACE_SVG_CONTEXT_UNRESOLVED", "Foreign content, animation or instantiated nodes are not static source-token coverage.")
        state = {"name": name, "kinds": labels, "unresolved": unresolved, "line": line,
                 "script": None, "parts": [], "style": name == "style"}
        if name == "script":
            state["script"] = self.record("script:" + str(self.ordinal), "SVGScript", labels, unresolved, line)
            if attrs.get("type", "").strip().lower() not in {"", "text/javascript", "application/javascript", "module"}:
                self.gap("NAMESPACE_SVG_SCRIPT_TYPE_UNSUPPORTED", "The declared script type requires another source parser.")
                state["script"] = None
        self.stack.append(state)
        if len(self.stack) > 256:
            raise ValueError("SVG nesting capacity exceeded")

    def data(self, text: str) -> None:
        if self.stack:
            self.stack[-1]["parts"].append(text)

    def end(self, expanded: str) -> None:
        state = self.stack.pop()
        source = "".join(state["parts"])
        if state["script"] and source.strip():
            self.fragment(state["script"], source, state["kinds"], state["unresolved"], state["line"])
        if state["style"] and re.search(r"url\s*\(|@import|expression\s*\(", source, re.I):
            self.gap("NAMESPACE_SVG_STYLE_UNRESOLVED", "Style resources require separate interpretation.")
        if "{{" in source or "<%" in source:
            self.gap("NAMESPACE_SVG_TEMPLATE_UNRESOLVED", "Template expansion requires generated-source evidence.")

    def instruction(self, target: str, data: str) -> None:
        self.gap("NAMESPACE_SVG_INSTRUCTION_UNRESOLVED", "Processing instructions may select external styles or transform the document.")

    def finish(self, raw: bytes) -> None:
        self.parser.Parse(raw, True)
        for identity, address in self.pending:
            parsed = urlsplit(address)
            decoded = unquote(parsed.path)
            target = posixpath.normpath(posixpath.join(posixpath.dirname(self.path), decoded))
            if (self.has_base or not address or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
                    or decoded.startswith("/") or "\\" in decoded or "\x00" in decoded or target not in self.files):
                self.gap("NAMESPACE_SVG_RESOURCE_UNRESOLVED", "A script reference is not a unique selected relative source; no resource is fetched.")
            else:
                self.references.append({"surface_id": identity, "target_path": target,
                    "target_source_digest": self.files[target], "scope": "DECLARED_RELATIVE_SOURCE_NOT_RUNTIME_FETCH"})


def discover(path: str, raw: bytes, files: dict[str, str]) -> dict[str, Any]:
    try:
        if len(raw) > MAX_AST_BYTES:
            raise ValueError("SVG input capacity exceeded")
        parser = _Census(path, files)
        parser.finish(raw)
    except (expat.ExpatError, ValueError, RecursionError) as exc:
        return {"surfaces": [], "fragments": [], "references": [], "gaps": [{"path": path,
            "code": "NAMESPACE_SVG_PARSE_UNAVAILABLE", "reason": "SVG source interpretation unavailable: " + type(exc).__name__}]}
    return {"surfaces": parser.surfaces, "fragments": parser.fragments,
            "references": parser.references, "gaps": parser.gaps}
