"""Authored explanation definitions and bounded, preparation-only projections.

Terminology: abstract syntax tree (AST); identifier (ID); JavaScript Object
Notation (JSON); pull request (PR); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8).

This module preserves authored intent as authored intent. Comment projection
does not establish implementation correspondence, execution, author identity,
requirement authority, or any numbered-profile conformance. Candidate source is
parsed as data and is never imported or executed. Callers receive staged bytes;
this module never writes their source. Commit observations are path-scoped Git
history observations, not authenticated authorship or independently witnessed
precommit timing. PR associations are never guessed.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import textwrap
import time
import tokenize
from typing import Any

DEFINITION_SCHEMA = "verifier-explanation-definitions-1"
PROJECTION_SCHEMA = "verifier-explanation-projection-1"
PROVENANCE_SCHEMA = "verifier-explanation-provenance-1"
MAX_DEFINITION_BYTES = 1024 * 1024
MAX_DEFINITIONS = 1000
MAX_TEXT_CHARS = 8192
MAX_LIST_ITEMS = 128
MAX_SOURCE_FILES = 10000
MAX_SOURCE_FILE_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_AST_NODES = 50000
MAX_HISTORY_COMMITS = 256
MAX_GIT_BYTES = 2 * 1024 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_PROVENANCE_SECONDS = 30
ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_MARKER = re.compile(r"# vstd-explanation: (begin|end) (" + ID_PATTERN + r")\Z")


class DefinitionError(ValueError):
    """A known structural obligation of definitions or managed comments failed."""


class ProjectionUnavailable(ValueError):
    """An observation or supported interpretation is unavailable within bounds."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DefinitionError("duplicate JSON field")
        result[key] = value
    return result


def _path(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or any(
            ord(char) < 32
            or ord(char) == 127
            or char in '\\<>:"|?*\u0085\u2028\u2029'
            or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        )
    ):
        raise DefinitionError("target path must be a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise DefinitionError("target path must not traverse or normalize components")
    for part in path.parts:
        if part.endswith((" ", ".")) or part.split(".")[0].upper() in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *["COM" + str(n) for n in range(1, 10)],
            *["LPT" + str(n) for n in range(1, 10)],
        }:
            raise DefinitionError("target path contains a nonportable component")
    return value


def _text(value: Any, *, limit: int = MAX_TEXT_CHARS, empty: bool = True) -> str:
    if (
        type(value) is not str
        or len(value) > limit
        or (not empty and not value.strip())
        or any(
            (ord(char) < 32 and char not in "\n\r\t")
            or ord(char) == 127
            or char in "\u0085\u2028\u2029"
            or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        )
    ):
        raise DefinitionError("authored text is invalid or exceeds its bound")
    return value


def _validate(value: Any) -> dict[str, Any]:
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "definitions"}
        or value["schema_version"] != DEFINITION_SCHEMA
        or type(value["definitions"]) is not list
        or len(value["definitions"]) > MAX_DEFINITIONS
    ):
        raise DefinitionError("invalid canonical explanation definition contract")
    seen_ids: set[str] = set()
    seen_targets: set[tuple[str, str | None]] = set()
    text_chars = 0
    for row in value["definitions"]:
        if type(row) is not dict or set(row) != {
            "id",
            "target",
            "intent",
            "requirement_ids",
            "invariants",
            "limits",
        }:
            raise DefinitionError(
                "definition fields must exactly match the selected version"
            )
        target = row["target"]
        if type(target) is not dict or set(target) != {"path", "symbol"}:
            raise DefinitionError("invalid explanation target")
        texts = [row["id"], row["intent"], target["path"]]
        if target["symbol"] is not None:
            texts.append(target["symbol"])
        for name in ("requirement_ids", "invariants", "limits"):
            items = row[name]
            if type(items) is not list or len(items) > MAX_LIST_ITEMS:
                raise DefinitionError("authored list exceeds its structural bound")
            texts.extend(items)
        if any(type(item) is not str for item in texts):
            raise DefinitionError("authored definition fields must contain strings")
        # Direct dictionary callers have no prior byte envelope. Refuse excessive
        # text before scanning characters or allocating the complete JSON bytes.
        text_chars += sum(len(item) for item in texts)
        if text_chars > MAX_DEFINITION_BYTES:
            raise DefinitionError("canonical definition byte bound exceeded")
        definition_id = row["id"]
        if type(definition_id) is not str or not re.fullmatch(
            ID_PATTERN, definition_id
        ):
            raise DefinitionError("invalid stable explanation identifier")
        if definition_id in seen_ids:
            raise DefinitionError("duplicate explanation identifier")
        seen_ids.add(definition_id)
        path = _path(target["path"])
        symbol = target["symbol"]
        if symbol is not None and (
            type(symbol) is not str
            or len(symbol) > 512
            or not all(part.isidentifier() for part in symbol.split("."))
        ):
            raise DefinitionError(
                "symbol must be a dotted lexical declaration name or null"
            )
        key = (path.casefold(), symbol)
        if key in seen_targets:
            raise DefinitionError("duplicate or nonportable explanation target")
        seen_targets.add(key)
        _text(row["intent"])
        for name in ("requirement_ids", "invariants", "limits"):
            items = row[name]
            for item in items:
                _text(
                    item,
                    limit=128 if name == "requirement_ids" else MAX_TEXT_CHARS,
                    empty=False,
                )
                if name == "requirement_ids" and not re.fullmatch(ID_PATTERN, item):
                    raise DefinitionError("invalid selected requirement identifier")
            if len(set(items)) != len(items):
                raise DefinitionError("duplicate authored list item")
    return value


def load_definitions(raw: bytes) -> dict[str, Any]:
    """Decode the exact definitions version; malformed/duplicate fields raise
    ValueError."""
    if type(raw) is not bytes or len(raw) > MAX_DEFINITION_BYTES:
        raise DefinitionError("definition byte bound exceeded")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                DefinitionError("nonfinite JSON")
            ),
        )
        _validate(value)
        if len(_canonical(value)) > MAX_DEFINITION_BYTES:
            raise DefinitionError("canonical definition byte bound exceeded")
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DefinitionError("definitions are not bounded UTF-8 JSON") from exc
    return value


def canonical_definitions(definitions: dict[str, Any]) -> bytes:
    """Return strictly validated compact bytes; array order remains authored input."""
    try:
        raw = _canonical(_validate(definitions))
    except (TypeError, UnicodeError, RecursionError) as exc:
        raise DefinitionError("definitions are not canonically encodable") from exc
    if len(raw) > MAX_DEFINITION_BYTES:
        raise DefinitionError("canonical definition byte bound exceeded")
    return raw


def _inventory(files: dict[str, bytes]) -> str:
    return _sha(
        _canonical(
            [{"path": path, "sha256": _sha(raw)} for path, raw in sorted(files.items())]
        )
    )


def _finding(
    code: str,
    message: str,
    *,
    status: str = "FAIL",
    path: str | None = None,
    definition_id: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "status": status,
        "path": path,
        "definition_id": definition_id,
        "message": message,
    }


def _decode_source(raw: bytes) -> tuple[str, str, str]:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (UnicodeError, SyntaxError) as exc:
        raise ProjectionUnavailable(
            "Python source encoding cannot be interpreted"
        ) from exc
    newline_kinds = set(re.findall(r"\r\n|(?<!\r)\n|\r(?!\n)", text))
    if "\r" in newline_kinds or len(newline_kinds) > 1:
        raise ProjectionUnavailable("mixed or unsupported source newline conventions")
    return text, encoding, next(iter(newline_kinds), "\n")


def _blocks(text: str) -> list[tuple[int, int, str]]:
    """Recognize markers only as actual standalone comments, never quoted strings."""
    lines = text.splitlines(keepends=True)
    markers: list[tuple[int, str, str, str]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.COMMENT or not token.string.startswith(
                "# vstd-explanation:"
            ):
                continue
            match = _MARKER.fullmatch(token.string)
            if not match or lines[token.start[0] - 1][: token.start[1]].strip():
                raise DefinitionError(
                    "managed marker must be an exact standalone comment"
                )
            markers.append(
                (
                    token.start[0] - 1,
                    match[1],
                    match[2],
                    lines[token.start[0] - 1][: token.start[1]],
                )
            )
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        raise ProjectionUnavailable("Python tokenization is unresolved") from exc
    blocks: list[tuple[int, int, str]] = []
    current: tuple[int, str, str] | None = None
    seen: set[str] = set()
    for line, kind, definition_id, indent in markers:
        if kind == "begin":
            if current is not None or definition_id in seen:
                raise DefinitionError("nested or duplicate managed explanation block")
            current = (line, definition_id, indent)
        elif current is None or current[1:] != (definition_id, indent):
            raise DefinitionError("dangling or mismatched managed explanation marker")
        else:
            start, _, _ = current
            if any(
                content.strip() and not content.lstrip().startswith("#")
                for content in lines[start + 1 : line]
            ):
                raise DefinitionError(
                    "managed explanation block contains executable source"
                )
            blocks.append((start, line + 1, definition_id))
            seen.add(definition_id)
            current = None
    if current is not None:
        raise DefinitionError("dangling managed explanation begin marker")
    return blocks


def _anchors(tree: ast.Module, lines: list[str]) -> dict[str, list[tuple[int, str]]]:
    anchors: dict[str, list[tuple[int, str]]] = {}
    pending: list[tuple[ast.AST, str]] = [(tree, "")]
    visited = 0
    while pending:
        node, prefix = pending.pop()
        visited += 1
        if visited > MAX_AST_NODES:
            raise ProjectionUnavailable("Python declaration node-count bound exceeded")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = prefix + node.name
            line = (
                min(
                    [
                        node.lineno,
                        *[decorator.lineno for decorator in node.decorator_list],
                    ]
                )
                - 1
            )
            indent = lines[line][: len(lines[line]) - len(lines[line].lstrip(" \t"))]
            anchors.setdefault(symbol, []).append((line, indent))
            pending.extend((child, symbol + ".") for child in reversed(node.body))
        else:
            # Exception handlers and conditional scopes do not introduce lexical
            # namespaces.
            pending.extend(
                (child, prefix) for child in reversed(list(ast.iter_child_nodes(node)))
            )
    return anchors


def _module_anchor(lines: list[str]) -> int:
    anchor = 1 if lines and lines[0].startswith("#!") else 0
    cookie = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*[-\w.]+")
    for index, line in enumerate(lines[:2]):
        if cookie.match(line):
            anchor = max(anchor, index + 1)
    return anchor


def _authored_lines(row: dict[str, Any]) -> list[str]:
    lines = ["Authored intent (not verified):"]
    lines += ["  " + line for line in row["intent"].splitlines()] or [
        "  (not supplied)"
    ]
    if row["requirement_ids"]:
        lines.append("Requirements: " + ", ".join(row["requirement_ids"]))
    for label, key in (
        ("Invariant (authored)", "invariants"),
        ("Limit (authored)", "limits"),
    ):
        for value in row[key]:
            parts = value.splitlines()
            lines.append(label + ": " + parts[0])
            lines.extend("  " + part for part in parts[1:])
    return lines


def _comment(row: dict[str, Any], indent: str, newline: str) -> str:
    authored = []
    for line in _authored_lines(row):
        authored.extend(
            textwrap.wrap(
                line,
                width=max(20, 86 - len(indent)),
                break_long_words=False,
                break_on_hyphens=False,
                replace_whitespace=False,
            )
            or [line]
        )
    parts = [
        "vstd-explanation: begin " + row["id"],
        *authored,
        "vstd-explanation: end " + row["id"],
    ]
    return "".join(indent + "# " + part + newline for part in parts)


# vstd-explanation: begin prdel.self.explanation-projection
# Authored intent (not verified):
#   Project canonical authored intent into only explicitly managed comment blocks.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): Authored explanations do not prove implementation correspondence or
# historical authorship.
# vstd-explanation: end prdel.self.explanation-projection
def project_comments(
    files: dict[str, bytes], definitions: dict[str, Any]
) -> dict[str, Any]:
    """Stage an atomic Python-comment projection; PASS is preparation, not clearance.

    Lexical dotted symbols select function/class declarations, including nested
    declarations. Null selects the module. Missing targets fail; unsupported
    languages, parsing and ambiguous declarations remain UNKNOWN. Handwritten
    regions are retained byte-for-byte; existing managed blocks must occupy their
    declared anchor. On any FAIL/UNKNOWN, returned files equal the original files.
    """
    findings: list[dict[str, Any]] = []
    original = dict(files)
    definition_digest: str | None = None
    try:
        definition_digest = _sha(canonical_definitions(definitions))
        if len(files) > MAX_SOURCE_FILES:
            raise ProjectionUnavailable("source file-count bound exceeded")
        seen_paths: set[str] = set()
        for path, raw in files.items():
            _path(path)
            if path.casefold() in seen_paths or type(raw) is not bytes:
                raise DefinitionError(
                    "source inventory contains colliding paths or nonbytes"
                )
            seen_paths.add(path.casefold())
        if sum(len(raw) for raw in files.values()) > MAX_SOURCE_BYTES:
            raise ProjectionUnavailable("source byte bound exceeded")
    except (DefinitionError, ProjectionUnavailable) as exc:
        findings.append(
            _finding(
                "INVALID_PROJECTION_INPUT",
                str(exc),
                status="UNKNOWN" if isinstance(exc, ProjectionUnavailable) else "FAIL",
            )
        )
    staged = dict(original)
    changes: list[dict[str, Any]] = []
    if not findings:
        rows = {row["id"]: row for row in definitions["definitions"]}
        by_path: dict[str, list[dict[str, Any]]] = {}
        for row in rows.values():
            by_path.setdefault(row["target"]["path"], []).append(row)
        # Marker text in unselected prose/code examples is not a Python comment.
        # Explicit non-Python targets still remain unsupported below.
        for path in sorted(
            set(by_path)
            | {
                path
                for path, raw in files.items()
                if path.endswith(".py") and b"# vstd-explanation:" in raw
            }
        ):
            try:
                if path not in files:
                    raise DefinitionError("required explanation target file is missing")
                if not path.endswith(".py"):
                    raise ProjectionUnavailable(
                        "comment projection currently supports Python only"
                    )
                raw = files[path]
                if len(raw) > MAX_SOURCE_FILE_BYTES:
                    raise ProjectionUnavailable(
                        "selected Python source byte bound exceeded"
                    )
                text, encoding, newline = _decode_source(raw)
                blocks = _blocks(text)
                lines = text.splitlines(keepends=True)
                removed = 0
                previous: dict[str, int] = {}
                clean: list[str] = []
                cursor = 0
                for start, end, definition_id in blocks:
                    if (
                        definition_id not in rows
                        or rows[definition_id]["target"]["path"] != path
                    ):
                        raise DefinitionError(
                            "managed block has no matching canonical definition target"
                        )
                    previous[definition_id] = start - removed
                    clean.extend(lines[cursor:start])
                    removed += end - start
                    cursor = end
                clean.extend(lines[cursor:])
                clean_text = "".join(clean)
                try:
                    tree = ast.parse(clean_text)
                except (SyntaxError, ValueError, RecursionError) as exc:
                    raise ProjectionUnavailable(
                        "Python declaration parsing is unresolved"
                    ) from exc
                anchors = _anchors(tree, clean)
                insertions: dict[int, list[str]] = {}
                for row in sorted(by_path.get(path, []), key=lambda item: item["id"]):
                    symbol = row["target"]["symbol"]
                    if symbol is None:
                        line, indent = _module_anchor(clean), ""
                    else:
                        matches = anchors.get(symbol, [])
                        if not matches:
                            raise DefinitionError(
                                "required lexical declaration target is missing"
                            )
                        if len(matches) != 1:
                            raise ProjectionUnavailable(
                                "lexical declaration target is ambiguous"
                            )
                        line, indent = matches[0]
                    if row["id"] in previous and previous[row["id"]] != line:
                        raise DefinitionError(
                            "managed block is stale or moved from its declared target"
                        )
                    insertions.setdefault(line, []).append(
                        _comment(row, indent, newline)
                    )
                projected = "".join(
                    "".join(insertions.get(index, [])) + line
                    for index, line in enumerate(clean)
                )
                projected += "".join(insertions.get(len(clean), []))
                try:
                    result_raw = projected.encode(encoding)
                except UnicodeError as exc:
                    raise ProjectionUnavailable(
                        "authored comment is not representable in source encoding"
                    ) from exc
                if len(result_raw) > MAX_SOURCE_FILE_BYTES:
                    raise ProjectionUnavailable(
                        "projected Python source byte bound exceeded"
                    )
                staged[path] = result_raw
                if result_raw != raw:
                    changes.append(
                        {
                            "path": path,
                            "before_sha256": _sha(raw),
                            "after_sha256": _sha(result_raw),
                            "definition_ids": sorted(
                                row["id"] for row in by_path.get(path, [])
                            ),
                        }
                    )
            except (DefinitionError, ProjectionUnavailable) as exc:
                findings.append(
                    _finding(
                        "COMMENT_PROJECTION_BLOCKED",
                        str(exc),
                        path=path,
                        status=(
                            "UNKNOWN"
                            if isinstance(exc, ProjectionUnavailable)
                            else "FAIL"
                        ),
                    )
                )
    if findings:
        staged, changes = original, []
    status = (
        "FAIL"
        if any(row["status"] == "FAIL" for row in findings)
        else "UNKNOWN" if findings else "PASS"
    )
    try:
        if (
            len(original) > MAX_SOURCE_FILES
            or sum(len(raw) for raw in original.values()) > MAX_SOURCE_BYTES
        ):
            raise TypeError("inventory bound exceeded")
        before_digest, after_digest = _inventory(original), _inventory(staged)
    except (TypeError, UnicodeError, AttributeError):
        before_digest, after_digest = None, None
    return {
        "schema_version": PROJECTION_SCHEMA,
        "status": status,
        "scope": "COMMENT_PROJECTION_ONLY",
        "authored_status": "AUTHORED_NOT_PROVED",
        "definition_digest": definition_digest,
        "files": staged,
        "changes": changes,
        "source_before": before_digest,
        "source_after": after_digest,
        "findings": findings,
    }


def render_authored_intent(definitions: dict[str, Any]) -> str:
    """Render inert readable authored content separately from checked PR claims."""
    canonical_definitions(definitions)
    lines = ["Authored explanations (intent and invariants are not verified):", ""]
    for row in sorted(definitions["definitions"], key=lambda item: item["id"]):
        # JSON quotation makes authored fences/links/markup inert rather than executable
        # markup.
        def quoted(value: str) -> str:
            return json.dumps(value, ensure_ascii=True)

        lines.append(
            "    Explanation "
            + quoted(row["id"])
            + " for "
            + quoted(row["target"]["path"])
            + (
                " module"
                if row["target"]["symbol"] is None
                else " symbol " + quoted(row["target"]["symbol"])
            )
        )
        lines.extend(
            "    " + line
            for line in _authored_lines(
                {
                    **row,
                    "intent": quoted(row["intent"]),
                    "invariants": [quoted(value) for value in row["invariants"]],
                    "limits": [quoted(value) for value in row["limits"]],
                }
            )
        )
        lines.append("")
    return "\n".join(lines) + "\n"


def _git(root: Path, *args: str, deadline: float | None = None) -> bytes:
    remaining = (
        MAX_PROVENANCE_SECONDS if deadline is None else deadline - time.monotonic()
    )
    if remaining <= 0:
        raise ProjectionUnavailable("Git observation duration bound exceeded")
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                ["git", "--no-replace-objects", "-C", str(root), *args],
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=min(30, remaining),
                check=False,
            )
            if output.tell() > MAX_GIT_BYTES:
                raise ProjectionUnavailable("Git observation byte bound exceeded")
            output.seek(0)
            raw = output.read(MAX_GIT_BYTES + 1)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProjectionUnavailable("Git observation unavailable within bound") from exc
    if result.returncode:
        raise ProjectionUnavailable("selected Git observation unavailable")
    return raw


def _blob(
    root: Path, head: str, path: str, *, deadline: float | None = None
) -> bytes | None:
    entries = [
        entry
        for entry in _git(
            root, "ls-tree", "-z", head, "--", path, deadline=deadline
        ).split(b"\0")
        if entry
    ]
    if not entries:
        return None
    if len(entries) != 1:
        raise ProjectionUnavailable("definition path Git object is ambiguous")
    metadata, separator, raw_path = entries[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or raw_path != path.encode("utf-8")
        or len(fields) != 3
        or fields[0] not in (b"100644", b"100755")
        or fields[1] != b"blob"
    ):
        raise ProjectionUnavailable("definition path is not an exact regular Git blob")
    raw = _git(root, "cat-file", "blob", fields[2].decode("ascii"), deadline=deadline)
    if len(raw) > MAX_DEFINITION_BYTES:
        raise ProjectionUnavailable("historical definition byte bound exceeded")
    return raw


def resolve_definition_provenance(
    root: Path, head: str, definition_path: str
) -> dict[str, Any]:
    """Observe bounded linear, path-scoped introducing/edit commits without writes.

    The exact full commit identifier is required. Differing/untracked workspace
    bytes are PENDING_COMMIT, not associated with a future commit. Renames and
    merges are not inferred; incomplete/unsupported history remains UNKNOWN.
    Introduction means first retained occurrence of this ID at this selected path,
    not original authorship anywhere else. A later caller must revalidate all
    carried definition/head bindings before relying on this observation.
    """
    report: dict[str, Any] = {
        "schema_version": PROVENANCE_SCHEMA,
        "status": "UNKNOWN",
        "scope": "BOUNDED_PATH_OCCURRENCE_HISTORY",
        "head": head,
        "definition_path": definition_path,
        "definition_digest": None,
        "workspace_sha256": None,
        "committed_sha256": None,
        "commit_status": "UNRESOLVED",
        "definitions": [],
        "findings": [],
        "pr_associations": [],
        "limits": [
            (
                "No authorship, occurrence authenticity or "
                "independently witnessed timing is established."
            ),
            "Earlier renamed paths and PR associations are not inferred.",
        ],
    }
    try:
        deadline = time.monotonic() + MAX_PROVENANCE_SECONDS
        _path(definition_path)
        if type(head) is not str or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head
        ):
            raise DefinitionError(
                "provenance requires an exact full selected commit identifier"
            )
        root = Path(root).resolve()
        selected = root.joinpath(*PurePosixPath(definition_path).parts)
        if not selected.resolve().is_relative_to(root):
            raise DefinitionError("definition workspace path escapes the selected root")
        try:
            with selected.open("rb") as stream:
                workspace = stream.read(MAX_DEFINITION_BYTES + 1)
        except FileNotFoundError as exc:
            raise DefinitionError("required workspace definitions are missing") from exc
        except OSError as exc:
            raise ProjectionUnavailable(
                "workspace definitions cannot be observed"
            ) from exc
        definitions = load_definitions(workspace)
        report["definition_digest"] = _sha(canonical_definitions(definitions))
        report["workspace_sha256"] = _sha(workspace)
        resolved = (
            _git(
                root,
                "rev-parse",
                "--verify",
                "--end-of-options",
                head + "^{commit}",
                deadline=deadline,
            )
            .decode()
            .strip()
        )
        if resolved != head:
            raise DefinitionError(
                "selected commit observation contradicts its exact identifier"
            )
        committed = _blob(root, head, definition_path, deadline=deadline)
        report["committed_sha256"] = _sha(committed) if committed is not None else None
        if workspace != committed:
            report.update(status="UNKNOWN", commit_status="PENDING_COMMIT")
            report["definitions"] = [
                {
                    "id": row["id"],
                    "status": "PENDING_COMMIT",
                    "definition_sha256": _sha(_canonical(row)),
                    "introduced_commit": None,
                    "last_edit_commit": None,
                }
                for row in sorted(
                    definitions["definitions"], key=lambda item: item["id"]
                )
            ]
            return report
        if (
            _git(
                root, "rev-parse", "--is-shallow-repository", deadline=deadline
            ).strip()
            != b"false"
        ):
            raise ProjectionUnavailable(
                "shallow definition history cannot establish introduction"
            )
        history = (
            _git(
                root,
                "log",
                "--full-history",
                "--topo-order",
                "--format=%H %P",
                "--max-count=" + str(MAX_HISTORY_COMMITS + 1),
                head,
                "--",
                definition_path,
                deadline=deadline,
            )
            .decode("ascii")
            .splitlines()
        )
        if len(history) > MAX_HISTORY_COMMITS:
            raise ProjectionUnavailable(
                "definition history commit-count bound exceeded"
            )
        observed: dict[str, dict[str, Any]] = {}
        previous: dict[str, str] = {}
        history_bytes = 0
        for line in reversed(history):
            commits = line.split()
            if not commits or any(
                not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", item)
                for item in commits
            ):
                raise ProjectionUnavailable(
                    "Git history identifiers cannot be interpreted"
                )
            if len(commits) > 2:
                raise ProjectionUnavailable(
                    "merged definition history requires an independent lineage policy"
                )
            commit = commits[0]
            commit_bytes = _git(root, "cat-file", "commit", commit, deadline=deadline)
            parents = [
                row[7:].decode("ascii")
                for row in commit_bytes.split(b"\n\n", 1)[0].splitlines()
                if row.startswith(b"parent ")
            ]
            if parents != commits[1:]:
                raise ProjectionUnavailable(
                    "Git history parents differ from retained commit object parents"
                )
            raw = _blob(root, commit, definition_path, deadline=deadline)
            history_bytes += len(commit_bytes) + (len(raw) if raw is not None else 0)
            if history_bytes > MAX_HISTORY_BYTES:
                raise ProjectionUnavailable(
                    "definition history total-byte bound exceeded"
                )
            current = (
                {}
                if raw is None
                else {
                    row["id"]: _sha(_canonical(row))
                    for row in load_definitions(raw)["definitions"]
                }
            )
            for definition_id, row_digest in current.items():
                if definition_id not in previous:
                    if definition_id in observed:
                        observed[definition_id].update(
                            last_edit_commit=commit, definition_sha256=row_digest
                        )
                    else:
                        observed[definition_id] = {
                            "id": definition_id,
                            "status": "OBSERVED_COMMIT_HISTORY",
                            "definition_sha256": row_digest,
                            "introduced_commit": commit,
                            "last_edit_commit": commit,
                        }
                elif previous[definition_id] != row_digest:
                    observed[definition_id].update(
                        last_edit_commit=commit, definition_sha256=row_digest
                    )
            previous = current
        for row in definitions["definitions"]:
            if row["id"] not in observed or observed[row["id"]][
                "definition_sha256"
            ] != _sha(_canonical(row)):
                raise DefinitionError(
                    "current definition does not match the observed committed lineage"
                )
        report.update(
            status="PASS",
            commit_status="COMMITTED_BYTES_OBSERVED",
            definitions=[
                observed[row["id"]]
                for row in sorted(
                    definitions["definitions"], key=lambda item: item["id"]
                )
            ],
        )
    except (
        DefinitionError,
        ProjectionUnavailable,
        UnicodeError,
        RecursionError,
    ) as exc:
        status = "FAIL" if isinstance(exc, DefinitionError) else "UNKNOWN"
        report["status"] = status
        report["findings"].append(
            _finding(
                "DEFINITION_PROVENANCE_BLOCKED",
                str(exc),
                status=status,
                path=definition_path,
            )
        )
    return report
