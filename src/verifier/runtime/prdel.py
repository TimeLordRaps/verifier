"""Pull Request Domain Explanation Language (PRDEL), proposed version one.

Terminology: abstract syntax tree (AST); command-line interface (CLI); identifier
(ID); JavaScript Object Notation (JSON); pull request (PR); strongly connected
component (SCC); Secure Hash Algorithm
256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).

The predicates below establish exact retained source changes and selected quotes.
They do not interpret arbitrary prose, authenticate test execution, establish
requirement authority, or certify complete runtime or release correctness.
Candidate source is data: it is never imported or executed by this module.
"""

from __future__ import annotations

import ast
from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import Any

SCHEMA = "verifier-prdel-1"
REPORT_SCHEMA = "verifier-prdel-report-1"
SCHEMA_V2 = "verifier-prdel-2"
REPORT_SCHEMA_V2 = "verifier-prdel-report-2"
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_DESCRIPTION_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_V2_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_V2_FILE_BYTES = 32 * 1024 * 1024
MAX_INLINE_SOURCE_BYTES = 512 * 1024
MAX_FILES = 10000
MAX_REGIONS = 10000
MAX_AST_SOURCE_BYTES = 512 * 1024
MAX_GIT_QUERY_BYTES = MAX_SNAPSHOT_BYTES + 16 * 1024 * 1024
MAX_V2_GIT_QUERY_BYTES = MAX_V2_SNAPSHOT_BYTES + 16 * 1024 * 1024
BOUNDARY = (
    "Exact commit source-region representation, selected "
    "requirement quotations and supported deterministic source "
    "predicates only. Arbitrary narrative meaning, execution "
    "provenance, complete objective coverage and runtime "
    "correctness remain separately unestablished. No workspace "
    "or publication clearance."
)
DEFAULT_REQUIREMENTS = {
    "schema_version": "verifier-prdel-requirements-1",
    "items": [
        {
            "id": "bounded-source-description",
            ("text"): (
                "Explain the exact retained changes without claiming "
                "runtime correctness or complete release "
                "qualification."
            ),
        }
    ],
}
LIMITS = {
    "NO_RUNTIME_CORRECTNESS": "Runtime correctness is not established.",
    "NO_EXECUTION_PROVENANCE": "Historical test execution is not authenticated.",
    "NO_REQUIREMENT_AUTHORITY": "Selected requirement authority is not established.",
    ("NO_COMPLETE_OBJECTIVE_CLOSURE"): (
        "Complete objective and release qualification is not " "established."
    ),
    ("EXACT_COMMIT_SCOPE"): (
        "Only the selected immutable commits are assessed; workspace "
        "clearance is not established."
    ),
}


class PrdelError(ValueError):
    """A bounded input or exact source coordinate could not be established."""


class PrdelUnavailable(PrdelError):
    """The declared source could not be observed; this is not a successful check."""


class PrdelRefuted(PrdelError):
    """A supported deterministic predicate contradicts the selected expected value."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _portable_metadata(value: str) -> bool:
    return not any(
        ord(char) < 32 or ord(char) == 127 or char in "\u0085\u2028\u2029"
        for char in value
    )


def _quoted(value: str) -> str:
    """Keep retained metadata and selected quotations inert in Markdown prose."""
    return json.dumps(value, ensure_ascii=True)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrdelError("duplicate JSON field")
        result[key] = value
    return result


def decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise PrdelError("document byte bound exceeded")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(PrdelError("nonfinite JSON")),
    )
    if type(value) is not dict:
        raise PrdelError("document must be a JSON object")
    return value


def _git(
    root: Path,
    *args: str,
    git_input: bytes | None = None,
    max_output_bytes: int = MAX_GIT_QUERY_BYTES,
) -> bytes:
    if (
        type(max_output_bytes) is not int
        or max_output_bytes < 1
        or max_output_bytes > MAX_V2_GIT_QUERY_BYTES
    ):
        raise PrdelError("invalid Git query output byte bound")
    try:
        # Spool bounded Git data rather than capturing an unlimited pipe in memory.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                ["git", "-C", str(root), *args],
                input=git_input,
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            if output.tell() > max_output_bytes:
                raise PrdelUnavailable("Git query output byte bound exceeded")
            output.seek(0)
            raw = output.read(max_output_bytes + 1)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PrdelUnavailable("Git query unavailable within bound") from exc
    if result.returncode:
        raise PrdelUnavailable("exact Git object unavailable")
    return raw


def _revision(root: Path, name: str) -> str:
    if type(name) is not str or not name or len(name) > 256 or "\x00" in name:
        raise PrdelError("invalid revision selector")
    value = (
        _git(root, "rev-parse", "--verify", "--end-of-options", name + "^{commit}")
        .decode()
        .strip()
    )
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise PrdelError("invalid resolved revision")
    return value


class SourceSnapshot(dict[str, bytes]):
    """Exact regular Git blobs plus retained executable mode metadata."""

    def __init__(self) -> None:
        super().__init__()
        self.modes: dict[str, str] = {}


def _snapshot(
    root: Path,
    revision: str,
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_snapshot_bytes: int = MAX_SNAPSHOT_BYTES,
) -> SourceSnapshot:
    if (
        type(max_file_bytes) is not int
        or type(max_snapshot_bytes) is not int
        or max_file_bytes < 1
        or max_file_bytes > MAX_V2_FILE_BYTES
        or max_snapshot_bytes < max_file_bytes
        or max_snapshot_bytes > MAX_V2_SNAPSHOT_BYTES
    ):
        raise PrdelError("invalid snapshot resource bound")
    listing = _git(root, "ls-tree", "-r", "-l", "-z", revision).split(b"\x00")
    declared_bytes = 0
    entries: list[tuple[str, str, bytes, int]] = []
    seen: set[str] = set()
    for entry in listing:
        if not entry:
            continue
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split()
        if (
            len(fields) != 4
            or fields[0] not in (b"100644", b"100755")
            or fields[1] != b"blob"
        ):
            raise PrdelError("snapshot refuses links and special entries")
        if not separator or not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", fields[2]):
            raise PrdelError("invalid exact tree entry")
        path = raw_path.decode("utf-8", errors="strict")
        normalized = PurePosixPath(path)
        if (
            not path
            or len(raw_path) > 4096
            or not _portable_metadata(path)
            or normalized.is_absolute()
            or ".." in normalized.parts
            or normalized.as_posix() != path
            or path in seen
        ):
            raise PrdelError("invalid or duplicate exact tree path")
        seen.add(path)
        size = int(fields[3])
        declared_bytes += size
        if (
            size < 0
            or size > max_file_bytes
            or declared_bytes > max_snapshot_bytes
            or len(seen) > MAX_FILES
        ):
            raise PrdelError("snapshot resource bound exceeded")
        entries.append((path, fields[0].decode("ascii"), fields[2], size))
    # Archives honor export-ignore/export-subst and therefore cannot establish
    # the exact retained tree. Query bounded blobs directly, without checkout.
    raw = _git(
        root,
        "cat-file",
        "--batch",
        git_input=b"".join(oid + b"\n" for _, _, oid, _ in entries),
        max_output_bytes=max_snapshot_bytes + 16 * 1024 * 1024,
    )
    if len(raw) > declared_bytes + len(entries) * 128:
        raise PrdelError("snapshot batch output bound exceeded")
    files = SourceSnapshot()
    offset = 0
    for path, mode, oid, size in entries:
        end = raw.find(b"\n", offset)
        if end < offset or raw[offset:end] != oid + b" blob " + str(size).encode(
            "ascii"
        ):
            raise PrdelError("exact blob header differs")
        start = end + 1
        data = raw[start : start + size]
        if len(data) != size or raw[start + size : start + size + 1] != b"\n":
            raise PrdelError("exact blob byte length differs")
        content = b"blob " + str(size).encode("ascii") + b"\x00" + data
        actual = (
            hashlib.sha1(content).hexdigest()
            if len(oid) == 40
            else hashlib.sha256(content).hexdigest()
        )
        if actual.encode("ascii") != oid:
            raise PrdelError("exact blob content digest differs")
        files[path] = data
        files.modes[path] = mode
        offset = start + size + 1
    if offset != len(raw):
        raise PrdelError("extraneous exact blob output")
    return files


def _snapshot_for_contract(
    root: Path, revision: str, contract: str
) -> SourceSnapshot:
    if contract == SCHEMA_V2:
        return _snapshot(
            root,
            revision,
            max_file_bytes=MAX_V2_FILE_BYTES,
            max_snapshot_bytes=MAX_V2_SNAPSHOT_BYTES,
        )
    return _snapshot(root, revision)


def _requirements(
    raw: bytes | None, expected: str | None
) -> tuple[dict[str, Any], str]:
    if raw is None:
        if expected is not None:
            raise PrdelError("selected requirements bytes missing")
        raw = canonical(DEFAULT_REQUIREMENTS)
    elif expected is None or expected != digest(raw):
        raise PrdelError(
            "independently selected requirements digest differs or is missing"
        )
    value = decode(raw)
    if (
        set(value) != {"schema_version", "items"}
        or value["schema_version"] != DEFAULT_REQUIREMENTS["schema_version"]
    ):
        raise PrdelError("unsupported exact requirements contract")
    if (
        type(value["items"]) is not list
        or not value["items"]
        or len(value["items"]) > 10000
    ):
        raise PrdelError("bounded nonempty requirements inventory required")
    seen: set[str] = set()
    for item in value["items"]:
        if (
            type(item) is not dict
            or set(item) not in ({"id", "text"}, {"id", "text", "predicate"})
            or any(
                type(item[k]) is not str or not item[k].strip() for k in ("id", "text")
            )
            or not _portable_metadata(item["id"])
            or len(item["id"]) > 256
            or len(item["text"]) > 16384
            or item["id"] in seen
        ):
            raise PrdelError("invalid or duplicate requirement")
        if "predicate" in item:
            predicate = item["predicate"]
            if (
                type(predicate) is not dict
                or set(predicate) != {"kind", "path", "symbol", "cases"}
                or predicate["kind"] != "finite_python_function"
                or any(
                    type(predicate[k]) is not str or not predicate[k]
                    for k in ("path", "symbol")
                )
                or type(predicate["cases"]) is not list
                or not predicate["cases"]
                or len(predicate["cases"]) > 128
            ):
                raise PrdelError("unsupported or unbounded requirement predicate")
            for case in predicate["cases"]:
                if (
                    type(case) is not dict
                    or set(case) != {"arguments", "expected"}
                    or type(case["arguments"]) is not list
                    or len(case["arguments"]) > 16
                    or any(
                        type(x) is not int or abs(x) > 1_000_000_000
                        for x in case["arguments"]
                    )
                    or type(case["expected"]) is not int
                    or abs(case["expected"]) > 1_000_000_000
                ):
                    raise PrdelError("finite contract requires bounded integer cases")
        seen.add(item["id"])
    return value, digest(raw)


def _symbols(raw: bytes, first: int, last: int) -> list[str]:
    if len(raw) > MAX_AST_SOURCE_BYTES:
        return []
    try:
        tree = ast.parse(raw)
    except (ValueError, SyntaxError, UnicodeError):
        return []
    result = []

    def visit(nodes: list[ast.stmt], prefix: str = "") -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + node.name
                if (
                    node.lineno <= last
                    and (getattr(node, "end_lineno", node.lineno) or node.lineno)
                    >= first
                ):
                    result.append(name)
                if isinstance(node, ast.ClassDef):
                    visit(node.body, name + ".")

    visit(tree.body)
    return sorted(set(result))


def _bounded_text_intervals(
    before: list[str], after: list[str], prefix: int, suffix: int,
) -> list[tuple[str, int, int, int, int]] | None:
    """Use exact monotonic anchors without increasing aggregate diff work."""
    old_end, new_end = len(before) - suffix, len(after) - suffix
    windows = [(prefix, old_end, prefix, new_end)]
    if (old_end - prefix) * (new_end - prefix) > 2_000_000:
        old_counts = Counter(before[prefix:old_end])
        new_counts = Counter(after[prefix:new_end])
        positions = {line: i for i, line in enumerate(after[prefix:new_end], prefix)
                     if new_counts[line] == 1}
        windows = []
        a = c = prefix
        for i in range(prefix, old_end):
            line = before[i]
            j = positions.get(line)
            if old_counts[line] != 1 or j is None or j < c:
                continue
            if i > a or j > c:
                windows.append((a, i, c, j))
            a, c = i + 1, j + 1
        if a < old_end or c < new_end:
            windows.append((a, old_end, c, new_end))
    if (len(windows) > MAX_REGIONS
            or sum((b - a) * (d - c) for a, b, c, d in windows) > 2_000_000):
        return None
    result = []
    for a, b, c, d in windows:
        result.extend(
            (tag, i + a, j + a, k + c, m + c)
            for tag, i, j, k, m in difflib.SequenceMatcher(
                None, before[a:b], after[c:d], autojunk=False,
            ).get_opcodes() if tag != "equal"
        )
    return result


def _changes(before: dict[str, bytes], after: dict[str, bytes]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in sorted(set(before) | set(after)):
        if not _portable_metadata(path):
            raise PrdelError(
                "source paths with control or line-separator characters are unsupported"
            )
        old, new = before.get(path), after.get(path)
        old_mode = getattr(before, "modes", {}).get(
            path, "100644" if old is not None else None
        )
        new_mode = getattr(after, "modes", {}).get(
            path, "100644" if new is not None else None
        )
        if old == new and old_mode == new_mode:
            continue
        previous, current = old or b"", new or b""
        binary = b"\x00" in previous[:8000] or b"\x00" in current[:8000]
        large_artifact = (
            previous != current
            and max(len(previous), len(current)) > MAX_INLINE_SOURCE_BYTES
        )
        if large_artifact:
            old_lines, new_lines = [], []
        else:
            try:
                old_lines = previous.decode("utf-8").splitlines(keepends=True)
                new_lines = current.decode("utf-8").splitlines(keepends=True)
            except UnicodeError:
                binary = True
                old_lines, new_lines = [], []
        large = len(old_lines) * len(new_lines) > 2_000_000
        prefix = suffix = 0
        if large and not binary:
            # Exact equal edges require linear comparisons, not quadratic diffing.
            common = min(len(old_lines), len(new_lines))
            while prefix < common and old_lines[prefix] == new_lines[prefix]:
                prefix += 1
            while (suffix < common - prefix
                   and old_lines[-suffix - 1] == new_lines[-suffix - 1]):
                suffix += 1
            large = ((len(old_lines) - prefix - suffix)
                     * (len(new_lines) - prefix - suffix) > 2_000_000)
        intervals = None if binary or large_artifact else _bounded_text_intervals(
            old_lines, new_lines, prefix, suffix,
        )
        large = not binary and not large_artifact and intervals is None
        if intervals is None:
            intervals = [("replace", 0, len(old_lines), 0, len(new_lines))]
        # Empty added/deleted files still have a source obligation.
        if not intervals:
            intervals = [("replace", 0, 0, 0, 0)]
        for _, a, b, c, d in intervals:
            row: dict[str, Any] = {
                "path": path,
                "kind": (
                    "added" if old is None else "removed" if new is None else "modified"
                ),
                "old_range": [a + 1, b],
                "new_range": [c + 1, d],
                "before_sha256": digest(previous) if old is not None else None,
                "after_sha256": digest(current) if new is not None else None,
                "before_mode": old_mode,
                "after_mode": new_mode,
                "before_text": "".join(old_lines[a:b]),
                "after_text": "".join(new_lines[c:d]),
                "symbols": sorted(
                    set(
                        (
                            _symbols(previous, a + 1, max(a + 1, b))
                            if path.endswith(".py")
                            else []
                        )
                        + (
                            _symbols(current, c + 1, max(c + 1, d))
                            if path.endswith(".py")
                            else []
                        )
                    )
                ),
                "analysis_boundary": (
                    "LARGE_EXACT_ARTIFACT_NOT_INLINED"
                    if large_artifact
                    else "BINARY_CHANGE"
                    if binary
                    else "LARGE_REGION_REQUIRES_SUBDIVISION" if large else None
                ),
            }
            if large_artifact:
                row["before_bytes"] = len(previous) if old is not None else None
                row["after_bytes"] = len(current) if new is not None else None
            row["id"] = "source:" + digest(canonical(row))
            row["question"] = (
                "Explain the exact before/after change, its "
                "selected requirement and exclusions."
            )
            result.append(row)
            if len(result) > MAX_REGIONS:
                raise PrdelError("changed region count bound exceeded")
    return result


def generate_prdel(
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Keep the version-one generated document and its original byte ceiling."""
    return _generate_prdel_template(root, base, head, requirements_bytes,
        expected_requirements_digest, limits)


def generate_prdel_v2(
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate the explicit source-bound version-two manual template."""
    return _generate_prdel_template(
        root,
        base,
        head,
        requirements_bytes,
        expected_requirements_digest,
        limits,
        contract=SCHEMA_V2,
        source_bound=True,
    )


def _build_source_bound_impact_graph(
    before: dict[str, bytes],
    after: dict[str, bytes],
    changes: list[dict[str, Any]],
    **limits: Any,
) -> dict[str, Any]:
    """Keep the v2 graph import lazy without exposing it as the v1 default."""
    from verifier.runtime.prdel_graph import build_source_bound_impact_graph

    return build_source_bound_impact_graph(before, after, changes, **limits)


def _source_set_identifier(values: list[str]) -> str:
    raw = json.dumps((values,), sort_keys=True, separators=(",", ":"))
    return "source-set:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _resolved_source_bound_rows(
    graph: dict[str, Any], changes: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve impact-2 provenance sets for existing v1 obligation consumers."""
    if graph.get("schema_version") != "verifier-prdel-impact-2":
        raise PrdelError("source-bound impact graph version required")
    raw_sets = graph.get("source_obligation_sets")
    if type(raw_sets) is not list or len(raw_sets) > MAX_REGIONS * 4:
        raise PrdelError("bounded source obligation set inventory required")
    selected = {row["id"] for row in changes}
    source_sets: dict[str, tuple[list[str], int]] = {}
    for row in raw_sets:
        if type(row) is not dict or set(row) != {"id", "source_obligations"}:
            raise PrdelError("exact source obligation set fields required")
        identifier, values = row["id"], row["source_obligations"]
        if (
            type(identifier) is not str
            or identifier in source_sets
            or type(values) is not list
            or any(type(value) is not str or value not in selected for value in values)
            or values != sorted(set(values))
            or identifier != _source_set_identifier(values)
        ):
            raise PrdelError("invalid or substituted source obligation set")
        source_sets[identifier] = (values, len(canonical(values)))

    selected_rows: dict[str, list[dict[str, Any]]] = {}
    expanded_refs = 0
    expanded_bytes = 0
    for name in ("nodes", "edges", "obligations", "frontier"):
        rows = graph.get(name)
        if type(rows) is not list or len(rows) > MAX_REGIONS * 4:
            raise PrdelError("bounded source-bound graph rows required")
        for row in rows:
            if type(row) is not dict:
                raise PrdelError("source-bound graph row must be an object")
            identifier = row.get("source_obligation_set_id")
            if type(identifier) is not str or identifier not in source_sets:
                raise PrdelError("unknown source obligation set reference")
            if name in {"obligations", "frontier"}:
                values, wire_bytes = source_sets[identifier]
                expanded_refs += len(values)
                expanded_bytes += wire_bytes
                if (
                    expanded_refs > MAX_DOCUMENT_BYTES // 16
                    or expanded_bytes > MAX_DOCUMENT_BYTES
                ):
                    raise PrdelUnavailable(
                        "source-bound obligation provenance expansion exceeds bound"
                    )
        if name in {"obligations", "frontier"}:
            selected_rows[name] = rows

    resolved = []
    for name in ("obligations", "frontier"):
        expanded = []
        for row in selected_rows[name]:
            values, _ = source_sets[row["source_obligation_set_id"]]
            projected = dict(row)
            projected.pop("source_obligation_set_id")
            projected["source_obligations"] = list(values)
            expanded.append(projected)
        resolved.append(expanded)
    return resolved[0], resolved[1]


def _finalize_source_bound_graph_size(graph: dict[str, Any]) -> None:
    """Bind the byte counter to the final nested graph emitted by PRDEL v2."""
    counters, bounds = graph.get("counters"), graph.get("bounds")
    if type(counters) is not dict or type(bounds) is not dict:
        raise PrdelError("source-bound graph counters and bounds required")
    limit = bounds.get("max_output_bytes")
    if type(limit) is not int or limit <= 0:
        raise PrdelError("positive source-bound graph output limit required")
    for _ in range(16):
        measured = len(canonical(graph))
        if counters.get("materialized_bytes") == measured:
            break
        counters["materialized_bytes"] = measured
    else:
        raise PrdelUnavailable("source-bound graph size counter did not stabilize")
    measured = len(canonical(graph))
    if counters.get("materialized_bytes") != measured:
        raise PrdelUnavailable("source-bound graph size counter is not exact")
    if measured > limit:
        raise PrdelUnavailable("source-bound impact graph final byte bound exceeded")


def _generate_prdel_template(
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    limits: dict[str, Any] | None = None,
    *,
    sharded: bool = False,
    contract: str = SCHEMA,
    source_bound: bool = False,
) -> dict[str, Any]:
    if sharded and contract not in {SCHEMA, SCHEMA_V2}:
        raise PrdelUnavailable("unsupported sharded PRDEL contract")
    if source_bound != (contract == SCHEMA_V2):
        raise PrdelError("explicit PRDEL generator contract mismatch")
    root = Path(root)
    requirements, requirement_digest = _requirements(
        requirements_bytes, expected_requirements_digest
    )
    start_base, start_head = _revision(root, base), _revision(root, head)
    _git(root, "merge-base", "--is-ancestor", start_base, start_head)
    before = _snapshot_for_contract(root, start_base, contract)
    after = _snapshot_for_contract(root, start_head, contract)
    changes = _changes(before, after)
    if source_bound:
        graph = _build_source_bound_impact_graph(before, after, changes, **(limits or {}))
        graph_obligations, graph_frontier = _resolved_source_bound_rows(graph, changes)
    else:
        from verifier.runtime.prdel_graph import build_impact_graph

        graph = build_impact_graph(before, after, changes, **(limits or {}))
        graph_obligations, graph_frontier = (
            graph.get("obligations", []),
            graph.get("frontier", []),
        )
    binding = {
        "base": start_base,
        "head": start_head,
        "source_digest": digest(
            canonical(
                {
                    side: {
                        p: {
                            "sha256": digest(b),
                            "mode": getattr(snapshot, "modes", {}).get(p, "100644"),
                        }
                        for p, b in sorted(snapshot.items())
                    }
                    for side, snapshot in (("before", before), ("after", after))
                }
            )
        ),
        "requirements_digest": requirement_digest,
    }
    graph["binding"] = binding.copy()
    predicates = {}
    predicate_bytes = 0
    for item in requirements["items"]:
        if "predicate" in item:
            predicate = item["predicate"]
            source = after.get(predicate["path"], b"")
            # Preflight expansion before decoding/copying repeated selected
            # sources. JSON escaping can expand one byte to six characters.
            predicate_bytes += 6 * len(source)
            if predicate_bytes > MAX_DOCUMENT_BYTES // 2:
                raise PrdelUnavailable(
                    "selected predicate aggregate source byte bound exceeded"
                )
            predicates[item["id"]] = {
                **predicate,
                "source_boundary": (
                    "SOURCE_BYTES_BOUND" if len(source) > MAX_AST_SOURCE_BYTES else None
                ),
                "source_bytes": (
                    ""
                    if len(source) > MAX_AST_SOURCE_BYTES
                    else source.decode("utf-8", errors="strict")
                ),
            }
    graph["selected_predicates"] = predicates
    if source_bound:
        _finalize_source_bound_graph_size(graph)
    obligations = [
        {**row, "kind": "source", "change_kind": row["kind"]} for row in changes
    ]
    if not changes:
        obligations.append(
            {
                "id": "source:no-change:" + digest(canonical(binding)),
                "kind": "source",
                "change_kind": "unchanged",
                "path": "<exact-diff>",
                "no_change": True,
                ("question"): (
                    "Explicitly represent the exact empty source "
                    "diff; no runtime claim follows."
                ),
            }
        )
    obligations += graph_obligations
    # Only boundaries reached by a changed region are required. Unrelated static
    # unknowns remain visible in the graph rather than poisoning a bounded scope.
    obligations += [
        {
            **row,
            "frontier_kind": row.get("kind"),
            "kind": "frontier",
            "path": row.get("path") or "<analysis-frontier>",
        }
        for row in graph_frontier
        if (
            row.get("source_obligations")
            or row.get("kind") in {"analysis_bound", "frontier_bound"}
        )
        and not (
            row.get("kind") == "unsupported_language"
            and row.get("path", "").endswith((".md", ".txt", ".rst"))
        )
    ]
    records = [
        {
            "id": row["id"],
            "requirement_ids": [],
            "why": {"requirement_id": None, "quote": ""},
            "claims": [],
            "summary": "",
            "limits": [],
            "coverage": {},
        }
        for row in obligations
    ]
    if _revision(root, base) != start_base or _revision(root, head) != start_head:
        raise PrdelError("revision moved during generation")
    document = {
        "schema_version": contract,
        "binding": binding,
        "requirements": requirements,
        "source_obligations": obligations,
        "impact_graph": graph,
        "records": records,
        "evidence": [],
    }
    if sharded:
        return _decode_sharded_document(document)
    if len(canonical(document)) > MAX_DOCUMENT_BYTES:
        raise PrdelUnavailable(
            (
                "generated document byte bound exceeded; split the "
                "declared review into bounded changes"
            )
        )
    return document


def claim_text(claim: dict[str, Any], document: dict[str, Any]) -> str:
    """Render supported predicates; arbitrary submitted prose is not a predicate."""
    if type(claim) is not dict:
        raise PrdelError("claim must be a typed object")
    kind = claim.get("kind")
    if kind == "source_delta" and set(claim) == {"kind", "obligation_id"}:
        rows = {r["id"]: r for r in document["source_obligations"]}
        row = rows.get(claim["obligation_id"])
        if row is None or row["kind"] != "source" or row.get("analysis_boundary"):
            raise PrdelError("selected source delta is missing or unsupported")
        if row.get("no_change"):
            raise PrdelError(
                "empty diff requires an explicit no_source_changes predicate"
            )
        return (
            f"{row['change_kind'].capitalize()} retained region in "
            f"{_quoted(row['path'])}: "
            f"base lines {row['old_range'][0]}–{row['old_range'][1]} to "
            f"head lines {row['new_range'][0]}–{row['new_range'][1]}. "
            f"Git mode {row['before_mode']} → {row['after_mode']}. "
            f"Before: {row['before_text']!r}; after: {row['after_text']!r}."
        )
    if kind == "exact_artifact_delta" and set(claim) == {
        "kind",
        "obligation_id",
    }:
        rows = {r["id"]: r for r in document["source_obligations"]}
        row = rows.get(claim["obligation_id"])
        if (
            row is None
            or row.get("kind") != "source"
            or row.get("analysis_boundary")
            != "LARGE_EXACT_ARTIFACT_NOT_INLINED"
        ):
            raise PrdelError("selected exact artifact delta is absent")
        before = (
            "absent"
            if row.get("before_bytes") is None
            else f"{row['before_bytes']} bytes sha256:{row['before_sha256']}"
        )
        after = (
            "absent"
            if row.get("after_bytes") is None
            else f"{row['after_bytes']} bytes sha256:{row['after_sha256']}"
        )
        return (
            "Large exact artifact "
            + row["change_kind"]
            + " in "
            + _quoted(row["path"])
            + f": {before} ({row['before_mode']}) to "
            + f"{after} ({row['after_mode']}). Content is digest-bound but not "
            + "inlined; semantic coverage and relationship discovery remain "
            + "separate obligations."
        )
    if kind == "no_source_changes" and set(claim) == {"kind", "obligation_id"}:
        rows = {r["id"]: r for r in document["source_obligations"]}
        if not rows.get(claim["obligation_id"], {}).get("no_change"):
            raise PrdelError("selected diff is not empty")
        return (
            "The selected exact base and head retain identical "
            "source bytes and Git modes; no changed-region impact is "
            "asserted."
        )
    if kind == "ast_relationship" and set(claim) == {"kind", "edge_id"}:
        graph = document["impact_graph"]
        edges = {r["id"]: r for r in graph["edges"]}
        nodes = {r["id"]: r for r in graph["nodes"]}
        edge = edges.get(claim["edge_id"])
        if edge is None or edge["evidence_state"] != "resolved_relationship":
            raise PrdelError("AST relationship is unresolved")
        start, end = nodes[edge["source"]], nodes[edge["target"]]
        return (
            f"Retained {edge['side']} AST {edge['relationship']} relationship: "
            f"{_quoted(start['path'] + '::' + start['symbol'])} → "
            f"{_quoted(end['path'] + '::' + end['symbol'])}. "
            "This establishes syntactic endpoints, not a behavioral invariant."
        )
    if kind == "frontier_resolution" and set(claim) == {
        "kind",
        "frontier_id",
        "mechanism_id",
    }:
        rows = {r["id"]: r for r in document["source_obligations"]}
        row = rows.get(claim["frontier_id"])
        if row is None or row.get("kind") != "frontier":
            raise PrdelError("selected frontier is absent")
        if claim["mechanism_id"] not in {
            "exact-json-plus-replay-1",
            "exact-utf8-plus-replay-1",
            "selected-replay-1",
        }:
            raise PrdelError("frontier mechanism is outside the closed catalogue")
        return (
            "Selected bounded frontier replay "
            + _quoted(claim["frontier_id"])
            + " uses closed mechanism "
            + _quoted(claim["mechanism_id"])
            + ". This represents only the replayed explanation obligation; "
            + "whole-estate completeness and runtime correctness remain "
            + "unestablished."
        )
    if kind == "requirement_quote" and set(claim) == {
        "kind",
        "requirement_id",
        "quote",
    }:
        requirements = {r["id"]: r["text"] for r in document["requirements"]["items"]}
        if requirements.get(claim["requirement_id"]) != claim["quote"]:
            raise PrdelError("requirement quotation differs")
        return (
            f"Selected requirement "
            f"{_quoted(claim['requirement_id'])}"
            f": "
            f"{_quoted(claim['quote'])}"
        )
    if kind == "finite_function_contract" and set(claim) == {"kind", "requirement_id"}:
        predicate = (
            document["impact_graph"]
            .get("selected_predicates", {})
            .get(claim["requirement_id"])
        )
        if predicate is None:
            raise PrdelError("finite contract was not independently selected")
        if predicate.get("source_boundary"):
            raise PrdelError("selected finite function source byte bound exceeded")
        tree = ast.parse(predicate["source_bytes"])
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == predicate["symbol"]
        ]
        if len(functions) != 1:
            raise PrdelError("selected finite function unavailable or ambiguous")
        function = functions[0]
        if (
            function.decorator_list
            or function.args.defaults
            or function.args.kw_defaults
            or function.args.posonlyargs
            or function.args.vararg
            or function.args.kwarg
            or function.args.kwonlyargs
            or len(function.body) != 1
            or not isinstance(function.body[0], ast.Return)
            or function.body[0].value is None
            or len(list(ast.walk(function))) > 1000
        ):
            raise PrdelError(
                (
                    "finite interpreter supports undecorated "
                    "straight-line integer return expressions only"
                )
            )
        names = [arg.arg for arg in function.args.args]

        def evaluate(node: ast.AST, values: dict[str, int], depth: int = 0) -> int:
            if depth > 32:
                raise PrdelError("finite expression depth exhausted")
            if isinstance(node, ast.Constant) and type(node.value) is int:
                value = node.value
            elif isinstance(node, ast.Name) and node.id in values:
                value = values[node.id]
            elif isinstance(node, ast.UnaryOp) and isinstance(
                node.op, (ast.UAdd, ast.USub)
            ):
                operand = evaluate(node.operand, values, depth + 1)
                value = operand if isinstance(node.op, ast.UAdd) else -operand
            elif isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Add, ast.Sub, ast.Mult)
            ):
                left, right = evaluate(node.left, values, depth + 1), evaluate(
                    node.right, values, depth + 1
                )
                value = (
                    left + right
                    if isinstance(node.op, ast.Add)
                    else left - right if isinstance(node.op, ast.Sub) else left * right
                )
            else:
                raise PrdelError(
                    "expression outside supported finite integer semantics"
                )
            if abs(value) > 1_000_000_000:
                raise PrdelError("finite integer bound exhausted")
            return value

        for case in predicate["cases"]:
            if len(case["arguments"]) != len(names):
                raise PrdelError("finite contract argument arity differs")
            actual = evaluate(
                function.body[0].value, dict(zip(names, case["arguments"]))
            )
            if actual != case["expected"]:
                raise PrdelRefuted(
                    (
                        "finite retained function contradicts "
                        "independently selected expected case"
                    )
                )
        return (
            f"Under the supported "
            f"straight-line integer AST "
            f"semantics, "
            f"{predicate['path']}"
            f"::"
            f"{predicate['symbol']}"
            f" matches all "
            f"{len(predicate['cases'])}"
            f" independently selected "
            f"finite input/output cases. "
            f"This does not establish "
            f"actual historical Python "
            f"execution, caller correctness "
            f"or unselected inputs."
        )
    raise PrdelError("unsupported semantic predicate")


def _finding(
    code: str,
    status: str,
    *,
    row: dict[str, Any] | None = None,
    reason: str,
    question: str | None = None,
    execution_status: str | None = None,
) -> dict[str, Any]:
    row = row or {}
    result = {
        "code": code,
        "category": code,
        "status": status,
        "obligation_id": row.get("id"),
        "path": row.get("path"),
        "reason": reason,
        "question": question
        or row.get("question")
        or "Supply exact bound inputs and supported evidence for this obligation.",
    }
    if execution_status is not None:
        result["execution_status"] = execution_status
    return result


def _status(findings: list[dict[str, Any]]) -> str:
    return (
        "FAIL"
        if any(item["status"] == "FAIL" for item in findings)
        else "UNKNOWN" if findings else "PASS"
    )


def _known_missing_structure(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Retain directly visible missing fields even when source replay is unavailable."""
    records = document.get("records")
    if type(records) is not list or len(records) > MAX_REGIONS * 4:
        return []
    if not records:
        return [
            _finding(
                "UNREPRESENTED_CHANGE",
                "FAIL",
                reason="The required explanation record inventory is empty.",
                execution_status="NOT_RUN",
            )
        ]
    findings = []
    for record in records:
        if type(record) is not dict:
            continue
        row = {"id": record.get("id") if isinstance(record.get("id"), str) else None}
        why = record.get("why")
        if (
            not record.get("requirement_ids")
            or not isinstance(why, dict)
            or not why.get("requirement_id")
            or not why.get("quote")
        ):
            findings.append(
                _finding(
                    "INCOMPLETE_EXPLANATION",
                    "FAIL",
                    row=row,
                    reason=(
                        "Required selected requirement linkage and "
                        "quotation are missing."
                    ),
                )
            )
        if not record.get("claims"):
            findings.append(
                _finding(
                    "MISSING_REQUIRED_CLAIM",
                    "FAIL",
                    row=row,
                    reason="The required claim list is empty.",
                    execution_status="NOT_RUN",
                )
            )
        if not isinstance(record.get("summary"), str) or not record["summary"].strip():
            findings.append(
                _finding(
                    "MISSING_REQUIRED_SUMMARY",
                    "FAIL",
                    row=row,
                    reason="The required explanation summary is missing.",
                )
            )
        if not record.get("limits"):
            findings.append(
                _finding(
                    "INCOMPLETE_EXPLANATION",
                    "FAIL",
                    row=row,
                    reason="Required selected exclusions are missing.",
                )
            )
    return findings


def assertion_text(body: str, report: dict[str, Any]) -> str:
    """Separate current prose from retained structured data and checked quotations.

    This does not clear omitted prose: evaluate_description still compares the
    complete body with its supported rendering and retains unsupported meaning.
    """
    text = re.sub(
        r"^```vstd-prdel[ \t]*\n.*?^```[ \t]*$",
        "",
        body,
        flags=re.MULTILINE | re.DOTALL,
    )
    for result in report.get("predicate_results", []):
        if result.get("status") == "PASS" and type(result.get("text")) is str:
            text = text.replace(result["text"], "")
    return text


def _finalize(report: dict[str, Any]) -> dict[str, Any]:
    """Finalize all aggregate fields after every relevant input is assessed."""
    status = _status(report["findings"])
    report["status"] = status
    report["semantic_status"] = status
    # This is correspondence for the complete selected explanation, rather than
    # an early partial success that survives malformed records or stale inputs.
    report["source_grounding_status"] = status
    report["verdict_scope"] = "GATE_OBLIGATION_FULFILLMENT"
    report["proposition_truth"] = "NOT_INFERRED_FROM_MISSING_EVIDENCE"
    report["required_checks_not_run"] = sum(
        item.get("execution_status") == "NOT_RUN" for item in report["findings"]
    )
    coverage = report.get("coverage")
    if coverage and "layers" in coverage:
        for layer in ("base", "unit", "integration", "regression", "preventative"):
            coverage["layers"].setdefault(
                layer,
                {
                    "verdict": "UNKNOWN",
                    "obligations": [],
                    ("reason"): (
                        "Layer assessment was not completed within "
                        "the declared bounds."
                    ),
                },
            )
        coverage["verdict"] = status
        base_findings = [
            item
            for item in report["findings"]
            if item.get("layer") in (None, "base")
            and item["code"] != "EXECUTED_VALIDATION_NOT_ESTABLISHED"
        ]
        base_status = _status(base_findings)
        coverage["base_predicate_status"] = base_status
        base = coverage["layers"]["base"]
        base["verdict"] = base_status
        for obligation in base.get("obligations", []):
            relevant = [
                item
                for item in base_findings
                if item.get("obligation_id") in (None, obligation["obligation_id"])
            ]
            obligation["verdict"] = _status(relevant)
        report["required_checks_not_run"] = sum(
            item.get("execution_status") == "NOT_RUN"
            for layer in coverage["layers"].values()
            for item in layer.get("obligations", [])
        )
        executions = {
            layer.get("execution_status", "UNRESOLVED")
            for layer in coverage["layers"].values()
        }
        coverage["execution_status"] = (
            "NOT_RUN"
            if "NOT_RUN" in executions
            else (next(iter(executions)) if len(executions) == 1 else "MIXED")
        )
    return report


def _known_contradictions(body: str, after: dict[str, bytes]) -> list[dict[str, Any]]:
    # These exact public Verifier facts come from retained candidate enum syntax;
    # historical quotations and code examples are not current assertions.
    raw = after.get("src/verifier/core/namespace.py")
    if raw is None:
        return []
    try:
        tree = ast.parse(raw)
        tiers = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "MetaTier"
        )
        values = [
            node.value.value
            for node in tiers.body
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is int
        ]
    except (SyntaxError, StopIteration, ValueError, UnicodeError):
        return []
    if 9 not in values:
        return []
    lines = []
    fenced = False
    for line in body.splitlines():
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced and not line.lstrip().startswith(">"):
            lines.append(line)
    found = []
    for line in lines:
        if re.search(
            (
                "(?i)(?:current notation|implementation audit|every "
                "object|same eight|eight (?:positive |general "
                "|required )?meta.tiers)"
            ),
            line,
        ) and re.search(r"1\.\.8|eight|\b8\b", line):
            found.append(
                _finding(
                    "CURRENT_REQUIREMENT_CONTRADICTION",
                    "FAIL",
                    reason=(
                        "Current eight-tier statement contradicts "
                        "retained SECURITY tier nine."
                    ),
                    question=(
                        "Preserve historical quotations; correct "
                        "current notation and requirements to 1..9.m."
                    ),
                )
            )
        if re.search(
            (
                "(?i)(?:all\\s+234|(?:complete|fully "
                "qualified|implements?)\\s+(?:all\\s+)?234)"
            ),
            line,
        ) and not re.search(
            r"(?i)\b(?:not|no|unestablished|unknown|missing|incomplete|does not)\b",
            line,
        ):
            found.append(
                _finding(
                    "UNSUPPORTED_FULL_QUALIFICATION",
                    "FAIL",
                    reason=(
                        "Registration and tier counts do not "
                        "establish all required objective "
                        "certificates."
                    ),
                    question=(
                        "Remove the qualification claim or provide "
                        "independently selected complete objective "
                        "evidence."
                    ),
                )
            )
    return found


# vstd-explanation: begin prdel.self.prdel
# Authored intent (not verified):
#   Check exact retained source explanations while preserving missing evidence and
# unresolved analysis.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): A passing source fact cannot establish complete behavioral
# qualification.
# vstd-explanation: end prdel.self.prdel
def validate_prdel(
    document: dict[str, Any],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Preserve the version-one whole-document transport and exact-source contract."""
    return _validate_prdel_document(document, root, base, head, requirements_bytes,
        expected_requirements_digest, evidence_bytes, expected_evidence_digest)


def validate_prdel_v2(
    document: dict[str, Any],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
    replay_plan_bytes: bytes | None = None,
    expected_replay_plan_digest: str | None = None,
    limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the explicit version-two document against exact selected source."""
    return _validate_prdel_document(
        document,
        root,
        base,
        head,
        requirements_bytes,
        expected_requirements_digest,
        evidence_bytes,
        expected_evidence_digest,
        contract=SCHEMA_V2,
        report_schema=REPORT_SCHEMA_V2,
        generator=generate_prdel_v2,
        replay_plan_bytes=replay_plan_bytes,
        expected_replay_plan_digest=expected_replay_plan_digest,
        limits=limits,
    )


def _validate_sharded_prdel(
    document: dict[str, Any],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Internal logical check after separately selected bounded shard transport.

    This does not resolve artifacts or qualify a manifest. The admission caller
    must first check selected exact manifest/shard bytes and complete membership.
    Selected source is recomputed here; the shard route preserves the exact
    ordinary compiled row/record order. Version-one bounds stay unchanged.
    """
    return _validate_prdel_document(document, root, base, head, requirements_bytes,
        expected_requirements_digest, evidence_bytes, expected_evidence_digest,
        sharded=True)


def _validate_sharded_prdel_v2(
    document: dict[str, Any],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
    limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one reconstructed v2 logical document under selected limits.

    Artifact admission and exact packet coverage belong to the separately
    versioned private transport.  This helper only replays its reconstructed
    logical document against the exact selected source.
    """
    return _validate_prdel_document(
        document,
        root,
        base,
        head,
        requirements_bytes,
        expected_requirements_digest,
        evidence_bytes,
        expected_evidence_digest,
        sharded=True,
        contract=SCHEMA_V2,
        report_schema=REPORT_SCHEMA_V2,
        generator=generate_prdel_v2,
        limits=limits,
    )


def _decode_sharded_document(document: dict[str, Any]) -> dict[str, Any]:
    """Decode finite individual parts with an unchanged finite aggregate ceiling."""
    if type(document) is not dict:
        raise PrdelError("exact sharded document object required")
    sequences = {"source_obligations", "records", "evidence"}
    header = {key: value for key, value in document.items() if key not in sequences}
    raw = canonical(header)
    total = len(raw)
    decoded = decode(raw)
    for key in sorted(sequences):
        values = document.get(key)
        if type(values) is not list or len(values) > MAX_REGIONS * 4:
            raise PrdelError("complete bounded sharded document lists required")
        items = []
        for value in values:
            raw = canonical(value)
            total += len(raw) + 1
            if total > MAX_DESCRIPTION_BYTES:
                raise PrdelUnavailable("sharded evidence aggregate byte bound exhausted")
            items.append(decode(raw))
        decoded[key] = items
    if total > MAX_DESCRIPTION_BYTES:
        raise PrdelUnavailable("sharded evidence aggregate byte bound exhausted")
    return decoded


def _validate_prdel_document(
    document: dict[str, Any],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
    *,
    sharded: bool = False,
    contract: str = SCHEMA,
    report_schema: str = REPORT_SCHEMA,
    generator: Any | None = None,
    limits: dict[str, Any] | None = None,
    replay_plan_bytes: bytes | None = None,
    expected_replay_plan_digest: str | None = None,
) -> dict[str, Any]:
    if sharded and contract not in {SCHEMA, SCHEMA_V2}:
        raise PrdelUnavailable("unsupported sharded PRDEL validation contract")
    if generator is None:
        generator = generate_prdel
    found: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": report_schema,
        "status": "UNKNOWN",
        "source_grounding_status": "UNKNOWN",
        "semantic_status": "UNKNOWN",
        "claim_boundary": BOUNDARY,
        "findings": found,
        "source_scope": "EXACT_COMMITS_ONLY",
        "execution_provenance": "NOT_ESTABLISHED",
        "requirement_authority": "NOT_ESTABLISHED",
        "checker_independence": "NOT_ESTABLISHED",
        "runtime_correctness": "NOT_ESTABLISHED",
        "whole_estate_completeness": "NOT_ESTABLISHED",
        "release_clearance": "NOT_ESTABLISHED",
        "publication_clearance": "NOT_ESTABLISHED",
        "workspace_clearance": "NOT_ESTABLISHED",
    }
    try:
        if bool(replay_plan_bytes) != bool(expected_replay_plan_digest):
            raise PrdelError(
                "replay plan bytes and their expected digest must be selected together"
            )
        if replay_plan_bytes is not None and contract != SCHEMA_V2:
            raise PrdelError("independent replay plans require verifier-prdel-2")
        # Reject duplicate keys and nonfinite values even for direct Python callers.
        document = _decode_sharded_document(document) if sharded else decode(canonical(document))
        if (
            set(document)
            != {
                "schema_version",
                "binding",
                "requirements",
                "source_obligations",
                "impact_graph",
                "records",
                "evidence",
            }
            or document["schema_version"] != contract
        ):
            raise PrdelError("unsupported exact PRDEL fields")
        if (
            type(document["records"]) is not list
            or len(document["records"]) > MAX_REGIONS * 4
        ):
            raise PrdelError("bounded explanation list required")
        for record in document["records"]:
            if type(record) is not dict or set(record) != {
                "id",
                "requirement_ids",
                "why",
                "claims",
                "summary",
                "limits",
                "coverage",
            }:
                raise PrdelError("invalid explanation record fields")
        selected_requirements, selected_requirements_digest = _requirements(
            requirements_bytes, expected_requirements_digest
        )
        if type(document["binding"]) is not dict:
            raise PrdelError("exact binding object required")
        if document["requirements"] != selected_requirements:
            found.append(
                _finding(
                    "STALE_OR_SUBSTITUTED_REQUIREMENTS",
                    "FAIL",
                    reason=(
                        "Carried requirements differ from "
                        "independently selected exact requirement "
                        "bytes."
                    ),
                )
            )
        if (
            document["binding"].get("requirements_digest")
            != selected_requirements_digest
        ):
            found.append(
                _finding(
                    "STALE_OR_SUBSTITUTED_BINDING",
                    "FAIL",
                    reason=(
                        "Declared requirements digest differs from "
                        "independently selected exact bytes."
                    ),
                )
            )
        for key, selected in (("base", base), ("head", head)):
            if (
                isinstance(selected, str)
                and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", selected)
                and document["binding"].get(key) != selected
            ):
                found.append(
                    _finding(
                        "STALE_OR_SUBSTITUTED_BINDING",
                        "FAIL",
                        reason=(
                            f"Declared "
                            f"{key}"
                            f" differs from the explicitly "
                            f"selected exact commit."
                        ),
                    )
                )
        if evidence_bytes is not None:
            if expected_evidence_digest != digest(evidence_bytes):
                raise PrdelError(
                    "independently selected evidence digest differs or missing"
                )
            selected = decode(evidence_bytes)
            if (
                set(selected) != {"schema_version", "binding", "evidence"}
                or selected["schema_version"] != "verifier-prdel-evidence-1"
                or selected["binding"] != document["binding"]
                or selected["evidence"] != document["evidence"]
            ):
                raise PrdelError(
                    "selected evidence differs from carried bindings or records"
                )
        elif expected_evidence_digest is not None:
            raise PrdelError("selected evidence bytes missing")
        expected = (_generate_prdel_template(
            Path(root), base, head, requirements_bytes, expected_requirements_digest,
            limits, sharded=True, contract=contract,
            source_bound=(contract == SCHEMA_V2)) if sharded else generator(
            Path(root), base, head, requirements_bytes,
            expected_requirements_digest, limits))
        report["binding"] = expected["binding"]
        for key in ("binding", "requirements", "source_obligations", "impact_graph"):
            if document[key] != expected[key]:
                found.append(
                    _finding(
                        "STALE_OR_SUBSTITUTED_" + key.upper(),
                        "FAIL",
                        reason=(
                            f"{key}"
                            f" differs from exact independently "
                            f"recomputed input."
                        ),
                        question=(
                            "Regenerate against the exact selected "
                            "revisions and requirement bytes."
                        ),
                    )
                )
        if any(r["status"] == "FAIL" for r in found):
            return _finalize(report)
        replay_assessment = None
        if replay_plan_bytes is not None:
            from verifier.runtime.prdel_evidence import replay_plan

            before_replay = _snapshot_for_contract(
                Path(root), expected["binding"]["base"], contract
            )
            after_replay = _snapshot_for_contract(
                Path(root), expected["binding"]["head"], contract
            )
            replay_assessment = replay_plan(
                replay_plan_bytes,
                expected_replay_plan_digest or "",
                expected["binding"],
                expected["source_obligations"],
                before_replay,
                after_replay,
            )
            report["replay"] = {
                "schema_version": "verifier-prdel-replay-report-1",
                "plan_digest": replay_assessment.plan_digest,
                "result_provenance": "VERIFIER_PRODUCED",
                "execution_authentication": (
                    "VERIFIER_REPLAYED"
                    if replay_assessment.results
                    and all(
                        result.status == "PASS"
                        for result in replay_assessment.results
                    )
                    else "NOT_ESTABLISHED"
                ),
                "results": [
                    {
                        "id": result.identifier,
                        "layer": result.layer,
                        "status": result.status,
                        "result_digest": result.result_digest,
                        "reason_code": result.reason_code,
                        "obligation_ids": list(result.obligation_ids),
                    }
                    for result in replay_assessment.results
                ],
                "frontier_statuses": dict(replay_assessment.frontier_statuses),
                "frontier_mechanisms": dict(replay_assessment.frontier_mechanisms),
                "issues": [
                    {
                        "code": issue.code,
                        "status": issue.status,
                        "frontier_id": issue.frontier_id,
                    }
                    for issue in replay_assessment.issues
                ],
                "claim_boundary": (
                    "Fresh fixed replay against the private exact-head snapshot; "
                    "test adequacy, runtime correctness, checker independence and "
                    "whole-estate completeness remain NOT_ESTABLISHED."
                ),
            }
        if (
            type(document["records"]) is not list
            or len(document["records"]) > MAX_REGIONS * 4
        ):
            raise PrdelError("bounded explanation list required")
        required = {row["id"]: row for row in expected["source_obligations"]}
        observed: dict[str, dict[str, Any]] = {}
        requirements = {
            item["id"]: item["text"] for item in expected["requirements"]["items"]
        }
        used_requirements: set[str] = set()
        predicate_results = []
        # Selected executable predicates are mandatory: omitting a claim cannot
        # conceal an independently selected counterexample.
        for item in expected["requirements"]["items"]:
            if "predicate" not in item:
                continue
            claim = {"kind": "finite_function_contract", "requirement_id": item["id"]}
            try:
                text = claim_text(claim, expected)
                predicate_results.append(
                    {
                        "requirement_id": item["id"],
                        "predicate": claim["kind"],
                        "status": "PASS",
                        "selection": "MANDATORY_SELECTED_REQUIREMENT",
                        "text": text,
                    }
                )
            except PrdelRefuted as exc:
                predicate_results.append(
                    {
                        "requirement_id": item["id"],
                        "predicate": claim["kind"],
                        "status": "FAIL",
                        "selection": "MANDATORY_SELECTED_REQUIREMENT",
                    }
                )
                found.append(
                    _finding(
                        "CONTRADICTED_SELECTED_REQUIREMENT", "FAIL", reason=str(exc)
                    )
                )
            except (PrdelError, KeyError, TypeError, SyntaxError) as exc:
                predicate_results.append(
                    {
                        "requirement_id": item["id"],
                        "predicate": claim["kind"],
                        "status": "UNKNOWN",
                        "selection": "MANDATORY_SELECTED_REQUIREMENT",
                    }
                )
                found.append(
                    _finding(
                        "UNRESOLVED_SELECTED_REQUIREMENT", "UNKNOWN", reason=str(exc)
                    )
                )
        for record in document["records"]:
            if type(record) is not dict or set(record) != {
                "id",
                "requirement_ids",
                "why",
                "claims",
                "summary",
                "limits",
                "coverage",
            }:
                raise PrdelError("invalid explanation record fields")
            identifier = record["id"]
            if (
                type(identifier) is not str
                or identifier in observed
                or identifier not in required
            ):
                raise PrdelError("duplicate or extraneous explanation obligation")
            observed[identifier] = record
            row = required[identifier]
            ids = record["requirement_ids"]
            if (
                type(ids) is not list
                or any(type(x) is not str or x not in requirements for x in ids)
                or len(ids) != len(set(ids))
            ):
                raise PrdelError("invalid requirement selections")
            used_requirements.update(ids)
            why = record["why"]
            if (
                type(why) is not dict
                or set(why) != {"requirement_id", "quote"}
                or why["requirement_id"] not in ids
                or requirements.get(why["requirement_id"]) != why["quote"]
            ):
                found.append(
                    _finding(
                        "INCOMPLETE_EXPLANATION",
                        "FAIL",
                        row=row,
                        reason=(
                            "Rationale must quote one exact selected "
                            "requirement; rationale causality is not "
                            "inferred."
                        ),
                    )
                )
            if (
                type(record["limits"]) is not list
                or not record["limits"]
                or len(record["limits"]) > len(LIMITS)
                or any(type(x) is not str or x not in LIMITS for x in record["limits"])
                or len(set(record["limits"])) != len(record["limits"])
            ):
                found.append(
                    _finding(
                        "INCOMPLETE_EXPLANATION",
                        "FAIL",
                        row=row,
                        reason=(
                            "Select supported exclusion IDs; "
                            "arbitrary limits prose is not certified."
                        ),
                    )
                )
            if type(record["claims"]) is not list or len(record["claims"]) > 256:
                raise PrdelError("bounded typed claim list required")
            rendered: list[str] = []
            represents = False
            unresolved = False
            if not record["claims"]:
                found.append(
                    _finding(
                        "MISSING_REQUIRED_CLAIM",
                        "FAIL",
                        row=row,
                        reason=(
                            "The required claim list is empty; a "
                            "template is not a completed explanation."
                        ),
                        execution_status="NOT_RUN",
                    )
                )
            for claim in record["claims"]:
                if (
                    type(claim) is not dict
                    or not isinstance(claim.get("kind"), str)
                    or not claim["kind"].strip()
                ):
                    found.append(
                        _finding(
                            "INVALID_CLAIM_STRUCTURE",
                            "FAIL",
                            row=row,
                            reason=(
                                "A claim must be a typed object with "
                                "a nonempty kind."
                            ),
                        )
                    )
                    continue
                try:
                    text = claim_text(claim, expected)
                    rendered.append(text)
                    if (
                        row["kind"] == "source"
                        and claim.get("kind") in {"source_delta", "no_source_changes"}
                        and claim.get("obligation_id") == identifier
                    ):
                        represents = True
                    if (
                        row["kind"] == "contract"
                        and claim.get("kind") == "ast_relationship"
                        and claim.get("edge_id") == row.get("edge_id")
                    ):
                        represents = True
                    if (
                        row["kind"] == "frontier"
                        and claim.get("kind") == "frontier_resolution"
                        and claim.get("frontier_id") == identifier
                        and replay_assessment is not None
                        and replay_assessment.frontier_statuses.get(identifier)
                        == "PASS"
                        and replay_assessment.frontier_mechanisms.get(identifier)
                        == claim.get("mechanism_id")
                    ):
                        represents = True
                    predicate_results.append(
                        {
                            "obligation_id": identifier,
                            "predicate": claim["kind"],
                            "status": "PASS",
                            "text": text,
                        }
                    )
                except PrdelRefuted as exc:
                    predicate_results.append(
                        {
                            "obligation_id": identifier,
                            "predicate": claim.get("kind"),
                            "status": "FAIL",
                        }
                    )
                    found.append(
                        _finding(
                            "CONTRADICTED_SUPPORTED_CLAIM",
                            "FAIL",
                            row=row,
                            reason=str(exc),
                        )
                    )
                except (PrdelError, KeyError, TypeError, SyntaxError) as exc:
                    unresolved = True
                    predicate_results.append(
                        {
                            "obligation_id": identifier,
                            "predicate": (
                                claim.get("kind") if isinstance(claim, dict) else None
                            ),
                            "status": "UNKNOWN",
                        }
                    )
                    found.append(
                        _finding(
                            "UNSUPPORTED_CLAIM", "UNKNOWN", row=row, reason=str(exc)
                        )
                    )
            if not represents:
                representation_status = "UNKNOWN" if unresolved else "FAIL"
                if row["kind"] == "frontier":
                    replayed_frontier = (
                        replay_assessment.frontier_statuses.get(identifier, "UNKNOWN")
                        if replay_assessment is not None
                        else "UNKNOWN"
                    )
                    representation_status = (
                        "FAIL" if replayed_frontier == "FAIL" else "UNKNOWN"
                    )
                found.append(
                    _finding(
                        "UNREPRESENTED_CHANGE",
                        representation_status,
                        row=row,
                        reason=(
                            "No supported typed claim represents "
                            "this exact source region or "
                            "relationship."
                        ),
                    )
                )
            if type(record["summary"]) is not str or not record["summary"].strip():
                found.append(
                    _finding(
                        "MISSING_REQUIRED_SUMMARY",
                        "FAIL",
                        row=row,
                        reason=(
                            "The required explanation summary is "
                            "empty or has invalid type."
                        ),
                    )
                )
            elif not unresolved and record["summary"] != "\n".join(rendered):
                found.append(
                    _finding(
                        "SUMMARY_RENDERING_MISMATCH",
                        "FAIL",
                        row=row,
                        reason=(
                            "Summary differs from the exact natural "
                            "rendering of the supported claims."
                        ),
                    )
                )
            elif unresolved:
                found.append(
                    _finding(
                        "UNSUPPORTED_NARRATIVE",
                        "UNKNOWN",
                        row=row,
                        reason=(
                            "Summary is not the natural rendering of "
                            "supported claims; nonempty prose is "
                            "insufficient."
                        ),
                    )
                )
            if row["kind"] == "frontier":
                frontier_status = (
                    replay_assessment.frontier_statuses.get(identifier, "UNKNOWN")
                    if replay_assessment is not None
                    else "UNKNOWN"
                )
                if frontier_status != "PASS":
                    found.append(
                        _finding(
                            (
                                "FRONTIER_REPLAY_REFUTED"
                                if frontier_status == "FAIL"
                                else "UNRESOLVED_CONTRACT_BOUNDARY"
                            ),
                            frontier_status,
                            row=row,
                            reason=(
                                "The materialized frontier was not discharged by "
                                "a matching closed-catalogue verifier replay."
                            ),
                        )
                    )
        for identifier in sorted(set(required) - set(observed)):
            found.append(
                _finding(
                    "UNREPRESENTED_CHANGE",
                    "FAIL",
                    row=required[identifier],
                    reason=(
                        "Required changed region or affected "
                        "relationship has no explanation record."
                    ),
                )
            )
        for identifier in sorted(set(requirements) - used_requirements):
            found.append(
                _finding(
                    "UNREPRESENTED_REQUIREMENT",
                    "FAIL",
                    reason=(
                        f"Selected requirement "
                        f"{identifier}"
                        f" has no explanation link."
                    ),
                    question=(
                        "Explain its implementation, unresolved "
                        "state, or explicitly selected retirement."
                    ),
                )
            )
        # Requirement text is independently selected context, not an exemption
        # for a known current claim contradicting retained implementation facts.
        selected_text = "\n".join(requirements.values())
        found.extend(
            _known_contradictions(
                selected_text,
                _snapshot_for_contract(
                    Path(root), expected["binding"]["head"], contract
                ),
            )
        )
        evidence = document["evidence"]
        if type(evidence) is not list:
            raise PrdelError("evidence inventory must be a list")
        if evidence_bytes is not None:
            if expected_evidence_digest != digest(evidence_bytes):
                raise PrdelError(
                    "independently selected evidence digest differs or missing"
                )
            selected = decode(evidence_bytes)
            if (
                set(selected) != {"schema_version", "binding", "evidence"}
                or selected["schema_version"] != "verifier-prdel-evidence-1"
                or selected["binding"] != expected["binding"]
                or selected["evidence"] != evidence
            ):
                raise PrdelError(
                    "selected evidence differs from exact source or carried records"
                )
        elif expected_evidence_digest is not None:
            raise PrdelError("selected evidence bytes missing")
        from verifier.runtime.prdel_coverage import assess_coverage

        # Only retained narrative documentation is eligible for this explicit
        # reduced scope. Unknown languages/configuration never receive a waiver.
        narrative_only = all(
            row["kind"] == "source"
            and (
                row.get("no_change")
                or (
                    row["path"].lower().endswith((".md", ".txt", ".rst"))
                    and PurePosixPath(row["path"]).name.lower()
                    not in {"requirements.txt", "constraints.txt", "cmakelists.txt"}
                    and not row["path"].startswith(".github/workflows/")
                    and row.get("before_mode") in (None, "100644")
                    and row.get("after_mode") in (None, "100644")
                )
            )
            for row in required.values()
        )
        executable = not narrative_only
        coverage_rows = []
        for row in required.values():
            active = (
                ["unit", "integration", "regression", "preventative"]
                if executable
                else []
            )
            reasons = {
                layer: (
                    "Exact selected diff is regular narrative "
                    "documentation or an explicitly empty diff; no "
                    "behavioral clearance is requested."
                )
                for layer in ("unit", "integration", "regression", "preventative")
                if layer not in active
            }
            reasons["base"] = (
                "Base representation is assessed by current "
                "deterministic source predicates; carried "
                "receipts cannot substitute for that replay."
            )
            coverage_rows.append(
                {**row, "required_layers": active, "applicability_reasons": reasons}
            )
        coverage = assess_coverage(
            coverage_rows,
            list(observed.values()),
            evidence,
            expected["binding"],
            replayed_evidence=(
                replay_assessment.results if replay_assessment is not None else ()
            ),
        )
        # Base evidence is produced by the current deterministic predicates, never
        # by a carried PASS field or a candidate-authored test result.
        base_status = _status(found)
        report["predicate_results"] = predicate_results
        report["coverage"] = coverage
        if coverage["execution_authentication"] == "VERIFIER_REPLAYED":
            report["execution_provenance"] = "VERIFIER_REPLAYED_EXACT_HEAD"
        report["coverage"]["base_predicate_status"] = base_status
        for item in coverage["findings"]:
            if item.get("layer") == "base" and item["verdict"] != "FAIL":
                continue
            finding = _finding(
                item["code"],
                item["verdict"],
                row=required.get(item.get("obligation_id")),
                reason=item["question"],
                question=item["question"],
                execution_status=item.get("execution_status"),
            )
            if item.get("layer") is not None:
                finding["layer"] = item["layer"]
            found.append(finding)
        evaluated_obligations = {
            result.get("obligation_id") for result in predicate_results
        }
        coverage["layers"]["base"] = {
            "verdict": base_status,
            "predicate_scope": "EXACT_RETAINED_SOURCE_REPRESENTATION",
            "execution_status": (
                "NOT_RUN" if set(required) - evaluated_obligations else "EXECUTED"
            ),
            "obligations": [
                {
                    "obligation_id": key,
                    "verdict": base_status,
                    "execution_status": (
                        "EXECUTED" if key in evaluated_obligations else "NOT_RUN"
                    ),
                }
                for key in sorted(required)
            ],
        }
        if executable and coverage["execution_authentication"] != "VERIFIER_REPLAYED":
            found.append(
                _finding(
                    "EXECUTED_VALIDATION_NOT_ESTABLISHED",
                    "UNKNOWN",
                    reason=(
                        "Carried test receipts do not independently "
                        "authenticate required execution or "
                        "behavioral correspondence."
                    ),
                    question=(
                        "Run and retain relevant independent unit, "
                        "integration, regression and preventative "
                        "evidence; preserve unsupported dimensions."
                    ),
                )
            )
        current = (_generate_prdel_template(
            Path(root), base, head, requirements_bytes, expected_requirements_digest,
            limits, sharded=True, contract=contract,
            source_bound=(contract == SCHEMA_V2)) if sharded else generator(
            Path(root), base, head, requirements_bytes, expected_requirements_digest,
            limits))
        if current["binding"] != expected["binding"]:
            found.append(
                _finding(
                    "SOURCE_CHANGED_DURING_VALIDATION",
                    "FAIL",
                    reason="Exact source selection moved during validation.",
                )
            )
        report["evaluated_document_digest"] = digest(canonical(document))
    except PrdelUnavailable as exc:
        existing = {(item["code"], item.get("obligation_id")) for item in found}
        found.extend(
            item
            for item in _known_missing_structure(document)
            if (item["code"], item.get("obligation_id")) not in existing
        )
        found.append(_finding("SOURCE_UNAVAILABLE", "UNKNOWN", reason=str(exc)))
        report["status"] = "UNKNOWN"
    except (
        PrdelError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        OverflowError,
    ) as exc:
        found.append(_finding("INVALID_OR_UNAVAILABLE_INPUT", "FAIL", reason=str(exc)))
        report["status"] = "FAIL"
    return _finalize(report)


def evaluate_description(
    body: str,
    root: Path,
    base: str,
    head: str,
    document: dict[str, Any] | None = None,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Evaluate the historical version-one description contract."""
    return _evaluate_description(
        body,
        root,
        base,
        head,
        document,
        requirements_bytes,
        expected_requirements_digest,
        evidence_bytes,
        expected_evidence_digest,
        validator=validate_prdel,
        renderer=render_prdel,
        report_schema=REPORT_SCHEMA,
    )


def evaluate_description_v2(
    body: str,
    root: Path,
    base: str,
    head: str,
    document: dict[str, Any] | None = None,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
    replay_plan_bytes: bytes | None = None,
    expected_replay_plan_digest: str | None = None,
    limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate only an explicitly selected version-two description."""
    return _evaluate_description(
        body,
        root,
        base,
        head,
        document,
        requirements_bytes,
        expected_requirements_digest,
        evidence_bytes,
        expected_evidence_digest,
        replay_plan_bytes,
        expected_replay_plan_digest,
        limits,
        validator=validate_prdel_v2,
        renderer=render_prdel_v2,
        report_schema=REPORT_SCHEMA_V2,
    )


def _evaluate_description(
    body: str,
    root: Path,
    base: str,
    head: str,
    document: dict[str, Any] | None,
    requirements_bytes: bytes | None,
    expected_requirements_digest: str | None,
    evidence_bytes: bytes | None,
    expected_evidence_digest: str | None,
    replay_plan_bytes: bytes | None = None,
    expected_replay_plan_digest: str | None = None,
    limits: dict[str, Any] | None = None,
    *,
    validator: Any,
    renderer: Any,
    report_schema: str,
) -> dict[str, Any]:
    try:
        if type(body) is not str or len(body.encode("utf-8")) > MAX_DESCRIPTION_BYTES:
            raise PrdelError("description byte bound exceeded")
        blocks = re.findall(
            r"^```vstd-prdel[ \t]*\n(.*?)^```[ \t]*$", body, re.MULTILINE | re.DOTALL
        )
        if document is None:
            if len(blocks) != 1:
                missing = _finding(
                    "PRDEL_REPRESENTATION_MISSING",
                    "FAIL",
                    reason=(
                        "Exactly one bound vstd-prdel document is "
                        "required; its known absence fails the "
                        "explanation contract."
                    ),
                    question=(
                        "Generate a PRDEL template, fill supported "
                        "claims and validate the exact selected diff."
                    ),
                    execution_status="NOT_RUN",
                )
                findings = [missing]
                try:
                    findings.extend(
                        _known_contradictions(
                            body,
                            _snapshot_for_contract(
                                Path(root),
                                _revision(Path(root), head),
                                SCHEMA_V2 if report_schema == REPORT_SCHEMA_V2 else SCHEMA,
                            ),
                        )
                    )
                except (PrdelUnavailable, OSError) as exc:
                    findings.append(
                        _finding("SOURCE_UNAVAILABLE", "UNKNOWN", reason=str(exc))
                    )
                return _finalize(
                    {
                        "schema_version": report_schema,
                        "claim_boundary": BOUNDARY,
                        "coverage": {},
                        "findings": findings,
                    }
                )
            document = decode(blocks[0].encode("utf-8"))
        elif len(blocks) > 1 or (
            blocks and decode(blocks[0].encode("utf-8")) != document
        ):
            raise PrdelError(
                "embedded PRDEL differs from the explicitly selected document"
            )
        if len(re.findall(r"^```vstd-prdel\b", body, re.MULTILINE)) != len(blocks):
            raise PrdelError("malformed PRDEL block")
        report = validator(
            document,
            root,
            base,
            head,
            requirements_bytes,
            expected_requirements_digest,
            evidence_bytes,
            expected_evidence_digest,
            *(
                (
                    replay_plan_bytes,
                    expected_replay_plan_digest,
                    limits,
                )
                if report_schema == REPORT_SCHEMA_V2
                else ()
            ),
        )
        # Arbitrary prose outside the exact rendering is not certified by source
        # identities. A caller may use the canonical rendering without the fence.
        outside = re.sub(
            r"^```vstd-prdel[ \t]*\n.*?^```[ \t]*$",
            "",
            body,
            flags=re.MULTILINE | re.DOTALL,
        ).strip()
        expected_body = renderer(document, include_document=False).strip()
        if outside and outside != expected_body:
            report["findings"].append(
                _finding(
                    "UNSUPPORTED_NARRATIVE",
                    "UNKNOWN",
                    reason=(
                        "Additional prose is outside supported "
                        "deterministic claim rendering."
                    ),
                    question=(
                        "Represent the claims with supported "
                        "predicates or retain their semantic status "
                        "as UNKNOWN."
                    ),
                )
            )
            try:
                snapshot = _snapshot_for_contract(
                    Path(root),
                    _revision(Path(root), head),
                    SCHEMA_V2 if report_schema == REPORT_SCHEMA_V2 else SCHEMA,
                )
                report["findings"].extend(
                    _known_contradictions(assertion_text(outside, report), snapshot)
                )
            except (PrdelUnavailable, OSError) as exc:
                report["findings"].append(
                    _finding("SOURCE_UNAVAILABLE", "UNKNOWN", reason=str(exc))
                )
        report["description_digest"] = digest(body.encode("utf-8"))
        return _finalize(report)
    except PrdelUnavailable as exc:
        return _finalize(
            {
                "schema_version": report_schema,
                "status": "UNKNOWN",
                "source_grounding_status": "UNKNOWN",
                "semantic_status": "UNKNOWN",
                "claim_boundary": BOUNDARY,
                "coverage": {},
                "findings": [
                    _finding("SOURCE_UNAVAILABLE", "UNKNOWN", reason=str(exc))
                ],
            }
        )
    except (PrdelError, OSError, ValueError, TypeError, KeyError) as exc:
        return _finalize(
            {
                "schema_version": report_schema,
                "status": "FAIL",
                "source_grounding_status": "UNKNOWN",
                "semantic_status": "UNKNOWN",
                "claim_boundary": BOUNDARY,
                "coverage": {},
                "findings": [
                    _finding("INVALID_OR_UNAVAILABLE_INPUT", "FAIL", reason=str(exc))
                ],
            }
        )


def render_prdel(
    document: dict[str, Any],
    report: dict[str, Any] | None = None,
    *,
    include_document: bool = True,
) -> str:
    """Render the historical version-one document."""
    return _render_prdel(
        document,
        report,
        include_document=include_document,
        contract=SCHEMA,
    )


def render_prdel_v2(
    document: dict[str, Any],
    report: dict[str, Any] | None = None,
    *,
    include_document: bool = True,
) -> str:
    """Render only an explicitly versioned source-bound document."""
    return _render_prdel(
        document,
        report,
        include_document=include_document,
        contract=SCHEMA_V2,
    )


def _render_prdel(
    document: dict[str, Any],
    report: dict[str, Any] | None,
    *,
    include_document: bool,
    contract: str,
) -> str:
    if type(document) is not dict or document.get("schema_version") != contract:
        raise PrdelError("unsupported PRDEL render input")
    binding = document["binding"]
    lines = [
        "# Source-bound change explanation",
        "",
        "## Coordinate",
        "",
        f"Current head: `{binding['head']}`",
        f"Base: `{binding['base']}`",
        "",
        BOUNDARY,
        "",
    ]
    by_id = {row["id"]: row for row in document["source_obligations"]}
    for record in document["records"]:
        row = by_id.get(record["id"], {})
        lines += [
            "## " + _quoted(row.get("path", record["id"])),
            "",
            "Selected rationale: "
            + _quoted(record.get("why", {}).get("quote") or "UNRESOLVED"),
            "",
            record.get("summary") or "Explanation: UNRESOLVED",
            "",
            "Limits: "
            + "; ".join(
                (
                    LIMITS.get(x, "UNRESOLVED: unsupported exclusion")
                    if type(x) is str
                    else "UNRESOLVED: invalid exclusion"
                )
                for x in (record.get("limits") or ["UNRESOLVED"])
            ),
            "",
        ]
    if report is not None:
        lines += [
            "## Remaining obligations",
            "",
            "Evaluation status: " + report["status"],
            "",
        ]
        for finding in report["findings"]:
            lines.append(
                f"- {finding['code']}: {finding['reason']} {finding['question']}"
            )
    if include_document:
        lines += ["", "```vstd-prdel", canonical(document).decode("utf-8"), "```"]
    return "\n".join(lines).rstrip() + "\n"


def render_impact_mermaid(document: dict[str, Any]) -> str:
    graph = document["impact_graph"]
    lines = ["flowchart LR"]
    components = graph.get("components", [])
    identifiers = {row["id"]: f"c{index}" for index, row in enumerate(components)}
    nodes = {row["id"]: row for row in graph.get("nodes", [])}
    edges = {row["id"]: row for row in graph.get("edges", [])}

    def safe_label(value: str) -> str:
        return "".join(
            char if re.fullmatch(r"[\w .:/()-]", char) else f"&#{ord(char)};"
            for char in value[:240]
        )

    for row in components:
        labels = [
            str(nodes[key].get("side"))
            + " "
            + str(nodes[key].get("path"))
            + "::"
            + str(nodes[key].get("symbol"))
            for key in row["members"][:3]
            if key in nodes
        ]
        label = safe_label(
            " | ".join(labels)
            + (
                f" ({len(row['members'])} nodes; SCC)"
                if len(row["members"]) > 1
                else ""
            )
        )
        lines.append(f'  {identifiers[row["id"]]}["{label}"]')
    for edge in graph.get("dag_edges", []):
        if edge["source"] in identifiers and edge["target"] in identifiers:
            label = safe_label(
                "; ".join(
                    sorted(
                        {
                            str(edges[key].get("side"))
                            + " "
                            + str(edges[key].get("relationship"))
                            + " "
                            + str(edges[key].get("evidence_state"))
                            for key in edge.get("edge_ids", [])
                            if key in edges
                        }
                    )
                )
            )
            lines.append(
                (
                    f"  "
                    f"{identifiers[edge['source']]}"
                    f' -->|"'
                    f"{label}"
                    f'"| '
                    f"{identifiers[edge['target']]}"
                )
            )
    if graph.get("frontier"):
        lines.append(
            '  frontier["Unresolved analysis frontier; see exact graph evidence"]'
        )
    return "\n".join(lines) + "\n"
