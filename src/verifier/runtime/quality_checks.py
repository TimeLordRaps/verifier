"""Opt-in, check-only quality application profiles for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) policy bytes are independently selected by the
caller using Secure Hash Algorithm 256-bit (SHA-256). Managed Python comments,
or admitted Ruff/Black adapters, establish only their declared formatting checks.
They do not establish authored meaning, runtime correctness, authenticity or a
sandbox. No source fixes, package installation or candidate commands are offered.
Diagnostics use Unicode Transformation Format, 8-bit (UTF-8); Tom's Obvious
Minimal Language (TOML) project configuration is disabled for tool adapters.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys
import sysconfig
import time
import tokenize
from typing import Any

from verifier.runtime.gate_pipeline import _command

PROFILE = "verifier-quality-profile-1"
REPORT = "verifier-quality-report-1"
STAGES = ("comment-format", "lint", "pretty-format")
MAX_BYTES = 16 * 1024 * 1024
MAX_FILES = 1024
BOUNDARY = (
    "Selected formatting checks on exact retained bytes only; no authored meaning, "
    "behavioral correctness, execution authenticity or sandbox. Tool dependencies "
    "outside the selected distribution and inherited environment are not bound."
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(
    r"# vstd-explanation: (begin|end) ([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\Z"
)


class _Invalid(ValueError):
    """Known unmet selected contract."""


class _Unavailable(OSError):
    """Observation or supported semantics unavailable."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Invalid("duplicate JSON key")
        result[key] = value
    return result


def _object(value: Any, fields: str) -> None:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise _Invalid("unknown or missing fields")


def _json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise _Invalid("selected JSON bytes required within byte bound")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                _Invalid("nonfinite number")
            ),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise _Invalid("invalid selected JSON") from exc
    if type(value) is not dict:
        raise _Invalid("selected JSON object required")
    return value


def _relative(root: Path, name: Any) -> Path:
    if (
        type(name) is not str
        or not name
        or len(name) > 4096
        or any(
            ord(char) < 32 or ord(char) == 127 or char in '\\<>:"|?*' for char in name
        )
        or name.startswith("/")
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise _Invalid("portable relative file path required")
    current = root
    for part in name.split("/"):
        if part.endswith((" ", ".")) or part.split(".")[0].upper() in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *["COM" + str(n) for n in range(1, 10)],
            *["LPT" + str(n) for n in range(1, 10)],
        }:
            raise _Invalid("portable path component required")
        current /= part
        if current.is_symlink() or (
            hasattr(current, "is_junction") and current.is_junction()
        ):
            raise _Invalid("linked source/config paths unsupported")
    resolved = current.resolve()
    if root not in resolved.parents:
        raise _Invalid("path outside selected root")
    return resolved


def _read(path: Path, maximum: int = MAX_BYTES) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise _Invalid("selected regular file missing or unsupported")
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
    except FileNotFoundError as exc:
        raise _Invalid("selected regular file missing") from exc
    except OSError as exc:
        raise _Unavailable("selected file observation unavailable") from exc
    if len(raw) > maximum:
        raise _Unavailable("selected file exceeds analysis byte bound")
    return raw


def _inventory(
    root: Path, names: list[str]
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows, contents, total = [], {}, 0
    for name in sorted(names):
        raw = _read(_relative(root, name))
        total += len(raw)
        if total > MAX_BYTES:
            raise _Unavailable("selected source total exceeds analysis byte bound")
        rows.append({"path": name, "size_bytes": len(raw), "digest": _digest(raw)})
        contents[name] = raw
    return rows, contents


def _root(root: str | Path) -> Path:
    selected = Path(root).absolute()
    for path in [*reversed(selected.parents), selected]:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise _Invalid("linked selected root or ancestor unsupported")
    selected = selected.resolve()
    if not selected.is_dir():
        raise _Invalid("selected root directory missing")
    return selected


def _profile(raw: bytes, expected: str | None) -> dict[str, Any]:
    if (
        type(expected) is not str
        or not _DIGEST.fullmatch(expected)
        or _digest(raw) != expected
    ):
        raise _Invalid("independently selected profile digest missing or mismatched")
    value = _json(raw)
    _object(value, "schema_version sources stages timeout_seconds max_output_bytes")
    if value["schema_version"] != PROFILE:
        raise _Invalid("unsupported quality profile version")
    sources = value["sources"]
    if (
        type(sources) is not list
        or not 1 <= len(sources) <= MAX_FILES
        or any(type(name) is not str for name in sources)
        or len({name.casefold() for name in sources}) != len(sources)
    ):
        raise _Invalid("unique nonempty selected source paths required")
    timeout = value["timeout_seconds"]
    if (
        type(timeout) not in (int, float)
        or not math.isfinite(timeout)
        or not 0.05 <= timeout <= 60
    ):
        raise _Invalid("timeout must be finite and 0.05 through 60 seconds per stage")
    if (
        type(value["max_output_bytes"]) is not int
        or not 1 <= value["max_output_bytes"] <= 1048576
    ):
        raise _Invalid("output bound must be 1 through 1048576 bytes")
    stages = value["stages"]
    if type(stages) is not list or len(stages) != 3:
        raise _Invalid("all three quality stage selections required")
    ids = []
    for stage in stages:
        _object(stage, "id selected required backend tool config")
        stage_id = stage["id"]
        if type(stage_id) is not str or stage_id not in STAGES or stage_id in ids:
            raise _Invalid("unknown or duplicate quality stage")
        ids.append(stage_id)
        if type(stage["selected"]) is not bool or type(stage["required"]) is not bool:
            raise _Invalid("boolean selection and requirement required")
        if not stage["selected"]:
            if stage["required"] or any(
                stage[key] is not None for key in ("backend", "tool", "config")
            ):
                raise _Invalid("required stage cannot be not selected")
        elif stage_id == "comment-format":
            if (
                stage["backend"] != "builtin-managed-python-comments-1"
                or stage["tool"] is not None
                or stage["config"] is not None
            ):
                raise _Invalid(
                    "only builtin managed Python comments supported for comment-format"
                )
        else:
            if stage["backend"] != {"lint": "ruff", "pretty-format": "black"}[stage_id]:
                raise _Invalid("unapproved quality backend")
            _object(stage["tool"], "version interpreter_digest distribution_digest")
            if (
                type(stage["tool"]["version"]) is not str
                or not 1 <= len(stage["tool"]["version"]) <= 128
            ):
                raise _Invalid("exact tool version required")
            for key in ("interpreter_digest", "distribution_digest"):
                if type(stage["tool"][key]) is not str or not _DIGEST.fullmatch(
                    stage["tool"][key]
                ):
                    raise _Invalid("exact tool digest required")
            _object(stage["config"], "path digest")
            if type(stage["config"]["digest"]) is not str or not _DIGEST.fullmatch(
                stage["config"]["digest"]
            ):
                raise _Invalid("exact configuration digest required")
    return value


def _definitions(
    value: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if value is None:
        return None, None
    # Shared strict validation is imported only when this optional binding is selected.
    from verifier.runtime.explanation_projection import (
        canonical_definitions,
        load_definitions,
    )

    raw = canonical_definitions(value)
    parsed = load_definitions(raw)
    return {row["id"]: row for row in parsed["definitions"]}, _digest(raw)


def _comments(
    contents: dict[str, bytes], definitions: dict[str, Any] | None
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, raw in sorted(contents.items()):
        if not name.endswith(".py"):
            raise _Unavailable(
                "managed-comment checker supports selected Python files only"
            )
        if len(raw) > 512 * 1024:
            raise _Unavailable(
                "managed-comment Python file exceeds token analysis byte bound"
            )
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            text = raw.decode(encoding)
            lines = [line.removesuffix("\r") for line in text.split("\n")]
            comments = list(tokenize.generate_tokens(io.StringIO(text).readline))
        except (
            UnicodeError,
            tokenize.TokenError,
            IndentationError,
            SyntaxError,
        ) as exc:
            raise _Unavailable(
                "selected Python comment structure cannot be tokenized"
            ) from exc
        active: tuple[str, int, str] | None = None
        for token in comments:
            if token.type != tokenize.COMMENT or not token.string.startswith(
                "# vstd-explanation:"
            ):
                continue
            line, column = token.start
            marker = _MARKER.fullmatch(token.string)
            prefix = lines[line - 1][:column]
            if marker is None or prefix.strip() or len(lines[line - 1]) > 512:
                findings.append(
                    {"code": "INVALID_MANAGED_MARKER", "path": name, "line": line}
                )
                continue
            direction, identifier = marker.groups()
            if direction == "begin":
                if active is not None or identifier in seen:
                    findings.append(
                        {
                            "code": "NESTED_OR_DUPLICATE_MANAGED_ID",
                            "path": name,
                            "line": line,
                        }
                    )
                if definitions is not None and (
                    identifier not in definitions
                    or definitions[identifier]["target"]["path"] != name
                ):
                    findings.append(
                        {
                            "code": "UNKNOWN_OR_MISBOUND_MANAGED_ID",
                            "path": name,
                            "line": line,
                        }
                    )
                seen.add(identifier)
                active = identifier, line, prefix
            elif active is None or active[0] != identifier or active[2] != prefix:
                findings.append(
                    {"code": "UNMATCHED_MANAGED_END", "path": name, "line": line}
                )
            else:
                _, start, indent = active
                if line == start + 1:
                    findings.append(
                        {
                            "code": "EMPTY_MANAGED_COMMENT_BLOCK",
                            "path": name,
                            "line": start,
                        }
                    )
                if line - start > 256:
                    findings.append(
                        {
                            "code": "MANAGED_BLOCK_BOUND_EXCEEDED",
                            "path": name,
                            "line": start,
                        }
                    )
                for interior in range(start + 1, line):
                    rendered = lines[interior - 1]
                    if (
                        not rendered.startswith(indent + "# ")
                        or len(rendered) > 512
                        or any(
                            ord(character) < 32
                            or ord(character) == 127
                            or character in "\u0085\u2028\u2029"
                            for character in rendered[len(indent) :]
                        )
                    ):
                        findings.append(
                            {
                                "code": "INVALID_MANAGED_COMMENT_LINE",
                                "path": name,
                                "line": interior,
                            }
                        )
                active = None
        if active is not None:
            findings.append(
                {"code": "UNTERMINATED_MANAGED_BLOCK", "path": name, "line": active[1]}
            )
    return findings


def _distribution_locations() -> tuple[Path, ...]:
    """Return the finite interpreter-owned roots admitted for quality tools."""
    values = {
        value
        for value in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib"))
        if value
    }
    return tuple(sorted((Path(value).resolve() for value in values), key=str))


def _metadata_value(raw: bytes, field: str) -> str:
    """Read one unfolded core-metadata field without loading distribution code."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Unavailable("tool distribution metadata is not UTF-8") from exc
    values: list[str] = []
    active: list[str] | None = None
    for line in text.splitlines():
        if not line:
            break
        if line[:1] in {" ", "\t"}:
            if active is not None:
                active.append(line.strip())
                values[-1] = " ".join(active)
            continue
        name, separator, value = line.partition(":")
        active = None
        if separator and name.lower() == field.lower():
            active = [value.strip()]
            values.append(" ".join(active))
    if len(values) != 1 or not values[0]:
        raise _Unavailable(f"tool distribution {field.lower()} unavailable or ambiguous")
    return values[0]


def _record_paths(raw: bytes) -> tuple[PurePosixPath, ...]:
    """Parse a bounded wheel RECORD as paths; recorded hashes are not trusted."""
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise _Unavailable("tool distribution RECORD unavailable") from exc
    if not rows or len(rows) > MAX_FILES:
        raise _Unavailable("tool distribution file count bound exceeded")
    result: list[PurePosixPath] = []
    for row in rows:
        if len(row) != 3 or not row[0] or "\x00" in row[0]:
            raise _Unavailable("tool distribution RECORD invalid")
        entry = PurePosixPath(row[0])
        if entry.is_absolute() or not entry.parts:
            raise _Unavailable("tool distribution RECORD path invalid")
        result.append(entry)
    return tuple(result)


def _installed_distributions(backend: str) -> tuple[dict[str, Any], ...]:
    """Discover exact installed distributions from direct ``.dist-info`` data.

    This deliberately does not invoke package finders, entry points, import hooks,
    or subject code.  Only direct children of the interpreter's two configured
    package roots are considered, and every admitted file is read later.
    """
    candidates: list[dict[str, Any]] = []
    inspected = 0
    for base in _distribution_locations():
        if not base.is_dir():
            continue
        for info in sorted(base.glob("*.dist-info"), key=lambda path: path.name):
            inspected += 1
            if inspected > 4096:
                raise _Unavailable("tool distribution directory bound exceeded")
            if info.is_symlink() or (
                hasattr(info, "is_junction") and info.is_junction()
            ):
                raise _Invalid("linked tool distribution directory unsupported")
            metadata = _read(info / "METADATA", 1024 * 1024)
            if _metadata_value(metadata, "Name").lower() != backend:
                continue
            candidates.append(
                {
                    "base": base,
                    "version": _metadata_value(metadata, "Version"),
                    "files": _record_paths(_read(info / "RECORD", 16 * 1024 * 1024)),
                }
            )
            if len(candidates) > 4:
                raise _Unavailable("tool distribution discovery bound exceeded")
    return tuple(candidates)


def _tool_identity(backend: str, root: Path) -> dict[str, Any]:
    interpreter = Path(sys.executable).resolve()
    try:
        interpreter_digest = _digest(_read(interpreter))
        candidates = list(_installed_distributions(backend))
        if len(candidates) != 1:
            raise _Unavailable("admitted tool distribution unavailable or ambiguous")
        dist = candidates[0]
        base = dist["base"]
        if base == root or root in base.parents:
            raise _Invalid("candidate root cannot supply tool distribution")
        rows, total = [], 0
        for entry in sorted(dist["files"], key=str):
            located = base.joinpath(*entry.parts)
            target = located.resolve()
            if located.is_symlink():
                raise _Invalid("linked tool distribution files unsupported")
            # Console wrappers are not used: isolated interpreter invokes the module.
            if base not in target.parents:
                if str(entry).replace("\\", "/").startswith(backend + "/"):
                    raise _Invalid("tool module file outside installed distribution")
                continue
            for parent in located.parents:
                if parent.resolve() == base:
                    break
                if parent.is_symlink() or (
                    hasattr(parent, "is_junction") and parent.is_junction()
                ):
                    raise _Invalid("linked tool distribution directory unsupported")
            raw = _read(target, 128 * 1024 * 1024)
            total += len(raw)
            if len(rows) >= MAX_FILES or total > 128 * 1024 * 1024:
                raise _Unavailable("tool distribution inventory bound exceeded")
            rows.append(
                {
                    "path": target.relative_to(base).as_posix(),
                    "digest": _digest(raw),
                    "size_bytes": len(raw),
                }
            )
        if not rows or not any(row["path"].startswith(backend + "/") for row in rows):
            raise _Unavailable("tool module inventory unavailable")
        return {
            "backend": backend,
            "version": dist["version"],
            "interpreter": str(interpreter),
            "interpreter_digest": interpreter_digest,
            "distribution_digest": _digest(_canonical(rows)),
            "distribution_files": len(rows),
            "invocation": "isolated Python module, check-only",
        }
    except OSError as exc:
        raise _Unavailable("tool identity observation unavailable") from exc


def _configuration(
    root: Path, stage: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = stage["config"]
    raw = _read(_relative(root, selected["path"]))
    digest = _digest(raw)
    if digest != selected["digest"]:
        raise _Invalid("selected configuration digest mismatch")
    value = _json(raw)
    keys = "schema_version line_length" + (
        " select" if stage["backend"] == "ruff" else ""
    )
    _object(value, keys)
    if value["schema_version"] != "verifier-quality-tool-config-1":
        raise _Invalid("unsupported quality configuration version")
    if type(value["line_length"]) is not int or not 40 <= value["line_length"] <= 320:
        raise _Invalid("line length must be 40 through 320")
    if stage["backend"] == "ruff":
        codes = value["select"]
        if (
            type(codes) is not list
            or not 1 <= len(codes) <= 64
            or any(
                type(code) is not str or not re.fullmatch(r"[A-Z]{1,5}[0-9]{0,4}", code)
                for code in codes
            )
            or len(set(codes)) != len(codes)
        ):
            raise _Invalid("unique supported lint selector tokens required")
    return value, {"path": selected["path"], "digest": digest, "size_bytes": len(raw)}


def _argv(
    stage: dict[str, Any], config: dict[str, Any], root: Path, names: list[str]
) -> list[str]:
    prefix = [sys.executable, "-I", "-B", "-m", stage["backend"]]
    if stage["backend"] == "ruff":
        options = [
            "check",
            "--isolated",
            "--no-cache",
            "--no-fix",
            "--output-format",
            "json",
            "--line-length",
            str(config["line_length"]),
            "--select",
            ",".join(sorted(config["select"])),
        ]
    else:
        # Suppress project configuration discovery with an explicit empty file.
        # Black's TOML discovery is disabled by an existing safe empty config: the
        # adapter JSON is not passed as a third-party configuration file.
        options = [
            "--check",
            "--no-cache",
            "--workers",
            "1",
            "--line-length",
            str(config["line_length"]),
        ]
        # Black still discovers pyproject.toml unless --config is explicit. A
        # null-device configuration has empty bytes and cannot carry project hooks.
        options.extend(["--config", os.devnull])
    return (
        prefix
        + options
        + ["--"]
        + [str(_relative(root, name)) for name in sorted(names)]
    )


def _producer_verdict(
    stage: dict[str, Any],
    result: dict[str, Any],
    root: Path,
    names: list[str],
    config: dict[str, Any],
) -> tuple[str, int | None]:
    """Recognize bounded tool protocols; nonzero exits alone are not violations."""
    code = result["exit_code"]
    if code not in {0, 1} or result["status"] != ("PASS" if code == 0 else "FAIL"):
        return "UNKNOWN", None
    try:
        if stage["backend"] == "ruff":
            diagnostics = json.loads(result["stdout"], object_pairs_hook=_pairs)
            if type(diagnostics) is not list or len(diagnostics) > 4096:
                return "UNKNOWN", None
            selected = {str(_relative(root, name)): name for name in names}
            for finding in diagnostics:
                if (
                    type(finding) is not dict
                    or not {"code", "filename", "location", "message"}.issubset(finding)
                    or set(finding)
                    - {
                        "cell",
                        "code",
                        "end_location",
                        "filename",
                        "fix",
                        "location",
                        "message",
                        "noqa_row",
                        "url",
                    }
                ):
                    return "UNKNOWN", None
                location = finding["location"]
                if (
                    type(location) is not dict
                    or set(location) != {"row", "column"}
                    or any(
                        type(number) is not int or not 1 <= number <= MAX_BYTES
                        for number in location.values()
                    )
                    or type(finding["filename"]) is not str
                    or finding["filename"] not in selected
                    or type(finding["message"]) is not str
                    or not 1 <= len(finding["message"]) <= 8192
                    or type(finding["code"]) is not str
                ):
                    return "UNKNOWN", None
                rule = finding["code"]
                if rule != "invalid-syntax" and (
                    not re.fullmatch(r"[A-Z]{1,5}[0-9]{3,4}", rule)
                    or not any(
                        rule.startswith(selector) or selector == "ALL"
                        for selector in config["select"]
                    )
                ):
                    return "UNKNOWN", None
            count = len(diagnostics)
            return (
                ("PASS", 0)
                if code == 0 and count == 0
                else ("FAIL", count) if code == 1 and count > 0 else ("UNKNOWN", None)
            )
        summary = result["stderr"] + "\n" + result["stdout"]
        if "error:" in summary.lower() or "would fail to reformat" in summary.lower():
            return "UNKNOWN", None
        changed = re.findall(
            r"(?<![0-9])([0-9]+) files? would be reformatted[.,]", summary
        )
        unchanged = re.findall(
            r"(?<![0-9])([0-9]+) files? would be left unchanged[.,]", summary
        )
        if len(changed) > 1 or len(unchanged) > 1 or not (changed or unchanged):
            return "UNKNOWN", None
        changed_count = int(changed[0]) if changed else 0
        unchanged_count = int(unchanged[0]) if unchanged else 0
        if changed_count + unchanged_count != len(names):
            return "UNKNOWN", None
        changed_paths = re.findall(
            r"^would reformat (.+)$", summary, flags=re.MULTILINE
        )
        changed_paths = [path.removesuffix("\r") for path in changed_paths]
        selected_paths = {str(_relative(root, name)) for name in names}
        if (
            len(changed_paths) != changed_count
            or len(set(changed_paths)) != changed_count
            or any(path not in selected_paths for path in changed_paths)
        ):
            return "UNKNOWN", None
        return (
            ("PASS", 0)
            if code == 0 and changed_count == 0
            else (
                ("FAIL", changed_count)
                if code == 1 and changed_count > 0
                else ("UNKNOWN", None)
            )
        )
    except (ValueError, TypeError, RecursionError):
        return "UNKNOWN", None


def _environment() -> dict[str, str]:
    """Fixed adapter environment; candidate metadata supplies no entries."""
    names = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "TEMP", "TMP"}
    result = {
        name: value for name, value in os.environ.items() if name.upper() in names
    }
    result.update({"LANG": "C", "LC_ALL": "C"})
    return result


def _row(stage: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": stage["id"],
        "selected": stage["selected"],
        "required": stage["required"],
        "applicability_status": "SELECTED" if stage["selected"] else "NOT_SELECTED",
        "execution_status": "NOT_RUN" if stage["selected"] else "NOT_SELECTED",
        "status": "FAIL" if stage["selected"] else "NOT_SELECTED",
        "findings": [],
        "tool": None,
        "config": None,
    }


def _finalize(report: dict[str, Any]) -> dict[str, Any]:
    statuses = [report["status"]] + [
        row["status"] for row in report["stages"] if row["selected"]
    ]
    report["status"] = (
        "FAIL" if "FAIL" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
    )
    return report


# vstd-explanation: begin prdel.self.quality-checks
# Authored intent (not verified):
#   Run explicitly selected pinned comment, lint and formatting checks without source
# fixes.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): Check results establish only their selected policy and exact source
# scope.
# vstd-explanation: end prdel.self.quality-checks
def run_quality_profile(
    root: str | Path,
    profile_bytes: bytes | None,
    expected_profile_digest: str | None,
    definitions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run independently admitted checks; never modify source or install tools.

    The caller must choose the profile digest independently of candidate metadata.
    Source paths select scope; the report binds current bytes. Reuse/resume requires
    independently comparing the whole retained binding with current inputs.
    """
    report: dict[str, Any] = {
        "schema_version": REPORT,
        "status": "PASS",
        "claim_boundary": BOUNDARY,
        "profile_digest": None,
        "source_digest": None,
        "sources": [],
        "definitions_digest": None,
        "inputs_unchanged": None,
        "requirements": [],
        "stages": [],
        "findings": [],
    }
    if profile_bytes is None and expected_profile_digest is None:
        report["stages"] = [
            _row({"id": name, "selected": False, "required": False}) for name in STAGES
        ]
        return report
    try:
        if profile_bytes is None:
            raise _Invalid("selected quality profile bytes missing")
        value = _profile(profile_bytes, expected_profile_digest)
        report["profile_digest"] = _digest(profile_bytes)
        report["stages"] = [
            _row(stage)
            for stage in sorted(
                value["stages"], key=lambda item: STAGES.index(item["id"])
            )
        ]
        report["requirements"] = [
            row["id"] for row in report["stages"] if row["required"]
        ]
        selected_root = _root(root)
        inventory, contents = _inventory(selected_root, value["sources"])
        report["sources"] = inventory
        report["source_digest"] = _digest(_canonical(inventory))
        known, definition_digest = _definitions(definitions)
        report["definitions_digest"] = definition_digest
    except (_Invalid, ValueError, TypeError, RecursionError) as exc:
        report["status"] = "FAIL"
        report["findings"].append(
            {
                "code": "QUALITY_CONTRACT_UNMET",
                "detail": str(exc),
                "execution_status": "NOT_RUN",
            }
        )
        return _finalize(report)
    except (OSError, ImportError) as exc:
        report["status"] = "UNKNOWN"
        for row in report["stages"]:
            if row["selected"]:
                row["status"] = "UNKNOWN"
        report["findings"].append(
            {
                "code": "QUALITY_OBSERVATION_UNAVAILABLE",
                "detail": str(exc),
                "execution_status": "NOT_RUN",
            }
        )
        return _finalize(report)
    configurations: dict[str, dict[str, Any]] = {}
    tools: dict[str, dict[str, Any]] = {}
    for row in report["stages"]:
        if not row["selected"]:
            continue
        stage = next(item for item in value["stages"] if item["id"] == row["id"])
        try:
            if row["id"] == "comment-format":
                row["findings"] = _comments(contents, known)
                row["tool"] = {
                    "backend": stage["backend"],
                    "mechanism_digest": _digest(_read(Path(__file__))),
                    "version": "1",
                    "language_scope": "Python tokenize comment tokens only",
                    "format_bounds": {
                        "max_line_characters": 512,
                        "max_block_lines": 256,
                    },
                    "analysis_bounds": {"max_python_file_bytes": 512 * 1024},
                }
                row["status"] = "FAIL" if row["findings"] else "PASS"
                row["execution_status"] = "EXECUTED"
            else:
                config, selected_config = _configuration(selected_root, stage)
                row["config"] = configurations[row["id"]] = selected_config
                tool = _tool_identity(stage["backend"], selected_root)
                row["tool"] = tools[row["id"]] = tool
                if any(
                    tool[key] != stage["tool"][key]
                    for key in ("version", "interpreter_digest", "distribution_digest")
                ):
                    raise _Invalid("selected tool identity mismatch")
                if any(not name.endswith(".py") for name in value["sources"]):
                    raise _Unavailable(
                        "admitted adapters support explicit Python source files only"
                    )
                argv = _argv(stage, config, selected_root, value["sources"])
                environment = _environment()
                result = _command(
                    argv,
                    selected_root,
                    time.monotonic() + value["timeout_seconds"],
                    value["max_output_bytes"],
                    lambda _: None,
                    env=environment,
                )
                row["execution_status"] = "EXECUTED"
                row["invocation"] = argv
                row["observation"] = {
                    key: result[key] for key in ("exit_code", "cleanup")
                }
                row["observation"]["producer_status"] = result["status"]
                row["observation"]["environment_digest"] = _digest(
                    _canonical(environment)
                )
                row["observation"]["environment_names"] = sorted(environment)
                row["observation"]["diagnostic_encoding"] = (
                    "UTF-8 replacement-decoded text, re-encoded for "
                    "digest; raw diagnostics not retained"
                )
                if result["cleanup"] == "NOT_STARTED":
                    row["execution_status"] = "NOT_RUN"
                for channel in ("stdout", "stderr"):
                    raw_output = result[channel].encode("utf-8")
                    row["observation"][channel + "_digest"] = _digest(raw_output)
                    row["observation"][channel + "_bytes"] = len(raw_output)
                row["status"], row["observation"]["finding_count"] = _producer_verdict(
                    stage, result, selected_root, value["sources"], config
                )
                if row["status"] != "PASS":
                    row["findings"].append(
                        {
                            "code": (
                                "QUALITY_CHECK_FAILED"
                                if row["status"] == "FAIL"
                                else "QUALITY_EXECUTION_UNRESOLVED"
                            )
                        }
                    )
        except (_Invalid, ValueError, TypeError) as exc:
            row["status"] = "FAIL"
            row["findings"].append(
                {"code": "QUALITY_CONTRACT_UNMET", "detail": str(exc)}
            )
        except OSError as exc:
            row["status"] = "UNKNOWN"
            row["findings"].append(
                {"code": "QUALITY_OBSERVATION_UNAVAILABLE", "detail": str(exc)}
            )
        except KeyboardInterrupt:
            row["status"] = "UNKNOWN"
            row["execution_status"] = "INTERRUPTED"
            row["findings"].append({"code": "QUALITY_CANCELLED"})
            report["status"] = "UNKNOWN"
            for pending in report["stages"]:
                if pending["selected"] and pending["execution_status"] == "NOT_RUN":
                    pending["status"] = "UNKNOWN"
            break
    try:
        after, _ = _inventory(selected_root, value["sources"])
        unchanged = after == inventory
        for stage_id, config in configurations.items():
            unchanged = (
                unchanged
                and _digest(_read(_relative(selected_root, config["path"])))
                == config["digest"]
            )
        for stage_id, tool in tools.items():
            unchanged = (
                unchanged and _tool_identity(tool["backend"], selected_root) == tool
            )
        report["inputs_unchanged"] = unchanged
        if not unchanged:
            report["status"] = "FAIL"
            report["findings"].append({"code": "QUALITY_INPUT_CHANGED_DURING_CHECK"})
    except (_Invalid, ValueError) as exc:
        report["status"] = "FAIL"
        report["findings"].append({"code": "QUALITY_BINDING_LOST", "detail": str(exc)})
    except OSError as exc:
        report["status"] = "UNKNOWN"
        report["findings"].append(
            {"code": "QUALITY_FINAL_OBSERVATION_UNAVAILABLE", "detail": str(exc)}
        )
    return _finalize(report)
