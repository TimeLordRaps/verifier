"""Preparation-only Verifier Standard (VSTD) workflow.

Pull Request Domain Explanation Language (PRDEL); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); application programming
interface (API); identifier (ID). This module earns no numbered profile, publication
authority,
authenticated execution provenance, or complete behavioral qualification.
Candidate policy selects installed bounded dispatchers, never executable hooks.
Compare-before checks and retained recovery plans do not establish exclusive
filesystem ownership or an atomic transaction across multiple files.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

POLICY_SCHEMA = "verifier-polish-workflow-policy-1"
BUNDLE_SCHEMA = "verifier-polish-preparation-bundle-1"
REPORT_SCHEMA = "verifier-polish-workflow-report-1"
STAGES = (
    {
        "id": "bind-inputs",
        "depends_on": [],
        "description": "Bind admitted source and policy bytes.",
    },
    {
        "id": "validate-definitions",
        "depends_on": ["bind-inputs"],
        "description": "Validate canonical explanation definitions.",
    },
    {
        "id": "project-comments",
        "depends_on": ["validate-definitions"],
        "description": "Stage managed comment projections.",
    },
    {
        "id": "compile-explanations",
        "depends_on": ["bind-inputs", "validate-definitions"],
        "description": "Compile exact committed source facts into explanations.",
    },
    {
        "id": "quality",
        "depends_on": ["bind-inputs", "project-comments"],
        "description": "Run independently selected optional quality checks.",
    },
    {
        "id": "retain-bundle",
        "depends_on": ["bind-inputs"],
        "description": "Retain an immutable preparation bundle without publication.",
    },
)
MAX_RECORD_BYTES = 64 * 1024 * 1024
BOUNDARY = (
    "Declared local preparation only. No publication, execution authenticity, "
    "complete behavioral qualification, or polished nine-tier artifact issuance."
)


class WorkflowError(ValueError):
    """A known preparation contract violation."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowError("duplicate JSON key")
        result[key] = value
    return result


def _record(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        raise WorkflowError("record byte bound exceeded")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                WorkflowError("nonfinite JSON")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WorkflowError("invalid JSON") from exc
    if type(value) is not dict:
        raise WorkflowError("JSON object required")
    return value


def _keys(value: Any, names: str) -> None:
    if type(value) is not dict or set(value) != set(names.split()):
        raise WorkflowError("unknown or missing fields")


def _pin(raw: bytes | None, expected: str | None, name: str) -> str | None:
    if raw is None and expected is None:
        return None
    if raw is None or expected is None:
        raise WorkflowError(name + " requires independently selected bytes and digest")
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        raise WorkflowError(name + " byte bound exceeded")
    actual = digest(raw)
    if type(expected) is not str or expected.removeprefix("sha256:") != actual:
        raise WorkflowError(name + " digest mismatch")
    return actual


def _name(name: Any) -> str:
    if (
        type(name) is not str
        or not name
        or len(name) > 4096
        or any(c in name for c in '\\<>:"|?*')
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or name.startswith("/")
    ):
        raise WorkflowError("portable relative path required")
    for part in name.split("/"):
        if part in {"", ".", ".."} or part.rstrip(". ") != part:
            raise WorkflowError("escaping or ambiguous path")
        stem = part.split(".", 1)[0].casefold()
        if (
            stem
            in {
                ".git",
                "con",
                "prn",
                "aux",
                "nul",
                *("com" + str(i) for i in range(1, 10)),
                *("lpt" + str(i) for i in range(1, 10)),
            }
            or part.casefold() == ".git"
        ):
            raise WorkflowError("reserved source path")
    return name


def _ordinary(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise WorkflowError("linked paths refused")
    return info


def _read(path: Path, maximum: int = MAX_RECORD_BYTES) -> bytes:
    info = _ordinary(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkflowError("ordinary non-aliased input file required")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise WorkflowError("input file byte bound exceeded")
    return raw


def _root(path: str | Path) -> Path:
    result = Path(path).absolute()
    for parent in (result, *result.parents):
        _ordinary(parent)
    if not stat.S_ISDIR(_ordinary(result).st_mode):
        raise WorkflowError("ordinary source directory required")
    return result.resolve()


def _target(root: Path, name: str) -> Path:
    selected = root
    for part in _name(name).split("/"):
        selected = selected / part
        _ordinary(selected)
    if root not in selected.resolve().parents:
        raise WorkflowError("escaping source path")
    return selected


def _outside(root: Path, path: str | Path) -> Path:
    result = Path(path).absolute()
    for parent in (result, *result.parents):
        if parent.exists() or parent.is_symlink():
            _ordinary(parent)
    resolved = result.resolve()
    if resolved == root or root in resolved.parents:
        raise WorkflowError("output must be outside selected source root")
    return result


def load_policy(raw: bytes, expected_digest: str) -> dict[str, Any]:
    """Validate a separately selected closed policy and its dependency graph."""
    _pin(raw, expected_digest, "policy")
    value = _record(raw)
    _keys(value, "schema_version input_paths stages bounds")
    if value["schema_version"] != POLICY_SCHEMA:
        raise WorkflowError("unsupported workflow policy")
    _keys(value["bounds"], "max_files max_file_bytes max_total_bytes")
    for key, maximum in (
        ("max_files", 1024),
        ("max_file_bytes", 4 * 1024 * 1024),
        ("max_total_bytes", 64 * 1024 * 1024),
    ):
        if (
            type(value["bounds"][key]) is not int
            or not 1 <= value["bounds"][key] <= maximum
        ):
            raise WorkflowError("invalid finite bound")
    paths = value["input_paths"]
    if type(paths) is not list or not 1 <= len(paths) <= value["bounds"]["max_files"]:
        raise WorkflowError("nonempty bounded input paths required")
    for path in paths:
        _name(path)
    if len({p.casefold() for p in paths}) != len(paths):
        raise WorkflowError("duplicate or case-ambiguous input path")
    rows = value["stages"]
    if type(rows) is not list or not 1 <= len(rows) <= len(STAGES):
        raise WorkflowError("bounded stages required")
    declared = {row["id"]: row for row in STAGES}
    admitted: dict[str, dict[str, Any]] = {}
    for row in rows:
        _keys(row, "id selected required depends_on")
        if (
            type(row["id"]) is not str
            or row["id"] not in declared
            or row["id"] in admitted
        ):
            raise WorkflowError(
                "unknown or duplicate stage; publication is unsupported"
            )
        if type(row["selected"]) is not bool or type(row["required"]) is not bool:
            raise WorkflowError("boolean stage selection required")
        if row["required"] and not row["selected"]:
            raise WorkflowError("required stage cannot be deselected")
        deps = row["depends_on"]
        if (
            type(deps) is not list
            or any(type(dep) is not str or dep not in declared for dep in deps)
            or len(set(deps)) != len(deps)
        ):
            raise WorkflowError("invalid stage dependencies")
        admitted[row["id"]] = row
    if "bind-inputs" not in admitted or not admitted["bind-inputs"]["required"]:
        raise WorkflowError("input binding is mandatory")
    for stage_id, row in admitted.items():
        if any(dep not in admitted for dep in row["depends_on"]):
            raise WorkflowError("missing prerequisite stage")
        if row["selected"]:
            # Structural prerequisites are fixed by installed dispatchers; optional
            # projection may be explicitly deselected, without defeating binding.
            for dep in declared[stage_id]["depends_on"]:
                if dep not in row["depends_on"]:
                    raise WorkflowError("installed prerequisite omitted")
            if any(
                not admitted[dep]["selected"] and admitted[dep]["required"]
                for dep in row["depends_on"]
            ):
                raise WorkflowError("required prerequisite deselected")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(stage_id: str) -> None:
        if stage_id in visiting:
            raise WorkflowError("cyclic stage dependencies")
        if stage_id in visited:
            return
        visiting.add(stage_id)
        for dep in admitted[stage_id]["depends_on"]:
            visit(dep)
        visiting.remove(stage_id)
        visited.add(stage_id)

    for stage_id in admitted:
        visit(stage_id)
    return value


def _capture(root: Path, policy: dict[str, Any]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    for name in sorted(policy["input_paths"]):
        target = _target(root, name)
        info = _ordinary(target)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise WorkflowError("ordinary non-aliased source file required")
        maximum = min(
            policy["bounds"]["max_file_bytes"],
            policy["bounds"]["max_total_bytes"] - total,
        )
        with target.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise WorkflowError("source byte bound exceeded")
        files[name] = raw
        total += len(raw)
    return files


def _modes(root: Path, policy: dict[str, Any]) -> dict[str, int]:
    return {
        name: stat.S_IMODE(_ordinary(_target(root, name)).st_mode)
        for name in sorted(policy["input_paths"])
    }


def inventory(files: dict[str, bytes]) -> dict[str, Any]:
    rows = [
        {"path": name, "sha256": digest(raw), "size_bytes": len(raw)}
        for name, raw in sorted(files.items())
    ]
    return {"sha256": digest(canonical(rows)), "files": rows}


def _implementation() -> dict[str, Any]:
    paths = (
        "polish_workflow.py",
        "explanation_projection.py",
        "prdel_rules.py",
        "prdel.py",
        "prdel_graph.py",
        "prdel_coverage.py",
        "quality_checks.py",
        "gate_pipeline.py",
        "gate.py",
    )
    directory = Path(__file__).parent
    return {
        "mechanisms": {
            name: (
                digest((directory / name).read_bytes())
                if (directory / name).is_file()
                else None
            )
            for name in paths
        },
        "python_version": sys.version,
        "interpreter_sha256": digest(Path(sys.executable).read_bytes()),
        "platform": sys.platform,
    }


def _stage_order(policy: dict[str, Any]) -> list[dict[str, Any]]:
    rows = {row["id"]: row for row in policy["stages"]}
    ordered: list[dict[str, Any]] = []
    visited: set[str] = set()

    def visit(stage_id: str) -> None:
        if stage_id in visited:
            return
        for dep in sorted(rows[stage_id]["depends_on"]):
            visit(dep)
        visited.add(stage_id)
        ordered.append(rows[stage_id])

    for declaration in STAGES:
        if declaration["id"] in rows:
            visit(declaration["id"])
    return ordered


def _status(findings: list[dict[str, Any]]) -> str:
    return (
        "FAIL"
        if any(f["status"] == "FAIL" for f in findings)
        else "UNKNOWN" if findings else "PASS"
    )


def _event(output: Path, event: dict[str, Any]) -> Path:
    """Append a local journal event; a hash chain is not witnessed chronology."""
    journal = output / "journal"
    journal.mkdir(parents=True, exist_ok=True)
    _ordinary(journal)
    entries = []
    for entry in journal.glob("*.json"):
        entries.append(entry)
        if len(entries) >= 1000:
            raise WorkflowError("journal event bound exceeded")
    entries.sort()
    previous = None
    for index, entry in enumerate(entries, 1):
        if entry.name != f"{index:06d}.json":
            raise WorkflowError("journal sequence mismatch")
        _ordinary(entry)
        value = _record(_read(entry, 1024 * 1024))
        carried = value.pop("event_digest", None)
        if value.get("previous") != previous or digest(canonical(value)) != carried:
            raise WorkflowError("journal chain mismatch")
        previous = carried
    value = {
        "schema_version": "verifier-polish-local-journal-1",
        "previous": previous,
        **event,
    }
    value["event_digest"] = digest(canonical(value))
    target = journal / f"{len(entries) + 1:06d}.json"
    with target.open("xb") as stream:
        stream.write(canonical(value) + b"\n")
    return target


def _retain(output: Path, manifest: dict[str, Any], payload: dict[str, bytes]) -> Path:
    bundle_id = digest(canonical(manifest))
    destination = output / "bundles" / bundle_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    _ordinary(destination.parent)
    if destination.exists():
        if not stat.S_ISDIR(_ordinary(destination).st_mode):
            raise WorkflowError("bundle identity already occupied")
        expected = {"manifest.json": canonical(manifest) + b"\n", **payload}
        actual: dict[str, bytes] = {}
        entries = 0
        total = 0
        for path in destination.rglob("*"):
            entries += 1
            if entries > 4096:
                raise WorkflowError("retained bundle entry bound exceeded")
            info = _ordinary(path)
            if stat.S_ISREG(info.st_mode):
                raw = _read(path)
                total += len(raw)
                if total > 128 * 1024 * 1024:
                    raise WorkflowError("retained bundle byte bound exceeded")
                actual[path.relative_to(destination).as_posix()] = raw
            elif not stat.S_ISDIR(info.st_mode):
                raise WorkflowError("nonordinary retained bundle")
        if actual != expected:
            raise WorkflowError("immutable bundle identity has different bytes")
        return destination
    # Populate a private directory and rename once; no partial bundle gets its ID.
    temporary = Path(tempfile.mkdtemp(prefix=".preparation-", dir=destination.parent))
    try:
        for name, raw in {
            "manifest.json": canonical(manifest) + b"\n",
            **payload,
        }.items():
            target = temporary / _name(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)
        temporary.rename(destination)
    finally:
        if temporary.exists():
            # Every path was created above beneath this checked private directory.
            for path in sorted(
                temporary.rglob("*"), key=lambda p: len(p.parts), reverse=True
            ):
                path.unlink() if path.is_file() else path.rmdir()
            temporary.rmdir()
    return destination


def _retain_attempt(output: Path, report: dict[str, Any]) -> None:
    directory = output / "attempts"
    directory.mkdir(parents=True, exist_ok=True)
    _ordinary(directory)
    target = directory / (report["report_digest"] + ".json")
    raw = canonical(report) + b"\n"
    if len(raw) > MAX_RECORD_BYTES:
        raise WorkflowError("attempt output byte bound exceeded")
    if target.exists():
        _ordinary(target)
        if _read(target) != raw:
            raise WorkflowError("immutable attempt identity occupied")
    else:
        with target.open("xb") as stream:
            stream.write(raw)


def render_prepared_description(
    files: dict[str, bytes], definitions: dict[str, Any] | None
) -> str:
    """Project authored definitions and final selected byte facts without a future
    commit."""
    from verifier.runtime.explanation_projection import render_authored_intent

    lines = [
        "# Prepared source explanation",
        "",
        (
            "Preparation projection only; no future commit, "
            "execution evidence, or verification clearance."
        ),
        "",
        "## Selected prepared source bytes",
        "",
    ]
    for row in inventory(files)["files"]:
        # JSON quoting prevents authored paths from introducing Markdown structure.
        lines.append(
            "- Path "
            + json.dumps(row["path"], ensure_ascii=True)
            + ": "
            + row["sha256"]
            + "; "
            + str(row["size_bytes"])
            + " bytes."
        )
    lines.extend(
        [
            "",
            "## Authored intent",
            "",
            (
                render_authored_intent(definitions)
                if definitions is not None
                else (
                    "No authored definitions were selected; "
                    "motivation remains unresolved."
                )
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _validate_manifest(value: dict[str, Any]) -> None:
    _keys(
        value,
        (
            "schema_version polished promotable policy_sha256 "
            "definition_sha256 quality_profile_sha256 "
            "requirements_sha256 implementation selected_stages "
            "source git_binding git_modes committed_analysis_binding "
            "preparation_state payload claim_boundary"
        ),
    )
    if (
        value["schema_version"] != BUNDLE_SCHEMA
        or value["polished"] is not False
        or value["promotable"] is not False
    ):
        raise WorkflowError("unsupported preparation bundle or fabricated authority")
    for key in (
        "policy_sha256",
        "definition_sha256",
        "quality_profile_sha256",
        "requirements_sha256",
    ):
        selected = value[key]
        if selected is None and key != "policy_sha256":
            continue
        if type(selected) is not str or not re.fullmatch(r"[0-9a-f]{64}", selected):
            raise WorkflowError("invalid bundle input digest")
    for key in ("source", "payload"):
        table = value[key]
        _keys(table, "sha256 files")
        if type(table["files"]) is not list or len(table["files"]) > 1100:
            raise WorkflowError("bundle inventory bound exceeded")
        names = set()
        for row in table["files"]:
            _keys(row, "path sha256 size_bytes")
            name = _name(row["path"])
            if name.casefold() in names:
                raise WorkflowError("ambiguous bundle inventory path")
            names.add(name.casefold())
            if type(row["sha256"]) is not str or not re.fullmatch(
                r"[0-9a-f]{64}", row["sha256"]
            ):
                raise WorkflowError("invalid inventory digest")
            if (
                type(row["size_bytes"]) is not int
                or not 0 <= row["size_bytes"] <= MAX_RECORD_BYTES
            ):
                raise WorkflowError("invalid inventory byte bound")
        if (
            table["files"] != sorted(table["files"], key=lambda row: row["path"])
            or digest(canonical(table["files"])) != table["sha256"]
        ):
            raise WorkflowError("bundle inventory digest mismatch")
    _keys(value["git_binding"], "base head")
    if value["committed_analysis_binding"] is not None:
        _keys(
            value["committed_analysis_binding"],
            "base head source_digest requirements_digest",
        )
        for key, selected in value["committed_analysis_binding"].items():
            pattern = (
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
                if key in {"base", "head"}
                else r"[0-9a-f]{64}"
            )
            if type(selected) is not str or not re.fullmatch(pattern, selected):
                raise WorkflowError("invalid committed analysis binding")
    reconstructed_policy = {
        "schema_version": POLICY_SCHEMA,
        "input_paths": [row["path"] for row in value["source"]["files"]],
        "stages": value["selected_stages"],
        "bounds": {
            "max_files": 1024,
            "max_file_bytes": 4 * 1024 * 1024,
            "max_total_bytes": 64 * 1024 * 1024,
        },
    }
    raw = canonical(reconstructed_policy)
    load_policy(raw, digest(raw))
    if value["git_modes"] is not None:
        if type(value["git_modes"]) is not dict or any(
            _name(name) != name or mode not in {"100644", "100755"}
            for name, mode in value["git_modes"].items()
        ):
            raise WorkflowError("invalid selected Git modes")
    if value["preparation_state"] not in {
        "EXACT_SELECTED_COMMIT_BYTES",
        "PREPARED_PENDING_COMMIT",
    }:
        raise WorkflowError("invalid preparation state")


def _quality_projection(report: dict[str, Any]) -> dict[str, Any]:
    """Preserve outcomes/bindings while separating ephemeral executed arguments."""
    projected = _record(canonical(report))
    for row in projected.get("stages", []):
        row.pop("invocation", None)
    return {
        "schema_version": "verifier-polish-quality-projection-1",
        "observation": projected,
        ("claim_boundary"): (
            "Preparation projection of selected outcomes and byte "
            "identities. Executed arguments remain in the retained "
            "attempt; this is not a raw execution receipt."
        ),
    }


def _check_retained_payload(directory: Path, manifest: dict[str, Any]) -> None:
    rows = manifest["payload"]["files"]
    total = 0
    for row in rows:
        raw = _read(_target(directory, row["path"]))
        total += len(raw)
        if (
            total > 128 * 1024 * 1024
            or len(raw) != row["size_bytes"]
            or digest(raw) != row["sha256"]
        ):
            raise WorkflowError("retained resume payload mismatch")
    names = set()
    count = 0
    for path in directory.rglob("*"):
        count += 1
        if count > 4096:
            raise WorkflowError("resume bundle entry bound exceeded")
        info = _ordinary(path)
        if stat.S_ISREG(info.st_mode):
            names.add(path.relative_to(directory).as_posix())
        elif not stat.S_ISDIR(info.st_mode):
            raise WorkflowError("nonordinary resume bundle entry")
    if names != {"manifest.json", *(row["path"] for row in rows)}:
        raise WorkflowError("resume bundle has additional or missing payload")


def _replace(target: Path, before: bytes, after: bytes) -> None:
    if _read(target, 4 * 1024 * 1024) != before:
        raise WorkflowError("source changed before mutation")
    info = _ordinary(target)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkflowError("source alias changed before mutation")
    descriptor, name = tempfile.mkstemp(prefix=".vstd-preparation-", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        if _read(target, 4 * 1024 * 1024) != before:
            raise WorkflowError("source changed during mutation")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def recover_apply(
    root: str | Path, journal_path: str | Path, *, rollback: bool = False
) -> dict[str, Any]:
    """Recover an explicit local apply plan; reject edits outside either retained
    state."""
    source = _root(root)
    selected = _outside(source, journal_path)
    _ordinary(selected)
    journal = _record(_read(selected))
    _keys(journal, "schema_version files plan_digest")
    basis = {key: journal[key] for key in ("schema_version", "files")}
    if (
        journal["schema_version"] != "verifier-polish-apply-plan-1"
        or digest(canonical(basis)) != journal["plan_digest"]
    ):
        raise WorkflowError("apply plan binding mismatch")
    if type(journal["files"]) is not list or len(journal["files"]) > 1024:
        raise WorkflowError("invalid apply inventory")
    planned: list[tuple[Path, bytes, bytes]] = []
    names: set[str] = set()
    for row in journal["files"]:
        _keys(row, "path before after")
        name = _name(row["path"])
        if name.casefold() in names:
            raise WorkflowError("duplicate apply path")
        names.add(name.casefold())
        before = base64.b64decode(row["before"], validate=True)
        after = base64.b64decode(row["after"], validate=True)
        if max(len(before), len(after)) > 4 * 1024 * 1024:
            raise WorkflowError("apply file byte bound exceeded")
        target = _target(source, name)
        info = _ordinary(target)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > 4 * 1024 * 1024
        ):
            raise WorkflowError("ordinary bounded recovery source required")
        current = _read(target, 4 * 1024 * 1024)
        if current not in (before, after):
            raise WorkflowError("later source edit blocks recovery; no edits applied")
        desired = before if rollback else after
        planned.append((target, current, desired))
    # All comparisons precede mutation, with a fresh per-file comparison as well.
    for target, current, desired in planned:
        if current != desired:
            _replace(target, current, desired)
    return {
        "status": "PASS",
        "operation": "ROLLBACK" if rollback else "RECOVER_APPLY",
        "plan_digest": journal["plan_digest"],
        "scope": "LOCAL_RETAINED_BYTES_ONLY",
    }


def _apply(
    source: Path, output: Path, original: dict[str, bytes], prepared: dict[str, bytes]
) -> Path:
    changes = [
        {
            "path": name,
            "before": base64.b64encode(raw).decode("ascii"),
            "after": base64.b64encode(prepared[name]).decode("ascii"),
        }
        for name, raw in sorted(original.items())
        if raw != prepared[name]
    ]
    plan = {"schema_version": "verifier-polish-apply-plan-1", "files": changes}
    plan["plan_digest"] = digest(canonical(plan))
    directory = output / "apply-plans"
    directory.mkdir(parents=True, exist_ok=True)
    _ordinary(directory)
    target = directory / (plan["plan_digest"] + ".json")
    raw = canonical(plan) + b"\n"
    if target.exists():
        _ordinary(target)
        if _read(target) != raw:
            raise WorkflowError("apply plan identity occupied")
    else:
        with target.open("xb") as stream:
            stream.write(raw)
    _event(output, {"operation": "APPLY_STARTED", "plan_digest": plan["plan_digest"]})
    try:
        recover_apply(source, target)
    except (OSError, ValueError, KeyboardInterrupt):
        # Roll back only bytes still matching the prepared/original states. Later
        # edits are never overwritten; the retained plan supports manual recovery.
        try:
            recover_apply(source, target, rollback=True)
            disposition = "ROLLED_BACK"
        except (OSError, ValueError, KeyboardInterrupt):
            disposition = "RECOVERY_REQUIRED"
        _event(output, {"operation": disposition, "plan_digest": plan["plan_digest"]})
        raise
    _event(output, {"operation": "APPLY_FINISHED", "plan_digest": plan["plan_digest"]})
    return target


# vstd-explanation: begin prdel.self.polish-workflow
# Authored intent (not verified):
#   Retain final selected source bytes and check outcomes before any separately
# authorized promotion.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): Preparation success cannot issue polished status, human acceptance
# or publication authority.
# vstd-explanation: end prdel.self.polish-workflow
def prepare_workflow(
    root: str | Path,
    *,
    policy_bytes: bytes,
    expected_policy_digest: str,
    definition_bytes: bytes | None = None,
    quality_profile_bytes: bytes | None = None,
    expected_quality_profile_digest: str | None = None,
    git_root: str | Path | None = None,
    base: str | None = None,
    head: str | None = None,
    output: str | Path | None = None,
    resume: bytes | dict[str, Any] | str | Path | None = None,
    apply: bool = False,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    definition_path: str | None = None,
) -> dict[str, Any]:
    """Run fixed preparation stages; success never grants publication or
    qualification."""
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "status": "UNKNOWN",
        "polished": False,
        "promotable": False,
        "mode": "APPLY" if apply else "CHECK_ONLY",
        "stages": [],
        "findings": [],
        "bundle": None,
        "resume": {
            "requested": resume is not None,
            "reused_stages": [],
            "invalidated_stages": [],
        },
        "claim_boundary": BOUNDARY,
    }
    destination = None
    try:
        policy = load_policy(policy_bytes, expected_policy_digest)
        source = _root(root)
        destination = _outside(source, output) if output is not None else None
        if apply and destination is None:
            raise WorkflowError(
                "explicit apply requires an external retained journal directory"
            )
        if destination is not None:
            destination.mkdir(parents=True, exist_ok=True)
            _ordinary(destination)
        original = _capture(source, policy)
        from verifier.runtime.gate import SECRET_PATTERNS

        if any(
            pattern.search(raw.decode("utf-8", errors="replace"))
            for raw in original.values()
            for _, pattern in SECRET_PATTERNS
        ):
            raise WorkflowError(
                "secret pattern requires manual review; preparation blocked"
            )
        quality_pin = _pin(
            quality_profile_bytes, expected_quality_profile_digest, "quality profile"
        )
        requirements_pin = _pin(
            requirements_bytes, expected_requirements_digest, "requirements"
        )
        from verifier.runtime.quality_checks import _environment

        context = {
            "policy_sha256": digest(policy_bytes),
            "source": inventory(original),
            "workspace_modes": _modes(source, policy),
            "definition_sha256": (
                digest(definition_bytes) if definition_bytes is not None else None
            ),
            "quality_profile_sha256": quality_pin,
            "requirements_sha256": requirements_pin,
            "git_base": base,
            "git_head": head,
            "definition_path": definition_path,
            "implementation": _implementation(),
            "quality_environment_sha256": (
                digest(canonical(_environment())) if quality_pin is not None else None
            ),
        }
        context_digest = digest(canonical(context))
        report["binding"] = context
        report["binding_digest"] = context_digest
        if resume is not None:
            if type(resume) is dict:
                prior = dict(resume)
            elif type(resume) is bytes:
                prior = _record(resume)
            else:
                prior_path = Path(resume)
                if prior_path.is_dir():
                    prior_path = prior_path / "manifest.json"
                prior = _record(_read(prior_path))
            if prior.get("schema_version") == REPORT_SCHEMA:
                carried = prior.pop("report_digest", None)
                if digest(canonical(prior)) != carried:
                    raise WorkflowError("resume report digest mismatch")
            elif prior.get("schema_version") == BUNDLE_SCHEMA:
                _validate_manifest(prior)
                if type(resume) is not dict and type(resume) is not bytes:
                    _check_retained_payload(prior_path.parent, prior)
                    if prior_path.parent.name != digest(canonical(prior)):
                        raise WorkflowError("retained resume bundle identity mismatch")
                prior = {"binding_digest": None, "bundle_id": digest(canonical(prior))}
            else:
                raise WorkflowError("unsupported resume receipt")
            # Never deserialize carried PASS as authority. Re-run all selected
            # dispatchers, even when identities match; retain lineage separately.
            same = prior.get("binding_digest") == context_digest
            report["resume"].update(
                {
                    "prior_binding_digest": prior.get("binding_digest"),
                    "identity_matches": same,
                    "invalidated_stages": (
                        []
                        if same
                        else [
                            row["id"] for row in _stage_order(policy) if row["selected"]
                        ]
                    ),
                    "reason": (
                        "RECHECK_ALL_SELECTED_STAGES"
                        if same
                        else "CHANGED_INPUTS_RECHECK_REQUIRED"
                    ),
                }
            )
        if destination is not None:
            _event(
                destination,
                {"operation": "PREPARATION_STARTED", "binding_digest": context_digest},
            )
        prepared = dict(original)
        definitions = None
        git_modes = None
        analysis_binding = None
        payload: dict[str, bytes] = {}
        outcomes: dict[str, dict[str, Any]] = {}
        blocked = False
        for row in _stage_order(policy):
            stage_id = row["id"]
            result = {
                "id": stage_id,
                "required": row["required"],
                "depends_on": row["depends_on"],
                "status": "NOT_SELECTED",
                "execution_status": "NOT_SELECTED",
                "output_digest": None,
            }
            if not row["selected"]:
                outcomes[stage_id] = result
                report["stages"].append(result)
                continue
            if blocked:
                result.update(
                    status="FAIL" if row["required"] else "NOT_RUN",
                    execution_status="NOT_RUN",
                )
                if row["required"]:
                    report["findings"].append(
                        {
                            "code": "REQUIRED_STAGE_NOT_RUN",
                            "stage": stage_id,
                            "status": "FAIL",
                            "execution_status": "NOT_RUN",
                        }
                    )
            else:
                try:
                    value: dict[str, Any] = {"status": "PASS"}
                    if stage_id == "bind-inputs":
                        value = {"status": "PASS", "source": context["source"]}
                        if git_root is not None and head is not None:
                            from verifier.runtime.prdel import _snapshot, _revision

                            exact_head = _revision(Path(git_root), head)
                            if exact_head != head:
                                raise WorkflowError(
                                    (
                                        "input mode binding requires "
                                        "an exact full head commit"
                                    )
                                )
                            retained = _snapshot(Path(git_root), exact_head)
                            git_modes = {
                                name: retained.modes[name]
                                for name in prepared
                                if name in retained.modes
                            }
                            if len(git_modes) != len(prepared):
                                git_modes = None
                            value["selected_commit"] = exact_head
                            value["selected_git_modes"] = git_modes
                            value["input_matches_selected_head"] = all(
                                retained.get(name) == raw
                                for name, raw in original.items()
                            )
                            report["commit_correspondence"] = {
                                "input_matches_selected_head": value[
                                    "input_matches_selected_head"
                                ],
                                "prepared_matches_selected_head": value[
                                    "input_matches_selected_head"
                                ],
                                "scope": "SELECTED_INPUT_PATHS_ONLY",
                                "status": (
                                    "PASS"
                                    if value["input_matches_selected_head"]
                                    else "UNKNOWN"
                                ),
                            }
                    elif stage_id == "validate-definitions":
                        if definition_bytes is not None:
                            from verifier.runtime.explanation_projection import (
                                load_definitions,
                            )

                            definitions = load_definitions(definition_bytes)
                            value = {
                                "status": "PASS",
                                "definition_sha256": digest(definition_bytes),
                            }
                            payload["definition.json"] = definition_bytes
                            if (
                                definition_path is not None
                                and git_root is not None
                                and head is not None
                            ):
                                from verifier.runtime.explanation_projection import (
                                    resolve_definition_provenance,
                                    canonical_definitions,
                                )

                                if (
                                    _read(_target(_root(git_root), definition_path))
                                    != definition_bytes
                                ):
                                    raise WorkflowError(
                                        (
                                            "selected definition "
                                            "path differs from "
                                            "selected definition "
                                            "bytes"
                                        )
                                    )
                                report["definition_provenance"] = (
                                    resolve_definition_provenance(
                                        Path(git_root), head, definition_path
                                    )
                                )
                                observation = report["definition_provenance"]
                                if observation.get("status") == "FAIL":
                                    raise WorkflowError(
                                        "selected definition provenance contract failed"
                                    )
                                if observation.get("workspace_sha256") not in (
                                    None,
                                    digest(definition_bytes),
                                ) or observation.get("definition_digest") not in (
                                    None,
                                    digest(canonical_definitions(definitions)),
                                ):
                                    raise WorkflowError(
                                        (
                                            "definition bytes "
                                            "changed during "
                                            "provenance observation"
                                        )
                                    )
                            else:
                                report["definition_provenance"] = {
                                    "status": "NOT_SELECTED",
                                    "commit_status": "PENDING_COMMIT",
                                    ("reason"): (
                                        "No explicit committed "
                                        "definition path selected."
                                    ),
                                }
                            payload["definition-provenance.json"] = (
                                canonical(report["definition_provenance"]) + b"\n"
                            )
                        else:
                            value = {
                                "status": "PASS",
                                "definition_status": "NOT_PROVIDED",
                                "authored_intent": "UNRESOLVED",
                            }
                    elif stage_id == "project-comments":
                        if definitions is None:
                            raise WorkflowError(
                                (
                                    "selected comment projection "
                                    "requires canonical definitions"
                                )
                            )
                        from verifier.runtime.explanation_projection import (
                            project_comments,
                        )

                        projection = project_comments(prepared, definitions)
                        value = {
                            key: item
                            for key, item in projection.items()
                            if key != "files"
                        }
                        if projection["status"] == "PASS":
                            prepared = projection["files"]
                        report["projection"] = value
                    elif stage_id == "compile-explanations":
                        if git_root is None or base is None or head is None:
                            raise WorkflowError(
                                (
                                    "selected compilation requires "
                                    "exact Git root, base and head"
                                )
                            )
                        from verifier.runtime.prdel_rules import compile_prdel
                        from verifier.runtime.prdel import (
                            render_prdel,
                            validate_prdel,
                            _snapshot,
                            _revision,
                        )

                        value = compile_prdel(
                            Path(git_root),
                            base,
                            head,
                            requirements_bytes,
                            requirements_pin,
                            definitions,
                        )
                        document = value.get("document")
                        if document is not None:
                            analysis_binding = document["binding"]
                            payload["explanation.prdel.json"] = (
                                canonical(document) + b"\n"
                            )
                            payload["description.committed.pr.md"] = render_prdel(
                                document
                            ).encode("utf-8")
                            report["verification"] = validate_prdel(
                                document,
                                Path(git_root),
                                base,
                                head,
                                requirements_bytes,
                                requirements_pin,
                            )
                            exact = _snapshot(
                                Path(git_root), _revision(Path(git_root), head)
                            )
                            git_modes = {
                                name: exact.modes[name]
                                for name in prepared
                                if name in exact.modes
                            }
                            current_matches = all(
                                exact.get(name) == raw for name, raw in original.items()
                            )
                            final_matches = all(
                                exact.get(name) == raw for name, raw in prepared.items()
                            )
                            report["commit_correspondence"] = {
                                "input_matches_selected_head": current_matches,
                                "prepared_matches_selected_head": final_matches,
                                "scope": "SELECTED_INPUT_PATHS_ONLY",
                                "status": "PASS" if final_matches else "UNKNOWN",
                            }
                            if not current_matches:
                                raise WorkflowError(
                                    (
                                        "source inputs differ from "
                                        "selected committed "
                                        "compilation source"
                                    )
                                )
                        report["compilation"] = value
                        payload["compilation.json"] = canonical(value) + b"\n"
                    elif stage_id == "quality":
                        if quality_profile_bytes is None:
                            raise WorkflowError(
                                (
                                    "selected quality stage requires "
                                    "an independently pinned profile"
                                )
                            )
                        from verifier.runtime.quality_checks import run_quality_profile

                        with tempfile.TemporaryDirectory(
                            prefix="vstd-quality-"
                        ) as temporary:
                            staged = Path(temporary)
                            for name, raw in prepared.items():
                                target = staged / name
                                target.parent.mkdir(parents=True, exist_ok=True)
                                target.write_bytes(raw)
                            value = run_quality_profile(
                                staged,
                                quality_profile_bytes,
                                (
                                    "sha256:" + quality_pin
                                    if quality_pin is not None
                                    else None
                                ),
                                definitions,
                            )
                        report["quality"] = value
                        payload["quality-observation.json"] = (
                            canonical(_quality_projection(value)) + b"\n"
                        )
                    elif stage_id == "retain-bundle":
                        value = {
                            "status": "PASS",
                            "prepared_source": inventory(prepared),
                        }
                    result.update(
                        status=value.get("status", "UNKNOWN"),
                        execution_status="EXECUTED",
                        output_digest=digest(canonical(value)),
                    )
                    if result["status"] not in {"PASS", "FAIL", "UNKNOWN"}:
                        raise WorkflowError("dispatcher returned invalid outcome")
                    if result["status"] != "PASS":
                        report["findings"].append(
                            {
                                "code": "STAGE_BLOCKED",
                                "stage": stage_id,
                                "status": result["status"],
                                "residuals": value.get(
                                    "residuals", value.get("findings", [])
                                ),
                            }
                        )
                        blocked = True
                except (OSError, ValueError) as exc:
                    from verifier.runtime.prdel import PrdelUnavailable
                    from verifier.runtime.explanation_projection import (
                        ProjectionUnavailable,
                    )

                    unavailable = isinstance(
                        exc, (PrdelUnavailable, ProjectionUnavailable, PermissionError)
                    )
                    result.update(
                        status=(
                            "UNKNOWN"
                            if unavailable
                            else (
                                "FAIL"
                                if isinstance(
                                    exc, (WorkflowError, FileNotFoundError, ValueError)
                                )
                                else "UNKNOWN"
                            )
                        ),
                        execution_status=(
                            "NOT_RUN"
                            if isinstance(exc, FileNotFoundError)
                            else "EXECUTED"
                        ),
                    )
                    report["findings"].append(
                        {
                            "code": "STAGE_CONTRACT_VIOLATION",
                            "stage": stage_id,
                            "status": result["status"],
                            "message": str(exc),
                        }
                    )
                    blocked = True
            outcomes[stage_id] = result
            report["stages"].append(result)
        # Detect caller edits even on failed stages; none are overwritten.
        if (
            _capture(source, policy) != original
            or _modes(source, policy) != context["workspace_modes"]
        ):
            raise WorkflowError("source changed during preparation")
        if (
            definition_path is not None
            and git_root is not None
            and definition_bytes is not None
        ):
            if _read(_target(_root(git_root), definition_path)) != definition_bytes:
                raise WorkflowError(
                    "selected external definition changed during preparation"
                )
        if _implementation() != context["implementation"]:
            raise WorkflowError("installed mechanisms changed during preparation")
        if (
            quality_pin is not None
            and digest(canonical(_environment()))
            != context["quality_environment_sha256"]
        ):
            raise WorkflowError("quality environment changed during preparation")
        report["prepared_source"] = inventory(prepared)
        if prepared != original and "commit_correspondence" in report:
            report["commit_correspondence"].update(
                prepared_matches_selected_head=False, status="UNKNOWN"
            )
        report["state"] = (
            "PREPARED_PENDING_COMMIT"
            if prepared != original
            else "EXACT_INPUTS_RETAINED"
        )
        report["status"] = _status(report["findings"])
        if (
            report["status"] == "PASS"
            and outcomes.get("retain-bundle", {}).get("status") == "PASS"
        ):
            payload["description.prepared.md"] = render_prepared_description(
                prepared, definitions
            ).encode("utf-8")
            payload["policy.json"] = policy_bytes
            if requirements_bytes is not None:
                payload["requirements.json"] = requirements_bytes
            if quality_profile_bytes is not None:
                payload["quality-profile.json"] = quality_profile_bytes
            payload.update({"source/" + name: raw for name, raw in prepared.items()})
            if (
                any(len(raw) > MAX_RECORD_BYTES for raw in payload.values())
                or sum(map(len, payload.values())) > 128 * 1024 * 1024
            ):
                raise WorkflowError("bundle output byte bound exceeded")
            manifest = {
                "schema_version": BUNDLE_SCHEMA,
                "polished": False,
                "promotable": False,
                "policy_sha256": digest(policy_bytes),
                "definition_sha256": context["definition_sha256"],
                "quality_profile_sha256": quality_pin,
                "requirements_sha256": requirements_pin,
                "implementation": context["implementation"],
                "selected_stages": policy["stages"],
                "source": inventory(prepared),
                "git_binding": {"base": base, "head": head},
                "git_modes": git_modes,
                "committed_analysis_binding": analysis_binding,
                "preparation_state": (
                    "EXACT_SELECTED_COMMIT_BYTES"
                    if report.get("commit_correspondence", {}).get(
                        "prepared_matches_selected_head"
                    )
                    is True
                    else "PREPARED_PENDING_COMMIT"
                ),
                "payload": inventory(payload),
                "claim_boundary": BOUNDARY,
            }
            bundle_id = digest(canonical(manifest))
            retained = (
                _retain(destination, manifest, payload)
                if destination is not None
                else None
            )
            report["bundle"] = {
                "id": bundle_id,
                "manifest": manifest,
                "path": str(retained) if retained is not None else None,
            }
        if apply and report["status"] == "PASS":
            assert destination is not None
            if report["bundle"] is None:
                raise WorkflowError(
                    (
                        "explicit apply requires selected successful "
                        "immutable bundle retention"
                    )
                )
            if _modes(source, policy) != context["workspace_modes"]:
                raise WorkflowError("source permissions changed before apply")
            plan = _apply(source, destination, original, prepared)
            if (
                _capture(source, policy) != prepared
                or _modes(source, policy) != context["workspace_modes"]
            ):
                raise WorkflowError(
                    "source differs after apply; recovery plan retained"
                )
            report["apply_plan"] = str(plan)
            report["evidence_invalidated"] = prepared != original
    except KeyboardInterrupt:
        report["findings"].append(
            {
                "code": "PREPARATION_CANCELLED",
                "status": "UNKNOWN",
                "execution_status": "NOT_RUN",
                "recovery": (
                    "Inspect retained apply plan before resuming mutation."
                    if apply
                    else "Source was not applied."
                ),
            }
        )
        report["status"] = _status(report["findings"])
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        report["findings"].append(
            {
                "code": "PREPARATION_CONTRACT_VIOLATION",
                "status": (
                    "FAIL"
                    if isinstance(exc, (WorkflowError, FileNotFoundError, ValueError))
                    else "UNKNOWN"
                ),
                "message": str(exc),
            }
        )
        report["status"] = _status(report["findings"])
    report["report_digest"] = digest(canonical(report))
    if destination is not None:
        try:
            _retain_attempt(destination, report)
            _event(
                destination,
                {
                    "operation": "PREPARATION_FINISHED",
                    "binding_digest": report.get("binding_digest"),
                    "status": report["status"],
                    "report_digest": report["report_digest"],
                    "bundle_id": report["bundle"]["id"] if report["bundle"] else None,
                },
            )
        except (OSError, ValueError) as exc:
            report["findings"].append(
                {
                    "code": "ATTEMPT_RETENTION_FAILED",
                    "status": "FAIL",
                    "message": str(exc),
                }
            )
            report["status"] = "FAIL"
            report.pop("report_digest", None)
            report["report_digest"] = digest(canonical(report))
    return report


def associate_commit(
    root: str | Path, manifest: dict[str, Any], commit: str
) -> dict[str, Any]:
    """Observe a later exact whole-tree association; never mutate a retained bundle."""
    from verifier.runtime.prdel import _snapshot, _revision, PrdelUnavailable

    try:
        _validate_manifest(manifest)
        revision = _revision(Path(root), commit)
        if revision != commit:
            raise WorkflowError("full exact commit required")
        snapshot = _snapshot(Path(root), revision)
        observed = inventory(dict(snapshot))
        matches = observed == manifest["source"]
        selected_modes = manifest.get("git_modes")
        modes_match = (
            selected_modes == snapshot.modes if selected_modes is not None else None
        )
        return {
            "schema_version": "verifier-polish-commit-association-1",
            "status": (
                "FAIL"
                if not matches or modes_match is False
                else "UNKNOWN" if modes_match is None else "PASS"
            ),
            "bundle_id": digest(canonical(manifest)),
            "commit": revision,
            "tree": observed,
            "mode_correspondence": (
                "NOT_ESTABLISHED"
                if modes_match is None
                else "PASS" if modes_match else "FAIL"
            ),
            ("claim_boundary"): (
                "Exact retained whole-tree bytes and selected modes "
                "only; no author, historical timing, pull request or "
                "execution authenticity."
            ),
        }
    except PrdelUnavailable as exc:
        return {"status": "UNKNOWN", "reason": str(exc)}
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        return {"status": "FAIL", "reason": str(exc)}
