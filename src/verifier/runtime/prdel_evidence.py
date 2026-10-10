"""Fixed independent replay for Pull Request Domain Explanation Language (PRDEL).

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
and Verifier Standard (VSTD) coordinates bind an externally selected plan to
two exact Git snapshots.  The plan contains pytest node identifiers, never a
command, module import, option, outcome, or executable path.  This module
materializes the selected head in a private directory and performs the fixed
replay itself.

Replay establishes only that selected tests executed against the selected
bytes.  Candidate tests remain candidate code; replay does not establish their
adequacy, runtime correctness, checker independence, whole-estate completeness,
release readiness, or authority.  The subprocess is not a sandbox. Pytest's
Java unit test report format (JUnit) Extensible Markup Language (XML) is parsed
only as the fresh subprocess outcome; it is never accepted from the replay plan.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import xml.etree.ElementTree as ElementTree


SCHEMA = "verifier-prdel-replay-plan-1"
RUNNER = "pytest-nodeids-1"
LAYERS = ("unit", "integration", "regression", "preventative")
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_CHECKS = 64
MAX_NODEIDS = 256
MAX_SELECTED_FILES = 512
MAX_TIMEOUT_SECONDS = 120
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_TESTS = 1024
MAX_FILES = 10000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NODEID = re.compile(
    r"tests/[A-Za-z0-9_./-]+\.py::[A-Za-z_][A-Za-z0-9_]*(?:\[[A-Za-z0-9_.:/-]+\])?\Z"
)
_NON_DISCHARGEABLE = {
    "analysis_bound",
    "edge_bound",
    "frontier_bound",
    "node_bound",
    "output_bound",
    "parse_failure",
    "source_size_bound",
}


class ReplayError(ValueError):
    """The selected replay plan contradicts its exact source binding."""


@dataclass(frozen=True)
class ReplayResult:
    """One verifier-produced check result; JSON cannot construct this value."""

    identifier: str
    layer: str
    status: str
    obligation_ids: tuple[str, ...]
    command: str
    result_digest: str
    binding: dict[str, str]
    reason_code: str

    def as_evidence(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "kind": "test_result",
            "layer": self.layer,
            "status": self.status,
            "command": self.command,
            "result_digest": self.result_digest,
            **self.binding,
            "obligation_ids": list(self.obligation_ids),
        }


@dataclass(frozen=True)
class ReplayIssue:
    code: str
    status: str
    reason: str
    frontier_id: str | None = None


@dataclass(frozen=True)
class ReplayAssessment:
    results: tuple[ReplayResult, ...]
    frontier_statuses: dict[str, str]
    frontier_mechanisms: dict[str, str]
    issues: tuple[ReplayIssue, ...]
    plan_digest: str


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            raise ReplayError("duplicate replay-plan field")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_PLAN_BYTES:
        raise ReplayError("replay plan byte bound exceeded")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ReplayError("nonfinite replay-plan value")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReplayError("replay plan is not strict JSON") from exc
    if type(value) is not dict:
        raise ReplayError("replay plan must be an object")
    return value


def _exact_keys(value: Any, required: set[str]) -> None:
    if type(value) is not dict or set(value) != required:
        raise ReplayError("replay plan has unsupported fields")


def _portable_path(value: Any, *, test: bool = False) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 4096:
        raise ReplayError("replay path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ReplayError("replay path is not portable")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ReplayError("replay path contains control characters")
    if test and (not value.startswith("tests/") or not value.endswith(".py")):
        raise ReplayError("pytest node identifier must select a test file")
    return value


def _sorted_identifiers(value: Any, *, known: set[str] | None = None) -> list[str]:
    if (
        type(value) is not list
        or not value
        or any(type(item) is not str or _IDENTIFIER.fullmatch(item) is None for item in value)
        or value != sorted(set(value))
        or (known is not None and any(item not in known for item in value))
    ):
        raise ReplayError("replay identifiers must be sorted, unique, and selected")
    return value


def _validate_plan(
    raw: bytes,
    expected_digest: str,
    binding: dict[str, str],
    obligation_ids: set[str],
    frontiers: list[dict[str, Any]],
    before: dict[str, bytes],
    after: dict[str, bytes],
) -> dict[str, Any]:
    if _DIGEST.fullmatch(expected_digest or "") is None or _digest(raw) != expected_digest:
        raise ReplayError("selected replay-plan digest differs")
    value = _decode(raw)
    _exact_keys(
        value,
        {"schema_version", "binding", "checks", "frontier_resolutions", "limits"},
    )
    if value["schema_version"] != SCHEMA or value["binding"] != binding:
        raise ReplayError("replay plan binding differs from exact selected source")
    limits = value["limits"]
    _exact_keys(
        limits,
        {"timeout_seconds", "max_output_bytes", "max_tests", "max_files"},
    )
    bounded = (
        ("timeout_seconds", 1, MAX_TIMEOUT_SECONDS),
        ("max_output_bytes", 1, MAX_OUTPUT_BYTES),
        ("max_tests", 1, MAX_TESTS),
        ("max_files", 1, MAX_FILES),
    )
    for key, minimum, maximum in bounded:
        selected = limits[key]
        if type(selected) is not int or not minimum <= selected <= maximum:
            raise ReplayError("replay limit is outside the supported bound")
    if len(after) > limits["max_files"]:
        raise ReplayError("selected snapshot exceeds replay file bound")
    checks = value["checks"]
    if type(checks) is not list or not checks or len(checks) > MAX_CHECKS:
        raise ReplayError("bounded nonempty replay check list required")
    seen: set[str] = set()
    total_nodeids = 0
    total_files = 0
    for check in checks:
        _exact_keys(
            check,
            {"id", "layer", "obligation_ids", "runner", "nodeids", "selected_files"},
        )
        identifier = check["id"]
        if (
            type(identifier) is not str
            or _IDENTIFIER.fullmatch(identifier) is None
            or identifier in seen
        ):
            raise ReplayError("replay check identity is invalid or duplicate")
        seen.add(identifier)
        if check["layer"] not in LAYERS or check["runner"] != RUNNER:
            raise ReplayError("replay check selects an unsupported layer or runner")
        _sorted_identifiers(check["obligation_ids"], known=obligation_ids)
        nodeids = check["nodeids"]
        if (
            type(nodeids) is not list
            or not nodeids
            or nodeids != sorted(set(nodeids))
            or any(type(item) is not str or _NODEID.fullmatch(item) is None for item in nodeids)
        ):
            raise ReplayError("only sorted fixed pytest node identifiers are supported")
        total_nodeids += len(nodeids)
        if total_nodeids > min(MAX_NODEIDS, limits["max_tests"]):
            raise ReplayError("replay test selection exceeds its bound")
        files = check["selected_files"]
        if type(files) is not list or not files:
            raise ReplayError("selected test-file digest inventory required")
        selected: dict[str, str] = {}
        for row in files:
            _exact_keys(row, {"path", "sha256"})
            path = _portable_path(row["path"], test=True)
            digest = row["sha256"]
            if path in selected or _DIGEST.fullmatch(digest or "") is None:
                raise ReplayError("selected test-file binding is invalid or duplicate")
            if path not in after or _digest(after[path]) != digest:
                raise ReplayError("selected test-file digest differs from exact head")
            selected[path] = digest
        total_files += len(files)
        if total_files > min(MAX_SELECTED_FILES, limits["max_files"]):
            raise ReplayError("selected replay files exceed their bound")
        if any(item.partition("::")[0] not in selected for item in nodeids):
            raise ReplayError("every pytest node identifier needs an exact file binding")

    raw_frontiers = {row["id"]: row for row in frontiers}
    resolutions = value["frontier_resolutions"]
    if type(resolutions) is not list or len(resolutions) > len(raw_frontiers):
        raise ReplayError("bounded frontier-resolution list required")
    observed: set[str] = set()
    for row in resolutions:
        _exact_keys(
            row,
            {"frontier_id", "mechanism_id", "source_obligation_ids", "check_ids"},
        )
        frontier_id = row["frontier_id"]
        if frontier_id in observed or frontier_id not in raw_frontiers:
            raise ReplayError("frontier resolution is duplicate or extraneous")
        observed.add(frontier_id)
        _sorted_identifiers(row["source_obligation_ids"])
        if row["source_obligation_ids"] != sorted(
            raw_frontiers[frontier_id].get("source_obligations", [])
        ):
            raise ReplayError("frontier source binding differs")
        _sorted_identifiers(row["check_ids"], known=seen)
        if row["mechanism_id"] not in {
            "exact-json-plus-replay-1",
            "exact-utf8-plus-replay-1",
            "selected-replay-1",
        }:
            raise ReplayError("frontier mechanism is outside the closed catalogue")
        path = raw_frontiers[frontier_id].get("path")
        if type(path) is str and path and path != "<analysis-frontier>":
            _portable_path(path)
            if path not in before and path not in after:
                raise ReplayError("frontier path is absent from both exact snapshots")
    return value


def _snapshot_digest(files: dict[str, bytes]) -> dict[str, str]:
    return {path: _digest(raw) for path, raw in sorted(files.items())}


def _disk_digest(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        result[relative] = _digest(path.read_bytes())
    return result


def _materialize(root: Path, files: dict[str, bytes], modes: dict[str, str]) -> None:
    for name, raw in sorted(files.items()):
        path = root.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        if modes.get(name) == "100755":
            path.chmod(0o700)


def _environment(temporary: Path, source: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            result[key] = value
    result.update(
        PYTHONPATH=str(source / "src"),
        PYTHONDONTWRITEBYTECODE="1",
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        PYTHONHASHSEED="0",
        GIT_TERMINAL_PROMPT="0",
        TEMP=str(temporary),
        TMP=str(temporary),
        HOME=str(temporary),
        USERPROFILE=str(temporary),
    )
    return result


def _junit_counts(path: Path) -> tuple[int, int, int, int]:
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise ReplayError("pytest JUnit result is unavailable") from exc
    suites = [root] if root.tag == "testsuite" else list(root.findall("./testsuite"))
    if not suites:
        raise ReplayError("pytest JUnit result has no test suite")
    try:
        return tuple(
            sum(int(suite.attrib.get(key, "0")) for suite in suites)
            for key in ("tests", "failures", "errors", "skipped")
        )  # type: ignore[return-value]
    except ValueError as exc:
        raise ReplayError("pytest JUnit counts are invalid") from exc


def _run_check(
    check: dict[str, Any],
    binding: dict[str, str],
    source: Path,
    temporary: Path,
    limits: dict[str, int],
    index: int,
) -> ReplayResult:
    junit = temporary / f"junit-{index}.xml"
    base = temporary / f"pytest-{index}"
    argv = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--capture=no",
        "--tb=no",
        "--basetemp",
        str(base),
        "--junitxml",
        str(junit),
        *check["nodeids"],
    ]
    status = "UNKNOWN"
    reason = "REPLAY_TOOL_UNAVAILABLE"
    code: int | None = None
    try:
        child = subprocess.Popen(
            argv,
            cwd=source,
            env=_environment(temporary, source),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        reason = "REPLAY_RUNNING"
        output_count = 0
        output_exhausted = threading.Event()

        def drain() -> None:
            nonlocal output_count
            assert child.stdout is not None
            while True:
                try:
                    chunk = child.stdout.read(65536)
                except OSError:
                    return
                if not chunk:
                    return
                output_count += len(chunk)
                if output_count > limits["max_output_bytes"]:
                    output_exhausted.set()
                    try:
                        child.kill()
                    except OSError:
                        pass
                    return

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        deadline = time.monotonic() + limits["timeout_seconds"]
        while child.poll() is None:
            if output_exhausted.is_set():
                reason = "REPLAY_OUTPUT_BOUND"
                child.kill()
                break
            if time.monotonic() >= deadline:
                reason = "REPLAY_TIMEOUT"
                child.kill()
                break
            time.sleep(0.01)
        try:
            code = child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            reason = "REPLAY_TOOL_UNAVAILABLE"
        reader.join(timeout=5)
        if reader.is_alive():
            reason = "REPLAY_TOOL_UNAVAILABLE"
        if child.stdout is not None:
            child.stdout.close()
        reader.join(timeout=1)
        if output_exhausted.is_set():
            reason = "REPLAY_OUTPUT_BOUND"
        elif reason not in {"REPLAY_TIMEOUT", "REPLAY_TOOL_UNAVAILABLE"} and code is not None:
            if not junit.exists() or junit.stat().st_size > limits["max_output_bytes"]:
                reason = "REPLAY_OUTPUT_BOUND"
                raise ReplayError("pytest JUnit output exceeded its bound")
            tests, failures, errors, skipped = _junit_counts(junit)
            summary = {
                "exit_code": code,
                "tests": tests,
                "failures": failures,
                "errors": errors,
                "skipped": skipped,
            }
            if tests < 1 or tests > limits["max_tests"]:
                status, reason = "FAIL", "REPLAY_TEST_COUNT_INVALID"
            elif code == 0 and not failures and not errors and not skipped:
                status, reason = "PASS", "VERIFIER_REPLAYED"
            else:
                status, reason = "FAIL", "REPLAY_NOT_GREEN"
            result_digest = _digest(_canonical(summary))
            return ReplayResult(
                check["id"],
                check["layer"],
                status,
                tuple(check["obligation_ids"]),
                "python -m pytest <fixed-selected-nodeids>",
                result_digest,
                dict(binding),
                reason,
            )
    except ReplayError:
        if reason == "REPLAY_RUNNING":
            reason = "REPLAY_RESULT_UNAVAILABLE"
    except (OSError, subprocess.SubprocessError):
        pass
    summary = {"status": status, "reason_code": reason}
    return ReplayResult(
        check["id"],
        check["layer"],
        status,
        tuple(check["obligation_ids"]),
        "python -m pytest <fixed-selected-nodeids>",
        _digest(_canonical(summary)),
        dict(binding),
        reason,
    )


def _strict_json(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ReplayError("frontier JSON contains a nonfinite value")
        ),
    )


def _frontier_statuses(
    plan: dict[str, Any],
    frontiers: list[dict[str, Any]],
    before: dict[str, bytes],
    after: dict[str, bytes],
    results: tuple[ReplayResult, ...],
) -> tuple[dict[str, str], dict[str, str], list[ReplayIssue]]:
    checks = {row.identifier: row for row in results}
    resolutions = {
        row["frontier_id"]: row for row in plan["frontier_resolutions"]
    }
    statuses: dict[str, str] = {}
    mechanisms: dict[str, str] = {}
    issues: list[ReplayIssue] = []
    for frontier in frontiers:
        identifier = frontier["id"]
        kind = frontier.get("frontier_kind", "")
        selected = resolutions.get(identifier)
        if selected is None:
            statuses[identifier] = "UNKNOWN"
            issues.append(
                ReplayIssue(
                    "FRONTIER_REPLAY_NOT_SELECTED",
                    "UNKNOWN",
                    "Materialized frontier has no selected replay mechanism.",
                    identifier,
                )
            )
            continue
        mechanism = selected["mechanism_id"]
        mechanisms[identifier] = mechanism
        if (
            kind in _NON_DISCHARGEABLE
            or str(kind).startswith("incomplete_")
            or str(kind).endswith("_bound")
        ):
            statuses[identifier] = "UNKNOWN"
            issues.append(
                ReplayIssue(
                    "NON_DISCHARGEABLE_ANALYSIS_FRONTIER",
                    "UNKNOWN",
                    "Analysis and resource bounds require complete regeneration.",
                    identifier,
                )
            )
            continue
        selected_checks = [checks[item] for item in selected["check_ids"]]
        required = set(selected["source_obligation_ids"]) | {identifier}
        replayed_layers = {
            result.layer
            for result in selected_checks
            if result.status == "PASS" and required <= set(result.obligation_ids)
        }
        if replayed_layers != set(LAYERS):
            statuses[identifier] = (
                "FAIL" if any(item.status == "FAIL" for item in selected_checks) else "UNKNOWN"
            )
            issues.append(
                ReplayIssue(
                    "FRONTIER_REPLAY_INCOMPLETE",
                    statuses[identifier],
                    "Every active layer must replay the frontier and its source obligations.",
                    identifier,
                )
            )
            continue
        path = frontier.get("path", "")
        try:
            if mechanism == "exact-json-plus-replay-1":
                if kind != "unsupported_language" or not str(path).endswith(".json"):
                    raise ReplayError("JSON resolver does not match this frontier")
                for snapshot in (before, after):
                    if path in snapshot:
                        _strict_json(snapshot[path])
            elif mechanism == "exact-utf8-plus-replay-1":
                if kind != "unsupported_language" or not str(path).endswith(
                    (".html", ".toml", ".yaml", ".yml")
                ):
                    raise ReplayError("text resolver does not match this frontier")
                for snapshot in (before, after):
                    if path in snapshot:
                        raw = snapshot[path]
                        if b"\0" in raw:
                            raise ReplayError("text frontier contains a null byte")
                        raw.decode("utf-8", errors="strict")
            elif mechanism == "selected-replay-1":
                if kind == "unsupported_language":
                    raise ReplayError("unsupported language needs a typed resolver")
                if not (
                    kind == "dynamic_dispatch"
                    or str(kind).startswith("unresolved_")
                ):
                    raise ReplayError("selected replay does not match this frontier")
            statuses[identifier] = "PASS"
        except (ReplayError, UnicodeError, ValueError, TypeError):
            statuses[identifier] = "FAIL"
            issues.append(
                ReplayIssue(
                    "FRONTIER_RESOLVER_REFUTED",
                    "FAIL",
                    "Selected closed-catalogue frontier resolver did not match exact bytes.",
                    identifier,
                )
            )
    return statuses, mechanisms, issues


def replay_plan(
    raw: bytes,
    expected_digest: str,
    binding: dict[str, str],
    obligations: list[dict[str, Any]],
    before: dict[str, bytes],
    after: dict[str, bytes],
) -> ReplayAssessment:
    """Replay the exact selected plan without accepting carried outcomes."""
    obligation_ids = {row["id"] for row in obligations}
    frontiers = [row for row in obligations if row.get("kind") == "frontier"]
    plan = _validate_plan(
        raw,
        expected_digest,
        binding,
        obligation_ids,
        frontiers,
        before,
        after,
    )
    issues: list[ReplayIssue] = []
    results: list[ReplayResult] = []
    with tempfile.TemporaryDirectory(prefix="vstd-prdel-replay-") as directory:
        temporary = Path(directory)
        source = temporary / "source"
        source.mkdir()
        _materialize(
            source,
            after,
            getattr(after, "modes", {}),
        )
        expected = _snapshot_digest(after)
        if _disk_digest(source) != expected:
            raise ReplayError("exact head materialization differs before replay")
        for index, check in enumerate(plan["checks"]):
            result = _run_check(
                check,
                binding,
                source,
                temporary,
                plan["limits"],
                index,
            )
            if _disk_digest(source) != expected:
                result = ReplayResult(
                    result.identifier,
                    result.layer,
                    "FAIL",
                    result.obligation_ids,
                    result.command,
                    _digest(_canonical({"reason_code": "SOURCE_MUTATED_DURING_REPLAY"})),
                    result.binding,
                    "SOURCE_MUTATED_DURING_REPLAY",
                )
                issues.append(
                    ReplayIssue(
                        "SOURCE_MUTATED_DURING_REPLAY",
                        "FAIL",
                        "The private exact-head snapshot changed during replay.",
                    )
                )
                results.append(result)
                break
            results.append(result)
    frozen = tuple(results)
    frontier_statuses, frontier_mechanisms, frontier_issues = _frontier_statuses(
        plan, frontiers, before, after, frozen
    )
    issues.extend(frontier_issues)
    return ReplayAssessment(
        frozen,
        frontier_statuses,
        frontier_mechanisms,
        tuple(issues),
        _digest(raw),
    )

